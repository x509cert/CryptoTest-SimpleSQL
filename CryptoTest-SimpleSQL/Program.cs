using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Data;
using Azure.Core;
using Azure.Identity;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.Encryption.Cryptography.Serializers;
using Microsoft.Data.Encryption.AzureKeyVaultProvider;
using Microsoft.Data.SqlClient;

#region Setup (Azure login, AKV and crypto settings)

// Use this VM's Managed Service Identity
var creds = new DefaultAzureCredential();

// pulled from SQL, this is an AES key wrapped in an RSA key
// it should be in a config file or VM parameter
byte[] wrappedDek = FromHexString("0x01A8000001680074007400700073003A002F002F006B0076002D00630072007900700074006F0074006500730074002E007600610075006C0074002E0061007A007500720065002E006E00650074002F006B006500790073002F0063006D006B006100750074006F0036002F003800310037003200630039003200640035003800620066003400620061006200390035003900630065003300320066003600640033006500380063003000360010E884ADDFF94C26B9084B114D7ACA112C175644469E209691FFE5AE1BD98214EAAA71DC76DCEBC3B51FA0A47F17B6D23DFAEB86534593952A99E8B24EF384B6443DD2CCD6E3AFECD7DDB9EADEC2CC8B53C466DFA9CEF7C267E3DE49508A658DA8E53C7A375EFF6B4470600E006A1CF449FD7FB5E30CFE3670776D2210A1CBD5DB477136F2C7D4A50CE835720A5A4FC0D15555A8367C737839DCDD69E50B5F250C280A6FEC33F7ACB13B042E7A6B0408E6231757DBAE2D837F66DA8B5C8D4CBE8B5318D470206C642FDE350C857534FD791C5863E2196DABC196CA5AB99275A3E0E9851090724BA2F000A841FC253050D0E137B6DC307DF087035674D75A0787C003FF86F3407587259383B254665050B310449FE8D9CA0BCE3E866140F0849F4C3F203A5B7BB6CF87FE707DBE388F69FDAD0998B907ABEA9346C29120EB9637E9E61F1D79340496B3BC99F449FE413E9277846AF7E173474A9866C236153244F0E73084144CD9E5B1778AF60F0B8773EFCDBDAF39073BFEDDF8B724302632308B3A3A0C63D6851CF448F8A674411156254ABF33DB43224904951EEF58A8B5327EC328748226D7F74180EE7C0CC61DDB7828EEE69603D9DB2CCAD46AFAC7A18D09E6D0D804B329DAC89F39A8447E1F331C6366C6E4F5FAB3C9BD76372DD712CFC06BEE55634EB643CE900958A3DA859FEF853F54FD535B913B712CADF4ADD4CB");

// Connect to AKV
var akvKeys = new AzureKeyVaultKeyStoreProvider(creds);
var kek = new KeyEncryptionKey("CMK_Auto6", @"https://kv-cryptotest.vault.azure.net/keys/CMKAuto6/8172c92d58bf4bab959ce32f6d3e8c06", akvKeys);

// Crypto options and parameters
var encryptionSettings =
    new EncryptionSettings<string>(new ProtectedDataEncryptionKey("CEK_Auto4", kek, wrappedDek),
                                    EncryptionType.Deterministic,
                                    new SqlNCharSerializer(size: 12));
#endregion

#region Read from CSV File, encrypt SSN and write to a new CSV file

// read all entries from the CSV file, and encrypt the last element (SSN)
const string fileIn = @"c:\lotr\lotr.csv";
const string fileOut = @"c:\lotr\lotr-enc.csv";
var recordsIn = File.ReadAllLines(fileIn);
var temp = new StringBuilder();

for (int i = 0; i < recordsIn.Length; i++)
{
    if (recordsIn[i].Length <= 1) break;
    string[] elem = recordsIn[i].Split(',');

    //headers
    if (i == 0)
        temp.AppendLine(recordsIn[i]);
    // data
    else
        temp.AppendLine(elem[0] + "," + elem[1] + "," + Convert.ToBase64String(elem[2].Encrypt(encryptionSettings)));
}

File.WriteAllText(fileOut, temp.ToString());

#endregion

#region Insert encrypted CSV into Azure SQL using BulkCopy

var connectionString = "Data Source=sql-cryptotest.database.windows.net; Initial Catalog=LoTR;";
using var conn = new SqlConnection(connectionString);
conn.AccessToken = creds.GetToken(new TokenRequestContext(new[] { "https://database.windows.net/.default" })).Token;
conn.Open();

using var bulkCopy = new SqlBulkCopy(conn, SqlBulkCopyOptions.AllowEncryptedValueModifications, null);

// A DataTable is a DB-idependant way to represent data in col/rows.
// This is used by SQL Bulk Copy
var dt = new DataTable();

// Read all the encrypted data 
var recordsInEnc = File.ReadAllLines(fileOut);

for (int i = 0; i < recordsInEnc.Length; i++)
{
    // if we hit a blank line, we're done
    if (recordsInEnc[i].Length <= 1) break;

    string[] elem = recordsInEnc[i].Split(',');

    // column headings
    if (i == 0)
    {
        foreach (string header in elem)
            dt.Columns.Add(header, (header.CompareTo("ssn") == 0) ? typeof(Byte[]) : typeof(string));
    }
    else
    // row data
    if (i > 0)
    {
        dt.Rows.Add();
        dt.Rows[i - 1].SetField(0, elem[0]);                            // name
        dt.Rows[i - 1].SetField(1, elem[1]);                            // location
        dt.Rows[i - 1].SetField(2, Convert.FromBase64String(elem[2]));  // encrypted SSN
    }
}

dt.AcceptChanges();

// sets the column names in Azure SQL - case sensitive
string[] dbColumns = { "Name", "Location", "SSN"};
foreach (var column in dbColumns)
    bulkCopy.ColumnMappings.Add(column, column);

bulkCopy.DestinationTableName = "Characters2";
bulkCopy.WriteToServer(dt);

conn.Close();

#endregion

#region Helper code

byte[] FromHexString(string hex)
{
    string hexString = hex.Substring(0, 2).ToLower() == "0x" ? hex.Substring(2, hex.Length - 2) : hex;
    return Enumerable.Range(0, hexString.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                     .ToArray();
}

#endregion