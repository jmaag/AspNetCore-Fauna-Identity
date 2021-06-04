namespace Microsoft.AspNetCore.Identity.Fauna
{
    using global::FaunaDB;
    using global::FaunaDB.Client;
    using global::FaunaDB.Query;
    using global::FaunaDB.Types;
    public class IdentityRole
    {
        [FaunaConstructor]
        public IdentityRole()
        {
            /*FaunaClient client = new FaunaClient();
            var res = await client.Query(Language.NewId());
            Id = res.ToString();*/
        }

        [FaunaConstructor]
        public IdentityRole(string roleName) : this()
        {
            Name = roleName;
        }

        [FaunaIgnore]
        public string Id { get; set; }

        public string Name { get; set; }

        public string NormalizedName { get; set; }

        public override string ToString() => Name;
    }
}
