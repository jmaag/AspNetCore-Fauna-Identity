
namespace Microsoft.AspNetCore.Identity.Fauna
{
	using global::System.Threading.Tasks;
    using global::FaunaDB.Client;
	using static FaunaDB.Query.Language;
	using static FaunaDB.Types.Option;
	using static FaunaDB.Types.Encoder;

	public static class IndexChecks
    {
		public static async void EnsureUniqueIndexOnNormalizedUserName<TUser>(UserFactory<TUser> users)
			   where TUser : IdentityUser
		{

			// check first
			if (!await IsColl("users", users.Client)) {
				await users.Client.Query(CreateCollection(Obj("name", "users")));
			}

			if(!await IsInd("all_users", users.Client))
			{
				await users.Client.Query(CreateIndex(Obj(
					"name", "all_users",
					"active", true,
					"source", Collection("users")
				  )));
			}

			if (!await IsInd("user_by_name", users.Client))
			{
				await users.Client.Query(CreateIndex(Obj(
					"name", "user_by_name",
					"active", true,
					"source", Collection("users"),
					"terms", Arr(Obj("field", Arr("data", "NormalizedUserName")))
				  )));
			}

			if (!await IsInd("users_by_claim", users.Client))
			{
				await users.Client.Query(CreateIndex(Obj(
					"name", "users_by_claim",
					"active", true,
					"source", Collection("users"),
					"terms", Arr(
						Obj("field", Arr("data", "Claims", "Type")),
						Obj("field", Arr("data", "Claims", "Value"))
						)
				  )));
			}

			if (!await IsInd("users_by_login", users.Client))
			{
				await users.Client.Query(CreateIndex(Obj(
					"name", "users_by_login",
					"active", true,
					"source", Collection("users"),
					"terms", Arr(
						Obj("field", Arr("data", "Logins", "LoginProvider")),
						Obj("field", Arr("data", "Logins", "ProviderKey"))
						)
				  )));
			}

			if (!await IsInd("users_by_role", users.Client))
			{
				await users.Client.Query(CreateIndex(Obj(
					"name", "users_by_role",
					"active", true,
					"source", Collection("users"),
					"terms", Arr(Obj("field", Arr("data", "Roles")))
				  )));
			}
		}

		public static async void EnsureUniqueIndexOnNormalizedRoleName<TRole>(RoleFactory<TRole> roles)
			where TRole : IdentityRole
		{
			if (!await IsColl("users", roles.Client))
			{
				await roles.Client.Query(CreateCollection(Obj("name", "roles")));
			}

			if (!await IsInd("all_roles", roles.Client))
			{
				await roles.Client.Query(CreateIndex(Obj(
					"name", "all_roles",
					"active", true,
					"source", Collection("roles")
				  )));
			}

			if (!await IsInd("role_by_name", roles.Client))
			{
				await roles.Client.Query(CreateIndex(Obj(
					"name", "role_by_name",
					"active", true,
					"source", Collection("roles"),
					"terms", Arr(Obj("field", Arr("data", "NormalizedName")))
				  )));
			}
		}

		public static async void EnsureUniqueIndexOnNormalizedEmail<TUser>(UserFactory<TUser> users)
			where TUser : IdentityUser
		{
			if (!await IsInd("user_by_email", users.Client))
			{
				await users.Client.Query(CreateIndex(Obj(
					"name", "user_by_email",
					"active", true,
					"source", Collection("users"),
					"terms", Arr(Obj("field", Arr("data", "NormalizedEmail")))
				  )));
			}
		}

		private static async Task<bool> IsColl(string name, FaunaClient client)
		{
			var result = false;
			var validation = await client.Query(IsCollection(Collection(name)));

			if (validation != null)
			{
				result = validation.To<bool>().Value;
			}

			return result;
		}

		private static async Task<bool> IsInd(string name, FaunaClient client)
		{
			var result = false;
			var validation = await client.Query(IsIndex(Index(name)));

			if (validation != null)
			{
				result = validation.To<bool>().Value;
			}

			return result;
		}

		/// <summary>
		///     ASP.NET Core Identity now searches on normalized fields so these indexes are no longer required, replace with
		///     normalized checks.
		/// </summary>
		public static class OptionalIndexChecks
		{
			/*public static void EnsureUniqueIndexOnUserName<TUser>(IMongoCollection<TUser> users)
				where TUser : IdentityUser
			{
				var userName = Builders<TUser>.IndexKeys.Ascending(t => t.UserName);
				var unique = new CreateIndexOptions { Unique = true };
				users.Indexes.CreateOneAsync(new CreateIndexModel<TUser>(userName, unique));
				//users.Indexes.CreateOneAsync(userName, unique);
			}

			public static void EnsureUniqueIndexOnRoleName<TRole>(IMongoCollection<TRole> roles)
				where TRole : IdentityRole
			{
				var roleName = Builders<TRole>.IndexKeys.Ascending(t => t.Name);
				var unique = new CreateIndexOptions { Unique = true };

				roles.Indexes.CreateOneAsync(new CreateIndexModel<TRole>(roleName, unique));
				//roles.Indexes.CreateOneAsync(roleName, unique);
			}

			public static void EnsureUniqueIndexOnEmail<TUser>(IMongoCollection<TUser> users)
				where TUser : IdentityUser
			{
				var email = Builders<TUser>.IndexKeys.Ascending(t => t.Email);
				var unique = new CreateIndexOptions { Unique = true };

				users.Indexes.CreateOneAsync(new CreateIndexModel<TUser>(email, unique));
				//users.Indexes.CreateOneAsync(email, unique);
			}*/
		}
	}
}
