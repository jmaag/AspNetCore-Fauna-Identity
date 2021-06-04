namespace Microsoft.AspNetCore.Identity.Fauna
{
    using System.Collections.Generic;
    using System.Linq;
	using System.Threading;
	using System.Threading.Tasks;
	using global::FaunaDB.Client;
	using global::FaunaDB.Query;
	using global::FaunaDB.Types;

	public class RoleFactory<TRole>
	{
		public FaunaClient Client;

		public RoleFactory(FaunaClient client)
		{
			Client = client;
		}
	}

	/// <summary>
	///     Note: Deleting and updating do not modify the roles stored on a user document. If you desire this dynamic
	///     capability, override the appropriate operations on RoleStore as desired for your application. For example you could
	///     perform a document modification on the users collection before a delete or a rename.
	///     When passing a cancellation token, it will only be used if the operation requires a database interaction.
	/// </summary>
	/// <typeparam name="TRole">Needs to extend the provided IdentityRole type.</typeparam>
	public class RoleStore<TRole> : IQueryableRoleStore<TRole>
		// todo IRoleClaimStore<TRole>
		where TRole : IdentityRole
	{
		private readonly FaunaClient _client;
		private readonly Expr _collection;

		public RoleStore(RoleFactory<TRole> client)
		{
			//_Roles = roles;
			_client = client.Client;
			_collection = Language.Collection("roles");

			IndexChecks.EnsureUniqueIndexOnNormalizedRoleName(client);
		}

		public virtual void Dispose()
		{
			// no need to dispose of anything, mongodb handles connection pooling automatically
		}

		public virtual async Task<IdentityResult> CreateAsync(TRole role, CancellationToken token)
		{
			var beagles = await _client.Query(
				Language.Create(
					_collection,
					Language.Obj("data", Encoder.Encode(role))
				)
			);

			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken token)
		{
			var result = await _client.Query(
				Language.Update(
					Language.Ref(_collection, role.Id), 
					Language.Obj("data", Encoder.Encode(role))
				)
			);

			// todo low priority result based on replace result
			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken token)
		{
			var result = await _client.Query(
				Language.Delete(Language.Ref(_collection, role.Id))
			);

			// todo low priority result based on delete result
			return IdentityResult.Success;
		}

		public virtual async Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
			=> role.Id;

		public virtual async Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
			=> role.Name;

		public virtual async Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
			=> role.Name = roleName;

		// note: can't test as of yet through integration testing because the Identity framework doesn't use this method internally anywhere
		public virtual async Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
			=> role.NormalizedName;

		public virtual async Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
			=> role.NormalizedName = normalizedName;

		public virtual async Task<TRole> FindByIdAsync(string roleId, CancellationToken token)
        {
			var result = await _client.Query(Language.Get(Language.Ref(_collection, roleId)));
			TRole role = Decoder.Decode<TRole>(result.At("data"));
			var id = result.At("ref").To<RefV>();
			role.Id = id.Value.Id;

			return role;
        }

		public virtual async Task<TRole> FindByNameAsync(string normalizedName, CancellationToken token)
		{
			var result = await _client.Query(
				Language.Paginate(
					Language.Match(Language.Index("role_by_name"), normalizedName)
				)
			);

			var data = result.At("data").To<Value[]>();
			TRole role = null;

			if(data.Value != null && data.Value.Length > 0)
            {
				role = Decoder.Decode<TRole>(data.Value[0]);
				role.Id = data.Value[0].At("ref").To<RefV>().Value.Id;
            }

			return role;
		}

		public virtual IQueryable<TRole> Roles
        {
			get
			{
				var result = _client.Query(
					Language.Match(Language.Index("all_roles"))
				).GetAwaiter().GetResult();

				var data = result.At("data").To<Value[]>();
				List<TRole> roles = new List<TRole>();

				if (data.Value != null && data.Value.Length > 0)
				{
					foreach (var item in data.Value)
					{
						var role = Decoder.Decode<TRole>(item);
						role.Id = item.At("ref").To<RefV>().Value.Id;
						roles.Add(role);
					}
				}

				return roles.AsQueryable();
			}
        }
	}
}
