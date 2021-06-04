namespace Microsoft.AspNetCore.Identity.Fauna
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Security.Claims;
	using System.Threading;
	using System.Threading.Tasks;
	using global::FaunaDB.Client;
	using global::FaunaDB.Query;
	using global::FaunaDB.Types;

	using static FaunaDB.Query.Language;
	using static FaunaDB.Types.Option;
	using static FaunaDB.Types.Encoder;

	public class UserFactory<TUser>
	{
		public FaunaClient Client;

		public UserFactory(FaunaClient client)
        {
			Client = client;
        }
	}

	/// <summary>
	///     When passing a cancellation token, it will only be used if the operation requires a database interaction.
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public class UserStore<TUser> :
			IUserPasswordStore<TUser>,
			IUserRoleStore<TUser>,
			IUserLoginStore<TUser>,
			IUserSecurityStampStore<TUser>,
			IUserEmailStore<TUser>,
			IUserClaimStore<TUser>,
			IUserPhoneNumberStore<TUser>,
			IUserTwoFactorStore<TUser>,
			IUserLockoutStore<TUser>,
			IQueryableUserStore<TUser>,
			IUserAuthenticationTokenStore<TUser>,
			IUserAuthenticatorKeyStore<TUser>,
			IUserTwoFactorRecoveryCodeStore<TUser>
		where TUser : IdentityUser
	{
		//private readonly IMongoCollection<TUser> _Users;
		private readonly FaunaClient _client;
		private readonly Expr _collection;

		public UserStore(UserFactory<TUser> client)
		{
			//_Users = users;
			_client = client.Client;
			_collection = Collection("users");

			IndexChecks.EnsureUniqueIndexOnNormalizedUserName(client);
			IndexChecks.EnsureUniqueIndexOnNormalizedEmail(client);
		}

		public virtual void Dispose()
		{
			// no need to dispose of anything, mongodb handles connection pooling automatically
		}

		public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken token)
		{
			await _client.Query(
				Create(
					_collection,
					Obj("data", Encode(user))
				)
			);

			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken token)
		{
			// todo should add an optimistic concurrency check
			await _client.Query(
				Update(
					Ref(_collection, user.Id),
					Obj("data", Encode(user))
				)
			);

			// todo success based on replace result
			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken token)
		{
			await _client.Query(
				Delete(Ref(_collection, user.Id))
			);

			// todo success based on delete result
			return IdentityResult.Success;
		}

		public virtual async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
			=> user.Id;

		public virtual async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
			=> user.UserName;

		public virtual async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
			=> user.UserName = userName;

		// note: again this isn't used by Identity framework so no way to integration test it
		public virtual async Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
			=> user.NormalizedUserName;

		public virtual async Task SetNormalizedUserNameAsync(TUser user, string normalizedUserName, CancellationToken cancellationToken)
			=> user.NormalizedUserName = normalizedUserName;

		public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken token)
        {
			var result = await _client.Query(Get(Ref(_collection, userId)));
			var user = Decoder.Decode<TUser>(result.At("data"));
			user.Id = result.At("ref").To<RefV>().Value.Id;

			return user;
		} 

		public virtual async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken token)
		{
			try
			{
				Value result = await _client.Query(
					Get(
						Match(Index("user_by_name"), normalizedUserName)
					)
				);

				TUser user = Decoder.Decode<TUser>(result.At("data"));

				if (user != null)
				{
					user.Id = result.At("ref").To<RefV>().Value.Id;
				}

				return user;
			}
			catch(FaunaDB.Errors.NotFound exp)
            {
				return null;
            }
		}

		public virtual async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken token)
			=> user.PasswordHash = passwordHash;

		public virtual async Task<string> GetPasswordHashAsync(TUser user, CancellationToken token)
			=> user.PasswordHash;

		public virtual async Task<bool> HasPasswordAsync(TUser user, CancellationToken token)
			=> user.HasPassword();

		public virtual async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken token)
			=> user.AddRole(normalizedRoleName);

		public virtual async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken token)
			=> user.RemoveRole(normalizedRoleName);

		// todo might have issue, I'm just storing Normalized only now, so I'm returning normalized here instead of not normalized.
		// EF provider returns not noramlized here
		// however, the rest of the API uses normalized (add/remove/isinrole) so maybe this approach is better anyways
		// note: could always map normalized to not if people complain
		public virtual async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken token)
			=> user.Roles;

		public virtual async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken token)
			=> user.Roles.Contains(normalizedRoleName);

		public virtual async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken token)
        {
			var result = await _client.Query(
				Paginate(
					Match(Index("users_by_role"), normalizedRoleName)
				)
			);

			var data = result.At("data").To<Value[]>();
			List<TUser> users = new List<TUser>();

			if (data.Value != null)
			{
				foreach(var item in data.Value)
				{
					var user = Decoder.Decode<TUser>(data.Value[0]);
					user.Id = data.Value[0].At("ref").To<RefV>().Value.Id;
					users.Add(user);
				}
			}

			return users;
		} 

		public virtual async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken token)
        {
			user.AddLogin(login);
			await UpdateAsync(user, token);
        }

		public virtual async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
			=> user.RemoveLogin(loginProvider, providerKey);

		public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken token)
			=> user.Logins
				.Select(l => l.ToUserLoginInfo())
				.ToList();

		public virtual async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
			try
			{
				var result = await _client.Query(
					Get(Match(Index("users_by_login"), loginProvider, providerKey))
				);

				TUser user = Decoder.Decode<TUser>(result.At("data"));

				if (user != null)
				{
					user.Id = result.At("ref").To<RefV>().Value.Id;
				}

				return user;
			}
			catch (FaunaDB.Errors.NotFound exp)
			{
				return null;
			}
		}
			/*=> _Users
				.Find(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
				.FirstOrDefaultAsync(cancellationToken);*/

		public virtual async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken token)
			=> user.SecurityStamp = stamp;

		public virtual async Task<string> GetSecurityStampAsync(TUser user, CancellationToken token)
			=> user.SecurityStamp;

		public virtual async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken token)
			=> user.EmailConfirmed;

		public virtual async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken token)
			=> user.EmailConfirmed = confirmed;

		public virtual async Task SetEmailAsync(TUser user, string email, CancellationToken token)
			=> user.Email = email;

		public virtual async Task<string> GetEmailAsync(TUser user, CancellationToken token)
			=> user.Email;

		// note: no way to intergation test as this isn't used by Identity framework	
		public virtual async Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
			=> user.NormalizedEmail;

		public virtual async Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
			=> user.NormalizedEmail = normalizedEmail;

		public virtual async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken token)
		{

			try
			{
				var result = await _client.Query(
					Get(
						Match(Index("user_by_email"), normalizedEmail)
					)
				);

				TUser user = Decoder.Decode<TUser>(result.At("data"));

				if (user != null)
				{
					user.Id = result.At("ref").To<RefV>().Value.Id;
				}

				return user;
			}
			catch (FaunaDB.Errors.NotFound exp)
			{
				return null;
			}
		}

		public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken token)
			=> user.Claims.Select(c => c.ToSecurityClaim()).ToList();

		public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken token)
		{
			foreach (var claim in claims)
			{
				user.AddClaim(claim);
			}
			return Task.FromResult(0);
		}

		public virtual Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken token)
		{
			foreach (var claim in claims)
			{
				user.RemoveClaim(claim);
			}
			return Task.FromResult(0);
		}

		public virtual async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
		{
			user.ReplaceClaim(claim, newClaim);
		}

		public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken token)
		{
			user.PhoneNumber = phoneNumber;
			return Task.FromResult(0);
		}

		public virtual Task<string> GetPhoneNumberAsync(TUser user, CancellationToken token)
		{
			return Task.FromResult(user.PhoneNumber);
		}

		public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken token)
		{
			return Task.FromResult(user.PhoneNumberConfirmed);
		}

		public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken token)
		{
			user.PhoneNumberConfirmed = confirmed;
			return Task.FromResult(0);
		}

		public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken token)
		{
			user.TwoFactorEnabled = enabled;
			return Task.FromResult(0);
		}

		public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken token)
		{
			return Task.FromResult(user.TwoFactorEnabled);
		}

		public virtual async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
		{

			var result = await _client.Query(
				Paginate(
					Match(Index("users_by_claim"), claim.Type, claim.Value)
				)
			);

			var data = result.At("data").To<Value[]>();
			List<TUser> users = new List<TUser>();

			if (data.Value != null)
			{
				foreach (var item in data.Value)
				{
					var user = Decoder.Decode<TUser>(data.Value[0]);
					user.Id = data.Value[0].At("ref").To<RefV>().Value.Id;
					users.Add(user);
				}
			}

			return users;
			/*return await _Users
				.Find(u => u.Claims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
				.ToListAsync(cancellationToken);*/
		}

		public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken token)
		{
			DateTimeOffset? dateTimeOffset = user.LockoutEndDateUtc;
			return Task.FromResult(dateTimeOffset);
		}

		public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken token)
		{
			user.LockoutEndDateUtc = lockoutEnd?.UtcDateTime;
			return Task.FromResult(0);
		}

		public virtual Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken token)
		{
			user.AccessFailedCount++;
			return Task.FromResult(user.AccessFailedCount);
		}

		public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken token)
		{
			user.AccessFailedCount = 0;
			return Task.FromResult(0);
		}

		public virtual async Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken token)
			=> user.AccessFailedCount;

		public virtual async Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken token)
			=> user.LockoutEnabled;

		public virtual async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken token)
			=> user.LockoutEnabled = enabled;

		public virtual IQueryable<TUser> Users
		{
			get
			{
				var result = _client.Query(
					Match(Index("all_users"))
				).GetAwaiter().GetResult();

				var data = result.At("data").To<Value[]>();
				List<TUser> users = new List<TUser>();

				if (data.Value != null && data.Value.Length > 0)
				{
					foreach (var item in data.Value)
					{
						var user = Decoder.Decode<TUser>(item);
						user.Id = item.At("ref").To<RefV>().Value.Id;
						users.Add(user);
					}
				}

				return users.AsQueryable();
			}
		}

		public virtual async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
			=> user.SetToken(loginProvider, name, value);

		public virtual async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
			=> user.RemoveToken(loginProvider, name);

		public virtual async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
			=> user.GetTokenValue(loginProvider, name);

		#region IUserAuthenticatorKeyStore
		public virtual async Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
			=> user.SetAuthenticatorKey(key);

		public virtual async Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
			=> user.GetAuthenticatorKey();
		#endregion

		#region IUserTwoFactorRecoveryCodeStore
		public virtual async Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
			=> user.ReplaceCodes(recoveryCodes);

		public virtual async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
			=> user.RedeemCode(code);

		public virtual async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
			=> user.CountCodes();
		#endregion
	}
}
