// ReSharper disable once CheckNamespace - Common convention to locate extensions in Microsoft namespaces for simplifying autocompletion as a consumer.

namespace Microsoft.Extensions.DependencyInjection
{
    using System;
    using AspNetCore.Identity;
    using AspNetCore.Identity.Fauna;
    using FaunaDB.Client;

    public static class FaunaIdentityBuilderExtensions
    {
		/// <summary>
		///     This method only registers Fauna stores, you also need to call AddIdentity.
		///     Consider using AddIdentityWithFaunaStores.
		/// </summary>
		/// <param name="builder"></param>
		/// <param name="connectionString">Must contain the database name</param>
		public static IdentityBuilder RegisterFaunaStores<TUser, TRole>(this IdentityBuilder builder, string endpoint, string secret)
			where TRole : IdentityRole
			where TUser : IdentityUser
		{
			var client = new FaunaClient(endpoint: endpoint, secret: secret);

			return builder.RegisterFaunaStores(
				p => new UserFactory<TUser>(client),
				p => new RoleFactory<TRole>(client));
		}

		/// <summary>
		///     If you want control over creating the users and roles collections, use this overload.
		///     This method only registers Fauna stores, you also need to call AddIdentity.
		/// </summary>
		/// <typeparam name="TUser"></typeparam>
		/// <typeparam name="TRole"></typeparam>
		/// <param name="builder"></param>
		/// <param name="usersCollectionFactory"></param>
		/// <param name="rolesCollectionFactory"></param>
		public static IdentityBuilder RegisterFaunaStores<TUser, TRole>(this IdentityBuilder builder,
			Func<IServiceProvider, UserFactory<TUser>> userCollectionFactory,
			Func<IServiceProvider, RoleFactory<TRole>> roleCollectionFactory)
			where TRole : IdentityRole
			where TUser : IdentityUser
		{
			if (typeof(TUser) != builder.UserType)
			{
				var message = "User type passed to RegisterFaunaStores must match user type passed to AddIdentity. "
							  + $"You passed {builder.UserType} to AddIdentity and {typeof(TUser)} to RegisterFaunaStores, "
							  + "these do not match.";
				throw new ArgumentException(message);
			}
			if (typeof(TRole) != builder.RoleType)
			{
				var message = "Role type passed to RegisterFaunaStores must match role type passed to AddIdentity. "
							  + $"You passed {builder.RoleType} to AddIdentity and {typeof(TRole)} to RegisterFaunaStores, "
							  + "these do not match.";
				throw new ArgumentException(message);
			}
			builder.Services.AddSingleton<IUserStore<TUser>>(p => new UserStore<TUser>(userCollectionFactory(p)));
			builder.Services.AddSingleton<IRoleStore<TRole>>(p => new RoleStore<TRole>(roleCollectionFactory(p)));
			return builder;
		}

		/// <summary>
		///     This method registers identity services and FaunaDB stores using the IdentityUser and IdentityRole types.
		/// </summary>
		/// <param name="services"></param>
		/// <param name="connectionString">Connection string must contain the database name</param>
		public static IdentityBuilder AddIdentityWithFaunaStores(this IServiceCollection services, string endpoint, string secret)
		{
			return services.AddIdentityWithFaunaStoresUsingCustomTypes<IdentityUser, IdentityRole>(endpoint, secret);
		}

		/// <summary>
		///     This method allows you to customize the user and role type when registering identity services
		///     and FaunaDB stores.
		/// </summary>
		/// <typeparam name="TUser"></typeparam>
		/// <typeparam name="TRole"></typeparam>
		/// <param name="services"></param>
		/// <param name="connectionString">Connection string must contain the database name</param>
		public static IdentityBuilder AddIdentityWithFaunaStoresUsingCustomTypes<TUser, TRole>(this IServiceCollection services, string endpoint, string secret)
			where TUser : IdentityUser
			where TRole : IdentityRole
		{
			return services.AddIdentity<TUser, TRole>()
				.RegisterFaunaStores<TUser, TRole>(endpoint, secret);
		}
	}
}
