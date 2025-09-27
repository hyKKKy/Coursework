using Coursework.Data.Entities;
using Coursework.Services.Kdf;
using Microsoft.EntityFrameworkCore;

namespace Coursework.Data
{
    public class DataAccessor(DataContext dataContext, IKdfService kdfService)
    {
        private readonly DataContext _dataContext = dataContext;
        private readonly IKdfService _kdfService = kdfService;

        public UserAccess? Authenticate(String login, String password)
        {
            var userAccess = _dataContext
               .UserAccesses
               .AsNoTracking()
               .Include(ua => ua.User)
               .Include(ua => ua.Role)
               .FirstOrDefault(ua => ua.Login == login);

            if (userAccess == null)
            {
                return null;
            }

            String dk = _kdfService.Dk(password, userAccess.Salt);
            if (dk != userAccess.Dk)
            {
                return null;
            }
            return userAccess;
        }
    }
}
