using LetsEncrypt.Logic.Config;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Func.Config
{
    public interface IConfigurationLoader
    {
        Task<IEnumerable<(string configName, Configuration config)>> LoadConfigFilesAsync(Microsoft.Azure.WebJobs.ExecutionContext executionContext, CancellationToken cancellationToken);
    }
}
