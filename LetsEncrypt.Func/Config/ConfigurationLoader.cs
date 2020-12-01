using LetsEncrypt.Logic.Config;
using LetsEncrypt.Logic.Storage;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace LetsEncrypt.Func.Config
{
    public class ConfigurationLoader : IConfigurationLoader
    {
        private readonly IStorageProvider _storageProvider;
        private readonly IConfigurationProcessor _configurationProcessor;
        private readonly ILogger _logger;

        public ConfigurationLoader(
            IStorageProvider storageProvider,
            IConfigurationProcessor configurationProcessor,
            ILogger logger)
        {
            _storageProvider = storageProvider;
            _configurationProcessor = configurationProcessor;
            _logger = logger;
        }

        public async Task<IEnumerable<(string configName, Configuration)>> LoadConfigFilesAsync(
            Microsoft.Azure.WebJobs.ExecutionContext executionContext,
            CancellationToken cancellationToken)

        {
            var configs = new List<(string, Configuration)>();
            var paths = await _storageProvider.ListAsync("config/", cancellationToken);
            foreach (var path in paths)
            {
                if ("config/sample.json".Equals(path, StringComparison.OrdinalIgnoreCase))
                    continue; // ignore

                var content = await _storageProvider.GetAsync(path, cancellationToken);
                try
                {
                    configs.Add((path, _configurationProcessor.ValidateAndLoad(content)));
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Failed to process configuration file " + path);
                }
            }

            if (!paths.Any())
            {
                _logger.LogWarning("No config files found. Placing config/sample.json in storage!");
                var sampleJsonPath = Path.Combine(executionContext.FunctionAppDirectory, "sample.json");
                var content = await File.ReadAllTextAsync(sampleJsonPath, cancellationToken);
                await _storageProvider.SetAsync("config/sample.json", content, cancellationToken);
            }

            return configs.ToArray();
        }
    }
}
