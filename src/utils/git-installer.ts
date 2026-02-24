import { logger } from './logger';
import { spawn } from 'bun';

export interface GitStatus {
  installed: boolean;
  version?: string;
  path?: string;
  installCommand?: string;
  systemInfo?: {
    os: string;
    platform: string;
    arch: string;
  };
}

/**
 * Check if Git is installed and available
 */
export async function checkGitStatus(): Promise<GitStatus> {
  const status: GitStatus = {
    installed: false,
    systemInfo: {
      os: process.platform,
      platform: process.platform,
      arch: process.arch,
    },
  };

  try {
    // Try to get Git version
    const gitProc = spawn(['git', '--version'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(gitProc.stdout).text();
    const error = await new Response(gitProc.stderr).text();
    const exitCode = await gitProc.exited;

    if (exitCode === 0 && output.trim()) {
      status.installed = true;
      status.version = output.trim();
      
      // Get Git path
      try {
        const whichProc = spawn(['which', 'git'], {
          stdout: 'pipe',
          stderr: 'pipe',
        });
        const whichOutput = await new Response(whichProc.stdout).text();
        const whichExitCode = await whichProc.exited;
        if (whichExitCode === 0 && whichOutput.trim()) {
          status.path = whichOutput.trim();
        }
      } catch {
        // which command not available, ignore
      }
    }
  } catch (error) {
    logger.debug(`Git check failed: ${error}`);
  }

  // Determine install command based on system
  status.installCommand = getInstallCommand();

  return status;
}

/**
 * Get the appropriate install command for the current system
 */
function getInstallCommand(): string {
  const platform = process.platform;

  switch (platform) {
    case 'linux':
      return 'sudo ./install-git.sh';
    case 'darwin':
      return 'brew install git';
    case 'win32':
      return 'winget install Git.Git';
    default:
      return 'Please install Git manually from https://git-scm.com';
  }
}

/**
 * Detect Linux distribution for more specific commands
 */
function detectLinuxDistribution(): string {
  try {
    // Try to read /etc/os-release
    const fs = require('fs');
    if (fs.existsSync('/etc/os-release')) {
      const content = fs.readFileSync('/etc/os-release', 'utf8');
      const lines = content.split('\n');
      
      for (const line of lines) {
        if (line.startsWith('ID=')) {
          const distro = line.split('=')[1].replace(/"/g, '');
          return distro;
        }
      }
    }
  } catch {
    // Ignore errors
  }
  
  return 'unknown';
}

/**
 * Get specific install command for Linux distributions
 */
function getLinuxInstallCommand(): string {
  const distro = detectLinuxDistribution();
  
  switch (distro) {
    case 'ubuntu':
    case 'debian':
    case 'linuxmint':
    case 'pop':
      return 'sudo apt update && sudo apt install git';
    case 'centos':
    case 'rhel':
    case 'rocky':
    case 'almalinux':
      return 'sudo yum install git';
    case 'fedora':
      return 'sudo dnf install git';
    case 'arch':
      return 'sudo pacman -S git';
    case 'opensuse-leap':
    case 'opensuse-tumbleweed':
      return 'sudo zypper install git';
    case 'alpine':
      return 'sudo apk add git';
    default:
      return 'sudo ./install-git.sh';
  }
}

/**
 * Generate HTML for Git installation prompt
 */
export function generateGitInstallPrompt(status: GitStatus): string {
  if (status.installed) {
    return `
      <div style="background: #2d4a2d; border: 1px solid #3d5d3d; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <div style="font-size: 1.5rem;">✅</div>
          <div>
            <h4 style="margin: 0; color: #7fb069; font-size: 0.9rem;">Git is Installed</h4>
            <p style="margin: 0.25rem 0 0 0; color: #888; font-size: 0.8rem;">
              ${status.version || 'Git is available'}
              ${status.path ? `at ${status.path}` : ''}
            </p>
          </div>
        </div>
      </div>
    `;
  }

  const installCmd = status.systemInfo?.platform === 'linux' 
    ? getLinuxInstallCommand() 
    : status.installCommand;

  return `
    <div style="background: #4d2d2d; border: 1px solid #5d3d3d; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
      <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
        <div style="font-size: 1.5rem;">⚠️</div>
        <div>
          <h4 style="margin: 0; color: #d47d7d; font-size: 0.9rem;">Git Required for Updates</h4>
          <p style="margin: 0.25rem 0 0 0; color: #888; font-size: 0.8rem;">
            XeoKey needs Git to check for and install updates
          </p>
        </div>
      </div>
      
      <div style="background: #1d1d1d; border: 1px solid #3d3d3d; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem;">
        <p style="margin: 0; color: #9db4d4; font-size: 0.8rem; font-family: monospace;">
          ${installCmd}
        </p>
      </div>
      
      <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
        <button onclick="installGit()" style="background: #4d6d4d; color: #9db4d4; padding: 0.5rem 1rem; border: 1px solid #5d7d5d; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
          Auto-Install Git
        </button>
        <button onclick="checkGitStatus()" style="background: #4d4d4d; color: #9db4d4; padding: 0.5rem 1rem; border: 1px solid #5d5d5d; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">
          Recheck Status
        </button>
        <a href="/docs/git-requirements" target="_blank" style="color: #9db4d4; text-decoration: none; font-size: 0.8rem; padding: 0.5rem 1rem;">
          📖 Documentation
        </a>
      </div>
    </div>
    
    <script>
      async function installGit() {
        const button = event.target;
        button.disabled = true;
        button.textContent = 'Installing...';
        
        try {
          const response = await fetch('/api/install-git', { method: 'POST' });
          const result = await response.json();
          
          if (result.success) {
            button.textContent = 'Installation Started';
            button.style.background = '#4d7d4d';
            
            // Show installation output
            if (result.output) {
              alert('Git installation started. Output:\\n' + result.output);
            }
            
            // Check status after a delay
            setTimeout(() => checkGitStatus(), 5000);
          } else {
            button.textContent = 'Installation Failed';
            button.style.background = '#7d4d4d';
            alert('Installation failed: ' + result.error);
          }
        } catch (error) {
          button.textContent = 'Error';
          button.style.background = '#7d4d4d';
          alert('Error: ' + error.message);
        }
      }
      
      async function checkGitStatus() {
        try {
          const response = await fetch('/api/git-status');
          const status = await response.json();
          
          // Reload page if Git is now installed
          if (status.installed) {
            window.location.reload();
          } else {
            alert('Git is still not installed. Please install manually.');
          }
        } catch (error) {
          alert('Error checking Git status: ' + error.message);
        }
      }
    </script>
  `;
}

/**
 * Attempt to install Git automatically (Linux only)
 */
export async function installGitAutomatically(): Promise<{ success: boolean; output?: string; error?: string }> {
  if (process.platform !== 'linux') {
    return {
      success: false,
      error: 'Automatic installation is only supported on Linux. Please install Git manually.',
    };
  }

  try {
    logger.info('Starting automatic Git installation...');

    // Run the install script
    const installProc = spawn(['sudo', './install-git.sh'], {
      stdout: 'pipe',
      stderr: 'pipe',
      cwd: process.cwd().endsWith('src') ? '..' : process.cwd(),
    });

    const output = await new Response(installProc.stdout).text();
    const error = await new Response(installProc.stderr).text();
    const exitCode = await installProc.exited;

    if (exitCode === 0) {
      logger.info('Git installation completed successfully');
      return { success: true, output };
    } else {
      logger.error(`Git installation failed with exit code ${exitCode}: ${error}`);
      return { success: false, error: error || output };
    }
  } catch (error: any) {
    logger.error(`Git installation error: ${error.message || error}`);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

/**
 * Check if Git installation is possible
 */
export function canInstallGitAutomatically(): boolean {
  return process.platform === 'linux';
}

/**
 * Get Git installation documentation URL
 */
export function getGitDocumentationUrl(): string {
  return '/docs/git-requirements';
}
