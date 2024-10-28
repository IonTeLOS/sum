<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SUM - Simple Update Manager</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: auto;
            line-height: 1.6;
        }
        h1, h2, h3 {
            color: #003399;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 4px;
            border-radius: 3px;
        }
        a {
            color: #0066cc;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        ul {
            padding-left: 20px;
        }
    </style>
</head>
<body>
    <h1>SUM - Simple Update Manager</h1>

    <p><strong>SUM</strong> is a lightweight, intuitive, and powerful update manager designed to handle seamless updates for your standalone applications, particularly those developed with <code>PySide6</code>. SUM helps you maintain version control by automatically downloading, installing, and verifying updates without disrupting user experience.</p>

    <h2>🎯 Key Features</h2>
    <ul>
        <li><strong>Automatic Update Checks:</strong> Connect to your designated update server to check for newer versions.</li>
        <li><strong>Interactive GUI Mode:</strong> SUM provides an easy-to-follow interface, offering your users control over update timing.</li>
        <li><strong>Seamless Installation:</strong> Handles download, backup, and replacement of executables safely.</li>
        <li><strong>Rollback Functionality:</strong> If an update fails, SUM automatically restores the previous version, minimizing downtime.</li>
        <li><strong>Flexible Compatibility:</strong> Although optimized for PySide6 apps, SUM can manage updates for other standalone applications that do not require complex packaging systems (e.g., Debian packages).</li>
        <li><strong>Checksum Verification:</strong> Confirms the integrity of each downloaded update by verifying its checksum before installation.</li>
    </ul>

    <h2>💡 Getting Started</h2>

    <h3>Installation and Setup</h3>

<p>SUM is designed to be a standalone updater that any application can call to handle its own updates. To use SUM, simply place the <code>sum.py</code> executable in a known location and call it from within your application. Here's a sample command:</p>

<pre><code>python sum.py -v &lt;current_version&gt; -f &lt;path_to_executable&gt; -u &lt;update_url&gt;</code></pre>

<p>Your application can call SUM like this whenever it wants to check for updates and apply them. SUM will handle everything: downloading, validating, and installing the update, and then restarting your app.</p>


    <pre><code>pyinstaller --onefile --add-data "dep.sh:." --add-data "update_icon.png:." sum.py</code></pre>

    <h3>Using SUM with Arguments</h3>
    <p>SUM accepts command-line arguments to customize the update process. Here’s a breakdown of each argument:</p>
    <ul>
        <li><code>-v / --current_version</code> <em>(required)</em> - The current version of the application, used to compare against the latest version available online.</li>
        <li><code>-f / --current_location</code> <em>(required)</em> - The file path to the current executable, allowing SUM to locate and replace it if an update is available.</li>
        <li><code>-u / --url</code> <em>(required)</em> - URL to check for the latest version and update files.</li>
        <li><code>-n / --app-name</code> - Custom name for the application, which SUM will use in logs and notifications.</li>
        <li><code>-i / --interactive</code> - Enables the interactive GUI mode, making the update process more user-friendly.</li>
        <li><code>-e / --extras</code> - Additional script commands to execute prior to the update process, allowing for pre-installation checks or custom configurations.</li>
    </ul>

    <h2>🚀 How to Use SUM</h2>

    <p>Once SUM is configured and built into your application, it can be executed directly. Here’s an example:</p>

    <pre><code>./sum --current_version "1.0.0" --current_location "/path/to/app" --url "https://example.com/update" --interactive</code></pre>

    <p>In interactive mode, SUM will prompt the user with a graphical dialog, providing the option to proceed with updates or dismiss the notification. If an update is found, SUM downloads and installs it in the background. The app also maintains a backup of the current executable and can automatically restore it if an update fails.</p>

    <h2>⚠️ Compatibility Notes</h2>
    <p>SUM is optimized for PySide6 applications, but it can work with other single-file executables as well. However, it is not compatible with applications that use system package managers, like Debian’s <code>.deb</code> packages. SUM is best suited for independent executables that are not managed by system-level packaging tools.</p>

    <h2>🛠 Additional Dependencies</h2>
    <p>To ensure SUM’s functionality on various Linux distributions, it includes a dependency check script (<code>dep.sh</code>) that automatically installs required packages if missing. This script uses <code>pkexec</code> for privilege escalation if available, otherwise, it attempts to open <code>x-terminal-emulator</code> for password prompts.</p>

    <h2>🌐 Project Links and Documentation</h2>
    <p>For more information, detailed documentation, and code examples, please visit our <a href="https://github.com/IonTeLOS/sum" target="_blank">GitHub repository</a>.</p>

    <p>Thank you for using SUM! We’re excited to help you keep your applications up-to-date with ease and reliability.</p>
</body>
</html>
