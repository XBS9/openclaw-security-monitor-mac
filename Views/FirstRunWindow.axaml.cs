using Avalonia.Controls;
using Avalonia.Interactivity;

namespace OpenClawSecurityMonitorMac.Views;

public partial class FirstRunWindow : Window
{
    public FirstRunWindow()
    {
        InitializeComponent();
        this.FindControl<Button>("DismissButton")!.Click += (_, _) => Close();
    }
}
