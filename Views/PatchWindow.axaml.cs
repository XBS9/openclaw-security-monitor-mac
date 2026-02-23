using Avalonia.Controls;

namespace OpenClawSecurityMonitorMac.Views;

public partial class PatchWindow : Window
{
    public PatchWindow()
    {
        InitializeComponent();
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        if (DataContext is ViewModels.PatchViewModel vm)
            vm.Cleanup();
    }
}
