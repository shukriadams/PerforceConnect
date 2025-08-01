# PerforceConnect

Drop-in Perforce library for C# (Dotnet 6.0) There are no dependencies.

## How to get it

Manually download and place PerforceConnect.cs in your project, or fetch it programmatically at a tag with something like

  curl -L https://raw.githubusercontent.com/shukriadams/PerforceConnect/refs/tags/0.0.3/PerforceConnect.cs --output ./path/to/my/solution/PerforceConnect.cs

## How to use it

    # create an instance of connect  
    Madscience.Perforce.PerforceConnect perforceConnect = new Madscience.Perforce.PerforceConnect(
        "myuser", 
        "mypassword", 
        "ssl:p4.example.com:1666", 
        "00:00:00:00:00:00:00:00:00:00:00:00:00:00");

    # get raw shelve data from p4, you can parse this yourself if you want
    IEnumerable<string> rawShelves = perforceConnect.GetRawChanges(true, 100, "//mydepot/...");

    # or, you can use PerforceConnect to parse the raw output into Change objects
    IEnumerable<Madscience.Perforce.Change> shelves = Madscience.Perforce.PerforceConnect.ParseChanges(rawShelves);

