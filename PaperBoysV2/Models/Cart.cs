using System;
using System.Collections.Generic;

namespace PaperBoysV2.Models;

public partial class Cart
{
    public int CartId { get; set; }

    public int UserId { get; set; }

    public int BookId { get; set; }

    public int Quantity { get; set; }

    public decimal TotalPrice { get; set; }

    public virtual Book Book { get; set; } = null!;

    public virtual User User { get; set; } = null!;
}
