using System;
using System.Collections.Generic;

namespace PaperBoysV2.Models;

public partial class Book
{
    public int BookId { get; set; }

    public string? CoverPage { get; set; }

    public string Title { get; set; } = null!;

    public int Year { get; set; }

    public decimal Price { get; set; }

    public int? Copies { get; set; }

    public virtual ICollection<Cart> Carts { get; set; } = new List<Cart>();

    public virtual ICollection<OrderItem> OrderItems { get; set; } = new List<OrderItem>();
}
