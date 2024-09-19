Return-Path: <kasan-dev+bncBCSPV64IYUKBB3URWK3QMGQEEY36X2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f59.google.com (mail-wm1-f59.google.com [209.85.128.59])
	by mail.lfdr.de (Postfix) with ESMTPS id D97B297CE71
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 22:26:24 +0200 (CEST)
Received: by mail-wm1-f59.google.com with SMTP id 5b1f17b1804b1-42cb830ea86sf8174775e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 13:26:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726777583; cv=pass;
        d=google.com; s=arc-20240605;
        b=KE1QsmWthxYuyNTCFVAEOUG09VIYYtGP3R2aQAirZ6QpJ8EeHkldaeG7burzTvlkxW
         2bEsbfDBdfXDhnVmQ/1Q53fNpicaiv1ssnbeNynMw/CmXVM9lkKHHtKmRnObPK1dDdQ+
         7VkAJWatERvdwiOPZHIdX/HyUVrT2vKA7HYjIl1RkatJOTEAhyF9FLSYCGjSebXrEBQm
         FGgrXLtlPGzXrK/Q/NR0fTbemdjlnhe56Mpzki+7g/mYMKu2wXaLatV9phBTz021NQTG
         swbtfqxygQCblJPRmhwNF3OrCOgsE8EdagGbIxsB6HNvSxS8KcJIU+W4bfceJKJdLX97
         xjlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date;
        bh=ianzmNWJgysmpq6uTkHA7wchtSWw8Wq4+ITZqmx12zg=;
        fh=X30SKLn96MjDLKZEjsk/NnO+V/OWCChpgGecTOIfIn4=;
        b=P+P8k/HmhjX0t4kljIArK+9qH5CJFlgvX92SPdAy1bj4xFspppHv81MdY+N2JdOPM9
         pqUE+Y0jYPI4pi8cJ3tSLxTOYN5RVaaVFrqNAXt7IZAcK9v401OJKb1HUDL5p9/U1Yb7
         uo6WCCronVd/JzHzgHuH4VB2h8MVVzBBZNK1u5iw/bD6z+MkxvaG/KUB+z5/T3WJlj+j
         qsPOQNyexFmXZu3rmIdDmk9VYz0EyCLW8v8W71JVuAkMpYVyz7RVKgsb+w0xIYEaRUKn
         GD5i4mZiRfEFt8ycXTP8JYHhebIAOCFt9O52yomNE8AqUwD09By3jSAtFscMCS04kQIH
         rklQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=R6D72gmQ;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726777583; x=1727382383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ianzmNWJgysmpq6uTkHA7wchtSWw8Wq4+ITZqmx12zg=;
        b=pLv/akwFke2Zq+wxpipzaXXuoJnD9qkImGY8Mg/Ks4JlpIlWKxByT1x2EBB7Skz+Wd
         oSLk4ZmKUqP3RNGd0N+E0ououQH+WjLSTGB2uxOCjYJHo5itKH/2f3Trq4rTJEWcG7k1
         WNwOIUIZhgE67NTZhEeC+dfkZCZL904eiHeQ/llUlGVySC7s6eK6Q+SFIrSrwxSUOnH9
         28YXWq2xsQzeUw0yNq7wR1LGhul8j1y3urvcPX+JjWMOqZoFftbfjg4VOXzCq6E+f4uN
         h1sANjatxduQe7a/jU3OY4NF2XhzZhOdYPe3pLwjMfbN0qZHiJg65KDk2iLhCtqjTmwg
         jhyg==
X-Forwarded-Encrypted: i=2; AJvYcCX3LYMHzCoV/MQKYweq1CMCfD8d3QznC+arle96PmS8xkyc7yAgq0N9gO9d9Fb0x8Xl6AmZyQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHKaFVq2+m0LDA5YmynBBXMxFDA75V++16XWHix1mtoymqbQR9
	BnT6ZNPL89ZwCybBBtCvjr4YFDhUAjlSAhAafxI1g3ggbTQT2agD
X-Google-Smtp-Source: AGHT+IGht6D2JyIFc+Yt4BvrYjPfRdaTgUiYOmDnaAhdSkj8KrO/j6PUp/qE01sSwC8TrixZrz+VcQ==
X-Received: by 2002:a05:600c:4e43:b0:42c:bd27:4c12 with SMTP id 5b1f17b1804b1-42e7abe7e0dmr4020055e9.10.1726777582244;
        Thu, 19 Sep 2024 13:26:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c95:b0:42c:bb08:9fa6 with SMTP id
 5b1f17b1804b1-42e74554fe8ls9285e9.0.-pod-prod-03-eu; Thu, 19 Sep 2024
 13:26:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWr7Boii9Joa/24ava4xH7j9Jxf7KXbh/+janUzoRpP5u4dqIEdblJ/pDgg0oM7C+un6FLok1Ho9q4=@googlegroups.com
X-Received: by 2002:a05:600c:154d:b0:42c:acfa:9cae with SMTP id 5b1f17b1804b1-42e7adc0d9dmr3216335e9.35.1726777580214;
        Thu, 19 Sep 2024 13:26:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726777580; cv=none;
        d=google.com; s=arc-20240605;
        b=eojZSgXuiJ1Rtn3vLiyH6zqLiyZEN4wXiRYu+L3KdehFzDi1ihIYEnMe5kQo7mDAke
         l5UWlOSVd40f4cqi4VxJN8+ATyQg5MG1TSl8tqh2VoBCNDOTT/+EW/tjEAszVQ9x5u3b
         zpURuhSqiX+fj1IaH0KOKOO11JC0zrilsud6Oy9hoZCJnkRy2MEh80SJ7y6TxBq3uqA7
         ipFw4GvhaVLWeWwrgFUL7/2k8Kw6XSBaJ0B2SIBhWiDrdnHDMT4P4rEI5CyUu3JHBIhD
         pK4Nt+yyABR5wfAwRNNySPnfTIuu6GrCKkc9c74M/Uu2r3U1oJ9ILM1pB0Je5TPDTye4
         YIWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=sender:in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=oxlkKm87pGccXcq11SeNqGT8EGbtG4XA+NGpIJIuUMs=;
        fh=vvFsAELp3/ijmy+VyjXHqEgJwr2AV/p0Vw32McP4bZ8=;
        b=JSKDR9PkPHHwnUF7x0IwEZEjoBFeYUGG4Cwsqd+sJh6Jn9Hy5c0DMPIHtPgZLCf897
         ghQE3BHMwtX5jmnexqmTusTL6juW7BC4KQxD38q1TxKl2vacXoRKK8+I6PFj3Qeo57bH
         zGTwEI6E0OnsmnKldKMJqoZNzadDe+36V6h/A8UpUoMTlgICNLkg2KeKX9Bv2ejfOj66
         GlLwG2UnqLhdLQ3XfjUwwb7z5URyEewwnWzNWTNf1UHe1A7LGcO66KmaucwH7tr3kduX
         sP2GfpqGk089PZ2f4aVQlqoEIh2NC/IPu0WWLZd6yfp7KpE2cew0oRCOGSW2TzWU+rRO
         E0jQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=R6D72gmQ;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6bc41624si5510675e9.0.2024.09.19.13.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Sep 2024 13:26:20 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:50526)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1srNik-0000p3-0O;
	Thu, 19 Sep 2024 21:25:45 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.96)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1srNib-0001pq-1j;
	Thu, 19 Sep 2024 21:25:37 +0100
Date: Thu, 19 Sep 2024 21:25:37 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Ryan Roberts <ryan.roberts@arm.com>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	kernel test robot <lkp@intel.com>, linux-mm@kvack.org,
	llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
	linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Dimitri Sivanich <dimitri.sivanich@hpe.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Miaohe Lin <linmiaohe@huawei.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Message-ID: <ZuyIwdnbYcm3ZkkB@shell.armlinux.org.uk>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
 <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
 <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
 <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
 <5bd51798-cb47-4a7b-be40-554b5a821fe7@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <5bd51798-cb47-4a7b-be40-554b5a821fe7@arm.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=R6D72gmQ;
       spf=none (google.com: armlinux.org.uk does not designate permitted
 sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Thu, Sep 19, 2024 at 07:49:09PM +0200, Ryan Roberts wrote:
> On 19/09/2024 18:06, Russell King (Oracle) wrote:
> > On Thu, Sep 19, 2024 at 05:48:58PM +0200, Ryan Roberts wrote:
> >>> 32-bit arm uses, in some circumstances, an array because each level 1
> >>> page table entry is actually two descriptors. It needs to be this way
> >>> because each level 2 table pointed to by each level 1 entry has 256
> >>> entries, meaning it only occupies 1024 bytes in a 4096 byte page.
> >>>
> >>> In order to cut down on the wastage, treat the level 1 page table as
> >>> groups of two entries, which point to two consecutive 1024 byte table=
s
> >>> in the level 2 page.
> >>>
> >>> The level 2 entry isn't suitable for the kernel's use cases (there ar=
e
> >>> no bits to represent accessed/dirty and other important stuff that th=
e
> >>> Linux MM wants) so we maintain the hardware page tables and a separat=
e
> >>> set that Linux uses in the same page. Again, the software tables are
> >>> consecutive, so from Linux's perspective, the level 2 page tables
> >>> have 512 entries in them and occupy one full page.
> >>>
> >>> This is documented in arch/arm/include/asm/pgtable-2level.h
> >>>
> >>> However, what this means is that from the software perspective, the
> >>> level 1 page table descriptors are an array of two entries, both of
> >>> which need to be setup when creating a level 2 page table, but only
> >>> the first one should ever be dereferenced when walking the tables,
> >>> otherwise the code that walks the second level of page table entries
> >>> will walk off the end of the software table into the actual hardware
> >>> descriptors.
> >>>
> >>> I've no idea what the idea is behind introducing pgd_get() and what
> >>> it's semantics are, so I can't comment further.
> >>
> >> The helper is intended to read the value of the entry pointed to by th=
e passed
> >> in pointer. And it shoiuld be read in a "single copy atomic" manner, m=
eaning no
> >> tearing. Further, the PTL is expected to be held when calling the gett=
er. If the
> >> HW can write to the entry such that its racing with the lock holder (i=
.e. HW
> >> update of access/dirty) then READ_ONCE() should be suitable for most
> >> architectures. If there is no possibility of racing (because HW doesn'=
t write to
> >> the entry), then a simple dereference would be sufficient, I think (wh=
ich is
> >> what the core code was already doing in most cases).
> >=20
> > The core code should be making no access to the PGD entries on 32-bit
> > ARM since the PGD level does not exist. Writes are done at PMD level
> > in arch code. Reads are done by core code at PMD level.
> >=20
> > It feels to me like pgd_get() just doesn't fit the model to which 32-bi=
t
> > ARM was designed to use decades ago, so I want full details about what
> > pgd_get() is going to be used for and how it is going to be used,
> > because I feel completely in the dark over this new development. I fear
> > that someone hasn't understood the Linux page table model if they're
> > wanting to access stuff at levels that effectively "aren't implemented"
> > in the architecture specific kernel model of the page tables.
>=20
> This change isn't as big and scary as I think you fear.

The situation is as I state above. Core code must _not_ dereference pgd
pointers on 32-bit ARM.

> The core-mm today
> dereferences pgd pointers (and p4d, pud, pmd pointers) directly in its co=
de. See
> follow_pfnmap_start(),

Doesn't seem to exist at least not in 6.11.

> gup_fast_pgd_leaf(), and many other sites.

Only built when CONFIG_HAVE_GUP_FAST is set, which 32-bit ARM doesn't
set because its meaningless there, except when LPAE is in use (which is
basically the situation I'm discussing.)

> These changes
> aim to abstract those dereferences into an inline function that the archi=
tecture
> can override and implement if it so wishes.
>=20
> The core-mm implements default versions of these helper functions which d=
o
> READ_ONCE(), but does not currently use them consistently.
>=20
> From Anshuman's comments earlier in this thread, it looked to me like the=
 arm
> pgd_t type is too big to read with READ_ONCE() - it can't be atomically r=
ead on
> that arch. So my proposal was to implement the override for arm to do exa=
ctly
> what the core-mm used to do, which is a pointer dereference. So that woul=
d
> result in exact same behaviour for the arm arch.

Let me say this again: core code must NOT dereference pgds on 32-bit
non-LPAE ARM. They are meaningless to core code. A pgd_t does not
reference a single entry in hardware. It references two entries.

> > Essentially, on 32-bit 2-level ARM, the PGD is merely indexed by the
> > virtual address. As far as the kernel is concerned, each entry is
> > 64-bit, and the generic kernel code has no business accessing that
> > through the pgd pointer.
> >=20
> > The pgd pointer is passed through the PUD and PMD levels, where it is
> > typecast down through the kernel layers to a pmd_t pointer, where it
> > becomes a 32-bit quantity. This results in only the _first_ level 1
> > pointer being dereferenced by kernel code to a 32-bit pmd_t quantity.
> > pmd_page_vaddr() converts this pmd_t quantity to a pte pointer (which
> > points at the software level 2 page tables, not the hardware page
> > tables.)
>=20
> As an aside, my understanding of Linux's pgtable model differs from what =
you
> describe. As I understand it, Linux's logical page table model has 5 leve=
ls
> (pgd, p4d, pud, pmd, pte). If an arch doesn't support all 5 levels, then =
the
> middle levels can be folded away (p4d first, then pud, then pmd). But the
> core-mm still logically walks all 5 levels. So if the HW supports 2 level=
s,
> those levels are (pgd, pte). But you are suggesting that arm exposes pmd =
and
> pte, which is not what Linux expects? (Perhaps you call it the pmd in the=
 arch,
> but that is being folded and accessed through the pgd helpers in core cod=
e, I
> believe?

What ARM does dates from before the Linux MM invented the current
"folding" method when we had three page table levels - pgd, pmd
and pte. The current folding techniques were invented well after
32-bit ARM was implemented, which was using the original idea of
how to fold the page tables.

The new folding came up with a totally different way of doing it,
and I looked into converting 32-bit ARM over to it, but it wasn't
possible to do so with the need for two level-1 entries to be
managed for each level-2 page table.

> > So, as I'm now being told that the kernel wants to dereference the
> > pgd level despite the model I describe above, alarm bells are ringing.
> > I want full information please.
> >=20
>=20
> This is not new; the kernel already dereferences the pgd pointers.

Consider that 32-bit ARM has been this way for decades (Linux was ported
to 32-bit ARM by me back in the 1990s - so it's about 30 years old.)
Compare that to what you're stating is "not new"... I beg to differ with
your opinion on what is new and what isn't. It's all about the relative
time.

This is how the page tables are walked:

static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
{
        return (pgd + pgd_index(address));
}

#define pgd_offset(mm, address)         pgd_offset_pgd((mm)->pgd, (address)=
)

This returns a pointer to the pgd. This is then used with p4d_offset()
when walking the next level, and this is defined on 32-bit ARM from
include/asm-generic/pgtable-nop4d.h:

static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
{
        return (p4d_t *)pgd;
}

Then from include/asm-generic/pgtable-nopud.h:

static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
{
        return (pud_t *)p4d;
}

Then from arch/arm/include/asm/pgtable-2level.h:

static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
{
        return (pmd_t *)pud;
}

All of the above casts result in the pgd_t pointer being cast down
to a pmd_t pointer.

Now, looking at stuff in mm/memory.c such as unmap_page_range().

        pgd =3D pgd_offset(vma->vm_mm, addr);

This gets the pgd pointer into the level 1 page tables associated
with addr, and passes it down to zap_p4d_range().

That passes it to p4d_offset() without dereferencing it, which on
32-bit ARM, merely casts the pgd_t pointer to a p4d_t pointer. Since
a p4d_t is defined to be a struct of a pgd_t, this also points at an
array of two 32-bit quantities. This pointer is passed down to
zap_pud_range().

zap_pud_range() passes this pointer to pud_offset(), again without
dereferencing it, and we end up with a pud_t pointer. Since pud_t is
defined to be a struct of p4d_t, this also points to an array of two
32-bit quantities.

We then have:

                if (pud_trans_huge(*pud) || pud_devmap(*pud)) {

These is an implicit memory copy/access between the memory pointed to
by pud, and their destination (which might be a register). However,
these are optimised away because 32-bit ARM doesn't set
HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD nor ARCH_HAS_PTE_DEVMAP (as
neither inline function make use of their argument.)

NOTE: If making these use READ_ONCE results in an access that can not
be optimised away, that is a bug that needs to be addressed.

zap_pud_range() then passes the pud pointer to zap_pmd_range().

zap_pmd_range() passes this pointer to pud_offset() with no further
dereferences, and this gets cast to a pmd_t pointer, which is a
pointer to the first 32-bit quantity pointed to by the pgd_t pointer.

All the dereferences from this point on are 32-bit which can be done
as single-copy atomic accesses. This will be the first real access
to the level-1 page tables in this code path as the code stands today,
and from this point on, accesses to the page tables are as the
architecture intends them to be.


Now, realise that for all of the accesses above that have all been
optimised away, none of that code even existed when 32-bit ARM was
using this method. The addition of these features not intefering
with the way 32-bit non-LPAE ARM works relies on all of those
accesses being optimised away, and they need to continue to be so
going forward.


Maybe that means that this new (and I mean new in relative terms
compared to the age of the 32-bit ARM code) pgdp_get() accessor
needs to be a non-dereferencing operation, so something like:

#define pgdp_get(pgdp)		((pgd_t){ })

in arch/arm/include/asm/pgtable-2level.h (note the corrected
spelling of pgdp), and the existing pgdp_get() moved to
arch/arm/include/asm/pgtable-3level.h. This isn't tested.

However, let me say this again... without knowing exactly how
and where pgdp_get() is intended to be used, I'm clutching at
straws here. Even looking at Linus' tree, there's very little in
evidence there to suggest how pgdp_get() is intended to be used.
For example, there's no references to it in mm/.


Please realise that I have _no_ _clue_ what "[PATCH V2 7/7] mm: Use
pgdp_get() for accessing PGD entries" is proposing. I wasn't on its
Cc list. I haven't seen the patch. The first I knew anything about
this was with the email that Anshuman Khandual sent in response to
the kernel build bot's build error.

I'm afraid that the kernel build bot's build error means that this
patch:

commit eba2591d99d1f14a04c8a8a845ab0795b93f5646
Author: Alexandre Ghiti <alexghiti@rivosinc.com>
Date:   Wed Dec 13 21:29:59 2023 +0100

    mm: Introduce pudp/p4dp/pgdp_get() functions

is actually broken. I'm sorry that I didn't review that, but how the
series looked when it landed in my mailbox, it looked like it was
specific to RISC-V and of no interest to me, so I didn't bother
reading it (I get _lots_ of email, I can't read everything.) This
is how it looks like in my mailbox (and note that they're marked
as new to this day):

3218 N T Dec 13 Alexandre Ghiti (   0) [PATCH v2 0/4] riscv: Use READ_ONCE(=
)/WRI
3219 N T Dec 13 Alexandre Ghiti (   0) =E2=94=9C=E2=94=80>[PATCH v2 1/4] ri=
scv: Use WRITE_ONCE()
3220 N T Dec 13 Alexandre Ghiti (   0) =E2=94=9C=E2=94=80>[PATCH v2 2/4] mm=
: Introduce pudp/p4dp
3221 N T Dec 13 Alexandre Ghiti (   0) =E2=94=9C=E2=94=80>[PATCH v2 3/4] ri=
scv: mm: Only compile
3222 N T Dec 13 Alexandre Ghiti (   0) =E2=94=94=E2=94=80>[PATCH v2 4/4] ri=
scv: Use accessors to
3223 N C Dec 14 Anup Patel      (   0)   =E2=94=94=E2=94=80>

Sorry, but I'm not even going to look at something like that when it
looks like it's for RISC-V and nothing else.

One final point... because I'm sure someone's going to say "but you
were in the To: header". I've long since given up using "am I in the
Cc/To header" to carry any useful or meaningful information to
indicate whether it's something I should read. I'm afraid that the
kernel community has long since taught me that is of no value what
so ever, so I merely go by "does this look of any interest". If not,
I don't bother even _opening_ the email.

--=20
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZuyIwdnbYcm3ZkkB%40shell.armlinux.org.uk.
