Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBRP65X6AKGQERQ55WIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1979429FBA2
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:49:42 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id n14sf2081877wrp.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:49:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026181; cv=pass;
        d=google.com; s=arc-20160816;
        b=hiBZjQMKEtnVHDd7VfQeAkmoUlxt0qNF+OGXrJnKRWBFEMQXtzAG4ZKQ16TKrmlp5E
         I6xk11+gpFWKyuJ+AXZMwVfDT4EGFYqGyDHrCOcDkZm4y8KQ63DI3apRDwHf8CfVsVJV
         OcBvEcDRCCSYR2dQjCDGuBxJConVbSsBnh2/gbV4NKrz7gPOdUzWbpycIcWGsz5MVqoo
         VpBitv8lGfvsrn/ywczWePsCx3l63juHjsNFZzNyIEBIvAdZZa6DYCzBW65284QjGeMg
         1qv2A31jh1EKBbVwDQOQ261ZlAJfziCCMXALOEgTawnQuNf2W+GZn24nnhfFRkJXvAET
         jMNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9cvuGvFr4bVwrFj3VEGcrTobwLzhHb32hneB2QeJOg4=;
        b=lAifeZtR5b55NjcSoy0K5iG9hdUlEXc+npkWdCKiBcRqP6Yg5pn3pQ81lUcnxT3pEg
         lxDYjUTVCKnH74GSHJBQ3Mrl4AYnkFh9YXOGnYmyVAkIPyGxHqEpXlmOGbKQa4pQPIOm
         ztwfthz5hcil0bvMKBgD1J5EMFqONM3EoA+KV5KplytLLY/Yi8IIcP4mt7q8kTg5O+pR
         sbJO8103VZGQhD9VgzClEb3VlpwIGeB91l9o6CxOP0DG4koxEw+m6PcBfVKlUza9SLol
         NzTwyZk8v+Zo/KWGM+e6TaNBIKTG/O2ZakaPKIZfIgfO1/b0K7YxuQRp1v8X1XgdrCzB
         3tXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iaLTL98N;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9cvuGvFr4bVwrFj3VEGcrTobwLzhHb32hneB2QeJOg4=;
        b=GdE4Qnjh5ENVwbTf8E19kJwE7J4Lkenhgvyx2nfLvNgwDcyptWIaZatX9x7sxqukLX
         0p3fjLXEKYU9BRUBcPc1cuvPaMZQjzhLYvAbzxZuiBDy8YX/RAXXLkRHCyvOqlaHOHW1
         32qpgaqF0ORbYHI40kff/0ga7RIr5o+3n8VlGc9CefLeaEC4T8o9ddILY58mkUMWUwS4
         lyrCRMSYzpOp0yzCg6br0lg219ZLEa4usyjJHNPTs3T4x0yJCn0NfuvvEozVh/eDSZvP
         52snOuYNAMfEPf0Oo6TlxYr+oVnLszw0JKVXUEnUQ8w4vtqwaq1+MNc6Lf8tnM1WqRNn
         0D3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9cvuGvFr4bVwrFj3VEGcrTobwLzhHb32hneB2QeJOg4=;
        b=eo7BsW/JK+qmH/5fjcadZ4YyWVxayl6aX2828ZAcInJZCg+wdxSMtHo+k5hvUwTVg8
         P9RG7CgVYmeTagz3v+4QhwytrdRKMVtyk6hPTh56lwbYLyM2dPQ73xW3v0WHts07rDbA
         HSt6nObOjr2CzM2X479wwxkc2qa39PISZv2rJ39gqGxCuU+zWwBLv0P3KkR/CmA9tJg2
         D2iVhF+sDBooKWqH262XirMOnC4sfCE0uY+LD70UJruYfThcnzBOjAPOI6aKidV02sTp
         89Z2wLVPkJFzIpq0ugHF3+arSV66I0O6uy3x1+vAURsj3IPmJYDbMgVt+cviUP5wrV91
         0hYQ==
X-Gm-Message-State: AOAM530qRexrkJKbNlfSU4Ks5pIo1/HZXyZjxNPHY+vRVmrAVfAijv0g
	NBmcDUMWu/1iMtsR9hL7d1M=
X-Google-Smtp-Source: ABdhPJzKBINEVJyhLzLlc9y/wdgzRG0xMdfb60NNniUPC0X221TlAVx2XvaRUxCpdpLIbNK2tjjpKA==
X-Received: by 2002:a1c:7e0f:: with SMTP id z15mr77092wmc.118.1604026181841;
        Thu, 29 Oct 2020 19:49:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f7c4:: with SMTP id a4ls3600176wrq.1.gmail; Thu, 29 Oct
 2020 19:49:41 -0700 (PDT)
X-Received: by 2002:adf:f3cb:: with SMTP id g11mr194452wrp.210.1604026181005;
        Thu, 29 Oct 2020 19:49:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026181; cv=none;
        d=google.com; s=arc-20160816;
        b=xizYWPrAr0MgBZGkIYC6oH9VpFCLmdacFtqW8J5Fq/McP0G2NW673Jtxb0AWAdIsXW
         92OMfbOsRdrnbssZEDmpLsHmQPxqO4388J0pu3/ve+0GAOGnItt7QmxBV2n4b0bESCjd
         v0bSbOx9kQqLDYQT61z38g5X0kOP7+9vo14a4r4iKQyUY+9Vkdx8JWpDHH3F9hOANLTk
         eayXgLEng4hMCRkoGrVvwAw2SIQxIqnqEHJ89brKUzsfUY6focqpS09TiSdLcYfL5nEG
         aQm4ZyLrMr27FPDqoPqjVl21Q/MfIdhLvKZLKKttEyLNuQhKmX2U4dvqgBm0CHooCoQM
         cJDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bxX9Me9cwsFEBumfTFk5EKdPQHJ86xf2rO/msdc2EqI=;
        b=04YX9E+KV6EIgBcpOZtMC16UwCmsWhgyEfrQNUoTjs5xpPKeKzRW5juPMF3ifD/CMB
         7KuHCTceDYqvpo0AgRoDLTdMiAx3nR3kiM3k4t8uk1bfRIe8UuDjtSF7i3x5811NnR3a
         +gMPos1fKfgkxV/35Z2zxp6H2ukSRI1WEqlmfNsEvGpq8HGlY4Gb7Aj+4hF6kbq9627B
         3begAlFH/hIGwwtdqrIBxVqzDzRSepgV2nnsey4KS/Qk0HFjOFWRtnBKA4lhmdDNzxzj
         lMnaxiX0kxf0OQmjP0eEB1f5qZLIbo5QcVKtDgEzZ6qKxr0uJjbieHvPVevUQzklF+la
         3vjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iaLTL98N;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id w6si68565wmk.2.2020.10.29.19.49.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:49:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id 184so5970927lfd.6
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:49:40 -0700 (PDT)
X-Received: by 2002:a05:6512:1054:: with SMTP id c20mr23811lfb.576.1604026180208;
 Thu, 29 Oct 2020 19:49:40 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-2-elver@google.com>
In-Reply-To: <20201029131649.182037-2-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:12 +0100
Message-ID: <CAG48ez0TgomTec+r188t0ddYVZtivOkL1DvR3owiuDTBtgPNzA@mail.gmail.com>
Subject: Re: [PATCH v6 1/9] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iaLTL98N;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::144 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.
[...]
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
[...]
> +/**
> + * is_kfence_address() - check if an address belongs to KFENCE pool
> + * @addr: address to check
> + *
> + * Return: true or false depending on whether the address is within the KFENCE
> + * object range.
> + *
> + * KFENCE objects live in a separate page range and are not to be intermixed
> + * with regular heap objects (e.g. KFENCE objects must never be added to the
> + * allocator freelists). Failing to do so may and will result in heap
> + * corruptions, therefore is_kfence_address() must be used to check whether
> + * an object requires specific handling.
> + */

It might be worth noting in the comment that this is one of the few
parts of KFENCE that are highly performance-sensitive, since that was
an important point during the review.

> +static __always_inline bool is_kfence_address(const void *addr)
> +{
> +       /*
> +        * The non-NULL check is required in case the __kfence_pool pointer was
> +        * never initialized; keep it in the slow-path after the range-check.
> +        */
> +       return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && addr);
> +}
[...]
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
[...]
> +config KFENCE_STRESS_TEST_FAULTS
> +       int "Stress testing of fault handling and error reporting"
> +       default 0
> +       depends on EXPERT
> +       help
> +         The inverse probability with which to randomly protect KFENCE object
> +         pages, resulting in spurious use-after-frees. The main purpose of
> +         this option is to stress test KFENCE with concurrent error reports
> +         and allocations/frees. A value of 0 disables stress testing logic.
> +
> +         The option is only to test KFENCE; set to 0 if you are unsure.
[...]
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
[...]
> +#ifndef CONFIG_KFENCE_STRESS_TEST_FAULTS /* Only defined with CONFIG_EXPERT. */
> +#define CONFIG_KFENCE_STRESS_TEST_FAULTS 0
> +#endif

I think you can make this prettier by writing the Kconfig
appropriately. See e.g. ARCH_MMAP_RND_BITS:

config ARCH_MMAP_RND_BITS
  int "Number of bits to use for ASLR of mmap base address" if EXPERT
  range ARCH_MMAP_RND_BITS_MIN ARCH_MMAP_RND_BITS_MAX
  default ARCH_MMAP_RND_BITS_DEFAULT if ARCH_MMAP_RND_BITS_DEFAULT
  default ARCH_MMAP_RND_BITS_MIN
  depends on HAVE_ARCH_MMAP_RND_BITS

So instead of 'depends on EXPERT', I think the proper way would be to
append ' if EXPERT' to the line
'int "Stress testing of fault handling and error reporting"', so that
only whether the option is user-visible depends on EXPERT, and
non-EXPERT configs automatically use the default value.

[...]
> +static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
> +{
> +       unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
> +       unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
> +
> +       /* The checks do not affect performance; only called from slow-paths. */
> +
> +       /* Only call with a pointer into kfence_metadata. */
> +       if (KFENCE_WARN_ON(meta < kfence_metadata ||
> +                          meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
> +               return 0;
> +
> +       /*
> +        * This metadata object only ever maps to 1 page; verify the calculation
> +        * happens and that the stored address was not corrupted.

nit: This reads a bit weirdly to me. Maybe "; verify that the stored
address is in the expected range"? But feel free to leave it as-is if
you prefer it that way.

> +        */
> +       if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
> +               return 0;
> +
> +       return pageaddr;
> +}
[...]
> +/* __always_inline this to ensure we won't do an indirect call to fn. */
> +static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
> +{
> +       const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
> +       unsigned long addr;
> +
> +       lockdep_assert_held(&meta->lock);
> +
> +       /* Check left of object. */
> +       for (addr = pageaddr; addr < meta->addr; addr++) {
> +               if (!fn((u8 *)addr))
> +                       break;

It could be argued that "return" instead of "break" would be cleaner
here if the API is supposed to be "invoke fn() on each canary byte,
but stop when fn() returns false". But I suppose it doesn't really
matter, so either way is fine.

> +       }
> +
> +       /* Check right of object. */
> +       for (addr = meta->addr + meta->size; addr < pageaddr + PAGE_SIZE; addr++) {
> +               if (!fn((u8 *)addr))
> +                       break;
> +       }
> +}
> +
> +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> +{
[...]
> +       /* Set required struct page fields. */
> +       page = virt_to_page(meta->addr);
> +       page->slab_cache = cache;
> +       if (IS_ENABLED(CONFIG_SLUB))
> +               page->objects = 1;
> +       if (IS_ENABLED(CONFIG_SLAB))
> +               page->s_mem = addr;

Maybe move the last 4 lines over into the "hooks for SLAB" and "hooks
for SLUB" patches?

[...]
> +}
[...]
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
[...]
> +/*
> + * Get the number of stack entries to skip get out of MM internals. @type is

s/to skip get out/to skip to get out/ ?

> + * optional, and if set to NULL, assumes an allocation or free stack.
> + */
> +static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries,
> +                           const enum kfence_error_type *type)
[...]
> +void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
> +                        enum kfence_error_type type)
> +{
[...]
> +       case KFENCE_ERROR_CORRUPTION: {
> +               size_t bytes_to_show = 16;
> +
> +               pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
> +               pr_err("Corrupted memory at 0x" PTR_FMT " ", (void *)address);
> +
> +               if (address < meta->addr)
> +                       bytes_to_show = min(bytes_to_show, meta->addr - address);
> +               print_diff_canary((u8 *)address, bytes_to_show);

If the object was located on the right side, but with 1 byte padding
to the right due to alignment, and a 1-byte OOB write had clobbered
the canary byte on the right side, we would later detect a
KFENCE_ERROR_CORRUPTION at offset 0xfff inside the page, right? In
that case, I think we'd end up trying to read 15 canary bytes from the
following guard page and take a page fault?

You may want to do something like:

unsigned long canary_end = (address < meta->addr) ? meta->addr :
address | (PAGE_SIZE-1);
bytes_to_show = min(bytes_to_show, canary_end);



> +               pr_cont(" (in kfence-#%zd):\n", object_index);
> +               break;
> +       }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0TgomTec%2Br188t0ddYVZtivOkL1DvR3owiuDTBtgPNzA%40mail.gmail.com.
