Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCGN6H6AKGQECPTGSAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E7E22A0E65
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 20:16:25 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id u13sf6896444ybk.9
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 12:16:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604085384; cv=pass;
        d=google.com; s=arc-20160816;
        b=k018jK6/ZxGyy9kgpQpx3UoakmlM/ZasiyFPyPOyIK5EPAW8VStrdEaYxYHLUxOB0y
         ktPJZHe1u2tNSKJbeAVoFY4ueIm+8aaA8C+Ly8z0zFgqe2xgk0LI7kvgzpYJPy18c1+P
         s6/One+8UJCLzmjCa9azFwLTxUpwD+xcwaShrE6UZHyWnekd+i2EWmfYOEGkSrBAaZlf
         012WVOe7uBsHIitdtlhatXV9It4XFhiEH+Ue7+WH4bIMGi1VUHwR/Std8+qE65xJ95q7
         jHoN8qpTYyYhnPXZLvx3WJZy/jCsgq6BklLJqWCPCVWoZ7YVwssjWgifSWbsK7Uxq7no
         WV+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kfShvoboHnJZbVOlsGyOedeAZhm+8/Y/IWKwAIoR3LA=;
        b=neO9UW4XcZfiI2yrnQ8Gv+A4ViqIbUT1WhTPo5/ErRHqUDGNhaHIFk3wFke2xdY4sR
         zbM7ZRKDbUIwo81/I/yx1ZKZAB4dIZ68SMvI+QWMls01qP5iXCxKtmkIh70B5Ay5Cnhi
         zFrkBZcKj3PmP4sXaUr5QjLSxD+GBoI/UJVjhtL38y2AysCrpLmMIrrHKMRJkFptnbWZ
         MjXzpVyZ6Bya/ezmDLAKpnp7AzfJ9FTauwyk/wG3yapERAfrrSDq56DmNpik/Chy+G+8
         FlstXAE2ABRkiLouR9rFkKPI10eFrlCmyVeMEEGFBeWnc1C29wDHRFpUKVS794ZBhzxg
         fp5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RCDhFlYv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kfShvoboHnJZbVOlsGyOedeAZhm+8/Y/IWKwAIoR3LA=;
        b=UoS/RphottrDkm1PfbnXRyM3UvTiZYiDqcve+aY7lpGjTXLDzPR1YFzqLmskXBSFQB
         mFj00aKH+2Ta1pssemeSvDmgBSeuuLa5u/yGDAXuh4AXG8z5X8O4T60nmbIWCZVw+aSS
         NuRdA1rbMQwPNC2gdbMqiDTtdsFzb2PBJZ8vA7pkgtG2tnYrZjrg3UO0gCzDnkktbTUz
         rbCQxRQwewOBcPgCRaeaOSBu7A4v7KgStKr0TauHLIpWn6vXwBCZbUDqjdipuSEOA1wN
         COGgKkaBBXbte6kPCFBqvSj7FnHWNzJkvZE+HbOxvldQ1HjqnGU8VI9o3Z7jazjWftip
         bM6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kfShvoboHnJZbVOlsGyOedeAZhm+8/Y/IWKwAIoR3LA=;
        b=ruSW43rkp9I2FnDH/F9SRgmIJ3IFHtQtKvRt6ex2U8Kd10fy+U996/lRkecqFS00y6
         woQxOsILsF5LZ+P63m93vTTCkYtnhnr9Q13MNFrjV2VO82U+4Z0Pq10iqt9qzLsDUHno
         5DQdPh91SjSOY2vxoey3jvxprZN96JmYunRVlceWsobE9W0zoFTDci0iNbdfA/oMMagT
         hwRyDZ8FpmmI2FmHXibzmzBJU9A3ofwQLX484Bm61/rOk1Y3p0eKpBXkuA0efOccRFze
         oP3zXKn/eFZhj2yzaLiDNdIyEZeiphHJcsg32OKucXFV+No9nLbwt1MmUfAbqFZuXXqE
         imbQ==
X-Gm-Message-State: AOAM533Wm5NsWsdhPPghZfaY+k1aGHIg/E2g/VL7W+Iga2L8uVfHtF7r
	blOpoedI63ND64RD0FK5iOE=
X-Google-Smtp-Source: ABdhPJxc3hBgM2HMUsziE4G4dxjTX8X6DWr0UF82NsqTmvrqwtEwBbqyrNzNJYkRDSGzgeRCd/sD2g==
X-Received: by 2002:a25:a224:: with SMTP id b33mr6277447ybi.109.1604085384689;
        Fri, 30 Oct 2020 12:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4e08:: with SMTP id c8ls1037314ybb.3.gmail; Fri, 30 Oct
 2020 12:16:24 -0700 (PDT)
X-Received: by 2002:a5b:790:: with SMTP id b16mr5672801ybq.48.1604085384133;
        Fri, 30 Oct 2020 12:16:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604085384; cv=none;
        d=google.com; s=arc-20160816;
        b=VnRfkn8LkVK33OFi7if8shi06QH/FvkEMNlviT8Epr/GQI2fTVuruA8C7l/6w7XDmi
         YQFZGbgJumnFRh4j6HpNWmm29xmCP+rLlBqUn9WkNRcA6R0GnyIFMDsw5sYsBe/9x+4n
         o2hxSj/wpskUA0g2AbsF7Bo7ogOWlmlaxK8RvQ3yqHxDIG9NVUD5WAyCBFRrOJ+g6Es+
         vXAnXqiD8LXbaHuehRF8UGiDcA0T02U4JcW9PbNso4S+g1J6jCpAgY2B75iEGg93EpUq
         PuW4v1O6bJ9rcWIF2Qy2xTZOe0GBid6r2bHPCHwt0JpPvUohzaXspfRj5Y+68DWGKDjL
         yQlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IphFE7ilzXNXur1141KXwIQedEFrpv7O0T6mxNfExvI=;
        b=XhJhHXIJuCSTc5Q5f4EJnvIvdpLGdnm+W0cKfVUtBmgogKS0M0vtuYAewAP3xLTYwH
         0ylhBQLEe6MsbaIDyY0po3AvLa100bJhIpSH+6EDlJmzWJpDmcmOAjnETpiF3uR7KyyR
         ZaDo/2WJgnEnhuuSCpLoIrWjFymWyNlSx30Nl0bBRpF8x2PCHtWGTV3WPHIyH+NKQPA7
         cROl59Tm4MaxRZGogDbj3Xd+V53bKFgj5DtHd3EOcSBDZurIn8feF2w3cpy6ErVzO9RW
         n6yioRUarR/ZcDnuAwwIAi6W94libysUAXZ4Q6bP341HhrkpEE6bgBDiOKDgmKWRBixy
         4TNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RCDhFlYv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc43.google.com (mail-oo1-xc43.google.com. [2607:f8b0:4864:20::c43])
        by gmr-mx.google.com with ESMTPS id e184si334032ybe.0.2020.10.30.12.16.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 12:16:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) client-ip=2607:f8b0:4864:20::c43;
Received: by mail-oo1-xc43.google.com with SMTP id f25so1850907oou.4
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 12:16:24 -0700 (PDT)
X-Received: by 2002:a4a:b28b:: with SMTP id k11mr3076579ooo.54.1604085383351;
 Fri, 30 Oct 2020 12:16:23 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-2-elver@google.com>
 <CAG48ez0TgomTec+r188t0ddYVZtivOkL1DvR3owiuDTBtgPNzA@mail.gmail.com>
In-Reply-To: <CAG48ez0TgomTec+r188t0ddYVZtivOkL1DvR3owiuDTBtgPNzA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 20:16:11 +0100
Message-ID: <CANpmjNPFXutFT6QmTej2bCDGVP+QgBngws1fOEz=s_Q_sAJbOQ@mail.gmail.com>
Subject: Re: [PATCH v6 1/9] mm: add Kernel Electric-Fence infrastructure
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RCDhFlYv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 30 Oct 2020 at 03:49, Jann Horn <jannh@google.com> wrote:
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.
> [...]
> > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> [...]
> > +/**
> > + * is_kfence_address() - check if an address belongs to KFENCE pool
> > + * @addr: address to check
> > + *
> > + * Return: true or false depending on whether the address is within the KFENCE
> > + * object range.
> > + *
> > + * KFENCE objects live in a separate page range and are not to be intermixed
> > + * with regular heap objects (e.g. KFENCE objects must never be added to the
> > + * allocator freelists). Failing to do so may and will result in heap
> > + * corruptions, therefore is_kfence_address() must be used to check whether
> > + * an object requires specific handling.
> > + */
>
> It might be worth noting in the comment that this is one of the few
> parts of KFENCE that are highly performance-sensitive, since that was
> an important point during the review.

Done, thanks.

> > +static __always_inline bool is_kfence_address(const void *addr)
> > +{
> > +       /*
> > +        * The non-NULL check is required in case the __kfence_pool pointer was
> > +        * never initialized; keep it in the slow-path after the range-check.
> > +        */
> > +       return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && addr);
> > +}
> [...]
> > diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> [...]
> > +config KFENCE_STRESS_TEST_FAULTS
> > +       int "Stress testing of fault handling and error reporting"
> > +       default 0
> > +       depends on EXPERT
> > +       help
> > +         The inverse probability with which to randomly protect KFENCE object
> > +         pages, resulting in spurious use-after-frees. The main purpose of
> > +         this option is to stress test KFENCE with concurrent error reports
> > +         and allocations/frees. A value of 0 disables stress testing logic.
> > +
> > +         The option is only to test KFENCE; set to 0 if you are unsure.
> [...]
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> [...]
> > +#ifndef CONFIG_KFENCE_STRESS_TEST_FAULTS /* Only defined with CONFIG_EXPERT. */
> > +#define CONFIG_KFENCE_STRESS_TEST_FAULTS 0
> > +#endif
>
> I think you can make this prettier by writing the Kconfig
> appropriately. See e.g. ARCH_MMAP_RND_BITS:
>
> config ARCH_MMAP_RND_BITS
>   int "Number of bits to use for ASLR of mmap base address" if EXPERT
>   range ARCH_MMAP_RND_BITS_MIN ARCH_MMAP_RND_BITS_MAX
>   default ARCH_MMAP_RND_BITS_DEFAULT if ARCH_MMAP_RND_BITS_DEFAULT
>   default ARCH_MMAP_RND_BITS_MIN
>   depends on HAVE_ARCH_MMAP_RND_BITS
>
> So instead of 'depends on EXPERT', I think the proper way would be to
> append ' if EXPERT' to the line
> 'int "Stress testing of fault handling and error reporting"', so that
> only whether the option is user-visible depends on EXPERT, and
> non-EXPERT configs automatically use the default value.

I guess the idea was to not pollute the config in non-EXPERT configs,
but it probably doesn't matter much. Changed it to the suggested
cleaner approach.

> [...]
> > +static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
> > +{
> > +       unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
> > +       unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
> > +
> > +       /* The checks do not affect performance; only called from slow-paths. */
> > +
> > +       /* Only call with a pointer into kfence_metadata. */
> > +       if (KFENCE_WARN_ON(meta < kfence_metadata ||
> > +                          meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
> > +               return 0;
> > +
> > +       /*
> > +        * This metadata object only ever maps to 1 page; verify the calculation
> > +        * happens and that the stored address was not corrupted.
>
> nit: This reads a bit weirdly to me. Maybe "; verify that the stored
> address is in the expected range"? But feel free to leave it as-is if
> you prefer it that way.

Hmm, that really sounds weird... I've changed it. :-)

> > +        */
> > +       if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
> > +               return 0;
> > +
> > +       return pageaddr;
> > +}
> [...]
> > +/* __always_inline this to ensure we won't do an indirect call to fn. */
> > +static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
> > +{
> > +       const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
> > +       unsigned long addr;
> > +
> > +       lockdep_assert_held(&meta->lock);
> > +
> > +       /* Check left of object. */
> > +       for (addr = pageaddr; addr < meta->addr; addr++) {
> > +               if (!fn((u8 *)addr))
> > +                       break;
>
> It could be argued that "return" instead of "break" would be cleaner
> here if the API is supposed to be "invoke fn() on each canary byte,
> but stop when fn() returns false". But I suppose it doesn't really
> matter, so either way is fine.

Hmm, perhaps if there are corruptions on either side of an object
printing both errors (which includes indications of which bytes were
corrupted) might give more insights into what went wrong. Printing
errors for every canary byte on one side didn't make much sense
though, hence the break.

Until we see this in the wild, let's err on the side of "more
information might be better".

> > +       }
> > +
> > +       /* Check right of object. */
> > +       for (addr = meta->addr + meta->size; addr < pageaddr + PAGE_SIZE; addr++) {
> > +               if (!fn((u8 *)addr))
> > +                       break;
> > +       }
> > +}
> > +
> > +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> > +{
> [...]
> > +       /* Set required struct page fields. */
> > +       page = virt_to_page(meta->addr);
> > +       page->slab_cache = cache;
> > +       if (IS_ENABLED(CONFIG_SLUB))
> > +               page->objects = 1;
> > +       if (IS_ENABLED(CONFIG_SLAB))
> > +               page->s_mem = addr;
>
> Maybe move the last 4 lines over into the "hooks for SLAB" and "hooks
> for SLUB" patches?

Done.

> [...]
> > +}
> [...]
> > diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> [...]
> > +/*
> > + * Get the number of stack entries to skip get out of MM internals. @type is
>
> s/to skip get out/to skip to get out/ ?

Done.

> > + * optional, and if set to NULL, assumes an allocation or free stack.
> > + */
> > +static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries,
> > +                           const enum kfence_error_type *type)
> [...]
> > +void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
> > +                        enum kfence_error_type type)
> > +{
> [...]
> > +       case KFENCE_ERROR_CORRUPTION: {
> > +               size_t bytes_to_show = 16;
> > +
> > +               pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
> > +               pr_err("Corrupted memory at 0x" PTR_FMT " ", (void *)address);
> > +
> > +               if (address < meta->addr)
> > +                       bytes_to_show = min(bytes_to_show, meta->addr - address);
> > +               print_diff_canary((u8 *)address, bytes_to_show);
>
> If the object was located on the right side, but with 1 byte padding
> to the right due to alignment, and a 1-byte OOB write had clobbered
> the canary byte on the right side, we would later detect a
> KFENCE_ERROR_CORRUPTION at offset 0xfff inside the page, right? In
> that case, I think we'd end up trying to read 15 canary bytes from the
> following guard page and take a page fault?
>
> You may want to do something like:
>
> unsigned long canary_end = (address < meta->addr) ? meta->addr :
> address | (PAGE_SIZE-1);
> bytes_to_show = min(bytes_to_show, canary_end);

print_diff_canary() calculates max_addr using PAGE_ALIGN(), and we
won't read from the next page. I think I'll move all this logic into
print_diff_canary() to simplify.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPFXutFT6QmTej2bCDGVP%2BQgBngws1fOEz%3Ds_Q_sAJbOQ%40mail.gmail.com.
