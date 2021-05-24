Return-Path: <kasan-dev+bncBCU4TIPXUUFRBU6VV6CQMGQEGMY32SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC64938F2B7
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 20:05:08 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id d22-20020ab031960000b0290223019877e7sf3826228uan.11
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 11:05:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621879508; cv=pass;
        d=google.com; s=arc-20160816;
        b=loZwWFIpsxSgGImhkrWL26owoKY3kEaRaWlPG6CkjP8AqcJ6+CIXbfz8B6qJ3T+7nE
         ugT8qtPlFqSjh+pMDb4H3kE/jWIO6x1B477ddel9URyentHRzHwZs+h1MFCtazkmkrpD
         iU6tOsrB6g9kgD/oePK0x+/Bl7mBsFkp8j1DclspbJ4SIcXoS4MvH7bQi9oj0/z7WCAQ
         gK9PD7B1deSrOdinHwxIKIkLYgzmjxtSR+UXaxeYP0HOVLXA3KPkSQSZFHDhqzdVKB2R
         9aPvBKt72QlSRDxReMjtSn1m2eU7coEBznaQGLnOsb3VFnEn2XJfFbc4K9YYu4XlpU2d
         TkKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=qKXS+7rS6vAnYHDDVxj43IRZz6rJPmg6Eq7KZqTIALM=;
        b=Z0WNV+81Z3KriH8BvJA4pDv/FjlKP5FZTqgzPFqTU9juu707vWQI632L4xpOAeAUuB
         I5+sjfYFJJdFMy0LH7sG84ewDXVCjskEmOuwmkQfZbxF/0tOadNB7rXQmdf80k9nINeu
         oUEet46MYbp1i7TwVfHlNup6SWzzcg9c0P6dv/MhA7AKNYoTqy5spdpheVJUdVlSPhs1
         7BuFui7WRHbZzsmSeLivKNJ9wVOqs31rHxpNQHVQMzWO8ARto0HBaxV9RgW56MzL0yKt
         IY/eAGdG1+Dczk0nyizvHb9l1RHF7YtHcEPNEhFsS+618r84gU/L6Dx9eY5nd3lXBEVS
         F6rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BcdB6cNQ;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qKXS+7rS6vAnYHDDVxj43IRZz6rJPmg6Eq7KZqTIALM=;
        b=Ds0RzZiiEEWrsnqdx9Mt/iKn7kfctq7FhZx/xQHwnH6Bn52KagB0fbc/8gm0frs7kj
         5l2PXxMZbHyhC+4tJKL/TUWZMXpox9w1biiLOFyWcrk/cSTT5s8apHHJdJI/zLtM1Y72
         CBRx80S2eWgL68DZDX4uv26YPpAiS+WKxW+Mah8Qf5IzJaGF0cz2hyR0cgxcrpWKy2Hf
         u/f7ZrH9oGszEIng0ISyQ7oqGjB8oA9a9oW7QmzHInHT/bPWpE5a1dyhVjO4k009Oik9
         PAWfywgy6IJOE5yCx5/PlbZXaztl28ks2s5TEnEqqjmqBknWq5Mr19ZN9w3O8dtbznQ3
         L/ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qKXS+7rS6vAnYHDDVxj43IRZz6rJPmg6Eq7KZqTIALM=;
        b=KRwrMz/yHKP1WtiBOHFpxkMru7qa60aqJxUt2nnm/frrSgutBM7LLh/lgsHpCYQX8a
         DDatin2VECU8r5c1g6E8PK4eRbNORZF+q7f7eZSmA3TPRO5Qp7yizJNPydj7BhirSnXb
         VE1ieW5PSl+Thc/Z4l4bljIjQcefhNfeOAeJpdHv+HNkML4RqwoRMLOZxS3jgVsjZ3Ug
         U0Wdu5xDCPyhf8U49F5FGWSoMH2YOjkU6YFHL9+hb6yLog2Zu3RTvqb2sOeWiBMPJDRp
         g45mcORNqBrW8RoZ7hcnABW6UTOF2Ao6B7+Tlc0nqkhFcXnGIh8litLH0vYro6yfLrmX
         j0hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530f5lc38I6B9iMIKHWAdBgnjxu5MhhTl6fkZo+rWNdUkRSwb4e9
	HeHU7thFKO8TiHiMyfu/ZE4=
X-Google-Smtp-Source: ABdhPJxUft2ZMccMPGASZ0ieHPo4mxDQp3/V5aTTHnm7/WyWqXQR4OTKFYknkGqsnrF5Bo0DzHL+3Q==
X-Received: by 2002:ab0:6f02:: with SMTP id r2mr23203410uah.31.1621879507826;
        Mon, 24 May 2021 11:05:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cdf2:: with SMTP id v18ls1107242vkn.9.gmail; Mon, 24 May
 2021 11:05:07 -0700 (PDT)
X-Received: by 2002:ac5:cad1:: with SMTP id m17mr9213681vkl.12.1621879506778;
        Mon, 24 May 2021 11:05:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621879506; cv=none;
        d=google.com; s=arc-20160816;
        b=MPsbhlqOzKlgGqrLzG087t2xekUBfBS9w+LGsCL8C3ujYleqSuJu+aXWBzbW+H3VAc
         zR1Do/2CiVNTzYC3Klb9pe1Q/0NHWpHMXobk7a+DThdoQq+UI5+8Iu9cLnNnpJvxA+7h
         3EsDFM2mAuhGss5Q966YJIgoAuEBbx+UgcJXYtgo6YIFpusQQpQJX0sxcYRy0etGTe5v
         ddxNQpP9DJMPjcqvkgx4HDLbvSf+w4ETpFx7MTnv2IKMOPZ7f52NqtXhRmNaTst+A6lE
         0+nCxEGKP0TXat40garDMxUMNzYLwJl9JmLr9VsfQHXrjdy9+7Z7RzjIZLPVbqT9povr
         6tpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5dIDEt7Wm45PNtP1gAKppSpUDKIIPM67s68fJj3Bh90=;
        b=MLcyt8BPn0Hmbts/8mgKU7731AwJgyVB4xYdosInXhVkuJme6oDMwcyaTod61Gbh4C
         f2V0Qej+UEKXuK2pb3Tc7iKTzOrQ8Mexfs/7iuY9YGVokdMcXRYcTbPCSXnI8Wb3OljC
         JPr2jYP6MTT8HIMNXrZe/8nU+MSPBFGfVwyW3Is3DUh2kmrQsxkJ11Re6icuohoIo3Yx
         3O11tBZ2EXzSxzGn1z/HM88+JkaOpA4vhIZQa7CYHaDR+7Q69F4qGJydOT/W32b5PxkS
         F633YI0KADTXiBGhMaDZWe7beGlngzowHTSgTd2uYDJB0ykz2bjeyor+nIgpjfFtuG6U
         vxhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BcdB6cNQ;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t66si1123749vkc.5.2021.05.24.11.05.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 May 2021 11:05:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D4B0A61414
	for <kasan-dev@googlegroups.com>; Mon, 24 May 2021 18:05:05 +0000 (UTC)
Received: by mail-ot1-f46.google.com with SMTP id n3-20020a9d74030000b029035e65d0a0b8so4656039otk.9
        for <kasan-dev@googlegroups.com>; Mon, 24 May 2021 11:05:05 -0700 (PDT)
X-Received: by 2002:a9d:7cd8:: with SMTP id r24mr19941356otn.90.1621879505060;
 Mon, 24 May 2021 11:05:05 -0700 (PDT)
MIME-Version: 1.0
References: <20210524172433.015b3b6b@xhacker.debian> <20210524172606.08dac28d@xhacker.debian>
 <CANpmjNNuaYneLb3ScSwF=o0DnECBt4NRkBZJuwRqBrOKnTGPbA@mail.gmail.com>
In-Reply-To: <CANpmjNNuaYneLb3ScSwF=o0DnECBt4NRkBZJuwRqBrOKnTGPbA@mail.gmail.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 24 May 2021 20:04:53 +0200
X-Gmail-Original-Message-ID: <CAMj1kXGtguQ=rG4wM2=xXaDLBvN3+w7DRFeCGCeVabTGLinPuQ@mail.gmail.com>
Message-ID: <CAMj1kXGtguQ=rG4wM2=xXaDLBvN3+w7DRFeCGCeVabTGLinPuQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] arm64: remove page granularity limitation from KFENCE
To: Marco Elver <elver@google.com>
Cc: Jisheng Zhang <Jisheng.Zhang@synaptics.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BcdB6cNQ;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, 24 May 2021 at 19:31, Marco Elver <elver@google.com> wrote:
>
> +Cc Mark
>
> On Mon, 24 May 2021 at 11:26, Jisheng Zhang <Jisheng.Zhang@synaptics.com> wrote:
> >
> > KFENCE requires linear map to be mapped at page granularity, so that
> > it is possible to protect/unprotect single pages in the KFENCE pool.
> > Currently if KFENCE is enabled, arm64 maps all pages at page
> > granularity, it seems overkilled. In fact, we only need to map the
> > pages in KFENCE pool itself at page granularity. We acchieve this goal
> > by allocating KFENCE pool before paging_init() so we know the KFENCE
> > pool address, then we take care to map the pool at page granularity
> > during map_mem().
> >
> > Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>

Could you please share some performance numbers that result from this
optimization?

(There are other reasons why we may need to map the linear region down
to pages unconditionally in the future, so it would be good to have
some solid numbers about the potential impact of doing so)


> > ---
> >  arch/arm64/kernel/setup.c |  3 +++
> >  arch/arm64/mm/mmu.c       | 27 +++++++++++++++++++--------
> >  2 files changed, 22 insertions(+), 8 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> > index 61845c0821d9..51c0d6e8b67b 100644
> > --- a/arch/arm64/kernel/setup.c
> > +++ b/arch/arm64/kernel/setup.c
> > @@ -18,6 +18,7 @@
> >  #include <linux/screen_info.h>
> >  #include <linux/init.h>
> >  #include <linux/kexec.h>
> > +#include <linux/kfence.h>
> >  #include <linux/root_dev.h>
> >  #include <linux/cpu.h>
> >  #include <linux/interrupt.h>
> > @@ -345,6 +346,8 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
> >
> >         arm64_memblock_init();
> >
> > +       kfence_alloc_pool();
> > +
> >         paging_init();
> >
> >         acpi_table_upgrade();
> > diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> > index 89b66ef43a0f..12712d31a054 100644
> > --- a/arch/arm64/mm/mmu.c
> > +++ b/arch/arm64/mm/mmu.c
> > @@ -13,6 +13,7 @@
> >  #include <linux/init.h>
> >  #include <linux/ioport.h>
> >  #include <linux/kexec.h>
> > +#include <linux/kfence.h>
> >  #include <linux/libfdt.h>
> >  #include <linux/mman.h>
> >  #include <linux/nodemask.h>
> > @@ -515,10 +516,16 @@ static void __init map_mem(pgd_t *pgdp)
> >          */
> >         BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
> >
> > -       if (rodata_full || crash_mem_map || debug_pagealloc_enabled() ||
> > -           IS_ENABLED(CONFIG_KFENCE))
> > +       if (rodata_full || crash_mem_map || debug_pagealloc_enabled())
> >                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
> >
> > +       /*
> > +        * KFENCE requires linear map to be mapped at page granularity, so
> > +        * temporarily skip mapping for __kfence_pool in the following
> > +        * for-loop
> > +        */
> > +       memblock_mark_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> > +
>
> Did you build this with CONFIG_KFENCE unset? I don't think it builds.
>
> >         /*
> >          * Take care not to create a writable alias for the
> >          * read-only text and rodata sections of the kernel image.
> > @@ -553,6 +560,15 @@ static void __init map_mem(pgd_t *pgdp)
> >         __map_memblock(pgdp, kernel_start, kernel_end,
> >                        PAGE_KERNEL, NO_CONT_MAPPINGS);
> >         memblock_clear_nomap(kernel_start, kernel_end - kernel_start);
> > +
> > +       /*
> > +        * Map the __kfence_pool at page granularity now.
> > +        */
> > +       __map_memblock(pgdp, __pa(__kfence_pool),
> > +                      __pa(__kfence_pool + KFENCE_POOL_SIZE),
> > +                      pgprot_tagged(PAGE_KERNEL),
> > +                      NO_EXEC_MAPPINGS | NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> > +       memblock_clear_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> >  }
> >
> >  void mark_rodata_ro(void)
> > @@ -1480,12 +1496,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
> >
> >         VM_BUG_ON(!mhp_range_allowed(start, size, true));
> >
> > -       /*
> > -        * KFENCE requires linear map to be mapped at page granularity, so that
> > -        * it is possible to protect/unprotect single pages in the KFENCE pool.
> > -        */
> > -       if (rodata_full || debug_pagealloc_enabled() ||
> > -           IS_ENABLED(CONFIG_KFENCE))
> > +       if (rodata_full || debug_pagealloc_enabled())
> >                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
> >
> >         __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
> > --
> > 2.31.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210524172606.08dac28d%40xhacker.debian.
>
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGtguQ%3DrG4wM2%3DxXaDLBvN3%2Bw7DRFeCGCeVabTGLinPuQ%40mail.gmail.com.
