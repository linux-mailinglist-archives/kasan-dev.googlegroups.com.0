Return-Path: <kasan-dev+bncBDW2JDUY5AORB6MKXKGQMGQEBWNH6MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D8D446AAF3
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:49:46 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id q9-20020ad45749000000b003bdeb0612c5sf14178826qvx.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:49:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827385; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0AZeLS+e3BJmngKt8769w5Nxa72iFiaNwtD2j2sgCzVg7vdRkz+Gq+enJcdi3NbYU
         DGWP6/gsQgJvAbBS2v0//RzhRE/Zu9XZz+sxGP8Ghc5AkWHSrWkioZicPszb1xCxmqqx
         S5Afd205QwxxUT+6+jDRa0RCegxxtYHWQkJtN4ozk1xM7IoR36kpYHe1NExo0Gxe8/l2
         2qGlmXyG41cRIi3xSYXpMk+2X6zwIGjq7lSo/2J8fZVro2p1ko5cabINrCjSCzgfPMtc
         0Wyem7R/L3CN0piFnJlcPrHh4l/XawrW2qydlitgYJ/qCTLWJkxDp4E/rd8FO5WXHEQ8
         rorw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/tdndy62dHbYcUL/DznwjLubmWKP+NoZozMdW58p4rw=;
        b=vIRKms6/BAGCvmizNr4p/cc/Mx6NkbeRFlhpgI6XFJDYtasR7mXwzwcCm3D48KFqCA
         6wflxZUGJH9XSrj8y/IBXNEZkDrJAL9VCE/S17p8wb4vHc2V7EN/OP6NpIWZ3D2vk5V1
         zaUyZ6OV5Uo+6koCtNHff0CWe7dvAmEyYW+GxafofJ38uh78HYY62/BdKX0cdxCYg4bH
         opnq2HUwejD1l5RecCnBMhB5BjzeedOf++0Z+XgaSbrPtDyF7OJlBVpn1Ybd/0JjsDxW
         wmYTk3rtmOy+YvHVF+XraaAW4ckQ+hs4v6QApLIFNaAIcFF8DAHYjBc5Gd2lt1x6jcn7
         Tzyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iYqXj+Sr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/tdndy62dHbYcUL/DznwjLubmWKP+NoZozMdW58p4rw=;
        b=oSQaodE6V04wz3SKR/8C1WnKCoSKlp2V3qhzZxEaYa5ep38Df8edpreOFk5jxqDaN4
         AF+WlBzwHGYnSikSL9mSX4ZN+MzlmOnRb4d/qnviiTCYJSyqYqzIMWSBCSfhNxZi5pra
         PF3Vf6dyK3J1CdcEr59F9Yh1pQG1Q92IOOPaxlkMFv4Sdn1W7IdqSi93CAiH/3C0gtNd
         /zC+3dx2aTlY2dcNv1bSYjMVqL68hoK5g+sehXavnnjEo1f30bzHjLWZ13g1mX4jwAhE
         g944dWbTxpzYfxT3/KL1MRsgj9cjH2Bqrmd4pIggIcASS9xeDGDvYwdTidhldOYmvjeM
         0+aQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/tdndy62dHbYcUL/DznwjLubmWKP+NoZozMdW58p4rw=;
        b=n3YAb3EwTZkOdBEY5XU0SqZlOlz6VjDt/sm6sLDYbvVu6A7Pv3pOXkCPcwamcLU1Fl
         DTofLFzLOszJnmy0sxA/Vaovx5dpeBzjd8rhIqMrd2HQr7xfkeo+/p0Hwdwn0tXXbSBP
         V/hWHrBP9W2QbZtaedM1dwWVSvoHCy7+1mkI98zxJ7fi0VkBe87SpkyLqW6w/TBCveux
         pW01fn7xdNTTR8t/+T20EMpJ6OVMUB4+lZb78KiF1TwfnXG+kdlKiZOlEwsAZmXkd38+
         diVX21NHAyvJGOqCu9Q/N4ygURdgumwFPbKJnYY+bk4P/Y4O4b8OVQuAWmfl0gKUngzl
         iGPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/tdndy62dHbYcUL/DznwjLubmWKP+NoZozMdW58p4rw=;
        b=5YSi267S5Rl2DB7RQcRebXrEyrHOet7HTls1naeEmKEE/0Hqb0J2Wm3A942bpD0C2K
         ra8ddfUy28fJHnGXydPFeYOSA1Jr3IHyfg3tSswkLeuPx7HCIRUheXTUNHjTux/jMOLt
         1nqZj8b3ckAQjP/DvlZG4Ix9dfxExSVTElvIIfAgkNPoIDVlP6kgcNe943yyKkqGLtIy
         /Dyh6299yVobBF8Is5m+rPoG01Yw4eQmW6V7Hsph23tDmqV6CUDKExd5Z71vsjf9SOqP
         CQ3HKv3oWgu+WQ87/PgeOiX/2cRY2SHw3wB1bhab5dJBRCmW+IlItkDzheBMs2eDauFn
         RIEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EEY+DSpSuZkn5YUfX/37GQ9Jkq8aXGigJ7DINQFBNUd1iP33V
	ZTeoRTwy9msyCy7fb+58mno=
X-Google-Smtp-Source: ABdhPJxyRxZGUMhJpGr5XrVa/GozY72h5nOC2GgoGFAmilDi/fAoMSlNKc3reJixLGquzbfpwHPtPQ==
X-Received: by 2002:a05:6214:767:: with SMTP id f7mr41147329qvz.36.1638827385256;
        Mon, 06 Dec 2021 13:49:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f3cb:: with SMTP id f11ls9307071qvm.4.gmail; Mon, 06 Dec
 2021 13:49:44 -0800 (PST)
X-Received: by 2002:a05:6214:624:: with SMTP id a4mr41948631qvx.80.1638827384876;
        Mon, 06 Dec 2021 13:49:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827384; cv=none;
        d=google.com; s=arc-20160816;
        b=bnraar5ATYdhZtw3/1xqjIJvscT5wQOS6Cm58q+5v9TAHvxv1fYAhgx1Y+3PzQUYDc
         aiNJzu9PK8LfHrPc3pu062Em9nuDJUm7l402xV/Sa3csOWuQmmR6eWnwNTr1H/EU6mQo
         JYVfntFXjIOoD2cCFh1p6+VZKsfyU5o0mq3Sn3YL9QxX60OXvFDqC1Pd4SCn++1EPW95
         zk5InFcUhxvrAfbfXPTP9Xf85L4gtj9Winojbq+RMj4j6TUS1v4IilnoMuB5FXatSPJb
         uL0PV8GPEd9mJVa3Hze8Def12fUcPFXhg+GFIEJ4IzH3CdMFBtungk18UmupymI5jwgi
         xFcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ksl2Het3shbWwxstX/Qf/valmYx9RbWX8Li6L+VzZWM=;
        b=ltpdShtWtkqWTRjTBzKwx4geD59yW5HF+pGOKcx1GQUm4UAX2oDEjXonq1D5rfv7d7
         HFpZ1GwjFEYB+UiiExDw/+Bit1EDISoTQp22ESFi3K6OMEbf8WgyvTaieqBYIaL7B0hE
         1xSrZkXPTEC4+3WWSNk5FnN1CdGZAcokxAF1xHifK7A2hNLf0kI3QfLHU5BByXR3sKrv
         pf3B9h8t37qTWwh9K79Vb/45nPMBA/cDlek8ExFRHCkWNOk37845OhltUKRiQr+ugmFP
         qG5xvTcolGs+p/Ua0Z/oJvrQGpAYeHC0nfKcDiJ9k6GhFeRwWgN271EThl2EvpcIwWYE
         yjKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iYqXj+Sr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id b8si2403515qtg.5.2021.12.06.13.49.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:49:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id t8so11713756ilu.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:49:44 -0800 (PST)
X-Received: by 2002:a05:6e02:1605:: with SMTP id t5mr39284375ilu.233.1638827384286;
 Mon, 06 Dec 2021 13:49:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com> <72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl@google.com>
In-Reply-To: <72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:49:33 +0100
Message-ID: <CA+fCnZc2ae_j0TmDMdSD6q71S_z1LuaOrh_U8s1mByBT0SOu+Q@mail.gmail.com>
Subject: Re: [PATCH v2 28/34] kasan, vmalloc: add vmalloc support to HW_TAGS
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=iYqXj+Sr;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 6, 2021 at 10:46 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> This patch adds vmalloc tagging support to HW_TAGS KASAN.
>
> The key difference between HW_TAGS and the other two KASAN modes
> when it comes to vmalloc: HW_TAGS KASAN can only assign tags to
> physical memory. The other two modes have shadow memory covering
> every mapped virtual memory region.
>
> This patch makes __kasan_unpoison_vmalloc() for HW_TAGS KASAN:
>
> - Skip non-VM_ALLOC mappings as HW_TAGS KASAN can only tag a single
>   mapping of normal physical memory; see the comment in the function.
> - Generate a random tag, tag the returned pointer and the allocation,
>   and initialize the allocation at the same time.
> - Propagate the tag into the page stucts to allow accesses through
>   page_address(vmalloc_to_page()).
>
> The rest of vmalloc-related KASAN hooks are not needed:
>
> - The shadow-related ones are fully skipped.
> - __kasan_poison_vmalloc() is kept as a no-op with a comment.
>
> Poisoning and zeroing of physical pages that are backing vmalloc()
> allocations are skipped via __GFP_SKIP_KASAN_UNPOISON and
> __GFP_SKIP_ZERO: __kasan_unpoison_vmalloc() does that instead.
>
> This patch allows enabling CONFIG_KASAN_VMALLOC with HW_TAGS
> and adjusts CONFIG_KASAN_VMALLOC description:
>
> - Mention HW_TAGS support.
> - Remove unneeded internal details: they have no place in Kconfig
>   description and are already explained in the documentation.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> ---
>
> Changes v1->v2:
> - Allow enabling CONFIG_KASAN_VMALLOC with HW_TAGS in this patch.
> - Move memory init for page_alloc pages backing vmalloc() into
>   kasan_unpoison_vmalloc().
> ---
>  include/linux/kasan.h | 30 +++++++++++++--
>  lib/Kconfig.kasan     | 20 +++++-----
>  mm/kasan/hw_tags.c    | 89 +++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/shadow.c     | 11 +++++-
>  mm/vmalloc.c          | 32 +++++++++++++---
>  5 files changed, 162 insertions(+), 20 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 6a2619759e93..0bdc2b824b9c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -417,19 +417,40 @@ static inline void kasan_init_hw_tags(void) { }
>
>  #ifdef CONFIG_KASAN_VMALLOC
>
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +
>  void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
>  int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
>  void kasan_release_vmalloc(unsigned long start, unsigned long end,
>                            unsigned long free_region_start,
>                            unsigned long free_region_end);
>
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline void kasan_populate_early_vm_area_shadow(void *start,
> +                                                      unsigned long size)
> +{ }
> +static inline int kasan_populate_vmalloc(unsigned long start,
> +                                       unsigned long size)
> +{
> +       return 0;
> +}
> +static inline void kasan_release_vmalloc(unsigned long start,
> +                                        unsigned long end,
> +                                        unsigned long free_region_start,
> +                                        unsigned long free_region_end) { }
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
>  void * __must_check __kasan_unpoison_vmalloc(const void *start,
> -                                            unsigned long size);
> +                                            unsigned long size,
> +                                            bool vm_alloc, bool init);
>  static __always_inline void * __must_check kasan_unpoison_vmalloc(
> -                                       const void *start, unsigned long size)
> +                                       const void *start, unsigned long size,
> +                                       bool vm_alloc, bool init)
>  {
>         if (kasan_enabled())
> -               return __kasan_unpoison_vmalloc(start, size);
> +               return __kasan_unpoison_vmalloc(start, size, vm_alloc, init);
>         return (void *)start;
>  }
>
> @@ -456,7 +477,8 @@ static inline void kasan_release_vmalloc(unsigned long start,
>                                          unsigned long free_region_end) { }
>
>  static inline void *kasan_unpoison_vmalloc(const void *start,
> -                                          unsigned long size, bool unique)
> +                                          unsigned long size,
> +                                          bool vm_alloc, bool init)
>  {
>         return (void *)start;
>  }
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 3f144a87f8a3..7834c35a7964 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -178,17 +178,17 @@ config KASAN_TAGS_IDENTIFY
>           memory consumption.
>
>  config KASAN_VMALLOC
> -       bool "Back mappings in vmalloc space with real shadow memory"
> -       depends on (KASAN_GENERIC || KASAN_SW_TAGS) && HAVE_ARCH_KASAN_VMALLOC
> +       bool "Check accesses to vmalloc allocations"
> +       depends on HAVE_ARCH_KASAN_VMALLOC
>         help
> -         By default, the shadow region for vmalloc space is the read-only
> -         zero page. This means that KASAN cannot detect errors involving
> -         vmalloc space.
> -
> -         Enabling this option will hook in to vmap/vmalloc and back those
> -         mappings with real shadow memory allocated on demand. This allows
> -         for KASAN to detect more sorts of errors (and to support vmapped
> -         stacks), but at the cost of higher memory usage.
> +         This mode makes KASAN check accesses to vmalloc allocations for
> +         validity.
> +
> +         With software KASAN modes, checking is done for all types of vmalloc
> +         allocations. Enabling this option leads to higher memory usage.
> +
> +         With hardware tag-based KASAN, only VM_ALLOC mappings are checked.
> +         There is no additional memory usage.
>
>  config KASAN_KUNIT_TEST
>         tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 76cf2b6229c7..837c260beec6 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -192,6 +192,95 @@ void __init kasan_init_hw_tags(void)
>                 kasan_stack_collection_enabled() ? "on" : "off");
>  }
>
> +#ifdef CONFIG_KASAN_VMALLOC
> +
> +static void unpoison_vmalloc_pages(const void *addr, u8 tag)
> +{
> +       struct vm_struct *area;
> +       int i;
> +
> +       /*
> +        * As hardware tag-based KASAN only tags VM_ALLOC vmalloc allocations
> +        * (see the comment in __kasan_unpoison_vmalloc), all of the pages
> +        * should belong to a single area.
> +        */
> +       area = find_vm_area((void *)addr);
> +       if (WARN_ON(!area))
> +               return;
> +
> +       for (i = 0; i < area->nr_pages; i++) {
> +               struct page *page = area->pages[i];
> +
> +               page_kasan_tag_set(page, tag);
> +       }
> +}
> +
> +void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> +                               bool vm_alloc, bool init)
> +{
> +       u8 tag;
> +       unsigned long redzone_start, redzone_size;
> +
> +       if (!is_vmalloc_or_module_addr(start))
> +               return (void *)start;
> +
> +       /* Unpoisoning and pointer tag assignment is skipped for non-VM_ALLOC
> +        * mappings as:
> +        *
> +        * 1. Unlike the software KASAN modes, hardware tag-based KASAN only
> +        *    supports tagging physical memory. Therefore, it can only tag a
> +        *    single mapping of normal physical pages.
> +        * 2. Hardware tag-based KASAN can only tag memory mapped with special
> +        *    mapping protection bits, see arch_vmalloc_pgprot_modify().
> +        *    As non-VM_ALLOC mappings can be mapped outside of vmalloc code,
> +        *    providing these bits would require tracking all non-VM_ALLOC
> +        *    mappers.
> +        *
> +        * Thus, for VM_ALLOC mappings, hardware tag-based KASAN only tags
> +        * the first virtual mapping, which is created by vmalloc().
> +        * Tagging the page_alloc memory backing that vmalloc() allocation is
> +        * skipped, see ___GFP_SKIP_KASAN_UNPOISON.
> +        *
> +        * For non-VM_ALLOC allocations, page_alloc memory is tagged as usual.
> +        */
> +       if (!vm_alloc)
> +               return (void *)start;
> +
> +       tag = kasan_random_tag();
> +       start = set_tag(start, tag);
> +
> +       /* Unpoison and initialize memory up to size. */
> +       kasan_unpoison(start, size, init);
> +
> +       /*
> +        * Explicitly poison and initialize the in-page vmalloc() redzone.
> +        * Unlike software KASAN modes, hardware tag-based KASAN doesn't
> +        * unpoison memory when populating shadow for vmalloc() space.
> +        */
> +       redzone_start = round_up((unsigned long)start + size, KASAN_GRANULE_SIZE);
> +       redzone_size = round_up(redzone_start, PAGE_SIZE) - redzone_start;
> +       kasan_poison((void *)redzone_start, redzone_size, KASAN_TAG_INVALID, init);
> +
> +       /*
> +        * Set per-page tag flags to allow accessing physical memory for the
> +        * vmalloc() mapping through page_address(vmalloc_to_page()).
> +        */
> +       unpoison_vmalloc_pages(start, tag);
> +
> +       return (void *)start;
> +}
> +
> +void __kasan_poison_vmalloc(const void *start, unsigned long size)
> +{
> +       /*
> +        * No tagging here.
> +        * The physical pages backing the vmalloc() allocation are poisoned
> +        * through the usual page_alloc paths.
> +        */
> +}
> +
> +#endif
> +
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
>  void kasan_enable_tagging_sync(void)
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 4ca280a96fbc..8600dd925f35 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -475,8 +475,17 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>         }
>  }
>
> -void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
> +void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> +                               bool vm_alloc, bool init)
>  {
> +       /*
> +        * Software tag-based KASAN tags both VM_ALLOC and non-VM_ALLOC
> +        * mappings, so the vm_alloc argument is ignored.
> +        * Software tag-based KASAN can't optimize zeroing memory by combining
> +        * it with setting memory tags, so the init argument is ignored;
> +        * vmalloc() memory is poisoned via page_alloc.
> +        */
> +
>         if (!is_vmalloc_or_module_addr(start))
>                 return (void *)start;
>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 82ef1e27e2e4..d48db7cc3358 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2214,8 +2214,12 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
>                 return NULL;
>         }
>
> -       /* Mark the pages as accessible after they were mapped in. */
> -       mem = kasan_unpoison_vmalloc(mem, size);
> +       /*
> +        * Mark the pages as accessible after they were mapped in.
> +        * With hardware tag-based KASAN, marking is skipped for
> +        * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
> +        */
> +       mem = kasan_unpoison_vmalloc(mem, size, false, false);
>
>         return mem;
>  }
> @@ -2449,9 +2453,12 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>          * accessible after they are mapped in.
>          * Otherwise, as the pages can be mapped outside of vmalloc code,
>          * mark them now as a best-effort approach.
> +        * With hardware tag-based KASAN, marking is skipped for
> +        * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>          */
>         if (!(flags & VM_ALLOC))
> -               area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
> +               area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
> +                                                       false, false);
>
>         return area;
>  }
> @@ -2849,6 +2856,12 @@ vm_area_alloc_pages(gfp_t gfp, int nid,
>         struct page *page;
>         int i;
>
> +       /*
> +        * Skip page_alloc poisoning and zeroing for pages backing VM_ALLOC
> +        * mappings. Only effective in HW_TAGS mode.
> +        */
> +       gfp &= __GFP_SKIP_KASAN_UNPOISON & __GFP_SKIP_ZERO;
> +
>         /*
>          * For order-0 pages we make use of bulk allocator, if
>          * the page array is partly or not at all populated due
> @@ -3027,6 +3040,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  {
>         struct vm_struct *area;
>         void *addr;
> +       bool init;
>         unsigned long real_size = size;
>         unsigned long real_align = align;
>         unsigned int shift = PAGE_SHIFT;
> @@ -3083,8 +3097,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>         /*
>          * Mark the pages for VM_ALLOC mappings as accessible after they were
>          * mapped in.
> +        * The init condition should match the one in post_alloc_hook()
> +        * (except for the should_skip_init() check) to make sure that memory
> +        * is initialized under the same conditions regardless of the enabled
> +        * KASAN mode.
>          */
> -       addr = kasan_unpoison_vmalloc(addr, real_size);
> +       init = !want_init_on_free() && want_init_on_alloc(gfp_mask);
> +       addr = kasan_unpoison_vmalloc(addr, real_size, true, init);
>
>         /*
>          * In this function, newly allocated vm_struct has VM_UNINITIALIZED
> @@ -3784,10 +3803,13 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>          * Mark allocated areas as accessible.
>          * As the pages are mapped outside of vmalloc code,
>          * mark them now as a best-effort approach.
> +        * With hardware tag-based KASAN, marking is skipped for
> +        * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>          */
>         for (area = 0; area < nr_vms; area++)
>                 vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
> -                                                        vms[area]->size);
> +                                                        vms[area]->size,
> +                                                        false, false);
>
>         kfree(vas);
>         return vms;
> --
> 2.25.1
>

Hi Vincenzo,

This patch is partially based on an early version of the HW_TAGS
series you had. Could you PTAL and give your sign-off?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc2ae_j0TmDMdSD6q71S_z1LuaOrh_U8s1mByBT0SOu%2BQ%40mail.gmail.com.
