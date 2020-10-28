Return-Path: <kasan-dev+bncBCMIZB7QWENRBT5Q4X6AKGQE67FJWOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CB6629CFBD
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 12:38:57 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id f12sf2209330oos.23
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 04:38:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603885136; cv=pass;
        d=google.com; s=arc-20160816;
        b=ErgSMxNXszi1jOvEyiLsn2jVSAjrIL+Yp8Sui67cf55iGbb6ULbGZ4rmMhO+vMegHC
         TU6brOeXyf4RvkFuC4Qb6CVwT6R/5nzVnAs4ZgNBqQ0kVERu5+q2a+dPrEm+54MAvQ2C
         T1gOxTLYtIiiiWDmkNI4h+zIF28RVW4hV6s6qrXkuUm0cRaQdl00t4pL1d2IW323ocKN
         Wa3IfmNRaG5Trc6hVcRG5D0UmPGuVtmu8Q4tT2Rca1vkimQ21pxXKoA3NrCTorTWFWBu
         Gj74gfns8NPaFPHkdnad2TIXYx0c+BXRotz+9zeV1CZqYrpDcNTx7j9HPMqq+IynhuCj
         1K1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AjbzhctJg7S2sa37rVvk7qp7RbZqkdU2YbPdrYng30Y=;
        b=W43Qa1/FSx/LBfVC2oSI/tUZMpYGyi/8CjKpXFjiczLFDH69zXEiofefJZVc/Rgzju
         939PvMEB7+d5D0tCrcMcoaH88h6ca7bAIezynII7y46BdlE1jj8205UABnk5RBImzQYW
         KyML3FSjzw9xBEg1DUgDMrkYxk8sx5gnNhTJQhHoZNb9ZsvRcOoQpksJCnkhwbcpwswn
         hB762SzDseMIPz0AuNxxTMaBHIc6sCLu0Qe7Qa/65AeQ9qhwL/Frgv9+MWKks1BamusI
         tR02b6FvOrt3Sj8Xgwe9JxylT73Bix9CAS2LxNKRmhD4PEHwaR9aYcFSNa/ZyPd0dz0j
         jLMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=moy3QtjP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AjbzhctJg7S2sa37rVvk7qp7RbZqkdU2YbPdrYng30Y=;
        b=njzE1yjMC0llVf6hdU+RYD3EMEmcCfZSTllare0Xm7zB24owSX7Gdy6T1gewiLyUK1
         j0rehb1gpTWuSNyt4jpogNPl7pzsSiNX0bSmDmNGN3Y0P0dtUqfjfC37H3mU9Bv0O+18
         PI0QG33GLR5DOTZKuTumCjacPEbMVGMBz/NwsWDRS/IlBlnMJSbDsjScyqyzxITrwEfx
         YRHOk+cgt86uCWaEvYrrQ3XeJuUAEeZ5XVv/9zrVc+/pp3bU5H1GLSnaUqmmIIWvO/w2
         bTFJx8Uk3zukbbe6+SQ/BIzLZkwGgo8r2LLExxRFm3nKwjDTjOppgmoGB5HhSqBPZvNP
         0AcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AjbzhctJg7S2sa37rVvk7qp7RbZqkdU2YbPdrYng30Y=;
        b=S/cdNQuO6P2kmMbx2Ce+y5jLU/sYz/WD2u+tanlYPPkAbX5bWQydFlklVteS8wY5Fd
         1NFzbbqGZ9Gpqepi5jQT4qwbS0h3id3POjNz58VNWZfin5gN0tNmZvInKglnQvvbv/Sz
         cg9F+Oiw3jF/YIE0FRgVOmuCf37mw8H01ir+pgMalP12gI+xdGnXEzGxYuZa2dQdeBQg
         29+LMfX2ys3OCmIxMMNfPDFS/05McwZjk42Qbzg6rRZo2ZM8l/ackbiX5Lcl0RV7TELy
         qKUknarOV2E7qzVhXuQE3NQNi9raTr3yOV2DCfnuapkXDMmuhxlp9Lkmet4aT7pU+1z8
         T2ow==
X-Gm-Message-State: AOAM532/ucTNT3wKpWRbaucA5bmHJoZp9kvBRZ6lN/bDPHrPlbbd6Uek
	Jzi3KWCJ24vrSlXkMHmcnZ4=
X-Google-Smtp-Source: ABdhPJweF2VVwH1MAzY5so8pxj4qjlNbDhf1QfuniyZ4niBOl+2dcsvtJYVOI71CH+NW3SEMpZGrkA==
X-Received: by 2002:a05:6830:13c4:: with SMTP id e4mr4679142otq.142.1603885135918;
        Wed, 28 Oct 2020 04:38:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b81:: with SMTP id b1ls1154491otq.8.gmail; Wed, 28 Oct
 2020 04:38:55 -0700 (PDT)
X-Received: by 2002:a9d:ee6:: with SMTP id 93mr4996305otj.195.1603885135552;
        Wed, 28 Oct 2020 04:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603885135; cv=none;
        d=google.com; s=arc-20160816;
        b=XYoMnRXZsz2825OYAF/2ka0JNR6mXcSdIi7ZoVrp5Qypivb/F9Di9ssRSWY8WuKFgu
         I02JnXwk/pfSC81n0XFfLFHyBxBNFM71DfjLry4m0ZfiqThruwRTIxhVRmGrCXOR4a5e
         r/smBZorj7LdNchuYoYgcNqskWxhU3JKl73xVD/gt5xYU7x14MobjSPZLXRa7EmVMjGM
         RpTOfua44XaMlH5msLNoKcon/wcQ3KSmDF6jHxrXf0s+CLxELIBmxzy1CaxcbKPOOy3E
         kVW75ybJC9mSmEOZ3O9BPE+P+HPRPnBq0f2jgKevuz8+6GF/t/jaWi8EQFURDvxQghVB
         08bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/44VlBK6OKm+RXk0OJTWh6hF3WHJ///hTwLxttFcS6M=;
        b=FtshtKqXM8LggwG4RJwhAplw/IIPZ0OjtD3iB/+vq3JiOlxQk5GkANXQjdep6A50DL
         Q2xhNm/ja6yD+9rlnXSxPDqmy7FN4WybuI8p8BSczcm2cwhdUjUjIWK4aZxuaZqMBqU/
         dg63dqp+4p1cqhAss5pFabFKy8DYIJMWHshYPyWPFjkz5wBWngI4e8INCaS5mf+7uB6O
         NxngJKftex1NWTFpmpW6OvxdqCD1ySwQ40V2DSx7j/uAfGeThH84lYbhLuSMvOzAarI5
         6Lj4KwCbS3h25j8Dxnt/HP6dLo+jCjIjaEsAiSFZkTCLZIV6Rfe1Q7MXQiv6p4oS/MdG
         ucfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=moy3QtjP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id m127si444611oig.2.2020.10.28.04.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 04:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id j129so4141418qke.5
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 04:38:55 -0700 (PDT)
X-Received: by 2002:a05:620a:1188:: with SMTP id b8mr6917152qkk.265.1603885134792;
 Wed, 28 Oct 2020 04:38:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ae2caac58051ea4182c0278a1c1e4a945c3a1529.1603372719.git.andreyknvl@google.com>
In-Reply-To: <ae2caac58051ea4182c0278a1c1e4a945c3a1529.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 12:38:43 +0100
Message-ID: <CACT4Y+bG_xHcJqmXWKJseR7DWT=hg0AyJzmt8vC85jjL6JO-ZQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2 13/21] arm64: kasan: Add cpu_supports_tags helper
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=moy3QtjP;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add an arm64 helper called cpu_supports_mte() that exposes information
> about whether the CPU supports memory tagging and that can be called
> during early boot (unlike system_supports_mte()).
>
> Use that helper to implement a generic cpu_supports_tags() helper, that
> will be used by hardware tag-based KASAN.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ib4b56a42c57c6293df29a0cdfee334c3ca7bdab4

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  6 ++++++
>  arch/arm64/kernel/mte.c            | 20 ++++++++++++++++++++
>  mm/kasan/kasan.h                   |  4 ++++
>  4 files changed, 31 insertions(+)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index b5d6b824c21c..f496abfcf7f5 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -232,6 +232,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  }
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> +#define arch_cpu_supports_tags()               cpu_supports_mte()
>  #define arch_init_tags(max_tag)                        mte_init_tags(max_tag)
>  #define arch_get_random_tag()                  mte_get_random_tag()
>  #define arch_get_mem_tag(addr)                 mte_get_mem_tag(addr)
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index a4c61b926d4a..4c3f2c6b4fe6 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -9,6 +9,7 @@
>
>  #ifndef __ASSEMBLY__
>
> +#include <linux/init.h>
>  #include <linux/types.h>
>
>  /*
> @@ -30,6 +31,7 @@ u8 mte_get_random_tag(void);
>  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>
>  void mte_init_tags(u64 max_tag);
> +bool __init cpu_supports_mte(void);
>
>  #else /* CONFIG_ARM64_MTE */
>
> @@ -54,6 +56,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  static inline void mte_init_tags(u64 max_tag)
>  {
>  }
> +static inline bool cpu_supports_mte(void)
> +{
> +       return false;
> +}
>
>  #endif /* CONFIG_ARM64_MTE */
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index ca8206b7f9a6..8fcd17408515 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -134,6 +134,26 @@ void mte_init_tags(u64 max_tag)
>         gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
>  }
>
> +/*
> + * This function can be used during early boot to determine whether the CPU
> + * supports MTE. The alternative that must be used after boot is completed is
> + * system_supports_mte(), but it only works after the cpufeature framework
> + * learns about MTE.
> + */
> +bool __init cpu_supports_mte(void)
> +{
> +       u64 pfr1;
> +       u32 val;
> +
> +       if (!IS_ENABLED(CONFIG_ARM64_MTE))
> +               return false;
> +
> +       pfr1 = read_cpuid(ID_AA64PFR1_EL1);
> +       val = cpuid_feature_extract_unsigned_field(pfr1, ID_AA64PFR1_MTE_SHIFT);
> +
> +       return val >= ID_AA64PFR1_MTE;
> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>         /* ISB required for the kernel uaccess routines */
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index da08b2533d73..f7ae0c23f023 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -240,6 +240,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define set_tag(addr, tag)     ((void *)arch_kasan_set_tag((addr), (tag)))
>  #define get_tag(addr)          arch_kasan_get_tag(addr)
>
> +#ifndef arch_cpu_supports_tags
> +#define arch_cpu_supports_tags() (false)
> +#endif
>  #ifndef arch_init_tags
>  #define arch_init_tags(max_tag)
>  #endif
> @@ -253,6 +256,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
>  #endif
>
> +#define cpu_supports_tags()                    arch_cpu_supports_tags()
>  #define init_tags(max_tag)                     arch_init_tags(max_tag)
>  #define get_random_tag()                       arch_get_random_tag()
>  #define get_mem_tag(addr)                      arch_get_mem_tag(addr)
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbG_xHcJqmXWKJseR7DWT%3Dhg0AyJzmt8vC85jjL6JO-ZQ%40mail.gmail.com.
