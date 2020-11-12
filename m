Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTPFWX6QKGQE52KGTAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FDF72B0B64
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 18:37:19 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id s6sf4010598plp.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 09:37:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605202637; cv=pass;
        d=google.com; s=arc-20160816;
        b=UxEkLO4X5wpbbB6mCIgID0YGuQj0mamtdk24cOHj9GeTdkQPCHvP9Ohav3RSEQHA7y
         DelElwMCjY/F03UcPrp79qmxwGe24G+VhiB84welMs/o7/E64rTZLJBJnPgWSEneg6cD
         Gww0RvSO8AZ3QBOqnHcbRyVtS1QDHpN1XEhHTPN0fNvRNecj/W0hLqqI/H2efS07TK39
         MPBkwLvXawBEiMMxCqWtbyoxUZ0EZXBcuHxi8y+H+NYkFNJhdTmg306hrMeW+EFiDx/f
         0SZU9ciBdkvBuAsr0uTD/sAUO3cEA5XRoshP0+iH9UKwj1pwwHg05/i28XnBIwqNzpkm
         GzGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OkdBjza/KHR2aWZOESwWtGxW4JRBThk7pnp9n9O+SkA=;
        b=0Ug7bTlB9vY31OEAnzany6q8yn0/SY+Z5ERA9uV/CMxPcs0Mswt63s3UrAMLQ7yU1M
         iKS8Sh3mhVca7rg1HSLSILPDVX6Vkxcy5iK1snqi4IReMYJgUJC2ZSehLmm8oekK4Cil
         g5eDCnMPR+sBQSS/ciy5mZmYaMkZFA/n5bIP3A5gMC26h5n+FJG2ze3hOQFeNp7TF0D/
         KffU9EhevczahPV/Xs/GImXbSxtdkEVTiE5aRt963lAENzBcATruk3Y1IX3iCcfcrQO3
         ZSSKsOSHWsES39i81jOkfklCLnTT23kUXGkEZ6n0mz5Y26srkb2uPBNjvkNsGAgH384z
         Jfvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=um5dEiJD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OkdBjza/KHR2aWZOESwWtGxW4JRBThk7pnp9n9O+SkA=;
        b=tfwWK4UphzIyOsWW6Gb7ooeeegrtU6eSXDwi2a7V24XYlpxrmHcKi4hu6MsweHKAGm
         vb13Cp3DKLNPRlQ1ns2bbvoza7LDZ0Rh0iFRzVBFzozM1pJPAYFtmhYkYlaWiq/ZiU/e
         I4BfJJ3JMuQw8JvxVfqt3/lSTEDXjC6wx/7TI008yse8H/4+YMUNIj+BgEbWnvYTgyT1
         +RZ26LBAvY2NMdvXK1K/1l2xGGGBC3FTkSZqCI6U9uGZLGu8cNYkJN3VFunlh3yKwoDz
         qlH9jXKyv4nfs+W0rEltGDxNomg8h4vkmtPx9R9H2PBOLh0TcErPuJGutT19z9vCVN1p
         Jxnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OkdBjza/KHR2aWZOESwWtGxW4JRBThk7pnp9n9O+SkA=;
        b=qqwOS/1ZFB79MSvBHYnMrnU4C3vq6jM0o8QM9r7ycSzF0zaNuuAa3W4iClrH3qGCD4
         IulqXe8hf8ARPCXD+EFcT2ZgDDL2FHFCjQwj1DNOfmR7+3VMOYd7z6u1OeV6XQNcJbon
         5kuD8+uSJr8/iKWnWhjZYcfKX/WkaJxymfqJZPbNaRp+HuHbaCUFvcH3FaNMbZ6UjygK
         3kuAB2RVZgyA2KCUp51BJezfIVh7GcSwsdfbUwUpiiWddz2x5XshmHHomwUO+1QnoHAA
         khi48gXr0IjQI89MUtF01//GzIlMqRLZJGacj3JmbzLFqJtV+1hFg8DSclvPW9HLc+aG
         qLFw==
X-Gm-Message-State: AOAM533j4erQFTa5ROFLj9yt0q/pfAyM+eeQly2w2ZogKe8bTOcW+ejE
	1sHeFo/q9gGUXc0/SEAUqPQ=
X-Google-Smtp-Source: ABdhPJxAgDWy3OA0QzAfoJmi6RN8Jsq3Pc0is8OXPfY7Cj+D5EVW7ZR//coGi1qxV1xbauwASMj/eA==
X-Received: by 2002:a63:4c5b:: with SMTP id m27mr484697pgl.211.1605202637664;
        Thu, 12 Nov 2020 09:37:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:543:: with SMTP id 64ls1258117pff.2.gmail; Thu, 12 Nov
 2020 09:37:17 -0800 (PST)
X-Received: by 2002:a65:6556:: with SMTP id a22mr481630pgw.121.1605202636858;
        Thu, 12 Nov 2020 09:37:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605202636; cv=none;
        d=google.com; s=arc-20160816;
        b=pY07iHxlRRpbLAoE+sRfaBGRWDVreYoR82/AAJtnZ/TYpsQ1aG1o5AsVurBlCkRdVD
         OIUygHHdoMT/urU7NZn9vIPsFvmMvpfajl2rn8cDh3TgfZqH22NEIyU4lBpAnTh76zQL
         GLp29oSy5cUS3KPX3JvP777JlI6F9Fr2om2lgfvvBT7c8uvcozLB7UyI1ymNa1RcZ+hx
         AdLqxC18oQpF7G4WV4yZllAHYvGOE8jE8L+T0r737HEZmDT7/eF2lSLAOeBm4r425KSN
         8f7MZvYaMNZSQw8AL9BdztPsVloxSzw2HRt2Nx2fpbHemTEZy6hjsKacmX2BZYJdg05F
         uITA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kJRnZ1K/SsMcONZmbTC+Qa5zVrzQ+5qdaa05c9kyYcM=;
        b=xzZcMBFKlRmBzc+n8dNqSIgHkrLYhVdc15qp4Tsq5fMGhiVUcygNMn15eYBU7pejFW
         yApUOfzJwu1BbHAWdJZBH7pCFJ60R+5dLRJ/eKfd1UyihKanxMmkhHgeDPQtve2Gg8or
         eqE2dgWMiVzgPGJjsMuFv9YWnfH9TdlDcC/EhECKH4+KG0nNyfGmM6T3e01J2KbblDw2
         fRSrRm42zdXQ71BU37sWndcyGJw2GLHvSVvK2dO4QrgGq5F4EDdMfxFVKY3XX9xBS0qs
         EvOlB0mh/uI9hoGnGPY6T6J1+hBaHrkeUsErLNezQVZ5V0EJpq2yONnVCbzJ8X8HHPDT
         04IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=um5dEiJD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id e2si393738pjm.2.2020.11.12.09.37.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 09:37:16 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id u4so6020909qkk.10
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 09:37:16 -0800 (PST)
X-Received: by 2002:a05:620a:211b:: with SMTP id l27mr924168qkl.352.1605202635455;
 Thu, 12 Nov 2020 09:37:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <9f8119934070b7ffa8d129b64c9d05644ce7d20a.1605046192.git.andreyknvl@google.com>
In-Reply-To: <9f8119934070b7ffa8d129b64c9d05644ce7d20a.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 18:37:04 +0100
Message-ID: <CAG_fn=XOWPVX+Muysqu_u0w4o_rpyb+XuUZW2+pC9T6WG_3-iw@mail.gmail.com>
Subject: Re: [PATCH v9 39/44] kasan, arm64: implement HW_TAGS runtime
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=um5dEiJD;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Provide implementation of KASAN functions required for the hardware
> tag-based mode. Those include core functions for memory and pointer
> tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
> common KASAN code to support the new mode.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
> ---
>  arch/arm64/include/asm/memory.h   |  4 +-
>  arch/arm64/kernel/cpufeature.c    |  3 ++
>  arch/arm64/kernel/smp.c           |  2 +
>  include/linux/kasan.h             | 24 +++++++---
>  include/linux/mm.h                |  2 +-
>  include/linux/page-flags-layout.h |  2 +-
>  mm/kasan/Makefile                 |  5 ++
>  mm/kasan/common.c                 | 15 +++---
>  mm/kasan/hw_tags.c                | 80 +++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h                  | 17 +++++--
>  mm/kasan/report_hw_tags.c         | 42 ++++++++++++++++
>  mm/kasan/report_sw_tags.c         |  2 +-
>  mm/kasan/shadow.c                 |  2 +-
>  mm/kasan/sw_tags.c                |  2 +-
>  14 files changed, 177 insertions(+), 25 deletions(-)
>  create mode 100644 mm/kasan/hw_tags.c
>  create mode 100644 mm/kasan/report_hw_tags.c
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 656aaddb7014..5042eef5b111 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -214,7 +214,7 @@ static inline unsigned long kaslr_offset(void)
>         (__force __typeof__(addr))__addr;                               \
>  })
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  #define __tag_shifted(tag)     ((u64)(tag) << 56)
>  #define __tag_reset(addr)      __untagged_addr(addr)
>  #define __tag_get(addr)                (__u8)((u64)(addr) >> 56)
> @@ -222,7 +222,7 @@ static inline unsigned long kaslr_offset(void)
>  #define __tag_shifted(tag)     0UL
>  #define __tag_reset(addr)      (addr)
>  #define __tag_get(addr)                0
> -#endif /* CONFIG_KASAN_SW_TAGS */
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline const void *__tag_set(const void *addr, u8 tag)
>  {
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeatur=
e.c
> index dcc165b3fc04..6a1f2e3558c5 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -70,6 +70,7 @@
>  #include <linux/types.h>
>  #include <linux/mm.h>
>  #include <linux/cpu.h>
> +#include <linux/kasan.h>
>  #include <asm/cpu.h>
>  #include <asm/cpufeature.h>
>  #include <asm/cpu_ops.h>
> @@ -1704,6 +1705,8 @@ static void cpu_enable_mte(struct arm64_cpu_capabil=
ities const *cap)
>                 cleared_zero_page =3D true;
>                 mte_clear_page_tags(lm_alias(empty_zero_page));
>         }
> +
> +       kasan_init_hw_tags_cpu();
>  }
>  #endif /* CONFIG_ARM64_MTE */
>
> diff --git a/arch/arm64/kernel/smp.c b/arch/arm64/kernel/smp.c
> index 09c96f57818c..7235b9478413 100644
> --- a/arch/arm64/kernel/smp.c
> +++ b/arch/arm64/kernel/smp.c
> @@ -461,6 +461,8 @@ void __init smp_prepare_boot_cpu(void)
>         /* Conditionally switch to GIC PMR for interrupt masking */
>         if (system_uses_irq_prio_masking())
>                 init_gic_priority_masking();
> +
> +       kasan_init_hw_tags();
>  }
>
>  static u64 __init of_get_cpu_mpidr(struct device_node *dn)
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b6fc14b3da53..f22bdef82111 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -189,25 +189,35 @@ static inline void kasan_record_aux_stack(void *ptr=
) {}
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> -
> -void __init kasan_init_sw_tags(void);
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
>  void *kasan_reset_tag(const void *addr);
>
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> -#else /* CONFIG_KASAN_SW_TAGS */
> -
> -static inline void kasan_init_sw_tags(void) { }
> +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline void *kasan_reset_tag(const void *addr)
>  {
>         return (void *)addr;
>  }
>
> -#endif /* CONFIG_KASAN_SW_TAGS */
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +void __init kasan_init_sw_tags(void);
> +#else
> +static inline void kasan_init_sw_tags(void) { }
> +#endif
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void kasan_init_hw_tags_cpu(void);
> +void kasan_init_hw_tags(void);
> +#else
> +static inline void kasan_init_hw_tags_cpu(void) { }
> +static inline void kasan_init_hw_tags(void) { }
> +#endif
>
>  #ifdef CONFIG_KASAN_VMALLOC
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index db6ae4d3fb4e..0793d03a4183 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1413,7 +1413,7 @@ static inline bool cpupid_match_pid(struct task_str=
uct *task, int cpupid)
>  }
>  #endif /* CONFIG_NUMA_BALANCING */
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
>         return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags=
-layout.h
> index e200eef6a7fd..7d4ec26d8a3e 100644
> --- a/include/linux/page-flags-layout.h
> +++ b/include/linux/page-flags-layout.h
> @@ -77,7 +77,7 @@
>  #define LAST_CPUPID_SHIFT 0
>  #endif
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  #define KASAN_TAG_WIDTH 8
>  #else
>  #define KASAN_TAG_WIDTH 0
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index f1d68a34f3c9..9fe39a66388a 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -10,8 +10,10 @@ CFLAGS_REMOVE_init.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report_generic.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_hw_tags.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report_sw_tags.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_shadow.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_hw_tags.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_sw_tags.o =3D $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_sto=
re1
> @@ -27,10 +29,13 @@ CFLAGS_init.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report_generic.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_hw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report_sw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_shadow.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_hw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>
>  obj-$(CONFIG_KASAN) :=3D common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o shado=
w.o quarantine.o
> +obj-$(CONFIG_KASAN_HW_TAGS) +=3D hw_tags.o report_hw_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o report_sw_tags.o shadow.o sw_tag=
s.o
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d0b3ff410b0c..2bb0ef6da6bd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -113,7 +113,7 @@ void kasan_free_pages(struct page *page, unsigned int=
 order)
>   */
>  static inline unsigned int optimal_redzone(unsigned int object_size)
>  {
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 return 0;
>
>         return
> @@ -178,14 +178,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache=
)
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>                                         const void *object)
>  {
> -       return (void *)object + cache->kasan_info.alloc_meta_offset;
> +       return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_o=
ffset;
>  }
>
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>                                       const void *object)
>  {
>         BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> -       return (void *)object + cache->kasan_info.free_meta_offset;
> +       return (void *)reset_tag(object) + cache->kasan_info.free_meta_of=
fset;
>  }
>
>  void kasan_poison_slab(struct page *page)
> @@ -267,9 +267,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_c=
ache *cache,
>         alloc_info =3D get_alloc_info(cache, object);
>         __memset(alloc_info, 0, sizeof(*alloc_info));
>
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -               object =3D set_tag(object,
> -                               assign_tag(cache, object, true, false));
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_H=
W_TAGS))
> +               object =3D set_tag(object, assign_tag(cache, object, true=
, false));
>
>         return (void *)object;
>  }
> @@ -337,10 +336,10 @@ static void *__kasan_kmalloc(struct kmem_cache *cac=
he, const void *object,
>         redzone_end =3D round_up((unsigned long)object + cache->object_si=
ze,
>                                 KASAN_GRANULE_SIZE);
>
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_H=
W_TAGS))
>                 tag =3D assign_tag(cache, object, false, keep_tag);
>
> -       /* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> +       /* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
>         kasan_unpoison_memory(set_tag(object, tag), size);
>         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_=
start,
>                 KASAN_KMALLOC_REDZONE);
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> new file mode 100644
> index 000000000000..0080b78ec843
> --- /dev/null
> +++ b/mm/kasan/hw_tags.c
> @@ -0,0 +1,80 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains core hardware tag-based KASAN code.
> + *
> + * Copyright (c) 2020 Google, Inc.
> + * Author: Andrey Konovalov <andreyknvl@google.com>
> + */
> +
> +#define pr_fmt(fmt) "kasan: " fmt
> +
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +
> +#include "kasan.h"
> +
> +/* kasan_init_hw_tags_cpu() is called for each CPU. */
> +void kasan_init_hw_tags_cpu(void)
> +{
> +       hw_init_tags(KASAN_TAG_MAX);
> +       hw_enable_tagging();
> +}
> +
> +/* kasan_init_hw_tags() is called once on boot CPU. */
> +void kasan_init_hw_tags(void)
> +{
> +       pr_info("KernelAddressSanitizer initialized\n");
> +}
> +
> +void *kasan_reset_tag(const void *addr)
> +{
> +       return reset_tag(addr);
> +}
> +
> +void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +       hw_set_mem_tag_range(reset_tag(address),
> +                       round_up(size, KASAN_GRANULE_SIZE), value);
> +}
> +
> +void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +       hw_set_mem_tag_range(reset_tag(address),
> +                       round_up(size, KASAN_GRANULE_SIZE), get_tag(addre=
ss));
> +}
> +
> +u8 random_tag(void)
> +{
> +       return hw_get_random_tag();
> +}
> +
> +bool check_invalid_free(void *addr)
> +{
> +       u8 ptr_tag =3D get_tag(addr);
> +       u8 mem_tag =3D hw_get_mem_tag(addr);
> +
> +       return (mem_tag =3D=3D KASAN_TAG_INVALID) ||
> +               (ptr_tag !=3D KASAN_TAG_KERNEL && ptr_tag !=3D mem_tag);
> +}
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta =3D get_alloc_info(cache, object);
> +       kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta =3D get_alloc_info(cache, object);
> +       return &alloc_meta->free_track[0];
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d745a78745dd..21fe75c66f26 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,6 +153,10 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_=
cache *cache,
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>                                         const void *object);
>
> +void kasan_poison_memory(const void *address, size_t size, u8 value);
> +
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>         return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET=
)
> @@ -164,8 +168,6 @@ static inline bool addr_has_metadata(const void *addr=
)
>         return (addr >=3D kasan_shadow_to_mem((void *)KASAN_SHADOW_START)=
);
>  }
>
> -void kasan_poison_memory(const void *address, size_t size, u8 value);
> -
>  /**
>   * check_memory_region - Check memory region, and report if invalid acce=
ss.
>   * @addr: the accessed address
> @@ -177,6 +179,15 @@ void kasan_poison_memory(const void *address, size_t=
 size, u8 value);
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip);
>
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline bool addr_has_metadata(const void *addr)
> +{
> +       return true;
> +}
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
>  bool check_invalid_free(void *addr);
>
>  void *find_first_bad_addr(void *addr, size_t size);
> @@ -213,7 +224,7 @@ static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
>  void print_tags(u8 addr_tag, const void *addr);
>
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> new file mode 100644
> index 000000000000..da543eb832cd
> --- /dev/null
> +++ b/mm/kasan/report_hw_tags.c
> @@ -0,0 +1,42 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains hardware tag-based KASAN specific error reporting =
code.
> + *
> + * Copyright (c) 2020 Google, Inc.
> + * Author: Andrey Konovalov <andreyknvl@google.com>
> + */
> +
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +
> +#include "kasan.h"
> +
> +const char *get_bug_type(struct kasan_access_info *info)
> +{
> +       return "invalid-access";
> +}
> +
> +void *find_first_bad_addr(void *addr, size_t size)
> +{
> +       return reset_tag(addr);
> +}
> +
> +void metadata_fetch_row(char *buffer, void *row)
> +{
> +       int i;
> +
> +       for (i =3D 0; i < META_BYTES_PER_ROW; i++)
> +               buffer[i] =3D hw_get_mem_tag(row + i * KASAN_GRANULE_SIZE=
);
> +}
> +
> +void print_tags(u8 addr_tag, const void *addr)
> +{
> +       u8 memory_tag =3D hw_get_mem_tag((void *)addr);
> +
> +       pr_err("Pointer tag: [%02x], memory tag: [%02x]\n",
> +               addr_tag, memory_tag);
> +}
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index add2dfe6169c..aebc44a29e83 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains tag-based KASAN specific error reporting code.
> + * This file contains software tag-based KASAN specific error reporting =
code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 1fadd4930d54..616ac64c4a21 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -107,7 +107,7 @@ void kasan_unpoison_memory(const void *address, size_=
t size)
>
>                 if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                         *shadow =3D tag;
> -               else
> +               else /* CONFIG_KASAN_GENERIC */
>                         *shadow =3D size & KASAN_GRANULE_MASK;
>         }
>  }
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index b09a2c06abad..dfe707dd8d0d 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains core tag-based KASAN code.
> + * This file contains core software tag-based KASAN code.
>   *
>   * Copyright (c) 2018 Google, Inc.
>   * Author: Andrey Konovalov <andreyknvl@google.com>
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXOWPVX%2BMuysqu_u0w4o_rpyb%2BXuUZW2%2BpC9T6WG_3-iw%40mai=
l.gmail.com.
