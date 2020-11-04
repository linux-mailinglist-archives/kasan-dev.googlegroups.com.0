Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV73RT6QKGQES3SSSIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 036182A7238
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:48:40 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id h31sf97900qtd.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:48:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604533719; cv=pass;
        d=google.com; s=arc-20160816;
        b=siVB5XRcfHaSrBz3aHD8cahy3U7AoCY7TffZJ/egQj+c7e2+3P8lnb+KtLaQybb4aR
         qs1qeQIM7i+5OBClBYZqxO5QfSftocXivSZzlKqeDyyy8HL5KwzH8y67xD6ipbmjtEQB
         P/xiT3NklTxY4kwAftgxnQ42fByjXNWzL+veXy0F5+ruqIWwg8fIQPh8TgCajXxAVIXg
         E6CGCyl5Rmai3SH5822wpfrdXIuqgBtySPfLHKKfDPnacyckPPOP4vpFUUGCy4REdCb7
         /S6Bseqsm8Rbv0bIHomi1f8+LlxceV/oRPbhIq2skCVpAkYc4CCmFq7Rk9zVdFDBvqFu
         HQPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HecghKs0FKFPqtNldf1J6be0UxQfHnfoelYKGlbWdtA=;
        b=GpIUlTqxjzNWjOprOApBUEiYvSASXNsR4MbLeeHAftQU8ygPj1JrVAwxAwVyGhFDRE
         kATphi4vNCW+k50WF4mZLFao+foZiNSYRnqrgt+89qRBJ9RBV6A0nLo6HARNW0R9+JSL
         RgF0w1TzPXSuvgej+lIyEtzoNAiC1EGOecNGDFK6rrWBDYGwxOlbwPVBePp4FoQ3btEF
         bHNN8MR345xAj2mRl7cZrACdCfqQJx6nfsxTMeTtv22uGjubqTPNSI1ThLlHOxQNHI41
         WNg8y9s6MNTwmTHhnkjQe50pHIkFVlkX7+49/+FAk90f+bU9KX1U3TBqOs4pfxhSR149
         2OOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sK1NO5++;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HecghKs0FKFPqtNldf1J6be0UxQfHnfoelYKGlbWdtA=;
        b=jGX2p+lowusnSPjtlPXZ5L+xfl6xHj9kldUVbVA6GMUfVXKYajjQGw+yxGtqdb7Pqs
         VwFCPE71gH3fRm+W84zopaGwoiexsghJvjQuhqZ0ZGs7knkSIvn2nnge7cgL9IMbdPI2
         lpnZhTnO/VuMtnvzMLTzU1jS7W9GDucLap3PiMuSa1MW9hLZrSMCIzGjyXjs5XOpS28n
         hpmhHntbmn7IBWb8eOATuu+Hi1G0f0Yc0xmtoJ0THbPzgQESwS4yOWMC4P15IiGR9whZ
         cno87Vx9rdHbWzBYuUDNztTnczy/S8HJWcro/+iWYPccqBMgwmUfHt2aNKDJFSJ9aQ7R
         m7sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HecghKs0FKFPqtNldf1J6be0UxQfHnfoelYKGlbWdtA=;
        b=YOGqxFGMZP0HWuzMypZBxXsXr4a4ppX4RbwYpZVoi0Yt0celbz+GKYvtsRKUe8dfUY
         GNLcOS00D+P+GfFAnIVOWr/jwsQKfjWIKXMTfDyZjgcOEVk5hVNOVI8GMweFAZ73OvoY
         WETMVvxouZ/7WvA9y8zPYkePkjx2DfPBmbxIeGlctmaAt02Le6JY8bxLXeaxpINgw1Dj
         ja9WUaTNxXamLjfri6kE3XJzhlcbq8Wc6ZprdvwY4Nd9N4PDwGD2Qnf7rpDyOlnAqQEl
         UAozo0i63cRUSxwaqidalUlvOREZS+o4gIrhMhmGv2CmZpAA6clMiL2fldrN4I47LeLL
         Bqog==
X-Gm-Message-State: AOAM532HasOYatcy0GFIuLRZFF1eazIld3DSy93OiCyXsUgSVH6uL9Py
	aLVDgNTanYYjxdvuB7Jz2eM=
X-Google-Smtp-Source: ABdhPJxaKmLdnDQAgeD54Sv4C5GBqR5MXN2UCS3I2fQ1uYNId/2265Wdn4M4fKoZtgludFXo7ug3XQ==
X-Received: by 2002:ac8:4cc1:: with SMTP id l1mr571467qtv.128.1604533719095;
        Wed, 04 Nov 2020 15:48:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1248:: with SMTP id a8ls2114264qkl.11.gmail; Wed,
 04 Nov 2020 15:48:38 -0800 (PST)
X-Received: by 2002:a37:a990:: with SMTP id s138mr678031qke.113.1604533718667;
        Wed, 04 Nov 2020 15:48:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604533718; cv=none;
        d=google.com; s=arc-20160816;
        b=ak+GuO2S1wWHfTvDT/UllGRqrZWwsucqdXFhmzL17uXxAIkR2AR4Zj7CW2zoydoe27
         yl9d+7c6XOY0G5/Wbaf8LyX1PcGgmUgS7d67Nup+EJjL60bjQ7xQz9L2wLb3kFxjYkjA
         jXNd/FHo1hbg7zTl/pu78o1pY2u/K/LBb+/BG5tRBBR5QDbbEc9q5HS7ec7TKZ3JWR/K
         XpG4oYLq43usamLfLjolF9IlNQsXb3qSXjLq6GqNalfXdZXNup8Zd5arwwIlBXPDwfIC
         n6fzbEdDVviYZxDnhK062aftEDTqiZzoS4bsitV69H9LKZNPs+JDR2kAQlROsVu/zt/i
         yRGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wp+w8b4AFAXGjQKKBQtaL9VCmaHHu9rnir4s+oQgV0I=;
        b=RofEsVrX/QPXCWg2doOduoT7tKB92wc2lNq/o9d8WtmhIGpyJoTEdDH7LjRb5fQ8+m
         lZxwEO/1Zj/kYFowjt25H+gFZxQDtWNpp95dLaPwNFhWkzeGgFlBRvIRTuR57swPNLQy
         wIobXFwsfjfQh59YY02uM57b4dew0cyDubknI1XJNG5RBYNuCY+zlgtkFVdCib8DeCr6
         Ag22YvAjMmtjYsIB3ywqHqqx1ZU5/F/Pbcgy5QMEm8lHv44bX6ICMRHPC4CYK01OYjjg
         aeEmQc+Jg3KjdzewB1/z0GOQFj5VALFcOeUd61hcpmLyjcs91dGAqfPgEme1gAO2LTCZ
         NnrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sK1NO5++;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id 18si209187qkk.2.2020.11.04.15.48.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:48:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id 133so18667029pfx.11
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:48:38 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr332535pjz.136.1604533717527;
 Wed, 04 Nov 2020 15:48:37 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <9b0c00ddb76e15cdcd86e12f85ce4f8a5e946299.1604531793.git.andreyknvl@google.com>
In-Reply-To: <9b0c00ddb76e15cdcd86e12f85ce4f8a5e946299.1604531793.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 00:48:26 +0100
Message-ID: <CAAeHK+w=6v4AUPvd6jNEqkUAcUwkGFVZaH7C3==9_wrP54NY9g@mail.gmail.com>
Subject: Re: [PATCH v8 38/43] kasan, arm64: implement HW_TAGS runtime
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sK1NO5++;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Nov 5, 2020 at 12:20 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Provide implementation of KASAN functions required for the hardware
> tag-based mode. Those include core functions for memory and pointer
> tagging (tags_hw.c) and bug reporting (report_tags_hw.c). Also adapt
> common KASAN code to support the new mode.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
> Change-Id: I8a8689ba098174a4d0ef3f1d008178387c80ee1c
> ---
>  arch/arm64/include/asm/memory.h   |  4 +-
>  arch/arm64/kernel/cpufeature.c    |  3 ++
>  include/linux/kasan.h             | 22 ++++++---
>  include/linux/mm.h                |  2 +-
>  include/linux/page-flags-layout.h |  2 +-
>  mm/kasan/Makefile                 |  5 ++
>  mm/kasan/common.c                 | 15 +++---
>  mm/kasan/hw_tags.c                | 76 +++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h                  | 17 +++++--
>  mm/kasan/report_hw_tags.c         | 42 +++++++++++++++++
>  mm/kasan/report_sw_tags.c         |  2 +-
>  mm/kasan/shadow.c                 |  2 +-
>  mm/kasan/sw_tags.c                |  2 +-
>  13 files changed, 169 insertions(+), 25 deletions(-)
>  create mode 100644 mm/kasan/hw_tags.c
>  create mode 100644 mm/kasan/report_hw_tags.c
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 507012ed24f4..b245554984a2 100644
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
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index dcc165b3fc04..b66a96525a3e 100644
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
> @@ -1704,6 +1705,8 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>                 cleared_zero_page = true;
>                 mte_clear_page_tags(lm_alias(empty_zero_page));
>         }
> +
> +       kasan_init_hw_tags();
>  }
>  #endif /* CONFIG_ARM64_MTE */
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index beb699e90e55..c6bf762eb88c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -187,25 +187,33 @@ static inline void kasan_record_aux_stack(void *ptr) {}
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
> +void __init kasan_init_hw_tags(void);
> +#else
> +static inline void kasan_init_hw_tags(void) { }
> +#endif
>
>  #ifdef CONFIG_KASAN_VMALLOC
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index db6ae4d3fb4e..0793d03a4183 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1413,7 +1413,7 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
>  }
>  #endif /* CONFIG_NUMA_BALANCING */
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
>         return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
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
> @@ -10,8 +10,10 @@ CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_hw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report_sw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_hw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_sw_tags.o = $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
> @@ -27,10 +29,13 @@ CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>
>  obj-$(CONFIG_KASAN) := common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
> +obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d0b3ff410b0c..2bb0ef6da6bd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -113,7 +113,7 @@ void kasan_free_pages(struct page *page, unsigned int order)
>   */
>  static inline unsigned int optimal_redzone(unsigned int object_size)
>  {
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +       if (!IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 return 0;
>
>         return
> @@ -178,14 +178,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>                                         const void *object)
>  {
> -       return (void *)object + cache->kasan_info.alloc_meta_offset;
> +       return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>                                       const void *object)
>  {
>         BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> -       return (void *)object + cache->kasan_info.free_meta_offset;
> +       return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>
>  void kasan_poison_slab(struct page *page)
> @@ -267,9 +267,8 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>         alloc_info = get_alloc_info(cache, object);
>         __memset(alloc_info, 0, sizeof(*alloc_info));
>
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -               object = set_tag(object,
> -                               assign_tag(cache, object, true, false));
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +               object = set_tag(object, assign_tag(cache, object, true, false));
>
>         return (void *)object;
>  }
> @@ -337,10 +336,10 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         redzone_end = round_up((unsigned long)object + cache->object_size,
>                                 KASAN_GRANULE_SIZE);
>
> -       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>                 tag = assign_tag(cache, object, false, keep_tag);
>
> -       /* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> +       /* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
>         kasan_unpoison_memory(set_tag(object, tag), size);
>         kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>                 KASAN_KMALLOC_REDZONE);
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> new file mode 100644
> index 000000000000..bdb684c65561
> --- /dev/null
> +++ b/mm/kasan/hw_tags.c
> @@ -0,0 +1,76 @@
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
> +/* kasan_init_hw_tags() is called for each CPU. */
> +void __init kasan_init_hw_tags(void)

This should not be __init, forgot to include this change.

> +{
> +       hw_init_tags(KASAN_TAG_MAX);
> +
> +       if (smp_processor_id() == 0)
> +               pr_info("KernelAddressSanitizer initialized\n");
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
> +                       round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +}
> +
> +u8 random_tag(void)
> +{
> +       return hw_get_random_tag();
> +}
> +
> +bool check_invalid_free(void *addr)
> +{
> +       u8 ptr_tag = get_tag(addr);
> +       u8 mem_tag = hw_get_mem_tag(addr);
> +
> +       return (mem_tag == KASAN_TAG_INVALID) ||
> +               (ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> +}
> +
> +void kasan_set_free_info(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = get_alloc_info(cache, object);
> +       kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +                               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +
> +       alloc_meta = get_alloc_info(cache, object);
> +       return &alloc_meta->free_track[0];
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 618e69d12f61..b0a57d8f9803 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,6 +153,10 @@ struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>  struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>                                         const void *object);
>
> +void kasan_poison_memory(const void *address, size_t size, u8 value);
> +
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>         return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
> @@ -164,8 +168,6 @@ static inline bool addr_has_metadata(const void *addr)
>         return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
>  }
>
> -void kasan_poison_memory(const void *address, size_t size, u8 value);
> -
>  /**
>   * check_memory_region - Check memory region, and report if invalid access.
>   * @addr: the accessed address
> @@ -177,6 +179,15 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip);
>
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline bool addr_has_metadata(const void *addr)
> +{
> +       return PageSlab(virt_to_head_page(addr));
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
> + * This file contains hardware tag-based KASAN specific error reporting code.
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
> +       for (i = 0; i < META_BYTES_PER_ROW; i++)
> +               buffer[i] = hw_get_mem_tag(row + i * KASAN_GRANULE_SIZE);
> +}
> +
> +void print_tags(u8 addr_tag, const void *addr)
> +{
> +       u8 memory_tag = hw_get_mem_tag((void *)addr);
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
> + * This file contains software tag-based KASAN specific error reporting code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 1fadd4930d54..616ac64c4a21 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -107,7 +107,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
>
>                 if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
>                         *shadow = tag;
> -               else
> +               else /* CONFIG_KASAN_GENERIC */
>                         *shadow = size & KASAN_GRANULE_MASK;
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
> 2.29.1.341.ge80a0c044ae-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw%3D6v4AUPvd6jNEqkUAcUwkGFVZaH7C3%3D%3D9_wrP54NY9g%40mail.gmail.com.
