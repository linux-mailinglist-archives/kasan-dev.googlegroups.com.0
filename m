Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVF3D5QKGQEBRKL5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E79D280549
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:32:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id c204sf1116903wmd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:32:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573563; cv=pass;
        d=google.com; s=arc-20160816;
        b=v1EpjqYi8l5ICtX1BAv0MI3Sn/emY6d4/YFaHcdLlehXpmEl+VW2n1G6zhmGO4i2Wq
         1l2FLG63BnK1trf92bpkrk9STbUr6+LnUzIwjQEMD8suroKj6/F5cFG5tfDNijpj9Jd4
         RJnDsRqoJ5DC4nT9u/LTyB30UHTmvvnQECBrQ63k1ugkLIZ+vqZ0ZgM6d2SQ0ky9pOgI
         xkTQhammVKouCgHbC5nwO79YF5t0I9PD6CcJrN7jamR6Mrt0Y9mlIdYo8S9CnO2+AuC6
         7JIe5eMfUZkLnvi26EE+pbXqoJlWL7LYlIocVce4XK4YodFiqQ5PK7fRuDh7K29W1FOg
         RElw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2olkGOV/A/3x7lJpJonDhPMvOtkGknAGrk7LvixVwG4=;
        b=n6EHyGAF/XrnyKqE+L/ba+Bm9TV1b87eR8l5X8WBulGhL7XUWSzafsrH2Yf88meVRd
         /ByQmUtW47MymlljutZO/PROD2JcW2MHASmmZidm/vJse3j7HYFVMGZnKCTyaVSqSj5k
         VZR+ahrT9qWxh7JOf7jiA7sTJt+SO61LhcI66yv4XBlyPNR+mrwUDmraNajxEAJpfKhV
         1NoPMa5rQGPArYonh6y8ZKUIY6APHdYQV2WGL+0qLAnnsEiFODkoJ2aMJJqHPm8R06E4
         e0VgqcUAOa4wMnmdCZuK1foE8BRBws6mICZj3qF/Acfkw0lq9qmaDZtnP4mlhKh+mr0K
         JQcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rk1t1RHK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2olkGOV/A/3x7lJpJonDhPMvOtkGknAGrk7LvixVwG4=;
        b=jnHTUuDfkcs6WNwO4vOhRwC3XndMSNW6cqLMdrbzkgZCZBgPyooVq2Ht3Q+1HS4lLo
         RJFoF4aPpk6EK/cmjjqiUy8P53za1GqL0ZBCH3lh+rL5Z8fwYD1Tit7wNt2fDysNIuzx
         DBk0q5AvKHKPFoHTAwwNKYKhXtzx0U+8JQdbximT4Ko63VLo9xFaJ+zpucevgOwhHMeQ
         pnzuDVbLskrX8ziWQjyvCl6C6RDJd4qrPnpMbvx53NWx8LgFS7zVwlPHPvtxqJSqDD2s
         QFwAV6rchNxfpLtulZLE6KoauFvcH0v2vIAgyN2Qp7KKrevksQZS0FnJo9SH1QuLDCuJ
         Arqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2olkGOV/A/3x7lJpJonDhPMvOtkGknAGrk7LvixVwG4=;
        b=hflnAunrUaR0SnEAigTDZvisVQgrW8JslyEv1EZTXhleu5Jge7HJePmtlkzPnAwTEH
         ALs2PNPRJx7G0iGGQQXWnBEINzugnIYvfOPQK3Cepk6DFzdmaKeZZSXK6mBQXzSC8JPY
         iE9f08qRV683/uSLSqmk+WhQ0n7Xkrwy/Jj+zS8rEC1qNihQYCfwrNjksTavZwWAcJOJ
         PZxZyjsGXa/7DbJXf4pRM5ln/YLzJZH3rGh06bpZz03Jn5d2i3ib76s96lCRoID6j4II
         05t2JqLWpnRaK9ZnSOEMCDy3DvzFtq6xMyaosCBrjZudPLVsnnDVY9SgimpAwFht4D6G
         /wew==
X-Gm-Message-State: AOAM532iY+k/obsnxUomsukW9o5sK0Cn9mdKE8K6kzpkllpgdC++xfBv
	nLXc47vwGwMBd6hnfgmEC5o=
X-Google-Smtp-Source: ABdhPJxyLOl+VCIZDo5fucTwR63dO6sS9DMtv3bngiFahqatFd3ZF8HLfh+KL4/XakbW3n8aRCCf+A==
X-Received: by 2002:a7b:c397:: with SMTP id s23mr1145642wmj.174.1601573562996;
        Thu, 01 Oct 2020 10:32:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls1936338wrx.3.gmail; Thu, 01
 Oct 2020 10:32:42 -0700 (PDT)
X-Received: by 2002:adf:f5c7:: with SMTP id k7mr10680158wrp.246.1601573562004;
        Thu, 01 Oct 2020 10:32:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573562; cv=none;
        d=google.com; s=arc-20160816;
        b=Smg/gQ8M9RYB5IQjFX00ZEnR0xzbZKmYXT0GB4bD2BuSaDI64z3kcFddX2tsAM3Sk2
         q2fRVQNjXPkrWj8pfPfKzLY6mHm/ue0HAuY9YRLT8pXD8PPzvzC1bGbKzeiDoBaU16UU
         4tNc18m0FfpVQR+yr7HcEwDCX3olDUj6p51RRqEVS5K+8asOGRH5/kb6ca8Iwzd2Cm98
         pDd+E1kC43p4sGLnXuElvUO4KSrzlRIyBUna2UXVw6GQkR2jglf+5RwHex3i165+RntN
         6tWIWOZh62oea15VnC9ahdyqo/AZfLDh1BYgO6xY1QkKZBDvIkfCs2b8Spb4VPCY+Ffm
         Ammg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yx30PaLVI32eUDk7snFoKh7wyJHQAS6KdwOanI+u4DI=;
        b=QYEOgTljInc6qoVfEhbSFqZadDDValws6iCkLUaZV4IyRjc7as5/6LAR1arUYgHD/5
         EtDgOAHVr5wN0EpiN7iBp3+b7EoBaeALzNZsKds+5b17Kok6eFGSRQE9F9ImMMCcEWyW
         8LN0efDNGWG2Szd2qhiXJDbprMHn+Cr3BVYQD57Zsxv8XKKyAWo6NMR8EgDIBEG3tbbn
         dce0uVMponOWM5C84jx2H1hdX4EctbqTmhQh/ah9YdkA1AZofzf/YadBpBJit+fByGzu
         ljAuN+hxh4CppO4kGuni51OI190U5dB2Om3FSoue0thpAXZ9XcLihCoq/0BuF4T3gt1Z
         u4ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rk1t1RHK;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id w2si132595wrr.5.2020.10.01.10.32.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:32:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id z1so6761170wrt.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:32:41 -0700 (PDT)
X-Received: by 2002:adf:f78c:: with SMTP id q12mr10385819wrp.6.1601573561224;
        Thu, 01 Oct 2020 10:32:41 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id h8sm9758239wrw.68.2020.10.01.10.32.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:32:40 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:32:34 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 08/39] kasan: split out shadow.c from common.c
Message-ID: <20201001173234.GF4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <abe5a7455189ebd8ba8306d011776507d45c2cec.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <abe5a7455189ebd8ba8306d011776507d45c2cec.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Rk1t1RHK;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> The new mode won't be using shadow memory. Move all shadow-related code
> to shadow.c, which is only enabled for software KASAN modes that use
> shadow memory.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Ic1c32ce72d4649848e9e6a1f2c8dd269c77673f2
> ---
>  mm/kasan/Makefile |   6 +-
>  mm/kasan/common.c | 486 +-------------------------------------------
>  mm/kasan/shadow.c | 505 ++++++++++++++++++++++++++++++++++++++++++++++
>  3 files changed, 510 insertions(+), 487 deletions(-)
>  create mode 100644 mm/kasan/shadow.c
> 
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7cf685bb51bd..7cc1031e1ef8 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -10,6 +10,7 @@ CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
>  
> @@ -26,9 +27,10 @@ CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  
>  obj-$(CONFIG_KASAN) := common.o report.o
> -obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
> -obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
> +obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o shadow.o quarantine.o
> +obj-$(CONFIG_KASAN_SW_TAGS) += init.o shadow.o tags.o tags_report.o
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index f65c9f792f8f..123abfb760d4 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains common generic and tag-based KASAN code.
> + * This file contains common KASAN code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> @@ -13,7 +13,6 @@
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> -#include <linux/kmemleak.h>
>  #include <linux/linkage.h>
>  #include <linux/memblock.h>
>  #include <linux/memory.h>
> @@ -26,12 +25,8 @@
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> -#include <linux/vmalloc.h>
>  #include <linux/bug.h>
>  
> -#include <asm/cacheflush.h>
> -#include <asm/tlbflush.h>
> -
>  #include "kasan.h"
>  #include "../slab.h"
>  
> @@ -61,93 +56,6 @@ void kasan_disable_current(void)
>  	current->kasan_depth--;
>  }
>  
> -bool __kasan_check_read(const volatile void *p, unsigned int size)
> -{
> -	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
> -}
> -EXPORT_SYMBOL(__kasan_check_read);
> -
> -bool __kasan_check_write(const volatile void *p, unsigned int size)
> -{
> -	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
> -}
> -EXPORT_SYMBOL(__kasan_check_write);
> -
> -#undef memset
> -void *memset(void *addr, int c, size_t len)
> -{
> -	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> -		return NULL;
> -
> -	return __memset(addr, c, len);
> -}
> -
> -#ifdef __HAVE_ARCH_MEMMOVE
> -#undef memmove
> -void *memmove(void *dest, const void *src, size_t len)
> -{
> -	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> -	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> -		return NULL;
> -
> -	return __memmove(dest, src, len);
> -}
> -#endif
> -
> -#undef memcpy
> -void *memcpy(void *dest, const void *src, size_t len)
> -{
> -	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> -	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> -		return NULL;
> -
> -	return __memcpy(dest, src, len);
> -}
> -
> -/*
> - * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> - * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
> - */
> -void kasan_poison_memory(const void *address, size_t size, u8 value)
> -{
> -	void *shadow_start, *shadow_end;
> -
> -	/*
> -	 * Perform shadow offset calculation based on untagged address, as
> -	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
> -	 * addresses to this function.
> -	 */
> -	address = reset_tag(address);
> -
> -	shadow_start = kasan_mem_to_shadow(address);
> -	shadow_end = kasan_mem_to_shadow(address + size);
> -
> -	__memset(shadow_start, value, shadow_end - shadow_start);
> -}
> -
> -void kasan_unpoison_memory(const void *address, size_t size)
> -{
> -	u8 tag = get_tag(address);
> -
> -	/*
> -	 * Perform shadow offset calculation based on untagged address, as
> -	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
> -	 * addresses to this function.
> -	 */
> -	address = reset_tag(address);
> -
> -	kasan_poison_memory(address, size, tag);
> -
> -	if (size & KASAN_GRANULE_MASK) {
> -		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> -
> -		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -			*shadow = tag;
> -		else
> -			*shadow = size & KASAN_GRANULE_MASK;
> -	}
> -}
> -
>  static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
>  {
>  	void *base = task_stack_page(task);
> @@ -535,395 +443,3 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
>  		kasan_report_invalid_free(ptr, ip);
>  	/* The object will be poisoned by page_alloc. */
>  }
> -
> -#ifdef CONFIG_MEMORY_HOTPLUG
> -static bool shadow_mapped(unsigned long addr)
> -{
> -	pgd_t *pgd = pgd_offset_k(addr);
> -	p4d_t *p4d;
> -	pud_t *pud;
> -	pmd_t *pmd;
> -	pte_t *pte;
> -
> -	if (pgd_none(*pgd))
> -		return false;
> -	p4d = p4d_offset(pgd, addr);
> -	if (p4d_none(*p4d))
> -		return false;
> -	pud = pud_offset(p4d, addr);
> -	if (pud_none(*pud))
> -		return false;
> -
> -	/*
> -	 * We can't use pud_large() or pud_huge(), the first one is
> -	 * arch-specific, the last one depends on HUGETLB_PAGE.  So let's abuse
> -	 * pud_bad(), if pud is bad then it's bad because it's huge.
> -	 */
> -	if (pud_bad(*pud))
> -		return true;
> -	pmd = pmd_offset(pud, addr);
> -	if (pmd_none(*pmd))
> -		return false;
> -
> -	if (pmd_bad(*pmd))
> -		return true;
> -	pte = pte_offset_kernel(pmd, addr);
> -	return !pte_none(*pte);
> -}
> -
> -static int __meminit kasan_mem_notifier(struct notifier_block *nb,
> -			unsigned long action, void *data)
> -{
> -	struct memory_notify *mem_data = data;
> -	unsigned long nr_shadow_pages, start_kaddr, shadow_start;
> -	unsigned long shadow_end, shadow_size;
> -
> -	nr_shadow_pages = mem_data->nr_pages >> KASAN_SHADOW_SCALE_SHIFT;
> -	start_kaddr = (unsigned long)pfn_to_kaddr(mem_data->start_pfn);
> -	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)start_kaddr);
> -	shadow_size = nr_shadow_pages << PAGE_SHIFT;
> -	shadow_end = shadow_start + shadow_size;
> -
> -	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> -		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
> -		return NOTIFY_BAD;
> -
> -	switch (action) {
> -	case MEM_GOING_ONLINE: {
> -		void *ret;
> -
> -		/*
> -		 * If shadow is mapped already than it must have been mapped
> -		 * during the boot. This could happen if we onlining previously
> -		 * offlined memory.
> -		 */
> -		if (shadow_mapped(shadow_start))
> -			return NOTIFY_OK;
> -
> -		ret = __vmalloc_node_range(shadow_size, PAGE_SIZE, shadow_start,
> -					shadow_end, GFP_KERNEL,
> -					PAGE_KERNEL, VM_NO_GUARD,
> -					pfn_to_nid(mem_data->start_pfn),
> -					__builtin_return_address(0));
> -		if (!ret)
> -			return NOTIFY_BAD;
> -
> -		kmemleak_ignore(ret);
> -		return NOTIFY_OK;
> -	}
> -	case MEM_CANCEL_ONLINE:
> -	case MEM_OFFLINE: {
> -		struct vm_struct *vm;
> -
> -		/*
> -		 * shadow_start was either mapped during boot by kasan_init()
> -		 * or during memory online by __vmalloc_node_range().
> -		 * In the latter case we can use vfree() to free shadow.
> -		 * Non-NULL result of the find_vm_area() will tell us if
> -		 * that was the second case.
> -		 *
> -		 * Currently it's not possible to free shadow mapped
> -		 * during boot by kasan_init(). It's because the code
> -		 * to do that hasn't been written yet. So we'll just
> -		 * leak the memory.
> -		 */
> -		vm = find_vm_area((void *)shadow_start);
> -		if (vm)
> -			vfree((void *)shadow_start);
> -	}
> -	}
> -
> -	return NOTIFY_OK;
> -}
> -
> -static int __init kasan_memhotplug_init(void)
> -{
> -	hotplug_memory_notifier(kasan_mem_notifier, 0);
> -
> -	return 0;
> -}
> -
> -core_initcall(kasan_memhotplug_init);
> -#endif
> -
> -#ifdef CONFIG_KASAN_VMALLOC
> -
> -static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> -				      void *unused)
> -{
> -	unsigned long page;
> -	pte_t pte;
> -
> -	if (likely(!pte_none(*ptep)))
> -		return 0;
> -
> -	page = __get_free_page(GFP_KERNEL);
> -	if (!page)
> -		return -ENOMEM;
> -
> -	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> -	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> -
> -	spin_lock(&init_mm.page_table_lock);
> -	if (likely(pte_none(*ptep))) {
> -		set_pte_at(&init_mm, addr, ptep, pte);
> -		page = 0;
> -	}
> -	spin_unlock(&init_mm.page_table_lock);
> -	if (page)
> -		free_page(page);
> -	return 0;
> -}
> -
> -int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> -{
> -	unsigned long shadow_start, shadow_end;
> -	int ret;
> -
> -	if (!is_vmalloc_or_module_addr((void *)addr))
> -		return 0;
> -
> -	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> -	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> -	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> -
> -	ret = apply_to_page_range(&init_mm, shadow_start,
> -				  shadow_end - shadow_start,
> -				  kasan_populate_vmalloc_pte, NULL);
> -	if (ret)
> -		return ret;
> -
> -	flush_cache_vmap(shadow_start, shadow_end);
> -
> -	/*
> -	 * We need to be careful about inter-cpu effects here. Consider:
> -	 *
> -	 *   CPU#0				  CPU#1
> -	 * WRITE_ONCE(p, vmalloc(100));		while (x = READ_ONCE(p)) ;
> -	 *					p[99] = 1;
> -	 *
> -	 * With compiler instrumentation, that ends up looking like this:
> -	 *
> -	 *   CPU#0				  CPU#1
> -	 * // vmalloc() allocates memory
> -	 * // let a = area->addr
> -	 * // we reach kasan_populate_vmalloc
> -	 * // and call kasan_unpoison_memory:
> -	 * STORE shadow(a), unpoison_val
> -	 * ...
> -	 * STORE shadow(a+99), unpoison_val	x = LOAD p
> -	 * // rest of vmalloc process		<data dependency>
> -	 * STORE p, a				LOAD shadow(x+99)
> -	 *
> -	 * If there is no barrier between the end of unpoisioning the shadow
> -	 * and the store of the result to p, the stores could be committed
> -	 * in a different order by CPU#0, and CPU#1 could erroneously observe
> -	 * poison in the shadow.
> -	 *
> -	 * We need some sort of barrier between the stores.
> -	 *
> -	 * In the vmalloc() case, this is provided by a smp_wmb() in
> -	 * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
> -	 * get_vm_area() and friends, the caller gets shadow allocated but
> -	 * doesn't have any pages mapped into the virtual address space that
> -	 * has been reserved. Mapping those pages in will involve taking and
> -	 * releasing a page-table lock, which will provide the barrier.
> -	 */
> -
> -	return 0;
> -}
> -
> -/*
> - * Poison the shadow for a vmalloc region. Called as part of the
> - * freeing process at the time the region is freed.
> - */
> -void kasan_poison_vmalloc(const void *start, unsigned long size)
> -{
> -	if (!is_vmalloc_or_module_addr(start))
> -		return;
> -
> -	size = round_up(size, KASAN_GRANULE_SIZE);
> -	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
> -}
> -
> -void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> -{
> -	if (!is_vmalloc_or_module_addr(start))
> -		return;
> -
> -	kasan_unpoison_memory(start, size);
> -}
> -
> -static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> -					void *unused)
> -{
> -	unsigned long page;
> -
> -	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> -
> -	spin_lock(&init_mm.page_table_lock);
> -
> -	if (likely(!pte_none(*ptep))) {
> -		pte_clear(&init_mm, addr, ptep);
> -		free_page(page);
> -	}
> -	spin_unlock(&init_mm.page_table_lock);
> -
> -	return 0;
> -}
> -
> -/*
> - * Release the backing for the vmalloc region [start, end), which
> - * lies within the free region [free_region_start, free_region_end).
> - *
> - * This can be run lazily, long after the region was freed. It runs
> - * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
> - * infrastructure.
> - *
> - * How does this work?
> - * -------------------
> - *
> - * We have a region that is page aligned, labelled as A.
> - * That might not map onto the shadow in a way that is page-aligned:
> - *
> - *                    start                     end
> - *                    v                         v
> - * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
> - *  -------- -------- --------          -------- --------
> - *      |        |       |                 |        |
> - *      |        |       |         /-------/        |
> - *      \-------\|/------/         |/---------------/
> - *              |||                ||
> - *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
> - *                 (1)      (2)      (3)
> - *
> - * First we align the start upwards and the end downwards, so that the
> - * shadow of the region aligns with shadow page boundaries. In the
> - * example, this gives us the shadow page (2). This is the shadow entirely
> - * covered by this allocation.
> - *
> - * Then we have the tricky bits. We want to know if we can free the
> - * partially covered shadow pages - (1) and (3) in the example. For this,
> - * we are given the start and end of the free region that contains this
> - * allocation. Extending our previous example, we could have:
> - *
> - *  free_region_start                                    free_region_end
> - *  |                 start                     end      |
> - *  v                 v                         v        v
> - * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
> - *  -------- -------- --------          -------- --------
> - *      |        |       |                 |        |
> - *      |        |       |         /-------/        |
> - *      \-------\|/------/         |/---------------/
> - *              |||                ||
> - *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
> - *                 (1)      (2)      (3)
> - *
> - * Once again, we align the start of the free region up, and the end of
> - * the free region down so that the shadow is page aligned. So we can free
> - * page (1) - we know no allocation currently uses anything in that page,
> - * because all of it is in the vmalloc free region. But we cannot free
> - * page (3), because we can't be sure that the rest of it is unused.
> - *
> - * We only consider pages that contain part of the original region for
> - * freeing: we don't try to free other pages from the free region or we'd
> - * end up trying to free huge chunks of virtual address space.
> - *
> - * Concurrency
> - * -----------
> - *
> - * How do we know that we're not freeing a page that is simultaneously
> - * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
> - *
> - * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc running
> - * at the same time. While we run under free_vmap_area_lock, the population
> - * code does not.
> - *
> - * free_vmap_area_lock instead operates to ensure that the larger range
> - * [free_region_start, free_region_end) is safe: because __alloc_vmap_area and
> - * the per-cpu region-finding algorithm both run under free_vmap_area_lock,
> - * no space identified as free will become used while we are running. This
> - * means that so long as we are careful with alignment and only free shadow
> - * pages entirely covered by the free region, we will not run in to any
> - * trouble - any simultaneous allocations will be for disjoint regions.
> - */
> -void kasan_release_vmalloc(unsigned long start, unsigned long end,
> -			   unsigned long free_region_start,
> -			   unsigned long free_region_end)
> -{
> -	void *shadow_start, *shadow_end;
> -	unsigned long region_start, region_end;
> -	unsigned long size;
> -
> -	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -
> -	free_region_start = ALIGN(free_region_start,
> -				  PAGE_SIZE * KASAN_GRANULE_SIZE);
> -
> -	if (start != region_start &&
> -	    free_region_start < region_start)
> -		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
> -
> -	free_region_end = ALIGN_DOWN(free_region_end,
> -				     PAGE_SIZE * KASAN_GRANULE_SIZE);
> -
> -	if (end != region_end &&
> -	    free_region_end > region_end)
> -		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
> -
> -	shadow_start = kasan_mem_to_shadow((void *)region_start);
> -	shadow_end = kasan_mem_to_shadow((void *)region_end);
> -
> -	if (shadow_end > shadow_start) {
> -		size = shadow_end - shadow_start;
> -		apply_to_existing_page_range(&init_mm,
> -					     (unsigned long)shadow_start,
> -					     size, kasan_depopulate_vmalloc_pte,
> -					     NULL);
> -		flush_tlb_kernel_range((unsigned long)shadow_start,
> -				       (unsigned long)shadow_end);
> -	}
> -}
> -
> -#else /* CONFIG_KASAN_VMALLOC */
> -
> -int kasan_module_alloc(void *addr, size_t size)
> -{
> -	void *ret;
> -	size_t scaled_size;
> -	size_t shadow_size;
> -	unsigned long shadow_start;
> -
> -	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
> -	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
> -				KASAN_SHADOW_SCALE_SHIFT;
> -	shadow_size = round_up(scaled_size, PAGE_SIZE);
> -
> -	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> -		return -EINVAL;
> -
> -	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
> -			shadow_start + shadow_size,
> -			GFP_KERNEL,
> -			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> -			__builtin_return_address(0));
> -
> -	if (ret) {
> -		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -		find_vm_area(addr)->flags |= VM_KASAN;
> -		kmemleak_ignore(ret);
> -		return 0;
> -	}
> -
> -	return -ENOMEM;
> -}
> -
> -void kasan_free_shadow(const struct vm_struct *vm)
> -{
> -	if (vm->flags & VM_KASAN)
> -		vfree(kasan_mem_to_shadow(vm->addr));
> -}
> -
> -#endif
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> new file mode 100644
> index 000000000000..ca0cc4c31454
> --- /dev/null
> +++ b/mm/kasan/shadow.c
> @@ -0,0 +1,505 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains KASAN runtime code that manages shadow memory for
> + * generic and software tag-based KASAN modes.
> + *
> + * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> + * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> + *
> + * Some code borrowed from https://github.com/xairy/kasan-prototype by
> + *        Andrey Konovalov <andreyknvl@gmail.com>
> + */
> +
> +#include <linux/init.h>
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/kmemleak.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +#include <linux/vmalloc.h>
> +
> +#include <asm/cacheflush.h>
> +#include <asm/tlbflush.h>
> +
> +#include "kasan.h"
> +
> +bool __kasan_check_read(const volatile void *p, unsigned int size)
> +{
> +	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
> +}
> +EXPORT_SYMBOL(__kasan_check_read);
> +
> +bool __kasan_check_write(const volatile void *p, unsigned int size)
> +{
> +	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
> +}
> +EXPORT_SYMBOL(__kasan_check_write);
> +
> +#undef memset
> +void *memset(void *addr, int c, size_t len)
> +{
> +	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +		return NULL;
> +
> +	return __memset(addr, c, len);
> +}
> +
> +#ifdef __HAVE_ARCH_MEMMOVE
> +#undef memmove
> +void *memmove(void *dest, const void *src, size_t len)
> +{
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return NULL;
> +
> +	return __memmove(dest, src, len);
> +}
> +#endif
> +
> +#undef memcpy
> +void *memcpy(void *dest, const void *src, size_t len)
> +{
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +		return NULL;
> +
> +	return __memcpy(dest, src, len);
> +}
> +
> +/*
> + * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> + * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
> + */
> +void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +	void *shadow_start, *shadow_end;
> +
> +	/*
> +	 * Perform shadow offset calculation based on untagged address, as
> +	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
> +	 * addresses to this function.
> +	 */
> +	address = reset_tag(address);
> +
> +	shadow_start = kasan_mem_to_shadow(address);
> +	shadow_end = kasan_mem_to_shadow(address + size);
> +
> +	__memset(shadow_start, value, shadow_end - shadow_start);
> +}
> +
> +void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +	u8 tag = get_tag(address);
> +
> +	/*
> +	 * Perform shadow offset calculation based on untagged address, as
> +	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
> +	 * addresses to this function.
> +	 */
> +	address = reset_tag(address);
> +
> +	kasan_poison_memory(address, size, tag);
> +
> +	if (size & KASAN_GRANULE_MASK) {
> +		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> +
> +		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +			*shadow = tag;
> +		else
> +			*shadow = size & KASAN_GRANULE_MASK;
> +	}
> +}
> +
> +#ifdef CONFIG_MEMORY_HOTPLUG
> +static bool shadow_mapped(unsigned long addr)
> +{
> +	pgd_t *pgd = pgd_offset_k(addr);
> +	p4d_t *p4d;
> +	pud_t *pud;
> +	pmd_t *pmd;
> +	pte_t *pte;
> +
> +	if (pgd_none(*pgd))
> +		return false;
> +	p4d = p4d_offset(pgd, addr);
> +	if (p4d_none(*p4d))
> +		return false;
> +	pud = pud_offset(p4d, addr);
> +	if (pud_none(*pud))
> +		return false;
> +
> +	/*
> +	 * We can't use pud_large() or pud_huge(), the first one is
> +	 * arch-specific, the last one depends on HUGETLB_PAGE.  So let's abuse
> +	 * pud_bad(), if pud is bad then it's bad because it's huge.
> +	 */
> +	if (pud_bad(*pud))
> +		return true;
> +	pmd = pmd_offset(pud, addr);
> +	if (pmd_none(*pmd))
> +		return false;
> +
> +	if (pmd_bad(*pmd))
> +		return true;
> +	pte = pte_offset_kernel(pmd, addr);
> +	return !pte_none(*pte);
> +}
> +
> +static int __meminit kasan_mem_notifier(struct notifier_block *nb,
> +			unsigned long action, void *data)
> +{
> +	struct memory_notify *mem_data = data;
> +	unsigned long nr_shadow_pages, start_kaddr, shadow_start;
> +	unsigned long shadow_end, shadow_size;
> +
> +	nr_shadow_pages = mem_data->nr_pages >> KASAN_SHADOW_SCALE_SHIFT;
> +	start_kaddr = (unsigned long)pfn_to_kaddr(mem_data->start_pfn);
> +	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)start_kaddr);
> +	shadow_size = nr_shadow_pages << PAGE_SHIFT;
> +	shadow_end = shadow_start + shadow_size;
> +
> +	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> +		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
> +		return NOTIFY_BAD;
> +
> +	switch (action) {
> +	case MEM_GOING_ONLINE: {
> +		void *ret;
> +
> +		/*
> +		 * If shadow is mapped already than it must have been mapped
> +		 * during the boot. This could happen if we onlining previously
> +		 * offlined memory.
> +		 */
> +		if (shadow_mapped(shadow_start))
> +			return NOTIFY_OK;
> +
> +		ret = __vmalloc_node_range(shadow_size, PAGE_SIZE, shadow_start,
> +					shadow_end, GFP_KERNEL,
> +					PAGE_KERNEL, VM_NO_GUARD,
> +					pfn_to_nid(mem_data->start_pfn),
> +					__builtin_return_address(0));
> +		if (!ret)
> +			return NOTIFY_BAD;
> +
> +		kmemleak_ignore(ret);
> +		return NOTIFY_OK;
> +	}
> +	case MEM_CANCEL_ONLINE:
> +	case MEM_OFFLINE: {
> +		struct vm_struct *vm;
> +
> +		/*
> +		 * shadow_start was either mapped during boot by kasan_init()
> +		 * or during memory online by __vmalloc_node_range().
> +		 * In the latter case we can use vfree() to free shadow.
> +		 * Non-NULL result of the find_vm_area() will tell us if
> +		 * that was the second case.
> +		 *
> +		 * Currently it's not possible to free shadow mapped
> +		 * during boot by kasan_init(). It's because the code
> +		 * to do that hasn't been written yet. So we'll just
> +		 * leak the memory.
> +		 */
> +		vm = find_vm_area((void *)shadow_start);
> +		if (vm)
> +			vfree((void *)shadow_start);
> +	}
> +	}
> +
> +	return NOTIFY_OK;
> +}
> +
> +static int __init kasan_memhotplug_init(void)
> +{
> +	hotplug_memory_notifier(kasan_mem_notifier, 0);
> +
> +	return 0;
> +}
> +
> +core_initcall(kasan_memhotplug_init);
> +#endif
> +
> +#ifdef CONFIG_KASAN_VMALLOC
> +
> +static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +				      void *unused)
> +{
> +	unsigned long page;
> +	pte_t pte;
> +
> +	if (likely(!pte_none(*ptep)))
> +		return 0;
> +
> +	page = __get_free_page(GFP_KERNEL);
> +	if (!page)
> +		return -ENOMEM;
> +
> +	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> +	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> +
> +	spin_lock(&init_mm.page_table_lock);
> +	if (likely(pte_none(*ptep))) {
> +		set_pte_at(&init_mm, addr, ptep, pte);
> +		page = 0;
> +	}
> +	spin_unlock(&init_mm.page_table_lock);
> +	if (page)
> +		free_page(page);
> +	return 0;
> +}
> +
> +int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> +{
> +	unsigned long shadow_start, shadow_end;
> +	int ret;
> +
> +	if (!is_vmalloc_or_module_addr((void *)addr))
> +		return 0;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> +	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> +	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +
> +	ret = apply_to_page_range(&init_mm, shadow_start,
> +				  shadow_end - shadow_start,
> +				  kasan_populate_vmalloc_pte, NULL);
> +	if (ret)
> +		return ret;
> +
> +	flush_cache_vmap(shadow_start, shadow_end);
> +
> +	/*
> +	 * We need to be careful about inter-cpu effects here. Consider:
> +	 *
> +	 *   CPU#0				  CPU#1
> +	 * WRITE_ONCE(p, vmalloc(100));		while (x = READ_ONCE(p)) ;
> +	 *					p[99] = 1;
> +	 *
> +	 * With compiler instrumentation, that ends up looking like this:
> +	 *
> +	 *   CPU#0				  CPU#1
> +	 * // vmalloc() allocates memory
> +	 * // let a = area->addr
> +	 * // we reach kasan_populate_vmalloc
> +	 * // and call kasan_unpoison_memory:
> +	 * STORE shadow(a), unpoison_val
> +	 * ...
> +	 * STORE shadow(a+99), unpoison_val	x = LOAD p
> +	 * // rest of vmalloc process		<data dependency>
> +	 * STORE p, a				LOAD shadow(x+99)
> +	 *
> +	 * If there is no barrier between the end of unpoisioning the shadow
> +	 * and the store of the result to p, the stores could be committed
> +	 * in a different order by CPU#0, and CPU#1 could erroneously observe
> +	 * poison in the shadow.
> +	 *
> +	 * We need some sort of barrier between the stores.
> +	 *
> +	 * In the vmalloc() case, this is provided by a smp_wmb() in
> +	 * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
> +	 * get_vm_area() and friends, the caller gets shadow allocated but
> +	 * doesn't have any pages mapped into the virtual address space that
> +	 * has been reserved. Mapping those pages in will involve taking and
> +	 * releasing a page-table lock, which will provide the barrier.
> +	 */
> +
> +	return 0;
> +}
> +
> +/*
> + * Poison the shadow for a vmalloc region. Called as part of the
> + * freeing process at the time the region is freed.
> + */
> +void kasan_poison_vmalloc(const void *start, unsigned long size)
> +{
> +	if (!is_vmalloc_or_module_addr(start))
> +		return;
> +
> +	size = round_up(size, KASAN_GRANULE_SIZE);
> +	kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
> +}
> +
> +void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> +{
> +	if (!is_vmalloc_or_module_addr(start))
> +		return;
> +
> +	kasan_unpoison_memory(start, size);
> +}
> +
> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +					void *unused)
> +{
> +	unsigned long page;
> +
> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> +
> +	spin_lock(&init_mm.page_table_lock);
> +
> +	if (likely(!pte_none(*ptep))) {
> +		pte_clear(&init_mm, addr, ptep);
> +		free_page(page);
> +	}
> +	spin_unlock(&init_mm.page_table_lock);
> +
> +	return 0;
> +}
> +
> +/*
> + * Release the backing for the vmalloc region [start, end), which
> + * lies within the free region [free_region_start, free_region_end).
> + *
> + * This can be run lazily, long after the region was freed. It runs
> + * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
> + * infrastructure.
> + *
> + * How does this work?
> + * -------------------
> + *
> + * We have a region that is page aligned, labelled as A.
> + * That might not map onto the shadow in a way that is page-aligned:
> + *
> + *                    start                     end
> + *                    v                         v
> + * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
> + *  -------- -------- --------          -------- --------
> + *      |        |       |                 |        |
> + *      |        |       |         /-------/        |
> + *      \-------\|/------/         |/---------------/
> + *              |||                ||
> + *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
> + *                 (1)      (2)      (3)
> + *
> + * First we align the start upwards and the end downwards, so that the
> + * shadow of the region aligns with shadow page boundaries. In the
> + * example, this gives us the shadow page (2). This is the shadow entirely
> + * covered by this allocation.
> + *
> + * Then we have the tricky bits. We want to know if we can free the
> + * partially covered shadow pages - (1) and (3) in the example. For this,
> + * we are given the start and end of the free region that contains this
> + * allocation. Extending our previous example, we could have:
> + *
> + *  free_region_start                                    free_region_end
> + *  |                 start                     end      |
> + *  v                 v                         v        v
> + * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
> + *  -------- -------- --------          -------- --------
> + *      |        |       |                 |        |
> + *      |        |       |         /-------/        |
> + *      \-------\|/------/         |/---------------/
> + *              |||                ||
> + *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
> + *                 (1)      (2)      (3)
> + *
> + * Once again, we align the start of the free region up, and the end of
> + * the free region down so that the shadow is page aligned. So we can free
> + * page (1) - we know no allocation currently uses anything in that page,
> + * because all of it is in the vmalloc free region. But we cannot free
> + * page (3), because we can't be sure that the rest of it is unused.
> + *
> + * We only consider pages that contain part of the original region for
> + * freeing: we don't try to free other pages from the free region or we'd
> + * end up trying to free huge chunks of virtual address space.
> + *
> + * Concurrency
> + * -----------
> + *
> + * How do we know that we're not freeing a page that is simultaneously
> + * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
> + *
> + * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc running
> + * at the same time. While we run under free_vmap_area_lock, the population
> + * code does not.
> + *
> + * free_vmap_area_lock instead operates to ensure that the larger range
> + * [free_region_start, free_region_end) is safe: because __alloc_vmap_area and
> + * the per-cpu region-finding algorithm both run under free_vmap_area_lock,
> + * no space identified as free will become used while we are running. This
> + * means that so long as we are careful with alignment and only free shadow
> + * pages entirely covered by the free region, we will not run in to any
> + * trouble - any simultaneous allocations will be for disjoint regions.
> + */
> +void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +			   unsigned long free_region_start,
> +			   unsigned long free_region_end)
> +{
> +	void *shadow_start, *shadow_end;
> +	unsigned long region_start, region_end;
> +	unsigned long size;
> +
> +	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +
> +	free_region_start = ALIGN(free_region_start,
> +				  PAGE_SIZE * KASAN_GRANULE_SIZE);
> +
> +	if (start != region_start &&
> +	    free_region_start < region_start)
> +		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
> +
> +	free_region_end = ALIGN_DOWN(free_region_end,
> +				     PAGE_SIZE * KASAN_GRANULE_SIZE);
> +
> +	if (end != region_end &&
> +	    free_region_end > region_end)
> +		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
> +
> +	shadow_start = kasan_mem_to_shadow((void *)region_start);
> +	shadow_end = kasan_mem_to_shadow((void *)region_end);
> +
> +	if (shadow_end > shadow_start) {
> +		size = shadow_end - shadow_start;
> +		apply_to_existing_page_range(&init_mm,
> +					     (unsigned long)shadow_start,
> +					     size, kasan_depopulate_vmalloc_pte,
> +					     NULL);
> +		flush_tlb_kernel_range((unsigned long)shadow_start,
> +				       (unsigned long)shadow_end);
> +	}
> +}
> +
> +#else /* CONFIG_KASAN_VMALLOC */
> +
> +int kasan_module_alloc(void *addr, size_t size)
> +{
> +	void *ret;
> +	size_t scaled_size;
> +	size_t shadow_size;
> +	unsigned long shadow_start;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
> +	scaled_size = (size + KASAN_GRANULE_SIZE - 1) >>
> +				KASAN_SHADOW_SCALE_SHIFT;
> +	shadow_size = round_up(scaled_size, PAGE_SIZE);
> +
> +	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> +		return -EINVAL;
> +
> +	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
> +			shadow_start + shadow_size,
> +			GFP_KERNEL,
> +			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> +			__builtin_return_address(0));
> +
> +	if (ret) {
> +		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
> +		find_vm_area(addr)->flags |= VM_KASAN;
> +		kmemleak_ignore(ret);
> +		return 0;
> +	}
> +
> +	return -ENOMEM;
> +}
> +
> +void kasan_free_shadow(const struct vm_struct *vm)
> +{
> +	if (vm->flags & VM_KASAN)
> +		vfree(kasan_mem_to_shadow(vm->addr));
> +}
> +
> +#endif
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001173234.GF4162920%40elver.google.com.
