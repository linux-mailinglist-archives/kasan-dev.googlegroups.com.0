Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBMVKYSVQMGQENI64GEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 42792807D5F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 01:43:32 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-db3ef4c7094sf552608276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 16:43:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701909811; cv=pass;
        d=google.com; s=arc-20160816;
        b=X8T40p2VC9nbgIcSnaVyNq8Ll00a99qKsKrRNN6vseIuC/R/p/te3h7DjKHpIMzK6H
         yZ7VIy4d2pBqXd6Kn2IcPKj5CffkSLphak4xsStYCLhN7QoB5JCAQ2RXdmzpgHCoFruG
         gbYXEGwTAU6E1+SQE/j3NeN6efVtPw/FZ+yB7TMURKwLLma8/YvNK+mPG4Ol2AxoB2lg
         UAgAQ9+quw6vrPFZTC2zDG6UhpND6ijyRV2ekEGmWVeo+19hGaCME3LvHuRPIL7osxP8
         o9I6hVysWVwjWDugh9KXMe8WmiwdTbRv/gtIL1UBKs621+3OS0dMSZ/X+/lqhS9sDExO
         yOZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=tfH25SPW6/Pu2IOQ3I9O8o66ZsgfZJnIeHKpM7sZUPc=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=007M2tNm/YvgxwD+t5aKGhZ6O4gYll/dQ05co87qbks8lUnFnyEYGxejfupv7ylL9x
         UIDJ1BDemiS6SkXFcD8y0u8w7sRmBmxyFZ0kliz0LycJbIBNRR+uOrSdkct9tT7u5mKg
         udwOm4Vk0a+w07gefugQJIGNlyTSTYBWeqhFMpxrkdaFc0bB7CboceFZvie5ZWMd/paA
         WByNDMfICylbTkgPS0Y/5emzbp8orOa/R+u4sYBlN0LjyMzw4AabHjU31Jbbb0Mc1ksD
         nlCN0FwTmMV++5VpDqdUPvf822Ve3e/S79kcRa1LtMeORQdTxr7D4c4YWeYUTmh5cqi8
         WNUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BI6J2IqD;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701909811; x=1702514611; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tfH25SPW6/Pu2IOQ3I9O8o66ZsgfZJnIeHKpM7sZUPc=;
        b=ZZZOsWTSe0NrpPHvZxsiXQdijcRel7ThvhPrI1rHF61lrZhSdve9tu132UZPvrAYAF
         EGsOG0mrYtceRmPjYvUSA+OJ0qi4pLbUi2h/EsCd+bPedVEXlxdzyFpki+WNaVk0Ogfj
         bO8FTfLYcwLt+rfNcMSNmvu7KGvSKhUu1OpvP4I8pf4hDf8Ff9gHWcGspQq0IsY3kP7g
         6hjkmJ5gWHEYrRzS7qukaHhhdEXLPbyELaG59a3AyCUK/QexTi+4v6pvxv3G/kpD+JmI
         AMCPzpbEXktC6GqkDsA+XU3ApTaAZxYMi9Odt7nKsupsnfiNluCWU/yfoZi4lBHwzote
         2vNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701909811; x=1702514611; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tfH25SPW6/Pu2IOQ3I9O8o66ZsgfZJnIeHKpM7sZUPc=;
        b=FEkpT9eLPhDeCArrKPDzAHRfVo+FaiYFaRiOhN8gL/gKahGvsmVpnczj5dPCKxQRNT
         XpxvlVAYJGB727GHYDZIG7Kuh0CLrvx02gRkxsb+RzWBhERevixy2OSDee9/fBt+HO1e
         45h/fUHx232slmmomrmg29IWueBXRe4qU/Ss8se3boBDLhVCj37qFgwGDdSts/54TXiu
         G/3B4eQTKq/xS1/Ambkn/oT56UsbxvXrNDJt4Q2QdIwf/gMLjS/jyiUL0ZZ13B9M/T8Y
         iAFQ6er0eAqsL4eWSaFVdeoo2kU8039dNaJ8hD7StV0JfaqEWOdF00uPF3f+ELH9NRdX
         crqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701909811; x=1702514611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tfH25SPW6/Pu2IOQ3I9O8o66ZsgfZJnIeHKpM7sZUPc=;
        b=SIoGDvQbRIQMEcw0OxA5GW8Eq1uVYBrBjJ58kriAghN4QI8Hi0k57hrcpi3C8High0
         thJyApNiDiXG4Y11G75dvvDRzttcutOcW/kUoWkoZMO/iOjfD5DAV3srEz8R8dWXPVpv
         d6pP7NYboI7LciKE//2W3FdozLzih15cy5+wMysIkGdOo7qbSb9x295hIzWr97CWLnaM
         gz/Q3BERqgM1u3QmZg3bVPLTA7zpjQkUdqhCNmPwOp7IqluIraFOnJkJfkkOKbn305gy
         cVFzn0iOMp6Da/kGaoU7uY4ecszQGci3YQn5CPSlj5XKJ8PbjnWcZv0RK56epcCnIHP1
         GrkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwYhjqXCIFLEnyG2RJf4Lmff3pkIVDsBjFR8WY4kPwmHgASBah9
	ZYVMs73RKJYaDXIbnqd/F6A=
X-Google-Smtp-Source: AGHT+IH3jfnjFiv1QUnEIWGLrDB7vfTUXhlAMMzNmvrgnS1xaLmNnPIcQUvT0suLUlff1mgW5NcMVw==
X-Received: by 2002:a25:868e:0:b0:db4:af02:6626 with SMTP id z14-20020a25868e000000b00db4af026626mr1649338ybk.29.1701909810926;
        Wed, 06 Dec 2023 16:43:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8602:0:b0:d9c:b193:bdf4 with SMTP id y2-20020a258602000000b00d9cb193bdf4ls143462ybk.1.-pod-prod-04-us;
 Wed, 06 Dec 2023 16:43:30 -0800 (PST)
X-Received: by 2002:a25:bd89:0:b0:db7:dacf:5a0d with SMTP id f9-20020a25bd89000000b00db7dacf5a0dmr1444693ybh.129.1701909810096;
        Wed, 06 Dec 2023 16:43:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701909810; cv=none;
        d=google.com; s=arc-20160816;
        b=CVitqh7X0uPuXmVHws4CcopGDq1UAMnl1gfBxso50H5zAQv8kVoZHnZc0LKv1amWr0
         /zHeaCcZWt14smWD6MmTcL8efzLxCra+6R1DMj1bDHlIVaactw/v3+QIJ9sa4Y5Lwwfl
         TQCKjs0JEjxlUVsHFpXybnd1BUuVrYoc6x/gpK1+sfRhLbyVmD2f2XJr1ePuetZhaO5+
         zl/41bo+dkOM6qAihInMo4o8baJNetpNEAS2Iy54YL5VPCUpKiNJzOxnriEGgAB6tRm7
         hHml2AdBos4oKELuUIJIlLwf1Hb7rVj7t8rxVDrxRQWwcKnFJRAYCHMjmfz6C2T6tkoJ
         UwSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eh9CtMoBA+zmGvG+NMP6SS+GUAPZn7ZW9r8sCwWKZF8=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=Bz9xrP/5J3tKEQB69IofBdJnKeA+KDt9CNh05nMBfR9xo9XVzlq7haS5CjHWA/rwEr
         dyi4Kfq9K9XfnPOh57CMAqedhJA6QMMS6mj1YC2wGXAL5X051/RkqCCYdz+LQYHYVt4b
         jwjgC76pwwRrKvE4fE36pXhhxXbapCQKqvVn/hPMhw00hoqNcwz5XZJVsuMguJM/DR7q
         IX42piSemX7X06InHDhL2s8OlRvx5ues9p0YzJDnffgGtsU6E+s7EiL2Uwao66DUJoRc
         NOOfHLbj0PPzZJgZWvJgRLf4G66an4H308pm8up2BPOYvgaejZV0OzbiqN8jcQaBPuh9
         /uew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BI6J2IqD;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id e8-20020ad44428000000b0065afd3576a7si12710qvt.3.2023.12.06.16.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 16:43:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-6ce831cbba6so79357b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 16:43:30 -0800 (PST)
X-Received: by 2002:a05:6a20:2449:b0:18a:de88:e0d with SMTP id t9-20020a056a20244900b0018ade880e0dmr1780832pzc.15.1701909808906;
        Wed, 06 Dec 2023 16:43:28 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id p12-20020a170902e74c00b001cf7bd9ade5sm63977plf.3.2023.12.06.16.43.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 16:43:28 -0800 (PST)
Date: Thu, 7 Dec 2023 09:43:04 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 13/21] mm/slab: move pre/post-alloc hooks from slab.h
 to slub.c
Message-ID: <ZXEVGNxKTNC6v5NR@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-13-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-13-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BI6J2IqD;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Mon, Nov 20, 2023 at 07:34:24PM +0100, Vlastimil Babka wrote:
> We don't share the hooks between two slab implementations anymore so
> they can be moved away from the header. As part of the move, also move
> should_failslab() from slab_common.c as the pre_alloc hook uses it.
> This means slab.h can stop including fault-inject.h and kmemleak.h.
> Fix up some files that were depending on the includes transitively.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/kasan/report.c |  1 +
>  mm/memcontrol.c   |  1 +
>  mm/slab.h         | 72 -------------------------------------------------
>  mm/slab_common.c  |  8 +-----
>  mm/slub.c         | 81 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
>  5 files changed, 84 insertions(+), 79 deletions(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e77facb62900..011f727bfaff 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -23,6 +23,7 @@
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> +#include <linux/vmalloc.h>
>  #include <linux/kasan.h>
>  #include <linux/module.h>
>  #include <linux/sched/task_stack.h>
> diff --git a/mm/memcontrol.c b/mm/memcontrol.c
> index 947fb50eba31..8a0603517065 100644
> --- a/mm/memcontrol.c
> +++ b/mm/memcontrol.c
> @@ -64,6 +64,7 @@
>  #include <linux/psi.h>
>  #include <linux/seq_buf.h>
>  #include <linux/sched/isolation.h>
> +#include <linux/kmemleak.h>
>  #include "internal.h"
>  #include <net/sock.h>
>  #include <net/ip.h>
> diff --git a/mm/slab.h b/mm/slab.h
> index 1ac3a2f8d4c0..65ebf86b3fe9 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -9,8 +9,6 @@
>  #include <linux/kobject.h>
>  #include <linux/sched/mm.h>
>  #include <linux/memcontrol.h>
> -#include <linux/fault-inject.h>
> -#include <linux/kmemleak.h>
>  #include <linux/kfence.h>
>  #include <linux/kasan.h>
>  
> @@ -796,76 +794,6 @@ static inline size_t slab_ksize(const struct kmem_cache *s)
>  	return s->size;
>  }
>  
> -static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> -						     struct list_lru *lru,
> -						     struct obj_cgroup **objcgp,
> -						     size_t size, gfp_t flags)
> -{
> -	flags &= gfp_allowed_mask;
> -
> -	might_alloc(flags);
> -
> -	if (should_failslab(s, flags))
> -		return NULL;
> -
> -	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
> -		return NULL;
> -
> -	return s;
> -}
> -
> -static inline void slab_post_alloc_hook(struct kmem_cache *s,
> -					struct obj_cgroup *objcg, gfp_t flags,
> -					size_t size, void **p, bool init,
> -					unsigned int orig_size)
> -{
> -	unsigned int zero_size = s->object_size;
> -	bool kasan_init = init;
> -	size_t i;
> -
> -	flags &= gfp_allowed_mask;
> -
> -	/*
> -	 * For kmalloc object, the allocated memory size(object_size) is likely
> -	 * larger than the requested size(orig_size). If redzone check is
> -	 * enabled for the extra space, don't zero it, as it will be redzoned
> -	 * soon. The redzone operation for this extra space could be seen as a
> -	 * replacement of current poisoning under certain debug option, and
> -	 * won't break other sanity checks.
> -	 */
> -	if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
> -	    (s->flags & SLAB_KMALLOC))
> -		zero_size = orig_size;
> -
> -	/*
> -	 * When slub_debug is enabled, avoid memory initialization integrated
> -	 * into KASAN and instead zero out the memory via the memset below with
> -	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
> -	 * cause false-positive reports. This does not lead to a performance
> -	 * penalty on production builds, as slub_debug is not intended to be
> -	 * enabled there.
> -	 */
> -	if (__slub_debug_enabled())
> -		kasan_init = false;
> -
> -	/*
> -	 * As memory initialization might be integrated into KASAN,
> -	 * kasan_slab_alloc and initialization memset must be
> -	 * kept together to avoid discrepancies in behavior.
> -	 *
> -	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
> -	 */
> -	for (i = 0; i < size; i++) {
> -		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
> -		if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
> -			memset(p[i], 0, zero_size);
> -		kmemleak_alloc_recursive(p[i], s->object_size, 1,
> -					 s->flags, flags);
> -		kmsan_slab_alloc(s, p[i], flags);
> -	}
> -
> -	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> -}
>  
>  /*
>   * The slab lists for all objects.
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 63b8411db7ce..bbc2e3f061f1 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -21,6 +21,7 @@
>  #include <linux/swiotlb.h>
>  #include <linux/proc_fs.h>
>  #include <linux/debugfs.h>
> +#include <linux/kmemleak.h>
>  #include <linux/kasan.h>
>  #include <asm/cacheflush.h>
>  #include <asm/tlbflush.h>
> @@ -1470,10 +1471,3 @@ EXPORT_TRACEPOINT_SYMBOL(kmem_cache_alloc);
>  EXPORT_TRACEPOINT_SYMBOL(kfree);
>  EXPORT_TRACEPOINT_SYMBOL(kmem_cache_free);
>  
> -int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
> -{
> -	if (__should_failslab(s, gfpflags))
> -		return -ENOMEM;
> -	return 0;
> -}
> -ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
> diff --git a/mm/slub.c b/mm/slub.c
> index 979932d046fd..9eb6508152c2 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -34,6 +34,7 @@
>  #include <linux/memory.h>
>  #include <linux/math64.h>
>  #include <linux/fault-inject.h>
> +#include <linux/kmemleak.h>
>  #include <linux/stacktrace.h>
>  #include <linux/prefetch.h>
>  #include <linux/memcontrol.h>
> @@ -3494,6 +3495,86 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
>  			0, sizeof(void *));
>  }
>  
> +noinline int should_failslab(struct kmem_cache *s, gfp_t gfpflags)
> +{
> +	if (__should_failslab(s, gfpflags))
> +		return -ENOMEM;
> +	return 0;
> +}
> +ALLOW_ERROR_INJECTION(should_failslab, ERRNO);
> +
> +static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> +						     struct list_lru *lru,
> +						     struct obj_cgroup **objcgp,
> +						     size_t size, gfp_t flags)
> +{
> +	flags &= gfp_allowed_mask;
> +
> +	might_alloc(flags);
> +
> +	if (should_failslab(s, flags))
> +		return NULL;
> +
> +	if (!memcg_slab_pre_alloc_hook(s, lru, objcgp, size, flags))
> +		return NULL;
> +
> +	return s;
> +}
> +
> +static inline void slab_post_alloc_hook(struct kmem_cache *s,
> +					struct obj_cgroup *objcg, gfp_t flags,
> +					size_t size, void **p, bool init,
> +					unsigned int orig_size)
> +{
> +	unsigned int zero_size = s->object_size;
> +	bool kasan_init = init;
> +	size_t i;
> +
> +	flags &= gfp_allowed_mask;
> +
> +	/*
> +	 * For kmalloc object, the allocated memory size(object_size) is likely
> +	 * larger than the requested size(orig_size). If redzone check is
> +	 * enabled for the extra space, don't zero it, as it will be redzoned
> +	 * soon. The redzone operation for this extra space could be seen as a
> +	 * replacement of current poisoning under certain debug option, and
> +	 * won't break other sanity checks.
> +	 */
> +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE) &&
> +	    (s->flags & SLAB_KMALLOC))
> +		zero_size = orig_size;
> +
> +	/*
> +	 * When slub_debug is enabled, avoid memory initialization integrated
> +	 * into KASAN and instead zero out the memory via the memset below with
> +	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
> +	 * cause false-positive reports. This does not lead to a performance
> +	 * penalty on production builds, as slub_debug is not intended to be
> +	 * enabled there.
> +	 */
> +	if (__slub_debug_enabled())
> +		kasan_init = false;
> +
> +	/*
> +	 * As memory initialization might be integrated into KASAN,
> +	 * kasan_slab_alloc and initialization memset must be
> +	 * kept together to avoid discrepancies in behavior.
> +	 *
> +	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
> +	 */
> +	for (i = 0; i < size; i++) {
> +		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
> +		if (p[i] && init && (!kasan_init ||
> +				     !kasan_has_integrated_init()))
> +			memset(p[i], 0, zero_size);
> +		kmemleak_alloc_recursive(p[i], s->object_size, 1,
> +					 s->flags, flags);
> +		kmsan_slab_alloc(s, p[i], flags);
> +	}
> +
> +	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> +}
> +
>  /*
>   * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
>   * have the fastpath folded into their functions. So no function call
> 
> -- 

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEVGNxKTNC6v5NR%40localhost.localdomain.
