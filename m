Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB46P3WGQMGQEVCSW7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 31D924730A0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 16:34:12 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id b15-20020aa7c6cf000000b003e7cf0f73dasf14230434eds.22
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 07:34:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639409652; cv=pass;
        d=google.com; s=arc-20160816;
        b=i2oF+hrL29B6RCmWPsrI9V8oesoB0Qudvs0chG8dwC7/PE9tfwUA8m9p4cMd5hO871
         N4iX7zf6UCN6fSJrcJWotWjE7hj1es1sem0nle/R1PCsFtd3v6Aac5JyZpR/3hpoPyS9
         7ChW1w38caIlp6qaDqLoKcXmiVii+1KkTMHQHL1HU2o7dUUfF8nSoP/cMaVKOGOa3dfQ
         n6l7Rsu5v4IEv86soHhpFWTglJ24xUpYz3wwjUafRkTtKcPo2uNqE2E9bToKRdW/bV0j
         SnL29S8zYdnhymq7NaNFwNiSzQAZHWbLJxs08yY++SDwQib+M8UfQzLbQzWQlQAnuFYS
         Qs3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=SRZaYBA+SbArFwHv2ezYH0BEZYagIjtzyiLfCMO+jaM=;
        b=tEmDSbHQm3hazXNE/uWDdtxenxPlqRh8FRZRo7Qz3iZ4GNFajjFHQ1yoCh+BtAKf26
         KgJ3iojAVVZf2Ch5Ls3d2SSrj/UryWnlEtGKuNATuHktVaJnXZ0IK2OfFiZ4HrVTDGSY
         RSBQgIsoy7B8ondPk19DCSKCPfxjfFucEZJorTZQohHUGKNPjfc7e5qCSFuOl9Pq1jbj
         Fcx45r39eElNXJPgn/UVIHo6XVZcvA4u0Tmzbo5jUOyan7TfjZZPas6/dAUwiRrCmAFf
         N4MprjtnxiruE3hZBaKITUh3BIrjiUADJNtFVcqsc/m763WNpQOz3Y3XRNlxM1FjVP1o
         231Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SRZaYBA+SbArFwHv2ezYH0BEZYagIjtzyiLfCMO+jaM=;
        b=k+FZnTOWop7RBcTfV84cdkbkaULnAv/mcTDLhGsPxB+4VjsLkw0TjtbPP3arNexJU7
         6BEqFXd3KmtuVJCOJGNn495Nh+oSQ7o9b2TdtvdrawOiq78w3uw0JrtXeiljIav50Vvz
         tmkFJIEt3jx7CDbYEeqNAls5umUCM8Ype9JT4T3euMxmBhaXnjL30tnI8dg1R3+IMWRT
         7x9DdzmEK/idJ6BaZm0DUYKw2IGjVpb8wmXwZSGsBx88z7dQN8CkYH2ZeG3HNmcsisoS
         vIMJJ23hS3nPm7RncUXzNNca2fo5cHjRF5KFqpWCZduZ0EnsaVd7oRvX0m3j2/+B+EsI
         I9IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SRZaYBA+SbArFwHv2ezYH0BEZYagIjtzyiLfCMO+jaM=;
        b=nFkBZ9cy9UcEon79zveWwovVZq45tRs/Z437zicSAGhdCElstDyIcHJoGZN2YeBBkk
         1RKtPcp7ez/H9g6C+pSZTixPm31uJ5bSiUS2SmOSZd8+Ay2li70zJjPRgJAorJJpHVnR
         Z1d4nEJd6bwf5uV+2btSUcXuVQsmUQnHW0VmMTpxrNQG2WBEIYiWvqpXGN+S6kZRFE5v
         T7R7j0glpa8DkE1gw8/IbByQXTPKwDgMVLvq5z84jOtvzk1IQNQ1M06Khl3zKPORc0K0
         +UzJESUqSXrZFdAcvWVzz0JNLxdUwdNJaqN5D5XAkreejCjUrZfwkvGJpcVOz8T7x7Ih
         RyGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532izodDt33HYIevFRnaICEx6vDHKz+7zO7eK3uRGeJYMYCpkViQ
	LBNQYr2WEXB4BY/VovMTayI=
X-Google-Smtp-Source: ABdhPJwYSHD8RFW72VQzfT5gJxFGK7ly4a1DRxjqdYn4ossvM4j0GlFiLE5ekzHBcBaZuvEioH5bSQ==
X-Received: by 2002:a17:907:3e25:: with SMTP id hp37mr44983905ejc.43.1639409651836;
        Mon, 13 Dec 2021 07:34:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd09:: with SMTP id i9ls1464941eds.3.gmail; Mon, 13 Dec
 2021 07:34:11 -0800 (PST)
X-Received: by 2002:aa7:c50b:: with SMTP id o11mr63151682edq.160.1639409650943;
        Mon, 13 Dec 2021 07:34:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639409650; cv=none;
        d=google.com; s=arc-20160816;
        b=SrtLD40F+Ggo0GRNXW7OwIN4Kdw5VIpw/WVeGNnNaTmcmLvtNSU8npdPpegt9eWRbX
         egkoWwf9NT7qFsOfKyU8qGCqzBme2aSQWQfimrlERJV8LXWuynd+JtI1f3vMPJkY8wAK
         oCCOU621KqX9Hp/w+vA/bbmjQV1FIu9ON8UtX5ICDIKsQnEeeYnx4k6WwSa0W3IwCjjf
         762CmNKfldiJagwz638vdjrTrA8OYsVprsSbrkK1VQFGgzWrTZ/52Y6Rx5ifwaoRhqDa
         9hNXNfQDrA8N7eQeiLPxT2rV3/z2oW3545QAEdV+ESQgCWcvM8/hUnYT4iyFCu3PFWj5
         dtfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=UdydYhrBaQJDgMrMQqhl20D1HAa9j2fRebHxIfPQ89A=;
        b=njoWa8fq9uxpfsJzXof2qdCz/PP0pmFUgGZzrv3hhQi+crcUtMCayfPdxWe2cUTWV+
         KWuI6Wp0LkUD2nh5pQQWaFDWdU8h75fI+7XwOQZMQj2nzvQzr5E+7Fo2wO9VIuf9iUrD
         WeJ/wzG7mmn3T/0sy+mTKCcpO96hrHMsBmB9LJrv4B4MwrJ0FGnQAHB23PpC7V+A7zM/
         nHQ6xa+/u5E4ttIwvM84NJmTDsCwztqfRkYGbPN7UuLQVVIAJOxwlfBPokSG8FHVhulP
         lCleC+cGlWVb3GI4cLbEjtge4wwP2/DnIfkQNBaSKFk+tqD6lxBHGCZT2lYimX8SiF6g
         STug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e10si721683edz.5.2021.12.13.07.34.10
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Dec 2021 07:34:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2A7FA1FB;
	Mon, 13 Dec 2021 07:34:10 -0800 (PST)
Received: from [10.0.0.183] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A20B13F73B;
	Mon, 13 Dec 2021 07:34:06 -0800 (PST)
Subject: Re: [PATCH v2 28/34] kasan, vmalloc: add vmalloc support to HW_TAGS
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 linux-arm-kernel@lists.infradead.org, Evgenii Stepanov <eugenis@google.com>,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
 <72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <b777d2d2-421c-8854-e895-988ddc4ff9a6@arm.com>
Date: Mon, 13 Dec 2021 15:34:00 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <72a8a7aa09eb279d7eabf7ea1101556d13360950.1638825394.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On 12/6/21 9:44 PM, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> This patch adds vmalloc tagging support to HW_TAGS KASAN.
> 

Can we reorganize the patch description in line with what I commented on patch 24?

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
>  			   unsigned long free_region_start,
>  			   unsigned long free_region_end);
>  
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline void kasan_populate_early_vm_area_shadow(void *start,
> +						       unsigned long size)
> +{ }
> +static inline int kasan_populate_vmalloc(unsigned long start,
> +					unsigned long size)
> +{
> +	return 0;
> +}
> +static inline void kasan_release_vmalloc(unsigned long start,
> +					 unsigned long end,
> +					 unsigned long free_region_start,
> +					 unsigned long free_region_end) { }
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
>  void * __must_check __kasan_unpoison_vmalloc(const void *start,
> -					     unsigned long size);
> +					     unsigned long size,
> +					     bool vm_alloc, bool init);
>  static __always_inline void * __must_check kasan_unpoison_vmalloc(
> -					const void *start, unsigned long size)
> +					const void *start, unsigned long size,
> +					bool vm_alloc, bool init)

Can we replace booleans with enumerations? It should make the code clearer on
the calling site.

...

With these changes:

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

---

Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b777d2d2-421c-8854-e895-988ddc4ff9a6%40arm.com.
