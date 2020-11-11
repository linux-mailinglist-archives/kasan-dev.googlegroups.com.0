Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNOWD6QKGQE45XFKFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B99112AF6FC
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:55:01 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id o13sf1098933ljp.7
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605113701; cv=pass;
        d=google.com; s=arc-20160816;
        b=MlShHmN/ZXCxFzgNtyr8a3TE38hfBaa6o8lRJ0BY7qfIIgclBZ11ayKoTgIZ7uPvSS
         7HDAoFN61M94WJVsCEk9OoJTT9Q0D+U01dENUIZrnYs5v/EA4vwrkdjabKiIcNQCAb4Q
         MSP7Bx7zTd6rgFVIjFUoQ2FPiBHfoFsN5RNTD55juzN90CAgYErxE2YWYx4vlQ/px6en
         eMwBE0YLxl25mIPXdjMVx2tUbEcnOeqbvDJwrI9LmMRqYu5Sqd2luBo1/cfzsUNqEQV6
         llDoMtDUr/HBdGhQeL6FImx7rOaNyHOI7D3QqwidDfkex2oBs/iJYRwOUPV4JvxEbvVJ
         o0gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NF1jJ/Wb+7xK2xFp98QWK783yVeOyx8fOMPvosQohoo=;
        b=oFHrJgTkGIu/F2hDLJV+GlYpQ2dXzBrFYD4IdW4Lz4ynDlGSeS8DccSVKZLr4S2VkE
         2IOnOB620fKEXbTYwnK5kxnUraCaPKcPP0wtlVFK/kVADn4MiyuqaDwnLmQavMpiHsho
         NZYO/ZNuGj1N1lBR/0W3a7/ekPIZh6ToP14jhO/0fxCWjUZFLztL+6aPlwM089/it0MB
         8uSvCPDvEbZffOcsApPOip3TXq3D9DIpUnUzdHZ2GIf0ZEy5qwhlg0a6fdstlZ8fzvo5
         iT93wkEB/enWmJCCNv5cLTQCffYYhRXthFtcyz4PB06qFkIcSCExpNpZCbOXeiP+v7HB
         xrxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nmgpixr7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=NF1jJ/Wb+7xK2xFp98QWK783yVeOyx8fOMPvosQohoo=;
        b=miUOlTC6ZVdsK/l3kohWVIVh6x9IcRAyqxDVaJ5Bd9KzymBH6diCN/C3AZqcM51+yI
         KW2uM0Ni/7dWQVCDlhaQwaAXLUiZvuXAEPFz2HnlXryrHI9JMK6/RIXOQr8c8yBj2++H
         PoscAa+phSAbGO7H3IQ3DIHhgwZnQ0z+WoRXGOT+TixYVx29eWsIhMKKcRGpDRZF1DGw
         E53ybCWs2UotqvYlsHgIV38rmFpbT0QLQWgvYiqo9YoRa03PDificBRdwKQCoiDGlnCm
         yFu51INEYldNtW3VB4FHx65meOcU0aXbrBj9j3wxw1axKtxPpBlxzBcIT5k4EKqEZ4E7
         bfPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NF1jJ/Wb+7xK2xFp98QWK783yVeOyx8fOMPvosQohoo=;
        b=nXbKV1vUYo+VlkLD2G2LTAwRYZOX+XSkCPTRjt6BmMB427OlN+UbvI4mCAP7bJ0nVG
         JC0TJaz49wHTUtB+8ANkCzkbr6bSaQU9cSdiAhPqwPQ9xIEUizcgQ2Z2nc6jXeh+U+6z
         J+I+tiktxHXLBN985rGitcUQ1PZXi12Sh5M1ldJt+gdi56/ksgORZuIpPjg212//pkCe
         510pJ9dLldd1UkfCZQpgr0g/g0qxxGvfn1OUfE8GKlNEZE23FmYR5GtKL/n7sM62i/wL
         prFPyUCSsz+BtJTUbxLV2+nVbwV1Dh/bq/078+QVH1VWAhFiH85qFbYPXaGpYaWqMl5h
         cDmg==
X-Gm-Message-State: AOAM530RzUdPqq+zAnuETFPKSK40Jr+cunjjMbOS0N/6yIbpicx7mRKA
	MwnoIVbfO1JJYkeNFJEXMCs=
X-Google-Smtp-Source: ABdhPJzFAdwNV0xE/H97cJHyc3VowtgualoBYB9cY8oTuH0AfXY6Chy91OSnJCB9meqW/t5al4w3cw==
X-Received: by 2002:a05:651c:1198:: with SMTP id w24mr11529513ljo.383.1605113701248;
        Wed, 11 Nov 2020 08:55:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls92970lfg.3.gmail; Wed, 11 Nov
 2020 08:55:00 -0800 (PST)
X-Received: by 2002:ac2:48b2:: with SMTP id u18mr6879134lfg.313.1605113700004;
        Wed, 11 Nov 2020 08:55:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605113699; cv=none;
        d=google.com; s=arc-20160816;
        b=DtxduDAy8Papaqvct3syiQrXbjGRohTFE6lgbyXTSBEeyFKFCxHwMGH2ISGGNpzWET
         9pnE/fUM7trcJzewba7aSprntcapLtoy7fW0izmzPJSlckw6hHCdTyuYAx1qTCCn/0da
         qOqa/x2rL7rpzADZq4Fz+n8Ocx4UsMw48wy0Vrhxz0mG36VBEZZBSrAQ3Xauyn4CuTL0
         7UhbhHT806uBvy9dsCOaGxgWLL2/GR29q/C9WdJ8N5S+GEzdlJFGu7VllTyOW4XEO29y
         xzBfML5qqzZZnsJIkkbEw2qoT7xxbeHEk8jkqEEkTyeoXVAbs7EIiIhBVgzv4x5J3uz6
         9HNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OrzYDM8svlnj5hHY+u0nDuLQxqJ3IUm9fI7fqLn+JR4=;
        b=gN9IhEBadheVH2YhTNg8GvUD0bLcEuXbMUyvkhrYywUqfq/fm8sIDqbKWNdQMQH76Q
         EmLT8psQEz9ruH/PaNRIfg9OcBNerhEEKgvDgEPfprN38FX6KV33zlt93Vje6u8nl4+y
         nPCpCYQ/jg/kDvnUTAsV5FjnEu5BY+jA/3oZbyAz7xyjkR2DdZ9Es1hFXBJMh2BFMvCT
         n8R5HfPdrGHC8hC57HHJwuzPrg0qacqUfG9TAyyQjIXHGAokKNrpTCBWtqJlGhKAbx0M
         41/pIVRhuzMEJdSSdhG+2cYL0VjTOBC1MdRtHJfN+UUpulYw1HllXm7YmjyR+dzyyKWt
         lkOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nmgpixr7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id i17si96153ljn.4.2020.11.11.08.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:54:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id l1so3177298wrb.9
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:54:59 -0800 (PST)
X-Received: by 2002:a5d:5651:: with SMTP id j17mr20421341wrw.221.1605113699452;
        Wed, 11 Nov 2020 08:54:59 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id v19sm3148470wmj.31.2020.11.11.08.54.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:54:58 -0800 (PST)
Date: Wed, 11 Nov 2020 17:54:53 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 07/20] kasan: inline kasan_reset_tag for tag-based
 modes
Message-ID: <20201111165453.GI517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <ceba8fba477518e5dc26b77bc395c264cd1e593a.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ceba8fba477518e5dc26b77bc395c264cd1e593a.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nmgpixr7;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Using kasan_reset_tag() currently results in a function call. As it's
> called quite often from the allocator code, this leads to a noticeable
> slowdown. Move it to include/linux/kasan.h and turn it into a static
> inline function. Also remove the now unneeded reset_tag() internal KASAN
> macro and use kasan_reset_tag() instead.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I4d2061acfe91d480a75df00b07c22d8494ef14b5
> ---
>  include/linux/kasan.h     | 5 ++++-
>  mm/kasan/common.c         | 6 +++---
>  mm/kasan/hw_tags.c        | 9 ++-------
>  mm/kasan/kasan.h          | 4 ----
>  mm/kasan/report.c         | 4 ++--
>  mm/kasan/report_hw_tags.c | 2 +-
>  mm/kasan/report_sw_tags.c | 4 ++--
>  mm/kasan/shadow.c         | 4 ++--
>  mm/kasan/sw_tags.c        | 9 ++-------
>  9 files changed, 18 insertions(+), 29 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b9b9db335d87..53c8e8b12fbc 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -193,7 +193,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>  
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  
> -void *kasan_reset_tag(const void *addr);
> +static inline void *kasan_reset_tag(const void *addr)
> +{
> +	return (void *)arch_kasan_reset_tag(addr);
> +}
>  
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 9008fc6b0810..a266b90636a1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -174,14 +174,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>  					      const void *object)
>  {
> -	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
> +	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>  
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>  					    const void *object)
>  {
>  	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> -	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
> +	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>  
>  void kasan_poison_slab(struct page *page)
> @@ -278,7 +278,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  
>  	tag = get_tag(object);
>  	tagged_object = object;
> -	object = reset_tag(object);
> +	object = kasan_reset_tag(object);
>  
>  	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
>  	    object)) {
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 70b88dd40cd8..49ea5f5c5643 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -30,20 +30,15 @@ void kasan_init_hw_tags(void)
>  	pr_info("KernelAddressSanitizer initialized\n");
>  }
>  
> -void *kasan_reset_tag(const void *addr)
> -{
> -	return reset_tag(addr);
> -}
> -
>  void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
> -	hw_set_mem_tag_range(reset_tag(address),
> +	hw_set_mem_tag_range(kasan_reset_tag(address),
>  			round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>  
>  void kasan_unpoison_memory(const void *address, size_t size)
>  {
> -	hw_set_mem_tag_range(reset_tag(address),
> +	hw_set_mem_tag_range(kasan_reset_tag(address),
>  			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index db8a7a508121..8a5501ef2339 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -246,15 +246,11 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  	return addr;
>  }
>  #endif
> -#ifndef arch_kasan_reset_tag
> -#define arch_kasan_reset_tag(addr)	((void *)(addr))
> -#endif
>  #ifndef arch_kasan_get_tag
>  #define arch_kasan_get_tag(addr)	0
>  #endif
>  
>  #define set_tag(addr, tag)	((void *)arch_kasan_set_tag((addr), (tag)))
> -#define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
>  #define get_tag(addr)		arch_kasan_get_tag(addr)
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0cac53a57c14..25ca66c99e48 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -328,7 +328,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>  	unsigned long flags;
>  	u8 tag = get_tag(object);
>  
> -	object = reset_tag(object);
> +	object = kasan_reset_tag(object);
>  
>  #if IS_ENABLED(CONFIG_KUNIT)
>  	if (current->kunit_test)
> @@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  	disable_trace_on_warning();
>  
>  	tagged_addr = (void *)addr;
> -	untagged_addr = reset_tag(tagged_addr);
> +	untagged_addr = kasan_reset_tag(tagged_addr);
>  
>  	info.access_addr = tagged_addr;
>  	if (addr_has_metadata(untagged_addr))
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index da543eb832cd..57114f0e14d1 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -22,7 +22,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  
>  void *find_first_bad_addr(void *addr, size_t size)
>  {
> -	return reset_tag(addr);
> +	return kasan_reset_tag(addr);
>  }
>  
>  void metadata_fetch_row(char *buffer, void *row)
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 317100fd95b9..7604b46239d4 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -41,7 +41,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	int i;
>  
>  	tag = get_tag(info->access_addr);
> -	addr = reset_tag(info->access_addr);
> +	addr = kasan_reset_tag(info->access_addr);
>  	page = kasan_addr_to_page(addr);
>  	if (page && PageSlab(page)) {
>  		cache = page->slab_cache;
> @@ -72,7 +72,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  void *find_first_bad_addr(void *addr, size_t size)
>  {
>  	u8 tag = get_tag(addr);
> -	void *p = reset_tag(addr);
> +	void *p = kasan_reset_tag(addr);
>  	void *end = p + size;
>  
>  	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 616ac64c4a21..8e4fa9157a0b 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -81,7 +81,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
>  	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
>  	 * addresses to this function.
>  	 */
> -	address = reset_tag(address);
> +	address = kasan_reset_tag(address);
>  
>  	shadow_start = kasan_mem_to_shadow(address);
>  	shadow_end = kasan_mem_to_shadow(address + size);
> @@ -98,7 +98,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
>  	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
>  	 * addresses to this function.
>  	 */
> -	address = reset_tag(address);
> +	address = kasan_reset_tag(address);
>  
>  	kasan_poison_memory(address, size, tag);
>  
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 3bffb489b144..d1af6f6c6d12 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -67,11 +67,6 @@ u8 random_tag(void)
>  	return (u8)(state % (KASAN_TAG_MAX + 1));
>  }
>  
> -void *kasan_reset_tag(const void *addr)
> -{
> -	return reset_tag(addr);
> -}
> -
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip)
>  {
> @@ -107,7 +102,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  	if (tag == KASAN_TAG_KERNEL)
>  		return true;
>  
> -	untagged_addr = reset_tag((const void *)addr);
> +	untagged_addr = kasan_reset_tag((const void *)addr);
>  	if (unlikely(untagged_addr <
>  			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>  		return !kasan_report(addr, size, write, ret_ip);
> @@ -126,7 +121,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  bool check_invalid_free(void *addr)
>  {
>  	u8 tag = get_tag(addr);
> -	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
> +	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(kasan_reset_tag(addr)));
>  
>  	return (shadow_byte == KASAN_TAG_INVALID) ||
>  		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111165453.GI517454%40elver.google.com.
