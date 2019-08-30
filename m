Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTO6UTVQKGQEOFC4CBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 64C5AA38DD
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 16:14:39 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id q9sf4024056pgv.17
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 07:14:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567174478; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZYhI7Qpshji05rkWmN/MNUbDjSP4QjHHWZxETgE881Dxxf4u5pPsrYBetVniRlwYLZ
         aAu43/Rfscl2YKyoP5obLUOPoH6AqPOUBR+Uqa8N1no5TwGxABVjMPU9S7vXoBllXZ9h
         sEbnx1wMuEQF+HcBAdI1GDpLifPFGhuBqN3nQ9u/WU+idVKQP6rhe9gwnVys/JIA5c+T
         lig3AlsrsP7YHz69A/1N+w+96VZO+I37rm9pUtbm7FPGP3UhTIMy8q+uhuo/4MDMxIx3
         alquTC6liWsEcaPfm5vXomQcydAnMwA3JXIh4jQMAx8pdpESofiujBOqfEvGKr25s96O
         VVbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=0wxmb2JEgjnpBCGiEqNyFVJihHSLT3qoF2IZhvWFI+0=;
        b=ZR1ajZeys7teG9miArxyiDj2VUePNjOVA+BFgokeQQpEvdCslUnCxhE2LeLFMPVG//
         0H9EVQU1pLj3Fn2FiYrn/DypWsSMzDnnWUIev31mWBWQL85cijsjBVVs58QFIBTn5Ct7
         HVH7zAgEv+i+m8KzANjTn22+LEoi9wwDkI/1DKD/p2hllZ737xkxiriHjorQHCfmjqxl
         Oq026I6PE9y76CIjKCPcgx1ZyoDUpNqYOwC9fA9QSKLbpk6x0FFtOJt/zUcot0I1mp3x
         cSK8qDnbw+7tPRsOkKDQ3tBBiusZZxOVaWHLa/PBozh4815aHUBJHWCNN9U1vabgArTS
         WIrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CO9IufDi;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0wxmb2JEgjnpBCGiEqNyFVJihHSLT3qoF2IZhvWFI+0=;
        b=A9jLXKU9L4qR5lLd4PMPvehWWX7fzEu8J4jW8iFeq2SabpOSsHYJSVOHlUQ2O3fGz8
         M/ZnBsrYaT62xeqJaSKXpVbtOwqa4JsMc+RJWPbgtjsGpOZvRdQsmrtz2suKsgTy38yo
         whcftmAhH3OLUUv3LhubAiWu8Vz+77kOm++OPJsZZhIRlJqV/IFYHiaFnY/SemZyAwlq
         52HlxlUx0GruAjkrOl+WGAbjX8NOcIxodUL9zmR//FHRUlRpoBdWkIXe6S6z/lSqVyz7
         gs2qB9QvRETdBUaUgRwsZ7bx1FHkAK/K/JD+72KZwLYflox67+mqFaQiJkG9UDZQHCIq
         dzXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0wxmb2JEgjnpBCGiEqNyFVJihHSLT3qoF2IZhvWFI+0=;
        b=CfEYoaPKvcwU1C1O3E4rvEkP6AkTvLawyHI3zXbSDSkNTZW7RNToQXdxt2JPaJdJvK
         hQm8HL6dOtSVZY2arBqc9IOwUR4Hio50pkr14Y4v9z19IK5OgQ9VQUVEieupts92uDvo
         6vLZDkCE+nGhIheO/UzwaQVY/uLCHA2jpJlSN9jg0to3b7w+NGZ/wmrrE8Ep3gaSvAs9
         OcHNuAQxdS8WwvQfiRD7aF/totlO3LjFmUzUntFLsA/wujgi++E5qpPOuHCZQ0r5t5Yx
         dzPPL1dT9YQqP75eZHDX+XJgdZHkKC8PboqFmWJIwrJgRw83/H1zpZWg5odl9uAKiH8p
         Q6bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXCXQsENT5mneD13DfCqrulmMhLUEobMbNpS7flCADgR3WzR2zo
	xpSHZj3tTImU/vqdJHm6it0=
X-Google-Smtp-Source: APXvYqySduOJfdatNUZDa62DtPKIgJRPH0VAmOfAQVZxCN6N9SJfk96mwQWuae55ho76WJBN8x2iFw==
X-Received: by 2002:a17:90a:f995:: with SMTP id cq21mr16226804pjb.27.1567174477977;
        Fri, 30 Aug 2019 07:14:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e2c7:: with SMTP id fr7ls1824717pjb.3.canary-gmail;
 Fri, 30 Aug 2019 07:14:37 -0700 (PDT)
X-Received: by 2002:a17:90a:b108:: with SMTP id z8mr15963862pjq.108.1567174477710;
        Fri, 30 Aug 2019 07:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567174477; cv=none;
        d=google.com; s=arc-20160816;
        b=J+KU2H4VtZTreUPABpw/tSL31+odfG8e+93INQVukeaLs638ak62yZcZ/kkDePVeLw
         V5cp7Ia/OxBnxzkzlKK5VvEG9Q2dy+Mveo90GN+wezoyF6CgYm8c7UReY5Syaxvrld3V
         xXJ7MjJ9C9W5CoXD7y7N2Qm/+3/TtPsqVrJci759ocp98JCmhScYipKtP1OzmXpYa2fT
         jNfw1b6UoixjfkSw6o1p9ky9ZTtWWHHel+KpaelF3FMi3f771+tv7S3Ashy7l/BW1NQ0
         1AqewiFlT/HpFW194n21vd4sMEOu2G+kpyCeOsqNYX6LTBveX9FB+H4AttF6rcgktFln
         5PsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=GQjSOvbaapj7b1lMAgf5SR118C4E3gkJs2yq2l1Stv4=;
        b=BxuxpiAnEzK2n9uUbuLnQtDBpsEZyv0ZPZ9Ffoe4o/Suwyj40bE3QnEfemNJj/H54c
         vkivhUy2YkSgowsAduzk/ZBn199ytFgGrZbu8QtmXYU/tthnARa2QkG07C9qryJJjqBc
         RWAxybaXiYxkqpPAp3DBJGJGaSLi1GZNr1vUBlKlTzbycj1RuV+bamYI7cOkqxs1Ib4N
         y9jbaidbg2mkKmkR7FdrTzOiKfKT6x1a8bvo1UDntBBHiR8lDWY/lRYb2b8tP06HB1Lx
         jF4InbD5U4PbVGYTN+9jfCAYdBjMn4qpMbkc0YhF3aI9ZZZ1/817QCgYojmOoEod3HHj
         +paA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=CO9IufDi;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id m12si692863pjs.2.2019.08.30.07.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Aug 2019 07:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id y9so4742850pfl.4
        for <kasan-dev@googlegroups.com>; Fri, 30 Aug 2019 07:14:37 -0700 (PDT)
X-Received: by 2002:aa7:8a48:: with SMTP id n8mr18631624pfa.143.1567174476689;
        Fri, 30 Aug 2019 07:14:36 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id g2sm7247374pfm.32.2019.08.30.07.14.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Aug 2019 07:14:35 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v5 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20190830003821.10737-2-dja@axtens.net>
References: <20190830003821.10737-1-dja@axtens.net> <20190830003821.10737-2-dja@axtens.net>
Date: Sat, 31 Aug 2019 00:14:21 +1000
Message-ID: <871rx2viyq.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=CO9IufDi;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi all,

> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +					void *unused)
> +{
> +	unsigned long page;
> +
> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> +
> +	spin_lock(&init_mm.page_table_lock);
> +
> +	/*
> +	 * we want to catch bugs where we end up clearing a pte that wasn't
> +	 * set. This will unfortunately also fire if we are releasing a region
> +	 * where we had a failure allocating the shadow region.
> +	 */
> +	WARN_ON_ONCE(pte_none(*ptep));
> +
> +	pte_clear(&init_mm, addr, ptep);
> +	free_page(page);
> +	spin_unlock(&init_mm.page_table_lock);

It's just occurred to me that the free_page really needs to be guarded
by an 'if (likely(!pte_none(*pte))) {' - there won't be a page to free
if there's no pte.

I'll spin v6 on Monday.

Regards,
Daniel

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
> + */
> +void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +			   unsigned long free_region_start,
> +			   unsigned long free_region_end)
> +{
> +	void *shadow_start, *shadow_end;
> +	unsigned long region_start, region_end;
> +
> +	/* we start with shadow entirely covered by this region */
> +	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +
> +	/*
> +	 * We don't want to extend the region we release to the entire free
> +	 * region, as the free region might cover huge chunks of vmalloc space
> +	 * where we never allocated anything. We just want to see if we can
> +	 * extend the [start, end) range: if start or end fall part way through
> +	 * a shadow page, we want to check if we can free that entire page.
> +	 */
> +
> +	free_region_start = ALIGN(free_region_start,
> +				  PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +
> +	if (start != region_start &&
> +	    free_region_start < region_start)
> +		region_start -= PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +
> +	free_region_end = ALIGN_DOWN(free_region_end,
> +				     PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
> +
> +	if (end != region_end &&
> +	    free_region_end > region_end)
> +		region_end += PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
> +
> +	shadow_start = kasan_mem_to_shadow((void *)region_start);
> +	shadow_end = kasan_mem_to_shadow((void *)region_end);
> +
> +	if (shadow_end > shadow_start)
> +		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
> +				    (unsigned long)(shadow_end - shadow_start),
> +				    kasan_depopulate_vmalloc_pte, NULL);
> +}
> +#endif
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 36c645939bc9..2d97efd4954f 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -86,6 +86,9 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
>  	case KASAN_ALLOCA_RIGHT:
>  		bug_type = "alloca-out-of-bounds";
>  		break;
> +	case KASAN_VMALLOC_INVALID:
> +		bug_type = "vmalloc-out-of-bounds";
> +		break;
>  	}
>  
>  	return bug_type;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 35cff6bbb716..3a083274628e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -25,6 +25,7 @@
>  #endif
>  
>  #define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
> +#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped page */
>  
>  /*
>   * Stack redzone shadow values
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index b8101030f79e..bf806566cad0 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -690,8 +690,19 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	struct list_head *next;
>  	struct rb_node **link;
>  	struct rb_node *parent;
> +	unsigned long orig_start, orig_end;
>  	bool merged = false;
>  
> +	/*
> +	 * To manage KASAN vmalloc memory usage, we use this opportunity to
> +	 * clean up the shadow memory allocated to back this allocation.
> +	 * Because a vmalloc shadow page covers several pages, the start or end
> +	 * of an allocation might not align with a shadow page. Use the merging
> +	 * opportunities to try to extend the region we can release.
> +	 */
> +	orig_start = va->va_start;
> +	orig_end = va->va_end;
> +
>  	/*
>  	 * Find a place in the tree where VA potentially will be
>  	 * inserted, unless it is merged with its sibling/siblings.
> @@ -741,6 +752,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  		if (sibling->va_end == va->va_start) {
>  			sibling->va_end = va->va_end;
>  
> +			kasan_release_vmalloc(orig_start, orig_end,
> +					      sibling->va_start,
> +					      sibling->va_end);
> +
>  			/* Check and update the tree if needed. */
>  			augment_tree_propagate_from(sibling);
>  
> @@ -754,6 +769,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	}
>  
>  insert:
> +	kasan_release_vmalloc(orig_start, orig_end, va->va_start, va->va_end);
> +
>  	if (!merged) {
>  		link_va(va, root, parent, link, head);
>  		augment_tree_propagate_from(va);
> @@ -2068,6 +2085,22 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>  
>  	setup_vmalloc_vm(area, va, flags, caller);
>  
> +	/*
> +	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
> +	 * area with real memory. If we come here through VM_ALLOC, this is
> +	 * done by a higher level function that has access to the true size,
> +	 * which might not be a full page.
> +	 *
> +	 * We assume module space comes via VM_ALLOC path.
> +	 */
> +	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
> +		if (kasan_populate_vmalloc(area->size, area)) {
> +			unmap_vmap_area(va);
> +			kfree(area);
> +			return NULL;
> +		}
> +	}
> +
>  	return area;
>  }
>  
> @@ -2245,6 +2278,9 @@ static void __vunmap(const void *addr, int deallocate_pages)
>  	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
>  	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
>  
> +	if (area->flags & VM_KASAN)
> +		kasan_poison_vmalloc(area->addr, area->size);
> +
>  	vm_remove_mappings(area, deallocate_pages);
>  
>  	if (deallocate_pages) {
> @@ -2495,6 +2531,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	if (!addr)
>  		return NULL;
>  
> +	if (kasan_populate_vmalloc(real_size, area))
> +		return NULL;
> +
>  	/*
>  	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>  	 * flag. It means that vm_struct is not fully initialized.
> @@ -3349,10 +3388,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  	spin_unlock(&vmap_area_lock);
>  
>  	/* insert all vm's */
> -	for (area = 0; area < nr_vms; area++)
> +	for (area = 0; area < nr_vms; area++) {
>  		setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
>  				 pcpu_get_vm_areas);
>  
> +		/* assume success here */
> +		kasan_populate_vmalloc(sizes[area], vms[area]);
> +	}
> +
>  	kfree(vas);
>  	return vms;
>  
> -- 
> 2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871rx2viyq.fsf%40dja-thinkpad.axtens.net.
