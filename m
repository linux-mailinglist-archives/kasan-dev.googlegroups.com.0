Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBGAT3XQKGQEK7TM4PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C1AB4112AD9
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 13:01:09 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id q4sf4884840ion.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 04:01:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575460868; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkMVl5fvTgk1RBUZgOVPjK9O78wOkh5b32XFoQIdARfDLiJx1MSJp60VnSDYhL6KqF
         IvF30zUMXFSTMd2zHY8/veNT8lHV26+uhSIaupl1kUHIJQz8JT9cIa0oDsNnRenQeV+g
         6OLnVokoiCvXs7tJ/mHgw8qrF9ZKs9IDBY6FKyYHts8msmTVXblB4aWm+WT8qZACFfAb
         1Uc1++gmQ1MK7PSvtGHMlWC0atsDFxqfGKvB8IrdN2TVPUvuqmRlNYnM+t0O0UsF/Tjq
         xHojAi/FWej88NaecOFFwchc2rC3/hOqajRg1kq28wyNCJrhCtaTMxCQpKl1RlWh7FS3
         6nwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=RZD4E/SG0k5EDuau4qRK6PpwbnbcQrXqkHysFffFMEM=;
        b=o9wDsdoQZuAZ4QBuuuPqRywpl8/kb80PMoDhPhbXhdVsjgXbnHBSWFa/BUktrnExVB
         5UW/Hv3Dyd2bFnOQZUq5VvPDkQAmS4Bvklat+AiDEKVUJjrGfCgETlRbDUqPu290okT/
         vMUyagh1dz/j3GYWrt5MQ3R/+wSUUM0ELUcZktBoFqAfoSKMgXZd3dhAVuoao1AC2sBe
         vjXhNVoQgwEos0ybyI4Epn229n6NQGeCf8lF2ORnEaXTemBPplR6zk1IfUvutnR5DWyp
         vvtMcCbHbtLQpKkRIR82YTlSbfgwgouU/rlc1Yo9ZFcm1oAxelSgbDkmpZ2n8M8RDq67
         egkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=o226C2dU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZD4E/SG0k5EDuau4qRK6PpwbnbcQrXqkHysFffFMEM=;
        b=NGuYr8ebRGMJ3yvwsAl+lTKoCqvlsj6fU2paOd/pFImIf6VSw70js5BP0hlbqtSKze
         k3MURk16Gzas0IxQajmnS3bs/aWkBAONs0BvDeXaJOtfjxIlhpzNiYfn3/eRthBz0Q6l
         DC0oIsnNgmGPGK+KgzDJISfC2NGXFlfPJRtjYXRxng8iqTtWkknCAsQEvgphuPF163S7
         rq7UmXwbQlQ1e2Ox9rIbqpAUE23QumeoGuzOTQbRUgVU8K7iGKSvvaor/HlaefqgXZMQ
         eOwn3n7nqcIHrfCcUKFFyJKLXo2GZrpb66F56C6a3lVGj7HCJuJOVA7jhyu4GlEt5y4U
         yYow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZD4E/SG0k5EDuau4qRK6PpwbnbcQrXqkHysFffFMEM=;
        b=mR528xNiRYNaiiQv3vkd03sVsd4LgVKSwdqiLDku6KWwWSBWmXG8X/y9fPNUSMJtfI
         rVfHYm3Fd/seiFbBTBiAr8vOxvZIWJmg3+4B3Fn1T6Wg1Dz0KKEWbqF+LU5X+V5Pg9Uy
         14rJQG0IoqvlGmIYlk5G2iv07rUlDmr3kswgFkOP6S8cNYuvEu4O/KAVh0Mv0DadyxK6
         Zqrd0LOYfVr/4fixNIP9MTAb9ZPN6vFabr84X6hvDrLPQm5Nv90SAypyXhTYpRm2cqbQ
         17YFGPFDmFcEXzhTKe3r016AjXZQ1vM2oXvTAlysWwZiVLJqvEBMGGtju3zCOFUEUdyZ
         UKdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXOhWwBcGtprNODmDJ0SYlVKYnuQeCIErA7o6X8yF+Wte/cp2FC
	gpphR55tVZkVo3jw69GROy8=
X-Google-Smtp-Source: APXvYqymU678qGjpmxxlFO3hLGCciSmfDj7q0W10xona7xSPzCxHABE6vSUudMt6SHYoI7TzoutSOg==
X-Received: by 2002:a92:1d8c:: with SMTP id g12mr2959021ile.91.1575460868729;
        Wed, 04 Dec 2019 04:01:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b602:: with SMTP id g2ls934101iof.2.gmail; Wed, 04 Dec
 2019 04:01:08 -0800 (PST)
X-Received: by 2002:a6b:6217:: with SMTP id f23mr1814890iog.177.1575460868162;
        Wed, 04 Dec 2019 04:01:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575460868; cv=none;
        d=google.com; s=arc-20160816;
        b=SIuetgCWmDBaCqakQ5seJPVfkm8Hh9WJTi6tHqedApfqIR7wyXAE4KCSvmSyhekbHW
         FG/KDUZDeB0olmqQGNhpsvDNmbB2PXiArs98kfyT9/dV0+RimFjgN7QrH+eZ2xvIthFm
         /dNCj4HnX8mCMCBb8WC2ozd65kqJhYy/tTBUAGYkpEZbZ8ZeRn1CdpImwDc9Dr9vPC77
         XzYT9R6NjHUxQfo5adtd4Bl/y7E6iWXCATuUiLU6G4iSjEvPTJbQ8m2SGUXdUvI2T6Ha
         vZL8yJgBoETcb4i2BLcP8d+Kmk8IplHeJ+JZcXT1ciFJRhlVWtWVnFLcmq8cGWeAciAU
         aEfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=rxuqclm9QwY2ereJARQY1d6ZkLRCh/xjgCtTC93zfPo=;
        b=rjSSLJj1bc1QuUCj1OONWkG3LrSpAPJoqhLWZO8wmaiJtodlzVNe4AMYqp85AEj0WZ
         pageFaOefdmC7atQ8nKzp26z27XlquV6x5dGjaVh0hUXhazVfMrrhjVdIHkONVfGpj7F
         bJSSBwhNjoAmzaDKO0oTNGxuUkVLWgnXjoqMF98ts78FOWFc0tXw4h9FIDDUlY2q8gXJ
         16zmC/OtG3/CY6NKiJe/XwMIfJoLX/AhhOjd9j+TAqk8/Gu7zQ+0azFydbY4H6uZotGP
         huijKJDI23iwZzbPDYn9kmgvF5JLCelbmYDWEY1aQzI26H77HVpTaMVeNFvAfc5GNJE1
         sT4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=o226C2dU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id g10si366691ilb.2.2019.12.04.04.01.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 04:01:07 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id ay6so3105059plb.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 04:01:07 -0800 (PST)
X-Received: by 2002:a17:902:bf08:: with SMTP id bi8mr2861953plb.75.1575460866914;
        Wed, 04 Dec 2019 04:01:06 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-7daa-d2ea-7edb-cfe8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:7daa:d2ea:7edb:cfe8])
        by smtp.gmail.com with ESMTPSA id u7sm7598987pfh.84.2019.12.04.04.01.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Dec 2019 04:01:06 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, linux-kernel@vger.kernel.org, dvyukov@google.com
Cc: Qian Cai <cai@lca.pw>
Subject: Re: [PATCH] kasan: support vmalloc backing of vm_map_ram()
In-Reply-To: <20191129154519.30964-1-dja@axtens.net>
References: <20191129154519.30964-1-dja@axtens.net>
Date: Wed, 04 Dec 2019 23:01:02 +1100
Message-ID: <87h82ge1vl.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=o226C2dU;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
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

I've realised this throws a few compile warnings, I'll respin it.

Daniel Axtens <dja@axtens.net> writes:

> This fixes some crashes in xfs, binder and the i915 mock_selftests,
> with kasan vmalloc, where no shadow space was being allocated when
> vm_map_ram was called.
>
> vm_map_ram has two paths, a path that uses vmap_block and a path
> that uses alloc_vmap_area. The alloc_vmap_area path is straight-forward,
> we handle it like most other allocations.
>
> For the vmap_block case, we map a shadow for the entire vmap_block
> when the block is allocated, and unpoison it piecewise in vm_map_ram().
> It already gets cleaned up when the block is released in the lazy vmap
> area freeing path.
>
> For both cases, we need to tweak the interface to allow for vmalloc
> addresses that don't have an attached vm_struct.
>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Qian Cai <cai@lca.pw>
> Thanks-to: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  include/linux/kasan.h |  6 ++++++
>  mm/kasan/common.c     | 37 +++++++++++++++++++++++--------------
>  mm/vmalloc.c          | 24 ++++++++++++++++++++++++
>  3 files changed, 53 insertions(+), 14 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 4f404c565db1..0b50b59a8ff5 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -207,6 +207,7 @@ static inline void *kasan_reset_tag(const void *addr)
>  #ifdef CONFIG_KASAN_VMALLOC
>  int kasan_populate_vmalloc(unsigned long requested_size,
>  			   struct vm_struct *area);
> +int kasan_populate_vmalloc_area(unsigned long size, void *addr);
>  void kasan_poison_vmalloc(void *start, unsigned long size);
>  void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  			   unsigned long free_region_start,
> @@ -218,6 +219,11 @@ static inline int kasan_populate_vmalloc(unsigned long requested_size,
>  	return 0;
>  }
>  
> +static inline int kasan_populate_vmalloc_area(unsigned long size, void *addr)
> +{
> +	return 0;
> +}
> +
>  static inline void kasan_poison_vmalloc(void *start, unsigned long size) {}
>  static inline void kasan_release_vmalloc(unsigned long start,
>  					 unsigned long end,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index df3371d5c572..27d8522ffaad 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -779,27 +779,15 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  
>  int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
>  {
> -	unsigned long shadow_start, shadow_end;
>  	int ret;
> -
> -	shadow_start = (unsigned long)kasan_mem_to_shadow(area->addr);
> -	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> -	shadow_end = (unsigned long)kasan_mem_to_shadow(area->addr +
> -							area->size);
> -	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> -
> -	ret = apply_to_page_range(&init_mm, shadow_start,
> -				  shadow_end - shadow_start,
> -				  kasan_populate_vmalloc_pte, NULL);
> +	ret = kasan_populate_vmalloc_area(area->size, area->addr);
>  	if (ret)
>  		return ret;
>  
> -	flush_cache_vmap(shadow_start, shadow_end);
> +	area->flags |= VM_KASAN;
>  
>  	kasan_unpoison_shadow(area->addr, requested_size);
>  
> -	area->flags |= VM_KASAN;
> -
>  	/*
>  	 * We need to be careful about inter-cpu effects here. Consider:
>  	 *
> @@ -838,6 +826,27 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
>  	return 0;
>  }
>  
> +int kasan_populate_vmalloc_area(unsigned long size, void *addr)
> +{
> +	unsigned long shadow_start, shadow_end;
> +	int ret;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
> +	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +	shadow_end = (unsigned long)kasan_mem_to_shadow(addr + size);
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
> +	return 0;
> +}
> +
>  /*
>   * Poison the shadow for a vmalloc region. Called as part of the
>   * freeing process at the time the region is freed.
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index bf030516258c..2896189e351f 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -1509,6 +1509,13 @@ static void *new_vmap_block(unsigned int order, gfp_t gfp_mask)
>  		return ERR_CAST(va);
>  	}
>  
> +	err = kasan_populate_vmalloc_area(VMAP_BLOCK_SIZE, va->va_start);
> +	if (unlikely(err)) {
> +		kfree(vb);
> +		free_vmap_area(va);
> +		return ERR_PTR(err);
> +	}
> +
>  	err = radix_tree_preload(gfp_mask);
>  	if (unlikely(err)) {
>  		kfree(vb);
> @@ -1554,6 +1561,7 @@ static void free_vmap_block(struct vmap_block *vb)
>  	spin_unlock(&vmap_block_tree_lock);
>  	BUG_ON(tmp != vb);
>  
> +	/* free_vmap_area will take care of freeing the shadow */
>  	free_vmap_area_noflush(vb->va);
>  	kfree_rcu(vb, rcu_head);
>  }
> @@ -1780,6 +1788,8 @@ void vm_unmap_ram(const void *mem, unsigned int count)
>  	if (likely(count <= VMAP_MAX_ALLOC)) {
>  		debug_check_no_locks_freed(mem, size);
>  		vb_free(mem, size);
> +		kasan_poison_vmalloc(mem, size);
> +
>  		return;
>  	}
>  
> @@ -1787,6 +1797,7 @@ void vm_unmap_ram(const void *mem, unsigned int count)
>  	BUG_ON(!va);
>  	debug_check_no_locks_freed((void *)va->va_start,
>  				    (va->va_end - va->va_start));
> +	/* vmap area purging will clean up the KASAN shadow later */
>  	free_unmap_vmap_area(va);
>  }
>  EXPORT_SYMBOL(vm_unmap_ram);
> @@ -1817,6 +1828,11 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
>  		if (IS_ERR(mem))
>  			return NULL;
>  		addr = (unsigned long)mem;
> +
> +		/*
> +		 * We don't need to call kasan_populate_vmalloc_area here, as
> +		 * it's done at block allocation time.
> +		 */
>  	} else {
>  		struct vmap_area *va;
>  		va = alloc_vmap_area(size, PAGE_SIZE,
> @@ -1826,7 +1842,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node, pgprot_t pro
>  
>  		addr = va->va_start;
>  		mem = (void *)addr;
> +
> +		if (kasan_populate_vmalloc_area(size, mem)) {
> +			vm_unmap_ram(mem, count);
> +			return NULL;
> +		}
>  	}
> +
> +	kasan_unpoison_shadow(mem, size);
> +
>  	if (vmap_page_range(addr, addr + size, prot, pages) < 0) {
>  		vm_unmap_ram(mem, count);
>  		return NULL;
> -- 
> 2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h82ge1vl.fsf%40dja-thinkpad.axtens.net.
