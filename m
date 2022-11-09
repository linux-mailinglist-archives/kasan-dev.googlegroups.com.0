Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBBPSV2NQMGQEYBEF3ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DAF82622DDD
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 15:28:21 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id v12-20020adfa1cc000000b00236eaee7197sf5000765wrv.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 06:28:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668004101; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q/wRRxT6Fz1iBZS/OujXP0hm5tN2Kla9DTrb+sA604nE0dvp5D+l0Nx6RnD3ZLtY8r
         awXJQGchLh47Qc2PdaxG+wZtEazMQwD1HICOS9njbGw1rIbu4ToeXRX6P418Fp6OJrCi
         ACpjsmtMMjlPU6r9L6i6xSnMtojl4QKyFvOOR2H0hPmiE0WmlJGvuIp1S2XYZueuIQnu
         n0zx6JBtU9BnqXtzdA3F3IcLFurcGFUYzjDc1HjQRkLyEuk9bsfXW2dhOG/ziihZIM8l
         U7xGoStJRS+NcbpcSakJHGHbf4fFNm69Uf+3vEx5v/1AGblCP4vyvpu2HiuDvD1GHST+
         zaQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=O1NQvgmWanELOPOqvP90Ruwe5+okJIkdRIExViE5EIM=;
        b=JLoe2pzJ9XEVpUE3iIUL0PA+moA+P/j8RsYmC3sJ4IdbHcHxhwOgDWXsC+Wi2GsEsj
         o9AKNfUyesiXg4mMB+t4P1sRzHXufphDJCP6sq+dE8R0q77kVU/8EfZeQVB3L6hH+3gC
         PZuNK2t4OWy4C7TD+j9KLDvaTPm4jJ+dAzzIhEi+5aRMGgI+4JVAXoQelvtrTrat9WqP
         o43ae6T0poZb+2J8toFlBGAiqssIBW0enL4Us/uV/d/ZXyRdxjSdSdRx5ttsDJTPj0Rm
         JFr6ZOWramUyQgqrOxLFGA4oQAzUVls/2FXylQRpqSR3VKk3/PWukEUAetbZnU2vRUxN
         sbEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=p2fROSMJ;
       dkim=neutral (no key) header.i=@suse.cz header.b=fbT9ZNCc;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=O1NQvgmWanELOPOqvP90Ruwe5+okJIkdRIExViE5EIM=;
        b=W3Y1qrrtqzVTCcaNMWEw5auIcsU2tEwGXsvwMjIyHYm3gyzoFhwzwnukQ9HiXjqbPK
         ASfDBDqYVQRYd3RG+Dmtcy3woRuxPprNIxze2jK9Iz8cJOxbG+CHcnVuQ8Ba4DlCHJFc
         Zc5NifN4SoFTHg+syDTKc5ZDnuEdcWamrIh8QMIGdWWPQyJW7CPMrzn7ZDf7LSX5KxY/
         3HWCxexoL0w2w0eUG+eeCFLCE6jifm98eonCrLpGsgQEqSvTm5ZP1/lh6OkH5kQXNQ9a
         ekWmN7GCthv0GwiUwu5ZHWBANp8JNuGriKuY65d1jZr6FMslf+mJKXinHiCjH2vG/2YY
         aNDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O1NQvgmWanELOPOqvP90Ruwe5+okJIkdRIExViE5EIM=;
        b=1IvdkNz1F/aNeGNgJfqswWjtw2Y0DfKLE4376JfwYmyqbeIjAFon03HcHcCL8UuKzM
         S+C8LNh4BBl4Yvr4VA8PAWc0VA6UWO1bLzqG66ftmXAOVFczmZO8Ar0K+gb0g3scYuFP
         /UjB/db7IP7au1YN/6m7VawV3NGv93IhAqvxC3ioce7YbxS/BbLaGltTFD57jAMl+EXX
         z5ly6ZntH537FtDGBdpLwuVLrOGEYGwRyJWw5+tGGwUIuuXdBiM26XM7fAL/oZMXrv7h
         koQDR9lrgG+lPP6VciQDhuy7QrH1vczsq/Ma0lZGrI5U/150HMoC6hpG1gb24pCBa3v+
         hPkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Ho0GIh3Ok9xF29OR7JJa1uy0u0nceE6J439HVLbxyTTedx7kA
	+W4GllSoIHrtszgagGmZJLU=
X-Google-Smtp-Source: AMsMyM7HaIKSvdCM6oQRjQP4uFdUNbK3H4Q8kQVOWSCiVLiSBpvcbHNfyj6moWcNjkTtlyWKOCtLVQ==
X-Received: by 2002:a05:600c:1819:b0:3cf:63fe:944a with SMTP id n25-20020a05600c181900b003cf63fe944amr39717899wmp.17.1668004101316;
        Wed, 09 Nov 2022 06:28:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:238:b0:22c:d34e:768c with SMTP id
 l24-20020a056000023800b0022cd34e768cls1053528wrz.0.-pod-prod-gmail; Wed, 09
 Nov 2022 06:28:20 -0800 (PST)
X-Received: by 2002:adf:fb0a:0:b0:225:265d:493 with SMTP id c10-20020adffb0a000000b00225265d0493mr38698984wrr.394.1668004100105;
        Wed, 09 Nov 2022 06:28:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668004100; cv=none;
        d=google.com; s=arc-20160816;
        b=IGn43ob2gEZFV8Gct8qkJu7p+znXcUDNAWGjdTPqdH5A3yhaFh7dP74p8CFTtecsOx
         Vc6B/bFt1PEJOe0Ivx4uckPyWYUliIa1+7sBoM/7Ei257la0xXW0zHG+8HhqODJxdd0d
         LF+OcaVFJybX/E4L0+rqA7feXqqVkTykplcm+r6cBU8FIGPL7Vr6t5ab84+ZqiIhTgtw
         LE6daH5BvfCSfHo2It9+c/lZScqfmSu97D2vYTLuxXLEy34xDxU93j1sYShISAJK7aPG
         01yD5kJ25f+kl4oTxp56A9u5dwN/u64r3vKSzKUelAyG9D3NTAjefGoQLF1OGxRDsorZ
         XwkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=u2xkKJq1iZsD6H4gomAlOFSM/WEi/FOicLRRE3V7xGE=;
        b=ijZZGORLxgDGAAuvOfbExd9yi55IRvKuJhpD6LkTZ7JBg0IrTnz/1aZ320EI5HtdxL
         x2j6dpI6g9G7AFkyZ2h4PuEdDU601lZw8kJFp8ht8xSs4WpetJFI0YUB6NjwS0PYncq5
         gKHAvppBvGck+/8qZP7DYDCu9WrnlMPLahZqPEkU4vvT/Xqs7HzQG0kTYlSXLNAL4agX
         6YVFdiJtXLAyAoA9qqovU2H3kQ939vhudER7alEZaZr1kLy2XDhjZOd+WWrJBSBs4s3e
         JjZblRzlsiXvDoqbiZL2JIgxSypyvSQRlA6Irpxa0OABvKilsrZiMxJLAeCkqnRSySzj
         Z8pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=p2fROSMJ;
       dkim=neutral (no key) header.i=@suse.cz header.b=fbT9ZNCc;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id by9-20020a056000098900b00239778ccf84si464139wrb.2.2022.11.09.06.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 06:28:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id BBDFE228F4;
	Wed,  9 Nov 2022 14:28:19 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 73403139F1;
	Wed,  9 Nov 2022 14:28:19 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id veZRGwO5a2NnKgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 09 Nov 2022 14:28:19 +0000
Message-ID: <09074855-f0ee-8e4f-a190-4fad583953c3@suse.cz>
Date: Wed, 9 Nov 2022 15:28:19 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for
 kzalloc when debug enabled
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Kees Cook <keescook@chromium.org>
Cc: Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-2-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221021032405.1825078-2-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=p2fROSMJ;       dkim=neutral
 (no key) header.i=@suse.cz header.b=fbT9ZNCc;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/21/22 05:24, Feng Tang wrote:
> kzalloc/kmalloc will round up the request size to a fixed size
> (mostly power of 2), so the allocated memory could be more than
> requested. Currently kzalloc family APIs will zero all the
> allocated memory.
> 
> To detect out-of-bound usage of the extra allocated memory, only
> zero the requested part, so that redzone sanity check could be
> added to the extra space later.
> 
> For kzalloc users who will call ksize() later and utilize this
> extra space, please be aware that the space is not zeroed any
> more when debug is enabled. (Thanks to Kees Cook's effort to
> sanitize all ksize() user cases [1], this won't be a big issue).
> 
> [1]. https://lore.kernel.org/all/20220922031013.2150682-1-keescook@chromium.org/#r
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/slab.c |  7 ++++---
>  mm/slab.h | 18 ++++++++++++++++--
>  mm/slub.c | 10 +++++++---
>  3 files changed, 27 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/slab.c b/mm/slab.c
> index a5486ff8362a..4594de0e3d6b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3253,7 +3253,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
>  	init = slab_want_init_on_alloc(flags, cachep);
>  
>  out:
> -	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
> +				cachep->object_size);
>  	return objp;
>  }
>  
> @@ -3506,13 +3507,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	 * Done outside of the IRQ disabled section.
>  	 */
>  	slab_post_alloc_hook(s, objcg, flags, size, p,
> -				slab_want_init_on_alloc(flags, s));
> +			slab_want_init_on_alloc(flags, s), s->object_size);
>  	/* FIXME: Trace call missing. Christoph would like a bulk variant */
>  	return size;
>  error:
>  	local_irq_enable();
>  	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>  	kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }
> diff --git a/mm/slab.h b/mm/slab.h
> index 0202a8c2f0d2..8b4ee02fc14a 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -720,12 +720,26 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
>  
>  static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  					struct obj_cgroup *objcg, gfp_t flags,
> -					size_t size, void **p, bool init)
> +					size_t size, void **p, bool init,
> +					unsigned int orig_size)
>  {
> +	unsigned int zero_size = s->object_size;
>  	size_t i;
>  
>  	flags &= gfp_allowed_mask;
>  
> +	/*
> +	 * For kmalloc object, the allocated memory size(object_size) is likely
> +	 * larger than the requested size(orig_size). If redzone check is
> +	 * enabled for the extra space, don't zero it, as it will be redzoned
> +	 * soon. The redzone operation for this extra space could be seen as a
> +	 * replacement of current poisoning under certain debug option, and
> +	 * won't break other sanity checks.
> +	 */
> +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&

Shouldn't we check SLAB_RED_ZONE instead? Otherwise a debugging could be
specified so that SLAB_RED_ZONE is set but SLAB_STORE_USER?

> +	    (s->flags & SLAB_KMALLOC))
> +		zero_size = orig_size;
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_alloc and initialization memset must be
> @@ -736,7 +750,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  	for (i = 0; i < size; i++) {
>  		p[i] = kasan_slab_alloc(s, p[i], flags, init);
>  		if (p[i] && init && !kasan_has_integrated_init())
> -			memset(p[i], 0, s->object_size);
> +			memset(p[i], 0, zero_size);
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, flags);
>  		kmsan_slab_alloc(s, p[i], flags);
> diff --git a/mm/slub.c b/mm/slub.c
> index 12354fb8d6e4..17292c2d3eee 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3395,7 +3395,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>  	init = slab_want_init_on_alloc(gfpflags, s);
>  
>  out:
> -	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +	/*
> +	 * When init equals 'true', like for kzalloc() family, only
> +	 * @orig_size bytes will be zeroed instead of s->object_size

s/will be/might be/ because it depends on the debugging?

> +	 */
> +	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>  
>  	return object;
>  }
> @@ -3852,11 +3856,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>  	 * Done outside of the IRQ disabled fastpath loop.
>  	 */
>  	slab_post_alloc_hook(s, objcg, flags, size, p,
> -				slab_want_init_on_alloc(flags, s));
> +			slab_want_init_on_alloc(flags, s), s->object_size);
>  	return i;
>  error:
>  	slub_put_cpu_ptr(s->cpu_slab);
> -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> +	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
>  	kmem_cache_free_bulk(s, i, p);
>  	return 0;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/09074855-f0ee-8e4f-a190-4fad583953c3%40suse.cz.
