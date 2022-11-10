Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB7NYWSNQMGQEMCIYYKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id A299C62463F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 16:45:02 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id h9-20020a05640250c900b00461d8ee12e2sf1783429edb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 07:45:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668095102; cv=pass;
        d=google.com; s=arc-20160816;
        b=uafBqhQhLnwpT7IUEU3CjU7IoQfOhZ6iRNWxkyg+r6Dtru8km0rD02f+Z7UsMX7wTZ
         0QcpAPX/99J6mLiQoGOW9uizKvTmDIteBiRdPK/D/d2Lpx82rToRxIAe+fOVP4JheQPo
         gy34TbQ6yEup21dTtlVLUaIFM9E6TEl2EeVxPNnFVsNU9qHXQCLaOpzGT0pEkUJi/ZVI
         9a/gDHIw1XXsMXDJjbjo40WexQ5bqqvhFBcTF3x4HXZFh1kWrpRsRyB4llNRWhsOpAlJ
         o79Qn/1MLGRSLDlwWbASrI4TFqA/w2oayyRb33l8y1XuJgvcIkZUBwffDa/fT3kKR9ns
         auFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=r24HEVKFwoZWLT/AROTbDe/C+NvhSWh+QEIxhNTL6TU=;
        b=DZhPEkIA3mo+Yah70nNsUPxIiOYIcqSmbMloiy4TOK3/h8cRpW+QjIy7ppWQOn6Z61
         obZreGyAx9VKOPTKqo1Y4rGEOkSLyDaAeupgkaavfBZhhUWhPCaV0E2lU6w/99Sf9Rnx
         e0XEczUB6rlB9FpVRCm2XKLT6FRQnT0X5/NpNJsWPNzTyEhpFjHbUyj4Zj1IiQgpHiQT
         JZDf86qjPkHSIREnPv6YP7W50WLCjxKJwYnz5Y8xMmSDzD6D6c8pMk4Bnzb1NOWqUOGZ
         576AspRwdVglu/fXnnzcctKcLy+HDd8101hO2Ki8sA8RW5sZYmG45ggmvAoOin4aL3oC
         hi3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="GxqOHHb/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=r24HEVKFwoZWLT/AROTbDe/C+NvhSWh+QEIxhNTL6TU=;
        b=mC8dIBWRDdGA4OdVoCsRLyHHDnNNJUcryHMNdHDp1jMy5gFARsJ5N5pyjXhZ3igjsN
         ItdoFtuQjMm1/CstYonSoGnwFfDPdcVLGJSCIM8qI5zJOeBC9I24FkoUr6TWNOhyWA0c
         aGniJZUa180YIq7uosRJX6TfShOo9FubIjKELJltP9B4h0zJhopowoDYnVsZMo+kRhcZ
         oOuATgs9haiWJz2jycKa1ECeSiJGvwLKsN1qhoHUAzd3egNUesOowBnIZ/zVCd9zPYds
         IhezWGTtU0fDwPMZCBp2ZFJQDegvCpXlUfAWRsY9tcQDzqo5cexF9yh3LA+YJZINYU3n
         Y6RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=r24HEVKFwoZWLT/AROTbDe/C+NvhSWh+QEIxhNTL6TU=;
        b=1ekBDInu87Bs6j0F/oOuIhw1nmCiBT3NLsY/r3SrYyWB+Qw4b+bvy7X8oqUh8mLvLB
         QwQHw+/+Lls0Y/BsZLF8sDT7Xcqhzh7YimmSZOmFkgXiFcKdWSG3lLIZ6cfIte9O74C6
         PmT2vxbSi6WKpIz+mHiu8J4QYB+2b+65aVtimWceAUQiq+4nJg08h+vF08lG+7gGJi3v
         xNBpCFHJOiMvVwF+zFt2kh9cP64wJlHtY6/C9YvFvD4XeUMmY5VSRJNzrrD3lamq/w6S
         nS9d5bj6ErT/98KRHAjZYaMCmA0vePQ7H0zvSJot0dJpDvo+k0xvOpULOXA3zjIn2whY
         m7WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plK6ahq0sHqg+HW4iEawoG5DDry2FxBbfzc7xNLrTueGjKd/3iY
	T1uOcN/K48V8++5pASkCvxE=
X-Google-Smtp-Source: AA0mqf7bHC2KXiFstrt61qIxheR+JyWK3g4nisnasDczX6Ymp+I+5sTwYk8h2XkeAr7prDIhLjjbWw==
X-Received: by 2002:a17:907:3f9d:b0:7ae:587e:73aa with SMTP id hr29-20020a1709073f9d00b007ae587e73aamr22447891ejc.289.1668095101971;
        Thu, 10 Nov 2022 07:45:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a98d:b0:78d:e7b8:d105 with SMTP id
 jr13-20020a170906a98d00b0078de7b8d105ls1417954ejb.8.-pod-prod-gmail; Thu, 10
 Nov 2022 07:45:00 -0800 (PST)
X-Received: by 2002:a17:906:4f82:b0:7ad:c7d6:eee5 with SMTP id o2-20020a1709064f8200b007adc7d6eee5mr52566045eju.681.1668095100590;
        Thu, 10 Nov 2022 07:45:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668095100; cv=none;
        d=google.com; s=arc-20160816;
        b=N3yeBDVuMbOP9qNqyfaxzMSO1fi8VO+j1f/Wt+0RfBKg1gJEPTN6SWcUZjAxI9pSIo
         46MM4wRSWuyu1KHzZ88BIMPhg93xs+DYkCkl3HoliG6AFd3KF1PdHHO9ExeU7LGxfQQF
         NpWPM9NnZNEH4diyEWj69iViXEcL4nvzUt3RzFKuQ+Fgrn7VjA/mXvAPr1okihQzXjv3
         nXXzWefoMsaEMDUkXYLfRvTnlQm6KAOBnNYA1MbsJ2RRHae0gdNziAPPoIgzAxg5IdOy
         oLUNBOBl05aUPs0sEvWyiyQOFfccbQa84GN+/shjZKQLwvQm6k/43pbtcZiHKF+YvAxZ
         v97A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=rE+02xU6mztiIRlwXx9oBSZM5mpBJgWeTTExeZCwG8s=;
        b=qRgT0+ZZ2nPLFcxvg6ACFJkrxdToZNXbL9gcnNnhNx/hOBqCYoRjaKjutZELpeBlD3
         0KaMpeikrwBpc/CxBEFmt/A/RshlpCiFsqbuhFjBmGrRk6mRYiEvv4pdN/9pm/2/V6Xj
         e4qS/0SyULsSzBX4XCVuas9ytI33RsfE6ykulnVRdrD2Dl6aOFsjvi/GdgzQZqu9LuLt
         JqrZtzU1rEYcaRT+AsfkiHH9mIkw0HseOW1I9Rk2XojtOgTIFnbsFRUk2iKrNvYmdKm5
         b32ZTmB4M7weuvkqZ4A5W3nHl+/ca+keZr9/d7ewXn8a2A46uLYd/sC79Aa0Vdc4/PsU
         y+3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="GxqOHHb/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id og26-20020a1709071dda00b007ae2368c8cdsi707942ejc.2.2022.11.10.07.45.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Nov 2022 07:45:00 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2965F2298A;
	Thu, 10 Nov 2022 15:45:00 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id EEC6813B58;
	Thu, 10 Nov 2022 15:44:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id lyeYOXscbWOqUAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 10 Nov 2022 15:44:59 +0000
Message-ID: <eaf74c95-6641-8785-61f6-c7013c2f55eb@suse.cz>
Date: Thu, 10 Nov 2022 16:44:59 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for
 kzalloc when debug enabled
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Kees Cook <keescook@chromium.org>,
 "Hansen, Dave" <dave.hansen@intel.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-2-feng.tang@intel.com>
 <09074855-f0ee-8e4f-a190-4fad583953c3@suse.cz> <Y2xuAiZD9IEMwkSh@feng-clx>
 <Y2z1M4zc2Re5Fsdl@feng-clx>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y2z1M4zc2Re5Fsdl@feng-clx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="GxqOHHb/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/10/22 13:57, Feng Tang wrote:
> On Thu, Nov 10, 2022 at 11:20:34AM +0800, Tang, Feng wrote:
>> On Wed, Nov 09, 2022 at 03:28:19PM +0100, Vlastimil Babka wrote:
> [...]
>> > > +	/*
>> > > +	 * For kmalloc object, the allocated memory size(object_size) is likely
>> > > +	 * larger than the requested size(orig_size). If redzone check is
>> > > +	 * enabled for the extra space, don't zero it, as it will be redzoned
>> > > +	 * soon. The redzone operation for this extra space could be seen as a
>> > > +	 * replacement of current poisoning under certain debug option, and
>> > > +	 * won't break other sanity checks.
>> > > +	 */
>> > > +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
>> > 
>> > Shouldn't we check SLAB_RED_ZONE instead? Otherwise a debugging could be
>> > specified so that SLAB_RED_ZONE is set but SLAB_STORE_USER?
>> 
>> Thanks for the catch!
>> 
>> I will add check for SLAB_RED_ZONE. The SLAB_STORE_USER is for
>> checking whether 'orig_size' field exists. In earlier discussion,
>> we make 'orig_size' depend on STORE_USER, https://lore.kernel.org/lkml/1b0fa66c-f855-1c00-e024-b2b823b18678@suse.cz/ 
> 
> Below is the updated patch, please review, thanks! 

Thanks, grabbing it including Andrey's review, with a small change below:

> - Feng
> 
> -----8>----
> From b2a92f0c2518ef80fcda340f1ad37b418ee32d85 Mon Sep 17 00:00:00 2001
> From: Feng Tang <feng.tang@intel.com>
> Date: Thu, 20 Oct 2022 20:47:31 +0800
> Subject: [PATCH 1/3] mm/slub: only zero requested size of buffer for kzalloc
>  when debug enabled
> 
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
> Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> ---
>  mm/slab.c |  7 ++++---
>  mm/slab.h | 19 +++++++++++++++++--
>  mm/slub.c | 10 +++++++---
>  3 files changed, 28 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/slab.c b/mm/slab.c
> index 4b265174b6d5..1eddec4a50e4 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -3258,7 +3258,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
>  	init = slab_want_init_on_alloc(flags, cachep);
>  
>  out:
> -	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> +	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
> +				cachep->object_size);
>  	return objp;
>  }
>  
> @@ -3511,13 +3512,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
> index 8c4aafb00bd6..2551214392c7 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -730,12 +730,27 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
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
> +	    (s->flags & SLAB_RED_ZONE) &&

Combined the two above to:

  if (kmem_cache_debug_flags(s, SLAB_STORE_USER | SLAB_RED_ZONE)

> +	    (s->flags & SLAB_KMALLOC))
> +		zero_size = orig_size;
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_alloc and initialization memset must be
> @@ -746,7 +761,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>  	for (i = 0; i < size; i++) {
>  		p[i] = kasan_slab_alloc(s, p[i], flags, init);
>  		if (p[i] && init && !kasan_has_integrated_init())
> -			memset(p[i], 0, s->object_size);
> +			memset(p[i], 0, zero_size);
>  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
>  					 s->flags, flags);
>  		kmsan_slab_alloc(s, p[i], flags);
> diff --git a/mm/slub.c b/mm/slub.c
> index 0a14e7bc278c..13490f317f5f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3387,7 +3387,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
>  	init = slab_want_init_on_alloc(gfpflags, s);
>  
>  out:
> -	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> +	/*
> +	 * When init equals 'true', like for kzalloc() family, only
> +	 * @orig_size bytes might be zeroed instead of s->object_size
> +	 */
> +	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
>  
>  	return object;
>  }
> @@ -3844,11 +3848,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eaf74c95-6641-8785-61f6-c7013c2f55eb%40suse.cz.
