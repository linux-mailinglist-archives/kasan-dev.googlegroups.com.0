Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBVV2WSNQMGQEKE6LBAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1586624650
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 16:48:39 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id z21-20020a2e9655000000b0027736b9bb8asf704577ljh.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 07:48:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668095319; cv=pass;
        d=google.com; s=arc-20160816;
        b=pElx8lnm9v9/lainJ8Db9nJqD5+JYPQZgNYrG0z7+43TL3thYI1IjdiZhSxiYiz2d2
         4rhOUDXUU6YbHwZo0qz1GR+Hd43ruJ+vmt0lpTO4vfTuV3MZTNy4VCU5jvlOvlIZ/rFr
         qsUcpHW6/Vg+VaSyCB4nkNvviIu6hYouSFyu0b3KWevNtkSplf5Ko0P00W7pzsTB0tBs
         yY2UTCMwwezmx9NcsgW7U8vKwxBHQprwdINSsLNhZys/YBYusrWt5rCZQx82z+xjYOzS
         DxELchUDIpTD33MZwowGo49Hv8bwGMerz3f6mtGZvPuSnIO3/Kk5yKmXgeBHEtbFxNIV
         8NyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7b+rpUk3AqSssonJOLTEs5vZnvEVFYbTOb1slXYFa6I=;
        b=1Hg0D69au1RULDz6gTJqWX0wuTn8FVXLAKTzDRsAXM1tvHfOBkwDo8zM9j/6Hrybx4
         dIwFuOotD+WeNei0c2ImwyMSLH7O542cP7W6oBOYuGGX31VG4EBz5W6CW4oESmHWjlHt
         g7JMEILebxKPr11RKE/EYaBn3OH+y1SD3rtDVxLQ4FLpq0RVKqhUDjy/L2Xd9IF9nZ/j
         k1S3mHy7hTmtfbCIvx3Adnz82xJBEW89jIiyTRzec5vPJc+mT4Vh7F/MCqqxQMmSakJa
         XJ4BjcdH5SlpvOu00quknfztYcOoTL8WAXgYHFRpZtYqoYCSwWSYHNC6rvePvh5LyQfL
         m5BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zskpez+6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=zwMcF9Q1;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7b+rpUk3AqSssonJOLTEs5vZnvEVFYbTOb1slXYFa6I=;
        b=WYoV5LtbLc+nNAJd8UcR0DSJogINov7oGgmhNdENHJMMghQ0BoeLnpb/Lo7XkVixKb
         NpJl9yCYd8Qc3QHIloFIpWAmalYuezWeQo3FcM2z5LHWNSPTYa8Rhf6xuXL31BjYD6sG
         2xyfK4q1iDJQ8CBkNra4QUgmSqqq0AcVvY4abpihC6X0G6Q35zPMtqqQH+MxB6I8zGRg
         A2vMlw0MMq/Po2rb3mp9F+lJUcXG49Cwzc9ufXFtJDhxqUKjCZ/9q64Jw0ZENgqqjSqe
         UqARqjQqTLuMxw34O7f0aN3i5cdGh+sGRgfNn0wrj5lRHG0D7rY3D/sBadRb5brjeif7
         CuvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7b+rpUk3AqSssonJOLTEs5vZnvEVFYbTOb1slXYFa6I=;
        b=KaZ8b/MKv1KBvLpNSLFR7JQPNmkDvXVrf0x31u2CSyt7i3gSYvc8boMPvnFynB+gxy
         xs2pQqO+A6LSos1k0jC7COg7RzmuPpoST9GK43GhYdpC15LzSMBIZT+NOXo3yJ/6aPJ4
         +D7MHe3VZzx7cw1WfEnQLzAaP0v95L6npfHpNEyj3DIqnKHPb2z0Eu1fgGGS6JIvVDJo
         kSvBEBQdcXtWUIayoqH5GfI1YJtzuNfn9FOF7AsdgKNMwiI/ca35BmMJA9eDuGre9Um5
         l2NB4yNhyuNzwIyQcU41bKcnvf5cNOQ61Q10z7N5hJX8S5/YBzI0ZboclcW/girdc8JD
         jFxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0SvC4hWjIFjAutOXW2XC73hCB1+Ui672mt/Nbdqzgz/SqAS1Gs
	Wq/3kzSWk7oF1AG1Pe8yPck=
X-Google-Smtp-Source: AMsMyM6ACBHYLxfhWc7vXQcZapBnZ/A86bJzC0Nx37y082gM0x0PXJw+WG3ti06NUfCq2XiEJndWHQ==
X-Received: by 2002:ac2:5cd1:0:b0:4a2:291a:9460 with SMTP id f17-20020ac25cd1000000b004a2291a9460mr21200917lfq.203.1668095318607;
        Thu, 10 Nov 2022 07:48:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5d5:b0:48b:2227:7787 with SMTP id
 o21-20020a05651205d500b0048b22277787ls397104lfo.3.-pod-prod-gmail; Thu, 10
 Nov 2022 07:48:36 -0800 (PST)
X-Received: by 2002:a05:6512:30f:b0:4b0:7020:7a5e with SMTP id t15-20020a056512030f00b004b070207a5emr19462263lfp.189.1668095316895;
        Thu, 10 Nov 2022 07:48:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668095316; cv=none;
        d=google.com; s=arc-20160816;
        b=aZqsi7WwOldeUni3gEqb7zczKLS2LRAAa5bg0xKr7fQRnsQoWpbzesMnleapZxo+aK
         FLKN3vdQF9DVeXm1juYwAIzXOfRVOS2OrfJ/VSRIB97Zt7dk9oKtGeXKrSVGa2VNxwBk
         viZh0U+QEUNJuF2MaqC9YlDdnh/JU8aBMhEGYOro1McrtfSZ4oD/RXozaPdKRhjdoV82
         9CUcDvTFFzA1Tm4DPCIQ9lfCeqBT8iqv3AOlUyeA/64D7SmmmESBxNUtFa03bCPBDU5O
         6vKVJfYklpxcfe2+7sx1XZkcOagaeTaX4ceqo5sfdZlRzzCYdaDTBmReTOJP8iEIOOx8
         rZHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=J3QJBtM4MnGOZMLT0ADfXmiVyB/zENfV6p3Drb9JBbs=;
        b=QkCNX0RQhLNpRsjntI2M8xcdVTJ7iFEtHpTZerh2MeqQ+W1EE+XpVYRn82D6r/NKwV
         lF8XjbA4fFATTmxTOtYXxzZUnMdFcsJLoZbIp+knEyfAdbD/pMhMNmCjL/1XKdUaqPNJ
         810A65vaEtpflWLDsVfekSa9WUvTLZ30Qrt3TKaqU5L3E0JRS5EQsAAZU0L49xdV2uzu
         Gv3sHK6UACg0tRNAPbvAE6Ty/MQQFnzP5pBwQY0f3Fi0fgYI+EeCUO5nt9KHCyO3TGnD
         yYF6yGxgIP2j1iN8/V2rbandbpY4sAZJE4swfg+OKoRfzriCzevyC6N2dHo56kpzSBwF
         gaZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zskpez+6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=zwMcF9Q1;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id k9-20020a2ea269000000b0027737e93a12si530791ljm.0.2022.11.10.07.48.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Nov 2022 07:48:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 43F6222999;
	Thu, 10 Nov 2022 15:48:36 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 047A813B58;
	Thu, 10 Nov 2022 15:48:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yQlpAFQdbWPjUgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 10 Nov 2022 15:48:36 +0000
Message-ID: <e2dd7c7c-b0b7-344a-de37-4624f5339bce@suse.cz>
Date: Thu, 10 Nov 2022 16:48:35 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH v7 3/3] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
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
 <20221021032405.1825078-4-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221021032405.1825078-4-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zskpez+6;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=zwMcF9Q1;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> kmalloc will round up the request size to a fixed size (mostly power
> of 2), so there could be a extra space than what is requested, whose
> size is the actual buffer size minus original request size.
> 
> To better detect out of bound access or abuse of this space, add
> redzone sanity check for it.
> 
> In current kernel, some kmalloc user already knows the existence of
> the space and utilizes it after calling 'ksize()' to know the real
> size of the allocated buffer. So we skip the sanity check for objects
> which have been called with ksize(), as treating them as legitimate
> users.

Hm so once Kees's effort is finished and all ksize() users behave correctly,
we can drop all that skip_orig_size_check() code, right?

> In some cases, the free pointer could be saved inside the latter
> part of object data area, which may overlap the redzone part(for
> small sizes of kmalloc objects). As suggested by Hyeonggon Yoo,
> force the free pointer to be in meta data area when kmalloc redzone
> debug is enabled, to make all kmalloc objects covered by redzone
> check.
> 
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Looks fine, but a suggestion below:

> ---
>  mm/slab.h        |  4 ++++
>  mm/slab_common.c |  4 ++++
>  mm/slub.c        | 51 ++++++++++++++++++++++++++++++++++++++++++++----
>  3 files changed, 55 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 8b4ee02fc14a..1dd773afd0c4 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -885,4 +885,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
>  }
>  #endif
>  
> +#ifdef CONFIG_SLUB_DEBUG
> +void skip_orig_size_check(struct kmem_cache *s, const void *object);
> +#endif
> +
>  #endif /* MM_SLAB_H */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 33b1886b06eb..0bb4625f10a2 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1037,6 +1037,10 @@ size_t __ksize(const void *object)
>  		return folio_size(folio);
>  	}
>  
> +#ifdef CONFIG_SLUB_DEBUG
> +	skip_orig_size_check(folio_slab(folio)->slab_cache, object);
> +#endif
> +
>  	return slab_ksize(folio_slab(folio)->slab_cache);
>  }
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index adff7553b54e..76581da6b9df 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -829,6 +829,17 @@ static inline void set_orig_size(struct kmem_cache *s,
>  	if (!slub_debug_orig_size(s))
>  		return;
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +	/*
> +	 * KASAN could save its free meta data in object's data area at
> +	 * offset 0, if the size is larger than 'orig_size', it will
> +	 * overlap the data redzone in [orig_size+1, object_size], and
> +	 * the check should be skipped.
> +	 */
> +	if (kasan_metadata_size(s, true) > orig_size)
> +		orig_size = s->object_size;
> +#endif
> +
>  	p += get_info_end(s);
>  	p += sizeof(struct track) * 2;
>  
> @@ -848,6 +859,11 @@ static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
>  	return *(unsigned int *)p;
>  }
>  
> +void skip_orig_size_check(struct kmem_cache *s, const void *object)
> +{
> +	set_orig_size(s, (void *)object, s->object_size);
> +}
> +
>  static void slab_bug(struct kmem_cache *s, char *fmt, ...)
>  {
>  	struct va_format vaf;
> @@ -966,13 +982,27 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
>  static void init_object(struct kmem_cache *s, void *object, u8 val)
>  {
>  	u8 *p = kasan_reset_tag(object);
> +	unsigned int orig_size = s->object_size;
>  
> -	if (s->flags & SLAB_RED_ZONE)
> +	if (s->flags & SLAB_RED_ZONE) {
>  		memset(p - s->red_left_pad, val, s->red_left_pad);
>  
> +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +			orig_size = get_orig_size(s, object);
> +
> +			/*
> +			 * Redzone the extra allocated space by kmalloc
> +			 * than requested.
> +			 */
> +			if (orig_size < s->object_size)
> +				memset(p + orig_size, val,
> +				       s->object_size - orig_size);

Wondering if we can remove this if - memset and instead below:

> +		}
> +	}
> +
>  	if (s->flags & __OBJECT_POISON) {
> -		memset(p, POISON_FREE, s->object_size - 1);
> -		p[s->object_size - 1] = POISON_END;
> +		memset(p, POISON_FREE, orig_size - 1);
> +		p[orig_size - 1] = POISON_END;
>  	}
>  
>  	if (s->flags & SLAB_RED_ZONE)

This continues by:
    memset(p + s->object_size, val, s->inuse - s->object_size);
Instead we could do this, no?
    memset(p + orig_size, val, s->inuse - orig_size);

> @@ -1120,6 +1150,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  {
>  	u8 *p = object;
>  	u8 *endobject = object + s->object_size;
> +	unsigned int orig_size;
>  
>  	if (s->flags & SLAB_RED_ZONE) {
>  		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> @@ -1129,6 +1160,17 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
>  			endobject, val, s->inuse - s->object_size))
>  			return 0;
> +
> +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> +			orig_size = get_orig_size(s, object);
> +
> +			if (s->object_size > orig_size  &&
> +				!check_bytes_and_report(s, slab, object,
> +					"kmalloc Redzone", p + orig_size,
> +					val, s->object_size - orig_size)) {
> +				return 0;
> +			}
> +		}
>  	} else {
>  		if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
>  			check_bytes_and_report(s, slab, p, "Alignment padding",
> @@ -4206,7 +4248,8 @@ static int calculate_sizes(struct kmem_cache *s)
>  	 */
>  	s->inuse = size;
>  
> -	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
> +	if (slub_debug_orig_size(s) ||
> +	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
>  	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
>  	    s->ctor) {
>  		/*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e2dd7c7c-b0b7-344a-de37-4624f5339bce%40suse.cz.
