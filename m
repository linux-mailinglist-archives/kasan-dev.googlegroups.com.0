Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB4H63GIAMGQEMSHUV7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A5664C1B0F
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 19:39:44 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id j27-20020adfb31b000000b001ea8356972bsf2848755wrd.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 10:39:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645641584; cv=pass;
        d=google.com; s=arc-20160816;
        b=bL8bUY/Xlj6G264drpwW8FaCNPX18NqpmS1/mrinGpcpXvJQEsswjUzSPxd5jbNoL/
         b6A5gG76eU55L9urp2ZhuIVyG6iYiOEmGtKxp/jXdqEjPn7k89XlOpU4/OHggvdUp6eT
         pCd8SSPYlgz8MRAdXwVHoQwogxl+Ut7hadjRXC8mokwGOB7tG19uYpd3KG4vXNTf1MJr
         BDRtf0nsQj5oWn/W29NT7KbqQvHTeXYWGK1u7iKBa7eu5HCFnieSM+oLaOetItJJjQWT
         1kto/hjb1zidlTvFgMA2OX8bZ3qgfQDj0bYtt3njPk3jT7S36gaGWRD41Un7TwVmCrez
         kAqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ZqreV1uorrODVlW4y9BaoyO0uCM7hL3Sz4DbdWJgZzE=;
        b=X7y1tUvQZeu+KC6/SfJZTTtt+aRzWmW7YI0vdl0WCtdCyBuGG/HQOgKDkr6w3/P2BS
         UxNnv1ESYgZbXIJMk3+lv59ZWR1LVLs+zwwyGzIj9H+/Cd58yYxDBYLrgdWGRorveTW4
         qO5HhTrX7aEXdg65nn0GcmdXq4bV1cCv7nz/SCIalWBykjZ9lbCcE9fhJIjjLSe2RQOn
         4zxMyRg46b/pmIBvbhPuZJ6dwEhE6DATyQmcqGZYA1HaebonRPidv/7JUnOlokcQYCpE
         STk5m3Z+GIW0NLab84/uwLIZ4ikCVpwb9Gn/FCdoPLAJOrt+5xVXlksyvdFNhuYR0nrf
         s9pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=03tUfnH6;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZqreV1uorrODVlW4y9BaoyO0uCM7hL3Sz4DbdWJgZzE=;
        b=Nv0aGo+n2EYTXRvKIVl0Kd3o3It61PoLNg1P9ggbauBJHH6UpRm4mzGCuEx5kS5aC5
         Ey2565kZe+Rhk+xTKG/B+aLCdYg5XIlz9gPl6aNvwJiU8cK3i6FWrWNvBcIeXi7wc7pB
         H6glN6+TUn/f5FHuBpExShAq6Zl9KG8hJeVkn3QzfS2qCS2Lj/RSKKWsvMG8gT/kPMBu
         NuIq79eCBTJ45r46h0+dgoK4dMBLRJBWNqo32VN7VCCNuB45BNbJrhbsXp2N3ryyEwYb
         8QZ735SkfEjtXj3oavR7F4n5G/Gf0C2gjSl09yTdEd3imaTjOPeAr4RXEYaItCmI/7bF
         asBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZqreV1uorrODVlW4y9BaoyO0uCM7hL3Sz4DbdWJgZzE=;
        b=PC5pb7ND2fpVwx1CDdb9Cgb01WotPzgNFrf+Br+QO0GGFo8QkaypwBpT+QHVLyROSZ
         xGndv/n/hQFI7iD+kcqBL4WqAlknLdw3LjCYsIUfKkwxVQ17Yw9UyroB7HkHp5a83tTF
         UpkcoUmrtAaP4Qe+v55FNGS3OSipc+7NCYrbGF7dkpXo0lO51/13NQCpxcM7VMMrtLvH
         p178UATU+/bw2G1v56HNV2WF7A8j1CgSr5U7fBdpWmOIGd+1OYNq/krygsuYJHGtwlKE
         GRkR+YJxiS8hkh/N/R7YE3nA7dQvv+0GRaNwBAHwxkpT04k0NlDKnTLKU5sDlg1Mmpk7
         MMXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vrOq7OeL9tz/q9q/nYAfNSqBs+NLW66UaKL6ThY9W4bYywvMW
	7qWI0WnIEJgM6JXvpYIrzEg=
X-Google-Smtp-Source: ABdhPJyFKRmc+IDDgInYfHD0ZLDn4cJ3ud5X5M2iR6lehU4/PXL24Ngx7EcdNloJzB+qXDUAv2Sr6Q==
X-Received: by 2002:a5d:6d0c:0:b0:1ea:9ac5:7848 with SMTP id e12-20020a5d6d0c000000b001ea9ac57848mr690294wrq.185.1645641584198;
        Wed, 23 Feb 2022 10:39:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls32705wrc.1.gmail;
 Wed, 23 Feb 2022 10:39:43 -0800 (PST)
X-Received: by 2002:a5d:6d0c:0:b0:1ea:9bf7:f30e with SMTP id e12-20020a5d6d0c000000b001ea9bf7f30emr746974wrq.256.1645641583278;
        Wed, 23 Feb 2022 10:39:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645641583; cv=none;
        d=google.com; s=arc-20160816;
        b=i4VUG6m3ZdU1n1lV3imiHVA7lCDr13JiINnnoZtPqNblrId1Z5YYgToyhsR0tpILLc
         AAsLMBKF2qNWf2F6vN69PY19TzfqSC6LqPmCJlaq+WJYxRY7mSrYXzJS+l41ZhUxhOem
         0oGtMO/tG74M7BlU4HbGGa+2p1a6Hp+USvtwMUfa4CquOnbww6ui/kNwOamFj2BjBstF
         V5VPcQqKwI15dPmCtBUkOVfHiRst2P+LwW3oDfAMgFOVOxaNx4Znw/gu93Px26l2Hj7U
         r32YaLxfKLmYbPAvEbrYCH0zaZBSoBPwz5LNBQZvITxfUuao6s6EKrBDXZ50atN/FXDc
         lKSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=DlJpzM5pIlT2qJDNths/PTMX9nYQ4QyiwW04BJRqenY=;
        b=YdG5PxKsGfPfR8kcVFkgeL+wmqNl/Bz4/6D62GQsZm6lD/Z5Xnyy0o6fb9pubqZZA0
         XF/kmwcyOeT6mFiGBwdD5XigbsbpBSc/l26qPA4gQZEYzUmycHkJXM2eBlhV77Vyxgv7
         GFMC9W0lWbYeHgA+xB/lwaD4qOt9elhS+D+TOFNE9DekIyH9HBbCho2WBy3grFF/z6ni
         kSbSt+boHgqOSAuGbVGvvul7nPFtOqy8hOfLr1x6HKQ9mWA4HkLssoD0U1I/Jv6e7q98
         weTHb6zLLEUnJ+MK5bBKIutldwRg7gx3/P6AVRgnw2JA2yE+2B9nyl859i/dxXZQoqOI
         S1Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=03tUfnH6;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id d9si15322wru.3.2022.02.23.10.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Feb 2022 10:39:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E43581F44C;
	Wed, 23 Feb 2022 18:39:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id B5D9213C98;
	Wed, 23 Feb 2022 18:39:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id wyOWK25/FmJZPgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Feb 2022 18:39:42 +0000
Message-ID: <4d42fcec-ff59-2e37-4d8f-a58e641d03c8@suse.cz>
Date: Wed, 23 Feb 2022 19:39:42 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.6.1
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org
Cc: Roman Gushchin <guro@fb.com>, Andrew Morton <akpm@linux-foundation.org>,
 linux-kernel@vger.kernel.org, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Kees Cook <keescook@chromium.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
References: <20220221105336.522086-1-42.hyeyoo@gmail.com>
 <20220221105336.522086-2-42.hyeyoo@gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH 1/5] mm/sl[au]b: Unify __ksize()
In-Reply-To: <20220221105336.522086-2-42.hyeyoo@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=03tUfnH6;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/22 11:53, Hyeonggon Yoo wrote:
> Only SLOB need to implement __ksize() separately because SLOB records
> size in object header for kmalloc objects. Unify SLAB/SLUB's __ksize().
> 
> Signed-off-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> ---
>  mm/slab.c        | 23 -----------------------
>  mm/slab_common.c | 29 +++++++++++++++++++++++++++++
>  mm/slub.c        | 16 ----------------
>  3 files changed, 29 insertions(+), 39 deletions(-)
> 
> diff --git a/mm/slab.c b/mm/slab.c
> index ddf5737c63d9..eb73d2499480 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -4199,27 +4199,4 @@ void __check_heap_object(const void *ptr, unsigned long n,
>  }
>  #endif /* CONFIG_HARDENED_USERCOPY */
>  
> -/**
> - * __ksize -- Uninstrumented ksize.
> - * @objp: pointer to the object
> - *
> - * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
> - * safety checks as ksize() with KASAN instrumentation enabled.
> - *
> - * Return: size of the actual memory used by @objp in bytes
> - */
> -size_t __ksize(const void *objp)
> -{
> -	struct kmem_cache *c;
> -	size_t size;
>  
> -	BUG_ON(!objp);
> -	if (unlikely(objp == ZERO_SIZE_PTR))
> -		return 0;
> -
> -	c = virt_to_cache(objp);
> -	size = c ? c->object_size : 0;

This comes from commit a64b53780ec3 ("mm/slab: sanity-check page type when
looking up cache") by Kees and virt_to_cache() is an implicit check for
folio slab flag ...

> -
> -	return size;
> -}
> -EXPORT_SYMBOL(__ksize);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 23f2ab0713b7..488997db0d97 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1245,6 +1245,35 @@ void kfree_sensitive(const void *p)
>  }
>  EXPORT_SYMBOL(kfree_sensitive);
>  
> +#ifndef CONFIG_SLOB
> +/**
> + * __ksize -- Uninstrumented ksize.
> + * @objp: pointer to the object
> + *
> + * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
> + * safety checks as ksize() with KASAN instrumentation enabled.
> + *
> + * Return: size of the actual memory used by @objp in bytes
> + */
> +size_t __ksize(const void *object)
> +{
> +	struct folio *folio;
> +
> +	if (unlikely(object == ZERO_SIZE_PTR))
> +		return 0;
> +
> +	folio = virt_to_folio(object);
> +
> +#ifdef CONFIG_SLUB
> +	if (unlikely(!folio_test_slab(folio)))
> +		return folio_size(folio);
> +#endif
> +
> +	return slab_ksize(folio_slab(folio)->slab_cache);

... and here in the common version you now for SLAB trust that the folio
will be a slab folio, thus undoing the intention of that commit. Maybe
that's not good and we should keep the folio_test_slab() for both cases?
Although maybe it's also strange that prior this patch, SLAB would return 0
if the test fails, and SLUB would return folio_size(). Probably because with
SLUB this can be a large kmalloc here and with SLAB not. So we could keep
doing that in the unified version, or KASAN devs (CC'd) could advise
something better?

> +}
> +EXPORT_SYMBOL(__ksize);
> +#endif
> +
>  /**
>   * ksize - get the actual amount of memory allocated for a given object
>   * @objp: Pointer to the object
> diff --git a/mm/slub.c b/mm/slub.c
> index 261474092e43..3a4458976ab7 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4526,22 +4526,6 @@ void __check_heap_object(const void *ptr, unsigned long n,
>  }
>  #endif /* CONFIG_HARDENED_USERCOPY */
>  
> -size_t __ksize(const void *object)
> -{
> -	struct folio *folio;
> -
> -	if (unlikely(object == ZERO_SIZE_PTR))
> -		return 0;
> -
> -	folio = virt_to_folio(object);
> -
> -	if (unlikely(!folio_test_slab(folio)))
> -		return folio_size(folio);
> -
> -	return slab_ksize(folio_slab(folio)->slab_cache);
> -}
> -EXPORT_SYMBOL(__ksize);
> -
>  void kfree(const void *x)
>  {
>  	struct folio *folio;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d42fcec-ff59-2e37-4d8f-a58e641d03c8%40suse.cz.
