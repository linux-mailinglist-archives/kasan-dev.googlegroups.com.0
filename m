Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDFK2S2QMGQEBCDWNIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id DCAFC94C4F8
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 20:57:17 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ef3133ca88sf12232761fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2024 11:57:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723143437; cv=pass;
        d=google.com; s=arc-20160816;
        b=FCPFAYDN+5ZhjeM/wjLhUbdbRTkCyd4FwBOgQrO51bdtY3c4iN0S9L5dwfYORX9ltG
         5ojSUBorH43dXG9kVt01/goHaST4jIWx+Tos/q7kkTE15+vRxnZO0Gsq2kE1AVCqf78T
         avnCOkSnt8d14WQskO04+Vx0wK/R2AvM7oP/tVn2larGaNWKM44BhN87ZBtnQBOaloU2
         lUkB8UooJwdcjEHXGDWwb0UNYmx8W0PwZdWY8kJaRIj+YxsU+Icn4qgLgayDm3WVLCZE
         A1/BHDm8gDDKcA0Y63ZGMLzNZeEN33F25KgiPJp3l5B9VHmqNTmSBhPIlh7qz1XIBQek
         slDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=LRHlAHmTIwWSQUm6Yq8ou6EnhcPPVemo58JLlqg4k4g=;
        fh=FyWpElhwUjxnQA27zxeaVewC09tznDmA3a0ocLEjiL8=;
        b=uFobF3cvYUtBZS2xv/GJUx50dYaDxYzvsOR93+tQstbqje66QNXYM9bvdFHKvXs1kN
         g2tM1cdlFIejUBaqTj9ZEQx5WM3I1NG7pBF1GGLM9GmcgMrIWE2IoAXxvEk8jtL8I+bh
         irOKXQgkHbMoDFIbdneuF0595I8O2+/lTy6Hsy28hxXryypkl+OcxukbivWaaXggUzpK
         zc1De+txK00ykXC1qAmu4nhivDc6B4Batb4a2URZmY8G65s6Rb6QzXyD8lrTYrT3ZCxn
         4OzLFflnESH1i3Y5ovCxOP3lbAXC+DJBIt5p621FhV8IIzGt2Ebh9OMI6YB8AvYYRl+3
         WiXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTjlZ+qi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=OPlEzteZ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTjlZ+qi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723143437; x=1723748237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LRHlAHmTIwWSQUm6Yq8ou6EnhcPPVemo58JLlqg4k4g=;
        b=F00A54QxK43GwGX07+Og2ZyM9no85/2dVTeu7Co5xXAidA5ZHteZZtZv/qrnW3TtMI
         z5hN/6f5Vikq3TZPKaFwHYLtC0T+e47VuA+ku1FCTC8q7wHZ/VWhvsrDM/fjoNQfigtU
         9HyobBzM5D9kRnmQedYgS2lppi4LyoIDpCL8MBUnmc7wHPueCZmYylrAJfAmvGf93jJe
         Kq8ZJzMzXhcc9lv7UY/5/cWGGUsFmhsWq+XiBp3ypVQj2yi2HmPBpNGIoJfyjPp3XVWO
         nBmrGQ4DmcROW9HnlfsOvKaVWcrmPStqSAcy09Wfd8/AVpxCMS68wmygK0Zy8TtZYGfx
         jQRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723143437; x=1723748237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LRHlAHmTIwWSQUm6Yq8ou6EnhcPPVemo58JLlqg4k4g=;
        b=ZXgUAUHb4Qs6op1jm89eADICnhVk+Mjtx80OHGZ46rpy87XgQ8lv4vDQsl8FBsHwlc
         Vuy9JyWB7xAL45Va0MrgW2opMVJM/X74aaYi8WdfWgKlw0VQdduA1XKAtbDVs7KOaaA9
         f9krapJR5gm/IfaPMauZgIaCLGWSioZsBovxwDTsYQ7aJWNALDtKYSiD7jPYgWqbh47C
         l+y3/d6Cl5jWHIcbumfJnC7Cx8hUEfZ/I/qZGNjK3NfqlUmbUQgNzQ7kYLG7E2qZVt/T
         7CmkWHPpoyQOHNlVpwexWVpSAp/PLoCWPEYNtz4AavqypB9dUni4TG2ns/9vZ0OKXWxo
         SStQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2EqZ8+B8OM8QNGqPob9w5lWq66u4xdD1U2Woks6B1WsB4eW57VjnivsgZJ6xhFk4iDwTNkuplU9Om7phN3SX8LbHLn7Gf2g==
X-Gm-Message-State: AOJu0Yznzveazf61ebmkvS2QlvmOo1yP0HOJoF1dcBShzdAGFBQROiA7
	bpbPpXFIMOaoz5Zasy9pP8BaNwM4kf1gSW/lavfMogT5JdN6rQ/h
X-Google-Smtp-Source: AGHT+IEFMJ6XmJzQVLGMFmZp8SrD7mBMuws+MdTFy8WLZesDNCtGgQjYnxIQgPx6WCGHb9QLr4EaHA==
X-Received: by 2002:a2e:7812:0:b0:2f0:2027:7241 with SMTP id 38308e7fff4ca-2f19de4567emr20373711fa.29.1723143436517;
        Thu, 08 Aug 2024 11:57:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2243:0:b0:2f0:1cb8:9ec5 with SMTP id 38308e7fff4ca-2f19bb21448ls3236441fa.0.-pod-prod-09-eu;
 Thu, 08 Aug 2024 11:57:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtyPe6tLQxZXw40T7qBYkQSKBrDZ+1IAmpivs5G2LGDJXo6hbcMWQ4lkTIOL56xcDRlXWIZBIDRsT3+qsUDZGTSYDMtBVtU6fmag==
X-Received: by 2002:a05:6512:acb:b0:52e:767a:ada3 with SMTP id 2adb3069b0e04-530e5876555mr2471970e87.47.1723143434392;
        Thu, 08 Aug 2024 11:57:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723143434; cv=none;
        d=google.com; s=arc-20160816;
        b=elyg8R596qUmJnhBV0scCAOrnvZm0zYYDwS+033h/g3PAe/HroN6K8ygxZJ+k+0YWv
         ow64QiBl6EY4IHAeaIiIV5aS1kCXDrnTIDV3B2g0BZBPbmjk4Wvbcn7/Io1M8tQRh1Sn
         YFaX4rIz6gBWGoI2Yyb3Pz83NLtXARPFDTPQqh8vmoywJdFCr9PSiJtZseNMv4Y66zjT
         +C34yb2U6a2EU/oHQxLs3C/oE88a/aT/QVpk+rZRwtTxHIMGNM1c0f2dLeS1I9kp4ocX
         v1UF3ihmva3kiC0lvPqvJyp0iNJlekrb7WN5ZLQBBXnKc9P2LqASnX5kau9bnQHFEHad
         RQXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=3XZ1KdontnFU5/Se3Co5kaGh6xMEyUNzr24XjDVGQww=;
        fh=ag/UOWmB8elzOiktGLmxBgLRQf6CvI12ulU3lg/L3MA=;
        b=iWADNUqXUPuCskS5p5zlxCk1FSgnNT6Oj/g0MRt5/y65oVgVp4PqcOOWH9qjhR9Isa
         bsDMLSOOs5Nudoc+mCGTLeDbtPtHLsG6C4V3AuFbwQtrHQP5wo97rSn4C0W/00Y4eNQg
         ikKv3bCDzhQdrkH0C7pIAk6hgNZomU3WAnsIseDf5BqeVg4LSgnxpo2Gp1iqjfQKjerh
         fys9UWayJFn3B2EtDehJhiEx5UX/k6+CBDzfO/b849IMxqy5V9i0QPyJHpECakU5qJCS
         JyzN52mQFqvy8dkGhXwDIs+HkQ3Xn7R3CiI07G41kRyflUgpp/2jpGJI32Q1kv0japEI
         /DRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTjlZ+qi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=OPlEzteZ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTjlZ+qi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530de44190bsi79842e87.9.2024.08.08.11.57.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Aug 2024 11:57:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 5D6B521DAC;
	Thu,  8 Aug 2024 18:57:13 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 348BD13876;
	Thu,  8 Aug 2024 18:57:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id hJJnDAkVtWarVwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 08 Aug 2024 18:57:13 +0000
Message-ID: <1ca6275f-a2fc-4bad-81dc-6257d4f8d750@suse.cz>
Date: Thu, 8 Aug 2024 20:57:12 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v7 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Content-Language: en-US
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 David Sterba <dsterba@suse.cz>,
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
References: <20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com>
 <20240808-kasan-tsbrcu-v7-2-0d0590c54ae6@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240808-kasan-tsbrcu-v7-2-0d0590c54ae6@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.79
X-Spamd-Result: default: False [-2.79 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	URIBL_BLOCKED(0.00)[appspotmail.com:email];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[263726e59eab6b442723];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCVD_COUNT_TWO(0.00)[2];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[appspotmail.com:email]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yTjlZ+qi;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=OPlEzteZ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yTjlZ+qi;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/8/24 20:30, Jann Horn wrote:
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
> slabs because use-after-free is allowed within the RCU grace period by
> design.
> 
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when this
> option is enabled.
> 
> For now I've configured Kconfig.debug to default-enable this feature in the
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
> mode because I'm not sure if it might have unwanted performance degradation
> effects there.
> 
> Note that this is mostly useful with KASAN in the quarantine-based GENERIC
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)
> 
> Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Acked-by: Marco Elver <elver@google.com>
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>      [slab]

Just some very minor suggestions:

> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -582,12 +582,24 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
>  
>  	s->refcount--;
>  	if (s->refcount)
>  		goto out_unlock;
>  
> +	if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
> +	    (s->flags & SLAB_TYPESAFE_BY_RCU)) {
> +		/*
> +		 * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
> +		 * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will internally
> +		 * defer their freeing with call_rcu().
> +		 * Wait for such call_rcu() invocations here before actually
> +		 * destroying the cache.
> +		 */
> +		rcu_barrier();

If we wanted to be really nice and not do rcu_barrier() with the mutex held
(but it's a debugging config so who cares, probably), we could do it before
taking the mutex. It won't be even done unnecessarily as
SLAB_TYPESAFE_BY_RCU cannot merge so refcount should always go from 1 to 0
for there.

> +	}
> +
>  	err = shutdown_cache(s);
>  	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
>  	     __func__, s->name, (void *)_RET_IP_);
>  out_unlock:
>  	mutex_unlock(&slab_mutex);
>  	cpus_read_unlock();
> diff --git a/mm/slub.c b/mm/slub.c
> index 0c98b6a2124f..eb68f4a69f59 100644

<snip>

> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +	struct rcu_delayed_free *delayed_free =
> +			container_of(rcu_head, struct rcu_delayed_free, head);
> +	void *object = delayed_free->object;
> +	struct slab *slab = virt_to_slab(object);
> +	struct kmem_cache *s;
> +
> +	kfree(delayed_free);
> +
> +	if (WARN_ON(is_kfence_address(object)))
> +		return;
> +
> +	/* find the object and the cache again */
> +	if (WARN_ON(!slab))
> +		return;
> +	s = slab->slab_cache;
> +	if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
> +		return;
> +
> +	/* resume freeing */
> +	if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
> +		return;
> +	do_slab_free(s, slab, object, object, 1, _THIS_IP_);

Nit: at this point we could just do the more standard pattern
if (slab_free_hook())
	fo_slab_free()

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ca6275f-a2fc-4bad-81dc-6257d4f8d750%40suse.cz.
