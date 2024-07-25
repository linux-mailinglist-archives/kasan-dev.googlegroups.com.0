Return-Path: <kasan-dev+bncBDXYDPH3S4OBBFNCRG2QMGQE6Z57JXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 2495493C2CB
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 15:20:23 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-42808efc688sf1707975e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 06:20:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721913623; cv=pass;
        d=google.com; s=arc-20160816;
        b=REQ6oYCAEph8PPp1gAvDEvbyHlfqkhjDanAp3LYJLSzosnUm84dVWZvM/81473unSF
         TD8Sfp+cW5HiXZS+0ZAwz/WNfQnEBbQnSqhBBt+HiOntugn/liqbF3NrwIydjn0dlr9v
         gvPQM9DQAXrwfY9swh8astygEwkBOJIDAlfmbBIj4UH5V4p5DQAgsBHxIVOLTzn6smtz
         XFx1c5GQPOPWeiJHx5wXqjs2amUVSkO5lY6NnR94J1M1vAjhy2MU49ODIa+jutoyWi6G
         wPms38VhY4CrJxolHXTVz3J5OEAOyHi85Xd2UfOXpF5GmpRI7w4NubiwTQ5r4sC/kDSl
         JlEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=vf2T4uj4sszcgE9oqag20lwNb6kFWJ5/7wGSugcx41k=;
        fh=g6V29geDJjD4u0f2jm/O7oUHoWvqRcVL41s4WyQgFI0=;
        b=KW4/SNMMfzMPrwWD6fAIYuSA8ifceuSc4zPmr5vl5K+msRsW21LhDcX/S7n44CTRXp
         Q7Ffs2nz3VG11YCB2yse3TjGNKao+9ShIUiiaB9ppYKthpGDKKdxQ7/1tlYMvgcexRqz
         nT19RCSc2RDdKJnbRAfIpglLThTyVy9HCB4VYGymm0coPROIQiHgmC3f2Fm5zw0IYz/+
         SUx3GexXpugBXRdfGeZdyqatRqWbVm+mxkwo0TomlSf7t24ACteuApHzxHoLAGOCbRB5
         ey48RB5pOokwtRPQxOGFRorK8X+pgrfHRbUyh56+d2vv+3oaX7KLbEsRYQo0z0gUkfM9
         p/ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gh+9JTsH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gh+9JTsH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721913623; x=1722518423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vf2T4uj4sszcgE9oqag20lwNb6kFWJ5/7wGSugcx41k=;
        b=WAhYb2erTQMan5Poy3BzmLmHGk9h2nfINfbV6Kw+Rg1CPk/rqOConywO4w2vsiDuWV
         fKcs883SNf9Vjdyr5kPFqkCD67D4EcoWiywcm1uELWK2sP7P+Gpk1rYsafT2lqwXdtrQ
         CQcYgdJP1oFujJWFXPv4pWbgrXw4jULwmVBDL2uhAqu7j3acqzrcklGIu4AJ2LLPbyfX
         hK78aY9kVtNwbdZAjKv7dB2wf8a9U+uem+j61yrXPyg8BDtyjh+9pDFx49Wx3zhz4hl/
         9Oo0dTggg2Vr31vMjBbpwRA9twv+h9DRUEq2A14B+FXdVRaipubigikbIkvt30OSYU1X
         NdpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721913623; x=1722518423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vf2T4uj4sszcgE9oqag20lwNb6kFWJ5/7wGSugcx41k=;
        b=UE/O95JWLgwi8RVxqPRI0VowfrzLarSaY7vU1xkROShGiKcELFqJOeZzEQ0YJCrNgL
         ozJsjdog0b3uGhHKfmZafrYtd2i4BvL4nDE+F5BTxlDVA6EaP5OiHerJ2l+D3aq/3scs
         ePJ8jzPB6YSgulUmRZI+UP/8oDGdFAhufsbM8h3bYZ7rhbhShegs9lLtZhjKGn5zaPfB
         RFCwgeKRFhEbEy+89MVlbYNm/JGDo0Ef+30rhkF0Ody1Xsa8ioXmKq8xDfJEpyedvPm7
         dFqoNkXjVgB9jxZ3G5xUn/7Uq/CNiEwZVwFaRPIIAqihEfxsau6rN9YZKOfo9RIU/S0G
         ww1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKSZeJEF2Gz9sBIu0Z44f4OL/s/jWnc1mBZaHu4xgAjbEzMZYuvpm7rEYZnstF5SsvCHcuYJyy9JbalWi6DOL4pkEmnA/Gnw==
X-Gm-Message-State: AOJu0YxOY2Jv6zNvjy+bqppjJ09dL+R/ifOFy5W5sOmJmvfrk0ga95x6
	K0rf/2SE9vjUxtljS45LpIDlIOs6j5wQzHPsAHQdKF7ZSMH5YYE+
X-Google-Smtp-Source: AGHT+IHL04yja6DDIG1bcb9OtkctPnejbw9m4D8ZcUdaeTv+y5nSYrMC3auVtzI1FReKmZvF3R85qQ==
X-Received: by 2002:a05:600c:4513:b0:426:6353:4b7c with SMTP id 5b1f17b1804b1-428055087eemr16829905e9.8.1721913621749;
        Thu, 25 Jul 2024 06:20:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5126:b0:426:6982:f5c6 with SMTP id
 5b1f17b1804b1-42803b57b24ls4227475e9.1.-pod-prod-02-eu; Thu, 25 Jul 2024
 06:20:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnAHIwbSZGnBrfvZusE3KucwIEaE1wnuTp2P1S7mVZWPZvyLDapAS7Qb659r4EvPkS/IsglIn4bbEEj27J8OuHL7IAswyFOvmAPA==
X-Received: by 2002:a5d:49c2:0:b0:367:83e9:b4a5 with SMTP id ffacd0b85a97d-36b31a79ff7mr1840165f8f.49.1721913619643;
        Thu, 25 Jul 2024 06:20:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721913619; cv=none;
        d=google.com; s=arc-20160816;
        b=ffowDNoSOPc2FrXCZTOr1vvTvwtfaj7ylLzGhnuu2LirEYZ2wXDTbdSW13/2vx4otl
         zcLxT415bUOuaXYYRa5NLrG5y9dSR0G/6QEMIpufVfSTRLxaFsNQ6bKRdRJwagb9waHh
         fmg80dUWbXU0WYgSvTlXO7qdfuKKqEeNV3gUGkN81VViKXyL8OWr0kb4rY5M3AA+MuvI
         hlNSpAaEiqstujhMCHkYYaOK/EtTTRz8C9VRYsSBb+JhxPij/B3rttp4oFuDBU0utvs6
         Haf+JjlMLXXVMdimNRjCxavTFMf/dS41Bi+RLejloxSJZ1i4r8f2m+L/YTUHixSRdS0j
         NRAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=7Stw7qPfwbB4swhWbYP34yYgfEmapZZj8phemCP1P9I=;
        fh=HmT76vcs+zO1ZG5U/D+utUyYOLBDzdTx2ZsGVz/wSR0=;
        b=tYKWpOyjauAulg8xbYF1AyT2HSbUh6ZEjbP1bDAaUQBay3XiDkrhSKamupTSsApzNB
         gqiRZqpUAxK0owUd+AeTWYl02/lWud3YHITgynAh2jegJu3qDK0wbnnpMcAJqI/kOoTz
         6+eVb7lyK0yqMT6o9tqqX64ubvWSsd76qDX9Icl8zB2hcg2YgdGRkWVgWgkSqRk5qF4p
         piOC2J9nOQ1fYYF+r4pmWGAwlutL9//s9yObCXjDdmDKDVx8b3IauD7bAJOKkQuaT4a4
         XR2B8PqEBvjdg0umakaumqYTkCHdFNdrTvtxlgw1UAB+daBlkaw2JiyECHyABH0fdtCg
         Wnkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gh+9JTsH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Gh+9JTsH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36771c65si31143f8f.1.2024.07.25.06.20.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jul 2024 06:20:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id F18AD1F45A;
	Thu, 25 Jul 2024 13:20:18 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CC09B13874;
	Thu, 25 Jul 2024 13:20:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 5wR4MRJRombhfgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 25 Jul 2024 13:20:18 +0000
Message-ID: <1d6913c7-5a6a-412b-a4fa-0eb7b7622d4f@suse.cz>
Date: Thu, 25 Jul 2024 15:20:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
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
 linux-kernel@vger.kernel.org, linux-mm@kvack.org
References: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
 <20240724-kasan-tsbrcu-v2-1-45f898064468@google.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240724-kasan-tsbrcu-v2-1-45f898064468@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: F18AD1F45A
X-Spam-Score: -2.80
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[17];
	ARC_NA(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Gh+9JTsH;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Gh+9JTsH;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/24/24 6:34 PM, Jann Horn wrote:
> Currently, when KASAN is combined with init-on-free behavior, the
> initialization happens before KASAN's "invalid free" checks.
> 
> More importantly, a subsequent commit will want to use the object metadata
> region to store an rcu_head, and we should let KASAN check that the object
> pointer is valid before that. (Otherwise that change will make the existing
> testcase kmem_cache_invalid_free fail.)
> 
> So add a new KASAN hook that allows KASAN to pre-validate a
> kmem_cache_free() operation before SLUB actually starts modifying the
> object or its metadata.
> 
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slub

> ---
>  include/linux/kasan.h | 10 ++++++++++
>  mm/kasan/common.c     | 51 +++++++++++++++++++++++++++++++++++++++------------
>  mm/slub.c             |  7 +++++++
>  3 files changed, 56 insertions(+), 12 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 70d6a8f6e25d..eee8ca1dcb40 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -175,6 +175,16 @@ static __always_inline void * __must_check kasan_init_slab_obj(
>  	return (void *)object;
>  }
>  
> +bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
> +			unsigned long ip);
> +static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
> +						void *object)
> +{
> +	if (kasan_enabled())
> +		return __kasan_slab_pre_free(s, object, _RET_IP_);
> +	return false;
> +}
> +
>  bool __kasan_slab_free(struct kmem_cache *s, void *object,
>  			unsigned long ip, bool init);
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 85e7c6b4575c..7c7fc6ce7eb7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -208,31 +208,52 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> -static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
> -				      unsigned long ip, bool init)
> +enum free_validation_result {
> +	KASAN_FREE_IS_IGNORED,
> +	KASAN_FREE_IS_VALID,
> +	KASAN_FREE_IS_INVALID
> +};
> +
> +static enum free_validation_result check_slab_free(struct kmem_cache *cache,
> +						void *object, unsigned long ip)
>  {
> -	void *tagged_object;
> +	void *tagged_object = object;
>  
> -	if (!kasan_arch_is_ready())
> -		return false;
> +	if (is_kfence_address(object) || !kasan_arch_is_ready())
> +		return KASAN_FREE_IS_IGNORED;
>  
> -	tagged_object = object;
>  	object = kasan_reset_tag(object);
>  
>  	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) != object)) {
>  		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
> -		return true;
> +		return KASAN_FREE_IS_INVALID;
>  	}
>  
> -	/* RCU slabs could be legally used after free within the RCU period. */
> -	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> -		return false;
> -
>  	if (!kasan_byte_accessible(tagged_object)) {
>  		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
> -		return true;
> +		return KASAN_FREE_IS_INVALID;
>  	}
>  
> +	return KASAN_FREE_IS_VALID;
> +}
> +
> +static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
> +				      unsigned long ip, bool init)
> +{
> +	void *tagged_object = object;
> +	enum free_validation_result valid = check_slab_free(cache, object, ip);
> +
> +	if (valid == KASAN_FREE_IS_IGNORED)
> +		return false;
> +	if (valid == KASAN_FREE_IS_INVALID)
> +		return true;
> +
> +	object = kasan_reset_tag(object);
> +
> +	/* RCU slabs could be legally used after free within the RCU period. */
> +	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +		return false;
> +
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
>  			KASAN_SLAB_FREE, init);
>  
> @@ -242,6 +263,12 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
>  	return false;
>  }
>  
> +bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> +				unsigned long ip)
> +{
> +	return check_slab_free(cache, object, ip) == KASAN_FREE_IS_INVALID;
> +}
> +
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  				unsigned long ip, bool init)
>  {
> diff --git a/mm/slub.c b/mm/slub.c
> index 4927edec6a8c..34724704c52d 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2170,6 +2170,13 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  	if (kfence_free(x))
>  		return false;
>  
> +	/*
> +	 * Give KASAN a chance to notice an invalid free operation before we
> +	 * modify the object.
> +	 */
> +	if (kasan_slab_pre_free(s, x))
> +		return false;
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_free and initialization memset's must be
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d6913c7-5a6a-412b-a4fa-0eb7b7622d4f%40suse.cz.
