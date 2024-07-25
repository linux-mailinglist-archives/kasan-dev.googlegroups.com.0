Return-Path: <kasan-dev+bncBDXYDPH3S4OBB67PRG2QMGQEC2C5HWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D46D593C6F5
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 18:06:20 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-52f02833519sf410584e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 09:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721923580; cv=pass;
        d=google.com; s=arc-20160816;
        b=pqpzUpQ1sF9RZVq7tEOQP1QIQptLcFpABMf1y3iaCNd9zSGCjoChBbtU+H0MQ6q+lV
         qjXLJuwRbbpXwbofKmygXxOxitMrDRb6TmoqLt5+JhK77PDmXt1gMXEmUqmY5E+VL3gy
         8fxZ0Rjfwh1m02X3JNmYZlZWbd0JG2YYSUdwGaQgXIEhn8vPb4oaBpi9mGumjbMNI6sT
         LWtoU/mdkODyx5M8RqdZ790vLXXAntULeQHa3xvYox0tvsZ9bLaq4Wpm+xvBYaS2C7+9
         idQ5YswScbIZmp0Y4Y9iktaoo5SN4hzkadWrZOVEYQFZ/NjViUsmMGN+g3JDlHdlcWgZ
         b46Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=xlyJpMMrLALVFbi0fNlsJBH5xLGPECSQMp1qXjUUvUs=;
        fh=3cqmD/fQt6Hnr0pCNmI8RewcLSlH89M21srG+oq3eh4=;
        b=Ase2LsISMJ0uHs/2+Wb/J9RUNLy+UEQKO3vb2agNXsWcTFxezw6LYQp0OigodeNTk0
         u7lUmurHZ/kO5nzXFm0HHLHcAKUDoEas6noILjrRcW/IVx/KUiVKq3V6KdY9gY5QWhsU
         vJ4pZfzgDMMDrokjh6kukTGvO7PAdGOmqoFGBzsNHZ1s/UPrGuD0hnhLWn4wp38FB3mg
         q5CII3jhwVZ4rHex6gj2b3YTbEHVDr5vbqdftdz0s3OmEhYg227dgv/Lp5mEV78rYqTB
         zHNgrTOZEjPzGs66DhWi8jAmZLViWCM0ha38+D/4/eLbPXaitFiWNuSGScxO3vjXglTy
         Cz8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=26F7tr18;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=26F7tr18;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721923580; x=1722528380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xlyJpMMrLALVFbi0fNlsJBH5xLGPECSQMp1qXjUUvUs=;
        b=NSnPWzUoqJycwbN1rdoiwsL1KYsAQj72PVDc5ym9pqHGnEZdVuE0psn5DCjxV50Nux
         LOZGspgFROthmOXOJmWxj6yhU5Mw2rK36cnATmwDplWvnoQsWY/MjiUHM8FntfmZA4j+
         pIpWHN+9252rlUsy8vzJVCwBKfEcwPnoKQ3t25Oq9ShzPdcsw7KvG70BhyXom3SKFuLi
         vCEcgluOhLQeLjko9WLy7Q1QSpO8r6bagwWmcSW5nretwbTbolsiQrpx56NM9Vn15vgR
         iMgYX5l5VyFH98R+c8HtkK2NdWAqBFnhrWNMp4j/uDzaa3zsu2XlVbsvaru3k6FOXC21
         p1pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721923580; x=1722528380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xlyJpMMrLALVFbi0fNlsJBH5xLGPECSQMp1qXjUUvUs=;
        b=SisjdUtHe37FHztZ+7bu3nXQRK8qz+qMYKH5W8rxqW/g56LHCEfDLTTG6DRqrdJ894
         5Ml4dlCevSeWT4gPECq8UyFmtHhLVRHkEbKCloO1p/eaAWvx1wCl8z8lcPSEsFD6a3L1
         dJF1l1HLXxP2MAqrzrR8Lpz8pwhgk3lvUVqHS98xUeukmHhpveUt34KeabDTv6umU/vP
         gch/RkOdKTUtsqLdd4oqbPVRgGYtlTTg046BoA4FjHA5OII8qJrxzHY2/Qm4UUo+t0kl
         qUCcb9/ao1AwNrkvqD0lF0ldw488BOwwqH/c9QiqUGKZlU1bTWifJTFjzv8fMu2BDuRc
         V++Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtqQgMSdLEqTzuNLwOSO3bUj2sVREU6lnMuPLtOXj15oMUeO94vNSIH7871Sepod7amelDHkjTHJYF4o5OzYKxn1IFtTVf9A==
X-Gm-Message-State: AOJu0Yxz5liEaBF11JNoDnvwWQccixvAmV23n5ORfprQBYM6FlqfCQU4
	+VmMi8eGTy5IKzddBSUmPpPd9ENUSSHN3lIVkKaq7fH7LdsIVNdQ
X-Google-Smtp-Source: AGHT+IGfwSSunwq6r52Oqx/7LZNamwOLBJ41QCO6l1PFmWhgplg7L5xuMdTTDRIY64nD/EXr5Z25zA==
X-Received: by 2002:ac2:4c54:0:b0:52c:def6:7c97 with SMTP id 2adb3069b0e04-52fd3f8ee01mr2487647e87.45.1721923579413;
        Thu, 25 Jul 2024 09:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2820:b0:52f:317:fe07 with SMTP id
 2adb3069b0e04-52fd422e198ls575986e87.2.-pod-prod-03-eu; Thu, 25 Jul 2024
 09:06:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuBoQ9PsdufCsVmYf9cPpRNYlGRyEKazpe22n192iULubOrkWx8emPPPTpJg+w4uK/d8yvc+Qw2Uz0OQR1z6bpVuE9fRnUz4T0Fw==
X-Received: by 2002:a05:6512:108b:b0:52c:e012:efad with SMTP id 2adb3069b0e04-52fd3ef050fmr2766074e87.12.1721923577328;
        Thu, 25 Jul 2024 09:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721923577; cv=none;
        d=google.com; s=arc-20160816;
        b=Sxt6YwaQrYOwfvddUrRKr7L/tEQQNNIvEO3U8yv+7x6+rgrC6bBdILeTcvGy7K2Wd5
         468irJrEab6msb8L+8HKvl1pbkfFTpi9TDUiN6CrP9i+1j/iBH7Rw6zjrsJoh/9ypUeV
         ukUyVZx7gdBdTSHf67ICmwbhVii749buQXnMY79XOA1YQrgPWFt2a9GLINhsmplllcdJ
         2ygoeHkNqeyvRcNyQ9lw2955MvGNEB302iAY4PS7RBeT4FVFu8l/VaPLmm95yjcNeqjm
         otGvLGsTr3qQRbZAoCe9QNH0ppivwx+eIJ4clvqhropqpXaVSBn4v2Yhj6HQdaD9Tvlx
         jNdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=atCrfLpqCItwLbU6RYWL9jaXMO3SoRG/K7yz6Y4y8VE=;
        fh=HmT76vcs+zO1ZG5U/D+utUyYOLBDzdTx2ZsGVz/wSR0=;
        b=Js7Z0E8OeWJk39Tl2+Fz0vVlJU/pVUVrMbo2c+XLvlv6P80iliFpHwMz2Jh4p7Zb/w
         T8qMWHWVyuJdT2iDeFNhjQjz7H7ySGjZuqwgQPCAj00qAQzxAg5hCGOpRdMxscxc5ZkG
         zTggffwWEivS3R4kTyNLAIkzNFDVUTwGBxVv8wCMyV/kXK1yDdRfbg+4f4KP4L6VaNjS
         8gxgLask9wTkbH+oFvlYBMxWF/d4wJKUJddKOoK7i6WyQsvVPcTqmlRkm/A8VpYOrjd7
         6UB1gh2i8FtUtwbPWsb6kRI9/s4f4A64MWgTjdlF6GEUmyw1CWwJsyYHmC9fkSp24Huc
         nshQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=26F7tr18;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=26F7tr18;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5b96739si40447e87.4.2024.07.25.09.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jul 2024 09:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 42B0521ABA;
	Thu, 25 Jul 2024 16:06:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1177D1368A;
	Thu, 25 Jul 2024 16:06:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SVDPA/h3omYFNAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 25 Jul 2024 16:06:16 +0000
Message-ID: <45d91310-1c0c-4e14-b705-eb35260be04a@suse.cz>
Date: Thu, 25 Jul 2024 18:06:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
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
 linux-kernel@vger.kernel.org, linux-mm@kvack.org
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
 <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev];
	TAGGED_RCPT(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Rspamd-Queue-Id: 42B0521ABA
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=26F7tr18;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=26F7tr18;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
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

On 7/25/24 5:31 PM, Jann Horn wrote:
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
> Signed-off-by: Jann Horn <jannh@google.com>

Yeah this "we try but might fail" looks to be a suitable tradeoff for this
debuggin feature in that it keeps the complexity lower. Thanks.

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slab

> ---
>  include/linux/kasan.h | 14 ++++++----
>  mm/Kconfig.debug      | 29 ++++++++++++++++++++
>  mm/kasan/common.c     | 13 +++++----
>  mm/kasan/kasan_test.c | 44 +++++++++++++++++++++++++++++
>  mm/slab_common.c      | 12 ++++++++
>  mm/slub.c             | 76 +++++++++++++++++++++++++++++++++++++++++++++------
>  6 files changed, 170 insertions(+), 18 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index ebd93c843e78..c64483d3e2bd 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -186,12 +186,15 @@ static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
>  }
>  
>  bool __kasan_slab_free(struct kmem_cache *s, void *object,
> -			unsigned long ip, bool init);
> +			unsigned long ip, bool init, bool after_rcu_delay);
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> -						void *object, bool init)
> +						void *object, bool init,
> +						bool after_rcu_delay)
>  {
> -	if (kasan_enabled())
> -		return __kasan_slab_free(s, object, _RET_IP_, init);
> +	if (kasan_enabled()) {
> +		return __kasan_slab_free(s, object, _RET_IP_, init,
> +				after_rcu_delay);
> +	}
>  	return false;
>  }
>  
> @@ -387,7 +390,8 @@ static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
>  	return false;
>  }
>  
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> +				   bool init, bool after_rcu_delay)
>  {
>  	return false;
>  }
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index afc72fde0f03..0c088532f5a7 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -70,6 +70,35 @@ config SLUB_DEBUG_ON
>  	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
>  	  "slab_debug=-".
>  
> +config SLUB_RCU_DEBUG
> +	bool "Make use-after-free detection possible in TYPESAFE_BY_RCU caches"
> +	depends on SLUB_DEBUG
> +	default KASAN_GENERIC || KASAN_SW_TAGS
> +	help
> +	  Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the cache
> +	  was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
> +	  kfree_rcu() instead.
> +
> +	  This is intended for use in combination with KASAN, to enable KASAN to
> +	  detect use-after-free accesses in such caches.
> +	  (KFENCE is able to do that independent of this flag.)
> +
> +	  This might degrade performance.
> +	  Unfortunately this also prevents a very specific bug pattern from
> +	  triggering (insufficient checks against an object being recycled
> +	  within the RCU grace period); so this option can be turned off even on
> +	  KASAN builds, in case you want to test for such a bug.
> +
> +	  If you're using this for testing bugs / fuzzing and care about
> +	  catching all the bugs WAY more than performance, you might want to
> +	  also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
> +
> +	  WARNING:
> +	  This is designed as a debugging feature, not a security feature.
> +	  Objects are sometimes recycled without RCU delay under memory pressure.
> +
> +	  If unsure, say N.
> +
>  config PAGE_OWNER
>  	bool "Track page owner"
>  	depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7c7fc6ce7eb7..d92cb2e9189d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -238,7 +238,8 @@ static enum free_validation_result check_slab_free(struct kmem_cache *cache,
>  }
>  
>  static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
> -				      unsigned long ip, bool init)
> +				      unsigned long ip, bool init,
> +				      bool after_rcu_delay)
>  {
>  	void *tagged_object = object;
>  	enum free_validation_result valid = check_slab_free(cache, object, ip);
> @@ -251,7 +252,8 @@ static inline bool poison_slab_object(struct kmem_cache *cache, void *object,
>  	object = kasan_reset_tag(object);
>  
>  	/* RCU slabs could be legally used after free within the RCU period. */
> -	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) &&
> +	    !after_rcu_delay)
>  		return false;
>  
>  	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
> @@ -270,7 +272,8 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>  }
>  
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> -				unsigned long ip, bool init)
> +				unsigned long ip, bool init,
> +				bool after_rcu_delay)
>  {
>  	if (is_kfence_address(object))
>  		return false;
> @@ -280,7 +283,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  	 * freelist. The object will thus never be allocated again and its
>  	 * metadata will never get released.
>  	 */
> -	if (poison_slab_object(cache, object, ip, init))
> +	if (poison_slab_object(cache, object, ip, init, after_rcu_delay))
>  		return true;
>  
>  	/*
> @@ -535,7 +538,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>  		return false;
>  
>  	slab = folio_slab(folio);
> -	return !poison_slab_object(slab->slab_cache, ptr, ip, false);
> +	return !poison_slab_object(slab->slab_cache, ptr, ip, false, false);
>  }
>  
>  void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..cba782a4b072 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -996,6 +996,49 @@ static void kmem_cache_invalid_free(struct kunit *test)
>  	kmem_cache_destroy(cache);
>  }
>  
> +static void kmem_cache_rcu_uaf(struct kunit *test)
> +{
> +	char *p;
> +	size_t size = 200;
> +	struct kmem_cache *cache;
> +
> +	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
> +
> +	cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
> +				  NULL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +	p = kmem_cache_alloc(cache, GFP_KERNEL);
> +	if (!p) {
> +		kunit_err(test, "Allocation failed: %s\n", __func__);
> +		kmem_cache_destroy(cache);
> +		return;
> +	}
> +	*p = 1;
> +
> +	rcu_read_lock();
> +
> +	/* Free the object - this will internally schedule an RCU callback. */
> +	kmem_cache_free(cache, p);
> +
> +	/* We should still be allowed to access the object at this point because
> +	 * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU read-side
> +	 * critical section since before the kmem_cache_free().
> +	 */
> +	READ_ONCE(*p);
> +
> +	rcu_read_unlock();
> +
> +	/* Wait for the RCU callback to execute; after this, the object should
> +	 * have actually been freed from KASAN's perspective.
> +	 */
> +	rcu_barrier();
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +
> +	kmem_cache_destroy(cache);
> +}
> +
>  static void empty_cache_ctor(void *object) { }
>  
>  static void kmem_cache_double_destroy(struct kunit *test)
> @@ -1937,6 +1980,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kmem_cache_oob),
>  	KUNIT_CASE(kmem_cache_double_free),
>  	KUNIT_CASE(kmem_cache_invalid_free),
> +	KUNIT_CASE(kmem_cache_rcu_uaf),
>  	KUNIT_CASE(kmem_cache_double_destroy),
>  	KUNIT_CASE(kmem_cache_accounted),
>  	KUNIT_CASE(kmem_cache_bulk),
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 1560a1546bb1..19511e34017b 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -450,6 +450,18 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
>  
>  static int shutdown_cache(struct kmem_cache *s)
>  {
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
> +	}
> +
>  	/* free asan quarantined objects */
>  	kasan_cache_shutdown(s);
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 34724704c52d..f44eec209e3e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2144,15 +2144,26 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>  }
>  #endif /* CONFIG_MEMCG_KMEM */
>  
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
> +
> +struct rcu_delayed_free {
> +	struct rcu_head head;
> +	void *object;
> +};
> +#endif
> +
>  /*
>   * Hooks for other subsystems that check memory allocations. In a typical
>   * production configuration these hooks all should produce no code at all.
>   *
>   * Returns true if freeing of the object can proceed, false if its reuse
> - * was delayed by KASAN quarantine, or it was returned to KFENCE.
> + * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was returned
> + * to KFENCE.
>   */
>  static __always_inline
> -bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> +bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
> +		    bool after_rcu_delay)
>  {
>  	kmemleak_free_recursive(x, s->flags);
>  	kmsan_slab_free(s, x);
> @@ -2163,7 +2174,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  		debug_check_no_obj_freed(x, s->object_size);
>  
>  	/* Use KCSAN to help debug racy use-after-free. */
> -	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
> +	if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
>  		__kcsan_check_access(x, s->object_size,
>  				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>  
> @@ -2177,6 +2188,28 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  	if (kasan_slab_pre_free(s, x))
>  		return false;
>  
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +	if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
> +		struct rcu_delayed_free *delayed_free;
> +
> +		delayed_free = kmalloc(sizeof(*delayed_free), GFP_NOWAIT);
> +		if (delayed_free) {
> +			/*
> +			 * Let KASAN track our call stack as a "related work
> +			 * creation", just like if the object had been freed
> +			 * normally via kfree_rcu().
> +			 * We have to do this manually because the rcu_head is
> +			 * not located inside the object.
> +			 */
> +			kasan_record_aux_stack_noalloc(x);
> +
> +			delayed_free->object = x;
> +			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
> +			return false;
> +		}
> +	}
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_slab_free and initialization memset's must be
> @@ -2200,7 +2233,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  		       s->size - inuse - rsize);
>  	}
>  	/* KASAN might put x into memory quarantine, delaying its reuse. */
> -	return !kasan_slab_free(s, x, init);
> +	return !kasan_slab_free(s, x, init, after_rcu_delay);
>  }
>  
>  static __fastpath_inline
> @@ -2214,7 +2247,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
>  	bool init;
>  
>  	if (is_kfence_address(next)) {
> -		slab_free_hook(s, next, false);
> +		slab_free_hook(s, next, false, false);
>  		return false;
>  	}
>  
> @@ -2229,7 +2262,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
>  		next = get_freepointer(s, object);
>  
>  		/* If object's reuse doesn't have to be delayed */
> -		if (likely(slab_free_hook(s, object, init))) {
> +		if (likely(slab_free_hook(s, object, init, false))) {
>  			/* Move object to the new freelist */
>  			set_freepointer(s, object, *head);
>  			*head = object;
> @@ -4442,7 +4475,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  	memcg_slab_free_hook(s, slab, &object, 1);
>  	alloc_tagging_slab_free_hook(s, slab, &object, 1);
>  
> -	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
>  		do_slab_free(s, slab, object, object, 1, addr);
>  }
>  
> @@ -4451,7 +4484,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  static noinline
>  void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
>  {
> -	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +	if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
>  		do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
>  }
>  #endif
> @@ -4470,6 +4503,33 @@ void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
>  		do_slab_free(s, slab, head, tail, cnt, addr);
>  }
>  
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +	struct rcu_delayed_free *delayed_free =
> +			container_of(rcu_head, struct rcu_delayed_free, head);
> +	void *object = delayed_free->object;
> +	struct slab *slab = virt_to_slab(object);
> +	struct kmem_cache *s;
> +
> +	if (WARN_ON(is_kfence_address(rcu_head)))
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
> +	do_slab_free(s, slab, object, NULL, 1, _THIS_IP_);
> +	kfree(delayed_free);
> +}
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
>  {
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/45d91310-1c0c-4e14-b705-eb35260be04a%40suse.cz.
