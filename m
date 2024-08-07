Return-Path: <kasan-dev+bncBDXYDPH3S4OBBAWNZ62QMGQEHWPUSKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 55B6994B21F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 23:26:28 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-52efce218fesf270095e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 14:26:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723065987; cv=pass;
        d=google.com; s=arc-20160816;
        b=AJebsos2NCGTE8QIkQUM6OTG59UItW40aM+a+OghbtHOd0rsEKUXd4yJh8/23bMl9q
         AyAe2KT3oxn2PCw9YN766IZqwg8BfuQB3IwpEmdpjORVukXDo7ZGblsWLq6w9+Y1MWZI
         Yoomh3WiEAeyDtl8vu2hApMz30ad/0e18vbYcOVIZdQ9kdoF4KNWgbCG4y4p1VHKbJKp
         xezshFrtTTku4GGK0Xyo4nENd/zIiPk+ybrP1hCjARK4hbjzhVMLJ7uV3Iq9vp99342n
         rfG3B+DysQ5LBW3dNNxDAVq7JQt4C1t8SlpSkGusYyUa1l6uYgNjPX9hfddZSHEwMGlR
         BXLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=tvKpoO3YuaTNy3PHpEOAVeAmWpwJYmWIPgOIx2CcT9w=;
        fh=c2qwkB3vVuhIvo9lKUPT25VLGQKI2rtvP/Tpay76yLA=;
        b=F1C9FPPXto2Y7WLw/f2bKvB/fntpOCvcv6b+2X9K7VYlrlRJ3qPu0ZmMguhom/aRxG
         Cvlowm5a0r7LuL2gRQ0uKvdS8HewgwJLGx3osgbvQXefzyzacLmMgasxEvs26S0jmBHt
         G0O2l72rl0adsMMVRUfEcU35nBRJjmP9OQ5wmYEnUmuIecBS5Q2cIeqWk6GfcqxxDeC+
         pYciEgT/EuqqXybuvqvU3cp1czB5hSIdGJdtRjLC/Bbt7FU73HzsD8y3TiRgP8AQIhHj
         1udEbe95CjA6kxA7ZDIndSOzav5XltxXIGI2V5Meixd/qSNB3XxdkeTlTSLuuVSxc+zJ
         Ehsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nuCqc8hG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nuCqc8hG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723065987; x=1723670787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tvKpoO3YuaTNy3PHpEOAVeAmWpwJYmWIPgOIx2CcT9w=;
        b=uaVvaP6NC/wd0AAwWXJE7T+XytSB7f9BiUNvQlNPd1iGdiCYG3jLol03IIUBCVvUsF
         L+F0jHvJ8Kls7oUmmNCuOcahsawz+eS2OHwGIC8xL1nzPMZKqo33wIp7jJp1Ck/PMEQp
         oHw2mybOtJ6zI9SIpNDCFeC9IAB4hIwYfpm+LmbbbFOLYjMVPFZirWphMT8GPQt8DfIO
         EXEqTQJNXMRUZwhsX4lfAK5aKp4Udzynf8jgl/Nlq3lh76hhKmaZTbC5ibpEYGmhkegI
         bTHd82u8bvAaTzDkO31V6vDEnh3/mupGGypc0HJIjZUxes4ZE+ylMm5mRcqn3mPUHZTa
         hP+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723065987; x=1723670787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tvKpoO3YuaTNy3PHpEOAVeAmWpwJYmWIPgOIx2CcT9w=;
        b=dlbsFp77YcnEiM5WB5yZToFFpCws9yTWomV40DUxH71O7v3gvuLR94eHWL3Tw4sgqB
         5Eh+WNwj2rukI8x2yrmqCoZ+teY4BxpzC+hiXqx60ug8qfKwIzhq7qWwQqsUmQCH4K7L
         fJQ/ZfYu/N6PS+tV/jSBN3SAFc4m+vN5U01/osAj5NaoYjXv9M3h86Dn/S1iMk4UnrE4
         e6Zi9LCIg5dqOmhNOrQjHZUyRyy06DZW8iYbMPRhrla7IihIMxkqd7PQ74Q5GhbbS5LQ
         a/kRt9jy3DvReId/9qhYdlY6Zj+/81gNOG2vhYqj4yWwTrCjIX/Z3fd1i/Na7dt5Ukff
         nKHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwvyVZPNXBaMOM7yvKqYBX57qR4YbHZTVFOpFPwiMyhZTqIX4EzmEs9iJLvoNVwnXgrG+Yu70o9X4DXCuL/5qM8Rh5apLsFQ==
X-Gm-Message-State: AOJu0Yw3kBdCfS96r0ozdydg9uLZz7NVNBb2qq/uVfz7z2xrXPhqrl3Z
	q5CAjQIhI7Y/XMZtl2hL/ycnrL89fjku6ZLFvAEMnVJFFd6Rl0C5
X-Google-Smtp-Source: AGHT+IGtp8scQevJLsd1ppzMRZerUAkb6cy8IOkHMPtpMS5a3VQ0uTm4mt2GfAfZg5DsXPAw9fVdhA==
X-Received: by 2002:a05:6512:239e:b0:52c:daa4:2f5c with SMTP id 2adb3069b0e04-530bb395ea1mr14071592e87.42.1723065986845;
        Wed, 07 Aug 2024 14:26:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0b:b0:52e:9bbf:bef3 with SMTP id
 2adb3069b0e04-530e3952a42ls157134e87.0.-pod-prod-04-eu; Wed, 07 Aug 2024
 14:26:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLy1xa6QprPyOs0NkvQakeDxfC+JT9TslnwRIdJ5R5uo/9xzXeyyH1BJhdKZD5hyP6gvjJNtVpp+eGpdmNtfwhQKUNIP9Rnrx8Gw==
X-Received: by 2002:a05:6512:3083:b0:52b:8ef7:bf1f with SMTP id 2adb3069b0e04-530bb36c127mr12822777e87.17.1723065984519;
        Wed, 07 Aug 2024 14:26:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723065984; cv=none;
        d=google.com; s=arc-20160816;
        b=wYaVAb9PdDczayfIAkvAeOpsttcvqm11MVrJMFX2K86TN1Wxnv2N3zewP1iNJrA3cV
         jpAz+hkr6cckNuqEJI97JpQyce+oM9+izVQgReaIj7KcSnrzxT2JJQYd1McEtpIJWQLI
         tFL34goRPsnFydDj1uYpqTmMb3lBKD2hhfibFtk6/bNM6K2AxOuTxr+qDmwbEbnvt7dJ
         izmaxvV3AyCZ/i96ETiDKG7qqQuhkQivnb9xtrdJHKXvH6JJOsxhDexy2cSsl9rKj+Tz
         U0+662iT2QefFug3YXJoLmfWZWQ5+VobPkfsRAfuA7LL9tPx8qT/l+lufU+rTsLmTLLU
         6lww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=yFaaPhzAcNeg29ttS56jgyY0UwZ+hQiKmIaFkQWJJyg=;
        fh=QQQbUPTd7BKvLP/JMAEk1jecmoELXGKtNiSX0qHuHFI=;
        b=vvOeLIRgf5yVWx5Rk0nH8/kLTLX7o7yjEQe25O9/VWbFIfRnjxJdif83rdF9inn0Ha
         DZLp0EEMk4svWwT9oPb1ObNmajLa/EpEyPYJitjUjXLRihnruf87ua2EPBUlegNNaEZ3
         ThAR0//BdpYYq0mY9OGcknVbdJ5fvLA0jAcPReMFXCgZi+lM8nkohq38BP6oxcHkNP8/
         byt4OE441pj+sc3YRCUQwl/QFpkeMXYCqCrXsPaD2fCcRh5B9Gbo2gPUFQo1Ti4IEN5D
         8PqLI80tPMMjMBCx555alxP4ZsiW1w335+GBEsb+QAQTht0CxWHIjHQ+t80MeYqy7YUG
         8/ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nuCqc8hG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nuCqc8hG;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530de3ec20esi51631e87.7.2024.08.07.14.26.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 14:26:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7EB621FBA3;
	Wed,  7 Aug 2024 21:26:23 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5159013297;
	Wed,  7 Aug 2024 21:26:23 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id w4k2E3/ms2bTYwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 21:26:23 +0000
Message-ID: <c41afd73-97b4-4683-96a1-0da4a4dfeb2b@suse.cz>
Date: Wed, 7 Aug 2024 23:26:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Content-Language: en-US
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, David Sterba <dsterba@suse.cz>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
 <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-2.79 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	TAGGED_RCPT(0.00)[263726e59eab6b442723];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[19];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[appspotmail.com:email]
X-Spam-Score: -2.79
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nuCqc8hG;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nuCqc8hG;       dkim=neutral
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

On 8/2/24 22:31, Jann Horn wrote:
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
> Signed-off-by: Jann Horn <jannh@google.com>

Actually, wait a second...

> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +	struct rcu_delayed_free *delayed_free =
> +			container_of(rcu_head, struct rcu_delayed_free, head);
> +	void *object = delayed_free->object;
> +	struct slab *slab = virt_to_slab(object);
> +	struct kmem_cache *s;
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
> +	kfree(delayed_free);

This will leak memory of delayed_free when slab_free_hook() returns false
(such as because of KASAN quarantine), the kfree() needs to happen always.
Even in the WARN_ON cases but that's somewhat less critical.

Thanks to David Sterba for making me look again, as he's been asking me
about recent OOMs in -next with heavy kmalloc-32 cache usage (delayed_free
is 24 bytes) and CONFIG_SLUB_RCU_DEBUG was so far almost certainly confirmed.

> +}
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
>  {
>  	do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
>  }
>  #endif
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c41afd73-97b4-4683-96a1-0da4a4dfeb2b%40suse.cz.
