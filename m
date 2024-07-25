Return-Path: <kasan-dev+bncBDXYDPH3S4OBB5FFRG2QMGQEDLLWOEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F54C93C2E6
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 15:28:22 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ef1b1f93basf1945551fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 06:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721914101; cv=pass;
        d=google.com; s=arc-20160816;
        b=c1HsIfW+hs8DjbcHPpLX/GLzoMT58f7iQeNqHXhquHy9QpEyK9GbHiOzSZvFvllktg
         jEB4pxOvvoozlcIJsmYlKMZwDxcF6CERZvoWvkti7ICwfpIs5F0WI7sdjAuFqxPY1se5
         7FeUgAVReIsWGwX+dV74aVJYxifBcuoXc2ibbECqEM91EV1p6zxHspnqpjAg1t+Kp9mT
         KQby/R1rvcuUM/QfDitLtwAAq8NkoumoOBR+CQlFrKoJuIK+dZhZai3tquReijLfkafD
         qtC1VwwuoZFts0FbCIIWvqQEOgz7sEm8eNErXjDcO7eT1dpTT0LohvMqgDHydiuR0nco
         8NXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=7AZMtqCUMI9dsiJAhjIc3xAlEjfOWnmg3kSPtkLYvZc=;
        fh=s+gVuuxHuEEeBpCvT22XaoHHOhU/tBVM+liDXbeAV/c=;
        b=pBdHhc3N6m3+ADu6omQNOPUOzxpBh268oRA5XJf/G7LII2lkR/1QoEUKgO94wIs1YR
         GulORBG1uC3SS44Jru3jtN9xlL3PvyzV6apwhesPMc38fqdQOXxY6JTqUpgKFIfEw5Jp
         m7Lpwwqkr3coZE1BP4fMzbQPXp18YilqxpMHaF5yTszNcz5dsVQ4BxhB56U5SEjMtWug
         Ppuog3ZDO6oaUplpLpkHMxWf2C/A0r0/Lmq53ZqKUqCeMiavfa9Ss1DtnKZbfLwyMZKm
         D1qN3Io2J9tQq66S79pidZah5Jj5O9emPFEdng8qT40PxdkAPuLDOgVJcFzLP+Zr3HDq
         /zbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qwgv5WgF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qwgv5WgF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721914101; x=1722518901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7AZMtqCUMI9dsiJAhjIc3xAlEjfOWnmg3kSPtkLYvZc=;
        b=sVxK6PfiNdyoMAMN1L2oDFtH//18oasOfeQNPWWmGlAJRa8ZvpfrLWZj14A2KclAW9
         7xkYaI9qImgYyrFBVUFcOCeVzC4/TZcVr5R44+cYTobJFPVNfyyKedVOPj1dEVbV9rAA
         AA75y+XCZedXzKU7pmHIwTKsc/PlKTKX58c+/jtCeLrhY3rHll1TDiD4NMIUh2OnO0I+
         aZYkzg+JlUbG+6EyHPcBd5cOSszi6zosMVItnb49JPQd84OJ4ouQyPorMPUosIU0QJvj
         /8ANpVFhnak1ZFlQvcHeayhmi99+WkHczedftJwfq4MNvwt+DaiRfZAWliD/c8agn1ZQ
         wR5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721914101; x=1722518901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7AZMtqCUMI9dsiJAhjIc3xAlEjfOWnmg3kSPtkLYvZc=;
        b=s0zLRwwjQxQIdkRHvGf60UTOmwUHQCfI6RDXZd4bMN1oLPqRhc7AlQw3/B1StPoGjZ
         iAUoEYz8LaNIoSnVlKOFu63LFUOqwlH6pNea1WnO6dhcydUhcrauAftmzTu55myu9rL9
         i/kyt7WO4WnOFeIr+54VBry51AZNENrxDhsmyn7zUcSZN2we/iuVvWBKIG3UxMKSbAl1
         cVeUH+dcM3Ru4PRZ+XUQegYTpWq5W0AqOsTLmVbIGXzpQijENGHyQrA1wYiMPIZdsEi2
         mltTAjzhda5bHeVr2hG59UjYALwtl0g4hvGeSnBVyNR57UiEVVM3G5xxw+vt9fCBN4O3
         p6ug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVNICwykv3EiUdVXxlLeQ4vwufuxAuNyn5WHc8Y4mk8PBe14ACMjRTQUAVTGynwcq0OtCCvwo21QZ7JQI0kgaGynm9MMbVmnQ==
X-Gm-Message-State: AOJu0YyhyXSr9LTy4n16rSoTLQOad0j46Yu6EFNe/hv2Gltl9GTOSD3h
	yIKXIm1XuqaXh7kbmvdJTDmxYgIHMeKcajuUrVB24ts5ErriBCpT
X-Google-Smtp-Source: AGHT+IFaAPGHHKGYZPJsp+Ja8oztEZoXuju9cTsl2omSPCvP7kgnmHLZZP2FzcmNl5gkOEwtuyvqQw==
X-Received: by 2002:a2e:9110:0:b0:2ef:2f60:1950 with SMTP id 38308e7fff4ca-2f039d92401mr21303211fa.30.1721914100934;
        Thu, 25 Jul 2024 06:28:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be9c:0:b0:2ef:256c:a25f with SMTP id 38308e7fff4ca-2f03aa79675ls3326961fa.2.-pod-prod-02-eu;
 Thu, 25 Jul 2024 06:28:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYFZKNWqQ1wXLChwJWwxvFnsOxmY+g+GBMtifHmA+3OjBMHfaj0GqBSWHc/qGMtj9cze2lmxDxsIP8beIDGeE66CHfTYBZaxNrIA==
X-Received: by 2002:a2e:3511:0:b0:2ef:2dc7:a8f0 with SMTP id 38308e7fff4ca-2f039db070fmr19291671fa.45.1721914098755;
        Thu, 25 Jul 2024 06:28:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721914098; cv=none;
        d=google.com; s=arc-20160816;
        b=M1pjv1ryh4x/AOtzajLeBtGvSDWD1NgTzBWJWz3lN7o/2lnrPb8qJnHWdpTG0O8EZJ
         7rwS7fuTuTsHUhQIku7YBkxuGEkB/+8SRkXDWDmJ18y9ojXfI2oOa0gnIqYvZ1Syc0X8
         3OnNm0w4J1tEzRDrCryNTufRTdyuKzxzD2j9C8rUh1s6vO1RMqfx3p+vn+yHmKGSB8G8
         SZgtLRdCqXhsjotGUODnjpzT6V00uUsZHco5iUs+WZol5HXvlK+MR1DszgiHoyie3HPW
         Ina/zi0C8EW9/vokQSOYsEQlxV+zdSJ6SuAjJYnh6/N/ZOQhHdqjw8VeD+aUAwBkQlY3
         K+PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=nzZHcDWPcyAz8CXsFh+8t8U1Us29p2EGEPiftIzXCfo=;
        fh=HmT76vcs+zO1ZG5U/D+utUyYOLBDzdTx2ZsGVz/wSR0=;
        b=G32p+55giVV9VZ1ABeXEoBIHCCFy97CY+4ES/ngYe3lB18qPq11N+FzgiSPZ1lS290
         QdC4F+MpWafv8wC5lu5r3hizzXI0YzgXjFPtBzr/tPfgYwy97oY9zjN4uc9oPEs7jYLQ
         yGIcDpsSWeddodmQ+/RQvcV86QbuNYuMKJ+vpbDvGiu1QLosA2TQLq49ytc3A6Ymt3z6
         Au5D0u0rR+Vg7RPtSIQUDLS7/dEZ40rYsdGrQaF3mPESHcnTCvE9owwUAzGk/+1HkIat
         r7P0W2z0U3NOZ/oSYmecYpNEtXHPsNhFByQGSSfPnOkd8KgT7yEhpf+zkk1dDPas4RZ3
         VLOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qwgv5WgF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qwgv5WgF;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ff6e21c4si604575e9.2.2024.07.25.06.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jul 2024 06:28:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2D2241F45A;
	Thu, 25 Jul 2024 13:28:18 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 047A813874;
	Thu, 25 Jul 2024 13:28:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id EEqDAPJSomZlAgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 25 Jul 2024 13:28:18 +0000
Message-ID: <9e05f9be-9e75-4b4d-84a4-1da52591574b@suse.cz>
Date: Thu, 25 Jul 2024 15:28:17 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
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
References: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
 <20240724-kasan-tsbrcu-v2-2-45f898064468@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240724-kasan-tsbrcu-v2-2-45f898064468@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-2.59 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev];
	TAGGED_RCPT(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -2.59
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qwgv5WgF;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qwgv5WgF;       dkim=neutral
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
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
> slabs because use-after-free is allowed within the RCU grace period by
> design.
> 
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when this
> option is enabled.
> 
> Note that this creates an aligned 16-byte area in the middle of the slab
> metadata area, which kinda sucks but seems to be necessary in order to be
> able to store an rcu_head in there that can be unpoisoned while the RCU
> callback is pending.

An alternative could be a head-less variant of kfree_rcu_mightsleep() that
would fail instead of go to reclaim if it can't allocate, and upon failure
we would fall back ot the old behavior and give up on checking that object?
But maybe it's just too complicated and we just pay the overhead. At least
this doesn't concern kmalloc caches with their power-of-two alignment
guarantees where extra metadata blows things up more.

> (metadata_access_enable/disable doesn't work here because while the RCU
> callback is pending, it will be accessed by asynchronous RCU processing.)
> To be able to re-poison the area after the RCU callback is done executing,
> a new helper kasan_poison_range_as_redzone() is necessary.
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

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slab

...

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

I think once we have the series [1] settled (patch 5/6 specifically), the
delayed destruction could handle this case too?

[1]
https://lore.kernel.org/linux-mm/20240715-b4-slab-kfree_rcu-destroy-v1-0-46b2984c2205@suse.cz/

> +
>  	/* free asan quarantined objects */
>  	kasan_cache_shutdown(s);
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 34724704c52d..999afdc1cffb 100644


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9e05f9be-9e75-4b4d-84a4-1da52591574b%40suse.cz.
