Return-Path: <kasan-dev+bncBDXYDPH3S4OBBV7GUPCAMGQETLEFJRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 40E1CB15109
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 18:14:17 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-456175dba68sf34794495e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 09:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753805656; cv=pass;
        d=google.com; s=arc-20240605;
        b=eVPOQljtqx0G1FlgLZbT1WJeU9vzDdJhgzaFAn72aQ9T0OI2LHr+kYnIf0RYuYzPa7
         oxeKhr2jo/K5enK8MkCe+BbMvmxFx9WsD0fPzHwB5YRAIURx++v988Y4rwasi3OWIeGf
         M9oDRZChUWQotfQ9MVRjixUf4Y2GziQB3G15E+MIv1Ma7miSNLOOC+HeCcMiMr1eHZl+
         irwBtpMYiD4mTC1hjD4EDvMgeIweQpKiDpT8FWEQzcyjiQbnGA8nxDUOBE96ntrXBxC2
         uUOKCuyjOFiGdqklgNYtUTdbHfpyOMhlV3aYRwrV4jIC4MGEQrHlJFsC49gwDDFZ2ZUT
         WmOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=f2teMCQqrHsVkZVvUMjGP7ZeMPLqaZRZ3hSV3Q3+1IA=;
        fh=LoL8hUMlg674/jY/gKpEV6kS+Qg2cGiYOcjiSGOuGb8=;
        b=iuGA8VNvoVmX0wFOWHrqYFTEyFwg7KeCnkM7IMUKVYgSihoUg8FpGxA0SAxGA74xxY
         ZMdER5V63hYO7Ar7/0SoWHE5gJPbNVpsVrSY2nNi+AQ2+s5d79l3HfDHEcZIIZB1g30B
         i4z7ui2S1CbFGY+LxFPStAHNaElpuQvcbR79aaoqbd8JDJaLgZFfErfEuNX6wCgBkj17
         7illUfXAKlXkkaTI8tQo5873vXCmQe3WNIwqPv26YUJWFam0cfyYWJecZKwCSwNHXF4G
         /XnKlNKTaak5IljenIjtcoCdukxSiAWvxJb/LFs32PTSOIZnKxR6RqFMwMzvccS8ef8a
         oVng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dV7yyvvm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dV7yyvvm;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753805656; x=1754410456; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f2teMCQqrHsVkZVvUMjGP7ZeMPLqaZRZ3hSV3Q3+1IA=;
        b=VRRsxxKH2HTkLUM1XmdDQsmqUrzs9YgPexKYL8gu9cZg+JBGicUrxyjJCMRV0DZlm2
         EeQjQ/WxgpbCz20YisLgrCJllyrjyl1z6FSNYGGTs2dP9d6ndoZrVr+wXVuUov7khi9W
         brn30H7r1HJSdIcTkiuiB75zFjJhCTLiE8MjEeCMGXEXZmMNTwH6V1/9/Mkx8zTA9JND
         AiZtrh/wu6vKki7aHFJgwWCzlE8PCaZP5bq8p6YenD825LQvZMY7GTd7XSKhkSQBS33g
         B+3zSDVO/OGtOerIVKVSqOqMfCHpiWDi2Qa/zzMQWndsf5aJT3Cn3Ymsb1Y4wZau6JFm
         YR/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753805656; x=1754410456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=f2teMCQqrHsVkZVvUMjGP7ZeMPLqaZRZ3hSV3Q3+1IA=;
        b=fc+DEjMFTJrNCcH8KVNzF1EGXRVIIwwXKVd/YfunN5rIvZbgY4NZNdkXwRPiGE2OyD
         6lQGJkJ4aDN429r9KkzMyGajgvaIv6vdxCBrKgcEWv8noJ2Tjbvj4vkfUL9isbXF9kUj
         2n4nGT5CZLgt5L6CqSg5ZhSYH0otR3wlOAV7KzUZHfZWB8V6IDu3DFCClUo1N1v2Ns/j
         f+p0h9Jb+xk89JFreI+ncOh/Tp0eIDMQrPqDFRqghskLbP2mOH5hv0N8MeOMrWRiAWw+
         evxuMEI4+MvdfR5n8+0ZcAuD0X4WccgUOknhfAWQsYTioS3yypwDXLvlDPnWGkh6rpa0
         7J2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU94eMMDL2Pxdb88yPphbKJWNK5qtlz0rb4BXgiesCQ5YlukwAB4bum75K1iXrf4MrPBL3D3A==@lfdr.de
X-Gm-Message-State: AOJu0YytCqg1IUxIbsLsd+uFiBR0WM3LtWDYIb7iSmxENEb2TjuWtvlD
	+U1CQWHHGkP8LwZD5htpOre8bByxmyKrpI7Xg6UWvAukzWFq3qg3nd01
X-Google-Smtp-Source: AGHT+IHs7nenQWBr15Nys9rz226d/weCqgvF/ChHviArwhOZAV1Pyx1X2eP7nCZPiXGT5FmYvykUYg==
X-Received: by 2002:a05:600c:1e12:b0:453:6ca:16b1 with SMTP id 5b1f17b1804b1-45892bde4f2mr3209745e9.26.1753805656088;
        Tue, 29 Jul 2025 09:14:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZckBfnXwwNqeuZ7il5lQujclFnUduuGbqmYrbGIu4UMMQ==
Received: by 2002:a05:600c:5298:b0:456:241d:50d0 with SMTP id
 5b1f17b1804b1-45875c582ffls23222825e9.2.-pod-prod-07-eu; Tue, 29 Jul 2025
 09:14:13 -0700 (PDT)
X-Received: by 2002:a05:600c:46d0:b0:456:28d4:ef1 with SMTP id 5b1f17b1804b1-45892bdff7bmr3315955e9.29.1753805653366;
        Tue, 29 Jul 2025 09:14:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753805653; cv=none;
        d=google.com; s=arc-20240605;
        b=YOfKA7p9SwouG+w+znHENIRx4QpbEawxH0E+1bZk4wxxhlspYFvkD9bP6Lzr0qoRpw
         hdQ9Jp9+57dgUjq3JljyNCoI4/2mhf5i7ucnPYTrJ2p/elqxFIgIKzv5sNWGnTyEGl/O
         h8PdcvAOkAqRIOKfVedcgnVaEANUBYEr7mLhZmsunSf1L86I2AD8l6Im5vq1wHANtszr
         C9N5tIPJAgTTcB4xPpznKNRTiIsCfKH/9ShuMuOvaxYkmRE/yIwIppzME2rPYTEQjb8a
         2rnYKmXaVyDnpYxERrcG5dbINkqgyx/O01KpNmmZ9hheDnwVMIiWxY3pXAm9vZ/SkR5g
         yT8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=tRO/PahJzO9a91Wm1hhkBQhQCmcAHpY0UEI4yNOBKrQ=;
        fh=Z1akeSglz1VnNM7UindtLmbCq84Y8wrvu/XSLABU9l4=;
        b=CqPAQrp7xwHm34YdvTqIEDQDURqdDZpwIJRz9u4uVGpahlrrIAYvzzxXiXSjfBqf+N
         LL7enTjL6we0JBrNV1tDffeWh0QkiJ1Pa5o/e3nEIfwJ4LOUUUzz43IfHEMigTyQ2Oc7
         BWvXY4NOP1oIX9YZ6rUj+HI0N2smvTyeQ/5fKhwlwhaJRbuslN0TKqKq0vlyY01KiBqv
         JcXT5CfO+wZUSRQ07awGbCu7DsTo+7c+8LmTBelcopqZaaooc33Zu1Kj1BZvvthiV+Pg
         HGKMOmm1UKWYjZ+4CHpJeDtl9HlbWaVRzftWGHfyK8LTLwmhLpFTno4FjakTA0hd1Vq8
         WexQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dV7yyvvm;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=dV7yyvvm;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588dd3fe52si758455e9.1.2025.07.29.09.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 09:14:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C04191F385;
	Tue, 29 Jul 2025 16:14:12 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A63E313A73;
	Tue, 29 Jul 2025 16:14:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 29nsJ1TziGg5WQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 29 Jul 2025 16:14:12 +0000
Message-ID: <6aeb9c5d-7c3f-4c0c-989f-df309267ffbe@suse.cz>
Date: Tue, 29 Jul 2025 18:14:12 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine
 skipping
Content-Language: en-US
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20250728-kasan-tsbrcu-noquarantine-test-v1-1-fa24d9ab7f41@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20250728-kasan-tsbrcu-noquarantine-test-v1-1-fa24d9ab7f41@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org];
	TAGGED_RCPT(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCPT_COUNT_SEVEN(0.00)[10];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=dV7yyvvm;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=dV7yyvvm;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/28/25 17:25, Jann Horn wrote:
> Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU slabs
> if CONFIG_SLUB_RCU_DEBUG is off.
> 
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
> Feel free to either take this as a separate commit or squash it into the
> preceding "[PATCH] kasan: skip quarantine if object is still accessible
> under RCU".
> 
> I tested this by running KASAN kunit tests for x86-64 with KASAN
> and tracing manually enabled; there are two failing tests but those
> seem unrelated (kasan_memchr is unexpectedly not detecting some
> accesses, and kasan_strings is also failing).
> ---
>  mm/kasan/kasan_test_c.c | 36 ++++++++++++++++++++++++++++++++++++
>  1 file changed, 36 insertions(+)
> 
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 5f922dd38ffa..15d3d82041bf 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1073,6 +1073,41 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
>  	kmem_cache_destroy(cache);
>  }
>  
> +/*
> + * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
> + * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
> + */
> +static void kmem_cache_rcu_reuse(struct kunit *test)
> +{
> +	char *p, *p2;
> +	struct kmem_cache *cache;
> +
> +	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_SLUB_RCU_DEBUG);
> +
> +	cache = kmem_cache_create("test_cache", 16, 0, SLAB_TYPESAFE_BY_RCU,
> +				  NULL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);

Hmm is there anything inherent in kunit that keeps the test pinned to the
same cpu? Otherwise I think you'll need here

migrate_disable();


> +	p = kmem_cache_alloc(cache, GFP_KERNEL);
> +	if (!p) {
> +		kunit_err(test, "Allocation failed: %s\n", __func__);
> +		kmem_cache_destroy(cache);
> +		return;
> +	}
> +
> +	kmem_cache_free(cache, p);
> +	p2 = kmem_cache_alloc(cache, GFP_KERNEL);

and here (or later)

migrate_enable();

> +	if (!p2) {
> +		kunit_err(test, "Allocation failed: %s\n", __func__);
> +		kmem_cache_destroy(cache);
> +		return;
> +	}
> +	KUNIT_ASSERT_PTR_EQ(test, p, p2);

Otherwise the cpu slab caching of SLUB and a migration could mean this won't
hold as you'll get object from another slab.

> +	kmem_cache_free(cache, p2);
> +	kmem_cache_destroy(cache);
> +}
> +
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>  	struct kmem_cache *cache;
> @@ -2098,6 +2133,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kmem_cache_double_free),
>  	KUNIT_CASE(kmem_cache_invalid_free),
>  	KUNIT_CASE(kmem_cache_rcu_uaf),
> +	KUNIT_CASE(kmem_cache_rcu_reuse),
>  	KUNIT_CASE(kmem_cache_double_destroy),
>  	KUNIT_CASE(kmem_cache_accounted),
>  	KUNIT_CASE(kmem_cache_bulk),
> 
> ---
> base-commit: 0df7d6c9705b283d5b71ee0ae86ead05bd3a55a9
> change-id: 20250728-kasan-tsbrcu-noquarantine-test-5c723367e056
> prerequisite-change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24:v1
> prerequisite-patch-id: 4fab9d3a121bfcaacc32a40f606b7c04e0c6fdd0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6aeb9c5d-7c3f-4c0c-989f-df309267ffbe%40suse.cz.
