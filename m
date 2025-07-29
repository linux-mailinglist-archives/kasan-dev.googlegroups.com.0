Return-Path: <kasan-dev+bncBDXYDPH3S4OBBGHYUPCAMGQEWLV3NIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id EE6CFB151A9
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 18:51:37 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-32b49f95c5esf256001fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 09:51:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753807897; cv=pass;
        d=google.com; s=arc-20240605;
        b=hRPHWqEB8BRoRx3syPe1hog8pN9PuwbKCv7/lFMrCZwlNjT1MaPFsYcs9BFf+WJmIk
         GJH3qaQPUZPHxk8xVP6oaK0S9RIw1K24gtNIIKX24EDy/zGlUq6UhB5zRCFD5pjy2kpx
         /KXUVUa+Yl3/LaHNGOrfPMJFUea9eI+xYjozvvX8EuqVo8cS+Zy2dzmvZnvBgMnrvIlH
         cVOMn82G0FQsNRhhpDj43HFeM91FNYP3fCRRWQKcqzapUh0E+A6AaxZeQXh7f/6rahg+
         Rhb5JRxthdpFO/q9n2zq9DWTTZvyIEMBpzLxHo5Sft4HjzXgKUy1aT3gmYVkz1BIZVUs
         nHoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=8HHTKquT2z/xeKUEr6HzzNXix2Yk75UzhJVC09zSNm4=;
        fh=k9C3pqoJwk/3lAk9SQ0nabpQw3O5pMxE7NT8bQkfhi4=;
        b=V+fFDtg+BMgOBM75Fx0POv5J1oHqf6lkgZEOBP18Oe9Xmoavn4GzA6KD9xIZ7Rx4lc
         eQwcoo7udQHJbqrkk6ddwId7bd2t3AKhB1SXMaV4PkR1Bq2iIvK9wCxA9W6iDGSHbY8A
         4PZZf9nEADawn2KoDC3Y14SotiSWhA/c22uNCtR69Mg1AhsXUdlJX0WKgrOVXUVce65j
         lia2MCINnpQnWADTUgRkpmoquWOiv56RePPMqMHzulzN/p3kC5CDVMycqPwMY8/4O7VC
         vNr5dRMChE9p8rzn8Ia2VWvabAuLYaWbff1jb7b8nW0zuQhpgjHzkPgzPSoM/Rn2E3dx
         SV1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yqzfRphf;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yX4hHVFV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753807897; x=1754412697; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8HHTKquT2z/xeKUEr6HzzNXix2Yk75UzhJVC09zSNm4=;
        b=veqNhHggYTGxQf7Gl2olLbog+gZJITJp1S6jONFHGesv2YlJI5pZ2g+7Ym/dmLWjmG
         GzC3u1NbvtwJWvGOhXf2GuwCe233p3y5dTXso+nBBudtLG/RMpaDNybbaH4OJ15fG6KR
         RL0Waz1vCUjCUONsQXtZAqdlD3iIiaz5afQjlPPELT2QQ3fki0VdHNzlutmimEm1FK15
         UEHnsgBLllWuyob1nxyaip7WPo6DUqXMPCWrZZi8mFlfk09dy2KYjgzC8TcQ95AhW+Lx
         lFN5gNO5nmdSLhp8HiOmfm8wZmMmspYnMBF9aE/hgAThaSMajMdyGOQv8s9Xa98rhNdN
         4XAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753807897; x=1754412697;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8HHTKquT2z/xeKUEr6HzzNXix2Yk75UzhJVC09zSNm4=;
        b=n0atbJfv8KeFxmQzshUdElbBT6xBANDTh0u62BhsdQAy34fM2YwTML/ZX2ey6hjjQ2
         1TCvD8/p6DkTKvC3wLJ48S0s0VrM/kcM1b41IJhF3Z+JbnYzC7zF0h/wAvR1tVR8GEZ0
         OHrnnzh4A9S648xfGv7HrV25XTTcE7GOp7jgAf/5dCPEH2n9sim42pX/JjiJKPLNpaMj
         CENrkzXo6ekn7s3Eoc9ASvjpqeYDlrFWoifkzws699r0RKOSgncylXXszKztw+MDQDBK
         I/IRTeqPwvV/xyC39tq3QuBq8Kzo4LOWDFcsSvj/i5tCLoIHZghP3boZjp+p4WOu2pOG
         /inQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUH9fOv7YUzz888ONy3UezL4gHJqvjCHPVFF4B8qHmT/+fLRNbGUTslHYIzQtGEa/eqcYuU8A==@lfdr.de
X-Gm-Message-State: AOJu0Yxma+gMi7D7nHpWCi8n43/BO50hV9P/mFYYDIH8I3W6ErkBRhQv
	iemG+TOHC1Wr4/Z25TANSARt12PG53UyjodP2Ftv1VoYdaLo+0csMyHd
X-Google-Smtp-Source: AGHT+IEkbRJ3gSJv6A8K+oQ5jAk3oJFBiAJTaa8drzhoVWIGYxIDr0oem9gQvIYxh0xajV/OuoGzWA==
X-Received: by 2002:a05:651c:211d:b0:331:e667:90fd with SMTP id 38308e7fff4ca-33224c31520mr285991fa.35.1753807896894;
        Tue, 29 Jul 2025 09:51:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZem8ZIRY/rcGq1Cm6pugWKXQBHuk5kRRJbrgG4nfmTSZw==
Received: by 2002:a05:651c:31d2:b0:330:5c59:1d51 with SMTP id
 38308e7fff4ca-331ddabb887ls13145151fa.1.-pod-prod-01-eu; Tue, 29 Jul 2025
 09:51:34 -0700 (PDT)
X-Received: by 2002:a2e:b88b:0:b0:331:e667:9128 with SMTP id 38308e7fff4ca-33224ae4024mr287851fa.13.1753807893930;
        Tue, 29 Jul 2025 09:51:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753807893; cv=none;
        d=google.com; s=arc-20240605;
        b=h3AfsSK1sdJxYtO+fTKp7V+Nbf4UVcnX18rlc7kzeApto0+9AODGi3Hc1EMXtyzJAX
         8V7i63zMGaT/PrRTr80yeee1DkwQz1eWUxLDWbzHZdrtY4vntnlgUObWTNA9pBFYKeDJ
         2XeA22HZZ5s1N4Df00CczTQj6d96OgYlA1HasH9b5NtajoqfGjrtdWAlGlW2W67tl1r6
         F39nRyL6Yf3d5o6y1Cky8BzxzIJt6+A+eKKb/lBsdKUy5HHAo6Vx3JK1pIkQndtDAKBz
         EvhFveLdhDn9lML2fBSKnraJ2Jeb1inzBVB8FRxsCLlM/1xKBn3Ctku3T7oK5XgdEXLW
         YrwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=B9zblHd7B1NwjU/h+HwxYaQdPAptYF7/21/a0/VsbEc=;
        fh=Z1akeSglz1VnNM7UindtLmbCq84Y8wrvu/XSLABU9l4=;
        b=YqybVdOjR0PkCPMrwimrk/CIKM1rlWxfLVbb0dqplEdPOWCpST3asnbpsBPLJFo+vH
         vyzm2HZNK48zbS9lTQ/jCPuVd/DuKYKVqPaDzTEzTxg3QHHPlHcfIfUlUCl7nngaE396
         oGxTj+9g0lkan22z4mOuHsiVasHcrZ30FNUe/Jawnf4fRKlW+iKVQ/EPxzLavqdgwUfg
         0vgSaBXDOSvPPIvtGMotP87AZQXx9tDXmROdAagBcsFIm8Kv4pTJygF7TxRz4jvOfl3t
         Sl/FNWq6fcs2hr6fDS0I9VIhdsKEdiEa721owo6b9IvVz1sAoIzrth4Xi6ILw2hy+XyI
         vjlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yqzfRphf;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=yX4hHVFV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f41ce93bsi2366591fa.4.2025.07.29.09.51.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 09:51:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EE6CD1F385;
	Tue, 29 Jul 2025 16:51:32 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D477613876;
	Tue, 29 Jul 2025 16:51:32 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QTteMhT8iGhnZAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 29 Jul 2025 16:51:32 +0000
Message-ID: <5109febc-21b4-43fb-98a2-14c552c27bfe@suse.cz>
Date: Tue, 29 Jul 2025 18:51:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine
 skipping
Content-Language: en-US
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=yqzfRphf;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=yX4hHVFV;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/29/25 18:49, Jann Horn wrote:
> Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU slabs
> if CONFIG_SLUB_RCU_DEBUG is off.
> 
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
> changes in v2:
>  - disable migration to ensure that all SLUB operations use the same
>    percpu state (vbabka)
>  - use EXPECT instead of ASSERT for pointer equality check so that
>    expectation failure doesn't terminate the test with migration still
>    disabled
> ---
>  mm/kasan/kasan_test_c.c | 38 ++++++++++++++++++++++++++++++++++++++
>  1 file changed, 38 insertions(+)
> 
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 5f922dd38ffa..0d50402d492c 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1073,6 +1073,43 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
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
> +
> +	migrate_disable();
> +	p = kmem_cache_alloc(cache, GFP_KERNEL);
> +	if (!p) {
> +		kunit_err(test, "Allocation failed: %s\n", __func__);
> +		goto out;
> +	}
> +
> +	kmem_cache_free(cache, p);
> +	p2 = kmem_cache_alloc(cache, GFP_KERNEL);
> +	if (!p2) {
> +		kunit_err(test, "Allocation failed: %s\n", __func__);
> +		goto out;
> +	}
> +	KUNIT_EXPECT_PTR_EQ(test, p, p2);
> +
> +	kmem_cache_free(cache, p2);
> +
> +out:
> +	migrate_enable();
> +	kmem_cache_destroy(cache);
> +}
> +
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>  	struct kmem_cache *cache;
> @@ -2098,6 +2135,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5109febc-21b4-43fb-98a2-14c552c27bfe%40suse.cz.
