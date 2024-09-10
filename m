Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNETQG3QMGQEI6Q6Z4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 78F0D9738A2
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 15:29:26 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2f75a817a3esf28108181fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 06:29:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725974965; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tr2puGSUVEQbQEbSJ4bdD/Lqaotuuu2udGZlJmYvvwETpWHtp/UMrP5qEX5AWbBeK3
         sWeceKLQap27wUPXOeMMfNmm4XqqrV4mGOo+y/hbQCEwK1s+znD5FQAVXutjIB/fM85q
         8wkOmwA2Gf7cUEwlI0/OaGUgI7u2KcER4D9ySHhBIeEEdDEKTOKF8e6C/mjApQMvJh8g
         Y+1nWjmqnoE7MyUvBhuNpFsfozljXxP6bjxBXRoJ6fcsSerHK52+5WRvcvaESVa09gn0
         SqSDMtOy6DNjfFVM5AbcflES3MrqD6lWV56aLdgEZLKod7uCrS4bfnnJck9B20hrl8sX
         o1iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=k+C//EmwD0nHFnQGcUnqy98GofcFX3HKwo00vLgErbk=;
        fh=tmkxke1FXmgbL0zeSe+BL6CQlcMNpYQbe461onGleXk=;
        b=HiwvDdS/Er5XGNJpAj62ILRkm7bsyXP0CE6ERq+QKIN7zgyrC0IuAB7JoM0FIQlfEZ
         vwFISI6q8CO8iSmxbcFD1mp1JVPXzREPfCChlVU0hubm17bWONdvMYOBcxzohTRayoSr
         bXcKGj4GvQpa1ozwtY2AuaYpXwCsjkfBfKeCAtxnZIL3Ftnod828wTkJgMHVESuhN/EV
         La3b66ja9nnSAM9jcM3nZ4tek8xF89VL76AZ4FAlb/6GSnsyaeN8tKdQzsRAy2PzfKG7
         XVCNlfStBc4VX5B6O1ofH/qYy74LYrvox9PN+k/Ho4MF+Mk9XztoZwDJ3h6Eh8by7VTq
         L71A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=vZRg2DFJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=HMIm890K;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="L/HvcHR9";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725974965; x=1726579765; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k+C//EmwD0nHFnQGcUnqy98GofcFX3HKwo00vLgErbk=;
        b=fXGHpLqQox3HMX3Ipb58F790sJ8mFIo54n8DCtYu3PO/s/1Vir+gRj9HmvwZJFoJFK
         BGSJBN5Ckj/YKtZbotNc+jIHmNrK7KbUUHPlIZ9GUDu56ZMzGJtkDNB4YteU10QEMvh3
         IvJ3T3Tl00KAPLvt0XmiIDNw51Uwmk1FY7BYA3XiRFNsvLjCTwjr7FsGXM8X6AAv+rqp
         EyS9tvNXza+EHvdrVsLq5ePTmK1A51NqU+IelmRSRBHvfzkKL+BVQc0amRPN6IAJeihQ
         yVC2mY994HsLgKrx3/RoVZv4Toi+Hxayfpv4NBGTAvrDWUjg/gVu4QS9sztCXGL0Eso9
         OJbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725974965; x=1726579765;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k+C//EmwD0nHFnQGcUnqy98GofcFX3HKwo00vLgErbk=;
        b=AjxlLwCIdSPBBfPjbPGDFYnw3rV3oCOS28JK0vK/wixG8YpwQZt4fVSew0a23z68XU
         ajXd/fLyRuZBtllzT6NhL19bYXXs2gNQge2HOVfDo3UBku4cTRQCiudT1qCur5N+VTkN
         rlBcrW2rmy5N17C3Vy/ZhYlYt0RDrtATsIlEbLSr0ZqL0oROXN6DgE8qNfAMmqyrxPjA
         SNt0jaZgK8WGB/RaNR2dOIalW/KZBZCNHa2Nc8LmanSWayuQz7bduD2TiF3xj6jj2r9R
         QWYZbzAwvxp8T+OtOWTKPkG1z1XkSWhT/AkKnQJDGrR9rvjjpPKebOFm5JPra2buwbG4
         Z8kg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUejNiTy+NPUh4rE5BT+DB3Tgy2+j0mCwvJFANWZ5XcPJmwgNJxAuWL6rmop/MwaweXpn+caQ==@lfdr.de
X-Gm-Message-State: AOJu0YzzoloxLfbH3f0A09jVLTj02hDYeeAZNUaabgN4FtkIHqFIxEAi
	U/B9yaWF5tTQd0c70V5ze9bZpCV2esddvfBWNUlyQzjgJztoZXRE
X-Google-Smtp-Source: AGHT+IGxohFxPr/dct5aaj1A9rmDao8XrGtMmsVeCBQH/P30Gu0lI3DV+NDcDHn2G6lfOSmUoGNliA==
X-Received: by 2002:a05:6512:104b:b0:536:5625:511a with SMTP id 2adb3069b0e04-536587f82d0mr8517740e87.47.1725974964937;
        Tue, 10 Sep 2024 06:29:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1d:b0:536:53c2:bc54 with SMTP id
 2adb3069b0e04-53657849cbals384729e87.1.-pod-prod-01-eu; Tue, 10 Sep 2024
 06:29:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4n+LgaQPhif/yQVCSdala2fLxs4eJH+3bSatIGib0gPH9LSNtXqHItDVt+DXpFxBtW5J9rdbxT6A=@googlegroups.com
X-Received: by 2002:a05:6512:2c0e:b0:530:ba92:f9a5 with SMTP id 2adb3069b0e04-536587f56c5mr9111340e87.45.1725974962835;
        Tue, 10 Sep 2024 06:29:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725974962; cv=none;
        d=google.com; s=arc-20240605;
        b=O3Sh9BgIMaf9dCOxJapApZN+JABIAyxnEHLIww8+zUcdXOHHUaJU2z4GJo19QIf+Jk
         reW8s1692RjcaAZ0o73OWIGh5aJIyP1AbXAStULrEw3AGvZo/IpJwJ3+h8u5EHpeHR1m
         V7kHUJKssJ/t8e5cc9Kf/HByzU3vZUr8/uQ26PClFIqDY8BlILvFRoiPNpSIyjWsX09I
         l3+z7aHaC8qhOMhbryXBE5cO7atp3LK74E4FYWzKzYaEyLTsowzcM0GaJ9eOjJrTV8CY
         pfa8J00t8jATsl1b82es6Wv5Gy+nrm+KxeG9p/DJ/RzEtpcg5e58bhoBmtC5ce63T/DM
         VtpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=mOYVq6F7Ob2XxqE+z2md4uwqaGeL3XgktjUkUkC12Ak=;
        fh=0xRBb/eFYt1OwNgyWpv0boRELUlsWEBHSNu42J9xXtM=;
        b=F/1q3tfVWxF4V+lVUL759hZcMqUfj5hq1WlqbmlDydwNxik0dKcV24ImaEnkkDBG5y
         6323LV1VgoJ1xK3wtPbuG4nIQW7kovZxObPUC/SmpUB98gJ6zzh1VvopCVw6m6RFXCRZ
         MmWdhsgqq0HA+26e8kRYdnWQTsorpns9SVyeSdvHjo53d6dveBzy3SuuUAYT3WQkFZzv
         LHduCGQAmSTM/pPZjFv/3fBO0NZcdXxPn3HHo37qtOgK5q86YU5dFMF8oehUMjSkIUDH
         Jfm3S6rUmaek5RF4xyzRlSLIqQup/bc6fdT2VrO7xKf/hpnd/9tPuSctOgtHcHtlgJtg
         oBxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=vZRg2DFJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=HMIm890K;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="L/HvcHR9";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5365f86fd79si131837e87.5.2024.09.10.06.29.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Sep 2024 06:29:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CD9AD21227;
	Tue, 10 Sep 2024 13:29:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9D82113A3A;
	Tue, 10 Sep 2024 13:29:21 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id dkq+JbFJ4GY+HgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 10 Sep 2024 13:29:21 +0000
Message-ID: <a4805d44-9595-429c-86c1-6003b9faa59f@suse.cz>
Date: Tue, 10 Sep 2024 15:29:21 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 5/5] mm/slub, kunit: Add testcase for krealloc redzone and
 zeroing
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>,
 Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20240909012958.913438-1-feng.tang@intel.com>
 <20240909012958.913438-6-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240909012958.913438-6-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=vZRg2DFJ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=HMIm890K;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="L/HvcHR9";
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

On 9/9/24 03:29, Feng Tang wrote:
> Danilo Krummrich raised issue about krealloc+GFP_ZERO [1], and Vlastimil
> suggested to add some test case which can sanity test the kmalloc-redzone
> and zeroing by utilizing the kmalloc's 'orig_size' debug feature.
> 
> It covers the grow and shrink case of krealloc() re-using current kmalloc
> object, and the case of re-allocating a new bigger object.
> 
> User can add "slub_debug" kernel cmdline parameter to test it.
> 
> [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
> 
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  lib/slub_kunit.c | 46 ++++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 46 insertions(+)
> 
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index 6e3a1e5a7142..03e0089149ad 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -186,6 +186,51 @@ static void test_leak_destroy(struct kunit *test)
>  	KUNIT_EXPECT_EQ(test, 1, slab_errors);
>  }
>  
> +static void test_krealloc_redzone_zeroing(struct kunit *test)
> +{
> +	char *p;
> +	int i;
> +
> +	KUNIT_TEST_REQUIRES(test, __slub_debug_enabled());

AFAICS this is insufficient, because the static key may be enabled due to
debugging enabled for different caches than kmalloc, or it might not include
both red zone and object tracking.

But it should be possible to instead create a fake kmalloc cache of size 64
and use __kmalloc_cache_noprof() like test_kmalloc_redzone_access()?

> +
> +	/* Allocate a 64B kmalloc object */
> +	p = kzalloc(48, GFP_KERNEL);
> +	if (unlikely(is_kfence_address(p))) {
> +		kfree(p);
> +		return;
> +	}
> +	memset(p, 0xff, 48);
> +
> +	kasan_disable_current();
> +	OPTIMIZER_HIDE_VAR(p);
> +
> +	/* Test shrink */
> +	p = krealloc(p, 40, GFP_KERNEL | __GFP_ZERO);
> +	for (i = 40; i < 64; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
> +
> +	/* Test grow within the same 64B kmalloc object */
> +	p = krealloc(p, 56, GFP_KERNEL | __GFP_ZERO);
> +	for (i = 40; i < 56; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], 0);
> +	for (i = 56; i < 64; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
> +
> +	/* Test grow with allocating a bigger 128B object */
> +	p = krealloc(p, 112, GFP_KERNEL | __GFP_ZERO);

The only downside is that krealloc() here might use kmalloc-128 cache that's
not doing red zoning and object tracking....

> +	if (unlikely(is_kfence_address(p)))
> +		goto exit;
> +
> +	for (i = 56; i < 112; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], 0);

... but this test is still valid and necessary

> +	for (i = 112; i < 128; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);

... we might skip this test as the red zoning is not done by __do_krealloc()
anyway in the alloc_new case.

> +
> +exit:
> +	kfree(p);

Ideally we'd also validate the fake kmalloc cache we created and expect zero
slab_errors.

Hopefully this approach works and I'm not missing something...

> +	kasan_enable_current();
> +}
> +
>  static int test_init(struct kunit *test)
>  {
>  	slab_errors = 0;
> @@ -196,6 +241,7 @@ static int test_init(struct kunit *test)
>  }
>  
>  static struct kunit_case test_cases[] = {
> +	KUNIT_CASE(test_krealloc_redzone_zeroing),
>  	KUNIT_CASE(test_clobber_zone),
>  
>  #ifndef CONFIG_KASAN

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a4805d44-9595-429c-86c1-6003b9faa59f%40suse.cz.
