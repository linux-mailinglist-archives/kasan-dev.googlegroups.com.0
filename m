Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQXP5KAAMGQEKYUZLGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 9402C30DD2D
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 15:48:35 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id o139sf3142609lfa.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 06:48:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612363715; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rgn7609Lr3v60NhxUf97vjaaw0veo5bj89FKA6fqzP6w28nSJ+/bxwX0KQQzCiEhjI
         Cyos57veceEne0WlA6SXxeT/+0TdSXyIJeFTtoXLZ98BKOS1hS3pjOQe+sYkha77ytG9
         OlRv+2cIakkhflyySfDJngeNKGZDGUy1k+qN3AkAVf1xlDZ7TRci97gCwP+vtgDGDbFX
         GZ+gFR3AyXmRhEt7K7FI2K5AxxKrqLLN9yrRFLDlENjStCE7OuMfU/t0/wzfFA+6a4VM
         5V6T+wqI/2AUTcs4fGDWibDitGEvcTuRm0p+qMMmf8AmEVJMCu3QTA9L3uXciel+1WtN
         Uz8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ipHCh++7S4f0If/2ZUIC8tfxziABTjZ6tFdeLLMK4pE=;
        b=ZwpwYLyfV/5ZqsrMsRk3/ScXao+9Pr4YbQlTiNRk4C5oQ4zWWFjb+wIeIXdqMjbvfx
         OGnER+JrcWcmyOSCM4AyuMhz75DfKP9oSXWipk61psyy1+C1DmtcipIj2pv4rWN3ajfD
         E6AuZqUbEYadY/UY3XKjCDUOm9yNi2wjbv+zxECLopX1rhopE1VVy65DATrRVfZrJBew
         09oyfh0delmh87ZlPLEnwDpMk3PNGr8o0ARdbBOiHpJECjYEESk/Z/SDCCadwyDuz3I1
         MiltTJNwpM2aEBJ/hTVCJDcKS0WyLDL2v23Qv+78z4aZPImT8iwr4DbRqlvHd5jCY5Ar
         7X9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fQIVmx98;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ipHCh++7S4f0If/2ZUIC8tfxziABTjZ6tFdeLLMK4pE=;
        b=r6v7FyBPPd2rCpxYekPn2KbIRg/1au9PLOh0+jODT9gA5qyKZfta0GUd+6dPCmnab3
         cLnwoV3FJjoXjJbf/YdUb5kKYouSp06C55hOcw6tOM3kkYxqU4dsiYVOeuzkK+FPEJtY
         1otz0kvGirWlcr8hHao7EbATxa2DKfX+DBO35/zJ2t8m8VE7NVhoBYVvr+4YLv3LyGcz
         2EAHSkUeb/xGiX6qjxIskynS/cSTjGvSE7BLHbi9PuKJrx9LojRVwKzC/MupTwJeJLLT
         rWVcxUjMag7urVootGeoZcH/uihELKViCXB3c+ycQEXmEyKfRkaJ0iTQjHzmP84wGL3M
         Od6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ipHCh++7S4f0If/2ZUIC8tfxziABTjZ6tFdeLLMK4pE=;
        b=rwCREls+vuRWxVQumNX7dUUcPyUib5d7zFmZfKMwy6BdF9yzfSdBPhTwUKk/J+k+tk
         IyP3KWNyF5GSFi9kseYHAYZ4820xNB9SbZsYk1cXiYSU83d2ZnolRHk1GeNN/P9Q2g8f
         BNk1SaLMy+ZrFonmOUoXXG7HcAIhIwtpuKMu/p49dS0EwBA8vwBOtFT8yzosw/6w090/
         11kvBcOCxXCrKcSkkVNjq7/klQpU8TJn+R4iduXlkP37plJJMFQ6yGHIRYUVnehTNmRV
         +gNifUldgcg9SmAUUlbk+RAjrZH/oJylLsrH4RnXZDxX1nm+pqxuDrPTKMMcv6OCZNTa
         njug==
X-Gm-Message-State: AOAM530TCXZSgbloq9VglLZgXNWEFPQW+NUFxs60LSKqu2D1oX6nq8LZ
	Swqq0DtBaPfFzvoJINZYQlc=
X-Google-Smtp-Source: ABdhPJxkTc6Zr1GD7/V7R775kcNusLVl/j6wcLi7zg6W5K3rerCu1wH+GOACIk/U5doocAOJA4rXlQ==
X-Received: by 2002:a19:2245:: with SMTP id i66mr1971204lfi.400.1612363715173;
        Wed, 03 Feb 2021 06:48:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:97c5:: with SMTP id m5ls431915ljj.10.gmail; Wed, 03 Feb
 2021 06:48:34 -0800 (PST)
X-Received: by 2002:a2e:965a:: with SMTP id z26mr1957495ljh.342.1612363714002;
        Wed, 03 Feb 2021 06:48:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612363713; cv=none;
        d=google.com; s=arc-20160816;
        b=OMHwLL29Hq2NAWnCc59aBkA9bYYvmF0TeB3pxPwjCzXBNkgRWIz7xTRmA1YZ5XaC5U
         w2VS5hgpW3sPWzLB5vrG2unStS9PY46UrzdU7MSoLkqJEHyOPOkwqkh1j7dGwxnEUE1n
         765ZaM7ZnBwKb6yBouSN5scOxoPiHOoqb8GbIfI4tiVSpesr67VZiK8kzzB12riU4T8t
         2s7/5tv0FvtY6uQ3VmW/7JoRjTLPOgcT5sparF2PV+hcEgbIq8H+QekPNC29bJlIMNtf
         WO9oPOSRLWOPElhiuehsAOzuwP039VSye5J2wlKBybTZ+vVvlPFSJe/v7KmQfpDcKztv
         7yxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9VGn7w2tNlFuEz50GpubxUEDNHCrhMt0WO2PGFie8Ao=;
        b=qSRY8cfVIOaU2g+5TLp+iBwCEyKTPnJhwfABvASKOc01tQqMVAcRC8kKKzksfhXnps
         VF2norvUAyoXKJxZOymP9LSSSdBQQDCCjTK3VzU33HdG1XCnUZUrUwfCNiQTwKHEbZtM
         XyzMPCzi6tgoqQce8iB81kRh7oYVkfbxWIb37cGfYde61X8SOoBeiJvE8ND+BtwOxNGp
         lxKvfRkH847RUDlLSuUSvaJSSqvWFbtG6OHFpvab6z/pRgrpNtCBTVBCwDGWmbYBmUpe
         TPMmV1usIUP3WyzGmgLjG/IrO+LCQ3iSfvOPEPT4p+Q2jte92Yiq3zQXGrMRU7hguXJ9
         qIxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fQIVmx98;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id d25si97321lji.8.2021.02.03.06.48.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 06:48:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id v15so24677208wrx.4
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 06:48:33 -0800 (PST)
X-Received: by 2002:adf:c109:: with SMTP id r9mr3973330wre.261.1612363713245;
        Wed, 03 Feb 2021 06:48:33 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1de:c7d:30ce:1840])
        by smtp.gmail.com with ESMTPSA id 17sm2919952wmk.48.2021.02.03.06.48.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 06:48:32 -0800 (PST)
Date: Wed, 3 Feb 2021 15:48:25 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 06/12] kasan: rework krealloc tests
Message-ID: <YBq3uZOKeRnW3eBl@elver.google.com>
References: <cover.1612208222.git.andreyknvl@google.com>
 <995edb531f4f976277d7da9ca8a78a96a2ea356e.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <995edb531f4f976277d7da9ca8a78a96a2ea356e.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fQIVmx98;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Feb 01, 2021 at 08:43PM +0100, Andrey Konovalov wrote:
> This patch reworks KASAN-KUnit tests for krealloc() to:
> 
> 1. Check both slab and page_alloc based krealloc() implementations.
> 2. Allow at least one full granule to fit between old and new sizes for
>    each KASAN mode, and check accesses to that granule accordingly.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 91 ++++++++++++++++++++++++++++++++++++++++++------
>  1 file changed, 81 insertions(+), 10 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 5699e43ca01b..2bb52853f341 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -258,11 +258,14 @@ static void kmalloc_large_oob_right(struct kunit *test)
>  	kfree(ptr);
>  }
>  
> -static void kmalloc_oob_krealloc_more(struct kunit *test)
> +static void krealloc_more_oob_helper(struct kunit *test,
> +					size_t size1, size_t size2)
>  {
>  	char *ptr1, *ptr2;
> -	size_t size1 = 17;
> -	size_t size2 = 19;
> +	size_t middle;
> +
> +	KUNIT_ASSERT_LT(test, size1, size2);
> +	middle = size1 + (size2 - size1) / 2;
>  
>  	ptr1 = kmalloc(size1, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> @@ -270,15 +273,31 @@ static void kmalloc_oob_krealloc_more(struct kunit *test)
>  	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>  
> -	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
> +	/* All offsets up to size2 must be accessible. */
> +	ptr2[size1 - 1] = 'x';
> +	ptr2[size1] = 'x';
> +	ptr2[middle] = 'x';
> +	ptr2[size2 - 1] = 'x';
> +
> +	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
> +
> +	/* For all modes first aligned offset after size2 must be inaccessible. */
> +	KUNIT_EXPECT_KASAN_FAIL(test,
> +		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
> +
>  	kfree(ptr2);
>  }
>  
> -static void kmalloc_oob_krealloc_less(struct kunit *test)
> +static void krealloc_less_oob_helper(struct kunit *test,
> +					size_t size1, size_t size2)
>  {
>  	char *ptr1, *ptr2;
> -	size_t size1 = 17;
> -	size_t size2 = 15;
> +	size_t middle;
> +
> +	KUNIT_ASSERT_LT(test, size2, size1);
> +	middle = size2 + (size1 - size2) / 2;
>  
>  	ptr1 = kmalloc(size1, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> @@ -286,10 +305,60 @@ static void kmalloc_oob_krealloc_less(struct kunit *test)
>  	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
>  
> -	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2 + OOB_TAG_OFF] = 'x');
> +	/* Must be accessible for all modes. */
> +	ptr2[size2 - 1] = 'x';
> +
> +	/* Generic mode is precise, so unaligned size2 must be inaccessible. */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +		KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size2] = 'x');
> +
> +	/* For all modes first aligned offset after size2 must be inaccessible. */
> +	KUNIT_EXPECT_KASAN_FAIL(test,
> +		ptr2[round_up(size2, KASAN_GRANULE_SIZE)] = 'x');
> +
> +	/*
> +	 * For all modes both middle and size1 should land in separate granules

middle, size1, and size2?

> +	 * and thus be inaccessible.
> +	 */
> +	KUNIT_EXPECT_LE(test, round_up(size2, KASAN_GRANULE_SIZE),
> +				round_down(middle, KASAN_GRANULE_SIZE));
> +	KUNIT_EXPECT_LE(test, round_up(middle, KASAN_GRANULE_SIZE),
> +				round_down(size1, KASAN_GRANULE_SIZE));
> +	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[middle] = 'x');
> +	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size1 - 1] = 'x');
> +	KUNIT_EXPECT_KASAN_FAIL(test, ptr2[size1] = 'x');
> +
>  	kfree(ptr2);
>  }
>  
> +static void krealloc_more_oob(struct kunit *test)
> +{
> +	krealloc_more_oob_helper(test, 201, 235);
> +}
> +
> +static void krealloc_less_oob(struct kunit *test)
> +{
> +	krealloc_less_oob_helper(test, 235, 201);
> +}
> +
> +static void krealloc_pagealloc_more_oob(struct kunit *test)
> +{
> +	/* page_alloc fallback in only implemented for SLUB. */
> +	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
> +
> +	krealloc_more_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 201,
> +					KMALLOC_MAX_CACHE_SIZE + 235);
> +}
> +
> +static void krealloc_pagealloc_less_oob(struct kunit *test)
> +{
> +	/* page_alloc fallback in only implemented for SLUB. */
> +	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
> +
> +	krealloc_less_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 235,
> +					KMALLOC_MAX_CACHE_SIZE + 201);
> +}
> +
>  static void kmalloc_oob_16(struct kunit *test)
>  {
>  	struct {
> @@ -983,8 +1052,10 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(pagealloc_oob_right),
>  	KUNIT_CASE(pagealloc_uaf),
>  	KUNIT_CASE(kmalloc_large_oob_right),
> -	KUNIT_CASE(kmalloc_oob_krealloc_more),
> -	KUNIT_CASE(kmalloc_oob_krealloc_less),
> +	KUNIT_CASE(krealloc_more_oob),
> +	KUNIT_CASE(krealloc_less_oob),
> +	KUNIT_CASE(krealloc_pagealloc_more_oob),
> +	KUNIT_CASE(krealloc_pagealloc_less_oob),
>  	KUNIT_CASE(kmalloc_oob_16),
>  	KUNIT_CASE(kmalloc_uaf_16),
>  	KUNIT_CASE(kmalloc_oob_in_memset),
> -- 
> 2.30.0.365.g02bc693789-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBq3uZOKeRnW3eBl%40elver.google.com.
