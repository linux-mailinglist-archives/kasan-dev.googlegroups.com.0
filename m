Return-Path: <kasan-dev+bncBDYZHQ6J7ENRBY7MXOHQMGQEQBIWQAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BE6D49897A
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:56:36 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id z15-20020a25bb0f000000b00613388c7d99sf36665244ybg.8
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643050595; cv=pass;
        d=google.com; s=arc-20160816;
        b=CwztIxD5bfcGwUqipd0KQexBhPG4UKWzqv643KWqP5Aa6vgfKlVqDL+ZOqtuE1Cl8j
         hewwTvO/db4XtoE85QpTJKW9x7k4yHldQz+1Av66vCgrruXZAgTQ6LTGhWrqNBLTdahQ
         dt44qYRiYSn6tpYBLnXQDkaPfiNvx/IThJPZdL63k93yeoIygfCMTjMZMjKiaCBA+Mgl
         mbQOqFeNvD5DyWz+ZGeiDWodEw6axw8blCXCyQ5slJEBUPH+ibYWS2kGLiAlHrVfYTs6
         QJvHGqm1SvNTMPb19/58qkEkKyn1JbBjf8la5zD4SVVQaUj3daxQhqP7H9ItO22xi7G9
         7Ebg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=e6xVgm17ESztZUnqoWqldF3Nhd6S+oISNVJ8HhqlVJY=;
        b=M5x4MZ2SvjyAPzhghdp8diwOJ1/JohjC9+w+OXX2bZsnQfhYhmBtdmOL/Mapq7gkXJ
         JbHTHiEwMCu1PuzS+r9uJAQJz7BXcs0iBvBMsqwHit5v/Jq9qQGgO2luERyg9K0K+3zS
         haIaNEMnxpdjnvhUO71eIObb5XJ845f1Eiwi3XRXKSKoXj71ygvScSE7mak4TEnryP2M
         tV6RFjlIY99a95XmMeujzkeZJXAPrz67fwzF7gIon4ScLSSrkiYWzGShVPsSYHWcyctF
         ajorSEtiU/JTPMuIjbm2DUh7Tp6u4rDgswFHWXRiVpMvBdiK0xcZeqdbYOK9LTntqYnC
         2VIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UBsX8t7t;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject:to:cc
         :references:from:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e6xVgm17ESztZUnqoWqldF3Nhd6S+oISNVJ8HhqlVJY=;
        b=mEUrN3H3p/lcpI9y80f1gTim5ztRFWZXZM+NN22eTcnHGLp5MBOHP2JNEXXtux9MFl
         X82jdFTc2wdmobXAxn2vMh6WbSQfIjPm9kAh/ejLSCb/5CkvMH00WgE6bczhqixjybAN
         6QyzZVGWQpsSWSHG35JbBz/vkeqlwUzKrPdJeAQtxpNJ4Ne4vDWt0B6jLmsGsTy+2bVP
         FCq9rJ0wHLLPmMnDpCVSTkQbtwFlzFP8mYlHxnzd9cxFKtkvpG9kvU6WbWwWj2JfxcVj
         VdTeafT26EBleXZ4ohgt4Umct4PWldbQpzraxf2RUKALJoA7GEeK+0W2az9sO6d9cQI2
         D5eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:to:cc:references:from:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e6xVgm17ESztZUnqoWqldF3Nhd6S+oISNVJ8HhqlVJY=;
        b=KiVgIF6Gvmrq86YBrsxUYsGUYW9mnyus5LpPwNNDIjd90Ic6HsLw6uusbFJVzlFx6i
         ssMcJ1JnSLl0Q8ODyb9/K60Kq1O4CUG2EfUoZAI3X9FRG5AADWLDhKULktSl7LiVZjZs
         A9ipuPC1hVbPreus5E5WqiHDw/A3sUZY1uYeABzmZD8thAHEa/aI0VOamHJpn1t5cm9c
         E8i0xji0aAHoj0NXJwUixSrvAjm/F1T/4HimC0/xuBhuUjKKkuEshNeFLigq5oH02OzO
         PrnmwqOKD5UUoI0yiOZGS5QSBzbK+f2ltq2ZM1FVD0KKCKHH1NmwJPNADk2c0Z1+0e1W
         uqjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Lw+IEsYkdBENHsxkHcBxF+42ex5w0Zv79VebWLCfAfTcxFgIP
	8wTsqPup0PXxSVR10KT6U6o=
X-Google-Smtp-Source: ABdhPJxz8CXQ8a+77Vr90WvNJoGSH/AlDkccdMd411Mm24AZ6dvCKIMRj4AA8862Ju80JgI2ERMZDw==
X-Received: by 2002:a25:8a08:: with SMTP id g8mr24235034ybl.739.1643050595463;
        Mon, 24 Jan 2022 10:56:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:52c1:: with SMTP id g184ls17754184ybb.1.gmail; Mon, 24
 Jan 2022 10:56:35 -0800 (PST)
X-Received: by 2002:a25:db03:: with SMTP id g3mr19535424ybf.261.1643050594986;
        Mon, 24 Jan 2022 10:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643050594; cv=none;
        d=google.com; s=arc-20160816;
        b=A8+lG+d+Byts5WwkQjwDaEf7fqzZd08O51ysMrGmd+mDtRo/Tc8NkTuyJIs6VnDjMx
         C4ctVjYh1tcIIAZmMJOKelgJo7g90AlGXEvG35T1rH3vXouGZD3tWjG8aNMJ9QHiA6Ij
         UOoWjYTP86piSzIfC58GEi1aYWjf4xE8ftwwQjBfoezSmqKsZaL30oV4+lIKp8a6vvAJ
         yljim+sYvXaDCoN3zo7fNe4plAu+rwirkdTvjiTPGuGRLc2OM7dEdFVvpnw3ae5SHbvP
         TcjJUZPHfNl0/0qblJJQq/RFSZkoohUafYg+vu2iUH5eBxgl6WY0wbWu8bpZI93XtIRG
         Tqjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=OmJVF3D4x24T0ZfBgEiGjVTIdFS2FiU3zC/rm7HZ71k=;
        b=WnJIl0FvQxuQq1HCcjSmvnqjnNH1KyB3GssrFnUYndQOKOZyvIEZTlTG7mP17b7jf+
         L9pTGo381zJ79CspqISCT1OZGGjeSh35PmIsEPZLQGMlzOBmK32o1UhYVt//neqTHxVJ
         edtZPfx/DR25R/vSCsLjYae5874fMNuQA3XXr3MuO2bfnTHIztjN5Jel04Xw2BAD/qxW
         Yy6h3GpDoCRVCnOc88/qhxLJeTdGriampExkzInzL007lsrMJHpmsqHqs/FMzULrcqUQ
         nJ2LwsJxrAt8z3W4txd8XIox0gMbSp2lXKnTuymQQ4MXMQ/9ts680f5yU4semYxuXTA2
         SUJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UBsX8t7t;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id r11si1057749ybu.2.2022.01.24.10.56.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jan 2022 10:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-io1-f70.google.com (mail-io1-f70.google.com
 [209.85.166.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-509-rrMtYy5WPzaEEu3KuX08-g-1; Mon, 24 Jan 2022 13:56:33 -0500
X-MC-Unique: rrMtYy5WPzaEEu3KuX08-g-1
Received: by mail-io1-f70.google.com with SMTP id o189-20020a6bbec6000000b00604e5f63337so12825601iof.15
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 10:56:33 -0800 (PST)
X-Received: by 2002:a05:6e02:1648:: with SMTP id v8mr9493339ilu.286.1643050592802;
        Mon, 24 Jan 2022 10:56:32 -0800 (PST)
X-Received: by 2002:a05:6e02:1648:: with SMTP id v8mr9493326ilu.286.1643050592493;
        Mon, 24 Jan 2022 10:56:32 -0800 (PST)
Received: from ?IPV6:2601:280:4400:a2e0::2b4c? ([2601:280:4400:a2e0::2b4c])
        by smtp.gmail.com with ESMTPSA id h8sm6822557iow.15.2022.01.24.10.56.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 10:56:32 -0800 (PST)
Message-ID: <8f457c89-28ed-71d1-5afa-2386abec6da9@redhat.com>
Date: Mon, 24 Jan 2022 13:56:30 -0500
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH] kasan: test: fix compatibility with FORTIFY_SOURCE
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, Kees Cook <keescook@chromium.org>,
 Brendan Higgins <brendanhiggins@google.com>, linux-hardening@vger.kernel.org
References: <20220124160744.1244685-1-elver@google.com>
From: Nico Pache <npache@redhat.com>
In-Reply-To: <20220124160744.1244685-1-elver@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UBsX8t7t;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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



On 1/24/22 11:07, Marco Elver wrote:
> With CONFIG_FORTIFY_SOURCE enabled, string functions will also perform
> dynamic checks using __builtin_object_size(ptr), which when failed will
> panic the kernel.
> 
> Because the KASAN test deliberately performs out-of-bounds operations,
> the kernel panics with FORITY_SOURCE, for example:
> 
>  | kernel BUG at lib/string_helpers.c:910!
>  | invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
>  | CPU: 1 PID: 137 Comm: kunit_try_catch Tainted: G    B             5.16.0-rc3+ #3
>  | Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
>  | RIP: 0010:fortify_panic+0x19/0x1b
>  | ...
>  | Call Trace:
>  |  <TASK>
>  |  kmalloc_oob_in_memset.cold+0x16/0x16
>  |  ...
> 
> Fix it by also hiding `ptr` from the optimizer, which will ensure that
> __builtin_object_size() does not return a valid size, preventing
> fortified string functions from panicking.
> 
> Reported-by: Nico Pache <npache@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>

Looks good! Thanks for posting this Marco :)

Reviewed-by: Nico Pache <npache@redhat.com>

> ---
>  lib/test_kasan.c | 5 +++++
>  1 file changed, 5 insertions(+)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 847cdbefab46..26a5c9007653 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -492,6 +492,7 @@ static void kmalloc_oob_in_memset(struct kunit *test)
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
> +	OPTIMIZER_HIDE_VAR(ptr);
>  	OPTIMIZER_HIDE_VAR(size);
>  	KUNIT_EXPECT_KASAN_FAIL(test,
>  				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
> @@ -515,6 +516,7 @@ static void kmalloc_memmove_negative_size(struct kunit *test)
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
>  	memset((char *)ptr, 0, 64);
> +	OPTIMIZER_HIDE_VAR(ptr);
>  	OPTIMIZER_HIDE_VAR(invalid_size);
>  	KUNIT_EXPECT_KASAN_FAIL(test,
>  		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> @@ -531,6 +533,7 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
>  	memset((char *)ptr, 0, 64);
> +	OPTIMIZER_HIDE_VAR(ptr);
>  	KUNIT_EXPECT_KASAN_FAIL(test,
>  		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
>  	kfree(ptr);
> @@ -893,6 +896,7 @@ static void kasan_memchr(struct kunit *test)
>  	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
> +	OPTIMIZER_HIDE_VAR(ptr);
>  	OPTIMIZER_HIDE_VAR(size);
>  	KUNIT_EXPECT_KASAN_FAIL(test,
>  		kasan_ptr_result = memchr(ptr, '1', size + 1));
> @@ -919,6 +923,7 @@ static void kasan_memcmp(struct kunit *test)
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  	memset(arr, 0, sizeof(arr));
>  
> +	OPTIMIZER_HIDE_VAR(ptr);
>  	OPTIMIZER_HIDE_VAR(size);
>  	KUNIT_EXPECT_KASAN_FAIL(test,
>  		kasan_int_result = memcmp(ptr, arr, size+1));
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f457c89-28ed-71d1-5afa-2386abec6da9%40redhat.com.
