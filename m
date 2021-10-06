Return-Path: <kasan-dev+bncBDV37XP3XYDRBTEV62FAMGQEXVSKVYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 909C5423CEC
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 13:38:53 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id f32-20020a0565123b2000b003fd19ba9acasf1763441lfv.10
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 04:38:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633520333; cv=pass;
        d=google.com; s=arc-20160816;
        b=JfnU2u6pmf4b2JXJlq8Y+KG5NwSBowEePoZiJ2afnMgpum/t2sji0SU+q0t/aUr8d9
         pF2tQIibjPpdqEv7OJolgkXY2q1/rOzyQfCSZoo1h4hOly8Q433TLvrKL2dMWJj9P7Zn
         CtclhbqSRkmiZVDdMZIO9iyaTBG+QA3hqoJ3DtOKCG68YNwGmXUL1MlJ3vxxNA5S4nSF
         ymXs5wk4SOUQnigiuroskXoB8Z+9ktKHhOPNJaFPRFPKYRmaB61zxHnJVKYbczJFB0Nx
         ApI7ahWKnAw7N9kg6XnIHLkye/oxMCA0R4SHh/YDracD4NWpSO4baeTAscjzTUkDlnz8
         wlDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=l2UYa7zi04U5w3oFcQLeD49jh9BF19fK5AFxABdaVIQ=;
        b=kPhUdtt6K5tha4hV5sia/Z1R4xdZX7HoOkFhzfUke09+kKtWZe7XctJIY3NMbbK1tm
         lhxNE9leB1orbkh6umsvwd9xjXjHr/jKWndPOAHci398BNaJTJbAD7qm5qq/sS8KqX1W
         a/2c9rqMgvKTXO8EhqMJGS7olx1vOL+BCh9+fnlPj2/40qkg2Lvpmxwx7hii514RzDvr
         vIBZrWDDr5NEKuCj9JlwK24Dc6+/w40C6Ya0Z7VaZrN/Canaeix6QhUHyjcO7/1cX9QN
         5ld8RFaKa8n1cUTCCS981WgL0faaMeXwJkGegp1S5JZ5oA2z5E6Ayg9eJU7vqbAH+Ajt
         IdAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l2UYa7zi04U5w3oFcQLeD49jh9BF19fK5AFxABdaVIQ=;
        b=ZYGKi2OolTNvduYvpf7wm/wiATZy5NtLaGQ22KBVc7ewGZnBEAbKXJWVAa2WOQluM7
         eVbL73jDBnugspANns9219DmhznfZ+nhKZ2QOnxEwF46w0yUwCokMoPf/4IbdVFJRXUr
         dqWAwQs8yRLhqTCkEN10GowZtHRLmkFb8CJLMvv2lg8DODRGlaiRrOR7PmeYEXDlY9uR
         2f94wrsA9AuULIMw5LL4cK83MXG1/R76+SAaHQprK4z832tVrMKKTX98HGT5YT09qVHM
         PKEH3Xe4uJA7C7hme97m0n6CJvFTk/r7VwCHB6ifOJubpxLotLnoVPnl3aSu7B+NRZu+
         jUNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=l2UYa7zi04U5w3oFcQLeD49jh9BF19fK5AFxABdaVIQ=;
        b=GH346pXRhoY+g42WAdCJI4ljTg0/xAIBja5Xzr0PRxBpfE4gUsoTZmLfS2N1V5nhkC
         yhGiFVhTqOFK0zkfwP7IT6OtPFP9lLf70iNiazdI3fCaKhzZSv9oyJr6LQelQxsZLfrF
         yc17fJ9rV7y2XC+qA+Zngkmyfh0HZZ5/+em7QBFFv/ztlxCGSsIEFz5ZMo52hx+ts5hl
         8bL1izFxOsqAYYTWWs3C0jkhxVrqQRVTKSiHW0DCOc+dyl3YidNClaTtWPw8d2wriOZS
         u5PSf8YlB7u6n7psCcRDH+4oFmZvKcuZJbwBp5ZIKPyYYenUhjZYkrE7I5PvRTj8yirj
         pTPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Pqo0vx6jGQV/DHN3hZwI4iVQEvz87hi/tVsRktZWroAG0hopI
	3MR+uZ7HPnLGMFN0+mF94eQ=
X-Google-Smtp-Source: ABdhPJwjiBSKDJgWT9EseBrMJTcjf4TOeGwb8Byb4swP5GPlDQ3CjH3PqZjEu44cQv+x07Vu4ZvRjQ==
X-Received: by 2002:a05:6512:3da8:: with SMTP id k40mr3399639lfv.44.1633520333160;
        Wed, 06 Oct 2021 04:38:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3994:: with SMTP id j20ls265227lfu.3.gmail; Wed, 06
 Oct 2021 04:38:52 -0700 (PDT)
X-Received: by 2002:a05:6512:36d0:: with SMTP id e16mr4806908lfs.562.1633520332085;
        Wed, 06 Oct 2021 04:38:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633520332; cv=none;
        d=google.com; s=arc-20160816;
        b=QRcMClrtebU1nSw/E01KFr05XUHoS9yB0FebaO9lDmlEQEGWH4T+Z9xCcBqHgQYaoB
         DHqZEdYYnGfNUgTinrvgK5Ep9BDLR978Od3LaWBddkbKGWD6jqkcUky275BImUafwJ8f
         xttV9OGRGZh+JZcGy45i7cAxJAncTEovOVcYMA9NHdADratzEjM2R2BEgLKzXGP6lhAL
         TiFiGnpggQ/oR5t2Z5AHEFMKc+uFoK/WU1sbVZv4V1QuIshgqHadL8QXOmCGfkrCcKhK
         aDVKwtV7ZiFhtRCS21Vui5B7G4CJSoVolYy5hq2CPXh3M7yCTMGTnOLXvkS9Zq1nWj0M
         tegg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=awt1nW1wfP1aYhPyxc4sbw2+cvFYBw39Zp/runaqdto=;
        b=WbQ9IqDl7pjUc9/uttHw+hM5+y+dp3blaKoqLIPud+24/GGDSb647YCgTRJDpSAXiR
         uRVHT1BxcSUiAoYs0/4kP113XFHUL7mWs1dUA5k4GT9iOmVpzf4wVQtGkbH4vlMkZYEa
         u8B/tEA+g3fNZ9Sjrlw3hw2WqD9vDgKPcNFUmPLydveFd2Y1nCPEHcRJaTmjebiETVyi
         pSzQLzv0FJD8Usd7bj3w+nb8ktvjoTnoq6FMKSHrC9gCTL7DGAmmb90DxZIls2B2MQmX
         d4LSwR62o/dJa3noCA/Cj/2hKWwY/UBm1ba6jKhBu0kRLJBZGyGbYrLqGzyNQoQfEXoG
         MIWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z1si248029lfu.5.2021.10.06.04.38.51
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 04:38:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AB9DB1FB;
	Wed,  6 Oct 2021 04:38:50 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.22.219])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E72033F70D;
	Wed,  6 Oct 2021 04:38:46 -0700 (PDT)
Date: Wed, 6 Oct 2021 12:38:36 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kasan: test: Bypass __alloc_size checks
Message-ID: <20211006113732.GA14159@C02TD0UTHF1T.local>
References: <20211006035522.539346-1-keescook@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211006035522.539346-1-keescook@chromium.org>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Kees,

On Tue, Oct 05, 2021 at 08:55:22PM -0700, Kees Cook wrote:
> Intentional overflows, as performed by the KASAN tests, are detected
> at compile time[1] (instead of only at run-time) with the addition of
> __alloc_size. Fix this by forcing the compiler into not being able to
> trust the size used following the kmalloc()s.

It might be better to use OPTIMIZER_HIDE_VAR(), since that's intended to
make the value opaque to the compiler, and volatile might not always do
that depending on how the compiler tracks the variable.

Thanks,
Mark.

> 
> [1] https://lore.kernel.org/lkml/20211005184717.65c6d8eb39350395e387b71f@linux-foundation.org
> 
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/test_kasan.c        | 10 +++++-----
>  lib/test_kasan_module.c |  2 +-
>  2 files changed, 6 insertions(+), 6 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 8835e0784578..0e1f8d5281b4 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -435,7 +435,7 @@ static void kmalloc_uaf_16(struct kunit *test)
>  static void kmalloc_oob_memset_2(struct kunit *test)
>  {
>  	char *ptr;
> -	size_t size = 128 - KASAN_GRANULE_SIZE;
> +	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -447,7 +447,7 @@ static void kmalloc_oob_memset_2(struct kunit *test)
>  static void kmalloc_oob_memset_4(struct kunit *test)
>  {
>  	char *ptr;
> -	size_t size = 128 - KASAN_GRANULE_SIZE;
> +	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -459,7 +459,7 @@ static void kmalloc_oob_memset_4(struct kunit *test)
>  static void kmalloc_oob_memset_8(struct kunit *test)
>  {
>  	char *ptr;
> -	size_t size = 128 - KASAN_GRANULE_SIZE;
> +	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -471,7 +471,7 @@ static void kmalloc_oob_memset_8(struct kunit *test)
>  static void kmalloc_oob_memset_16(struct kunit *test)
>  {
>  	char *ptr;
> -	size_t size = 128 - KASAN_GRANULE_SIZE;
> +	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> @@ -483,7 +483,7 @@ static void kmalloc_oob_memset_16(struct kunit *test)
>  static void kmalloc_oob_in_memset(struct kunit *test)
>  {
>  	char *ptr;
> -	size_t size = 128 - KASAN_GRANULE_SIZE;
> +	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index 7ebf433edef3..c8cc77b1dcf3 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -19,7 +19,7 @@ static noinline void __init copy_user_test(void)
>  {
>  	char *kmem;
>  	char __user *usermem;
> -	size_t size = 128 - KASAN_GRANULE_SIZE;
> +	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
>  	int __maybe_unused unused;
>  
>  	kmem = kmalloc(size, GFP_KERNEL);
> -- 
> 2.30.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006113732.GA14159%40C02TD0UTHF1T.local.
