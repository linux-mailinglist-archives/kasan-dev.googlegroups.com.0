Return-Path: <kasan-dev+bncBCF5XGNWYQBRBO46W6FQMGQEQIXJNOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A7644327EA
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 21:47:09 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id q193-20020a252aca000000b005ba63482993sf21608276ybq.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Oct 2021 12:47:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634586428; cv=pass;
        d=google.com; s=arc-20160816;
        b=ceq5jRFmctrXmHO8/61YwkDiw/1+VYCyV7CGuGO89uDpThBi6571j0Oi3cCEOKjs5b
         LlYNEzgiTV1M4fDRm8rrgVpm9V8sbZH3mXsoDwfIfQNK82HtYrPXLcspaF/xf9TVC82M
         s/MPNhyCJUCebP5EYzMvAQQTEKwc2pdUpSS4JATAZ9zaQs6vScRz8bYjT/PsW39NF6sh
         LFPEH33RmzT/1EqE3dAvfqPVNsn84C6CptBr7DTbOdHxwKi7eJM0RmtJfO59XPu8apjH
         aeiFwFHIsFevxpwZ6N3MbC5vis5huo+LwDghq+2QCdT3qGL+pDmQrN2qlnkksMtw18n4
         Em0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zQ2Npr2cJ2nwR5J4uzt0G65z61Dt7n5jYXXXpvOg20Y=;
        b=SIiFosr0+5WY7ru586ai2+zXL6ITl9hNkHurTN2R8PmoZf9PLwdsujRcrpcIfRRrCZ
         zlDrw2ewdVhYwM4oUU6dFpQaCPpqKHRDl/oFz36sg+vjGyI4tzog1qAgZCaTPUbgUU+2
         dvVnTpHRXczHMDoOJHERPw1o6ZPoBK1VpmXg0M2ukf67gtyRA/pdUrxeREL+7VVG3ZWX
         9uy8sgH9Vq2UExF4nGALze6R1xhy4v3RF6vJvLed01Jw6T3IEK1ixRj3GW+7u8Lvelu/
         6pXEu2dbENnBgJRjYKEC08ONOc5gry9O58yHQy3N7LhiUbQC3L5skZTwkyLB+0Dvth5l
         7A2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fuCYcYo2;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zQ2Npr2cJ2nwR5J4uzt0G65z61Dt7n5jYXXXpvOg20Y=;
        b=YdAhx31nVvIGEE+29W0A/3KW2y4GO+QrpV1TSbAJE2n4RH5v4yErh8xMlW7NNo5DsE
         UEkNR1HxCtpRUvaHkmAXpPo34Dsr2r8rw60XFMi+E/7pj5Zj9k59e2Jo14lAATC4LD0q
         ZkRQbpriTAT5Nt/HrcO57tZy0qtcsiZupPk3H7upCw6BSoKW9Sz4oFf9sdnMP0UvshhG
         GqS+gAyc4J452dNjPSOggt8O8zQ5/DH+GZzthXG8/ktvNlcPPe9teU0XHJqZE8Od8bV7
         c/H64gmrOloziWV+/WkB89IuVVbhSX2LiYbhzrJiTzDnHE2ee8YQjROM1fnmSMrZTJqs
         JL1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zQ2Npr2cJ2nwR5J4uzt0G65z61Dt7n5jYXXXpvOg20Y=;
        b=fNaagVGr1jCnrFttztwCfJti9lP3MYyQu4mfxbJqUH8Rp7aO2bduUNUBMNS5/+WSL6
         +8WdarTSlLtkTbKChX3tTJTGSJt7fVF/Jcx9RZDk2M2SN+Gx27T1dYborPBKh+rEy2Gk
         4sFHiL0m+/J8eDYYwcCIk4Ei41XhfdPr1TrXdlkbssC07Iy6x140ygnbZZvCv1+ET0uQ
         eJr0HkH0otPMLlqs5OHs9UX6KmKAHbYHxF+bsgYYpnj1JzGB8EPwePUV5JzRCTCymgmw
         uQQMPd/q2EFpsGGZHwxe3rLvnLonkKan33cxArdUDtrow7G7hF67mtBid7aco+Cp9dBy
         +/cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319QEGNYVjaARdzGi++NvBuhTtOaPzJV5HqsabC0qbcjaHgrHn7
	APe49syNKA4jb40heph2vqw=
X-Google-Smtp-Source: ABdhPJwcFQ2iMxBo8olVreeG9OcG7va225DqILr1ccocV6N1pAWIIaVJdxE9PFiPM833HaCSYXOxLw==
X-Received: by 2002:a25:f803:: with SMTP id u3mr31073054ybd.386.1634586428001;
        Mon, 18 Oct 2021 12:47:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4f54:: with SMTP id d81ls5364592ybb.8.gmail; Mon, 18 Oct
 2021 12:47:07 -0700 (PDT)
X-Received: by 2002:a25:4289:: with SMTP id p131mr32716018yba.141.1634586427479;
        Mon, 18 Oct 2021 12:47:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634586427; cv=none;
        d=google.com; s=arc-20160816;
        b=bkXHjM6jAKLm3kcoz0qucQ9/by6xnlLyqcGbmXPEQRYyZQUG2RvDfiKb6ECZad1oNK
         yJh8ps1ta74KAApq8HcXlHkqyt1bOmPZpkqFoiGpPcmemogqUsVmAZ7GqeERGuME9mtw
         LiJxVC8EX6q0IJGKkXy7jqHeEm5GcO7ksBqzlqzD+CkUnCD1UhTrtb/DGIq6377uESbw
         FUmVZBOKCBLWl/YnNXlURxXrBhUu2Rj7ohW63g0k6R52WImFheyvbjkzeqO1pYbS8n1/
         yeaoYzEcwGYpyoOWQhE4ZretWX/yrJ3lWLtpgjrpdeRZrVAbwx7AI0sQ69WCSGd1GiEF
         wcYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=N/UkEqZsUw28dgpf+wkDefjIGznCOnGAPbrDklw8cgA=;
        b=j8gzmx3tjawLal2UJrPZoimTKjUh6P2wOwZqIx94/B/ips2wd3Q4RLMMcYxOU7qO0P
         2rNdGzzkaIkot2Dc7pXiVULVvXLBWLMzhF/Ntg8+EVn4EG4EfQ5qjSj3nL5znWkPVYGa
         DyLEpyeNiN6OAc0sJlOoOrW6Y35DqMS2y6fk/VxyWs/GLU4dlXMnxcMqxKnjnmzXcgqn
         b2OrQwzQQpozALCctabiSxNHjhvip7jkyTu1m5+DxNO2w/svWnignxYJj8J+1Vyg/W3L
         ZZi6p43leTYHnsmSJJySaxplyEpW1htm3UOeRzXKJdlZ/gjCf5o3Vf0//0glw2yCCtWd
         xaLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fuCYcYo2;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id k1si1206407ybp.1.2021.10.18.12.47.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Oct 2021 12:47:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id oa4so12963603pjb.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Oct 2021 12:47:07 -0700 (PDT)
X-Received: by 2002:a17:903:2287:b0:13e:5d9f:1ebf with SMTP id b7-20020a170903228700b0013e5d9f1ebfmr28807432plh.75.1634586426677;
        Mon, 18 Oct 2021 12:47:06 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id s8sm13500519pfh.186.2021.10.18.12.47.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Oct 2021 12:47:06 -0700 (PDT)
Date: Mon, 18 Oct 2021 12:47:05 -0700
From: Kees Cook <keescook@chromium.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: linux-hardening@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Arnd Bergmann <arnd@arndb.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Patricia Alfonso <trishalfonso@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kasan: test: use underlying string helpers
Message-ID: <202110181245.499CB7594B@keescook>
References: <20211013150025.2875883-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211013150025.2875883-1-arnd@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=fuCYcYo2;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1032
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Oct 13, 2021 at 05:00:05PM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Calling memcmp() and memchr() with an intentional buffer overflow
> is now caught at compile time:
> 
> In function 'memcmp',
>     inlined from 'kasan_memcmp' at lib/test_kasan.c:897:2:
> include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>   263 |                         __read_overflow();
>       |                         ^~~~~~~~~~~~~~~~~
> In function 'memchr',
>     inlined from 'kasan_memchr' at lib/test_kasan.c:872:2:
> include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>   277 |                 __read_overflow();
>       |                 ^~~~~~~~~~~~~~~~~
> 
> Change the kasan tests to wrap those inside of a noinline function
> to prevent the compiler from noticing the bug and let kasan find
> it at runtime.

Is this with W=1 ? I had explicitly disabled the read overflows for
"phase 1" of the overflow restriction tightening...

(And what do you think of using OPTIMIZER_HIDE_VAR() instead[1]?

-Kees

[1] https://lore.kernel.org/linux-hardening/20211006181544.1670992-1-keescook@chromium.org/T/#u

> 
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  lib/test_kasan.c | 19 +++++++++++++++++--
>  1 file changed, 17 insertions(+), 2 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 67ed689a0b1b..903215e944f1 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -852,6 +852,21 @@ static void kmem_cache_invalid_free(struct kunit *test)
>  	kmem_cache_destroy(cache);
>  }
>  
> +/*
> + * noinline wrappers to prevent the compiler from noticing the overflow
> + * at compile time rather than having kasan catch it.
> + * */
> +static noinline void *__kasan_memchr(const void *s, int c, size_t n)
> +{
> +	return memchr(s, c, n);
> +}
> +
> +static noinline int __kasan_memcmp(const void *s1, const void *s2, size_t n)
> +{
> +	return memcmp(s1, s2, n);
> +}
> +
> +
>  static void kasan_memchr(struct kunit *test)
>  {
>  	char *ptr;
> @@ -870,7 +885,7 @@ static void kasan_memchr(struct kunit *test)
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  
>  	KUNIT_EXPECT_KASAN_FAIL(test,
> -		kasan_ptr_result = memchr(ptr, '1', size + 1));
> +		kasan_ptr_result = __kasan_memchr(ptr, '1', size + 1));
>  
>  	kfree(ptr);
>  }
> @@ -895,7 +910,7 @@ static void kasan_memcmp(struct kunit *test)
>  	memset(arr, 0, sizeof(arr));
>  
>  	KUNIT_EXPECT_KASAN_FAIL(test,
> -		kasan_int_result = memcmp(ptr, arr, size+1));
> +		kasan_int_result = __kasan_memcmp(ptr, arr, size+1));
>  	kfree(ptr);
>  }
>  
> -- 
> 2.29.2
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202110181245.499CB7594B%40keescook.
