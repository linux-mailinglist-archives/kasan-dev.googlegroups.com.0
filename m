Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5GMT6FQMGQES5RNOZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2858C42D493
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 10:12:37 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id 10-20020a5d47aa000000b001610cbda93dsf3889962wrb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 01:12:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634199157; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gg/2yzcCiKbyY19OQe7xNq2Dqjk07/OI+77c+Ipx2M4XqFOo08DMLwnm7ayLiZpn5W
         OF94z017EcqlP/nbwJnhrlQljM/0xXv3eIJcRNfq1OSIe6G3dsFrTXYR8Jhz9N0M21gc
         c6lyXdIFaa8V17OHZKvTuskX66wPQEAvAc+NskEdaSbI/ozy0PgUkkD65OrQMqq2/bcM
         sF0qlCGWEqgZmLIzmEsAAlDKfEK4c22ypTBDj2RPlGfE0eH29d/0BMNnMGmdHQKy682G
         Wdr7HoUGB+iR1aSu8i2izUfAEai3p0p9MiPP2MxCczNDGZWdxYnsIYmdHIepIGUJZjwQ
         Jinw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=FoSN4KyUvHbC1UAZIb2rgbHTlFjn8HEaqpxb+lxuPuc=;
        b=KM5NA6nBY25zAKMPftwIRm+oBqzxgFWPNJcGK6K1uH4EMfHGjIc6tK58c/MNUfDXdi
         0st7ewkc7FCef7Albfro61u0izX9KtTjdWaB4w7Xkigz136G26L4/JYOlzPLqdGanu9l
         7N0w9y/1SGCWWFEoUurg1V3aCEbBSAdA0X5t+Srh7nnJ1izhg4azVzh4wak7UsNJ/KZu
         ZsDyyjryzi+MrsPZsvRZ5aZG/AO42zTCpzJvGTG3FDhr+AZLcwXuivyUPM9yPoTk/u28
         j2eyc4wIA/z4W7E9BytV7WeELIFHYKFus4rEUpBfKitWxm2rbjzxITIFGO6StfDUFxGf
         87SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FoSN4KyUvHbC1UAZIb2rgbHTlFjn8HEaqpxb+lxuPuc=;
        b=fLhyLNuSrJRVTYpdvVpyyHNeshYnIUrTh+W3fuFtTDGk9zHsHZtTjEGG+hKAcwu6IK
         w81BUHSR+xQhdu8mPVXGoebXWwJvONGbHIy2tMjWl1nWTIK4CQ/h+07fiBQ9s64wxKtt
         ALR4yR4iPGVzlQOftp48Ud8JazbX+eSWoTVVFTmU8fgxVGuJuhlYZeA67h/VHUVih4CT
         TQ3WnlJxXScPPuyRmfVr4o/wci/8A1kC3TqZwU/67hO2mt2ryWHZp2NVQtyjAdSWJ4/I
         QIAYC6TpX+sphCLJYup8xFkPKZSE9s+objE8bpryB1f7j1YI/eFCoCCvj1Z76uNXbXxS
         trkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FoSN4KyUvHbC1UAZIb2rgbHTlFjn8HEaqpxb+lxuPuc=;
        b=mVzn8veV4bg/FoKSWZ9nP8fg/6m5GozC6UrsrzRZWtKhC22rRNkowlqq0NvQb3TVNf
         3+3t+lfITPm5f2wz3Whm373OHh/QIgBiL9WyFFH6K3CUiUgrrTqKwTtz7Q+1SHSSbtZm
         wh3J2lJCjJtyEB4Rz+GL45s9bIIfwuz4ExZwmz66t3ouHJ5JjOOuTus4MKqnn1Ckeiz/
         Iu4yuUuBHnplyI3ZIIVkKTf/zyx0Y0kHBPWB6YoI3uYAwjNK2tzTqYUREo1qggKggzex
         SvdLQsxi5LAbuq3sCzjs70xFWOhBYKSiQATnTEhdtsY2+BCt9+dZrU1qHgs06gq8VIOV
         f98g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sRxDkgdp7S8fQh74o96DNhl9RvOQDcFa8E8rYE3eoItRxG18Z
	KM+/C3m8bzfJU6B09Z3MJk4=
X-Google-Smtp-Source: ABdhPJw1qec40avPU/AmquEIZqYsJS6T4Uy5vvoFsF0uS7DT/vdsL+mCNRsBlBVRXplZ/mhbzzLEcQ==
X-Received: by 2002:a05:6000:1864:: with SMTP id d4mr4944941wri.345.1634199156959;
        Thu, 14 Oct 2021 01:12:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1caa:: with SMTP id k42ls4367559wms.3.canary-gmail;
 Thu, 14 Oct 2021 01:12:36 -0700 (PDT)
X-Received: by 2002:a1c:2b04:: with SMTP id r4mr12687923wmr.48.1634199156094;
        Thu, 14 Oct 2021 01:12:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634199156; cv=none;
        d=google.com; s=arc-20160816;
        b=VcLQdhJCVRHG41Si2QB9RX+zOCc21a7WqRy7oglhAeLujJ0BWJiDIwH7QpEht+Vd1q
         +mS/qE58k7fN8JhmaaPy7JgDxOHFaCj7mzxGpTmzmyxAEL24IQWXVAzAi4MRHfUEAkLg
         MCtLkMcjY80M1kQfps4o94PwENTa3TPBNTLYmtjkuYSv8YHXeB5/x9CFSPb8ISeTqfGQ
         iOMLL7edEZiW71uTjwOJUIdsZDC9SVr5EEVe0+m/crPeSBsv5yVkvQaLDwws+r0MaiWJ
         5zGpU+fJ5TtiRTmtxpudGIVwasY9r7xmthNimw/l2GGcCybP0qzD8rbXdI3RSTtMgakk
         v+nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=T4BBGf8C8Hds99rvLv0C8gO68kXruefDce9diJnZZ/E=;
        b=BtSctjklM92XMiwnVSGdQtsP+B3HmVpQ0VoDo2nih9UAUQGPXvU+fsCInkt/viVdjp
         YRSgtqflU/sjgsWBEgxw7e9S4f+qNp0c+TFczN0EwApwIdielD4gkiSzofiWus9v3IKo
         KZInVussNMJe8A/uLhrIJTCODojVmnfnaje/lf0oNBU/5OKPTelL5pfJqqNeuHEZomzW
         FQRm7/tVn/XLFfxyUi3AdqnlO1fLFxQ831TstwSnml4TfIbdZ/ybOvg9iXaYs+7N5nvv
         gs6WK5bw3LKuYX3uczFYgZVqG4jkEDlpUIxZG3GQIP6HPKe+H1YM9rCKSjqTi3FseVda
         c67w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z4si37306wre.0.2021.10.14.01.12.35
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Oct 2021 01:12:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 145C61063;
	Thu, 14 Oct 2021 01:12:35 -0700 (PDT)
Received: from [192.168.1.131] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CD7A43F66F;
	Thu, 14 Oct 2021 01:12:31 -0700 (PDT)
Subject: Re: [PATCH 1/2] kasan: test: use underlying string helpers
To: Arnd Bergmann <arnd@kernel.org>, linux-hardening@vger.kernel.org,
 Kees Cook <keescook@chomium.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com
Cc: Arnd Bergmann <arnd@arndb.de>, Andrew Morton <akpm@linux-foundation.org>,
 Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
 Peter Collingbourne <pcc@google.com>,
 Patricia Alfonso <trishalfonso@google.com>, linux-kernel@vger.kernel.org
References: <20211013150025.2875883-1-arnd@kernel.org>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <b35768f5-8e06-ebe6-1cdd-65f7fe67ff7a@arm.com>
Date: Thu, 14 Oct 2021 10:12:54 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20211013150025.2875883-1-arnd@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 10/13/21 5:00 PM, Arnd Bergmann wrote:
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
> 
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

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
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b35768f5-8e06-ebe6-1cdd-65f7fe67ff7a%40arm.com.
