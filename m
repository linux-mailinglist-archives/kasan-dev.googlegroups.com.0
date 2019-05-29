Return-Path: <kasan-dev+bncBDV37XP3XYDRBBGEXLTQKGQEAV4I3XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 294AB2E0CA
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 17:15:17 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 25sf284510ljs.16
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 08:15:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559142916; cv=pass;
        d=google.com; s=arc-20160816;
        b=BOr8utN4aAOkmb5/EHVQybwRG9GuQ8XCauwUlwWiJkyY23xMyL6s9jnn91wETORaye
         BM9on9pVQXggUQHMcpNKkBeWtVW/ZoaTokhD8iD4UWSBa1laQwxakwBFU8rLVg/UvH3Z
         9Z60Ri/gnVlKDvjZ7aQQmby6oZ7g/gt4hw2cUL7jsOZGaDye5LaTU2uGcyHbUoIKeVDT
         1TPaar8XYBh9qiPtlaXR5YVq+2+fd8PEDhifDu4VZvSt0c+/ZJTXH/5XgtFyOo+NWf6D
         Tw1n0v3SJr2ZCmxEJXPfX5zt8CsqoWYtMQmHjiQUeWqxXP9YBkEv3uuM2QpOQEMVJ6S8
         a/5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/41SwZGVz9ZCrpi6JEV5EutPbQYaSPe1Sp5taNAL4sk=;
        b=d456N5ikmBROryOBfCih6UHp06vouhB+dLwKrL430ycRmvEkobn/Eti8ntBzpsDeTw
         T1OUuiQPU9PThm/PnnLFqH1pFeNU7vz8xKMicU6JnT19r1xdjd5T9pYdnKy8wAzzu1ty
         vjlHamvW+nu8BSRSBjpfCt0NuGy3KhswPhMADFIJNyb9qWKYMlr1oWrEwP/YU+jtHLK6
         ACxE8IhO5fT4ddyygC19sp33rJR6fyORk+P3fM8EIsFQ8bYviQnbjB8plgc8SoE7xDF6
         8asdvjHL9O3WtV26ir/83u+jFppev/dq9OGnSO8a8QM+eAR7xND8XHHzLXIw+wfHUHb3
         4PkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/41SwZGVz9ZCrpi6JEV5EutPbQYaSPe1Sp5taNAL4sk=;
        b=d9a1jxnKmNlqcEfTvq81BluGr4cAzNvzn0GHWbnN3JKrs5SekpfFZK4StNF2FmOWK5
         clt/NxGtmbUmxj8vlr3jjPKA3/lhmBiGyPsYD0QE1KhHawjJlKyZEn1w6etI8XXu9fvN
         z4wpX3NvgkUjNMti4QQQagTGG0JNLwKmWxLTfTEpdHAKk8Hn2T+ayg6OasXqVd2pOKKh
         fLwjSS/TpAbJtwnwGUaKK90qKhLpc5ltKrVDjl2yYAwc9D3SZoUNfhZWNNUr26rRz2cz
         ilG2ykTWM3VDZWxJ9QSba6pBRLtWwsdGAj2dm8pSzC2C3fzXEeX5tb11oUNFhsaxm8j/
         tONQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/41SwZGVz9ZCrpi6JEV5EutPbQYaSPe1Sp5taNAL4sk=;
        b=KqzaNhWPZ+ynPOyArHhIIwjH/yCCpqD/niNUh4Ixq3+rPsnRiBxKAcOp2XgfA4Fia/
         By3to4bNLGxkL+GwrQuU7LOeW3FHO1BNiXs02A+MsuRSfl6zMPqAVuyKBvm1GTNqBpYX
         vVSwZteoYrJFTPRb3wER/rrFhgLdZi69vmaybIUFi+Eco9RtFS7/XTz3Vizp/IVbtF0U
         U+p+VKKZI+BSZRyL0N3VN/+Q9b9dAaRYW/YmydbE8+f4UxHijbzoqcP02KBn/9bvBny0
         Hzkkq5gnocmyMCgNWa+FwfqaIUqkRNHCSKVGLNGAjaVRdk+f9GlxiVjGQvMf2DoBh5VJ
         C7rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU401si0LLWc8t0aXsajTYnpDEgxCUixTztEaXhXWotgWIndeIP
	U5UU0pueguSwc2QmgDpuk1E=
X-Google-Smtp-Source: APXvYqyUj8eK4VhwN81therXD+JqiGKf9NKLgLbI/fU16/TEsW5yLKxcszCy7McxwmCuiCOtHPA/ow==
X-Received: by 2002:ac2:5337:: with SMTP id f23mr12920162lfh.15.1559142916657;
        Wed, 29 May 2019 08:15:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2b4a:: with SMTP id q71ls324750lje.13.gmail; Wed, 29 May
 2019 08:15:16 -0700 (PDT)
X-Received: by 2002:a2e:2c17:: with SMTP id s23mr15865927ljs.214.1559142915993;
        Wed, 29 May 2019 08:15:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559142915; cv=none;
        d=google.com; s=arc-20160816;
        b=LA3qAM9nCisd29Po1AWJSIB6pfWiPSrWvDKGhhbtcN2jWwPpL/U3hzbOR+r+RV7Uqu
         tfCKcT6rM8pu0nkxIt7m7XDfhgsF3UBGuz+kM7I3aBGUnbn2ec63q+T+bGPF3ReO7GWV
         WRLsdKDRzBU3kHuPKeLXRhfFNdLg06gZ7RmI+TqZ/QtVPodXLXTWS1xWsSQp5dSIU4va
         wqLuyydY/A7HNMc+Aizdl23AwxHG0uRNXXg1bbIu1LPuyykxx2ysq1kdGsSyiwm1bJJB
         6JMfxC7wLyVcl9mjE6z7yRFRXu+BrqdYjAd9tZtMMX3c2NtVWINfmB8AZToTuWj/7p+8
         xdvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=HZkrRc/HiXxNBOObYKoeQgd+L+tdRSc3/FsW3MGr9So=;
        b=QFjmKVV3NPwi+kg8X12+uHRMzrMpLuqm0JYtP3HVAkjzf4D3uwUbv0nsFu+vd+4bem
         ynIe01mWryydOtXM52cHNnkyNMxQCLwrCDvMMvVILgZ/dSIGY0XzfSDukcd28ktAQ4ZU
         KYVsN+mXmcCOLXfFptKpXcKdF4+Q/kOBaCUvpQ/r3b/TDJvGgc2+yAfO5WiAM9C3B0cm
         hfBhZYN38Rip5BeMbbX6XAEIgpTfLnvhDKhgOV9w0gbDzMAyfeXTrg7KNLHj5wnIqz5p
         RcoaMmBlqJOJsYuC8HQs6tVE+2f1Y6whCzZz6ZtLtB4+tXtlMwvznTLi9uZT8BYIARDq
         VJiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (usa-sjc-mx-foss1.foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id s187si740345lfe.4.2019.05.29.08.15.14
        for <kasan-dev@googlegroups.com>;
        Wed, 29 May 2019 08:15:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D7737341;
	Wed, 29 May 2019 08:15:12 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E0F0A3F5AF;
	Wed, 29 May 2019 08:15:09 -0700 (PDT)
Date: Wed, 29 May 2019 16:15:07 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com, corbet@lwn.net,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, hpa@zytor.com,
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 1/3] lib/test_kasan: Add bitops tests
Message-ID: <20190529151507.GI31777@lakrids.cambridge.arm.com>
References: <20190529141500.193390-1-elver@google.com>
 <20190529141500.193390-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190529141500.193390-2-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of mark.rutland@arm.com designates
 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Wed, May 29, 2019 at 04:14:59PM +0200, Marco Elver wrote:
> This adds bitops tests to the test_kasan module. In a follow-up patch,
> support for bitops instrumentation will be added.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Changes in v2:
> * Use BITS_PER_LONG.
> * Use heap allocated memory for test, as newer compilers (correctly)
>   warn on OOB stack access.
> ---
>  lib/test_kasan.c | 75 ++++++++++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 72 insertions(+), 3 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7de2702621dc..6562df0ca30d 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -11,16 +11,17 @@
>  
>  #define pr_fmt(fmt) "kasan test: %s " fmt, __func__
>  
> +#include <linux/bitops.h>
>  #include <linux/delay.h>
> +#include <linux/kasan.h>
>  #include <linux/kernel.h>
> -#include <linux/mman.h>
>  #include <linux/mm.h>
> +#include <linux/mman.h>
> +#include <linux/module.h>
>  #include <linux/printk.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
> -#include <linux/module.h>
> -#include <linux/kasan.h>
>  
>  /*
>   * Note: test functions are marked noinline so that their names appear in
> @@ -623,6 +624,73 @@ static noinline void __init kasan_strings(void)
>  	strnlen(ptr, 1);
>  }
>  
> +static noinline void __init kasan_bitops(void)
> +{
> +	long *bits = kmalloc(sizeof(long), GFP_KERNEL | __GFP_ZERO);

Trivial nit, but this can/should be:

	long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);


... which is the usual style for sizeof() to keep the LHS and RHS types
the same, and using kzalloc avoids the need to explicitly pass
__GFP_ZERO.

Otherwise, this looks good to me.

> +	if (!bits)
> +		return;
> +
> +	pr_info("within-bounds in set_bit");
> +	set_bit(0, bits);
> +
> +	pr_info("within-bounds in set_bit");
> +	set_bit(BITS_PER_LONG - 1, bits);
> +
> +	pr_info("out-of-bounds in set_bit\n");
> +	set_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __set_bit\n");
> +	__set_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in clear_bit\n");
> +	clear_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __clear_bit\n");
> +	__clear_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in clear_bit_unlock\n");
> +	clear_bit_unlock(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __clear_bit_unlock\n");
> +	__clear_bit_unlock(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in change_bit\n");
> +	change_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __change_bit\n");
> +	__change_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in test_and_set_bit\n");
> +	test_and_set_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __test_and_set_bit\n");
> +	__test_and_set_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in test_and_set_bit_lock\n");
> +	test_and_set_bit_lock(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in test_and_clear_bit\n");
> +	test_and_clear_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __test_and_clear_bit\n");
> +	__test_and_clear_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in test_and_change_bit\n");
> +	test_and_change_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in __test_and_change_bit\n");
> +	__test_and_change_bit(BITS_PER_LONG, bits);
> +
> +	pr_info("out-of-bounds in test_bit\n");
> +	(void)test_bit(BITS_PER_LONG, bits);
> +
> +#if defined(clear_bit_unlock_is_negative_byte)
> +	pr_info("out-of-bounds in clear_bit_unlock_is_negative_byte\n");
> +	clear_bit_unlock_is_negative_byte(BITS_PER_LONG, bits);
> +#endif
> +	kfree(bits);
> +}
> +
>  static int __init kmalloc_tests_init(void)
>  {
>  	/*
> @@ -664,6 +732,7 @@ static int __init kmalloc_tests_init(void)
>  	kasan_memchr();
>  	kasan_memcmp();
>  	kasan_strings();
> +	kasan_bitops();
>  
>  	kasan_restore_multi_shot(multishot);
>  
> -- 
> 2.22.0.rc1.257.g3120a18244-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529151507.GI31777%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
