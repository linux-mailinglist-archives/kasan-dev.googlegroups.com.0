Return-Path: <kasan-dev+bncBDV37XP3XYDRB545YXTQKGQEXTIRQKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 668C4311D0
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 17:57:43 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id o17sf4219038wrm.10
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 08:57:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559318263; cv=pass;
        d=google.com; s=arc-20160816;
        b=RDix6xWuGAuE73fvGsqyWWaSsKaqIWyevC6SsGav1vIrZSkeOgwZpsIepfl/Z0ZZ/6
         bjhS4FaCnB66BENRDU8kXa7CHFhyZRiw5n/NJVX3pQWLw3VWvpmJTeLX/QDGwBof1arR
         uwJ1e6yMrJzoux4aekkq4dqJes3MXA461BtzCrhCAtEDJrTR9gs9p6au1f4taZAJw671
         ieobEZhbz1DO9HaU5Zxy4GLC1J6P2mTYE5e7Cp5gZchJ2NBUQNIz6nE4h2BzDBfzKo5d
         HvJqf3SK+7X02s1QD5NqgZXyLqWvmo4veQ6v7hR7N/NyHOCvRYWr1/m1aj46y5/TPwSv
         TfuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=JRTwBErGnj5edJrK2I/KuaJOvCIftPb80rrWl13Xwb8=;
        b=vgP94AC/zUTJtyhzLV9qF302WzMnP+2rUx8jRx0bmwV665MGt6slvGLVQgekhNwk1K
         hVgQaL2kbYVwte0sjadyTUd9VMKn4yi7cfmVEYFoWS/DeXPDBTKFXP/f8YL+BsN/fT3u
         tIj6OLsDn7Pm9Q4LEH7sU/qfZyaRb6e4L0xnKDfxLErfrQ2PRT6GFc/uQiigFYsEdwTT
         AJtgr+KYkyRkDlbu/b8lL9c2K7s407Wq6F6B+sPV6/eHRCOv4MqP6h78SsmZ1SriJjjs
         MEIkApwHg76nK9jZtdraYcUmS+V702hlDpE/RXJqmfR2mnMSqbSYhBvRBXTePeRaN6yY
         0hBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JRTwBErGnj5edJrK2I/KuaJOvCIftPb80rrWl13Xwb8=;
        b=QZB0nx4xkRMjys1los4En/go6HWGzm2c1OXlhU9fz4Z5X1+BE/BVJpIFIxE0zlzkyR
         hPMjSaV8MqlC22kENa9pSHj+bONHwGMOT9bxmTB++/5O4s6HqF3kOO/iKc/VM7HvBH5J
         3qzeJX1ehsAsaUfGKrz3gpgHDkH9ecK8uPCVmtPOp6U6d3FxDEXpCZ4SMOa5eFhkFM3/
         ccp1nufbyVlIqEfApi5E7fgipHfNESKc4hwI9sLVOgVRFjIVkIATw2P5skZuzvK8gJR9
         OCsqOA2kDxBQIIOGufHLn9waq9j58+Hi58bKGj1LO95gWrbjZPe0E+IsWu9X/Jrrmcjc
         kCsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JRTwBErGnj5edJrK2I/KuaJOvCIftPb80rrWl13Xwb8=;
        b=O2cQ6L5UmEYT/+9Cu7P1vs6vAsRGLsR2A6GeSbZY7WHn26GPZxheaMLgOt/6lBCgKj
         hnyS+7NAzUMD5Vav2x2hPxY1iqwJJr1XZYE8r2Fi9WFmSpDX8eON8s4BoqW7pqMlAKWE
         3zxvk9eDWOzmAVvh6USalKLARWd0sv9jXHYmJmLUsoJ+evXnnXsw5hHn0sA3kbEKfOEb
         Qz5EfFSbY9HCwSfUzOyIxIvXCVCZW10TnOguhkBPEUo6wbBSRzEqvnW/2Unx6jOOMxjr
         E0NovqQQ7BgDekEr7G3mKg1GS9s6w4zNtZUswolM0G95IRO/7DNXN9xchbChn/eHmBzi
         U4Kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX51kW7LF8Y3KF/eKnkFgmWODypSimcV6AIkF0Y60rU+SA3+0D4
	OxnfmwMQ7WtCtLfz0O/RYaU=
X-Google-Smtp-Source: APXvYqwgI0T0F/+7g//RWuxoUyzRcfEhXhcjWuXnw8+B9HeagJpAZ4AySmmL/WOUNkiBq8lF5JxfqQ==
X-Received: by 2002:a5d:4e41:: with SMTP id r1mr7258442wrt.66.1559318263149;
        Fri, 31 May 2019 08:57:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c18b:: with SMTP id x11ls2019525wre.15.gmail; Fri, 31
 May 2019 08:57:42 -0700 (PDT)
X-Received: by 2002:a5d:6191:: with SMTP id j17mr500202wru.172.1559318262550;
        Fri, 31 May 2019 08:57:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559318262; cv=none;
        d=google.com; s=arc-20160816;
        b=U0p5nIlsnux0bcYKpV1X4Bx0HsjWWw0knB2V0SDVfdnvb9RcosK68oL9r8q7wOTGgZ
         6iBlKsCv9zBXQ4OsUBvmCk/jEFRSpwtzzpRdrp0sXItGCQjBPrUobhECKNeN4ckJwIG4
         6oJNjhAN5hgz7f5scqd1JdVgnjIKDzv7KhvcwFoL0SjgnKdGeuusP/x2ii3yI7IFJVGq
         Qw1aHLaNKEhVmpuS31XkA5HmAv+ejN9XXy+mN5ezW9s20psmBYX7lxvxRs0sFJe7TVgS
         qq4fC7POY99LKQLjfAKoYTPH1Xe6jl8dL2APlHKFnvTh+69NTwkckYju+M1mPERKFNOY
         5F1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5q4pd8tkqz3U6d/6DU2z08AiX+G7zcZW73Uqv7mWZVM=;
        b=yPKDga1QuYf0nDQtu8LFp03mgemsaRd3ohwzjh94sZIW1UToHYLqEbjmmPA0RzgNz5
         RTErnS4gK82Jt4ggxHJC1bDAfRhGY3UAEvL4sbm/iZPVfEREc/cpYwGNjvh8XXZf+3Hq
         Js+ugzdAi5kh2udi9jH6952p8EBYiUBOZidKxYVXPqaTAf6pldwQ+hhT+WFGKcOGy5Z8
         2pK7dRTAz8QiW/FM7dKBUob96c2qaapjWBdH/hP+4Ck51Jn7Bs48GVrVI6K7MoVvGwL8
         kU39e5oAtcqlpx6XokZaoVqeT3aB+J0xsgwOatr8L9vtkp437Z7sBlHXkzTRF+l97p8R
         a5yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (usa-sjc-mx-foss1.foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id x8si211884wrt.3.2019.05.31.08.57.41
        for <kasan-dev@googlegroups.com>;
        Fri, 31 May 2019 08:57:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3324A341;
	Fri, 31 May 2019 08:57:40 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3DB213F59C;
	Fri, 31 May 2019 08:57:37 -0700 (PDT)
Date: Fri, 31 May 2019 16:57:30 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com, hpa@zytor.com,
	corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de,
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/3] lib/test_kasan: Add bitops tests
Message-ID: <20190531155730.GA2646@lakrids.cambridge.arm.com>
References: <20190531150828.157832-1-elver@google.com>
 <20190531150828.157832-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190531150828.157832-2-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, May 31, 2019 at 05:08:29PM +0200, Marco Elver wrote:
> This adds bitops tests to the test_kasan module. In a follow-up patch,
> support for bitops instrumentation will be added.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Changes in v3:
> * Use kzalloc instead of kmalloc.
> * Use sizeof(*bits).

Thatnks for cleaning these up! FWIW:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> 
> Changes in v2:
> * Use BITS_PER_LONG.
> * Use heap allocated memory for test, as newer compilers (correctly)
>   warn on OOB stack access.
> ---
>  lib/test_kasan.c | 75 ++++++++++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 72 insertions(+), 3 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7de2702621dc..1ef9702327d2 100644
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
> +	long *bits = kzalloc(sizeof(*bits), GFP_KERNEL);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190531155730.GA2646%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
