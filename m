Return-Path: <kasan-dev+bncBCS4VDMYRUNBBJ4KQ6MQMGQEASGQA3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AA4D5B87EB
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Sep 2022 14:12:24 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id j186-20020a676ec3000000b0039796d528bcsf1495256vsc.23
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Sep 2022 05:12:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663157543; cv=pass;
        d=google.com; s=arc-20160816;
        b=p8sCcixvJkRKYi8Aql/O7nfS8kTOqWUDnJWi5eIsh3Tw8QW21NXCBO5zznYvQhL1Hs
         hgZz+mxddO1xMGfgjfgMmHBUULoZo9KUlKfdTvu6NF85DbTS4Y/DFWKrUbQX8jOMjzrl
         qtfkEqzPqVA3f/ag1ri/MBt8rVBQzdruGQ2JqlnIIJOwZvS5sz9w0bg1XEitEFJ60kfw
         LPearaVFGKVubhD013bqJ+DUbI+QVb0Wv9rM8yX3aGB4k3Y/GyWSE0xCUsHtE4M6jwpZ
         ckyeciH5ihBuxSbiJUMWQ8J/bwZ3Mge2qExDE8xSh9COLKjpRuZD5yyp6Ds6W0+Z9iGv
         a6FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ex9RLeKu8KnM8uluOAD9Ts83y4ZT0Ddwn6d1tjwZGCY=;
        b=Vryzutst6k53KeCRBKjzNbyElPHBZW39odszIFDJyk/osnH11un63CSzWjHrhJ+1Kq
         4t1NMqwlfkT2pudUqlnjr4uECIoRsyUcw6+fFhxf/uydPXHyihDeGm9Fo2q4EKOe/6Gd
         oec59FxZBQK6DPjuHkqe4QxKjxR5dHzzTeUPlG8s5gTQ3DZDkYIJyzwot8728/ui3KS7
         slcpbJJ5a+nWDlpKvNmAbmte+NKLeTaMY3Ei8dFKwUS0acCSPvlA+Ohi+sUJ4ASsCmSc
         mz/Z8W/RQ2vz/ni4XtSrRAfsWcs7/dzzf5n4SSl9RqzjZ5ZS84APnFzBQqwanqXxpLbF
         p9GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Qy/Fb2wv";
       spf=pass (google.com: domain of srs0=lam/=zr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=LAm/=ZR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date;
        bh=ex9RLeKu8KnM8uluOAD9Ts83y4ZT0Ddwn6d1tjwZGCY=;
        b=SBp8CTnxFRY07k/u4VTjSYztzTnxTHcUA/ACQG7ZBmSuv69IwyJTxmBFkt4DrJZmdx
         OtCpxP06cPb5ie/m0YNeva+r+tNsHv0wg9JBWUpUC5mgp3Unqz5n49z6ltY+RXJd9MRW
         ik48FWb3zhJ2dGDnkEJdIVI4D8cbtX6gZBIf3zVcE6GACsSLyrxBTXMjShlDBl3jW6cI
         bKchblWBDHAd4WHhJ+BbgyiCrXk3Epoo9pXI+4oNdBPiHg4Nnqu8vA8TreMtBGz2Jikn
         mFcT96aO73zY7Ob+enQ3dDbllij8AgOG1PSQNJqkAr2u8PlpidCwnuqIIR+SZ2uxG/l8
         VEJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=ex9RLeKu8KnM8uluOAD9Ts83y4ZT0Ddwn6d1tjwZGCY=;
        b=dlCpKspKuSze6dPyRuLuD42haeES8D/KZIjjAW9XYym+G1cdsslBQXPDr6x0Odtq2D
         22QAVvFQ76vpQQWd72KItqqEF3slLrgfn1EBOJIgPpcGxL46YbO15FqLyB97OlTOul0V
         IWTYH47iyh2KUcVKwhdWeVC0Dl8o3qpQkVs7CHaK8aKZJFgPr/lpehTuT2vNQ0D6eZNQ
         VmH72C7/yOrQfdHEMeLzoey8C0X7rWqsZKAe+vgd2fYlDuX+S1YOgkLEhnKnNzTEC6Hf
         JU6mlyrxDABg54FlAzmBVql2CZkEbM6ejBeW0Mb4wNJCGKz5bfDf2SQAH7riSMFltxJb
         5gfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo00Q7VWzUAXM4M6z72Hs8HnBN64w4Z+q4N6qvw71sPSNYzVvvsc
	FxkoH/dcf2NotWeAmvHhWyE=
X-Google-Smtp-Source: AA6agR5DYW0t7Kv2EKig8OWJ8VWZ0qbf4vK834J4dX6JWYbF9vw7+qUkv244SgGn+gd8U6NL6+ms4w==
X-Received: by 2002:a67:a44d:0:b0:38a:8a55:a97d with SMTP id p13-20020a67a44d000000b0038a8a55a97dmr12255646vsh.39.1663157543549;
        Wed, 14 Sep 2022 05:12:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd93:0:b0:398:a64d:75a7 with SMTP id i19-20020a67dd93000000b00398a64d75a7ls1249634vsk.0.-pod-prod-gmail;
 Wed, 14 Sep 2022 05:12:22 -0700 (PDT)
X-Received: by 2002:a67:e219:0:b0:398:90b4:9ed0 with SMTP id g25-20020a67e219000000b0039890b49ed0mr4875052vsa.5.1663157542940;
        Wed, 14 Sep 2022 05:12:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663157542; cv=none;
        d=google.com; s=arc-20160816;
        b=WaG/l4BHgedaw+Frdoz1ALFWfR7cplI08INdRHjgRglRfxno9qB2EEdaA6kPW14oNR
         fgOpmYLl0x7M0vF82FuodqIgbpPDic3Xu2oH1N6x/Jqz7Ucm+mkgzyqTHLmYkWTqWdvy
         eQgKfHoW0s9uS6n1ZEbUGZRuJ/ibBhjLszk7dSvZuRMiHx57rHixJ3ItwRJ8MUR8ZiHI
         z+d7XircnXDhg1OJ3iEZQWdc4HxOEpOtI90l7vamOo2UF2dKn0mWtSFwljbM+9qz5NJI
         ROa+sNIXXh3m+ctXg2kpHT41kQennXdd+WyDyfC2i/4S31i6+fB8MSQcJBjAUQvqfGKN
         JNeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5BvhJMkrkPfuADEpjG7EtXP+7RJ2C/gU5N4ATj/PT0g=;
        b=IiYEtXs8Cm3faqvKBWsEbPMn4Twg6bQOXyqM7+upG+/EMbRYZhhmcYaBoMMonzmLrs
         jGSmDGz+HNQu8OdC1QDRBIvbIQxzKLm+gCiL90hNh7mr+asQYcBBAvoWn22iAHQtC/Qd
         J+hymof1+1cTYFPLNT2KtQc4ltSFdhKEi+es2slLBp9ThTPK7463AsOTagWh/Cyl6VOD
         yI/fvur754KqUc3wJpFKnT2zwLVs5u7lnyBp6T+Ny4gpuY6afBK4ExnDarE60S0HeCJw
         YB55KI3Ua7+x/cNNt0MYP5fMkbnu15kj7zbxmI+7uJPKNvyUnZ9yqAgYePqEKF5GW0kD
         PuEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Qy/Fb2wv";
       spf=pass (google.com: domain of srs0=lam/=zr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=LAm/=ZR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g16-20020a1f2010000000b0039e8dc4638bsi135415vkg.1.2022.09.14.05.12.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Sep 2022 05:12:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=lam/=zr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6DFCE61CD5;
	Wed, 14 Sep 2022 12:12:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A239AC433C1;
	Wed, 14 Sep 2022 12:12:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 1A4025C06AB; Wed, 14 Sep 2022 05:12:19 -0700 (PDT)
Date: Wed, 14 Sep 2022 05:12:19 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/2] kcsan: Instrument memcpy/memset/memmove with
 newer Clang
Message-ID: <20220914121219.GA360920@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220912094541.929856-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220912094541.929856-1-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Qy/Fb2wv";       spf=pass
 (google.com: domain of srs0=lam/=zr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=LAm/=ZR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 12, 2022 at 11:45:40AM +0200, Marco Elver wrote:
> With Clang version 16+, -fsanitize=thread will turn
> memcpy/memset/memmove calls in instrumented functions into
> __tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.
> 
> Add these functions to the core KCSAN runtime, so that we (a) catch data
> races with mem* functions, and (b) won't run into linker errors with
> such newer compilers.
> 
> Cc: stable@vger.kernel.org # v5.10+
> Signed-off-by: Marco Elver <elver@google.com>

Queued and pushed, thank you!

							Thanx, Paul

> ---
> v3:
> * Truncate sizes larger than MAX_ENCODABLE_SIZE, so we still set up
>   watchpoints on them. Iterating through MAX_ENCODABLE_SIZE blocks may
>   result in pathological cases where performance would seriously suffer.
>   So let's avoid that for now.
> * Just use memcpy/memset/memmove instead of __mem*() functions. Many
>   architectures that already support KCSAN don't define them (mips,
>   s390), and having both __mem* and mem versions of the functions
>   provides little benefit elsewhere; and backporting would become more
>   difficult, too. The compiler should not inline them given all
>   parameters are non-constants here.
> 
> v2:
> * Fix for architectures which do not provide their own
>   memcpy/memset/memmove and instead use the generic versions in
>   lib/string. In this case we'll just alias the __tsan_ variants.
> ---
>  kernel/kcsan/core.c | 50 +++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 50 insertions(+)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index fe12dfe254ec..54d077e1a2dc 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -14,10 +14,12 @@
>  #include <linux/init.h>
>  #include <linux/kernel.h>
>  #include <linux/list.h>
> +#include <linux/minmax.h>
>  #include <linux/moduleparam.h>
>  #include <linux/percpu.h>
>  #include <linux/preempt.h>
>  #include <linux/sched.h>
> +#include <linux/string.h>
>  #include <linux/uaccess.h>
>  
>  #include "encoding.h"
> @@ -1308,3 +1310,51 @@ noinline void __tsan_atomic_signal_fence(int memorder)
>  	}
>  }
>  EXPORT_SYMBOL(__tsan_atomic_signal_fence);
> +
> +#ifdef __HAVE_ARCH_MEMSET
> +void *__tsan_memset(void *s, int c, size_t count);
> +noinline void *__tsan_memset(void *s, int c, size_t count)
> +{
> +	/*
> +	 * Instead of not setting up watchpoints where accessed size is greater
> +	 * than MAX_ENCODABLE_SIZE, truncate checked size to MAX_ENCODABLE_SIZE.
> +	 */
> +	size_t check_len = min_t(size_t, count, MAX_ENCODABLE_SIZE);
> +
> +	check_access(s, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +	return memset(s, c, count);
> +}
> +#else
> +void *__tsan_memset(void *s, int c, size_t count) __alias(memset);
> +#endif
> +EXPORT_SYMBOL(__tsan_memset);
> +
> +#ifdef __HAVE_ARCH_MEMMOVE
> +void *__tsan_memmove(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
> +{
> +	size_t check_len = min_t(size_t, len, MAX_ENCODABLE_SIZE);
> +
> +	check_access(dst, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +	check_access(src, check_len, 0, _RET_IP_);
> +	return memmove(dst, src, len);
> +}
> +#else
> +void *__tsan_memmove(void *dst, const void *src, size_t len) __alias(memmove);
> +#endif
> +EXPORT_SYMBOL(__tsan_memmove);
> +
> +#ifdef __HAVE_ARCH_MEMCPY
> +void *__tsan_memcpy(void *dst, const void *src, size_t len);
> +noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
> +{
> +	size_t check_len = min_t(size_t, len, MAX_ENCODABLE_SIZE);
> +
> +	check_access(dst, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
> +	check_access(src, check_len, 0, _RET_IP_);
> +	return memcpy(dst, src, len);
> +}
> +#else
> +void *__tsan_memcpy(void *dst, const void *src, size_t len) __alias(memcpy);
> +#endif
> +EXPORT_SYMBOL(__tsan_memcpy);
> -- 
> 2.37.2.789.g6183377224-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220914121219.GA360920%40paulmck-ThinkPad-P17-Gen-1.
