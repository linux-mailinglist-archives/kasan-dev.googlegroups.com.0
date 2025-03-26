Return-Path: <kasan-dev+bncBD4NDKWHQYDRBBGMSG7QMGQEL235CRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 36739A7200F
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 21:39:34 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e572df6db3esf501358276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Mar 2025 13:39:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743021573; cv=pass;
        d=google.com; s=arc-20240605;
        b=cVDmCDJ0jawzVSdcLxGFA3EG8xBAQPajXhjJvfUkeUlZae4naBH5l63FiFp/tZd8cH
         oYtEBwS6nU11q01hKuLO1bRoz8X6q/v8CNILQj1Sv80SaIzs9AVTWil4IzhU6GmVkBxe
         AJTG+q6HQD1QFpQ4TyrS7brf4Pt3gyivCrDMfFfTY+LFogE/NFjeWEibbN95NXIuTEQ8
         PPJMuoZBcIQunQgW+l454ISHKuemKAKzT2dYrpnT214LvGthntM3T8+hg1Ng1m79SLn/
         0RVx+oB/6kulcdoM+ykNCWUXQxvSZcyfL1//2lwKld+0Dzr+EQD8nu4Hb11tCHvnXcKH
         1RYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6Kn5a4ioPIFf4SfX8qiMFKlIDypab9VbBgLHJuaA4UI=;
        fh=mCngaRlgUE0n+tFiZ6oGalA6HLJLoa5miYu3l+SoXp0=;
        b=Te43Ck0cHqFX4e/LePRuyaQZlZ5Iy5rxs/myOulRfFC5lNGYBbHwrVMcQ3xeousOIT
         Nadt5T5h1zlIIbDOag0A/19ib26s+tlRSoSjteKruFi1nkAVQ2TWK2bFTFZv04tGfDcX
         aX/G/C7tHSn6S0ZLhG94yWBteIvQJyOTYVeb3tGKEMF/M0krNgiIHS9HIGIJ8i5/ucfC
         zOIp9ewu6GaQGoMxgBZep4VYa/UkSK66fpGLupM4YEEv+8vXOjOpEPfuXI5umySf73Jp
         REHxM8HXyVxZmx8lqaczKajcl073A1Oz9tS43gj/yp2X4J5kXJWTHbBrvOd9JJG/TsjJ
         ccxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WhKJK7Mh;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743021573; x=1743626373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=6Kn5a4ioPIFf4SfX8qiMFKlIDypab9VbBgLHJuaA4UI=;
        b=QRUBhDEwzcotboVQf+plS0MiZgPc055kM/SOcr0127zwKcSVa+QqfPKQJGmUg72xoI
         QskgUQ+sgSESR2hY2eUlOzHDk2Ddd60OxbMx8hCcK2/JmvY3X7IkwYTJMuLlsS8OaQqC
         gqSSKV6ZeEYpwNeiqHsryzP3eA7/uE2KZv1YYot3hcAHNxfigUnXlpr8DxvjzvywZyy/
         D6UEE1dhDkFHrwdL+2zdy1i0KFK+Rsu9swR7Q7GEBgreSfAOvzQjBsoDljBkSKviRcUf
         6eJr5cKiFhWd+FjhB9b+gEuF+UL7oynHG3jrdY3bTivwdPcbx3kZjcgrRPMCdy8dWvm6
         J3JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743021573; x=1743626373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6Kn5a4ioPIFf4SfX8qiMFKlIDypab9VbBgLHJuaA4UI=;
        b=bYhigzjpI+F9Pug8UzDVHtx4llTSw3eEgDaRFyWQ9uZlzQQe8P9YJeu1HqUmSLXZ8M
         nNuIu6B6pNGroUr/S0eIlpDDhQeAQ/Cb5TDSkx9GpEfdTfqOmSNVOks0FPQw7Pe70pPz
         nJ81zdDpt1JEpVo9A+XD1LTEWRY7y/zMUSptLi4Bh3+xKROTfvdf5mZ8LcHWRYLi64OX
         UpbBJqceK66NGMBEK+oaJ60tOJv4e/mlV1GlKN4M9aobFlxwYaC/P2ZhUDhvxawIaeIg
         K5q96Fc/9Vjag74KIlL62We+yciPFokJof0qV5Nc8dTt24zrE+K17xdIrcRGmUZdH/QM
         qJmQ==
X-Forwarded-Encrypted: i=2; AJvYcCX3Oo5KjMEqTbl+NF7RZLgsWMb17TnDhQZ/i32L2yNhE6s6gX8YFuXeDER64oSchO9ZPDTxwA==@lfdr.de
X-Gm-Message-State: AOJu0Yygi8rDV8tVd2QUoHhdaUCbi6fKRx40sK7Y8GpKaHe2zrBpzzeM
	CK4kTBqZosDlFyt7FQjOEC2xHNCru8F3aoSjRLil9p6W6W5U2JON
X-Google-Smtp-Source: AGHT+IHnvM/dpYUU+LFQfoyr1wRX/7M74hRQWONCl1xKrmPpltCatp4O07uVHERyDG+6Y2V9Vegc9g==
X-Received: by 2002:a05:6902:1b8e:b0:e63:c936:c091 with SMTP id 3f1490d57ef6-e69435094damr1647844276.8.1743021572590;
        Wed, 26 Mar 2025 13:39:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL7VBTnqpuIfN460UuzW53A5N2oSOSDAQRpijYrIaJJNQ==
Received: by 2002:a25:5f4f:0:b0:e63:4a11:a984 with SMTP id 3f1490d57ef6-e6942b9c2b2ls446887276.0.-pod-prod-02-us;
 Wed, 26 Mar 2025 13:39:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXA5CVTqtteVAZP2ttfbJCjRoTZxZQNKDpIFtpHGDnZIB6Tyw9I59M0fHisdi58LMYOWaROTylmLOg=@googlegroups.com
X-Received: by 2002:a05:6902:2013:b0:e61:1b41:176e with SMTP id 3f1490d57ef6-e69437ab712mr1654821276.47.1743021571501;
        Wed, 26 Mar 2025 13:39:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743021571; cv=none;
        d=google.com; s=arc-20240605;
        b=WTOYxC0cQBeRuc31IY6bFG6kzF8Xyc252DDWcfzjNxcVFWES+uyhgokoc8aURwtLw2
         xFe2t+X0PTjc0TcMs05W88Cjf3JQXM+msqJEqamBI+zSYh2O52NHTmNVWiIFgDMJ7egn
         GwQH8hdAa1R+8z6lTJili6REx7phZw5kg+sQxdUpoq6idUop1w/6nMt6CG9YlkkkcxdV
         8DOlwMBxjf1gJFk4kmEeb8SU263Rlv5tGJFmyvWLBz29h6FURXfPdSwwYnipwXXcTC3e
         5hk33rbbw4lctcLLfEXpyrTSsLGZwhBF5G03l+3W0XEegEyEsxMhnaji74kgcKhevd/r
         ZikA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=H+DeIDFhS0i6Lg64nvKnCHRvSxX5c1/ISIJHhrk1VJY=;
        fh=kR80lbw9vkIpg0+5HvxLiDHAcJl6vbTFpLjq7zLbOiM=;
        b=FbW2QJpopoTAjUqGd7V3/i2y4nS7gSRx/CMKx+v4fA+n8pBTG4Tvcf32in5EEBbwxw
         lI2DCQL/+mvfkwaWnLoCIcVC3439WuFF2VAYjYcm+eMZfGKNi7Hmx+Ci+726KLh4B7vI
         8luHWuZgB5quZHKfq0NA5bOPpMIH1xLlIDDFZ89gjclYxNauLm3pWvVqMKxKrV0VSNeA
         dr/FWignBDzbq9bdqXK/pUBIF3M+IUBt+JU6HXl13LK4vpxvmD9myOQMPCEbA5L9o8DW
         xCgUblVVQ5Tr5+4fh9olUBrGtGWaIJQFa5VY1+/wYPcsnV6NQ9Lj/JmEnXsivVPhunwe
         OcWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WhKJK7Mh;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e66a53fc166si515699276.4.2025.03.26.13.39.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Mar 2025 13:39:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 02CB35C5809;
	Wed, 26 Mar 2025 20:37:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3441EC4CEE2;
	Wed, 26 Mar 2025 20:39:29 +0000 (UTC)
Date: Wed, 26 Mar 2025 13:39:26 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jann Horn <jannh@google.com>, Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
Message-ID: <20250326203926.GA10484@ax162>
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WhKJK7Mh;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Hi Jann,

On Tue, Mar 25, 2025 at 05:01:34PM +0100, Jann Horn wrote:
> Also, since this read can be racy by design, we should technically do
> READ_ONCE(), so add that.
> 
> Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrastructure")
> Signed-off-by: Jann Horn <jannh@google.com>
...
> diff --git a/include/asm-generic/rwonce.h b/include/asm-generic/rwonce.h
> index 8d0a6280e982..e9f2b84d2338 100644
> --- a/include/asm-generic/rwonce.h
> +++ b/include/asm-generic/rwonce.h
> @@ -79,11 +79,14 @@ unsigned long __read_once_word_nocheck(const void *addr)
>  	(typeof(x))__read_once_word_nocheck(&(x));			\
>  })
>  
> -static __no_kasan_or_inline
> +static __no_sanitize_or_inline
>  unsigned long read_word_at_a_time(const void *addr)
>  {
> +	/* open-coded instrument_read(addr, 1) */
>  	kasan_check_read(addr, 1);
> -	return *(unsigned long *)addr;
> +	kcsan_check_read(addr, 1);
> +
> +	return READ_ONCE(*(unsigned long *)addr);

I bisected a boot hang that I see on arm64 with LTO enabled to this
change as commit ece69af2ede1 ("rwonce: handle KCSAN like KASAN in
read_word_at_a_time()") in -next. With LTO, READ_ONCE() gets upgraded to
ldar / ldapr, which requires an aligned address to access, but
read_word_at_a_time() can be called with an unaligned address. I
confirmed this should be the root cause by removing the READ_ONCE()
added above or removing the selects of DCACHE_WORD_ACCESS and
HAVE_EFFICIENT_UNALIGNED_ACCESS in arch/arm64/Kconfig, which avoids
the crash.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250326203926.GA10484%40ax162.
