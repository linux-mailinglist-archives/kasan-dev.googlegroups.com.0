Return-Path: <kasan-dev+bncBAABBQOC5PYQKGQEIM6KGHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 04CB8153402
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 16:37:39 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id m18sf1803615ill.7
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 07:37:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580917057; cv=pass;
        d=google.com; s=arc-20160816;
        b=e4ACGt49Ypp9Gw+bqNbhNMKPjHN7YqNUx53TSHWu6Dm2NXH+JpI6pGLrepg/KTdbGz
         sdlWdbSE0qnEQmFttp2nTfBH6HF5/4yMugIN6zmx8w78gMClPcacbePu87BR5c5eKa95
         7f6Su6jlvbB8UEOlbO+TwRwJ42khZ2A8/BJvnZs37NfqjRS/xXzdg4kdNJqGeKmpaM0H
         zFKuatdB9w24IeO/kNpZfqYO7HiRlgh6Q2G9kHIxXRtzezuZCuMzfEkPx+zOIaNGZulu
         yWHvxqOx2AODDWT2TDKS5l0iBjoIorzUVXysJFYNF31V4u7Fft3SRgww88daEA3BuahI
         08xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=gdSyK02AUnvwjqgMSqJFn67AKBXnpNw2qBpsOGjKboI=;
        b=tTfI29z3HcHBLhrFP7nJ46TzEV99nhwXrioRDKcN3JIDNQaenO62OBqL5vdTvpkmLj
         eJQYG2TF0O9SiXs3D3mUqJ8X0CBYr0WtYAjjUkfswDMGNHBNbpWvaxsbqBFk3ETijxon
         Xc3E35ZRX9wKnm+1cm5mqM6sFV1qCnapKW+SeTWTBlQChTR8/SVZBSRop2aJbNWdEEyH
         sgPprhlzr4IW5lv+eX7nVJ6ssuSlpBRw+TBmqCxgdSROB8RJTmZUxqQcZS+8V9N8jOji
         Jt8on+ALP5/OtrHGwoq8AdcuRfniFp+ajUBHfoqSqlyORPkSvNL1nhgdYmqTIe9y0iz5
         QJ1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=dy5Bfasr;
       spf=pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gdSyK02AUnvwjqgMSqJFn67AKBXnpNw2qBpsOGjKboI=;
        b=GObnXK/SIqrwHJaR4/OvZGQ6e+Nn+P/4zEbEjUBsw6RagWsoNgVf4HUNiO+7mLlVX6
         XlZtXlLErlGnPKm1KQ2yy8p7CHBTlUaffiZdwL8rwkjwiQjysAyxTK8I1Gz+ucBZZTOh
         HWpyboCVY+Uh0DfuDLA6wqIbPffxcf16CEjO3821z8qpdgn9qoRVSM7FF8aACPozBA1E
         zslJRnH6usxJZaEzoR70nV1DrvJITI2J15DmW1FefPF731Ypah/n/NZIJEJD7GBotcpm
         IkGh0UJcPBgjM/sQiM2TxnJEXimqM7VtwIhPtcWU6bYH0JIerL1AoOivgvD+aCPgvf5B
         gMQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gdSyK02AUnvwjqgMSqJFn67AKBXnpNw2qBpsOGjKboI=;
        b=lTt21tZDeTgp1U+veGMIQMkOycgLp9RJqba7bwXKKCPNrOQISACGWzpIlKiPeHoRfg
         Tp/MV4NtOzen4PC/S6vSTmNzkcAb0r9CydKPCEIPyqBofbu6Jl8GPoWFFPYNHnX63Ywh
         ZA/s4z+SZlFgTjOgAuli7Gyh3hHZMgIcnHyOt6jemHRIxN/jXc1sZjgdh33djHmEh9TX
         vikvzf0vPV691xH80fcBkAh/Cv5aHmRSKABsL01Yr94RZPEBwEyVGpZveslPhFSHDUr1
         KMGgTSZVzl0NY6/7WSdnLOEJiW0Xi4Oa0oAbjB2LM9w+mRJFskdBCY2tXQTI5zDG20tu
         kfCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUCB0QDgF2ef2+vp8+09BYejFqAtzpUNuH2pStGX4NFK0vi/vvV
	DVwgJlUopksZ1etQYPlYw1g=
X-Google-Smtp-Source: APXvYqx7/mvIdljkpRaujYx9H4+iz4VTgjmuQvjSnEhI2JzrSdKAOF1csHUuJmSU5IV1AR3s+xj+Ww==
X-Received: by 2002:a6b:760f:: with SMTP id g15mr27966413iom.56.1580917057533;
        Wed, 05 Feb 2020 07:37:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:5110:: with SMTP id f16ls524151iob.2.gmail; Wed, 05 Feb
 2020 07:37:37 -0800 (PST)
X-Received: by 2002:a6b:bb45:: with SMTP id l66mr29149413iof.73.1580917057144;
        Wed, 05 Feb 2020 07:37:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580917057; cv=none;
        d=google.com; s=arc-20160816;
        b=wZyh0xj9owWaKNDXEUIWlcw+LlKQSi8045cm3WZZM02+wHtxT6kAFd6kfF6d2c3IIL
         FJTTZiJMKbSgV2ykF+KQBnztveO28f7WGbswVOTGBCxBrC99Dwu14JJ3ikWCAlj+nJ/O
         rpYh34kjlMR4Swun3YSNvCQyQYMQ/r7DEB6pSlF1B6b0OZxTZUOGhoYKmpeGwwhwmqBU
         vLbxMWQkmhOxsN5rf644c9XBotqQQ8ax6r2ykSbP7u8bwpvTU62O2NzShKjVSffaX+LG
         QNqVHLEewA2+MZLVog3ATSBPL1TY6zkvNBJuxEbe1zoXdNixKbr18WD4rq2QCachCJBy
         DN0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=eFRNuuTsMmhE9sra5dwvYU3KWqvN22oz2bku6/S0n18=;
        b=LHT8BuWje2ESq9ae90oBd1bnEg4FH4iT+HPu+It9yzSbSU3DJFJ3EaJGRJTCUjXrqO
         IcCYBLOSOXmRJYvCCBDtIES4Aq7/Qx/CI7YqEmGCO8ldDlLTNgisKg8OInrUyofbAZuT
         lILWPUmIrcSz6nSOa7Gc7TrqlWj8cbHtW08oBLJovkzcd3V0u9J5KU8yoqBMcf3IqXX/
         ABXxxeiCetGO//i9t8uhZoN8By5M+f2PJ27ARmKsZrZUuDXYbSG73iIZmyIau6dnV0Qe
         4StFucsaAmfPCO7zPJG/E3OAk41+N6JrgcTzU0BTamskdOEoZyLplXHc6kY2Rx+tRQbf
         aSBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=dy5Bfasr;
       spf=pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f85si5868ilg.2.2020.02.05.07.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Feb 2020 07:37:37 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 31B8320730;
	Wed,  5 Feb 2020 15:37:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id F093A35227F6; Wed,  5 Feb 2020 07:37:35 -0800 (PST)
Date: Wed, 5 Feb 2020 07:37:35 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Fix 0-sized checks
Message-ID: <20200205153735.GY2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200205101419.149903-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200205101419.149903-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=dy5Bfasr;       spf=pass
 (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Feb 05, 2020 at 11:14:19AM +0100, Marco Elver wrote:
> Instrumentation of arbitrary memory-copy functions, such as user-copies,
> may be called with size of 0, which could lead to false positives.
> 
> To avoid this, add a comparison in check_access() for size==0, which
> will be optimized out for constant sized instrumentation
> (__tsan_{read,write}N), and therefore not affect the common-case
> fast-path.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued, thank you!

							Thanx, Paul

> ---
>  kernel/kcsan/core.c |  7 +++++++
>  kernel/kcsan/test.c | 10 ++++++++++
>  2 files changed, 17 insertions(+)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index e3c7d8f34f2ff..82c2bef827d42 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -455,6 +455,13 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
>  	atomic_long_t *watchpoint;
>  	long encoded_watchpoint;
>  
> +	/*
> +	 * Do nothing for 0 sized check; this comparison will be optimized out
> +	 * for constant sized instrumentation (__tsan_{read,write}N).
> +	 */
> +	if (unlikely(size == 0))
> +		return;
> +
>  	/*
>  	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
>  	 * user_access_save, as the address that ptr points to is only used to
> diff --git a/kernel/kcsan/test.c b/kernel/kcsan/test.c
> index cc6000239dc01..d26a052d33838 100644
> --- a/kernel/kcsan/test.c
> +++ b/kernel/kcsan/test.c
> @@ -92,6 +92,16 @@ static bool test_matching_access(void)
>  		return false;
>  	if (WARN_ON(matching_access(9, 1, 10, 1)))
>  		return false;
> +
> +	/*
> +	 * An access of size 0 could match another access, as demonstrated here.
> +	 * Rather than add more comparisons to 'matching_access()', which would
> +	 * end up in the fast-path for *all* checks, check_access() simply
> +	 * returns for all accesses of size 0.
> +	 */
> +	if (WARN_ON(!matching_access(8, 8, 12, 0)))
> +		return false;
> +
>  	return true;
>  }
>  
> -- 
> 2.25.0.341.g760bfbb309-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205153735.GY2935%40paulmck-ThinkPad-P72.
