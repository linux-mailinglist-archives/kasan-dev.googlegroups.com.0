Return-Path: <kasan-dev+bncBDAZZCVNSYPBBAW34SAAMGQEMJS3XJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id BB00C30BC4C
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 11:46:27 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id a48sf6392248uad.16
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 02:46:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612262786; cv=pass;
        d=google.com; s=arc-20160816;
        b=UvA+qYR5ptDulZQObvfnIfctm5OyItgXqSnizJUa6s1vj12/OF3HPUKkhgNgQTrI9e
         1L2TW4WfqyMiRvbqvasqPWcE5ZWJv64qUCpm+/Gg5kb0ahfnII10ImwKJ35SWvi8b/4R
         bnNeH6qfqzTa1YFQpr0RXMWix/voOkGcG2OH4vqxvle0+UOFHPQQVaXQ3Q3uphJqXazv
         BhRafHzXvRkv4T/eSNW1dywgCvm/9KybhnsTPyp0zhfus0xC8oy6QK2xN+Zq2SaylZYE
         Prp/kZcSDRyjCq/tbtF7W7NBrFuFd5PaTj4Uh+CGL2ArEsGuNJXTxhLXDJGZi4/naQjO
         9Xnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OFXcewLI4qMn0nzopseiwPqzkjm4fHLnaIyd5L0wRz8=;
        b=LZGERgNE/WccdWjzLbzkyC2B2hO5J9XAMm13LLJQRx54RzEOG+JBxtZ6JK/MJJhXS+
         TleufdpzfWDBtvHhG5bJltdPJ4kBPP3JTpDYCcDtGUs0PT/GvaAAs/N7qZExxPIrOSG+
         I8Uk+VSSU5n0aPMsZ/1JzJYA8pPOob2N/NwfjVVuavyeK9xKUffW8N3uh8UwkGHZ6l7s
         x/sdggteFWfrCHfbZp0uLMLbgdE7oO0DcjYZc01x3+kmTBc5tMLum+7ciKPsL77dcYS7
         c/ITaFIkIOQZD0Oo63Y3gcS5G5+oB0rogTi8ELc5Kqann8zB72TzlxwEF70/wtcFUDXe
         yLKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=maVk3g8j;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OFXcewLI4qMn0nzopseiwPqzkjm4fHLnaIyd5L0wRz8=;
        b=K8IDtv2C5k9KS3q/vazwTSUUwmq3ocZK4t2Wu6PaQb2DXGAHeMioctDSPwWkiMhH+j
         1eu5QNO4jLMsflRqoa/ehB861sa5H/osoAwsAufsvpr50hMoy2miQcO0KRL/3mpZNoZo
         JJ/kn+HyCDGfVgryzjt+rtWv9g1M+RAC5nHmC6X2wPCMrxHFoVGcT8ID4373/U2ePVzx
         TGdku9T8dLsTj93aUfOje9lIDU00AEp8YC7M8SV8njq0AeEQrXWU7KECm6P83ubWd2TL
         44dCOB1zEpViupBB81Z5XjBKBWW6tL9J8s8DwVJHlw2y2YTCnfluRAq2raF3xu0NgdA+
         9xeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OFXcewLI4qMn0nzopseiwPqzkjm4fHLnaIyd5L0wRz8=;
        b=EpT3omLWq7H0e8rG6Qct8wNB/pc2eHZX6ADoGJpTweq5C8OHnHoZgilRxXmFxoJ+r1
         X+qkr3PyX4hfG/5bwX5+VX1fCVJNrVLi4PxOqB/XWO5mFDNm0hlwClhCrtgUJY4xuqGI
         whX1iXuK6DY+klq5KdCWUGS5Hm5IkkygN6ouuvPyltEJn+2ijmxW1Sf9T7r/ikEp7m4P
         QZrTEXnVyNxrgG2yp0mcpUYX+VB3NW/0jQWIoPcMJ/S7S95+5uoPFG69cACgwWAkE4eY
         ovVHQwQrB+dYEgymnZiRUIyPnApqz6H7rj3b/ya8bzRvwGdNMVFEWR+h/hXQy9otM1de
         ggMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UMM1rAOz8vkv9TjLg2T/OP1M5IBMNMCOczWVDk4xjFfIP8pnJ
	CsnMarT070usWu0K7Sa1umE=
X-Google-Smtp-Source: ABdhPJwzM7iGf00UkxXPVgQme73qmaVErjGzbe4kG6OaoUypAWH8CBQ/r9CCvlY8ficjs9zc/Tw83A==
X-Received: by 2002:a05:6102:22d2:: with SMTP id a18mr11266411vsh.15.1612262786443;
        Tue, 02 Feb 2021 02:46:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls2328690vsm.3.gmail; Tue, 02 Feb
 2021 02:46:26 -0800 (PST)
X-Received: by 2002:a67:2f0b:: with SMTP id v11mr567292vsv.39.1612262786036;
        Tue, 02 Feb 2021 02:46:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612262786; cv=none;
        d=google.com; s=arc-20160816;
        b=xZVnB3D4eiNeApXPO9Us2fRRsBXg9Q2LPKyZglSRtn7ot4CeRheQeH4Xer7AkvwgQ8
         UuYtfl4Yagslda6zWCtDxrnU3saRYz5fwO4FxwuC4Z5UGwfdgjTiSxUaLJiG6SqLDiSA
         qvYs5trxMIS4tBYINNYW713OJQFstcvnVwNA07qnCWS75HuyvoFlPvLLWLmkK19nO9Y1
         xmIj37JwU7rvcCPpg63XhFLayGequq4FdXE3W6kqOAGrn/EZSIkFLt6tkWyokFdbym5q
         iSjO9P66lBfVEexheka3SvtTWd5Qlde9bU1YcPjiJPx4/WgX/qA7kpK5Gq79xiWFjKx6
         ciWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hcNtPkix8xJ5zI1E7VEA9UJ9pxI6zuF5nSuIkhqp710=;
        b=FSfsDHWysp9VZTuWFR5rK085ODfPqlG7vkD6n6FItglM3kX48gOr8ROnoN4KW+3RXQ
         +Ykf2Eo8jMPcRZg7zrtMQ/pX/VVVI3TCtzvMXQQjKIQbFFqrD+8gQ9SvZxdPkKCnzaLV
         l/Pvb1aVwb3DHChE7bpfLoP4gX6Z4YBxa2jeIaj8Jge4awQY5RRfOJA9ZxcDuJt+pprh
         tcPIFEYATHyOSVzVUAzQXpBO9NlA3ATMx5nft68xxgjcRlfcCJYc569G1gOaN197ms67
         XhQL55ZZ0bzO6ibRv3laUtRhJG0A5qN3fx7JNEZs9tBHO0uW16aCpv5g4mLHi3jcjJ4J
         yn3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=maVk3g8j;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p73si959160vkp.3.2021.02.02.02.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Feb 2021 02:46:25 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 086A764D9C;
	Tue,  2 Feb 2021 10:46:21 +0000 (UTC)
Date: Tue, 2 Feb 2021 10:46:18 +0000
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>
Subject: Re: [PATCH 12/12] arm64: kasan: export MTE symbols for KASAN tests
Message-ID: <20210202104618.GA16723@willie-the-truck>
References: <cover.1612208222.git.andreyknvl@google.com>
 <d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=maVk3g8j;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Feb 01, 2021 at 08:43:36PM +0100, Andrey Konovalov wrote:
> Export mte_enable_kernel() and mte_set_report_once() to fix:
> 
> ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
> ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/kernel/mte.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 8b27b70e1aac..2c91bd288ea4 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -120,6 +120,7 @@ void mte_enable_kernel_sync(void)
>  {
>  	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
>  }
> +EXPORT_SYMBOL(mte_enable_kernel_sync);
>  
>  void mte_enable_kernel_async(void)
>  {
> @@ -130,6 +131,7 @@ void mte_set_report_once(bool state)
>  {
>  	WRITE_ONCE(report_fault_once, state);
>  }
> +EXPORT_SYMBOL(mte_set_report_once);

EXPORT_SYMBOL_GPL ?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210202104618.GA16723%40willie-the-truck.
