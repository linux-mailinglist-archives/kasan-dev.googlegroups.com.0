Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTNPTGBAMGQEK6VLERY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BF5523313EC
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:58:54 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id x197sf6799039pfc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:58:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615222733; cv=pass;
        d=google.com; s=arc-20160816;
        b=qL7CBazchbLOgSRrE9HbJ1l/8ewkfXO3K0mUCP+JxUwU1CNBcunTwAYQbwy1q3UDoU
         ncdijQ9/0OpK4XNavsGv7P2t4yBA/RRbh48kNf/u0hsvBFlU6QxAU1kvbNaQseqsF6Bv
         gSeZMjkLgqGYG68bDfC8P68nduTvjLJwi5XnHeJdmqZC3HvO3T8wqsqLG1i6Qskmb7hl
         OhNEikux3BE+SQxhxJJPp2E2IPuUgX4M1h55iWdtC7OS5cGKlGIwVk6gLco+ZlrRv3k8
         qGAH0vnZ5MCRl2bI0Qhz5pPZN4w54f2Fx3buSdALVVEfDUpcq43k2qMj4veM8HfGp7ww
         3Skg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lYnL2JDgk1C4K8QZN7Hn4AKeFjQrZEtrKEOoPqa6VtU=;
        b=JWhAoKX50PvY23MmD7IuI6SD8UJnSKR6Oi7zqafxZZoiXKnIH9ox/4xA9ZRWi51Wdy
         Z7ZQITXWrLLpczin4lj7e5aFo63bCg6OnoUCg1ydDnyqJzkeeWwIWKw0Bzx99n2vjzL0
         iyLxzIbtFc+9hj2Fi29daX9xf0n6u+JyzzZH3aKSonDq6hyIXJbQDH2G1KxkSC0cvEBw
         3EstWp1qxgYw7GkBM3877pkP7vwf5bP/thlJ5tL/Hyno8OYuZWiPb7B+EB7gLO5JibCH
         O59k6x1p/VYyqXOO86vwwKfLCiPX02dFqHKA0m8R2t1/tvtsL/dqGm7X+63aO2M3+jLx
         dGLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lYnL2JDgk1C4K8QZN7Hn4AKeFjQrZEtrKEOoPqa6VtU=;
        b=dS+dVu9VPPCk4hiZFPmVQDjEJYvDY0Ke09PWdfAywlLxUZDPXtwZWC2YDNEuF3Yu60
         t3pSWVieHIBt+7wFvjh2e//K0GH7YRHT/Cw5Q+Rnix1H1Jqje/Vlhiu0SE7svi8Y5in0
         pXJBGA2//8O0VKh1Q8slHibQ7PNtmZjiFZQNMiIr0X8c+dwj/KN8alL5EaLHhCR1YiUg
         YO/Wqwycmel6aSQI94grFsK9io+jsM++wCYovnERQw0ttEqYmvrWJ36UO9DTgPjuRUiU
         1kqDq4cZG4rla8W9bxmgZgtOOX1Y5dnaiTvjuXwsfAoU71IGBytmUlE3Dbfi32tZIRqc
         6VZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lYnL2JDgk1C4K8QZN7Hn4AKeFjQrZEtrKEOoPqa6VtU=;
        b=jt7BQPN27ob9d7JvLpv0ZIMyfbHWa7Hp/sFt/O1dnAlxjo1TkMBSIFhNDG4dBFwQva
         /UDZ92PZQeSI5aMIHw3zZu4JMgcSDYucIHGRNCAVj9Dy1uzMLw7/mGWJPjpwSlVDOF2A
         K6Z4lWNv7hFaU3xHCMqKnJI/iL79XUqkZRqbWYBdX/izJvNrwkfAMKxWE2Qhf9AzXsrm
         Yf7IzVi0Ep92f77ySE/p+SLZVsrf7TnFUFuWi0fhvddpoIwcvH/ZyYGTl6zdrYOkrIY+
         GQQJ2cWJaM1IsFwAYrfBNDkkSSxHULbTva+mLuvcV8jq7JqdtdieTRZJPL5qeHOiazBr
         IUvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rNJIGGRSgK6SfmMZyFk1UwRoJHAJIRohD3WwX5eMPmpA0/VXe
	TrfmRqnuWIRMiO1E6XFHNRU=
X-Google-Smtp-Source: ABdhPJzTLwoynHVo8FL+CbRaF/Naatk31wpTA4iDcL1AXZraBTap1D9yw0Ofxne9yOp85dcH56lf4Q==
X-Received: by 2002:aa7:875a:0:b029:1ed:aebe:e1e with SMTP id g26-20020aa7875a0000b02901edaebe0e1emr22464887pfo.50.1615222733530;
        Mon, 08 Mar 2021 08:58:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d43:: with SMTP id j3ls6971315pgt.1.gmail; Mon, 08 Mar
 2021 08:58:53 -0800 (PST)
X-Received: by 2002:a62:8811:0:b029:1ef:2105:3594 with SMTP id l17-20020a6288110000b02901ef21053594mr20922110pfd.70.1615222732990;
        Mon, 08 Mar 2021 08:58:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615222732; cv=none;
        d=google.com; s=arc-20160816;
        b=SZCIOEzGNtObfFh1q2pkpxoGIjQTBYVeDOszckfNJcTdDWy/LjEh2NYV4ebHpfgXcs
         vJw0SyQRacMNFtSG56PnaqOXNLVznlTDvJm8QZ7LQG3ZEwMOTLz83JMfifbQ4fORV2Tk
         lK3XNteSoeZYp6p4/8KwwXber/pRwlQN0cQeEkSqZJ3x6a98+p6z8BBGz0CIdCHSgCZi
         PEeqqhf2tNlrpNwj/orBvW/Gi034YqdlYwPcCz3eZVVmvfmjGQf8TDgwi3UTUTiZ2T1y
         dExjkTI2ZHNyDNxi2yPbft84TqFUZVtg956MJIdX65waj6/6OLkdNfUu1nZv8sFOUriV
         D5MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=8ToXTQru4Ld/NsGpTeWfUy1g1HoUNB3H/miVswj0yV8=;
        b=l+65z7bGuVeNscLQA4xlj6cSRziR6T8pUqDSKocaeQlnMN3O4GLFNywLYsxZv7wDNy
         db6+ZSdOC9jmsdaxCmwI/Gy9IV3kptBD8aLlt+Xr3d0y9582jerbzv5k4+5cdj/L/LkG
         sBgdyROOXw0k7+4WHLM5XId1w9n9GO0Q2kkgOKK8cHcWArQxNTNRFRcJxgZR2od48PxC
         +5DwByNeYHI8fgDII/cD3FQPDfrbCfTwp56aK8GYqeFkYEezXxoxmQsdjgf05VJv5Lmd
         gWPOCy7i1DfUuP5lm4xqYmH5XKb5TlHkt4AJPI1se1OuLdPQz4L/wxQBxY73Abr1Hp52
         gA7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x1si650114plm.5.2021.03.08.08.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Mar 2021 08:58:52 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E424E6522C;
	Mon,  8 Mar 2021 16:58:49 +0000 (UTC)
Date: Mon, 8 Mar 2021 16:58:47 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 1/5] arm64: kasan: allow to init memory when setting
 tags
Message-ID: <20210308165847.GF15644@arm.com>
References: <cover.1615218180.git.andreyknvl@google.com>
 <755161094eac5b0fc15273d609c78a459d4d07b9.1615218180.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <755161094eac5b0fc15273d609c78a459d4d07b9.1615218180.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Mar 08, 2021 at 04:55:14PM +0100, Andrey Konovalov wrote:
> @@ -68,10 +69,16 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  		 * 'asm volatile' is required to prevent the compiler to move
>  		 * the statement outside of the loop.
>  		 */
> -		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> -			     :
> -			     : "r" (curr)
> -			     : "memory");
> +		if (init)
> +			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
> +				     :
> +				     : "r" (curr)
> +				     : "memory");
> +		else
> +			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> +				     :
> +				     : "r" (curr)
> +				     : "memory");
>  
>  		curr += MTE_GRANULE_SIZE;
>  	} while (curr != end);

Is 'init' always a built-in constant here? If not, checking it once
outside the loop may be better (or check the code generation, maybe the
compiler is smart enough).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308165847.GF15644%40arm.com.
