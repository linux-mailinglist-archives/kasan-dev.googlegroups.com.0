Return-Path: <kasan-dev+bncBDV37XP3XYDRBPXCVWKAMGQE7F5DIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B6AE530E92
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 13:34:23 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id w25-20020a05651234d900b0044023ac3f64sf7594636lfr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 04:34:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653305663; cv=pass;
        d=google.com; s=arc-20160816;
        b=cbLGY0AXRJoHUg91pGTNOvhTWo+rAkRuY5+v7YJSbAu9ln/6lEVhkXt4yyhD5SzwZT
         Dxp+8b8YQg3G8YQcPANQ7cIvve9xyLE1zsk67nHAEuQF+dN6Y9T0Yxy5SIhWLXvBv0Dx
         +8u3XlDRtdG22/JGMc52tNiG1tJNNuW7QV1YVLht8GeR84EN9vfds7pceyzNXb2dZhP5
         aPNa8u2/w7U1z1fV6gZ//u81Go1lyGwXlTrus9B9wjfC8XAKWn8ShlbnccapMSi/wEj/
         d4bfjOG8VorjrxTnMdKiI4HQX2UqenAZu8s5PuylRtoWyNzG6EO6zI33D/YIFEwydYWz
         +tzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZRDTMPvmAJruU/r361iCCQYJpmHQ4g4UKx0buhwxjcA=;
        b=PEYL0B8BWf/wRgL3fgpVVYH1bYxUbM2hIukxYZflHhVLuChoQ/i/WQwgeS6hT84rXH
         APaeEidE6VXz66tDsa8CntmX7z035GN4Oa7mSpQH9EdXiJKIR82Z/CWBZav61xaG4sYN
         pa0DE3/DCbZ6KohbHuUSH0gjSQ7blkJFy/KRJwuhtCB3toMTKnSuDuonwclHyHCqvvv3
         zLiZtdqJ3B9rYsTuT1HaQa8dCo7TsNOoTCxpY4DKoAjfhP8WNWQqhkxyfeCGD4iomxMY
         c7d+cgczEv43pGjhz37k4kSFcaoiix52nfpwNnfvblQNZ4Z4qjBMk+5g4Vb/5yat4A5X
         t2lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZRDTMPvmAJruU/r361iCCQYJpmHQ4g4UKx0buhwxjcA=;
        b=b6dneCYHAXaR2NYo5ATlFdlVkeUkrfXf4HJswCUM75AfsX6wY/h9M3uH6cq/CMu+ng
         /OLnbshxL4mWjcox2FwzWxq2K3obEUN6WrcsP4DZBEsVPO9YDjrCWqBi5QEcdfm1k6NI
         1vUKP0DGwORbmT9eN5iEkP6S9Kfmrlweoo70D++CCniWiKiAKjdDVetP1dbSRcueeEcj
         jLilPEvF9MMzXZpwhKtxgMUONp8LSlb1heJF30wB68OF89Hwr9CVE2IiNLbjf5INiGjR
         3rIB65r0WxWuOZ0QvSVhsC8qTe1bhqfHbkOljs3ZOw9NT3AsEDnsEMbSOkFeT68/EX72
         ImzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZRDTMPvmAJruU/r361iCCQYJpmHQ4g4UKx0buhwxjcA=;
        b=fCweFN7TigQe74lGmFp2y2SjWW694wh5To9oULrkiMCK5TuQB6DOffsPdbD1dFlN0s
         GNhnPLYgfoiBXWYzFKRJlPNcsh8ZX7HXU/xcdamCoPUteQnbShlDsckvNAECk8sMADSy
         hqenoRuc6U/ActcHgqu6Dl4tt9Hxxg4FWPAMeosl0a9j67g2SfRAFgMoDNK+0mtLUZv1
         a3dLEC7NcT4M6hlpsT0fEqBlW2+VXVGmJIFUUYJloP2M/SDM26c9NIoUcBWKskM+bNDS
         n6ARB4zOfCeF5BlhKdcDuY0Ac4k9zs663z0pWTZx/1QFoQmcekjHurPPgLsY/qRcwwB9
         luVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XFQUpepBMNPnqSPsh+CFblk5lWZZ9f9dmmMc8Eikzod9wxZ6H
	beyiRKtziYcE+wzRJcFlcwE=
X-Google-Smtp-Source: ABdhPJw111d1R2hyztwNXKBbe4333NwpmCi63djywxDhRcDjzy3KpjR+Dl+VD2lwDuSVkVXnkjB/Yw==
X-Received: by 2002:a2e:878d:0:b0:24f:2bf2:5a79 with SMTP id n13-20020a2e878d000000b0024f2bf25a79mr12959251lji.497.1653305662811;
        Mon, 23 May 2022 04:34:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10cb:b0:478:7256:822a with SMTP id
 k11-20020a05651210cb00b004787256822als787617lfg.3.gmail; Mon, 23 May 2022
 04:34:21 -0700 (PDT)
X-Received: by 2002:a05:6512:3eb:b0:478:75de:26c6 with SMTP id n11-20020a05651203eb00b0047875de26c6mr2311365lfq.163.1653305661450;
        Mon, 23 May 2022 04:34:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653305661; cv=none;
        d=google.com; s=arc-20160816;
        b=B6ab7rdV8458PnA6u3kLTAM5wkHW46rtwmyJmswWzCLhm5RlP3tBgSwKnnnQeJysQ9
         P5c52UTQHe1f3lMGCnwBAoPhpialpYCD+kuGvVkos1e7h/iaOWOd1PYmqDvhOa0WSOnn
         uf1S36lXanwLFjospMOZuV1ejwwooTp+bWZddsInUE43kMwuexFoxnNDsn+OPeKHU65d
         Uf4n6td0ZVuXWvfQpXpry6wYYidEi9YrhkmyEwewijzg9Vgsm6VUDOHgdcizHtaDZjhr
         qje18gK8FggznUmRFRrZUjs+M+0XXIwUssJPYs/klTmuEi1G/JmcDYOgFMxvB691PYWn
         QOmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=VDTsDtT+zEBcCyg/9LAsRqHP7aUfyXXVX+q1VHfTNxE=;
        b=Yyy2dlSKwzBlY2J/pLm9qPF8ga41Ypijr8r1PaS0F+PKp+xkR2rfvgPSojJR7AMiuG
         ZaS16+A1OreI43Y5CugdyxpG3H7JGRc0BoQQWQa4n8HDm76xfhUi6KrNFB/rfuvl0UD+
         XOPUcJ3dk59iulICPKnSKusNkrmDbfjQAs7HbnV5HHv7rCcDm4yGb6CMPrvy5fPi+684
         CVfyMmrcekg2+4H4s9GXWWkHZxhfQ8CK49YR8cOwLUylGSDTT4jx+8976x5uRXyUt7+a
         DbY5WVHS/V7FDdeZnNS0SwXdUOCznBNJB6UMUx/dD+eQqdBbodnEhy3bGsWeocbxN1Pn
         R8LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id cf28-20020a056512281c00b00478805f57b5si39445lfb.11.2022.05.23.04.34.21
        for <kasan-dev@googlegroups.com>;
        Mon, 23 May 2022 04:34:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 66AFA11FB;
	Mon, 23 May 2022 04:34:20 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.9.63])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 405B23F73D;
	Mon, 23 May 2022 04:34:18 -0700 (PDT)
Date: Mon, 23 May 2022 12:34:15 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 2/2] arm64: stacktrace: use non-atomic __set_bit
Message-ID: <YotxNzMfMdqw0uY2@FVFF77S0Q05N>
References: <697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl@google.com>
 <a584e95f613d59c7ff45686c2805deb63bd61442.1653177005.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a584e95f613d59c7ff45686c2805deb63bd61442.1653177005.git.andreyknvl@google.com>
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

On Sun, May 22, 2022 at 01:50:59AM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Use the non-atomic version of set_bit() in arch/arm64/kernel/stacktrace.c,
> as there is no concurrent accesses to frame->prev_type.
> 
> This speeds up stack trace collection and improves the boot time of
> Generic KASAN by 2-5%.
> 
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> ---
>  arch/arm64/kernel/stacktrace.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
> index 33e96ae4b15f..03593d451b0a 100644
> --- a/arch/arm64/kernel/stacktrace.c
> +++ b/arch/arm64/kernel/stacktrace.c
> @@ -103,7 +103,7 @@ static int notrace unwind_frame(struct task_struct *tsk,
>  		if (fp <= frame->prev_fp)
>  			return -EINVAL;
>  	} else {
> -		set_bit(frame->prev_type, frame->stacks_done);
> +		__set_bit(frame->prev_type, frame->stacks_done);
>  	}
>  
>  	/*
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YotxNzMfMdqw0uY2%40FVFF77S0Q05N.
