Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEXE677QKGQERZFIZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A21752F3954
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 20:01:39 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id l18sf4641333iok.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 11:01:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610478098; cv=pass;
        d=google.com; s=arc-20160816;
        b=BVWhTOB6SHy03x/P+u2JOyAzkiUsjAuowrs/NRrqcXWvINNpfrzFFg+gGqnbt6awbI
         WKoz66mU6c3kUMpi2FY1IyUxt7bHmaC/8FMy5jzTXg6VcGFTLLJ5kq7UcmbYnAuKUUYs
         4qU24kbZZgFzUDqJW9cqnz4vam4LV0YkDj0MGOqQ6fIjOm3XyvaNTlsThDKNgKbuH1UN
         TG5kuqeWpostXHh+mfBwH0+MLIY8YmmZjak+NRvwjCX0oEnELU3szMId3tibrvkfuZYO
         ildx4IFoNmEdb35a6S/1IRLBQ1SgIHym9W5wuCyrsdsYwPP8Z6dqrN6+ZSvX/Ug5U+9w
         tjCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=e2lZ272/E1aAA1dRlB3FBHI7lJ8Ab4HNvysyzmxFX0Y=;
        b=gFIN31pEiVq/K3k6FeJSvnpxTuVTH4Og5JxW3EUhZnGyVPEPmBps5KNDhlPHFaax/H
         +ob7Xt0p8fL/cMpw82EsR/7Z1OfmMa1Qb1hSplCy8HybVgjRmseyJy6URmGn/R1u2cCc
         Oc7E4JpXSR1uK5mEIFm3RncHb2amwopA4Z+lIGY7NSq6SSoNUHPeUJ5iEf0/H7lYX7i9
         DHiWaCm5PmLKosLU4UHfUib5OOk9XT/tojorQC0JdzqTGoNpI2B71ER+hyG5KoIkjaU/
         90f6XHqrsqNlCsLM/frcfWgaMKHoQR33DiKZpGL5gz74ttn1T4++XSyR+v/11VkZB0Bh
         CNTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e2lZ272/E1aAA1dRlB3FBHI7lJ8Ab4HNvysyzmxFX0Y=;
        b=HCEL79oZEQsswkn4uQs102dn7WLtx4IFZ9ITccmETRCK73hVDGs/mnMb8SZt+8p0Bz
         +evVkfok4178nBjakI6lC4Xf/cDvJ9gJMOQQkQkQBJE/oPGvveBtvL/kN4VAuzsXHk5N
         co5Ypcm+xWHNjbwQ9vPwpq577ORcmjKvIUUBJ267SV+r2Kl2XD+Bj4Bo8g5CAqqp7YKE
         feEu4S79a0qXZPnVhBGzhiFBejwnCLa3Z7eRFbrZT8p26eM6CKVxJOnJiYlN3P/bfuLq
         B99Q9DDJjSt14w2u2/sRJUrqyvz68AWXzu7vRGuh7yNP8nF5EtatYxDUgVUAslT/0epx
         u5BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e2lZ272/E1aAA1dRlB3FBHI7lJ8Ab4HNvysyzmxFX0Y=;
        b=UQDJ8YhHscHM5+nxSyXj63d/7LrnMB/pu2CcyorPoTm7JGQDnhHVqv1ggPO9Lx6wpI
         Y6RZ7DfUlOhT6yk4XwMr+xXFbMa5h4Qx6dhD7be7BPX6rqjXJOAuxRI7hFKQFMs4X1/e
         YBcASi940rlfCc/wBHEIT8jxuH0rOKMgpFlB8z9bpcRZEncKozHy/5fSB+0A9vi7hPco
         e5a/tdum4nqcEaPeWSzGlGlaI9nmXnLkespvIi7WhZbMAlrB5b+ZQ1dqfjgsK7VJGeti
         i7svPld5nKV41jSWe2t6nO5+QZmgL7/mPnWd9M2URw613P9SH6YeGzTIYs1TNvw9LOXd
         YeOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338YaNxuz2yzEaQxyGy9qjCNlEEWAWwbjJlZF5I9aTghJ7islkZ
	OYL7wC7pLSqk/nsXMjUbI0Y=
X-Google-Smtp-Source: ABdhPJydH5xiHoadvHKYPtJPO2hQgEIm/zVhp/CQqxZ3giMepf8mTasHaTjV3y7X8+FE1Cf6OFj0oA==
X-Received: by 2002:a02:6a50:: with SMTP id m16mr752809jaf.129.1610478098663;
        Tue, 12 Jan 2021 11:01:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:8719:: with SMTP id y25ls763692ioj.2.gmail; Tue, 12 Jan
 2021 11:01:38 -0800 (PST)
X-Received: by 2002:a6b:3115:: with SMTP id j21mr303866ioa.55.1610478098217;
        Tue, 12 Jan 2021 11:01:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610478098; cv=none;
        d=google.com; s=arc-20160816;
        b=M7qZK9o4TCImhvDtX6awWyN9hVL/3VWYI+O2aoJjmBva43qrEbn/auDNe8lo3nUsh8
         avIbLomWae+KC3ODgtF6yX0VUfbzOE/gL6bAJ3oQ6+p6CtVkFmFFU6IHEoO6MawtBw8s
         U+qS+t8EjbFMwmw8fhZZgOfnO3SFQ/j+BoYi3Ig8uUOsj4jStNiZkFdj5hbV7LNkCGdO
         yRsEunVcdNQD9T+bh/+sCJ3Iy3oYomhuBQj6HMOdefbVIg0TNZqWQG3DzinUCbUOp509
         MCiDM9cYCKcXBa5qn7SOL0MXWcqmHX/0kUpihVtRhH8eG98lTpJ3Q1T7f9q/ixXm2R9j
         RNmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=SP+NUTFvp17i9S5C1CDMr1WvuTdzVkFZgv+dfka9Sqk=;
        b=C6m4orYewfbz8tcM7JbTsk9SpOx9UX9QkYDyrhkSaOA3zsOPkXoxwUv8m8z6wG18gT
         ITlmmWWOlt52TpY3eE4EDA50wi8UaMzqzCMGGU3QqCJKfSpF1NcJUsRvopcITWg7QrDn
         fPbwvz47WbfaS5q6tX4TOC29aqSlN2qvj2AWdwROITHWChANOMfQTaUYTNTezZoZbjuq
         WcOK3EYbZ8y8jO1TwdN/yPzQoyGrB59Rmm/u0TU4YSoPJvhroCF+3a0zs/sRVOZDR+X0
         HyAahVMgtO8tpfaff2ppbL9WGfsa6FZQm/iwxGaRuaVRb7RnbPuo2ingVp7njzDe5+fA
         ittA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t69si426018ill.3.2021.01.12.11.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jan 2021 11:01:38 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B3467230F9;
	Tue, 12 Jan 2021 19:01:34 +0000 (UTC)
Date: Tue, 12 Jan 2021 19:01:32 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 05/11] kasan, arm64: allow using KUnit tests with HW_TAGS
 mode
Message-ID: <X/3yDGfTJ+ng+GJt@Catalins-MacBook-Air.local>
References: <cover.1609871239.git.andreyknvl@google.com>
 <dd061dfca76dbf86af13393edacd37e0c75b6f4a.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dd061dfca76dbf86af13393edacd37e0c75b6f4a.1609871239.git.andreyknvl@google.com>
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

On Tue, Jan 05, 2021 at 07:27:49PM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 3c40da479899..57d3f165d907 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -302,12 +302,20 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
>  static void report_tag_fault(unsigned long addr, unsigned int esr,
>  			     struct pt_regs *regs)
>  {
> -	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> +	static bool reported;
> +	bool is_write;
> +
> +	if (READ_ONCE(reported))
> +		return;
> +
> +	if (mte_report_once())
> +		WRITE_ONCE(reported, true);

I guess the assumption here is that you don't get any report before the
tests start and temporarily set report_once to false. It's probably
fine, if we get a tag check failure we'd notice in the logs anyway.

>  	/*
>  	 * SAS bits aren't set for all faults reported in EL1, so we can't
>  	 * find out access size.
>  	 */
> +	is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;

I now noticed, you could write this in a shorter way:

	is_write = !!(esr & ESR_ELx_WNR);

>  	kasan_report(addr, 0, is_write, regs->pc);
>  }

The patch looks fine to me.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/3yDGfTJ%2Bng%2BGJt%40Catalins-MacBook-Air.local.
