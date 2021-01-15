Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUHGQWAAMGQEPXAGK4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BB502F7702
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 11:49:53 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id x64sf5613577yba.23
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 02:49:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610707792; cv=pass;
        d=google.com; s=arc-20160816;
        b=hOUv+kJtZjBJD8FLzqnz8YwkIJLUiUiLLQYUZUS18jebuPjRt4Wu/B0lgwSnpQfPFK
         paNKcBVFAEItnrE6R9u8l7nJq0ic6gwx7IvwWyW1jcJpL9YpjpsFNLeHWc26jv6qig95
         HWIUnhA58zl6ZxGiGpmZipZQ/VruHJcuKFr1ShdqM67hP9RHA7YpfYiStWunVXEneLrx
         7RJOA1y4tCy8zRaXGgZKetU+eAmeg4m0a+38BeDLVasJIPCdBa4j7WZ5zcZfXWBkrwyk
         uJELR06EeLf2xmmn880zWe81GfX5nXdkABk1X/uORrV+fCzRhFdgxz244+3llHuQjBMc
         R/dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=LIqm2mK0QzCjDaonxOoQgeQh4/XoxC/BYBHrdXIXVCU=;
        b=zXUbrjZwcpFbLjU1tQo7G1KCjtTWLKc+HOW/5Zq/o0jkyEbmyGZJ3pRT8w/AO/FVnN
         3gtCdlS5ToFDrzA7+s1mNDQvi0VDZ1Q2lgpIAdaKzvhOXQmLVxsZHGHndZRR1Q9PSLTu
         KVR/30gL/ISMUKZGBu9kniZ/QaLwKo70kfNrFYuhVpdKT7RY2pnXjZUZ6wP9TVt6dgCb
         x+EpoUTdEbIM5t9j7ok61xDDMd8aiC4kaGMCP8sw5qclXbAFRO0KhsXtidJYf1QwCJv0
         6OyqkNmV7entxUecuAlOl1eFlH4AFo214tQXu13NLfS9288g75TrhWcanjNXFPkku1+I
         1bqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LIqm2mK0QzCjDaonxOoQgeQh4/XoxC/BYBHrdXIXVCU=;
        b=b5BLDQBqyQ+Uf3tPNE1mgzDXpp9FyqFgInMUenx/VH4OdCpTs/6XC+grgERToUYR78
         u0CqlHnT+GoWmYY1VDiVInLw4REAM5bjleHp0h70h0Y1EECQOt+9qlcQe/R5VF25+Z5r
         AbBLHMqU/JBn1Y6x2OKfm2+URMOQwuMG1oL24LB5Lo9lgCmAOc2s0nFSwa+3+bdpG029
         w21F1lWFKyf5zRzGvnmFBHYtr/VPl11+SYYoFlT6LIg7GS7gHbysEsVEFrMaWiaGgmPm
         cN7YdElM1OqJeuBVenormJlMWqTU+FdpUnWyiAKMQcjVFgi+KHg2e1kfd49ARrrr5O3j
         OoHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LIqm2mK0QzCjDaonxOoQgeQh4/XoxC/BYBHrdXIXVCU=;
        b=BC6yzxNitYAWT+vrfKvEZ4BFM4AM0jRVyzBJLF3PoprGauogFUtzNtg+xqcc2NdO2V
         /vURs16Ye/Ze60xebLfctSTbSueYmcFabk6APH3Qkvy5ws4+vp/XitwBPDXtf2zZs11C
         wPxyxY6NHSctAdSi85RkDlDOCYMr1Fc9FVidBiFLNqYpaCuKb8tNwyGxVbHN7YIlvpcZ
         X+hxpcqujtJ3lCUhqHzdaUxGbHKv12+5hhN1U7RKqpOoqsxr3Y/f+waF8n2GwL8l2Dyw
         QfUvev2w7avh6+MHq3uqgYW7FtOeu8lenpkZDq7Zb8d2rsGRzelOAQEtB9Smp7VETcGr
         eLsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kzcZJKYsA2XmsTKZYQ2CYDWkJaHY03m+iXPq7rOFMYyG5HDEA
	OzXGX6ceFUxNxRSCDuydDlE=
X-Google-Smtp-Source: ABdhPJxWDPvacgU7FCwhWmjTY9DYin/m0O24M4lqyBe/6LB6U9jydeIp9dxHJXjUEA6A1TC6tIYVsg==
X-Received: by 2002:a25:80c4:: with SMTP id c4mr18660301ybm.95.1610707792281;
        Fri, 15 Jan 2021 02:49:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c802:: with SMTP id y2ls4250154ybf.7.gmail; Fri, 15 Jan
 2021 02:49:51 -0800 (PST)
X-Received: by 2002:a25:3812:: with SMTP id f18mr16731695yba.157.1610707791775;
        Fri, 15 Jan 2021 02:49:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610707791; cv=none;
        d=google.com; s=arc-20160816;
        b=siJ9f9UTYN3eIWFzvNZBWitEOVTgjbnB59GrszHENgVZYKjH2S44hkNmD7BOXa6G+/
         Xv6hEbqRgpbrLDKv8hO279+XqClk+J8T5JbyV8KdO+SL5QCjxu5te4lMe5S5fEWMF8/N
         UIdHvzuaupoMw9OV/lCr510QCAu8yr/ZntVVNcq8kasFxgyW1A1LoIJI56IM9q7+s7TT
         emnSPvR7TsNlx0e5VTZayvSaBUtBDf4zID4JDCt/Al1MbVmBYxnT6cJ2eobNkgloXxry
         ri/e5uR6XCDbxsXjiudHg6aMBXdpKp0w1fWc0RBaOJy5U27jYTWz2M2T36WIE5VFCbJ3
         k36A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5id6NLyrqX63EjWUTtht1lzc3xCeaLMh/2cFhttq1j4=;
        b=D8aNEJiY+k+drYhDLj8fHIQFOPvRBXV4CYo9+pl57tVW+XOgIpYgjkE8xqCzIXb6fJ
         t4Z4xc52DLo10MSlXNRxerGoGF4E2H707KKF+gqEWRuAjge85ns6UpaTRMpip7cVFOoq
         DLCvMqIMdWkHWfepOXHEft5sVWBNAYQXvqjwp33B0fb5BnSj4QtSY+uetWnrn4JnNLim
         gsJWIewxF5AhSSHCU1DVaXfNpHFJdRbdGgK71zRGxYXjJkPe8t//c/HCIw/WtbdICiwA
         EX2i6pu/L5dnVkBmz0UJctHhG3f8/5YsuhGowaGSAbQ9J9JS8nRuy9fPkS2WThnAUhYZ
         HzXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i70si636881ybg.1.2021.01.15.02.49.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 02:49:51 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2CCB722583;
	Fri, 15 Jan 2021 10:49:48 +0000 (UTC)
Date: Fri, 15 Jan 2021 10:49:45 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/2] kasan, arm64: fix pointer tags in KASAN reports
Message-ID: <20210115104945.GB16707@gaia>
References: <cover.1610652791.git.andreyknvl@google.com>
 <3d9e6dece676e9da49d9913c78fd647db7dad552.1610652791.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3d9e6dece676e9da49d9913c78fd647db7dad552.1610652791.git.andreyknvl@google.com>
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

On Thu, Jan 14, 2021 at 08:33:57PM +0100, Andrey Konovalov wrote:
> As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> while KASAN uses 0xFX format (note the difference in the top 4 bits).
> 
> Fix up the pointer tag before calling kasan_report.
> 
> Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/mm/fault.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 3c40da479899..a218f6f2fdc8 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
>  {
>  	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>  
> +	/* The format of KASAN tags is 0xF<x>. */
> +	addr |= (0xF0UL << MTE_TAG_SHIFT);
>  	/*
>  	 * SAS bits aren't set for all faults reported in EL1, so we can't
>  	 * find out access size.

I already replied here but I don't see any change in v2:

https://lore.kernel.org/linux-arm-kernel/20210113165441.GC27045@gaia/

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115104945.GB16707%40gaia.
