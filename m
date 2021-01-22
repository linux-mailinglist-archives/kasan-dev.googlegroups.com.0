Return-Path: <kasan-dev+bncBDDL3KWR4EBRBYH3VKAAMGQESNKFV2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A4F330022B
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 12:58:26 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id y2sf3300081pgq.23
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 03:58:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611316704; cv=pass;
        d=google.com; s=arc-20160816;
        b=U+sBnvJ84KiBJZYttjhKSXwtoZH1Td57NQtCXhCo3cVm1vbI6AD5lCDqBsbQ5g7cBZ
         oLqIyaXIQalWz5bTD/cihH2Me7pVij0Bay7DXtPCSzmvQG2y9zoR17EaCeMd3dpfEcFN
         LLnjI5oKKT/tulIsnMX57XZTcvDlDDCGnB2n2XvWDW2nEhF7hxIuS1yLO8ZoCJTHxMrh
         +Y0U84lNdO9e/UC3rgLd5ORdOebflBqLQgsQqSkSjrogUsFiDZgAx+O9VvdGoUV4CZ/c
         gNeMNBBaMY59jM0b/Cw+t0p7rI4r+IpzEXEmYf9A8fTpyeYd0UcsFRkZPNW9IcMkjyWu
         k1WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=GivaDcoTh1sabCa14S4Dz/xNZfDGNe7pSLtKtuhhOmY=;
        b=NRzpTHDP9rgZ/lPYVRID+N8VqEBhHi3y06FD3R60Aa9NlOt62D3CYODFpt+CZZ+bXo
         WZEzxtnmDOcCY8SlYL3DqxdoA3GFPn6oI3VKACrRa7Gp6si/BbHQfdu9jX7slYj0wGvA
         pyLe00RNWj1tKNqStPIFPGozG+Vr4SFP9VAqxj8ypD9CkegF8ksBntauMxjkbZOsnvF2
         teT7r0KTFGQJbpzpe5PP4lzmknxTcch/M2xC904sEpNwG1BtPuiqF5CKHP7SRU2NRESI
         fOuWToo/3e31ZZ5p0TAMYudPplaOcmSl1CUeUo9YO5tem/r7pLNZw3EQmEWlmT+EI39G
         yeyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GivaDcoTh1sabCa14S4Dz/xNZfDGNe7pSLtKtuhhOmY=;
        b=ldbwqNaUPTCQ2bDv2iGHeq6d5EaarYLDuKoSCd55qs82MrD/36Zvg3AjnFlIZQesbO
         U1RfhQ76A4XhDdB5mzpXKKOdofOK8qdnDhJGU8W59ShQKWkWmJaF3veVgfv0esOuFp9v
         wdQ+dclkfgDKYDbN3ka6PMUeGYTzxFYvwZnUvnffwGypXU9hoFxyssGfCeMdC/ZF5ef+
         Zb4x4AfXXolHjaUluWPx2mNPWVmR22/r0Zc6LJmVm13N0BrIUZSFfaYUyNATIx9QPjj6
         N/j0kLf/IcwUL1IRszr2vI8Y3p0ZvS2bAGPlzQZra/XatKAJO4SGLD6bVrtA7muJyz+h
         88Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GivaDcoTh1sabCa14S4Dz/xNZfDGNe7pSLtKtuhhOmY=;
        b=aB7Bc5BIKWt/n0FACH8ypk+tlArZ10UqVBfKxpKgOweA9ZqeJsC6R5w1Rp1c215tqd
         h/FMpDgXwaRPpFqkxnLKfzsDYzBi4wCYkV5MUw9MjkKYJM/WT8jGLvyDEYI0NTLAjXyo
         OVSUrW5LqTTdrfB3NC6LE5WvKSnNzmEODFKV53O3iR7SKO9zPDK8o8NOeg6EU2j5qZfv
         0M7PgoqfRQnZnvW2Djhr2UBg5hJCbgAhBJkjUh2d+gbIKhs8f/fiDqnzKGAEU8JKW04N
         7bmEBQk4h6I0G0ubrvXTPvdL+oUr57IqVsYRv9EXOD/SuBQokPTuqiYhKa/0qqS5xb8i
         EClA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KR/K2oh8BryuDdgGPvi8ir0Cu2HvlAc+YrGmGUEakeNvr/xrV
	UW4epjX5QhRs0LoUoOnC8rQ=
X-Google-Smtp-Source: ABdhPJxgczmcsYvoJnmNCuvO9MjmoLdSTG1QiRmr6fGYgi4kRtfBkIZzFP18D9I/mgJJQOihr5Ygwg==
X-Received: by 2002:a65:6450:: with SMTP id s16mr4228961pgv.71.1611316704807;
        Fri, 22 Jan 2021 03:58:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7047:: with SMTP id h7ls413058plt.8.gmail; Fri, 22
 Jan 2021 03:58:24 -0800 (PST)
X-Received: by 2002:a17:90a:886:: with SMTP id v6mr5001952pjc.143.1611316704185;
        Fri, 22 Jan 2021 03:58:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611316704; cv=none;
        d=google.com; s=arc-20160816;
        b=BePyCwOnF+BxjJtdzmvDCj9uxoHFi6JIRschsIxEgJl9F4tzho/1vWJoasHMlzumDs
         s54aOULHXxZ83ZjA04LPf4NLJ8OcIiF3cr/WQV+N6B6AgWnVBuCD2PcubADBwBfSKWOQ
         /llVWIiqedCFYRm+sDdrlIybOcenGuMbpb65n7vMPN1OSrerqj2gBDSk662tfqXspYtd
         XQdUwWi3OOwTiAUDMI0vl204dH2BHsJSKiSjhelwloIAFC/HoQDMF7jDg04SJ2gJ06zx
         2G/Asu9tfWC/sF3GABBW1eJngWJuo3OqTYeKh2WS4PfaDhQAWthOAk5o92DTo7zkI9Ir
         jY+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=cOn3oEb9temo43bBNL5mXvvTC2HZrQ266FpPUxWCdzc=;
        b=X9QeLyKZkxTXMlDMpXM5m/esDpTlUfQ1QZzpbQvXpKwq0BsJmbhQGat0z1L/X9nqd2
         1W2z3cdfveECdP4yvvKMvnPq32UcgUTv8EYYfkggoEnvcVGUrcqxftoYlT1HTcfWcsZm
         tlXJ9CCJAlmlspbNHaJ+ssptyh0IVIkYqAnqLaSRviRVOEXy/BOhi+2VtFYeJEHvToJq
         P1uXuALrN7jr8ir9YUQ+YkNO2jGS0278Ckyeu3ITWjGXxYnyWr3LvbZj+V/53qTGpTHZ
         bWfOgkPjpE/UQi7snnOb4BybOXA/MD7vliH2HmhY3lwCpbD5iadnnKGo6T0Yhg2jIXuJ
         a0dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z18si459847plo.5.2021.01.22.03.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jan 2021 03:58:24 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C384622C9F;
	Fri, 22 Jan 2021 11:58:21 +0000 (UTC)
Date: Fri, 22 Jan 2021 11:58:19 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v5 4/6] arm64: mte: Enable async tag check fault
Message-ID: <20210122115818.GA8567@gaia>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210121163943.9889-5-vincenzo.frascino@arm.com>
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

On Thu, Jan 21, 2021 at 04:39:41PM +0000, Vincenzo Frascino wrote:
> MTE provides a mode that asynchronously updates the TFSR_EL1 register
> when a tag check exception is detected.
> 
> To take advantage of this mode the kernel has to verify the status of
> the register at:
>   1. Context switching
>   2. Return to user/EL0 (Not required in entry from EL0 since the kernel
>   did not run)
>   3. Kernel entry from EL1
>   4. Kernel exit to EL1
> 
> If the register is non-zero a trace is reported.
> 
> Add the required features for EL1 detection and reporting.
> 
> Note: ITFSB bit is set in the SCTLR_EL1 register hence it guaranties that
> the indirect writes to TFSR_EL1 are synchronized at exception entry to
> EL1. On the context switch path the synchronization is guarantied by the
> dsb() in __switch_to().
> The dsb(nsh) in mte_check_tfsr_exit() is provisional pending
> confirmation by the architects.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122115818.GA8567%40gaia.
