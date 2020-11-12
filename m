Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLMLWT6QKGQER5DKFII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C53A12B0245
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:51:42 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id v8sf1552479vso.10
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:51:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605174702; cv=pass;
        d=google.com; s=arc-20160816;
        b=wLZMPduoBtf/lfq5C0btD6oipp7GSBYlwQdEridVWB0HLp6tkhz/ZUwPEC0PNC5XLC
         l4R7TGauXgJWFW5+/KLeugeECHNye7v3vrbHFkzcLxjNpIjrTia0b888GsCd8QIdQ5GW
         lJ4W2uDNvAni/bjhiEUjQlNwauSZ7HDDrStflqJq30ifOJNQaUg1LMsoaHii2WKHsDFo
         VyJkinP4ZZSLEMVSvVkxzBSb9pboK7ce2hu+RdRXMN034eGkMaDKRQ0fR0wb9XFqt36a
         5L4KpGfzlVzPIwDDCCQVLbavm234KH/5u6KkNrCmubiVRlEImPn2qoM/+r5O5e+Q2K/t
         z1dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=IQTdVywNOlO4i/hpJ6TmguaxSmuyNaFjLFoiIOAo9Ug=;
        b=AuI0cNLdIDuJhHEv8fMWi4e2Xzq/ef2qirbKaDL4hq1HjQlma7goqsjJk+v4Muig4b
         gHkcud2bQl7bd1TaqExnTQDj5ERNbJaXdZoHbK9VEZXQ1ez6p1tyzaLemx8m5vv9EZ+g
         A2Sm6KQ+o6JGo7glXmIlTky+dXQSWLf8VYeFKIHZbx4XLe+e5pErJh8LpVhgC0Vh9nE/
         UAtJcdh2hGRb8l36Zw/GZwgVjMPXlywPNQhjb16N2XU2h1m63HEprnSGF/WPH+m+E3oH
         ouq3klMGGxL9+Pzvj0LRGZwoVrUDz56QG+f8BJOGQpKjhKL75Uwk3ORcRhgE7TqhXz0z
         mFTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IQTdVywNOlO4i/hpJ6TmguaxSmuyNaFjLFoiIOAo9Ug=;
        b=PlUpVaCTXsqbgnBcdkI4AqcWUTZ2pYyPqFWJfuyN21gKXt4MD/EvAn0mecEodMd5Bd
         pcz/+P0MUQ7jcIOQZKfcwEBDoK9xCh7BgBoL7vZ6/7ljMw7P/nXLLfEnQsGz8gn7lCiY
         trra3RdlV79XbHI4XCnHhekVFq2j5w4QTbjOqj4Tf6NWmnNDzsqvuFpuryAm6Ymiz4Bw
         kKXAliOfJcPQIm/09D8ij8kcy7573YVOuyYwPYxicOm97vHxFRQLZWOhV2SgZqa91nVX
         2eCrKjxvKYLqfJgyGxADK6NEVu3uPbOi7FbLBU8AHOtdbDBwNmtxtM3dTUz5z1JoRTZ2
         G0cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IQTdVywNOlO4i/hpJ6TmguaxSmuyNaFjLFoiIOAo9Ug=;
        b=Vr4YZO4MT//Re+2wH/Hv9nxEQSsmmCCBISBAicmS3YDtKamUp5B7btGzYgAMjtBAJX
         DNDRCibgHRlXZqogoJB8Mhf7xR9LfFTjHrzA4MOOXbghL8Oa8wbjruSldBhSt3lO4iBD
         C+GPMd2tkasaU7xvfR5A37V2MuJ+3ghwA+Omcr4umH3/lUqFTVNwqnjMSPywNMeLB8hY
         CHA0l55XJshAGnbX64W3xmBPVY+188kNCcvABH+QFDy93uelO01XF8A4LUQF+8TXgwSu
         AFmhBSSIWizml+iXt6s1mRX+EqkmsKeYCZuQPbyZpL3MUR4w4Lxp+W/bX9qWVJj4qOt/
         2CYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+u0/xH8Q9s6lo9Vshf1xvJz4s3270aRrkB6wCcM4sxpy0wbFd
	Yq5ZI/g5oAM0fxTzbpY0cXo=
X-Google-Smtp-Source: ABdhPJxVpSySKucC7yEIMP2aAAK51DvBRM1gaWNJmqKTsMsVNp5Bccj7ZEtS4hjmz/70vU/PRja8JA==
X-Received: by 2002:a67:f290:: with SMTP id m16mr18988547vsk.46.1605174701904;
        Thu, 12 Nov 2020 01:51:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9bcf:: with SMTP id d198ls127260vke.9.gmail; Thu, 12 Nov
 2020 01:51:41 -0800 (PST)
X-Received: by 2002:a1f:a0cf:: with SMTP id j198mr16356061vke.3.1605174701375;
        Thu, 12 Nov 2020 01:51:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605174701; cv=none;
        d=google.com; s=arc-20160816;
        b=H35LKaJvhksSN+QuwAHRmM7g83a9itFmgAOyxTdPl4vhPxafmPg5JcgSH6w6FUkPRM
         s3nFFNqCNXqKBfkNw3G/TymC4O5ulnOi1w6vn7NcHsQyOLhUhQp0W8j3BP5GaJ2nshM2
         +tlRmq+Y3Mom/RYAa/QANS0dcelX1VWK7bQGzEgLueoK5k7B3lLHqkzB7EmMDPYHiAJ1
         k83r0qPLeNoT1UNv/UvhftE1Rl+g3gQ5XC5r9oVnXZ0ja0qnrjParuUrYkc1+Q//WUJY
         GWA239l/xJNyy8VRtTrKjfieWU1iVmXOeA3eii70zzdzSbOX//3WzzK3lxfDiCUsTV+G
         aucw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=7iwh72+BvaNWzPAbdR1tCaVm/Ug3yNqjOtD06/oAPVQ=;
        b=UZV1MXORQ6P3zY2RUgfxnG1GePr8CpbDEzivDIOSsa+xkBQB1or0Ufuw2asX9BiUVT
         we7DSvplECS+MO2b7B3+yPchVjd6I1weVnwFSeQ2YKy3Wslnx6s7nGtNs5KZSnQzuj7o
         s0Uv1AFFhVnbNNISGsgm2nf3WbuLXS4AWtuwo4AudmRaTTgBDh+Yt9MFyusxv9l0o61u
         Q4lb+uNX9afMGzdrK52kqup9k6/2EFwa9hH0aXGSV80KOJ3907/VzbXFU2C2p+z2K61p
         unsuMzdIw4xe6GLpozioM5fCla363YliT6jUGyNet03a7z2YLKKBHj8h985O+7BDyLkA
         5TsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c124si309943vkb.4.2020.11.12.01.51.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:51:41 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 95C632053B;
	Thu, 12 Nov 2020 09:51:37 +0000 (UTC)
Date: Thu, 12 Nov 2020 09:51:35 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 04/20] kasan, arm64: unpoison stack only with
 CONFIG_KASAN_STACK
Message-ID: <20201112095134.GI29613@gaia>
References: <cover.1605046662.git.andreyknvl@google.com>
 <7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl@google.com>
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

On Tue, Nov 10, 2020 at 11:20:08PM +0100, Andrey Konovalov wrote:
> There's a config option CONFIG_KASAN_STACK that has to be enabled for
> KASAN to use stack instrumentation and perform validity checks for
> stack variables.
> 
> There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> enabled.
> 
> Note, that CONFIG_KASAN_STACK is an option that is currently always
> defined when CONFIG_KASAN is enabled, and therefore has to be tested
> with #if instead of #ifdef.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> ---
>  arch/arm64/kernel/sleep.S        |  2 +-
>  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
>  include/linux/kasan.h            | 10 ++++++----
>  mm/kasan/common.c                |  2 ++
>  4 files changed, 10 insertions(+), 6 deletions(-)
> 
> diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> index ba40d57757d6..bdadfa56b40e 100644
> --- a/arch/arm64/kernel/sleep.S
> +++ b/arch/arm64/kernel/sleep.S
> @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
>  	 */
>  	bl	cpu_do_resume
>  
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>  	mov	x0, sp
>  	bl	kasan_unpoison_task_stack_below
>  #endif

I don't understand why CONFIG_KASAN_STACK is not a bool (do you plan to
add more values to it?) but for arm64:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112095134.GI29613%40gaia.
