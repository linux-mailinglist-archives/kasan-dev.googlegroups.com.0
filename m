Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB77ATDFQMGQE2N7SI5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F40AD188BE
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 12:46:09 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-47d5bd981c8sf51232135e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 03:46:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768304768; cv=pass;
        d=google.com; s=arc-20240605;
        b=i/JErK6ZFthKt8btlWLnbK/5uvyiycl5Nc9K5vzvEAPEQnCNP7ZrS/mVn7w2yqH5xC
         96fdtKkJfpqzWmewyiAdUPMlQqZQYJrib9HXGIE+Rj0+h9U3JbW14Re6bC5nYRRGl21M
         Oir1+aQdfOJ7xT9+i5TmwN9o0MT402eGFY5JAyPadIWKoIcT0fOSg3W+ctiotLWGp9lx
         xyxBk82AFhgUQlRTlEZf/dN6C3FTvwuwCHPYJJlxGjmeMBDDIDgZXu6AMvpUgAprzclq
         2RCEhf/7q8pcjdpPF9K237lKEdli4PtgbjqG/n7d+S1gzsc6FZYRa+TDCR5aTKxua784
         8dqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7jL9T7Z59bTb337WTW5n/qAxy/FxFVZYJ2ZvBFIrUdo=;
        fh=WjQtuafljq9yb+NZa1Jb4d2BOttASDhTCXF1/fdu8tw=;
        b=jr3vRFH14jy4/0dh2QYzAegSdpjzb375KoocizY2I0VS+2hdfcIYrditQwbhTKEUej
         UxjAkKJgtIB5PjKd0TtuPZgTUqDSwVEXqcXE9zdFg5daE3WeuHh9CuJdtwpgU6g5dqtA
         fmgfKnAHEI9N1dJUQJ+x7BzpVxmvL1lb/95D1xx6S4bPBkql3rvRGpmqHoq5lqmUnwmF
         lDXIdOlHCTepDKKKIWvAUu8Av6HvXZlmmBvDiBhZ1bUviEMFVUTzcjdB4hxxhz0SOplP
         mKMXTv5Llaqj7CgrPS51dsVML3PX++2RGZj9/PcqRQNt9PAIZ0qsC1A3vXC2mUwnS7Sf
         lieQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=RkjHT1Gs;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768304768; x=1768909568; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7jL9T7Z59bTb337WTW5n/qAxy/FxFVZYJ2ZvBFIrUdo=;
        b=MurSg90SMhU5P9o71mRJ6WaX26AgmNEnFuBufgDXx1GtF2DIyJXZ9T1gC4HdtDoU+D
         bl/Nuj42eDK0OECJ37+rsTmFaxiCbaFSrtwLQKx7LXQW5vA2hrT7rbFkfLxOD4I5kdZg
         7qe9IgiCZCu64ZidRK1IrR7cy7Lfs+ZpuWrS5s+yqau3kfj76MwoYtlaOZ2ZQQrsWdt7
         2pdghMyt3jIU8EybwkeOAiva6/g4GW2MpwspEcDTIyJ7JN+5bAjk5v0K6oWXOaAwxc71
         HmGhlGrulfYje4wEld7Y92fwCwkb48gicDXzOcw+z+kQN0Y6u8Yux89Bf5VhXZSfaXM3
         gl3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768304768; x=1768909568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7jL9T7Z59bTb337WTW5n/qAxy/FxFVZYJ2ZvBFIrUdo=;
        b=t6DZIGG2YhF3pTM1wAixjx+xWoZw0zCjKubS2TeNV8FSCMAImvX/9NfxznhLZd58N5
         e6Udn+6v5pZiBrbrg0DZm0yr/yv6W9HPvxlP61yu0LvBN0xJQjcc9FjmkYiecC85L6ll
         xbCc8OoTLIk3fBSonaRugDNYWxXpAw2Ac9hik1q5s+CaiFPAx1YtN0liY0ByaEoy0PHj
         h/M3q17ATkuZhwHBkUzKJLEUIUQxpmIj8HKf1IrpSom9OT7uUDOhP5sz+Ze/YUjuHDnM
         HZf+OrEOfkEQ2zMnKM9+7MRzaf1esJ1ScferAmZRB2mFifNM6UdtexPyVS61w+Nw5kcC
         rmAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3GdyZcQhU3sE85nBe17iY/G2zvZbGlRMMyqExJYNRHBsyd79emFgG5drCAZAkTyNpX9kTNw==@lfdr.de
X-Gm-Message-State: AOJu0YzWBZP/DZhtSBmuyB5iXVj8Vj4laywgyYiYCUGwZseZSo8A3+Cb
	r0Are2NXRGGVm8tzQV6WtFR51RTswTVfdyMHwvRcLff9QSl8ZZ3LrA66
X-Google-Smtp-Source: AGHT+IG0U53qURcnKcZFdo+D3oeEckPMYMhq3o5AqTs9d1XdHx/BwBu1eG3s/sql+VDRA4FnfImgDA==
X-Received: by 2002:a05:600c:19cc:b0:47a:7fd0:9f01 with SMTP id 5b1f17b1804b1-47d84b21227mr267034645e9.16.1768304768217;
        Tue, 13 Jan 2026 03:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HZo7PZgqe2Shf7yjtQyEeM9tYBoIUhWoCHkRl338CRtA=="
Received: by 2002:a05:600c:4703:b0:477:980b:bafe with SMTP id
 5b1f17b1804b1-47d7eb13f6dls58236525e9.1.-pod-prod-04-eu; Tue, 13 Jan 2026
 03:46:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWRXv8yjTMItepPkqc6/hN4QstY0WGxHQej1+9IIa6VXnOFHbv2MtlvFRWn79SKcnl+R74EyB6h7U4=@googlegroups.com
X-Received: by 2002:a05:600c:1992:b0:471:9da:5232 with SMTP id 5b1f17b1804b1-47d84b1a08amr267996635e9.15.1768304765974;
        Tue, 13 Jan 2026 03:46:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768304765; cv=none;
        d=google.com; s=arc-20240605;
        b=YwqR4Es92yggo1MOvJMIOwk0F0idI7vyu/JGg1Q+OL3gJKsxKRKHyQztelVGjVm4iY
         OfW5goQJqmcogIvO92lRq+x4llTlI5ZqIzvg4WyEXQUTq0sDZ9tT/gGJYzMDfJkpqYvk
         3fkKCLnxUyk48HzOI1PiVlcykekVHsmhBZng+kKYoh0cOgmlA6b1qeQGXGO4BQcGwD7S
         aY0fXDHVWcDRnPlxfjnP8kyTwx40rzrwUvqNjqeMgx9pBxK7kXpo6FNV7ln2sp9CYT/l
         aJTyTnMhF/+liBTk3ZyTwTwqPTgrlXoOsCG9xs4CD8DUiZJPnX5KYaF8tDukMOMAFiL9
         YTVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pz0WnAch0eItdE8vpx3eUHqQth068Vy2LdHGkHAEuPQ=;
        fh=uNrXn1fp/rD3r8l45eii5VO6lFn8NZM8tPn9l5l6iCA=;
        b=gzP2pDECd9n9BO1M2vWRj5lgTpUmZJE8hHlmS+VikIgxESwu4oBQ9F6K3mwuGCFbK8
         Rindj4zyF3MiBDcssJP/HvLi2e10gDNPdFZY7vcunIShQrVxCgSRVod0ewtBRd5xL5LI
         FXt48q7Af0qlhI1aVA2yAQMr8+Pn/XBM1vrxEpzJ5G0PJiSHzLhktC975yw1OookysqM
         TKYp7GdkEAYx+YmYEEUaxYnfzLhVPGaPZ/AlfD7GTxaGzom3ZtXSj9asCp+8H42jqLIt
         vwC+wYLnYKO4FXfRGa/ar8GdkfBYXTcxw67eNxOLchYX0ut+RPeX6vHpjX9G0KV+pwQw
         +tnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=RkjHT1Gs;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432c1a1bca1si313361f8f.5.2026.01.13.03.46.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 03:46:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id E41DC40E00DA;
	Tue, 13 Jan 2026 11:46:04 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id F_eJBAeyuWOC; Tue, 13 Jan 2026 11:46:00 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id 52D5340E0194;
	Tue, 13 Jan 2026 11:45:40 +0000 (UTC)
Date: Tue, 13 Jan 2026 12:45:39 +0100
From: Borislav Petkov <bp@alien8.de>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v8 14/14] x86/kasan: Make software tag-based kasan
 available
Message-ID: <20260113114539.GIaWYwY9q4QuC-J66e@fat_crate.local>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=RkjHT1Gs;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

For all your $Subjects: make sure they have a verb in the name.

For that consult:

https://kernel.org/doc/html/latest/process/maintainer-tip.html#patch-subject

and the following "Changelog" section.

On Mon, Jan 12, 2026 at 05:28:35PM +0000, Maciej Wieczor-Retman wrote:
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

...

>  Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
>  arch/x86/Kconfig                     | 4 ++++
>  arch/x86/boot/compressed/misc.h      | 1 +
>  arch/x86/include/asm/kasan.h         | 5 +++++
>  arch/x86/mm/kasan_init_64.c          | 6 ++++++
>  lib/Kconfig.kasan                    | 3 ++-
>  6 files changed, 22 insertions(+), 3 deletions(-)
> 
> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
> index a6cf05d51bd8..ccbdbb4cda36 100644
> --- a/Documentation/arch/x86/x86_64/mm.rst
> +++ b/Documentation/arch/x86/x86_64/mm.rst
> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN shadow memory (software tag-based mode)

These here are non-overlapping ranges. Yours are overlapping. Why?

>    __________________|____________|__________________|_________|____________________________________________________________
>                                                                |
>                                                                | Identical layout to the 56-bit one from here on:
> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
>    __________________|____________|__________________|_________|____________________________________________________________
>                                                                |

...

> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 7f5c11328ec1..3a5577341805 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -465,4 +465,10 @@ void __init kasan_init(void)
>  
>  	init_task.kasan_depth = 0;
>  	kasan_init_generic();
> +	pr_info("KernelAddressSanitizer initialized\n");

Why?

> +
> +	if (boot_cpu_has(X86_FEATURE_LAM))

cpu_feature_enabled()

> +		kasan_init_sw_tags();
> +	else
> +		pr_info("KernelAddressSanitizer not initialized (sw-tags): hardware doesn't support LAM\n");

You just said "initialized". Now it is not? How about we make up our minds
first and then issue one single true statement?

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113114539.GIaWYwY9q4QuC-J66e%40fat_crate.local.
