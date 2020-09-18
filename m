Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIVASL5QKGQEHAVSHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DEE126FAD4
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 12:46:59 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id f16sf1919227ljm.17
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 03:46:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600426018; cv=pass;
        d=google.com; s=arc-20160816;
        b=0c1i7aJgvvzRa0MHfYVlJUaIAkZfFMp3jbtR1ljkEupE2G7PeewWKqA0sXk99ncbgx
         rURlzbZZ5Oqfkz9+XXa+d+fY6t+qp85m6e/dIPHOH5qFMJBlGAWq8HMWmqIZjOhLsEGz
         54ZnV8O7ME4ZB72xE6zFu7CscJVuwlNePujqCtxI5bRP1Ym8i+eEN8b3IrTJWitJdpQj
         OVVeFjUV1zq079B6FBwYsvIxUMftu+V9nZJsCxvHp10HIipvl0zFI2DyYc91f0ZtQPAV
         2kLIeOROZHSLzWzw8NzYgqKf5hpq7st7dO7tZxQ0ln2Ma7VLJxUBbFDGFhi1HKp2TjaL
         O+rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MAZ9BqodVzOFpGV7Sa/xjWFIAopkYS1NZqqD4EN8MHs=;
        b=QXno0uewxQuL8+c5JWgEtOFO74Un6NCxPDRBiabrmsfjAcN0al70zLRAcCDPD19DL/
         cimsdNGszz/1PIvxPfx0VkpNJDJygQw2rhBIrMGpQzHryHB4wt/pwx0YOj3Jnsf21swt
         8JH7sWMWyn6TPNL9lmBTjk7xoXmkwip7FXyMy1pgorVTe1JoF6NgNcweIeEruLcVy4pG
         YVv5HYW9I+G3oVCiihyz8siJppNXwb2IbzdpLRZ+TReWJaGTe6GBTD0hLE4XwtwXdGBd
         lWHBAUuPHO6o32hAcInow7jaccTze94XJ/F9VfTYLHwMIXleHlx8riGN8Hz4u3nsSeBf
         dTig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GCp5nQJs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MAZ9BqodVzOFpGV7Sa/xjWFIAopkYS1NZqqD4EN8MHs=;
        b=izd4iSTaGV2M9rvMMEYK3h3zepOYGiGHuUDarA0Nt4nQ0pC2srBLUf7E9iDjmZJPgW
         4PySHizGv5FxNzs2ZJSdR13Av2pkAt+RW1d/zyPhWF/OPSZnrKmx3yLWNbvWCPj9Nghb
         Yjw/iWAy1eBLa2g18afGmS82NQWtRmjzxCjGK8RAu6Ad7edXHqa4hZay6ZNaeIfs27ni
         iBH/f0YRWkq6D5klAm2kSGBTBz9RnV9tCr5cXYC6WmWEV9TpKlN9j+7uh5wyoVAI4Up5
         9mR6C7PSIF8rNmPDCT00skjHatn4zprX5Cf/2+fAet7TB+aURqQQ6xoze6EnN4Th31FJ
         ajXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MAZ9BqodVzOFpGV7Sa/xjWFIAopkYS1NZqqD4EN8MHs=;
        b=ZX5GhDTBbL9wJd6FV5sEd8S0oBIgXnoMYz+iUwMvPAX8wB1gkJ1BiwV/AUXwFzLyJd
         wfKMYF5IS5IO453YYiMn4UKvpqGRR5vntCpbs1Oh3/MIwL/YNqs/ynseVn5MOd8yh56x
         wRhMsUza8a4KQQ70Xx3lyZNievM4C2xkt+h7zo8NbiU98m0ph78mlevBb9qgQHpJwxpp
         W3wr9dYzu8jv+CO9e7VZaAhdhf1zTXW7KVZetfYanpHPKFs5udc/p996mXKFrAlYtjkb
         K6tnot1RXVKtIkpK6TQq+c1Ql6aWYctPapd/nAQtKyDREV0mzmCguKyhHlM8HGSVastC
         eCFQ==
X-Gm-Message-State: AOAM5313wnboIRsY0BJPOUOeQJznLBz2koV/0ayEPrjANPUxr8xq9nye
	hJa7MjNDUja1h2QUTY9DKGs=
X-Google-Smtp-Source: ABdhPJzyzvI9hPJwZJgo2af4HGWtW7E4Kg0HHUUUDkg1czUO+W8dD5kuXuCVQBWhWu5iuAAuuvkiBQ==
X-Received: by 2002:a05:651c:514:: with SMTP id o20mr12403043ljp.312.1600426018670;
        Fri, 18 Sep 2020 03:46:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls168523lff.0.gmail; Fri, 18 Sep
 2020 03:46:57 -0700 (PDT)
X-Received: by 2002:a19:8087:: with SMTP id b129mr11513143lfd.471.1600426017500;
        Fri, 18 Sep 2020 03:46:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600426017; cv=none;
        d=google.com; s=arc-20160816;
        b=Ik8Jrk8aSZBAG6BsEMYGG/Oapor27miIsAl+FW1ipgA8HG8jAoEZkDxL8FldL3o/Pa
         0K+EOTZTUYcZ8t+D+GNIFf9w+Ga1xYq7UxqnliiYcfdINhegjvWCuHeFmSPNmO85G3mQ
         B0mdLNqJMEwM/1MkJAD4i2LwEJKAZfOjlq2WRcblwGiOOhf7oVhT17pQTMcs20a8S+a5
         f6qzrVd7/+Dr7+IKxcwoEnUWXhNUHYXIjogOeptQeM7FXZUPPwP4ukuSYSud16r0rWS9
         E+CK/+vhExGiyIY6S06mfOq+TdscKcyWAeMFf2Hsdhh0kHVrlC8haDmOGyAehzyRqUAy
         Fovw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QHJwfG6F4o4CDJIq3QihHGujfsirLPtmR49z41IlzGM=;
        b=l5UO4zR0d62p7z5kJy7aZucz6C1KsKJIi9yLHVi9HJUA0bn53lbDa0MXwJipMaY3Rf
         GuVR/k03/CInw9KxyFbHuUZ+VkhtGi1GuyW42kmUZkJSG58cfJ/W954mSmPA8t4e5zhv
         u5MJp7nmnFIueaeGmZoIZbffvaA3nsxFAq0+L/MhWGkI5tagKQVqMT3lgyPeCS1ZiWbZ
         F6igvJ8noz97pcGFYoZJRtyVbtA3QxqK1HiK3lokRzmE1gjumlaTFjMOzgVQ+hsJXCcc
         smOQl55ArXMEO2in6hW3+18ClffJYPQGeuyh50uW0N7uRMJZGpH6lzezuJkv/owrQS2b
         SoXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GCp5nQJs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id 11si70315lfl.4.2020.09.18.03.46.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 03:46:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id e17so4868181wme.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 03:46:57 -0700 (PDT)
X-Received: by 2002:a1c:7e15:: with SMTP id z21mr14738241wmc.21.1600426016909;
        Fri, 18 Sep 2020 03:46:56 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id u17sm4317615wmm.4.2020.09.18.03.46.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 03:46:56 -0700 (PDT)
Date: Fri, 18 Sep 2020 12:46:50 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
Message-ID: <20200918104650.GA2384246@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GCp5nQJs;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
[...]
>  arch/arm64/include/asm/memory.h   |  4 +-
>  arch/arm64/kernel/setup.c         |  1 -
>  include/linux/kasan.h             |  6 +--
>  include/linux/mm.h                |  2 +-
>  include/linux/page-flags-layout.h |  2 +-
>  mm/kasan/Makefile                 |  5 ++
>  mm/kasan/common.c                 | 14 +++---
>  mm/kasan/kasan.h                  | 17 +++++--
>  mm/kasan/report_tags_hw.c         | 47 +++++++++++++++++++
>  mm/kasan/report_tags_sw.c         |  2 +-
>  mm/kasan/shadow.c                 |  2 +-
>  mm/kasan/tags_hw.c                | 78 +++++++++++++++++++++++++++++++
>  mm/kasan/tags_sw.c                |  2 +-
>  13 files changed, 162 insertions(+), 20 deletions(-)
>  create mode 100644 mm/kasan/report_tags_hw.c
>  create mode 100644 mm/kasan/tags_hw.c
[...]
> diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> index 77c4c9bad1b8..5985be8af2c6 100644
> --- a/arch/arm64/kernel/setup.c
> +++ b/arch/arm64/kernel/setup.c
> @@ -358,7 +358,6 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
>  	smp_init_cpus();
>  	smp_build_mpidr_hash();
>  
> -	/* Init percpu seeds for random tags after cpus are set up. */

Why was the comment removed and not updated?

>  	kasan_init_tags();
>  
>  #ifdef CONFIG_ARM64_SW_TTBR0_PAN

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918104650.GA2384246%40elver.google.com.
