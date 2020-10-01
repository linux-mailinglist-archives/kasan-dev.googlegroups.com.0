Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5U63D5QKGQE6UALSAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D0D72804F9
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:18:47 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id n133sf2075042lfd.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:18:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601572726; cv=pass;
        d=google.com; s=arc-20160816;
        b=lbhl6i/xckyfgA0NLMlQWzBOzH09L1+WrJPaPoXkyBeGwEA9bF0QrXf/lz7pP2npRW
         t5o5vpVuXK4Zink9jKnWQOzOoKcYx/kRKbtMbkeuedPA6K8OxQvWQTjYmXUSuSWlQHDB
         HzxVkZo7/HsdSpLeDpif6ugAKrzy9v6XHmMJmEHMpYQMOn4jfxEaBEE4qqC1gaaXX7qx
         OSL+sjPcVBUUQ5L0TbrwXhM9EdcyI14er0MhmGKfjM1uoUIZiaKAriSDV2tZY/TagWnR
         cmzoeLHQhww4RMokweZ05U96VXvDVfRQXhs1GAWsOqheVD2rsOT0P17xXkWjpASd975A
         UzUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=d3gwOc1C0kDVHKnpfCMtv/zFUW6nwPj1GG/x8Rr67V0=;
        b=s0YKBRa0PIEd2xZ4mtt5K/SL8EJXO/RfG3gB3OqsqMZFQGVi/bsRgkoOC08HgmVpuw
         AOkT7kOKk4hLPsfbp2QrzJGoucmVyaXQmDf5RValF9QXpJY91ee9EgBbjYY1xNauS69o
         DWLNXaihIPsF6KkpxcZhbACeq4K551FZoadfO+Hm/X950cwA3t8jQ+u+sWZBUtEuLtnx
         8OygEdp+iAeEZ7iRkBneqS+PyekJVXVv5VY3+mTkXJ0ZXTFLUBh+MhoROzL+g63wyZxf
         ac34sRqcdTmLiku46JCVpq1iWaGsXbtUkVkk9FItXAwiJHKpkZwnKwbmTsT0OPT6993t
         PZjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EJ6ylxnq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=d3gwOc1C0kDVHKnpfCMtv/zFUW6nwPj1GG/x8Rr67V0=;
        b=hjkj/HbdsQdYn/NcL4n5Z4Rvb661uZsytAu7mzTeZqEdcBAaOwN2OhHg43nxkQHMN1
         22qxN6cyn4zJC6qbXOco6kG/RNi6cZv8/1sZVEHTm9sQkBZvrhTljZWLis2OdCltLEY9
         so8G5a/kyQ+WSsyOYjKVWaqtXThBzXyMQxtKshG9ucLYuVHeGvJaRnDwLIHI/Sly0d43
         7n7RCpo1e9O9q1BjtR5f2P+aMxH9+lgQi68ZKe5xfhg6YhhpEVAtXvGgzUtYvW9zsfIQ
         K/fPr70LugSvtvO433mI8EQVjy9Z3M1LfJxf6vDYw+B7vDOiqS8sdvyEJ4Pz9Cb4Mwou
         EFxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d3gwOc1C0kDVHKnpfCMtv/zFUW6nwPj1GG/x8Rr67V0=;
        b=lf0H+TKav+X/E9NjXhpOxBM+i6cUmhCQFrhHx3ungO2JFBp3SJI7ggNNnCIVRJNkoO
         Si2sHMPe+GVhF2xUAFLCq6b5bXxi6HU+vSb/thaOZS+rXqyS5M25Y3qrBspuCnMwnnth
         g4I7Yeh/ZNd9OFGp/rHuTcDD2/vhhvbNsejUYdq2gHeNUZTBQfoAVfOtNkMYEbDRbcZ+
         GbrpTsT5R1+h3amRHpl6V5OvDSl2H8Rot5k+a4wa/DwFTuxicEaOcM5+vNSKpYk31KoT
         5w0lBi8sK7ZC4k2f01UAw1jRE8KX23Jo5pfjQc1s0i/UuhQLNsfTbIAus1lE03+BrZZd
         kVkA==
X-Gm-Message-State: AOAM532uRlwLLll++2tFiHAlQrlYD4NA/U7G2xqUs3QGa0jo8/uNiiwN
	MtP+xFFEqKLNSlwTs/VsiNU=
X-Google-Smtp-Source: ABdhPJxP+g7iZ+fJJCNaPWa81v+WO/YdIbpK0ls+LCuCTuFMmVKrqnKQAcWdLWYExcW+7M3ILQYGcw==
X-Received: by 2002:a19:e602:: with SMTP id d2mr3329685lfh.514.1601572726554;
        Thu, 01 Oct 2020 10:18:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1654131lfn.2.gmail; Thu, 01 Oct
 2020 10:18:45 -0700 (PDT)
X-Received: by 2002:ac2:4a6d:: with SMTP id q13mr3184207lfp.486.1601572725178;
        Thu, 01 Oct 2020 10:18:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601572725; cv=none;
        d=google.com; s=arc-20160816;
        b=o7+91pSnKuqJ+sy/ZINGxC2/wG8xPQzjlqPQ73sJLhdreL1ONxrAbFht9KtR6YyelA
         /KsCv5EOlvnlSkSFe7BBk9gGVfkgWRuWadYOaume1pSnUtE07g9fxSCzHcdNGLGZNNhX
         ma+dDMYbSMl/RVlfR6Xp8Xm+yYXpx/2cdqMQ59jpWWU6TD92Uw+v4pYPD2PTm/uMcSHB
         9PA4uk1GiRHqS/wTNaO96IWeEb1VFHDEr5644yXfFKHHpKFJ04p7B/ObtWyX3+yj3SHS
         W+WT645l2To9ccL0pL7v/iMZBWnukpzCVvDqGXx4ZQTEvUQ9hWz1Pi3zES3cTMsAxg24
         sX7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=AMM+i1pr6nkLHNqAVkSTj1TPYNn/WMfQYxPOkfPrgTg=;
        b=lu9o7SxuT08asZ9SSDOMjj1kmGoQyxvuY1+Kdlgti+ylmO/Zo7lorOzEP/5VWJKKpa
         oF1uH/wNXXNP+jhnVbGhMPeOoA1+GqFjpvvSdhA8ne+VnVw+jMhHJw5emUvoLnGUsAeV
         g5HFwG7ZC8rgGUJCS0I0MwsQXx2SZcFUWtgm8inbNIWULncuQZu6ur6GhsI9P4zkPRly
         qYmSUxXoQYXo0JovNu5lNNFuejvxzlruljs5yRVQeIofyqn9U/HanIJnIDhv2KZby6jW
         720lgNq1XvzmWWhbMjesiL89NKn/mN9NLMYXOZvGWieKv1nK1AklCF4+7CfJYAVQKMJV
         A+Vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EJ6ylxnq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v191si173746lfa.6.2020.10.01.10.18.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:18:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id l15so2688248wmh.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:18:45 -0700 (PDT)
X-Received: by 2002:a1c:e48b:: with SMTP id b133mr1068332wmh.0.1601572724362;
        Thu, 01 Oct 2020 10:18:44 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id x2sm10076139wrl.13.2020.10.01.10.18.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:18:43 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:18:36 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
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
Subject: Re: [PATCH v3 01/39] kasan: drop unnecessary GPL text from comment
 headers
Message-ID: <20201001171836.GA4156371@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <56eae03b7b8112b5456632f0c00bd42e7337966c.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <56eae03b7b8112b5456632f0c00bd42e7337966c.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EJ6ylxnq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Don't mention "GNU General Public License version 2" text explicitly,
> as it's already covered by the SPDX-License-Identifier.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: If0a2690042a2aa0fca70cea601ae9aabe72fa233
> ---
>  mm/kasan/common.c         |  5 -----
>  mm/kasan/generic.c        |  5 -----
>  mm/kasan/generic_report.c |  5 -----
>  mm/kasan/init.c           |  5 -----
>  mm/kasan/quarantine.c     | 10 ----------
>  mm/kasan/report.c         |  5 -----
>  mm/kasan/tags.c           |  5 -----
>  mm/kasan/tags_report.c    |  5 -----
>  8 files changed, 45 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 950fd372a07e..33d863f55db1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #include <linux/export.h>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 248264b9cb76..37ccfadd3263 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index a38c7a9e192a..6bb3f66992df 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #include <linux/bitops.h>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index fe6be0be1f76..9ce8cc5b8621 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -4,11 +4,6 @@
>   *
>   * Copyright (c) 2015 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #include <linux/memblock.h>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 4c5375810449..580ff5610fc1 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -6,16 +6,6 @@
>   * Copyright (C) 2016 Google, Inc.
>   *
>   * Based on code by Dmitry Chernenkov.
> - *
> - * This program is free software; you can redistribute it and/or
> - * modify it under the terms of the GNU General Public License
> - * version 2 as published by the Free Software Foundation.
> - *
> - * This program is distributed in the hope that it will be useful, but
> - * WITHOUT ANY WARRANTY; without even the implied warranty of
> - * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
> - * General Public License for more details.
> - *
>   */
>  
>  #include <linux/gfp.h>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 4f49fa6cd1aa..c3031b4b4591 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #include <linux/bitops.h>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index e02a36a51f42..5c8b08a25715 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -4,11 +4,6 @@
>   *
>   * Copyright (c) 2018 Google, Inc.
>   * Author: Andrey Konovalov <andreyknvl@google.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index bee43717d6f0..5f183501b871 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -7,11 +7,6 @@
>   *
>   * Some code borrowed from https://github.com/xairy/kasan-prototype by
>   *        Andrey Konovalov <andreyknvl@gmail.com>
> - *
> - * This program is free software; you can redistribute it and/or modify
> - * it under the terms of the GNU General Public License version 2 as
> - * published by the Free Software Foundation.
> - *
>   */
>  
>  #include <linux/bitops.h>
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001171836.GA4156371%40elver.google.com.
