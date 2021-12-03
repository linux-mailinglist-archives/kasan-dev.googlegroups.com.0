Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLE7VCGQMGQEWYFONGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 91683467784
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 13:38:04 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203sf1307478wms.6
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 04:38:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638535084; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyxz0xdh7abCbRwxyQBsugHZ/IzUcmzyeZxkXn2cla7fYSxBnS2DtQUYQTmp7GzoVL
         98C3HsTHNE6x4a20hY++isEWH9YbdCC83d7We1rWUbvH4UKiVuo5/R683acaqJa+LsPN
         GNQRcanXrdJoxwzpGQFf6af3coUwrmrtmxLiZ2KX1qaaT2oQm5ITYfUB4CA64prWF9HK
         2EajDrjTw4CC0TkRCoyv/S1ziv6J10IwBLD13uGuUcdoYIff5uEl/zL13hpWyn0Hj8lT
         IkQv7ZxyFF/Ipcq83O6vwHlWbAVdz63XIt7w69+IPyrEDNtNLDXIja3EmE+TLXbwPyPu
         +jkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fe0uCDkGtzRt0dE+q5f8AWOD5wDnz4XvgnWUlm36Gi8=;
        b=EoNruBi17QSEp+lNRQIqlw9KdnBV5CyV4gWpV6zUWem+rBlafv2VoKnJzY7Z14fT8e
         yi/HLRtI8BRksFvWF+LtRKlhOPGL3rjfa2hbbnpa12Mi6FqxObKIonBL0g4+0kond5vk
         yBa3FbwSxbT+0a9N8LkOf/1DsfCgYdOg4XoOsHknPZPHRu/dOJ9sCpNOKXX+LS7/aKyp
         6UBz+Vd1e2Qt6ZKm890ZJ8SQKQziuCd6jERLittEkwmG1y9cZTuOVOOsGItLly0h6dKp
         gp3QlQRayvBMOz+qJm/vJT0o1xnrIgc2MfrtcCM+WnUunN6XCsSqOcWfhjft1Y9o13m+
         yefQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y5fbPakt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fe0uCDkGtzRt0dE+q5f8AWOD5wDnz4XvgnWUlm36Gi8=;
        b=mExIHFyHwaMMRcHSU8lwjLbPjLpiLiME6pC6c34Xm1TAdjQxa2XiS8ExXB+MUVWwlD
         cnSSKhB0hattGa/jYMd/HIL6joBkVYhwC4f+C/dEjVoKwDhf72Xa+KDpPokChREWWrDs
         iwxC5kqeISgvE1s0YuliCmR9wkQ/2wGURDkzYzV+R6KHjIIcC52wzbEkYpZ/zPwlKzyi
         A6gc4LdoK6vMYEUdoiFJZr43KEXMDGvhEsG/1DPTcq370I/cA6TA3tkDF71hErFCBPiG
         9YO2Ms44WNz11N0Zt2VE7+spkmotII6A2/hCjQUhmIHeeQd4ENvapWLE1+XZejqgv6SO
         EZnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fe0uCDkGtzRt0dE+q5f8AWOD5wDnz4XvgnWUlm36Gi8=;
        b=l3C5wA4JMrct44cbNPUFgAhyYWjyT9wsS1opPjQ+PYUd1Zesgf4PJMq5AL1gz97kK5
         glwvU+vQSvbDZ5mYCMiwFg0FxHvHAWL8l1qU8FSAPPHucCsfGmwW0ST0rx8FPlofMrrF
         0wag5xZ57kudLlFyBBPbLH9KRK8mKG0wM1svGo1cJYl25sGCYcFtlcCFWNF2CzA3BriD
         p+nqwA+OkVO/pIl19AFptYGxDmgjmFrPtk7Mk1HtGJNRvrumks8MGIwIbw6T/khKemFt
         IheXUBNve+C7NWmKxxwWMQKJApfdq/cbquS29BSG2b3xSiZ+xze/nmy55SjN0k6uLr4I
         Bd0Q==
X-Gm-Message-State: AOAM531fHIVkEO5tIHMi+VmLb0uF1zp2G1MiWbg5ivaeTkWgXlIg1DOv
	z8udr4Sy+nfAsW0p/Dz4Gdk=
X-Google-Smtp-Source: ABdhPJwmQwmKpxZVmHmzIXvT+SsN66iLzvuFY6+Ibri+RAK/Azj1KbtGmbb6b7QmW83KR6u6Vym9Pg==
X-Received: by 2002:adf:cc91:: with SMTP id p17mr21464146wrj.589.1638535084339;
        Fri, 03 Dec 2021 04:38:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls460926wro.2.gmail; Fri, 03 Dec
 2021 04:38:03 -0800 (PST)
X-Received: by 2002:adf:df0b:: with SMTP id y11mr21054839wrl.181.1638535083365;
        Fri, 03 Dec 2021 04:38:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638535083; cv=none;
        d=google.com; s=arc-20160816;
        b=hPK1NSLjRlXoCSZ1v3Chl1hE8lPT5B8Q/78aPdC7dEvOuLzI1KlEvd7Yk9vWCPOqRC
         NZqWkU9jXzPM+seQ/MSM/XXOPqfH6japyyLBlPbXg/iHASUmU8NraFSpDnXYGEQLfStp
         a8XvkQeVN8RGeDSn9iWoiKGTLeNcX5kW6+mzol0lw9RN8ftOSywzVmTv76QDBaPN5gxj
         aJkuvSRrXcEZDoYOt7ujbzyqVikj0DjGMkWamqS0+oAT3iG9VWuamZo5R0aOl5ER/aVN
         EsWV5lmniWB6I92L90Lqw3tmQ4xxLrZpKkxQg6b3popx6qSiSgPTp5WYa6oNqUI5AR7b
         SJGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JhF4DJloD8iRgaeJPijyIb6Lv1uWFcqJB9vbZ2tw7/U=;
        b=WQldmOdHCJ37kjfKq6rYs1dRwVD+ieJXC07h+1DfFRKhYH0ea/mUGGL8MvoghyX9yl
         KewF+h8d2AFNsJiOMPM/xeDdRnGp+ow7ODXNiuiqWaWDDmjdVgxH8CE30XcRzq/DG4RW
         847cAOH+BvX9JZQCMZhJm7Ifllgw+EWGAU1mbuvNXvcjmVeztORn703d3cFdpy5DV4SJ
         FCa8EY0cUpUbfpnid5agIPeWhqcJaDN8n11+a/CF1389puUlX17sOM785jrXj3CC9mhv
         HsQubX6Nvt+kkvLxJhgvQxlLd6ljmr2ropokRsKkng/LkYJjSBNdsEJTbihAUKpIs9m5
         XFpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y5fbPakt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id z64si603731wmc.0.2021.12.03.04.38.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 04:38:03 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id y196so2226453wmc.3
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 04:38:03 -0800 (PST)
X-Received: by 2002:a7b:c3c6:: with SMTP id t6mr828526wmj.119.1638535082851;
        Fri, 03 Dec 2021 04:38:02 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:cb5f:d3e:205e:c7c4])
        by smtp.gmail.com with ESMTPSA id q26sm2513762wrc.39.2021.12.03.04.38.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Dec 2021 04:38:02 -0800 (PST)
Date: Fri, 3 Dec 2021 13:37:56 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 23/31] kasan, arm64: allow KASAN_VMALLOC with SW_TAGS
Message-ID: <YaoPpPAKi0/OZB2f@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <f90dfb0c02598aab3ad1b5b6ea4a4104b14e099d.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f90dfb0c02598aab3ad1b5b6ea4a4104b14e099d.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Y5fbPakt;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
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

On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> vmalloc support for SW_TAGS KASAN is now complete.
> 
> Allow enabling CONFIG_KASAN_VMALLOC.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

This change is small enough that I would have expected the
lib/Kconfig.kasan change to appear in "kasan, vmalloc: add vmalloc
support to SW_TAGS" because that sounds like it would fully unlock
core KASAN support.

However, the arm64 change could be in its own patch, since there may be
conflicts with arm64 tree or during backports, and only dropping that
may be ok.

I've been backporting too many patches lately, that I feel that would
help.

> ---
>  arch/arm64/Kconfig | 1 +
>  lib/Kconfig.kasan  | 2 +-
>  2 files changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index c4207cf9bb17..c05d7a06276f 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -206,6 +206,7 @@ config ARM64
>  	select IRQ_DOMAIN
>  	select IRQ_FORCED_THREADING
>  	select KASAN_VMALLOC if KASAN_GENERIC
> +	select KASAN_VMALLOC if KASAN_SW_TAGS
>  	select MODULES_USE_ELF_RELA
>  	select NEED_DMA_MAP_STATE
>  	select NEED_SG_DMA_LENGTH
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cdc842d090db..3f144a87f8a3 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -179,7 +179,7 @@ config KASAN_TAGS_IDENTIFY
>  
>  config KASAN_VMALLOC
>  	bool "Back mappings in vmalloc space with real shadow memory"
> -	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
> +	depends on (KASAN_GENERIC || KASAN_SW_TAGS) && HAVE_ARCH_KASAN_VMALLOC
>  	help
>  	  By default, the shadow region for vmalloc space is the read-only
>  	  zero page. This means that KASAN cannot detect errors involving
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaoPpPAKi0/OZB2f%40elver.google.com.
