Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEIV2BAMGQEFTWMX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A7153390CF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:09:45 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id m71sf8011419lfa.5
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:09:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561785; cv=pass;
        d=google.com; s=arc-20160816;
        b=q7l+gmAxd1bdmhH4I4qqEYY26U7ycn7w5jzZIG+ayXojxbSIV7ZpDPKmcl7bnzgUAf
         biS9q5YEIPCihRNrrToF9tvQcPC54zO9CBKGViZhaJ69mhfjKZM2HTrzFGlWbhlqKHOw
         a3jt7gFtWNrfuoo3RgiBaQ5Inp20hIDfcZp3p5mbXnAoKcO3eGaZx0onNC+pahZqYbgS
         gBzxelA2fooPqynZNxELg2GiseleV3SNBvZuDapjErfAtvp8xpq532zIwKANwAM0rRop
         TnIfqcDaeU2yq0l6aDg3xoyk9Wy+6oQCA/4Nwa4+lFrVPD51i7r0WRc1DHjyvfeQHi5i
         Ib2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=FsBL9WwRNc0H/592m06rWBuXcvuV/1q4Hml0/auPP54=;
        b=TpSbCzK+d7GL+wYUFb+sZmxZSV0az3qxhOmTyfoWj3JZ1bY5vxiyxdsBPMava3uFpo
         6pR5M39Goj42iicyk+gwQs5UuhQ1lrm/cYFcVlbt2Gr/OAG5x/HIGGyWn4lsX+TBUv8/
         p6DyxZyoxBkBgpAWhKTn7V7cbE7DPO7l+Mfo1evKa8cJ05As/4suj3IAw+mTabvmReMk
         A6ryeSaJieqcCvtkQZ9mCCgFbtuyrME31x/rz1qIyz4KmtTfao3eUShCwXY4Nz/F9C1x
         OY3QmdEgHLbliF+9yRgSkqRw7YfQ3vIIAvj7ficc7Ur1ZKz+YUWMjTP3WvxOw3wZcNu6
         QgMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GN9pLSpi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FsBL9WwRNc0H/592m06rWBuXcvuV/1q4Hml0/auPP54=;
        b=Vryw9gxCcMqWqMUol1vblZQAF+RJSYI958Kje7phd8gHhHPh38bJpXF9gQIlp/+xt7
         10f0BHk/9t1Snwk3U/UZue3ZtRwmZHii9YX0Ac3ZxWKYzbaq2Jzdufq2xiYtegZfHAnW
         4D4cgNiFQ13I1kdI96AUafGOtqSIpHNGPDG30EiPv1PUXiZ7yDBvm6D2PcBUThQi2lj1
         rxHjlGBrtUJ1nx7rNjpzb+Acqjw4a9+ybpWcpCSi+PtZS7E6UuzOCsHNLtafQgJRdcu/
         aq21vbhOtzu6TVtNKm03xPEvwpt1XxAcDQVv39lg6aGU7/6lqmrohg+TK8u+SauN9txa
         2Xfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FsBL9WwRNc0H/592m06rWBuXcvuV/1q4Hml0/auPP54=;
        b=Awnz4xooaA90OXTt6mKj7j7oR3ZiyYmmldV4bV7EWGUDwokkvdI5w15R+VjyElnPzy
         Aoh3U06uKPf9DxLQrq2MqDveFnOZkDgT2TpP0eJ5+cATz53sQ/tdc/TBH66amplEjpYy
         c8Ws/fRmBzTIw7g5j7PD1yqNwVxZQaqyXn3zToaRly1FLltoGZuG+v9NdtfzyS87csTI
         KPEfZfYWFn8sj2bp1SaN3ZILtpv7KUOs0y3dtqZeOMzJsyEaIgzpFD17HohQlAupAVVd
         2+wMIeKLAE/8obyLpDG3H8ad9VygDYqwIc/x5PVQkfQsfX7GYdreeEx4Q4NiWTTMVZB1
         bC3g==
X-Gm-Message-State: AOAM531xwNYTeriflZtYXuNuxUClKxtSYS2cy1rT4n8TGABo2QtgheF+
	Pfqkv9ffWx5t9HB8TKgGM0s=
X-Google-Smtp-Source: ABdhPJyAEjQYQcT3bPBC/2s48iENrwqi+XiRQpsJ3olxP/5l0y273Znd2F0izWlJpfmXROKhpz3rVg==
X-Received: by 2002:ac2:5b5a:: with SMTP id i26mr5635944lfp.182.1615561785053;
        Fri, 12 Mar 2021 07:09:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8503:: with SMTP id j3ls2017616lji.6.gmail; Fri, 12 Mar
 2021 07:09:43 -0800 (PST)
X-Received: by 2002:a05:651c:1206:: with SMTP id i6mr2682322lja.426.1615561783861;
        Fri, 12 Mar 2021 07:09:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561783; cv=none;
        d=google.com; s=arc-20160816;
        b=cHVmBEv4YHXJuo6h80n36vE1RwnHdHVDqV9hiejQ3Xl66LNe76QOh/BoqwAPFTRUuK
         yMRy8kBqu042NlBkawNnXDEeMUm/zkQ+pfVOeXpIoZIVpFxUZVg0d4aFTV6SzQ84dbU7
         TDHkNYEDUs1kJp7O1Aa0YLg00eHFMUfsVH/34lmPvfhcaVxaJMMF6gDvRZDvF6O9EcEp
         Dosr4z8eeMW/7sAQierKIxnMtMZ57LdWZdpzw+B4JHK7xaK/drVtgyKVXqwVHPC2LvVS
         J9Y/J1EcqiyQyC5cXmtDPkjfpmq1nE6/tGkE4Ggpfrw7vaRtY+j1MX7D3AEgDAfgWpZk
         45uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8Z7mWKRFjAgMHFPpQ+htbK5SeLG117LB/ZqDOLBkzko=;
        b=r5bXmDOcXnYTjbLcXGLcblMYlBnxNgUtSCowUeMKss1+x5rg4WN1F0o3gSFXzhKpoa
         Qmfp+oo7kcH3IYPR05hwCbhiNURmH7CSerwaGjiVzbGvKdjgDS97724oTC3cxUyBzOKn
         7okemHybBGJIby7yTOF9i79IFrNTpo90Ef9WLbaM2zO6U0J0dJ8qagOK2vtFwLSRArPB
         yK35XMpdVv7GOXXczb2Im2A3QpTtc/H7PHSM4SEx0Q2Sd/bX+T63+UQMCIMDBmv+LmJG
         fwWJN+/XIeP5/YC9OZvsRhn37+OzmGExA0sGBxK33TrZTEmL6gDvhsGV/i4lz5TiHVqA
         v90g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GN9pLSpi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id h2si69975lja.3.2021.03.12.07.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:09:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id v4so1963414wrp.13
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:09:43 -0800 (PST)
X-Received: by 2002:a5d:6049:: with SMTP id j9mr14291212wrt.117.1615561783490;
        Fri, 12 Mar 2021 07:09:43 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id e8sm2374802wme.14.2021.03.12.07.09.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:09:42 -0800 (PST)
Date: Fri, 12 Mar 2021 16:09:37 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 08/11] kasan: docs: update HW_TAGS implementation
 details section
Message-ID: <YEuEMajjvbyByzJA@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <ee2caf4c138cc1fd239822c2abefd5af6c057744.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ee2caf4c138cc1fd239822c2abefd5af6c057744.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GN9pLSpi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Fri, Mar 12, 2021 at 03:24PM +0100, Andrey Konovalov wrote:
> Update the "Implementation details" section for HW_TAGS KASAN:
> 
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 26 +++++++++++++-------------
>  1 file changed, 13 insertions(+), 13 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 5873d80cc1fd..2744ae6347c6 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -270,35 +270,35 @@ memory.
>  Hardware tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>  
> -Hardware tag-based KASAN is similar to the software mode in concept, but uses
> +Hardware tag-based KASAN is similar to the software mode in concept but uses
>  hardware memory tagging support instead of compiler instrumentation and
>  shadow memory.
>  
>  Hardware tag-based KASAN is currently only implemented for arm64 architecture
>  and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
> -Instruction Set Architecture, and Top Byte Ignore (TBI).
> +Instruction Set Architecture and Top Byte Ignore (TBI).
>  
>  Special arm64 instructions are used to assign memory tags for each allocation.
>  Same tags are assigned to pointers to those allocations. On every memory
> -access, hardware makes sure that tag of the memory that is being accessed is
> -equal to tag of the pointer that is used to access this memory. In case of a
> -tag mismatch a fault is generated and a report is printed.
> +access, hardware makes sure that the tag of the memory that is being accessed is
> +equal to the tag of the pointer that is used to access this memory. In case of a
> +tag mismatch, a fault is generated, and a report is printed.
>  
>  Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
> -pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
> +pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
>  reserved to tag freed memory regions.
>  
> -Hardware tag-based KASAN currently only supports tagging of
> -kmem_cache_alloc/kmalloc and page_alloc memory.
> +Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
> +memory.
>  
> -If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KASAN
> -won't be enabled. In this case all boot parameters are ignored.
> +If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
> +will not be enabled. In this case, all KASAN boot parameters are ignored.
>  
> -Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
> -enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
> +Note that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
> +enabled. Even when ``kasan.mode=off`` is provided or when the hardware does not
>  support MTE (but supports TBI).
>  
> -Hardware tag-based KASAN only reports the first found bug. After that MTE tag
> +Hardware tag-based KASAN only reports the first found bug. After that, MTE tag
>  checking gets disabled.
>  
>  Shadow memory
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuEMajjvbyByzJA%40elver.google.com.
