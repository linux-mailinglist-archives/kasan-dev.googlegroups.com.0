Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU5G5GJQMGQEQIZ4FVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E03652147B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 13:58:12 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id e8-20020ac24e08000000b00473b1bae573sf7165939lfr.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 04:58:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652183892; cv=pass;
        d=google.com; s=arc-20160816;
        b=aB1VCt9vU9yX6voa3vFKA26gsYw8pcrsARUqmlrcv6cPPK3vc1NmkqUBC/L322zUrv
         P63s0VmnAFga+tEvFc6osjDHFnU1anK7bQVDCjdDxeXytcY6KkCkMvdjhPvriZrsIUzB
         qhZ61NlO3+SKKu6+H0TMlFwdGP25eFdNKu3Z+1Dn+6GZiYtREdT5MsW/OOe4NWkNz1X/
         hVGA73OoCURC58QDJQrftDjQT9GhORWa6lHHjRvpfP7zkN2k2BTUJdsNtEcTHWwLLN5M
         cysUX0rqECUdGGZyIO6gzhOl0e8SRpwdsslyeAsjfICSa50QPd7OKP6B/cquYTvBL8+Y
         OCxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5o6Bow47yPNG7ZaHsQh2+l/Mu+S5sXhlGcFdtp6RuJ4=;
        b=VIf2wbn4ZATTHARiDUBBHhtMpgtuaMR8/7Cxm0laQx2ZRTpRVQERgIv+V/WKlMCWDW
         w7p7NzVkdCMiiRy2d9I8PXrYGqHdUwZ3XmuvqI37D8EdA1PDiF+JTidGbIiJ+ZXE+zHo
         P/wiXqPkTPoY2/RMo4E+gv07+sfKjRYlJGyhmFsz952JB5HA6wXMtkwBa0dA3xk1xRdM
         pWrScFgW/gXrqBW9qpAPMDuHnHaUB7O75FafNClBtFn3AjzJq0SXocqeH37jfo0ABegd
         oQllM789fHPoBUpBXECswHSu35xLe733VkVyG7ycTuJ1sbVfYNC8y9jrMZ/bWbk0LL7Y
         KfAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R6G+qM4k;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5o6Bow47yPNG7ZaHsQh2+l/Mu+S5sXhlGcFdtp6RuJ4=;
        b=pyVR3tLM2hXebh4ry1AIxNjavxzOQfUl/ql7/zYGPY1fKVszqEBUO568xFCu7mwzbs
         owvo93WqUUyf07+YCRZSPapI8n0qOl887mDekmVUmxX7cNEgxoa5MExw4BqHOQ/xKmFO
         gN7RlRxg5VvDlaEFqJsaFn/WHETo7HhD/v3jGHvVycdh6l5wo0TFsmfyUlawXCFxSR9o
         VPZkI6jE/ov9gQ+WDExc0B5Phq4t2CUU8OYMCpu76PlYTkwH/jwVwvrZ0LPLTem1p5rB
         XXSnk12L7ZvBy8+aK9tcQGiJPTc8ChSf3SIjnD+bgZJ9i/W/0jzXIDBQ/f8HAyg+/abM
         9llA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5o6Bow47yPNG7ZaHsQh2+l/Mu+S5sXhlGcFdtp6RuJ4=;
        b=FsHirHoxEAvWcrcRiJk2r/qe+Uu714OmD5MDSs8h9boGrIkyfAnRYLqvbX8j8cdV+o
         +uJZEXbcevSWW5wMvsMVPx0DWAdj9fb67bTA0EbkaLR65U6uBLoLzZA75I8tr7s8RZOp
         PCubT5RpnuhgRPiI2oXpqTiSnnXPwBgjJqWU27RUfRCeXB6NnDIQVI8xGp1338fiJrNj
         IckQYUJvs9GGbVQCyHBCCL2zrCusa+LxGPnUNfPijfWYtzBom2IeQfxujbWWqgONjE9M
         1NrVqoTtFLLdRZTomy2rCH2riLw2MPIS1ZVrqR2rBzD4+Mxta6q4mPbiifBk66q8BzdG
         IS8Q==
X-Gm-Message-State: AOAM533J4aChHkXdDGiW6ToSdAhum2QhXaLM/i0c3ypxn0f6EoN2MAJb
	bN9y+Ine5fkoJ3s2yvFsAjo=
X-Google-Smtp-Source: ABdhPJw5UoZF8aNinva8B9m9Qou1hvuw89pQuX16sV1Dn12Ho+KM84sFXiBIHmZNvm5mH11jiUSRzg==
X-Received: by 2002:a05:6512:3b10:b0:473:b6bf:88b1 with SMTP id f16-20020a0565123b1000b00473b6bf88b1mr16399702lfv.277.1652183891426;
        Tue, 10 May 2022 04:58:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf11:0:b0:24a:fdc1:7af4 with SMTP id c17-20020a2ebf11000000b0024afdc17af4ls3516844ljr.1.gmail;
 Tue, 10 May 2022 04:58:08 -0700 (PDT)
X-Received: by 2002:a2e:96d8:0:b0:24f:3087:a09c with SMTP id d24-20020a2e96d8000000b0024f3087a09cmr13891318ljj.402.1652183888472;
        Tue, 10 May 2022 04:58:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652183888; cv=none;
        d=google.com; s=arc-20160816;
        b=NTbtIaVis0Fsjx00zetbIXYJ8ptkvtVUZScDnJSdtxi50++LWJEFFXmvXFqxwIxbIs
         Fq2NjHZclSEKCvzmpjkNj8YAnYHWYqSNQTSGSHUIEJnVz0XRtXLKcV7oF2pHMlRZJOgx
         3aYETIwLUnmTx3a+DlI+0VzIhU0xq87+ysC9Y5aIhe5SAhHxrYg6ikrQfVhQeNTqIU0Z
         2imIPhED7SlnzViVJATuj6e4e3ex9mCraliaa40ygU3qutX95W2i0VVH9Dx9BqIqlg0S
         wKMp45UissSVT+J++inIEEsB7iX5/o2x/BocaD6iZ6bpcmy0iTR0FUWqGuMeGfQB9PGY
         Dl+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fGBBzJMSY58ZqJQmQlHeFlOhEyr8JQc2d5kb0lSfqro=;
        b=lEsz61wGQAGdWZjL1tZQuCE2+5TEQSUw8vTkuFwB2/3pcFlOy70fgr1yAWajk8Dx9i
         hU8VUuxCi7iprmwxQd8+e3EWysY4lMuc2l+EhZYZdjGkzIo78EkxKrA4+hhR6U4y8iXq
         9KhKvHee5XlxXGCwAqObSOJYjgQGyqEHFAaLX9qoNfmdkYnkADNctXaaES/oUiTbKrzK
         OLIWnbI4PeEigStk3N6P/O5HeKu0nnrnysq0DlZO8OoMubYliJn7nkcJ7vWpR1OUkPjs
         +wL8BC8f8h0Z+ZvECW6RTaP7NHgK96DLk2KrJJnfM/v/zN9P8UeLZCoSU4m/ejwTJhrr
         tUpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R6G+qM4k;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id b7-20020a056512070700b004720a623d80si786424lfs.7.2022.05.10.04.58.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 May 2022 04:58:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 125-20020a1c1983000000b003941f354c62so1280309wmz.0
        for <kasan-dev@googlegroups.com>; Tue, 10 May 2022 04:58:08 -0700 (PDT)
X-Received: by 2002:a05:600c:220e:b0:394:2695:ce9b with SMTP id z14-20020a05600c220e00b003942695ce9bmr21325260wml.64.1652183887631;
        Tue, 10 May 2022 04:58:07 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:640f:aa66:3ec8:cbb6])
        by smtp.gmail.com with ESMTPSA id o23-20020a5d58d7000000b0020c635ca28bsm13557898wrf.87.2022.05.10.04.58.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 May 2022 04:58:07 -0700 (PDT)
Date: Tue, 10 May 2022 13:58:01 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 2/3] kasan: move boot parameters section in documentation
Message-ID: <YnpTSS3JTR4e9G0b@elver.google.com>
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
 <ec9c923f35e7c5312836c4624a7f317dc1ee2c1c.1652123204.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ec9c923f35e7c5312836c4624a7f317dc1ee2c1c.1652123204.git.andreyknvl@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=R6G+qM4k;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Mon, May 09, 2022 at 09:07PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Move the "Boot parameters" section in KASAN documentation next to the
> section that describes KASAN build options.
> 
> No content changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 82 +++++++++++++++----------------
>  1 file changed, 41 insertions(+), 41 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index aca219ed1198..7f103e975ac2 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -94,6 +94,47 @@ To include alloc and free stack traces of affected slab objects into reports,
>  enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
>  physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
>  
> +Boot parameters
> +~~~~~~~~~~~~~~~
> +
> +KASAN is affected by the generic ``panic_on_warn`` command line parameter.
> +When it is enabled, KASAN panics the kernel after printing a bug report.
> +
> +By default, KASAN prints a bug report only for the first invalid memory access.
> +With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
> +effectively disables ``panic_on_warn`` for KASAN reports.
> +
> +Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
> +parameter can be used to control panic and reporting behaviour:
> +
> +- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> +  report or also panic the kernel (default: ``report``). The panic happens even
> +  if ``kasan_multi_shot`` is enabled.
> +
> +Hardware Tag-Based KASAN mode (see the section about various modes below) is
> +intended for use in production as a security mitigation. Therefore, it supports
> +additional boot parameters that allow disabling KASAN or controlling features:
> +
> +- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
> +
> +- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
> +  is configured in synchronous, asynchronous or asymmetric mode of
> +  execution (default: ``sync``).
> +  Synchronous mode: a bad access is detected immediately when a tag
> +  check fault occurs.
> +  Asynchronous mode: a bad access detection is delayed. When a tag check
> +  fault occurs, the information is stored in hardware (in the TFSR_EL1
> +  register for arm64). The kernel periodically checks the hardware and
> +  only reports tag faults during these checks.
> +  Asymmetric mode: a bad access is detected synchronously on reads and
> +  asynchronously on writes.
> +
> +- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
> +  allocations (default: ``on``).
> +
> +- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
> +  traces collection (default: ``on``).
> +
>  Error reports
>  ~~~~~~~~~~~~~
>  
> @@ -208,47 +249,6 @@ traces point to places in code that interacted with the object but that are not
>  directly present in the bad access stack trace. Currently, this includes
>  call_rcu() and workqueue queuing.
>  
> -Boot parameters
> -~~~~~~~~~~~~~~~
> -
> -KASAN is affected by the generic ``panic_on_warn`` command line parameter.
> -When it is enabled, KASAN panics the kernel after printing a bug report.
> -
> -By default, KASAN prints a bug report only for the first invalid memory access.
> -With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
> -effectively disables ``panic_on_warn`` for KASAN reports.
> -
> -Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
> -parameter can be used to control panic and reporting behaviour:
> -
> -- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
> -  report or also panic the kernel (default: ``report``). The panic happens even
> -  if ``kasan_multi_shot`` is enabled.
> -
> -Hardware Tag-Based KASAN mode (see the section about various modes below) is
> -intended for use in production as a security mitigation. Therefore, it supports
> -additional boot parameters that allow disabling KASAN or controlling features:
> -
> -- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
> -
> -- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
> -  is configured in synchronous, asynchronous or asymmetric mode of
> -  execution (default: ``sync``).
> -  Synchronous mode: a bad access is detected immediately when a tag
> -  check fault occurs.
> -  Asynchronous mode: a bad access detection is delayed. When a tag check
> -  fault occurs, the information is stored in hardware (in the TFSR_EL1
> -  register for arm64). The kernel periodically checks the hardware and
> -  only reports tag faults during these checks.
> -  Asymmetric mode: a bad access is detected synchronously on reads and
> -  asynchronously on writes.
> -
> -- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
> -  allocations (default: ``on``).
> -
> -- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
> -  traces collection (default: ``on``).
> -
>  Implementation details
>  ----------------------
>  
> -- 
> 2.25.1
> 
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec9c923f35e7c5312836c4624a7f317dc1ee2c1c.1652123204.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YnpTSS3JTR4e9G0b%40elver.google.com.
