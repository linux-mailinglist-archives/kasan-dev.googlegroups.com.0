Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXEHV2BAMGQE4ALMGQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B463390C7
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:08:12 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id j194sf8050030lfj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:08:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561692; cv=pass;
        d=google.com; s=arc-20160816;
        b=IZo6WyfJhXT93EMRx9fPmCmuwhPxtGbWBoTxOOLuETuE8lgjquR2EQldHTV0kq2o92
         6h3CWE0rFjV0hqGbPhfWTNxfWoxPLdwZpzpU7X1wQq3s4z0xjSR+Y39hXjC+hcpAQ+ku
         ENavfd8fIlKO/0MmeesMS2JEXrQwgIWNnnk1ufTRiRzhR1qf7c2GvQTi3RgD45k8mzQm
         c9NnYnIXugTB0S5VSvfX76YjhY5kl7voMBemEzrZvxhZQyv8IleQ9kgHi1ugDaJeMZw+
         jlnefnlJI2bmtR76bvGEPjAZYp45kS7cufUc8PStlNAxt7jB4IeOg1V1t5gv2RgwYr1I
         /pbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zRN4PEGzoys2IaSZcKFumobZIqMoO6V+cepQZKKfy/4=;
        b=0/TTYXdJm2llJvIBcbEcmZzv5vsKuKdhYBqfXaXkENgExqcSoO5md+qG6hZ7KImXPi
         amw4euJ87CH6Jl09Ox8X2zQA/REtN5yQUvPsXV9xnxGUDGV5kWbB4fS1AT2aQ7MASDjD
         9d8H8m8u8+WRjrF8hk1UwB5O1f8s+YTJmr7QdGu4MN0dBvYrlwEsjk6joKBY1DcWja1d
         xh0wC0Rb4ujupuUzeIHiAQq6YOvm5SQgU758NMkK0uO4gmceMdx3KO1qQDTsnZZyxzhR
         D9hWiT57xZwOR12z+ApZIK1c4+U8zofIgP4E3Bczg7fh60E2ZeeG+KmPCvie4hN31M83
         U2Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lUp7M+Ii;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zRN4PEGzoys2IaSZcKFumobZIqMoO6V+cepQZKKfy/4=;
        b=BX83b1RNMb6CbNW6xOIkhZb23XQ13zuOafNj2MMq0En9HdKUKRHErnfxEm4tWSF+AR
         K66XWTNcpsCVYPZNYXpuXem7eFIlHfFLMvFPyUPdvpuJhpncD5+N7Cxvdih6MhPZmtHW
         YaQ6zlwRgXvwKGZg0jx4bJT1BwAZG7SM893++shTbiachgALSk0lYkMwnFsKYvQFrFm3
         T+onTI334iX0DrgqrpbJNkT3OjHgHXxyevifNiv9vLxoWG8tArdkrAg5MyDzrZO/yY1M
         Je9hy+imEBl5YbipymUXRM1Px1HiPSzkO18dBtuMfF31koDXr5za4xP1yJ9Qjn7Q02DZ
         GmFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zRN4PEGzoys2IaSZcKFumobZIqMoO6V+cepQZKKfy/4=;
        b=trN03Me0lxvtuAw7ifHMS5CJNQxSKfR0I7PLf+Y+bUCSOD09PIaboFbwXeUGCBIUIg
         KpjG9p6/i0rj3YbIypyOflBmUZE7O7/s3H04I91MxmKP2Xf2rIq+WQiJdpx6eBalM1tn
         hNtxhHDjsBSLL2XgD36NCGS4lJi/IZWyUA9WwSPvz08uc8wVny+FCOCnqiETo/KjRH5w
         HCuAy6yKpvnmingTC2bI44txNRu++C96rb1u6MnboEHtpiQX5FbzD9UPAGSyakYzHM5+
         pkGDMc6mv3Eg/ti4OElq+bmZY/1PbXa9iIbVezXxsTqA7+Ilzllq0z3VabeGReYOYLEg
         xFKQ==
X-Gm-Message-State: AOAM530tzPcGJV5sSNPl0uAU3wa9z/EvY5qQKDitu5IzpUTE53ZnUxIU
	giKCREHiMUC5YHsEFL5QWLs=
X-Google-Smtp-Source: ABdhPJxhbI2+2SOBHSJyUPIBicJ3CjRYlfoz4z3CoxtEIzSJRlazXsreWjZY/vaTNfsa3swnQjmOEw==
X-Received: by 2002:ac2:4245:: with SMTP id m5mr5892127lfl.168.1615561692479;
        Fri, 12 Mar 2021 07:08:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls3656345lfo.0.gmail; Fri, 12 Mar
 2021 07:08:11 -0800 (PST)
X-Received: by 2002:a05:6512:328f:: with SMTP id p15mr5660106lfe.628.1615561691320;
        Fri, 12 Mar 2021 07:08:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561691; cv=none;
        d=google.com; s=arc-20160816;
        b=OJHtpz1uhXfwHogA8oy0KfDwheszoev0yy3h0DXBZ0zfx56MvUWmSGmHgsROq33Euy
         T/CNbxg2jTmfIT7Pv10/TfUfxfXunjUySjF9A/TDl/tKmuRETM3WWh3nze+6kI2ndhDq
         PXOXRyP5tNOXfnGfK7jYBcEcssq3N8ze83XW3o3H2NZL9BDpVkD/+E77uk6S+nRQv2to
         tRN0bsvojF6hw/aEmiQVX1gk3i3BlOtKf/seKLbLJVtZT5FiJ6ueisTy16/r3lGQLLYP
         iHxG2piJzDtrzmtDYpnPObJdscCZ5G2IlK0cK/irdOOpSG7NFPa5MkCxugujWfTX6uDX
         wJ6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=11LkVFc2ai96+FS3xzLxLBdovdC4Bzzrs8ahU7qpmeI=;
        b=yYDd3mHH8EDaxxO3GBBeiWggCWsYzMu8Z3ddV5fBz//mSOg9hZhE5fkOHcQ/2IwiqH
         js25GyKmyf2sWpZq/WoFowRR0wmB7x+e+GlT0m3pKHRxKGa2sq45j1roK3uhUVIKg3w+
         HCMRHobzeN4kqzUJiUpL/VhoLv6yq+y+BFBVHD/d3XoWDdAEQ/Mu/fPsZGvERskQcB0e
         A8cAfHoKEWpEkXoypPD/0aniHDVXVn7wAdA/Ld365YvlmPuBgZWQY6p1nFF4SARo/Gub
         ww3IMX27DYKmNVHePQS1A0DajauvcTgaxxx1ggeBLmb2IkVzJTgrrvwNg1XCgRUtzGI+
         LNUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lUp7M+Ii;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id q3si281133lji.2.2021.03.12.07.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:08:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id c76-20020a1c9a4f0000b029010c94499aedso16007656wme.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 07:08:11 -0800 (PST)
X-Received: by 2002:a05:600c:289:: with SMTP id 9mr13639929wmk.135.1615561690926;
        Fri, 12 Mar 2021 07:08:10 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id w131sm2400544wmb.8.2021.03.12.07.08.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 07:08:10 -0800 (PST)
Date: Fri, 12 Mar 2021 16:08:04 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 04/11] kasan: docs: update error reports section
Message-ID: <YEuD1Ghn+5bf0TJO@elver.google.com>
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
 <3531e8fe6972cf39d1954e3643237b19eb21227e.1615559068.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3531e8fe6972cf39d1954e3643237b19eb21227e.1615559068.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lUp7M+Ii;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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
> Update the "Error reports" section in KASAN documentation:
> 
> - Mention that bug titles are best-effort.
> - Move and reword the part about auxiliary stacks from
>   "Implementation details".
> - Punctuation, readability, and other minor clean-ups.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 46 +++++++++++++++++--------------
>  1 file changed, 26 insertions(+), 20 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 46f4e9680805..cd12c890b888 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -60,7 +60,7 @@ physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
>  Error reports
>  ~~~~~~~~~~~~~
>  
> -A typical out-of-bounds access generic KASAN report looks like this::
> +A typical KASAN report looks like this::
>  
>      ==================================================================
>      BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_kasan]
> @@ -133,33 +133,43 @@ A typical out-of-bounds access generic KASAN report looks like this::
>       ffff8801f44ec400: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
>      ==================================================================
>  
> -The header of the report provides a short summary of what kind of bug happened
> -and what kind of access caused it. It's followed by a stack trace of the bad
> -access, a stack trace of where the accessed memory was allocated (in case bad
> -access happens on a slab object), and a stack trace of where the object was
> -freed (in case of a use-after-free bug report). Next comes a description of
> -the accessed slab object and information about the accessed memory page.
> +The report header summarizes what kind of bug happened and what kind of access
> +caused it. It is followed by a stack trace of the bad access, a stack trace of
> +where the accessed memory was allocated (in case a slab object was accessed),
> +and a stack trace of where the object was freed (in case of a use-after-free
> +bug report). Next comes a description of the accessed slab object and the
> +information about the accessed memory page.
>  
> -In the last section the report shows memory state around the accessed address.
> -Internally KASAN tracks memory state separately for each memory granule, which
> +In the end, the report shows the memory state around the accessed address.
> +Internally, KASAN tracks memory state separately for each memory granule, which
>  is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
>  memory state section of the report shows the state of one of the memory
>  granules that surround the accessed address.
>  
> -For generic KASAN the size of each memory granule is 8. The state of each
> +For generic KASAN, the size of each memory granule is 8. The state of each
>  granule is encoded in one shadow byte. Those 8 bytes can be accessible,
> -partially accessible, freed or be a part of a redzone. KASAN uses the following
> -encoding for each shadow byte: 0 means that all 8 bytes of the corresponding
> +partially accessible, freed, or be a part of a redzone. KASAN uses the following
> +encoding for each shadow byte: 00 means that all 8 bytes of the corresponding
>  memory region are accessible; number N (1 <= N <= 7) means that the first N
>  bytes are accessible, and other (8 - N) bytes are not; any negative value
>  indicates that the entire 8-byte word is inaccessible. KASAN uses different
>  negative values to distinguish between different kinds of inaccessible memory
>  like redzones or freed memory (see mm/kasan/kasan.h).
>  
> -In the report above the arrows point to the shadow byte 03, which means that
> -the accessed address is partially accessible. For tag-based KASAN modes this
> -last report section shows the memory tags around the accessed address
> -(see the `Implementation details`_ section).
> +In the report above, the arrow points to the shadow byte ``03``, which means
> +that the accessed address is partially accessible.
> +
> +For tag-based KASAN modes, this last report section shows the memory tags around
> +the accessed address (see the `Implementation details`_ section).
> +
> +Note that KASAN bug titles (like ``slab-out-of-bounds`` or ``use-after-free``)
> +are best-effort: KASAN prints the most probable bug type based on the limited
> +information it has. The actual type of the bug might be different.
> +
> +Generic KASAN also reports up to two auxiliary call stack traces. These stack
> +traces point to places in code that interacted with the object but that are not
> +directly present in the bad access stack trace. Currently, this includes
> +call_rcu() and workqueue queuing.
>  
>  Boot parameters
>  ~~~~~~~~~~~~~~~
> @@ -214,10 +224,6 @@ function calls GCC directly inserts the code to check the shadow memory.
>  This option significantly enlarges kernel but it gives x1.1-x2 performance
>  boost over outline instrumented kernel.
>  
> -Generic KASAN also reports the last 2 call stacks to creation of work that
> -potentially has access to an object. Call stacks for the following are shown:
> -call_rcu() and workqueue queuing.
> -
>  Generic KASAN is the only mode that delays the reuse of freed object via
>  quarantine (see mm/kasan/quarantine.c for implementation).
>  
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEuD1Ghn%2B5bf0TJO%40elver.google.com.
