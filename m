Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUUVWBAMGQEII3SUPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6E99338ADD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 12:02:54 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 6sf9611449ljr.11
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 03:02:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615546974; cv=pass;
        d=google.com; s=arc-20160816;
        b=N9QGtlWGVlJVcaX41X7AKtO2XKa9phx5hifErW9Kc0nhITqyAWXj6eiu8I/VUNdcVI
         Taq+3xVSECQe3LTx0nHgYss3jDo0CgZlLYRMTahCuObvjlhl1VqytuZOFcJz3YzinJx0
         awPr6omCsQgwbLYWKHOOkipN8fJdFMD0d3AOClyR64VHlui2yhOA80tvlu/bnU24+sf0
         PvGwsWoRDLFGPikfw3bz+qIwTRes7nWt390kwk8sB5mzib1/GT0faEkJybP+ZzneDkgQ
         H6QvhCeRIqPCZJux7hRaDCu4WKJ8l7D2ZB2+W5DR0PlHoz6QEYbmXYq8PhJTN4gUKnjB
         uj+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=N7xxhkHekJ2HM39DwO2tdC0h2GKA30PhF8WOx65mj00=;
        b=hqHKjKbkwGSrlFt4HKC/+tzpkKpBn/wNazPSsRONufPYzRzrGb9VFTqHMJdLIP4dYL
         EbFfsxb4m0yca3dW5UM3hVJ2WJpF0+FLifohpZig0lqsUK4/pOtkg+S8hTZ1Fffwu5dA
         SJNaRTXqvOr1ucMabq4D6Z3qFZPfZJFMPoSlL3bRmVmmZfqU/q80JxT2sG84GVIucnqS
         xMqYLiHc4igD/H31LEFJTNZBttVMxzXhCEhWWZV9WRRQQ2SxFHtAdSbJeQW5cHuLt6vu
         +mzkViy76BLMg+kgl/UG2a5jJLlDs2gl3nwtL5ogi8dsBCHM8rP5nv2It4ZumVW0V76f
         WanA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EVuw7+Te;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=N7xxhkHekJ2HM39DwO2tdC0h2GKA30PhF8WOx65mj00=;
        b=Xxf+yffEPOghV3scZIdiSgBQte7JzmQU2wdxdkiG+PgDoduB+Nc8Bb1zQ5AS5bStOy
         9GI+vbRtt1uDW24UppUIyeF7+YtMfcVlnCUuqz09x/lKy8nY8ZmVIoDw7AHuHFWMiaLA
         on/1P78DUGjrPTgtkU2vKG/nIl5osslRkINPXtiI4ZjggbBgta6XLUrERrnzQ6fWXBiQ
         WJM5LXM3yqiEbWF9O9ICJ1E4TMuPyc1brvPwQ7LfK31lms6F5wHv9eOQBQv8OYTFCcT/
         nxKeZowco9P3dIjK+MhHZ832TtIWoMVkbNPcHQXXewNQd3ruXBHU4/eM8ss43qC2Tyho
         Cegg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N7xxhkHekJ2HM39DwO2tdC0h2GKA30PhF8WOx65mj00=;
        b=Ayam3+dfTvzBQW1yUUEshbjAa9rhPqU7RWUodekXCe3We+iNPtfGZ0CfG3JlOGvrVL
         jVGy+LBSmGT8xFRiPHJ2Ja8mKMQpW2CPjJAuuq4q/A4n8ii0qKt2zGf1aXD0aJLfzg/O
         UDXwtJytDk3hnQGsYZquqkt5POuNZ0lu/Vg4sQubeTkMP3jQree/BUX7McF91PMVUiQm
         68pqHZ/V2AYIoIbeBduhJsZZQ2Iac935a5CLG7gX2Lr5Xh+TezerE1zWSB0Rc67g7htq
         6YTJq2nTRAyIVGycIokz+NOD2N4GmZsJZaCuG67+7MNULtxbyyMYBCTLzpN7L0RBPadS
         fE4A==
X-Gm-Message-State: AOAM532xLeGAZRhVBclveTj9Lh0hZ3W5AZXxQYHPt5YuHzCy4q63y2Ky
	+gwgfO58t9DvWPGwlTnjzK4=
X-Google-Smtp-Source: ABdhPJxJ09Qcuh87bYDDofVt51wMn4VF49D4X6Gs9sYWsMygKyGRQ2prQEOlQZfaSwAYjeSBlWWj/A==
X-Received: by 2002:a2e:8084:: with SMTP id i4mr2127346ljg.122.1615546974485;
        Fri, 12 Mar 2021 03:02:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ac46:: with SMTP id r6ls3095951lfc.2.gmail; Fri, 12 Mar
 2021 03:02:53 -0800 (PST)
X-Received: by 2002:a05:6512:1088:: with SMTP id j8mr4861189lfg.475.1615546973358;
        Fri, 12 Mar 2021 03:02:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615546973; cv=none;
        d=google.com; s=arc-20160816;
        b=jlDPshH8nlY5RcsIFOXzgjQyo6XqrRPAL5rTaXPV6YRaAa0Qs1smFgg+tkQbBoRWtD
         c6MpBvBoPRZlf77F8nCbJsKhgwVlXgE42QY1im1XA3Pe5CoMBVabaE0LwDkcvopL9Rg6
         7UBzMp3+yE/8LF9sJTQAZDxU35YqxDnBd9DSc3/sKmFWSC1Sllhs6xiGsGhKdc8VTw1z
         I1pCcrHsk1ztxypua6iOUgQAHL+J0k17Rm348t/y56zG6N0oOMATlELhd/s07EO4VWrn
         6DFQ6hIok6vYlquNTh2xWo6Qr2UND/Bugl/ITt4DKSlRvFaVcGyMw/QH6s1jJawdf2mr
         RpWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dihNwmS8eg72fB7m8NAEuzih9r4cxSiPgspyafvWSkU=;
        b=pD4dX+vYxKsmEu9P+UWW6Ml0+/CRQ2o7SKEz5fGLGaAXPGvQQoCLC1hW6hMbbw9Yin
         a39XecYO1p2t0OMnenuhV/+SQnB10jCCxpLnC3mOo/kePcrVJNlSRmgsZTY+36fkGCzO
         f3WNg7fPUrfI/whcgQAHeHD1NEffRw5PdM3gvy6AIE7U46BJst/ULQC3znT5wuu+SCz6
         8N8WuPDlpjg8jk++HCVG4DgXwIN1Z36SAroNToRCxHTm7Q+5GORdQbi8jG6lttfLK5y1
         CCGT8qA1Q9+bVeLA0S9P3yskS0UeDtY40dcd77z2pggwA7TTysfdylobSsTFLLCNkmaA
         U5Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EVuw7+Te;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id v3si255265lfd.4.2021.03.12.03.02.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 03:02:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id g8so3547348wmd.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 03:02:53 -0800 (PST)
X-Received: by 2002:a1c:730f:: with SMTP id d15mr12347734wmb.135.1615546972704;
        Fri, 12 Mar 2021 03:02:52 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d5de:d45f:f79c:cb62])
        by smtp.gmail.com with ESMTPSA id j11sm7373970wro.55.2021.03.12.03.02.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Mar 2021 03:02:51 -0800 (PST)
Date: Fri, 12 Mar 2021 12:02:45 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 10/11] kasan: docs: update ignoring accesses section
Message-ID: <YEtKVYVeUycUKySP@elver.google.com>
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <c0f6a95b0fa59ce0ef502f4ea11522141e3c8faf.1615498565.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c0f6a95b0fa59ce0ef502f4ea11522141e3c8faf.1615498565.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EVuw7+Te;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Thu, Mar 11, 2021 at 10:37PM +0100, Andrey Konovalov wrote:
[...]  
> +Other parts of the kernel might access metadata for allocated objects. Normally,
> +KASAN detects and reports such accesses, but in certain cases (e.g., in memory
> +allocators) these accesses are valid. Disabling instrumentation for memory
> +allocators files helps with accesses that happen directly in that code for
> +software KASAN modes. But it does not help when the accesses happen indirectly
> +(through generic function calls) or with the hardware tag-based mode that does
> +not use compiler instrumentation.
> +
> +To disable KASAN reports in a certain part of the kernel code:
> +
> +- For software modes, add a
> +  ``kasan_disable_current()``/``kasan_enable_current()`` critical section.

Should we mention function attribute __no_sanitize_address (and noinstr,
which just applies to any kind of instrumentation) here? Perhaps with
the note that called functions may still be instrumented, and in such
cases would require combining with kasan_{disable,enable}_current().

> +- For tag-based modes, use ``kasan_reset_tag()`` or ``page_kasan_tag_reset()``.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YEtKVYVeUycUKySP%40elver.google.com.
