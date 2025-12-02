Return-Path: <kasan-dev+bncBCT4XGV33UIBBTNKXTEQMGQELKGC73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 81760C9C38C
	for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 17:35:27 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-8804b9afe30sf167182456d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 08:35:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764693326; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z/vGio4Vf1TvFOfQ9PkcQ6sUTCbillG3ciLj6L3pxwPOo7dJW0PyynguGa5iPm9hI5
         mhbMoF2URZ3GV6xgNuq7zcuQKgYzzX/er4kZQcfamHqWZEzq+XxlJEOnvguU84YZONCD
         oxtGlq2InlkHVfN+zbME8r1NV2Cs9RvurMfL/qGr2kYsBNLao8Lxqko0/5vuOfwNOcV/
         /GuFLvNsd1YeefbruZG30nfF/BvwqD23gs9CWdufwuM6rjDpSAbFRIhgc3VOrYd2WFso
         6Cvn/iRiZ10VzL1JTiXjusjaIMozWvAamX03NabGtwgAbSBYDAFmeaMQFV2DP9M2la9M
         EYDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=erGPIVCkdQ6tUZDZgnPPWIMAFHF/S2flJKfsXbcMLF8=;
        fh=eckcKJlJne2aDJZWCFN8XV7fYaZOCwmd21uUkVf+dRo=;
        b=XJobLtnd0LwW9E4jQY18IaV3GWX6GsIFUo+cvKu7a6uX6KkMXk0W49QBveuuKBrFpO
         /L+y1nPNa9LPgmp86GEaOpXcDa+dV1uQjGSCRI+hopA6MQ7V5QnaFQSpH4fUfuwUteiV
         448GA0fIjjoBebFKB8UxYEklhGOccKKAkAgoeVhKFyU+GDq42dfM69igcSnnm0d7zwTJ
         Ad2BcduSGRkQklg8blCrGXZQ+8cA0g9xWuy5bSX7ZC56EifmMetXQ877kvQwPEKK/RQk
         O/tqdA/dL4GvMeyUej+NTBBcDJ6Ts2Uo+IS90YnxLnCeGe1meo1LNjcKm5iyfk7Vcgc0
         WXeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=NPe3ok8n;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764693326; x=1765298126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=erGPIVCkdQ6tUZDZgnPPWIMAFHF/S2flJKfsXbcMLF8=;
        b=cfXBJZYz041cAd+UJnWP94+o/ImWWsim6FJNnBzw7jzd6JQ7IJ7DOAAKQhhVXezC43
         KiINb07Nwth0cQgbhGFmcZoKmm8QSxnAJr4P677aD5qbet+RvoujB3R5NjyyzwU8Q8PT
         a+eG9jmLMoB9xD+G0hdfYlxlZ1qIbGp0PP9Ab22xZzGm7EpGO0g7bO2vNw+qW6dRMsZT
         uN0kUS7ijW+GNobuIDgfIpK98YPXwx62wsSczrDhn4UJdRoGpr2AcX/1W4oHWpT/yBfz
         XPLJFgBAmwSvuoE+5XdrJq9zGusgKpGmEPzPdYz2kEkGpI4Ak3g5GeBVTl7X/ylwe40Y
         w0Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764693326; x=1765298126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=erGPIVCkdQ6tUZDZgnPPWIMAFHF/S2flJKfsXbcMLF8=;
        b=hg87c0flq41WD5Q1N8sj7BzeucwGhzM63Lw6oRclsOIu0/EegVfc2PPcW0lCAgd5Qz
         nQYaGeuum6IfmB8yw90zOK7nTgPdvqWP8kLfKGnkChHF/dVl+gm9V3Y8OiFOanMM4V5b
         aipu4hP2kjYeyKB9JDkTfA1xJNAUa586SN41tcz7uesSMDH8mxU+8/ZxZZJLKMv9Wfh1
         afnoSHPxDzDThsboFk9bSZ1/Wqao+AAmT26se0r3a2WWHBsmKAnwgoRTxA8eMH+lIwwP
         msDRpWM1XBbI2Smq0Sm1Hh8IQzRHgTedCPjUGb3MaVL2cSKRhoBJe38FWYYrOpbdHmin
         BrEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfWkDiLZfvunLH4VU1QsUPwSWKrmHidpZRgYlDkIrYo0lOrbOzVMTHCcSOG/c/a4H6TgzxfQ==@lfdr.de
X-Gm-Message-State: AOJu0YxXWXsnXxXMb8aGuvoGJcV8Rxc/jz546WFNbAa3dobbG6TJoJ/S
	78TnrKmJyFiGov9EDm23YAzR7d0yz+UFxG5itmA3HCGEYVqPyOU4AFCT
X-Google-Smtp-Source: AGHT+IFBuoroXziPLyDSLQNS3zKBxC8ZWdIbTxHSXPlCUOIPW6UlsLRPyaWGPCUaZJr5ISKQ1Uh7VA==
X-Received: by 2002:a05:6214:5249:b0:87f:fffc:10a3 with SMTP id 6a1803df08f44-8847c527dbfmr675669746d6.39.1764693325826;
        Tue, 02 Dec 2025 08:35:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZdNQdcF1l3RRVY7M07QCo4NbzVznoaEQXJgHRWVBeP5g=="
Received: by 2002:ad4:568b:0:b0:880:3e5e:11b2 with SMTP id 6a1803df08f44-8864f8e2553ls105184176d6.1.-pod-prod-04-us;
 Tue, 02 Dec 2025 08:35:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXN654oqy9iony+U16DEarCCAZyw9Rlh5iNU0kQ4wi8e+E/K9MCwE4Y6D1rx9c+bD1VaBlXyZrsdcc=@googlegroups.com
X-Received: by 2002:a05:6214:2aab:b0:882:4130:d108 with SMTP id 6a1803df08f44-8847c5278c1mr649392666d6.43.1764693324203;
        Tue, 02 Dec 2025 08:35:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764693324; cv=none;
        d=google.com; s=arc-20240605;
        b=NoUiMM6PJg2LxovGNn826G6xcAzV9aIMsIs/C9atE8AHVz9+wKGJwHelery7hO6eov
         y8WJ/7PXlw10rfr+0sNkJQhVyWssafePGPj8upUmFqrKNdBubryrFWd6sDyRHe8fzNUu
         i43Bxflmal7TcfQNAPmFdBaTJ9TKbWd305zqETbHGuLXSzDiX7LCWLCd+Jor5GUmH3hh
         louiLkxzeMFFyXqmMu6vhJbo8ABRkKsJqvlKb20X8GIhRyizex2q2WQDPtHZKPDuB6yZ
         O++xXBwvoIe7txB/+cUkMV/9UzvjiSPCKM4UDZ0u3oKZGi8efEg8HY+EeplSralPbPha
         paqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=n/ucUR2savlJdlRsAB8Ua/zzHH9A/STh55e1ZFGoMok=;
        fh=ix0wU3JoDW0Aqvx8IjzJebdOLrcQity8DZzGeMSm2PY=;
        b=Ut1QoQkNvVG1gZv4HLEqGkRBTIWhPfid8AH5n3638huQGWVpGgS9W5FysXdJC8MRiR
         IDyQpouswvj06/CECfuDeJI0y1DgEkKH2cHJD/TkpGlit5DNNqNQcgkpHW08Cddb2+Ir
         bdDF2Rp1Y68gDGU26Nby2DEo0cLOaLEeSicr9wDs2paEWVN2CAlh9p3pIPcs4Sh+LmPc
         Pld6DuwJSZm0edgt2SZEw9K0bcceXZ/gy9B576C9dzHmCyg9tOjC6ktMMjtIzyn8Vmz/
         oYPykRXU39Wj+YpsIs5KisORzrffQUkdG9QmAGrbWQYoKGTDvQZXVjVeqS4gUdp0dmqI
         EP+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=NPe3ok8n;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88652b01a84si5756566d6.10.2025.12.02.08.35.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 08:35:24 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3572643F71;
	Tue,  2 Dec 2025 16:35:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A1859C4CEF1;
	Tue,  2 Dec 2025 16:35:22 +0000 (UTC)
Date: Tue, 2 Dec 2025 08:35:22 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: urezki@gmail.com, elver@google.com, vincenzo.frascino@arm.com,
 glider@google.com, dvyukov@google.com, ryabinin.a.a@gmail.com,
 andreyknvl@gmail.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 maciej.wieczor-retman@intel.com, Jiayuan Chen <jiayuan.chen@linux.dev>
Subject: Re: [PATCH v2 0/2] kasan: vmalloc: Fix incorrect tag assignment
 with multiple vm_structs
Message-Id: <20251202083522.1b0349117b9159b891808532@linux-foundation.org>
In-Reply-To: <cover.1764685296.git.m.wieczorretman@pm.me>
References: <cover.1764685296.git.m.wieczorretman@pm.me>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=NPe3ok8n;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 02 Dec 2025 14:27:56 +0000 Maciej Wieczor-Retman <m.wieczorretman@pm.me> wrote:

> A KASAN tag mismatch, possibly resulting in a kernel panic, can be
> observed on systems with a tag-based KASAN enabled and with multiple
> NUMA nodes. Initially it was only noticed on x86 [1] but later a similar
> issue was also reported on arm64 [2].
> 
> Specifically the problem is related to how vm_structs interact with
> pcpu_chunks - both when they are allocated, assigned and when pcpu_chunk
> addresses are derived.
> 
> When vm_structs are allocated they are tagged if vmalloc support is
> enabled along the KASAN mode. Later when first pcpu chunk is allocated
> it gets its 'base_addr' field set to the first allocated vm_struct.
> With that it inherits that vm_struct's tag.
> 
> When pcpu_chunk addresses are later derived (by pcpu_chunk_addr(), for
> example in pcpu_alloc_noprof()) the base_addr field is used and offsets
> are added to it. If the initial conditions are satisfied then some of
> the offsets will point into memory allocated with a different vm_struct.
> So while the lower bits will get accurately derived the tag bits in the
> top of the pointer won't match the shadow memory contents.
> 
> The solution (proposed at v2 of the x86 KASAN series [3]) is to tag the
> vm_structs the same when allocating them for the per cpu allocator (in
> pcpu_get_vm_areas()).
> 
> Originally these patches were part of the x86 KASAN series [4].
> 
> The series is based on 6.18.

This series overlaps a lot with

https://lkml.kernel.org/r/20251128111516.244497-1-jiayuan.chen@linux.dev

Please discuss!

> [1] https://lore.kernel.org/all/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com/
> [2] https://lore.kernel.org/all/aMUrW1Znp1GEj7St@MiWiFi-R3L-srv/
> [3] https://lore.kernel.org/all/CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com/
> [4] https://lore.kernel.org/all/cover.1761763681.git.m.wieczorretman@pm.me/
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251202083522.1b0349117b9159b891808532%40linux-foundation.org.
