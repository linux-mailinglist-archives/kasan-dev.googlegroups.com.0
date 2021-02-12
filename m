Return-Path: <kasan-dev+bncBCT4XGV33UIBBDGETOAQMGQE7LRIJZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2701B31A5DF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 21:16:14 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id y62sf224257oiy.15
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 12:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613160973; cv=pass;
        d=google.com; s=arc-20160816;
        b=uEp/IW31S1e6tcbvGIoD7rXOMt9JLDCHRzScNDD79mcswkHzeDLVOANXQEnvD1oS0T
         U4JPSSsRkm2Wp8eHaRiadanMrPLdo3zeD4H0ox0KtjdQG7Zrk4oB/Z4ce3qPAaFiT0j6
         omla5M1OsTWQ/digFVrBb1js4SPxMTGQY/DN8k3+0DA2MfAhzM68vUdAIIvY0nBHsLOC
         gP9+IgoxUzUjm65AOguNdllbdLNaEI34/vYxEo7cXHkv2sdjokI5LiXPRyA1thAVurYl
         +jFzcBbWAhrxqDK0RsRpSQ5lZCqr8VfxpSRWHWJbf2x27ONXCn9zetVpxq3Gj6VhPhFU
         bzWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KKyzRpr4Fucf/HKiSDOSb65H4jf8WNywfK8PyKz0S6c=;
        b=k9ubXJ60KwmZsptqBF9EuQtUPoz3pPAGDNLu9SiCyd7P3lrRN8btRD1AKuun1AV0aU
         4MGTNvnMXoVUSincwNpP+LFvwl0qtTeTGk8Qdr7F3YOIAbBhjhlFgLn0nPi0B0OCEVrh
         HbdQhKDChTW1Um0wES+VrNq2YdPHU6V6E32mNfZKLw+hYX1L6eS0688x8/J4+FolESrr
         yTDCGBXuvTC4JqpI4PSGU6YVrcSRLRHiFuH+CDJSIzeKpNxRyUFoWCA5bN6vQmUHQlJO
         l+GZxU5G+gfGrWh9VLfDqO+ox0WZyoFfL7MQ2qp5QsAoZMT68fjADgkg93e6BP2OTrEs
         Nu/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="XZc0O/AH";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KKyzRpr4Fucf/HKiSDOSb65H4jf8WNywfK8PyKz0S6c=;
        b=AlaJIGieYzURm8P/obQKIztD0z3LObru0WJjg7i9VJoKiNQEahHJj1F90zY/Mdmzlv
         vIVPzovGymQ28y1ELGxj/jhfKO0NIbKdu3EgMg42TOIzhHLEibBFX1krh6jh5ieEb7BF
         Bwv7SzImGhnHHYrpi8Y1Vhuj28XEyEUrGfLNYwFtKMWLI+1r7GQAMCIcRLmL5QiaEvdO
         v7Cf/n7bMrrgTHjjnWXhfNedqOp0WTgcjJUq0yybzXBLtVv5G9DnScaGlsm5Yisuc2rb
         KodDCd+WjgB+Kq8Kq14wlsqoIG19fkvq2rQzcENWsiQqzh+SdwIXoipUlfaCCGEgjQZj
         shjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KKyzRpr4Fucf/HKiSDOSb65H4jf8WNywfK8PyKz0S6c=;
        b=hSrqdflchH38oFvVGo3re4GVSLUiodt54PG2271wKQ8oxqAGZSntWQY/Y7r5B/TaZ6
         3ToHnh6U1AH8GEwAOH5Rsj5/TwEslaDURWu8LNSe/1zGmJlfXBRXVdP+1t3y16Wdk8+Q
         FSYK06hS2QG/COyMcPTOV1Jw/c531rbFY437BNYlNF+UTsab9FGPQdiIqxq5MLGHFspM
         ed5G6s9Kk+R+LUHLB9xkmf6SnXIdMKrKDPAdFsJXWU9m1lou6SoolrQSK5fwjtSwkdIK
         56IKzQSqHEpivVy5HsGb3MpyQD86d0q9rj/13NSSYvohzUNbKiZ+3Numla53FSqCR/YF
         hfGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333zp3W/imqkDrObT4tx/YxJ9gsUenVxl8MaG0zISYAY9rRGQnM
	KIRZ8lICqzkD1nXJl2ZcqKc=
X-Google-Smtp-Source: ABdhPJxSebB8r/Xdk376DRuhlr11AilxsyfGX720tEr8ld7XkJIOaw44FBSyh+Xxm5Rupwsb2Y/lNA==
X-Received: by 2002:a9d:d2d:: with SMTP id 42mr3329415oti.24.1613160972911;
        Fri, 12 Feb 2021 12:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:da5:: with SMTP id 34ls2359992ots.5.gmail; Fri, 12 Feb
 2021 12:16:12 -0800 (PST)
X-Received: by 2002:a05:6830:151:: with SMTP id j17mr3377342otp.252.1613160972479;
        Fri, 12 Feb 2021 12:16:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613160972; cv=none;
        d=google.com; s=arc-20160816;
        b=Ik2gbPuBjO0L4PBUHeuMBai6YdMC0wQpjUSrlFWBw0wXvfkUDYoKmS3CLLB74P4Gok
         gtuxWcZqlC3LoZWGrP/Jbp/wO66X4/Su6ItSVqi1d1xZzbdDh+xXewi4khUI1wtxFJT1
         7JObUYE5xqrfZg5fFTr+MKh0L74/ww1g9bUOGhoucRuAoXa9ypTLhKUX+CX+DsG1TnWr
         MAwFtJMKguoqpkbmCuSv4qIUpn8h9kpt2iSwmnoNX4PM0VvV4iawIQj6f1HWnVWdxoFt
         9P9cclOoIXVtcraUWYHmCty3kccWlziDkmSWGtQM2G6iElA/LpYd+aRdUa2Veuk1wKYj
         QGCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=86YuSJCwc55KUOmNf/A3C8FQ9KMioYrgFWSAePLtRo0=;
        b=RXcYjw/XC2BpJIUdnivA94RwOCq0G6Q2qdVXSEwE1HtfWeWQFfGe7LxvbnPitX+yol
         e/sdD7GZytxwmFUt63T7TGX4V7NYuP1qKOdQ5Jdu6ZksUuQzG+4DJSPtnS+qRb+F73yC
         1PtevL4MY1tayJQKgS0yypOq0wqxIpzYPBVd48IUbX/GEI/j6QJnZwL+q2CTSw7TNIbf
         5TtTHfQqMVfbuNf8rhG5oNVvzUIU1nrsthSdTPysuNQTBEzPTvIUlUK5dEVILKQ9zig1
         OgAMXSNb9Tibg7mbAsWsfXdRqF8XO7i7AZs+oFJYNz2FRuOnZgnraS4LOHEepe7Fb8kA
         kgKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="XZc0O/AH";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b11si607123otq.0.2021.02.12.12.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 12:16:12 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AFB1764E8A;
	Fri, 12 Feb 2021 20:16:10 +0000 (UTC)
Date: Fri, 12 Feb 2021 12:16:10 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Will Deacon <will.deacon@arm.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Kevin
 Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig <hch@infradead.org>,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
Message-Id: <20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
In-Reply-To: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
References: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="XZc0O/AH";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 12 Feb 2021 21:08:52 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> Currently, building KASAN-KUnit tests as a module fails with:
> 
> ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
> ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!
> 
> This change adds KASAN wrappers for mte_enable_kernel() and
> mte_set_report_once() and only defines and exports them when KASAN-KUnit
> tests are enabled.
> 
> The wrappers aren't defined when tests aren't enabled to avoid misuse.
> The mte_() functions aren't exported directly to avoid having low-level
> KASAN ifdefs in the arch code.
> 

Please confirm that this is applicable to current Linus mainline?

Today is pretty much the last day for getting material into 5.11, and
this patch has been churning somewhat.

So I think it would be better to merge this into 5.12-rc1, with a
cc:stable so it goes into 5.11.1.

For which we'll need a Fixes:, please?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212121610.ff05a7bb37f97caef97dc924%40linux-foundation.org.
