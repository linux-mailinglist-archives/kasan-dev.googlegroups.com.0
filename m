Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXHCWGDQMGQENMCYTBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B3CE63C60BD
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 18:44:12 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id d16-20020a1c73100000b02901f2d21e46efsf259827wmb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jul 2021 09:44:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626108252; cv=pass;
        d=google.com; s=arc-20160816;
        b=xI+aYolrrBNbVaEbFz2suzbHu2mR2ZxYn7qF3DO+K0o+IkMDU0hA3ojK8r2FvoOIMV
         ZyHpFA5+Dne+BJfkEOH0iRFOtdosRzW4GSNKn/QhVrFCT/dFPWRPqLzsa2H2gxOTmd5U
         snMvceXgNckGm+z89iRa1KUIo6J5mHYw9xqN7lOnS5uK9OI1QrMoqqphrhOCq5tiHKK1
         ZVAo8IPf9NiFJU5VxqjQmW7izayw3wyrJn6ARfvH1+YnUk27QpPHZWJ0cMd7qB5rbixI
         JjVxJ7NHMStSi8n0VSiWIZ5J9vIz73Rxh5mOdbnqOX5pzsQM6Fxg1KFUkRHTlnA7uqKA
         Pa9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=N17B7IZbhRolEgeFnweCJt1/P4IN8TN33xF5NU3b5Js=;
        b=FhGs75Cw7yk3YDnFTpbRYoLDRNyXAHg3UFCrWJA8uHATlSXgmjtMkjj7qemC6gQRi9
         W8iZjGmHIdmVTAyzuV2PMqRIJAvO1FhiGDouQDbYrpRTCCTtl2+FbLGO9+R9Kovez9z2
         WM61XsFR/m6odIX0jjJAw1qFlzaQDt71e6eqjyfMEjc8abeNj/hEG3mQoRQAQMj4Q2kO
         J/rmnP+rbPiaLIoqM75sLbQKYiDX1ehoeEyO5hN5IUZ+eGQevdtIwOLCEnjIWr3hcrFg
         s5pWYCgo/SZoueWA6nqCbu/tPb2Oe54P6o+gv30aVpVGxtKdYMFXQ0r2Z9v4puf/kuU5
         +YKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YxBBHmI3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=N17B7IZbhRolEgeFnweCJt1/P4IN8TN33xF5NU3b5Js=;
        b=eE1ZkwzJKtvN/riADmBLzTxh541i5bD/nL1Eo1M9XojXfn1xyLaJ8rMIXLQAnsq2Tc
         Jniu2Pf0koH1O5FC/ZEM1YzozO1NuOYd6OCllmkC73y4vgpHIPuq5/D5F7h2yWdmvABC
         uvjGKPUQ1lwVXYaceS3dgpJAbaB2xNx6gX61MwzEn5z0V+ScoD6mGNSWP+n6z0XFGIu8
         OIMYlMQMwEZK3U8vQ25h42yhrLA5EahA+LtyAXhl0r8Ae65bK8TYTo+jQbTpl/kWz7ug
         fDkkLGIc2Vr8DKeUyXtSYLr2bVB6dXR66QpK/HujRO58H1/+TmcYcqPQQrRb9ttMFhtP
         v7Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N17B7IZbhRolEgeFnweCJt1/P4IN8TN33xF5NU3b5Js=;
        b=MqdP8c68/SRzIyr06QD3nStlNtWD5A+8p86LxZYHWPB+nIhtGq7D0dkvBhqIyruKrZ
         2yla1GGN1eWo40GvQ+Q+1gTvShdcExq4CY3DslFxoA7MN4hdIxMrzzbaR5toFCTjd5F4
         DbPlvlCHB0TukquQfcH0XuhUVdsQGRVlKap8hmFrJsmSh6VCjLxxgCEYEpmye5fi+VWg
         czT9mptPkPCDHYKBmTLG1PAI3x/NcwaHvIrTgzaKE26SwS7tBCLa/KlC3kW28y22RHf/
         MTjp5EpwkEDEXk8+KF0SRA1L1on3QKUed5IUyIRzRR6LlseyXIvU90Eb5SFltScVWDlS
         bSGw==
X-Gm-Message-State: AOAM532LzT9aJZOIR88/SM5lL2rOcQn15HbPZmcL0l+xyx6zHVELBqfF
	gh+jemf7FUZlgpAOvFu0MRw=
X-Google-Smtp-Source: ABdhPJznXZgxzW4CckCNULWH1/e90COuOGz1TyCchfoukIJfjrgmbg7/eqH1M6AW0OzgvO1ZGpWSwA==
X-Received: by 2002:a05:6000:10c3:: with SMTP id b3mr4817488wrx.271.1626108252464;
        Mon, 12 Jul 2021 09:44:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3544:: with SMTP id i4ls3672wmq.1.canary-gmail;
 Mon, 12 Jul 2021 09:44:11 -0700 (PDT)
X-Received: by 2002:a05:600c:1c86:: with SMTP id k6mr103351wms.147.1626108251465;
        Mon, 12 Jul 2021 09:44:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626108251; cv=none;
        d=google.com; s=arc-20160816;
        b=eRLei6wQb/CVKGHkGDy3zl+bmEqpbjL+16/F0A0ETAQwFMrJy3aihEjfbPC9uS325z
         P+r+Qow2BvM5+reuMaejxTQP3pK71CyOdfxvTdbbFI5qin1oCMlq9Tbl6YFN9HpIthzj
         bCfHL30KpkG+jboEkUd/MGRAVfteNUWk54gfojdFlbpZVjwk0skGu5L3JGQVPADX1YEc
         QokJRIP2Zz4BakKMvMvcTdoiZSChIqFUO9Ep6sOcHsMY8Yemx9ksZPsEYSvZe4v5dATN
         OgchKK2P5pdVHoR0/TDFJArp+ARTvguVaHk57Zr246hz64JNdh6LIn5+C7Lt58Hiom5T
         6yoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qv3Vo5xsbAOEJgLGiYQjQnACJg9fyGkdPANxzyRJ0u0=;
        b=o3hkWtH2Zx5g2QP/9BUmAJzdN04D1XAB2sceGZ+E2EUAw4VPoBE9YHt0P74cQZkrG5
         TWXIih3REgOE2g8EeHUmFByV1nuzUNUxHIGWwvmL/mNe19DtFP8ZjLMQIBEScL6rynkj
         UgG23Jx4H45T4y7unmFVn1NkuyEn2Z57mwONSs7Ny2BYK9n7rVQau4qg3Nx1y6VgGnyx
         1CczmuDGh3a25v1vLsIGgYaXwTcMb5obKH/L0dNjz+zVUqv2s4EVNwiJB2VniS7yn5MC
         LsC8v9/xNRdHFdsJhLIzQesatBvpwq+NvT3etCzJJ7sTuCE9j6Hg4tqm4qW2rOWdYd9o
         pHfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YxBBHmI3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id c26si830767wmr.1.2021.07.12.09.44.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jul 2021 09:44:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id l7so25601990wrv.7
        for <kasan-dev@googlegroups.com>; Mon, 12 Jul 2021 09:44:11 -0700 (PDT)
X-Received: by 2002:a5d:530c:: with SMTP id e12mr28211287wrv.130.1626108251006;
        Mon, 12 Jul 2021 09:44:11 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:30c:6a5f:a6ae:eba0])
        by smtp.gmail.com with ESMTPSA id f2sm14920362wrq.69.2021.07.12.09.44.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jul 2021 09:44:09 -0700 (PDT)
Date: Mon, 12 Jul 2021 18:44:04 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Woody Lin <woodylin@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH] mm/kasan: move kasan.fault to mm/kasan/report.c
Message-ID: <YOxxVKvJxVfQxLv7@elver.google.com>
References: <20210712151618.1549371-1-woodylin@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210712151618.1549371-1-woodylin@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YxBBHmI3;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
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

On Mon, Jul 12, 2021 at 11:16PM +0800, 'Woody Lin' via kasan-dev wrote:
> Move the boot parameter 'kasan.fault' from hw_tags.c to report.c, so it
> can support all KASAN modes - generic, and both tag-based.
> 
> Signed-off-by: Woody Lin <woodylin@google.com>
> ---
>  Documentation/dev-tools/kasan.rst |  2 ++
>  mm/kasan/hw_tags.c                | 43 -------------------------------
>  mm/kasan/report.c                 | 29 ++++++++++++++++++---
>  3 files changed, 28 insertions(+), 46 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 83ec4a556c19..ab8e27d45632 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -203,6 +203,8 @@ boot parameters that allow disabling KASAN or controlling its features.
>    report or also panic the kernel (default: ``report``). The panic happens even
>    if ``kasan_multi_shot`` is enabled.
>  
> +  Note: The boot parameter 'kasan.fault' is supported by all KASAN modes.

This documentation change seems hacked on. Could we change it like this:

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 83ec4a556c19..21dc03bc10a4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -181,9 +181,16 @@ By default, KASAN prints a bug report only for the first invalid memory access.
 With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
 effectively disables ``panic_on_warn`` for KASAN reports.
 
+Alternatively, independent of ``panic_on_warn`` the ``kasan.fault=`` boot
+parameter can be used to control panic and reporting behaviour:
+
+- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
+  report or also panic the kernel (default: ``report``). The panic happens even
+  if ``kasan_multi_shot`` is enabled.
+
 Hardware tag-based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore, it supports
-boot parameters that allow disabling KASAN or controlling its features.
+additional boot parameters that allow disabling KASAN or controlling features:
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
@@ -199,10 +206,6 @@ boot parameters that allow disabling KASAN or controlling its features.
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
-- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``). The panic happens even
-  if ``kasan_multi_shot`` is enabled.
-
 Implementation details
 ----------------------
 

[...]
> -/* Whether to panic or print a report and disable tag checking on fault. */
> -bool kasan_flag_panic __ro_after_init;

There's also an extern declaration in kasan.h, which should be removed.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YOxxVKvJxVfQxLv7%40elver.google.com.
