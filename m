Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUEQSUQMGQEEB2FJFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 456587BC552
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Oct 2023 09:02:00 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6564dbde089sf59937696d6.1
        for <lists+kasan-dev@lfdr.de>; Sat, 07 Oct 2023 00:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696662119; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3wm6iQcsUCV5gA2wlUla6fw50drHB5E/rwoA39yXvVeMbadPKy9RkGTEnLidDHFG4
         pizBjFaeYuxfg3mb71n/9QIDshFLaTviJlZklRqE2UA1xOIr79I4Dd8n4zkarj44oFXg
         UNrAdPrY4APTfwS5Y7inP9Dl/ZU8/w1ZoM8TWTtn9fADVCijM4AFhuJH7p3gby2bv9zz
         /gdcnleOmhRpcHip4HcrG6jJnxi5UaierpV/0/9wZDVRkbkN1scCIWgS6ugr+JwvSdgu
         eQ8+0CwfGFIxP6dwbBpAi114PT8R7dPoMGkYObu7BAhovvXMFEF07q/F4rvbN0z0pMSZ
         Wi8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5E7FRshq466li0wCKbNZdVbX79Qr79OqXMqjM9mKOP4=;
        fh=PAMwWFIyYDX+NdZBJdEl/NRibBpELs9BvAUsR3hyWOM=;
        b=QMIoLqwzn5rLvVIlAsFje6FRtFVNx72J0lMxiyZAsOLz25weQ5l3gBHxLQZJAozPkC
         ITGWDwCiTXIwYI7WcffgS4ovFHBbsPLX7KDYM7DW05lCWLfe3UHTrcc3m3O4KAVNIPNV
         MEAsw7hQ8MywXdBL7sl3eyIBaP3gQXKOZQ3h8IcvvaLATBRoaswMegjp4TNSLh4itQyd
         ROGDJj38TuF/ui0VG3/zTFot35CE/0EV77FoFRvu0ylzZZQFvBk7OF9XBvnSjGoL2uDE
         SUD9swSzWSdkicVGmTC+qotXsQsTEduQ1A886PK4cft4VYzhmlIJ3ky/zvg2DmZPlpEA
         eqHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D6zreWF9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696662119; x=1697266919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5E7FRshq466li0wCKbNZdVbX79Qr79OqXMqjM9mKOP4=;
        b=SsFucO4GYLRd1QoZZOr6OaEF565jpIBRAY1HDSDZ6tRlXzVerQZ7mGefJ68LYW6KeA
         u+PiAwUOzl8Y7QlwN7H0YihVSQ9BfQwpeOImT1xpOlIgiWNWsr3gGAoq92uX5s5UaTCH
         c06fAF5lrz7DM7V5wgGRSfPurbsdCifHi4cU22VdQzhLVtIiD3eQklM44XvdtEEznuBY
         Spzuhyehj6zEvrKelMcQoPDHACCEHAAE3AxbfgrWBMBNGJ93Y/z+Jl22trj0AbWNAKyS
         iGa8RvmrP/E4OEL+UkCI/Mp/B/e4e7oSgDi1RrOLa0NKV4wM/+cj7nbnKnNgck63r82+
         Ul3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696662119; x=1697266919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5E7FRshq466li0wCKbNZdVbX79Qr79OqXMqjM9mKOP4=;
        b=laVW/+4pKkQ5S69hA6QuW3t9YSNsyvKNxYOnmZKetuA8Xno+aE6WZI75WZpe7+Qj2K
         4xrBv+8pkzT0IvWVoB9lQ9pjIHIc5lFsPcoBpbYvkIinTtfbwsuwnvWZzt47uLVHJeQs
         IgYaquEDEiDTof5V8Ws3He1Mbk9+yJEXTmeOU6ETFEe81r2+gaoI85bR55UwGrpbBh5R
         JOSonAwmOWDTUSivpkt+RynBbOYOnTkkPKtUvYNEkUpRWi7l8xbyuKL8T+vasI4RA5ev
         LhDcFin/DRBPLLbGrvmxR0rMOanMqU6H6vRgdfUGVARD5JCfvu906yjqRu9v5WFKAozI
         PJgg==
X-Gm-Message-State: AOJu0Yx1ovEg/gb7D/T9Dfs7h29/qZ4o2O7MsiKmZuQl+/DMQZUiYFBh
	Ar99GL9HTRzhL40ceqItEMU=
X-Google-Smtp-Source: AGHT+IG5gUFsw6cSR06FafZFql6B38pGrNuQUxGJwuh/LX8kRrUyYP0nw1w3g1GXQQ5uyfPqyBbdvw==
X-Received: by 2002:a05:6214:5e94:b0:65b:2ebd:d826 with SMTP id mm20-20020a0562145e9400b0065b2ebdd826mr10276838qvb.1.1696662118785;
        Sat, 07 Oct 2023 00:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e0c5:0:b0:656:fdc:a7b4 with SMTP id x5-20020a0ce0c5000000b006560fdca7b4ls503007qvk.2.-pod-prod-00-us;
 Sat, 07 Oct 2023 00:01:57 -0700 (PDT)
X-Received: by 2002:a05:620a:4711:b0:774:219f:627d with SMTP id bs17-20020a05620a471100b00774219f627dmr8349428qkb.18.1696662117763;
        Sat, 07 Oct 2023 00:01:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696662117; cv=none;
        d=google.com; s=arc-20160816;
        b=iu+vawAv/H5kOPAH6oHoVvAQcLMYHH/H96tJMUn0dafXGguyrPwjxxmB5gw+pDrhV3
         kwli6PTE8lA+Yscox0ksXRnhYvevzBX65ydf2QpnrHI/c2hHoK9fPLC1hKI5DYmTfr3l
         Zd8302tIAI09VTjil6R2Ytcj1qUaJMF04E9KsxxV7xAvgPtHB1LuZUEUKmCZ2xnutJDs
         xWKAy7gX5xIR/z+1ryUexuIaxkzb19uQ9Y2Mi2caOzJPGSo9e1KpiD5zaTYRsIoT+CIV
         vZ084Bvu/CTzkLvTpM5fI5iuRX38Sj7Zyw2eBjWOKT0V73RsxMNxwkdtzV37QcnO5hpC
         jL8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MV3fajDywtr5Jk/wqj0ujD7RNZVpvrV8ESz+9hWBpd0=;
        fh=PAMwWFIyYDX+NdZBJdEl/NRibBpELs9BvAUsR3hyWOM=;
        b=UFbXSzkLx2wFkoqPHD6hZJJc8PmBLrPIDOMuYQG1ess2rn+pa3YrujNH6rg7pxzfgR
         ZyDBxxedoiE9WZTlH3uilIUsMncBU2cBu8hhvw3NArSZYqdWGI1M/XTVylEl1nuhv4Pd
         xXe4RkZPl1X4b+EChIwukRpeQfnLrSaA9p5lqsfN2IZUdTMkd6Y/Vvt28VWQsVN6Md26
         tCl53RfOlayqwKuOqjo97YYu5NrqHN/UMC2pSumWGgxKhmQiTjBjgdMmYN2bsmxwAQnO
         JpKn3NSNeqc68RF34wZo1FiaJx43IEVt5CucwRquGz6zOiJJyYc5pnNqy2hGAt52SnKh
         gJKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D6zreWF9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x932.google.com (mail-ua1-x932.google.com. [2607:f8b0:4864:20::932])
        by gmr-mx.google.com with ESMTPS id fi15-20020a05622a58cf00b00417048548c7si358969qtb.2.2023.10.07.00.01.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 07 Oct 2023 00:01:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as permitted sender) client-ip=2607:f8b0:4864:20::932;
Received: by mail-ua1-x932.google.com with SMTP id a1e0cc1a2514c-7abe4fa15ceso1840200241.1
        for <kasan-dev@googlegroups.com>; Sat, 07 Oct 2023 00:01:57 -0700 (PDT)
X-Received: by 2002:a1f:9889:0:b0:49d:2a13:58fc with SMTP id
 a131-20020a1f9889000000b0049d2a1358fcmr3336138vke.2.1696662117155; Sat, 07
 Oct 2023 00:01:57 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <1c4eb354a3a7b8ab56bf0c2fc6157c22050793ca.1696605143.git.andreyknvl@google.com>
In-Reply-To: <1c4eb354a3a7b8ab56bf0c2fc6157c22050793ca.1696605143.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 7 Oct 2023 09:01:21 +0200
Message-ID: <CANpmjNM7rytkGRjyG3Pf5PakCdibtpvsm7o-K3am-U0kT-d2Rw@mail.gmail.com>
Subject: Re: [PATCH 5/5] Documentation: *san: drop "the" from article titles
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=D6zreWF9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::932 as
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

On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Drop "the" from the titles of documentation articles for KASAN, KCSAN,
> and KMSAN, as it is redundant.
>
> Also add SPDX-License-Identifier for kasan.rst.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  Documentation/dev-tools/kasan.rst | 7 +++++--
>  Documentation/dev-tools/kcsan.rst | 4 ++--
>  Documentation/dev-tools/kmsan.rst | 6 +++---

UBSan also has it: https://docs.kernel.org/dev-tools/ubsan.html

Reviewed-by: Marco Elver <elver@google.com>

>  3 files changed, 10 insertions(+), 7 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 382818a7197a..858c77fe7dc4 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -1,5 +1,8 @@
> -The Kernel Address Sanitizer (KASAN)
> -====================================
> +.. SPDX-License-Identifier: GPL-2.0
> +.. Copyright (C) 2023, Google LLC.
> +
> +Kernel Address Sanitizer (KASAN)
> +================================
>
>  Overview
>  --------
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index 3ae866dcc924..94b6802ab0ab 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -1,8 +1,8 @@
>  .. SPDX-License-Identifier: GPL-2.0
>  .. Copyright (C) 2019, Google LLC.
>
> -The Kernel Concurrency Sanitizer (KCSAN)
> -========================================
> +Kernel Concurrency Sanitizer (KCSAN)
> +====================================
>
>  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic race detector, which
>  relies on compile-time instrumentation, and uses a watchpoint-based sampling
> diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
> index 55fa82212eb2..323eedad53cd 100644
> --- a/Documentation/dev-tools/kmsan.rst
> +++ b/Documentation/dev-tools/kmsan.rst
> @@ -1,9 +1,9 @@
>  .. SPDX-License-Identifier: GPL-2.0
>  .. Copyright (C) 2022, Google LLC.
>
> -===================================
> -The Kernel Memory Sanitizer (KMSAN)
> -===================================
> +===============================
> +Kernel Memory Sanitizer (KMSAN)
> +===============================
>
>  KMSAN is a dynamic error detector aimed at finding uses of uninitialized
>  values. It is based on compiler instrumentation, and is quite similar to the
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM7rytkGRjyG3Pf5PakCdibtpvsm7o-K3am-U0kT-d2Rw%40mail.gmail.com.
