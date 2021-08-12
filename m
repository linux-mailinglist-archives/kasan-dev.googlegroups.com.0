Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWGE2OEAMGQES6A2YIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9C9B3EA115
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:56:57 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id l14-20020a67ba0e0000b02902c10effe47fsf163425vsn.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:56:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758617; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gsu7q8g5Pe0yeHkRDIoPXnM+U8wb0JOAzUcN9aUYYHeHA6pcgzH9qD1hoxkCQuNLk8
         RLc2SjdtAZ8lPkFF0TTNAi49xVMOST8WgmWArbNdYaSyWaCTspsgpVvliL23k8spNWx6
         /wjDfhRZeRwMM+nR+z2X1uY3/AfDP8i44HXgf3a7+awLET5Oi9Yy9jCkQx8EzVvQDoiV
         6vYegUERylf/QpO1CvNCSQY45NlphR9b/uZWwl2igMv0c2Hulr2sYa7r8K9XG5GKPnIs
         KFIWBDWElVIGVZYJ1ihHRcVzMCJ80mGkVv6zeFGBD7e/VNKTU1c8t6QhAiXzTjz1044K
         9sHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=neb5j2GnSb7TDlL/279F7NFWNSUR4oRZT8DAW4gTu/g=;
        b=GnB8wYBGV8Vwnjj4rVHmp6OeNOW92WLVNuSBV7uhIVLVEa1v+VbKem4Lr6XHMFQu/Y
         68F9qUQA9nnVYUag+lAL0f5c1WWOrmSyPueQTS47ZbRpavEqeB9XLtueGnpH3QLIxG/F
         xbTjJosiCqOok2uXWSGntzPxAFCaaGE64jqoi7Z1MEB25pe2K0ebNonFxjtH0BZpewCp
         Kip1t7TDLIEVAkUi30RTedG45ehk4b+Ha7MAhy+p97hpiQMXObdmZndnCqGOqtLa8cAC
         3zJt7D+nDUAx5Bo1iDZKJFO1LywtqS+UuX7Vuhf+cj+eUYJXaEoRIx5X6eIwYCuVOTXX
         EPOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XKyvMwXf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=neb5j2GnSb7TDlL/279F7NFWNSUR4oRZT8DAW4gTu/g=;
        b=InmVgfvCiWZjuWeaFfgtYtjj1JLkn6gzNsoEPqSYWvPVx1Ad562hact1jgXJRRR8uH
         fBiAnn63p9dYND89xvmZD96YRmf7oX1F50kD6pucOEEiJ6PSVs9JNkwYAckFNOrH2D4R
         NxcphZEwm5Fe1EHprSZqGwWv0+PEq/so3QD/vGdssnDXClWMn+LSsQ1C1YJjAbmaIe09
         E0pD2FIsRIGCy/WDQXcj32MG/ZTCYItIyapFRiA0G2Ft7ykWCI0dLx+o9ERQg+zDqJuI
         ZKLkRG3IJmzwEvA4QMK+a9SEyUXILTCcDV9gxkJmCsLFRScWZ1GG0toOrBaTxVLLdiCr
         eWXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=neb5j2GnSb7TDlL/279F7NFWNSUR4oRZT8DAW4gTu/g=;
        b=L7jmrYH38WjOAOe8JG+/rtGLGb00RLajIXrecDPknppZe7vS1LItsdqQGBVY3BTY/z
         vr0bZEaytbHf8AdvPVmyYlAm6Rded1pvVPAL3D36V+uTAzYUQqGoyaOF0KQaJpzlc/yt
         +SNVRwDw9iGDKKbcaYRAkFu0/J5Ejy5JSi7V2/Wvpr1JnzRAAUJlum3mP6edfausH2xH
         yrRus5cg20/z1GhR40O3AkRxPhTbjgT3/YdyR4MyBySR2V7rl/w3611seI9pPZS+JAuK
         xRykPh48STcGnYH9/BXz4F3zSKCF+C4G/EtWTK6LIKll5e0Sr/ifS1gdxRe5soW9XhOD
         hzdg==
X-Gm-Message-State: AOAM530foaaZWQ1kgBb1Cq1kUux1uOypj8rSVES31i3mC3EBrZoKxNm6
	mIbbm3I2pF4t6sK6nnPvPKI=
X-Google-Smtp-Source: ABdhPJz4V8lBRUed/lGt+6264QYWbqFFJan/DGiCRc6LdGruRJShRkcSl6IgAEyz2du4c5q+P7b6Sw==
X-Received: by 2002:a67:fad2:: with SMTP id g18mr1902262vsq.45.1628758616903;
        Thu, 12 Aug 2021 01:56:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:5e03:: with SMTP id s3ls884190vsb.11.gmail; Thu, 12 Aug
 2021 01:56:56 -0700 (PDT)
X-Received: by 2002:a67:e95a:: with SMTP id p26mr1876632vso.56.1628758616401;
        Thu, 12 Aug 2021 01:56:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758616; cv=none;
        d=google.com; s=arc-20160816;
        b=SqadG6h/vtBVzi78rkn2nVPxno2X4H9EpI/wD3k1Kq87E51PUd42kKjj+ezBHyd/6k
         TH+8eeVMwyt8LCGKzZylOIA10xOiz37VVQ8CCA0c7tKlk31uMiV+4cQxWA25v1ZohasH
         p4NZVZmZGtjQivY6YXO3qXrUzZuqi3q15+r44pvUU64zzdSGlKshMeT3vRG/kRAbA7zl
         Kx5hc9iE/b5tCUwMsoFIQi6dzqT7KY5CK7jGl8sC89A+o1ZPzZRugHW+WMf7sGMwytrY
         TuU/Iw++XECBMwpo18GoAgfl72iO380/LzrMNgPAEEqKeKeUA32ZQ8U2jN/yfkU6SBj9
         MJyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CpNbFyXnXHPCTrfQK9jrNKENE4zlP3yIY6h8yYZAoL0=;
        b=cI8W2gWo8qv42TBxVzjGeK7y1DUW1TjVW91Bf7vX/StkAlizuywFKXJpwyg/hBF8f2
         zC2+T+Z75bLjCTlGesCDAP2A9eAglnSFXf7BRwhkI+ebN22DLns5ZzYH9Z1NPpW/CCg/
         a3+RAwWDd/4a314PuJ7skWyISFFu3kN3xYmxPWnUMRpdpm3NNgkSARNKftqFAVbhD72e
         Gyw8lryMoCxpAcuqCiXtWu/h0QAi4PQwYA5wTvScI+uiUCCJxM7M3lWF+W8ZIszrje94
         atWD/TlZwHNBAaNqlRYu+bCb3cSg2F5ivlrR82wSWY2j2vyiXDuA5Zhtb1g9cNiLpNAP
         1a4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XKyvMwXf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id m184si154688vkg.1.2021.08.12.01.56.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:56:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id bj40so9262410oib.6
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:56:56 -0700 (PDT)
X-Received: by 2002:aca:2316:: with SMTP id e22mr2503665oie.172.1628758615724;
 Thu, 12 Aug 2021 01:56:55 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <6e0ddf32ce140b9e8aaf127e9e40cbfff4430995.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <6e0ddf32ce140b9e8aaf127e9e40cbfff4430995.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:56:43 +0200
Message-ID: <CANpmjNMNMoPc8S_xTG3ANBZkVsanq=vnsAPkL=pe+cOXbTySzw@mail.gmail.com>
Subject: Re: [PATCH 5/8] kasan: test: only do kmalloc_uaf_memset for generic mode
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XKyvMwXf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
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

On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> kmalloc_uaf_memset() writes to freed memory, which is only safe with the
> GENERIC mode (as it uses quarantine). For other modes, this test corrupts
> kernel memory, which might result in a crash.
>
> Only enable kmalloc_uaf_memset() for the GENERIC mode.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Acked-by: Marco Elver <elver@google.com>


> ---
>  lib/test_kasan.c | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 0b5698cd7d1d..efd0da5c750f 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -528,6 +528,12 @@ static void kmalloc_uaf_memset(struct kunit *test)
>         char *ptr;
>         size_t size = 33;
>
> +       /*
> +        * Only generic KASAN uses quarantine, which is required to avoid a
> +        * kernel memory corruption this test causes.
> +        */
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> --
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMNMoPc8S_xTG3ANBZkVsanq%3DvnsAPkL%3Dpe%2BcOXbTySzw%40mail.gmail.com.
