Return-Path: <kasan-dev+bncBCT4VV5O2QKBBW4PRODQMGQELVWL4XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC3CB3BB99E
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 10:50:36 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id d14-20020a65588e0000b02902288bbae35bsf6409856pgu.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 01:50:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625475035; cv=pass;
        d=google.com; s=arc-20160816;
        b=SsfaYvmlyJaR4Nfo5+LLVJm2hw0haR/WwC1q6mw3GGEK1Yz+wiW3MYhwcNI/mxL89j
         LKdbiSU11kRFZrZCZYi2+75kRdzjpE2MnRsyfypoRbj+zwe6nXnRDDGmPQuvL1YkR142
         ZL5bvgJF7032nuBcdOTR24MnWoV7Dee2cFqhzowEmuj+F13fNGY5Mqu8VYJ+KqIb8Tmd
         MZPr3SCAk/BSlIWEm5X4Ys0mihKdwfPyigSBWfBp17O5DF3oCVMQa9qzpN4SFL5Ww9nr
         l/Coj3WO8IqAHFmSHU3yMzzFdnEJbBsBGvmjuV1sNULZ8MbDDYCC7qs5xjqhvjVVNRLQ
         /Zgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kPeimqhMT8G7RP1GseIaJmSLNatEjK2H8aXNuL9IAcw=;
        b=QKrPwGqSZmxjZb/9l0O7sAZO/sc6BBeulrUx2rddA3NuHXUHavQBzlOwV4FwrXxcBe
         zdQiN1k1Mtie+hSSFBncSLVsXlu+MC1z9zSclnaunsNonUoqMZ4H3IMLj0O4E0YFUkTq
         znh65+LO7+K+QzCjfBgeCAcIvCmgYWQ7dYsRkiw0gNmWZuORtjFigJLHTIdWwr0PmWjs
         Amg80T3ielrGqyxJoXZgc9Wx4Ma2NBHBPeJ7ER19MfHVGRFOsQJTsU46dcRRBZKCJLVy
         fbOyOf75TfgJaxrVDDDhLgQDRyXmpgLXq4lYfIppwN6Ex/4w8y78DhaYmjwtwE4mJikq
         Yz4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qJEV7ygJ;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kPeimqhMT8G7RP1GseIaJmSLNatEjK2H8aXNuL9IAcw=;
        b=oAj8u/Hty/lRYVOaYzpI+eI1T19oSpUpYN42uHOZwW8BOFLEMzkm7m1PabnkusEZj8
         duPcK1iopbv63ole0BKLDtO8n3agIMDJEwZTomSLgkhDnXk3Cj3cB5zxUEK1jsnkzibJ
         8jq3wI6u+BDXFfxGNWle337lHOy+iKymh3l+5wN/n+XZW4UKpCfAipydPD3hNY3TcY9Y
         tPSj8Bg9p3WdXJTMelwoM9LxzwhLstwszciENGCuhHxCFDjsaBOmL/0ok0qKd9J6qKtA
         4eJOIKIfsZZT6X8k2bHFihjWLsPgq/2wX1HK4IRUnuu7s0tjJZ9ApqQo7WHwXqEXtt60
         YhPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kPeimqhMT8G7RP1GseIaJmSLNatEjK2H8aXNuL9IAcw=;
        b=qiEvtC+oSrGdujRF6XzqkvC3NReO6f8p2S6bOEX0pMZYKaF3SDfDrPZN0IT4rKC0Pj
         zQs0LBy9rY9uQhYvzM1lCyMyDjDjfhqlX5l80pMq9ktWaaEWaYcyqfydLaBds5NK6jOY
         lhDvp343WFklzfs3IueNDz/34fGUQrq4RIUSNC3CoMIBf1ggg3XoPOgA7IpVZuWSh6/Z
         FyY8y55Lz+RzhvqdGCSdutik4cwAU1WQuMzX/IrQCBqt+pP3thNo1YM5FRHu2nakp30E
         B3c1NxLBZLfRwlB9SDUKX0hZJQ4zXC2KgzqKdcSl+CPTiHLox0Bk9N5bLycIT+/FPjjP
         r2GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kPeimqhMT8G7RP1GseIaJmSLNatEjK2H8aXNuL9IAcw=;
        b=UxKDgOWIs1YBTa0G/7ZBf6eBYpOTQ/rjPdHVk7hgcIOLmemyL9e0fOZIxNKUWCg57p
         T8EzA8g7gwwpiQYoSK88dLhryB9lOOxYSwYjfqAzIiQNtzMeaH93i9ngMhBQcv16dDSC
         CxEEZRDVeBuHue+fTAABoZ1/6k1I4FQu31k/zIiwd6z837I6F9s2TeoN9r+RRxBq7oUW
         EOHyG1j9fWuJonAXBjTjjv2VpW9StksEB9gs5atOnNSft3A/FBvEG2ZwR1uAS8z/vEND
         7vj1RtwJGGyvoZKwK6b6Ln+WzUxCB6HaOto/ZxWzgOM32z5dKtCroom2YH/M+aVw/ZM7
         KONA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IeDBIbzCQluyEd/zZM1Jikz2ndJoG7/5nbjaUtT9svIV2ilIu
	bMkAQ7qun/tqfLiQF/85AIU=
X-Google-Smtp-Source: ABdhPJyk548pzjDGWPy+baODbM3rQSfSwtLOOYSIh+X1EaWIAqYaVIHExpU+8rKK4hZe1TBn70dNFA==
X-Received: by 2002:a17:90b:194b:: with SMTP id nk11mr14155118pjb.85.1625475035352;
        Mon, 05 Jul 2021 01:50:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b418:: with SMTP id x24ls8817703plr.7.gmail; Mon, 05
 Jul 2021 01:50:34 -0700 (PDT)
X-Received: by 2002:a17:90a:f198:: with SMTP id bv24mr10897114pjb.141.1625475034790;
        Mon, 05 Jul 2021 01:50:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625475034; cv=none;
        d=google.com; s=arc-20160816;
        b=TjVk+JsQD/ClfiGBN3P1YR70rdfaX/joT2FP+zSRM+VeJoWEKwNhB6iwOI+8PVTW/h
         Zcm3yqkFSBt/8+7k1S+JNvurV5za57h2OSoD8XX0BOGJou1NYGitJqeHHJN/SUTZVH/B
         l4R0xkB7+XEiHefVEa4elcmMBj/PsfvMBDC22JVKUGyjUcq20JmD09DP2EqR4tjQ4y7u
         oE5anJpsD/Cym7nPLeqT4R4A7lXzlM08vZw5Bn/UopVvX5UdbXNKiDu5fKSNj5b5oU8i
         WqwNNzkR1HnOgfzyztxe2OTyoPwd1s9lM1/QJv6X9GdU6+okF2VyvwWuAmFv2Z4SXOPH
         bVlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FvrjfH1l3R1Ny9FwdhcW/69zM1+NBkCbF2wgXmSb3LI=;
        b=P2qHR4RCa5sfVHcAjroKNdM07HtL32z1PQkViHl2h+93FDoMOpGmitJvx3u2wOje/h
         PgT6zZYRp+s16H6/lHv825H9bKhZScNPnDpHoy1OM3tGP2ID9SWSHLGH1dsOl4EN1ed6
         1k1TL9CYdFuduu5k8R5sIQu7X3KlEG1l7DZf6Ro37DToUiIRv++JNEYFfOMlVlOx2eju
         Z6P4/cvG+1+mbk2yTF9ClAtJ+KWZ5//qtuHmOThknNG3dd/Hc7C+zj+OkA++PDycHNJv
         PME2NYr3EsZ153eJI8x2pDN/Iy7qUn0nECRDolMNSinfI/zz0WNQ2m6MT2NIaleSoJ4j
         ovWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qJEV7ygJ;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id o13si910542pji.3.2021.07.05.01.50.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 01:50:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id x21-20020a17090aa395b029016e25313bfcso11385054pjp.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 01:50:34 -0700 (PDT)
X-Received: by 2002:a17:902:e9c5:b029:128:d5ea:7ef5 with SMTP id
 5-20020a170902e9c5b0290128d5ea7ef5mr11777932plk.21.1625475034406; Mon, 05 Jul
 2021 01:50:34 -0700 (PDT)
MIME-Version: 1.0
References: <20210705072716.2125074-1-elver@google.com>
In-Reply-To: <20210705072716.2125074-1-elver@google.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Mon, 5 Jul 2021 11:49:58 +0300
Message-ID: <CAHp75VeRosmsAdCD7W7o9upb+G-de-rwhjCnPtTra2FToEmytg@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix build by including kernel.h
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, pcc@google.com, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qJEV7ygJ;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jul 5, 2021 at 10:28 AM Marco Elver <elver@google.com> wrote:
>
> The <linux/kasan.h> header relies on _RET_IP_ being defined, and had
> been receiving that definition via inclusion of bug.h which includes
> kernel.h. However, since f39650de687e that is no longer the case and get
> the following build error when building CONFIG_KASAN_HW_TAGS on arm64:
>
>   In file included from arch/arm64/mm/kasan_init.c:10:
>   ./include/linux/kasan.h: In function 'kasan_slab_free':
>   ./include/linux/kasan.h:230:39: error: '_RET_IP_' undeclared (first use in this function)
>     230 |   return __kasan_slab_free(s, object, _RET_IP_, init);
>
> Fix it by including kernel.h from kasan.h.

...which I would like to avoid in the long term, but for now it's
probably the best quick fix, otherwise it will require the real split
of _RET_IP or at least rethinking its location.

Reviewed-by: Andy Shevchenko <andy.shevchenko@gmail.org>
Thanks!

> Fixes: f39650de687e ("kernel.h: split out panic and oops helpers")

P.S. I have tested the initial patch against full build of x86_64, and
it was long time available for different CIs/build bots, none
complained so far.

> Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/kasan.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5310e217bd74..dd874a1ee862 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -3,6 +3,7 @@
>  #define _LINUX_KASAN_H
>
>  #include <linux/bug.h>
> +#include <linux/kernel.h>
>  #include <linux/static_key.h>
>  #include <linux/types.h>
>
> --
> 2.32.0.93.g670b81a890-goog
>


-- 
With Best Regards,
Andy Shevchenko

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHp75VeRosmsAdCD7W7o9upb%2BG-de-rwhjCnPtTra2FToEmytg%40mail.gmail.com.
