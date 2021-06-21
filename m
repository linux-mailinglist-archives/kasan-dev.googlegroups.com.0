Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ47YODAMGQEQDAMXZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C29A3AF235
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 19:43:04 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id v17-20020ab055910000b029027851bdbbf2sf6004298uaa.11
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 10:43:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624297383; cv=pass;
        d=google.com; s=arc-20160816;
        b=hlnCQgC2sPvlC0x8xZX3Zu5GhbqHXTjEsUQ6Nl6nthSkB+u9paor2p36TvMvIAj8GJ
         asB29oGyrapywMjkCsCJENYFytHzPBMA6qHIBXKzbXJNe6pDhPL1pn44wJT46vS7fEJK
         2MYkLPMJy1n56l3qO5TPE0Moh7CnADPKvvc4xaFi1Hrv8116n0NKXi87BZU7Y/ywVOKk
         OEJ2CrFs/7mtIAHA6C1/HwVA3+Wix5HPQfpw3CQt8lYwjwZHD1zCud/1mZc8dHXu/i5k
         H5FvSZLwceUXM6UyCZankXH9hnNwbeUeZLB04IlWd58Yh2Z3z2Rbe1h/XXoyTceM4gCg
         Y7pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L+0tAg+44XqO4V9pLnxoz768ZpktcBTUmNbLyx61Ayw=;
        b=Clryx90SVtmwdWHM9opJ2t5EqkmEhY6EzAvL/HW9mLEmQsxIhTOlF7oDlXSMIJ/0np
         1w3kbgZzCqZ+racvyGvl4sRPbzUkteKr0U7pe3iFw8Y2ESVCL1Apm3IvOQdaUNiLwWVf
         9uVmq6/S5j+2AkBygKED/Exf8jgFQm8nlO8EveDrNPJOAVtboX2ih2s+hTqaX+IDL3sr
         2IjnttSzw/yNTC/3886HAyvg1/HulEorG/lYj1VSED83X1OAuaZkv7wwYr/371Ail/w0
         UNKwpdHWnOyTi++MldiqAl4NF+L/ig8f9Q3WTW38zkmkZ3NcVGqgIUPhdmFTEcSmSM0k
         L3tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CiXJ6n5G;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L+0tAg+44XqO4V9pLnxoz768ZpktcBTUmNbLyx61Ayw=;
        b=LtD7N5d1hfaeJ3jNW0vwyLqZjGY4OafdCV4k3a+QZYLn0n9/NAydAujEkvX4Kgc+Dt
         945x6mh/I9XDRhMeB+JnzIDZef8icOi5m8CSqW7rJZBxczMzDxMxhMMr9k6i+U2g1lYk
         1bKpYZELAGGO5GDAMq3daCOFdPmus6NSCRSk8S0DIYL6zgQ0poaVgjJWQ0zbEQb//dwT
         Hr+QyHuAGscv3lrsPDTobnjkYha5S3WZIHDdkv+PXaqt+bfPmJ8N1g/Oxtrgx6GDrdSP
         5Rktdo3bvgv9X7TwWJU4+83xqKkgleFQoEaSMid2YI9JQ5/dnKasZp5oZTw8Vw37Md2F
         2zDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L+0tAg+44XqO4V9pLnxoz768ZpktcBTUmNbLyx61Ayw=;
        b=WyI7VmtXcNdxUJwR5N0d5KZ+XJU/XHYJNsk4atexEcyiCFJsQjVEKck/Tj5ILYvpeN
         h+rGZO+WPArPZ4QvWBq0Y+goIUZukJ/rph1qKmm0cT4FfP+Vy+smFRF4QVeoB7wstMkB
         9znbkIP/cinhAc6S1FpzDf93OiwU5EhTEY7kAdOOUNweDcDZXiq8bGWKU1X+HQ7h62V5
         9xjNepmH0K4NHvoJZkFs2cfwNYPP95KNwFVj52s8xFWKv7ZIde3ERzSDQaGfAGV5Cn9I
         1USNX8xdvIDxgmGvbTK0rFxt7I9svIXC5bkxzFCpormEL9LHmImACyPpLx4FUw7Tl73I
         wPSQ==
X-Gm-Message-State: AOAM531YiOOhNrZhEHSOC7D/+ITaaiambq2g8g8mNmvoVEHC1vNtBLGg
	wey2QZ+KKqS430TeF3+PcYs=
X-Google-Smtp-Source: ABdhPJzIVoucyjCIsQaYUJG5rfjd5uPRGYszazU1+ZUNzuQ21khFtKKsNKTnr1mLqyTLbVBVgpTodA==
X-Received: by 2002:a9f:2acf:: with SMTP id d15mr2663910uaj.82.1624297383242;
        Mon, 21 Jun 2021 10:43:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e9d5:: with SMTP id q21ls4634574vso.3.gmail; Mon, 21 Jun
 2021 10:43:02 -0700 (PDT)
X-Received: by 2002:a05:6102:45a:: with SMTP id e26mr9902541vsq.41.1624297382716;
        Mon, 21 Jun 2021 10:43:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624297382; cv=none;
        d=google.com; s=arc-20160816;
        b=sY7P5r8QbxUTBnKkMIyAR5hD3Q3bY9D9snC0rxxaTq1kLJoyXPPQHWGVtsVIkr1JYH
         d07xtGhy7JR+ypDV165CUmhRgbez+Dajn8v8u678vR9WdGLjAr+SexDsPYoMEO8rrrPM
         zOG2C73LQUr195RkAF64Y/95xxlRVllnVMWAXgwfthtVPnpERcwdLKtKQCpNdrDs16ze
         e2zVJ4cTu3d16mzkdezOvXp/A9pfGUfsCnrxIeof6ADI/+ZYHUSghYaqW4o7og6p2fuS
         6aX6QAl5OGUZTrW4jBkPDFME4wiEqqHK/6zx0O7Expizyr5iBSEirbzq0Uvvay6MJ+eX
         e50A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kWdKmgG81sJBpjzyn6TSXwSeeJGUkRqGGWlo4fqoDn8=;
        b=reBCmsB0MoTOs54JR3aFXo0uonR45lzS3LrN21+/z8gBVYjjSCCbdAvIrtSoD7FXPT
         uEDcWxc6S/NcLW4L0yMpi4RMqoNxZwMN+gRdsqA2VC+ce4aAZdZ4VA2pO+4Lpgp8Ue4C
         EIYa0SQLqo8F6WXVvPCKi367+amxNE+DX8dMHUGBee4RxHB7f6sOIV/fUckARqr4ihFW
         0monFO2QNyc8jjOA08a2fvDiMzzbudqku8CEh9knCNjQb9yrdl2a/1dIQh0M2qiboH4T
         79DYNfXVt4YiVJ3K5EjCgiy2ULclBxo4LqJRrEA2Gs/pxc+/tn8TwFZhKh6jz7GgYM2C
         wn/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CiXJ6n5G;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id g20si627668vso.1.2021.06.21.10.43.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 10:43:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id v22-20020a0568301416b029044e2d8e855eso9340897otp.8
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 10:43:02 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr22053479oto.17.1624297381993;
 Mon, 21 Jun 2021 10:43:01 -0700 (PDT)
MIME-Version: 1.0
References: <20210621154442.18463-1-yee.lee@mediatek.com>
In-Reply-To: <20210621154442.18463-1-yee.lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Jun 2021 19:42:50 +0200
Message-ID: <CANpmjNPYSVgmNU0gCobSb67WZ74-8s48LyN7N+sBtH15teVN3A@mail.gmail.com>
Subject: Re: [PATCH] kasan: unpoison use memset to init unaligned object size
To: yee.lee@mediatek.com
Cc: andreyknvl@gmail.com, wsd_upstream@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CiXJ6n5G;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

On Mon, 21 Jun 2021 at 17:45, <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> This patch adds a memset to initialize object of unaligned size.

s/This patch adds/Add/

> Duing to the MTE granulrity, the integrated initialization using

s/Duing/Doing/
s/granulrity/granularity/

> hwtag instruction will force clearing out bytes in granular size,
> which may cause undesired effect, such as overwriting to the redzone
> of SLUB debug. In this patch, for the unaligned object size, function

Did you encounter a crash due to this? Was it only SLUB debug that
caused the problem?

Do you have data on what the percentage of allocations are that would
now be treated differently? E.g. what's the percentage of such
odd-sized allocations during a normal boot with SLUB debug off?

We need to know if this change would pessimize a non-debug kernel, and
if so, we'd have to make the below behave differently.

> uses memset to initailize context instead of the hwtag instruction.

s/initailize/initialize/

> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..d8faa64614b7 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -387,8 +387,11 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> +       if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +               init = false;
> +               memset((void *)addr, 0, size);

Should use memzero_explicit().

> +       }
>         size = round_up(size, KASAN_GRANULE_SIZE);
> -

Remove whitespace change.

>         hw_set_mem_tag_range((void *)addr, size, tag, init);
>  }

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYSVgmNU0gCobSb67WZ74-8s48LyN7N%2BsBtH15teVN3A%40mail.gmail.com.
