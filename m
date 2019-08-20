Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIPV6DVAKGQE3DF4ZRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A97F096881
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 20:23:30 +0200 (CEST)
Received: by mail-yw1-xc3d.google.com with SMTP id k63sf6489720ywg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 11:23:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566325409; cv=pass;
        d=google.com; s=arc-20160816;
        b=c3e29K0vaPxG+jLy/RsXyd8awR1DfAids5Bt//b5mKYRqJgASc55vQUQXiH60L1c/R
         95w+asGf+6O8gEBeJtR+wONdSqynztEU7ulC1TLpFAjWaL7+3gget059C1/O3viSdM3m
         S+CZrOnKd+/2Ryvx4zFWYI8/Pqc3I6Df3cCHVvmqwSKuGQ6nYAea1Kp6r+HAcTwmzMb0
         Ju30o6atZehzzMV41sYk0BSQKp72TRi9U/fgVN/E+42ImcIudcoTjTtdsOksfaOIXwDw
         38DYeRQIKIHWqSVwixvE7D/g4I7WgAEGvhQG12wtIMnAY/GCyxqpbKLhZp7f2Ix6pjE8
         4wtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GEz0+vVjE0GfsfFnjjXiMAYogiIx4vLMzA+4cpjsn10=;
        b=oIdCqOjBSK4e+rHkbgMnG+dWTr56Ry/n8Ws1sdjN9QLXDaifYxciI4oNFdI/iK838h
         /NPk2nRh106AdAl0iZBCYVBHRxVX9OtxdKGdNzHAnzy3cdwHr9RDhnHN5V3qdhGRHDTp
         x3cVTn2pz0toI7FWQqsrapox11/rjhv41Q1gs5GEsu37mlJGXMD9E2rT/ULcFSpmPnRd
         gvDz4BjnZc05Zzys20h7SKbWFcWsmhFpLWfbI6nHgsovTUNSRCRhGfEi+kNEsh91zTxA
         X6x6pGI0d6mI5cvrLLshod7Xn56xjm6Lsks0+w6HdCpS0cUiCTZBaoOdb/eAKYD4zXE+
         VhsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RTgt2WBF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEz0+vVjE0GfsfFnjjXiMAYogiIx4vLMzA+4cpjsn10=;
        b=TFDdHSn7frjDTMYccTu8bf/Gdb0wq3ywo2WR/a0ChaaUw6kHo/hjDxBIKDaKS9jFIV
         vVunLkz5D7IFFWWad52CYvEbSMQr1Em58S17OsMxgIEtE4F4UZzRySqCC5EUqM+alXge
         VhNBeD2MNgjSduAe0OY5zjCvB2yHiW6IbVTfekWiGU1hFFp9IMu8VN/SmBT3pbVggQCf
         XfEiXPxTceHZalgeHtDZvTb/K5L08cfnsBA1FyoiUSXByodTMrUnWpXsBtifmJpXCePR
         948NstC4qVflWEpnlo3IKzQljS6yZ/eIzMLLROZQcDd56TjXBDdFuKuKJcsvuzaCkMsQ
         91RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEz0+vVjE0GfsfFnjjXiMAYogiIx4vLMzA+4cpjsn10=;
        b=Q6hzBaueygzrkO4SMyUUmi3RJO0wL6ZzABRLDOTtRmp8VrjXuPr3LCJgiZOJo126EK
         pR/6OTF2KeKVyl6PPFp5ay5nufjMD7iWIJLWus/zW84fcnQXOQZh0ajP6Uqr+ydBQvv+
         Uo9TQgCivA+0UnN0NbNqvj/39VJ3IlUM8GS7hjCiqE1cyPVerr08kG2tStECKvBnyRGR
         OGUcdugxXmaGLoQSqTId9hom8GFWXgUla/qFZDpgQ5aFAdyp8d80xLMsBvmQB/hZRN8X
         +eJQlMrUno4XBqi3c0nYmxAimxPp+7gly2X0uYUHNQnwed78Fma/Fv4qrsTUham08w4M
         kcFg==
X-Gm-Message-State: APjAAAVhcpcehw7WxQrEEvV4whCxWe35ZQ6+ch3vsf/LjlxlhNBrqyAC
	DziFlNuZCP34cMj8C0FOl8c=
X-Google-Smtp-Source: APXvYqyyaIFPdoSa0tQnZMDvzg0aI6ETvc1FgQwCeAo2VXvM2PBt64Vkf8BKGgc3fqa0nOE64PQm1w==
X-Received: by 2002:a81:368d:: with SMTP id d135mr16023767ywa.94.1566325409727;
        Tue, 20 Aug 2019 11:23:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e4c2:: with SMTP id n185ls3471084ywe.1.gmail; Tue, 20
 Aug 2019 11:23:29 -0700 (PDT)
X-Received: by 2002:a81:358d:: with SMTP id c135mr21732600ywa.269.1566325409414;
        Tue, 20 Aug 2019 11:23:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566325409; cv=none;
        d=google.com; s=arc-20160816;
        b=pyJrRSz8+R4muXuHWWNOC1w+B/pbNVh5ml3QYB6Q95mybFYnVgaDhy/Nug2ty7RO1G
         fsvmbJ/cjjKJ9dPGrBbOGcHj7Z+gl7dFl5Td6sjn88/PiKWmgIcbHad3+1guPcxPJ3rd
         DHcU3EYIxpLnR8TpEVj6AU182LhGFUEteKkpNH1528LsA0U6E+DrZDBHmOMjyQg7lPs3
         Upd46pgZc3gtrYhqHIQe6DFXN3/wP84MBD6l12TF4TozoyNrRZuAaG7UpWi7NVowY+E9
         3WD5vqPi+/svHWaXFtwapAMgokdxgwQbJ1aMrnG4+ljMU0gLymVf+1pFQ5gV1apCgyZi
         8inA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zOFyNsed5rJiYxQ0MTC7KZVSzKzfGGoAHwsINBTkR8c=;
        b=EhUxE9+e2ya8v1WXwXX63fug0h2QaIPQxuSuGNb3ru2pyO9/WXL/c9/xmRJZlMMkJJ
         KRsxTREKBu38iaxWd2N1tt8nGYR5njzJzhOr0Vz1aBUPhzHfx8s/Fe005usqM3b+LUpF
         fVbUwSKFRtBN3W4YSmxNZ4gxr10P8drEHwSr4PavCZ2dluFemmUX3fIeJSL5zJld2vYa
         4EaMded1fsB8FAK0iJBWziAaGiOEftVz3z3UIKmBy748VBi29Wgdi8Y+wCsaGAZEENPL
         vRNGPze2/y/PUlAwVKgXmlzq/H8C01ysB2ZWnc7bsEyNIUx+nvTMAZTIh5e/KyTtI2Eu
         vaIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RTgt2WBF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id f190si1243119ywh.2.2019.08.20.11.23.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2019 11:23:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id 129so3870952pfa.4
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2019 11:23:29 -0700 (PDT)
X-Received: by 2002:a17:90a:6581:: with SMTP id k1mr1293058pjj.47.1566325408133;
 Tue, 20 Aug 2019 11:23:28 -0700 (PDT)
MIME-Version: 1.0
References: <20190819172540.19581-1-aryabinin@virtuozzo.com>
In-Reply-To: <20190819172540.19581-1-aryabinin@virtuozzo.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Aug 2019 20:23:17 +0200
Message-ID: <CAAeHK+yhaZ07ojK4v-=iVTBiEunXOu=V3f9zvTr9P2wZzAq3Zw@mail.gmail.com>
Subject: Re: [PATCH] mm/kasan: Fix false positive invalid-free reports with CONFIG_KASAN_SW_TAGS=y
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mark Rutland <mark.rutland@arm.com>, stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RTgt2WBF;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Aug 19, 2019 at 7:26 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>
> The code like this:
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         page = virt_to_page(ptr);
>         offset = offset_in_page(ptr);
>         kfree(page_address(page) + offset);
>
> may produce false-positive invalid-free reports on the kernel with
> CONFIG_KASAN_SW_TAGS=y.
>
> In the example above we loose the original tag assigned to 'ptr',
> so kfree() gets the pointer with 0xFF tag. In kfree() we check that
> 0xFF tag is different from the tag in shadow hence print false report.
>
> Instead of just comparing tags, do the following:
>  1) Check that shadow doesn't contain KASAN_TAG_INVALID. Otherwise it's
>     double-free and it doesn't matter what tag the pointer have.
>
>  2) If pointer tag is different from 0xFF, make sure that tag in the shadow
>     is the same as in the pointer.
>
> Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Reported-by: Walter Wu <walter-zh.wu@mediatek.com>
> Reported-by: Mark Rutland <mark.rutland@arm.com>
> Cc: <stable@vger.kernel.org>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

> ---
>  mm/kasan/common.c | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 895dc5e2b3d5..3b8cde0cb5b2 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -406,8 +406,14 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>                 return shadow_byte < 0 ||
>                         shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
> -       else
> -               return tag != (u8)shadow_byte;
> +
> +       /* else CONFIG_KASAN_SW_TAGS: */
> +       if ((u8)shadow_byte == KASAN_TAG_INVALID)
> +               return true;
> +       if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
> +               return true;
> +
> +       return false;
>  }
>
>  static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> --
> 2.21.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByhaZ07ojK4v-%3DiVTBiEunXOu%3DV3f9zvTr9P2wZzAq3Zw%40mail.gmail.com.
