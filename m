Return-Path: <kasan-dev+bncBDW2JDUY5AORB2F45KJQMGQEVTJMBFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 58174522229
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 19:18:34 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id bx30-20020a0568081b1e00b00326a3063b13sf2383168oib.9
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 10:18:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652203112; cv=pass;
        d=google.com; s=arc-20160816;
        b=XNdYCDmtVYPymPingEHidNjtyFJgj4tUj4AdSZZK7x/AGG3DXW5uvXNLOpLAwiPCtT
         qSBUxtyzPPfwqhvi+1ZucQhyj/0cSVhgX8+AZhkoInfwN7+SD9QkSK1Ep6Kv9gYgcxSr
         I85si23xgJzEfjw1CVQy58G5kVRYP3twLYHV2xm26Zc7Ua76ElpU17kfacBfLqqm4UVC
         7rEig2lGyehbFu/TANX8w06H4Ku+xHXth/PqmjGDGOTyLgo3yZuV1HDVFLxz4Rflq0px
         oNwBbf4fE9x4dhEhOFGFtKuAU80FuiCDcH2XscfeBXhsNdXrRQVnHS8hVhCn0kIk2XyD
         45eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=S6XaVPSkfsMIkbEnFf77+AzxasxkBukF8Cdd1OQMxYk=;
        b=x+b6ieQvUMr5LWBP6EBPMLarTwTxFgSK7gW497i+1H0luFK+jHv1mUMVw+2dOwB10A
         MAnKHVSFESPiHrP/PAZYJqMa1Ri1zac1pfR06OFI/ofvALqXthOD7iX/IKZda2HISdb2
         YWTn003lA/EXDLPaacMf6BU8gKfTx8vIVlL417QdWis0OFTkyEGYTDLgxShORGdLfIK1
         oqlASBz4yadhPm6ig0hhn+qiDJ/XBJ3Iq5XuYQ5QTqEzYjbv3UQCZItAr6ldTImMtAnK
         +6LBzBsZh2Tpqs+UZWHpexScgfq8lMJ/b0i7td8iBZkLQj35vb0AoVAsNwCXL1x+AWai
         Lrhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dE+nuGgA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S6XaVPSkfsMIkbEnFf77+AzxasxkBukF8Cdd1OQMxYk=;
        b=lt+y8gdJ0KJ2atQJSs7Kt7BKmykFo12F3iaj4SYkslsXilkFFy2WI2mRgriY/E1kNG
         w575w9buSgZol7gGg4JViZcY2W/1OuTNjH4UqIEDpV+xcJSVQzp7OY2C8TJUIUJ0JN6u
         jlSzkoE7Ook7yNOFOF+FbyjljCUbm8I8rXxusp170NewKIAI4La2qYNhejpdtAJvCOYT
         /OI1WM5KlVjf/pOAk0c3TRJxIyYjeo5a3EupaQKzp2VpBSlKAznTn1MgNDc1Uxk2owxJ
         QXyVc2igGzumLR0OrihJMjGmp+8UagkGx6X4eq2CN3SS4sbJ+lf77x/rrRx73orGS1Lb
         jDEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S6XaVPSkfsMIkbEnFf77+AzxasxkBukF8Cdd1OQMxYk=;
        b=oe34lMn+2LQRRLQbg/GxRDIAZAqe166lJxPJDVquWNSgKMy5A54GMaVEjZrZW4BgGP
         vRXFYmXnNl85QWkKsxguYBuecJPzHLnOomZEDzunsjt+39p4w1xxSh6F6dP0Dcsiv8tc
         nJ+A+sFtjNQ3tOALDiXsPsZcA6YnvuXISQutaRtiLd3H+2jR9EGJrLfa76+cnOYS63Uj
         ULssyhym1K1O8fTkinxOQQd2OL4ccYJoO24uw2exYtxxD45Th5UPrJagHhVAxcCQBm15
         Q2gvQXN21K0I9aLRBje3EN6It84B2i3rLTFfRTPWV36IWYHvgqCqELkvfFxfWSVBVmiG
         diig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S6XaVPSkfsMIkbEnFf77+AzxasxkBukF8Cdd1OQMxYk=;
        b=lFrQ7Lz4dDoZ0yzuuWJsWCx1A9DcTBWMcsxi0lg2yV7ZHxwV8scC8EiKy2gNJVO3PX
         HX4z5kXxLouNktoxYMEbscqJzIcvzk0Aqyk541HhvhgdhQbUpc9YTwwAHWQ/boVkdJBG
         Hgqe5darDghKai8g2e5If+Ypo02nQOgPLkqefSUSWLd2tM6mhZK4IMzwYG9yLkRT4M/I
         t3IqodACWkucOEK9XH5Umf/JiD3oXRbOWyXgsNVJpbI9JRAoJ1/+NdhyItXFYV3bA4ST
         DPJqaBMuK6H4QBZ+20GyQZe/5RRsb3ecG6gbeMJA3AIOTmwap8LpAAsFaw0iriLb2qH6
         3xRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sFf22rD/FvY0JDUhw8m3i02mIgFBHuy078GHv6fGaQoCVRnBk
	e65k1Y4ffnKSfX7fcqFY/YQ=
X-Google-Smtp-Source: ABdhPJxsbfydX3CZPIpELoJmy6lhXSGhqvUyAUn60rLs4ZfKOkEnfty2QMP4XYvVRXCg2uTNRQp2/Q==
X-Received: by 2002:a05:6830:4ab:b0:606:2151:74d6 with SMTP id l11-20020a05683004ab00b00606215174d6mr8470869otd.322.1652203112745;
        Tue, 10 May 2022 10:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f693:b0:e2:1a68:2965 with SMTP id
 el19-20020a056870f69300b000e21a682965ls7241298oab.2.gmail; Tue, 10 May 2022
 10:18:32 -0700 (PDT)
X-Received: by 2002:a05:6870:14c3:b0:ec:578a:72c0 with SMTP id l3-20020a05687014c300b000ec578a72c0mr619567oab.151.1652203112421;
        Tue, 10 May 2022 10:18:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652203112; cv=none;
        d=google.com; s=arc-20160816;
        b=0RcMra8tScbrkIjzXpFjaXrwofKKlZlIgqHnhkX02g/O3gDkdW4lnMwslZf7gizLnx
         kzWROzu18Wud1IaPv719Xy480Wzhc688xf0AhNM2RL743jGDqWnek4F9ZEwuPQ4UgalH
         qSHAI+F9YIZXsSYbkbcs3SrvS2P1RtLf0v92PC/kCSi+gSMFXpqM5qFISZYk895SacJr
         yHRK/RlczWMeoMNHw+pG/SfCV4UfFtnkFDbxaJSyZXSfnXbApLcpmMP4bstd/UiMssBY
         2f5UKAsjNFkXD5p9u9TXSEEW/eGCMnjffk0SjaG54yKtC0O/ZW3gRtlYt62byiz21ui4
         D60w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JjMlOQV9Js69yelDDoYzxf+n6vZz1PVMWrLc6+SPdvU=;
        b=mTpHMagt0wYH+1xzErjYYx66/VpKVZosheMQ1qSL1+5Qu5GWn1rX+vO+4RLTlUv4Kl
         DM5SEhYXf1mazScuzDf1J3JG6Ize8gd284lz7QMGFZVSN4SdjsSxDdbScZ/swx2EN5Bn
         97HS3AbZOMclxQ33Xjo96TUrfYK88C/WESHAP8CSIW/7syEokAUvYUAesIJPRo973xdV
         AUFjJzzL2EwHy4qIP6wlrGxPhGaZKmJxhS89Rv5mdNfYBUTeIP6P3JrP/ADsisVFkZeA
         rQLmIDn59nwHoQcmh0wBVUWToNgDxBsuMx1hrjnT2rxW+Pv5bZYnXX3EKrQLKMLtKEUA
         bJbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dE+nuGgA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id x30-20020a056830409e00b005e6c62a483dsi972652ott.0.2022.05.10.10.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 May 2022 10:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id z26so19216464iot.8
        for <kasan-dev@googlegroups.com>; Tue, 10 May 2022 10:18:32 -0700 (PDT)
X-Received: by 2002:a05:6638:168f:b0:32d:8105:7646 with SMTP id
 f15-20020a056638168f00b0032d81057646mr5172978jat.9.1652203112126; Tue, 10 May
 2022 10:18:32 -0700 (PDT)
MIME-Version: 1.0
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
 <YnpVJJz9IKyvBfFI@elver.google.com>
In-Reply-To: <YnpVJJz9IKyvBfFI@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 10 May 2022 19:18:21 +0200
Message-ID: <CA+fCnZcnVf41WrFRAV5RzeL6J9tkhTpYSYZrhZtC=jfWjTvXeg@mail.gmail.com>
Subject: Re: [PATCH 1/3] kasan: update documentation
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dE+nuGgA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 10, 2022 at 2:06 PM Marco Elver <elver@google.com> wrote:
>
> > -For tag-based KASAN modes (include the hardware one), to disable access
> > +For tag-based KASAN modes (include the Hardware one), to disable access
>
> The changes related to capitalization appear weird here. At least in
> this case, it starts with "tag-based" (lower case) and then in braces
> ".. the Hardware one". This does not look like correct English.
>
> The "hardware" here is not part of a name, so no need for
> capitalization. And "tag-based" can also stay lower case, since it is
> not part of a name either, but an adjective to "KASAN".
>
> Or you rewrite the sentence.

Yeah, I agree that this looks weird. I'll just drop the part in
parentheses in v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcnVf41WrFRAV5RzeL6J9tkhTpYSYZrhZtC%3DjfWjTvXeg%40mail.gmail.com.
