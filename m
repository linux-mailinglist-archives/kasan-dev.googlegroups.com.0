Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK767GGAMGQEUMUWYZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB49745CBCE
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 19:06:36 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id y28-20020ab05e9c000000b002c9e6c618c9sf2207617uag.14
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 10:06:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637777195; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5zfl/xMgKiv/Gf73gFtCQUoQ9FQtrVDUqFrVvxgq2XYsBSVd5IkXwrYsAfWIZjqRN
         nEFBDYcDXW2d+63M0KSVT1nrhSuJcw/TCKzjaRp3ozeRFr6EuQHGmZRSZP5UJlJl8r+x
         Jw+OfjyNEC62DxHvLcgy51cGiDakX3/9jaPZ+D3bp6YJ3h/vb7610+fKnng9plbS+KEC
         7bJyjQJ7YsQY4KyIJtwS7vIWnGU7ytwazw1w2wngRxaoadzhUDEzoKTKRlMiQKWGEufx
         e4pUCyFVH4esBvK/Nkc4IJvFSWaHQbjQHR+XTrwgG2jE8KgzuTD+DZEW8CEyZSiS0fEQ
         wFBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uJbv2//48ZAej7KIkxACGRTUbw0w/garTqss+hcT+mg=;
        b=XWufN8zF15jjaV07zVp+rMT9HA+47qc7GtRYFeI/Nu3F2akaQ84gPoOdQTr3R21FkU
         S4l82nYLvbUPcl0BuaL5ALDybdGLXIbs6lp/yp+jpubFKJf4bVycZd5/MqJOLrC6NDBq
         nqefGmFrz/GYWRSM1MrFafpFEqYPwkC2b1VCeg1VC73bJVwSWfPmTAHPVlWuqIsjFycv
         oE/o0KWiV2gndrN8SfjMZ4SY6HpYwNgGyLmBPnHIbFWQ0on8tBNYTju257b61LTT9lsq
         DrOijpfFtBKgbj/d5vf/JitlzLz9g7Mx3tXTFScVy9IDv+H+QbNmmBlxvOfjP1RJTA7M
         3z2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tZ1DG4V4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uJbv2//48ZAej7KIkxACGRTUbw0w/garTqss+hcT+mg=;
        b=jc8sgVa0RyWsxaTfrMPyjq2pRxdAHhakVkE81GEDhC0gKc981ipIPOrKgEfDoi1Ysl
         8ZX/f+ofSYEQiiSocwGGL/qMMWy9akOkgNW6P5Hv0BKDkJo/IV7kwatVZeFBOwU7i9tK
         rCDdbIbRPVbmUASWy9P1jW9om9guNgMvccNLrSGKWcXMoxHiZBVHWhixyUpRFBotlh2b
         wAd/Ia9qumxjJygFisFW+OVBcXs/g+pcOZXS+GWq5IK2I7G7Wiaf34t4JFsRKiMB5d7d
         CUY8qJ68+O7d2sqmopgbPaP9C3I4qYPECoynl3jYtj/FBt5sH0U+hkTKPj4Zq1Q5ZXc4
         9zlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uJbv2//48ZAej7KIkxACGRTUbw0w/garTqss+hcT+mg=;
        b=cRLS0J+HACPrLNad1HxzRQ4V1fTlDFmFzsDAHiqWzJKNGdSQnVyoO/BMoJiVPo5LxM
         D4W0BXvnrNWQfjiuGSYnHayBg2HEwqPG+0SSGvtcvHqtbe6SvHqicjimyNI3VHxhPmDK
         EatmxIxYJXWjtrgmwz6VaHA1X4HNgepy9gJ3EiYMyTjGuxt13RGZ8ZB7GwDee94xgy7c
         XFMl9+vClUCcXhvc7iyDUAqmAi1om6QCOtZDy33n595HwbfYBosYGA0lu3Qy81eOgB2K
         IwW2aSouZQHN1BGXHRSmcxRMg0w3JjhoghtobctIpFyjsYBOJUXwGvaGNAKHEXvI3zxE
         Wprg==
X-Gm-Message-State: AOAM533CUltvtm8YRCBl2P9V4BpX3/V521b7HU6/olggwR4TluRjg7db
	m6vOaWSgzl2VM9ytuMFowj8=
X-Google-Smtp-Source: ABdhPJzE4KWNV2jEMFEEH1ZjRZrunroMK17xx33fh7zTfAlkNVOZeYGLHoj+CZLPWdffU+cANOxLdw==
X-Received: by 2002:a05:6122:14b4:: with SMTP id c20mr3077052vkq.30.1637777195608;
        Wed, 24 Nov 2021 10:06:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2454:: with SMTP id g20ls142137vss.4.gmail; Wed, 24
 Nov 2021 10:06:35 -0800 (PST)
X-Received: by 2002:a67:e44e:: with SMTP id n14mr26598145vsm.55.1637777195007;
        Wed, 24 Nov 2021 10:06:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637777195; cv=none;
        d=google.com; s=arc-20160816;
        b=loIlIjl3dX/HGJkmgJBx959fTiGo+Ue1tT7ik3GOyQh3xoU9oMZkO7osuZyuTfQA8M
         4DQYmi7pUXvUqQdkSi7jZ+rUHRDaNS6HGlhcIHeuHcdhoxVzEKhoBHT5s3l03VqhsaEC
         TDLm/rvgKwyVrgV6TtX1prqdgBKWDpClOrCMpsHVuENX66ticnMvSesJgbTXHNbslzum
         M6RYK1i8YWNdC6MFQZBhhoUDaTDCfHHGFqxkFRx6FktwyRSoSLckkomLIvkovHbf/RyH
         1aIHYJ47+qq6P2o6O/Mx2IBBet2yAGSf0jWkIbV1jtAFJbtSgPG0rpIIpgUec7ZiUxaD
         mPVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yMUMI0m488pbWUAXr6OzZzxKEpJRpDah7A59AGDrcqc=;
        b=eLw7NuZAl6hUfIydltIGL8XWBvob33AFkQCCDygO/Tg61HIAcNJAicXQIAOsZOQNOX
         HGHq34vZLDR248C8u+hjiFN6BEK/W8Eyvy7k4XpNj4Hd4OdxVCFY2mvYmrxFGchUnUzG
         wknAz1SjkmfY3Osb7grJ1/IqXPORoLiY/o0jbM+cSjM+5mrKFvx4tmtjt9D356H4863W
         v5HLD4iRoyv1rkmEfjehWF6bQXJ3StZ9t7r12oUmn1tqPTOv06qQJ3IXFy7MlESuv66u
         mVuVGO6QY+LQHPEvuSX8hVrv4BzPytOPk7UBsGxFa5vrQpeZvnC2u1rWjQWWxsggdNF0
         w7Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tZ1DG4V4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc32.google.com (mail-oo1-xc32.google.com. [2607:f8b0:4864:20::c32])
        by gmr-mx.google.com with ESMTPS id v5si64207vsm.1.2021.11.24.10.06.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Nov 2021 10:06:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as permitted sender) client-ip=2607:f8b0:4864:20::c32;
Received: by mail-oo1-xc32.google.com with SMTP id e17-20020a4a8291000000b002c5ee0645e7so1200641oog.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Nov 2021 10:06:34 -0800 (PST)
X-Received: by 2002:a4a:4f04:: with SMTP id c4mr10227828oob.62.1637777194256;
 Wed, 24 Nov 2021 10:06:34 -0800 (PST)
MIME-Version: 1.0
References: <nycvar.YFH.7.76.2111241839590.16505@cbobk.fhfr.pm>
In-Reply-To: <nycvar.YFH.7.76.2111241839590.16505@cbobk.fhfr.pm>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Nov 2021 19:06:22 +0100
Message-ID: <CANpmjNOHN7SWu-pKGr9EBb3=in2AWiGmqNb6sYwhebGtRk+1uQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: distinguish kasan report from generic BUG()
To: Jiri Kosina <jikos@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, jslaby@suse.cz
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tZ1DG4V4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c32 as
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

On Wed, 24 Nov 2021 at 18:41, Jiri Kosina <jikos@kernel.org> wrote:
>
> From: Jiri Kosina <jkosina@suse.cz>
>
> The typical KASAN report always begins with
>
>         BUG: KASAN: ....
>
> in kernel log. That 'BUG:' prefix creates a false impression that it's an
> actual BUG() codepath being executed, and as such things like
> 'panic_on_oops' etc. would work on it as expected; but that's obviously
> not the case.
>
> Switch the order of prefixes to make this distinction clear and avoid
> confusion.
>
> Signed-off-by: Jiri Kosina <jkosina@suse.cz>

I'm afraid writing "KASAN: BUG: " doesn't really tell me this is a
non-BUG() vs. "BUG: KASAN". Using this ordering ambiguity to try and
resolve human confusion just adds more confusion.

The bigger problem is a whole bunch of testing tools rely on the
existing order, which has been like this for years -- changing it now
just adds unnecessary churn. For example syzkaller, which looks for
"BUG: <tool>: report".

Changing the order would have to teach all kinds of testing tools to
look for different strings. The same format is also used by other
dynamic analysis tools, such as KCSAN, and KFENCE, for the simple
reason that it's an established format and testing tools don't need to
be taught new tricks.

Granted, there is a subtle inconsistency wrt. panic_on_oops, in that
the debugging tools do use panic_on_warn instead, since their
reporting behaviour is more like a WARN. But I'd also not want to
prefix them with "WARNING" either, since all reports are serious bugs
and shouldn't be ignored. KASAN has more fine-grained control on when
to panic, see Documentation/dev-tools/kasan.rst.

If the problem is potentially confusing people, I think the better
solution is to simply document all kernel error reports and their
panic-behaviour (and flags affecting panic-behaviour) in a central
place in Documentation/.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHN7SWu-pKGr9EBb3%3Din2AWiGmqNb6sYwhebGtRk%2B1uQ%40mail.gmail.com.
