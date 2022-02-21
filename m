Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL5HZWIAMGQENSAQ6XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 885DD4BD863
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 09:56:16 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id d3-20020a05683018e300b005ad2cb4db18sf6970159otf.7
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 00:56:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645433775; cv=pass;
        d=google.com; s=arc-20160816;
        b=nw7gMjxb9+9kTIYwZ1b78jhTALuzozq5ll/0wKnHq9+8uTOV4SZ9p/I79qoKHS7V4w
         gpIu8vitsWD7I1Ak+8nEbOSYImRx2/aHBcBicQ+cW11kThtJ1WNwN/7DBFPghAKFAuCL
         34Z6nX+oJw+LwSLUAgiaLEPiZUzAqZQrYkeI5+UB153SZKiS4aH4odXhsPEtwBJtC6Kn
         vqPpxI6cmCDHmVUeP0YORZWK5R4ZeBLeucnXsqbw1UFTzeeXX1shhNy01pPiIb/ZMc4L
         SuvczAhrlY98QCufb0xGID/DMCPetxu1enkdVzwLZMS7RtdYQZFZSBPzImm25CmEv2S6
         I8Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dMEf8HbUKcng+Gh8JcPidxxe8PKKgLMBJe0H347SYzY=;
        b=X2YIHjDjhb+x1Ke+VMBVnSNHc705Q3/LFjVC8jxbAGJgIxVJpi8x+5tGVkHN0ODYCw
         r0iTG2T1nQ2qWbyUAJ3f9inzqHDrXDEt0qTHa48LJED4NxN3XLO/BGxtagZzDXi1qmDW
         2WKsguaw5Ha/DMh9SgNlE5NTjreaU1hu9e6Ub10j19MGxJn0nfbPb4X0kxyaIScvxO7g
         DYsI0agUZ5Tw8TB5K6rrlDVWHnEkw9hQjdQXoPzGL+ntQljfzhwX1xZli0zOsdw0mCgR
         vDowXUekJmCjdgZvBwjZQtay/jnpOSgX1/j6gAEnTKaM5tUAQqJ+RaqTZqkwV2q+JhEV
         QLkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=r6XMOfHz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dMEf8HbUKcng+Gh8JcPidxxe8PKKgLMBJe0H347SYzY=;
        b=bCCZ5v9C2H7DgYeQ4Rq+xsqpziVat31XOTtAwIZKZIyCBRvjuUeozKGnqAoDFzNIzY
         UAJfi/IBYuVjegIhzzlrBBOEU5HpQ0ee6pHXaGgW7WeC+z6hs4B1ilxzqVDMWgMIa5wT
         iDzEl1CBXlfMFpYUBn/AuwWREIhdi0VGhhc69So6O0T0xSaciqtRj/OUG8YKbFvgGtgL
         P+rRAbex6zN/T4o+dr4toKbyHf5ObKy/VdSmKda4Oe/Is9/cbD0TRn320NMy9LGSTGH0
         C73Lv8II++4Ujj4aCgcRdqavF6QGIYblasD0d7nW3t8HbUmniJPRbcfiL4IHl8ky3lsR
         VbFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dMEf8HbUKcng+Gh8JcPidxxe8PKKgLMBJe0H347SYzY=;
        b=2p0MjcSHAvh+ASuaPOU3gJSZQe0lCBQW5yqa+MKISOfag4EwsxbcHLGe4d+wBTURE1
         qynmJaRJpkEC9VCPRBVDerdnGRLc0xDaJo4U/f1iPUZl5eRFdgpjn+TAQyvmy+2oUmOQ
         qN6FL+e+5cEmOkl+HPMq0M8t+fJYzh3hs16hNOs4OM+cMO2rGZF0Wq1BlqojDrufQoze
         VS4IEDyEJJKTCSDnqsgyCIxsWWUwF/HOo6TBSWocaXJyA0eNUhQL1V7OlfCcjOo4tQ9p
         ftCMLL8eAjufOrGrFDi+xHe/2ImtkSmyI5PG4OiVClHmsZbU+YSW6wUZK4NTNJlco747
         hixA==
X-Gm-Message-State: AOAM533IiF1j9SS8Jvz/IC4STjAGnvnO4vNuBN0mGCS+sZtPwGSpw0+i
	ArUQdge7+b4BngRuPXsdCi0=
X-Google-Smtp-Source: ABdhPJxKhsSCMLrnEzp2poaeL1yf+aNf02OQaNEbHj7MwYAJ5yny4jAbWHVc7NvMWH0TOAUtOtVIrQ==
X-Received: by 2002:a05:6870:5385:b0:ce:c0c9:6b0 with SMTP id h5-20020a056870538500b000cec0c906b0mr8677564oan.258.1645433775360;
        Mon, 21 Feb 2022 00:56:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ed86:b0:d2:7941:55a9 with SMTP id
 fz6-20020a056870ed8600b000d2794155a9ls3251378oab.5.gmail; Mon, 21 Feb 2022
 00:56:15 -0800 (PST)
X-Received: by 2002:a05:6870:45a3:b0:d2:cf71:2af with SMTP id y35-20020a05687045a300b000d2cf7102afmr8414073oao.113.1645433774983;
        Mon, 21 Feb 2022 00:56:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645433774; cv=none;
        d=google.com; s=arc-20160816;
        b=LGd2Da4WnM3wm7cD9IwEZN7vvleH5crdZFJPB3HXoX6qHqYTPmAKSmu/NIM6EJNkEh
         OFiNwxD5hv2J36B899nacI0dsYfaJpF7+hgczqnmXYKB3F6RmMG4GdOZaXhOE2/LjoN6
         otFejme5Udtl2ybz8cCGXokX8vpZ/Jx7GLvtv+0MNVOUU0hSR72RyTw6NXvm/CojPKUX
         yZIAPIqE/f9+W7sUOGOnACGbPzzuMGsXANvvoH9GgKHsPTfPecVz4yB4cPMmZaI7Uzl0
         hEOo5uyAS6yyn4fm5HB+C5whw74XJmH2xWb0P6NzSR17uUBKatjTe//Ktex5hnW1Sk4w
         Daww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OndnQyyeZ+3miOBGH8r6YA5jEmN8diDxn0ywrPw5RbI=;
        b=p09uy9ADb12ekmP2SwH2USZs2zEFnYT5QNCPrim/jLuiWZuA4jc9l7VXhfIFNw9aaw
         GBnZ3vr2Y1mUJVDFdS5iKp6kZwfZlFuPf7nAxl8eh9vKmd6xG7k5ab8nqyVyjafzmecy
         iufeiU1ifbMnAG9KQghJvVNyNCaWLvOauL+RPf5lxVAlWnsgdeXCPeP54DfkEYKaCDHe
         0HRxl2dCKB9puvNY113ysAgTF0OM2aZ2dPl/Q/MhVmDADtD0+XiTLr8ZdInl3YYs4w7g
         cEmuo0S2QQ7usQyjtHvsH0agQSauZrnQXuys8CGz5V86RWLXf1+JX7dqskgaP/9U/0Hi
         mt3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=r6XMOfHz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id x16si940630ote.1.2022.02.21.00.56.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Feb 2022 00:56:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id d21so10483814yba.11
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 00:56:14 -0800 (PST)
X-Received: by 2002:a25:3542:0:b0:622:caf1:2c88 with SMTP id
 c63-20020a253542000000b00622caf12c88mr13329448yba.625.1645433774543; Mon, 21
 Feb 2022 00:56:14 -0800 (PST)
MIME-Version: 1.0
References: <20220221065525.21344-1-tangmeng@uniontech.com>
In-Reply-To: <20220221065525.21344-1-tangmeng@uniontech.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Feb 2022 09:56:03 +0100
Message-ID: <CANpmjNNTsj-+=BBbt2pcbrqwOmiixjc6fE=Q=JoT=2kQfR0y_Q@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: remove unnecessary CONFIG_KFENCE option
To: tangmeng <tangmeng@uniontech.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=r6XMOfHz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as
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

On Mon, 21 Feb 2022 at 07:55, tangmeng <tangmeng@uniontech.com> wrote:
>
> In mm/Makefile has:
> obj-$(CONFIG_KFENCE) += kfence/
>
> So that we don't need 'obj-$(CONFIG_KFENCE) :=' in mm/kfence/Makefile,
> delete it from mm/kfence/Makefile.
>
> Signed-off-by: tangmeng <tangmeng@uniontech.com>

Looks reasonable, thanks.

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kfence/Makefile | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
> index 6872cd5e5390..0bb95728a784 100644
> --- a/mm/kfence/Makefile
> +++ b/mm/kfence/Makefile
> @@ -1,6 +1,6 @@
>  # SPDX-License-Identifier: GPL-2.0
>
> -obj-$(CONFIG_KFENCE) := core.o report.o
> +obj-y := core.o report.o
>
>  CFLAGS_kfence_test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
>  obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
> --
> 2.20.1
>
>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221065525.21344-1-tangmeng%40uniontech.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNTsj-%2B%3DBBbt2pcbrqwOmiixjc6fE%3DQ%3DJoT%3D2kQfR0y_Q%40mail.gmail.com.
