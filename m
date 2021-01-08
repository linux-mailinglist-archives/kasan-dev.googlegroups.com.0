Return-Path: <kasan-dev+bncBAABBD4C4P7QKGQEJLFJBUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 202EF2EF933
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 21:31:13 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id i1sf9143886qtw.4
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 12:31:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610137872; cv=pass;
        d=google.com; s=arc-20160816;
        b=rhBarqv3+p2CKG996Rr7iAq9K3we4rLfRqkRNjrxSUAB22jAQMkF9L1F1OgSe5rph+
         BbXXdah9IDb+iRT9rdRed28zu79R03Lbz6YZznC7yA1TXKe8EAccWhgeFRu/0PcI8iGk
         38hPv1IDdHY0RJmdaZBELPi/NeeML+NxthbyaR65VM3m4gVJ14BqHEn+GJZrEJluIe8M
         ljjmn0WvRee3FiOk6Aqf9q5+hgGFVdD4Qd3IUHXWTqDJ8CaT0sfh+1ZYoyRDufjGeVv8
         DZ1h8TKvGouIB0Cd5EWIPW92X81rvdiAPrsP0kk4cslRXggreVNfbc8i54ujZHv/8DIP
         2gSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=9G5TuI9nnijkxjaQF4h08AxdDyJunoYoe47CKojQyTs=;
        b=qR1FxSGZFZr5B7XQJ6vyoGWaGue8vwMYU3wi7wbJ5npvhpDDW5mdSZ3izcz7bhGKFP
         Nn1QzHtz9HTxAsQtCmWf9bQE6IO7hVni1EbAs/hzWjPY2bJ89OnO3DOXXE5johDarOv9
         pZxeaMiOuhNEbcw9nPz5ykwrqjjw+kd6LrkRig4OKbglVNFShFRmaZ3ApDZVsV/iDEkb
         OAC0OkDgwuvWql5AJZp2Fu8WrogKVIIdLf6YFL031PjHgi8j/EEPv3uoC9IvvcRyCgoU
         ZUs/xqitOEYy/HYYIL1H50vHDN675EAcoakcFc6+ZCuPUaTTn4ZJgICG2Mg7mc79mXNZ
         gW1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CK8hMSmJ;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9G5TuI9nnijkxjaQF4h08AxdDyJunoYoe47CKojQyTs=;
        b=GlcdEs0KiVQmWrlRWCpu0nNbPkUPAR5DSXiUj9JLup1SMgIgDlqKjvCJv+eR89BsBP
         cGlWHS4zb2Sfgx1dNdOVg7rRq0V0mvo0zAz6OMdXnnKsfvR0LOtEkchF49qH6wJkxkwv
         xysaYxaFX5tnaNPMjvg1IIynTRfNqWywbpKhc46/08Rv5h3Er6cAN+gQ+U9cn8HzneAZ
         fwFgy6QPzDnMb6IPrPN3in/UpBVAxsdSKSBwd7KxfBcUKaxNAFHPeVjx0zGLy3sqyTKG
         JprAhV5VszzO5rNGxHoDKmT2iPvPN5lgGdA2kQFc76iSv2xpV9i2e7fCF7yI6WmegyV/
         aGkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9G5TuI9nnijkxjaQF4h08AxdDyJunoYoe47CKojQyTs=;
        b=q0UOYxkS8S0BfKRm5mHdRmz+s6Y9Ed9T7QvigyTcsGBNb6klZzrPcg5EOAbMhXrmao
         pj3gCtGndaVWk8dgepxzbEqvmfnSTiEgmKyIAoB0M1eTBqiglx0Hfr7OUP4vdZQEo45I
         2nlb/BIBB9u7MD2mYjX/uK4AJSH/omT+S8gGaFKDSH3SgEpndMTTBSXlGAbK2SZbgN42
         Brmj1pDgz7cdatIQCZNZ5JHeL0J9Bhy+MNlFuUVgl978wV3OPpISXZtzfEhwFGJ17tcy
         N9rUqTnkvXPNmN7BvWUcLkg6cJMJSTplFAyUgqzWPXpKjqefuyZjeZ+FJsdFmKIG5gAL
         Q8Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jMclhjzuBVnbSX9lSI5CsVoa0oU6c1VwZuxrX09hAghZdh5Xt
	9PL7DYI4jGVjYfgXRMOVsts=
X-Google-Smtp-Source: ABdhPJwepadmvcdSJ0Mdv7YjHgF1bsOIYXd3kCUGzp35MZq8GNGANd7At7L7T4VAE3S0FQSOZ3VIMw==
X-Received: by 2002:ac8:3a25:: with SMTP id w34mr5150591qte.285.1610137872068;
        Fri, 08 Jan 2021 12:31:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b8a7:: with SMTP id y39ls2883508qvf.5.gmail; Fri, 08 Jan
 2021 12:31:11 -0800 (PST)
X-Received: by 2002:a05:6214:8c9:: with SMTP id da9mr8583143qvb.29.1610137871646;
        Fri, 08 Jan 2021 12:31:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610137871; cv=none;
        d=google.com; s=arc-20160816;
        b=rw6WBelKCcruWT0lsCOwIs8wlhVpDay6y52ri04/3BhjxtDJN36GrJsFvOzEO2KA1n
         S8aLOmhtTtogsJT4KvhofxCynlB4f0XWGS+qDb8dE/12Jd6A11WhQbVaZ8d9+rodPYew
         h27I5LWfUN0lS0pvrkLfAXfmSyMBuXjsFlglHNvtvKJgcWGmnRiLDdYu/2QO5iODm1lx
         w6ZkaEYZkRVCTk0vfeOpqPZvLhzCVvFLtbKjk6WyNlG55yfK1G7jKwpRcyW0vX51Z5HK
         Ci6Hw9Y7iVxYPLnBkmgu5A6XN/zN50UgoSIPpwLgEjIQiGVWeMnllmaV8I7zOn394Hm8
         zWzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fPcd5e17kvFT6rSYsfQi6Rm5JBuk365tGQ3m6T4XhzY=;
        b=V4rE6pXPyUPB3saMYLHXIBWEnIL0c0MQmCHaGIy7304UR+l1nPvuQLaw7nelheVbWw
         wdloXzG4trkZDyJ7rkHIMyPSwXN+y8pVjxRG8hhJI5O9OCF0A7V3hyc6o1ahhkxDWYcZ
         KHtQBzNbZ9l436zq1iDrjFBO8WGjgdJIP477IJhh+WCeO8MfektROI8OCqTBNz0MWMzK
         Yu0xLhSSSzhIBugFvyKu6VGQ0UpswdEyJMMMDvCj47CSpPiD6+7ykSUU+PIKY4rnne4I
         NC5Q0uHEU5x2kSgAHT/LlXWLd9SDlPu2mQTBr4qrG2hF5zg4K9jpf3svP3FrV27idUBM
         QHRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CK8hMSmJ;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y56si1229861qtb.4.2021.01.08.12.31.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Jan 2021 12:31:11 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 78EC923AC6
	for <kasan-dev@googlegroups.com>; Fri,  8 Jan 2021 20:31:10 +0000 (UTC)
Received: by mail-oi1-f180.google.com with SMTP id s2so12789999oij.2
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 12:31:10 -0800 (PST)
X-Received: by 2002:aca:44d:: with SMTP id 74mr3515461oie.4.1610137869802;
 Fri, 08 Jan 2021 12:31:09 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com> <CAAeHK+wW3bTCvk=6v_vDQFYLC6=3kunmprXA-P=tWyXCTMZjhQ@mail.gmail.com>
In-Reply-To: <CAAeHK+wW3bTCvk=6v_vDQFYLC6=3kunmprXA-P=tWyXCTMZjhQ@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Fri, 8 Jan 2021 21:30:53 +0100
X-Gmail-Original-Message-ID: <CAK8P3a3FakV-Y9xkoy_fpYKBNkMvcO7DPOQC8R7ku7yPcgDw3g@mail.gmail.com>
Message-ID: <CAK8P3a3FakV-Y9xkoy_fpYKBNkMvcO7DPOQC8R7ku7yPcgDw3g@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: remove redundant config option
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <natechancellor@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CK8hMSmJ;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Jan 8, 2021 at 7:56 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> On Fri, Jan 8, 2021 at 5:09 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:

> > @@ -2,6 +2,12 @@
> >  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> >  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> >
> > +ifdef CONFIG_KASAN_STACK
> > +       stack_enable := 1
> > +else
> > +       stack_enable := 0
> > +endif
> > +
>
> AFAIR, Arnd wanted to avoid having KASAN_STACK to be enabled by
> default when compiling with Clang, since Clang instrumentation leads
> to very large kernel stacks, which, in turn, lead to compile-time
> warnings. What I don't remember is why there are two configs.
>
> Arnd, is that correct? What was the reason behind having two configs?

I think I just considered it cleaner than defining the extra variable in the
Makefile at the time, as this was the only place that referenced
CONFIG_KASAN_STACK.

The '#if CONFIG_KASAN_STACK' (rather than #ifdef) that got added
later do make my version more confusing though, so I agree that
Walter's second patch improves it.

Acked-by: Arnd Bergmann <arnd@arndb.de>

On a related note: do you have any hope that clang will ever fix
https://bugs.llvm.org/show_bug.cgi?id=38809 and KASAN_STACK
can be enabled by default on clang without risking stack
overflows?

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3FakV-Y9xkoy_fpYKBNkMvcO7DPOQC8R7ku7yPcgDw3g%40mail.gmail.com.
