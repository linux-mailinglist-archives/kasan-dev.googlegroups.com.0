Return-Path: <kasan-dev+bncBCT4XGV33UIBBXOISKFQMGQEUJJ62FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2062A429872
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 22:53:51 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id bj6-20020a05620a190600b0045e164b4576sf14929403qkb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 13:53:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633985630; cv=pass;
        d=google.com; s=arc-20160816;
        b=KOoMr6SP00Gi2qUCrgCKoWv1f9KQ2zLMU4AlZipCjO8yzgPTFcIbiYPWi2Yc+fTQv9
         1IZd9S7DCX3rofwV1VvhWZO6LUO1VA4JEj7bQPU+PpVh6RIQz60bsr8vHFyiETI2ofBW
         3sB9A7eq9b5164Zo+I5w5x9ok/c7qtsPnxTTWc8nORS6j07bQtcUHUMZZOUZaAHKrMZ9
         F2Pun9tlTYhLuEz+qMfO3UqwoBESmOntRxg0COMmKYpsy3MQWNvP34sPsYQ/c5EST/VC
         v+sHcJv20V59ZNgWQgtxhqhdRGd/LkZwrXjEnenAsfXSAgn+bzv8wIwHy2Kl6qLoq8NM
         iadg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=f7BUEKRlqz4RP83DKiFVwoXAFr8E/Q3F9ZUPtu1YmvY=;
        b=PfNk+MA9+aGL0t8cukPSRtXOoVt8R5YLhuCn+XAGPPrhIrKd4GhkLiUQk7bm992YEL
         j1kH2wMcoEVBoGf5cSlUROIUex9Prt88YUFUJeG5XEiPKb6TsVJ8QiEe95HoXUOzW9KV
         Dv4UDJQlAXmYNj3SW+y0KhzCT1MKs1ZCn1r385joIj0WR7AqGH2xlaGnJrE0Aqv2U0Mk
         swAXJow5tFbjBykkwYVPkwfKcFu9S4ue+eWbiRUD4/HBX0PGIkt9MXvEgOJ9uqs/rsZx
         e/1Tobli6Eb9nr8A+3X7ABK+1ff7SWID4FA0U2GGKlEmqOBYCTYMJe5oyAuDvRWbPPvd
         +S6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=bPTVvzI2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f7BUEKRlqz4RP83DKiFVwoXAFr8E/Q3F9ZUPtu1YmvY=;
        b=K8cu1bhiEAZYmu1qWpUTG9WscLNSGHganPReXgFAvx2+l7vPOC/GGUoDWDIZpej9/K
         7aMQZGit6Y124jzeUfKa0c5BX+8hz4hQjqunmcXDxyIEXRy9lH0R5r07QFFXYTgc37nL
         OKend67UHoVSEE94irfkLY1FVxjH2reHX6HBqnEvHtaeluY8cIfHLeTkeDWMBTkX2TjM
         L2Fga977a028fm0EyadmP44vnpEXqCnugj5O9QSovNFn1iAC0DbBN6M21q2p7V7GyG2n
         sSvQQ9z1yDjiQtAu6e8nYiEHKFtx/28GoN42li5u9CpbJYdfbxgr9o6aDUm6dnoufAYl
         kN4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f7BUEKRlqz4RP83DKiFVwoXAFr8E/Q3F9ZUPtu1YmvY=;
        b=RTjOvPR0KnRce8kOITFZCTbNMPr4PRJXqOvuYTleJtNZl2UE+umK91Lcky204m3DWO
         nk90V2LRcZybDllHazy0rqhXrZpjhGbdSQPrfHIsSdW2BOsMqYOfhQbjN73toZD9MNhb
         I5us9H3P9wB8mkv8+k7OSgqK1/UC4oPl9XEQlDIrCdHIO41ZocRDtv6OSWk9tVAvNu5+
         FCXadDahdHbaKyUJR3Ob0rSxeOP9GSUxRqqWq6ZVe/cgGx0Ud9kukOkDOD5RgTgJYQLM
         6b0yNQZmPDwOFbGWPKGZrtXTvay49sCDo0JSs6u6Lbc/3eI8Hj99jiJ22YKLoRZGi7Ri
         Zy7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XtQOiz/tJbIE5Rvb3p3XLRYvrjGsQnJvCC9pFKw5eap4rlld3
	DPT4Dx3jGS2AtPmhFVlSwxA=
X-Google-Smtp-Source: ABdhPJx+wK5WOqSCxG3Ye+oKa/gSOa8BRj0bwAdIkD/0yNufwt53D0LAS0lVlnKjAN94FWqOHMYN+g==
X-Received: by 2002:ac8:4b52:: with SMTP id e18mr17899150qts.213.1633985630067;
        Mon, 11 Oct 2021 13:53:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:14a8:: with SMTP id x8ls5990280qkj.8.gmail; Mon, 11
 Oct 2021 13:53:49 -0700 (PDT)
X-Received: by 2002:a37:f702:: with SMTP id q2mr16990840qkj.135.1633985629580;
        Mon, 11 Oct 2021 13:53:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633985629; cv=none;
        d=google.com; s=arc-20160816;
        b=mKd/FFWO/1VTxkVR0/yWmvT5MdKfBhC9HqrtwDzaQDRkDi2NOqMmtkPcsQ4JjmiLKi
         KuudhosVemMhs/WeOVmg7BU+XXGTwLV0cULH93+bJF5b0pKM99Hd9oIo3IloOGfN2Z/k
         zvKCZLL25ekiFcTlJzO3BGT9yDH4ZJ+E/pfFf8ReAJo7h6+sj/eU8xfuL4OMSVbMseG4
         yLFelWmNlkt2G0upa+Xz6QT3GWG0cjQW00qO6j4RNEoGsORT5NCyqh0CFSQwYU8xfNbE
         v0AbVo1rquxV14vQk1Tyf2KilPZUz1mXzVTBGmtqvrPblSce5y55Vnj5qg0oWf4tjLcY
         J87Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Mf8aZsn7zRLVZIvP/Bl2wAFBk0x3xpA3/afyeWY9Nvk=;
        b=NOKW7gHNbnS7A4Hq0QaZjw2ZijKh1llXqSRcD/gIPASEi+zHkSpiajSsTSBhXVUTfb
         iVF8loOHnk2B/Bg4rzEsRMkLquJ0iHQA/BfumwkrOYDbkatZu80ksB0R+NYZnJ7cZ1SC
         S1P1POoRNEs96NdQr7AzdF/Z4Uz6BbUdEF0Bcw5Cdbow8mDDmQmFjNx4IXDtpxPmG+F7
         M83yEUflYwxoT6ALWZRaVYxWnNGr2WwqDB/DAbUP4o4yuBMEvtVry6EMWq9+0jj3XzXM
         OBlx0iUmsXW2s8MqlaFmCFVzvAsLd2UzVoIBz6ryfhz5N3Vtiwg980mU7/1rxH/20/lp
         DiMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=bPTVvzI2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k16si857386qkg.7.2021.10.11.13.53.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Oct 2021 13:53:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1B16760F11;
	Mon, 11 Oct 2021 20:53:48 +0000 (UTC)
Date: Mon, 11 Oct 2021 13:53:45 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Linux-Next Mailing List <linux-next@vger.kernel.org>, open list
 <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Stephen
 Rothwell <sfr@canb.auug.org.au>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: Re: mm/kasan/init.c:282:20: error: redefinition of
 'kasan_populate_early_vm_area_shadow'
Message-Id: <20211011135345.9506437ee2504a81054dc06f@linux-foundation.org>
In-Reply-To: <CA+G9fYtD2EFu7-j1wPLCiu2yVpZb_wObXXXebKNSW5o4gh9vgA@mail.gmail.com>
References: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
	<CA+G9fYtD2EFu7-j1wPLCiu2yVpZb_wObXXXebKNSW5o4gh9vgA@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=bPTVvzI2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 11 Oct 2021 18:12:44 +0530 Naresh Kamboju <naresh.kamboju@linaro.org> wrote:

> + Andrew Morton <akpm@linux-foundation.org>
> 
> On Mon, 11 Oct 2021 at 17:08, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> >
> > Regression found on x86_64 gcc-11 built with KASAN enabled.
> > Following build warnings / errors reported on linux next 20211011.
> >
> > metadata:
> >     git_describe: next-20211011
> >     git_repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
> >     git_short_log: d3134eb5de85 (\"Add linux-next specific files for 20211011\")
> >     target_arch: x86_64
> >     toolchain: gcc-11
> >
> > build error :
> > --------------
> > mm/kasan/init.c:282:20: error: redefinition of
> > 'kasan_populate_early_vm_area_shadow'
> >   282 | void __init __weak kasan_populate_early_vm_area_shadow(void *start,
> >       |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > In file included from include/linux/mm.h:34,
> >                  from include/linux/memblock.h:13,
> >                  from mm/kasan/init.c:9:
> > include/linux/kasan.h:463:20: note: previous definition of
> > 'kasan_populate_early_vm_area_shadow' with type 'void(void *, long
> > unsigned int)'
> >   463 | static inline void kasan_populate_early_vm_area_shadow(void *start,
> >       |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > make[3]: *** [scripts/Makefile.build:288: mm/kasan/init.o] Error 1
> > make[3]: Target '__build' not remade because of errors.
> >
> >
> > Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> >
> > build link:
> > -----------
> > https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/build.log
> >
> > build config:
> > -------------
> > https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config
> >
> > # To install tuxmake on your system globally
> > # sudo pip3 install -U tuxmake
> > tuxmake --runtime podman --target-arch x86_64 --toolchain gcc-11
> > --kconfig defconfig --kconfig-add
> > https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config

Presumably "kasan: arm64: fix pcpu_page_first_chunk crash with
KASAN_VMALLOC".  Let's cc Kefeng.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211011135345.9506437ee2504a81054dc06f%40linux-foundation.org.
