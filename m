Return-Path: <kasan-dev+bncBCMIZB7QWENRBYWMWOIAMGQEY5ONFSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 2003C4B8732
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 12:56:20 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q23-20020a170902edd700b0014ed722ba9csf999881plk.18
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 03:56:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645012578; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rk+eV86jZImd+KW3JngOFUzykRG7CI6jIOfQyVGEJHT0hh1ARufSNKunSTH6pRcG7D
         fRTEARLF4is8qYRFnSj+c4c+trrUs7NkCh0H3mAuESu+4ZvC9bH9F/LmQ/HgOAFtm6Y+
         ytkHntTB55Yb7NiWOswjMVnJ7/vVBzPvoYCibQU/AZoXpTYKxSzQTiSvTjFp2FEmRot5
         6C7OvcTI5C1QXe3DzkWqSfzBaEe9+XWTBPaMpcGwOe2zlnqTXsM5qT9Fh9L/Op19XGHd
         cST1EpwHevPom6FEV17IHjgn3cFU+uHaFeyfpjnf0lB6mwao67IWX9/bjyn/1p7TRgms
         wsWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UbNHW7X0XRwYkejH9GZnvLH36T9XtP9cpRjTnUtf+BI=;
        b=ILjedExJJvZFcAkkT2pXfe+KJ6hXAB3rhZHuGnh7fhZ6uRaDuIXLJx19VKzBLiqERe
         9WKaLtCcROC6geCUxivpJ+ZHPK4mrmQyNYjecbmUjpojBBA5iWIkW9QOZBcBpbiRitw5
         pVIPn7/sRsYtOzoz+3iHd+umg3NltWFw8DfCXYH5lqhh4zwmFygNPmiXmWOVtpg222J4
         qQkejeN3FkREOD5OtnCo0Js195gkXiR03W5gUTOpN/haNB28w8Hkj/OayiQXdqZO9eOt
         dYkoDcBZ6Yi08R3whZx4oA4wHZmJsf3NPu0tnQrjOq+T0MTrg5G2zE/vGyCkqZ0y4g/U
         F0bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iT2AEWwx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbNHW7X0XRwYkejH9GZnvLH36T9XtP9cpRjTnUtf+BI=;
        b=qYL/sXeNWHNx5KqPnLJHmw5NeYc4twI4Z3L2v04kmEC7MUzRYceRKICh+HsjfVrK6W
         omhR7eHY1HfXpAQkNpzMRDQ79+JWfcAnvSPDpgK6jBrJKSjrhqoA5iYz2EONAWIlm0NC
         MwqC2AnyA3E3nz7CGs1tmPY8uuMN3uzDKFo/PEbQtBd+DEVn4svBgLd1Pb2t0bn8nmLE
         mPvMLBWKGYUBDX3/vFavIerE1chsPg2GtVK2PWI7/EfqvanV0bidiMSlgV5MvFuyxfZ3
         6f3YzJ2nEAoad0P1DTmOyJd6kRpbKCvkxdMwAo/qOTJNnje/WdA4kDdvvyUzYK3cmVvE
         sZdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbNHW7X0XRwYkejH9GZnvLH36T9XtP9cpRjTnUtf+BI=;
        b=m+vu6KnG911ycvcFzpXGtTdquBa3sBvrLZhuKQvSY3YSX8VfwJuQWG5Ebd77FK2ztQ
         teuG0/ksvx/3csi160mfzYDCTOc0c2XW+DwblwnBvKTHsZW6PzDjd3sHxw87X/M/GZnS
         gCOAytcYHVbBqU6P52CjVb5hxSfXk6mO7S4Xt/hw+WeV1eA/gqCFOnSeNTz/2CTuBKYo
         PgjJpT9CpXm1D7STknObDHOVLOh1+guJW0IAPJ59bIkTKAxpWfuWmYlT2zBc5yU+nCAP
         8jcHvxdyqf3ohYi7qRdfXfc7pCryyh28/8CqeM2+cgneK6NhwCwkxZgq1UYHwaQqZLbo
         2cVg==
X-Gm-Message-State: AOAM532bqHoXe3UQnz/QJ+N5C9lLV7t/KPHIVhcOfxNpNTFhOd/BrVOM
	u+q42RxYt2bKy5Y/XNYNZUs=
X-Google-Smtp-Source: ABdhPJwJLzAARW2qPcmruDAstWCNthweXxT60dci0/oojscCjG57mGqXEXGyOzTXpXU9j5Hgy8tpDw==
X-Received: by 2002:a17:902:b7c4:b0:14d:54bc:88d with SMTP id v4-20020a170902b7c400b0014d54bc088dmr2286225plz.44.1645012578604;
        Wed, 16 Feb 2022 03:56:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:165e:: with SMTP id 30ls2341646pgw.7.gmail; Wed, 16 Feb
 2022 03:56:18 -0800 (PST)
X-Received: by 2002:a05:6a00:1ad0:b0:4a8:2462:ba0a with SMTP id f16-20020a056a001ad000b004a82462ba0amr2697726pfv.75.1645012577900;
        Wed, 16 Feb 2022 03:56:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645012577; cv=none;
        d=google.com; s=arc-20160816;
        b=X7zlP5p6MVHjmh/wu6GEb5DMf1cEAnfCpNE8HI95YKeWtHmcVOlTFBALIK4AqSuFr2
         QrdMv/UjUZHOjPTF/1LZ4SnBRy/Kj8qpD4DXpzh1SrSVbFyPD+DHKI+yRSWTrXdkJs0/
         h2TiDeNwjbjseKniBLsmK5xeLp/I58IEE0BBe5fY6uOQX9eAeMETE5EQ7Wcli0dZn50c
         a7K01oH7S8nHR0HCEB9JFtO8PBRO8pJI/5cPi8wp5xOdtf5AnRo3h2+oJJKHEChzZAko
         kmppMcmyc19YkmMKmUHuQyce3VCYd8QUrXIwEoD8O2ehNP7YWWZENBYngKoApQ2qmCoW
         NugA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fhNx+q9flxByCxUrkRhgBlwV1E/I95+1uqa0YFgkq6g=;
        b=p/1LvUDqoLasGZM8OzDT731QUGNcCCZlbgW0NOkRQ2O6wFhUJKb0P6EhaVEC9zspOl
         jwER39+ge0HGQ8REj9QUAGIwTeghKDSYtjj0McHqZsJnx9EY8MuksPxh5vjyyhii3cSP
         YzhJWgqaSSx90Rmy5fQ9etGMWh5co9sVcGO+MxztlMcOsiVjXdhCEL5GxiH+cQXOPu4W
         rqmTuIv4wabhBZyeNc4YDxyial6f2x5278YsNbiu66rgtNYGK/pODX/9qhxDoI+/sfpG
         JpwYaki4hPaD40oYG9xG0GMhJ+iIje6sRsUgYF1XSKIvdrzNvzM1Hgmx3n/imB0LmDlb
         EvcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iT2AEWwx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id e14si208558pgm.2.2022.02.16.03.56.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 03:56:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id g12-20020a9d6b0c000000b005ad077c9a9cso138853otp.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 03:56:17 -0800 (PST)
X-Received: by 2002:a9d:77c4:0:b0:5a3:326f:9236 with SMTP id
 w4-20020a9d77c4000000b005a3326f9236mr676453otl.196.1645012577018; Wed, 16 Feb
 2022 03:56:17 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
In-Reply-To: <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 12:56:06 +0100
Message-ID: <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Alexandre Ghiti <alex@ghiti.fr>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv@lists.infradead.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iT2AEWwx;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Hi Alex,
> >
> > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > >
> > > Hi Dmitry,
> > >
> > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > <alexandre.ghiti@canonical.com> wrote:
> > > >> Hi Aleksandr,
> > > >>
> > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >>> Hello,
> > > >>>
> > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > >> That's a longtime, I'll take a look more regularly.
> > > >>
> > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > >>> to the following commit:
> > > >>>
> > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > >>>
> > > >>>      riscv: Fix asan-stack clang build
> > > >>>
> > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > >>> enabled. In the previous message syzbot mentions
> > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > >>> For convenience, I also duplicate the .config file from the bot's
> > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > >>>
> > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > >> I'll take a look at that today.
> > > >>
> > > >> Thanks for reporting the issue,
> > > >
> > >
> > > I took a quick look, not enough to fix it but I know the issue comes
> > > from the inline instrumentation, I have no problem with the outline
> > > instrumentation. I need to find some cycles to work on this, my goal is
> > > to fix this for 5.17.
> >
> > Thanks for the update!
> >
> > Can you please share the .config with which you tested the outline
> > instrumentation?
> > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > but it still does not boot :(
> >
> > Here's what I used:
> > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
>
> Update: it doesn't boot with that big config, but boots if I generate
> a simple one with KASAN_OUTLINE:
>
> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> ./scripts/config -e KASAN -e KASAN_OUTLINE
> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>
> And it indeed doesn't work if I use KASAN_INLINE.

It may be an issue with code size. Full syzbot config + KASAN + KCOV
produce hugely massive .text. It may be hitting some limitation in the
bootloader/kernel bootstrap code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv%3DAPwh7AvgEUQ%40mail.gmail.com.
