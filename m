Return-Path: <kasan-dev+bncBCXKTJ63SAARB7FHWOIAMGQEVSVJANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 61A2D4B85F1
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 11:37:49 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id f18-20020a926a12000000b002be48b02bc6sf969830ilc.17
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 02:37:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645007868; cv=pass;
        d=google.com; s=arc-20160816;
        b=ppndmIdhcKP9dFOHGFyVw1RIicaoLyN7moxT1nEAVA2E3qDh/KOuTq+Dp9yJTU5MCE
         vNcdwSv8y+kPJhUSCjyPr2idZ1+FIn3qEkQjBPuGls5a8Q8Ahff6gJUQsidBK+4nMxGo
         gtg04v1wIzb8q0rMmPGHhfiO7dj9oQ9iqXlYxpPk6D6/iQx+iVCCy/rzRNYgrQy2cq1F
         6kG9iDrGemWE092kuSd8KDHdiCN9xFBP96R/W30fNSl3kRmElyaupw18IDaqqct2nesz
         GIM0n7oREiqw9DyJfxYuyeVm0Lmr7514hwIxMk2P05zfVFWVCVGYATrnXZp1S6aZl/rn
         12uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h+ZiKxrjvL+QIvpRkJyaQUoMLh2Q6VHcBZnJ4hngMjc=;
        b=UL3wExdqPi7V+B/y3FpmxafAuK+ccncSTTQRs6Qg3UumCtp3aiMllOUaqZuBA6RG+q
         qpc798Zp+AwPjaCRFwdXw0bZ2rZtE0YSJ3TirvWgLWtKXM72D8GNHgg+YKQp4/r6V4C0
         77iZX607AOc+9kpwY4H9YOQrjXRENBF7jaoA9+Antytp7Aqq+rPrRIG9QMgRry7tvwqT
         M5yIJYDUXWFtwcrqOdnIOn/F+G8ox9PmWmk7/7D/v1j3prsyscxdtC2w3ll6DDkJfzlL
         Rm8IE6+7ysobb+CPXcIZrJG4Nxnk7YO1yM/f2FEHdDYPrQzToUZMzcYA59VDUp3i2ziF
         7LWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hRGOhZEq;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h+ZiKxrjvL+QIvpRkJyaQUoMLh2Q6VHcBZnJ4hngMjc=;
        b=OIMYZEpTK0zvfPox7P2rv+vM34sm5X05U3G4iYEdpbGfNrs10ZYr5NZBXmYzC1Zys0
         2q8iQk052TFwOjbmv4rwR4kgOGZOheQgA1SqZwEW7YVpmVO5x4MzGk/MrdARem71zlSs
         bZnT1qFUgTUDGE3ZraOOK4cF1941xb8Xu7NBgmof2S5lNIS1j/n9LED3pdH2ebu10x+f
         yDRGFrPUhMrjHRcdnlPWaNXTkrW9JNI1KjkK5zTSJMss6qs+eLSuaDJ56KdZui2xWGen
         7oGk1ROIkltbbME8BMQmigGC1ySOMUC32avKund6uFyTMk0zSmkwnKNZzzRn/hnHwQdp
         IGNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h+ZiKxrjvL+QIvpRkJyaQUoMLh2Q6VHcBZnJ4hngMjc=;
        b=XtddPLIm7DVy0q8YWHxZsqbnNeOmCIEvMSzRvAgXkvEy02ekNDTE6EfoEg64AvKqNx
         l9HL5B7i2ehAS9qZGoPxgzdkAPqRk/OeFUudkpLShUKjU/+brBQizk0vxyWmdY+uiFHX
         29krp9P6pRFBMf0nsWiCf6tepeHG6FNdFM7r++/mLGmDqIuGKLvUfP/71idYLk2ILkT4
         k8Qe2xdIWslCvl0MKZSVKgnmatIafEYN2NquSr15yhRYdK+g/JR8UpJRnh1Hk5DW8k7y
         sYYLsVIImxZ9TmrznB6bn0TAboPDYPluAid2kDoRR38/vl40wt34s532/0Nw/u1awfsC
         FtZQ==
X-Gm-Message-State: AOAM533hNODxRgJlBg0SoN10xoHgt0VfqIhTKMF+RxZlPxJwnnOj27OQ
	jJuzDzNyYN6s/YMuR4GXPPo=
X-Google-Smtp-Source: ABdhPJwfcAoV2uxsVgjlU6j5h5ZcpxnOU1K2puON/q672kClx/0zwyEDmOF3R1MpevVygMN+qNIK6w==
X-Received: by 2002:a05:6638:1450:b0:2fd:df2d:9c13 with SMTP id l16-20020a056638145000b002fddf2d9c13mr1272592jad.28.1645007868168;
        Wed, 16 Feb 2022 02:37:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:37aa:: with SMTP id w42ls1102953jal.4.gmail; Wed,
 16 Feb 2022 02:37:47 -0800 (PST)
X-Received: by 2002:a02:c9cf:0:b0:30d:2b78:8b6d with SMTP id c15-20020a02c9cf000000b0030d2b788b6dmr1274318jap.70.1645007867752;
        Wed, 16 Feb 2022 02:37:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645007867; cv=none;
        d=google.com; s=arc-20160816;
        b=NKklRx+km0uFs8s7wOMBVMPjbCmiADd8hIKHt/cw/Nw6ezpIwQSE62/te/vmNZcCv2
         TqCsLdOEQ0b6FwSD6C4JYgQ4WrEYipljSZ1PK4+7JKYF5tiBRnacPIZGZAtN8+HsnFd+
         kf35BgaeUGr8Z3w2vG7+sxw1mrpR39PrrpMW7LkPgcy5bbFE9TscAJIUEjSvWbA/wj93
         WAthtU8cVmKh69v/kNz/7Jgzt+NWXoS2RTIkgP1htXbOipUYIZeGOJyJlJCydz1eTFNg
         S14PLyTJv1dVQuIGDBya7x6lku/jxbQaO8FynjlBZKT3jJqdGtvtVHIfesQd/PKwMj/+
         5A1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pN9JYDOrzujGng7ZER6xyWI6CgQWXz9WnMXVqwu2nsA=;
        b=JCIHILO6ByCGFe2G6Fe31cqyQZmviCRzeV8JS6IAXovfcpcK//Hsts8WZ3lx72tMck
         La4qpuNTyAe+YJWzgSDg2P0X+PNp62jWAQrHqYxTdUnaflV11HMUGgwaX+biqNRqguRa
         taSJhmJr/GOCLYNQvjQZ2BoSmQqF0775QyX4R4jWzSeAKVTr9eDLbXkuFeyiYmNu7F8c
         JHtQmHD0DPefhyTQ9BdaV2NNNDZGk9F/EBoHqebhjWHfsLWqNMJIpbN2r/O1P5fAnceL
         /ZlC9aMARwEJzIYbNG31H7Csf4GT/chLrB2IWzagjv9G1J82iwXdHMVeSQOmeVXAYhFA
         V8gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hRGOhZEq;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id d15si4724428jak.1.2022.02.16.02.37.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 02:37:47 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id a26so419562iot.6
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 02:37:47 -0800 (PST)
X-Received: by 2002:a02:6308:0:b0:30e:7e14:848b with SMTP id
 j8-20020a026308000000b0030e7e14848bmr1218612jac.139.1645007867380; Wed, 16
 Feb 2022 02:37:47 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com> <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr>
In-Reply-To: <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 11:37:36 +0100
Message-ID: <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv@lists.infradead.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hRGOhZEq;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::d34 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Hi Alex,

On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
>
> Hi Dmitry,
>
> On 2/15/22 18:12, Dmitry Vyukov wrote:
> > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> >> Hi Aleksandr,
> >>
> >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >>> Hello,
> >>>
> >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> >> That's a longtime, I'll take a look more regularly.
> >>
> >>> days now because the compiled kernel cannot boot. I bisected the issue
> >>> to the following commit:
> >>>
> >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> >>>
> >>>      riscv: Fix asan-stack clang build
> >>>
> >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> >>> enabled. In the previous message syzbot mentions
> >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> >>> For convenience, I also duplicate the .config file from the bot's
> >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> >>>
> >>> Can someone with KASAN and RISC-V expertise please take a look?
> >> I'll take a look at that today.
> >>
> >> Thanks for reporting the issue,
> >
>
> I took a quick look, not enough to fix it but I know the issue comes
> from the inline instrumentation, I have no problem with the outline
> instrumentation. I need to find some cycles to work on this, my goal is
> to fix this for 5.17.

Thanks for the update!

Can you please share the .config with which you tested the outline
instrumentation?
I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
but it still does not boot :(

Here's what I used:
https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138

--
Best Regards,
Aleksandr

>
> Sorry about the delay,
>
> Alex
>
>
> >
> >
> >>> --
> >>> Best Regards,
> >>> Aleksandr
> >>>
> >>>
> >>> On Tue, Jan 18, 2022 at 11:26 AM syzbot
> >>> <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com> wrote:
> >>>> Hello,
> >>>>
> >>>> syzbot found the following issue on:
> >>>>
> >>>> HEAD commit:    f6f7fbb89bf8 riscv: dts: sifive unmatched: Link the tmp451..
> >>>> git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git fixes
> >>>> console output: https://syzkaller.appspot.com/x/log.txt?x=1095f85bb00000
> >>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> >>>> dashboard link: https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be
> >>>> compiler:       riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> >>>> userspace arch: riscv64
> >>>>
> >>>> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> >>>> Reported-by: syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com
> > _______________________________________________
> > linux-riscv mailing list
> > linux-riscv@lists.infradead.org
> > http://lists.infradead.org/mailman/listinfo/linux-riscv
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/a0769218-c84a-a1d3-71e7-aefd40bf54fe%40ghiti.fr.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y4WMhsE_-VWvNbwq18%2Bqvb1Qc-ES80h_j_G-N_hcAnRAw%40mail.gmail.com.
