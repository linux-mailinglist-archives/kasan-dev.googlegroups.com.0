Return-Path: <kasan-dev+bncBCXKTJ63SAARBXGIWOIAMGQE5K3JFAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EAEF4B8708
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 12:47:42 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id p8-20020a056e02144800b002be41f4c3d2sf1036801ilo.15
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 03:47:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645012061; cv=pass;
        d=google.com; s=arc-20160816;
        b=NU5HqSAImde0XCQM1F7Yb63yMkmY9UIDS5O3YZBSXfrXsHBCK2WOVZhq99jK3PlNuj
         nnKpzisfPEOve/oklrdLn+nurd8j6ODHjc6SUbL9bfGGcGnBf6MNnMXPfQjBVlWriSDW
         S9ZpDD0LfJV1gspRRyeO7FBV1FpEsXxCnbYKt3N8GFq4LLe0cwGvSpSBRsgneq99vQmj
         ljLAAWR0rOg7nCXhtBJJMl3aWZf1rd+hepyAhhWvFxwUB4J7mN9Qm4b2EnnKDJXQSo7v
         qxJu1iky5xBPXWMIuZxhQ9/R5uujcMaS3+Ao1kXo92TX976ZneqvLXCowbgGwtwZwiz4
         u6Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j4GToCuHf8r3N/Os/+E4eTpSLuJXncy8u6URCllkqVQ=;
        b=q7AuHnG5WTohMdqSBUh9UPIoTt816n8Ghj/745ZCSMdEay0xM20v6+0fSvwLvyqIEO
         7c7iAObD8oWl0KaomkSSzDsyWrluyXYa0o69ptdGdJWM9lB/3m/4IG5FDZJKvWGnBvbW
         piwwbXI6EM1PhAaSilkHa1d9xxuHFhhJB4EIbuk57QLoHFNVa1rNaiRVmdTifR4wS0xD
         u1lsdas+1ZB9r4eCHvoY9GvLiO66bLGBhQciC9BNT/o4N8gUfdPSiJYmNJDRJUnZhHxh
         DfXHgImi3U3QQpa1elYbabCUT0t3zYGUIqghWZDrz90cpqGTKJMOfbuGY61FU6nGpB1Z
         ErPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JIL+GG0b;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4GToCuHf8r3N/Os/+E4eTpSLuJXncy8u6URCllkqVQ=;
        b=igtjaiJDqc9AafDheTK/IoMaAJQL7UodjpAHXBNPps9rjMtezGgd356QY7q386P/lS
         icdrJedcovVDJne8PZClwHG1tYxonCwn9k7Y3DaqkLPYXHxSAVZc22DSEwxFVRExkKuT
         cWPM/0uucMSra4nSHuZJdNUY5GeQFR6mPsCLwzGo8eofMReD/uQu9UPq1wLw9gxOsfkN
         Ptmuuddp/DnIlMv0SLGsalUdiBmrb07p7Epv1Pgh1U6SR+BfonSHzuOZiuD83gG60+x4
         Op68CTVJxksqZR23VUt3SGRmJN85J1c+ex8y4HKo8YERHNUfgss7lzSYDYqGibYtBe32
         Xqlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4GToCuHf8r3N/Os/+E4eTpSLuJXncy8u6URCllkqVQ=;
        b=7f5NnNhUeFLSgAN6Lshke5qpNTKWHiXW5TT2DUkNGkbmd4RD1a5TU8uwki4AlJInRv
         RHXoNIwk0PsAp2HnJmJ37+lE9IMETdECuFWf2cO1x/yQTiL2tfC/VPa0clmfJaXQXKBq
         iE61TzXyTnD/ZY3cv+zB7HQvYpm43bowgt7D1OG6/twxkqRBO71AEAMaGRSFIBQ/EPxo
         6v5e7+H5wC0WuDX7/q3Hgg3d4dPTAzlWD1Vfsh+yRSeUsqMrbrsbOCogr/BzjA46vku/
         BmqYC1cK/5FoBrQPPCavrqjJ/Miy1Ani8RktPVHs5Adz9Bgn8iuOL6fmFyYZjuI9WM/U
         9c9g==
X-Gm-Message-State: AOAM5325M3eejumfN6X1CbROYnUnWVlhuBzaf+F5s2w4h2IW19FFhr8R
	+I2bzCdQoHqaNXvVwWwOKZI=
X-Google-Smtp-Source: ABdhPJwKtJzp0m1mVQEoDQZkI3n2HEJgwJYuVyAOyEfjlQEMYGZBrmnZgoj2cCVEkcCK/TizyNyWcQ==
X-Received: by 2002:a05:6602:2143:b0:5ec:fba5:8645 with SMTP id y3-20020a056602214300b005ecfba58645mr1637279ioy.44.1645012061115;
        Wed, 16 Feb 2022 03:47:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1788:: with SMTP id y8ls1077178ilu.9.gmail; Wed, 16
 Feb 2022 03:47:40 -0800 (PST)
X-Received: by 2002:a92:d0b:0:b0:2ba:66f4:858f with SMTP id 11-20020a920d0b000000b002ba66f4858fmr1567094iln.145.1645012060616;
        Wed, 16 Feb 2022 03:47:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645012060; cv=none;
        d=google.com; s=arc-20160816;
        b=l0v/K3J88Th8v0cUl677J2eorw4AhGF4gQhvpdS6UpZ9Wni+Akkm8DERK1wNx7oDFa
         CMU/fsmKkD7A0sLYOm2ABs/I57aSMncolbDFjdc9E3+xZKF8ezCPbROhJTpkgekBOsML
         Aebv2PFyJONRnMK1Ia28Suej8hUHGa9DsWQtXROh5hZsqdHGf8eIrcd2l+HnmdMszk9u
         m/2uz+ewBCJj1mTasnJjlNepu+eTh25z5w48iV3W4OgA2JZUKvqgPJDFmfbTbOUTuOVz
         8pA0wVA8XCjHJT4JGO8dhbVghDNA6eHDBOrtTtYr8oAA5ghVzJXi66HjUYBwFu7x52kv
         4XPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zQ426YIiyZCGwhq/0eYvVXz0if/mrj+i3L6Ot4o8TMs=;
        b=BxYPqSUHSRT8Hl3X6g9Z8NR+GU3ub9h09AVZ7dW/IMvSmNHB6UWWdHlC3H1TZxNJ+n
         AA6byITffmSvFjLnzNWOCUubAcz1Hex1Y+y80lFT6b5MkW6bpOniDEyDxOzSVOjx3Dq5
         oDgAsiH94007DGHoSrXc6+ysDtFrnglFDVUc2d+TClbflzd3ei/wP5lNa4xdhxTqTt8O
         otYVFfkhLh5ZxUkllbZXAbdmIIKc1WRKMrzEh4o5pALG0OQ5KuXmoILfuEgZrEeUiZbI
         SD4DxHnvnbwEIt/bQvihaHGGfZbGscZPxVC7TP3Uuexepl/0BJavuYbOFVq7wAGDryJS
         ptrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JIL+GG0b;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id n10si417219jaj.0.2022.02.16.03.47.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 03:47:40 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id m8so1222575ilg.7
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 03:47:40 -0800 (PST)
X-Received: by 2002:a05:6e02:1bc5:b0:2be:ebbe:1879 with SMTP id
 x5-20020a056e021bc500b002beebbe1879mr1528527ilv.127.1645012059881; Wed, 16
 Feb 2022 03:47:39 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
In-Reply-To: <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 12:47:28 +0100
Message-ID: <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=JIL+GG0b;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::129 as
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

On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Hi Alex,
>
> On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> >
> > Hi Dmitry,
> >
> > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > <alexandre.ghiti@canonical.com> wrote:
> > >> Hi Aleksandr,
> > >>
> > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > >>> Hello,
> > >>>
> > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > >> That's a longtime, I'll take a look more regularly.
> > >>
> > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > >>> to the following commit:
> > >>>
> > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > >>>
> > >>>      riscv: Fix asan-stack clang build
> > >>>
> > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > >>> enabled. In the previous message syzbot mentions
> > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > >>> For convenience, I also duplicate the .config file from the bot's
> > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > >>>
> > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > >> I'll take a look at that today.
> > >>
> > >> Thanks for reporting the issue,
> > >
> >
> > I took a quick look, not enough to fix it but I know the issue comes
> > from the inline instrumentation, I have no problem with the outline
> > instrumentation. I need to find some cycles to work on this, my goal is
> > to fix this for 5.17.
>
> Thanks for the update!
>
> Can you please share the .config with which you tested the outline
> instrumentation?
> I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> but it still does not boot :(
>
> Here's what I used:
> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138

Update: it doesn't boot with that big config, but boots if I generate
a simple one with KASAN_OUTLINE:

make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
./scripts/config -e KASAN -e KASAN_OUTLINE
make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-

And it indeed doesn't work if I use KASAN_INLINE.

>
> --
> Best Regards,
> Aleksandr
>
> >
> > Sorry about the delay,
> >
> > Alex
> >
> >
> > >
> > >
> > >>> --
> > >>> Best Regards,
> > >>> Aleksandr
> > >>>
> > >>>
> > >>> On Tue, Jan 18, 2022 at 11:26 AM syzbot
> > >>> <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com> wrote:
> > >>>> Hello,
> > >>>>
> > >>>> syzbot found the following issue on:
> > >>>>
> > >>>> HEAD commit:    f6f7fbb89bf8 riscv: dts: sifive unmatched: Link the tmp451..
> > >>>> git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git fixes
> > >>>> console output: https://syzkaller.appspot.com/x/log.txt?x=1095f85bb00000
> > >>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > >>>> dashboard link: https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be
> > >>>> compiler:       riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> > >>>> userspace arch: riscv64
> > >>>>
> > >>>> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > >>>> Reported-by: syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com
> > > _______________________________________________
> > > linux-riscv mailing list
> > > linux-riscv@lists.infradead.org
> > > http://lists.infradead.org/mailman/listinfo/linux-riscv
> >
> > --
> > You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/a0769218-c84a-a1d3-71e7-aefd40bf54fe%40ghiti.fr.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw%3D6Ewtotm6ck6MN9FQ%40mail.gmail.com.
