Return-Path: <kasan-dev+bncBCXKTJ63SAARBK6DWSIAMGQEU5FWD3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C74B84B8D53
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 17:09:16 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id a12-20020a056902056c00b0061dc0f2a94asf5005547ybt.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 08:09:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645027755; cv=pass;
        d=google.com; s=arc-20160816;
        b=NWela8TPyZyhemUlQVE9ZXILhStK5Hkuk+ekHtPrwN0mSTMxeq2PCkvohL26iEC7mA
         MnDO5glbByPvQjSWy2A3PATDRiEJBycALqWA/55x7QIhVCTn3xu8KG9gGIdq7xYzbcPA
         9TbhMAHthKkoelv3CxOIzbAuhSANNdbpycboyTJNtFcqHqP62Yp3Dm/8l4dFBnZ0dQCi
         5iZxmV8iFenhX6kIhGoV1Ary3neZbWD76dt/JPErD9JhYRrFBpnzeg9U182Abi6/xRnx
         MbxdGivFZqCDOvH/+UHw+F56YHh/aoxJPSjM1FFya8NpdaC/HPkoi7QQzfSK7F/vXjM+
         /+Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MgWVipgwvKBg9yr5kMYSG+yu+4B55r+oWyLMA1DOXjo=;
        b=uERRXlDefQsBS9BIUgLNK17cM8+lWzDueLZ+acxEI2H3aT5gkv1igwuMOaTCl7uC28
         kV4wPSt56YE1WiEWnEUjAWRqfCccrGlYDGzZGF9dAnmJBBf2qatqAzQw3cI86VVsA0OO
         iekChTocAal5Le/NTPQS9r2yG6Xb+6UvLbAKgnfdDfP7SDmy3C4CMjaZIcnibi3c4tYc
         21VusQAStX9Z1S2NON19OzloqDTfaDN+xfm6sY9G09cvOyL4o+dKBoWmkevICC8M4vMh
         L/x0lFnweGxiLoPMX2yTJ45oPgHzear/bEtL9KFS1Qbo1HLN2sIRq07ia+J2yFBntWQb
         Yujw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J+IlJwKw;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MgWVipgwvKBg9yr5kMYSG+yu+4B55r+oWyLMA1DOXjo=;
        b=BQUOnNF5ZtYFWYW+rA0SEk96WtQUL7GgSqcHGuA6sHtDxbzeepStPkC6YSm87Pg+mI
         Z5RKtT20c04GklaQXyrJUKHTbpJzLnTp8FBVjCs5dwcwslHc6Co0x4fG81MrDWDf0k47
         IeRwdwV6myyR3pUqCDnKNjJ/t1ib+PzJCIR7AewBUeo5KuTeDQNApSQa8+ecRNfuoKkc
         YPtDLVcfa2bpp8aVEM7SCkkH6+o9JMuCT2TaET8pGgVdz/4V3iuGUwtaPRahmvHym+Hp
         puZuTZfArtjuva2423PMs+iFaxvPhNQqvM7GnX0POyXy5LU25dRfoc0EcazRPn2nrwLV
         E6TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MgWVipgwvKBg9yr5kMYSG+yu+4B55r+oWyLMA1DOXjo=;
        b=pkjJW2jmSUEKOWT1C0HxqunBddTmA6/OaS6KevwK4XJhKnoIInHcIUHzcmmzOHnEJn
         3RLy9ICnXZtwbUkzyR9bNoYarg5VbflgnhOe6XpGCKtxh2crrB9z8NRLwZSACfRwsjWO
         R8YbDYvz2xeh3EqqlGyAG2tyDevxj89X9h73C/FYrnmFR4nDqUfgvZTXAynqzIIncpbo
         okr2jupul9xYcfo2e+2/zZnuiNiBl0Fb0xtptjyrz29lIKRZiJzZYDuFDe+CnX58FZ3P
         HB/SqCRD0/T71DMzuIbl2zzSkBsfrq1MSdXMxHbvITnvWghoC8l3d2wlzjCUEYNH8G53
         4NiQ==
X-Gm-Message-State: AOAM531Ni9Lv73k7iuU0K9C6iPT3PsPQYl6E/WR1yXiGxyZHqPZzq18i
	YItSkxiKp/3vZVWb5WNYdHE=
X-Google-Smtp-Source: ABdhPJwMZLnUM6EIRiFEK2l3wCQWTKHuwLMnYd+i3znoVhNAeKuoJ+XgkbQag6TrSXPnYGsq+Mn02w==
X-Received: by 2002:a81:6e03:0:b0:2d0:e553:e979 with SMTP id j3-20020a816e03000000b002d0e553e979mr3032289ywc.505.1645027755586;
        Wed, 16 Feb 2022 08:09:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:a48:0:b0:2d0:7710:4454 with SMTP id 69-20020a810a48000000b002d077104454ls41204ywk.1.gmail;
 Wed, 16 Feb 2022 08:09:15 -0800 (PST)
X-Received: by 2002:a81:7848:0:b0:2ca:287c:6ce3 with SMTP id t69-20020a817848000000b002ca287c6ce3mr3041967ywc.392.1645027755079;
        Wed, 16 Feb 2022 08:09:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645027755; cv=none;
        d=google.com; s=arc-20160816;
        b=eKAGxjm5IWyOpi4OUACWZLjtQRqRktkkzOvN7T4dw4Q4YIzE1MKHCXfvCol5dQxcer
         z3BDqD43NrtFCyuYL3UApJRAPqmD98FaQn32kSBRBRegTW1fG4rkD2Smpz7nWw7jKM7v
         +MyRyn/78ii0xyq2tslennN8yBQyPupA4hmjajueplgjRNR3PGNsiMRSwp+mZ2EA42tX
         USX6SSsrHd5/6y9VTxfN8mSRqRXxUHV+4vs+lljh6BO6U91SrbNwNq4i6JNWGiRtHF63
         rxQbvuSAnCf9EvDTNpTdcO5T1TLrJeCBaqpVCtgblY7Wn6BfyckOFk9xMDKfi+77xqCU
         4SSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X1DbyhBVBvnUPYaFyX9FKtS0pYUg5/jmB2DYqrFTT5U=;
        b=L4u55JSax1GXXcAYnHro6MTAdT4QplIsDsOAXYOFCMHaFSZMZLcIuwj8bJiYaB++GU
         ql66VNSaQmWAiaWFQakfjTnxwZ8UICsBqyNAm0/TnaH/O+C7iPWGr9eHY0T/XmXVGD02
         MIJH4UjGGrXbYTqgw1VrBKiLmSLXbGvU/XYO/6o04mLaTyGS2AMee15xaCeJbx/xH37w
         LOjO6ZZxgiUa4S5nlz2BmZDc2BPZZ6DcojSM2wNQwombeUKQ9kVKtNWdP1i246PJvLs1
         IP5lH3OgQjrQscdRpe/e8MrSyn4Q5cX3OpiXj6kxgJXZgmAbQWgni4KW7fygYJmIVkJX
         vLEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J+IlJwKw;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id e5si1833430yba.0.2022.02.16.08.09.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 08:09:15 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id f13so131649ilq.5
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 08:09:15 -0800 (PST)
X-Received: by 2002:a05:6e02:1a26:b0:2bc:2e01:ae73 with SMTP id
 g6-20020a056e021a2600b002bc2e01ae73mr2263040ile.44.1645027754573; Wed, 16 Feb
 2022 08:09:14 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com> <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 17:09:03 +0100
Message-ID: <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexandre Ghiti <alex@ghiti.fr>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv@lists.infradead.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=J+IlJwKw;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12d as
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

On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > >
> > > Hi Alex,
> > >
> > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > >
> > > > Hi Dmitry,
> > > >
> > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > >> Hi Aleksandr,
> > > > >>
> > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >>> Hello,
> > > > >>>
> > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > >> That's a longtime, I'll take a look more regularly.
> > > > >>
> > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > >>> to the following commit:
> > > > >>>
> > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > >>>
> > > > >>>      riscv: Fix asan-stack clang build
> > > > >>>
> > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > >>> enabled. In the previous message syzbot mentions
> > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > >>>
> > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > >> I'll take a look at that today.
> > > > >>
> > > > >> Thanks for reporting the issue,
> > > > >
> > > >
> > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > from the inline instrumentation, I have no problem with the outline
> > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > to fix this for 5.17.
> > >
> > > Thanks for the update!
> > >
> > > Can you please share the .config with which you tested the outline
> > > instrumentation?
> > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > but it still does not boot :(
> > >
> > > Here's what I used:
> > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> >
> > Update: it doesn't boot with that big config, but boots if I generate
> > a simple one with KASAN_OUTLINE:
> >
> > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> >
> > And it indeed doesn't work if I use KASAN_INLINE.
>
> It may be an issue with code size. Full syzbot config + KASAN + KCOV
> produce hugely massive .text. It may be hitting some limitation in the
> bootloader/kernel bootstrap code.

I bisected the difference between the config we use on syzbot and the
simple one that was generated like I described above.
Turns out that it's the DEBUG_VIRTUAL config that makes the difference.

make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-

And the resulting kernel does not boot.
My env: the `riscv/fixes` branch, commit
6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ%40mail.gmail.com.
