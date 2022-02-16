Return-Path: <kasan-dev+bncBCXKTJ63SAARB7WGWSIAMGQEIOHYPKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A1624B8DAA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 17:17:03 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id m17-20020a923f11000000b002c10e8f4c44sf125690ila.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 08:17:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645028222; cv=pass;
        d=google.com; s=arc-20160816;
        b=zMI6nQqEY2lykL7VxUK5HZ1WTnrRxQm7yz6uWVgd160E6+40kGf9m8CMzTLN+LkZDu
         mKk2cu+/1F+RgljAE8MR8ocAzJdSm2n1dp1TVK5KMUn/1BUv/i3cdJphOmMDgd9C3OW6
         +X0dBAYKL+uUl81BnHq21a7X7p0hdon21GK8XiGH6HXW+Uj5Y+0LsAGpyTTLIvHw6UCe
         +jimEfgo7l47ez33slLrKEz8LpW5w6w1LBUdE/PUHtPByU3ZOdiqyookwSAYuFoSKGhP
         UXMmJUtU9PFgskmIJw7ViJpEwI5SW9kUlxDIOahf4zN2umbfl7QOsVAO7xBCzpdRp7C7
         lYJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L7VN93apcYCzm8ttmCk3Aav3eCchslw1amBppm55E/4=;
        b=hn0E1qptV/y/UpnIKlh/j3QpiI2jwforQzCsUsNuNPFLXQjMg98yoixV+9LphqghI0
         yrbH5qlyJAwjGraSO6qIxWYPkp6MXyVOJvjOMfjmpTPJkr50TnA1Du8IIJ+acxWnOzwe
         fzmaWaWdwUTzk6uP4BGyoGJITussvEfKDAJ33xJdKW92oubGEGkqBpf6k6qRqK0vpZaL
         aspKRZvmIziGC46PNmvaURrES46yZxbFfJ16zJH0B/brLZxp7lZ5rrBzNHKcpZ26Cf8s
         qP7ngkczxvgeeFGrL3VXzxxagjMn9qUgw39io3agA5MK8IrzC3fdaFmIvRd+s0mE9HOX
         rhCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NtvZYC1A;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L7VN93apcYCzm8ttmCk3Aav3eCchslw1amBppm55E/4=;
        b=Nbo8iUYYMUnMdKiD/jBZcd6rCZfjNQnMpMr1UM6/a2LJAKqVeuBQB6gjW487/elbs4
         eUd1atrEuClqrAYlFwsifEmCyLafmVYQYnq6/bb2YXIJtNkirjZ5/R+WAq3KjrN6hgb2
         IbL9YHIooUIjwuAHIHTFPgeBFpg84669UncIL6/cZgXCaqT9RXeD1ddazeisWgVZSQsR
         Trf6J6cx3N2NR11o4CfuIZ6B66/MfsaaD+Rld+qXqrK3DwKFh3PsQHvaeEVtALqKLCVY
         +UYLc22MpJ3sBP6wdAokYz+QvETw+8mv3y5djn1NVycLFmvPgDZOTu2xc12zYNUSPkQ9
         wM4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L7VN93apcYCzm8ttmCk3Aav3eCchslw1amBppm55E/4=;
        b=UpaZxx3xsI2VB7gNQkfIpwfvL5UH7TZMeKCnTKYMkiiq1EOL5yGV3iU8BEEszG1o1F
         3U/L6+TUveRD9x1Xo+XfH4sU2vLT2dFiUvfmIaOa94y8P8p6mn7T0bQzbmrpan850gwm
         xsnmQH3oUCsxauGA0HQgS/HkTSmcWe+ILOHNXJajvB89bM66SmUFvRyPxMon4t+9hS18
         s83lQw41RgP3AmBhu95F9zlDkfVujQ82mpJBflkTPsJdBnm1bQkH0emAWoXmOkyXbvMo
         /fahLsPqTTVJru1IeITZ4SQbceaTOREeIjoxrPqgsy0IBti5bvoHA2kgDZt82ECigOi6
         WC+w==
X-Gm-Message-State: AOAM531xdVtzRDjmMNrKZSk+80qtvolUqQ74o+8ApVE1rCyw2vh9TCxA
	iyuVc90p3sN3/1CZMFIPHcY=
X-Google-Smtp-Source: ABdhPJwh4h5F0YPBZsqG9mBkaFgq7ESRcIRueUXGtoWQQTa8M/llYOZeHSwF+CVyb0P36IHjc4SQ0Q==
X-Received: by 2002:a05:6e02:1567:b0:2bf:adf4:43ec with SMTP id k7-20020a056e02156700b002bfadf443ecmr2173898ilu.215.1645028222527;
        Wed, 16 Feb 2022 08:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:158c:b0:2b9:7f53:df13 with SMTP id
 m12-20020a056e02158c00b002b97f53df13ls21773ilu.4.gmail; Wed, 16 Feb 2022
 08:17:02 -0800 (PST)
X-Received: by 2002:a05:6e02:1449:b0:2be:e26b:6a50 with SMTP id p9-20020a056e02144900b002bee26b6a50mr2328623ilo.218.1645028222150;
        Wed, 16 Feb 2022 08:17:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645028222; cv=none;
        d=google.com; s=arc-20160816;
        b=NoLmNbX0KE5Ip0fwy491bwkUV0PN/cnakTkF1lz6ILV9wOpr7kUAwD8jBseoNTvm+H
         BWk3DYGBub7cYxe7o3KqCkITrtCVAsxlYL7QfgChgEe+GpmFjMxiLParQz2R34blBAEr
         dCBhO3K9FSHv5V7kMgSvUygLEaW9tCFlNKIKoUPPoJ36iCphMZWCBBhTjkofgZCMmK+O
         MPi/tr95MGiirQlx6mQvAoNyk0jKQVQAkh6z3qsH23BynfLov7a/mSIXYbrzb1LSv/HM
         GTxAuP0+XWZZLHLfk02nCQupAv3iiaUDmxgknIh8G5QNvRUhzCcorNA3kkbKLFDiz9Wy
         qpyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q/am0HDxpBYA40FHZaIrVn8nXi2cQpq4EMCF+My6Irk=;
        b=nxGK6HT/OGSjgOw11imjzxmq4JAKXqR4fjFeD5U416+gj132rjqSL526RpGNUNk4Bl
         FIfjPvTravuM1bEpxGx6Sczuy7DMp9QvaeqKsHbyI53gGEyHamkZC/qrYrvsd6isIsxp
         85LlheAA5WNodUDSiradhX+mOq8ZmV2a6dtgqdI3UNFH/c15kePqWzHIQyxcH3OUsB3l
         2vvDkk2tJGDEc1dj085Z9wkc5kLV3kGTMH4Q47KHI+AtPQPWWs+em2u5HzyyIFoM3KNH
         LczuFM7kkkAHyOOymfwgReY67BKoZXVNflQTJLBUudJQt4w05WlWATVVouPPMFTDzNzS
         13zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NtvZYC1A;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id t35si1435752jal.4.2022.02.16.08.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 08:17:02 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id z7so147261ilb.6
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 08:17:02 -0800 (PST)
X-Received: by 2002:a92:c241:0:b0:2b9:80f9:e2a with SMTP id
 k1-20020a92c241000000b002b980f90e2amr2303305ilo.208.1645028221681; Wed, 16
 Feb 2022 08:17:01 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com> <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
In-Reply-To: <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 17:16:50 +0100
Message-ID: <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=NtvZYC1A;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::12c as
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

If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
to boot, but overwhelms me with tons of `virt_to_phys used for
non-linear address:` errors.

Like that

[    2.701271] virt_to_phys used for non-linear address:
00000000b59e31b6 (0xffffffff806c2000)
[    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
__virt_to_phys+0x7e/0x86
[    2.702207] Modules linked in:
[    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
  5.17.0-rc1 #1
[    2.702806] Hardware name: riscv-virtio,qemu (DT)
[    2.703051] epc : __virt_to_phys+0x7e/0x86
[    2.703298]  ra : __virt_to_phys+0x7e/0x86
[    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
ffff8f800021bde0
[    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
ffffffff80eea56f
[    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
ffff8f800021be00
[    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
ffffffff80e723d8
[    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
0000000000000000
[    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
ffffffffffffffff
[    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
ffffffff806c2000
[    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
0000000000000001
[    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
00000000000000cc
[    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
ffffffffffffffff
[    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
[    2.708433] status: 0000000000000120 badaddr: 0000000000000000
cause: 0000000000000003
[    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
[    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
[    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
[    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
[    2.710310] ---[ end trace 0000000000000000 ]---

On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > >
> > > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > >
> > > > Hi Alex,
> > > >
> > > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > >
> > > > > Hi Dmitry,
> > > > >
> > > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > > >> Hi Aleksandr,
> > > > > >>
> > > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > >>> Hello,
> > > > > >>>
> > > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > > >> That's a longtime, I'll take a look more regularly.
> > > > > >>
> > > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > > >>> to the following commit:
> > > > > >>>
> > > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > > >>>
> > > > > >>>      riscv: Fix asan-stack clang build
> > > > > >>>
> > > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > > >>> enabled. In the previous message syzbot mentions
> > > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > > >>>
> > > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > > >> I'll take a look at that today.
> > > > > >>
> > > > > >> Thanks for reporting the issue,
> > > > > >
> > > > >
> > > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > > from the inline instrumentation, I have no problem with the outline
> > > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > > to fix this for 5.17.
> > > >
> > > > Thanks for the update!
> > > >
> > > > Can you please share the .config with which you tested the outline
> > > > instrumentation?
> > > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > but it still does not boot :(
> > > >
> > > > Here's what I used:
> > > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > >
> > > Update: it doesn't boot with that big config, but boots if I generate
> > > a simple one with KASAN_OUTLINE:
> > >
> > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > >
> > > And it indeed doesn't work if I use KASAN_INLINE.
> >
> > It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > produce hugely massive .text. It may be hitting some limitation in the
> > bootloader/kernel bootstrap code.
>
> I bisected the difference between the config we use on syzbot and the
> simple one that was generated like I described above.
> Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
>
> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>
> And the resulting kernel does not boot.
> My env: the `riscv/fixes` branch, commit
> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y5%2BMuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5%3D2%2B5enVFVA%40mail.gmail.com.
