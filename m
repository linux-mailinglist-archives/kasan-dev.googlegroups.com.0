Return-Path: <kasan-dev+bncBCMIZB7QWENRB7PH6OJQMGQEECYAQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 66689524C07
	for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 13:48:15 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id h1-20020a056e021d8100b002d0eca04dbasf436652ila.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 04:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652356094; cv=pass;
        d=google.com; s=arc-20160816;
        b=qEadkG9D80FYuTh8nF5ICiWy422+nQAZfSQtQvd+wr6ggNJGRXdKOmasTTzRvvB8kf
         nZ+/DCRe7er+gYDjluW286NKS+kdLbmA+dxr0aVz9BWlb3oVWhliEawbYQ7gWZ0QJrvP
         REKklxoX+lweSwGygFe3jWcMtWxaRrR+xrYHDXy16V4Kx3BwaSrvtmSlazjBCeh6xAA+
         pWn0Jj0Y3zS1hrGW2PC3EvkcFhZjpgMeDO6IBcJL4WKAZTRqFalpR857D7lvSl7yY44s
         wYIpI3kkUWTGWydolkytl9PeAG3Wwj5rq2wjnz1IDzqEeW6JSrgpvsdhEmGG6jMuOO4Q
         HxzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=29GVgi6oiUhOr7qNHF4/FFp5c/sS1BLMTsgBZOILycI=;
        b=0D0PS9/ORJoY4zAHmapvv/SthnJI2iGrZE6/R40S3PiD6g9OfkgcHQiifC07B7fvKI
         XLP8FUVl4twntuLXx5fZpvSVhNq/7qbGdQ2l77rW+PFbEoIGOmtJ9EsTJrpVIBj6KRFK
         S+WqmwBVQ41CDB+2m67vuEokl3xg09ZQHxqCDP9k2apCtqpAhSwiEiuJdpusPxWAGo55
         xsPRDRpl6Qyzmw2p6hd6bbKgtgr6l6l1a0aq2nf1cQQrjkpZ52lqTBMUykStqi+/aS/S
         giFkdLkMAu7xn7RpSbqkg84yFUt1TxKWrn1239a0BlU43SBrK4CnoiTcwvr7FRpEllLr
         iRHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aAFcTqcS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=29GVgi6oiUhOr7qNHF4/FFp5c/sS1BLMTsgBZOILycI=;
        b=ZdpvhlPzV8KOmw1kw8sLgc5dRk79IZwj5Y59ThEWvubx6eyVZp1TL+5x2QXTWohMnJ
         qpoPucIKr+Mc53aGZ9rNm9EQNlQTOKwnOHpZLcOaWfZKxY0QxPl3h5ed8mONI46eZePT
         u5/jsTTo7WLsu5GAfzNEhJIkF5Cy2/jAiPccGJe91qqlIXKK9O9Og+V57NwslThK59Lm
         RZgttNDI99PtAPNnYV8GUQuQLnfMGqxhXcNwRQAz272XBT8lENlswQjfLv4zLHakK3af
         MJrai8zIO18Kp2p4ityIGTTFOhNz2HGmoF9sN4DrHwDNbmJQHa2mCQd5nu0HFKhNp09e
         woyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=29GVgi6oiUhOr7qNHF4/FFp5c/sS1BLMTsgBZOILycI=;
        b=D6jATd5oWy+0tAUr2FzIMmKh7zFFEzLhPnmob8wt3Ip/kJAfFqBN//zCCxh5XGJ3BS
         yWrgeV1hh9sXV0YWGo1sdOmWFBFpZh6VdaPwoh/sLdIm2JjYqhudz0CsJJO+1hQHm5DH
         JnWLh1HB2dbFCEhM+24vknn8u7Rn0ockjHUs7T9EgrTb5C+jUKPr3/myGOcg20WTFcrB
         +SCr9w39nlYZpbTUQH6itmbtj3wlPHTe7BmlU7OVbjdlaXb8tKiV9hCtgCpYv5rUswKN
         Ghm0Ao4QR9aV+FQNdC4g1QWjPokYO+oSAA0u32ielNPhCQ7MtxmNDpK7PuqIwwGzaMr2
         TkJA==
X-Gm-Message-State: AOAM531EKiDexSdXZ3BDXyzkpK6EqSVRQ0bkROTF/xgcHK3AuSd6eIsT
	Q/Co1EDi83sgt7fNUjnUqps=
X-Google-Smtp-Source: ABdhPJxb6KLKY/elJpGIDYzxeS3lOsi4QjCR3Y+UnwxSKBvT5x950hzcSJ/2sddhazXMuBgEpuNM5w==
X-Received: by 2002:a05:6602:2a42:b0:65a:eb90:2a12 with SMTP id k2-20020a0566022a4200b0065aeb902a12mr9473831iov.73.1652356093650;
        Thu, 12 May 2022 04:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3010:b0:319:c97e:f47d with SMTP id
 r16-20020a056638301000b00319c97ef47dls926613jak.1.gmail; Thu, 12 May 2022
 04:48:13 -0700 (PDT)
X-Received: by 2002:a05:6638:4705:b0:32b:5e0b:b58f with SMTP id cs5-20020a056638470500b0032b5e0bb58fmr15187393jab.34.1652356093194;
        Thu, 12 May 2022 04:48:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652356093; cv=none;
        d=google.com; s=arc-20160816;
        b=IwXb/IZVg2rZxONBqEunDvyJUA95zVmFODmUJy7NZ+gGcduoaDUWubH4Hjf9opbF/z
         gzYsmQBnNF5NzPzfIsutIk412C0RITy1+q0IXOaE8nrGLF55sAFTPpoUso1cGuWYVtos
         7z3jBOWIAhp/pRoFA0pBG8RC7jeBjtf9RP2WRkCTdT82d90g27QN3R2MEXJ10p7okX7P
         n1HM0Q3zVYGUQ3bgTpkGnRz7hYZ95UgPhntYwHMqp7T3hi+oJtvWaJwDcLvEjjRrh4xI
         NGmrqblwuf3joUDX3VXqFIB/2yH9XWuoIvJegLVVt+a9nZwrwGNHQ7u9zE2PcVRfGhxe
         yB+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JK2+i5Ku98GGSVUQ7q25UBT/j75Io56SBd88g6FXM58=;
        b=BRgrFjtEEZj2WSPBerhXWapZx7LMxkrDvAXQGQGKuk/Oa/juSVfjmQy95PdQ4nmBkZ
         rBGGlneCyOtLRwC51QOl7nGLTLjyPZNC/0zCc//Zgg5zJ5V8DOBw0CVRMxdR+cpWsWNg
         PRHfFqE+2l6bdlJjVWm8L0eTe8fza/9T3yDA11Jt596FAKZFH1uV81svlXjJU1oI+jWt
         ALgH4hOZPPQuhAYo49exaoCm0AQRbXfHIDKKjGIUNIM3I906OcJjodajQcXtuInFSPNm
         6vurll9XeRqy0DEmAI/VZhGKXjA/ZmOCd5nie2+CHAfWUOByuHlLkY+/f+jjWT/r4ILY
         b+yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aAFcTqcS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id j28-20020a056e02219c00b002cd85b685c5si334195ila.4.2022.05.12.04.48.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 May 2022 04:48:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id m6-20020a05683023a600b0060612720715so2485371ots.10
        for <kasan-dev@googlegroups.com>; Thu, 12 May 2022 04:48:13 -0700 (PDT)
X-Received: by 2002:a05:6830:23a6:b0:606:1bc8:b0d3 with SMTP id
 m6-20020a05683023a600b006061bc8b0d3mr11690535ots.196.1652356092670; Thu, 12
 May 2022 04:48:12 -0700 (PDT)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com>
 <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
 <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
 <CANp29Y4rDSjrfTOxcQqwh+Qm+ocR0v6Oxr7EkFxScf+24M1tNA@mail.gmail.com> <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
In-Reply-To: <CA+zEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 May 2022 13:48:01 +0200
Message-ID: <CACT4Y+Z=3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aAFcTqcS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32f
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

On Fri, 18 Feb 2022 at 14:45, Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi Aleksandr,
>
> On Thu, Feb 17, 2022 at 6:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Hi Alex,
> >
> > On Thu, Feb 17, 2022 at 5:53 PM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > Aleksandr,
> > >
> > > On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
> > > <alexandre.ghiti@canonical.com> wrote:
> > > >
> > > > First, thank you for working on this.
> > > >
> > > > On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >
> > > > > If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > > > > to boot, but overwhelms me with tons of `virt_to_phys used for
> > > > > non-linear address:` errors.
> > > > >
> > > > > Like that
> > > > >
> > > > > [    2.701271] virt_to_phys used for non-linear address:
> > > > > 00000000b59e31b6 (0xffffffff806c2000)
> > > > > [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > > > > __virt_to_phys+0x7e/0x86
> > > > > [    2.702207] Modules linked in:
> > > > > [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> > > > >   5.17.0-rc1 #1
> > > > > [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > > > > [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > > > > [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > > > > [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > > > > ffff8f800021bde0
> > > > > [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > > > > ffffffff80eea56f
> > > > > [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > > > > ffff8f800021be00
> > > > > [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > > > > ffffffff80e723d8
> > > > > [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > > > > 0000000000000000
> > > > > [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > > > > ffffffffffffffff
> > > > > [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > > > > ffffffff806c2000
> > > > > [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > > > > 0000000000000001
> > > > > [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > > > > 00000000000000cc
> > > > > [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > > > > ffffffffffffffff
> > > > > [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > > > > [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > > > > cause: 0000000000000003
> > > > > [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > > > > [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > > > > [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > > > > [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > > > > [    2.710310] ---[ end trace 0000000000000000 ]---
> > > > >
> > > >
> > > > I was able to reproduce this: the first one regarding init_zero_pfn is
> > > > legit but not wrong, I have to check when it was introduced and how to
> > > > fix this.
> > > > Regarding the huge batch that follows, at first sight, I would say
> > > > this is linked to my sv48 patchset but that does not seem important as
> > > > the address is a kernel mapping address so the use of virt_to_phys is
> > > > right.
> > > >
> > > > > On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > >
> > > > > > On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > > >
> > > > > > > On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > >
> > > > > > > > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > > >
> > > > > > > > > Hi Alex,
> > > > > > > > >
> > > > > > > > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > > > > > > >
> > > > > > > > > > Hi Dmitry,
> > > > > > > > > >
> > > > > > > > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > > > > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > > > > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > > > > > > > >> Hi Aleksandr,
> > > > > > > > > > >>
> > > > > > > > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > > > > >>> Hello,
> > > > > > > > > > >>>
> > > > > > > > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > > > > > > > >> That's a longtime, I'll take a look more regularly.
> > > > > > > > > > >>
> > > > > > > > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > > > > > > > >>> to the following commit:
> > > > > > > > > > >>>
> > > > > > > > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > > > > > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > > > > > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > > > > > > > >>>
> > > > > > > > > > >>>      riscv: Fix asan-stack clang build
> > > > > > > > > > >>>
> > > > > > > > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > > > > > > > >>> enabled. In the previous message syzbot mentions
> > > > > > > > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > > > > > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > > > > > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > > > > > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > > > > > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > > > > > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > > > > > > > >>>
> > > > > > > > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > > > > > > > >> I'll take a look at that today.
> > > > > > > > > > >>
> > > > > > > > > > >> Thanks for reporting the issue,
> > > > > > > > > > >
> > > > > > > > > >
> > > > > > > > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > > > > > > > from the inline instrumentation, I have no problem with the outline
> > > > > > > > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > > > > > > > to fix this for 5.17.
> > > > > > > > >
> > > > > > > > > Thanks for the update!
> > > > > > > > >
> > > > > > > > > Can you please share the .config with which you tested the outline
> > > > > > > > > instrumentation?
> > > > > > > > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > > > > > > but it still does not boot :(
> > > > > > > > >
> > > > > > > > > Here's what I used:
> > > > > > > > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > > > > > >
> > > > > > > > Update: it doesn't boot with that big config, but boots if I generate
> > > > > > > > a simple one with KASAN_OUTLINE:
> > > > > > > >
> > > > > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > > > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > > >
> > > > > > > > And it indeed doesn't work if I use KASAN_INLINE.
> > > > > > >
> > > > > > > It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > > > > > produce hugely massive .text. It may be hitting some limitation in the
> > > > > > > bootloader/kernel bootstrap code.
> > > >
> > > > I took a quick glance and it traps on a KASAN address that is not
> > > > mapped, either because it is too soon or because the mapping failed
> > > > somehow.
> > > >
> > > > I'll definitely dive into that tomorrow, sorry for being slow here and
> > > > thanks again for all your work, that helps a lot.
> > > >
> > > > Thanks,
> > > >
> > > > Alex
> > > >
> > > > > >
> > > > > > I bisected the difference between the config we use on syzbot and the
> > > > > > simple one that was generated like I described above.
> > > > > > Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > > > > >
> > > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > >
> > > > > > And the resulting kernel does not boot.
> > > > > > My env: the `riscv/fixes` branch, commit
> > > > > > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.
> > >
> > > I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
> > > maybe KASAN  + KCOV.
> > >
> > > With those small fixes, I was able to boot your large dotconfig with
> > > KASAN_OUTLINE, the inline version still fails, this is my next target
> > > :)
> > > I'll push that tomorrow!
> >
> > Awesome, thank you very much!
> > Looking forward to finally seeing the instance run :)
>
> I sent a patchset which should fix your config with *outline* instrumentation.

Was this fix merged? The riscv instance still does not boot:
https://syzkaller.appspot.com/bug?id=5f2ff52ad42cba9f222202219baebd4e63e35127

> However, as you'll see in the cover letter, I have an issue with
> another KASAN config and if you can take a look at the stacktrace and
> see if that rings a bell, that would be great.
>
> Don't hesitate next time to ping me when the riscv syzbot instance fails :)
>
> Alex
>
>
> >
> > --
> > Best Regards,
> > Aleksandr
> >
> > >
> > > Thanks again,
> > >
> > > Alex
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCtB0rTuNAJkrM2q3JQL7D-9fAXBo0Ud0w__gy9CAfo_Ag%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%3D3MWEhVUH3mAH150XpOmhdjsGPOHoP1nvBcBwU_sphQ%40mail.gmail.com.
