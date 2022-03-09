Return-Path: <kasan-dev+bncBCMIZB7QWENRB5MNUKIQMGQE3YOEVAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B4D24D2D6C
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 11:52:38 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id m17-20020a923f11000000b002c10e8f4c44sf1062609ila.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 02:52:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646823157; cv=pass;
        d=google.com; s=arc-20160816;
        b=x8ykXVy7FLwffFks26KXnqnQVvkS7DdcqJKyvciGKyYcCRbpOqMreBx1a9slQuLUOm
         vrGsBTl3PHWcHsK7yZmRnUuE3jtuGwC3x9uDiT22iLNZ5EYQSz8Ti3yroc6mQo5fKRqk
         TFXlz+caluiyAI7PinohAtE1aVPYlcB32uVKFDLGM8kq7DdeEBwjRvfrCumqoAZ3E3Pb
         OZbR7MHq9E/7GbloAQGqnqVVRZerBG8K1MIFm0nMtyyP486tnV/QheX3mVJr+rzq1x3M
         561seAev5MdHVFQDQsqaVtd6YF0VIXsk+IzK33+W1qrXQj2ALnunmkuW4Ui23S6gP3C6
         7EBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M+b5mF9Cgh6C4hgXL4P3HyaNW12MBFMTzdGMxaaMLa8=;
        b=Xvp4Ur8M/1g2b6LvrTQt5VyZlO3GMzssva20AX37TuLCYlZWXUREffaTY8flHlLif/
         S0EZUW2UJvKPAdxA5qQ2nmfyTNVSkKrIFpy9NAbP1d2OiRnt9A61pOZ9bxl4c1qXTFcm
         Es8kidYhba82o+afu4R6rLRK5zb+r6vPLiKjI564obtA9LDeaB1rTF3UUE46SrtTEaBK
         +s8KmjhTlpT5z5drUIdzep7tgm7tTcOXXGrMa/YqGCKYJUCN9OFqX1sqNR3GkRjFVIQ0
         DnNBuinqvpr7kx1HX/B3qibN0MHMnm4yp5JyoSYPjrtksW9PFXBlFf1sm6sEUlPAAhQg
         T6mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hrrGRELY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=M+b5mF9Cgh6C4hgXL4P3HyaNW12MBFMTzdGMxaaMLa8=;
        b=Ckvd9JABUw8U+kgfxhozZSWWN5psaCsRpG6VgtSOtPnQiYj7SjZei9IIWa4Up2poi4
         yY96bvUs1CCXYvVzKYtIlwxe+YhBXOjSB7sBX1ioUfzUfhDi/Mvzjb+bOaDB8zkA85gp
         XZgPXiFY7FrCrohbQSNRdDfom9mFKaKtQUHnLbdyU0mQe+1dGfJCqkodG0KauxUCrUJd
         //qRCeMvlIQOyvpTM8J2e5KVen8y6mHvxkQ9Myz+jeABPxjJWOHRcv1DVmTbkpa3/vr+
         CH6tzpU/R9bo612KnA7Hd1OYCjl9dzxAd0Tj8UsKgDbpXuI8WRhtGns53sqYMt4eKDRC
         RsAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M+b5mF9Cgh6C4hgXL4P3HyaNW12MBFMTzdGMxaaMLa8=;
        b=RDMBQvpytUuclr7ur9sW8EWPh7H4NZcIo0lhYowvSVI7E+dJyDGXT+5/bQdiCwzsG6
         el0545MLz98VOq3kvQSiw1eDdTispAkcXxXSyR7CqVa8gtiuMMJea+hrukS49Bjw5ekJ
         /9HmbnNdzuW393gaQGpeZUEJAYghdlhFzDsIimjx6KPt3iDzIuWlsRsOvYc7nygGpWQ7
         iGeB67WWbMPxhuqdoW9ZSuRNK4t17MbIvRX22HpQTtiGGucRCqBmkg9W9hOWKrxVEw+F
         n/rGZ0lJvqHgq3aIU8bMIX/wImRTE5smAJwZEL7gjgHd/9F5Nlm1/ZCjyQ1nI5PEwuhM
         GYvw==
X-Gm-Message-State: AOAM531rqqPf+7sUUG3wvU8KhLT4kTHAEtxm8pf4DjObq6ofzqaQz+LK
	nXVKOxLknu8bKnWJtt6PFfY=
X-Google-Smtp-Source: ABdhPJz3PdvP6gCJA3R727sEkFsUgSpLnHO3gMP0COyFgCxNdD8ClqVQzFbv+huwabAvytSv2JhQSg==
X-Received: by 2002:a05:6638:bcd:b0:314:9138:8344 with SMTP id g13-20020a0566380bcd00b0031491388344mr19494916jad.64.1646823157096;
        Wed, 09 Mar 2022 02:52:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1512:b0:314:5a70:95ee with SMTP id
 b18-20020a056638151200b003145a7095eels322109jat.3.gmail; Wed, 09 Mar 2022
 02:52:36 -0800 (PST)
X-Received: by 2002:a05:6638:2581:b0:317:ae44:3575 with SMTP id s1-20020a056638258100b00317ae443575mr16660144jat.0.1646823156637;
        Wed, 09 Mar 2022 02:52:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646823156; cv=none;
        d=google.com; s=arc-20160816;
        b=oIzVFeA3s344iRGesiot0M5az1kP4hEnsiKYqtZXCDK+Gc1sTn2tE3z91cVcmhSo8r
         TmJTZSKfEgbiBxvtSkryCFFFNKvQSaLHJRAbm9Fs6jCbcuETdcQkZavHdY7ouMOCOWrf
         LsHVmaC9Bt3av3fXJ0a6un3XIDolRvhfc/KnkzhtHQGSlHvgvS7aFntPB3VO4U3MF1tN
         E3wuHBVO9vUGvHfuJ8OdlW3AhguIDuRUVaztp6vOTgbhc1pxOiV58yOEPiQD7hCA49Cx
         wdwJ0JhTUDJm7YkOIqkKc7UaOtuNuGNjl36q2BtcgpQr+ldGrSqdKJVw5afWZiEK9OZx
         OPwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fJu02Rm+819yVYZ0AGS3TauUWd+drbepJKgAxQy5Opw=;
        b=hS9eMlI+VLqXqgeE0gRz7VEpmwzNfLVh3miFK/syg/otl/vNNvgkNd0Ka5cWbUI182
         h2iGFHd/1O8bMaJ8r/xq188UQ6HCgmxPMPkoHzyAhyulPFtM5vSOtp6uNgpaSbNGj3d3
         vGj2N0GokO8jNRCGHsCbcbSgRIAFXNEmK/2yBP1VfaV1ZPNJpnlpur7knbfrut8NXN6K
         n9T7VNOSXsDcrXbjOzNQWLOeoYhRwr3tzyEihGBvalpKynMTWzH6HW/0hTvgLCINAJda
         k/YojJsd4MFssbVsqTLbS93jh8eMtgF2QAPn9G2EKnc9y0lS+Te0b6Y1qSUCWx5+7loG
         jNxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hrrGRELY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc33.google.com (mail-oo1-xc33.google.com. [2607:f8b0:4864:20::c33])
        by gmr-mx.google.com with ESMTPS id i5-20020a056602134500b006411847597bsi54253iov.1.2022.03.09.02.52.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Mar 2022 02:52:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) client-ip=2607:f8b0:4864:20::c33;
Received: by mail-oo1-xc33.google.com with SMTP id j7-20020a4ad6c7000000b0031c690e4123so2303102oot.11
        for <kasan-dev@googlegroups.com>; Wed, 09 Mar 2022 02:52:36 -0800 (PST)
X-Received: by 2002:a05:6870:95a1:b0:da:b3f:2b34 with SMTP id
 k33-20020a05687095a100b000da0b3f2b34mr5052480oao.211.1646823155943; Wed, 09
 Mar 2022 02:52:35 -0800 (PST)
MIME-Version: 1.0
References: <mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9@palmer-mbp2014>
 <mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74@palmer-ri-x1c9> <CANp29Y6MvZvx4Xjwx=bxZ86D7Kubg0JPwBzP6HH8A6+Zj7YeLQ@mail.gmail.com>
In-Reply-To: <CANp29Y6MvZvx4Xjwx=bxZ86D7Kubg0JPwBzP6HH8A6+Zj7YeLQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 11:52:24 +0100
Message-ID: <CACT4Y+ZA7CRNfYgPmi6jHTKD9rwvaJy=nh5Gz_c-PFHq3tuziQ@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, Alexander Potapenko <glider@google.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, Marco Elver <elver@google.com>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Nick Hu <nickhu@andestech.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hrrGRELY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c33
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

On Wed, 9 Mar 2022 at 11:45, Aleksandr Nogikh <nogikh@google.com> wrote:
>
> I switched the riscv syzbot instance to KASAN_OUTLINE and now it is
> finally being fuzzed again!
>
> Thank you very much for the series!


But all riscv crashes are still classified as "corrupted" and thrown
away (not reported):
https://syzkaller.appspot.com/bug?id=3Dd5bc3e0c66d200d72216ab343a67c4327e4a=
3452

The problem is that risvc oopses don't contain "Call Trace:" in the
beginning of stack traces, so it's hard to make sense out of them.
arch/riscv seems to print "Call Trace:" in a wrong function, not where
all other arches print it.



> --
> Best Regards,
> Aleksandr
>
> On Fri, Mar 4, 2022 at 5:12 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
> >
> > On Tue, 01 Mar 2022 09:39:54 PST (-0800), Palmer Dabbelt wrote:
> > > On Fri, 25 Feb 2022 07:00:23 PST (-0800), glider@google.com wrote:
> > >> On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
> > >> alexandre.ghiti@canonical.com> wrote:
> > >>
> > >>> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@google.=
com>
> > >>> wrote:
> > >>> >
> > >>> >
> > >>> >
> > >>> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
> > >>> alexandre.ghiti@canonical.com> wrote:
> > >>> >>
> > >>> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@goog=
le.com>
> > >>> wrote:
> > >>> >> >
> > >>> >> >
> > >>> >> >
> > >>> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
> > >>> alexandre.ghiti@canonical.com> wrote:
> > >>> >> >>
> > >>> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com=
>
> > >>> wrote:
> > >>> >> >> >
> > >>> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> > >>> >> >> > <alexandre.ghiti@canonical.com> wrote:
> > >>> >> >> > >
> > >>> >> >> > > As reported by Aleksandr, syzbot riscv is broken since co=
mmit
> > >>> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This =
commit
> > >>> actually
> > >>> >> >> > > breaks KASAN_INLINE which is not fixed in this series, th=
at will
> > >>> come later
> > >>> >> >> > > when found.
> > >>> >> >> > >
> > >>> >> >> > > Nevertheless, this series fixes small things that made th=
e syzbot
> > >>> >> >> > > configuration + KASAN_OUTLINE fail to boot.
> > >>> >> >> > >
> > >>> >> >> > > Note that even though the config at [1] boots fine with t=
his
> > >>> series, I
> > >>> >> >> > > was not able to boot the small config at [2] which fails =
because
> > >>> >> >> > > kasan_poison receives a really weird address 0x4075706301=
000000
> > >>> (maybe a
> > >>> >> >> > > kasan person could provide some hint about what happens b=
elow in
> > >>> >> >> > > do_ctors -> __asan_register_globals):
> > >>> >> >> >
> > >>> >> >> > asan_register_globals is responsible for poisoning redzones=
 around
> > >>> >> >> > globals. As hinted by 'do_ctors', it calls constructors, an=
d in
> > >>> this
> > >>> >> >> > case a compiler-generated constructor that calls
> > >>> >> >> > __asan_register_globals with metadata generated by the comp=
iler.
> > >>> That
> > >>> >> >> > metadata contains information about global variables. Note,=
 these
> > >>> >> >> > constructors are called on initial boot, but also every tim=
e a
> > >>> kernel
> > >>> >> >> > module (that has globals) is loaded.
> > >>> >> >> >
> > >>> >> >> > It may also be a toolchain issue, but it's hard to say. If =
you're
> > >>> >> >> > using GCC to test, try Clang (11 or later), and vice-versa.
> > >>> >> >>
> > >>> >> >> I tried 3 different gcc toolchains already, but that did not =
fix the
> > >>> >> >> issue. The only thing that worked was setting asan-globals=3D=
0 in
> > >>> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
> > >>> >> >> I tried to bisect this issue but our kasan implementation has=
 been
> > >>> >> >> broken quite a few times, so it failed.
> > >>> >> >>
> > >>> >> >> I keep digging!
> > >>> >> >>
> > >>> >> >
> > >>> >> > The problem does not reproduce for me with GCC 11.2.0: kernels=
 built
> > >>> with both [1] and [2] are bootable.
> > >>> >>
> > >>> >> Do you mean you reach userspace? Because my image boots too, and=
 fails
> > >>> >> at some point:
> > >>> >>
> > >>> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, =
wraps
> > >>> >> every 4398046511100ns
> > >>> >> [    0.015847] Console: colour dummy device 80x25
> > >>> >> [    0.016899] printk: console [tty0] enabled
> > >>> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
> > >>> >>
> > >>> >
> > >>> > In my case, QEMU successfully boots to the login prompt.
> > >>> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Aleksa=
ndr
> > >>> shared with me (guess it was built according to this instruction:
> > >>> https://github.com/google/syzkaller/blob/master/docs/linux/setup_li=
nux-host_qemu-vm_riscv64-kernel.md
> > >>> )
> > >>> >
> > >>>
> > >>> Nice thanks guys! I always use the latest opensbi and not the one t=
hat
> > >>> is embedded in qemu, which is the only difference between your comm=
and
> > >>> line (which works) and mine (which does not work). So the issue is
> > >>> probably there, I really need to investigate that now.
> > >>>
> > >>> Great to hear that!
> > >>
> > >>
> > >>> That means I only need to fix KASAN_INLINE and we're good.
> > >>>
> > >>> I imagine Palmer can add your Tested-by on the series then?
> > >>>
> > >> Sure :)
> > >
> > > Do you mind actually posting that (i, the Tested-by tag)?  It's less
> > > likely to get lost that way.  I intend on taking this into fixes ASAP=
,
> > > my builds have blown up for some reason (I got bounced between machin=
es,
> > > so I'm blaming that) so I need to fix that first.
> >
> > This is on fixes (with a "Tested-by: Alexander Potapenko
> > <glider@google.com>"), along with some trivial commit message fixes.
> >
> > Thanks!
> >
> > >
> > >>
> > >>>
> > >>> Thanks again!
> > >>>
> > >>> Alex
> > >>>
> > >>> >>
> > >>> >> It traps here.
> > >>> >>
> > >>> >> > FWIW here is how I run them:
> > >>> >> >
> > >>> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
> > >>> >> >   -device virtio-rng-pci -machine virt -device \
> > >>> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
> > >>> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:=
22 -device \
> > >>> >> >   virtio-blk-device,drive=3Dhd0 -drive \
> > >>> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
> > >>> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
> > >>> "root=3D/dev/vda
> > >>> >> >   console=3DttyS0 earlyprintk=3Dserial"
> > >>> >> >
> > >>> >> >
> > >>> >> >>
> > >>> >> >> Thanks for the tips,
> > >>> >> >>
> > >>> >> >> Alex
> > >>> >> >
> > >>> >> >
> > >>> >> >
> > >>> >> > --
> > >>> >> > Alexander Potapenko
> > >>> >> > Software Engineer
> > >>> >> >
> > >>> >> > Google Germany GmbH
> > >>> >> > Erika-Mann-Stra=C3=9Fe, 33
> > >>> >> > 80636 M=C3=BCnchen
> > >>> >> >
> > >>> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > >>> >> > Registergericht und -nummer: Hamburg, HRB 86891
> > >>> >> > Sitz der Gesellschaft: Hamburg
> > >>> >> >
> > >>> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschliche=
rweise
> > >>> erhalten haben sollten, leiten Sie diese bitte nicht an jemand ande=
res
> > >>> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und las=
sen Sie mich bitte
> > >>> wissen, dass die E-Mail an die falsche Person gesendet wurde.
> > >>> >> >
> > >>> >> >
> > >>> >> >
> > >>> >> > This e-mail is confidential. If you received this communicatio=
n by
> > >>> mistake, please don't forward it to anyone else, please erase all c=
opies
> > >>> and attachments, and please let me know that it has gone to the wro=
ng
> > >>> person.
> > >>> >>
> > >>> >> --
> > >>> >> You received this message because you are subscribed to the Goog=
le
> > >>> Groups "kasan-dev" group.
> > >>> >> To unsubscribe from this group and stop receiving emails from it=
, send
> > >>> an email to kasan-dev+unsubscribe@googlegroups.com.
> > >>> >> To view this discussion on the web visit
> > >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhKnv=
jujXkMXuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
> > >>> .
> > >>> >
> > >>> >
> > >>> >
> > >>> > --
> > >>> > Alexander Potapenko
> > >>> > Software Engineer
> > >>> >
> > >>> > Google Germany GmbH
> > >>> > Erika-Mann-Stra=C3=9Fe, 33
> > >>> > 80636 M=C3=BCnchen
> > >>> >
> > >>> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > >>> > Registergericht und -nummer: Hamburg, HRB 86891
> > >>> > Sitz der Gesellschaft: Hamburg
> > >>> >
> > >>> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherwe=
ise erhalten
> > >>> haben sollten, leiten Sie diese bitte nicht an jemand anderes weite=
r,
> > >>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie =
mich bitte wissen,
> > >>> dass die E-Mail an die falsche Person gesendet wurde.
> > >>> >
> > >>> >
> > >>> >
> > >>> > This e-mail is confidential. If you received this communication b=
y
> > >>> mistake, please don't forward it to anyone else, please erase all c=
opies
> > >>> and attachments, and please let me know that it has gone to the wro=
ng
> > >>> person.
> > >>>
> > >>> --
> > >>> You received this message because you are subscribed to the Google =
Groups
> > >>> "kasan-dev" group.
> > >>> To unsubscribe from this group and stop receiving emails from it, s=
end an
> > >>> email to kasan-dev+unsubscribe@googlegroups.com.
> > >>> To view this discussion on the web visit
> > >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNdFq=
DM96bzKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
> > >>> .
> > >>>
> > >>
> > >>
> > >> --
> > >> Alexander Potapenko
> > >> Software Engineer
> > >>
> > >> Google Germany GmbH
> > >> Erika-Mann-Stra=C3=9Fe, 33
> > >> 80636 M=C3=BCnchen
> > >>
> > >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > >> Registergericht und -nummer: Hamburg, HRB 86891
> > >> Sitz der Gesellschaft: Hamburg
> > >>
> > >> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise=
 erhalten
> > >> haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter=
,
> > >> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie m=
ich bitte wissen,
> > >> dass die E-Mail an die falsche Person gesendet wurde.
> > >>
> > >>
> > >>
> > >> This e-mail is confidential. If you received this communication by m=
istake,
> > >> please don't forward it to anyone else, please erase all copies and
> > >> attachments, and please let me know that it has gone to the wrong pe=
rson.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZA7CRNfYgPmi6jHTKD9rwvaJy%3Dnh5Gz_c-PFHq3tuziQ%40mail.gm=
ail.com.
