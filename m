Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBZXTU2IQMGQENVKM5ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A01044D42C4
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 09:42:14 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id a26-20020a7bc1da000000b003857205ec7csf2020558wmj.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 00:42:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646901734; cv=pass;
        d=google.com; s=arc-20160816;
        b=e48KXqL2TFxXKRcJ64bPFtoFVUe2+zOtRK+i1Ki7bxXqD/8pPmBgJ6rpwaUx4CGWGc
         PYctNJIPomaIocJ7xcUccqWKa1CaM4QWq+vJOXWMHRxJpgdam1IqY9Ebvbx7kgt6uLFU
         x3YDH64r8fKlQn8p7uMx2WI7X3s2SeIcOqQZzaKNoTMJd8oWEfpeEXo8nxyRwb6k2dbG
         OFVeJ817OijglaKPJ/Ah9Boq7Y+UPzjJz9HTzkMtahu2V/tWg85STkkOl4kXI6XZYKfk
         cEFmIJeDIZrkiiF+dCATDosn8fwQSfYq5fpJuIVN1KcNQ+TqeLkzR49ynbGCF9l1TIEf
         fWmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ZVj23lIgbjp1qRV7akvtUrC3OqgkN6o8Bsp8QrbcgJQ=;
        b=dYn4zdTmwzvmfjdSe8RpmieA1n3Onh9W9K1cJsLT8GaNzBenCeYE5v59BoTj3SSYqK
         q58tanh6CmFiWnNF9q2f2uXNG2LfVykg4X0bzsZ96ouF8JcNNW3gEdHaaHEjENDEOz7j
         jXjTxlfMcb+SZwz1a5eKK90jqX9tEXsUlfjs/I5DukeXV/YsSvvPq9zMv2rb3PRXh+wu
         v2OoWqr14qO8nVZAY9omIlcND9mBhdP5dM8JS1QtYTCn/fzXHweiQEiUd5B/j9JPOqjN
         hCy5oH7693N7bKgXLyrkty2AivAgu2Asr5rV4uxXupNdkkBDhxACZWaPSVQf7WlKO4kG
         E7yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=aV+5dyqH;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZVj23lIgbjp1qRV7akvtUrC3OqgkN6o8Bsp8QrbcgJQ=;
        b=L/hkgDLs9imzoHR1ifAihEfD7FQ3HoAX9Oa/a42SRbMK0klE/FuoAQAiD5VKQLVyyx
         H5UbN6sFWjH2Uiu1SlFSkOGnOmwt4u/rhkOH6qeXb731/QIMeySBPOy36qAqs9srG42x
         oeddG7t40jY4qAvDtNFxll2ZpADSLSsACAicERQmz3cC51XrL+BOmiJDhvRfjCZ5grMD
         Llzk/MA+b2QFzMJ5k0bPvtT/4v4MRQDARqDrxpHeXtTZgWk45EFHjaLKws7p+5TlOp0T
         6AD9+NRFJNZJS8wW31nAJx0CL9i0NYTcPwpFNAIK1W70sIRwxb7y+Sog5f5IcT1+7j4m
         9n0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZVj23lIgbjp1qRV7akvtUrC3OqgkN6o8Bsp8QrbcgJQ=;
        b=S6kdXB0z3o8yEieirlI+ulX3ylR/tcPF8k4Fx71b792A0wVa83KKMistPUbbHW7XRJ
         duw1cEvv8yLyu3LOMhItyg51n2NBtYSP1tq+w9qQyFkDZ9rEarHfDHaxulrV2+1G9Lzh
         7Pr2/XRLfn2ojhzXzczbK2B4G3myReh7BwqZA9O6L9QJViIPsTQW3gbzGq68S8Ez4GaR
         VIp80s6FI2p3Z/HsUiqwAscmdi5bdzdD7S+E6d5qtyO16+bYy+EC1aMdCubTwY4lPSm4
         JXiU7tgswTyRWKIzLnZ4YuFGvDSCZgHmspVWDD0GCymiykCAmZ5sJO7OrwSMS5+SK7mn
         abuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Dzv2nqeMtwqsAiXMh03XqItPiCY5YWkXbHuU8lK6rI0shQO2b
	+SqVWvMi4WJrOppNO1w+W8o=
X-Google-Smtp-Source: ABdhPJx98oOA+yaQ5NOChTnifUWRBGyUyuItRXIFMvEHFPkLQT6JzvsqjQotePjJ6V+Do7l1/BQUVQ==
X-Received: by 2002:a05:600c:350f:b0:389:e77f:3c17 with SMTP id h15-20020a05600c350f00b00389e77f3c17mr462632wmq.81.1646901734242;
        Thu, 10 Mar 2022 00:42:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d0c5:0:b0:1f0:7735:e337 with SMTP id z5-20020adfd0c5000000b001f07735e337ls44368wrh.1.gmail;
 Thu, 10 Mar 2022 00:42:13 -0800 (PST)
X-Received: by 2002:adf:b645:0:b0:1e3:bab:7594 with SMTP id i5-20020adfb645000000b001e30bab7594mr2695511wre.346.1646901733296;
        Thu, 10 Mar 2022 00:42:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646901733; cv=none;
        d=google.com; s=arc-20160816;
        b=NTu2wK4rtJHKK8Im1tSLRjRm83lhdy7hNKYpM39WGD0m0g4nswnhZp7DCwNpV7jYjF
         UgnhUSLZZO7OAJn33mhk91N0GEuyr8tS5LfNUI22Jw9U5OnWNdols9Uc+nCZ3U58kx6T
         0wKbMOYyA2tuUQN9WLsVlgi/sCZPuoory0ynXKjZlevyBR15wdUc1FZ+zZddongvibWw
         hHPINs5N+ItukQZlJgAH1IINiMCGCx9JZpFI/h2vIs88GP5thdPOoqEGlJvlhYmtzLhh
         aWGE8WTrksXgYfNK03sHDbAhPiBybbYlGqByN6z7vlHVrNuleWXoH31fhETSXfUquYyw
         VXqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cAFDXSKpDn5Z6TlMfaE+wkbrmhm+ae2B/76qxjjTkJs=;
        b=b43eopX1avZ/MS4vzULmYSdXND2/NiQ4j1uHXDnbY6uJU5Vt8QC6mkaxa+NuVqSJR7
         W5VD/rtfQmogcnQ+6OeMFl7vN6byOVG254atm7MQ4V94ek+wxAMqJ8Xb84dAIzMGgxj6
         W420nvmRhOG5kvLlFjL4lvlpGdF9tbNH/2wEy9cLB23MaqaiX7WS2HXJ7RfuA+sWGfKo
         tmpusmI1RJyUjNU49naAs9sEEpwVTbpRUEgZPi7ZCmBUBIcO28Skkx8cQQoxcsfiwnUZ
         u7focjfroGrX+h65ourZspkRNyEl9ISOCDcev7evrZBUnllp3c/ubLV9eUjhCG9gpjSk
         Qytw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=aV+5dyqH;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id a6-20020a056000188600b002037aa59394si264715wri.3.2022.03.10.00.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Mar 2022 00:42:13 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 6ABA43F07E
	for <kasan-dev@googlegroups.com>; Thu, 10 Mar 2022 08:42:11 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id r8-20020aa7d588000000b00416438ed9a2so2715423edq.11
        for <kasan-dev@googlegroups.com>; Thu, 10 Mar 2022 00:42:11 -0800 (PST)
X-Received: by 2002:a17:906:c14e:b0:6da:970b:cc33 with SMTP id dp14-20020a170906c14e00b006da970bcc33mr3147154ejc.307.1646901730947;
        Thu, 10 Mar 2022 00:42:10 -0800 (PST)
X-Received: by 2002:a17:906:c14e:b0:6da:970b:cc33 with SMTP id
 dp14-20020a170906c14e00b006da970bcc33mr3147131ejc.307.1646901730537; Thu, 10
 Mar 2022 00:42:10 -0800 (PST)
MIME-Version: 1.0
References: <mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9@palmer-mbp2014>
 <mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74@palmer-ri-x1c9>
 <CANp29Y6MvZvx4Xjwx=bxZ86D7Kubg0JPwBzP6HH8A6+Zj7YeLQ@mail.gmail.com> <CACT4Y+ZA7CRNfYgPmi6jHTKD9rwvaJy=nh5Gz_c-PFHq3tuziQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZA7CRNfYgPmi6jHTKD9rwvaJy=nh5Gz_c-PFHq3tuziQ@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 10 Mar 2022 09:41:57 +0100
Message-ID: <CA+zEjCsCHhaQ4nEC8VEbCyQt3aG0E78S6PoCgzJA5qkoGC10ZA@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Nick Hu <nickhu@andestech.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=aV+5dyqH;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Hi,

On Wed, Mar 9, 2022 at 11:52 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, 9 Mar 2022 at 11:45, Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > I switched the riscv syzbot instance to KASAN_OUTLINE and now it is
> > finally being fuzzed again!
> >
> > Thank you very much for the series!
>
>
> But all riscv crashes are still classified as "corrupted" and thrown
> away (not reported):
> https://syzkaller.appspot.com/bug?id=3Dd5bc3e0c66d200d72216ab343a67c4327e=
4a3452
>
> The problem is that risvc oopses don't contain "Call Trace:" in the
> beginning of stack traces, so it's hard to make sense out of them.
> arch/riscv seems to print "Call Trace:" in a wrong function, not where
> all other arches print it.
>

Does the following diff fix this issue?

diff --git a/arch/riscv/kernel/stacktrace.c b/arch/riscv/kernel/stacktrace.=
c
index 201ee206fb57..348ca19ccbf8 100644
--- a/arch/riscv/kernel/stacktrace.c
+++ b/arch/riscv/kernel/stacktrace.c
@@ -109,12 +109,12 @@ static bool print_trace_address(void *arg,
unsigned long pc)
 noinline void dump_backtrace(struct pt_regs *regs, struct task_struct *tas=
k,
                    const char *loglvl)
 {
+       pr_cont("%sCall Trace:\n", loglvl);
        walk_stackframe(task, regs, print_trace_address, (void *)loglvl);
 }

 void show_stack(struct task_struct *task, unsigned long *sp, const
char *loglvl)
 {
-       pr_cont("%sCall Trace:\n", loglvl);
        dump_backtrace(NULL, task, loglvl);
 }

Thanks,

Alex

>
>
> > --
> > Best Regards,
> > Aleksandr
> >
> > On Fri, Mar 4, 2022 at 5:12 AM Palmer Dabbelt <palmer@dabbelt.com> wrot=
e:
> > >
> > > On Tue, 01 Mar 2022 09:39:54 PST (-0800), Palmer Dabbelt wrote:
> > > > On Fri, 25 Feb 2022 07:00:23 PST (-0800), glider@google.com wrote:
> > > >> On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
> > > >> alexandre.ghiti@canonical.com> wrote:
> > > >>
> > > >>> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@googl=
e.com>
> > > >>> wrote:
> > > >>> >
> > > >>> >
> > > >>> >
> > > >>> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
> > > >>> alexandre.ghiti@canonical.com> wrote:
> > > >>> >>
> > > >>> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@go=
ogle.com>
> > > >>> wrote:
> > > >>> >> >
> > > >>> >> >
> > > >>> >> >
> > > >>> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
> > > >>> alexandre.ghiti@canonical.com> wrote:
> > > >>> >> >>
> > > >>> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.c=
om>
> > > >>> wrote:
> > > >>> >> >> >
> > > >>> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> > > >>> >> >> > <alexandre.ghiti@canonical.com> wrote:
> > > >>> >> >> > >
> > > >>> >> >> > > As reported by Aleksandr, syzbot riscv is broken since =
commit
> > > >>> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). Thi=
s commit
> > > >>> actually
> > > >>> >> >> > > breaks KASAN_INLINE which is not fixed in this series, =
that will
> > > >>> come later
> > > >>> >> >> > > when found.
> > > >>> >> >> > >
> > > >>> >> >> > > Nevertheless, this series fixes small things that made =
the syzbot
> > > >>> >> >> > > configuration + KASAN_OUTLINE fail to boot.
> > > >>> >> >> > >
> > > >>> >> >> > > Note that even though the config at [1] boots fine with=
 this
> > > >>> series, I
> > > >>> >> >> > > was not able to boot the small config at [2] which fail=
s because
> > > >>> >> >> > > kasan_poison receives a really weird address 0x40757063=
01000000
> > > >>> (maybe a
> > > >>> >> >> > > kasan person could provide some hint about what happens=
 below in
> > > >>> >> >> > > do_ctors -> __asan_register_globals):
> > > >>> >> >> >
> > > >>> >> >> > asan_register_globals is responsible for poisoning redzon=
es around
> > > >>> >> >> > globals. As hinted by 'do_ctors', it calls constructors, =
and in
> > > >>> this
> > > >>> >> >> > case a compiler-generated constructor that calls
> > > >>> >> >> > __asan_register_globals with metadata generated by the co=
mpiler.
> > > >>> That
> > > >>> >> >> > metadata contains information about global variables. Not=
e, these
> > > >>> >> >> > constructors are called on initial boot, but also every t=
ime a
> > > >>> kernel
> > > >>> >> >> > module (that has globals) is loaded.
> > > >>> >> >> >
> > > >>> >> >> > It may also be a toolchain issue, but it's hard to say. I=
f you're
> > > >>> >> >> > using GCC to test, try Clang (11 or later), and vice-vers=
a.
> > > >>> >> >>
> > > >>> >> >> I tried 3 different gcc toolchains already, but that did no=
t fix the
> > > >>> >> >> issue. The only thing that worked was setting asan-globals=
=3D0 in
> > > >>> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
> > > >>> >> >> I tried to bisect this issue but our kasan implementation h=
as been
> > > >>> >> >> broken quite a few times, so it failed.
> > > >>> >> >>
> > > >>> >> >> I keep digging!
> > > >>> >> >>
> > > >>> >> >
> > > >>> >> > The problem does not reproduce for me with GCC 11.2.0: kerne=
ls built
> > > >>> with both [1] and [2] are bootable.
> > > >>> >>
> > > >>> >> Do you mean you reach userspace? Because my image boots too, a=
nd fails
> > > >>> >> at some point:
> > > >>> >>
> > > >>> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns=
, wraps
> > > >>> >> every 4398046511100ns
> > > >>> >> [    0.015847] Console: colour dummy device 80x25
> > > >>> >> [    0.016899] printk: console [tty0] enabled
> > > >>> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
> > > >>> >>
> > > >>> >
> > > >>> > In my case, QEMU successfully boots to the login prompt.
> > > >>> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Alek=
sandr
> > > >>> shared with me (guess it was built according to this instruction:
> > > >>> https://github.com/google/syzkaller/blob/master/docs/linux/setup_=
linux-host_qemu-vm_riscv64-kernel.md
> > > >>> )
> > > >>> >
> > > >>>
> > > >>> Nice thanks guys! I always use the latest opensbi and not the one=
 that
> > > >>> is embedded in qemu, which is the only difference between your co=
mmand
> > > >>> line (which works) and mine (which does not work). So the issue i=
s
> > > >>> probably there, I really need to investigate that now.
> > > >>>
> > > >>> Great to hear that!
> > > >>
> > > >>
> > > >>> That means I only need to fix KASAN_INLINE and we're good.
> > > >>>
> > > >>> I imagine Palmer can add your Tested-by on the series then?
> > > >>>
> > > >> Sure :)
> > > >
> > > > Do you mind actually posting that (i, the Tested-by tag)?  It's les=
s
> > > > likely to get lost that way.  I intend on taking this into fixes AS=
AP,
> > > > my builds have blown up for some reason (I got bounced between mach=
ines,
> > > > so I'm blaming that) so I need to fix that first.
> > >
> > > This is on fixes (with a "Tested-by: Alexander Potapenko
> > > <glider@google.com>"), along with some trivial commit message fixes.
> > >
> > > Thanks!
> > >
> > > >
> > > >>
> > > >>>
> > > >>> Thanks again!
> > > >>>
> > > >>> Alex
> > > >>>
> > > >>> >>
> > > >>> >> It traps here.
> > > >>> >>
> > > >>> >> > FWIW here is how I run them:
> > > >>> >> >
> > > >>> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
> > > >>> >> >   -device virtio-rng-pci -machine virt -device \
> > > >>> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
> > > >>> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529=
-:22 -device \
> > > >>> >> >   virtio-blk-device,drive=3Dhd0 -drive \
> > > >>> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot =
\
> > > >>> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
> > > >>> "root=3D/dev/vda
> > > >>> >> >   console=3DttyS0 earlyprintk=3Dserial"
> > > >>> >> >
> > > >>> >> >
> > > >>> >> >>
> > > >>> >> >> Thanks for the tips,
> > > >>> >> >>
> > > >>> >> >> Alex
> > > >>> >> >
> > > >>> >> >
> > > >>> >> >
> > > >>> >> > --
> > > >>> >> > Alexander Potapenko
> > > >>> >> > Software Engineer
> > > >>> >> >
> > > >>> >> > Google Germany GmbH
> > > >>> >> > Erika-Mann-Stra=C3=9Fe, 33
> > > >>> >> > 80636 M=C3=BCnchen
> > > >>> >> >
> > > >>> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > > >>> >> > Registergericht und -nummer: Hamburg, HRB 86891
> > > >>> >> > Sitz der Gesellschaft: Hamburg
> > > >>> >> >
> > > >>> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlic=
herweise
> > > >>> erhalten haben sollten, leiten Sie diese bitte nicht an jemand an=
deres
> > > >>> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und l=
assen Sie mich bitte
> > > >>> wissen, dass die E-Mail an die falsche Person gesendet wurde.
> > > >>> >> >
> > > >>> >> >
> > > >>> >> >
> > > >>> >> > This e-mail is confidential. If you received this communicat=
ion by
> > > >>> mistake, please don't forward it to anyone else, please erase all=
 copies
> > > >>> and attachments, and please let me know that it has gone to the w=
rong
> > > >>> person.
> > > >>> >>
> > > >>> >> --
> > > >>> >> You received this message because you are subscribed to the Go=
ogle
> > > >>> Groups "kasan-dev" group.
> > > >>> >> To unsubscribe from this group and stop receiving emails from =
it, send
> > > >>> an email to kasan-dev+unsubscribe@googlegroups.com.
> > > >>> >> To view this discussion on the web visit
> > > >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7CdhK=
nvjujXkMXuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
> > > >>> .
> > > >>> >
> > > >>> >
> > > >>> >
> > > >>> > --
> > > >>> > Alexander Potapenko
> > > >>> > Software Engineer
> > > >>> >
> > > >>> > Google Germany GmbH
> > > >>> > Erika-Mann-Stra=C3=9Fe, 33
> > > >>> > 80636 M=C3=BCnchen
> > > >>> >
> > > >>> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > > >>> > Registergericht und -nummer: Hamburg, HRB 86891
> > > >>> > Sitz der Gesellschaft: Hamburg
> > > >>> >
> > > >>> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicher=
weise erhalten
> > > >>> haben sollten, leiten Sie diese bitte nicht an jemand anderes wei=
ter,
> > > >>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Si=
e mich bitte wissen,
> > > >>> dass die E-Mail an die falsche Person gesendet wurde.
> > > >>> >
> > > >>> >
> > > >>> >
> > > >>> > This e-mail is confidential. If you received this communication=
 by
> > > >>> mistake, please don't forward it to anyone else, please erase all=
 copies
> > > >>> and attachments, and please let me know that it has gone to the w=
rong
> > > >>> person.
> > > >>>
> > > >>> --
> > > >>> You received this message because you are subscribed to the Googl=
e Groups
> > > >>> "kasan-dev" group.
> > > >>> To unsubscribe from this group and stop receiving emails from it,=
 send an
> > > >>> email to kasan-dev+unsubscribe@googlegroups.com.
> > > >>> To view this discussion on the web visit
> > > >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQNd=
FqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
> > > >>> .
> > > >>>
> > > >>
> > > >>
> > > >> --
> > > >> Alexander Potapenko
> > > >> Software Engineer
> > > >>
> > > >> Google Germany GmbH
> > > >> Erika-Mann-Stra=C3=9Fe, 33
> > > >> 80636 M=C3=BCnchen
> > > >>
> > > >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > > >> Registergericht und -nummer: Hamburg, HRB 86891
> > > >> Sitz der Gesellschaft: Hamburg
> > > >>
> > > >> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherwei=
se erhalten
> > > >> haben sollten, leiten Sie diese bitte nicht an jemand anderes weit=
er,
> > > >> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie=
 mich bitte wissen,
> > > >> dass die E-Mail an die falsche Person gesendet wurde.
> > > >>
> > > >>
> > > >>
> > > >> This e-mail is confidential. If you received this communication by=
 mistake,
> > > >> please don't forward it to anyone else, please erase all copies an=
d
> > > >> attachments, and please let me know that it has gone to the wrong =
person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BzEjCsCHhaQ4nEC8VEbCyQt3aG0E78S6PoCgzJA5qkoGC10ZA%40mail.gmai=
l.com.
