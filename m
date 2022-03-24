Return-Path: <kasan-dev+bncBCXKTJ63SAARBFWE6KIQMGQEBUXJCUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D1B944E674B
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 17:53:43 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id z16-20020a05660217d000b006461c7cbee3sf3434012iox.21
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Mar 2022 09:53:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648140822; cv=pass;
        d=google.com; s=arc-20160816;
        b=AR4DQfh9aWBoIpdgd2gJuDMCiSjy7MzxsVRyBg1KuKZ7wgnMyX/oFHm6KBKwrBoGa7
         +ArpFa4mv9YjZslRvXgprFLVCYZcKG4IsH7CLR7ViWqq3hI/EpS4vBHSdxVhbiytNCiD
         hAVUnx+5fTpNhhhhpppbggZaCdXb50roKP9VNgEkk7Re5xXGcc+Rvv372620VGrZFhWz
         UkvtvwMkdlGD6StmFoDgQaCKArMh5VYsDGgHdEFdQ4lGrai4y9tto9fP0pU966YoM6he
         Knn3aQszUW7c+TV25aIR6VMk51Z8MG00E1ucfOKEu6rmZWKXkrs8bEq9xoDD8ezlaRJI
         V1Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N3rEnko7tv/APk+npNRo963TGxRQoTicuHQW0/AMn6s=;
        b=NOPppBQkczjAvXr3qjgHuemHc0VmRoV0GMeRrjKjysIbFZxNPnQZnldyI9HOLq3uCR
         IJD9pnTue8bqmRsNAcgZNxt8zXb5wVCZ3GDHJ1D6g/qNvj8nJUQZ14MyyXWIgweSlMlb
         9xLOH7os+xhGHHmh0UHmD/2ogh73qiRFTs0j6UMcuYHElt1W6xo41I4s6hEPYC75jNta
         DfvhTIWe0oFI/QUpknMr5JSO1J6lqHHnIe3G5Sgx9M/rTdhxtz+nf8zKmiz1M64+nMI/
         f2dOxyW9ybM2T2bTCXdGXhZdPaJsN6sP0mEaPLBNZ8XPfVY+O8DsJCSEq/Y2FPB0p5nV
         pqyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gKiiT/5m";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=N3rEnko7tv/APk+npNRo963TGxRQoTicuHQW0/AMn6s=;
        b=ChEsWLPAVmm0JHb03SvRW87kHZF3GSWRhXX9FiTUg5Jkg6Df0mguM04YiSZPPrjRKs
         YyuTECVHSkRRb9s2ZH2plB841HFJobuz2gO1PyBnoNwXA2h8JhSYRd5qOqzTSYvd4OiZ
         twONhijS9HGRUBkoDT9DxAck4hzr2lnFtngNqFeXh1qrOBvCSuCJI+kGkvRD87iomLf1
         McZzkqGOwLVWgP6uP+pHX3SfIUL8xdNJCANK4GFsHdjw+G2uReWvyHVYwyUOwDVizBzv
         BX4Lsz0WA6K8F1iJw4kv42Z2SYKFf5XmE1D31tSh0K7R5aZSqEyiUzD8XD2fDqRfYUOo
         yBRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N3rEnko7tv/APk+npNRo963TGxRQoTicuHQW0/AMn6s=;
        b=UvamB+sdYSh/j4uMrl+O6SUpXGyGD5cSXlG0Lu6JWmk4XmHEhQFOR9khsgGGh6wzAn
         yqi90gHS6cprQ5sR2CLKtRWebVM5MVA9Fil8UoNcvbhgtOyO4MDfHe19jIPLNGQNYeVI
         PQa/S4ALhl6b91+AcWSTzlSXZcL5CDQDNKY5s1WgNRlqX8XTcmK5mEcHeBId2FfqUdc1
         1V8v3MYGi7VySa7cEW0BvuTC8JUP8d068hCNCPDUqDdUekPrhBqV/VDZjm+B7wDUcN4Z
         33UeuGUnx/0kSo+708cBEw4CfB1TSmgILyZsoPALrnekFnbQDN2FFXHXQZtOGD45RsGp
         vnXA==
X-Gm-Message-State: AOAM531OGi5YCXCZW1BNKJnF5bv5r1bsWj3sELd/1pSfBSFAysvbjD8Q
	pX57bi7i4mWq65G/pgT+5Qc=
X-Google-Smtp-Source: ABdhPJyXJr9oSaI69dkpSm3Psjr/vTosv3C8ublIivVIMvO4Mh/wwc7IfVReiJGVW0oGhrPRnIBnbQ==
X-Received: by 2002:a05:6638:3729:b0:31a:1376:5226 with SMTP id k41-20020a056638372900b0031a13765226mr3296606jav.279.1648140822651;
        Thu, 24 Mar 2022 09:53:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:270f:b0:322:f908:276 with SMTP id
 m15-20020a056638270f00b00322f9080276ls336962jav.3.gmail; Thu, 24 Mar 2022
 09:53:42 -0700 (PDT)
X-Received: by 2002:a05:6638:f8b:b0:321:4c9d:c274 with SMTP id h11-20020a0566380f8b00b003214c9dc274mr3335188jal.244.1648140822187;
        Thu, 24 Mar 2022 09:53:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648140822; cv=none;
        d=google.com; s=arc-20160816;
        b=uIddm9Lgs5i28ILULbSfJGdpofV1Gzd9i17cBedka5KfQuOWVz1bOp+x2NMFwaHXv/
         2EY7SOZiD3jPyq3zYCu3BhZJ4FloojqGqgn738wGeFTeNSgb4nkjqyb0iNSGnNGN/DdY
         S7TJx8uW7rJv4qbzGE/zRZdKIFmKERzKVRO24MijDZWIieSbewKODs4r5jxMWNDP5TVr
         CmwjJo6trzhipEuME8Qy1GGqSgwr/xSS2GrFE/pJ4uxH2NLL9mZhk9skeLWlDhwy5dYF
         NBIdlLw1nF8/uoy7doJ7vjOFfG7WPGuBUKJqBN9Ntbq0SPwRkXZGz1sPsqLurCXlcgx4
         p0lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YpLkW0tRBoZ4kAOuJruK4ALvjxQUbEEcnwwvWAs5ZKQ=;
        b=dBfQvc+6q4kbdRRqO8xkdYVKeLuf21lL6WF5dSIzjlCPP7ni31SBVKT4QjalQT3pW6
         t9+vmAXAfJLnIu3PHoLxVhECGC/zMS6sETrNO+l2m4LEjEru2G1XAD8vH6Oww9D7W2Fb
         xGJgThdVeVhCkb9RTx4ux4gnGVoR6KFTbv7ejBcwkpl6TuzdO6dw9NjB3PT0YbXEDZLN
         3mNX01S+xVvL1U57Gz29C+uZVS+M3S/eH904PE8cz8BQZxNhKFrWfoGFyH9DG9GxhwNj
         1fZNa3o9ZDyB3BAB1JF/fUTrEOv4XvZgzdIq5TVMu/oXaUX47c/GZk89duU9oyUIYQ2x
         UNhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gKiiT/5m";
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id x3-20020a023403000000b0031a548f05b8si283380jae.3.2022.03.24.09.53.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Mar 2022 09:53:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id i1so3587835ila.0
        for <kasan-dev@googlegroups.com>; Thu, 24 Mar 2022 09:53:42 -0700 (PDT)
X-Received: by 2002:a05:6e02:1be1:b0:2c7:a99f:c67f with SMTP id
 y1-20020a056e021be100b002c7a99fc67fmr3197474ilv.44.1648140821733; Thu, 24 Mar
 2022 09:53:41 -0700 (PDT)
MIME-Version: 1.0
References: <mhng-ffd5d5c5-9894-4dec-b332-5176d508bcf9@palmer-mbp2014>
 <mhng-ef0f4bac-b55e-471e-8e3d-8ea597081b74@palmer-ri-x1c9>
 <CANp29Y6MvZvx4Xjwx=bxZ86D7Kubg0JPwBzP6HH8A6+Zj7YeLQ@mail.gmail.com>
 <CACT4Y+ZA7CRNfYgPmi6jHTKD9rwvaJy=nh5Gz_c-PFHq3tuziQ@mail.gmail.com> <CA+zEjCsCHhaQ4nEC8VEbCyQt3aG0E78S6PoCgzJA5qkoGC10ZA@mail.gmail.com>
In-Reply-To: <CA+zEjCsCHhaQ4nEC8VEbCyQt3aG0E78S6PoCgzJA5qkoGC10ZA@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Mar 2022 17:53:30 +0100
Message-ID: <CANp29Y57fAHjy_Xm4_XvAMXvjvkPPipXsq-KD4ccEXwxHSRhHw@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Nick Hu <nickhu@andestech.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="gKiiT/5m";       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::131 as
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

https://pastebin.com/pN4rUjSi))))On Thu, Mar 10, 2022 at 9:42 AM
Alexandre Ghiti <alexandre.ghiti@canonical.com> wrote:
>
> Hi,
>
> On Wed, Mar 9, 2022 at 11:52 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, 9 Mar 2022 at 11:45, Aleksandr Nogikh <nogikh@google.com> wrote=
:
> > >
> > > I switched the riscv syzbot instance to KASAN_OUTLINE and now it is
> > > finally being fuzzed again!
> > >
> > > Thank you very much for the series!
> >
> >
> > But all riscv crashes are still classified as "corrupted" and thrown
> > away (not reported):
> > https://syzkaller.appspot.com/bug?id=3Dd5bc3e0c66d200d72216ab343a67c432=
7e4a3452
> >
> > The problem is that risvc oopses don't contain "Call Trace:" in the
> > beginning of stack traces, so it's hard to make sense out of them.
> > arch/riscv seems to print "Call Trace:" in a wrong function, not where
> > all other arches print it.
> >
>
> Does the following diff fix this issue?
>
> diff --git a/arch/riscv/kernel/stacktrace.c b/arch/riscv/kernel/stacktrac=
e.c
> index 201ee206fb57..348ca19ccbf8 100644
> --- a/arch/riscv/kernel/stacktrace.c
> +++ b/arch/riscv/kernel/stacktrace.c
> @@ -109,12 +109,12 @@ static bool print_trace_address(void *arg,
> unsigned long pc)
>  noinline void dump_backtrace(struct pt_regs *regs, struct task_struct *t=
ask,
>                     const char *loglvl)
>  {
> +       pr_cont("%sCall Trace:\n", loglvl);
>         walk_stackframe(task, regs, print_trace_address, (void *)loglvl);
>  }
>
>  void show_stack(struct task_struct *task, unsigned long *sp, const
> char *loglvl)
>  {
> -       pr_cont("%sCall Trace:\n", loglvl);
>         dump_backtrace(NULL, task, loglvl);
>  }
>
> Thanks,
>
> Alex

I wouldn't say that all riscv crashes are ending up in the "corrupted
report" bucket, but for some classes of errors there are definitely
differences from other architectures and they prevent syzkaller from
making sense out of those reports. At the moment everything seems to
be working fine at least with "WARNING:", "KASAN:" and "kernel
panic:".

I've run syzkaller with and without the small patch. From what I
observed, it definitely helps with the "BUG: soft lockup in" class of
reports. Previously they were declared corrupted, now syzkaller parses
them normally.

There's still a problem with "INFO: rcu_preempt detected stalls on
CPUs/tasks", which might be a bit more complicated than just the Call
Trace printing location.

Here's an example of such a report from x86: https://pastebin.com/KMEE5YRf
There goes a header with the  "rcu: INFO: rcu_preempt detected stalls
on CPUs/tasks:" title
(https://elixir.bootlin.com/linux/v5.17/source/kernel/rcu/tree_stall.h#L520=
),
then backtrace for one CPU
(https://elixir.bootlin.com/linux/v5.17/source/kernel/rcu/tree_stall.h#L331=
),
then there goes another error message about starving kthread
(https://elixir.bootlin.com/linux/v5.17/source/kernel/rcu/tree_stall.h#L442=
),
then there go two kthread-related traces.

And here's a report from riscv: https://pastebin.com/pN4rUjSi
There's de facto no backtrace between "rcu: INFO: rcu_preempt detected
stalls on CPUs/tasks:" and "rcu: RCU grace-period kthread stack
dump:".


>
> >
> >
> > > --
> > > Best Regards,
> > > Aleksandr
> > >
> > > On Fri, Mar 4, 2022 at 5:12 AM Palmer Dabbelt <palmer@dabbelt.com> wr=
ote:
> > > >
> > > > On Tue, 01 Mar 2022 09:39:54 PST (-0800), Palmer Dabbelt wrote:
> > > > > On Fri, 25 Feb 2022 07:00:23 PST (-0800), glider@google.com wrote=
:
> > > > >> On Fri, Feb 25, 2022 at 3:47 PM Alexandre Ghiti <
> > > > >> alexandre.ghiti@canonical.com> wrote:
> > > > >>
> > > > >>> On Fri, Feb 25, 2022 at 3:31 PM Alexander Potapenko <glider@goo=
gle.com>
> > > > >>> wrote:
> > > > >>> >
> > > > >>> >
> > > > >>> >
> > > > >>> > On Fri, Feb 25, 2022 at 3:15 PM Alexandre Ghiti <
> > > > >>> alexandre.ghiti@canonical.com> wrote:
> > > > >>> >>
> > > > >>> >> On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@=
google.com>
> > > > >>> wrote:
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> > On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <
> > > > >>> alexandre.ghiti@canonical.com> wrote:
> > > > >>> >> >>
> > > > >>> >> >> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google=
.com>
> > > > >>> wrote:
> > > > >>> >> >> >
> > > > >>> >> >> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
> > > > >>> >> >> > <alexandre.ghiti@canonical.com> wrote:
> > > > >>> >> >> > >
> > > > >>> >> >> > > As reported by Aleksandr, syzbot riscv is broken sinc=
e commit
> > > > >>> >> >> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). T=
his commit
> > > > >>> actually
> > > > >>> >> >> > > breaks KASAN_INLINE which is not fixed in this series=
, that will
> > > > >>> come later
> > > > >>> >> >> > > when found.
> > > > >>> >> >> > >
> > > > >>> >> >> > > Nevertheless, this series fixes small things that mad=
e the syzbot
> > > > >>> >> >> > > configuration + KASAN_OUTLINE fail to boot.
> > > > >>> >> >> > >
> > > > >>> >> >> > > Note that even though the config at [1] boots fine wi=
th this
> > > > >>> series, I
> > > > >>> >> >> > > was not able to boot the small config at [2] which fa=
ils because
> > > > >>> >> >> > > kasan_poison receives a really weird address 0x407570=
6301000000
> > > > >>> (maybe a
> > > > >>> >> >> > > kasan person could provide some hint about what happe=
ns below in
> > > > >>> >> >> > > do_ctors -> __asan_register_globals):
> > > > >>> >> >> >
> > > > >>> >> >> > asan_register_globals is responsible for poisoning redz=
ones around
> > > > >>> >> >> > globals. As hinted by 'do_ctors', it calls constructors=
, and in
> > > > >>> this
> > > > >>> >> >> > case a compiler-generated constructor that calls
> > > > >>> >> >> > __asan_register_globals with metadata generated by the =
compiler.
> > > > >>> That
> > > > >>> >> >> > metadata contains information about global variables. N=
ote, these
> > > > >>> >> >> > constructors are called on initial boot, but also every=
 time a
> > > > >>> kernel
> > > > >>> >> >> > module (that has globals) is loaded.
> > > > >>> >> >> >
> > > > >>> >> >> > It may also be a toolchain issue, but it's hard to say.=
 If you're
> > > > >>> >> >> > using GCC to test, try Clang (11 or later), and vice-ve=
rsa.
> > > > >>> >> >>
> > > > >>> >> >> I tried 3 different gcc toolchains already, but that did =
not fix the
> > > > >>> >> >> issue. The only thing that worked was setting asan-global=
s=3D0 in
> > > > >>> >> >> scripts/Makefile.kasan, but ok, that's not a fix.
> > > > >>> >> >> I tried to bisect this issue but our kasan implementation=
 has been
> > > > >>> >> >> broken quite a few times, so it failed.
> > > > >>> >> >>
> > > > >>> >> >> I keep digging!
> > > > >>> >> >>
> > > > >>> >> >
> > > > >>> >> > The problem does not reproduce for me with GCC 11.2.0: ker=
nels built
> > > > >>> with both [1] and [2] are bootable.
> > > > >>> >>
> > > > >>> >> Do you mean you reach userspace? Because my image boots too,=
 and fails
> > > > >>> >> at some point:
> > > > >>> >>
> > > > >>> >> [    0.000150] sched_clock: 64 bits at 10MHz, resolution 100=
ns, wraps
> > > > >>> >> every 4398046511100ns
> > > > >>> >> [    0.015847] Console: colour dummy device 80x25
> > > > >>> >> [    0.016899] printk: console [tty0] enabled
> > > > >>> >> [    0.020326] printk: bootconsole [ns16550a0] disabled
> > > > >>> >>
> > > > >>> >
> > > > >>> > In my case, QEMU successfully boots to the login prompt.
> > > > >>> > I am running QEMU 6.2.0 (Debian 1:6.2+dfsg-2) and an image Al=
eksandr
> > > > >>> shared with me (guess it was built according to this instructio=
n:
> > > > >>> https://github.com/google/syzkaller/blob/master/docs/linux/setu=
p_linux-host_qemu-vm_riscv64-kernel.md
> > > > >>> )
> > > > >>> >
> > > > >>>
> > > > >>> Nice thanks guys! I always use the latest opensbi and not the o=
ne that
> > > > >>> is embedded in qemu, which is the only difference between your =
command
> > > > >>> line (which works) and mine (which does not work). So the issue=
 is
> > > > >>> probably there, I really need to investigate that now.
> > > > >>>
> > > > >>> Great to hear that!
> > > > >>
> > > > >>
> > > > >>> That means I only need to fix KASAN_INLINE and we're good.
> > > > >>>
> > > > >>> I imagine Palmer can add your Tested-by on the series then?
> > > > >>>
> > > > >> Sure :)
> > > > >
> > > > > Do you mind actually posting that (i, the Tested-by tag)?  It's l=
ess
> > > > > likely to get lost that way.  I intend on taking this into fixes =
ASAP,
> > > > > my builds have blown up for some reason (I got bounced between ma=
chines,
> > > > > so I'm blaming that) so I need to fix that first.
> > > >
> > > > This is on fixes (with a "Tested-by: Alexander Potapenko
> > > > <glider@google.com>"), along with some trivial commit message fixes=
.
> > > >
> > > > Thanks!
> > > >
> > > > >
> > > > >>
> > > > >>>
> > > > >>> Thanks again!
> > > > >>>
> > > > >>> Alex
> > > > >>>
> > > > >>> >>
> > > > >>> >> It traps here.
> > > > >>> >>
> > > > >>> >> > FWIW here is how I run them:
> > > > >>> >> >
> > > > >>> >> > qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
> > > > >>> >> >   -device virtio-rng-pci -machine virt -device \
> > > > >>> >> >   virtio-net-pci,netdev=3Dnet0 -netdev \
> > > > >>> >> >   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:125=
29-:22 -device \
> > > > >>> >> >   virtio-blk-device,drive=3Dhd0 -drive \
> > > > >>> >> >   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapsho=
t \
> > > > >>> >> >   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append
> > > > >>> "root=3D/dev/vda
> > > > >>> >> >   console=3DttyS0 earlyprintk=3Dserial"
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> >>
> > > > >>> >> >> Thanks for the tips,
> > > > >>> >> >>
> > > > >>> >> >> Alex
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> > --
> > > > >>> >> > Alexander Potapenko
> > > > >>> >> > Software Engineer
> > > > >>> >> >
> > > > >>> >> > Google Germany GmbH
> > > > >>> >> > Erika-Mann-Stra=C3=9Fe, 33
> > > > >>> >> > 80636 M=C3=BCnchen
> > > > >>> >> >
> > > > >>> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > > > >>> >> > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >>> >> > Sitz der Gesellschaft: Hamburg
> > > > >>> >> >
> > > > >>> >> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschl=
icherweise
> > > > >>> erhalten haben sollten, leiten Sie diese bitte nicht an jemand =
anderes
> > > > >>> weiter, l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und=
 lassen Sie mich bitte
> > > > >>> wissen, dass die E-Mail an die falsche Person gesendet wurde.
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> >
> > > > >>> >> > This e-mail is confidential. If you received this communic=
ation by
> > > > >>> mistake, please don't forward it to anyone else, please erase a=
ll copies
> > > > >>> and attachments, and please let me know that it has gone to the=
 wrong
> > > > >>> person.
> > > > >>> >>
> > > > >>> >> --
> > > > >>> >> You received this message because you are subscribed to the =
Google
> > > > >>> Groups "kasan-dev" group.
> > > > >>> >> To unsubscribe from this group and stop receiving emails fro=
m it, send
> > > > >>> an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > >>> >> To view this discussion on the web visit
> > > > >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsQPVYSV7Cd=
hKnvjujXkMXuRQd%3DVPok1awb20xifYmidw%40mail.gmail.com
> > > > >>> .
> > > > >>> >
> > > > >>> >
> > > > >>> >
> > > > >>> > --
> > > > >>> > Alexander Potapenko
> > > > >>> > Software Engineer
> > > > >>> >
> > > > >>> > Google Germany GmbH
> > > > >>> > Erika-Mann-Stra=C3=9Fe, 33
> > > > >>> > 80636 M=C3=BCnchen
> > > > >>> >
> > > > >>> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > > > >>> > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >>> > Sitz der Gesellschaft: Hamburg
> > > > >>> >
> > > > >>> > Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlich=
erweise erhalten
> > > > >>> haben sollten, leiten Sie diese bitte nicht an jemand anderes w=
eiter,
> > > > >>> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen =
Sie mich bitte wissen,
> > > > >>> dass die E-Mail an die falsche Person gesendet wurde.
> > > > >>> >
> > > > >>> >
> > > > >>> >
> > > > >>> > This e-mail is confidential. If you received this communicati=
on by
> > > > >>> mistake, please don't forward it to anyone else, please erase a=
ll copies
> > > > >>> and attachments, and please let me know that it has gone to the=
 wrong
> > > > >>> person.
> > > > >>>
> > > > >>> --
> > > > >>> You received this message because you are subscribed to the Goo=
gle Groups
> > > > >>> "kasan-dev" group.
> > > > >>> To unsubscribe from this group and stop receiving emails from i=
t, send an
> > > > >>> email to kasan-dev+unsubscribe@googlegroups.com.
> > > > >>> To view this discussion on the web visit
> > > > >>> https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuJw8N0dUmQ=
NdFqDM96bzKqPDjRe4FUnOCbjhJtO0R8Hg%40mail.gmail.com
> > > > >>> .
> > > > >>>
> > > > >>
> > > > >>
> > > > >> --
> > > > >> Alexander Potapenko
> > > > >> Software Engineer
> > > > >>
> > > > >> Google Germany GmbH
> > > > >> Erika-Mann-Stra=C3=9Fe, 33
> > > > >> 80636 M=C3=BCnchen
> > > > >>
> > > > >> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> > > > >> Registergericht und -nummer: Hamburg, HRB 86891
> > > > >> Sitz der Gesellschaft: Hamburg
> > > > >>
> > > > >> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherw=
eise erhalten
> > > > >> haben sollten, leiten Sie diese bitte nicht an jemand anderes we=
iter,
> > > > >> l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen S=
ie mich bitte wissen,
> > > > >> dass die E-Mail an die falsche Person gesendet wurde.
> > > > >>
> > > > >>
> > > > >>
> > > > >> This e-mail is confidential. If you received this communication =
by mistake,
> > > > >> please don't forward it to anyone else, please erase all copies =
and
> > > > >> attachments, and please let me know that it has gone to the wron=
g person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y57fAHjy_Xm4_XvAMXvjvkPPipXsq-KD4ccEXwxHSRhHw%40mail.gmail.=
com.
