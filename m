Return-Path: <kasan-dev+bncBCMIZB7QWENRBMG5TKAAMGQEDUD57HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 746832FB51B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:04:34 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id u9sf1847305oon.23
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:04:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611050673; cv=pass;
        d=google.com; s=arc-20160816;
        b=IpR4WW2GcAwvmoRygLqASKl67viGoeAFhd4X65DPXauq//Q8Gt1P8CMCe2X4Agt/Bk
         u9t4rkIBo6sl5VOKDpxHMpm6VwgKeJm2sBh3WWgEzYfAydGk8ErVNnk7dAp9aEdYkpWu
         59Pjqlw9eMiKafu56ZCVASTOywFTd8DDnRSh1X124Gw+PXgoNJyp3/pyBbSk7T0F8Y5z
         P8QH1y1KUWng7dyhBAv0Y+Bi/Mj/j2TQOG4WzKzAt9EirNGZpB+8ZIG2Z+7BYbnh26vw
         w0ndkGNgzsZ8Kb41H6ni6GaUR37rTajNgc1B7B32bbk0Njg0KLAGuMuZ75wEDM/UU9PE
         3xTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SsNwYxxuBbj7aK8MYWASEGrpechQdFkMaUh0N4Tq5jQ=;
        b=YotgMyHEYLwOJ0ouEWZ1tJiXkjAKk5kt9pR2p2rmuJP/JCir0lf9SfED47xohhpgDQ
         SD+RYa4+7rgKbuGR+/EAicuEDR5AHRTXAsjq8rPAMUmYuCWdJI+MNR56n4WzDSDLCV4i
         qnyN0P7yxHdgTVYIIRG7p/QMbk98MxixQdC5tyyb2gk8FuLS/lu7k2DjYXf2hOOFIr2i
         QDTlhUchx5dkCzWmX1Q2VHZQf7nd5Ck2SW0OUuXw6GkMDa0lIgwBmiH3UOYsCdnDorsT
         /hHkmgxOh7BzjPXjJYh7twdute9wCRIMR/wvVICVNRAZzJgxhdvoIqfE3zc85ejlF68c
         +eRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xnak2wD8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SsNwYxxuBbj7aK8MYWASEGrpechQdFkMaUh0N4Tq5jQ=;
        b=Ab7Q35aN90R9RbctHyEfQ1dGdHt8xFz3g9xE5ZEEFxu76f+Uty5mpf6vFB/6nL/u2v
         i7QwZkEuWqUceFun1beE7XYHQNg1ThyUw1OEWFN/5LEB1v6/kIaReHeKmEYu2e0aA84h
         uXI5A+Q8EAOm8zIW4pitcXY40cWXEGvhzwSzlI6FeoObRbhiQEgabGNOLQvgvUp/vj3T
         r4AwjohiRnjnNLAedxXdCqnnAuftIngWkz2+anJXyYPSCS8Jatlzsk6hTPKrvQPOFaXV
         uvoF9FeDONg09L8jSdPXbxC7f3+LBUtXywEXiOJHG7XRT0jJ78aHou+6RXtTRveTLhhC
         DkkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SsNwYxxuBbj7aK8MYWASEGrpechQdFkMaUh0N4Tq5jQ=;
        b=lNqLplAlrMtaB8VdSGxP+iDz5UUexy2jGsSbRfCWvh8O5BYaHbn9YTPBVx4J6WbaCC
         8hyfxRDi1m0B2/R9B5vBX+5uJy3O3vNLVEIwSqhFHCgTweJag8eJFzc1PzzXeaXp26bO
         g1/BFMFJ3WcldDPe9aUs0mqOd2+btm3T/gB8i4NLoR2moP43Gs2xFw8ILadhHevvG24u
         AZmhHY0szIlc6Z8mz7wbOxMEthoBL+TXuUx+0yIvjzYWeMoHXbgGDMLf5Mtnzo/Hlo8y
         ryr7U6wD3C7fL56/q6IBP6612X8eqNCm4lrlisSh2UqaVJGcIotIhbA2vzsZd6RS4Cyu
         Hd4Q==
X-Gm-Message-State: AOAM533FEqYhe8jHItkSRkMWOlgZYd4GAbwiMjqRcedLCENn/EyAuwNh
	PW1/usc/JcWl9y9bbisKdcA=
X-Google-Smtp-Source: ABdhPJyfUcYwuLLQlQmrM5Po0HSnGFVrqhZhGuFXzdnG5RPNsBzJg6GQEmcLAmMJKryAy3Eok3hL8g==
X-Received: by 2002:a05:6830:1be4:: with SMTP id k4mr2769004otb.271.1611050672980;
        Tue, 19 Jan 2021 02:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1592:: with SMTP id i18ls1798752otr.10.gmail; Tue,
 19 Jan 2021 02:04:32 -0800 (PST)
X-Received: by 2002:a9d:1ec:: with SMTP id e99mr2146336ote.257.1611050672612;
        Tue, 19 Jan 2021 02:04:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611050672; cv=none;
        d=google.com; s=arc-20160816;
        b=ARm792oauDMXfp4CLUVfJVpHxS1US/EIIR5O26nqpgLHxVcO1g1kEHndrPO8DbPh38
         TJukZS6qijfx0tnXNV/QDgSTUP7w7a39DHgSvLSd9TUqjeslbfl+CFIbr3N/N6JevFrM
         eTi3+WM3j2RSqRmFCUhTgerdR+XUTAT+PFut+iF7MsagKTv4fVz1wO4WTuGqqcSkrbYm
         X4ITBzfG+hOJRbey6OmQ/IHaWSW8lCq0450eXvsfh5BYd04jAnqQZ8xNVqbRKCGLSJRt
         x+Y1ftpTX01byF+f0wIWTCa3Ge/nkALgl1GA/17tNiyIwSbQaLlbaWpSJAm7KNHMEfRx
         Cc5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=njmUJy6w/va45NJBs7QBuv4pecmiAEDbCKlqcpoRuMo=;
        b=rHZa0JDdsZmlzI2rbGntDzXNEdxnSArKhSWFlJyQmGZ9e9NmWPrsR/9j+XlYhUKGo6
         fHfvBz1G2tC/quBHL5TanuN1yiVnY1KwqEBseoH7LnDqTCTLtGFYLLm3wPrWn5q0H60i
         WdhKULgBN7CbUUQ2ol7nLYWGbA+uLYPnHsucZsXdIXFOlXma5q4FvQJXpNwlgPOCtDTO
         bJGDil4nH7Bvbxgw9rm9gjpC52kDwib9GKzYULJCEaaJQcmv0snya1Er09qhNSR8hrz9
         Rf4XlTHOJCzllhH1E0ts7DpuC0e9oAbFKFgZBuQF3kHeWE/XUtnVDgTcKJoIRNqjvevO
         MpnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xnak2wD8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id r8si2123351otp.4.2021.01.19.02.04.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:04:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d15so7821116qtw.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:04:32 -0800 (PST)
X-Received: by 2002:a05:622a:c9:: with SMTP id p9mr1703100qtw.337.1611050671877;
 Tue, 19 Jan 2021 02:04:31 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
In-Reply-To: <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 11:04:20 +0100
Message-ID: <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Krzysztof Kozlowski <krzk@kernel.org>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linus Walleij <linus.walleij@linaro.org>, liu.hailong6@zte.com.cn, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Xnak2wD8;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835
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

On Tue, Jan 19, 2021 at 9:37 AM Krzysztof Kozlowski <krzk@kernel.org> wrote:
>
> On Mon, 18 Jan 2021 at 17:31, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > Hello Arm maintainers,
> >
> > We are considering setting up an Arm 32-bit instance on syzbot for
> > continuous testing using qemu emulation and I have several questions
> > related to that.
> >
> > 1. Is there interest in this on your end?
>
> Sure, the more, the better.
>
> > What git tree/branch should
> > be used for testing (contains latest development and is regularly
> > updated with fixes)?
>
> Depends on your testing capabilities, whether you can deal with every
> sub-maintainer's tree. 0-day kernel robot tests everything possible
> and this allows each submaintanier to early receive feedback about his
> tree. It can be around 30 Git trees, though... If you want only few, I
> would start with:
>  - https://git.kernel.org/pub/scm/linux/kernel/git/soc/soc.git/
>  - linux-next
>  - and Russell's for-next
> (http://git.armlinux.org.uk/cgit/linux-arm.git/log/?h=for-next)

Hi Krzysztof,

We need to start with just 1 tree. What syzbot is doing is slightly
different from 0-day. 0-day is unit testing, while syzbot is fuzzing.
One caveat is that majority of bugs won't be arm-specific, hundreds of
bugs will be just generic kernel bugs, so the tested tree needs to be
regularly updated to pick up fixes for all these generic bugs.
Otherwise the instance will be just re-hitting these known and already
fixed bugs all the time without having time to discover any new
arm-specific bugs.
I see that for-next branch of
git://git.armlinux.org.uk/~rmk/linux-arm.git is last updated on Dec
21, so it does not even include v5.11-rc11 created on Dec 27, and we
are now on rc4.
We could use linux-next, but sometimes it's broken or pulls in bugs
that cause crashes all the time. So it's not ideal as well.
Maybe we should just use the upstream tree?



> > 2. I see KASAN has just become supported for Arm, which is very
> > useful, but I can't boot a kernel with KASAN enabled. I am using
> > v5.11-rc4 and this config without KASAN boots fine:
> > https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt
>
> Maybe try first with a kernel based on vexpress defconfig. Yours looks
> closer to multi_v7 which enables a lot of stuff also as modules and
> this by itself brought up few issues (mostly with order of probes).

The first config I provided above works fine, so there is no need to
reduce it. The problem is with KASAN.

syzbot also needs a number of debugging configs, a number of configs
that allow to run in qemu, sandboxing/isolation configs, etc. Plus it
enables configs for tested subsystems. All syzbot configs:
https://github.com/google/syzkaller/tree/master/dashboard/config/linux
are produced from the same fragments:
https://github.com/google/syzkaller/tree/master/dashboard/config/linux/bits
That's the plan for Arm as well, we don't want to do 100% custom
things for each new tree/configuration. That's not
scalable/maintainable.


> You could also try other QEMU machine (I don't know many of them, some
> time ago I was using exynos defconfig on smdkc210, but without KASAN).

vexpress-a15 seems to be the most widely used and more maintained. It
works without KASAN. Is there a reason to switch to something else?

> > using the following qemu command line:
> > qemu-system-arm \
> >   -machine vexpress-a15 -cpu max -smp 2 -m 2G \
> >   -device virtio-blk-device,drive=hd0 \
> >   -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
> >   -kernel arch/arm/boot/zImage \
> >   -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \
> >   -nographic \
> >   -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
> > virtio-net-device,netdev=net0 \
> >   -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
> > oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"
> >
> > However, when I enable KASAN and get this config:
> > https://gist.githubusercontent.com/dvyukov/a7e3edd35cc39a1b69b11530c7d2e7ac/raw/7cbda88085d3ccd11227224a1c9964ccb8484d4e/gistfile1.txt
> >
> > kernel does not boot, qemu only prints the following output and then silence:
> > pulseaudio: set_sink_input_volume() failed
> > pulseaudio: Reason: Invalid argument
> > pulseaudio: set_sink_input_mute() failed
> > pulseaudio: Reason: Invalid argument
> >
> > What am I doing wrong?
>
> No clue but I just tried KASAN on my ARMv7 Exynos5422 board (real
> hardware) and it works (although kernel log appeared with a bigger
> delay):
>
> [    0.000000] Booting Linux on physical CPU 0x100
> [    0.000000] Linux version
> 5.11.0-rc3-next-20210115-00001-g77140600eeec (kozik@kozik-lap)
> (arm-linux-gnueabi-gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld
> (GNU Binutils for Ubuntu) 2.34) #144 SMP PREEMPT Tue Jan 19 09:23:24
> CET 2021
> [    0.000000] CPU: ARMv7 Processor [410fc073] revision 3 (ARMv7), cr=10c5387d
> ...
> [    0.000000] kasan: Truncating shadow for memory block at
> 0x40000000-0xbea00000 to lowmem region at 0x70000000
> [    0.000000] kasan: Mapping kernel virtual memory block:
> c0000000-f0000000 at shadow: b7000000-bd000000
> [    0.000000] kasan: Mapping kernel virtual memory block:
> bf000000-c0000000 at shadow: b6e00000-b7000000
> [    0.000000] kasan: Kernel address sanitizer initialized
>
> Best regards,
> Krzysztof

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg%40mail.gmail.com.
