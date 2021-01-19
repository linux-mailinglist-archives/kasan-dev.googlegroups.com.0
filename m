Return-Path: <kasan-dev+bncBCMIZB7QWENRB3HZTKAAMGQERN6N6JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id AA8712FB58A
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:05:17 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id b2sf13680293pls.18
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 03:05:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611054316; cv=pass;
        d=google.com; s=arc-20160816;
        b=pDanaCR5vi7qN6tLDZP2AcnDPzp/cjkTMOQ0wSXUr1qxBc9Ds4W/wLYyhsprrmUw9A
         Zdtx40V7kTNXgHx4SflgU8yH6KxosEyJ63QhD5Ay3VaarQBptuqoY7Lste3WSytMCA4p
         076p85NpeztSmr3WRNo2CPmSjQN+DHTprdiByQuN2RVjh4BsSabt9Yrno1xpvpwdMU/E
         +tHfU07jd5edVyU9tTCUKJgMKuRw8MtlI/yimaqJIxgz2bPgu4qUraFoqrykxGWxngsQ
         IRyZs74raRHCwsI46iafSPozw8dtbdLgViP9lKsNEf6CGWYfLun0mxQh6yKA5eufvs5M
         ZgvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T49ML9utX4i9iEpHJq1A+XXJ2nstgEgrGNqaUxdurGQ=;
        b=TMx5lngTJunB6PbvfacwYxDRjtzs4QrUZb4u4bL/uJd1I/+uZKNIWyrJlIwuBmR+Up
         e2ep4N6V4iuWRrirjk2iiBxerRsnhYOuKW51AMuMLQYF1Earq0MOB8+BQxlNCha/dyxx
         CpeaQwJCt5f2xiLrFbZHor4m4XROxBlQ69FquuejltSZi0kr+luEdAHoYB+8K30gZf+H
         d5Cfqp8AQphPIGl87iQa8RTLLXsNmQwzoe6rdcWT9XUPldZU345now8SGAXlcwMAmol0
         glJztx3Q6ljYelUzOLr5/8/0b3LOnDCqRV2P1rdrGQJhHvex7s3EAyPzCvQrMGAMD92e
         JfiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jurnQJW9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T49ML9utX4i9iEpHJq1A+XXJ2nstgEgrGNqaUxdurGQ=;
        b=gGLc6npm3p2Fo092rKpv9HlBW1qRRj+BZtGODdmBs7RixeOsHoaVhqqJJ9oCWB0vlg
         cuiM+t3yUJXoRccIgBTrhoj61u13YA83lzQtUh7/SXZlzNjfo1Sxfp2tB2HLTEHBTK4T
         zZH7/HmxvvfjU8LwOKY3YbEWma6ybhGdpanzqAx1cQMaFLWUD8V+gAr7bRZ9oed675LT
         leHnnkUKn/42rckoGkgtMdosxfh/7ilKCIaxiSkBlghhRl/js3hHawpe5I+Py8CTz+pF
         +9RcN7AjqkG3qxc8lYC7DtRqEhDxE9/Jgq70fkWhNXdPr/HiRFBMEM/tOap/5OFW69Vb
         jDGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T49ML9utX4i9iEpHJq1A+XXJ2nstgEgrGNqaUxdurGQ=;
        b=r5e6gKImjHlecpTKE9u2YubjE1/SrMDO7OYRqKttDSKkUhufSx0co77bWYVKzdi+FK
         8g1U1t+bMf1W8bl6Inr6ywQdDbgfWLebspvNQvvdwfyrsNtsuMnirzOgfw/kECEAapeg
         zJ+NZ4VYyuz9QPxZhrFT3HD7xOGL6lsCiA3tb55WkELR6C55CDmH6l+uvDych4uu9SRV
         ybaVrJdypOcaF6eb1NQwqVJE+FSCfIw9bg8HcQhEbUUePaD/l5agJ9xJWipSxTIwKApc
         JApEckIiXrXbNCfU6GQBoh/CGMJnejGN8XfhuwncgOQxytx5u1G1Lpv49WS162T5Y6JA
         RHNA==
X-Gm-Message-State: AOAM532FN1cVZ58lvdODP/tIdlHz5TIkqf5GwlOJIgtvULB4meGbCi/4
	YMTgMXjI17ERFf1a7PA0a28=
X-Google-Smtp-Source: ABdhPJy+wQtcKTrMeOWi2MVSxXDJKJtGodcmy3u2pE1tw8jbkof5o1sTIXV9iWWykqZEvaR2FV2+lg==
X-Received: by 2002:a17:902:c94d:b029:de:9b70:d886 with SMTP id i13-20020a170902c94db02900de9b70d886mr4115428pla.5.1611054316444;
        Tue, 19 Jan 2021 03:05:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c1:: with SMTP id e1ls6719134plh.10.gmail; Tue, 19
 Jan 2021 03:05:14 -0800 (PST)
X-Received: by 2002:a17:90a:2947:: with SMTP id x7mr4770088pjf.157.1611054314439;
        Tue, 19 Jan 2021 03:05:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611054314; cv=none;
        d=google.com; s=arc-20160816;
        b=hOsvbyYH3JKB0adwb6w41H/MECvh+sj6HD3ea4HF34dqZeP/ycjfxUALy39/dS80CA
         70mCcSlR92wLCfX5xg5nhgAAyaxGcY6Mul/+bJQFPBtGkMR1Ykw9TK1ujRx9Vlp35edn
         7SFEuXJTsiIObrrLruRXq318sRGSlxU+GSCHYNaEje5q7yvKOs7UTkBuluw60wWARYcS
         1fsJ9iL3LSisv6bTNdgnEBCcitwZ9n31O2w6Fc1tzm0K5tMOl1wWwB98njzHxX3wNyNb
         27SPR2l+Jt46aP28SY0ax9Ddrh73rLpsOJtTqe37jx7JjMAcK/3Qbid73gbRHMrP3hzt
         REFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ILx4KO/OmBo4bRyCxJivePnbOqIM8dYLjVqyTMBrimo=;
        b=kZ3bfnjM093JSBLNoaW+7wClfUgQxJcS69sM+vr2nIMMbZ+m7QqQx8J688Sc0BwA9n
         /5PqzI5Vk5RrbFs4Hn6fGUKy9fW2/e+3CwcDve9TGAaY4zznHeaBfldxx7Ds/IIS8Lz+
         726zwwR11awE58F2NOf+FKmVakooc2s/VnWAJdvUja6xi89PoIAzxTeeVVLz1GMRAs1Z
         yUs49wBGOfhzewA2+CqMIxBglvCIsm6VDp65hSsPwhJw9dlIWfTXYK4/dd2ylmE2eyjL
         OPLLCr6RY2IRgRjzgZal8YgbjJn3BGdJjde40idphxiBwiHq9HMkt5wH0t43r9F9jY9a
         3xXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jurnQJW9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id j11si1657163pgm.4.2021.01.19.03.05.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 03:05:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id z6so6278946qtn.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 03:05:14 -0800 (PST)
X-Received: by 2002:ac8:4e1c:: with SMTP id c28mr3571093qtw.67.1611054313343;
 Tue, 19 Jan 2021 03:05:13 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com> <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
In-Reply-To: <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 12:05:01 +0100
Message-ID: <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Krzysztof Kozlowski <krzk@kernel.org>, Russell King - ARM Linux <linux@armlinux.org.uk>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jurnQJW9;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e
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

On Tue, Jan 19, 2021 at 11:53 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Jan 19, 2021 at 11:28 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> >
> > On Tue, Jan 19, 2021 at 11:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > On Tue, Jan 19, 2021 at 11:17 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> > > > > > You could also try other QEMU machine (I don't know many of them, some
> > > > > > time ago I was using exynos defconfig on smdkc210, but without KASAN).
> > > > >
> > > > > vexpress-a15 seems to be the most widely used and more maintained. It
> > > > > works without KASAN. Is there a reason to switch to something else?
> > > >
> > > > Vexpress A15 is as good as any.
> > > >
> > > > It can however be compiled in two different ways depending on whether
> > > > you use LPAE or not, and the defconfig does not use LPAE.
> > > > By setting CONFIG_ARM_LPAE you more or less activate a totally
> > > > different MMU on the same machine, and those are the two
> > > > MMUs used by ARM32 systems, so I would test these two.
> > > >
> > > > The other interesting Qemu target that is and was used a lot is
> > > > Versatile, versatile_defconfig. This is an older ARMv5 (ARM926EJ-S)
> > > > CPU core with less memory, but the MMU should be behaving the same
> > > > as vanilla Vexpress.
> > >
> > > That's interesting. If we have more than 1 instance in future we could
> > > vary different aspects between them to get more combined coverage.
> > > E.g. one could use ARM_LPAE=y while another ARM_LPAE=n.
> > >
> > > But let's start with 1 instance running first :)
> >
> > Hm I noticed that I was running in LPAE mode by default on Vexpress
> > so I try non-LPAE now. Let's see what happens...
>
> Good point. I've tried to enable CONFIG_ARM_LPAE=y in my config with
> KASAN, and it did not help. No output after 8 minutes.

But I also spied this in your makefile:

config-earlydebug: config-base
$(CURDIR)/scripts/config --file $(config_file) \
--enable DEBUG_LL \
--enable EARLY_PRINTK \
--enable DEBUG_VEXPRESS_UART0_RS1 \

With these configs, qemu prints something more useful:

pulseaudio: set_sink_input_volume() failed
pulseaudio: Reason: Invalid argument
pulseaudio: set_sink_input_mute() failed
pulseaudio: Reason: Invalid argument
Error: invalid dtb and unrecognized/unsupported machine ID
  r1=0x000008e0, r2=0x00000000
Available machine support:
ID (hex) NAME
ffffffff Generic DT based system
ffffffff Samsung Exynos (Flattened Device Tree)
ffffffff Hisilicon Hi3620 (Flattened Device Tree)
ffffffff ARM-Versatile Express
Please check your kernel config and/or bootloader.


What does this mean? And is this affected by KASAN?... I do specify
the ARM-Versatile Express machine...

Can it be too large kernel size which is not supported/properly
diagnosed by qemu/kernel?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYyw6zohheKtfPsmggKURhZopF%2BfVuB6dshJREsVz8ehQ%40mail.gmail.com.
