Return-Path: <kasan-dev+bncBCMIZB7QWENRBXX7TKAAMGQEVSD7O3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EF9B2FB59E
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:17:51 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id g9sf17874763qtv.12
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 03:17:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611055070; cv=pass;
        d=google.com; s=arc-20160816;
        b=JxaHVUfBaCw06eFdLqVfbUDfjZNzeWm2GiXHU8o75zmhBXjcQBeU1Y+FMHUceO0R0L
         /NIYKfWh3BtaNt/3nUBfw6PTuYrv38Ct32bFxwME1IIzBMHGVXMvPJmt/eklcVlYWuGB
         wM+UX89x5QMELAtYnOBb8CUziSTrftTjUC6Lfs/ic6Pcyxd5PLTxSOFlUDm5NCvcf9F0
         eIWtzGoodjumS6k+eOl9WxjikYZ1VH3YaMuqR63FgfwwD8FF9spB+Emy/fphpct7hOIw
         JqBjdkR7aJ7GR9iYWXYqkfAMfBV/LPeRdkpVX8h+forXnAXUcYOumsnnNno8mZAXRoyv
         oviw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ti7/5EGRBVyNzePYpdB/nxU3Rr0+LR3Sm5Vp77KFM4s=;
        b=jetoXpjvWQWzYt0lmUK+Il3q1ut6TVWxKvJZZksSrSK/ix3Xg2qWEL8i5MlwYRzvkD
         VnQGeobXQSxr/HE/IZIofyIKVyEvUV0HipfdVDknFPZJm07s6SE/nQHVwWHVCiqm01vP
         MYrIiE2YaTnJKMec3H2f5YN0+I7IvkP3sU9quf0uvih9gfApVqeczsCaQbZQrmsoOF4Q
         1ku7lwb+5lsbBY+udH7eLjnasUU9rrxfZcyYOeAV6dDKMf7AEXjAWvh3ojoJRp29R7ou
         ewX0zzmZ2IxwJHn605B31waFSvtt2dg7XLJ6CwDrrntduTnkM8AiNq6rkRG9XmZGQF0H
         f6Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eTPQb7/J";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ti7/5EGRBVyNzePYpdB/nxU3Rr0+LR3Sm5Vp77KFM4s=;
        b=YBDJ3sba+ZMtNFXbMshU0oL3+wL/TgSmaKrpOUGrx1AfwPFqJ859+sZUQmnAP4xKSJ
         lk32VpD7Ts3M3WMGSue9gP3zn7B6AU3xuezrx+RVVQCtiZUfaB76814H6zvtRyKyWIyv
         nCN0u1CbnJuWqu5tFZAUFQTfdC6FI5SR9BrzOHsEpQXR1tbFZ6aScgFDam7/rRKUQRJk
         yjZmie42aPl6dRdjAcPoqp4QLn/4KFdCyg4sTOtGOYT3H6DBZTVFwkShxvpaPLu8OUwr
         6Gf6E5v1whN0Jk18V5fpaDu+0KQSROeFyvjwI3/GBsTtd6m9H0tTlp6Okq/bWLNhZofs
         5d4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ti7/5EGRBVyNzePYpdB/nxU3Rr0+LR3Sm5Vp77KFM4s=;
        b=gAw9v9hvM8av+6eDJbiSC+cN1tVIfkbfzpUrbwii06RMCI17jImCStVjP2s1RgZHVt
         mzCFLXYcdRcMSdeOxjmW0O4Oig9IY2JG/iaWu0qLhRT2myTi62WuUnDnvYo8aA0E2KM1
         mNMKf+MCNmHJ4Vkd+dX7Kg/dH8AwxdhOWtsuW9oiYV2aZYxe/XXHyeqHCyJjGmhxiYtY
         wh1612hz48cBjU0FkdRbkP6BpeBX/WF6c1BrdH6Rg+gzRVIaR+/kZzlTpqoOHscj5Lqo
         xu5WRXgfEPsrlFNnxnnKMlT16g7IZZvmSHLO1bcorwJxPVD6/IeDO+uTtzAzjTvgOx4P
         YTmQ==
X-Gm-Message-State: AOAM531ytDTjYZD+5xnmg0FyNjJ9hKkIK+CBDZuaPsLBwPVcLkwUljFC
	6/8LitozIdpkg9iNUtrhsQk=
X-Google-Smtp-Source: ABdhPJzaiZbdMOxazb6ma2LZvGICxBsMEjCqa62D6mOCcpGM3IkeAZzeOfnMP0USaKawYsctL3Z4yQ==
X-Received: by 2002:a37:a085:: with SMTP id j127mr3662889qke.273.1611055070300;
        Tue, 19 Jan 2021 03:17:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:434d:: with SMTP id q13ls4573201qvs.8.gmail; Tue, 19 Jan
 2021 03:17:49 -0800 (PST)
X-Received: by 2002:ad4:496c:: with SMTP id p12mr3646848qvy.40.1611055069873;
        Tue, 19 Jan 2021 03:17:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611055069; cv=none;
        d=google.com; s=arc-20160816;
        b=q0QwK9DbBBS1Jttsi69ex2TnERG8ejlRw4y2miXPXggQqOsXCHlgnuRBl476Tde9c4
         T2Lgz6AVmFRzahS2SHS43WAfG75GbMgo3puqUD4zcGoRPRyGypzUQVjGdE5Gpr20SV/M
         1fsFw/AyMuJkAWJK6MBkS9URsABXi3ynPhXim0BVj+JoMKV7v6PEconBZTVi7isfT+eU
         /qcq8kcmNmu4a/HXBAk1etQiJb9bcL40EHVS0+aN6gFQmYaPIwY6C/3yQOlfvn+FSduN
         VeFqaJvA6/58+Y5DcW/hURGxb7srq3/Bjmn15wrY2ult8frvLdLeRTV/XQCRkGz5wvSu
         nOeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4w3C4Zt98HIitoffWsAMzSb43p1C5vNaT7n8ZctA8hM=;
        b=j/+ovIsykb1TPgAE5XPZabOquaGxesnNNe1O4UfgJB02saUAEMZMBC5JXc2ZBn10lY
         Apy29ZZCHPdt4VrHzfqLTKE1L9hdGLI66W2ChIUn8Tp86I1+E/OgV8WRay0W3cFqfNzF
         +Ka/Yz+MVZ9Mi61DDOjgPpn0Kss7OTwdcJaBxXyVZs3zYRauFgIyKlS6jOt64dTBmE12
         vXrPy4mfxWakVErBm5cIK0J9wtp3H93GubITmoOp/686bxAwFwvfNRwHTL6pG3hhar3n
         Hy7Jd8jwyblHEvquNVj1D9TSGzGGshl5WOp0H5BxiFrgyTjTTkXuJOOVnC1BXUEHjgfk
         4chQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eTPQb7/J";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id p55si2318820qtc.2.2021.01.19.03.17.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 03:17:49 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id w79so21395925qkb.5
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 03:17:49 -0800 (PST)
X-Received: by 2002:a05:620a:713:: with SMTP id 19mr3800342qkc.424.1611055069386;
 Tue, 19 Jan 2021 03:17:49 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com> <20210119111319.GH1551@shell.armlinux.org.uk>
In-Reply-To: <20210119111319.GH1551@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 12:17:37 +0100
Message-ID: <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Linus Walleij <linus.walleij@linaro.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="eTPQb7/J";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730
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

On Tue, Jan 19, 2021 at 12:13 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Tue, Jan 19, 2021 at 12:05:01PM +0100, Dmitry Vyukov wrote:
> > But I also spied this in your makefile:
> >
> > config-earlydebug: config-base
> > $(CURDIR)/scripts/config --file $(config_file) \
> > --enable DEBUG_LL \
> > --enable EARLY_PRINTK \
> > --enable DEBUG_VEXPRESS_UART0_RS1 \
> >
> > With these configs, qemu prints something more useful:
> >
> > pulseaudio: set_sink_input_volume() failed
> > pulseaudio: Reason: Invalid argument
> > pulseaudio: set_sink_input_mute() failed
> > pulseaudio: Reason: Invalid argument
> > Error: invalid dtb and unrecognized/unsupported machine ID
> >   r1=0x000008e0, r2=0x00000000
> > Available machine support:
> > ID (hex) NAME
> > ffffffff Generic DT based system
> > ffffffff Samsung Exynos (Flattened Device Tree)
> > ffffffff Hisilicon Hi3620 (Flattened Device Tree)
> > ffffffff ARM-Versatile Express
> > Please check your kernel config and/or bootloader.
> >
> >
> > What does this mean? And is this affected by KASAN?... I do specify
> > the ARM-Versatile Express machine...
> >
> > Can it be too large kernel size which is not supported/properly
> > diagnosed by qemu/kernel?
>
> It means that your kernel only supports DT platforms, but there was
> no DT passed to the kernel (r2 is the pointer to DT). Consequently
> the kernel has no idea what hardware it is running on.
>
> I don't use qemu very much, so I can't suggest anything.

I do pass DT and it boots fine w/o KASAN, so it seems to be poor
diagnostics of something else.

It seems to be due to kernel size. I enabled CONFIG_KASAN_OUTLINE=y
and CONFIG_CC_OPTIMIZE_FOR_SIZE=y and now it boots...

Almost...
Now I got the following, which will prevent it from booting with
panic_on_warn that syzbot uses.


------------[ cut here ]------------
WARNING: CPU: 0 PID: 0 at kernel/printk/printk.c:2790
register_console+0x2f4/0x3c4 kernel/printk/printk.c:2790
console 'earlycon0' already registered
Modules linked in:
CPU: 0 PID: 0 Comm: swapper Not tainted 5.11.0-rc4-next-20210119 #27
Hardware name: ARM-Versatile Express
Backtrace:
[<82e981d0>] (dump_backtrace) from [<82e98430>] (show_stack+0x18/0x1c
arch/arm/kernel/traps.c:252)
 r7:00000080 r6:600001d3 r5:00000000 r4:84efddc0
[<82e98418>] (show_stack) from [<82ead110>] (__dump_stack
lib/dump_stack.c:79 [inline])
[<82e98418>] (show_stack) from [<82ead110>] (dump_stack+0x9c/0xc4
lib/dump_stack.c:120)
[<82ead074>] (dump_stack) from [<8024c6bc>] (__warn+0x12c/0x174
kernel/panic.c:609)
 r7:8303c220 r6:802e5554 r5:84a03c20 r4:8303c7e0
[<8024c590>] (__warn) from [<82e99040>] (warn_slowpath_fmt+0xb8/0x114
kernel/panic.c:635)
 r10:8303c7e0 r9:00000009 r8:00000ae6 r7:802e5554 r6:8303c220 r5:84a03c20
 r4:6f940780
[<82e98f8c>] (warn_slowpath_fmt) from [<802e5554>]
(register_console+0x2f4/0x3c4 kernel/printk/printk.c:2790)
 r10:848f747e r9:848f7472 r8:830000c0 r7:84a70a20 r6:85d00dc0 r5:84a70a20
 r4:84a70a20
[<802e5260>] (register_console) from [<84808424>]
(setup_early_printk+0x24/0x34 arch/arm/kernel/early_printk.c:43)
 r10:848f747e r9:848f7472 r8:830000c0 r7:849203d8 r6:848f747e r5:848f7472
 r4:85d018e0
[<84808400>] (setup_early_printk) from [<848004e4>]
(do_early_param+0x90/0xdc init/main.c:735)
 r5:848f7472 r4:8491fc04
[<84800454>] (do_early_param) from [<8028079c>] (parse_one
kernel/params.c:153 [inline])
[<84800454>] (do_early_param) from [<8028079c>]
(parse_args+0x37c/0x460 kernel/params.c:188)
 r9:848f7472 r8:83000a00 r7:00000000 r6:848f7485 r5:848f7000 r4:84a03de0
[<80280420>] (parse_args) from [<84800ddc>]
(parse_early_options+0x38/0x48 init/main.c:745)
 r10:856ed8c0 r9:80008000 r8:000002de r7:00000000 r6:848f7404 r5:848f7000
 r4:000002de
[<84800da4>] (parse_early_options) from [<84800e64>]
(parse_early_param+0x78/0x94 init/main.c:760)
[<84800dec>] (parse_early_param) from [<848057c8>]
(setup_arch+0x250/0xc5c arch/arm/kernel/setup.c:1129)
 r7:848f7a80 r6:84a6a200 r5:848f20f8 r4:84a03f80
[<84805578>] (setup_arch) from [<84800ff0>] (start_kernel+0x7c/0x3e4
init/main.c:873)
 r10:30c5387d r9:412fc0f1 r8:88000000 r7:000008e0 r6:ffffffff r5:84a50c40
 r4:856ed000
[<84800f74>] (start_kernel) from [<00000000>] (0x0)
 r6:30c0387d r5:00000000 r4:84800334
irq event stamp: 0
hardirqs last  enabled at (0): [<00000000>] 0x0
hardirqs last disabled at (0): [<00000000>] 0x0
softirqs last  enabled at (0): [<00000000>] 0x0
softirqs last disabled at (0): [<00000000>] 0x0
random: get_random_bytes called from init_oops_id kernel/panic.c:546
[inline] with crng_init=0
random: get_random_bytes called from init_oops_id+0x2c/0x4c
kernel/panic.c:543 with crng_init=0
---[ end trace 0000000000000000 ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb64a75ceu0vbT1Cyb%2B6trccwE%2BCD%2BrJkYYDi8teffdVw%40mail.gmail.com.
