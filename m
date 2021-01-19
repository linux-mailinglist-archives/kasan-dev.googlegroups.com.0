Return-Path: <kasan-dev+bncBCMIZB7QWENRBGWXTSAAMGQERRHLGFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 8701B2FBF8F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:57:31 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q13sf14702912pll.10
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:57:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611082650; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSwXuCIi8NXHzqrteonXZ+Yc2QtboxpDevTAEAgdn64WW73J3Nzd9PYisEfQ16wQW7
         aGaNepcra77osKHLrX3SAICzMRuu8axf4zq8na3VgxODftYshrhOeoCkoniyfavHK1i9
         DxVzP39tEoIhWFq6PMX+LrzNHB4HVdKdByh5IbB7T0ABrgD8rkpy2WiTP9TmlFtjCW2T
         WDA7k9V5k7saQU/A844vdtUXrZ0UQl5Picsmfumm11lMrXYwgD7WETJv4g+IrxwMoK9R
         JsRr96JAU8WrXl9T2Y3axJOZvtBfmiyoMwfTB9RseJwRW5B+BIVUGrjebJey6hM35imy
         wiHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zZQ45r+fB1d4Uf8GMAAhMvdXXnIMgMEcLCLEIhKIrPA=;
        b=Nigilduhd4oUjbQWsL7o1s1vpPSOgGLUKG/ez02ZQSFGNJrCP/7VhE6Z/PaV/fiIzF
         1+j/h589RZUHpMFTo4ji0IE1BzJHZag5fQuJUYnNkhkeCxT3pBKFBQ5WcuT/GtQnD/Rn
         nGCB9yWq/i++fU0+QZ6sV94o+GMtn/csjOpEIxWzmO3E/gx1r4uKwXeOcGDGad2jwnaz
         ZdWR/QocqUBcBNFAiYa0l/3WKn2hMNgprfvpoLow3leuURgMLiFU8PZ53peVtH6ZTOF4
         6kyzmtyqzFEftDXrpEik8AxpMNUruXTf28cu9rspQkB6YxDzQ/9YNiFX0O0Jdd4TrZam
         ex7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aJzkVnE7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zZQ45r+fB1d4Uf8GMAAhMvdXXnIMgMEcLCLEIhKIrPA=;
        b=qxt6CCrJYYgyAnB6jT4RT48mw70SH4dQKlZ1Sl2El4RQohVr0lgk6j+fkhMwKyivYJ
         /HaAKHVlowuw/ik1Ai1x3YupcR0DuHn6hKg6JfdtRKDcNmVRMV/eypBtU+ruqvyW1f5x
         Ykz6TmeSu+NyFDAzI5IAn5LN3xE/33NQPaml9/q4CaKV2QkcqeXf5ARFMNYOt8Ou6gU1
         sxFgNayq0iyddUCn9e19vWrjPteDSlFcYmv/EAg+LF1tETjtiM+KtuXx2HHSvaVrPsMo
         dJNAWhBUUfOI3mUwggDzpiiYDu+DOlUjx7ZTY5eANA5oPc0//G/4aZiUlhQ7gVwaHB8u
         gjpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zZQ45r+fB1d4Uf8GMAAhMvdXXnIMgMEcLCLEIhKIrPA=;
        b=IPNdfeO5qYzogeQOXPhpn6eRUwM8jCkmjcdOdOmU8t6psFb8eW3oz3B9/XPJ1493aX
         NUoIeQxAqFPKKVm/BvUTSQfL7EVdhrY+0tmvRPa92tUZgvumy7QDOOjEFiHCOjLxS1Kg
         NDuJ98heMUPHlB88bZKJVvktPEJtJk2GUFRD6nadlx6fas+nv6c5KeYNJhuLuFs35AuJ
         vROyBsmKncgaR2pe82AqK/m9e4sKV72iwuR1zjIZmnsnmh6F3a0271poMvqwjZDT2eNt
         B7kSR2Tg6MIBDCNS8IkKpV8x71WUyUcbEPaMR8Bxug95yJK/nYEYFJESZyrayoHIRphF
         5xKw==
X-Gm-Message-State: AOAM532weJxSmx2j2ibHnkWb+gitdICJQmHqHi6mUPXo4YOvu1mTV1jM
	vSKK8PuTfb0LliF5ixa+6F0=
X-Google-Smtp-Source: ABdhPJxidx5+TWYRNSvmIoNrHLDopmsy5k1Fb5K7HPZ3Zj16FlgZ8Z+49cQ2/th2YS1YYh1wC5jDDw==
X-Received: by 2002:a17:902:bb95:b029:dc:e7b:fd6e with SMTP id m21-20020a170902bb95b02900dc0e7bfd6emr6244198pls.12.1611082650291;
        Tue, 19 Jan 2021 10:57:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22d2:: with SMTP id y18ls10277170plg.6.gmail; Tue,
 19 Jan 2021 10:57:29 -0800 (PST)
X-Received: by 2002:a17:902:b097:b029:dc:5c:a986 with SMTP id p23-20020a170902b097b02900dc005ca986mr6021466plr.59.1611082649637;
        Tue, 19 Jan 2021 10:57:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611082649; cv=none;
        d=google.com; s=arc-20160816;
        b=qxSLJKRsrpInpvrUjs1SziID5XPv3fEvoFtvJFi5CuoyAvFa/eEizyOd8BWyUuQ2tg
         PfvUyNEWIQP/IIXcNd8aC15G4Bb1Zctke4DfxBmXKmQ6Qjcktp0tfJVyKrIBqcZIvS9k
         alBIZry7zUxCVMy48OYDc1R2whVbFYds+XfHLMB8hfzfQnRmAD4febGDcr4qX13ysKOJ
         O5gpiFbK7zddNy9DJjzXpSjvU9/2Xlr4GLWwrl/OdhX+ZVbW3rHnZsvw3iWw05nAqLMt
         H0R3RiJh4yrRT0rbOMK1KdKDEKk2rVDrhXfP94XiAqTC/umEybZ67XpLOM/ZPn4U3we4
         N3NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HKuO6KlRwjLvl5xc3pGLNHW5oMVADl8h0bk1TaQjuJ4=;
        b=MVFfR7jF9MQcJle1PCg6vYDHVI12fUOfqpDTc0KtWklF5FfHZnh3OEWp9F7t7xfuGb
         FHAGVpN6iv3qYaDNbK6gOG+Dh0EN1mvcG3I6STLe9EqTc59ZTyqqIWhe8AaToqcTKbdg
         Ne8c5ktY+GO8HfhcGwgT7OmMFt0fKOSPh7sHUgqUeJckQLQQdQcaFLFrKgH5Of6ef3oj
         o/hFdcQPIknA7X3PAboCQuv5bwnlaZ12ZykoHxE1y5m54MAu3Cj3FKWihO5E7IAGsESm
         QV2Ob1oNX+lRJG7a8haPko621w3eAaioPzxb0A1tIeyUkF3FPEuh5MwCzdns+nzbHLoD
         90TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aJzkVnE7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id i12si1486931plt.3.2021.01.19.10.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:57:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id v126so22873550qkd.11
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:57:29 -0800 (PST)
X-Received: by 2002:a05:620a:983:: with SMTP id x3mr5907866qkx.231.1611082648942;
 Tue, 19 Jan 2021 10:57:28 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk>
In-Reply-To: <20210119123659.GJ1551@shell.armlinux.org.uk>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:57:16 +0100
Message-ID: <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Arnd Bergmann <arnd@arndb.de>, Linus Walleij <linus.walleij@linaro.org>, 
	Krzysztof Kozlowski <krzk@kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aJzkVnE7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733
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

On Tue, Jan 19, 2021 at 1:37 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
>
> On Tue, Jan 19, 2021 at 01:05:11PM +0100, Dmitry Vyukov wrote:
> > Yes, I used the qemu -dtb flag.
> >
> > I tried to use CONFIG_ARM_APPENDED_DTB because it looks like a very
> > nice option. However, I couldn't make it work.
> > I enabled:
> > CONFIG_ARM_APPENDED_DTB=y
> > CONFIG_ARM_ATAG_DTB_COMPAT=y
> > # CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_FROM_BOOTLOADER is not set
> > CONFIG_ARM_ATAG_DTB_COMPAT_CMDLINE_EXTEND=y
> > and removed qemu -dtb flag and I see:
> >
> > Error: invalid dtb and unrecognized/unsupported machine ID
> >   r1=0x000008e0, r2=0x80000100
> >   r2[]=05 00 00 00 01 00 41 54 01 00 00 00 00 10 00 00
>
> Right, r2 now doesn't point at valid DT, but points to an ATAG list.
>
> The decompressor should notice that, and fix up the appended DTB.
>
> I assume you concatenated the zImage and the appropriate DTB and
> passed _that_ as the kernel to qemu?

Mkay, I didn't. I assumed kbuild will do this for me.

Appending dtb works, but not completely. I did:

cp arch/arm/boot/zImage arch/arm/boot/zImage.dtb
cat arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb >> arch/arm/boot/zImage.dtb

Now I have:
ls -l arch/arm/boot/zImage* arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb
-rw-r----- 1 dvyukov primarygroup    13209 Jan 14 13:41
arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb
-rwxr-x--- 1 dvyukov primarygroup 33712008 Jan 19 16:55 arch/arm/boot/zImage
-rwxr-x--- 1 dvyukov primarygroup 33725217 Jan 19 18:57 arch/arm/boot/zImage.dtb

Using "-kernel arch/arm/boot/zImage -dtb
arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb" fully works.
Using just "-kernel arch/arm/boot/zImage" does not work, not output
from qemu whatsoever (expected).
But using just "-kernel arch/arm/boot/zImage.dtb" gives an interesting
effect. Kernel starts booting, I see console output up to late init
stages, but then it can't find the root device.
So appended dtb works... but only in half. Is names of block devices
something that's controlled by dtb?

[   89.140285][    T1] VFS: Cannot open root device "vda" or
unknown-block(0,0): error -6
[   89.144547][    T1] Please append a correct "root=" boot option;
here are the available partitions:
[   89.146058][    T1] 0100            4096 ram0
[   89.146295][    T1]  (driver?)
[   89.147537][    T1] 0101            4096 ram1
[   89.147740][    T1]  (driver?)
[   89.148948][    T1] 0102            4096 ram2
[   89.149150][    T1]  (driver?)
[   89.150296][    T1] 0103            4096 ram3
[   89.150497][    T1]  (driver?)
[   89.152714][    T1] 0104            4096 ram4
[   89.152920][    T1]  (driver?)
[   89.154198][    T1] 0105            4096 ram5
[   89.154401][    T1]  (driver?)
[   89.155609][    T1] 0106            4096 ram6
[   89.155811][    T1]  (driver?)
[   89.157020][    T1] 0107            4096 ram7
[   89.157221][    T1]  (driver?)
[   89.158507][    T1] 0108            4096 ram8
[   89.158708][    T1]  (driver?)
[   89.159907][    T1] 0109            4096 ram9
[   89.160109][    T1]  (driver?)
[   89.163842][    T1] 010a            4096 ram10
[   89.164055][    T1]  (driver?)
[   89.165300][    T1] 010b            4096 ram11
[   89.165502][    T1]  (driver?)
[   89.166705][    T1] 010c            4096 ram12
[   89.166906][    T1]  (driver?)
[   89.168131][    T1] 010d            4096 ram13
[   89.168341][    T1]  (driver?)
[   89.169551][    T1] 010e            4096 ram14
[   89.169753][    T1]  (driver?)
[   89.170957][    T1] 010f            4096 ram15
[   89.172047][    T1]  (driver?)
[   89.175569][    T1] 1f00          131072 mtdblock0
[   89.175801][    T1]  (driver?)
[   89.177051][    T1] 1f01           32768 mtdblock1
[   89.177256][    T1]  (driver?)
[   89.178481][    T1] 1f02             128 mtdblock2
[   89.178685][    T1]  (driver?)


Just in case, that's v5.11-rc4 with this config:
https://gist.githubusercontent.com/dvyukov/aeb69235ff37a3d48c1a8a74c2fad162/raw/b37273ba14306d4ca2e2fffc07af41c759e092b7/gistfile1.txt
and this qemu command line:

qemu-system-arm      -machine vexpress-a15 -cpu max -smp 2 -m 2G
-device virtio-blk-device,drive=hd0     -drive
if=none,format=raw,id=hd0,file=image-arm -snapshot     -kernel
arch/arm/boot/zImage.dtb                -nographic      -netdev
user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
virtio-net-device,netdev=net0 -append "earlyprintk=serial oops=panic
panic_on_warn=1 nmi_watchdog=panic panic=86400 net.ifnames=0
sysctl.kernel.hung_task_all_cpu_backtrace=1 ima_policy=tcb
kvm-intel.nested=1 nf-conntrack-ftp.ports=20000
nf-conntrack-tftp.ports=20000 nf-conntrack-sip.ports=20000
nf-conntrack-irc.ports=20000 nf-conntrack-sane.ports=20000
vivid.n_devs=16 vivid.multiplanar=1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2
netrom.nr_ndevs=16 rose.rose_ndevs=16 spec_store_bypass_disable=prctl
numa=fake=2 nopcid dummy_hcd.num=8 binder.debug_mask=0
rcupdate.rcu_expedited=1 root=/dev/vda console=ttyAMA0 vmalloc=512M
watchdog_thresh=165 workqueue.watchdog_thresh=420"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYwiLTLcAVN7%2BJp%2BD9VXkdTgYNpXiHfJejTANPSOpA3%2BA%40mail.gmail.com.
