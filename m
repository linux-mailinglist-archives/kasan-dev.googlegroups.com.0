Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBJFDZWAAMGQE2PLOBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C7C0308237
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 01:07:01 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id r5sf4022786wrx.18
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 16:07:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611878821; cv=pass;
        d=google.com; s=arc-20160816;
        b=SZQHfW28JhfupGRjq0YJX6W7WFezEV7iN8k+CLAzp8U96LQeusFzclSNINOPe273QJ
         hE8PPv1bdt1PFMzm7V2iSUoGb2ihihn8GAeEt90hSmUrRk77u1l5Cvw+SYEg11UiiPtl
         r7HcPW6qyswUT3FuVLsPUgFhOfcTgJule32Mgs+Icry2r+4ElDVWseeFyjFBXCvrNqoI
         fZid7maDwJKEIncpid9uLMzOSDo5L2PnwB/wKujxOn5uttKJPZL5vXRnep3s7AiqNlOt
         HQaM5whRMeXSaQf5atrvyLHXvLu3HDBnFXr9dJPizAYvIrbDR7Wl4lQBbYV9m7NrG8QS
         A5IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=gGNxmwrzt0WkRrlm0JNSKZuwknaw3iUDMcISHR90dXc=;
        b=M5TSN7WegSLVuT6/Nz9BaUHEjIOoA8AS8Ztcjlz9a28La3OIKYoH8GGGefJ7RgqQ19
         LY8+OMj6a88ZZzlaieGFULfVjxuHQoB74oRIqcoohEoAqfSgKrJq3DMBWsO3oZlNM5Az
         VSsc/cKtGgtVoQ64Ad5ocpOuH5I2sXeIMv2erVhzKQSYMeyU0kmscMZkTtwpxyz+JUdI
         AYkrSLSWNYDZ9KmxWwNT2gxatS4jFFFdHm+72K6S6PIcQR9WQDaeYt6gn3oIRpBR5Fu0
         F/GSQ9vwKj949VxMGtICeWTEUijrTZegvELtOBDxAepfl+uGWKP5ypYk1lS7UCi/dPF6
         OLng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RdNA0Xt8;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gGNxmwrzt0WkRrlm0JNSKZuwknaw3iUDMcISHR90dXc=;
        b=YLI8AaYaGIujN7cyr7Paf5tlgOKQ6TL0LuAPD8C34rPwIHxsTO0Wl51VMY6w27758Z
         S8AdnvQsKVF2MarvQQaCnECXISMTRFuZc1xBgpimWyYY2of7pLD4oI6bwLFHTNNsoYSY
         I6yuKWp/rNK1/WvGFgFVYJn9lhowaEheu26LPGfAoXzeMpC3KSWTze69nkzdcwfMlrM5
         6mQEEMTjL3LGfQ/KIpDk5ZxfFQX9oP9VOdApConCJ6BNVlRSgZNlvvfWwRnf3M96izXO
         bVi9Co+7h0cyl4qabXCVJMx6jUB6lh+hao2cFb/2cETCPy1PJaOYKOOD5YilTD/lAVGw
         hZog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gGNxmwrzt0WkRrlm0JNSKZuwknaw3iUDMcISHR90dXc=;
        b=kUoSwTmppMkI4DRINPA2CGsPSbPsPVNdNWkivhaXv+p3IHMRUxAd7yBjeaHGiSUNkB
         sle4e9x0InSM6z1ROyoAG8nSUnT+2G5lElby3FOpcyIWZEFGBgx+f68pPwJoQigZk2cy
         yH+K0WI0jHaeT4CzEuf9z1JnZ/tY1JNpEiPVaUAa8nWH2Wmm9dd+0fzP26QiqXJtGOSe
         7sxC/rLuI1RmbphZIt0RsQjK2CJ2wgXFWPnoDDzHo+wLwy+ARxNiC1K59d01T0VWeBXP
         CUUgwftGAOk/F8XjYfbZteF9TmRNM1Fz0ZYjAgm34MGa8SmQ86fAOaHPULimXrNddaVB
         OcBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gGNxmwrzt0WkRrlm0JNSKZuwknaw3iUDMcISHR90dXc=;
        b=nCUSlrbR0ruIweDLs6sew5glFe7Apk5YK0rCmA4rBhXOF+rzZgFhWrcpXFmMOZbaI1
         fv1nLj3cdwQXJVYh0X3X6e8x3v2KFWGBOB2JDqYM+YymLMi3q2N83ynRAUgWiFDfjQqy
         zIWoT/qfiVEltu34aH17icWx+47AR3ttVNqRFX93xasn1ZusiEgF5qzGRkW3MawJdpLE
         q/V6Rguimm3PCjyd2sbWvAXlfw1SLfoJuv4G8OWJdEBaRa7MfMk15ZHDfT7YUgqywTXF
         qVrYxA+x9YLOCHJz5GbGdAASeS16ZNGxpf7cBtzeAKlSlwLROzAiLU9EpRhvCljnYmJS
         8VFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ABfWOEygfDkna2kssRcG1t4xRSurcktECCgwPTlyKAifHijZN
	5zXsHkMvTOaIFVTPgDjHkI8=
X-Google-Smtp-Source: ABdhPJws2hwOzHBzGEu+zjmLXKTA5n3yKzxJhSeWgEi8pfczNDb5DqwxVhT/BMRY7/lPSJseQcAS7w==
X-Received: by 2002:a1c:dc41:: with SMTP id t62mr1390257wmg.106.1611878821019;
        Thu, 28 Jan 2021 16:07:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4482:: with SMTP id r124ls3400662wma.1.canary-gmail;
 Thu, 28 Jan 2021 16:07:00 -0800 (PST)
X-Received: by 2002:a1c:26c1:: with SMTP id m184mr1381327wmm.49.1611878820097;
        Thu, 28 Jan 2021 16:07:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611878820; cv=none;
        d=google.com; s=arc-20160816;
        b=s1TK61d1MD8zhQlKqMudammlv5XROtFSaM/KFZZNVFNb5hQcks84BAxVHhk/LhIwVy
         dH+CD6xELBrMTkZGbz1zZMSUe7GROz1eeX2Fb3eACDLtrrw5/GXs0+yPxrXbsYaW8YcI
         P94jL43BaQfgiCUIq2WD0TyQywij+UKVJ8kQn6bGGfs3Q0KSTjrGdqYvajxxy0z5uGh8
         UyV4nWDkCXjGH+9Ens+Z5B8xc1VYbjl/dty8uykK9/M0hT6gWv6nK8Vb3OMBQSqviwzA
         WyGx3xleMOHRXJyFnEru4t+Vkq9UXdYcFvc7yr9zCzhfr8jr6wSkdYMzCS7EvoUUzDeS
         Ds1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IeV9U2vYxYh/os91L3phBprfuNxTtaZ1a/v5dWaGLzw=;
        b=vN1B7TSc82Yiugy0TLnG34+WUXI9/XPz781YPh5e+NofuHIlrY9CIp4mZxY+QRKIJN
         jgnko9+R+RGnAo8GxTzELzX0LqLlOxBAEHX/FPiPaj0vly+WwD8Ch0d+2EYCuFnRcgOV
         /2+HjG6RDhjaDb4+fgY5tz+gfHZxinDtx/O+gObgoedr3f2OIoLN+8uEnsDiU0DaJAfY
         nPk5Xp4domiPBlJE1G3DTSDGmfdk0ucN6s9iZxqIsD2EEPuWPIiHbkAWW66taMTH/D38
         Ba5IX801WYwm1Mb/ZuNnPlUHBqwu6T15fVWPcOFCTRKcI7sDSP7HqmSw/KkNyshpGpLj
         V37A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RdNA0Xt8;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id u24si332142wmm.1.2021.01.28.16.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Jan 2021 16:07:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id rv9so10376512ejb.13
        for <kasan-dev@googlegroups.com>; Thu, 28 Jan 2021 16:07:00 -0800 (PST)
X-Received: by 2002:a17:906:4a13:: with SMTP id w19mr1957737eju.33.1611878819702;
 Thu, 28 Jan 2021 16:06:59 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com> <20210128232821.GW2743@paulmck-ThinkPad-P72>
In-Reply-To: <20210128232821.GW2743@paulmck-ThinkPad-P72>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Thu, 28 Jan 2021 19:06:49 -0500
Message-ID: <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
Subject: Re: KCSAN how to use
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="0000000000007829d405b9fec895"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=RdNA0Xt8;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::630
 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000007829d405b9fec895
Content-Type: text/plain; charset="UTF-8"

Thank you for your reply, Paul.

Sorry I did not state my question clearly, my question is now I want to get
the call stack myself, not from syzkaller report. For example I write the
code in linux kernel some point, dump_stack(), then I can get the call
stack when execution, and later I can translate the symbol to get the
file:line.

But the point is dump_stack() function in Linux Kernel does not contain the
inline function calls as shown below, if I want to implement display call
stack myself, do you have any idea? I think I can modify dump_stack(), but
seems I cannot figure out where the address of inline function is,
according to the source code of dump_stack() in Linux Kernel, it only
displays the address of the function call within 'kernel_text_address', or
maybe the inline function calls have  not even been recorded. Or maybe I am
not on the right track.
I also try to compile with -fno-inline, but the kernel cannot be compiled
successfully in this way.

Syzkaller report:

dont_mount include/linux/dcache.h:355 [*inline*]

 vfs_unlink+0x269/0x3b0 fs/namei.c:3837

 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899

 __do_sys_unlink fs/namei.c:3945 [*inline*]

 __se_sys_unlink fs/namei.c:3943 [*inline*]

 __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943

 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46

 entry_SYSCALL_64_after_hwframe+0x44/0xa9

dump_stack result, the* inline function* calls are missing.

vfs_unlink+0x269/0x3b0 fs/namei.c:3837

 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899

  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943

 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46

 entry_SYSCALL_64_after_hwframe+0x44/0xa9


Thank You
Best
Jin Huang


On Thu, Jan 28, 2021 at 6:28 PM Paul E. McKenney <paulmck@kernel.org> wrote:

> On Thu, Jan 28, 2021 at 05:43:00PM -0500, Jin Huang wrote:
> > Hi, Dmitry
> > Thank you for your help.
> >
> > I also want to ask an interesting question about the call stack
> > information, how did you get the inline function call information in the
> > call stack like this:
> >
> > vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> >
> >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> >
> >  __do_sys_unlink fs/namei.c:3945 [inline]
> >
> >  __se_sys_unlink fs/namei.c:3943 [inline]
> >
> >  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> >
> >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> >
> >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> >
> > I use dump_stack(), but can only get this kind of info:
> >
> > vfs_unlink+0x269/0x3b0
> >
> > do_unlinkat+0x28a/0x4d0
> >
> > __x64_sys_unlink+0x2c/0x30
> >
> > do_syscall_64+0x39/0x80
> >
> > entry_SYSCALL_64_after_hwframe+0x44/0xa9
> >
> > Obviously, inline function info misses. When I look at the Linux Kernel
> > source code, the implementation of dump_stack(), seems because the inline
> > function is not within the range of kernel_text_address().
> > Do you have any idea?
>
> If you build your kernel with CONFIG_DEBUG_INFO=y, any number of tools
> will be able to translate those addresses to filenames and line numbers.
> For but one example, given the vmlinux, you could give the following
> command to "gdb vmlinux":
>
>         l *vfs_unlink+0x269
>
>                                                         Thanx, Paul
>
> > Thank You
> > Best
> > Jin Huang
> >
> >
> > On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov <dvyukov@google.com>
> wrote:
> >
> > > On Wed, Jan 27, 2021 at 5:57 AM Jin Huang <andy.jinhuang@gmail.com>
> wrote:
> > > >
> > > > Hi, Macro
> > > > Could you provide some instructions about how to use syz-symbolize to
> > > locate the kernel source code?
> > > > I did not find any document about it.
> > >
> > > Hi Jin,
> > >
> > > If you build kernel in-tree, then you can just run:
> > > $ syz-symbolize file-with-kernel-crash
> > > from the kernel dir.
> > >
> > > Otherwise add -kernel_src flag and/or -kernel_obj flag:
> > >
> > >
> https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go#L24
> > >
> > >
> > >
> > > > Thank You
> > > > Best
> > > > Jin Huang
> > > >
> > > >
> > > > On Mon, Jan 11, 2021 at 2:09 AM Marco Elver <elver@google.com>
> wrote:
> > > >>
> > > >> On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com>
> > > wrote:
> > > >>>
> > > >>> Really thank you for your help, Dmitry.
> > > >>> I tried and saw the KCSAN info.
> > > >>>
> > > >>> But now it seems weird, the KCSAN reports differently every time I
> run
> > > the kernel, and the /sys/kernel/debug/kcsan seems does not match with
> the
> > > KCSAN report. What is wrong?
> > > >>
> > > >>
> > > >> /sys/kernel/debug/kcsan shows the total data races found, but that
> may
> > > differ from those reported to console, because there is an extra
> filtering
> > > step (e.g. KCSAN won't report the same data race more than once 3 sec).
> > > >>
> > > >>>
> > > >>> And I also want to ask, besides gdb, how to use other ways to
> locate
> > > the kernel source code, like decode_stacktrace.sh and syz-symbolize,
> talked
> > > about here https://lwn.net/Articles/816850/. Is gdb the best way?
> > > >>
> > > >>
> > > >> I use syz-symbolize 99% of the time.
> > > >>
> > > >>>
> > > >>> Also, does KCSAN recognizes all the synchronizations in the Linux
> > > Kernel? Is there false positives or false negatives?
> > > >>
> > > >>
> > > >> Data races in the Linux kernel is an ongoing story, however, there
> are
> > > no false positives (but KCSAN can miss data races).
> > > >>
> > > >> Regarding the data races you're observing: there are numerous known
> > > data races in the kernel that are expected when you currently run
> KCSAN. To
> > > understand the severity of different reports, let's define the
> following 3
> > > concurrency bug classes:
> > > >>
> > > >> A. Data race, where failure due to current compilers is unlikely
> > > (supposedly "benign"); merely marking the accesses appropriately is
> > > sufficient. Finding a crash for these will require a miscompilation,
> but
> > > otherwise look "benign" at the C-language level.
> > > >>
> > > >> B. Race-condition bugs where the bug manifests as a data race, too
> --
> > > simply marking things doesn't fix the problem. These are the types of
> bugs
> > > where a data race would point out a more severe issue.
> > > >>
> > > >> C. Race-condition bugs where the bug never manifests as a data
> race. An
> > > example of these might be 2 threads that acquire the necessary locks,
> yet
> > > some interleaving of them still results in a bug (e.g. because the
> logic
> > > inside the critical sections is buggy). These are harder to detect with
> > > KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or
> > > ASSERT_EXCLUSIVE_WRITER() in the right place. See
> > > https://lwn.net/Articles/816854/.
> > > >>
> > > >> One problem currently is that the kernel has quite a lot type-(A)
> > > reports if we run KCSAN, which makes it harder to identify bugs of
> type (B)
> > > and (C). My wish for the future is that we can get to a place, where
> the
> > > kernel has almost no unintentional (A) issues, so that we primarily
> find
> > > (B) and (C) bugs.
> > > >>
> > > >> Hope this helps.
> > > >>
> > > >> Thanks,
> > > >> -- Marco
> > >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnapTjGjYJXojTXa%3DNpz81sCZBtiaTci7K3Qq5gd7Myi-ow%40mail.gmail.com.

--0000000000007829d405b9fec895
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank you for your reply, Paul.<div><br><div>Sorry I did n=
ot state my question clearly, my question is now I want to get the call sta=
ck myself,=C2=A0not from syzkaller report. For example=C2=A0I write the cod=
e in linux kernel some point, dump_stack(), then I can get the call stack w=
hen execution, and later I can translate the symbol to get the file:line.</=
div><div><br></div><div>But the point is dump_stack() function in Linux Ker=
nel does not contain the inline function calls as shown below, if I want to=
 implement display=C2=A0call stack myself, do you have any idea? I think I =
can modify dump_stack(), but seems I cannot figure out=C2=A0where the addre=
ss of inline=C2=A0function is, according to the source code of dump_stack()=
 in Linux Kernel, it only displays=C2=A0the address of the function call wi=
thin &#39;kernel_text_address&#39;, or maybe the inline function calls have=
=C2=A0 not even been recorded. Or maybe I am not on the right track.</div><=
div>I also try to compile=C2=A0with -fno-inline, but the kernel cannot be c=
ompiled successfully in this way.</div><div><br></div><div>Syzkaller report=
:</div><div><span id=3D"m_-465421789212237850gmail-docs-internal-guid-bfe5e=
757-7fff-5c57-3498-3c687b71635b"><p dir=3D"ltr" style=3D"line-height:1.38;m=
argin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:=
Arial;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;vertical-align:baseline;white-space:pre=
-wrap">dont_mount include/linux/dcache.h:355 [<b>inline</b>]</span></p><p d=
ir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><spa=
n style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;v=
ertical-align:baseline;white-space:pre-wrap">=C2=A0vfs_unlink+0x269/0x3b0 f=
s/namei.c:3837</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-to=
p:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;co=
lor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=
=C2=A0do_unlinkat+0x28a/0x4d0 fs/namei.c:3899</span></p><p dir=3D"ltr" styl=
e=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:b=
aseline;white-space:pre-wrap">=C2=A0__do_sys_unlink fs/namei.c:3945 [<b>inl=
ine</b>]</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;=
margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rg=
b(0,0,0);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0_=
_se_sys_unlink fs/namei.c:3943 [<b>inline</b>]</span></p><p dir=3D"ltr" sty=
le=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"fon=
t-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent=
;font-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:=
baseline;white-space:pre-wrap">=C2=A0__x64_sys_unlink+0x2c/0x30 fs/namei.c:=
3943</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;marg=
in-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0do_sy=
scall_64+0x39/0x80 arch/x86/entry/common.c:46</span></p><p dir=3D"ltr" styl=
e=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:b=
aseline;white-space:pre-wrap">=C2=A0entry_SYSCALL_64_after_hwframe+0x44/0xa=
9</span></p></span><br></div><div>dump_stack result, the<b> <font size=3D"4=
">inline function</font></b> calls are missing.</div><div><span id=3D"m_-46=
5421789212237850gmail-docs-internal-guid-43ee84df-7fff-aae8-af14-ddd1a6d60c=
9f"><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0=
pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);backgr=
ound-color:transparent;font-variant-numeric:normal;font-variant-east-asian:=
normal;vertical-align:baseline;white-space:pre-wrap">vfs_unlink+0x269/0x3b0=
 fs/namei.c:3837</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-=
top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;=
color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap"=
>=C2=A0do_unlinkat+0x28a/0x4d0 fs/namei.c:3899</span></p><p dir=3D"ltr" sty=
le=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"fon=
t-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent=
;font-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:=
baseline;white-space:pre-wrap">=C2=A0=C2=A0__x64_sys_unlink+0x2c/0x30 fs/na=
mei.c:3943</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0p=
t;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:=
rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=
=A0do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46</span></p><p dir=3D"l=
tr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=
=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;vertical=
-align:baseline;white-space:pre-wrap">=C2=A0entry_SYSCALL_64_after_hwframe+=
0x44/0xa9</span></p></span></div><div><br></div><div><div><div dir=3D"ltr" =
data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div><br></div><div>Tha=
nk You</div>Best<div>Jin Huang</div></div></div></div><br></div></div></div=
><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Th=
u, Jan 28, 2021 at 6:28 PM Paul E. McKenney &lt;<a href=3D"mailto:paulmck@k=
ernel.org" target=3D"_blank">paulmck@kernel.org</a>&gt; wrote:<br></div><bl=
ockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-lef=
t:1px solid rgb(204,204,204);padding-left:1ex">On Thu, Jan 28, 2021 at 05:4=
3:00PM -0500, Jin Huang wrote:<br>
&gt; Hi, Dmitry<br>
&gt; Thank you for your help.<br>
&gt; <br>
&gt; I also want to ask an interesting question about the call stack<br>
&gt; information, how did you get the inline function call information in t=
he<br>
&gt; call stack like this:<br>
&gt; <br>
&gt; vfs_unlink+0x269/0x3b0 fs/namei.c:3837<br>
&gt; <br>
&gt;=C2=A0 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899<br>
&gt; <br>
&gt;=C2=A0 __do_sys_unlink fs/namei.c:3945 [inline]<br>
&gt; <br>
&gt;=C2=A0 __se_sys_unlink fs/namei.c:3943 [inline]<br>
&gt; <br>
&gt;=C2=A0 __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943<br>
&gt; <br>
&gt;=C2=A0 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46<br>
&gt; <br>
&gt;=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9<br>
&gt; <br>
&gt; I use dump_stack(), but can only get this kind of info:<br>
&gt; <br>
&gt; vfs_unlink+0x269/0x3b0<br>
&gt; <br>
&gt; do_unlinkat+0x28a/0x4d0<br>
&gt; <br>
&gt; __x64_sys_unlink+0x2c/0x30<br>
&gt; <br>
&gt; do_syscall_64+0x39/0x80<br>
&gt; <br>
&gt; entry_SYSCALL_64_after_hwframe+0x44/0xa9<br>
&gt; <br>
&gt; Obviously, inline function info misses. When I look at the Linux Kerne=
l<br>
&gt; source code, the implementation of dump_stack(), seems because the inl=
ine<br>
&gt; function is not within the range of kernel_text_address().<br>
&gt; Do you have any idea?<br>
<br>
If you build your kernel with CONFIG_DEBUG_INFO=3Dy, any number of tools<br=
>
will be able to translate those addresses to filenames and line numbers.<br=
>
For but one example, given the vmlinux, you could give the following<br>
command to &quot;gdb vmlinux&quot;:<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 l *vfs_unlink+0x269<br>
<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 Thanx, Paul<br>
<br>
&gt; Thank You<br>
&gt; Best<br>
&gt; Jin Huang<br>
&gt; <br>
&gt; <br>
&gt; On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov &lt;<a href=3D"mailto:dv=
yukov@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wrote:<br>
&gt; <br>
&gt; &gt; On Wed, Jan 27, 2021 at 5:57 AM Jin Huang &lt;<a href=3D"mailto:a=
ndy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&gt; w=
rote:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Hi, Macro<br>
&gt; &gt; &gt; Could you provide some instructions about how to use syz-sym=
bolize to<br>
&gt; &gt; locate the kernel source code?<br>
&gt; &gt; &gt; I did not find any document about it.<br>
&gt; &gt;<br>
&gt; &gt; Hi Jin,<br>
&gt; &gt;<br>
&gt; &gt; If you build kernel in-tree, then you can just run:<br>
&gt; &gt; $ syz-symbolize file-with-kernel-crash<br>
&gt; &gt; from the kernel dir.<br>
&gt; &gt;<br>
&gt; &gt; Otherwise add -kernel_src flag and/or -kernel_obj flag:<br>
&gt; &gt;<br>
&gt; &gt; <a href=3D"https://github.com/google/syzkaller/blob/master/tools/=
syz-symbolize/symbolize.go#L24" rel=3D"noreferrer" target=3D"_blank">https:=
//github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go#=
L24</a><br>
&gt; &gt;<br>
&gt; &gt;<br>
&gt; &gt;<br>
&gt; &gt; &gt; Thank You<br>
&gt; &gt; &gt; Best<br>
&gt; &gt; &gt; Jin Huang<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; On Mon, Jan 11, 2021 at 2:09 AM Marco Elver &lt;<a href=3D"m=
ailto:elver@google.com" target=3D"_blank">elver@google.com</a>&gt; wrote:<b=
r>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; On Mon, 11 Jan 2021 at 07:54, Jin Huang &lt;<a href=3D"m=
ailto:andy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a=
>&gt;<br>
&gt; &gt; wrote:<br>
&gt; &gt; &gt;&gt;&gt;<br>
&gt; &gt; &gt;&gt;&gt; Really thank you for your help, Dmitry.<br>
&gt; &gt; &gt;&gt;&gt; I tried and saw the KCSAN info.<br>
&gt; &gt; &gt;&gt;&gt;<br>
&gt; &gt; &gt;&gt;&gt; But now it seems weird, the KCSAN reports differentl=
y every time I run<br>
&gt; &gt; the kernel, and the /sys/kernel/debug/kcsan seems does not match =
with the<br>
&gt; &gt; KCSAN report. What is wrong?<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; /sys/kernel/debug/kcsan shows the total data races found=
, but that may<br>
&gt; &gt; differ from those reported to console, because there is an extra =
filtering<br>
&gt; &gt; step (e.g. KCSAN won&#39;t report the same data race more than on=
ce 3 sec).<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt;&gt;<br>
&gt; &gt; &gt;&gt;&gt; And I also want to ask, besides gdb, how to use othe=
r ways to locate<br>
&gt; &gt; the kernel source code, like decode_stacktrace.sh and syz-symboli=
ze, talked<br>
&gt; &gt; about here <a href=3D"https://lwn.net/Articles/816850/" rel=3D"no=
referrer" target=3D"_blank">https://lwn.net/Articles/816850/</a>. Is gdb th=
e best way?<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; I use syz-symbolize 99% of the time.<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt;&gt;<br>
&gt; &gt; &gt;&gt;&gt; Also, does KCSAN recognizes all the synchronizations=
 in the Linux<br>
&gt; &gt; Kernel? Is there false positives or false negatives?<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; Data races in the Linux kernel is an ongoing story, howe=
ver, there are<br>
&gt; &gt; no false positives (but KCSAN can miss data races).<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; Regarding the data races you&#39;re observing: there are=
 numerous known<br>
&gt; &gt; data races in the kernel that are expected when you currently run=
 KCSAN. To<br>
&gt; &gt; understand the severity of different reports, let&#39;s define th=
e following 3<br>
&gt; &gt; concurrency bug classes:<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; A. Data race, where failure due to current compilers is =
unlikely<br>
&gt; &gt; (supposedly &quot;benign&quot;); merely marking the accesses appr=
opriately is<br>
&gt; &gt; sufficient. Finding a crash for these will require a miscompilati=
on, but<br>
&gt; &gt; otherwise look &quot;benign&quot; at the C-language level.<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; B. Race-condition bugs where the bug manifests as a data=
 race, too --<br>
&gt; &gt; simply marking things doesn&#39;t fix the problem. These are the =
types of bugs<br>
&gt; &gt; where a data race would point out a more severe issue.<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; C. Race-condition bugs where the bug never manifests as =
a data race. An<br>
&gt; &gt; example of these might be 2 threads that acquire the necessary lo=
cks, yet<br>
&gt; &gt; some interleaving of them still results in a bug (e.g. because th=
e logic<br>
&gt; &gt; inside the critical sections is buggy). These are harder to detec=
t with<br>
&gt; &gt; KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or<br>
&gt; &gt; ASSERT_EXCLUSIVE_WRITER() in the right place. See<br>
&gt; &gt; <a href=3D"https://lwn.net/Articles/816854/" rel=3D"noreferrer" t=
arget=3D"_blank">https://lwn.net/Articles/816854/</a>.<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; One problem currently is that the kernel has quite a lot=
 type-(A)<br>
&gt; &gt; reports if we run KCSAN, which makes it harder to identify bugs o=
f type (B)<br>
&gt; &gt; and (C). My wish for the future is that we can get to a place, wh=
ere the<br>
&gt; &gt; kernel has almost no unintentional (A) issues, so that we primari=
ly find<br>
&gt; &gt; (B) and (C) bugs.<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; Hope this helps.<br>
&gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt;&gt; Thanks,<br>
&gt; &gt; &gt;&gt; -- Marco<br>
&gt; &gt;<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnapTjGjYJXojTXa%3DNpz81sCZBtiaTci7K3Qq5gd7Myi-o=
w%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CACV%2BnapTjGjYJXojTXa%3DNpz81sCZBtiaTci7K3Qq5g=
d7Myi-ow%40mail.gmail.com</a>.<br />

--0000000000007829d405b9fec895--
