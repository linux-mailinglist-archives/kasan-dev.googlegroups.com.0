Return-Path: <kasan-dev+bncBCCMH5WKTMGRB54U2LUAKGQEPUY7HFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B686A57F24
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:20:56 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id h184sf688121oif.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:20:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561627255; cv=pass;
        d=google.com; s=arc-20160816;
        b=d0UmcoQXnhnZo7J6KX9tMcUAzI4M0RSzGHiWDc4XTN7UBGKoFx5QwfIVU0I7jfSwbd
         HUJpsZwnLaFMeRxqnevKCrOweFP2BmUZK3MV22bcrt41R/WkDhlUzJ5DbzW3owB52dGZ
         +Vd796RcCFOJyl0B5Nn4WhxJZ/gaQNe6OUxo+hty+e4SeP+RuBGkaunARRvVKN94YprL
         KiRmMeIpyrM8Vdv0OD/ZUe4zGnUvjArLG5EUvmrTMq5ivdHOTvyF63GOF70+cFXQ+vj0
         d1X1L3jGYm/7eKXfhKJyzY6aBgmHLPKS8ELEhABfFy4K+TsdnjDTY57wfEBI1Ih6A7KA
         +oFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pxBJ5Zq8pc1MMIP+NMmHaqdVHnxXu548t5XA+a5bljY=;
        b=U2nzata4tQPAYoC70by9npuBM2BA0bzpf7yl2uxggojaL4YjhZHHupUN0rrkeDfwz2
         g++28x9No+XRq/XZeroahQHXlo6QlWLbM18gSysY+t9lkUgEobFe6ZDC82cDoUmta1No
         VMe21e1aYR6wVcCsF65/5To3hqo2Up8n6nKF9QowpRRP29Tj93gk4/rxGQm+UHPSX7RM
         wNKnlL6GBkST2KNUfVpO27ZfxYNwtv6S+O23kvKHvxNSDSE4kLzQliUFcv8j4bA+vl73
         15rTpNid3LYA5nJB1+TJ2HI7YR+epj9Bwdzb+vfIfZi06hRL28iYW2Pw4UD8fW1lPHIq
         YI6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SOZZUqXu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e43 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pxBJ5Zq8pc1MMIP+NMmHaqdVHnxXu548t5XA+a5bljY=;
        b=V47VfaOIwVhR/U4GRAvG5QdsSS+n+gQn50+LpiZxbTR53Kg/dJCrWJoZ02icm1a3cm
         uhVMqEj2vYGnoMAclX4w369lIx+t1vLwSAQjJ35XSNeutdP6YSvET/fHZXC+ou19iJ6q
         ySokJlRP9tREJkBiVoLE4Tbx/2MameytWll2GfAqXTeSz/anDK31LGwidtzC3UVtTm3w
         YOYOsL2xZf6Y3t7tOqd96VMkSAHBnKaIOkDwcdM4Fse9o5wJyIn3MAAcwcydVz6TDc9w
         OpqmgIMzQljurHsDrn+mbxprwf+rfw6/U9V8Tx/FZMdV+z17oxPfohwR/iJ7AXEZwo62
         1TdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pxBJ5Zq8pc1MMIP+NMmHaqdVHnxXu548t5XA+a5bljY=;
        b=IzdfNlSxqVfiBcmbiHXLLZHlkgs9P8kPexRTl1zOKRS5KTCYvxmDy1L7jZU0xSrUNc
         47O+IBGPc+o8Lmwy4LzDSw43aOi/FSZuEMiOPcWxbj/s8LfHCNIGmEZUBTEyJymh99hK
         8kuEPmSpC+x6EAypnOIh38poWIgpIYpuJ3C9QwfkYGUTDBuADFhidH9H1yP41pUs7qSD
         emQE5co2JGq55gb4qDETWzpYlEuO9o4b89UpqeHK/t/AuzTczHGOBOgebjFs0ShZ4M55
         X6gPg7bh6U6mYHLnQruyICEhIXMuqJ90vuK3ifuTvADP6mYCfRo+xoYmBz812IMddZHp
         AvHQ==
X-Gm-Message-State: APjAAAWl9T7RfBBV1KKAZ6dYobOaRBRETHbX4EDvjkb4obBhj6IEIdoe
	5aXh4obnZUuiLIRIuuTHtZs=
X-Google-Smtp-Source: APXvYqzjX34tSJ63Mlnl8UB+bAbzuanaoS8W6rEAn5oG2L38mpN635+hcIEnTVhIOhe3MN2vsbItTg==
X-Received: by 2002:a9d:2c47:: with SMTP id f65mr2506689otb.185.1561627255201;
        Thu, 27 Jun 2019 02:20:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3a44:: with SMTP id h65ls302972oia.1.gmail; Thu, 27 Jun
 2019 02:20:54 -0700 (PDT)
X-Received: by 2002:aca:7585:: with SMTP id q127mr1626556oic.113.1561627254847;
        Thu, 27 Jun 2019 02:20:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561627254; cv=none;
        d=google.com; s=arc-20160816;
        b=c5rmKXwViqRLidGekXdx3gj1rj4uGmuyTinwgvAUejU8d39IHcnaTacM2Mq5lkyXcm
         qamp6BOuvh8Q/fb+84ieX8OcitX55cxjtxZAtuu8nKmHXaIGQK6V7ZdzIwkju/OKiQ/S
         Oo2NexKWHOk/l/mZ4Pv2qrag0Hb4ABtZoMD7NxI+7pNlOjd28+xpv0RJ79v8VJ4zTkm9
         zerUI0s61QRNbUqC4ibHTg6U3ROJpTcFEB8ASb+N6bj9gha20Fy+ftwY1I8E/0lBvhde
         +3GurNALgAPQlxBSv8UK7+EDcAHHDvM/PWbS2+1WxBUsbMKdTojUHBPZn1Qwyo5LrkG8
         Z8Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5ty7FWvYz/AGXkbAWOGnkru2DyJ/8IMoQi8dW3hZl6o=;
        b=ivcxE2fPSzaRZwM3dTeyB5ENSt61W0AHD/jh3iz+vLZj0MIynhhgMow3HB/L3LE4uu
         lHPb62b5rO2bi9q00BK274EAUCprGIadYOICLWTEj5MjmMDtouYJ035SQ/o4lOeP3gsN
         aoWuPS/jQlcMfZfiOZXk4pvEKqOLYZc8MIyosFmX2mRKA3EcAKuMKkPf+HgeHxneiOSS
         EJYJ+qP3odbO6pk0OhKF+RtbwzDgzYjxWlQg2/0s8w4IncHz6sw39VCrBdTafUfwi2C4
         XPC+hU+NOt/FEIbrZZXiF+izRwYYySyVQergOSnXAIAC+cevavUh/T9+/dvR8nCB0n+l
         t/EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SOZZUqXu;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e43 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe43.google.com (mail-vs1-xe43.google.com. [2607:f8b0:4864:20::e43])
        by gmr-mx.google.com with ESMTPS id k19si79485otf.4.2019.06.27.02.20.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:20:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e43 as permitted sender) client-ip=2607:f8b0:4864:20::e43;
Received: by mail-vs1-xe43.google.com with SMTP id v129so1133139vsb.11
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:20:54 -0700 (PDT)
X-Received: by 2002:a67:11c1:: with SMTP id 184mr1874196vsr.217.1561627253862;
 Thu, 27 Jun 2019 02:20:53 -0700 (PDT)
MIME-Version: 1.0
References: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
 <CAG_fn=UoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw@mail.gmail.com> <CADvbK_fTGwW=HHhXFgatN7QzhNHoFTjmNH7orEdb3N1Gt+1fgg@mail.gmail.com>
In-Reply-To: <CADvbK_fTGwW=HHhXFgatN7QzhNHoFTjmNH7orEdb3N1Gt+1fgg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Jun 2019 11:20:41 +0200
Message-ID: <CAG_fn=U-OBaRhPN7ab9dFcpchC1AftBN+wJMF+13FOBZORieUg@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Xin Long <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SOZZUqXu;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e43 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Hi Xin,

Sorry for the late reply.
I've built the ToT KMSAN tree using your config and my almost-ToT
Clang and couldn't reproduce the problem.
I believe something is wrong with your Clang version, as
CONFIG_CLANG_VERSION should really be 90000.
You can run `make V=3D1` to see which Clang version is being invoked -
make sure it's a fresh one.

HTH,
Alex

On Fri, Jun 21, 2019 at 10:09 PM Xin Long <lucien.xin@gmail.com> wrote:
>
> as attached,
>
> It actually came from https://syzkaller.appspot.com/x/.config?x=3D6024681=
64ccdc30a
> after I built, clang version changed to:
>
> CONFIG_CLANG_VERSION=3D80000
>
> On Sat, Jun 22, 2019 at 2:06 AM Alexander Potapenko <glider@google.com> w=
rote:
> >
> > Hi Xin,
> >
> > Could you please share the config you're using to build the kernel?
> > I'll take a closer look on Monday when I am back to the office.
> >
> > On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien.xin@gmail.com> wrote:
> >>
> >> this is my command:
> >>
> >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \
> >>     -net nic -net user,hostfwd=3Dtcp::10022-:22 \
> >>     -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \
> >>     -device virtio-scsi-pci,id=3Dscsi \
> >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> >>     -drive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=3Dd0=
 \
> >>     -append "root=3D/dev/sda console=3DttyS0 earlyprintk=3Dserial roda=
ta=3Dn \
> >>       oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D=
1 \
> >>       security=3Dapparmor ima_policy=3Dtcb workqueue.watchdog_thresh=
=3D140 \
> >>       nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=3D20000 \
> >>       nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=3D20000 \
> >>       nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \
> >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
> >>       spec_store_bypass_disable=3Dprctl nopcid"
> >>
> >> the commit is on:
> >> commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)
> >> Author: Alexander Potapenko <glider@google.com>
> >> Date:   Wed May 22 12:30:13 2019 +0200
> >>
> >>     kmsan: use kmsan_handle_urb() in urb.c
> >>
> >> and when starting, it shows:
> >> [    0.561925][    T0] Kernel command line: root=3D/dev/sda
> >> console=3DttyS0 earlyprintk=3Dserial rodata=3Dn       oops=3Dpanic
> >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1       security=3D=
ad
> >> [    0.707792][    T0] Memory: 3087328K/4193776K available (219164K
> >> kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K bss,
> >> 1106448K reserved, 0K cma-reserved)
> >> [    0.710935][    T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0=
,
> >> CPUs=3D2, Nodes=3D1
> >> [    0.711953][    T0] Starting KernelMemorySanitizer
> >> [    0.712563][    T0]
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [    0.713657][    T0] BUG: KMSAN: uninit-value in mutex_lock+0xd1/0xe=
0
> >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1.0 #=
5
> >> [    0.715417][    T0] Hardware name: Red Hat KVM, BIOS
> >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> [    0.716659][    T0] Call Trace:
> >> [    0.717127][    T0]  dump_stack+0x134/0x190
> >> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> >> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> >> [    0.719478][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> >> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
> >> [    0.720926][    T0]  ? rb_get_reader_page+0x1140/0x1140
> >> [    0.721632][    T0]  __cpuhp_setup_state+0x181/0x2e0
> >> [    0.722374][    T0]  ? rb_get_reader_page+0x1140/0x1140
> >> [    0.723115][    T0]  tracer_alloc_buffers+0x16b/0xb96
> >> [    0.723846][    T0]  early_trace_init+0x193/0x28f
> >> [    0.724501][    T0]  start_kernel+0x497/0xb38
> >> [    0.725134][    T0]  x86_64_start_reservations+0x19/0x2f
> >> [    0.725871][    T0]  x86_64_start_kernel+0x84/0x87
> >> [    0.726538][    T0]  secondary_startup_64+0xa4/0xb0
> >> [    0.727173][    T0]
> >> [    0.727454][    T0] Local variable description:
> >> ----success.i.i.i.i@mutex_lock
> >> [    0.728379][    T0] Variable was created at:
> >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> >> [    0.729536][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> >> [    0.730323][    T0]
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [    0.731364][    T0] Disabling lock debugging due to kernel taint
> >> [    0.732169][    T0] Kernel panic - not syncing: panic_on_warn set .=
..
> >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B
> >>         5.1.0 #5
> >> [    0.734080][    T0] Hardware name: Red Hat KVM, BIOS
> >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> [    0.735319][    T0] Call Trace:
> >> [    0.735735][    T0]  dump_stack+0x134/0x190
> >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> >> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> >> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> >> [    0.738527][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> >> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
> >> [    0.739972][    T0]  ? rb_get_reader_page+0x1140/0x1140
> >> [    0.740695][    T0]  __cpuhp_setup_state+0x181/0x2e0
> >> [    0.741412][    T0]  ? rb_get_reader_page+0x1140/0x1140
> >> [    0.742160][    T0]  tracer_alloc_buffers+0x16b/0xb96
> >> [    0.742866][    T0]  early_trace_init+0x193/0x28f
> >> [    0.743512][    T0]  start_kernel+0x497/0xb38
> >> [    0.744128][    T0]  x86_64_start_reservations+0x19/0x2f
> >> [    0.744863][    T0]  x86_64_start_kernel+0x84/0x87
> >> [    0.745534][    T0]  secondary_startup_64+0xa4/0xb0
> >> [    0.746290][    T0] Rebooting in 86400 seconds..
> >>
> >> when I set "panic_on_warn=3D0", it foods the console with:
> >> ...
> >> [   25.206759][    C0] Variable was created at:
> >> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> >> [   25.207844][    C0]  vprintk_deferred+0x90/0xed
> >> [   25.208404][    C0]
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   25.209763][    C0]  x86_64_start_reservations+0x19/0x2f
> >> [   25.209769][    C0]
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   25.211408][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/=
0x800
> >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
> >>           5.1.0 #5
> >> [   25.213206][    C0] Hardware name: Red Hat KVM, BIOS
> >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> [   25.214326][    C0] Call Trace:
> >> [   25.214725][    C0]  <IRQ>
> >> [   25.215080][    C0]  dump_stack+0x134/0x190
> >> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> >> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> >> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> >> [   25.217334][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
> >> [   25.218127][    C0]  vprintk_deferred+0x90/0xed
> >> [   25.218714][    C0]  printk_deferred+0x186/0x1d3
> >> [   25.219353][    C0]  __printk_safe_flush+0x72e/0xc00
> >> [   25.220006][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> >> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> >> [   25.221210][    C0]  ? flat_init_apic_ldr+0x170/0x170
> >> [   25.221851][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> >> [   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
> >> [   25.223110][    C0]  </IRQ>
> >> [   25.223475][    C0] RIP: 0010:kmem_cache_init_late+0x0/0xb
> >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48 89 d3
> >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b
> >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> >> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 00000246
> >> ORIG_RAX: ffffffffffffff09
> >> [   25.227548][    C0] RAX: ffff88813f995785 RBX: 0000000000000000
> >> RCX: 0000000000000000
> >> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI: 0000160000000000
> >> RDI: 0000000000000785
> >> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08: 000000000fac3785
> >> R09: 0000778000000001
> >> [   25.230440][    C0] R10: ffffd0ffffffffff R11: 0000100000000000
> >> R12: 0000000000000000
> >> [   25.231403][    C0] R13: 0000000000000000 R14: ffffffff8fb8cfd0
> >> R15: 0000000000000000
> >> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
> >> [   25.233003][    C0]  x86_64_start_reservations+0x19/0x2f
> >> [   25.233670][    C0]  x86_64_start_kernel+0x84/0x87
> >> [   25.234314][    C0]  secondary_startup_64+0xa4/0xb0
> >> [   25.234949][    C0]
> >> [   25.235231][    C0] Local variable description: ----flags.i.i.i@vpr=
intk_emit
> >> [   25.236101][    C0] Variable was created at:
> >> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> >> [   25.237188][    C0]  vprintk_deferred+0x90/0xed
> >> [   25.237752][    C0]
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   25.239117][    C0]  x86_64_start_kernel+0x84/0x87
> >> [   25.239123][    C0]
> >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   25.240704][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/=
0x800
> >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
> >>           5.1.0 #5
> >> [   25.242512][    C0] Hardware name: Red Hat KVM, BIOS
> >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> [   25.243635][    C0] Call Trace:
> >> [   25.244038][    C0]  <IRQ>
> >> [   25.244390][    C0]  dump_stack+0x134/0x190
> >> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> >> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> >> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> >> [   25.246638][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
> >> [   25.247430][    C0]  vprintk_deferred+0x90/0xed
> >> [   25.248018][    C0]  printk_deferred+0x186/0x1d3
> >> [   25.248650][    C0]  __printk_safe_flush+0x72e/0xc00
> >> [   25.249320][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> >> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> >> [   25.250524][    C0]  ? flat_init_apic_ldr+0x170/0x170
> >> [   25.251167][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> >> [   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
> >> [   25.252424][    C0]  </IRQ>
> >> ....
> >>
> >>
> >> I couldn't even log in.
> >>
> >> how should I use qemu with wheezy.img to start a kmsan kernel?
> >>
> >> Thanks.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU-OBaRhPN7ab9dFcpchC1AftBN%2BwJMF%2B13FOBZORieUg%40mail.=
gmail.com.
For more options, visit https://groups.google.com/d/optout.
