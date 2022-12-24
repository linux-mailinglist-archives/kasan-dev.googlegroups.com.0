Return-Path: <kasan-dev+bncBCLI747UVAFRBYP4TGOQMGQEKAE6KYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BBBD655862
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Dec 2022 05:21:55 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id i18-20020ad44112000000b00523149d387esf3330781qvp.16
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 20:21:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671855714; cv=pass;
        d=google.com; s=arc-20160816;
        b=pGdxRKRy5fcBUOOKvZoipHsdAexAU+9+eTvLb4A/omEMrRGXhRaRCZvmh4ECfN62zi
         zXJFD6O22TfSKqFn/mkWuzSWR2yZwQlsgdMCMxYa7I48KDyIkJyR+qctFw/yGU7S2o6t
         ZUKgTo4XVf7xfIVJ4DniBETCwXCqZLUaTNIa2YPtC84OYeU+c946G12TtsmtDZcA3+76
         YD8yyPAO+6kJwnMtj6OusZVB0xA/ZaxJhz7s9l3riezT0sKnSlVeldwWnbLl/VYuFJpn
         ZjOLO8QDrrUqmRUoOvpLUfpVOSDdsmY2Vl6ramjQibM0wSWD8ahd/srCtVF6Y/2SUcvB
         Pz9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=tkKPrzEgRIFXfAGE5l6/pXkWU/N/lxI9tjcjILDTZ3w=;
        b=nRjb6hxLWd7mWpjCfqoJQ9M9Pgiy4YJ5iYlFkTzOpNrReFQq7tfCEoK4Nh7pPmLZnO
         BkOkxjVas/R5FBVNIvh2YSyaODPY4p8fjdMwJxCW5zrgvTAwg2kce6JLxBm4Tgy8h4Eh
         PWt3J7UpqC29q0c7/3NBepNqXQDxCafSEff0U3pbsQkyUErRK4JMjJBBkZzWPOu6OvWb
         8xA6GA/ZfaxllxHwR4ImcpEJB9V/Gt4IRektqIAS/OL87jq+IMrVRw+kwuMGPSXXQ4hJ
         7nOWdVEkKJxLmiEa6DC4UsqdNAMjMN0pAkJOVFG26GufUckI2qOJUcxZsqjykk8XPUuw
         50lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=IY8ie7RO;
       spf=pass (google.com: domain of srs0=zjrg=4w=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=zjrg=4W=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tkKPrzEgRIFXfAGE5l6/pXkWU/N/lxI9tjcjILDTZ3w=;
        b=LYpmN3sGJPZ/0mZYancczY70hBniBzdMKcbhwYRvrTCJUwS6R43cRVJ990PfkJQ+T+
         70TwXaGiytkaJhlLX1NmC2WcfXXFXdXi9FxSVd/le9uJ6bGkMJKqPmUmOq8f22H4rSYr
         2leDH9qqoOTfIPCin1+1qyD6yrqIkotb2IeFo19brBCd/JEQlpLvtQiZrDhm7IZVY2rg
         KXBxx29Pcbw2KlQNHSHacpnC6Bmgwst3FJaoZfZwm/Hu27bR2OVIt/w8Qg2CW5dOxk8k
         BBu/Yc9Z7ajglEDsQ7eALUc0psIaFX3UupzoHHERG1YdG7K885chS7DGr8Z2g/vL6BoJ
         ThLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tkKPrzEgRIFXfAGE5l6/pXkWU/N/lxI9tjcjILDTZ3w=;
        b=Pw95dkE5jwQDy/0/x615GHIBy4bO2IXzB/KVjs/wV+A/FaySusqPG3CAAuifJB/iBi
         ZeasqT587N8/ZskVrdwVpe9clLHKhJoU4iQiUx9xT8e7aUfboDxxdefmQ6eEb1kfCRdb
         Vhp+HHnJwO1oLrmWXkuD5mJr1eHyYTJ2QAHDBZ4Nk2D5eYD0i4QQBGMgyu1mn0Kjp/ag
         003km38i4XOciu/7T8QWF0NJtospEQsM6oOgqQVwX00Bihy1DRQtasrsTD1jXFdrtdO+
         1S1oPlxOUREeMpwXJzmikUynJ3rLXSjpujZA7sLuhgEGhrqLBxLz8Lx3tiCm3NjYMNd6
         UaBg==
X-Gm-Message-State: AFqh2koD5fjniDguNnKY4rRdqLqTyUvTAY/FLT+gJ60qlVEQ1UpdKEt8
	pQ/JOgKQaiBTnCj6/vM08VI=
X-Google-Smtp-Source: AMrXdXtIwKSexBwFmnIUoOBvnIOm9d2Zaiz6cg62UkNRGx7bvctvcsWl4N4ppgJ2gqUZobpaf//m6A==
X-Received: by 2002:a05:620a:2190:b0:6ff:aaca:3c2f with SMTP id g16-20020a05620a219000b006ffaaca3c2fmr515910qka.635.1671855713873;
        Fri, 23 Dec 2022 20:21:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:259a:b0:3a9:7e8b:ed6c with SMTP id
 cj26-20020a05622a259a00b003a97e8bed6cls4374969qtb.8.-pod-prod-gmail; Fri, 23
 Dec 2022 20:21:53 -0800 (PST)
X-Received: by 2002:ac8:7772:0:b0:3a8:22f2:1782 with SMTP id h18-20020ac87772000000b003a822f21782mr12837009qtu.35.1671855713100;
        Fri, 23 Dec 2022 20:21:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671855713; cv=none;
        d=google.com; s=arc-20160816;
        b=ZQ8mWJVkRcmpDKdXujKjW6TQTHtfjH4ySYL92HWGZr7g3OUCq8HzwvqB59Fg7sf/i/
         Fqp+rQqTLC9PI5cRirh2iZ8/9ySfxgysIASXnJU7Dr9t09M0sUEdwV3piBDi1E18M+it
         8HSND9S/S8pWPVeGPFzSr4p6KQHBKW3/0GCS1P5kL48do8QWds5hqDVZ0wN9KQdMf/mz
         y8mWfVcZlV7Da3rMNu+9jmqWzXmCD9r+Z4t5apVe67vgNGzXMnOETuGBxBm5pgyDVKmr
         ot8H4h0EOv+svTHozofwYgB1PQlBtgxn7sWc0Woe1Yj8QPJIDLy1ANPDRgP2mze6jsAg
         yj2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wMVEWgAImpaXOXkbRJR5Q/isX0SCyP6IRhnpnkOD6IQ=;
        b=OBNJcVfIKBkTjQkeHSwATT6g6WW+9z7ys1QAPPXh0tDI9uL7iGbdk3VbnVT3p5IWxT
         2tPH01fIAQjIfZBVMfoo6Z15u+9MAhfxJ+97gUGhoDkplNaOR4yAHvNa9mONY3SLf0sE
         8kWgkG8OZlwoPafQ3hGbnBX6nVzQ0x/q5gqDlubl54R427Zxu5ahrDq4ETJMwRs57bEt
         /p7cMMh6TjGIde0WnfNLHUdEEx19BmA7GTTwvs1vElv1evAEReyKfpocbIytaIUq8Bh+
         D2SWfy7ZQjOtkOMWPz2FjTYfYqJAHrdmUld0f4L7Chwo8d3Fkn8KblZrw3edCfNQ/aY1
         KTuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=IY8ie7RO;
       spf=pass (google.com: domain of srs0=zjrg=4w=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=zjrg=4W=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id s16-20020ac85ed0000000b003a7fa08057asi339264qtx.1.2022.12.23.20.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Dec 2022 20:21:52 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zjrg=4w=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5100C6006F;
	Sat, 24 Dec 2022 04:21:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 332DDC433D2;
	Sat, 24 Dec 2022 04:21:50 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id ff9fbfc8 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 24 Dec 2022 04:21:47 +0000 (UTC)
Date: Sat, 24 Dec 2022 05:21:46 +0100
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Eric Biggers <ebiggers@kernel.org>
Cc: pbonzini@redhat.com, qemu-devel@nongnu.org,
	Laurent Vivier <laurent@vivier.eu>,
	"Michael S . Tsirkin" <mst@redhat.com>,
	Peter Maydell <peter.maydell@linaro.org>,
	Philippe =?utf-8?Q?Mathieu-Daud=C3=A9?= <f4bug@amsat.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Ard Biesheuvel <ardb@kernel.org>, Gerd Hoffmann <kraxel@redhat.com>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 4/4] x86: re-enable rng seeding via SetupData
Message-ID: <Y6Z+WpqN59ZjIKkk@zx2c4.com>
References: <20220921093134.2936487-1-Jason@zx2c4.com>
 <20220921093134.2936487-4-Jason@zx2c4.com>
 <Y6ZESPx4ettBLuMt@sol.localdomain>
 <Y6ZtVGtFpUNQP+KU@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Y6ZtVGtFpUNQP+KU@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=IY8ie7RO;       spf=pass
 (google.com: domain of srs0=zjrg=4w=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=zjrg=4W=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Sat, Dec 24, 2022 at 04:09:08AM +0100, Jason A. Donenfeld wrote:
> Hi Eric,
>=20
> Replying to you from my telephone, and I'm traveling the next two days,
> but I thought I should mention some preliminary results right away from
> doing some termux compiles:
>=20
> On Fri, Dec 23, 2022 at 04:14:00PM -0800, Eric Biggers wrote:
> > Hi Jason,
> >=20
> > On Wed, Sep 21, 2022 at 11:31:34AM +0200, Jason A. Donenfeld wrote:
> > > This reverts 3824e25db1 ("x86: disable rng seeding via setup_data"), =
but
> > > for 7.2 rather than 7.1, now that modifying setup_data is safe to do.
> > >=20
> > > Cc: Laurent Vivier <laurent@vivier.eu>
> > > Cc: Michael S. Tsirkin <mst@redhat.com>
> > > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > > Cc: Peter Maydell <peter.maydell@linaro.org>
> > > Cc: Philippe Mathieu-Daud=C3=A9 <f4bug@amsat.org>
> > > Cc: Richard Henderson <richard.henderson@linaro.org>
> > > Cc: Ard Biesheuvel <ardb@kernel.org>
> > > Acked-by: Gerd Hoffmann <kraxel@redhat.com>
> > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> > > ---
> > >  hw/i386/microvm.c | 2 +-
> > >  hw/i386/pc_piix.c | 3 ++-
> > >  hw/i386/pc_q35.c  | 3 ++-
> > >  3 files changed, 5 insertions(+), 3 deletions(-)
> > >=20
> >=20
> > After upgrading to QEMU 7.2, Linux 6.1 no longer boots with some config=
s.  There
> > is no output at all.  I bisected it to this commit, and I verified that=
 the
> > following change to QEMU's master branch makes the problem go away:
> >=20
> > diff --git a/hw/i386/pc_piix.c b/hw/i386/pc_piix.c
> > index b48047f50c..42f5b07d2f 100644
> > --- a/hw/i386/pc_piix.c
> > +++ b/hw/i386/pc_piix.c
> > @@ -441,6 +441,7 @@ static void pc_i440fx_8_0_machine_options(MachineCl=
ass *m)
> >      pc_i440fx_machine_options(m);
> >      m->alias =3D "pc";
> >      m->is_default =3D true;
> > +    PC_MACHINE_CLASS(m)->legacy_no_rng_seed =3D true;
> >  }
> >=20
> > I've attached the kernel config I am seeing the problem on.
> >=20
> > For some reason, the problem also goes away if I disable CONFIG_KASAN.
> >=20
> > Any idea what is causing this?
>=20
> - Commenting out the call to parse_setup_data() doesn't fix the issue.
>   So there's no KASAN issue with the actual parser.
>=20
> - Using KASAN_OUTLINE rather than INLINE does fix the issue!
>=20
> That makes me suspect that it's file size related, and QEMU or the BIOS
> is placing setup data at an overlapping offset by accident, or something
> similar.

I removed the file systems from your config to bring the kernel size
back down, and voila, it works, even with KASAN_INLINE. So perhaps I'm
on the right track here...


>=20
> I'll investigate this hypothesis when I'm back at a real computer.
>=20
> Jason
>=20
>=20
>=20
>=20
>=20
>=20
> >=20
> > - Eric
>=20
> > #
> > # Automatically generated file; DO NOT EDIT.
> > # Linux/x86 6.1.0 Kernel Configuration
> > #
> > CONFIG_CC_VERSION_TEXT=3D"gcc (GCC) 12.2.0"
> > CONFIG_CC_IS_GCC=3Dy
> > CONFIG_GCC_VERSION=3D120200
> > CONFIG_CLANG_VERSION=3D0
> > CONFIG_AS_IS_GNU=3Dy
> > CONFIG_AS_VERSION=3D23900
> > CONFIG_LD_IS_BFD=3Dy
> > CONFIG_LD_VERSION=3D23900
> > CONFIG_LLD_VERSION=3D0
> > CONFIG_CC_CAN_LINK=3Dy
> > CONFIG_CC_CAN_LINK_STATIC=3Dy
> > CONFIG_CC_HAS_ASM_GOTO_OUTPUT=3Dy
> > CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT=3Dy
> > CONFIG_CC_HAS_ASM_INLINE=3Dy
> > CONFIG_CC_HAS_NO_PROFILE_FN_ATTR=3Dy
> > CONFIG_PAHOLE_VERSION=3D0
> > CONFIG_CONSTRUCTORS=3Dy
> > CONFIG_IRQ_WORK=3Dy
> > CONFIG_BUILDTIME_TABLE_SORT=3Dy
> > CONFIG_THREAD_INFO_IN_TASK=3Dy
> >=20
> > #
> > # General setup
> > #
> > CONFIG_INIT_ENV_ARG_LIMIT=3D32
> > # CONFIG_COMPILE_TEST is not set
> > # CONFIG_WERROR is not set
> > CONFIG_LOCALVERSION=3D""
> > CONFIG_LOCALVERSION_AUTO=3Dy
> > CONFIG_BUILD_SALT=3D""
> > CONFIG_HAVE_KERNEL_GZIP=3Dy
> > CONFIG_HAVE_KERNEL_BZIP2=3Dy
> > CONFIG_HAVE_KERNEL_LZMA=3Dy
> > CONFIG_HAVE_KERNEL_XZ=3Dy
> > CONFIG_HAVE_KERNEL_LZO=3Dy
> > CONFIG_HAVE_KERNEL_LZ4=3Dy
> > CONFIG_HAVE_KERNEL_ZSTD=3Dy
> > CONFIG_KERNEL_GZIP=3Dy
> > # CONFIG_KERNEL_BZIP2 is not set
> > # CONFIG_KERNEL_LZMA is not set
> > # CONFIG_KERNEL_XZ is not set
> > # CONFIG_KERNEL_LZO is not set
> > # CONFIG_KERNEL_LZ4 is not set
> > # CONFIG_KERNEL_ZSTD is not set
> > CONFIG_DEFAULT_INIT=3D""
> > CONFIG_DEFAULT_HOSTNAME=3D"(none)"
> > CONFIG_SYSVIPC=3Dy
> > CONFIG_SYSVIPC_SYSCTL=3Dy
> > CONFIG_SYSVIPC_COMPAT=3Dy
> > CONFIG_POSIX_MQUEUE=3Dy
> > CONFIG_POSIX_MQUEUE_SYSCTL=3Dy
> > # CONFIG_WATCH_QUEUE is not set
> > CONFIG_CROSS_MEMORY_ATTACH=3Dy
> > # CONFIG_USELIB is not set
> > # CONFIG_AUDIT is not set
> > CONFIG_HAVE_ARCH_AUDITSYSCALL=3Dy
> >=20
> > #
> > # IRQ subsystem
> > #
> > CONFIG_GENERIC_IRQ_PROBE=3Dy
> > CONFIG_GENERIC_IRQ_SHOW=3Dy
> > CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=3Dy
> > CONFIG_GENERIC_PENDING_IRQ=3Dy
> > CONFIG_GENERIC_IRQ_MIGRATION=3Dy
> > CONFIG_HARDIRQS_SW_RESEND=3Dy
> > CONFIG_IRQ_DOMAIN=3Dy
> > CONFIG_IRQ_DOMAIN_HIERARCHY=3Dy
> > CONFIG_GENERIC_MSI_IRQ=3Dy
> > CONFIG_GENERIC_MSI_IRQ_DOMAIN=3Dy
> > CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR=3Dy
> > CONFIG_GENERIC_IRQ_RESERVATION_MODE=3Dy
> > CONFIG_IRQ_FORCED_THREADING=3Dy
> > CONFIG_SPARSE_IRQ=3Dy
> > # CONFIG_GENERIC_IRQ_DEBUGFS is not set
> > # end of IRQ subsystem
> >=20
> > CONFIG_CLOCKSOURCE_WATCHDOG=3Dy
> > CONFIG_ARCH_CLOCKSOURCE_INIT=3Dy
> > CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE=3Dy
> > CONFIG_GENERIC_TIME_VSYSCALL=3Dy
> > CONFIG_GENERIC_CLOCKEVENTS=3Dy
> > CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=3Dy
> > CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST=3Dy
> > CONFIG_GENERIC_CMOS_UPDATE=3Dy
> > CONFIG_HAVE_POSIX_CPU_TIMERS_TASK_WORK=3Dy
> > CONFIG_POSIX_CPU_TIMERS_TASK_WORK=3Dy
> > CONFIG_CONTEXT_TRACKING=3Dy
> > CONFIG_CONTEXT_TRACKING_IDLE=3Dy
> >=20
> > #
> > # Timers subsystem
> > #
> > CONFIG_TICK_ONESHOT=3Dy
> > CONFIG_NO_HZ_COMMON=3Dy
> > # CONFIG_HZ_PERIODIC is not set
> > CONFIG_NO_HZ_IDLE=3Dy
> > # CONFIG_NO_HZ_FULL is not set
> > CONFIG_NO_HZ=3Dy
> > CONFIG_HIGH_RES_TIMERS=3Dy
> > CONFIG_CLOCKSOURCE_WATCHDOG_MAX_SKEW_US=3D100
> > # end of Timers subsystem
> >=20
> > CONFIG_BPF=3Dy
> > CONFIG_HAVE_EBPF_JIT=3Dy
> > CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=3Dy
> >=20
> > #
> > # BPF subsystem
> > #
> > # CONFIG_BPF_SYSCALL is not set
> > # end of BPF subsystem
> >=20
> > CONFIG_PREEMPT_BUILD=3Dy
> > CONFIG_PREEMPT_NONE=3Dy
> > # CONFIG_PREEMPT_VOLUNTARY is not set
> > # CONFIG_PREEMPT is not set
> > CONFIG_PREEMPT_COUNT=3Dy
> > CONFIG_PREEMPTION=3Dy
> > CONFIG_PREEMPT_DYNAMIC=3Dy
> > # CONFIG_SCHED_CORE is not set
> >=20
> > #
> > # CPU/Task time and stats accounting
> > #
> > CONFIG_TICK_CPU_ACCOUNTING=3Dy
> > # CONFIG_VIRT_CPU_ACCOUNTING_GEN is not set
> > # CONFIG_IRQ_TIME_ACCOUNTING is not set
> > # CONFIG_BSD_PROCESS_ACCT is not set
> > # CONFIG_TASKSTATS is not set
> > # CONFIG_PSI is not set
> > # end of CPU/Task time and stats accounting
> >=20
> > CONFIG_CPU_ISOLATION=3Dy
> >=20
> > #
> > # RCU Subsystem
> > #
> > CONFIG_TREE_RCU=3Dy
> > CONFIG_PREEMPT_RCU=3Dy
> > # CONFIG_RCU_EXPERT is not set
> > CONFIG_SRCU=3Dy
> > CONFIG_TREE_SRCU=3Dy
> > CONFIG_TASKS_RCU_GENERIC=3Dy
> > CONFIG_TASKS_RCU=3Dy
> > CONFIG_RCU_STALL_COMMON=3Dy
> > CONFIG_RCU_NEED_SEGCBLIST=3Dy
> > # end of RCU Subsystem
> >=20
> > CONFIG_IKCONFIG=3Dy
> > CONFIG_IKCONFIG_PROC=3Dy
> > # CONFIG_IKHEADERS is not set
> > CONFIG_LOG_BUF_SHIFT=3D17
> > CONFIG_LOG_CPU_MAX_BUF_SHIFT=3D12
> > CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=3D13
> > # CONFIG_PRINTK_INDEX is not set
> > CONFIG_HAVE_UNSTABLE_SCHED_CLOCK=3Dy
> >=20
> > #
> > # Scheduler features
> > #
> > # CONFIG_UCLAMP_TASK is not set
> > # end of Scheduler features
> >=20
> > CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=3Dy
> > CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=3Dy
> > CONFIG_CC_HAS_INT128=3Dy
> > CONFIG_CC_IMPLICIT_FALLTHROUGH=3D"-Wimplicit-fallthrough=3D5"
> > CONFIG_GCC12_NO_ARRAY_BOUNDS=3Dy
> > CONFIG_CC_NO_ARRAY_BOUNDS=3Dy
> > CONFIG_ARCH_SUPPORTS_INT128=3Dy
> > # CONFIG_NUMA_BALANCING is not set
> > CONFIG_CGROUPS=3Dy
> > # CONFIG_CGROUP_FAVOR_DYNMODS is not set
> > # CONFIG_MEMCG is not set
> > # CONFIG_BLK_CGROUP is not set
> > # CONFIG_CGROUP_SCHED is not set
> > # CONFIG_CGROUP_PIDS is not set
> > # CONFIG_CGROUP_RDMA is not set
> > # CONFIG_CGROUP_FREEZER is not set
> > # CONFIG_CPUSETS is not set
> > # CONFIG_CGROUP_DEVICE is not set
> > # CONFIG_CGROUP_CPUACCT is not set
> > # CONFIG_CGROUP_PERF is not set
> > # CONFIG_CGROUP_MISC is not set
> > # CONFIG_CGROUP_DEBUG is not set
> > CONFIG_NAMESPACES=3Dy
> > CONFIG_UTS_NS=3Dy
> > CONFIG_TIME_NS=3Dy
> > CONFIG_IPC_NS=3Dy
> > CONFIG_USER_NS=3Dy
> > CONFIG_PID_NS=3Dy
> > CONFIG_NET_NS=3Dy
> > # CONFIG_CHECKPOINT_RESTORE is not set
> > # CONFIG_SCHED_AUTOGROUP is not set
> > # CONFIG_SYSFS_DEPRECATED is not set
> > # CONFIG_RELAY is not set
> > CONFIG_BLK_DEV_INITRD=3Dy
> > CONFIG_INITRAMFS_SOURCE=3D""
> > CONFIG_RD_GZIP=3Dy
> > CONFIG_RD_BZIP2=3Dy
> > CONFIG_RD_LZMA=3Dy
> > CONFIG_RD_XZ=3Dy
> > CONFIG_RD_LZO=3Dy
> > CONFIG_RD_LZ4=3Dy
> > CONFIG_RD_ZSTD=3Dy
> > # CONFIG_BOOT_CONFIG is not set
> > CONFIG_INITRAMFS_PRESERVE_MTIME=3Dy
> > CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=3Dy
> > # CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
> > CONFIG_LD_ORPHAN_WARN=3Dy
> > CONFIG_SYSCTL=3Dy
> > CONFIG_HAVE_UID16=3Dy
> > CONFIG_SYSCTL_EXCEPTION_TRACE=3Dy
> > CONFIG_HAVE_PCSPKR_PLATFORM=3Dy
> > # CONFIG_EXPERT is not set
> > CONFIG_UID16=3Dy
> > CONFIG_MULTIUSER=3Dy
> > CONFIG_SGETMASK_SYSCALL=3Dy
> > CONFIG_SYSFS_SYSCALL=3Dy
> > CONFIG_FHANDLE=3Dy
> > CONFIG_POSIX_TIMERS=3Dy
> > CONFIG_PRINTK=3Dy
> > CONFIG_BUG=3Dy
> > CONFIG_ELF_CORE=3Dy
> > CONFIG_PCSPKR_PLATFORM=3Dy
> > CONFIG_BASE_FULL=3Dy
> > CONFIG_FUTEX=3Dy
> > CONFIG_FUTEX_PI=3Dy
> > CONFIG_EPOLL=3Dy
> > CONFIG_SIGNALFD=3Dy
> > CONFIG_TIMERFD=3Dy
> > CONFIG_EVENTFD=3Dy
> > CONFIG_SHMEM=3Dy
> > CONFIG_AIO=3Dy
> > CONFIG_IO_URING=3Dy
> > CONFIG_ADVISE_SYSCALLS=3Dy
> > CONFIG_MEMBARRIER=3Dy
> > CONFIG_KALLSYMS=3Dy
> > CONFIG_KALLSYMS_ALL=3Dy
> > CONFIG_KALLSYMS_ABSOLUTE_PERCPU=3Dy
> > CONFIG_KALLSYMS_BASE_RELATIVE=3Dy
> > CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=3Dy
> > CONFIG_RSEQ=3Dy
> > # CONFIG_EMBEDDED is not set
> > CONFIG_HAVE_PERF_EVENTS=3Dy
> >=20
> > #
> > # Kernel Performance Events And Counters
> > #
> > CONFIG_PERF_EVENTS=3Dy
> > # CONFIG_DEBUG_PERF_USE_VMALLOC is not set
> > # end of Kernel Performance Events And Counters
> >=20
> > CONFIG_SYSTEM_DATA_VERIFICATION=3Dy
> > # CONFIG_PROFILING is not set
> > CONFIG_TRACEPOINTS=3Dy
> > # end of General setup
> >=20
> > CONFIG_64BIT=3Dy
> > CONFIG_X86_64=3Dy
> > CONFIG_X86=3Dy
> > CONFIG_INSTRUCTION_DECODER=3Dy
> > CONFIG_OUTPUT_FORMAT=3D"elf64-x86-64"
> > CONFIG_LOCKDEP_SUPPORT=3Dy
> > CONFIG_STACKTRACE_SUPPORT=3Dy
> > CONFIG_MMU=3Dy
> > CONFIG_ARCH_MMAP_RND_BITS_MIN=3D28
> > CONFIG_ARCH_MMAP_RND_BITS_MAX=3D32
> > CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=3D8
> > CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=3D16
> > CONFIG_GENERIC_ISA_DMA=3Dy
> > CONFIG_GENERIC_CSUM=3Dy
> > CONFIG_GENERIC_BUG=3Dy
> > CONFIG_GENERIC_BUG_RELATIVE_POINTERS=3Dy
> > CONFIG_ARCH_MAY_HAVE_PC_FDC=3Dy
> > CONFIG_GENERIC_CALIBRATE_DELAY=3Dy
> > CONFIG_ARCH_HAS_CPU_RELAX=3Dy
> > CONFIG_ARCH_HIBERNATION_POSSIBLE=3Dy
> > CONFIG_ARCH_NR_GPIO=3D1024
> > CONFIG_ARCH_SUSPEND_POSSIBLE=3Dy
> > CONFIG_AUDIT_ARCH=3Dy
> > CONFIG_KASAN_SHADOW_OFFSET=3D0xdffffc0000000000
> > CONFIG_X86_64_SMP=3Dy
> > CONFIG_ARCH_SUPPORTS_UPROBES=3Dy
> > CONFIG_FIX_EARLYCON_MEM=3Dy
> > CONFIG_PGTABLE_LEVELS=3D5
> > CONFIG_CC_HAS_SANE_STACKPROTECTOR=3Dy
> >=20
> > #
> > # Processor type and features
> > #
> > CONFIG_SMP=3Dy
> > CONFIG_X86_FEATURE_NAMES=3Dy
> > CONFIG_X86_X2APIC=3Dy
> > CONFIG_X86_MPPARSE=3Dy
> > # CONFIG_GOLDFISH is not set
> > # CONFIG_X86_CPU_RESCTRL is not set
> > # CONFIG_X86_EXTENDED_PLATFORM is not set
> > # CONFIG_X86_INTEL_LPSS is not set
> > # CONFIG_X86_AMD_PLATFORM_DEVICE is not set
> > # CONFIG_IOSF_MBI is not set
> > CONFIG_X86_SUPPORTS_MEMORY_FAILURE=3Dy
> > CONFIG_SCHED_OMIT_FRAME_POINTER=3Dy
> > CONFIG_HYPERVISOR_GUEST=3Dy
> > CONFIG_PARAVIRT=3Dy
> > # CONFIG_PARAVIRT_DEBUG is not set
> > # CONFIG_PARAVIRT_SPINLOCKS is not set
> > CONFIG_X86_HV_CALLBACK_VECTOR=3Dy
> > # CONFIG_XEN is not set
> > CONFIG_KVM_GUEST=3Dy
> > CONFIG_ARCH_CPUIDLE_HALTPOLL=3Dy
> > # CONFIG_PVH is not set
> > # CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
> > CONFIG_PARAVIRT_CLOCK=3Dy
> > # CONFIG_JAILHOUSE_GUEST is not set
> > # CONFIG_ACRN_GUEST is not set
> > # CONFIG_INTEL_TDX_GUEST is not set
> > # CONFIG_MK8 is not set
> > # CONFIG_MPSC is not set
> > CONFIG_MCORE2=3Dy
> > # CONFIG_MATOM is not set
> > # CONFIG_GENERIC_CPU is not set
> > CONFIG_X86_INTERNODE_CACHE_SHIFT=3D6
> > CONFIG_X86_L1_CACHE_SHIFT=3D6
> > CONFIG_X86_INTEL_USERCOPY=3Dy
> > CONFIG_X86_USE_PPRO_CHECKSUM=3Dy
> > CONFIG_X86_P6_NOP=3Dy
> > CONFIG_X86_TSC=3Dy
> > CONFIG_X86_CMPXCHG64=3Dy
> > CONFIG_X86_CMOV=3Dy
> > CONFIG_X86_MINIMUM_CPU_FAMILY=3D64
> > CONFIG_X86_DEBUGCTLMSR=3Dy
> > CONFIG_IA32_FEAT_CTL=3Dy
> > CONFIG_X86_VMX_FEATURE_NAMES=3Dy
> > CONFIG_CPU_SUP_INTEL=3Dy
> > CONFIG_CPU_SUP_AMD=3Dy
> > CONFIG_CPU_SUP_HYGON=3Dy
> > CONFIG_CPU_SUP_CENTAUR=3Dy
> > CONFIG_CPU_SUP_ZHAOXIN=3Dy
> > CONFIG_HPET_TIMER=3Dy
> > CONFIG_DMI=3Dy
> > # CONFIG_GART_IOMMU is not set
> > # CONFIG_MAXSMP is not set
> > CONFIG_NR_CPUS_RANGE_BEGIN=3D2
> > CONFIG_NR_CPUS_RANGE_END=3D512
> > CONFIG_NR_CPUS_DEFAULT=3D64
> > CONFIG_NR_CPUS=3D48
> > CONFIG_SCHED_CLUSTER=3Dy
> > CONFIG_SCHED_SMT=3Dy
> > CONFIG_SCHED_MC=3Dy
> > CONFIG_SCHED_MC_PRIO=3Dy
> > CONFIG_X86_LOCAL_APIC=3Dy
> > CONFIG_X86_IO_APIC=3Dy
> > # CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS is not set
> > CONFIG_X86_MCE=3Dy
> > # CONFIG_X86_MCELOG_LEGACY is not set
> > CONFIG_X86_MCE_INTEL=3Dy
> > CONFIG_X86_MCE_AMD=3Dy
> > CONFIG_X86_MCE_THRESHOLD=3Dy
> > # CONFIG_X86_MCE_INJECT is not set
> >=20
> > #
> > # Performance monitoring
> > #
> > CONFIG_PERF_EVENTS_INTEL_UNCORE=3Dy
> > CONFIG_PERF_EVENTS_INTEL_RAPL=3Dy
> > CONFIG_PERF_EVENTS_INTEL_CSTATE=3Dy
> > # CONFIG_PERF_EVENTS_AMD_POWER is not set
> > CONFIG_PERF_EVENTS_AMD_UNCORE=3Dy
> > # CONFIG_PERF_EVENTS_AMD_BRS is not set
> > # end of Performance monitoring
> >=20
> > CONFIG_X86_16BIT=3Dy
> > CONFIG_X86_ESPFIX64=3Dy
> > CONFIG_X86_VSYSCALL_EMULATION=3Dy
> > CONFIG_X86_IOPL_IOPERM=3Dy
> > # CONFIG_MICROCODE is not set
> > # CONFIG_X86_MSR is not set
> > # CONFIG_X86_CPUID is not set
> > CONFIG_X86_5LEVEL=3Dy
> > CONFIG_X86_DIRECT_GBPAGES=3Dy
> > # CONFIG_X86_CPA_STATISTICS is not set
> > # CONFIG_AMD_MEM_ENCRYPT is not set
> > CONFIG_NUMA=3Dy
> > CONFIG_AMD_NUMA=3Dy
> > CONFIG_X86_64_ACPI_NUMA=3Dy
> > # CONFIG_NUMA_EMU is not set
> > CONFIG_NODES_SHIFT=3D6
> > CONFIG_ARCH_SPARSEMEM_ENABLE=3Dy
> > CONFIG_ARCH_SPARSEMEM_DEFAULT=3Dy
> > CONFIG_ILLEGAL_POINTER_VALUE=3D0xdead000000000000
> > # CONFIG_X86_PMEM_LEGACY is not set
> > # CONFIG_X86_CHECK_BIOS_CORRUPTION is not set
> > CONFIG_MTRR=3Dy
> > CONFIG_MTRR_SANITIZER=3Dy
> > CONFIG_MTRR_SANITIZER_ENABLE_DEFAULT=3D0
> > CONFIG_MTRR_SANITIZER_SPARE_REG_NR_DEFAULT=3D1
> > CONFIG_X86_PAT=3Dy
> > CONFIG_ARCH_USES_PG_UNCACHED=3Dy
> > CONFIG_X86_UMIP=3Dy
> > CONFIG_CC_HAS_IBT=3Dy
> > # CONFIG_X86_KERNEL_IBT is not set
> > CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=3Dy
> > CONFIG_X86_INTEL_TSX_MODE_OFF=3Dy
> > # CONFIG_X86_INTEL_TSX_MODE_ON is not set
> > # CONFIG_X86_INTEL_TSX_MODE_AUTO is not set
> > # CONFIG_X86_SGX is not set
> > # CONFIG_EFI is not set
> > # CONFIG_HZ_100 is not set
> > # CONFIG_HZ_250 is not set
> > CONFIG_HZ_300=3Dy
> > # CONFIG_HZ_1000 is not set
> > CONFIG_HZ=3D300
> > CONFIG_SCHED_HRTICK=3Dy
> > # CONFIG_KEXEC is not set
> > # CONFIG_KEXEC_FILE is not set
> > # CONFIG_CRASH_DUMP is not set
> > CONFIG_PHYSICAL_START=3D0x1000000
> > CONFIG_RELOCATABLE=3Dy
> > # CONFIG_RANDOMIZE_BASE is not set
> > CONFIG_PHYSICAL_ALIGN=3D0x200000
> > CONFIG_DYNAMIC_MEMORY_LAYOUT=3Dy
> > CONFIG_HOTPLUG_CPU=3Dy
> > # CONFIG_BOOTPARAM_HOTPLUG_CPU0 is not set
> > # CONFIG_DEBUG_HOTPLUG_CPU0 is not set
> > # CONFIG_COMPAT_VDSO is not set
> > CONFIG_LEGACY_VSYSCALL_XONLY=3Dy
> > # CONFIG_LEGACY_VSYSCALL_NONE is not set
> > # CONFIG_CMDLINE_BOOL is not set
> > CONFIG_MODIFY_LDT_SYSCALL=3Dy
> > # CONFIG_STRICT_SIGALTSTACK_SIZE is not set
> > CONFIG_HAVE_LIVEPATCH=3Dy
> > # end of Processor type and features
> >=20
> > CONFIG_CC_HAS_SLS=3Dy
> > CONFIG_CC_HAS_RETURN_THUNK=3Dy
> > CONFIG_SPECULATION_MITIGATIONS=3Dy
> > # CONFIG_PAGE_TABLE_ISOLATION is not set
> > # CONFIG_RETPOLINE is not set
> > CONFIG_CPU_IBPB_ENTRY=3Dy
> > CONFIG_CPU_IBRS_ENTRY=3Dy
> > # CONFIG_SLS is not set
> > CONFIG_ARCH_HAS_ADD_PAGES=3Dy
> > CONFIG_ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE=3Dy
> >=20
> > #
> > # Power management and ACPI options
> > #
> > # CONFIG_SUSPEND is not set
> > # CONFIG_HIBERNATION is not set
> > # CONFIG_PM is not set
> > # CONFIG_ENERGY_MODEL is not set
> > CONFIG_ARCH_SUPPORTS_ACPI=3Dy
> > CONFIG_ACPI=3Dy
> > CONFIG_ACPI_LEGACY_TABLES_LOOKUP=3Dy
> > CONFIG_ARCH_MIGHT_HAVE_ACPI_PDC=3Dy
> > CONFIG_ACPI_SYSTEM_POWER_STATES_SUPPORT=3Dy
> > # CONFIG_ACPI_DEBUGGER is not set
> > CONFIG_ACPI_SPCR_TABLE=3Dy
> > # CONFIG_ACPI_FPDT is not set
> > CONFIG_ACPI_LPIT=3Dy
> > # CONFIG_ACPI_REV_OVERRIDE_POSSIBLE is not set
> > # CONFIG_ACPI_EC_DEBUGFS is not set
> > CONFIG_ACPI_AC=3Dy
> > CONFIG_ACPI_BATTERY=3Dy
> > CONFIG_ACPI_BUTTON=3Dy
> > CONFIG_ACPI_FAN=3Dy
> > # CONFIG_ACPI_DOCK is not set
> > CONFIG_ACPI_CPU_FREQ_PSS=3Dy
> > CONFIG_ACPI_PROCESSOR_CSTATE=3Dy
> > CONFIG_ACPI_PROCESSOR_IDLE=3Dy
> > CONFIG_ACPI_CPPC_LIB=3Dy
> > CONFIG_ACPI_PROCESSOR=3Dy
> > CONFIG_ACPI_HOTPLUG_CPU=3Dy
> > # CONFIG_ACPI_PROCESSOR_AGGREGATOR is not set
> > CONFIG_ACPI_THERMAL=3Dy
> > CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=3Dy
> > # CONFIG_ACPI_TABLE_UPGRADE is not set
> > # CONFIG_ACPI_DEBUG is not set
> > # CONFIG_ACPI_PCI_SLOT is not set
> > CONFIG_ACPI_CONTAINER=3Dy
> > CONFIG_ACPI_HOTPLUG_IOAPIC=3Dy
> > # CONFIG_ACPI_SBS is not set
> > # CONFIG_ACPI_HED is not set
> > # CONFIG_ACPI_CUSTOM_METHOD is not set
> > # CONFIG_ACPI_NFIT is not set
> > CONFIG_ACPI_NUMA=3Dy
> > # CONFIG_ACPI_HMAT is not set
> > CONFIG_HAVE_ACPI_APEI=3Dy
> > CONFIG_HAVE_ACPI_APEI_NMI=3Dy
> > # CONFIG_ACPI_APEI is not set
> > # CONFIG_ACPI_DPTF is not set
> > # CONFIG_ACPI_CONFIGFS is not set
> > # CONFIG_ACPI_PFRUT is not set
> > CONFIG_ACPI_PCC=3Dy
> > # CONFIG_PMIC_OPREGION is not set
> > CONFIG_X86_PM_TIMER=3Dy
> >=20
> > #
> > # CPU Frequency scaling
> > #
> > CONFIG_CPU_FREQ=3Dy
> > CONFIG_CPU_FREQ_GOV_ATTR_SET=3Dy
> > # CONFIG_CPU_FREQ_STAT is not set
> > # CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE is not set
> > # CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
> > # CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
> > CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL=3Dy
> > CONFIG_CPU_FREQ_GOV_PERFORMANCE=3Dy
> > # CONFIG_CPU_FREQ_GOV_POWERSAVE is not set
> > # CONFIG_CPU_FREQ_GOV_USERSPACE is not set
> > # CONFIG_CPU_FREQ_GOV_ONDEMAND is not set
> > # CONFIG_CPU_FREQ_GOV_CONSERVATIVE is not set
> > CONFIG_CPU_FREQ_GOV_SCHEDUTIL=3Dy
> >=20
> > #
> > # CPU frequency scaling drivers
> > #
> > CONFIG_X86_INTEL_PSTATE=3Dy
> > # CONFIG_X86_PCC_CPUFREQ is not set
> > # CONFIG_X86_AMD_PSTATE is not set
> > # CONFIG_X86_AMD_PSTATE_UT is not set
> > # CONFIG_X86_ACPI_CPUFREQ is not set
> > # CONFIG_X86_SPEEDSTEP_CENTRINO is not set
> > # CONFIG_X86_P4_CLOCKMOD is not set
> >=20
> > #
> > # shared options
> > #
> > # end of CPU Frequency scaling
> >=20
> > #
> > # CPU Idle
> > #
> > CONFIG_CPU_IDLE=3Dy
> > # CONFIG_CPU_IDLE_GOV_LADDER is not set
> > CONFIG_CPU_IDLE_GOV_MENU=3Dy
> > # CONFIG_CPU_IDLE_GOV_TEO is not set
> > # CONFIG_CPU_IDLE_GOV_HALTPOLL is not set
> > CONFIG_HALTPOLL_CPUIDLE=3Dy
> > # end of CPU Idle
> >=20
> > # CONFIG_INTEL_IDLE is not set
> > # end of Power management and ACPI options
> >=20
> > #
> > # Bus options (PCI etc.)
> > #
> > CONFIG_PCI_DIRECT=3Dy
> > CONFIG_PCI_MMCONFIG=3Dy
> > CONFIG_MMCONF_FAM10H=3Dy
> > CONFIG_ISA_DMA_API=3Dy
> > CONFIG_AMD_NB=3Dy
> > # end of Bus options (PCI etc.)
> >=20
> > #
> > # Binary Emulations
> > #
> > CONFIG_IA32_EMULATION=3Dy
> > # CONFIG_X86_X32_ABI is not set
> > CONFIG_COMPAT_32=3Dy
> > CONFIG_COMPAT=3Dy
> > CONFIG_COMPAT_FOR_U64_ALIGNMENT=3Dy
> > # end of Binary Emulations
> >=20
> > CONFIG_HAVE_KVM=3Dy
> > CONFIG_VIRTUALIZATION=3Dy
> > # CONFIG_KVM is not set
> > CONFIG_AS_AVX512=3Dy
> > CONFIG_AS_SHA1_NI=3Dy
> > CONFIG_AS_SHA256_NI=3Dy
> > CONFIG_AS_TPAUSE=3Dy
> >=20
> > #
> > # General architecture-dependent options
> > #
> > CONFIG_HOTPLUG_SMT=3Dy
> > CONFIG_GENERIC_ENTRY=3Dy
> > CONFIG_JUMP_LABEL=3Dy
> > # CONFIG_STATIC_KEYS_SELFTEST is not set
> > # CONFIG_STATIC_CALL_SELFTEST is not set
> > CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=3Dy
> > CONFIG_ARCH_USE_BUILTIN_BSWAP=3Dy
> > CONFIG_HAVE_IOREMAP_PROT=3Dy
> > CONFIG_HAVE_KPROBES=3Dy
> > CONFIG_HAVE_KRETPROBES=3Dy
> > CONFIG_HAVE_OPTPROBES=3Dy
> > CONFIG_HAVE_KPROBES_ON_FTRACE=3Dy
> > CONFIG_ARCH_CORRECT_STACKTRACE_ON_KRETPROBE=3Dy
> > CONFIG_HAVE_FUNCTION_ERROR_INJECTION=3Dy
> > CONFIG_HAVE_NMI=3Dy
> > CONFIG_TRACE_IRQFLAGS_SUPPORT=3Dy
> > CONFIG_TRACE_IRQFLAGS_NMI_SUPPORT=3Dy
> > CONFIG_HAVE_ARCH_TRACEHOOK=3Dy
> > CONFIG_HAVE_DMA_CONTIGUOUS=3Dy
> > CONFIG_GENERIC_SMP_IDLE_THREAD=3Dy
> > CONFIG_ARCH_HAS_FORTIFY_SOURCE=3Dy
> > CONFIG_ARCH_HAS_SET_MEMORY=3Dy
> > CONFIG_ARCH_HAS_SET_DIRECT_MAP=3Dy
> > CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=3Dy
> > CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT=3Dy
> > CONFIG_ARCH_WANTS_NO_INSTR=3Dy
> > CONFIG_HAVE_ASM_MODVERSIONS=3Dy
> > CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=3Dy
> > CONFIG_HAVE_RSEQ=3Dy
> > CONFIG_HAVE_RUST=3Dy
> > CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=3Dy
> > CONFIG_HAVE_HW_BREAKPOINT=3Dy
> > CONFIG_HAVE_MIXED_BREAKPOINTS_REGS=3Dy
> > CONFIG_HAVE_USER_RETURN_NOTIFIER=3Dy
> > CONFIG_HAVE_PERF_EVENTS_NMI=3Dy
> > CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=3Dy
> > CONFIG_HAVE_PERF_REGS=3Dy
> > CONFIG_HAVE_PERF_USER_STACK_DUMP=3Dy
> > CONFIG_HAVE_ARCH_JUMP_LABEL=3Dy
> > CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=3Dy
> > CONFIG_MMU_GATHER_TABLE_FREE=3Dy
> > CONFIG_MMU_GATHER_RCU_TABLE_FREE=3Dy
> > CONFIG_MMU_GATHER_MERGE_VMAS=3Dy
> > CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=3Dy
> > CONFIG_HAVE_ALIGNED_STRUCT_PAGE=3Dy
> > CONFIG_HAVE_CMPXCHG_LOCAL=3Dy
> > CONFIG_HAVE_CMPXCHG_DOUBLE=3Dy
> > CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=3Dy
> > CONFIG_ARCH_WANT_OLD_COMPAT_IPC=3Dy
> > CONFIG_HAVE_ARCH_SECCOMP=3Dy
> > CONFIG_HAVE_ARCH_SECCOMP_FILTER=3Dy
> > CONFIG_SECCOMP=3Dy
> > CONFIG_SECCOMP_FILTER=3Dy
> > # CONFIG_SECCOMP_CACHE_DEBUG is not set
> > CONFIG_HAVE_ARCH_STACKLEAK=3Dy
> > CONFIG_HAVE_STACKPROTECTOR=3Dy
> > CONFIG_STACKPROTECTOR=3Dy
> > CONFIG_STACKPROTECTOR_STRONG=3Dy
> > CONFIG_ARCH_SUPPORTS_LTO_CLANG=3Dy
> > CONFIG_ARCH_SUPPORTS_LTO_CLANG_THIN=3Dy
> > CONFIG_LTO_NONE=3Dy
> > CONFIG_ARCH_SUPPORTS_CFI_CLANG=3Dy
> > CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES=3Dy
> > CONFIG_HAVE_CONTEXT_TRACKING_USER=3Dy
> > CONFIG_HAVE_CONTEXT_TRACKING_USER_OFFSTACK=3Dy
> > CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=3Dy
> > CONFIG_HAVE_IRQ_TIME_ACCOUNTING=3Dy
> > CONFIG_HAVE_MOVE_PUD=3Dy
> > CONFIG_HAVE_MOVE_PMD=3Dy
> > CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=3Dy
> > CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD=3Dy
> > CONFIG_HAVE_ARCH_HUGE_VMAP=3Dy
> > CONFIG_HAVE_ARCH_HUGE_VMALLOC=3Dy
> > CONFIG_ARCH_WANT_HUGE_PMD_SHARE=3Dy
> > CONFIG_HAVE_ARCH_SOFT_DIRTY=3Dy
> > CONFIG_HAVE_MOD_ARCH_SPECIFIC=3Dy
> > CONFIG_MODULES_USE_ELF_RELA=3Dy
> > CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK=3Dy
> > CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK=3Dy
> > CONFIG_SOFTIRQ_ON_OWN_STACK=3Dy
> > CONFIG_ARCH_HAS_ELF_RANDOMIZE=3Dy
> > CONFIG_HAVE_ARCH_MMAP_RND_BITS=3Dy
> > CONFIG_HAVE_EXIT_THREAD=3Dy
> > CONFIG_ARCH_MMAP_RND_BITS=3D28
> > CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=3Dy
> > CONFIG_ARCH_MMAP_RND_COMPAT_BITS=3D8
> > CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES=3Dy
> > CONFIG_PAGE_SIZE_LESS_THAN_64KB=3Dy
> > CONFIG_PAGE_SIZE_LESS_THAN_256KB=3Dy
> > CONFIG_HAVE_OBJTOOL=3Dy
> > CONFIG_HAVE_JUMP_LABEL_HACK=3Dy
> > CONFIG_HAVE_NOINSTR_HACK=3Dy
> > CONFIG_HAVE_NOINSTR_VALIDATION=3Dy
> > CONFIG_HAVE_UACCESS_VALIDATION=3Dy
> > CONFIG_HAVE_STACK_VALIDATION=3Dy
> > CONFIG_OLD_SIGSUSPEND3=3Dy
> > CONFIG_COMPAT_OLD_SIGACTION=3Dy
> > CONFIG_COMPAT_32BIT_TIME=3Dy
> > CONFIG_HAVE_ARCH_VMAP_STACK=3Dy
> > CONFIG_VMAP_STACK=3Dy
> > CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=3Dy
> > CONFIG_RANDOMIZE_KSTACK_OFFSET=3Dy
> > # CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set
> > CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=3Dy
> > CONFIG_STRICT_KERNEL_RWX=3Dy
> > CONFIG_ARCH_HAS_STRICT_MODULE_RWX=3Dy
> > CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=3Dy
> > # CONFIG_LOCK_EVENT_COUNTS is not set
> > CONFIG_ARCH_HAS_MEM_ENCRYPT=3Dy
> > CONFIG_HAVE_STATIC_CALL=3Dy
> > CONFIG_HAVE_STATIC_CALL_INLINE=3Dy
> > CONFIG_HAVE_PREEMPT_DYNAMIC=3Dy
> > CONFIG_HAVE_PREEMPT_DYNAMIC_CALL=3Dy
> > CONFIG_ARCH_WANT_LD_ORPHAN_WARN=3Dy
> > CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=3Dy
> > CONFIG_ARCH_SUPPORTS_PAGE_TABLE_CHECK=3Dy
> > CONFIG_ARCH_HAS_ELFCORE_COMPAT=3Dy
> > CONFIG_ARCH_HAS_PARANOID_L1D_FLUSH=3Dy
> > CONFIG_DYNAMIC_SIGFRAME=3Dy
> > CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG=3Dy
> >=20
> > #
> > # GCOV-based kernel profiling
> > #
> > # CONFIG_GCOV_KERNEL is not set
> > CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=3Dy
> > # end of GCOV-based kernel profiling
> >=20
> > CONFIG_HAVE_GCC_PLUGINS=3Dy
> > CONFIG_GCC_PLUGINS=3Dy
> > # CONFIG_GCC_PLUGIN_LATENT_ENTROPY is not set
> > # end of General architecture-dependent options
> >=20
> > CONFIG_RT_MUTEXES=3Dy
> > CONFIG_BASE_SMALL=3D0
> > # CONFIG_MODULES is not set
> > CONFIG_BLOCK=3Dy
> > CONFIG_BLOCK_LEGACY_AUTOLOAD=3Dy
> > # CONFIG_BLK_DEV_BSGLIB is not set
> > # CONFIG_BLK_DEV_INTEGRITY is not set
> > # CONFIG_BLK_DEV_ZONED is not set
> > # CONFIG_BLK_WBT is not set
> > CONFIG_BLK_DEBUG_FS=3Dy
> > # CONFIG_BLK_SED_OPAL is not set
> > # CONFIG_BLK_INLINE_ENCRYPTION is not set
> >=20
> > #
> > # Partition Types
> > #
> > # CONFIG_PARTITION_ADVANCED is not set
> > CONFIG_MSDOS_PARTITION=3Dy
> > CONFIG_EFI_PARTITION=3Dy
> > # end of Partition Types
> >=20
> > CONFIG_BLOCK_COMPAT=3Dy
> > CONFIG_BLK_MQ_PCI=3Dy
> > CONFIG_BLK_MQ_VIRTIO=3Dy
> > CONFIG_BLOCK_HOLDER_DEPRECATED=3Dy
> > CONFIG_BLK_MQ_STACKING=3Dy
> >=20
> > #
> > # IO Schedulers
> > #
> > CONFIG_MQ_IOSCHED_DEADLINE=3Dy
> > CONFIG_MQ_IOSCHED_KYBER=3Dy
> > # CONFIG_IOSCHED_BFQ is not set
> > # end of IO Schedulers
> >=20
> > CONFIG_ASN1=3Dy
> > CONFIG_UNINLINE_SPIN_UNLOCK=3Dy
> > CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=3Dy
> > CONFIG_MUTEX_SPIN_ON_OWNER=3Dy
> > CONFIG_RWSEM_SPIN_ON_OWNER=3Dy
> > CONFIG_LOCK_SPIN_ON_OWNER=3Dy
> > CONFIG_ARCH_USE_QUEUED_SPINLOCKS=3Dy
> > CONFIG_QUEUED_SPINLOCKS=3Dy
> > CONFIG_ARCH_USE_QUEUED_RWLOCKS=3Dy
> > CONFIG_QUEUED_RWLOCKS=3Dy
> > CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE=3Dy
> > CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE=3Dy
> > CONFIG_ARCH_HAS_SYSCALL_WRAPPER=3Dy
> >=20
> > #
> > # Executable file formats
> > #
> > CONFIG_BINFMT_ELF=3Dy
> > CONFIG_COMPAT_BINFMT_ELF=3Dy
> > CONFIG_ELFCORE=3Dy
> > CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=3Dy
> > CONFIG_BINFMT_SCRIPT=3Dy
> > # CONFIG_BINFMT_MISC is not set
> > CONFIG_COREDUMP=3Dy
> > # end of Executable file formats
> >=20
> > #
> > # Memory Management options
> > #
> > CONFIG_SWAP=3Dy
> > # CONFIG_ZSWAP is not set
> >=20
> > #
> > # SLAB allocator options
> > #
> > # CONFIG_SLAB is not set
> > CONFIG_SLUB=3Dy
> > CONFIG_SLAB_MERGE_DEFAULT=3Dy
> > # CONFIG_SLAB_FREELIST_RANDOM is not set
> > # CONFIG_SLAB_FREELIST_HARDENED is not set
> > # CONFIG_SLUB_STATS is not set
> > CONFIG_SLUB_CPU_PARTIAL=3Dy
> > # end of SLAB allocator options
> >=20
> > # CONFIG_SHUFFLE_PAGE_ALLOCATOR is not set
> > # CONFIG_COMPAT_BRK is not set
> > CONFIG_SPARSEMEM=3Dy
> > CONFIG_SPARSEMEM_EXTREME=3Dy
> > CONFIG_SPARSEMEM_VMEMMAP_ENABLE=3Dy
> > CONFIG_SPARSEMEM_VMEMMAP=3Dy
> > CONFIG_HAVE_FAST_GUP=3Dy
> > CONFIG_EXCLUSIVE_SYSTEM_RAM=3Dy
> > CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=3Dy
> > # CONFIG_MEMORY_HOTPLUG is not set
> > CONFIG_SPLIT_PTLOCK_CPUS=3D4
> > CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=3Dy
> > CONFIG_COMPACTION=3Dy
> > CONFIG_COMPACT_UNEVICTABLE_DEFAULT=3D1
> > # CONFIG_PAGE_REPORTING is not set
> > CONFIG_MIGRATION=3Dy
> > CONFIG_PHYS_ADDR_T_64BIT=3Dy
> > # CONFIG_KSM is not set
> > CONFIG_DEFAULT_MMAP_MIN_ADDR=3D4096
> > CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=3Dy
> > # CONFIG_MEMORY_FAILURE is not set
> > CONFIG_ARCH_WANT_GENERAL_HUGETLB=3Dy
> > CONFIG_ARCH_WANTS_THP_SWAP=3Dy
> > # CONFIG_TRANSPARENT_HUGEPAGE is not set
> > CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=3Dy
> > CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=3Dy
> > CONFIG_USE_PERCPU_NUMA_NODE_ID=3Dy
> > CONFIG_HAVE_SETUP_PER_CPU_AREA=3Dy
> > # CONFIG_CMA is not set
> > CONFIG_GENERIC_EARLY_IOREMAP=3Dy
> > # CONFIG_DEFERRED_STRUCT_PAGE_INIT is not set
> > # CONFIG_IDLE_PAGE_TRACKING is not set
> > CONFIG_ARCH_HAS_CACHE_LINE_SIZE=3Dy
> > CONFIG_ARCH_HAS_CURRENT_STACK_POINTER=3Dy
> > CONFIG_ARCH_HAS_PTE_DEVMAP=3Dy
> > CONFIG_ZONE_DMA=3Dy
> > CONFIG_ZONE_DMA32=3Dy
> > CONFIG_ARCH_USES_HIGH_VMA_FLAGS=3Dy
> > CONFIG_ARCH_HAS_PKEYS=3Dy
> > CONFIG_VM_EVENT_COUNTERS=3Dy
> > # CONFIG_PERCPU_STATS is not set
> > # CONFIG_GUP_TEST is not set
> > CONFIG_ARCH_HAS_PTE_SPECIAL=3Dy
> > CONFIG_SECRETMEM=3Dy
> > # CONFIG_ANON_VMA_NAME is not set
> > # CONFIG_USERFAULTFD is not set
> > # CONFIG_LRU_GEN is not set
> >=20
> > #
> > # Data Access Monitoring
> > #
> > # CONFIG_DAMON is not set
> > # end of Data Access Monitoring
> > # end of Memory Management options
> >=20
> > CONFIG_NET=3Dy
> >=20
> > #
> > # Networking options
> > #
> > CONFIG_PACKET=3Dy
> > CONFIG_PACKET_DIAG=3Dy
> > CONFIG_UNIX=3Dy
> > CONFIG_UNIX_SCM=3Dy
> > CONFIG_AF_UNIX_OOB=3Dy
> > CONFIG_UNIX_DIAG=3Dy
> > # CONFIG_TLS is not set
> > # CONFIG_XFRM_USER is not set
> > # CONFIG_NET_KEY is not set
> > CONFIG_INET=3Dy
> > # CONFIG_IP_MULTICAST is not set
> > # CONFIG_IP_ADVANCED_ROUTER is not set
> > # CONFIG_IP_PNP is not set
> > # CONFIG_NET_IPIP is not set
> > # CONFIG_NET_IPGRE_DEMUX is not set
> > CONFIG_NET_IP_TUNNEL=3Dy
> > # CONFIG_SYN_COOKIES is not set
> > # CONFIG_NET_IPVTI is not set
> > # CONFIG_NET_FOU is not set
> > # CONFIG_NET_FOU_IP_TUNNELS is not set
> > # CONFIG_INET_AH is not set
> > # CONFIG_INET_ESP is not set
> > # CONFIG_INET_IPCOMP is not set
> > CONFIG_INET_TABLE_PERTURB_ORDER=3D16
> > CONFIG_INET_TUNNEL=3Dy
> > CONFIG_INET_DIAG=3Dy
> > CONFIG_INET_TCP_DIAG=3Dy
> > # CONFIG_INET_UDP_DIAG is not set
> > # CONFIG_INET_RAW_DIAG is not set
> > # CONFIG_INET_DIAG_DESTROY is not set
> > # CONFIG_TCP_CONG_ADVANCED is not set
> > CONFIG_TCP_CONG_CUBIC=3Dy
> > CONFIG_DEFAULT_TCP_CONG=3D"cubic"
> > # CONFIG_TCP_MD5SIG is not set
> > CONFIG_IPV6=3Dy
> > # CONFIG_IPV6_ROUTER_PREF is not set
> > # CONFIG_IPV6_OPTIMISTIC_DAD is not set
> > # CONFIG_INET6_AH is not set
> > # CONFIG_INET6_ESP is not set
> > # CONFIG_INET6_IPCOMP is not set
> > # CONFIG_IPV6_MIP6 is not set
> > # CONFIG_IPV6_VTI is not set
> > CONFIG_IPV6_SIT=3Dy
> > # CONFIG_IPV6_SIT_6RD is not set
> > CONFIG_IPV6_NDISC_NODETYPE=3Dy
> > # CONFIG_IPV6_TUNNEL is not set
> > # CONFIG_IPV6_MULTIPLE_TABLES is not set
> > # CONFIG_IPV6_MROUTE is not set
> > # CONFIG_IPV6_SEG6_LWTUNNEL is not set
> > # CONFIG_IPV6_SEG6_HMAC is not set
> > # CONFIG_IPV6_RPL_LWTUNNEL is not set
> > # CONFIG_IPV6_IOAM6_LWTUNNEL is not set
> > # CONFIG_MPTCP is not set
> > # CONFIG_NETWORK_SECMARK is not set
> > # CONFIG_NETWORK_PHY_TIMESTAMPING is not set
> > # CONFIG_NETFILTER is not set
> > # CONFIG_BPFILTER is not set
> > # CONFIG_IP_DCCP is not set
> > # CONFIG_IP_SCTP is not set
> > # CONFIG_RDS is not set
> > # CONFIG_TIPC is not set
> > # CONFIG_ATM is not set
> > # CONFIG_L2TP is not set
> > # CONFIG_BRIDGE is not set
> > # CONFIG_NET_DSA is not set
> > # CONFIG_VLAN_8021Q is not set
> > # CONFIG_LLC2 is not set
> > # CONFIG_ATALK is not set
> > # CONFIG_X25 is not set
> > # CONFIG_LAPB is not set
> > # CONFIG_PHONET is not set
> > # CONFIG_6LOWPAN is not set
> > # CONFIG_IEEE802154 is not set
> > # CONFIG_NET_SCHED is not set
> > # CONFIG_DCB is not set
> > # CONFIG_DNS_RESOLVER is not set
> > # CONFIG_BATMAN_ADV is not set
> > # CONFIG_OPENVSWITCH is not set
> > # CONFIG_VSOCKETS is not set
> > # CONFIG_NETLINK_DIAG is not set
> > # CONFIG_MPLS is not set
> > # CONFIG_NET_NSH is not set
> > # CONFIG_HSR is not set
> > # CONFIG_NET_SWITCHDEV is not set
> > # CONFIG_NET_L3_MASTER_DEV is not set
> > # CONFIG_QRTR is not set
> > # CONFIG_NET_NCSI is not set
> > CONFIG_PCPU_DEV_REFCNT=3Dy
> > CONFIG_RPS=3Dy
> > CONFIG_RFS_ACCEL=3Dy
> > CONFIG_SOCK_RX_QUEUE_MAPPING=3Dy
> > CONFIG_XPS=3Dy
> > # CONFIG_CGROUP_NET_PRIO is not set
> > # CONFIG_CGROUP_NET_CLASSID is not set
> > CONFIG_NET_RX_BUSY_POLL=3Dy
> > CONFIG_BQL=3Dy
> > CONFIG_NET_FLOW_LIMIT=3Dy
> >=20
> > #
> > # Network testing
> > #
> > # CONFIG_NET_PKTGEN is not set
> > # CONFIG_NET_DROP_MONITOR is not set
> > # end of Network testing
> > # end of Networking options
> >=20
> > # CONFIG_HAMRADIO is not set
> > # CONFIG_CAN is not set
> > # CONFIG_BT is not set
> > # CONFIG_AF_RXRPC is not set
> > # CONFIG_AF_KCM is not set
> > # CONFIG_MCTP is not set
> > # CONFIG_WIRELESS is not set
> > # CONFIG_RFKILL is not set
> > # CONFIG_NET_9P is not set
> > # CONFIG_CAIF is not set
> > # CONFIG_CEPH_LIB is not set
> > # CONFIG_NFC is not set
> > # CONFIG_PSAMPLE is not set
> > # CONFIG_NET_IFE is not set
> > # CONFIG_LWTUNNEL is not set
> > CONFIG_DST_CACHE=3Dy
> > CONFIG_GRO_CELLS=3Dy
> > CONFIG_FAILOVER=3Dy
> > CONFIG_ETHTOOL_NETLINK=3Dy
> >=20
> > #
> > # Device Drivers
> > #
> > CONFIG_HAVE_EISA=3Dy
> > # CONFIG_EISA is not set
> > CONFIG_HAVE_PCI=3Dy
> > CONFIG_PCI=3Dy
> > CONFIG_PCI_DOMAINS=3Dy
> > # CONFIG_PCIEPORTBUS is not set
> > CONFIG_PCIEASPM=3Dy
> > CONFIG_PCIEASPM_DEFAULT=3Dy
> > # CONFIG_PCIEASPM_POWERSAVE is not set
> > # CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
> > # CONFIG_PCIEASPM_PERFORMANCE is not set
> > # CONFIG_PCIE_PTM is not set
> > CONFIG_PCI_MSI=3Dy
> > CONFIG_PCI_MSI_IRQ_DOMAIN=3Dy
> > CONFIG_PCI_QUIRKS=3Dy
> > # CONFIG_PCI_DEBUG is not set
> > # CONFIG_PCI_STUB is not set
> > CONFIG_PCI_LOCKLESS_CONFIG=3Dy
> > # CONFIG_PCI_IOV is not set
> > # CONFIG_PCI_PRI is not set
> > # CONFIG_PCI_PASID is not set
> > CONFIG_PCI_LABEL=3Dy
> > CONFIG_VGA_ARB=3Dy
> > CONFIG_VGA_ARB_MAX_GPUS=3D16
> > # CONFIG_HOTPLUG_PCI is not set
> >=20
> > #
> > # PCI controller drivers
> > #
> > # CONFIG_VMD is not set
> >=20
> > #
> > # DesignWare PCI Core Support
> > #
> > # CONFIG_PCIE_DW_PLAT_HOST is not set
> > # CONFIG_PCI_MESON is not set
> > # end of DesignWare PCI Core Support
> >=20
> > #
> > # Mobiveil PCIe Core Support
> > #
> > # end of Mobiveil PCIe Core Support
> >=20
> > #
> > # Cadence PCIe controllers support
> > #
> > # end of Cadence PCIe controllers support
> > # end of PCI controller drivers
> >=20
> > #
> > # PCI Endpoint
> > #
> > # CONFIG_PCI_ENDPOINT is not set
> > # end of PCI Endpoint
> >=20
> > #
> > # PCI switch controller drivers
> > #
> > # CONFIG_PCI_SW_SWITCHTEC is not set
> > # end of PCI switch controller drivers
> >=20
> > # CONFIG_CXL_BUS is not set
> > # CONFIG_PCCARD is not set
> > # CONFIG_RAPIDIO is not set
> >=20
> > #
> > # Generic Driver Options
> > #
> > # CONFIG_UEVENT_HELPER is not set
> > CONFIG_DEVTMPFS=3Dy
> > # CONFIG_DEVTMPFS_MOUNT is not set
> > # CONFIG_DEVTMPFS_SAFE is not set
> > CONFIG_STANDALONE=3Dy
> > CONFIG_PREVENT_FIRMWARE_BUILD=3Dy
> >=20
> > #
> > # Firmware loader
> > #
> > CONFIG_FW_LOADER=3Dy
> > CONFIG_EXTRA_FIRMWARE=3D""
> > # CONFIG_FW_LOADER_USER_HELPER is not set
> > # CONFIG_FW_LOADER_COMPRESS is not set
> > # CONFIG_FW_UPLOAD is not set
> > # end of Firmware loader
> >=20
> > CONFIG_ALLOW_DEV_COREDUMP=3Dy
> > # CONFIG_DEBUG_DRIVER is not set
> > # CONFIG_DEBUG_DEVRES is not set
> > # CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
> > CONFIG_GENERIC_CPU_AUTOPROBE=3Dy
> > CONFIG_GENERIC_CPU_VULNERABILITIES=3Dy
> > # end of Generic Driver Options
> >=20
> > #
> > # Bus devices
> > #
> > # CONFIG_MHI_BUS is not set
> > # CONFIG_MHI_BUS_EP is not set
> > # end of Bus devices
> >=20
> > # CONFIG_CONNECTOR is not set
> >=20
> > #
> > # Firmware Drivers
> > #
> >=20
> > #
> > # ARM System Control and Management Interface Protocol
> > #
> > # end of ARM System Control and Management Interface Protocol
> >=20
> > # CONFIG_EDD is not set
> > CONFIG_FIRMWARE_MEMMAP=3Dy
> > # CONFIG_DMIID is not set
> > # CONFIG_DMI_SYSFS is not set
> > CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK=3Dy
> > # CONFIG_FW_CFG_SYSFS is not set
> > # CONFIG_SYSFB_SIMPLEFB is not set
> > # CONFIG_GOOGLE_FIRMWARE is not set
> >=20
> > #
> > # Tegra firmware driver
> > #
> > # end of Tegra firmware driver
> > # end of Firmware Drivers
> >=20
> > # CONFIG_GNSS is not set
> > CONFIG_MTD=3Dy
> >=20
> > #
> > # Partition parsers
> > #
> > # CONFIG_MTD_AR7_PARTS is not set
> > # CONFIG_MTD_CMDLINE_PARTS is not set
> > # CONFIG_MTD_REDBOOT_PARTS is not set
> > # end of Partition parsers
> >=20
> > #
> > # User Modules And Translation Layers
> > #
> > # CONFIG_MTD_BLOCK is not set
> > # CONFIG_MTD_BLOCK_RO is not set
> > # CONFIG_FTL is not set
> > # CONFIG_NFTL is not set
> > # CONFIG_INFTL is not set
> > # CONFIG_RFD_FTL is not set
> > # CONFIG_SSFDC is not set
> > # CONFIG_SM_FTL is not set
> > # CONFIG_MTD_OOPS is not set
> > # CONFIG_MTD_SWAP is not set
> > # CONFIG_MTD_PARTITIONED_MASTER is not set
> >=20
> > #
> > # RAM/ROM/Flash chip drivers
> > #
> > # CONFIG_MTD_CFI is not set
> > # CONFIG_MTD_JEDECPROBE is not set
> > CONFIG_MTD_MAP_BANK_WIDTH_1=3Dy
> > CONFIG_MTD_MAP_BANK_WIDTH_2=3Dy
> > CONFIG_MTD_MAP_BANK_WIDTH_4=3Dy
> > CONFIG_MTD_CFI_I1=3Dy
> > CONFIG_MTD_CFI_I2=3Dy
> > # CONFIG_MTD_RAM is not set
> > # CONFIG_MTD_ROM is not set
> > # CONFIG_MTD_ABSENT is not set
> > # end of RAM/ROM/Flash chip drivers
> >=20
> > #
> > # Mapping drivers for chip access
> > #
> > # CONFIG_MTD_COMPLEX_MAPPINGS is not set
> > # CONFIG_MTD_INTEL_VR_NOR is not set
> > # CONFIG_MTD_PLATRAM is not set
> > # end of Mapping drivers for chip access
> >=20
> > #
> > # Self-contained MTD device drivers
> > #
> > # CONFIG_MTD_PMC551 is not set
> > # CONFIG_MTD_SLRAM is not set
> > # CONFIG_MTD_PHRAM is not set
> > # CONFIG_MTD_MTDRAM is not set
> > CONFIG_MTD_BLOCK2MTD=3Dy
> >=20
> > #
> > # Disk-On-Chip Device Drivers
> > #
> > # CONFIG_MTD_DOCG3 is not set
> > # end of Self-contained MTD device drivers
> >=20
> > #
> > # NAND
> > #
> > # CONFIG_MTD_ONENAND is not set
> > # CONFIG_MTD_RAW_NAND is not set
> >=20
> > #
> > # ECC engine support
> > #
> > # CONFIG_MTD_NAND_ECC_SW_HAMMING is not set
> > # CONFIG_MTD_NAND_ECC_SW_BCH is not set
> > # CONFIG_MTD_NAND_ECC_MXIC is not set
> > # end of ECC engine support
> > # end of NAND
> >=20
> > #
> > # LPDDR & LPDDR2 PCM memory drivers
> > #
> > # CONFIG_MTD_LPDDR is not set
> > # end of LPDDR & LPDDR2 PCM memory drivers
> >=20
> > CONFIG_MTD_UBI=3Dy
> > CONFIG_MTD_UBI_WL_THRESHOLD=3D4096
> > CONFIG_MTD_UBI_BEB_LIMIT=3D20
> > # CONFIG_MTD_UBI_FASTMAP is not set
> > # CONFIG_MTD_UBI_GLUEBI is not set
> > # CONFIG_MTD_UBI_BLOCK is not set
> > # CONFIG_MTD_HYPERBUS is not set
> > # CONFIG_OF is not set
> > CONFIG_ARCH_MIGHT_HAVE_PC_PARPORT=3Dy
> > # CONFIG_PARPORT is not set
> > CONFIG_PNP=3Dy
> > CONFIG_PNP_DEBUG_MESSAGES=3Dy
> >=20
> > #
> > # Protocols
> > #
> > CONFIG_PNPACPI=3Dy
> > CONFIG_BLK_DEV=3Dy
> > # CONFIG_BLK_DEV_NULL_BLK is not set
> > # CONFIG_BLK_DEV_FD is not set
> > # CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
> > # CONFIG_ZRAM is not set
> > CONFIG_BLK_DEV_LOOP=3Dy
> > CONFIG_BLK_DEV_LOOP_MIN_COUNT=3D8
> > # CONFIG_BLK_DEV_DRBD is not set
> > # CONFIG_BLK_DEV_NBD is not set
> > # CONFIG_BLK_DEV_RAM is not set
> > # CONFIG_ATA_OVER_ETH is not set
> > CONFIG_VIRTIO_BLK=3Dy
> > # CONFIG_BLK_DEV_RBD is not set
> > # CONFIG_BLK_DEV_UBLK is not set
> >=20
> > #
> > # NVME Support
> > #
> > # CONFIG_BLK_DEV_NVME is not set
> > # CONFIG_NVME_FC is not set
> > # CONFIG_NVME_TCP is not set
> > # end of NVME Support
> >=20
> > #
> > # Misc devices
> > #
> > # CONFIG_DUMMY_IRQ is not set
> > # CONFIG_IBM_ASM is not set
> > # CONFIG_PHANTOM is not set
> > # CONFIG_TIFM_CORE is not set
> > # CONFIG_ENCLOSURE_SERVICES is not set
> > # CONFIG_HP_ILO is not set
> > # CONFIG_SRAM is not set
> > # CONFIG_DW_XDATA_PCIE is not set
> > # CONFIG_PCI_ENDPOINT_TEST is not set
> > # CONFIG_XILINX_SDFEC is not set
> > # CONFIG_C2PORT is not set
> >=20
> > #
> > # EEPROM support
> > #
> > # CONFIG_EEPROM_93CX6 is not set
> > # end of EEPROM support
> >=20
> > # CONFIG_CB710_CORE is not set
> >=20
> > #
> > # Texas Instruments shared transport line discipline
> > #
> > # end of Texas Instruments shared transport line discipline
> >=20
> > #
> > # Altera FPGA firmware download module (requires I2C)
> > #
> > # CONFIG_INTEL_MEI is not set
> > # CONFIG_INTEL_MEI_ME is not set
> > # CONFIG_INTEL_MEI_TXE is not set
> > # CONFIG_VMWARE_VMCI is not set
> > # CONFIG_GENWQE is not set
> > # CONFIG_ECHO is not set
> > # CONFIG_BCM_VK is not set
> > # CONFIG_MISC_ALCOR_PCI is not set
> > # CONFIG_MISC_RTSX_PCI is not set
> > # CONFIG_HABANA_AI is not set
> > # CONFIG_PVPANIC is not set
> > # end of Misc devices
> >=20
> > #
> > # SCSI device support
> > #
> > CONFIG_SCSI_MOD=3Dy
> > # CONFIG_RAID_ATTRS is not set
> > # CONFIG_SCSI is not set
> > # end of SCSI device support
> >=20
> > # CONFIG_ATA is not set
> > CONFIG_MD=3Dy
> > # CONFIG_BLK_DEV_MD is not set
> > # CONFIG_BCACHE is not set
> > CONFIG_BLK_DEV_DM_BUILTIN=3Dy
> > CONFIG_BLK_DEV_DM=3Dy
> > # CONFIG_DM_DEBUG is not set
> > CONFIG_DM_BUFIO=3Dy
> > # CONFIG_DM_DEBUG_BLOCK_MANAGER_LOCKING is not set
> > CONFIG_DM_BIO_PRISON=3Dy
> > CONFIG_DM_PERSISTENT_DATA=3Dy
> > # CONFIG_DM_UNSTRIPED is not set
> > # CONFIG_DM_CRYPT is not set
> > CONFIG_DM_SNAPSHOT=3Dy
> > CONFIG_DM_THIN_PROVISIONING=3Dy
> > # CONFIG_DM_CACHE is not set
> > # CONFIG_DM_WRITECACHE is not set
> > # CONFIG_DM_EBS is not set
> > # CONFIG_DM_ERA is not set
> > # CONFIG_DM_CLONE is not set
> > # CONFIG_DM_MIRROR is not set
> > # CONFIG_DM_RAID is not set
> > CONFIG_DM_ZERO=3Dy
> > # CONFIG_DM_MULTIPATH is not set
> > # CONFIG_DM_DELAY is not set
> > # CONFIG_DM_DUST is not set
> > # CONFIG_DM_INIT is not set
> > # CONFIG_DM_UEVENT is not set
> > CONFIG_DM_FLAKEY=3Dy
> > # CONFIG_DM_VERITY is not set
> > # CONFIG_DM_SWITCH is not set
> > # CONFIG_DM_LOG_WRITES is not set
> > # CONFIG_DM_INTEGRITY is not set
> > # CONFIG_TARGET_CORE is not set
> > # CONFIG_FUSION is not set
> >=20
> > #
> > # IEEE 1394 (FireWire) support
> > #
> > # CONFIG_FIREWIRE is not set
> > # CONFIG_FIREWIRE_NOSY is not set
> > # end of IEEE 1394 (FireWire) support
> >=20
> > # CONFIG_MACINTOSH_DRIVERS is not set
> > CONFIG_NETDEVICES=3Dy
> > CONFIG_NET_CORE=3Dy
> > # CONFIG_BONDING is not set
> > # CONFIG_DUMMY is not set
> > # CONFIG_WIREGUARD is not set
> > # CONFIG_EQUALIZER is not set
> > # CONFIG_NET_TEAM is not set
> > # CONFIG_MACVLAN is not set
> > # CONFIG_IPVLAN is not set
> > # CONFIG_VXLAN is not set
> > # CONFIG_GENEVE is not set
> > # CONFIG_BAREUDP is not set
> > # CONFIG_GTP is not set
> > # CONFIG_MACSEC is not set
> > # CONFIG_NETCONSOLE is not set
> > # CONFIG_TUN is not set
> > # CONFIG_TUN_VNET_CROSS_LE is not set
> > # CONFIG_VETH is not set
> > CONFIG_VIRTIO_NET=3Dy
> > # CONFIG_NLMON is not set
> > # CONFIG_ARCNET is not set
> > # CONFIG_ETHERNET is not set
> > # CONFIG_FDDI is not set
> > # CONFIG_HIPPI is not set
> > # CONFIG_NET_SB1000 is not set
> > # CONFIG_PHYLIB is not set
> > # CONFIG_PSE_CONTROLLER is not set
> > # CONFIG_MDIO_DEVICE is not set
> >=20
> > #
> > # PCS device drivers
> > #
> > # end of PCS device drivers
> >=20
> > # CONFIG_PPP is not set
> > # CONFIG_SLIP is not set
> >=20
> > #
> > # Host-side USB support is needed for USB Network Adapter support
> > #
> > # CONFIG_WLAN is not set
> > # CONFIG_WAN is not set
> >=20
> > #
> > # Wireless WAN
> > #
> > # CONFIG_WWAN is not set
> > # end of Wireless WAN
> >=20
> > # CONFIG_VMXNET3 is not set
> > # CONFIG_FUJITSU_ES is not set
> > # CONFIG_NETDEVSIM is not set
> > CONFIG_NET_FAILOVER=3Dy
> > # CONFIG_ISDN is not set
> >=20
> > #
> > # Input device support
> > #
> > CONFIG_INPUT=3Dy
> > # CONFIG_INPUT_FF_MEMLESS is not set
> > # CONFIG_INPUT_SPARSEKMAP is not set
> > # CONFIG_INPUT_MATRIXKMAP is not set
> > CONFIG_INPUT_VIVALDIFMAP=3Dy
> >=20
> > #
> > # Userland interfaces
> > #
> > # CONFIG_INPUT_MOUSEDEV is not set
> > # CONFIG_INPUT_JOYDEV is not set
> > # CONFIG_INPUT_EVDEV is not set
> > # CONFIG_INPUT_EVBUG is not set
> >=20
> > #
> > # Input Device Drivers
> > #
> > CONFIG_INPUT_KEYBOARD=3Dy
> > CONFIG_KEYBOARD_ATKBD=3Dy
> > # CONFIG_KEYBOARD_LKKBD is not set
> > # CONFIG_KEYBOARD_NEWTON is not set
> > # CONFIG_KEYBOARD_OPENCORES is not set
> > # CONFIG_KEYBOARD_STOWAWAY is not set
> > # CONFIG_KEYBOARD_SUNKBD is not set
> > # CONFIG_KEYBOARD_XTKBD is not set
> > # CONFIG_INPUT_MOUSE is not set
> > # CONFIG_INPUT_JOYSTICK is not set
> > # CONFIG_INPUT_TABLET is not set
> > # CONFIG_INPUT_TOUCHSCREEN is not set
> > # CONFIG_INPUT_MISC is not set
> > # CONFIG_RMI4_CORE is not set
> >=20
> > #
> > # Hardware I/O ports
> > #
> > CONFIG_SERIO=3Dy
> > CONFIG_ARCH_MIGHT_HAVE_PC_SERIO=3Dy
> > CONFIG_SERIO_I8042=3Dy
> > # CONFIG_SERIO_SERPORT is not set
> > # CONFIG_SERIO_CT82C710 is not set
> > # CONFIG_SERIO_PCIPS2 is not set
> > CONFIG_SERIO_LIBPS2=3Dy
> > # CONFIG_SERIO_RAW is not set
> > # CONFIG_SERIO_ALTERA_PS2 is not set
> > # CONFIG_SERIO_PS2MULT is not set
> > # CONFIG_SERIO_ARC_PS2 is not set
> > # CONFIG_USERIO is not set
> > # CONFIG_GAMEPORT is not set
> > # end of Hardware I/O ports
> > # end of Input device support
> >=20
> > #
> > # Character devices
> > #
> > CONFIG_TTY=3Dy
> > CONFIG_VT=3Dy
> > CONFIG_CONSOLE_TRANSLATIONS=3Dy
> > CONFIG_VT_CONSOLE=3Dy
> > CONFIG_HW_CONSOLE=3Dy
> > # CONFIG_VT_HW_CONSOLE_BINDING is not set
> > CONFIG_UNIX98_PTYS=3Dy
> > # CONFIG_LEGACY_PTYS is not set
> > CONFIG_LDISC_AUTOLOAD=3Dy
> >=20
> > #
> > # Serial drivers
> > #
> > CONFIG_SERIAL_EARLYCON=3Dy
> > CONFIG_SERIAL_8250=3Dy
> > # CONFIG_SERIAL_8250_DEPRECATED_OPTIONS is not set
> > CONFIG_SERIAL_8250_PNP=3Dy
> > # CONFIG_SERIAL_8250_16550A_VARIANTS is not set
> > # CONFIG_SERIAL_8250_FINTEK is not set
> > CONFIG_SERIAL_8250_CONSOLE=3Dy
> > CONFIG_SERIAL_8250_PCI=3Dy
> > CONFIG_SERIAL_8250_EXAR=3Dy
> > CONFIG_SERIAL_8250_NR_UARTS=3D32
> > CONFIG_SERIAL_8250_RUNTIME_UARTS=3D32
> > # CONFIG_SERIAL_8250_EXTENDED is not set
> > CONFIG_SERIAL_8250_DWLIB=3Dy
> > # CONFIG_SERIAL_8250_DW is not set
> > # CONFIG_SERIAL_8250_RT288X is not set
> > CONFIG_SERIAL_8250_LPSS=3Dy
> > CONFIG_SERIAL_8250_MID=3Dy
> > CONFIG_SERIAL_8250_PERICOM=3Dy
> >=20
> > #
> > # Non-8250 serial port support
> > #
> > # CONFIG_SERIAL_UARTLITE is not set
> > CONFIG_SERIAL_CORE=3Dy
> > CONFIG_SERIAL_CORE_CONSOLE=3Dy
> > # CONFIG_SERIAL_JSM is not set
> > # CONFIG_SERIAL_LANTIQ is not set
> > # CONFIG_SERIAL_SCCNXP is not set
> > # CONFIG_SERIAL_ALTERA_JTAGUART is not set
> > # CONFIG_SERIAL_ALTERA_UART is not set
> > # CONFIG_SERIAL_ARC is not set
> > # CONFIG_SERIAL_RP2 is not set
> > # CONFIG_SERIAL_FSL_LPUART is not set
> > # CONFIG_SERIAL_FSL_LINFLEXUART is not set
> > # end of Serial drivers
> >=20
> > # CONFIG_SERIAL_NONSTANDARD is not set
> > # CONFIG_N_GSM is not set
> > # CONFIG_NOZOMI is not set
> > # CONFIG_NULL_TTY is not set
> > # CONFIG_SERIAL_DEV_BUS is not set
> > # CONFIG_VIRTIO_CONSOLE is not set
> > # CONFIG_IPMI_HANDLER is not set
> > CONFIG_HW_RANDOM=3Dy
> > # CONFIG_HW_RANDOM_TIMERIOMEM is not set
> > CONFIG_HW_RANDOM_INTEL=3Dy
> > CONFIG_HW_RANDOM_AMD=3Dy
> > # CONFIG_HW_RANDOM_BA431 is not set
> > CONFIG_HW_RANDOM_VIA=3Dy
> > # CONFIG_HW_RANDOM_VIRTIO is not set
> > # CONFIG_HW_RANDOM_XIPHERA is not set
> > # CONFIG_APPLICOM is not set
> > # CONFIG_MWAVE is not set
> > CONFIG_DEVMEM=3Dy
> > # CONFIG_NVRAM is not set
> > CONFIG_DEVPORT=3Dy
> > # CONFIG_HPET is not set
> > # CONFIG_HANGCHECK_TIMER is not set
> > # CONFIG_TCG_TPM is not set
> > # CONFIG_TELCLOCK is not set
> > # CONFIG_XILLYBUS is not set
> > CONFIG_RANDOM_TRUST_CPU=3Dy
> > CONFIG_RANDOM_TRUST_BOOTLOADER=3Dy
> > # end of Character devices
> >=20
> > #
> > # I2C support
> > #
> > # CONFIG_I2C is not set
> > # end of I2C support
> >=20
> > # CONFIG_I3C is not set
> > # CONFIG_SPI is not set
> > # CONFIG_SPMI is not set
> > # CONFIG_HSI is not set
> > # CONFIG_PPS is not set
> >=20
> > #
> > # PTP clock support
> > #
> > # CONFIG_PTP_1588_CLOCK is not set
> > CONFIG_PTP_1588_CLOCK_OPTIONAL=3Dy
> >=20
> > #
> > # Enable PHYLIB and NETWORK_PHY_TIMESTAMPING to see the additional cloc=
ks.
> > #
> > # end of PTP clock support
> >=20
> > # CONFIG_PINCTRL is not set
> > # CONFIG_GPIOLIB is not set
> > # CONFIG_W1 is not set
> > # CONFIG_POWER_RESET is not set
> > CONFIG_POWER_SUPPLY=3Dy
> > # CONFIG_POWER_SUPPLY_DEBUG is not set
> > # CONFIG_PDA_POWER is not set
> > # CONFIG_TEST_POWER is not set
> > # CONFIG_BATTERY_DS2780 is not set
> > # CONFIG_BATTERY_DS2781 is not set
> > # CONFIG_BATTERY_SAMSUNG_SDI is not set
> > # CONFIG_BATTERY_BQ27XXX is not set
> > # CONFIG_CHARGER_MAX8903 is not set
> > # CONFIG_BATTERY_GOLDFISH is not set
> > # CONFIG_HWMON is not set
> > CONFIG_THERMAL=3Dy
> > # CONFIG_THERMAL_NETLINK is not set
> > # CONFIG_THERMAL_STATISTICS is not set
> > CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=3D0
> > # CONFIG_THERMAL_WRITABLE_TRIPS is not set
> > CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=3Dy
> > # CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
> > # CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
> > # CONFIG_THERMAL_GOV_FAIR_SHARE is not set
> > CONFIG_THERMAL_GOV_STEP_WISE=3Dy
> > # CONFIG_THERMAL_GOV_BANG_BANG is not set
> > # CONFIG_THERMAL_GOV_USER_SPACE is not set
> > # CONFIG_THERMAL_EMULATION is not set
> >=20
> > #
> > # Intel thermal drivers
> > #
> > # CONFIG_INTEL_POWERCLAMP is not set
> > CONFIG_X86_THERMAL_VECTOR=3Dy
> > # CONFIG_X86_PKG_TEMP_THERMAL is not set
> > # CONFIG_INTEL_SOC_DTS_THERMAL is not set
> >=20
> > #
> > # ACPI INT340X thermal drivers
> > #
> > # CONFIG_INT340X_THERMAL is not set
> > # end of ACPI INT340X thermal drivers
> >=20
> > # CONFIG_INTEL_PCH_THERMAL is not set
> > # CONFIG_INTEL_TCC_COOLING is not set
> > # CONFIG_INTEL_MENLOW is not set
> > # CONFIG_INTEL_HFI_THERMAL is not set
> > # end of Intel thermal drivers
> >=20
> > # CONFIG_WATCHDOG is not set
> > CONFIG_SSB_POSSIBLE=3Dy
> > # CONFIG_SSB is not set
> > CONFIG_BCMA_POSSIBLE=3Dy
> > # CONFIG_BCMA is not set
> >=20
> > #
> > # Multifunction device drivers
> > #
> > # CONFIG_MFD_MADERA is not set
> > # CONFIG_HTC_PASIC3 is not set
> > # CONFIG_LPC_ICH is not set
> > # CONFIG_LPC_SCH is not set
> > # CONFIG_MFD_INTEL_LPSS_ACPI is not set
> > # CONFIG_MFD_INTEL_LPSS_PCI is not set
> > # CONFIG_MFD_JANZ_CMODIO is not set
> > # CONFIG_MFD_KEMPLD is not set
> > # CONFIG_MFD_MT6397 is not set
> > # CONFIG_MFD_RDC321X is not set
> > # CONFIG_MFD_SM501 is not set
> > # CONFIG_MFD_SYSCON is not set
> > # CONFIG_MFD_TI_AM335X_TSCADC is not set
> > # CONFIG_MFD_TQMX86 is not set
> > # CONFIG_MFD_VX855 is not set
> > # end of Multifunction device drivers
> >=20
> > # CONFIG_REGULATOR is not set
> > # CONFIG_RC_CORE is not set
> >=20
> > #
> > # CEC support
> > #
> > # CONFIG_MEDIA_CEC_SUPPORT is not set
> > # end of CEC support
> >=20
> > # CONFIG_MEDIA_SUPPORT is not set
> >=20
> > #
> > # Graphics support
> > #
> > # CONFIG_AGP is not set
> > # CONFIG_VGA_SWITCHEROO is not set
> > # CONFIG_DRM is not set
> >=20
> > #
> > # ARM devices
> > #
> > # end of ARM devices
> >=20
> > #
> > # Frame buffer Devices
> > #
> > # CONFIG_FB is not set
> > # end of Frame buffer Devices
> >=20
> > #
> > # Backlight & LCD device support
> > #
> > # CONFIG_LCD_CLASS_DEVICE is not set
> > # CONFIG_BACKLIGHT_CLASS_DEVICE is not set
> > # end of Backlight & LCD device support
> >=20
> > #
> > # Console display driver support
> > #
> > CONFIG_VGA_CONSOLE=3Dy
> > CONFIG_DUMMY_CONSOLE=3Dy
> > CONFIG_DUMMY_CONSOLE_COLUMNS=3D80
> > CONFIG_DUMMY_CONSOLE_ROWS=3D25
> > # end of Console display driver support
> > # end of Graphics support
> >=20
> > # CONFIG_SOUND is not set
> >=20
> > #
> > # HID support
> > #
> > # CONFIG_HID is not set
> >=20
> > #
> > # Intel ISH HID support
> > #
> > # CONFIG_INTEL_ISH_HID is not set
> > # end of Intel ISH HID support
> > # end of HID support
> >=20
> > CONFIG_USB_OHCI_LITTLE_ENDIAN=3Dy
> > # CONFIG_USB_SUPPORT is not set
> > # CONFIG_MMC is not set
> > # CONFIG_MEMSTICK is not set
> > # CONFIG_NEW_LEDS is not set
> > # CONFIG_ACCESSIBILITY is not set
> > # CONFIG_INFINIBAND is not set
> > CONFIG_EDAC_ATOMIC_SCRUB=3Dy
> > CONFIG_EDAC_SUPPORT=3Dy
> > CONFIG_RTC_LIB=3Dy
> > CONFIG_RTC_MC146818_LIB=3Dy
> > # CONFIG_RTC_CLASS is not set
> > # CONFIG_DMADEVICES is not set
> >=20
> > #
> > # DMABUF options
> > #
> > # CONFIG_SYNC_FILE is not set
> > # CONFIG_DMABUF_HEAPS is not set
> > # end of DMABUF options
> >=20
> > # CONFIG_AUXDISPLAY is not set
> > # CONFIG_UIO is not set
> > # CONFIG_VFIO is not set
> > CONFIG_VIRT_DRIVERS=3Dy
> > CONFIG_VMGENID=3Dy
> > # CONFIG_VBOXGUEST is not set
> > # CONFIG_NITRO_ENCLAVES is not set
> > CONFIG_VIRTIO_ANCHOR=3Dy
> > CONFIG_VIRTIO=3Dy
> > CONFIG_VIRTIO_PCI_LIB=3Dy
> > CONFIG_VIRTIO_PCI_LIB_LEGACY=3Dy
> > CONFIG_VIRTIO_MENU=3Dy
> > CONFIG_VIRTIO_PCI=3Dy
> > CONFIG_VIRTIO_PCI_LEGACY=3Dy
> > # CONFIG_VIRTIO_PMEM is not set
> > # CONFIG_VIRTIO_BALLOON is not set
> > # CONFIG_VIRTIO_INPUT is not set
> > # CONFIG_VIRTIO_MMIO is not set
> > # CONFIG_VDPA is not set
> > CONFIG_VHOST_MENU=3Dy
> > # CONFIG_VHOST_NET is not set
> > # CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set
> >=20
> > #
> > # Microsoft Hyper-V guest support
> > #
> > # CONFIG_HYPERV is not set
> > # end of Microsoft Hyper-V guest support
> >=20
> > # CONFIG_GREYBUS is not set
> > # CONFIG_COMEDI is not set
> > # CONFIG_STAGING is not set
> > # CONFIG_CHROME_PLATFORMS is not set
> > # CONFIG_MELLANOX_PLATFORM is not set
> > CONFIG_SURFACE_PLATFORMS=3Dy
> > # CONFIG_SURFACE_GPE is not set
> > # CONFIG_SURFACE_PRO3_BUTTON is not set
> > # CONFIG_X86_PLATFORM_DEVICES is not set
> > # CONFIG_P2SB is not set
> > # CONFIG_COMMON_CLK is not set
> > # CONFIG_HWSPINLOCK is not set
> >=20
> > #
> > # Clock Source drivers
> > #
> > CONFIG_CLKEVT_I8253=3Dy
> > CONFIG_I8253_LOCK=3Dy
> > CONFIG_CLKBLD_I8253=3Dy
> > # end of Clock Source drivers
> >=20
> > CONFIG_MAILBOX=3Dy
> > CONFIG_PCC=3Dy
> > # CONFIG_ALTERA_MBOX is not set
> > # CONFIG_IOMMU_SUPPORT is not set
> >=20
> > #
> > # Remoteproc drivers
> > #
> > # CONFIG_REMOTEPROC is not set
> > # end of Remoteproc drivers
> >=20
> > #
> > # Rpmsg drivers
> > #
> > # CONFIG_RPMSG_QCOM_GLINK_RPM is not set
> > # CONFIG_RPMSG_VIRTIO is not set
> > # end of Rpmsg drivers
> >=20
> > # CONFIG_SOUNDWIRE is not set
> >=20
> > #
> > # SOC (System On Chip) specific Drivers
> > #
> >=20
> > #
> > # Amlogic SoC drivers
> > #
> > # end of Amlogic SoC drivers
> >=20
> > #
> > # Broadcom SoC drivers
> > #
> > # end of Broadcom SoC drivers
> >=20
> > #
> > # NXP/Freescale QorIQ SoC drivers
> > #
> > # end of NXP/Freescale QorIQ SoC drivers
> >=20
> > #
> > # fujitsu SoC drivers
> > #
> > # end of fujitsu SoC drivers
> >=20
> > #
> > # i.MX SoC drivers
> > #
> > # end of i.MX SoC drivers
> >=20
> > #
> > # Enable LiteX SoC Builder specific drivers
> > #
> > # end of Enable LiteX SoC Builder specific drivers
> >=20
> > #
> > # Qualcomm SoC drivers
> > #
> > # end of Qualcomm SoC drivers
> >=20
> > # CONFIG_SOC_TI is not set
> >=20
> > #
> > # Xilinx SoC drivers
> > #
> > # end of Xilinx SoC drivers
> > # end of SOC (System On Chip) specific Drivers
> >=20
> > # CONFIG_PM_DEVFREQ is not set
> > # CONFIG_EXTCON is not set
> > # CONFIG_MEMORY is not set
> > # CONFIG_IIO is not set
> > # CONFIG_NTB is not set
> > # CONFIG_PWM is not set
> >=20
> > #
> > # IRQ chip support
> > #
> > # end of IRQ chip support
> >=20
> > # CONFIG_IPACK_BUS is not set
> > # CONFIG_RESET_CONTROLLER is not set
> >=20
> > #
> > # PHY Subsystem
> > #
> > # CONFIG_GENERIC_PHY is not set
> > # CONFIG_PHY_CAN_TRANSCEIVER is not set
> >=20
> > #
> > # PHY drivers for Broadcom platforms
> > #
> > # CONFIG_BCM_KONA_USB2_PHY is not set
> > # end of PHY drivers for Broadcom platforms
> >=20
> > # CONFIG_PHY_PXA_28NM_HSIC is not set
> > # CONFIG_PHY_PXA_28NM_USB2 is not set
> > # CONFIG_PHY_INTEL_LGM_EMMC is not set
> > # end of PHY Subsystem
> >=20
> > # CONFIG_POWERCAP is not set
> > # CONFIG_MCB is not set
> >=20
> > #
> > # Performance monitor support
> > #
> > # end of Performance monitor support
> >=20
> > # CONFIG_RAS is not set
> > # CONFIG_USB4 is not set
> >=20
> > #
> > # Android
> > #
> > # CONFIG_ANDROID_BINDER_IPC is not set
> > # end of Android
> >=20
> > CONFIG_LIBNVDIMM=3Dy
> > CONFIG_BLK_DEV_PMEM=3Dy
> > CONFIG_ND_CLAIM=3Dy
> > CONFIG_ND_BTT=3Dy
> > CONFIG_BTT=3Dy
> > CONFIG_DAX=3Dy
> > CONFIG_NVMEM=3Dy
> > CONFIG_NVMEM_SYSFS=3Dy
> > # CONFIG_NVMEM_RMEM is not set
> >=20
> > #
> > # HW tracing support
> > #
> > # CONFIG_STM is not set
> > # CONFIG_INTEL_TH is not set
> > # end of HW tracing support
> >=20
> > # CONFIG_FPGA is not set
> > # CONFIG_TEE is not set
> > # CONFIG_SIOX is not set
> > # CONFIG_SLIMBUS is not set
> > # CONFIG_INTERCONNECT is not set
> > # CONFIG_COUNTER is not set
> > # CONFIG_PECI is not set
> > # CONFIG_HTE is not set
> > # end of Device Drivers
> >=20
> > #
> > # File systems
> > #
> > CONFIG_DCACHE_WORD_ACCESS=3Dy
> > # CONFIG_VALIDATE_FS_PARSER is not set
> > CONFIG_FS_IOMAP=3Dy
> > CONFIG_EXT2_FS=3Dy
> > CONFIG_EXT2_FS_XATTR=3Dy
> > CONFIG_EXT2_FS_POSIX_ACL=3Dy
> > CONFIG_EXT2_FS_SECURITY=3Dy
> > # CONFIG_EXT3_FS is not set
> > CONFIG_EXT4_FS=3Dy
> > CONFIG_EXT4_FS_POSIX_ACL=3Dy
> > CONFIG_EXT4_FS_SECURITY=3Dy
> > CONFIG_EXT4_DEBUG=3Dy
> > CONFIG_JBD2=3Dy
> > CONFIG_JBD2_DEBUG=3Dy
> > CONFIG_FS_MBCACHE=3Dy
> > # CONFIG_REISERFS_FS is not set
> > # CONFIG_JFS_FS is not set
> > CONFIG_XFS_FS=3Dy
> > CONFIG_XFS_SUPPORT_V4=3Dy
> > CONFIG_XFS_QUOTA=3Dy
> > CONFIG_XFS_POSIX_ACL=3Dy
> > CONFIG_XFS_RT=3Dy
> > # CONFIG_XFS_ONLINE_SCRUB is not set
> > # CONFIG_XFS_WARN is not set
> > # CONFIG_XFS_DEBUG is not set
> > # CONFIG_GFS2_FS is not set
> > CONFIG_BTRFS_FS=3Dy
> > CONFIG_BTRFS_FS_POSIX_ACL=3Dy
> > # CONFIG_BTRFS_FS_CHECK_INTEGRITY is not set
> > # CONFIG_BTRFS_FS_RUN_SANITY_TESTS is not set
> > CONFIG_BTRFS_DEBUG=3Dy
> > CONFIG_BTRFS_ASSERT=3Dy
> > # CONFIG_BTRFS_FS_REF_VERIFY is not set
> > # CONFIG_NILFS2_FS is not set
> > CONFIG_F2FS_FS=3Dy
> > CONFIG_F2FS_STAT_FS=3Dy
> > CONFIG_F2FS_FS_XATTR=3Dy
> > CONFIG_F2FS_FS_POSIX_ACL=3Dy
> > CONFIG_F2FS_FS_SECURITY=3Dy
> > CONFIG_F2FS_CHECK_FS=3Dy
> > # CONFIG_F2FS_FAULT_INJECTION is not set
> > CONFIG_F2FS_FS_COMPRESSION=3Dy
> > CONFIG_F2FS_FS_LZO=3Dy
> > CONFIG_F2FS_FS_LZORLE=3Dy
> > CONFIG_F2FS_FS_LZ4=3Dy
> > CONFIG_F2FS_FS_LZ4HC=3Dy
> > CONFIG_F2FS_FS_ZSTD=3Dy
> > CONFIG_F2FS_IOSTAT=3Dy
> > CONFIG_FS_POSIX_ACL=3Dy
> > CONFIG_EXPORTFS=3Dy
> > # CONFIG_EXPORTFS_BLOCK_OPS is not set
> > CONFIG_FILE_LOCKING=3Dy
> > CONFIG_FS_ENCRYPTION=3Dy
> > CONFIG_FS_ENCRYPTION_ALGS=3Dy
> > CONFIG_FS_VERITY=3Dy
> > # CONFIG_FS_VERITY_DEBUG is not set
> > CONFIG_FS_VERITY_BUILTIN_SIGNATURES=3Dy
> > CONFIG_FSNOTIFY=3Dy
> > CONFIG_DNOTIFY=3Dy
> > CONFIG_INOTIFY_USER=3Dy
> > # CONFIG_FANOTIFY is not set
> > CONFIG_QUOTA=3Dy
> > CONFIG_QUOTA_NETLINK_INTERFACE=3Dy
> > # CONFIG_PRINT_QUOTA_WARNING is not set
> > # CONFIG_QUOTA_DEBUG is not set
> > CONFIG_QUOTA_TREE=3Dy
> > # CONFIG_QFMT_V1 is not set
> > CONFIG_QFMT_V2=3Dy
> > CONFIG_QUOTACTL=3Dy
> > CONFIG_AUTOFS4_FS=3Dy
> > CONFIG_AUTOFS_FS=3Dy
> > # CONFIG_FUSE_FS is not set
> > CONFIG_OVERLAY_FS=3Dy
> > # CONFIG_OVERLAY_FS_REDIRECT_DIR is not set
> > CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW=3Dy
> > # CONFIG_OVERLAY_FS_INDEX is not set
> > # CONFIG_OVERLAY_FS_XINO_AUTO is not set
> > # CONFIG_OVERLAY_FS_METACOPY is not set
> >=20
> > #
> > # Caches
> > #
> > # CONFIG_FSCACHE is not set
> > # end of Caches
> >=20
> > #
> > # CD-ROM/DVD Filesystems
> > #
> > # CONFIG_ISO9660_FS is not set
> > # CONFIG_UDF_FS is not set
> > # end of CD-ROM/DVD Filesystems
> >=20
> > #
> > # DOS/FAT/EXFAT/NT Filesystems
> > #
> > CONFIG_FAT_FS=3Dy
> > # CONFIG_MSDOS_FS is not set
> > CONFIG_VFAT_FS=3Dy
> > CONFIG_FAT_DEFAULT_CODEPAGE=3D437
> > CONFIG_FAT_DEFAULT_IOCHARSET=3D"iso8859-1"
> > # CONFIG_FAT_DEFAULT_UTF8 is not set
> > # CONFIG_EXFAT_FS is not set
> > # CONFIG_NTFS_FS is not set
> > # CONFIG_NTFS3_FS is not set
> > # end of DOS/FAT/EXFAT/NT Filesystems
> >=20
> > #
> > # Pseudo filesystems
> > #
> > CONFIG_PROC_FS=3Dy
> > # CONFIG_PROC_KCORE is not set
> > CONFIG_PROC_SYSCTL=3Dy
> > CONFIG_PROC_PAGE_MONITOR=3Dy
> > # CONFIG_PROC_CHILDREN is not set
> > CONFIG_PROC_PID_ARCH_STATUS=3Dy
> > CONFIG_KERNFS=3Dy
> > CONFIG_SYSFS=3Dy
> > CONFIG_TMPFS=3Dy
> > CONFIG_TMPFS_POSIX_ACL=3Dy
> > CONFIG_TMPFS_XATTR=3Dy
> > # CONFIG_TMPFS_INODE64 is not set
> > # CONFIG_HUGETLBFS is not set
> > CONFIG_ARCH_WANT_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=3Dy
> > CONFIG_MEMFD_CREATE=3Dy
> > CONFIG_ARCH_HAS_GIGANTIC_PAGE=3Dy
> > # CONFIG_CONFIGFS_FS is not set
> > # end of Pseudo filesystems
> >=20
> > CONFIG_MISC_FILESYSTEMS=3Dy
> > # CONFIG_ORANGEFS_FS is not set
> > # CONFIG_ADFS_FS is not set
> > # CONFIG_AFFS_FS is not set
> > # CONFIG_ECRYPT_FS is not set
> > # CONFIG_HFS_FS is not set
> > # CONFIG_HFSPLUS_FS is not set
> > # CONFIG_BEFS_FS is not set
> > # CONFIG_BFS_FS is not set
> > # CONFIG_EFS_FS is not set
> > # CONFIG_JFFS2_FS is not set
> > CONFIG_UBIFS_FS=3Dy
> > # CONFIG_UBIFS_FS_ADVANCED_COMPR is not set
> > CONFIG_UBIFS_FS_LZO=3Dy
> > CONFIG_UBIFS_FS_ZLIB=3Dy
> > CONFIG_UBIFS_FS_ZSTD=3Dy
> > # CONFIG_UBIFS_ATIME_SUPPORT is not set
> > CONFIG_UBIFS_FS_XATTR=3Dy
> > CONFIG_UBIFS_FS_SECURITY=3Dy
> > # CONFIG_UBIFS_FS_AUTHENTICATION is not set
> > # CONFIG_CRAMFS is not set
> > # CONFIG_SQUASHFS is not set
> > # CONFIG_VXFS_FS is not set
> > # CONFIG_MINIX_FS is not set
> > # CONFIG_OMFS_FS is not set
> > # CONFIG_HPFS_FS is not set
> > # CONFIG_QNX4FS_FS is not set
> > # CONFIG_QNX6FS_FS is not set
> > # CONFIG_ROMFS_FS is not set
> > # CONFIG_PSTORE is not set
> > # CONFIG_SYSV_FS is not set
> > # CONFIG_UFS_FS is not set
> > # CONFIG_EROFS_FS is not set
> > # CONFIG_NETWORK_FILESYSTEMS is not set
> > CONFIG_NLS=3Dy
> > CONFIG_NLS_DEFAULT=3D"iso8859-1"
> > CONFIG_NLS_CODEPAGE_437=3Dy
> > # CONFIG_NLS_CODEPAGE_737 is not set
> > # CONFIG_NLS_CODEPAGE_775 is not set
> > # CONFIG_NLS_CODEPAGE_850 is not set
> > # CONFIG_NLS_CODEPAGE_852 is not set
> > # CONFIG_NLS_CODEPAGE_855 is not set
> > # CONFIG_NLS_CODEPAGE_857 is not set
> > # CONFIG_NLS_CODEPAGE_860 is not set
> > # CONFIG_NLS_CODEPAGE_861 is not set
> > # CONFIG_NLS_CODEPAGE_862 is not set
> > # CONFIG_NLS_CODEPAGE_863 is not set
> > # CONFIG_NLS_CODEPAGE_864 is not set
> > # CONFIG_NLS_CODEPAGE_865 is not set
> > # CONFIG_NLS_CODEPAGE_866 is not set
> > # CONFIG_NLS_CODEPAGE_869 is not set
> > # CONFIG_NLS_CODEPAGE_936 is not set
> > # CONFIG_NLS_CODEPAGE_950 is not set
> > # CONFIG_NLS_CODEPAGE_932 is not set
> > # CONFIG_NLS_CODEPAGE_949 is not set
> > # CONFIG_NLS_CODEPAGE_874 is not set
> > # CONFIG_NLS_ISO8859_8 is not set
> > # CONFIG_NLS_CODEPAGE_1250 is not set
> > # CONFIG_NLS_CODEPAGE_1251 is not set
> > # CONFIG_NLS_ASCII is not set
> > CONFIG_NLS_ISO8859_1=3Dy
> > # CONFIG_NLS_ISO8859_2 is not set
> > # CONFIG_NLS_ISO8859_3 is not set
> > # CONFIG_NLS_ISO8859_4 is not set
> > # CONFIG_NLS_ISO8859_5 is not set
> > # CONFIG_NLS_ISO8859_6 is not set
> > # CONFIG_NLS_ISO8859_7 is not set
> > # CONFIG_NLS_ISO8859_9 is not set
> > # CONFIG_NLS_ISO8859_13 is not set
> > # CONFIG_NLS_ISO8859_14 is not set
> > # CONFIG_NLS_ISO8859_15 is not set
> > # CONFIG_NLS_KOI8_R is not set
> > # CONFIG_NLS_KOI8_U is not set
> > # CONFIG_NLS_MAC_ROMAN is not set
> > # CONFIG_NLS_MAC_CELTIC is not set
> > # CONFIG_NLS_MAC_CENTEURO is not set
> > # CONFIG_NLS_MAC_CROATIAN is not set
> > # CONFIG_NLS_MAC_CYRILLIC is not set
> > # CONFIG_NLS_MAC_GAELIC is not set
> > # CONFIG_NLS_MAC_GREEK is not set
> > # CONFIG_NLS_MAC_ICELAND is not set
> > # CONFIG_NLS_MAC_INUIT is not set
> > # CONFIG_NLS_MAC_ROMANIAN is not set
> > # CONFIG_NLS_MAC_TURKISH is not set
> > # CONFIG_NLS_UTF8 is not set
> > CONFIG_UNICODE=3Dy
> > # CONFIG_UNICODE_NORMALIZATION_SELFTEST is not set
> > CONFIG_IO_WQ=3Dy
> > # end of File systems
> >=20
> > #
> > # Security options
> > #
> > CONFIG_KEYS=3Dy
> > # CONFIG_KEYS_REQUEST_CACHE is not set
> > # CONFIG_PERSISTENT_KEYRINGS is not set
> > # CONFIG_TRUSTED_KEYS is not set
> > # CONFIG_ENCRYPTED_KEYS is not set
> > # CONFIG_KEY_DH_OPERATIONS is not set
> > # CONFIG_SECURITY_DMESG_RESTRICT is not set
> > # CONFIG_SECURITY is not set
> > # CONFIG_SECURITYFS is not set
> > CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=3Dy
> > CONFIG_HARDENED_USERCOPY=3Dy
> > CONFIG_FORTIFY_SOURCE=3Dy
> > # CONFIG_STATIC_USERMODEHELPER is not set
> > CONFIG_DEFAULT_SECURITY_DAC=3Dy
> > CONFIG_LSM=3D"landlock,lockdown,yama,loadpin,safesetid,integrity,bpf"
> >=20
> > #
> > # Kernel hardening options
> > #
> >=20
> > #
> > # Memory initialization
> > #
> > CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN=3Dy
> > CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO_BARE=3Dy
> > CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO=3Dy
> > # CONFIG_INIT_STACK_NONE is not set
> > # CONFIG_INIT_STACK_ALL_PATTERN is not set
> > CONFIG_INIT_STACK_ALL_ZERO=3Dy
> > # CONFIG_GCC_PLUGIN_STACKLEAK is not set
> > # CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set
> > # CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
> > CONFIG_CC_HAS_ZERO_CALL_USED_REGS=3Dy
> > CONFIG_ZERO_CALL_USED_REGS=3Dy
> > # end of Memory initialization
> >=20
> > # CONFIG_RANDSTRUCT_NONE is not set
> > CONFIG_RANDSTRUCT_FULL=3Dy
> > # CONFIG_RANDSTRUCT_PERFORMANCE is not set
> > CONFIG_RANDSTRUCT=3Dy
> > CONFIG_GCC_PLUGIN_RANDSTRUCT=3Dy
> > # end of Kernel hardening options
> > # end of Security options
> >=20
> > CONFIG_XOR_BLOCKS=3Dy
> > CONFIG_CRYPTO=3Dy
> >=20
> > #
> > # Crypto core or helper
> > #
> > CONFIG_CRYPTO_ALGAPI=3Dy
> > CONFIG_CRYPTO_ALGAPI2=3Dy
> > CONFIG_CRYPTO_AEAD=3Dy
> > CONFIG_CRYPTO_AEAD2=3Dy
> > CONFIG_CRYPTO_SKCIPHER=3Dy
> > CONFIG_CRYPTO_SKCIPHER2=3Dy
> > CONFIG_CRYPTO_HASH=3Dy
> > CONFIG_CRYPTO_HASH2=3Dy
> > CONFIG_CRYPTO_RNG2=3Dy
> > CONFIG_CRYPTO_AKCIPHER2=3Dy
> > CONFIG_CRYPTO_AKCIPHER=3Dy
> > CONFIG_CRYPTO_KPP2=3Dy
> > CONFIG_CRYPTO_ACOMP2=3Dy
> > CONFIG_CRYPTO_MANAGER=3Dy
> > CONFIG_CRYPTO_MANAGER2=3Dy
> > # CONFIG_CRYPTO_USER is not set
> > CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=3Dy
> > CONFIG_CRYPTO_GF128MUL=3Dy
> > CONFIG_CRYPTO_NULL=3Dy
> > CONFIG_CRYPTO_NULL2=3Dy
> > # CONFIG_CRYPTO_PCRYPT is not set
> > # CONFIG_CRYPTO_CRYPTD is not set
> > CONFIG_CRYPTO_AUTHENC=3Dy
> > # end of Crypto core or helper
> >=20
> > #
> > # Public-key cryptography
> > #
> > CONFIG_CRYPTO_RSA=3Dy
> > # CONFIG_CRYPTO_DH is not set
> > # CONFIG_CRYPTO_ECDH is not set
> > # CONFIG_CRYPTO_ECDSA is not set
> > # CONFIG_CRYPTO_ECRDSA is not set
> > # CONFIG_CRYPTO_SM2 is not set
> > # CONFIG_CRYPTO_CURVE25519 is not set
> > # end of Public-key cryptography
> >=20
> > #
> > # Block ciphers
> > #
> > CONFIG_CRYPTO_AES=3Dy
> > # CONFIG_CRYPTO_AES_TI is not set
> > # CONFIG_CRYPTO_ARIA is not set
> > # CONFIG_CRYPTO_BLOWFISH is not set
> > # CONFIG_CRYPTO_CAMELLIA is not set
> > # CONFIG_CRYPTO_CAST5 is not set
> > # CONFIG_CRYPTO_CAST6 is not set
> > # CONFIG_CRYPTO_DES is not set
> > # CONFIG_CRYPTO_FCRYPT is not set
> > # CONFIG_CRYPTO_SERPENT is not set
> > # CONFIG_CRYPTO_SM4_GENERIC is not set
> > # CONFIG_CRYPTO_TWOFISH is not set
> > # end of Block ciphers
> >=20
> > #
> > # Length-preserving ciphers and modes
> > #
> > CONFIG_CRYPTO_ADIANTUM=3Dy
> > CONFIG_CRYPTO_CHACHA20=3Dy
> > CONFIG_CRYPTO_CBC=3Dy
> > # CONFIG_CRYPTO_CFB is not set
> > # CONFIG_CRYPTO_CTR is not set
> > CONFIG_CRYPTO_CTS=3Dy
> > CONFIG_CRYPTO_ECB=3Dy
> > CONFIG_CRYPTO_HCTR2=3Dy
> > # CONFIG_CRYPTO_KEYWRAP is not set
> > # CONFIG_CRYPTO_LRW is not set
> > # CONFIG_CRYPTO_OFB is not set
> > # CONFIG_CRYPTO_PCBC is not set
> > CONFIG_CRYPTO_XCTR=3Dy
> > CONFIG_CRYPTO_XTS=3Dy
> > CONFIG_CRYPTO_NHPOLY1305=3Dy
> > # end of Length-preserving ciphers and modes
> >=20
> > #
> > # AEAD (authenticated encryption with associated data) ciphers
> > #
> > # CONFIG_CRYPTO_AEGIS128 is not set
> > # CONFIG_CRYPTO_CHACHA20POLY1305 is not set
> > # CONFIG_CRYPTO_CCM is not set
> > # CONFIG_CRYPTO_GCM is not set
> > # CONFIG_CRYPTO_SEQIV is not set
> > # CONFIG_CRYPTO_ECHAINIV is not set
> > CONFIG_CRYPTO_ESSIV=3Dy
> > # end of AEAD (authenticated encryption with associated data) ciphers
> >=20
> > #
> > # Hashes, digests, and MACs
> > #
> > CONFIG_CRYPTO_BLAKE2B=3Dy
> > # CONFIG_CRYPTO_CMAC is not set
> > # CONFIG_CRYPTO_GHASH is not set
> > CONFIG_CRYPTO_HMAC=3Dy
> > # CONFIG_CRYPTO_MD4 is not set
> > # CONFIG_CRYPTO_MD5 is not set
> > # CONFIG_CRYPTO_MICHAEL_MIC is not set
> > CONFIG_CRYPTO_POLYVAL=3Dy
> > # CONFIG_CRYPTO_POLY1305 is not set
> > # CONFIG_CRYPTO_RMD160 is not set
> > # CONFIG_CRYPTO_SHA1 is not set
> > CONFIG_CRYPTO_SHA256=3Dy
> > CONFIG_CRYPTO_SHA512=3Dy
> > # CONFIG_CRYPTO_SHA3 is not set
> > # CONFIG_CRYPTO_SM3_GENERIC is not set
> > # CONFIG_CRYPTO_STREEBOG is not set
> > # CONFIG_CRYPTO_VMAC is not set
> > # CONFIG_CRYPTO_WP512 is not set
> > # CONFIG_CRYPTO_XCBC is not set
> > CONFIG_CRYPTO_XXHASH=3Dy
> > # end of Hashes, digests, and MACs
> >=20
> > #
> > # CRCs (cyclic redundancy checks)
> > #
> > CONFIG_CRYPTO_CRC32C=3Dy
> > CONFIG_CRYPTO_CRC32=3Dy
> > # CONFIG_CRYPTO_CRCT10DIF is not set
> > # end of CRCs (cyclic redundancy checks)
> >=20
> > #
> > # Compression
> > #
> > CONFIG_CRYPTO_DEFLATE=3Dy
> > CONFIG_CRYPTO_LZO=3Dy
> > # CONFIG_CRYPTO_842 is not set
> > # CONFIG_CRYPTO_LZ4 is not set
> > # CONFIG_CRYPTO_LZ4HC is not set
> > CONFIG_CRYPTO_ZSTD=3Dy
> > # end of Compression
> >=20
> > #
> > # Random number generation
> > #
> > # CONFIG_CRYPTO_ANSI_CPRNG is not set
> > # CONFIG_CRYPTO_DRBG_MENU is not set
> > # CONFIG_CRYPTO_JITTERENTROPY is not set
> > # end of Random number generation
> >=20
> > #
> > # Userspace interface
> > #
> > # CONFIG_CRYPTO_USER_API_HASH is not set
> > # CONFIG_CRYPTO_USER_API_SKCIPHER is not set
> > # CONFIG_CRYPTO_USER_API_RNG is not set
> > # CONFIG_CRYPTO_USER_API_AEAD is not set
> > # end of Userspace interface
> >=20
> > CONFIG_CRYPTO_HASH_INFO=3Dy
> >=20
> > #
> > # Accelerated Cryptographic Algorithms for CPU (x86)
> > #
> > # CONFIG_CRYPTO_CURVE25519_X86 is not set
> > # CONFIG_CRYPTO_AES_NI_INTEL is not set
> > # CONFIG_CRYPTO_BLOWFISH_X86_64 is not set
> > # CONFIG_CRYPTO_CAMELLIA_X86_64 is not set
> > # CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64 is not set
> > # CONFIG_CRYPTO_CAST5_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_CAST6_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_DES3_EDE_X86_64 is not set
> > # CONFIG_CRYPTO_SERPENT_SSE2_X86_64 is not set
> > # CONFIG_CRYPTO_SERPENT_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_SERPENT_AVX2_X86_64 is not set
> > # CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_SM4_AESNI_AVX2_X86_64 is not set
> > # CONFIG_CRYPTO_TWOFISH_X86_64 is not set
> > # CONFIG_CRYPTO_TWOFISH_X86_64_3WAY is not set
> > # CONFIG_CRYPTO_TWOFISH_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_ARIA_AESNI_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_CHACHA20_X86_64 is not set
> > # CONFIG_CRYPTO_AEGIS128_AESNI_SSE2 is not set
> > # CONFIG_CRYPTO_NHPOLY1305_SSE2 is not set
> > # CONFIG_CRYPTO_NHPOLY1305_AVX2 is not set
> > # CONFIG_CRYPTO_BLAKE2S_X86 is not set
> > # CONFIG_CRYPTO_POLYVAL_CLMUL_NI is not set
> > # CONFIG_CRYPTO_POLY1305_X86_64 is not set
> > # CONFIG_CRYPTO_SHA1_SSSE3 is not set
> > # CONFIG_CRYPTO_SHA256_SSSE3 is not set
> > # CONFIG_CRYPTO_SHA512_SSSE3 is not set
> > # CONFIG_CRYPTO_SM3_AVX_X86_64 is not set
> > # CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL is not set
> > # CONFIG_CRYPTO_CRC32C_INTEL is not set
> > # CONFIG_CRYPTO_CRC32_PCLMUL is not set
> > # end of Accelerated Cryptographic Algorithms for CPU (x86)
> >=20
> > CONFIG_CRYPTO_HW=3Dy
> > # CONFIG_CRYPTO_DEV_PADLOCK is not set
> > # CONFIG_CRYPTO_DEV_CCP is not set
> > # CONFIG_CRYPTO_DEV_QAT_DH895xCC is not set
> > # CONFIG_CRYPTO_DEV_QAT_C3XXX is not set
> > # CONFIG_CRYPTO_DEV_QAT_C62X is not set
> > # CONFIG_CRYPTO_DEV_QAT_4XXX is not set
> > # CONFIG_CRYPTO_DEV_QAT_DH895xCCVF is not set
> > # CONFIG_CRYPTO_DEV_QAT_C3XXXVF is not set
> > # CONFIG_CRYPTO_DEV_QAT_C62XVF is not set
> > # CONFIG_CRYPTO_DEV_NITROX_CNN55XX is not set
> > # CONFIG_CRYPTO_DEV_VIRTIO is not set
> > # CONFIG_CRYPTO_DEV_SAFEXCEL is not set
> > # CONFIG_CRYPTO_DEV_AMLOGIC_GXL is not set
> > CONFIG_ASYMMETRIC_KEY_TYPE=3Dy
> > CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=3Dy
> > CONFIG_X509_CERTIFICATE_PARSER=3Dy
> > # CONFIG_PKCS8_PRIVATE_KEY_PARSER is not set
> > CONFIG_PKCS7_MESSAGE_PARSER=3Dy
> > # CONFIG_PKCS7_TEST_KEY is not set
> > # CONFIG_SIGNED_PE_FILE_VERIFICATION is not set
> > # CONFIG_FIPS_SIGNATURE_SELFTEST is not set
> >=20
> > #
> > # Certificates for signature checking
> > #
> > CONFIG_SYSTEM_TRUSTED_KEYRING=3Dy
> > CONFIG_SYSTEM_TRUSTED_KEYS=3D""
> > # CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
> > # CONFIG_SECONDARY_TRUSTED_KEYRING is not set
> > # CONFIG_SYSTEM_BLACKLIST_KEYRING is not set
> > # end of Certificates for signature checking
> >=20
> > CONFIG_BINARY_PRINTF=3Dy
> >=20
> > #
> > # Library routines
> > #
> > CONFIG_RAID6_PQ=3Dy
> > CONFIG_RAID6_PQ_BENCHMARK=3Dy
> > # CONFIG_PACKING is not set
> > CONFIG_BITREVERSE=3Dy
> > CONFIG_GENERIC_STRNCPY_FROM_USER=3Dy
> > CONFIG_GENERIC_STRNLEN_USER=3Dy
> > CONFIG_GENERIC_NET_UTILS=3Dy
> > # CONFIG_CORDIC is not set
> > # CONFIG_PRIME_NUMBERS is not set
> > CONFIG_RATIONAL=3Dy
> > CONFIG_GENERIC_PCI_IOMAP=3Dy
> > CONFIG_GENERIC_IOMAP=3Dy
> > CONFIG_ARCH_USE_CMPXCHG_LOCKREF=3Dy
> > CONFIG_ARCH_HAS_FAST_MULTIPLIER=3Dy
> > CONFIG_ARCH_USE_SYM_ANNOTATIONS=3Dy
> >=20
> > #
> > # Crypto library routines
> > #
> > CONFIG_CRYPTO_LIB_UTILS=3Dy
> > CONFIG_CRYPTO_LIB_AES=3Dy
> > CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC=3Dy
> > CONFIG_CRYPTO_LIB_CHACHA_GENERIC=3Dy
> > # CONFIG_CRYPTO_LIB_CHACHA is not set
> > # CONFIG_CRYPTO_LIB_CURVE25519 is not set
> > CONFIG_CRYPTO_LIB_POLY1305_RSIZE=3D11
> > CONFIG_CRYPTO_LIB_POLY1305_GENERIC=3Dy
> > # CONFIG_CRYPTO_LIB_POLY1305 is not set
> > # CONFIG_CRYPTO_LIB_CHACHA20POLY1305 is not set
> > CONFIG_CRYPTO_LIB_SHA1=3Dy
> > CONFIG_CRYPTO_LIB_SHA256=3Dy
> > # end of Crypto library routines
> >=20
> > # CONFIG_CRC_CCITT is not set
> > CONFIG_CRC16=3Dy
> > # CONFIG_CRC_T10DIF is not set
> > # CONFIG_CRC64_ROCKSOFT is not set
> > # CONFIG_CRC_ITU_T is not set
> > CONFIG_CRC32=3Dy
> > # CONFIG_CRC32_SELFTEST is not set
> > CONFIG_CRC32_SLICEBY8=3Dy
> > # CONFIG_CRC32_SLICEBY4 is not set
> > # CONFIG_CRC32_SARWATE is not set
> > # CONFIG_CRC32_BIT is not set
> > # CONFIG_CRC64 is not set
> > # CONFIG_CRC4 is not set
> > # CONFIG_CRC7 is not set
> > CONFIG_LIBCRC32C=3Dy
> > # CONFIG_CRC8 is not set
> > CONFIG_XXHASH=3Dy
> > # CONFIG_RANDOM32_SELFTEST is not set
> > CONFIG_ZLIB_INFLATE=3Dy
> > CONFIG_ZLIB_DEFLATE=3Dy
> > CONFIG_LZO_COMPRESS=3Dy
> > CONFIG_LZO_DECOMPRESS=3Dy
> > CONFIG_LZ4_COMPRESS=3Dy
> > CONFIG_LZ4HC_COMPRESS=3Dy
> > CONFIG_LZ4_DECOMPRESS=3Dy
> > CONFIG_ZSTD_COMMON=3Dy
> > CONFIG_ZSTD_COMPRESS=3Dy
> > CONFIG_ZSTD_DECOMPRESS=3Dy
> > CONFIG_XZ_DEC=3Dy
> > CONFIG_XZ_DEC_X86=3Dy
> > CONFIG_XZ_DEC_POWERPC=3Dy
> > CONFIG_XZ_DEC_IA64=3Dy
> > CONFIG_XZ_DEC_ARM=3Dy
> > CONFIG_XZ_DEC_ARMTHUMB=3Dy
> > CONFIG_XZ_DEC_SPARC=3Dy
> > # CONFIG_XZ_DEC_MICROLZMA is not set
> > CONFIG_XZ_DEC_BCJ=3Dy
> > # CONFIG_XZ_DEC_TEST is not set
> > CONFIG_DECOMPRESS_GZIP=3Dy
> > CONFIG_DECOMPRESS_BZIP2=3Dy
> > CONFIG_DECOMPRESS_LZMA=3Dy
> > CONFIG_DECOMPRESS_XZ=3Dy
> > CONFIG_DECOMPRESS_LZO=3Dy
> > CONFIG_DECOMPRESS_LZ4=3Dy
> > CONFIG_DECOMPRESS_ZSTD=3Dy
> > CONFIG_GENERIC_ALLOCATOR=3Dy
> > CONFIG_ASSOCIATIVE_ARRAY=3Dy
> > CONFIG_HAS_IOMEM=3Dy
> > CONFIG_HAS_IOPORT_MAP=3Dy
> > CONFIG_HAS_DMA=3Dy
> > CONFIG_NEED_SG_DMA_LENGTH=3Dy
> > CONFIG_NEED_DMA_MAP_STATE=3Dy
> > CONFIG_ARCH_DMA_ADDR_T_64BIT=3Dy
> > CONFIG_SWIOTLB=3Dy
> > # CONFIG_DMA_API_DEBUG is not set
> > # CONFIG_DMA_MAP_BENCHMARK is not set
> > CONFIG_SGL_ALLOC=3Dy
> > # CONFIG_FORCE_NR_CPUS is not set
> > CONFIG_CPU_RMAP=3Dy
> > CONFIG_DQL=3Dy
> > CONFIG_GLOB=3Dy
> > # CONFIG_GLOB_SELFTEST is not set
> > CONFIG_NLATTR=3Dy
> > CONFIG_CLZ_TAB=3Dy
> > # CONFIG_IRQ_POLL is not set
> > CONFIG_MPILIB=3Dy
> > CONFIG_OID_REGISTRY=3Dy
> > CONFIG_HAVE_GENERIC_VDSO=3Dy
> > CONFIG_GENERIC_GETTIMEOFDAY=3Dy
> > CONFIG_GENERIC_VDSO_TIME_NS=3Dy
> > CONFIG_SG_POOL=3Dy
> > CONFIG_ARCH_HAS_PMEM_API=3Dy
> > CONFIG_MEMREGION=3Dy
> > CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=3Dy
> > CONFIG_ARCH_HAS_COPY_MC=3Dy
> > CONFIG_ARCH_STACKWALK=3Dy
> > CONFIG_STACKDEPOT=3Dy
> > CONFIG_STACKDEPOT_ALWAYS_INIT=3Dy
> > CONFIG_SBITMAP=3Dy
> > # end of Library routines
> >=20
> > #
> > # Kernel hacking
> > #
> >=20
> > #
> > # printk and dmesg options
> > #
> > CONFIG_PRINTK_TIME=3Dy
> > # CONFIG_PRINTK_CALLER is not set
> > # CONFIG_STACKTRACE_BUILD_ID is not set
> > CONFIG_CONSOLE_LOGLEVEL_DEFAULT=3D7
> > CONFIG_CONSOLE_LOGLEVEL_QUIET=3D4
> > CONFIG_MESSAGE_LOGLEVEL_DEFAULT=3D4
> > # CONFIG_BOOT_PRINTK_DELAY is not set
> > CONFIG_DYNAMIC_DEBUG=3Dy
> > CONFIG_DYNAMIC_DEBUG_CORE=3Dy
> > CONFIG_SYMBOLIC_ERRNAME=3Dy
> > CONFIG_DEBUG_BUGVERBOSE=3Dy
> > # end of printk and dmesg options
> >=20
> > CONFIG_DEBUG_KERNEL=3Dy
> > CONFIG_DEBUG_MISC=3Dy
> >=20
> > #
> > # Compile-time checks and compiler options
> > #
> > CONFIG_DEBUG_INFO=3Dy
> > CONFIG_AS_HAS_NON_CONST_LEB128=3Dy
> > # CONFIG_DEBUG_INFO_NONE is not set
> > # CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set
> > # CONFIG_DEBUG_INFO_DWARF4 is not set
> > CONFIG_DEBUG_INFO_DWARF5=3Dy
> > CONFIG_DEBUG_INFO_REDUCED=3Dy
> > # CONFIG_DEBUG_INFO_COMPRESSED is not set
> > # CONFIG_DEBUG_INFO_SPLIT is not set
> > # CONFIG_GDB_SCRIPTS is not set
> > CONFIG_FRAME_WARN=3D2048
> > # CONFIG_STRIP_ASM_SYMS is not set
> > # CONFIG_READABLE_ASM is not set
> > # CONFIG_HEADERS_INSTALL is not set
> > CONFIG_DEBUG_SECTION_MISMATCH=3Dy
> > CONFIG_SECTION_MISMATCH_WARN_ONLY=3Dy
> > CONFIG_FRAME_POINTER=3Dy
> > CONFIG_OBJTOOL=3Dy
> > # CONFIG_STACK_VALIDATION is not set
> > # CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
> > # end of Compile-time checks and compiler options
> >=20
> > #
> > # Generic Kernel Debugging Instruments
> > #
> > # CONFIG_MAGIC_SYSRQ is not set
> > CONFIG_DEBUG_FS=3Dy
> > CONFIG_DEBUG_FS_ALLOW_ALL=3Dy
> > # CONFIG_DEBUG_FS_DISALLOW_MOUNT is not set
> > # CONFIG_DEBUG_FS_ALLOW_NONE is not set
> > CONFIG_HAVE_ARCH_KGDB=3Dy
> > # CONFIG_KGDB is not set
> > CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=3Dy
> > # CONFIG_UBSAN is not set
> > CONFIG_HAVE_ARCH_KCSAN=3Dy
> > CONFIG_HAVE_KCSAN_COMPILER=3Dy
> > # end of Generic Kernel Debugging Instruments
> >=20
> > #
> > # Networking Debugging
> > #
> > # CONFIG_NET_DEV_REFCNT_TRACKER is not set
> > # CONFIG_NET_NS_REFCNT_TRACKER is not set
> > # CONFIG_DEBUG_NET is not set
> > # end of Networking Debugging
> >=20
> > #
> > # Memory Debugging
> > #
> > # CONFIG_PAGE_EXTENSION is not set
> > CONFIG_DEBUG_PAGEALLOC=3Dy
> > # CONFIG_DEBUG_PAGEALLOC_ENABLE_DEFAULT is not set
> > CONFIG_SLUB_DEBUG=3Dy
> > # CONFIG_SLUB_DEBUG_ON is not set
> > # CONFIG_PAGE_OWNER is not set
> > # CONFIG_PAGE_TABLE_CHECK is not set
> > # CONFIG_PAGE_POISONING is not set
> > # CONFIG_DEBUG_PAGE_REF is not set
> > # CONFIG_DEBUG_RODATA_TEST is not set
> > CONFIG_ARCH_HAS_DEBUG_WX=3Dy
> > CONFIG_DEBUG_WX=3Dy
> > CONFIG_GENERIC_PTDUMP=3Dy
> > CONFIG_PTDUMP_CORE=3Dy
> > # CONFIG_PTDUMP_DEBUGFS is not set
> > # CONFIG_DEBUG_OBJECTS is not set
> > # CONFIG_SHRINKER_DEBUG is not set
> > CONFIG_HAVE_DEBUG_KMEMLEAK=3Dy
> > # CONFIG_DEBUG_KMEMLEAK is not set
> > # CONFIG_DEBUG_STACK_USAGE is not set
> > # CONFIG_SCHED_STACK_END_CHECK is not set
> > CONFIG_ARCH_HAS_DEBUG_VM_PGTABLE=3Dy
> > CONFIG_DEBUG_VM_IRQSOFF=3Dy
> > CONFIG_DEBUG_VM=3Dy
> > # CONFIG_DEBUG_VM_MAPLE_TREE is not set
> > # CONFIG_DEBUG_VM_RB is not set
> > # CONFIG_DEBUG_VM_PGFLAGS is not set
> > CONFIG_DEBUG_VM_PGTABLE=3Dy
> > CONFIG_ARCH_HAS_DEBUG_VIRTUAL=3Dy
> > # CONFIG_DEBUG_VIRTUAL is not set
> > CONFIG_DEBUG_MEMORY_INIT=3Dy
> > # CONFIG_DEBUG_PER_CPU_MAPS is not set
> > CONFIG_ARCH_SUPPORTS_KMAP_LOCAL_FORCE_MAP=3Dy
> > # CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP is not set
> > CONFIG_HAVE_ARCH_KASAN=3Dy
> > CONFIG_HAVE_ARCH_KASAN_VMALLOC=3Dy
> > CONFIG_CC_HAS_KASAN_GENERIC=3Dy
> > CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS=3Dy
> > CONFIG_KASAN=3Dy
> > CONFIG_KASAN_GENERIC=3Dy
> > # CONFIG_KASAN_OUTLINE is not set
> > CONFIG_KASAN_INLINE=3Dy
> > CONFIG_KASAN_STACK=3Dy
> > CONFIG_KASAN_VMALLOC=3Dy
> > CONFIG_HAVE_ARCH_KFENCE=3Dy
> > # CONFIG_KFENCE is not set
> > CONFIG_HAVE_ARCH_KMSAN=3Dy
> > # end of Memory Debugging
> >=20
> > # CONFIG_DEBUG_SHIRQ is not set
> >=20
> > #
> > # Debug Oops, Lockups and Hangs
> > #
> > # CONFIG_PANIC_ON_OOPS is not set
> > CONFIG_PANIC_ON_OOPS_VALUE=3D0
> > CONFIG_PANIC_TIMEOUT=3D5
> > CONFIG_LOCKUP_DETECTOR=3Dy
> > CONFIG_SOFTLOCKUP_DETECTOR=3Dy
> > # CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC is not set
> > CONFIG_HARDLOCKUP_DETECTOR_PERF=3Dy
> > CONFIG_HARDLOCKUP_CHECK_TIMESTAMP=3Dy
> > CONFIG_HARDLOCKUP_DETECTOR=3Dy
> > # CONFIG_BOOTPARAM_HARDLOCKUP_PANIC is not set
> > CONFIG_DETECT_HUNG_TASK=3Dy
> > CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=3D30
> > # CONFIG_BOOTPARAM_HUNG_TASK_PANIC is not set
> > CONFIG_WQ_WATCHDOG=3Dy
> > # end of Debug Oops, Lockups and Hangs
> >=20
> > #
> > # Scheduler Debugging
> > #
> > CONFIG_SCHED_DEBUG=3Dy
> > # CONFIG_SCHEDSTATS is not set
> > # end of Scheduler Debugging
> >=20
> > # CONFIG_DEBUG_TIMEKEEPING is not set
> > CONFIG_DEBUG_PREEMPT=3Dy
> >=20
> > #
> > # Lock Debugging (spinlocks, mutexes, etc...)
> > #
> > CONFIG_LOCK_DEBUGGING_SUPPORT=3Dy
> > CONFIG_PROVE_LOCKING=3Dy
> > # CONFIG_PROVE_RAW_LOCK_NESTING is not set
> > # CONFIG_LOCK_STAT is not set
> > CONFIG_DEBUG_RT_MUTEXES=3Dy
> > CONFIG_DEBUG_SPINLOCK=3Dy
> > CONFIG_DEBUG_MUTEXES=3Dy
> > CONFIG_DEBUG_WW_MUTEX_SLOWPATH=3Dy
> > CONFIG_DEBUG_RWSEMS=3Dy
> > CONFIG_DEBUG_LOCK_ALLOC=3Dy
> > CONFIG_LOCKDEP=3Dy
> > CONFIG_LOCKDEP_BITS=3D15
> > CONFIG_LOCKDEP_CHAINS_BITS=3D16
> > CONFIG_LOCKDEP_STACK_TRACE_BITS=3D19
> > CONFIG_LOCKDEP_STACK_TRACE_HASH_BITS=3D14
> > CONFIG_LOCKDEP_CIRCULAR_QUEUE_BITS=3D12
> > # CONFIG_DEBUG_LOCKDEP is not set
> > CONFIG_DEBUG_ATOMIC_SLEEP=3Dy
> > # CONFIG_DEBUG_LOCKING_API_SELFTESTS is not set
> > # CONFIG_LOCK_TORTURE_TEST is not set
> > # CONFIG_WW_MUTEX_SELFTEST is not set
> > # CONFIG_SCF_TORTURE_TEST is not set
> > # CONFIG_CSD_LOCK_WAIT_DEBUG is not set
> > # end of Lock Debugging (spinlocks, mutexes, etc...)
> >=20
> > CONFIG_TRACE_IRQFLAGS=3Dy
> > CONFIG_TRACE_IRQFLAGS_NMI=3Dy
> > # CONFIG_DEBUG_IRQFLAGS is not set
> > CONFIG_STACKTRACE=3Dy
> > # CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
> > # CONFIG_DEBUG_KOBJECT is not set
> >=20
> > #
> > # Debug kernel data structures
> > #
> > CONFIG_DEBUG_LIST=3Dy
> > # CONFIG_DEBUG_PLIST is not set
> > CONFIG_DEBUG_SG=3Dy
> > # CONFIG_DEBUG_NOTIFIERS is not set
> > # CONFIG_BUG_ON_DATA_CORRUPTION is not set
> > # CONFIG_DEBUG_MAPLE_TREE is not set
> > # end of Debug kernel data structures
> >=20
> > CONFIG_DEBUG_CREDENTIALS=3Dy
> >=20
> > #
> > # RCU Debugging
> > #
> > CONFIG_PROVE_RCU=3Dy
> > # CONFIG_RCU_SCALE_TEST is not set
> > # CONFIG_RCU_TORTURE_TEST is not set
> > # CONFIG_RCU_REF_SCALE_TEST is not set
> > CONFIG_RCU_CPU_STALL_TIMEOUT=3D10
> > CONFIG_RCU_EXP_CPU_STALL_TIMEOUT=3D0
> > CONFIG_RCU_TRACE=3Dy
> > CONFIG_RCU_EQS_DEBUG=3Dy
> > # end of RCU Debugging
> >=20
> > # CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
> > # CONFIG_CPU_HOTPLUG_STATE_CONTROL is not set
> > # CONFIG_LATENCYTOP is not set
> > CONFIG_USER_STACKTRACE_SUPPORT=3Dy
> > CONFIG_NOP_TRACER=3Dy
> > CONFIG_HAVE_RETHOOK=3Dy
> > CONFIG_HAVE_FUNCTION_TRACER=3Dy
> > CONFIG_HAVE_DYNAMIC_FTRACE=3Dy
> > CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=3Dy
> > CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=3Dy
> > CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=3Dy
> > CONFIG_HAVE_DYNAMIC_FTRACE_NO_PATCHABLE=3Dy
> > CONFIG_HAVE_FTRACE_MCOUNT_RECORD=3Dy
> > CONFIG_HAVE_SYSCALL_TRACEPOINTS=3Dy
> > CONFIG_HAVE_FENTRY=3Dy
> > CONFIG_HAVE_OBJTOOL_MCOUNT=3Dy
> > CONFIG_HAVE_C_RECORDMCOUNT=3Dy
> > CONFIG_HAVE_BUILDTIME_MCOUNT_SORT=3Dy
> > CONFIG_TRACE_CLOCK=3Dy
> > CONFIG_RING_BUFFER=3Dy
> > CONFIG_EVENT_TRACING=3Dy
> > CONFIG_CONTEXT_SWITCH_TRACER=3Dy
> > CONFIG_PREEMPTIRQ_TRACEPOINTS=3Dy
> > CONFIG_TRACING=3Dy
> > CONFIG_TRACING_SUPPORT=3Dy
> > # CONFIG_FTRACE is not set
> > # CONFIG_PROVIDE_OHCI1394_DMA_INIT is not set
> > # CONFIG_SAMPLES is not set
> > CONFIG_HAVE_SAMPLE_FTRACE_DIRECT=3Dy
> > CONFIG_HAVE_SAMPLE_FTRACE_DIRECT_MULTI=3Dy
> > CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=3Dy
> > CONFIG_STRICT_DEVMEM=3Dy
> > # CONFIG_IO_STRICT_DEVMEM is not set
> >=20
> > #
> > # x86 Debugging
> > #
> > CONFIG_X86_VERBOSE_BOOTUP=3Dy
> > CONFIG_EARLY_PRINTK=3Dy
> > # CONFIG_EARLY_PRINTK_DBGP is not set
> > # CONFIG_EARLY_PRINTK_USB_XDBC is not set
> > # CONFIG_DEBUG_TLBFLUSH is not set
> > CONFIG_HAVE_MMIOTRACE_SUPPORT=3Dy
> > # CONFIG_X86_DECODER_SELFTEST is not set
> > CONFIG_IO_DELAY_0X80=3Dy
> > # CONFIG_IO_DELAY_0XED is not set
> > # CONFIG_IO_DELAY_UDELAY is not set
> > # CONFIG_IO_DELAY_NONE is not set
> > # CONFIG_DEBUG_BOOT_PARAMS is not set
> > # CONFIG_CPA_DEBUG is not set
> > # CONFIG_DEBUG_ENTRY is not set
> > # CONFIG_DEBUG_NMI_SELFTEST is not set
> > CONFIG_X86_DEBUG_FPU=3Dy
> > # CONFIG_PUNIT_ATOM_DEBUG is not set
> > # CONFIG_UNWINDER_ORC is not set
> > CONFIG_UNWINDER_FRAME_POINTER=3Dy
> > # end of x86 Debugging
> >=20
> > #
> > # Kernel Testing and Coverage
> > #
> > # CONFIG_KUNIT is not set
> > # CONFIG_NOTIFIER_ERROR_INJECTION is not set
> > CONFIG_FAULT_INJECTION=3Dy
> > CONFIG_FAILSLAB=3Dy
> > CONFIG_FAIL_PAGE_ALLOC=3Dy
> > # CONFIG_FAULT_INJECTION_USERCOPY is not set
> > CONFIG_FAIL_MAKE_REQUEST=3Dy
> > # CONFIG_FAIL_IO_TIMEOUT is not set
> > CONFIG_FAIL_FUTEX=3Dy
> > CONFIG_FAULT_INJECTION_DEBUG_FS=3Dy
> > CONFIG_ARCH_HAS_KCOV=3Dy
> > CONFIG_CC_HAS_SANCOV_TRACE_PC=3Dy
> > # CONFIG_KCOV is not set
> > CONFIG_RUNTIME_TESTING_MENU=3Dy
> > # CONFIG_LKDTM is not set
> > # CONFIG_TEST_MIN_HEAP is not set
> > # CONFIG_TEST_DIV64 is not set
> > # CONFIG_BACKTRACE_SELF_TEST is not set
> > # CONFIG_TEST_REF_TRACKER is not set
> > # CONFIG_RBTREE_TEST is not set
> > # CONFIG_REED_SOLOMON_TEST is not set
> > # CONFIG_INTERVAL_TREE_TEST is not set
> > # CONFIG_ATOMIC64_SELFTEST is not set
> > # CONFIG_TEST_HEXDUMP is not set
> > # CONFIG_STRING_SELFTEST is not set
> > # CONFIG_TEST_STRING_HELPERS is not set
> > # CONFIG_TEST_STRSCPY is not set
> > # CONFIG_TEST_KSTRTOX is not set
> > # CONFIG_TEST_PRINTF is not set
> > # CONFIG_TEST_SCANF is not set
> > # CONFIG_TEST_BITMAP is not set
> > # CONFIG_TEST_UUID is not set
> > # CONFIG_TEST_XARRAY is not set
> > # CONFIG_TEST_MAPLE_TREE is not set
> > # CONFIG_TEST_RHASHTABLE is not set
> > # CONFIG_TEST_SIPHASH is not set
> > # CONFIG_TEST_IDA is not set
> > # CONFIG_FIND_BIT_BENCHMARK is not set
> > # CONFIG_TEST_FIRMWARE is not set
> > # CONFIG_TEST_SYSCTL is not set
> > # CONFIG_TEST_UDELAY is not set
> > # CONFIG_TEST_DYNAMIC_DEBUG is not set
> > # CONFIG_TEST_MEMCAT_P is not set
> > # CONFIG_TEST_MEMINIT is not set
> > # CONFIG_TEST_FREE_PAGES is not set
> > # CONFIG_TEST_FPU is not set
> > # CONFIG_TEST_CLOCKSOURCE_WATCHDOG is not set
> > CONFIG_ARCH_USE_MEMTEST=3Dy
> > # CONFIG_MEMTEST is not set
> > # end of Kernel Testing and Coverage
> >=20
> > #
> > # Rust hacking
> > #
> > # end of Rust hacking
> > # end of Kernel hacking

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y6Z%2BWpqN59ZjIKkk%40zx2c4.com.
