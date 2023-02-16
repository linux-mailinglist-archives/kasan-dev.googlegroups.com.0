Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS6JW6PQMGQERLMVVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 655B6698E4F
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 09:09:48 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id a42-20020a05651c212a00b002924f5e061dsf210564ljq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 00:09:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676534987; cv=pass;
        d=google.com; s=arc-20160816;
        b=vDEqAKrVOtUuchYmKR3al1joB4yaRej3khfbHss3w2+wD1EcY7wdxHn4h2GiOiiyBF
         rqrZqJ2jSuzo7ciPwvQdHQGOUCiiPxdiVC6mcKcWmt3Ujin27G7nsq07H/NdSmvBbDpI
         wFkZE9TwP28724d3gfOay5h3Ja2LYao6ZIF1U/KojnGmboGfKs723VNwcHzsdy8225cb
         P8YVbXlJ0x0z6zEGRNeXVcVOD37mmdDpPf4iRWjDEJYZh9nUmKYqYkvJwvf12Lx8SmwB
         2E4+5haXZpE3ycYSxJtYyKJW+aDtygetsOwXH+xTod45QyI4pZE4OJ76D1Mua18mCOeA
         PHXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=lXpeTrdoDTF1dhaljs/RT0X6wKCRpz7vxcjLW/zsDE4=;
        b=gQruCDIv9Yga5M1HUbMeNQgfQaDtPNdyWqUJhvv5MmYpyq1Cyqer9eesl5aziHcc9l
         8SaBOuRSfD5y+C2tgf5VW/HbqDBx6pn7rcVvxIx6ON3FuBOSI7zqBwrVHSdMqBDimIaH
         fW+bk2c0W8ejJxsI7zEEilmigCIvFD8nru/evaVsIkeFDPWdWDCW8TLGNCJoXcd/y3dj
         5gfuoKcI3AbcfCbO61VgeH90KNh5e0WwaXzAhpFo6cxgD0UZlUzmEsZ2vopysMXw0ZqG
         CnonMQ7ONhlld/ClLCJ3CfQpvj4OunNeabNH/lxZXHTuSdVYsKaiTtsbtN3xVQ71yJ0s
         YAxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GNTFnvYh;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lXpeTrdoDTF1dhaljs/RT0X6wKCRpz7vxcjLW/zsDE4=;
        b=Fk5JPiOnc48j05mD46m/5eaVE5IWo4tLH3yrpNTVd2gtxS9sam+I/fxmSyWfmlYxd4
         BPzIURc+WWBMq2T3ONT/umC+g8w7WLN53CFZCodnrsqup1rng+kl6EPpguwIJodzEczY
         7hnHraWJsJWQL9oVdNXyaJ+BL7KNtHXlFbyXZ73FoSfrw+ccQPSLETmjrARWsfLEgRjx
         OCcmWKd65c1F9mXsOQJ9dWz0imXCNTpPcujpARy61uh4NxtvguC5AllB6xQKXL3MPl8J
         EKKFYz6FRIaeJNV5KYFNqgkh1garxMWL4kt5Niirn2VRz5GWzHa0EHfbmdquphYc73s9
         2+Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lXpeTrdoDTF1dhaljs/RT0X6wKCRpz7vxcjLW/zsDE4=;
        b=xA+WRU7ocNMOc+CZuVoLsPgds9Yz9idk5lbksJV9btIMygulTZSFpsPZsfkcCSvw2n
         By8q9aToJ9MVdtgdBByCFNOo5pcA6y+P3kc1y771E99kWujYR/d5I4dZ46LW5pm+WLQ1
         aDwa61nDT5DJ8GC8zpdAYRFFMsqCPfc4zl2NPHPDXj275/MZDVuZOiNra+0UJcOK/qt8
         v0s7LSXqw3xZfaTgXIxxow0VMg1q4sLZxXnuY3xp8q7QDFRsQPd9eLnw3efN4uilqASe
         tATvKzs+49dYGh1uhodvC4N6XWyjNYj1reXCQM2D8t/Mq57WcxUgXqmj+eqq3tnTgHbb
         LlWA==
X-Gm-Message-State: AO0yUKWLLbjQpPgjXGbhGvPmWuwIJM13vN4rUW5PMTOGrIom7PkUjXMJ
	dxG3eghV+BDaEgzAc1q9d/o=
X-Google-Smtp-Source: AK7set8vdIgs6jNURrmB9Fi2kv0ZHjUoJ7tzW4NS9SytkfyF/q1ZKy7eQ7JQHcRQNiUZSap6j+4uCg==
X-Received: by 2002:a2e:a4b7:0:b0:293:4be3:9e6c with SMTP id g23-20020a2ea4b7000000b002934be39e6cmr1443137ljm.1.1676534987549;
        Thu, 16 Feb 2023 00:09:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b0f:b0:293:5310:5e0e with SMTP id
 b15-20020a05651c0b0f00b0029353105e0els225644ljr.7.-pod-prod-gmail; Thu, 16
 Feb 2023 00:09:45 -0800 (PST)
X-Received: by 2002:a2e:b162:0:b0:293:ed1:8674 with SMTP id a2-20020a2eb162000000b002930ed18674mr2235895ljm.29.1676534985727;
        Thu, 16 Feb 2023 00:09:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676534985; cv=none;
        d=google.com; s=arc-20160816;
        b=nhjqJB9+l7DyC76BRXs9coDvaCszLOG65CaDsnn3hjEXGCD8reTVQavfIp9zo6Vvea
         DtIkbwKyXo0BEqydW3sU4PCYRFerjYy4G4A+CbNHO/Pec6wnjrkApMMKrV/wUrCI9nIL
         hf4AG9fR06hfszkavRi9EWyqtgGlin4uQc4+6fNB03knFhP2FFoiIQOEelik+yIXU/IM
         t7RlQlHZxCCOMEueLuWu3lJSk7vbq740KtMfyldlqNuzGzzR3t18/s5GBFw0gHoTNI1P
         aD4iJ/5Z+Xex6kH/7wS41sfwE9C0Sp3b80XUXK6ssIkBfDyEqpy6MPYkBBOtMApD+B9/
         f24g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LPmlvzBmYvvcjdUPaFapX0ujkjEhw9P6vRzvD3nGlUc=;
        b=Ize/PRr/9UjMMLjaeNsBke51avAjZw5idg6I8f9NVEwb5u3gR6dfm9Dn5cwOD8Wmc5
         Fb+cG3tkmgUKhqp/Xr27aMRk8jsPsg+6Ev0FLP0kLEAvJD8TjVms6+3210e96SySzTe1
         xb9xxXJJx0naWFW3j4H9Ir+lPtepIbgDHf7GNZIyeHKoJvvTw+9M43MpoIl0PfrvtA/2
         Oj0pGmCF+Yun73mkLtcY4zgZdlxHfWHj0L2H5j4KESqvtkDsFS4SFa5B4rkIGNjuwa5a
         wNgOpfSkXSXe1Q/schr2ntbz+OuqHQkemp2SzESi4knTXbRnWhU3AZfefXsyfJz3b6hI
         tR8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GNTFnvYh;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id o16-20020a05651c051000b0028ffa3d673asi28360ljp.3.2023.02.16.00.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 00:09:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id s13-20020a05600c45cd00b003ddca7a2bcbso930800wmo.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 00:09:45 -0800 (PST)
X-Received: by 2002:a05:600c:80a:b0:3db:2e06:4091 with SMTP id k10-20020a05600c080a00b003db2e064091mr4865174wmp.37.1676534985292;
        Thu, 16 Feb 2023 00:09:45 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:f376:75c5:59e9:fb1c])
        by smtp.gmail.com with ESMTPSA id he8-20020a05600c540800b003e208cec49bsm2503310wmb.3.2023.02.16.00.09.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Feb 2023 00:09:44 -0800 (PST)
Date: Thu, 16 Feb 2023 09:09:38 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Rohan McLure <rmclure@linux.ibm.com>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"mpe@ellerman.id.au" <mpe@ellerman.id.au>,
	Max Filippov <jcmvbkbc@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH 1/2] kcsan: xtensa: Add atomic builtin stubs for 32-bit
 systems
Message-ID: <Y+3kwmFhWilN2OaE@elver.google.com>
References: <20230216050938.2188488-1-rmclure@linux.ibm.com>
 <42e62369-8dd0-cbfc-855d-7ad18e518cee@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <42e62369-8dd0-cbfc-855d-7ad18e518cee@csgroup.eu>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GNTFnvYh;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::332 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Feb 16, 2023 at 07:12AM +0000, Christophe Leroy wrote:
>=20
>=20
> Le 16/02/2023 =C3=A0 06:09, Rohan McLure a =C3=A9crit=C2=A0:
> > KCSAN instruments calls to atomic builtins, and will in turn call these
> > builtins itself. As such, architectures supporting KCSAN must have
> > compiler support for these atomic primitives.
> >=20
> > Since 32-bit systems are unlikely to have 64-bit compiler builtins,
> > provide a stub for each missing builtin, and use BUG() to assert
> > unreachability.
> >=20
> > In commit 725aea873261 ("xtensa: enable KCSAN"), xtensa implements thes=
e
> > locally. Move these definitions to be accessible to all 32-bit
> > architectures that do not provide the necessary builtins, with opt in
> > for PowerPC and xtensa.
> >=20
> > Signed-off-by: Rohan McLure <rmclure@linux.ibm.com>
> > Reviewed-by: Max Filippov <jcmvbkbc@gmail.com>
>=20
> This series should also be addressed to KCSAN Maintainers, shouldn't it ?
>=20
> KCSAN
> M:	Marco Elver <elver@google.com>
> R:	Dmitry Vyukov <dvyukov@google.com>
> L:	kasan-dev@googlegroups.com
> S:	Maintained
> F:	Documentation/dev-tools/kcsan.rst
> F:	include/linux/kcsan*.h
> F:	kernel/kcsan/
> F:	lib/Kconfig.kcsan
> F:	scripts/Makefile.kcsan
>=20
>=20
> > ---
> > Previously issued as a part of a patch series adding KCSAN support to
> > 64-bit.
> > Link: https://lore.kernel.org/linuxppc-dev/167646486000.1421441.1007005=
9569986228558.b4-ty@ellerman.id.au/T/#t
> > v1: Remove __has_builtin check, as gcc is not obligated to inline
> > builtins detected using this check, but instead is permitted to supply
> > them in libatomic:
> > Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D108734
> > Instead, opt-in PPC32 and xtensa.
> > ---
> >   arch/xtensa/lib/Makefile                              | 1 -
> >   kernel/kcsan/Makefile                                 | 2 ++
> >   arch/xtensa/lib/kcsan-stubs.c =3D> kernel/kcsan/stubs.c | 0
> >   3 files changed, 2 insertions(+), 1 deletion(-)
> >   rename arch/xtensa/lib/kcsan-stubs.c =3D> kernel/kcsan/stubs.c (100%)
> >=20
> > diff --git a/arch/xtensa/lib/Makefile b/arch/xtensa/lib/Makefile
> > index 7ecef0519a27..d69356dc97df 100644
> > --- a/arch/xtensa/lib/Makefile
> > +++ b/arch/xtensa/lib/Makefile
> > @@ -8,5 +8,4 @@ lib-y	+=3D memcopy.o memset.o checksum.o \
> >   	   divsi3.o udivsi3.o modsi3.o umodsi3.o mulsi3.o umulsidi3.o \
> >   	   usercopy.o strncpy_user.o strnlen_user.o
> >   lib-$(CONFIG_PCI) +=3D pci-auto.o
> > -lib-$(CONFIG_KCSAN) +=3D kcsan-stubs.o
> >   KCSAN_SANITIZE_kcsan-stubs.o :=3D n
> > diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> > index 8cf70f068d92..86dd713d8855 100644
> > --- a/kernel/kcsan/Makefile
> > +++ b/kernel/kcsan/Makefile
> > @@ -12,6 +12,8 @@ CFLAGS_core.o :=3D $(call cc-option,-fno-conserve-sta=
ck) \
> >   	-fno-stack-protector -DDISABLE_BRANCH_PROFILING
> >  =20
> >   obj-y :=3D core.o debugfs.o report.o
> > +obj-$(CONFIG_PPC32) +=3D stubs.o
> > +obj-$(CONFIG_XTENSA) +=3D stubs.o
>=20
> Not sure it is acceptable to do it that way.
>=20
> There should likely be something like a CONFIG_ARCH_WANTS_KCSAN_STUBS in=
=20
> KCSAN's Kconfig then PPC32 and XTENSA should select it.

The longer I think about it, since these stubs all BUG() anyway, perhaps
we ought to just avoid them altogether. If you delete all the stubs from
ppc and xtensa, but do this:

 | diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
 | index 54d077e1a2dc..8169d6dadd0e 100644
 | --- a/kernel/kcsan/core.c
 | +++ b/kernel/kcsan/core.c
 | @@ -1261,7 +1261,9 @@ static __always_inline void kcsan_atomic_builtin_m=
emorder(int memorder)
 |  DEFINE_TSAN_ATOMIC_OPS(8);
 |  DEFINE_TSAN_ATOMIC_OPS(16);
 |  DEFINE_TSAN_ATOMIC_OPS(32);
 | +#ifdef CONFIG_64BIT
 |  DEFINE_TSAN_ATOMIC_OPS(64);
 | +#endif
 | =20
 |  void __tsan_atomic_thread_fence(int memorder);
 |  void __tsan_atomic_thread_fence(int memorder)

Does that work?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y%2B3kwmFhWilN2OaE%40elver.google.com.
