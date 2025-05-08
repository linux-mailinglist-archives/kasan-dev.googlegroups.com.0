Return-Path: <kasan-dev+bncBDT2NE7U5UFRBAN76PAAMGQEA4EWNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D5C17AB00A4
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 18:44:50 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-607dceb1c53sf1014230eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 09:44:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746722689; cv=pass;
        d=google.com; s=arc-20240605;
        b=QANyRNDunYJTOZd4eviUcHFzjfj3K8H7uO3utc0OvnE5uK2VAAJbo/6OA8U1YofnV3
         q9yD9/QscIiBzJuS+P93JPfaq85bb/8/Zdg7brHFBXR8TJ7R73YrvRGDkX9IaWpSroJF
         tfZmFgIvt1Gioi5Zlf+2C0kiQNVRJ2hryYe/Cs+F2ATLHf0xLbAnZf8TYtG0Mux0m4Ca
         eGJNXTNO2n2daIghUQa4DI/8sYmfcRyPfGY3Ed2a6koVkCGp00cic1ONkODIjziZ4ANh
         UZ1laxxNeSQ/dXq1Xr1sUSM/DvvH6uhyQPMvTdDOlhai/iG67iGujgHvxLbSOOObVcgm
         5K7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Htr9Oe2T2NUVtnizfnpljvjdkZPlaxkqu0oDVmPjm6I=;
        fh=anFnGCpxwk1d8LyldgwR3S6wSnM6qqn89Aq3AZWC6Go=;
        b=e6I4j0yea5x2hHtRG2hdRfwcNg9d6OVsiDbJM0BFSEAoXm4V9omQtt0B0U7Q1dKNLS
         EN3XS6nZg3Y6QSIVd4abRospMZXwn3+KEvGVKqD750a0F3NIdm3CkHPH7bLUACCSOXr4
         ZIVDWj/O6r2dherk8FlZa1pZQbYwkGiZTC9y4TNYyYRyaoxliLUUn8B3Xc9VvImHft9h
         gWAZQ5uuWTtVZ/NjkXp+7B/+lRub4ecRNYZiKoGw8j13+I3GfrMhZJ0pEZnRUAWQHRvY
         /um/4g6cATrF1dpAqYJsjEQWEVcvJlzL636X69FY5mzp6c9BSQSHtd77Jzi+v+np+zx2
         Vskg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WM+LM73I;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746722689; x=1747327489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Htr9Oe2T2NUVtnizfnpljvjdkZPlaxkqu0oDVmPjm6I=;
        b=tuJo9xDZIAUlzmBjhYPoGwzj1pbgBfXwK7xFSRiLzEizozcG/AmhtaJqXfEY+hbTeY
         Jwkf/rNQd2qvLjlUvwpbgzlF5Lx69+NzW4ru7oos50vD3l9ipfsSLA6eBeaYEl8kRFIZ
         Qw/c1wjd0+p4Yj3s8U5oizpSEz0FLcz01tlF6Z07lYSOrbFc86tgsr2lr4UVpNgTtHfz
         KdeIuss3dSLd+EoBu1D/BrFgEfyMqJtuNEArK9CQth0LGezKEJxakLQoqXi9lAeAdLG3
         iMHtW4I1c81wmXJ47A4TJJRDfUvI1yRez+/w/IZ/rNNcmDlXYZwXeaK9zytOLp/p7mg0
         46Vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746722689; x=1747327489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Htr9Oe2T2NUVtnizfnpljvjdkZPlaxkqu0oDVmPjm6I=;
        b=I0NOViAF2shLI2jH+q6AkDB5lxEf1u6krVlQkjwm0STPy3ip8tvhgZYjb8WfsjWSmA
         v+xLg9pE/hoSel8OyzbGXW96+YWJ215x+R0hL4wVps7cD1Mrv2owLuvpEC3Qnko1kE15
         MSM7oxzL9mqZkRGPKJ4SrQcNC7nDlZOtfqzH7+53cP8KyQQRs67rQc2L8qUf5Hx8AyZA
         pK29NtvAVWOL2t7xmDE68Fnjy9CymGeaojKxiB50On6JlOvjaX2OyKafJeFrXqbR7W31
         YRnz8IwMPLTODnAlNM7NStnPSy5N8w8fx6FChFfnajhNnWjazvOPTCfImQ9H4YJRV6bo
         xt6g==
X-Forwarded-Encrypted: i=2; AJvYcCX8Stbnc1lRAV9OjuBXe+B8LVXzjV1MP5sBOe82iZNRUyEXozfUuKBt/RFnmNVsncroUnVjsQ==@lfdr.de
X-Gm-Message-State: AOJu0YyOR/v9wBRh7k4q40F41iU08OHGXmX2gB3lq7wH3EgOYQbBBOxl
	2odBy0AVYWAhAk594IohRKyv+0/a8xdKxMald46j3p9ntn3VXyUh
X-Google-Smtp-Source: AGHT+IGg3zS2V0Zy00dAdidcaDCyRz1ffpaQ+WcnrsIDkD7eB2FXndSpMPzjaWfMk6XTXPB8kDE3cg==
X-Received: by 2002:a05:6820:1a0b:b0:606:462:5d1a with SMTP id 006d021491bc7-6083ff15555mr214005eaf.2.1746722689508;
        Thu, 08 May 2025 09:44:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH1Lu66FI1CjwiosCoc4KziihkOgT0Hi0pvyNcFjWYarA==
Received: by 2002:a4a:e2c7:0:b0:604:8bd0:c016 with SMTP id 006d021491bc7-60832fc66d6ls499516eaf.2.-pod-prod-01-us;
 Thu, 08 May 2025 09:44:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVweGK3591uuzEloM5jyrTZ/ZrEuka5HYz6VBBY90YrkscsYPIIX7+CEYiU2gKcsYgPqXK3QnsZ23o=@googlegroups.com
X-Received: by 2002:a05:6808:2213:b0:3fe:af08:65b5 with SMTP id 5614622812f47-4037fed980emr254894b6e.37.1746722688507;
        Thu, 08 May 2025 09:44:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746722688; cv=none;
        d=google.com; s=arc-20240605;
        b=XUTVdEnR5ERbGWr+DCU7qyVlETFKl3dLl6RBMZsVh+gxXfqvM5azhUW2ooEr71sXCa
         HrC3d5TM5SM1bpoJdUbGcd7y+2KX98xiVn5DMnMCYbJqYDZ5yHPxVjahL1Wf4N0+9Qm8
         BGa2eb9yH3fny3GjY08fRabo6hHxzKWibRiC6qvAqhGlMDnXiZ0Eqaxmlv90JiraNGPO
         1l/mWXPnOPc4taqcAWVHSOSeYi5Nwtxib0ywas62A7I9Gc9Gyeyt+RrNxLsxhBT6Cpyu
         5NFnPdsM49zvHJH2uk8gJRJ+Uv0BxIv/BfPD3zGQDpsAZyUJ3z2Xz0p9pAianPzDNLP2
         Np6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pppXYxJy60TByf0z+7Os2rj90jXqInqF2/euTdlfyqA=;
        fh=k11sid+jGZq6wvLP+oxfsjbHpgDS4RuStkwXBnGbJ0I=;
        b=J9kJU9x0MWAmNAu1Q/Kh84sYDapVPfh+fjSRP8/byNjSdrVfRlyfLYKX7q9R/zTqbw
         OMIZ9gtPgSmONfHJgiGtE69jbo+gDdaj87/YRrDOpoLkuwlI04IhGQFGSWrHR7yRUcUW
         51Rn+XVw8eTtQlROjLIrQjCIQRPBw+YGbHL9BkU4FD7KNa6KWq5juqkB46DB+4RFOkc0
         C6JPNLNSj64T+fQb0tYGRNpQhjS3mvRlEkSRZf+82hqgFVh1iIK9ZGxM38Sl/cMi71KI
         hAIeZSCooAvLBlJrphNUJG8+gO3V0wk8Af3UYJMSV4G8qHsKl5P7coNsLXnYzEk15KOA
         qVLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WM+LM73I;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6083fe5da3esi3929eaf.2.2025.05.08.09.44.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 09:44:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id B16D160008
	for <kasan-dev@googlegroups.com>; Thu,  8 May 2025 16:44:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F7F4C4CEF2
	for <kasan-dev@googlegroups.com>; Thu,  8 May 2025 16:44:47 +0000 (UTC)
Received: by mail-lj1-f177.google.com with SMTP id 38308e7fff4ca-30eef9ce7feso11914341fa.0
        for <kasan-dev@googlegroups.com>; Thu, 08 May 2025 09:44:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWM9bPrLizvS+To+avVyCGGC2Kro5bmW9ivm8JKig7D1IiE5rTY1pEwfEvsJVfnjyPmQ+x619Ef/8g=@googlegroups.com
X-Received: by 2002:a05:651c:547:b0:30b:b987:b68d with SMTP id
 38308e7fff4ca-326c456b4e0mr971471fa.8.1746722686040; Thu, 08 May 2025
 09:44:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250502224512.it.706-kees@kernel.org> <CAK7LNAQCZMmAGfPTr1kgp5cNSdnLWMU5kC_duU0WzWnwZrqt2A@mail.gmail.com>
 <202505031028.7022F10061@keescook>
In-Reply-To: <202505031028.7022F10061@keescook>
From: "'Masahiro Yamada' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 9 May 2025 01:44:09 +0900
X-Gmail-Original-Message-ID: <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
X-Gm-Features: ATxdqUGBr2jT3f2a89H7dPi47dX43RaH0_KQGHELQlFyFtKIOvxwQNuJP6GjnKA
Message-ID: <CAK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] Detect changed compiler dependencies for full rebuild
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Petr Pavlu <petr.pavlu@suse.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Justin Stitt <justinstitt@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Johannes Berg <johannes@sipsolutions.net>, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WM+LM73I;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Masahiro Yamada <masahiroy@kernel.org>
Reply-To: Masahiro Yamada <masahiroy@kernel.org>
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

On Sun, May 4, 2025 at 2:37=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
> On Sat, May 03, 2025 at 06:39:28PM +0900, Masahiro Yamada wrote:
> > On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wrot=
e:
> > >
> > >  v2:
> > >   - switch from -include to -I with a -D gated include compiler-versi=
on.h
> > >  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel=
.org/
> >
> >
> > What do you think of my patch as a prerequisite?
> > https://lore.kernel.org/linux-kbuild/20250503084145.1994176-1-masahiroy=
@kernel.org/T/#u
> > Perhaps, can you implement this series more simply?
> >
> > My idea is to touch a single include/generated/global-rebuild.h
> > rather than multiple files such as gcc-plugins-deps.h, integer-wrap.h, =
etc.
> >
> > When the file is touched, the entire kernel source tree will be rebuilt=
.
> > This may rebuild more than needed (e.g. vdso) but I do not think
> > it is a big deal.
>
> This is roughly where I started when trying to implement this, but I
> didn't like the ergonomics of needing to scatter "touch" calls all over,
> which was especially difficult for targets that shared a build rule but
> may not all need to trigger a global rebuild. But what ultimately pushed
> me away from it was when I needed to notice if a non-built source file
> changed (the Clang .scl file), and I saw that I need to be dependency
> driven rather than target driven. (Though perhaps there is a way to
> address this with your global-rebuild.h?)
>
> As far as doing a full rebuild, if it had been available last week, I
> probably would have used it, but now given the work that Nicolas, you,
> and I have put into this, we have a viable way (I think) to make this
> more specific. It does end up being a waste of time/resources to rebuild
> stuff that doesn't need to be (efi-stub, vdso, boot code, etc), and that
> does add up when I'm iterating on something that keeps triggering a full
> rebuild. We already have to do the argument filtering for targets that
> don't want randstruct, etc, so why not capitalize on that and make the
> rebuild avoid those files too?


efi-stub, vdso are very small.

Unless this turns out to be painful, I prefer
a simpler implementation.

You will see how .scl file is handled.

See the below code:


diff --git a/Kbuild b/Kbuild
index f327ca86990c..85747239314c 100644
--- a/Kbuild
+++ b/Kbuild
@@ -67,10 +67,20 @@ targets +=3D $(atomic-checks)
 $(atomic-checks): $(obj)/.checked-%: include/linux/atomic/%  FORCE
        $(call if_changed,check_sha1)

+rebuild-$(CONFIG_GCC_PLUGINS)          +=3D $(addprefix
scripts/gcc-plugins/, $(GCC_PLUGIN))
+rebuild-$(CONFIG_RANDSTRUCT)           +=3D include/generated/randstruct_h=
ash.h
+rebuild-$(CONFIG_UBSAN_INTEGER_WRAP)   +=3D scripts/integer-wrap-ignore.sc=
l
+
+quiet_cmd_touch =3D TOUCH   $@
+      cmd_touch =3D touch $@
+
+include/generated/global-rebuild.h: $(rebuild-y)
+       $(call cmd,touch)
+
 # A phony target that depends on all the preparation targets

 PHONY +=3D prepare
-prepare: $(offsets-file) missing-syscalls $(atomic-checks)
+prepare: $(offsets-file) missing-syscalls $(atomic-checks)
include/generated/global-rebuild.h
        @:

 # Ordinary directory descending
diff --git a/Makefile b/Makefile
index b29cc321ffd9..f963a72b0761 100644
--- a/Makefile
+++ b/Makefile
@@ -558,7 +558,8 @@ USERINCLUDE    :=3D \
                -I$(srctree)/include/uapi \
                -I$(objtree)/include/generated/uapi \
                 -include $(srctree)/include/linux/compiler-version.h \
-                -include $(srctree)/include/linux/kconfig.h
+                -include $(srctree)/include/linux/kconfig.h \
+                -include $(objtree)/include/generated/global-rebuild.h

 # Use LINUXINCLUDE when you must reference the include/ directory.
 # Needed to be compatible with the O=3D option
@@ -1250,6 +1251,12 @@ endif
 include/config/kernel.release: FORCE
        $(call filechk,kernel.release)

+quiet_cmd_touch =3D TOUCH   $@
+      cmd_touch =3D touch $@
+
+include/generated/global-rebuild.h:
+       $(call cmd,touch)
+
 # Additional helpers built in scripts/
 # Carefully list dependencies so we do not try to build scripts twice
 # in parallel
@@ -1266,6 +1273,7 @@ scripts: scripts_basic scripts_dtc
 PHONY +=3D prepare archprepare

 archprepare: outputmakefile archheaders archscripts scripts
include/config/kernel.release \
+       include/generated/global-rebuild.h \
        asm-generic $(version_h) include/generated/utsrelease.h \
        include/generated/compile.h include/generated/autoconf.h \
        include/generated/rustc_cfg remove-stale-files
diff --git a/arch/um/Makefile b/arch/um/Makefile
index 1d36a613aad8..f564a26c1364 100644
--- a/arch/um/Makefile
+++ b/arch/um/Makefile
@@ -73,7 +73,8 @@ USER_CFLAGS =3D $(patsubst
$(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
                -D_FILE_OFFSET_BITS=3D64 -idirafter $(srctree)/include \
                -idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__ \
                -include $(srctree)/include/linux/compiler-version.h \
-               -include $(srctree)/include/linux/kconfig.h
+               -include $(srctree)/include/linux/kconfig.h \
+               -include $(objtree)/include/generated/global-rebuild.h

 #This will adjust *FLAGS accordingly to the platform.
 include $(srctree)/$(ARCH_DIR)/Makefile-os-Linux









--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AK7LNAQehmFgB3kJtrkVhUKM1NEXGQrfJ3v3piToh7YV7-3ccw%40mail.gmail.com.
