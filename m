Return-Path: <kasan-dev+bncBDT2NE7U5UFRB4HH23AAMGQEIFW64QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id ADFCCAA7EC2
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 08:13:06 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e73290d75a8sf3999244276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 23:13:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746252785; cv=pass;
        d=google.com; s=arc-20240605;
        b=kGcWdQmZmg/qm5fcqFbWBnEaEuBhNX5bTigeX7y4TBwR45QIfoH65MiIM5f6eim9xe
         313fA5ycG/u3KyriiMzW2lgfC7WeLq/clL13v9qxu/pR0xDtRLR51hxkh+rnG4/p6bt+
         wgQlDX80UPY84F9cEUR/FoLAPk94md2y0DKc3z/i5fJUJ+bXggenCB/M5T8dcLXa82JY
         ADKG0Xx18/LmDpTqvsCbAB2LvOBJHStq8m8TdDesI0HPVX+t3Wi3FSJaEP6crPnI7vY2
         VVgCznpgG7R83fQoXZKhQXFhMQAwCnplzwgAF30CbEMutDQ9rdC47myEx7miH2cV2yx8
         6KMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h7DEaKDlERPPtWT1ObQVhCab+uUZAtusTwwgqlknCoc=;
        fh=nDiNOsdTQYczS5QN7BZuOj5A9u/0TqNf/tcD2iDEQw0=;
        b=B9DQ42JfZW1v18YzagOqgfZhprAbQDJkh1eL6/PrFTXCnV2gRBn1gul36yORjvYiFy
         A6hQRuNERk60dwnflKICbFuUf5J3qBaNwQNK/yrf8QWg6TR+iKuBVzgXdGItHTnuZEd5
         d1GkDg0deg8ncZJ3mQR9GhJfxNLEIkTsFH7jUtxikTdwJ/bqFT/5lx8aGCmDcuVhfFAL
         F8g2dTilX/Eswotmy8F/nfS6P+J/tpiPf5mU/OM7xCYRZ/FdDvk/89zy46fXlSxYP92g
         7R1mT3sYjbfp0qCnRcRU/Ujjh6JxMxseTlzRUHs+ymV6jI/KJtfO4ov2XUwLqpNrdkdm
         zHvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qigHuDaL;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746252785; x=1746857585; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h7DEaKDlERPPtWT1ObQVhCab+uUZAtusTwwgqlknCoc=;
        b=lwEWcUtSMqdbawfuca/ZXbjppe2zoyf7ic5IQbAVEYU3ICnJnYSHPwq79aLh+q63+D
         WY0PslReayGIiA7SiZShd9xG6HZirYHgEgYIRJjlhUMxwS+clW1hWLcBQDxc2wlUjzTr
         LZt1+wgXfhpnhlG3F15x48WqDKYD3FE30nti6Ov99SfrtTp+cRx4cFtwvA7KYzrTsUHN
         wSfJfYdQA3tumaE16owj0vQ7UQLX+902dhMJZ/RkoisnG867QfkZDo143i+Cgn/zxPNc
         alMf/3S8DbBLZpxq1wgsdGWI4jVuWsg3aBRGH5lYt2/hFs4HiM6UwO2PjHaFy/X3aJOV
         ACaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746252785; x=1746857585;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=h7DEaKDlERPPtWT1ObQVhCab+uUZAtusTwwgqlknCoc=;
        b=s+YBCfEGB6EQBECGVvpScp2uBrHo5Vo10zdbroDLPEVW9+KkxQW55OmBqofyJUS60S
         5DdN7gixBxonlb/UIWX01u7QiY0bp748yrWaVmgdOsUbzi70OWnj0YWLK3rHl/sRQ1CF
         ss794Cj/PQqvf1XHBG+y5IE2k3MZzv+6QvsPTPZgXdT5ST2gd9L+OwoYs1XLAAVEW/AJ
         Qye1omX7gEF64wA0YWCAb3UGas3xAA7/wkOBMYbliRtEBjhF2YMHgRq/ym6gN7m8NmRJ
         gnVdI4NXIVmrmFTTFPPcP3yIBcv9D40FusIS40xYVUib4v4SH+htI7aDZ8IFj97fslT/
         qlfw==
X-Forwarded-Encrypted: i=2; AJvYcCUptMP8/x9wT4POxZZF11ZgFWwqeWErB2ylCANms6dvbBULbMdQrPreS3jj5tH5P2aH6svjYw==@lfdr.de
X-Gm-Message-State: AOJu0YwFX7nVlb5i+14RuQJQ1tMaI+v2/Sno5rhgz+SJJSdeuPlcPgVf
	wqwxAQxLLYDFv+MSig/aOBe3C8oNTpkpazjtwmsLSe2NnhtFpJ7m
X-Google-Smtp-Source: AGHT+IFiOO4eANV6lbjaYWz4yOhFCzjLIsLvk0qF/wdydcBiViKtmMI6zKi6zfrNurJyJd6hECtahg==
X-Received: by 2002:a05:6902:a83:b0:e73:58c:836e with SMTP id 3f1490d57ef6-e756555a7c5mr7250227276.11.1746252785149;
        Fri, 02 May 2025 23:13:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH+R4B/np3cNYafhMpF4fVMxQXN5/cben+ZYdVSg3VA5g==
Received: by 2002:a25:b225:0:b0:e72:6a60:9f92 with SMTP id 3f1490d57ef6-e74d9694c86ls938738276.0.-pod-prod-01-us;
 Fri, 02 May 2025 23:13:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVgFOHTwlVXeQoqRLHvWRhw0wgIe46Ls7R2hSrii5mlh1rKMt7Fha2GkHEXCZbZ3kVudUnI3lOqVU4=@googlegroups.com
X-Received: by 2002:a05:690c:e1a:b0:703:ace3:150a with SMTP id 00721157ae682-708cf2612b4mr68418297b3.34.1746252784130;
        Fri, 02 May 2025 23:13:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746252784; cv=none;
        d=google.com; s=arc-20240605;
        b=hh3vzovINTxpSHlidPVWCnLGCWUr9yA/zaZ+Cp6Mv1dypwCLGfuIxrZNUPg1+Job5V
         8pKBOTGenDelMqoIwVtu0/eRwXugzp6Pv3pqOxlHs5bubaKZdsj4MKC/vTRz+HgY4TJy
         q4fxfRDq8/hsF0u2m5XmGBcGgSvqkSI6xQrUhv2Ia5yMvLVwKBuKkmlXuPhYhBe+wNej
         ijj/hYkznHY3FNIr8LTYg1swEBN93QnytIGxhadynOVLzjBNPF4zvTCIj0o8fxHnkEA+
         jqyfpD/71K6+VX2BnUWUvsbDG1e5Lh5rchMa2I+cZDk4xo3o1uiD2pGedMnkoAPtmb0m
         PcjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rUOzOX9OTpEutPYy4ALL41qWHp3PghZKJrxQrq0kvgQ=;
        fh=aLGCzjA+HuXLH2oznZHgHb3j/9/ex72NUBz8gjtPguE=;
        b=YHroTv+BwAAlepbU79wnyQQLwJdl1kT8uI5a0Uk0aZaB2avIPJWP8VXh/84oC0xNMj
         Z5Z70DSt6Noq6+gy5vkhFEWzJ/OjwJan8lIbhf35iuoCCqP8JS3E0/EzaOOUrdjz4qCK
         f9gLU1GH4nAIkikbqIehTh4alLFPshmniQBljATT+hLk+erKYtK0Q6T9MehhY53BGkNE
         p3DKiSb6t8ITShwSA5QVymphtVlrJMupSerqQtvDzBh3oLHMv/igIHtOqlO9TsBWr8qk
         cfe9js7LlgbaXq+M59NdGjtsLsPKP75782vi/qMibFKNns6DAVhwBfWDq+MCRJgJIOjV
         33Gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qigHuDaL;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-708c467168fsi1855957b3.4.2025.05.02.23.13.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 23:13:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 3450B6112E
	for <kasan-dev@googlegroups.com>; Sat,  3 May 2025 06:12:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5E4C7C4AF0B
	for <kasan-dev@googlegroups.com>; Sat,  3 May 2025 06:13:02 +0000 (UTC)
Received: by mail-lj1-f178.google.com with SMTP id 38308e7fff4ca-3105ef2a06cso24270301fa.2
        for <kasan-dev@googlegroups.com>; Fri, 02 May 2025 23:13:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVdo8cJ0Q0xWCYC0qDPb0Rig19O93FlgT1Gl9D5WDm4TpU60X1J2SegC3EKFBx8viOrQIhuNgCTUHM=@googlegroups.com
X-Received: by 2002:a05:6512:3c98:b0:54e:8fbb:8f0 with SMTP id
 2adb3069b0e04-54eb2418f82mr329651e87.1.1746252780980; Fri, 02 May 2025
 23:13:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250502224512.it.706-kees@kernel.org> <20250502225416.708936-1-kees@kernel.org>
In-Reply-To: <20250502225416.708936-1-kees@kernel.org>
From: "'Masahiro Yamada' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 3 May 2025 15:12:23 +0900
X-Gmail-Original-Message-ID: <CAK7LNATs4uHnNHgESXcUEjpONZra=GvkuHMaDwsx0hbyUGY99w@mail.gmail.com>
X-Gm-Features: ATxdqUH1iIL3mgv0unyzF1cI5PCLwIrui50f8zRG3vA14o59y1H3vTcwLXDcJy0
Message-ID: <CAK7LNATs4uHnNHgESXcUEjpONZra=GvkuHMaDwsx0hbyUGY99w@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] gcc-plugins: Force full rebuild when plugins change
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	Petr Pavlu <petr.pavlu@suse.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Justin Stitt <justinstitt@google.com>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Johannes Berg <johannes@sipsolutions.net>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qigHuDaL;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
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

On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
> There was no dependency between the plugins changing and the rest of the
> kernel being built. Enforce this by including a synthetic header file
> when using plugins, that is regenerated any time the plugins are built.
>
> This cannot be included via '-include ...' because Makefiles use the
> "filter-out" string function, which removes individual words. Removing
> all instances of "-include" from the CFLAGS will cause a lot of
> problems. :)
>
> Instead, use -I to include the gcc-plugins directory, and depend on the
> new -DGCC_PLUGINS_ENABLED flag to include the generated header file via
> include/linux/compiler-version.h, which is already being used to control
> full rebuilds. The UM build requires that the -I be explicitly added.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: <linux-hardening@vger.kernel.org>
> Cc: <linux-kbuild@vger.kernel.org>
> ---
>  arch/um/Makefile                 | 1 +
>  include/linux/compiler-version.h | 4 ++++
>  scripts/Makefile.gcc-plugins     | 2 +-
>  scripts/gcc-plugins/Makefile     | 8 ++++++++
>  4 files changed, 14 insertions(+), 1 deletion(-)
>
> diff --git a/arch/um/Makefile b/arch/um/Makefile
> index 1d36a613aad8..8cc0f22ebefa 100644
> --- a/arch/um/Makefile
> +++ b/arch/um/Makefile
> @@ -72,6 +72,7 @@ USER_CFLAGS =3D $(patsubst $(KERNEL_DEFINES),,$(patsubs=
t -I%,,$(KBUILD_CFLAGS))) \
>                 $(ARCH_INCLUDE) $(MODE_INCLUDE) $(filter -I%,$(CFLAGS)) \
>                 -D_FILE_OFFSET_BITS=3D64 -idirafter $(srctree)/include \
>                 -idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__ =
\
> +               -I$(objtree)/scripts/gcc-plugins \
>                 -include $(srctree)/include/linux/compiler-version.h \
>                 -include $(srctree)/include/linux/kconfig.h
>
> diff --git a/include/linux/compiler-version.h b/include/linux/compiler-ve=
rsion.h
> index 573fa85b6c0c..08943df04ebb 100644
> --- a/include/linux/compiler-version.h
> +++ b/include/linux/compiler-version.h
> @@ -12,3 +12,7 @@
>   * and add dependency on include/config/CC_VERSION_TEXT, which is touche=
d
>   * by Kconfig when the version string from the compiler changes.
>   */
> +
> +#ifdef GCC_PLUGINS_ENABLED
> +#include "gcc-plugins-deps.h"
> +#endif
> diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
> index 5b8a8378ca8a..468bb8faa9d1 100644
> --- a/scripts/Makefile.gcc-plugins
> +++ b/scripts/Makefile.gcc-plugins
> @@ -38,7 +38,7 @@ export DISABLE_STACKLEAK_PLUGIN
>
>  # All the plugin CFLAGS are collected here in case a build target needs =
to
>  # filter them out of the KBUILD_CFLAGS.
> -GCC_PLUGINS_CFLAGS :=3D $(strip $(addprefix -fplugin=3D$(objtree)/script=
s/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
> +GCC_PLUGINS_CFLAGS :=3D $(strip $(addprefix -fplugin=3D$(objtree)/script=
s/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -I$(objtree)/scrip=
ts/gcc-plugins -DGCC_PLUGINS_ENABLED


This still relies on no-space after the -I option.



>  export GCC_PLUGINS_CFLAGS
>
>  # Add the flags to the build!
> diff --git a/scripts/gcc-plugins/Makefile b/scripts/gcc-plugins/Makefile
> index 320afd3cf8e8..24671d39ec90 100644
> --- a/scripts/gcc-plugins/Makefile
> +++ b/scripts/gcc-plugins/Makefile
> @@ -66,3 +66,11 @@ quiet_cmd_plugin_cxx_o_c =3D HOSTCXX $@
>
>  $(plugin-objs): $(obj)/%.o: $(src)/%.c FORCE
>         $(call if_changed_dep,plugin_cxx_o_c)
> +
> +quiet_cmd_gcc_plugins_updated =3D UPDATE  $@
> +      cmd_gcc_plugins_updated =3D echo '/* $^ */' > $(obj)/gcc-plugins-d=
eps.h

I think 'touch' should be enough.

If some plugins are disabled, it is detected by the normal if_changed rule.


> +
> +$(obj)/gcc-plugins-deps.h: $(plugin-single) $(plugin-multi) FORCE
> +       $(call if_changed,gcc_plugins_updated)
> +
> +always-y +=3D gcc-plugins-deps.h
> --
> 2.34.1
>


I think it is simpler to place the header
in include/generated/.

I attached my suggestion below:










diff --git a/arch/um/Makefile b/arch/um/Makefile
index 8cc0f22ebefa..1d36a613aad8 100644
--- a/arch/um/Makefile
+++ b/arch/um/Makefile
@@ -72,7 +72,6 @@ USER_CFLAGS =3D $(patsubst
$(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
                $(ARCH_INCLUDE) $(MODE_INCLUDE) $(filter -I%,$(CFLAGS)) \
                -D_FILE_OFFSET_BITS=3D64 -idirafter $(srctree)/include \
                -idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__ \
-               -I$(objtree)/scripts/gcc-plugins \
                -include $(srctree)/include/linux/compiler-version.h \
                -include $(srctree)/include/linux/kconfig.h

diff --git a/include/linux/compiler-version.h b/include/linux/compiler-vers=
ion.h
index 08943df04ebb..ea3d533dc04a 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -14,5 +14,5 @@
  */

 #ifdef GCC_PLUGINS_ENABLED
-#include "gcc-plugins-deps.h"
+#include <generated/gcc-plugins-deps.h>
 #endif
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 67b045a66157..f9b51c2c2158 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -44,7 +44,7 @@ export DISABLE_ARM_SSP_PER_TASK_PLUGIN

 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
-GCC_PLUGINS_CFLAGS :=3D $(strip $(addprefix
-fplugin=3D$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y))
$(gcc-plugin-cflags-y)) -I$(objtree)/scripts/gcc-plugins
-DGCC_PLUGINS_ENABLED
+GCC_PLUGINS_CFLAGS :=3D $(strip $(addprefix
-fplugin=3D$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y))
$(gcc-plugin-cflags-y)) -DGCC_PLUGINS_ENABLED
 export GCC_PLUGINS_CFLAGS

 # Add the flags to the build!
diff --git a/scripts/gcc-plugins/Makefile b/scripts/gcc-plugins/Makefile
index 24671d39ec90..b354c0f9f66d 100644
--- a/scripts/gcc-plugins/Makefile
+++ b/scripts/gcc-plugins/Makefile
@@ -67,10 +67,10 @@ quiet_cmd_plugin_cxx_o_c =3D HOSTCXX $@
 $(plugin-objs): $(obj)/%.o: $(src)/%.c FORCE
        $(call if_changed_dep,plugin_cxx_o_c)

-quiet_cmd_gcc_plugins_updated =3D UPDATE  $@
-      cmd_gcc_plugins_updated =3D echo '/* $^ */' > $(obj)/gcc-plugins-dep=
s.h
+quiet_cmd_gcc_plugins_updated =3D TOUCH   $@
+      cmd_gcc_plugins_updated =3D touch $@

-$(obj)/gcc-plugins-deps.h: $(plugin-single) $(plugin-multi) FORCE
+$(obj)/../../include/generated/gcc-plugins-deps.h: $(plugin-single)
$(plugin-multi) FORCE
        $(call if_changed,gcc_plugins_updated)

-always-y +=3D gcc-plugins-deps.h
+always-y +=3D ../../include/generated/gcc-plugins-deps.h




--
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AK7LNATs4uHnNHgESXcUEjpONZra%3DGvkuHMaDwsx0hbyUGY99w%40mail.gmail.com.
