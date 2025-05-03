Return-Path: <kasan-dev+bncBDT2NE7U5UFRBGPI23AAMGQENABKLIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CF824AA7EC5
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 08:13:47 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-72e90e6e171sf692001a34.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 23:13:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746252826; cv=pass;
        d=google.com; s=arc-20240605;
        b=QwSUnftv8jlLVOXIzamLoWKF0v87O4Ff1caZWQX7/pDjJtfjufQnmA9DQ+ZbS95qQX
         MwCKRy/XHZQHeOsLrnGR621zkfs7KotB4kKW0dCiF1f19f8tyKB7+ofnj+x5frHcf39m
         S88D4BCqwIcHghc29+WXi500K8f7fmFtIgge1DZeYRZcN7a0MiUVBYCbi5it5LJlT+bH
         Xt2yIPKM/j4rpeogaHD4LXwK+jMbiJX9DgDo4AKP1FXMPMG1zqT6t6gU80P+N2Q6ZmfG
         S3vD0ZvVsX6lEpCnS3Isg4qD8GBaOtijfMgefzYL9V9zoLDGna4NV46FjvpkWIvAmsPS
         3O/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gCioLQ/uhoO2YiZ5mt6C3ZyKFbS5yibERcRWNanyTO0=;
        fh=y2yL/4NMbKbVQv359BGgWKiHKgJMnnyN7si+KlZH3Ig=;
        b=J5NP6n2hn3jSOMYM4xutosxatys2Bw2x+xyCC7hKmJ+MXdZeW9KV6phxqENoebF+yo
         Ra5FwF9BUWoEZH738+OBGjmwvOaGXEiq23xrlUTF//e8kzeqC4yrJHCYXH1FohbBFD8Y
         M9PyeCcdw+udRXIe53jtmuvNflXzqImO6z0qzB77ysB4hKtJtadqIThMwNIapaLushJi
         ZZtv6JAK+5wSkZWS8TLjU9ZjLh535OJX3VNKnD2HS3UgQKzVgkYPQkFHdNc7Ryti7Cgh
         xPCuZskD+QQkLywrmaI3BE7hujn/SgePzXMDj+Tfnf0P/m3FK/Mo16/Pd1xiqSgK76Tj
         53Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n7KyF4ZB;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746252826; x=1746857626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gCioLQ/uhoO2YiZ5mt6C3ZyKFbS5yibERcRWNanyTO0=;
        b=cHbb+82fs0FNjOJV5xcgWJbN8dY4Lin6IgWlW0Dp6LD6o1dLLNmMG6M+A2TOAGjCaz
         dLprsTuw/GMffupR0P5DVPUQUkXoeo40skQNIwEcoyGpZufTGnHjN0hirB7810rXq6Gl
         CI2gz9DtbdRdsQ6apgzKEdx1a75flvoaoBbpkX8oZiqmoXDjNKJEhbTaH0PP0CNifV//
         I89Ob5JDGMvdFuaKlIrb71L5hFFfOkMV0HFksiQ5fylJ7keoCPm0O4aCLgpXrKsVa0fo
         0bmpj2XdiWC3whFg3Kb4LHHuKNuD7SJDzZQfxFBFZj+u0Bxd2C8aeub7dsyM8oXAr95m
         GuzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746252826; x=1746857626;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gCioLQ/uhoO2YiZ5mt6C3ZyKFbS5yibERcRWNanyTO0=;
        b=UvYrtuTK4EsrqQv65J2QLIZ0sMDEgUao9Kg37Hx/pMvjytj5kpxzkwxsfGkNlSnHXN
         xC/KkOwd05UUxTJq8iDYE2gGGhlxMTkLiyKFz+Va61WCBHuB0YGqqtDylryEXeBgQ4n4
         ocu56aJnUEhJBM8aG5Ro02Cu2uU9F3UVLiNvLkKugnVmSXXaUl6eoQNtRnxHV5KND8TE
         cAa6OcCiPHJjUCVGi4bbs7MDceYB0WvTa8ITKjOHZs5Vhi1Kjgo10Q9IEMf3mhdHmU8u
         ZjuHmXq+tkQM7TqZiEGILwGPCh3lTIPtIQOn0va2BDmhyMHR3nGueHiw7xPziUCdo84U
         gJfg==
X-Forwarded-Encrypted: i=2; AJvYcCVjsanYgDPfjEKJ56ZhSvc2UmcE15HEcpL9vmNRIGxU4EFrqSWe+ZuD5LqjqMlbKcPJpF4LYg==@lfdr.de
X-Gm-Message-State: AOJu0YxlSTRH1QtSP7tlzpfi21CCvePqIGswos/5rPoLAh8+E865NWhH
	QyojIbb0+KXinBsmICOYJesOiJRmDH1Wa6cD3o1+A69LQrgw0Ve0
X-Google-Smtp-Source: AGHT+IFthAz57X9SfYxo1Uy/cZuSbu8Zi3mFzjjAQ6iWDpNqEMDxQlGaQJpmrla7gEjAGDfAt+sDmQ==
X-Received: by 2002:a05:6870:8315:b0:2d6:6677:f311 with SMTP id 586e51a60fabf-2dae82c98fbmr13468fac.3.1746252826123;
        Fri, 02 May 2025 23:13:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHKooT1XD6iN+P3XWKNf1BK8wPb5qysokA6tGPuogRRew==
Received: by 2002:a05:6871:2b19:b0:2d5:b2c1:db0b with SMTP id
 586e51a60fabf-2da8a5b747els1038065fac.2.-pod-prod-06-us; Fri, 02 May 2025
 23:13:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwDThVGoLWZheXATgqM3DYzxRevdt8skyWZW97p7++DLWObBBzbOzkhIm5djVr1e8dQQ0o3nqZwwQ=@googlegroups.com
X-Received: by 2002:a05:6870:241d:b0:2d5:1725:f529 with SMTP id 586e51a60fabf-2dae862adbfmr8696fac.27.1746252825313;
        Fri, 02 May 2025 23:13:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746252825; cv=none;
        d=google.com; s=arc-20240605;
        b=XM5c4T3vALLQyUYNUrhgNdsjMaQEQk4/dhHABYeNYkN5pSC+gUEmgVGTnbR7eO0aWF
         ie4QIftUj6qI2i6DUINtZ0AOcW1fMonKSldvRI6b4I/XxaldKlh5TJpLEarPjz74mdAu
         hy6EyG/fL1Pzh2t6t3Hb+2nfr+B0BV9iyM7ZEVE7TV6+aOBPeaW4pprfT8ZoV37YDbGC
         wvhJOWSq60SygEMYxx2r8Ni7oV5pHaYZdzUu5zG/3p3x7ThBqOyVWDoPkAGq+uPe3mBn
         6N8VMbPYNuam3YZaYNN/8bm5zizv73GR+mvzY9a9a8wSv9xn426yg2AgPcpkG8RxeJRp
         t8Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0+Ax35WNqVI/5m43wjx3nYTlibRzAFsgYE2Zj2RZzvA=;
        fh=hEimdrmVHMO3C6Tmmaww1Lqrygx+uO4qZ+/MQw4nk68=;
        b=IhLMWuY0uI1ie0kljEMd0nNUF+QnUPWIZklKb3KcptwnAacPs3VL1zaIF48uoAM6Bj
         xBTS++OycGzx8vJ6I2xDLTA2IF2AuS8GhC9UuDfICspCiNqLxh9glvNlv/FoR1uUDXa2
         fuIc1uQR/0VP5IcbcJmzAxIy7YXbk+Q+8tk53oCq8ZL4Pdme9GvskBOTYNjil8MEvGmn
         GldKuTwOUqgC+CTXGPO6cOqCpBTmDyd3sUSHw2ZB1QiGHlyL0DFzv1qQUMJLP1vA7TQq
         VGhDIJsz4PT7u4PN5IyDOGwK/2wp0dOGKNKCNdA1ZaSnWkbSuUL45eZ/CxNY/vYWxIFF
         HTZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n7KyF4ZB;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2daa0e5b686si65457fac.1.2025.05.02.23.13.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 23:13:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id EE4CA43492
	for <kasan-dev@googlegroups.com>; Sat,  3 May 2025 06:13:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4E888C4AF09
	for <kasan-dev@googlegroups.com>; Sat,  3 May 2025 06:13:44 +0000 (UTC)
Received: by mail-lf1-f46.google.com with SMTP id 2adb3069b0e04-54c0fa6d455so3256842e87.1
        for <kasan-dev@googlegroups.com>; Fri, 02 May 2025 23:13:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVp63/pxdUsiRS+DNBBtJryrWIhU7Vt8dvdAFWNFTqF4cIb+cf527rN7UlWbNA5wuC3qjEV+S6Wwa0=@googlegroups.com
X-Received: by 2002:a05:6512:3f1c:b0:549:7d6e:fe84 with SMTP id
 2adb3069b0e04-54eac2433c8mr1283219e87.53.1746252823032; Fri, 02 May 2025
 23:13:43 -0700 (PDT)
MIME-Version: 1.0
References: <20250502224512.it.706-kees@kernel.org> <20250502225416.708936-2-kees@kernel.org>
In-Reply-To: <20250502225416.708936-2-kees@kernel.org>
From: "'Masahiro Yamada' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 3 May 2025 15:13:06 +0900
X-Gmail-Original-Message-ID: <CAK7LNATDbxc+3HQ6zoSk9t-Lkf4MSNmEUN6S5EqoVWnBQw_K6g@mail.gmail.com>
X-Gm-Features: ATxdqUF76dt_7gcYn_ksSKtSA5fymBjXQ0TBB0SjwOyXw1Ac63YqHHphqbqToKc
Message-ID: <CAK7LNATDbxc+3HQ6zoSk9t-Lkf4MSNmEUN6S5EqoVWnBQw_K6g@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] randstruct: Force full rebuild when seed changes
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Petr Pavlu <petr.pavlu@suse.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	linux-kbuild@vger.kernel.org, Justin Stitt <justinstitt@google.com>, 
	Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n7KyF4ZB;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 172.234.252.31 as
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
> While the randstruct GCC plugin was being rebuilt if the randstruct
> seed changed, Clangs build did not notice the change. Include the hash
> header directly so that it becomes a universal build dependency and full
> rebuilds will happen if it changes.
>
> Since we cannot use "-include ..." as the randstruct flags are removed
> via "filter-out" (which would cause all instances of "-include" to be
> removed), use the existing -DRANDSTRUCT to control the header inclusion
> via include/linux/compiler-version.h. Universally add a -I for the
> scripts/basic directory, where header exists. The UM build requires that
> the -I be explicitly added.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Petr Pavlu <petr.pavlu@suse.com>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: <linux-kbuild@vger.kernel.org>
> ---
>  Makefile                         |  1 +
>  arch/um/Makefile                 |  1 +
>  include/linux/compiler-version.h |  3 +++
>  include/linux/vermagic.h         |  1 -
>  scripts/basic/Makefile           | 11 ++++++-----
>  5 files changed, 11 insertions(+), 6 deletions(-)
>
> diff --git a/Makefile b/Makefile
> index 5aa9ee52a765..cef652227843 100644
> --- a/Makefile
> +++ b/Makefile
> @@ -567,6 +567,7 @@ LINUXINCLUDE    :=3D \
>                 -I$(objtree)/arch/$(SRCARCH)/include/generated \
>                 -I$(srctree)/include \
>                 -I$(objtree)/include \
> +               -I$(objtree)/scripts/basic \


Now you are adding random header search paths everywhere.
This is very hacky.


I recommend keeping <generated/randstruct_hash.h>

Then,  -I$(objtree)/scripts/basic is unneeded.


>                 $(USERINCLUDE)
>
>  KBUILD_AFLAGS   :=3D -D__ASSEMBLY__ -fno-PIE
> diff --git a/arch/um/Makefile b/arch/um/Makefile
> index 8cc0f22ebefa..38f6024e75d7 100644
> --- a/arch/um/Makefile
> +++ b/arch/um/Makefile
> @@ -73,6 +73,7 @@ USER_CFLAGS =3D $(patsubst $(KERNEL_DEFINES),,$(patsubs=
t -I%,,$(KBUILD_CFLAGS))) \
>                 -D_FILE_OFFSET_BITS=3D64 -idirafter $(srctree)/include \
>                 -idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__ =
\
>                 -I$(objtree)/scripts/gcc-plugins \
> +               -I$(objtree)/scripts/basic \
>                 -include $(srctree)/include/linux/compiler-version.h \
>                 -include $(srctree)/include/linux/kconfig.h
>
> diff --git a/include/linux/compiler-version.h b/include/linux/compiler-ve=
rsion.h
> index 08943df04ebb..05d555320a0f 100644
> --- a/include/linux/compiler-version.h
> +++ b/include/linux/compiler-version.h
> @@ -16,3 +16,6 @@
>  #ifdef GCC_PLUGINS_ENABLED
>  #include "gcc-plugins-deps.h"
>  #endif
> +#ifdef RANDSTRUCT
> +#include "randstruct_hash.h"
> +#endif
> diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
> index 939ceabcaf06..335c360d4f9b 100644
> --- a/include/linux/vermagic.h
> +++ b/include/linux/vermagic.h
> @@ -33,7 +33,6 @@
>  #define MODULE_VERMAGIC_MODVERSIONS ""
>  #endif
>  #ifdef RANDSTRUCT
> -#include <generated/randstruct_hash.h>
>  #define MODULE_RANDSTRUCT "RANDSTRUCT_" RANDSTRUCT_HASHED_SEED
>  #else
>  #define MODULE_RANDSTRUCT
> diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
> index dd289a6725ac..31637ce4dc5c 100644
> --- a/scripts/basic/Makefile
> +++ b/scripts/basic/Makefile
> @@ -8,9 +8,10 @@ hostprogs-always-y     +=3D fixdep
>  # before running a Clang kernel build.
>  gen-randstruct-seed    :=3D $(srctree)/scripts/gen-randstruct-seed.sh
>  quiet_cmd_create_randstruct_seed =3D GENSEED $@
> -cmd_create_randstruct_seed =3D \
> -       $(CONFIG_SHELL) $(gen-randstruct-seed) \
> -               $@ $(objtree)/include/generated/randstruct_hash.h
> -$(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
> +      cmd_create_randstruct_seed =3D $(CONFIG_SHELL) $(gen-randstruct-se=
ed) \
> +               $(obj)/randstruct.seed $(obj)/randstruct_hash.h
> +
> +$(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) =
FORCE
>         $(call if_changed,create_randstruct_seed)


This is wrong.


$(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) FOR=
CE
         $(call if_changed,create_randstruct_seed)

is equivalent to:

$(obj)/randstruct_hash.h: $(gen-randstruct-seed) FORCE
         $(call if_changed,create_randstruct_seed)

$(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
         $(call if_changed,create_randstruct_seed)


So, this rule is executed twice; for randstruct_hash.h and for randstruct.s=
eed

randstruct_hash.h and randstruct.seed will contain different hash values.

I recommend keeping the current code.













--
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AK7LNATDbxc%2B3HQ6zoSk9t-Lkf4MSNmEUN6S5EqoVWnBQw_K6g%40mail.gmail.com.
