Return-Path: <kasan-dev+bncBDAOJ6534YNBBYFMT3DAMGQE76EGVQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EB191B56F54
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 06:30:25 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45e05ff0b36sf14248025e9.0
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 21:30:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757910625; cv=pass;
        d=google.com; s=arc-20240605;
        b=AKuawX6rCLvS3Tv8elT7pDxvfW1aZ04zJA0EAckUjAuYPqhNVTvxObnjxjWDKOLCW0
         HsPbh7tdWPTH51kUP+LJUtz0dCYCW5eKdwMVyYYn5szMRXOOIbzrdOrpwOsj54PRSTai
         URVUEXjRhUnN8fRLtGM8zP0zfNG23MXyIgH1VEf1wdCqMHZbkb8sYoFAcxXabISdMr7v
         P3M8V30hwGDXb20groqBhGY/PIPK9KzU/+kc+Aiy3jh/5CheZFk6WhannUmSvpBIDuzs
         5Id9W3Nb73Kvqm6dRrSlFhe3Ue7lDfbb92PHNW2B4FADacuZ2hxDL/FaO6W2FQBzaOhy
         jNAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wlCPA0XPVfj0gGXWkmkIth60jvw3wuyNkgComBjRbtE=;
        fh=XVJIWeIHCA3j7bor1HQotVKyN/oBr+iwtPRUUGPfma4=;
        b=QZvF83NDtBWhy/8bgXO4Ukjb72K5xg1z1fapmqrICEMws5WFsSkRwqNowjPzkN5j5l
         wgVW5hRSQ/6xnAarJd7s0//sN5+6vH7TGJ0qWOX3/ww2hwq1O94uBA//HotvzGtr9Qir
         2phlQeuJJSqmL9SA0r+7RcF6aVtD34Fwayp3nAOSIQPjLOvFk958xL9ze9aARoWz6B5B
         Lob4Yoq4aZSHUnMzUJ5IwIy+yi2gnXLvsAlGZ6wmA/fA8CH6a0KdpV5laePXE1Cg59kx
         oxPhsJH9lOhoQAeIBptrMVLpC7Sj/PT9W6AU+dyGNvlvR+IasHg6pnvNyCOcjswEPHjw
         So+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MsHwKuyE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757910625; x=1758515425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wlCPA0XPVfj0gGXWkmkIth60jvw3wuyNkgComBjRbtE=;
        b=G5+OIVPeT7JcRN2aO7eEqoHhYHQQoLQq59VlmPWZ1VhExWXYsZ1GA1KkjjpORzJhTI
         fOgquTu1jiHrC4gJrPxVNrJEzm8Kfgm0BVTSpoh3WaNGUkvIOX+FUmp5/AQSP9ZilvC/
         +FXSM+YF9Yb6IFp1lcDF+f469aBaQOEev0VsZexs2099ipWd6w6H2yNBxjo8hhdoWyAR
         Usc7eZeRHZcwRzNehTrElJTvBsjko1NE5PlQ/bYPON5t+a2FH/TJ0kHDux++ou18b145
         qu3aWqGuVvCLCLzRXtXklZ3mr/KylqZ7HZnNo0eGVCXz55NW+rEiQ5Tf9Wfc3d110HeN
         U+mw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757910625; x=1758515425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wlCPA0XPVfj0gGXWkmkIth60jvw3wuyNkgComBjRbtE=;
        b=Mzgdy6QTN4SajoXecbj4+aNtX1rH02F/CMEaFpx4TXsT4rUu3gqDrz71N1wXQzG3Ho
         tAWJD9uPd7UHC9PzGfXrTQWLZDY6HnR2W3Cx6fwvbbIaKW04QuJIAEIDsGUtAhQO2dfd
         nevaLsmdOZWIv6ODZVmzhCbrGitxbM+cdsQ4n6uLXyEBGEBsVPhv36HTn6IwOcslGeSi
         IrCZp66JHDwi93lCCz0ncKMYX7h6XRZNLdBF7H2/W42uPDIY4x8VjSA/JJNqOCoOLHGb
         zG/m/upeC4wSccoKR3+rAiu74uV7Qc4cnHRIG/9eJl/tZE6p1Hb2kfUdR3R3D9b4VlY9
         S2qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757910625; x=1758515425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wlCPA0XPVfj0gGXWkmkIth60jvw3wuyNkgComBjRbtE=;
        b=cuBixTX663nIJ962+asl4pzkOXvYEUceyk5r9HxVoWICw4w8OitA/2IkwQ1xU3G02e
         8UebuEWsiBgNir84xydRLQUE6BEoKl2bWyj4Znajo2V9mUeAcbk97ngdegy1byxdfbP6
         MzaHp3uJmgrnwZKbB2pyViW/bHTgqudFRAZQTkJ5OPGVHA1meN1ohb5avcJmLkTYCxUi
         bP9YXb9QTE7TkIi1zWu4Ag2iTS6hcvTKKAPqVG/dwt0+psva6/4Ic0amZuM3v3rGJr7b
         E1GeH+Yc/7oOHCHYJ5jtrV10Hk1NdhddYqzVZ0X0L69t4+uaVlJxEf6DPERJQ7goDw6B
         ZpDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKlJpm2nF/Ia/yZx2tzFpWqAEIdW+rwZQw17YdaBMBGQC4SG8OB9yAkv7PLFr4Lj93H91LYw==@lfdr.de
X-Gm-Message-State: AOJu0YyxkgOokN026D0a9u/BdifPnwd3PbxmZLfNQJXmd572wey8Ot95
	o9qpmgGvehwwqpqQE5ZmOAbdthfWlHY/4bzA5kNZ/gyT1K8AHvAQuj8H
X-Google-Smtp-Source: AGHT+IHO0uytz0Si/aFQUjHoVIsDvqFKZzWEn35NUY+W2wmd9/n9WAqVDFVOw56jDjRAJl+HVbm/ZQ==
X-Received: by 2002:a05:6000:22c5:b0:3df:9ba8:21a3 with SMTP id ffacd0b85a97d-3e7659f3385mr7576242f8f.18.1757910624916;
        Sun, 14 Sep 2025 21:30:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Ftv8Tz6ismGWyfezjPas2OhJQcG8+pAKZ0kou23jUHQ==
Received: by 2002:a05:6000:4210:b0:3c6:83a6:d69d with SMTP id
 ffacd0b85a97d-3e75ef4ea37ls1565874f8f.0.-pod-prod-00-eu; Sun, 14 Sep 2025
 21:30:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0ylIYZSDUmi9ircsm7L1/zgHe4TQXQLu5gOD+mbwJIvsLhQFnqOcCszkQ4ZwoqAIHvQU7nm9TqHI=@googlegroups.com
X-Received: by 2002:a05:6000:2c02:b0:3e9:5213:2fc3 with SMTP id ffacd0b85a97d-3e9521330b9mr5727091f8f.10.1757910622329;
        Sun, 14 Sep 2025 21:30:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757910622; cv=none;
        d=google.com; s=arc-20240605;
        b=U2o6VhRrCIAmEfWI6GsSth1Ffi/+7789QwgEuzDyqD6DDO0e2V8fPJT724G7lSzmnx
         OUrtA1qq8lK+1UFsShk8GDRhQpNdGc8PeEn9Hp064heDTxHRp19qe6R0A/kM9cXJ6hrW
         vK2abqj9qGrR8oYtlOlquOm0+TUs8GEcgUdVq1NqFJT6wLDR01WavNJTdtUo6IcPES0L
         +mirA0QxasYEo2Vyit6L9mFu+dJECcHSyOt9Wqp5ejweF2+CEHzpGQFCkqaWh2NTeNUM
         c7ryEgTWDEWxTqaVKk8HXwdVbrV994wZ97Z0EX8/5A5J+3+Pgbluh49pxxJVrbSwC9c0
         5boA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=go7hweaAE58uKR62z5kHHsQPWXjABY7bZXE2nlLEF24=;
        fh=PadGVMfwD80vW4OHCPqp80u3NKMCBL+lXIAO685YBdM=;
        b=YDJVC+QEc0YZEoiKjZYGYhtcJczR7lv0SVJYmPGfhinywvAo2jyuh9QCHw7npcYeR+
         EVywDGhfSCLMTIEcFoWcfUDlM1h1+/u9VcRkdFkvMACNGsPF4/4LlJUgr7Mbm2cTI+vX
         JPyAHZ52SkTQokE0x5SJWuFxfvZLiH9IQHOBUgjOCTY9kxGSbwV0kLzAI+owGObKJDbK
         22d8FKKXRZGwdpK8MolWFUONFamewuv2x6OE4hMjfhZveFC2LV+5fq5d9CfbQbJ0spLm
         /3LJwtM5uU3KZzc4JqGiIEXHjR7qdRh+tmqFbY+Fl5SUEIbYoI1a87XvkOw32dwvR5zb
         T0NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MsHwKuyE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45e0632d433si1795815e9.1.2025.09.14.21.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 14 Sep 2025 21:30:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-57263febd12so1088739e87.1
        for <kasan-dev@googlegroups.com>; Sun, 14 Sep 2025 21:30:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKuW7w0uwq59TldVIlDqDLlsEZ2RZFw1vWvdIyQqg/E22561h27SKfhHSBbzkfYRqhJ0yv5S+moyY=@googlegroups.com
X-Gm-Gg: ASbGncuszfBTHDBbUDyIeMNmb9MG/6ZqLL1hDh+Mx6mG3BPNnT/LTxTjw6XqKUwlQVZ
	xg/nsvCaQc6cEDJ0lput7jox0PFglbB+qQD2N5DXoQPnfR3JUwPWk96YM8DucbGxP/Hs48U/gSN
	yJeabIVxE5+nMB7gfwmhqA8S+d3bMGLFhjMvBNFhw+AFvfM8fl5RwT5NjkL6AqUkvRLMpPEdRzw
	ZOddn4c4Y5m8WB0ow==
X-Received: by 2002:a05:6512:1195:b0:55f:61dd:6f5 with SMTP id
 2adb3069b0e04-56d79b23442mr4155585e87.14.1757910620905; Sun, 14 Sep 2025
 21:30:20 -0700 (PDT)
MIME-Version: 1.0
References: <20250810125746.1105476-1-snovitoll@gmail.com> <20250810125746.1105476-2-snovitoll@gmail.com>
 <CA+fCnZdFp69ZHbccLSEKYH3i7g6r2WdQ0qzyf+quLnA0tjfXJg@mail.gmail.com>
In-Reply-To: <CA+fCnZdFp69ZHbccLSEKYH3i7g6r2WdQ0qzyf+quLnA0tjfXJg@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Mon, 15 Sep 2025 09:30:03 +0500
X-Gm-Features: AS18NWDp8zAExztzkhZUMEcqPOjcBJv5p1-pZY4kdVc-Z24hbqQ_po0bm4wAyHg
Message-ID: <CACzwLxh4pJOBbU2fHKCPWkHHCuLtDW-rh52788u2Q6+nG-+bTA@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, christophe.leroy@csgroup.eu, bhe@redhat.com, 
	hca@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, davidgow@google.com, glider@google.com, 
	dvyukov@google.com, alexghiti@rivosinc.com, alex@ghiti.fr, 
	agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MsHwKuyE;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Sep 3, 2025 at 6:01=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
>
> On Sun, Aug 10, 2025 at 2:58=E2=80=AFPM Sabyrzhan Tasbolatov
> <snovitoll@gmail.com> wrote:
> >
> > Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] that ne=
ed
> > to defer KASAN initialization until shadow memory is properly set up,
> > and unify the static key infrastructure across all KASAN modes.
> >
> > [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
> >
> > The core issue is that different architectures haveinconsistent approac=
hes
> > to KASAN readiness tracking:
> > - PowerPC, LoongArch, and UML arch, each implement own
> >   kasan_arch_is_ready()
> > - Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
> > - Generic and SW_TAGS modes relied on arch-specific solutions or always=
-on
> >     behavior
> >
> > This patch addresses the fragmentation in KASAN initialization
> > across architectures by introducing a unified approach that eliminates
> > duplicate static keys and arch-specific kasan_arch_is_ready()
> > implementations.
> >
> > Let's replace kasan_arch_is_ready() with existing kasan_enabled() check=
,
> > which examines the static key being enabled if arch selects
> > ARCH_DEFER_KASAN or has HW_TAGS mode support.
> > For other arch, kasan_enabled() checks the enablement during compile ti=
me.
> >
> > Now KASAN users can use a single kasan_enabled() check everywhere.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > Changes in v6:
> > - Added more details in git commit message
> > - Fixed commenting format per coding style in UML (Christophe Leroy)
> > - Changed exporting to GPL for kasan_flag_enabled (Christophe Leroy)
> > - Converted ARCH_DEFER_KASAN to def_bool depending on KASAN to avoid
> >         arch users to have `if KASAN` condition (Christophe Leroy)
> > - Forgot to add __init for kasan_init in UML
> >
> > Changes in v5:
> > - Unified patches where arch (powerpc, UML, loongarch) selects
> >     ARCH_DEFER_KASAN in the first patch not to break
> >     bisectability
> > - Removed kasan_arch_is_ready completely as there is no user
> > - Removed __wrappers in v4, left only those where it's necessary
> >     due to different implementations
> >
> > Changes in v4:
> > - Fixed HW_TAGS static key functionality (was broken in v3)
> > - Merged configuration and implementation for atomicity
> > ---
> >  arch/loongarch/Kconfig                 |  1 +
> >  arch/loongarch/include/asm/kasan.h     |  7 ------
> >  arch/loongarch/mm/kasan_init.c         |  8 +++----
> >  arch/powerpc/Kconfig                   |  1 +
> >  arch/powerpc/include/asm/kasan.h       | 12 ----------
> >  arch/powerpc/mm/kasan/init_32.c        |  2 +-
> >  arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
> >  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
> >  arch/um/Kconfig                        |  1 +
> >  arch/um/include/asm/kasan.h            |  5 ++--
> >  arch/um/kernel/mem.c                   | 13 ++++++++---
> >  include/linux/kasan-enabled.h          | 32 ++++++++++++++++++--------
> >  include/linux/kasan.h                  |  6 +++++
> >  lib/Kconfig.kasan                      | 12 ++++++++++
> >  mm/kasan/common.c                      | 17 ++++++++++----
> >  mm/kasan/generic.c                     | 19 +++++++++++----
> >  mm/kasan/hw_tags.c                     |  9 +-------
> >  mm/kasan/kasan.h                       |  8 ++++++-
> >  mm/kasan/shadow.c                      | 12 +++++-----
> >  mm/kasan/sw_tags.c                     |  1 +
> >  mm/kasan/tags.c                        |  2 +-
> >  21 files changed, 106 insertions(+), 70 deletions(-)
> >
> > diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> > index f0abc38c40ac..e449e3fcecf9 100644
> > --- a/arch/loongarch/Kconfig
> > +++ b/arch/loongarch/Kconfig
> > @@ -9,6 +9,7 @@ config LOONGARCH
> >         select ACPI_PPTT if ACPI
> >         select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
> >         select ARCH_BINFMT_ELF_STATE
> > +       select ARCH_NEEDS_DEFER_KASAN
> >         select ARCH_DISABLE_KASAN_INLINE
> >         select ARCH_ENABLE_MEMORY_HOTPLUG
> >         select ARCH_ENABLE_MEMORY_HOTREMOVE
> > diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/includ=
e/asm/kasan.h
> > index 62f139a9c87d..0e50e5b5e056 100644
> > --- a/arch/loongarch/include/asm/kasan.h
> > +++ b/arch/loongarch/include/asm/kasan.h
> > @@ -66,7 +66,6 @@
> >  #define XKPRANGE_WC_SHADOW_OFFSET      (KASAN_SHADOW_START + XKPRANGE_=
WC_KASAN_OFFSET)
> >  #define XKVRANGE_VC_SHADOW_OFFSET      (KASAN_SHADOW_START + XKVRANGE_=
VC_KASAN_OFFSET)
> >
> > -extern bool kasan_early_stage;
> >  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> >
> >  #define kasan_mem_to_shadow kasan_mem_to_shadow
> > @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
> >  #define kasan_shadow_to_mem kasan_shadow_to_mem
> >  const void *kasan_shadow_to_mem(const void *shadow_addr);
> >
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -       return !kasan_early_stage;
> > -}
> > -
> >  #define addr_has_metadata addr_has_metadata
> >  static __always_inline bool addr_has_metadata(const void *addr)
> >  {
> > diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_i=
nit.c
> > index d2681272d8f0..170da98ad4f5 100644
> > --- a/arch/loongarch/mm/kasan_init.c
> > +++ b/arch/loongarch/mm/kasan_init.c
> > @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata _=
_aligned(PAGE_SIZE);
> >  #define __pte_none(early, pte) (early ? pte_none(pte) : \
> >  ((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_sha=
dow_page)))
> >
> > -bool kasan_early_stage =3D true;
> > -
> >  void *kasan_mem_to_shadow(const void *addr)
> >  {
> > -       if (!kasan_arch_is_ready()) {
> > +       if (!kasan_enabled()) {
> >                 return (void *)(kasan_early_shadow_page);
> >         } else {
> >                 unsigned long maddr =3D (unsigned long)addr;
> > @@ -298,7 +296,8 @@ void __init kasan_init(void)
> >         kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC=
_START),
> >                                         kasan_mem_to_shadow((void *)KFE=
NCE_AREA_END));
> >
> > -       kasan_early_stage =3D false;
> > +       /* Enable KASAN here before kasan_mem_to_shadow(). */
> > +       kasan_init_generic();
> >
> >         /* Populate the linear mapping */
> >         for_each_mem_range(i, &pa_start, &pa_end) {
> > @@ -329,5 +328,4 @@ void __init kasan_init(void)
> >
> >         /* At this point kasan is fully initialized. Enable error messa=
ges */
> >         init_task.kasan_depth =3D 0;
> > -       pr_info("KernelAddressSanitizer initialized.\n");
> >  }
> > diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> > index 93402a1d9c9f..4730c676b6bf 100644
> > --- a/arch/powerpc/Kconfig
> > +++ b/arch/powerpc/Kconfig
> > @@ -122,6 +122,7 @@ config PPC
> >         # Please keep this list sorted alphabetically.
> >         #
> >         select ARCH_32BIT_OFF_T if PPC32
> > +       select ARCH_NEEDS_DEFER_KASAN           if PPC_RADIX_MMU
> >         select ARCH_DISABLE_KASAN_INLINE        if PPC_RADIX_MMU
> >         select ARCH_DMA_DEFAULT_COHERENT        if !NOT_COHERENT_CACHE
> >         select ARCH_ENABLE_MEMORY_HOTPLUG
> > diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/as=
m/kasan.h
> > index b5bbb94c51f6..957a57c1db58 100644
> > --- a/arch/powerpc/include/asm/kasan.h
> > +++ b/arch/powerpc/include/asm/kasan.h
> > @@ -53,18 +53,6 @@
> >  #endif
> >
> >  #ifdef CONFIG_KASAN
> > -#ifdef CONFIG_PPC_BOOK3S_64
> > -DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> > -
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -       if (static_branch_likely(&powerpc_kasan_enabled_key))
> > -               return true;
> > -       return false;
> > -}
> > -
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -#endif
> >
> >  void kasan_early_init(void);
> >  void kasan_mmu_init(void);
> > diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/in=
it_32.c
> > index 03666d790a53..1d083597464f 100644
> > --- a/arch/powerpc/mm/kasan/init_32.c
> > +++ b/arch/powerpc/mm/kasan/init_32.c
> > @@ -165,7 +165,7 @@ void __init kasan_init(void)
> >
> >         /* At this point kasan is fully initialized. Enable error messa=
ges */
> >         init_task.kasan_depth =3D 0;
> > -       pr_info("KASAN init done\n");
> > +       kasan_init_generic();
> >  }
> >
> >  void __init kasan_late_init(void)
> > diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/k=
asan/init_book3e_64.c
> > index 60c78aac0f63..0d3a73d6d4b0 100644
> > --- a/arch/powerpc/mm/kasan/init_book3e_64.c
> > +++ b/arch/powerpc/mm/kasan/init_book3e_64.c
> > @@ -127,7 +127,7 @@ void __init kasan_init(void)
> >
> >         /* Enable error messages */
> >         init_task.kasan_depth =3D 0;
> > -       pr_info("KASAN init done\n");
> > +       kasan_init_generic();
> >  }
> >
> >  void __init kasan_late_init(void) { }
> > diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/k=
asan/init_book3s_64.c
> > index 7d959544c077..dcafa641804c 100644
> > --- a/arch/powerpc/mm/kasan/init_book3s_64.c
> > +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> > @@ -19,8 +19,6 @@
> >  #include <linux/memblock.h>
> >  #include <asm/pgalloc.h>
> >
> > -DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> > -
> >  static void __init kasan_init_phys_region(void *start, void *end)
> >  {
> >         unsigned long k_start, k_end, k_cur;
> > @@ -92,11 +90,9 @@ void __init kasan_init(void)
> >          */
> >         memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >
> > -       static_branch_inc(&powerpc_kasan_enabled_key);
> > -
> >         /* Enable error messages */
> >         init_task.kasan_depth =3D 0;
> > -       pr_info("KASAN init done\n");
> > +       kasan_init_generic();
> >  }
> >
> >  void __init kasan_early_init(void) { }
> > diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> > index 9083bfdb7735..1d4def0db841 100644
> > --- a/arch/um/Kconfig
> > +++ b/arch/um/Kconfig
> > @@ -5,6 +5,7 @@ menu "UML-specific options"
> >  config UML
> >         bool
> >         default y
> > +       select ARCH_NEEDS_DEFER_KASAN if STATIC_LINK
> >         select ARCH_WANTS_DYNAMIC_TASK_STRUCT
> >         select ARCH_HAS_CACHE_LINE_SIZE
> >         select ARCH_HAS_CPU_FINALIZE_INIT
> > diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> > index f97bb1f7b851..b54a4e937fd1 100644
> > --- a/arch/um/include/asm/kasan.h
> > +++ b/arch/um/include/asm/kasan.h
> > @@ -24,10 +24,9 @@
> >
> >  #ifdef CONFIG_KASAN
> >  void kasan_init(void);
> > -extern int kasan_um_is_ready;
> >
> > -#ifdef CONFIG_STATIC_LINK
> > -#define kasan_arch_is_ready() (kasan_um_is_ready)
> > +#if defined(CONFIG_STATIC_LINK) && defined(CONFIG_KASAN_INLINE)
> > +#error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled=
!
> >  #endif
> >  #else
> >  static inline void kasan_init(void) { }
> > diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> > index 76bec7de81b5..32e3b1972dc1 100644
> > --- a/arch/um/kernel/mem.c
> > +++ b/arch/um/kernel/mem.c
> > @@ -21,10 +21,10 @@
> >  #include <os.h>
> >  #include <um_malloc.h>
> >  #include <linux/sched/task.h>
> > +#include <linux/kasan.h>
> >
> >  #ifdef CONFIG_KASAN
> > -int kasan_um_is_ready;
> > -void kasan_init(void)
> > +void __init kasan_init(void)
> >  {
> >         /*
> >          * kasan_map_memory will map all of the required address space =
and
> > @@ -32,7 +32,11 @@ void kasan_init(void)
> >          */
> >         kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE)=
;
> >         init_task.kasan_depth =3D 0;
> > -       kasan_um_is_ready =3D true;
> > +       /*
> > +        * Since kasan_init() is called before main(),
> > +        * KASAN is initialized but the enablement is deferred after
> > +        * jump_label_init(). See arch_mm_preinit().
> > +        */
> >  }
> >
> >  static void (*kasan_init_ptr)(void)
> > @@ -58,6 +62,9 @@ static unsigned long brk_end;
> >
> >  void __init arch_mm_preinit(void)
> >  {
> > +       /* Safe to call after jump_label_init(). Enables KASAN. */
> > +       kasan_init_generic();
> > +
> >         /* clear the zero-page */
> >         memset(empty_zero_page, 0, PAGE_SIZE);
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enable=
d.h
> > index 6f612d69ea0c..9eca967d8526 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -4,32 +4,46 @@
> >
> >  #include <linux/static_key.h>
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -
> > +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> > +/*
> > + * Global runtime flag for KASAN modes that need runtime control.
> > + * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
> > + */
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > +/*
> > + * Runtime control for shadow memory initialization or HW_TAGS mode.
> > + * Uses static key for architectures that need deferred KASAN or HW_TA=
GS.
> > + */
> >  static __always_inline bool kasan_enabled(void)
> >  {
> >         return static_branch_likely(&kasan_flag_enabled);
> >  }
> >
> > -static inline bool kasan_hw_tags_enabled(void)
> > +static inline void kasan_enable(void)
> >  {
> > -       return kasan_enabled();
> > +       static_branch_enable(&kasan_flag_enabled);
> >  }
> > -
> > -#else /* CONFIG_KASAN_HW_TAGS */
> > -
> > -static inline bool kasan_enabled(void)
> > +#else
> > +/* For architectures that can enable KASAN early, use compile-time che=
ck. */
> > +static __always_inline bool kasan_enabled(void)
> >  {
> >         return IS_ENABLED(CONFIG_KASAN);
> >  }
> >
> > +static inline void kasan_enable(void) {}
> > +#endif /* CONFIG_ARCH_DEFER_KASAN || CONFIG_KASAN_HW_TAGS */
> > +
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +static inline bool kasan_hw_tags_enabled(void)
> > +{
> > +       return kasan_enabled();
> > +}
> > +#else
> >  static inline bool kasan_hw_tags_enabled(void)
> >  {
> >         return false;
> >  }
> > -
> >  #endif /* CONFIG_KASAN_HW_TAGS */
> >
> >  #endif /* LINUX_KASAN_ENABLED_H */
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 890011071f2b..51a8293d1af6 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -543,6 +543,12 @@ void kasan_report_async(void);
> >
> >  #endif /* CONFIG_KASAN_HW_TAGS */
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +void __init kasan_init_generic(void);
> > +#else
> > +static inline void kasan_init_generic(void) { }
> > +#endif
> > +
> >  #ifdef CONFIG_KASAN_SW_TAGS
> >  void __init kasan_init_sw_tags(void);
> >  #else
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index f82889a830fa..a4bb610a7a6f 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -19,6 +19,18 @@ config ARCH_DISABLE_KASAN_INLINE
> >           Disables both inline and stack instrumentation. Selected by
> >           architectures that do not support these instrumentation types=
.
> >
> > +config ARCH_NEEDS_DEFER_KASAN
> > +       bool
> > +
> > +config ARCH_DEFER_KASAN
> > +       def_bool y
> > +       depends on KASAN && ARCH_NEEDS_DEFER_KASAN
> > +       help
> > +         Architectures should select this if they need to defer KASAN
> > +         initialization until shadow memory is properly set up. This
> > +         enables runtime control via static keys. Otherwise, KASAN use=
s
> > +         compile-time constants for better performance.
> > +
> >  config CC_HAS_KASAN_GENERIC
> >         def_bool $(cc-option, -fsanitize=3Dkernel-address)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 9142964ab9c9..e3765931a31f 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -32,6 +32,15 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> > +/*
> > + * Definition of the unified static key declared in kasan-enabled.h.
> > + * This provides consistent runtime enable/disable across KASAN modes.
> > + */
> > +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > +EXPORT_SYMBOL_GPL(kasan_flag_enabled);
> > +#endif
> > +
> >  struct slab *kasan_addr_to_slab(const void *addr)
> >  {
> >         if (virt_addr_valid(addr))
> > @@ -246,7 +255,7 @@ static inline void poison_slab_object(struct kmem_c=
ache *cache, void *object,
> >  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
> >                                 unsigned long ip)
> >  {
> > -       if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +       if (is_kfence_address(object))
> >                 return false;
>
> Why is the check removed here and in some other places below? This
> need to be explained in the commit message.

kasan_arch_is_ready which was unified with kasan_enabled, was removed
here because
__kasan_slab_pre_free is called from include/linux/kasan.h [1] where
there's already kasan_enabled() check.

[1] https://elixir.bootlin.com/linux/v6.16.7/source/include/linux/kasan.h#L=
198

Please let me know if v7 is required with the change in the git commit
message only.

>
> >         return check_slab_allocation(cache, object, ip);
> >  }
> > @@ -254,7 +263,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache=
, void *object,
> >  bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool in=
it,
> >                        bool still_accessible)
> >  {
> > -       if (!kasan_arch_is_ready() || is_kfence_address(object))
> > +       if (is_kfence_address(object))
> >                 return false;
> >
> >         /*
> > @@ -293,7 +302,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, vo=
id *object, bool init,
> >
> >  static inline bool check_page_allocation(void *ptr, unsigned long ip)
> >  {
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return false;
> >
> >         if (ptr !=3D page_address(virt_to_head_page(ptr))) {
> > @@ -522,7 +531,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
> >                 return true;
> >         }
> >
> > -       if (is_kfence_address(ptr) || !kasan_arch_is_ready())
> > +       if (is_kfence_address(ptr))
> >                 return true;
> >
> >         slab =3D folio_slab(folio);
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index d54e89f8c3e7..b413c46b3e04 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -36,6 +36,17 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > +/*
> > + * Initialize Generic KASAN and enable runtime checks.
> > + * This should be called from arch kasan_init() once shadow memory is =
ready.
> > + */
> > +void __init kasan_init_generic(void)
> > +{
> > +       kasan_enable();
> > +
> > +       pr_info("KernelAddressSanitizer initialized (generic)\n");
> > +}
> > +
> >  /*
> >   * All functions below always inlined so compiler could
> >   * perform better optimizations in each of __asan_loadX/__assn_storeX
> > @@ -165,7 +176,7 @@ static __always_inline bool check_region_inline(con=
st void *addr,
> >                                                 size_t size, bool write=
,
> >                                                 unsigned long ret_ip)
> >  {
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return true;
> >
> >         if (unlikely(size =3D=3D 0))
> > @@ -193,7 +204,7 @@ bool kasan_byte_accessible(const void *addr)
> >  {
> >         s8 shadow_byte;
> >
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return true;
> >
> >         shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
> > @@ -495,7 +506,7 @@ static void release_alloc_meta(struct kasan_alloc_m=
eta *meta)
> >
> >  static void release_free_meta(const void *object, struct kasan_free_me=
ta *meta)
> >  {
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return;
> >
> >         /* Check if free meta is valid. */
> > @@ -562,7 +573,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache=
, void *object, gfp_t flags)
> >         kasan_save_track(&alloc_meta->alloc_track, flags);
> >  }
> >
> > -void kasan_save_free_info(struct kmem_cache *cache, void *object)
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object)
> >  {
> >         struct kasan_free_meta *free_meta;
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 9a6927394b54..c8289a3feabf 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
> >  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> >  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> >
> > -/*
> > - * Whether KASAN is enabled at all.
> > - * The value remains false until KASAN is initialized by kasan_init_hw=
_tags().
> > - */
> > -DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > -EXPORT_SYMBOL(kasan_flag_enabled);
> > -
> >  /*
> >   * Whether the selected mode is synchronous, asynchronous, or asymmetr=
ic.
> >   * Defaults to KASAN_MODE_SYNC.
> > @@ -260,7 +253,7 @@ void __init kasan_init_hw_tags(void)
> >         kasan_init_tags();
> >
> >         /* KASAN is now initialized, enable it. */
> > -       static_branch_enable(&kasan_flag_enabled);
> > +       kasan_enable();
> >
> >         pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s=
, vmalloc=3D%s, stacktrace=3D%s)\n",
> >                 kasan_mode_info(),
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 129178be5e64..8a9d8a6ea717 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -398,7 +398,13 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags,=
 depot_flags_t depot_flags);
> >  void kasan_set_track(struct kasan_track *track, depot_stack_handle_t s=
tack);
> >  void kasan_save_track(struct kasan_track *track, gfp_t flags);
> >  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp=
_t flags);
> > -void kasan_save_free_info(struct kmem_cache *cache, void *object);
> > +
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object);
> > +static inline void kasan_save_free_info(struct kmem_cache *cache, void=
 *object)
> > +{
> > +       if (kasan_enabled())
> > +               __kasan_save_free_info(cache, object);
> > +}
>
> What I meant with these __wrappers was that we should add them for the
> KASAN hooks that are called from non-KASAN code (i.e. for the hooks
> defined in include/linux/kasan.h). And then move all the
> kasan_enabled() checks from mm/kasan/* to where the wrappers are
> defined in include/linux/kasan.h (see kasan_unpoison_range() as an
> example).
>
> kasan_save_free_info is a KASAN internal function that should need
> such a wrapper.
>
> For now, to make these patches simpler, you can keep kasan_enabled()
> checks in mm/kasan/*, where they are now. Later we can move them to
> include/linux/kasan.h with a separate patch.

Yes, I'd like to revisit this in the next separate patch series.

>
>
> >
> >  #ifdef CONFIG_KASAN_GENERIC
> >  bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index d2c70cd2afb1..2e126cb21b68 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -125,7 +125,7 @@ void kasan_poison(const void *addr, size_t size, u8=
 value, bool init)
> >  {
> >         void *shadow_start, *shadow_end;
> >
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return;
> >
> >         /*
> > @@ -150,7 +150,7 @@ EXPORT_SYMBOL_GPL(kasan_poison);
> >  #ifdef CONFIG_KASAN_GENERIC
> >  void kasan_poison_last_granule(const void *addr, size_t size)
> >  {
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return;
> >
> >         if (size & KASAN_GRANULE_MASK) {
> > @@ -390,7 +390,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsi=
gned long size)
> >         unsigned long shadow_start, shadow_end;
> >         int ret;
> >
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return 0;
> >
> >         if (!is_vmalloc_or_module_addr((void *)addr))
> > @@ -560,7 +560,7 @@ void kasan_release_vmalloc(unsigned long start, uns=
igned long end,
> >         unsigned long region_start, region_end;
> >         unsigned long size;
> >
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return;
> >
> >         region_start =3D ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
> > @@ -611,7 +611,7 @@ void *__kasan_unpoison_vmalloc(const void *start, u=
nsigned long size,
> >          * with setting memory tags, so the KASAN_VMALLOC_INIT flag is =
ignored.
> >          */
> >
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return (void *)start;
> >
> >         if (!is_vmalloc_or_module_addr(start))
> > @@ -636,7 +636,7 @@ void *__kasan_unpoison_vmalloc(const void *start, u=
nsigned long size,
> >   */
> >  void __kasan_poison_vmalloc(const void *start, unsigned long size)
> >  {
> > -       if (!kasan_arch_is_ready())
> > +       if (!kasan_enabled())
> >                 return;
> >
> >         if (!is_vmalloc_or_module_addr(start))
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index b9382b5b6a37..c75741a74602 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -44,6 +44,7 @@ void __init kasan_init_sw_tags(void)
> >                 per_cpu(prng_state, cpu) =3D (u32)get_cycles();
> >
> >         kasan_init_tags();
> > +       kasan_enable();
> >
> >         pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrac=
e=3D%s)\n",
> >                 str_on_off(kasan_stack_collection_enabled()));
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index d65d48b85f90..b9f31293622b 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -142,7 +142,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache=
, void *object, gfp_t flags)
> >         save_stack_info(cache, object, flags, false);
> >  }
> >
> > -void kasan_save_free_info(struct kmem_cache *cache, void *object)
> > +void __kasan_save_free_info(struct kmem_cache *cache, void *object)
> >  {
> >         save_stack_info(cache, object, 0, true);
> >  }
> > --
> > 2.34.1
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxh4pJOBbU2fHKCPWkHHCuLtDW-rh52788u2Q6%2BnG-%2BbTA%40mail.gmail.com.
