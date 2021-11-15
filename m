Return-Path: <kasan-dev+bncBCQJP74GSUDRBCURZKGAMGQEP6BMR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id F18E3450975
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 17:19:23 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id x5-20020a05620a0b4500b004679442640asf11377855qkg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 08:19:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636993163; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmMFKWw/HMcwnKBpIouZbfpGj65hR1kSGXV2LoD8DsfGbhre3/FiN4BiSTRW66g4rT
         zEFEtnkxEHwOysI2fQDpN423MNUmC0lbbE7hhyb4O9kpNrOQyfCR0SeHIBXngiqX6CAN
         1nr2pfFMZthqDotY2AozjBcbYWR53Wh3WSVTNkuHj81MTtW/+VvTKrD3x50HqpSW+EWn
         5vpf/IQoGdTmKPSWRHGZFbl8mBAGGh5nYlOHDDzwtVTYdAMDPDaoALoFx+gsLeSu2mkm
         NkNsgWf0t0StGGw3unRN2NJ4sS07xXLVCqM3o4mYDGaVMHoFbh6kLYkTnmA/QQia2sNy
         Xcaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4PFPoMwbhkHp04OD4Dopg+eTjKEwc//4rs2+vOhHQSo=;
        b=X3c1tXQWv162cLm+GVqxVm44fQPrRRS6L3eYBy5S28HYeYnfhLPUmnR7l2Mx6ppWpi
         U9o1Cqu2r68oZglLN4z9dJH5Z8A+7pIjPZMW0HX2kb1+EMbFaumi7bVzT1n57mRX3RQG
         Q7hr5ncRT0r47BVt1IKDkhvXwZLoCBZeELn8tMjgL8+ySpaz+meoYpAFc2UVkNJRTd1M
         zhQ8wYMuo9MmatQ7EPRPveYp7+3QLq8DygNRkkQnmuTYW3+ajtsS90w37pHUquH/RY3X
         Vo74uYPRROh+AoWzj7AF3Z1RSvuqBdh9fO6pE3rxnBMxcdRcQnykoE05F0fm8uMmy1hx
         Uv7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.48 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4PFPoMwbhkHp04OD4Dopg+eTjKEwc//4rs2+vOhHQSo=;
        b=plxndEjoGQVR/vlWQZUU1ohEGGnNSq4bA3SgCtBiVK45EMZehlIbU3sGkpTTDXHqut
         ZVunIVX9WkU80orKAsSMnajRgJFNGaNWnasz61MtZ5Un+8Fg5eKQyQnydUJkWBZcnuM+
         X3NwNLATZp+LAAMDiX2dURVvQBuMUP+ZWWUQRR+aWd8sOLhjtP6Fq4XxJ+OWy5KGrHpx
         YjabaBZ2cUl3M0JR0gKtD2rxk/NXgRu3lgbAgD6jX+4IHSGi2+7Fa5FML8ISW9nkxFMK
         LntdKxVeLDm8N5y9a48CODMiRnc9KhJU/3Z5nvk89PJLbXFZfzpaZoWsuvMvUl0KHR2+
         lq8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4PFPoMwbhkHp04OD4Dopg+eTjKEwc//4rs2+vOhHQSo=;
        b=4iOPn0U9e1Y8La/mP0G1oVRCDSdRrNaypCgBocb6Yu44FZoLuwHm8mx0B5vsYAItcr
         0cMc9v0arMIUeWMbQmccBV5lbi0mYS89PmnqQYFqgruX7orpu+QxgOihewgrQEepdu7B
         j7Yrd8mUW2haE9woWk6nP9LMOEzum8+IaBhD+JKF4r5TSqzSMODCXP8mZKXzwNaPfYi7
         4gLYM/oyRz3mthJeshnJmPu+M2VkHn8n0DZ1c5wnM34N3PJCtV3JyfQr1lVHTbIZX+v4
         UrGxnXnmu11PuyrG+OsFCy68RATYUtuJH3LDFxCVaMWFZUnR6/Y8tI94+uS8fShph3BM
         mmyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Y9J0d3NqGBCPKSQeUHnRPKpHRkrq6EoC18OB2BICbgerwa5fK
	V29SxCfIG9Lc84r+CycRNSE=
X-Google-Smtp-Source: ABdhPJxj3PLHlHkRKqVHLDjFpZYnVL/oxrt02rqbJHduylCNZbINAkHZD0CbTYXd1BPwwwC+gLTVmQ==
X-Received: by 2002:a37:a4c5:: with SMTP id n188mr114352qke.337.1636993162893;
        Mon, 15 Nov 2021 08:19:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1926:: with SMTP id bj38ls7833158qkb.7.gmail; Mon,
 15 Nov 2021 08:19:22 -0800 (PST)
X-Received: by 2002:a37:4cc:: with SMTP id 195mr116132qke.349.1636993162454;
        Mon, 15 Nov 2021 08:19:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636993162; cv=none;
        d=google.com; s=arc-20160816;
        b=hJftNS7je7WQfZF70TSW/rQgZW8lFTDjSccgpxzPJka4YVqTL6kdJyRE9sAykcHfCC
         GzxJiR+my2joJoIdIJTrgzhrNBvnrIvc0Liuv50eQoY6HtYUy4ymv9R9UnKLrdHTy+Vk
         o8bDYUctTaYWHA1WD9IDhS8+D8Qmc46RO7jkViDB/lAShqI1cDV/v8LRG4SwWtAl+8ne
         ei4EV1hiuOlXHvhMB9BIEM+0wV/9QW9MdoAJ+5kYNMnIecqSNgzlfuEW6t73rAXA2ryD
         uGukjm7dbvLqVydC1eTECpEOkNg5yxwGEkRwvWKtLVosZeX+5CY5EzE5geU9h8O4A7ys
         +bbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=efm7nTUMt8rzsLA3IdyOYKyQXeHPPTB88YQ7l3tEZPU=;
        b=ODBdTpJdXi9PvXUf3Gw8BwKMcdR6AW0GZtBXoXkvXoSA4lNgKe3buI2hixBap0ILxP
         Gj0IdvDye67oXFPXwFIdeyGAtZz6eTAZFzhkj0SDRMNlIGftHGuC6HWpuqt0wDAZsVAR
         XHVEvLVMq4u1yPRQl5EEt6tEWaHZSclANmSsDbfMU9zMykXN+p+8PVUYb9YZ+Qyyxwwg
         At+zZNcDlOspL90Nt0luiharAY5wGRPBOShIV6uxkuGuLhfB1IYXRn8Bo+UWSv5OrcIJ
         YpUTpBtNfir0DKfTsGLnlw3T8rrq63K9C8Xsk8w2SU6+tzWWT4NijJEmnL0nlsD4ZwJo
         kWBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.48 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qv1-f48.google.com (mail-qv1-f48.google.com. [209.85.219.48])
        by gmr-mx.google.com with ESMTPS id m14si144552qkn.1.2021.11.15.08.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 08:19:22 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.48 as permitted sender) client-ip=209.85.219.48;
Received: by mail-qv1-f48.google.com with SMTP id a24so11687787qvb.5
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 08:19:22 -0800 (PST)
X-Received: by 2002:a05:6214:400c:: with SMTP id kd12mr38319070qvb.41.1636993161986;
        Mon, 15 Nov 2021 08:19:21 -0800 (PST)
Received: from mail-qv1-f54.google.com (mail-qv1-f54.google.com. [209.85.219.54])
        by smtp.gmail.com with ESMTPSA id t11sm6947823qkm.96.2021.11.15.08.19.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 08:19:21 -0800 (PST)
Received: by mail-qv1-f54.google.com with SMTP id jo22so11660649qvb.13
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 08:19:21 -0800 (PST)
X-Received: by 2002:a1f:f24f:: with SMTP id q76mr60850690vkh.11.1636992782095;
 Mon, 15 Nov 2021 08:13:02 -0800 (PST)
MIME-Version: 1.0
References: <20211115155105.3797527-1-geert@linux-m68k.org>
In-Reply-To: <20211115155105.3797527-1-geert@linux-m68k.org>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Mon, 15 Nov 2021 17:12:50 +0100
X-Gmail-Original-Message-ID: <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
Message-ID: <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
To: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Cc: Nick Terrell <terrelln@fb.com>, Rob Clark <robdclark@gmail.com>, 
	"James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>, Helge Deller <deller@gmx.de>, 
	Anton Altaparmakov <anton@tuxera.com>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, 
	Sergio Paracuellos <sergio.paracuellos@gmail.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Joey Gouly <joey.gouly@arm.com>, Stan Skowronek <stan@corellium.com>, 
	Hector Martin <marcan@marcan.st>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	=?UTF-8?Q?Andr=C3=A9_Almeida?= <andrealmeid@collabora.com>, 
	Peter Zijlstra <peterz@infradead.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"open list:GPIO SUBSYSTEM" <linux-gpio@vger.kernel.org>, Parisc List <linux-parisc@vger.kernel.org>, 
	linux-arm-msm <linux-arm-msm@vger.kernel.org>, 
	DRI Development <dri-devel@lists.freedesktop.org>, linux-ntfs-dev@lists.sourceforge.net, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>, linux-pci <linux-pci@vger.kernel.org>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.48
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.org> wrote:
> Below is the list of build error/warning regressions/improvements in
> v5.16-rc1[1] compared to v5.15[2].
>
> Summarized:
>   - build errors: +20/-13
>   - build warnings: +3/-28
>
> Happy fixing! ;-)
>
> Thanks to the linux-next team for providing the build service.
>
> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc43c1aa1ba12bca9d2dd4318c2a0dbf/ (all 90 configs)
> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972ad531c9b149c0a51ab43a417385813/ (all 90 configs)
>
>
> *** ERRORS ***
>
> 20 error regressions:
>   + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected ':' before '__stringify':  => 33:4, 18:4
>   + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_yes' defined but not used [-Werror=unused-label]:  => 38:1, 23:1

    due to static_branch_likely() in crypto/api.c

parisc-allmodconfig

>   + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined [-Werror]:  => 531
>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 3252 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 47:1
>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 3360 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 499:1
>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 5344 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 334:1
>   + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame size of 5380 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 354:1
>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of 1824 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 372:1
>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of 2224 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 204:1
>   + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of 3800 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]:  => 476:1

parisc-allmodconfig

>   + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2240 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]:  => 1311:1
>   + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2304 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]:  => 1311:1
>   + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2320 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]:  => 1311:1

powerpc-allmodconfig

>   + /kisskb/src/include/linux/compiler_types.h: error: call to '__compiletime_assert_366' declared with attribute error: FIELD_PREP: value too large for the field:  => 335:38

    in drivers/pinctrl/pinctrl-apple-gpio.c

arm64-allmodconfig (gcc8)

>   + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter):  => 263:25, 277:17

    in lib/test_kasan.c

s390-all{mod,yes}config
arm64-allmodconfig (gcc11)

>   + error: modpost: "mips_cm_is64" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>   + error: modpost: "mips_cm_lock_other" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>   + error: modpost: "mips_cm_unlock_other" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>   + error: modpost: "mips_cpc_base" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A
>   + error: modpost: "mips_gcr_base" [drivers/pci/controller/pcie-mt7621.ko] undefined!:  => N/A

mips-allmodconfig

> 3 warning regressions:
>   + <stdin>: warning: #warning syscall futex_waitv not implemented [-Wcpp]:  => 1559:2

powerpc, m68k, mips, s390, parisc (and probably more)

>   + arch/m68k/configs/multi_defconfig: warning: symbol value 'm' invalid for MCTP:  => 322
>   + arch/m68k/configs/sun3_defconfig: warning: symbol value 'm' invalid for MCTP:  => 295

Yeah, that happens when symbols are changed from tristate to bool...
Will be fixed in 5.17-rc1, with the next defconfig refresh.

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdUCsyUxaEf1Lz7%2BjMnur4ECwK%2BJoXQqmOCkRKqXdb1hTQ%40mail.gmail.com.
