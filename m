Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBX635KFAMGQEE6ZBODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D62694206A8
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 09:31:43 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x33-20020a0565123fa100b003fcfd99073dsf13503645lfa.6
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 00:31:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633332703; cv=pass;
        d=google.com; s=arc-20160816;
        b=SOuUcwOzp2mqfN7yLpImCVHLknlczMR9l44eL9lr1A/bU/vHuqvN1p5r7B4bDs6RP9
         k8BxA1PWuDprMthKZVNCML357WSYDVrwNUjSbKOgGRqcpfgZ/jjlTXVY4XSmwM+bduQa
         /pkwZqGMc37R/Df45K18UxzkwmANegWAyr+Soz45F08kY5Rza4Qjo1m7mL6sOBkaJwBb
         bZYPiQNwJhYOHkb80vT+7E2DEMOSnEaesBCWNi8l2RbS3IXLm/Iw5SGj1G7zYujJkIoJ
         bKDnP+3hU7wP4OjwpjMSAAqVlIFHB45Ku1ZS6v0PEQ/5u+icOFOurybRRnJXqJDN2asG
         lueg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=RqI3J+zE1o5lusBzSCZT8l5qURkMG32n+Mh4256x7KE=;
        b=Cdgrd1J5lG+sW1m5MdBHgqXkmiFVVhdHw1tyfMAsP7QrJ6GZKQkECXxTQR+jseOO/p
         sz3rzR+W4zuYzV7vjwTs951X//vQbWk9xbXJk52doDjOeVs9iXZVZ4ecXhE3XR+dNDmX
         1LXWT/U4Y/DW87uwi1s2X9ni/Par78lA7l+CGoAnrOTbFaepeD2aCAVb5T2VLdAKDOzx
         AsZ3YVRzyI2zyjkTK89M4AmGH1tD06WbK/8k3uw1FCRR/C8U2IDHVsnWdXwAMbInYq07
         OZh5Nj0IAHnUkn2KVPkTfE/KydYURlvUfMoG/K1w2NG9bB6wpnwVKVhGCfhla0e0wmts
         nnpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=rzrp8eHo;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RqI3J+zE1o5lusBzSCZT8l5qURkMG32n+Mh4256x7KE=;
        b=Zr3V20H3/FRBlUKoPxIp0bnSHLv1VUn2Ku+IkQe+w99K2ERRwysyZKbs2BcayV8PSH
         +4ad9OdE8XWxYGFBiRoKYuwPSP/gx9Lh4s4vabUld9hz1WG7xWGXl2erbqtMl1trL/Ih
         +iF+/e8gzqUgw3Tl+pY2WdLC/pQ+zmFo33kBJ19RiZCmQOSKWxFDwA5lO4ojcyGDO9Gy
         DyZlS8iAbv8OJI5WLa3jTvKdYIndmOqLZjJbGupG42HoumGf0rw6eZsea2pthmmExjrt
         TQc5ITYeuQPpI42Elcb4+gdMEFh+BaWryQeqUUhDy2EwH3NNCKi2Gst9EqgEzZL2wXwU
         YxlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RqI3J+zE1o5lusBzSCZT8l5qURkMG32n+Mh4256x7KE=;
        b=8Iloh07dWCN9fk4J7jqm6jIxJvLY1RPqR8a/96EkhVUvq6r/u6aOHu/CxgpDTtukJd
         W0GWPasRA3D3b6e//DgzseaYJgpRSqVSyIt9/wYhZna3D4LqmDfZQVlVVC72YeZfJYFb
         seciaxnsthH4PbAcmZelNbjMdkDUbX/Y5IuifB4Af94jnCc8cZvTuSKcQz6G3PTAhxai
         FLK3iw8obdQY+YMcu6SHlGhdFVOtKNzLYU/TfSz9qvhz2PZgQ4yKcFWxR1gZpUde6+JI
         Tz/2kxCHO/v8tKbqVIwEejLriaH2NWaPXBj0c9Ky7UcIYlXOvifVsW93j6UG7dDrH0W2
         QlXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LOp+ruC8eAtZYq10gj9QuWeU4WWmnwBpC1PauUnpXzOMk0a/Q
	XTVcta8kOIJiQGm2h3BxjUY=
X-Google-Smtp-Source: ABdhPJzogg7RmsmEPG2+41/Ud0vDw0IJQdyBSEezLO7WWowqjWyqLDwEdcKf9iAto+LtcPzIhBVhdg==
X-Received: by 2002:a05:651c:4d2:: with SMTP id e18mr14435936lji.432.1633332703372;
        Mon, 04 Oct 2021 00:31:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:240d:: with SMTP id k13ls2883924ljk.3.gmail; Mon, 04 Oct
 2021 00:31:42 -0700 (PDT)
X-Received: by 2002:a2e:99d3:: with SMTP id l19mr14137562ljj.184.1633332702359;
        Mon, 04 Oct 2021 00:31:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633332702; cv=none;
        d=google.com; s=arc-20160816;
        b=kZbvevowMdyf8r4aK23Cm4Da6fo4CbAOPO4ystioJH2izI0aU0o65Nr1dTrLm1Kan+
         +oWZV4LJLHM1bfKql36Jqm9Jc+VrimHAaZh3ZD23/gTLhxN/mscAmVllw+/zgYRKHTuT
         dMZvX74KMpQ1V4kBLFLsBKZAYznQCKf+2m+CWCjguCE4mYfEn1U5cHMtdxwm5uv2hbpX
         ytiFAu55KT0IrFqOdItn1j1uvwB19dQDv1cJQp2DspyQnbQL4wkndkAmPXUPk6qdk67g
         tebvOVX1Ehwg/nyXgu66HsGhQU2JDLeefxBv+t0AEMTX9XgKt5MqQdqJhKjI4qnUPaNX
         K7GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yMz7a2U4h7tYNWu8HY/sX3yR4RwoKAQESOaigGzONNc=;
        b=GNk3v9y0fK5mtPx0qVwRuQWNzlkZk/av61uvLZdcqfCVylsOVZ06PzweFJAk4CjVRz
         ofQt64wGxTpRsmXe3qe+XqeegsMtXua5beM28aCRGX8Udzgb+ihp01f1SswH8GCxfXAZ
         MdWWiDucZXcaLTfd+Su0eca2nRDCzBXneb0DHWoVGDor8477NkH0I9A35dBRNUfxnpy6
         0nlNLPnzlPEWAgUKe/+kjZ5aOsAHVtFVnRdq/3Rz2xdVVgazAd/4mSwAKilBtJoWnzsy
         MNf1tT9E91iS13mOs+0CQ6lj66XDCYi0UrIhTPPA/Ltadzc93df6hdDRtr57nwOq+D9V
         a9uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=rzrp8eHo;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id a3si886371lji.6.2021.10.04.00.31.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Oct 2021 00:31:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 2F61240294
	for <kasan-dev@googlegroups.com>; Mon,  4 Oct 2021 07:31:41 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id 1-20020a508741000000b003da559ba1eeso16348848edv.13
        for <kasan-dev@googlegroups.com>; Mon, 04 Oct 2021 00:31:41 -0700 (PDT)
X-Received: by 2002:a17:906:ed1:: with SMTP id u17mr16035048eji.304.1633332699388;
        Mon, 04 Oct 2021 00:31:39 -0700 (PDT)
X-Received: by 2002:a17:906:ed1:: with SMTP id u17mr16035032eji.304.1633332699195;
 Mon, 04 Oct 2021 00:31:39 -0700 (PDT)
MIME-Version: 1.0
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
 <20210929145113.1935778-5-alexandre.ghiti@canonical.com> <748a2c58-4d69-6457-0aa5-89797cb45a5c@sholland.org>
In-Reply-To: <748a2c58-4d69-6457-0aa5-89797cb45a5c@sholland.org>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Mon, 4 Oct 2021 09:31:26 +0200
Message-ID: <CA+zEjCv-2ONyXykRLP2dabELimYbbCmREP5v6DfeV5zk5T+zRg@mail.gmail.com>
Subject: Re: [PATCH v2 04/10] riscv: Implement sv48 support
To: Samuel Holland <samuel@sholland.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@wdc.com>, 
	Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>, 
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, 
	Mayuresh Chitale <mchitale@ventanamicro.com>, linux-doc@vger.kernel.org, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=rzrp8eHo;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Mon, Oct 4, 2021 at 3:34 AM Samuel Holland <samuel@sholland.org> wrote:
>
> On 9/29/21 9:51 AM, Alexandre Ghiti wrote:
> > By adding a new 4th level of page table, give the possibility to 64bit
> > kernel to address 2^48 bytes of virtual address: in practice, that offers
> > 128TB of virtual address space to userspace and allows up to 64TB of
> > physical memory.
> >
> > If the underlying hardware does not support sv48, we will automatically
> > fallback to a standard 3-level page table by folding the new PUD level into
> > PGDIR level. In order to detect HW capabilities at runtime, we
> > use SATP feature that ignores writes with an unsupported mode.
> >
> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > ---
> >  arch/riscv/Kconfig                      |   4 +-
> >  arch/riscv/include/asm/csr.h            |   3 +-
> >  arch/riscv/include/asm/fixmap.h         |   1 +
> >  arch/riscv/include/asm/kasan.h          |   2 +-
> >  arch/riscv/include/asm/page.h           |  10 +
> >  arch/riscv/include/asm/pgalloc.h        |  40 ++++
> >  arch/riscv/include/asm/pgtable-64.h     | 108 ++++++++++-
> >  arch/riscv/include/asm/pgtable.h        |  13 +-
> >  arch/riscv/kernel/head.S                |   3 +-
> >  arch/riscv/mm/context.c                 |   4 +-
> >  arch/riscv/mm/init.c                    | 237 ++++++++++++++++++++----
> >  arch/riscv/mm/kasan_init.c              |  91 +++++++--
> >  drivers/firmware/efi/libstub/efi-stub.c |   2 +
> >  13 files changed, 453 insertions(+), 65 deletions(-)
> >
> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> > index 13e9c4298fbc..69c5533955ed 100644
> > --- a/arch/riscv/Kconfig
> > +++ b/arch/riscv/Kconfig
> > @@ -149,7 +149,7 @@ config PAGE_OFFSET
> >       hex
> >       default 0xC0000000 if 32BIT
> >       default 0x80000000 if 64BIT && !MMU
> > -     default 0xffffffe000000000 if 64BIT
> > +     default 0xffffc00000000000 if 64BIT
> >
> >  config ARCH_FLATMEM_ENABLE
> >       def_bool !NUMA
> > @@ -197,7 +197,7 @@ config FIX_EARLYCON_MEM
> >
> >  config PGTABLE_LEVELS
> >       int
> > -     default 3 if 64BIT
> > +     default 4 if 64BIT
> >       default 2
> >
> >  config LOCKDEP_SUPPORT
> > diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
> > index 87ac65696871..3fdb971c7896 100644
> > --- a/arch/riscv/include/asm/csr.h
> > +++ b/arch/riscv/include/asm/csr.h
> > @@ -40,14 +40,13 @@
> >  #ifndef CONFIG_64BIT
> >  #define SATP_PPN     _AC(0x003FFFFF, UL)
> >  #define SATP_MODE_32 _AC(0x80000000, UL)
> > -#define SATP_MODE    SATP_MODE_32
> >  #define SATP_ASID_BITS       9
> >  #define SATP_ASID_SHIFT      22
> >  #define SATP_ASID_MASK       _AC(0x1FF, UL)
> >  #else
> >  #define SATP_PPN     _AC(0x00000FFFFFFFFFFF, UL)
> >  #define SATP_MODE_39 _AC(0x8000000000000000, UL)
> > -#define SATP_MODE    SATP_MODE_39
> > +#define SATP_MODE_48 _AC(0x9000000000000000, UL)
> >  #define SATP_ASID_BITS       16
> >  #define SATP_ASID_SHIFT      44
> >  #define SATP_ASID_MASK       _AC(0xFFFF, UL)
> > diff --git a/arch/riscv/include/asm/fixmap.h b/arch/riscv/include/asm/fixmap.h
> > index 54cbf07fb4e9..58a718573ad6 100644
> > --- a/arch/riscv/include/asm/fixmap.h
> > +++ b/arch/riscv/include/asm/fixmap.h
> > @@ -24,6 +24,7 @@ enum fixed_addresses {
> >       FIX_HOLE,
> >       FIX_PTE,
> >       FIX_PMD,
> > +     FIX_PUD,
> >       FIX_TEXT_POKE1,
> >       FIX_TEXT_POKE0,
> >       FIX_EARLYCON_MEM_BASE,
> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> > index a2b3d9cdbc86..1dcf5fa93aa0 100644
> > --- a/arch/riscv/include/asm/kasan.h
> > +++ b/arch/riscv/include/asm/kasan.h
> > @@ -27,7 +27,7 @@
> >   */
> >  #define KASAN_SHADOW_SCALE_SHIFT     3
> >
> > -#define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> > +#define KASAN_SHADOW_SIZE    (UL(1) << ((VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
>
> Does this change belong in patch 1, where you remove CONFIG_VA_BITS?

Indeed, I fixed KASAN in this version and wrongly rebased the changes.

Thanks!

Alex

>
> Regards,
> Samuel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCv-2ONyXykRLP2dabELimYbbCmREP5v6DfeV5zk5T%2BzRg%40mail.gmail.com.
