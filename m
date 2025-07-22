Return-Path: <kasan-dev+bncBDAOJ6534YNBB5F273BQMGQEWNELGLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CA51B0DD9C
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 16:17:26 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-451d30992bcsf43677545e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 07:17:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753193845; cv=pass;
        d=google.com; s=arc-20240605;
        b=K8GBeRQ6I9Z9lCmX4VXDS+150U5gyl6Lgz3UtG2croOo89jkgFNfr5Yn3ry2qu/6F/
         B6x1QIfYwlwxP5qSFY/zDl1hVs2AJ+Vcuwd9+AkSby7ZOp3zbUECCX7eOwNSNyfhEr2G
         vaURMx3aSy5qlwppkYJy7QD+w2F0ipn1eFdyIbZQ3REVb/An3KRt+VvpTzz3Ln1Rz8GF
         ekAsLqiEfD+VfWD6Izhszxm12NsBYAlTqtGO2/MTFpeXOprWC9CGGWQ49tZRiYGbb2mi
         mZ6cwi+2BM4AeG6+JpE0P2aUCXYxmRqPKzd9e9aXDRH725rNNuH2VHu9g4JareTf77cu
         cZCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zo+IubUxLJn9lDALX9A92GZ1OeP5beCmyWMzdxudI9A=;
        fh=Um1D1EttTVwGzMh16KwV20LTqQl5Ky9DtovjHjsiWRI=;
        b=g/3yJPXXf6VKTSmDSpNAGtl+YTFFnHxNURQSS8e00IWBoGSi7xtCI4O1yZrhtdoids
         7DvEZgRkB5kGu0jH2oWP2fz8H526eZ/2ChEYBhoMxMAhz2l0cGAtEoF/uyU1YG+UNsns
         nNwoFI64yIHbQERGkgvErGjw+TQA+3lnhGzkvFX+/lc0BABBps9Z2ViTpn7sc9wwTzM1
         4jxmnWRq57VS08E/HnotJn7B51bBNFSQL4JrY/moZ0iYS8oKykh89yES5cwisO+oQD1c
         bfQQMLbooOfFR1Mcr/bfeSa53sMedg6Yl/uIjSwTf/zwojZV7hPgZslCtI4sJYmLR4uH
         z6ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cYu15yF2;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753193845; x=1753798645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zo+IubUxLJn9lDALX9A92GZ1OeP5beCmyWMzdxudI9A=;
        b=ba6y3R3gmnLv9HbVbXjKQRr5WuseSsIlKMhI1VjAqDjKSWC+FVSzNyHhrhZDdBvLMm
         So3aQKiMaI/jtgXdmsZFa+G+MfyXorqwhS1murys6wlrNPI4sk+mIEEjKI/j92uqD3Y4
         UCZlTHWSS1d+K0NoFlAroV2xt1G0zpaArZPNBEKxrb/tNy7vPi0onuXVIuY2MWfxBxim
         ff93pfo0o4nQX2+KdyHt6Dw0404o7pvkeqfReIKr8VD7/JwFc3ZSXcty5wzrvh9HzmIe
         IrK8DIGev4NLY5Bq93fjqNI0s25KP6vLuRuqLtBsmmMpD37uWbDN3PKwXhsteQbrrWl5
         ohwA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753193845; x=1753798645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zo+IubUxLJn9lDALX9A92GZ1OeP5beCmyWMzdxudI9A=;
        b=a8i3iaKqypeHGox3f5zQUPK0V6pS+bFfmFJlp6UaEbJcilcho7ntPLemLCkXmBNQNq
         sCnG/pmbINKt/547ccMQ66B2DsgbjVdN3v3Ar4KXHxKFIGyoUz1cmwHqpodj5do2ZM+9
         q+RBrSEzAh4ZJZH/4wDoeAq24cIVdyb6ApltQocuIVai0yBX/Wl1ycaVOjhzAPOM6sZ2
         z1OkbiAcuiXcJhlv/5jfMXM3HVmtSu8pdfvYvjLDfMwyvgX5HKJFtKFVTH/0KF+NAv6f
         H7hDAvYD7AqnzB97H4HhQXA06BgqR5sUC4h5X74n5V90aF+eCPkhKagF45umDv+1WMcd
         FNrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753193845; x=1753798645;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zo+IubUxLJn9lDALX9A92GZ1OeP5beCmyWMzdxudI9A=;
        b=MdzEt4lxlZ7C94XcPvNa50WuC/pxSjwlDliJHbx+DWQf7UAPlReaDR3F/266sQ6ItB
         /69868+1h5UAbes7UqcEVkFCM/r+kCW9rn3THgBE3VIwp2th94KyoEo4kvIxYE0FTlNb
         jh3uFM72KmwFwVLop0dvftgDcv+jIvExFp/MjY/rVNKjrr1MdWdyVVJ78KM717IJ+SYF
         DGhiNxqxQvyQsSNAdP1RotIbLCL1a7Ja/XH1kcrpQvvn78GZhTbA/IBEw+1v6uKur8h+
         liZxyMBSZLxtnquOqK0l6bN7P4s/SsfO/b8pxdnxKHAprEXfCLwocznbXjlHDcL7bWY7
         7X2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbXMOno/ZSdi8Il9Makq5RLViuBPwSR5auCzeky/D68Ox1iDSUyJ9q1zi6CGVCIhUZyZRHhA==@lfdr.de
X-Gm-Message-State: AOJu0YynI/ZwrZ+0GgU5fZ/EB3jRzhmZRjXgTpIIGFLoxheN1fCh5c9B
	J7F1oryoCfdC+Bz2YMrx1FN8h8lcDru7zWluMi0SDlXMIdiw+nU2u+Vy
X-Google-Smtp-Source: AGHT+IFgssg9BuSpXHYfytGWMB5uPxlOJ2xpxro2pehLogT2Psj62sWtqw67T55jx2okaEYJtB+IfQ==
X-Received: by 2002:a05:600c:1e0f:b0:456:18ca:68fd with SMTP id 5b1f17b1804b1-45632ea481fmr262344465e9.10.1753193845141;
        Tue, 22 Jul 2025 07:17:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcFe9EIQzGdQMTV+a/7aPOtzVxjNsO+8uIBToR+e2PnMQ==
Received: by 2002:a05:600c:3b8e:b0:456:11a9:85d3 with SMTP id
 5b1f17b1804b1-45633fe3d3bls31734055e9.0.-pod-prod-09-eu; Tue, 22 Jul 2025
 07:17:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjOxMzWMldAnh7kaGt4PTaODTctPnE9i3KDGoZddFVJxYK7+hEdrdALKnxWb4IBD53QGrtWlfj/ao=@googlegroups.com
X-Received: by 2002:a05:600c:19cb:b0:43c:ee3f:2c3 with SMTP id 5b1f17b1804b1-4562e37a0ecmr191933345e9.7.1753193842510;
        Tue, 22 Jul 2025 07:17:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753193842; cv=none;
        d=google.com; s=arc-20240605;
        b=GJzNa24Ya7TNwCg58RHx8AeLJ57GqlafnXjY1A0rPA0CckqS6nO3YhBK1Tyof6U8n4
         xO1LPeb89U75oiU/+O1Tww7Gaj2qhAtnTnvvsAR8A0I1GbwGjjF/apRZyG75hapHLcUA
         StGGiLH9hDNB9001GdjK/PiinzEzUZW0wwfih8LhPn1vHpm2C28jwTSHTvok32JGwxb6
         /WrNu7kJOfaUW2F/OQzJFFJECPvygqTUnTYA/kh0soPj71ahGBEncqRolbYnb9Os0M/q
         c6DdPX8tNoAovTt3c7fcuqduf5s2ir017B8/4Q2Kq3Oc02xYdbXILRt5QXPF6Ndu5OM4
         W9fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GboL0eWXtD3fDsEKzgJ1xepA1JQohVF9co6pstDgRM8=;
        fh=A+lgdEk2SUkOZy1jNP+Nq+Ynl26BQjubWMJhhNQ8o/o=;
        b=ZFlwVHPsxGOLTc4rpVnlbH51u85giBuWnNBI4Rqhf/OOprHEX7rzPLQiNafSLfY2V4
         ybH0JHfYJQ4qNSbjbujrUUKZ7/tqLh8KM2zIXklMkG96FdT89JkhWdNJDawRYK+tNZxi
         dWb0tMppp05N0YWGlIsGkHASdC7bBEAqs53dbu+0Urcf7uJk8jMoYIg9da11MLzPgnGT
         0ew7WfcRRB4gBlcIW0mMXBZgrQ1TqB4kMQi6uzoOa2nTBTfgU24OFpv3mNOnFMqxapqn
         KqX/Le98kfVUfVzBRkdod4RK+0ZHWMUNtx6QWNkh7sqlV2kvwy9kq3RPcJcdSzNeklQ5
         JBxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cYu15yF2;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45863a20ae7si559565e9.1.2025.07.22.07.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jul 2025 07:17:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-32f2947ab0bso43520921fa.3
        for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 07:17:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpEEdP3465SyFgFCECvp84q3bdFxPtWRgV6sWFy9mGpXwil0Fy+fSJK620uU43b2+/SDjJ+d4BXak=@googlegroups.com
X-Gm-Gg: ASbGncsUcVf72p/dSsxQ9tjNFuNYsUioZ+A5+nmoDA8s2xEjAGzSpULhbTrO47bCsm4
	g54/1afeY6fYHxMz/C9StktsBiTAvQH+TiIx/2uFa4nUwzL1rI6el3nS0EwppE0QMxTIS1lQzpu
	8tXEIkgXImZtQEY9mEmpKrEFDDTQJK0RQZO9zeZ/uX9ZrQBkQ0OhJEe0lMG4F/8nTzZCrw17r5Z
	qwBm5A=
X-Received: by 2002:a05:651c:110d:b0:32b:75f0:cfa4 with SMTP id
 38308e7fff4ca-3308f5c95f9mr70998461fa.25.1753193841372; Tue, 22 Jul 2025
 07:17:21 -0700 (PDT)
MIME-Version: 1.0
References: <20250717142732.292822-1-snovitoll@gmail.com> <20250717142732.292822-9-snovitoll@gmail.com>
 <85de2e1f-a787-4862-87e4-2681e749cef0@gmail.com>
In-Reply-To: <85de2e1f-a787-4862-87e4-2681e749cef0@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 22 Jul 2025 19:17:03 +0500
X-Gm-Features: Ac12FXzF_nEInn7KovIF1rCbPeOEkryRpoS2Hx7q1NkLYIXq7eXxsmx3CUCidIg
Message-ID: <CACzwLxiD98BLmEmPhkJQgv297bP_7qw+Vm_icFhTiDYN7WvLjw@mail.gmail.com>
Subject: Re: [PATCH v3 08/12] kasan/um: select ARCH_DEFER_KASAN and call kasan_init_generic
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, akpm@linux-foundation.org, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cYu15yF2;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231
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

On Tue, Jul 22, 2025 at 4:00=E2=80=AFAM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
>
>
> On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
> > UserMode Linux needs deferred KASAN initialization as it has a custom
> > kasan_arch_is_ready() implementation that tracks shadow memory readines=
s
> > via the kasan_um_is_ready flag.
> >
> > Select ARCH_DEFER_KASAN to enable the unified static key mechanism
> > for runtime KASAN control. Call kasan_init_generic() which handles
> > Generic KASAN initialization and enables the static key.
> >
> > Delete the key kasan_um_is_ready in favor of the unified kasan_enabled(=
)
> > interface.
> >
> > Note that kasan_init_generic has __init macro, which is called by
> > kasan_init() which is not marked with __init in arch/um code.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > Changes in v3:
> > - Added CONFIG_ARCH_DEFER_KASAN selection for proper runtime control
> > ---
> >  arch/um/Kconfig             | 1 +
> >  arch/um/include/asm/kasan.h | 5 -----
> >  arch/um/kernel/mem.c        | 4 ++--
> >  3 files changed, 3 insertions(+), 7 deletions(-)
> >
> > diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> > index f08e8a7fac9..fd6d78bba52 100644
> > --- a/arch/um/Kconfig
> > +++ b/arch/um/Kconfig
> > @@ -8,6 +8,7 @@ config UML
> >       select ARCH_WANTS_DYNAMIC_TASK_STRUCT
> >       select ARCH_HAS_CPU_FINALIZE_INIT
> >       select ARCH_HAS_FORTIFY_SOURCE
> > +     select ARCH_DEFER_KASAN
> >       select ARCH_HAS_GCOV_PROFILE_ALL
> >       select ARCH_HAS_KCOV
> >       select ARCH_HAS_STRNCPY_FROM_USER
> > diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> > index f97bb1f7b85..81bcdc0f962 100644
> > --- a/arch/um/include/asm/kasan.h
> > +++ b/arch/um/include/asm/kasan.h
> > @@ -24,11 +24,6 @@
> >
> >  #ifdef CONFIG_KASAN
> >  void kasan_init(void);
> > -extern int kasan_um_is_ready;
> > -
> > -#ifdef CONFIG_STATIC_LINK
> > -#define kasan_arch_is_ready() (kasan_um_is_ready)
> > -#endif
> >  #else
> >  static inline void kasan_init(void) { }
> >  #endif /* CONFIG_KASAN */
> > diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> > index 76bec7de81b..058cb70e330 100644
> > --- a/arch/um/kernel/mem.c
> > +++ b/arch/um/kernel/mem.c
> > @@ -21,9 +21,9 @@
> >  #include <os.h>
> >  #include <um_malloc.h>
> >  #include <linux/sched/task.h>
> > +#include <linux/kasan.h>
> >
> >  #ifdef CONFIG_KASAN
> > -int kasan_um_is_ready;
> >  void kasan_init(void)
> >  {
> >       /*
> > @@ -32,7 +32,7 @@ void kasan_init(void)
> >        */
> >       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> >       init_task.kasan_depth =3D 0;
> > -     kasan_um_is_ready =3D true;
> > +     kasan_init_generic();
>
> I think this runs before jump_label_init(), and static keys shouldn't be =
switched before that.>  }

I got the warning in my local compilation and from kernel CI [1].

arch/um places kasan_init() in own `.kasan_init` section, while
kasan_init_generic() is called from __init.
Could you suggest a way how I can verify the functions call order?

I need to familiarize myself with how to run arch/um locally and try
to fix this warning.

[1] https://lore.kernel.org/all/CACzwLxicmky4CRdmABtN8m2cr2EpuMxLPqeF5Hk375=
cN2Kvu-Q@mail.gmail.com/

> >
> >  static void (*kasan_init_ptr)(void)
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxiD98BLmEmPhkJQgv297bP_7qw%2BVm_icFhTiDYN7WvLjw%40mail.gmail.com.
