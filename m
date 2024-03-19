Return-Path: <kasan-dev+bncBC7OBJGL2MHBB76F42XQMGQEERULGYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1881E87FFB7
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 15:36:49 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2218da55d89sf6398818fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 07:36:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710859007; cv=pass;
        d=google.com; s=arc-20160816;
        b=kJcgykLlGYzZ3J0pPAO/WgFl6nhv08soLEjk40JVGf2MUjCEH0ilWfKXBEXYafXnCg
         GyGyNNpNFR+nDy22FoKMpK0iJghsxTG6NKzPj1m7daAatLcAkS7ZRNG1+QLP7wdlBqY/
         OpoZ6hJlUuz/cOO97P8iZY64mcA0O9JRvTLPwmR0xtG5jzjvYQEUfal4apixICVHBfkT
         GcIVqrUws9evGUak8upLaTWrDl16vXscV2P9ElxEYUBpV27t0Q0K03DFHAHDI3eg6jvn
         QX/MWEiKNismN8+RePMjniaj3k1jFocn42F/yfmCw4G3kI0QDkJ6G5Ud0ActfQghZVSn
         RMkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1z4xqaaRsqksj4qwrwoO3jOjd/2d+R4Toc9bPUYWpBk=;
        fh=gCZXOTbo+sjWye4H51z74Dx7kEwIQM0901h32aPZUuc=;
        b=mHvYGZmHnynoY7Xpa2IFJau9CAIcuT5AUTKtz3sAAbzF7JqZSh+YzFPQffLAI5KCxW
         mzH+9J+yULedRMS+Y/W1K3VaVyG60Yn3dUSxzb978eh5rVZ0dhSkcNsdrRh/8ZKdc5kK
         S7p/q7o2P/WBFpnt0ECsXFP+KpiXKZBYc2zGeHXp0J78qyOKUre9sVgKJ4tzwanURdVu
         CSHiO4nri/ypClodWEuaCDS+33jsKxK0y5pZwBAHQb6MBx51VycGqH7Z6OKL4OJu38Xj
         +YUrgMaZwZg3XMJSpPxEPfYJGhUcxlTBytri7XelZsTb4JEijIBhtGfSd7wcLQtiq/9m
         JMYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aIkDuV7g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710859007; x=1711463807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1z4xqaaRsqksj4qwrwoO3jOjd/2d+R4Toc9bPUYWpBk=;
        b=k6BrADwKLJdt/fxlKr36FZCkmNcI68YYCfe52EwS5KRa6r7oWo20hyEYS2Dl9Nvjuz
         roHSVGL3V1D7hAeYwNjWBtwzjQnDP3vY7QH0ndTw/aNgVeYBgAG6UfVG1jSQlsI3QCFe
         +TwBLFpeWjfV318MWFyKZqDfrTdnHz0Zqt+eZnB8WVwXqb25a/Rz8c8PKzfCFn9Eifb8
         bLuN3o1I4M1ZYA8MUNps8BNC6yCFhLOr2tKckMKd66NU2bv6whCd0fkS7wOVWQN+N/5o
         wA8hKkWnl75XgQL9s8UD9KoSs7XsQ4IfLXjng5k7stq22F/MJ1DIqKowkDhQbBkMHpWR
         Z47g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710859007; x=1711463807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1z4xqaaRsqksj4qwrwoO3jOjd/2d+R4Toc9bPUYWpBk=;
        b=jyE4irLGgl8/R7qX50X8egwQ0eeXaySaebChWlYRTFwyA2z5ewHG21pLEVEuR96SC9
         CpYPMRbpf++1hZjOou+k8EtQHLmGbsFGR/XH/c2MFOYAyGUWpiwXWh6QGeosONIkeAu6
         y1/JWkA22nOmZdxLG0lVRhyCY6NnarJMCjos6cN8L/4aQtc/6hVWr2jy3DC8gePhu6Ee
         nI3diTduJ6lWzPUsMk6+HdKa2fIVqcdEyAXAYRzI5+lMK76Y+27n+uwjgBwP0ceDD4G6
         LaoT6OQ8B2rVFm0BpT02zeEPaephb8OSVRHSNs/FizWRyflXRr2E1kqMGgaG3pDRaDqZ
         Z7xg==
X-Forwarded-Encrypted: i=2; AJvYcCV12Ok5OUsSAm4zyufHAp4bFu5Sile8uCEudhAKPT6K6J/CjZvJZYyEffw88ULPhpffs5B+iHmmKps9l+2I8CjNIEZn/hfaXA==
X-Gm-Message-State: AOJu0Yzrv6Z2rN8hkUf+z7XM8uHkVpkqIg5nY6j6r348bXSmT+zVGP+I
	NhuhrigD3HigljAasszf5sbX5KlCM0u37w/G5MtBHq4bj8lZb+Ih
X-Google-Smtp-Source: AGHT+IHwjA3Z2X/3utpNTYdBUwxk6gBsurQXtEtCgPQ/hyY34tqUbDvIRT8vJ016zPwURJf9AUTpBQ==
X-Received: by 2002:a05:6870:f107:b0:21f:d4d0:391f with SMTP id k7-20020a056870f10700b0021fd4d0391fmr14295681oac.15.1710859007528;
        Tue, 19 Mar 2024 07:36:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2889:b0:226:8c3:a45a with SMTP id
 gy9-20020a056870288900b0022608c3a45als824554oab.0.-pod-prod-06-us; Tue, 19
 Mar 2024 07:36:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU340aXvLRCOnW2HG3lTGD/YEb0gZrOfVUekUYau4XVrxXUxdP5raUBTTbThwgJcLsuFXZ2GvZI4XViCO1A92JhCWV3I8scEmqeHQ==
X-Received: by 2002:a05:6358:2619:b0:17b:80e2:a105 with SMTP id l25-20020a056358261900b0017b80e2a105mr9794579rwc.24.1710859006345;
        Tue, 19 Mar 2024 07:36:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710859006; cv=none;
        d=google.com; s=arc-20160816;
        b=qnmctoCM4ZHus47A0Ae8p8OjkLOa+PA1xDNs647NB/Ldh85k2HD9bgONyZbGhrOVIR
         jkqoFFq5JF0IRrn7SPEtGRle7RVZSQ/OjgNrTf9RH8zY8LJBFWWCeP5LLXDmafOEIgeG
         knXRlbxHdntEVwtnL2ehLWOsFNL7t8x28h8jxCruQscYdDgSw/5N7wnDYQxHrUk+ymXV
         6IhjOfmyhv1n2vQLC2mGk8YzvmpIaCwOEK6uWCWQsdNceE25x0zJ28y6OgDmC7yCjGoZ
         WBm6Pv/fWGL647YXi1zteGVUtj9FVfmKYlOXJdZebx5IHXm0/JgnJ5ac3yXhUSaAKNii
         CVBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V9OV+eW8DhxAtTBGJzPFvnkPOnt+nsV63i/AeBiJVZ4=;
        fh=SsGsU9ETElM5ISKM3hVEhdg9lzNsukx4rZfmtvq08Z4=;
        b=0YZJzjpV3i2r4ePwbDamnZ62jjnSEw7xxqAEf91iNKpbhuq2U8wAJQIZvyP6mCO1RN
         1sRBLu0SuH6bEZ4NX0+jmtGw0o8x4qlJhdR3873ZahZ1KwzR8KOSB8rP15GU3o2IHtKR
         ElcFGTqWDxNGT9H2DfRYwxNBbDJLGvKYv5q+08OTRRj+k59oqsW65+gOSp1n5I1Z8J8s
         5iq9v5vVDFvSXlRwF3K2UKW8DnoPSyS2eUUvRjHCodmhJhH+gwXbON2Cqi/T6+xMKT5p
         BD0TUOQRvKjpPmDN5YW+i7GYhe8miGPhrBJmm7vkS38n+94FUNLcf5og/nTZwBCxPsrm
         SnKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aIkDuV7g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x934.google.com (mail-ua1-x934.google.com. [2607:f8b0:4864:20::934])
        by gmr-mx.google.com with ESMTPS id x24-20020a056a00189800b006e6a8a85ee9si660296pfh.6.2024.03.19.07.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 07:36:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as permitted sender) client-ip=2607:f8b0:4864:20::934;
Received: by mail-ua1-x934.google.com with SMTP id a1e0cc1a2514c-7e046990b6aso1073733241.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 07:36:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFds5hADPvbcIulJzbbRG97mta+bO7sRiieii1OJoeFgJe+vUKNJwYBFtSbs/HcBWFFIwb8EeQldRf4S8Xn1A77B3/+QDSgzbtNQ==
X-Received: by 2002:a05:6122:469c:b0:4d3:3adc:b639 with SMTP id
 di28-20020a056122469c00b004d33adcb639mr12560750vkb.6.1710859005155; Tue, 19
 Mar 2024 07:36:45 -0700 (PDT)
MIME-Version: 1.0
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
 <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
 <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop> <67baae71-da4f-4eda-ace7-e4f61d2ced0c@paulmck-laptop>
 <CANpmjNOmpOCfaFyMUnMtc3TT=VuTpWC4c85FW_u4dobmtikHtQ@mail.gmail.com>
 <CANpmjNNLXR1kC8XAqFjEO3N0P3scRott8Z1OcW2yoKu5BEDaYQ@mail.gmail.com> <5e6fdf1d-e84c-463c-b47b-f42500930b28@paulmck-laptop>
In-Reply-To: <5e6fdf1d-e84c-463c-b47b-f42500930b28@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Mar 2024 15:36:07 +0100
Message-ID: <CANpmjNOjAvg1AKBUYGRQTn5vxjsWqGMfQxt_C8zP79vn7D+VNw@mail.gmail.com>
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in rcu_trc_cmpxchg_need_qs()
To: paulmck@kernel.org
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com, 
	glider@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aIkDuV7g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::934 as
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

On Tue, 19 Mar 2024 at 02:59, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Mar 18, 2024 at 04:43:38PM +0100, Marco Elver wrote:
> > On Mon, 18 Mar 2024 at 11:01, Marco Elver <elver@google.com> wrote:
> > >
> > > On Sun, 17 Mar 2024 at 22:55, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Fri, Mar 08, 2024 at 02:31:53PM -0800, Paul E. McKenney wrote:
> > > > > On Fri, Mar 08, 2024 at 11:02:28PM +0100, Marco Elver wrote:
> > > > > > On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > >
> > > > > > > Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
> > > > > >
> > > > > > Because not all architectures support 1-byte cmpxchg?
> > > > > > What prevents us from implementing it?
> > > > >
> > > > > Nothing that I know of, but I didn't want to put up with the KCSAN report
> > > > > in the interim.
> > > >
> > > > And here is a lightly tested patch to emulate one-byte and two-byte
> > > > cmpxchg() for architectures that do not support it.  This is just the
> > > > emulation, and would be followed up with patches to make the relevant
> > > > architectures make use of it.
> > > >
> > > > The one-byte emulation has been lightly tested on x86.
> > > >
> > > > Thoughts?
> > > >
> > > >                                                         Thanx, Paul
> > > >
> > > > ------------------------------------------------------------------------
> > > >
> > > > commit d72e54166b56d8b373676e1e92a426a07d53899a
> > > > Author: Paul E. McKenney <paulmck@kernel.org>
> > > > Date:   Sun Mar 17 14:44:38 2024 -0700
> > > >
> > > >     lib: Add one-byte and two-byte cmpxchg() emulation functions
> > > >
> > > >     Architectures are required to provide four-byte cmpxchg() and 64-bit
> > > >     architectures are additionally required to provide eight-byte cmpxchg().
> > > >     However, there are cases where one-byte and two-byte cmpxchg()
> > > >     would be extremely useful.  Therefore, provide cmpxchg_emu_u8() and
> > > >     cmpxchg_emu_u16() that emulated one-byte and two-byte cmpxchg() in terms
> > > >     of four-byte cmpxchg().
> > > >
> > > >     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > >     Cc: Marco Elver <elver@google.com>
> > > >     Cc: Andrew Morton <akpm@linux-foundation.org>
> > > >     Cc: Thomas Gleixner <tglx@linutronix.de>
> > > >     Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
> > > >     Cc: Douglas Anderson <dianders@chromium.org>
> > > >     Cc: Petr Mladek <pmladek@suse.com>
> > > >     Cc: <linux-arch@vger.kernel.org>
> > > >
> > > > diff --git a/arch/Kconfig b/arch/Kconfig
> > > > index 154f994547632..eef11e9918ec7 100644
> > > > --- a/arch/Kconfig
> > > > +++ b/arch/Kconfig
> > > > @@ -1506,4 +1506,7 @@ config FUNCTION_ALIGNMENT
> > > >         default 4 if FUNCTION_ALIGNMENT_4B
> > > >         default 0
> > > >
> > > > +config ARCH_NEED_CMPXCHG_1_2_EMU
> > > > +       bool
> > > > +
> > > >  endmenu
> > > > diff --git a/include/linux/cmpxchg-emu.h b/include/linux/cmpxchg-emu.h
> > > > new file mode 100644
> > > > index 0000000000000..fee8171fa05eb
> > > > --- /dev/null
> > > > +++ b/include/linux/cmpxchg-emu.h
> > > > @@ -0,0 +1,16 @@
> > > > +/* SPDX-License-Identifier: GPL-2.0+ */
> > > > +/*
> > > > + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> > > > + * lacking direct support for these sizes.  These are implemented in terms
> > > > + * of 4-byte cmpxchg operations.
> > > > + *
> > > > + * Copyright (C) 2024 Paul E. McKenney.
> > > > + */
> > > > +
> > > > +#ifndef __LINUX_CMPXCHG_EMU_H
> > > > +#define __LINUX_CMPXCHG_EMU_H
> > > > +
> > > > +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new);
> > > > +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new);
> > > > +
> > > > +#endif /* __LINUX_CMPXCHG_EMU_H */
> > > > diff --git a/lib/Makefile b/lib/Makefile
> > > > index 6b09731d8e619..fecd7b8c09cbd 100644
> > > > --- a/lib/Makefile
> > > > +++ b/lib/Makefile
> > > > @@ -238,6 +238,7 @@ obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
> > > >  lib-$(CONFIG_GENERIC_BUG) += bug.o
> > > >
> > > >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> > > > +obj-$(CONFIG_ARCH_NEED_CMPXCHG_1_2_EMU) += cmpxchg-emu.o
> > >
> > > Since you add instrumentation explicitly, we need to suppress
> > > instrumentation somehow. For the whole file this can be done with:
> > >
> > > KCSAN_SANITIZE_cmpxchg-emu.o := n
> >
> > Hrm, I recall this doesn't actually work as-is because it also
> > disables instrument_read_write() instrumentation.
> >
> > So I think the most reliable would be to use data_race() after all.
> > It'll be a bit slower because of double-instrumenting, but I think
> > that's not a major concern with an instrumented build anyway.
>
> And I have added data_race(), thank you!
>
> > > Note, since you use cmpxchg, which pulls in its own
> > > instrument_read_write(), we can't use a function attribute (like
> > > __no_kcsan) if the whole-file no-instrumentation seems like overkill.
> > > Alternatively the cmpxchg could be wrapped into a data_race() (like
> > > your original RCU use case was doing).
> > >
> > > But I think "KCSAN_SANITIZE_cmpxchg-emu.o := n" would be my preferred way.
> > >
> > > With the explicit "instrument_read_write()" also note that this would
> > > do double-instrumentation with other sanitizers (KASAN, KMSAN). But I
> > > think we actually want to instrument the whole real access with those
> > > tools - would it be bad if we accessed some memory out-of-bounds, but
> > > that memory isn't actually used? I don't have a clear answer to that.
> > >
> > > Also, it might be useful to have an alignment check somewhere, because
> > > otherwise we end up with split atomic accesses (or whatever other bad
> > > thing the given arch does if that happens).
>
> Excellent point, added.
>
> I also fixed an embarrassing pointer-arithmetic bug which the act of
> coding the alignment check uncovered, so two for one!  ;-)
>
> Please see below for a patch to the patched code.

This looks very reasonable to me.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > > Thanks,
> > > -- Marco
> > >
> > > >  obj-$(CONFIG_DYNAMIC_DEBUG_CORE) += dynamic_debug.o
> > > >  #ensure exported functions have prototypes
> > > > diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
> > > > new file mode 100644
> > > > index 0000000000000..508b55484c2b6
> > > > --- /dev/null
> > > > +++ b/lib/cmpxchg-emu.c
> > > > @@ -0,0 +1,68 @@
> > > > +/* SPDX-License-Identifier: GPL-2.0+ */
> > > > +/*
> > > > + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> > > > + * lacking direct support for these sizes.  These are implemented in terms
> > > > + * of 4-byte cmpxchg operations.
> > > > + *
> > > > + * Copyright (C) 2024 Paul E. McKenney.
> > > > + */
> > > > +
> > > > +#include <linux/types.h>
> > > > +#include <linux/export.h>
> > > > +#include <linux/instrumented.h>
> > > > +#include <linux/atomic.h>
> > > > +#include <asm-generic/rwonce.h>
> > > > +
> > > > +union u8_32 {
> > > > +       u8 b[4];
> > > > +       u32 w;
> > > > +};
> > > > +
> > > > +/* Emulate one-byte cmpxchg() in terms of 4-byte cmpxchg. */
> > > > +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
> > > > +{
> > > > +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
> > > > +       int i = ((uintptr_t)p) & 0x3;
> > > > +       union u8_32 old32;
> > > > +       union u8_32 new32;
> > > > +       u32 ret;
> > > > +
> > > > +       old32.w = READ_ONCE(*p32);
> > > > +       do {
> > > > +               if (old32.b[i] != old)
> > > > +                       return old32.b[i];
> > > > +               new32.w = old32.w;
> > > > +               new32.b[i] = new;
> > > > +               instrument_atomic_read_write(p, 1);
> > > > +               ret = cmpxchg(p32, old32.w, new32.w);
> > > > +       } while (ret != old32.w);
> > > > +       return old;
> > > > +}
> > > > +EXPORT_SYMBOL_GPL(cmpxchg_emu_u8);
> > > > +
> > > > +union u16_32 {
> > > > +       u16 h[2];
> > > > +       u32 w;
> > > > +};
> > > > +
> > > > +/* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
> > > > +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
> > > > +{
> > > > +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
> > > > +       int i = ((uintptr_t)p) & 0x1;
> > > > +       union u16_32 old32;
> > > > +       union u16_32 new32;
> > > > +       u32 ret;
> > > > +
> > > > +       old32.w = READ_ONCE(*p32);
> > > > +       do {
> > > > +               if (old32.h[i] != old)
> > > > +                       return old32.h[i];
> > > > +               new32.w = old32.w;
> > > > +               new32.h[i] = new;
> > > > +               instrument_atomic_read_write(p, 2);
> > > > +               ret = cmpxchg(p32, old32.w, new32.w);
> > > > +       } while (ret != old32.w);
> > > > +       return old;
> > > > +}
> > > > +EXPORT_SYMBOL_GPL(cmpxchg_emu_u16);
>
> diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
> index 508b55484c2b6..b904f954dd4fc 100644
> --- a/lib/cmpxchg-emu.c
> +++ b/lib/cmpxchg-emu.c
> @@ -11,6 +11,8 @@
>  #include <linux/export.h>
>  #include <linux/instrumented.h>
>  #include <linux/atomic.h>
> +#include <linux/panic.h>
> +#include <linux/bug.h>
>  #include <asm-generic/rwonce.h>
>
>  union u8_32 {
> @@ -34,7 +36,7 @@ uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
>                 new32.w = old32.w;
>                 new32.b[i] = new;
>                 instrument_atomic_read_write(p, 1);
> -               ret = cmpxchg(p32, old32.w, new32.w);
> +               ret = data_race(cmpxchg(p32, old32.w, new32.w));
>         } while (ret != old32.w);
>         return old;
>  }
> @@ -48,12 +50,13 @@ union u16_32 {
>  /* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
>  uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
>  {
> -       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
> -       int i = ((uintptr_t)p) & 0x1;
> +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
> +       int i = (((uintptr_t)p) & 0x2) / 2;
>         union u16_32 old32;
>         union u16_32 new32;
>         u32 ret;
>
> +       WARN_ON_ONCE(((uintptr_t)p) & 0x1);
>         old32.w = READ_ONCE(*p32);
>         do {
>                 if (old32.h[i] != old)
> @@ -61,7 +64,7 @@ uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
>                 new32.w = old32.w;
>                 new32.h[i] = new;
>                 instrument_atomic_read_write(p, 2);
> -               ret = cmpxchg(p32, old32.w, new32.w);
> +               ret = data_race(cmpxchg(p32, old32.w, new32.w));
>         } while (ret != old32.w);
>         return old;
>  }
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e6fdf1d-e84c-463c-b47b-f42500930b28%40paulmck-laptop.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOjAvg1AKBUYGRQTn5vxjsWqGMfQxt_C8zP79vn7D%2BVNw%40mail.gmail.com.
