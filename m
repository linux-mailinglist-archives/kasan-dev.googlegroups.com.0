Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBVC4CXQMGQEXWSWXXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E197487E695
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 11:01:43 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5a0acbbca3bsf3729335eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 03:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710756102; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vvj606nUxKCKSEzdMwMk/P6j/TJw/AFEwRgVTIBdLtZNlc9l0E6yxmnsjtHSEznzlD
         j18DE9wx75t9VmAVHiF7mL/1E04RPobHwtYawvjXTmXiBfWGp1CV2tYLXhtWHMKddLcH
         CwfOAYm0V/gRZfRXjswluA55Hv/5EdgbUkHVesSQaancuqlmzybG4ELJu2+baii8pl8c
         Xad0Nw5C1P+E61VYwC421mZtEf0KObIRy2r+NMd8XW87a/VF0PQkulDUO43/ENJoHHe8
         /HxKhNTb4T8p7XX7nrJPeq1R2PdqQ3dw4Y1kMFgREdkajcftAPr4STJNN+r3AFALq+/M
         XjXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yPSChnx7hk+3TNJRZFK386cbw9OOH+rr8WVya9e4ycw=;
        fh=e8chXOo4EhU1vIV2QfzXjd1nmSbLTiIQHFWVxBX9tYI=;
        b=phZKiBxWhHIpmgnWm8uEoZ+1kQyd13gR10BnMHcvBjEuC1zuwyZwhh/V/fLW+1Jx47
         Cyc+4szVQGewnCvIq39vyBIkujNpHDcMguW6yQjyMZIqkklnGZwqp47j0dPtOXUI2scE
         okbXjeVdT4R+8ujCksX4oWyTBFM8q6w89ZsyDMCYK8LUHZ0aAvKt7vSXUmMphXkaKM/G
         5lCq7vrcfSCtnGpjf1fWdFFq7wt+9o1ZEJYoobUL7cuUSqNRDpv0WWY6hFCeFzE7ca/t
         G7Ax1X1UCqmqeff2BM1ZAB3h+qjb6WMm4w0owD0n9/JzzT7iHrGPNKtY570w7jRnqahR
         ogHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uUgIh2pZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710756102; x=1711360902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yPSChnx7hk+3TNJRZFK386cbw9OOH+rr8WVya9e4ycw=;
        b=LdADrRJJfM2rwArqtIMUxRJoJMI+ns1Bm+sFz/NNhp5ZDAu8jeB3b4rAL7+jFibR33
         6bwUa0/JVpUvaRlZIleUUaf4xKS7dCjy01n9CW1rzez+jLY8tNC+AUxLroDdCR4KmZsx
         lpaUW0gUT/9fhgT4H31ngJHWdfHYWyYgSKqXcbYCaYYGfEdw+9g2Yy1IuVYJSceBmH85
         zT0ugqjzqLm6SOIYUAtAVHZ2vm0JT1YVI2SSh8962P9boja220e4f58Njv1icCliXTnX
         Gl9A2TnZxcYIUPlQvO4/m3bQHsn9dV3xGusCF3AR93O5t8WiAkY79Mx3VJPXbnn1Npum
         DmUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710756102; x=1711360902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yPSChnx7hk+3TNJRZFK386cbw9OOH+rr8WVya9e4ycw=;
        b=iAZNQy/SL0/UWWTcwwqy6F+ML51yRyApr49p5WcoFgFADphwhQbukhqJr5fAEPOF+z
         0P977JFJRXfZvAL2k6TSC8NElL635oDUTLHhfsMTzHytgtG4vGedFxLRt2cmSrbyNb8Y
         O50l3rJ6k79yQXkwE8ShlA1AupxC4mGirxv3nTcIU9jkR25gmrgPvDCfOivu3660JSRD
         WMG+41SZgNQ8O06/+fipPT1yMmolZysgsX6najs38+Yep8AUXOdcdHPn8e9LQQ142j/j
         faI83rEiOJLPhBiJfNVgerybEwIkdj6jyIg2mUW9agaIEnLZ5Hr0pobFh1KsxlSLDWks
         cQnA==
X-Forwarded-Encrypted: i=2; AJvYcCUqh7SIHZpnQCa5jELtiV3AoFrPRIh/EvdO9kB6+brDwLwgX1Ean0PC+EGmP5s4i2o9hr0qF1bIp8De/iXYUoFZFMeodv15HQ==
X-Gm-Message-State: AOJu0YwDKTMyKuICUP+XbEkgydQf7jbcc5RDf2rzQ9IEW9ztGkN3ZBUc
	qO6LxBHDb06dGt2HO3QrUJ8man5agTRH86PbXAAxouCG7HG3M/U2
X-Google-Smtp-Source: AGHT+IFSod5lYeYpTZSgGYRIDycDApbo01Jblndup5auA6Xdzehe7t1FvFsVrxluDoQHD78jSUfoKA==
X-Received: by 2002:a05:6820:2290:b0:5a1:6cb9:d6f0 with SMTP id ck16-20020a056820229000b005a16cb9d6f0mr11534707oob.1.1710756102439;
        Mon, 18 Mar 2024 03:01:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1c04:b0:5a4:b452:a5aa with SMTP id
 cl4-20020a0568201c0400b005a4b452a5aals997515oob.2.-pod-prod-07-us; Mon, 18
 Mar 2024 03:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDX+UZs124Frb4Q57YBqoNN3aA3D3gGFu/bUBN+BWU1VXiKTDV0aCzItLaRGhvJVDT9pZYYlXXLguqMW/Z3Kub7YbI529T7To+lg==
X-Received: by 2002:a05:6808:1528:b0:3c3:801a:edfd with SMTP id u40-20020a056808152800b003c3801aedfdmr6366389oiw.41.1710756101357;
        Mon, 18 Mar 2024 03:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710756101; cv=none;
        d=google.com; s=arc-20160816;
        b=mI3qqGynRhh3q51wGc4l7rxmVLKYQQIDGNTauq9kBxi0o2Nsg7+ZmrT08KCEpMdvXY
         OjIIg1NYUqUQloifijG+VJQBZBL2/9vITyPwT6ZFvLUNQ7Hv2NkAiWzaOQjii+iOvFnu
         9mxbM6SIzmEMiLsjQ/ZvIe5GsgufeCZ9cZ+6liN9Jgdr4LUhech6oPsRDaF1zhiwNyM4
         lAdM2F2YR35rgWbOBcG69J5t31bVdncqt5SIoEh7Z9pbiediyXgie5VUROiPxsd8Z/q4
         /KKknUtFqjzdv+cTGM3WEgpJ59xDY3U2voqCI+ULx3wlsMBlIdoOtXo2Y7lQdvVbdfJ8
         i9jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NkcFjWrPC/z/IWM9mtgoQ+vuIaa1qEaVEiYJ1GABHoE=;
        fh=EDAE4R3SukCdqctY6HQ0wASzr3pFdCrYqclzy7Bk5NU=;
        b=GIqOyQLqg/8Pc6xzbsSnqI+gC3ue5at51QGMwH2Ubu2yFcJXmt8rmxg+1vxCe0jSNT
         RgAT6XAIIUAJAFKkRnN4IZDNBDiR0XO+tK6+pJSNmmpZgwL8hsCy+zgOEMl9VgIO2zpI
         GGJKBXIm0MNS+rtbypBFV8H9mVv9iq79msRHMsA3V7nHWrrFT9v2kK0g2WNRi7dshxD2
         6aNOQG2i3EYnwD3lWSDQK14Wg6rlFMlBYDWxSsvqDOBXomcjRkQPN1Vt6DJWyn8vJUtn
         48W1En45q3sYSj2FI7KcOo01rg5yE0TsU24j0uYI4aDrkd1kV97sqlw99/8TlTQQ/I5E
         rCMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uUgIh2pZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id i3-20020a544083000000b003c3818a1258si304043oii.0.2024.03.18.03.01.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Mar 2024 03:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id ada2fe7eead31-4766e56ccccso1088836137.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Mar 2024 03:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUMrsSqIKtg81K2fUJhImwdZDtYhL8gaL1TUS+sm0+udyxSMHELRX9e+hORzhdNdSKQ95ewSukwcvAKR+t5MI4cHEJR8vYPm9M93g==
X-Received: by 2002:a05:6102:2265:b0:472:9ce3:dccb with SMTP id
 v5-20020a056102226500b004729ce3dccbmr9426917vsd.30.1710756100583; Mon, 18 Mar
 2024 03:01:40 -0700 (PDT)
MIME-Version: 1.0
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
 <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
 <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop> <67baae71-da4f-4eda-ace7-e4f61d2ced0c@paulmck-laptop>
In-Reply-To: <67baae71-da4f-4eda-ace7-e4f61d2ced0c@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Mar 2024 11:01:03 +0100
Message-ID: <CANpmjNOmpOCfaFyMUnMtc3TT=VuTpWC4c85FW_u4dobmtikHtQ@mail.gmail.com>
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in rcu_trc_cmpxchg_need_qs()
To: paulmck@kernel.org
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com, 
	glider@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uUgIh2pZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as
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

On Sun, 17 Mar 2024 at 22:55, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Fri, Mar 08, 2024 at 02:31:53PM -0800, Paul E. McKenney wrote:
> > On Fri, Mar 08, 2024 at 11:02:28PM +0100, Marco Elver wrote:
> > > On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
> > >
> > > Because not all architectures support 1-byte cmpxchg?
> > > What prevents us from implementing it?
> >
> > Nothing that I know of, but I didn't want to put up with the KCSAN report
> > in the interim.
>
> And here is a lightly tested patch to emulate one-byte and two-byte
> cmpxchg() for architectures that do not support it.  This is just the
> emulation, and would be followed up with patches to make the relevant
> architectures make use of it.
>
> The one-byte emulation has been lightly tested on x86.
>
> Thoughts?
>
>                                                         Thanx, Paul
>
> ------------------------------------------------------------------------
>
> commit d72e54166b56d8b373676e1e92a426a07d53899a
> Author: Paul E. McKenney <paulmck@kernel.org>
> Date:   Sun Mar 17 14:44:38 2024 -0700
>
>     lib: Add one-byte and two-byte cmpxchg() emulation functions
>
>     Architectures are required to provide four-byte cmpxchg() and 64-bit
>     architectures are additionally required to provide eight-byte cmpxchg().
>     However, there are cases where one-byte and two-byte cmpxchg()
>     would be extremely useful.  Therefore, provide cmpxchg_emu_u8() and
>     cmpxchg_emu_u16() that emulated one-byte and two-byte cmpxchg() in terms
>     of four-byte cmpxchg().
>
>     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
>     Cc: Marco Elver <elver@google.com>
>     Cc: Andrew Morton <akpm@linux-foundation.org>
>     Cc: Thomas Gleixner <tglx@linutronix.de>
>     Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
>     Cc: Douglas Anderson <dianders@chromium.org>
>     Cc: Petr Mladek <pmladek@suse.com>
>     Cc: <linux-arch@vger.kernel.org>
>
> diff --git a/arch/Kconfig b/arch/Kconfig
> index 154f994547632..eef11e9918ec7 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -1506,4 +1506,7 @@ config FUNCTION_ALIGNMENT
>         default 4 if FUNCTION_ALIGNMENT_4B
>         default 0
>
> +config ARCH_NEED_CMPXCHG_1_2_EMU
> +       bool
> +
>  endmenu
> diff --git a/include/linux/cmpxchg-emu.h b/include/linux/cmpxchg-emu.h
> new file mode 100644
> index 0000000000000..fee8171fa05eb
> --- /dev/null
> +++ b/include/linux/cmpxchg-emu.h
> @@ -0,0 +1,16 @@
> +/* SPDX-License-Identifier: GPL-2.0+ */
> +/*
> + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> + * lacking direct support for these sizes.  These are implemented in terms
> + * of 4-byte cmpxchg operations.
> + *
> + * Copyright (C) 2024 Paul E. McKenney.
> + */
> +
> +#ifndef __LINUX_CMPXCHG_EMU_H
> +#define __LINUX_CMPXCHG_EMU_H
> +
> +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new);
> +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new);
> +
> +#endif /* __LINUX_CMPXCHG_EMU_H */
> diff --git a/lib/Makefile b/lib/Makefile
> index 6b09731d8e619..fecd7b8c09cbd 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -238,6 +238,7 @@ obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
>  lib-$(CONFIG_GENERIC_BUG) += bug.o
>
>  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> +obj-$(CONFIG_ARCH_NEED_CMPXCHG_1_2_EMU) += cmpxchg-emu.o

Since you add instrumentation explicitly, we need to suppress
instrumentation somehow. For the whole file this can be done with:

KCSAN_SANITIZE_cmpxchg-emu.o := n

Note, since you use cmpxchg, which pulls in its own
instrument_read_write(), we can't use a function attribute (like
__no_kcsan) if the whole-file no-instrumentation seems like overkill.
Alternatively the cmpxchg could be wrapped into a data_race() (like
your original RCU use case was doing).

But I think "KCSAN_SANITIZE_cmpxchg-emu.o := n" would be my preferred way.

With the explicit "instrument_read_write()" also note that this would
do double-instrumentation with other sanitizers (KASAN, KMSAN). But I
think we actually want to instrument the whole real access with those
tools - would it be bad if we accessed some memory out-of-bounds, but
that memory isn't actually used? I don't have a clear answer to that.

Also, it might be useful to have an alignment check somewhere, because
otherwise we end up with split atomic accesses (or whatever other bad
thing the given arch does if that happens).

Thanks,
-- Marco

>  obj-$(CONFIG_DYNAMIC_DEBUG_CORE) += dynamic_debug.o
>  #ensure exported functions have prototypes
> diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
> new file mode 100644
> index 0000000000000..508b55484c2b6
> --- /dev/null
> +++ b/lib/cmpxchg-emu.c
> @@ -0,0 +1,68 @@
> +/* SPDX-License-Identifier: GPL-2.0+ */
> +/*
> + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> + * lacking direct support for these sizes.  These are implemented in terms
> + * of 4-byte cmpxchg operations.
> + *
> + * Copyright (C) 2024 Paul E. McKenney.
> + */
> +
> +#include <linux/types.h>
> +#include <linux/export.h>
> +#include <linux/instrumented.h>
> +#include <linux/atomic.h>
> +#include <asm-generic/rwonce.h>
> +
> +union u8_32 {
> +       u8 b[4];
> +       u32 w;
> +};
> +
> +/* Emulate one-byte cmpxchg() in terms of 4-byte cmpxchg. */
> +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
> +{
> +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
> +       int i = ((uintptr_t)p) & 0x3;
> +       union u8_32 old32;
> +       union u8_32 new32;
> +       u32 ret;
> +
> +       old32.w = READ_ONCE(*p32);
> +       do {
> +               if (old32.b[i] != old)
> +                       return old32.b[i];
> +               new32.w = old32.w;
> +               new32.b[i] = new;
> +               instrument_atomic_read_write(p, 1);
> +               ret = cmpxchg(p32, old32.w, new32.w);
> +       } while (ret != old32.w);
> +       return old;
> +}
> +EXPORT_SYMBOL_GPL(cmpxchg_emu_u8);
> +
> +union u16_32 {
> +       u16 h[2];
> +       u32 w;
> +};
> +
> +/* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
> +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
> +{
> +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
> +       int i = ((uintptr_t)p) & 0x1;
> +       union u16_32 old32;
> +       union u16_32 new32;
> +       u32 ret;
> +
> +       old32.w = READ_ONCE(*p32);
> +       do {
> +               if (old32.h[i] != old)
> +                       return old32.h[i];
> +               new32.w = old32.w;
> +               new32.h[i] = new;
> +               instrument_atomic_read_write(p, 2);
> +               ret = cmpxchg(p32, old32.w, new32.w);
> +       } while (ret != old32.w);
> +       return old;
> +}
> +EXPORT_SYMBOL_GPL(cmpxchg_emu_u16);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOmpOCfaFyMUnMtc3TT%3DVuTpWC4c85FW_u4dobmtikHtQ%40mail.gmail.com.
