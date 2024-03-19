Return-Path: <kasan-dev+bncBCS4VDMYRUNBBE7D4OXQMGQEPOHKBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 01FB487F533
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 02:59:49 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dcbee93a3e1sf7694133276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Mar 2024 18:59:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710813587; cv=pass;
        d=google.com; s=arc-20160816;
        b=QJMzJsn2Xk6KHlrEx+QkH0caepzsOhloICN0IIE7LUdX/KpLQjNf/k0+Ci30TWId1u
         aUnQVhVgO44gHkhwkaSnAyCk+rXeM2pY6I/jGV00nTOE7Ky1wAjQWjzrfS2r8/lQK8rY
         nBCPyIQTzhQjBhhWyu3u9PGLYd6iVXyas8QOjPCkk3f39VZO8DEtoSFncQ5AtYw6TG2A
         DodjEIohBSl7Bw4r+GsmihgGOQO8mDAcyx6Hx7arOqy2bmzblK73QjOL7zheMKX7gcwD
         ENahI0ZOBYJ6d9iBwdaM2vFImloGm00YdQuhGgTnf64AcaXLnUJDVMPKf8q6pSr7j2NM
         HtCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=fXZtJUqJAmMbXfiP/LZTbGmHL3+gxp6xYePzC+ejITE=;
        fh=M8j8k0vesW80SIFu1r30/Qo9CgS2Nrh4Tg/RR6XTXhE=;
        b=KAY6dC2UdD18nXU1EsRHXUjLWkr0b2dhhSPRiOg0ORwIFRh8aRhChEAFSwWKmFea03
         /C1LO0QXxtH3INX91y5E89wKU4ZiIYOUx9Bz19OXPK8wV7U2ZKwacXPWZcdAD1K/gNJB
         uquErHUEFj5NFKOUCZcgYV9Og3SUrPX0Hi8gPT+3Uql/ZchuFz0ZAUiyjRjzb2CacQK7
         ykUx9hvOkeTHTXPDSPO8EHnfwAEFQHql04WsomvgEifWSj7vY/Nc7VgegjtdJifqeXyc
         CtVoQYgeeojAFIqGK0yAxsX4yVdh/wDdicjWYKZNHKcbI2b3ZxF8tB1LXN7P51bLBfUO
         aZGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pAp7+5Xn;
       spf=pass (google.com: domain of srs0=kwpk=kz=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=kwPk=KZ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710813587; x=1711418387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=fXZtJUqJAmMbXfiP/LZTbGmHL3+gxp6xYePzC+ejITE=;
        b=sTkD1tid/1GxzEK9swoyPsetZ2G6CdBOctIiaE40CpI0SQsMCGL637jBUPVg0jZ2XB
         VrDJ89H+pSaF/PA9Z/VojzcgrYw4U9beLvn2sclC33u6vt0bMIymc5DII3II1bUSqcXA
         nlY7D0lA7/9eJhzbmrM5EvdE/M2kN9Wut1p9yOxa+f2D8ACMapdNm7L4T00tCyCAmVs4
         OoaFhDABVnkSnPfFvRGfaUzm00Omx8zxoZTQ5DWcm5vcS8jznL0WOfc2KZG11jx/crTA
         wwcTgKCzTltqWfhkx6O/+Tmrb6h34dcNskH4hdxTnbjP26btd48bX/ZSPPHlW3NKIs1d
         Bn8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710813587; x=1711418387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=fXZtJUqJAmMbXfiP/LZTbGmHL3+gxp6xYePzC+ejITE=;
        b=sDlAcvI+8wHAwn3xxTzoYUxgIKUs5wV6b0SmgVP7bBFEa8Y2w3Ky6EO7oKQ3VcKkWl
         34m8sFu0YahxsMArve4W6YqK5DMH07yvdKaHpy2UwHrEnczPOwDv7RTJiv31JhbUDdZo
         okOB/HQTJHk/i9CWiNN3xPJuBKnqB2EqI4rmxhyEkFSfPRI5+BMMah8+BhxyUL3wnClS
         y8IOqZhofPxrAmlTtb+0JVNcF7BBcXBPmOOdpSpA/a/T1PjguMtumEfjmAiaKGtGZWFL
         0gR6QITglNlN8rv4lC5TlF69rcCDWfs2kXldbQspH8Yykkv7IM4OhExLV0Lr9qkBlorj
         oQEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLaYnrHhkM01uXcA1hWFVW9h/xPcaJDWRNj3Vl9l/s1VMU1F1PkEvKM/9Id//6ZsSptnMoAwvj6AX8lRmzyaI4+wN4vll4TA==
X-Gm-Message-State: AOJu0YyW8DWRWPRbRJ2lAl9P4DAEq/gojSESVODoQ7JNLtHmZ3p32Iz5
	J28Zev9yKZeezkytcVV1r8r6zrGUskY9J7kL6tcYhFZu2/2NKVO2
X-Google-Smtp-Source: AGHT+IGMs8tGglm9Ux3ryScHA+v0/puWff2wYQx/7U0RF+bgWzS7yEtI8FVHex5stu84bZqYDyH5yA==
X-Received: by 2002:a25:3308:0:b0:dcf:56c1:5a12 with SMTP id z8-20020a253308000000b00dcf56c15a12mr8679853ybz.38.1710813587454;
        Mon, 18 Mar 2024 18:59:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc07:0:b0:dc7:4417:ec4e with SMTP id y7-20020a25dc07000000b00dc74417ec4els1987035ybe.1.-pod-prod-04-us;
 Mon, 18 Mar 2024 18:59:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOvzf6k+gjMmu+CxlT0PoOaKR8LSjqQXvJQ3N7qeUBNhQa+qQkT7k/4I06MBe5FZqmrS32hIKm85lXRjhXlYme0ZR1/Q+cs2gWxA==
X-Received: by 2002:a0d:eb91:0:b0:60d:6034:2da2 with SMTP id u139-20020a0deb91000000b0060d60342da2mr11639259ywe.4.1710813586428;
        Mon, 18 Mar 2024 18:59:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710813586; cv=none;
        d=google.com; s=arc-20160816;
        b=zGhrm4ofkxTN57BsSaRQrZ+95xfUNVrILaVI7+wy4Y6bcbz3Lp32+9nJak0CmPTCEz
         sqbWGzfTeVCyfRPEQzevHVJF1CEWoJ33rgmZw+ZX1PV/PjccpBPJQUAPt02fidd1FE6o
         JrajlYq8+s9N4oz2738I6wnsoVLq7ruM4J9vfU+mfnTjlrGTaW07TLhAhk6jWZmO2cN9
         WUKZIs0y3z5c/m7tcM5tA0BnLXrLHgScvurY8DdjLlGPTXwOFRauM7xrhQZFmTMihsLk
         heYdxW22scBz1jDgxLJzBLwyGQiQTFGCQn2bSG5SZGdjmmIB64ZkvGFTliA9mTE/+pc3
         c4kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=r+1+yKllf4ieD2jkwJ/h2m0IyAmgE/guPw5e49DLKD4=;
        fh=rQPPKocvcSdU/KZDT5a1aA+odI3+PtCpik6mL0wgMXY=;
        b=FcTmcRD06Yced2WVCfyzY3OzECyAaEA6i7B7p4DumYA+cXQaGqa4TDEA1P9DWpheZS
         nvHUgGZcyvr2DCAad8QzqGA9csMdqtaCxPoE7nvH06xKSBpOy7c7edFJ1OS2JYQTpJE9
         rIG25DE7ljvv+lHsZMATAhX1ahN6ZT/i1MP9NlkYwbLRwBGV8wfmbFIQS1yFDbJBvtBU
         fjZ4tuMXWg98oMHqvks1Suw6Llfh1mrrKrxGZAtGmbWshFOc+9M0F0GO3cEmop9r980g
         I19TgVyu1pzgKNG6EFRPmvjqoBqYkwMu8NOH2jr1F2b12LoDu6Uc1lcQUq/Swq8RqGh2
         s/uA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pAp7+5Xn;
       spf=pass (google.com: domain of srs0=kwpk=kz=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=kwPk=KZ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id fl3-20020a05663863c300b00476fbaaca2dsi969289jab.4.2024.03.18.18.59.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Mar 2024 18:59:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kwpk=kz=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id E2729CE0B4C;
	Tue, 19 Mar 2024 01:59:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F3631C433C7;
	Tue, 19 Mar 2024 01:59:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 688EACE0D20; Mon, 18 Mar 2024 18:59:41 -0700 (PDT)
Date: Mon, 18 Mar 2024 18:59:41 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, dvyukov@google.com,
	glider@google.com
Subject: Re: [PATCH RFC rcu] Inform KCSAN of one-byte cmpxchg() in
 rcu_trc_cmpxchg_need_qs()
Message-ID: <5e6fdf1d-e84c-463c-b47b-f42500930b28@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <0733eb10-5e7a-4450-9b8a-527b97c842ff@paulmck-laptop>
 <CANpmjNO+0d82rPCQ22xrEEqW_3sk7T28Dv95k1jnB7YmG3amjA@mail.gmail.com>
 <53a68e29-cd33-451e-8cf0-f6576da40ced@paulmck-laptop>
 <67baae71-da4f-4eda-ace7-e4f61d2ced0c@paulmck-laptop>
 <CANpmjNOmpOCfaFyMUnMtc3TT=VuTpWC4c85FW_u4dobmtikHtQ@mail.gmail.com>
 <CANpmjNNLXR1kC8XAqFjEO3N0P3scRott8Z1OcW2yoKu5BEDaYQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNLXR1kC8XAqFjEO3N0P3scRott8Z1OcW2yoKu5BEDaYQ@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pAp7+5Xn;       spf=pass
 (google.com: domain of srs0=kwpk=kz=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=kwPk=KZ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Mar 18, 2024 at 04:43:38PM +0100, Marco Elver wrote:
> On Mon, 18 Mar 2024 at 11:01, Marco Elver <elver@google.com> wrote:
> >
> > On Sun, 17 Mar 2024 at 22:55, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Fri, Mar 08, 2024 at 02:31:53PM -0800, Paul E. McKenney wrote:
> > > > On Fri, Mar 08, 2024 at 11:02:28PM +0100, Marco Elver wrote:
> > > > > On Fri, 8 Mar 2024 at 22:41, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > >
> > > > > > Tasks Trace RCU needs a single-byte cmpxchg(), but no such thing exists.
> > > > >
> > > > > Because not all architectures support 1-byte cmpxchg?
> > > > > What prevents us from implementing it?
> > > >
> > > > Nothing that I know of, but I didn't want to put up with the KCSAN report
> > > > in the interim.
> > >
> > > And here is a lightly tested patch to emulate one-byte and two-byte
> > > cmpxchg() for architectures that do not support it.  This is just the
> > > emulation, and would be followed up with patches to make the relevant
> > > architectures make use of it.
> > >
> > > The one-byte emulation has been lightly tested on x86.
> > >
> > > Thoughts?
> > >
> > >                                                         Thanx, Paul
> > >
> > > ------------------------------------------------------------------------
> > >
> > > commit d72e54166b56d8b373676e1e92a426a07d53899a
> > > Author: Paul E. McKenney <paulmck@kernel.org>
> > > Date:   Sun Mar 17 14:44:38 2024 -0700
> > >
> > >     lib: Add one-byte and two-byte cmpxchg() emulation functions
> > >
> > >     Architectures are required to provide four-byte cmpxchg() and 64-bit
> > >     architectures are additionally required to provide eight-byte cmpxchg().
> > >     However, there are cases where one-byte and two-byte cmpxchg()
> > >     would be extremely useful.  Therefore, provide cmpxchg_emu_u8() and
> > >     cmpxchg_emu_u16() that emulated one-byte and two-byte cmpxchg() in terms
> > >     of four-byte cmpxchg().
> > >
> > >     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > >     Cc: Marco Elver <elver@google.com>
> > >     Cc: Andrew Morton <akpm@linux-foundation.org>
> > >     Cc: Thomas Gleixner <tglx@linutronix.de>
> > >     Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
> > >     Cc: Douglas Anderson <dianders@chromium.org>
> > >     Cc: Petr Mladek <pmladek@suse.com>
> > >     Cc: <linux-arch@vger.kernel.org>
> > >
> > > diff --git a/arch/Kconfig b/arch/Kconfig
> > > index 154f994547632..eef11e9918ec7 100644
> > > --- a/arch/Kconfig
> > > +++ b/arch/Kconfig
> > > @@ -1506,4 +1506,7 @@ config FUNCTION_ALIGNMENT
> > >         default 4 if FUNCTION_ALIGNMENT_4B
> > >         default 0
> > >
> > > +config ARCH_NEED_CMPXCHG_1_2_EMU
> > > +       bool
> > > +
> > >  endmenu
> > > diff --git a/include/linux/cmpxchg-emu.h b/include/linux/cmpxchg-emu.h
> > > new file mode 100644
> > > index 0000000000000..fee8171fa05eb
> > > --- /dev/null
> > > +++ b/include/linux/cmpxchg-emu.h
> > > @@ -0,0 +1,16 @@
> > > +/* SPDX-License-Identifier: GPL-2.0+ */
> > > +/*
> > > + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> > > + * lacking direct support for these sizes.  These are implemented in terms
> > > + * of 4-byte cmpxchg operations.
> > > + *
> > > + * Copyright (C) 2024 Paul E. McKenney.
> > > + */
> > > +
> > > +#ifndef __LINUX_CMPXCHG_EMU_H
> > > +#define __LINUX_CMPXCHG_EMU_H
> > > +
> > > +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new);
> > > +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new);
> > > +
> > > +#endif /* __LINUX_CMPXCHG_EMU_H */
> > > diff --git a/lib/Makefile b/lib/Makefile
> > > index 6b09731d8e619..fecd7b8c09cbd 100644
> > > --- a/lib/Makefile
> > > +++ b/lib/Makefile
> > > @@ -238,6 +238,7 @@ obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
> > >  lib-$(CONFIG_GENERIC_BUG) += bug.o
> > >
> > >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
> > > +obj-$(CONFIG_ARCH_NEED_CMPXCHG_1_2_EMU) += cmpxchg-emu.o
> >
> > Since you add instrumentation explicitly, we need to suppress
> > instrumentation somehow. For the whole file this can be done with:
> >
> > KCSAN_SANITIZE_cmpxchg-emu.o := n
> 
> Hrm, I recall this doesn't actually work as-is because it also
> disables instrument_read_write() instrumentation.
> 
> So I think the most reliable would be to use data_race() after all.
> It'll be a bit slower because of double-instrumenting, but I think
> that's not a major concern with an instrumented build anyway.

And I have added data_race(), thank you!

> > Note, since you use cmpxchg, which pulls in its own
> > instrument_read_write(), we can't use a function attribute (like
> > __no_kcsan) if the whole-file no-instrumentation seems like overkill.
> > Alternatively the cmpxchg could be wrapped into a data_race() (like
> > your original RCU use case was doing).
> >
> > But I think "KCSAN_SANITIZE_cmpxchg-emu.o := n" would be my preferred way.
> >
> > With the explicit "instrument_read_write()" also note that this would
> > do double-instrumentation with other sanitizers (KASAN, KMSAN). But I
> > think we actually want to instrument the whole real access with those
> > tools - would it be bad if we accessed some memory out-of-bounds, but
> > that memory isn't actually used? I don't have a clear answer to that.
> >
> > Also, it might be useful to have an alignment check somewhere, because
> > otherwise we end up with split atomic accesses (or whatever other bad
> > thing the given arch does if that happens).

Excellent point, added.

I also fixed an embarrassing pointer-arithmetic bug which the act of
coding the alignment check uncovered, so two for one!  ;-)

Please see below for a patch to the patched code.

							Thanx, Paul

> > Thanks,
> > -- Marco
> >
> > >  obj-$(CONFIG_DYNAMIC_DEBUG_CORE) += dynamic_debug.o
> > >  #ensure exported functions have prototypes
> > > diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
> > > new file mode 100644
> > > index 0000000000000..508b55484c2b6
> > > --- /dev/null
> > > +++ b/lib/cmpxchg-emu.c
> > > @@ -0,0 +1,68 @@
> > > +/* SPDX-License-Identifier: GPL-2.0+ */
> > > +/*
> > > + * Emulated 1-byte and 2-byte cmpxchg operations for architectures
> > > + * lacking direct support for these sizes.  These are implemented in terms
> > > + * of 4-byte cmpxchg operations.
> > > + *
> > > + * Copyright (C) 2024 Paul E. McKenney.
> > > + */
> > > +
> > > +#include <linux/types.h>
> > > +#include <linux/export.h>
> > > +#include <linux/instrumented.h>
> > > +#include <linux/atomic.h>
> > > +#include <asm-generic/rwonce.h>
> > > +
> > > +union u8_32 {
> > > +       u8 b[4];
> > > +       u32 w;
> > > +};
> > > +
> > > +/* Emulate one-byte cmpxchg() in terms of 4-byte cmpxchg. */
> > > +uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
> > > +{
> > > +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
> > > +       int i = ((uintptr_t)p) & 0x3;
> > > +       union u8_32 old32;
> > > +       union u8_32 new32;
> > > +       u32 ret;
> > > +
> > > +       old32.w = READ_ONCE(*p32);
> > > +       do {
> > > +               if (old32.b[i] != old)
> > > +                       return old32.b[i];
> > > +               new32.w = old32.w;
> > > +               new32.b[i] = new;
> > > +               instrument_atomic_read_write(p, 1);
> > > +               ret = cmpxchg(p32, old32.w, new32.w);
> > > +       } while (ret != old32.w);
> > > +       return old;
> > > +}
> > > +EXPORT_SYMBOL_GPL(cmpxchg_emu_u8);
> > > +
> > > +union u16_32 {
> > > +       u16 h[2];
> > > +       u32 w;
> > > +};
> > > +
> > > +/* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
> > > +uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
> > > +{
> > > +       u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
> > > +       int i = ((uintptr_t)p) & 0x1;
> > > +       union u16_32 old32;
> > > +       union u16_32 new32;
> > > +       u32 ret;
> > > +
> > > +       old32.w = READ_ONCE(*p32);
> > > +       do {
> > > +               if (old32.h[i] != old)
> > > +                       return old32.h[i];
> > > +               new32.w = old32.w;
> > > +               new32.h[i] = new;
> > > +               instrument_atomic_read_write(p, 2);
> > > +               ret = cmpxchg(p32, old32.w, new32.w);
> > > +       } while (ret != old32.w);
> > > +       return old;
> > > +}
> > > +EXPORT_SYMBOL_GPL(cmpxchg_emu_u16);

diff --git a/lib/cmpxchg-emu.c b/lib/cmpxchg-emu.c
index 508b55484c2b6..b904f954dd4fc 100644
--- a/lib/cmpxchg-emu.c
+++ b/lib/cmpxchg-emu.c
@@ -11,6 +11,8 @@
 #include <linux/export.h>
 #include <linux/instrumented.h>
 #include <linux/atomic.h>
+#include <linux/panic.h>
+#include <linux/bug.h>
 #include <asm-generic/rwonce.h>
 
 union u8_32 {
@@ -34,7 +36,7 @@ uintptr_t cmpxchg_emu_u8(volatile u8 *p, uintptr_t old, uintptr_t new)
 		new32.w = old32.w;
 		new32.b[i] = new;
 		instrument_atomic_read_write(p, 1);
-		ret = cmpxchg(p32, old32.w, new32.w);
+		ret = data_race(cmpxchg(p32, old32.w, new32.w));
 	} while (ret != old32.w);
 	return old;
 }
@@ -48,12 +50,13 @@ union u16_32 {
 /* Emulate two-byte cmpxchg() in terms of 4-byte cmpxchg. */
 uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
 {
-	u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x1);
-	int i = ((uintptr_t)p) & 0x1;
+	u32 *p32 = (u32 *)(((uintptr_t)p) & ~0x3);
+	int i = (((uintptr_t)p) & 0x2) / 2;
 	union u16_32 old32;
 	union u16_32 new32;
 	u32 ret;
 
+	WARN_ON_ONCE(((uintptr_t)p) & 0x1);
 	old32.w = READ_ONCE(*p32);
 	do {
 		if (old32.h[i] != old)
@@ -61,7 +64,7 @@ uintptr_t cmpxchg_emu_u16(volatile u16 *p, uintptr_t old, uintptr_t new)
 		new32.w = old32.w;
 		new32.h[i] = new;
 		instrument_atomic_read_write(p, 2);
-		ret = cmpxchg(p32, old32.w, new32.w);
+		ret = data_race(cmpxchg(p32, old32.w, new32.w));
 	} while (ret != old32.w);
 	return old;
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5e6fdf1d-e84c-463c-b47b-f42500930b28%40paulmck-laptop.
