Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHOIWOGAMGQEQIRWLFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id CAA0144D426
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 10:36:30 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id a9-20020a056830008900b0056561b8c755sf2637625oto.22
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 01:36:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636623389; cv=pass;
        d=google.com; s=arc-20160816;
        b=U1G55jNsKZ7ozQIvp1WHKdBQIxK4GA4OzMj8Ncr3HANtpccCoBDntQdgqIUmrq97QW
         jVCJRQdUFhs72UqvGGPsnYaWJJFzqgACWedGEgYqUaXqpsH5WIIPKkzjrAypB9Ef3h18
         Lczdvu3GUp062wxKIPbV/si60qOGgKtVItdiyhYfykIlMTweCJV4NXqApFu/YTANP/HT
         saz17+a2ng0r0QXhh61dsJWroiKPTQ0Bqojms0rtaoOGTqF5nE8UBzx4MlUasDy+kGFU
         TL3l9xPkY3B7OZOgyLnJg7IQM2VhaCIIMCeM7S5X4TDkeT6P3+AvZxhV4g7tB9F9Np1z
         unoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Yje1m4pQCujc2Awik1kEDy40v4cuuMotvoyBXpxBsLY=;
        b=rJsUiDzHP8GNaAPUcHWcJblTJQCU2gNQfFSZpNQ8kCHIX6RaItTzFpZMyr6DRI7nrm
         X4Vy2kj5IQ/L2D6Jt0hkhY+KUcTHYOlKkb8hfCOKaTqARDt0MDic3H/xtnPHilxlmGhv
         onea0kcgaWtzt7aMYff32OqRr7bwPYUOSrYStO7HOICuCz3Zbgbf5JMIFWu8+u9/kVP+
         o9ODfEXBUIriUO+qoXzi7XUswBe5ACzg3UivMYQEOWfA+TtPiDviWTuRgCf3z6Zol2T4
         LnCxrjASMtSXwCWbLl+ccS1PakPwln9XhMOWtbf8qAuV4Rt8Lyi0Q0EczP3ODXu4VgcL
         /SyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UpJAsHH3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yje1m4pQCujc2Awik1kEDy40v4cuuMotvoyBXpxBsLY=;
        b=FcxgnVZKoD7ByrIXErZvyD2MQhwbwWWxmElys4bFdcLEAnICElhM/dV4TAPzDsX96y
         CXWYAQymZSrIJ6c/kWD1/j0QsOELgftcscHX65OXPX5NMolK2LwdlkvfALq1Z+6/FnzA
         2WtbPlHOXyTyKOt9EOgL3zCpL/mp+m/OyzxfVE0ZW8xtPskyknRNJIN9pCpQETX69kdw
         NICSDoD/xak4NOPmkiJOw6TjZXtVDNHqfanhe85syRWSNQmc2sFky941f5BdjjtxHtEU
         ek2YCkJ2gA0YTEslbUAczTx/TpmNrDNYLMr5QN/w64cFklQKGhSSoaLczfxEiB0zwcVo
         dhoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yje1m4pQCujc2Awik1kEDy40v4cuuMotvoyBXpxBsLY=;
        b=RgpQh2zXNUkUsoYkh8kt5mMmk37quCpSczybp0TGN/59xvRUzrZ8WQK9BPa0pzMLNY
         PEqcp9GnQuPXUGxZi17oELj/2bXrKptCD5anSbWWdEVA9r31A1QZDPYFotGT9hYX7SAU
         Uta1zbEIubijYERsO9X0kgIesAqJW3yvBZ6QrB26ysC56YAWwWsx8dazChrlduwgGwMO
         oRhwJQyjCDM3ksFiNAlF/5fxscbb6okr+gBTkJPZS0qnLjiiHaaP6hQ3idkbkzd5e68j
         OoXCUHySUC78GpVKYjtE1FYHePU9KIviSrghhruyRyR/1AW/0VgUrsbB0RPy4M3ILJBh
         INnQ==
X-Gm-Message-State: AOAM533LdoE9sldXU6VA9etyWYAzhjVxvqQBnAqWvPFIRQInc0pGNe42
	EyE8PbYQJbWYXYz4F3ylphM=
X-Google-Smtp-Source: ABdhPJzdXTRwSpRdsVlcxr4kbQ6XBe6Oh9sfzzt0Cs8raCpH5DVf9mo0sCtjn6wrtO6eziEd7Q4gfA==
X-Received: by 2002:a05:6808:2106:: with SMTP id r6mr18830849oiw.110.1636623389478;
        Thu, 11 Nov 2021 01:36:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:440e:: with SMTP id q14ls969221otv.0.gmail; Thu, 11
 Nov 2021 01:36:29 -0800 (PST)
X-Received: by 2002:a9d:6a56:: with SMTP id h22mr4655427otn.135.1636623389119;
        Thu, 11 Nov 2021 01:36:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636623389; cv=none;
        d=google.com; s=arc-20160816;
        b=GLVuxdNbPv7IeZtsmBYV9FoGsMfuaOhy/v/aF+Ft90e+PslWtRFpvQLGWOlGZRCO0e
         9QJ23ogy/0f1EBa2xkZ52X8JmuZF7ZUDVoaL529BMo4U0va2KUdeZ8BuSSAO2L58Nq78
         JDRqOtOMQHzbAE8wkHBcoXrZOsqIrMRJflGB7k48Uy5lRSuUQGQ7ASLzYDg1ptbt2yEq
         5Ub+pJk8sIVZeF+O7TsLkRqZVvmTwEvTxQ9nZjCjGr9YkG+wsitTTcJQbW8+PCH+gGMz
         t7ByZ+iVU2TOOcVz7LnR84VpsaISbUxfoup/QeUG9kO8+vLGOjIgIizVTrlvXTAyg3Ax
         +VwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FQNotspdE85/ckyfVd22yizASeOICaHxBSL2D6Rwwpw=;
        b=TF3zkLsI1HgE6wiCOdhTeytAhGI7LZ9BREMkMxy0RuqHON6DeBWQvl0OG0XbHKe9t6
         SFgCvlrs+uH7nWclcbPhq3PU1EqC736U1EFluXZhPYlnpq9AFNfCfxnkROCZcfj0+q/8
         uzDPIuY+a6+UryIZhgC2zGhWYHEcec/hTKqt+46EYpFgdyFNpBcraY3cZ7xFsALmSqOY
         uykTBD208gYjHmnTEU5MpP41awL9iZG3BQdXy7Y2h0gWkXrhy4MZajSHU8HtyRztVejC
         JP5qizKL/lxQnBd2RhPG7OK5cbprMbG5qrD4K3W4mOz47QsLd1UhZT+3f/nXZsHJg0dl
         3jrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UpJAsHH3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id i6si212216oot.0.2021.11.11.01.36.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Nov 2021 01:36:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id g91-20020a9d12e4000000b0055ae68cfc3dso8068857otg.9
        for <kasan-dev@googlegroups.com>; Thu, 11 Nov 2021 01:36:29 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr4791136otl.329.1636623388618;
 Thu, 11 Nov 2021 01:36:28 -0800 (PST)
MIME-Version: 1.0
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-3-valentin.schneider@arm.com> <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de>
 <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de> <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
In-Reply-To: <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Nov 2021 10:36:17 +0100
Message-ID: <CANpmjNPeRwupeg=S8yGGUracoehSUbS-Fkfb8juv5mYN36uiqg@mail.gmail.com>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
To: Mike Galbraith <efault@gmx.de>
Cc: Valentin Schneider <valentin.schneider@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, 
	linux-kbuild@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman <mpe@ellerman.id.au>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Michal Marek <michal.lkml@markovi.net>, Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UpJAsHH3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Thu, 11 Nov 2021 at 04:47, Mike Galbraith <efault@gmx.de> wrote:
>
> On Thu, 2021-11-11 at 04:35 +0100, Mike Galbraith wrote:
> > On Thu, 2021-11-11 at 04:16 +0100, Mike Galbraith wrote:
> > > On Wed, 2021-11-10 at 20:24 +0000, Valentin Schneider wrote:
> > > >
> > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > index 5f8db54226af..0640d5622496 100644
> > > > --- a/include/linux/sched.h
> > > > +++ b/include/linux/sched.h
> > > > @@ -2073,6 +2073,22 @@ static inline void cond_resched_rcu(void)
> > > >  #endif
> > > >  }
> > > >
> > > > +#ifdef CONFIG_PREEMPT_DYNAMIC
> > > > +
> > > > +extern bool is_preempt_none(void);
> > > > +extern bool is_preempt_voluntary(void);
> > > > +extern bool is_preempt_full(void);
> > > > +
> > > > +#else
> > > > +
> > > > +#define is_preempt_none() IS_ENABLED(CONFIG_PREEMPT_NONE)
> > > > +#define is_preempt_voluntary()
> > > > IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY)
> > > > +#define is_preempt_full() IS_ENABLED(CONFIG_PREEMPT)
> > >
> > > I think that should be IS_ENABLED(CONFIG_PREEMPTION), see
> > > c1a280b68d4e.
> > >
> > > Noticed while applying the series to an RT tree, where tglx
> > > has done that replacement to the powerpc spot your next patch
> > > diddles.
> >
> > Damn, then comes patch 5 properly differentiating PREEMPT/PREEMPT_RT.
>
> So I suppose the powerpc spot should remain CONFIG_PREEMPT and become
> CONFIG_PREEMPTION when the RT change gets merged, because that spot is
> about full preemptibility, not a distinct preemption model.
>
> That's rather annoying :-/

I guess the question is if is_preempt_full() should be true also if
is_preempt_rt() is true?

Not sure all cases are happy with that, e.g. the kernel/trace/trace.c
case, which wants to print the precise preemption level.

To avoid confusion, I'd introduce another helper that says true if the
preemption level is "at least full", currently that'd be "full or rt".
Something like is_preempt_full_or_rt() (but might as well write
"is_preempt_full() || is_preempt_rt()"), or is_preemption() (to match
that Kconfig variable, although it's slightly confusing). The
implementation of that helper can just be a static inline function
returning "is_preempt_full() || is_preempt_rt()".

Would that help?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPeRwupeg%3DS8yGGUracoehSUbS-Fkfb8juv5mYN36uiqg%40mail.gmail.com.
