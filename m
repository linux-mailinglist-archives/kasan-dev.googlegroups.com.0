Return-Path: <kasan-dev+bncBDV37XP3XYDRB57JT2GQMGQEEPZO4YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E11A6465437
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 18:46:31 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf653031wme.0
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 09:46:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638380791; cv=pass;
        d=google.com; s=arc-20160816;
        b=peDYxbpFwGNmJj1IYXTXC2+kHKASVEZKNK52a3cRf4mu7wwM9Joa4BsVW5MgLr/3CF
         +NZ7fTIlHdPdNDxyFdxqno8yZ6RKiQ6ZMtunCHaLWtE+tlsmmVhX3VKsEHjJuuZ6065p
         L0FMrRA3uZP0WQAb57jgPN08kmo7WbwtJ4M2rmYGZGHxmfT3kxAgZSelE0fpUMK9qWS4
         smO0H08Q3Qd2JiXGCxB9aE7KAZr8FgT9MZbBwR/8RTCqS6UALRORs5oi98e0jTXaeDf6
         fpWuSCOW9LlQL0iErkk308p3Ley5KDTN0XpYNcPPmOVkSLUfqBLpw+KMb0zKteCFrGkv
         ct9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ip4I4sNAJwcPHJ8VOx5MOcaZC1qN+DsneegArhj0IEc=;
        b=bUTy1fubzZwgJ4P+yppiBkUJV8YQ49mE98o9Z9cwmgciMSQFcIEyVr5KIFjklZHeaz
         /QWhxwTOtoNMF1ucrXtXJkywP4MhkaedZYZIgXzKLxJEeZupHVddt2H/MKK5Rvm5k4hj
         pbfSDLIihvuKSJgv4U79pbFcNjXB0sYf8yyL/0aqdr6KeDd/GdNPhfa/Di9kElvVe9UJ
         4da2MPwV19v440pYkWJILqlCxNHEX/Nj/Q/lIopCiiYC3Rjt+CRtpx+SRvz5DB+pnhlC
         LNxQ0G/fKmiQHAfFMp41a/hHJGr7/DTqyu108yizwPQoKTPp/bk0Vs3NF2rws1Es1pmZ
         0Xmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ip4I4sNAJwcPHJ8VOx5MOcaZC1qN+DsneegArhj0IEc=;
        b=Fq5A0zNQScUfb61SLiFrtMh+ZLe/4u/vYwqIkXvAg2bIx6XofOAaH5FATk06PKLgjM
         ouHUaZPPXQG2hvEiGPgntEOtmkyT2JB84gNznCpZyBhZJ11l9fZ4JwvXaxFs8dlC1P4O
         vd1aYPARBYnOUZq0+0u7uooCJAGctGKr2I04wxqf1nnOwWElFSZu8O1mXBjTMYBu8wrl
         sQaLgoABC0C3kJZzBcUHmHs6j6zhC9dV+1g+C0xlQK1vELi5/QmxB6xpfNj7Sa/miq5v
         viyS+JHOYU2JFELqP6G2uEbtR9RY24w+/K34beSdNf86GVqZ4GaC5FI9GkoPTjuRfftg
         AEaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ip4I4sNAJwcPHJ8VOx5MOcaZC1qN+DsneegArhj0IEc=;
        b=ABZMBKZMyeEQJ1Y84eqp3c1hMTFHEYRqm0QAtZ3pxpalh8gYQ/uWpqG5K3t6WKYyRz
         EYejS1z5D8YD/pS3O7W0JqvX6cxjCyWP2JuV0ij1asFgP2nemXihfbuofpriNkJeqYMi
         o6MqrJXG7L9lFF0xiG8zC+bXc6HCeqqWjaTaMov5R0KdO6/LH5Fcm/lxQ4GYeqJiWIYS
         aqHzBgDqBiJZ1BSSgZTN+Ph1JS6YkCIe8Jf3wKYiFSKlOW6QesxTkCaB4ikPm7LFxz6z
         NHS367EHx84EPgEcz6i6JGRqNlwmcF8LHBd7NSIK7AcqAIIky+VHVfT5B4ayZYRDZbtR
         WYbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zD155fX+xn5B2vYfrHMWHn1TPTgpAIKUyhy9Cq/WQsHDJGOzN
	tq9Bc0ORHhjsXohVfKBPuRc=
X-Google-Smtp-Source: ABdhPJwtXINxHoMOWMEeONRYc69SltugLeC74Hu9wwrb1SH9QuQRI2TmP5ZTtP/GAU+0hBksAeN2og==
X-Received: by 2002:adf:d22a:: with SMTP id k10mr8774811wrh.80.1638380791619;
        Wed, 01 Dec 2021 09:46:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls144556wrr.0.gmail; Wed, 01 Dec
 2021 09:46:30 -0800 (PST)
X-Received: by 2002:a5d:54c5:: with SMTP id x5mr8341067wrv.442.1638380790641;
        Wed, 01 Dec 2021 09:46:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638380790; cv=none;
        d=google.com; s=arc-20160816;
        b=gMSJdBLCeIjxU65g7VpqWSoSbvJl/3XabgrEh3V7rbh1hYwE/rulDQ3Gt/m8Ompryu
         ZQYMOhjVWYowgBNzj3qSUnIfNKj0xc1N2lEvtzPoe4OFCJ25+/F8VbvzLzonoKZwWVsg
         VesPeYKa7wIRqSWbw84gL7wJJphXPrVTeepvZxIXzL8P4nZAMa2I+YtvISKlWWqwmcIX
         Joq3S33EKzrIf/RYUNgfnlcIq4YTiSUl7euqCjKetshxC2Fo0lUm407zjRArkytcpVEg
         Gz5FVgv+uSUMIbXRv8BnaGuf5vse9E6C68wu1FD6mSqc27Z/rozZCvTnLhWe3W01O/bU
         KhxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=YuTGEE0vt/S5GQPkKqLkBkvXNl3ciNX2TMB6DY69G4g=;
        b=mTWSz8C7THh5+YOFYpDS/uNyOOg/SKZe4z2KsYwe65w1Wf6sm/jy45oH8gOngaQtrm
         0Z5NHIYPaYXTMA1aZ1DNbk2aIFjuiSP6ld3lvGX1uIayzjVZk9vJSMbpQKBjwUVP5z9r
         4EAuVhgXPqzgFu39Ez4hJTx0pGWD3IlYzvaYA3EiwgL3miANDLImxS3IlXkzL3Y745RD
         sh6UgifYs+/OGJ+5F9k0a14HnpBdK7dincpraAxdcutAzcuA75gKJGJW1oq6hVenwyCo
         gpD6hSoLv5ZvVws69UTlF+76gLkjzAvEx7dqAZofmZGSndsdguVJpWMzRBPFjHLGALKf
         k5pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 138si63890wme.0.2021.12.01.09.46.30
        for <kasan-dev@googlegroups.com>;
        Wed, 01 Dec 2021 09:46:30 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9DB3C14BF;
	Wed,  1 Dec 2021 09:46:29 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.65.205])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D9BAD3F766;
	Wed,  1 Dec 2021 09:46:26 -0800 (PST)
Date: Wed, 1 Dec 2021 17:46:24 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if
 ARCH_WANTS_NO_INSTR
Message-ID: <Yae08MUQn5SxPwZ/@FVFF77S0Q05N>
References: <20211201152604.3984495-1-elver@google.com>
 <YaebeW5uYWFsDD8W@FVFF77S0Q05N>
 <CANpmjNO9f2SD6PAz_pF3Rg_XOmBtqEB_DNsoUY1ycwiFjoP88Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO9f2SD6PAz_pF3Rg_XOmBtqEB_DNsoUY1ycwiFjoP88Q@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Dec 01, 2021 at 05:10:39PM +0100, Marco Elver wrote:
> On Wed, 1 Dec 2021 at 16:57, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > Hi Marco,
> >
> > On Wed, Dec 01, 2021 at 04:26:04PM +0100, Marco Elver wrote:
> > > Until recent versions of GCC and Clang, it was not possible to disable
> > > KCOV instrumentation via a function attribute. The relevant function
> > > attribute was introduced in 540540d06e9d9 ("kcov: add
> > > __no_sanitize_coverage to fix noinstr for all architectures").
> > >
> > > x86 was the first architecture to want a working noinstr, and at the
> > > time no compiler support for the attribute existed yet. Therefore,
> > > 0f1441b44e823 ("objtool: Fix noinstr vs KCOV") introduced the ability to
> > > NOP __sanitizer_cov_*() calls in .noinstr.text.
> > >
> > > However, this doesn't work for other architectures like arm64 and s390
> > > that want a working noinstr per ARCH_WANTS_NO_INSTR.
> > >
> > > At the time of 0f1441b44e823, we didn't yet have ARCH_WANTS_NO_INSTR,
> > > but now we can move the Kconfig dependency checks to the generic KCOV
> > > option. KCOV will be available if:
> > >
> > >       - architecture does not care about noinstr, OR
> > >       - we have objtool support (like on x86), OR
> > >       - GCC is 12.0 or newer, OR
> > >       - Clang is 13.0 or newer.
> >
> > I agree this is the right thing to do, but since GCC 12.0 isn't out yet (and
> > only x86 has objtool atm) this will prevent using KCOV with a released GCC on
> > arm64 and s390, which would be unfortunate for Syzkaller.
> >
> > AFAICT the relevant GCC commit is:
> >
> >    https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
> >
> > Currently we mostly get away with disabling KCOV for while compilation units,
> > so maybe it's worth waiting for the GCC 12.0 release, and restricting things
> > once that's out?
> 
> An alternative would be to express 'select ARCH_WANTS_NO_INSTR' more
> precisely, say with an override or something. Because as-is,
> ARCH_WANTS_NO_INSTR then doesn't quite reflect reality on arm64
> (yet?).

It's more of a pragmatic thing -- ARCH_WANTS_NO_INSTR does reflect reality, and
we do *want* to enforce that strictly, it's just that we're just struck between
a rock and a hard place where until GCC 12 is released we either:

a) Strictly enforce noinstr, and be sure there aren't any bugs from unexpected
   instrumentation, but we can't test GCC-built kernels under Syzkaller due to
   the lack of KCOV.

b) Don't strictly enforce noinstr, and have the same latent bugs as today (of
   unknown severity), but we can test GCC-built kernels under Syzkaller.

... and since this (currently only affects KCOV, which people only practically
enable for Syzkaller, I think it's ok to wait until GCC 12 is out, so that we
can have the benefit of Sykaller in the mean time, and subsequrntly got for
option (a) and say those people need to use GCC 12+ (and clang 13+).

> But it does look simpler to wait, so I'm fine with that. I leave it to you.

FWIW, for my purposes I'm happy to take this immediately and to have to apply a
local patch to my fuzzing branches until GCC 12 is out, but I assume we'd want
the upstream testing to work in the mean time without requiring additional
patches.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yae08MUQn5SxPwZ/%40FVFF77S0Q05N.
