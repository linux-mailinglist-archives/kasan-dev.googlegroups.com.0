Return-Path: <kasan-dev+bncBDAMN6NI5EERB453632QKGQEC74IOQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 68E081D3DA7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 21:37:23 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id pj20sf8449ejb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 12:37:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589485043; cv=pass;
        d=google.com; s=arc-20160816;
        b=FCVwrbf1WAMejZUeIzkt1xU5HCu3CANqGaZQBP2XBCTSIJMVijMq2RZQlP7xbRLQ9O
         x+sqxz3MdF8Xny9SVIzUhqpv6ck6wMKgIN4uoCbqVt8Q36LBeBW/cfTWq6Z/f4W3ELvG
         8PhWpcMKuNw504sPw0nRnatuSL2UUnrpiQ4Z9+BOAubuMdYGMElON56xQNXvuYRHvUz3
         F11ZL2d8D38xvfZZ8EhRf5IwmVZ3+jwJsP9szOz8Dkr19U1uKmBMtAIILoggawh5YURz
         HBp7LcBzJY/NSr8yPqWLRwQvWA7DyVnr31WyrfwEJ/GkqkLaVIflN5uDPw2JABtnW2qu
         94nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=51SXSlCMo9EoW2Ij0CBr0LBC7w0j5/9xJssXKMorP38=;
        b=c4ZK3/kfsUXcKqAAdpLHIEs930XtdbcaYHCgm4MIOQdLQIRe6hjF4HB0bn53l92xUj
         36A3Bt2/0mlRZBZPZDrZQVDhI55Cryvtf7JaSA+uSBDOb0nhWjNuCLVZOuPTAga0C3+S
         GxQGFLxq4F5FWOIhFxTU8Ln299Uxn2DlAI0ScUuq2XpXtVWLRQftC+HUSNOYSI/pSjI9
         0GdEtZqHN1FgYz3tMB/fB8uYr7m0wGcob4p2PICrpbKY7xIMi7XbLkaR6ltiQqg9aF02
         AEcZ2bJ2SScEJ3IPoGbfh2ur4Hayzoxqi1VI4ZTzUCaCY5Zx2EZTtLQ1ujK+L/MStHiD
         yXIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=51SXSlCMo9EoW2Ij0CBr0LBC7w0j5/9xJssXKMorP38=;
        b=Eca69sDnEQGgZy1JvawV+QpZs9BNWFzjF/TM3xdKC/dHVGeycC5wkWR06Ay9zL7L/B
         L4rFPcPoNcGTj+YxtGXjQOuUAErI3U0356HwrVhj2fMpXeRp8nsR46yRTpNEiueOBDsW
         9C+rNIakLa0UfgA5bzPNSKoRrq12EeNvWtWDa9v5plBgsSyn/3ntDfis3sfa0WwoSBkG
         OhRRZCSuaidIQcO4OjKz+Vfoukl1JeDfiACQGhfp7xn8JjF2yF56vmAnDp34fpSB2AYQ
         /ux6Wk43tz3vru1znnzbRN0dK035H9iYVcmA4zgJs3N0M4bfg6DkQA0Za1G7AeRN4QBO
         HH/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=51SXSlCMo9EoW2Ij0CBr0LBC7w0j5/9xJssXKMorP38=;
        b=fYQWTEVSciVDGK8NtkY3IzctQBmywCQlOwtTFYj/YVZZl8sEPqnWCBanxYYzraxNoq
         UzJL5FMTGMILMzRkTDGr3s2BzyqgfmhkN2fueedp6d78VPjebYzeO7DdIHPUvw1OCI1/
         /i6GXXpWp46i/9xvDGM/esYHskM58NGkV51JsPB9vBqmGAlYM3zoSzL+Za5xGH9js5Ob
         L/x/bNWlm9b69YD57fOCn4SCDGSi+J6PM8nTJ1Ig89R2aTRpnHuKvq9j6V3F/5cg3O3Z
         ZqFZieaf6wZPUjG3wsNC8x+B5J/9O3cea9yMqrf0arsq1TgVkYnZKSuyXPJ14yYXfO8P
         3E3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MwGqyEvJ+vHGxHbr3b8cLghUg/aeni2/laSIaFyt7p2vC0Vu9
	gpWX/QeYVMyZtEVy2iN64kA=
X-Google-Smtp-Source: ABdhPJy7l6tlpkCuQRZi3ZBCCv609QCowCth5MZRh5jk4XPC5cSe8dGb9PPD6ZEmZPM7cU8z1mNsCw==
X-Received: by 2002:a17:906:4406:: with SMTP id x6mr5712237ejo.160.1589485043135;
        Thu, 14 May 2020 12:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d4dd:: with SMTP id e29ls102623edj.2.gmail; Thu, 14 May
 2020 12:37:22 -0700 (PDT)
X-Received: by 2002:a05:6402:cb4:: with SMTP id cn20mr2886256edb.150.1589485042613;
        Thu, 14 May 2020 12:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589485042; cv=none;
        d=google.com; s=arc-20160816;
        b=RnMAsWxbdcB/jSQLK4HHaOpjnVGN8oPPBVq15A7nK78M1Y+pkZ4u0pNfdYS/g0I+tP
         IW1us1M7rs11Jg8Gkd4ptOqVXLNcQ+N+X8SyLHJ3x+YlEFT5lQuh/RNvQyYJbe832kIG
         JtjSUcbGr9fOq7mGNlR3iU1PI/M2HS9RO4oLcCW3ThKymoCATPP2B/fc9Up8vbyBobJZ
         YZCXi9SF6OiyIEBL0WPuVFEntPN1vdJ5RSRMk548aUhB25p6TEvJjr0ID8j8lUGpc2Ow
         ohca1puSdLTc+RoieU7SD204uenfDmgKudZlyn/b2ix7ygTQ5IJER7ZiLVaqQaleBPtY
         9MeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=20Akrnf09SkhY9NmwgYU9d6lUr/dSk3YdcaTmZe3eTQ=;
        b=q7PQYS1ZYOEfONv6uB50e7xEBIhYY2cTSKAkKpSqaqS/AQJHfkp0NzCaDWLEcGZZy9
         1b5bcp3bKj6YcmqNJOClD1v6SD2eDNxijfeWgLK/NdIXFZO/UFbMecICNL153nFKXYHM
         YvqC+GAOBiWqdAGSTLIh10GrA80xNTOgvFGFCFouXbLy55mX8kCZdK9gLy+7/4/kzun1
         XwYaHMYOXs0FtRxRw4SnoZJyx3JqAhYuxNGCF+htaekHuG8ei5v898xRe9zu6Wy0Ioz3
         aHnyOgUkzlX2WfHilNoiglvncYnGQcwe2wW+a8lqTZE/p7/AbAG22Oh/1LoWjbmc9WJK
         cW2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id j24si201096ejo.1.2020.05.14.12.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Thu, 14 May 2020 12:37:22 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from p5de0bf0b.dip0.t-ipconnect.de ([93.224.191.11] helo=nanos.tec.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tglx@linutronix.de>)
	id 1jZJfV-0007qm-DB; Thu, 14 May 2020 21:37:21 +0200
Received: by nanos.tec.linutronix.de (Postfix, from userid 1000)
	id BD80F1004CE; Thu, 14 May 2020 21:37:20 +0200 (CEST)
From: Thomas Gleixner <tglx@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
In-Reply-To: <CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com>
References: <20200513124021.GB20278@willie-the-truck> <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com> <20200513165008.GA24836@willie-the-truck> <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com> <20200513174747.GB24836@willie-the-truck> <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com> <20200513212520.GC28594@willie-the-truck> <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com> <20200514110537.GC4280@willie-the-truck> <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com> <20200514142450.GC2978@hirez.programming.kicks-ass.net> <875zcyzh6r.fsf@nanos.tec.linutronix.de> <CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com>
Date: Thu, 14 May 2020 21:37:20 +0200
Message-ID: <87k11exq8f.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Linutronix-Spam-Score: -1.0
X-Linutronix-Spam-Level: -
X-Linutronix-Spam-Status: No , -1.0 points, 5.0 required,  ALL_TRUSTED=-1,SHORTCIRCUIT=-0.0001
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
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

Marco Elver <elver@google.com> writes:
> On Thu, 14 May 2020 at 17:09, Thomas Gleixner <tglx@linutronix.de> wrote:
>>
>> Peter Zijlstra <peterz@infradead.org> writes:
>> > On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:
>> >> Any preferences?
>> >
>> > I suppose DTRT, if we then write the Makefile rule like:
>> >
>> > KCSAN_SANITIZE := KCSAN_FUNCTION_ATTRIBUTES
>> >
>> > and set that to either 'y'/'n' depending on the compiler at hand
>> > supporting enough magic to make it all work.
>> >
>> > I suppose all the sanitize stuff is most important for developers and
>> > we tend to have the latest compiler versions anyway, right?
>>
>> Developers and CI/testing stuff. Yes we really should require a sane
>> compiler instead of introducing boatloads of horrible workarounds all
>> over the place which then break when the code changes slightly.
>
> In which case, let me prepare a series on top of -tip for switching at
> least KCSAN to Clang 11. If that's what we'll need, I don't see a
> better option right now.

And for a change that might make this time GCC people look at their open
bugs. :)

/me mumbles jumplabels and goes back to juggle patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k11exq8f.fsf%40nanos.tec.linutronix.de.
