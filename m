Return-Path: <kasan-dev+bncBAABB7U7373AKGQERPN3WGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE851ED460
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 18:29:51 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id r2sf2882039pgd.23
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 09:29:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591201790; cv=pass;
        d=google.com; s=arc-20160816;
        b=XZ/xta5UdDX6TZNHcsbQi9QmOa60dE7RU7JjLSEjugmSbFJod8yv6KwbCQs5F3Oq5u
         CDX40CJKyZJpkoq5hDiL6Dz2BWWIvxt6ZEc4w49mAcOs3Nh5XvorL/qln6XwMpqB4uXt
         W0r321V4f98PxvBrif17k5z7V5KzGUKbJnrtD8X3dLKg8CHK5zeHMyChyfSN9Jzlszsk
         bicuVQPYs7i51RUOwTOz5hL9Zl7x8A2Xa5JmH/UxluFk/T+xBYjJ0kDsfXRiBvjhUlJ+
         5bQh19uJayt3c6R7k5OQ4e1xFccMCvMkkDWD4OsgzvZjsvDDEbUQLs0bQbaW6IWo9uyC
         ZDcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=OiAL1RIpnVFTtH9VEUhxXUfYvFZ+eV5xCwGgdWn2j94=;
        b=cSjv61NEoBJiQ6/zX7GP5wvP/F7uDZowHD0ffzBuaKpILF2UYJ95Ge29rL/dhrUmJt
         xbhgrQYND3g9gXBj0cEpVPRZ38vFv3/1muzfsqotDm3j1nhfkK17kYYE0BWPU1rfK2Px
         Dq3qkY+e/VE3q9AtQQvNeOV88iSdiA55BizxKv8whRmT2Ac7oDfF6Mkryz1LM5hKQPlm
         VOXOiIi+/b9Ewhzhl/C8KQJiFhlsqGqDyu57Q180qBF5IBmW6+Inc0nusoPNAzC5QYq0
         AHyJ11rvyZYqBp+BrDygtpN2ZOUi+7r60LpQmtpcaL1XoXaJzbn6nInG8oUAA1T3jjKd
         VCRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="TSOOj/h7";
       spf=pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OiAL1RIpnVFTtH9VEUhxXUfYvFZ+eV5xCwGgdWn2j94=;
        b=eY8vkYoppriEQTUgkj2G2KSS4vE23jQtVWUEG/x/YyexxcsRc1D1KZ5Bw/ks9SXhWJ
         c+JvMGDnFQaROTZPG4EG+JlxMLCFLuhCTHYOhrowe0UGk34bRTEHw1gicQF8zDnsUcSJ
         HVVtshUR9SvR5EllyNgwTU2IuNOq0st9QXOBMFISTJJs4zGGYFA2IqFK6uhM85a/8YaD
         xvSsL4+LhVsqq9QgoXzaSNmgHnjD+A9g3mDfnnKOIvg+La9P8m/DdS4ZOjLqUg54yLsZ
         4Lb6kJhFQ742tocCCljfaWSHf8lcGR19DTFk1bwZ+RuPup3X2A+OpcICeYCBWRM3LPpr
         /kIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OiAL1RIpnVFTtH9VEUhxXUfYvFZ+eV5xCwGgdWn2j94=;
        b=nWRs7kk0bGO/2w/OOZcxMyN3ZVTqgv5HH5yC4nZzDdGiRFgRuRzI+O3qQXLHZQyFkD
         XhovYilxGW71D4mf13KTRUaVYRN42ORKmO7vITg/6Th/9/92TKuuVYdxV+gQI7XJY8RA
         +yH4DpUyDoZ7r/plXFU9lFY6aaGLxXgcs4qoi5KboDmhVkgRsV6RLanxwmeK/pdTFwhB
         5N6DNRJXnt0mVoll7rexWSN8bF2GnFx2/rrxGjA1JamSfR1viMH1SWL++Gm2+392eJc+
         K1x3C4s/f/KN1tfFs4XuZ6EDVIo/CyrqFEW7kL3D+mNNcS+V8cslf1hC8O+5XCbb+rNL
         /MJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Odv3hcu3TehuGxeQMD3zYfGekEJamsCNI6iyatdvV9qhxQJnl
	7la96YvgOoPWlwEC4IArGxA=
X-Google-Smtp-Source: ABdhPJwBEvSHXLTMcsmcthyf53dOAzERwIaAYBx08IomQ+Tey1aX5kc4Z9+uu7T6fGzzkSoy5sDN9Q==
X-Received: by 2002:a17:90a:aa8d:: with SMTP id l13mr706465pjq.92.1591201790500;
        Wed, 03 Jun 2020 09:29:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:178e:: with SMTP id 136ls829184pfx.2.gmail; Wed, 03 Jun
 2020 09:29:50 -0700 (PDT)
X-Received: by 2002:aa7:8ecd:: with SMTP id b13mr15631522pfr.297.1591201790121;
        Wed, 03 Jun 2020 09:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591201790; cv=none;
        d=google.com; s=arc-20160816;
        b=x+IkiUIIIlTnl+73TJlriEaxLUj9cdu/AQKXgPKOhLO4GG6KyAcu+NjbeZXyWm8VK3
         fW8eA+JnnczF4UQgjExPDGloDZ6X9kjSZGoFLAEle3GgTxdQJJC5q3tmNbeoDeaXsj3S
         0hcD/W2fH4fUrz7y+6r83w2031lgZugr7RqC4CuB4d/67rJqeDKuCd8qSpMqvzmNPLF5
         Fgv+i25QiBSYs1QK0uMYJlpQinG9E8Brt/AfrR2bkAqt6kThlEUpBGk8ZWLGo7FpiiXl
         /m7WKVXqqG2QHuwrcI3b/L8J+yCws12osl82GaXtzGh8OVQTkoF6i9LgVDnGv+eFg6BS
         e5Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pGtn01Ejxv4U5A8NN+buYh4/UyvofPXF8HV+4s2Dc8A=;
        b=QfGBDHCHYhdoOx18xoxeYnY11YThFrNyU0Tiw3qbPapT27hH8Y+lCqGeSrNdMDqBew
         +4QYrvl5BkXNP0Q+Na+ywdYKqnYHqLPaEXZZB/EXhtMyfiEKNkDbrTYLwjWpHqjcFMaL
         Vafc60cDfTER8krNIM6Xa5igQ270oVsw4/hKp07/qi9m/YoBQZPQ5gyOVJdw2mUmaWpf
         kQHMpZwS257YJTuf+rTj8HoXSby8mrvBL3MKCTqVhNmHW/E9y8YhPlxL5p9mIuOSes9e
         4/WsIYWbCv2+5+mx3UNso8nlyGZ804n1Jt8WZ57KPcXusKrObTMrPBqnVT4EgIVPqBtl
         XLPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="TSOOj/h7";
       spf=pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id gv9si270641pjb.3.2020.06.03.09.29.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jun 2020 09:29:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C70CF20659;
	Wed,  3 Jun 2020 16:29:49 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id AD32D35209C5; Wed,  3 Jun 2020 09:29:49 -0700 (PDT)
Date: Wed, 3 Jun 2020 09:29:49 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Will Deacon <will@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] rcu: Fixup noinstr warnings
Message-ID: <20200603162949.GP29598@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200602184409.22142-1-elver@google.com>
 <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
 <20200602191936.GE2604@hirez.programming.kicks-ass.net>
 <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
 <20200602193853.GF2604@hirez.programming.kicks-ass.net>
 <20200603084818.GB2627@hirez.programming.kicks-ass.net>
 <20200603095932.GM29598@paulmck-ThinkPad-P72>
 <20200603105206.GG2604@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603105206.GG2604@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="TSOOj/h7";       spf=pass
 (google.com: domain of srs0=w7he=7q=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=w7he=7Q=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jun 03, 2020 at 12:52:06PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 03, 2020 at 02:59:32AM -0700, Paul E. McKenney wrote:
> > On Wed, Jun 03, 2020 at 10:48:18AM +0200, Peter Zijlstra wrote:
> > > On Tue, Jun 02, 2020 at 09:38:53PM +0200, Peter Zijlstra wrote:
> > > 
> > > > That said; noinstr's __no_sanitize combined with atomic_t might be
> > > > 'interesting', because the regular atomic things have explicit
> > > > annotations in them. That should give validation warnings for the right
> > > > .config, I'll have to go try -- so far I've made sure to never enable
> > > > the *SAN stuff.
> > > 
> > > ---
> > > Subject: rcu: Fixup noinstr warnings
> > > 
> > > A KCSAN build revealed we have explicit annoations through atomic_t
> > > usage, switch to arch_atomic_*() for the respective functions.
> > > 
> > > vmlinux.o: warning: objtool: rcu_nmi_exit()+0x4d: call to __kcsan_check_access() leaves .noinstr.text section
> > > vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> > > vmlinux.o: warning: objtool: rcu_nmi_enter()+0x4f: call to __kcsan_check_access() leaves .noinstr.text section
> > > vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x2a: call to __kcsan_check_access() leaves .noinstr.text section
> > > vmlinux.o: warning: objtool: __rcu_is_watching()+0x25: call to __kcsan_check_access() leaves .noinstr.text section
> > > 
> > > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > 
> > This one does not apply cleanly onto the -rcu tree's "dev" branch, so
> > I am guessing that it is intended to be carried in -tip with yours and
> > Thomas's patch series.
> 
> Right, I've not played patch tetris yet so see how it should all fit
> together. I also didn't know you feel about loosing the instrumentation
> in these functions.

It would be very good for KCSAN to be able to detect misuse of ->dynticks!

> One option would be do add explicit: instrument_atomic_write() calls
> before instrument_end() / after instrument_begin() in
> the respective callers that have that.

One good thing: The atomic_andnot() goes away in -rcu patches slated
for v5.9.  However, the others remain.

So if today's -next is any guide, this instrument_atomic_write()
would be added (for one example) in the functions that invoke
rcu_dynticks_eqs_enter(), since it is noinstr.  Rather annoying, and
will require careful commenting.  But there are only two such calls and
they are both in the same file and it is very low-level code, so this
should be doable.

I should also add some commentary to the RCU requirements document
say why all of this is happening.

> Anyway, I'll shortly be posting a pile of patches resulting from various
> KCSAN and KASAN builds. The good news is that GCC-KASAN seems to behave
> quite well with Marco's patches, the bad news is that GCC-KASAN is
> retarded wrt inline and needs a bunch of kicks.
> 
> That is, it out-of-lines:
> 
> static inline bool foo(..)
> {
> 	return false;
> }
> 
> just because..

Compilers!!!  :-/

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603162949.GP29598%40paulmck-ThinkPad-P72.
