Return-Path: <kasan-dev+bncBAABB243XTXAKGQEN4XU5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 75999FE685
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 21:43:24 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id m15sf6082024otq.8
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 12:43:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573850603; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLSqUWEMBMSLMnH/tcPCZit/+t+ZYc8OaYLn7a33xqRV60bJvb/VRp1HN7MlsMOMWr
         L++HgUacA3JfEuvXoWK2932LJ8ncgGJa0fj5DqTGFt69F4jfSSCZ2r4RME0ngEr+aCFW
         v1Gf/RJrqF364/3qHJ2rW9WwBbzn9aSLMkTLsPJNJz1R7nbeJWOu9OKDeScLcLjkm2qf
         dL/44ilssT9aEl3QuveLkonmfND9+vLddROhunT/LROklv4SeewCDQSWyOGpRdcjutcy
         gci5RJriveMkTK6R8Pauf3jpMKW08cDpZyJAgH2J3HtUr5Ghc5C96SXCcwAg6wqTrHTS
         2PXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=QZfgW058fw1Ib7W4hXqBtcwaNjOzZZTYIB5D5UB3jkU=;
        b=EooNzM4h9/Iox8CAPxpUii0n+EfUSMdyZuLWI5a37jEGkvo0Sr65uNSTIDLmxksOIi
         +oY1L6vwl5QI5VoCuK4T8BFfMO/1akaumM32qPJ4zDqu5+D8Qq+OPBsLbie9KGLHeUWX
         rIdubI8kEfaYHZNHSHKWXfKEl1XpB/+b9YZrXhcYHpGfETYSyzvrLhvrw+TMhIcyLxEs
         r5khlcxqb6PlC3vjH/OCmxiKqnAwmkRdBIwktxlsqidBbzrwGxbvJ7ljK0cdRhb02H7h
         tJOVNI48ZeMjPGPaFTtSYyNQ8XH/1/+qisVYC0gBBNglhCz8FpqHKOFmvKVDnEqx/5h/
         i8Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0DyWlLJk;
       spf=pass (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=oSPD=ZH=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZfgW058fw1Ib7W4hXqBtcwaNjOzZZTYIB5D5UB3jkU=;
        b=cY0Dafdf6GICtGkqx1xBliEcoSOLaAc86afZqga8AWOC2dZvmqJipKNJQXVnF+nNi5
         Dev0+5Q3joZGxRHjokbyCsBocEe4sEuoAnYw1dZtJMkj5bq2jYgShFLiiDeS6ECi3wPJ
         C9Xg+hr82xclJWMzoXcvQiKVvyaB6zP2n5z5vWuokJdemuS0lzJqhvBV2xh5NRN1vNxj
         WvVEq7rteN89uNNdhRw7gvWs3SDyVMOvf2KQLiPBODyNW+qbhN68wD50ffZTm3Mlw3a+
         Tr3MevzwIy9qrYNlGclfdDMuoE6TWs8hlU7drZiCY6ctEMjUzzOOE6STw4fMEQ6a4wew
         zCkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QZfgW058fw1Ib7W4hXqBtcwaNjOzZZTYIB5D5UB3jkU=;
        b=cxXuRwXzb4vjHPWWjwcp2Ken0/OuUNixU9uPmzMf89F0uSDQWEj8C7J7xlJmUMOv6M
         QNtlde+bVqZb2RV6yN5FTaVTUYvTHkQlCkR69LayP1LCODBvPpDpYdfZHEVRIb0/s7mF
         rLCY8SdAE/Up+bSD1bKit3LCZnmqBMlzxv/OOfNSj7RIjZnJeM2ka2K1KoHyuuo9BHU/
         08HKQ/niDrL0dBX0avsPRR+a9ZPAoE9aFXX7mYediD+Chn67we9D4Cuhf2hjGda1hB0t
         mGP/lBq4qVvqnZm9CpwprGfOW4H703Cyly9+Wj+MF3yP6b9r2oFXB5pDBoal6t+UMSsw
         z6Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWA3Lyt5a+5Ewuwk3NRFu0WkkaFAaKJsA5SDURvnVzIsSU62aMl
	7SqD9rxlFLQ3HX4QZ0EfM6U=
X-Google-Smtp-Source: APXvYqyR2hseAn9SjjpX2xD17hFe+NhjPwEkRnlx+piw8XJ8TWTuqZejtlGorLgdWS6bRiVsvCM7ow==
X-Received: by 2002:a9d:3675:: with SMTP id w108mr12952914otb.81.1573850603187;
        Fri, 15 Nov 2019 12:43:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c490:: with SMTP id u138ls3258205oif.6.gmail; Fri, 15
 Nov 2019 12:43:22 -0800 (PST)
X-Received: by 2002:aca:f408:: with SMTP id s8mr9782630oih.69.1573850602824;
        Fri, 15 Nov 2019 12:43:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573850602; cv=none;
        d=google.com; s=arc-20160816;
        b=I2Aql0lLP7iUN2nWXM2QPy98Ym07GRD2doqjgqCpr1ImZ+i+4mVDCOSK+mGEo6riZB
         BWAKsiodhsgKXtFug/6g73odq7ZGkOT9rmBQ2RvJIXAekiRriu3KiZg3vMYIuz4U24uf
         e9Z98BzcOboQOH8GPISsOjY35L9HqGz3WDmClQEEUU2u7hEL1Ro3DuDXG3niBqjYA5vM
         roCcI9bh8I5gbg1oxqaRUpz12x54nQiIP4s3W5+4TkrFArjBSrf5YQRL49ryUXRM7fJS
         BRJCX+Ud7ZahDe7K03rtPvX5NvFW4NO8Soa3eOKVEzK03x0iqwRrwXuf3wZLhNE9kPYh
         tN3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=EhkF6eijMNCpVBpOM/9XbCrRso1VArafA73l7GGvBeI=;
        b=OWikyqRzJV4Du6tPM9nkXxC7fXf7ddxRNqSFYLmPZ8Ya+QPkz1LBMbUbVnHikFDGSE
         KOpj2UdI80NPfR8M2Q8gGkdGgayWhxXe4dQ6tEK501xHYH4QNVbyzkod4d8BW+0Yuff2
         biaPJGPV4zDvSC8/w/SsG9JslGR1MAQvOj3lE4w0eBdntpeB/Xf0wsWGfDQppB182lqO
         Ln8xGiga+cxFa0jzis5QXVziT3OpyZLveIFUlOwh5Bc48X1u32o4ULm4PUD1nKZyYW7y
         ENF9OpLB+QADMhNfSPIsiy2eeS7VcRomxsPD05HzqWta5H/Z+A6ANY9gJlHFmYp+K1g9
         LHQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0DyWlLJk;
       spf=pass (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=oSPD=ZH=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g5si313854oti.4.2019.11.15.12.43.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Nov 2019 12:43:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.141])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E23C720733;
	Fri, 15 Nov 2019 20:43:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 47B2A35207BD; Fri, 15 Nov 2019 12:43:21 -0800 (PST)
Date: Fri, 15 Nov 2019 12:43:21 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Eric Dumazet <edumazet@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191115204321.GX2865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191114180303.66955-1-elver@google.com>
 <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com>
 <20191114221559.GS2865@paulmck-ThinkPad-P72>
 <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
 <20191115164159.GU2865@paulmck-ThinkPad-P72>
 <CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=0DyWlLJk;       spf=pass
 (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=oSPD=ZH=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 15, 2019 at 06:14:46PM +0100, Marco Elver wrote:
> On Fri, 15 Nov 2019 at 17:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Fri, Nov 15, 2019 at 01:02:08PM +0100, Marco Elver wrote:
> > > On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > > > > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> > > > >
> > > > > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > > architectures is relatively straightforward (we are aware of
> > > > > > > experimental ARM64 and POWER support).
> > > > > > >
> > > > > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > > > > integrated the feedback where possible:
> > > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > > >
> > > > > > > The current list of known upstream fixes for data races found by KCSAN
> > > > > > > can be found here:
> > > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > > > >
> > > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > > including several articles that motivate why data races are dangerous
> > > > > > > [1, 2], justifying a data race detector such as KCSAN.
> > > > > > >
> > > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > > [2] https://lwn.net/Articles/799218/
> > > > > >
> > > > > > I queued this and ran a quick rcutorture on it, which completed
> > > > > > successfully with quite a few reports.
> > > > >
> > > > > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > > > > you mentioned, we're fine with your assumption to targeting the next
> > > > > (v5.6) merge window.
> > > > >
> > > > > I've just had a look at linux-next to check what a future rebase
> > > > > requires:
> > > > >
> > > > > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> > > > >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > > > > - bitops-instrumented.h was removed and split into 3 files, and needs
> > > > >   re-inserting the instrumentation into the right places.
> > > > >
> > > > > Otherwise there are no issues. Let me know what you recommend.
> > > >
> > > > Sounds good!
> > > >
> > > > I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> > > > approach is to fix any conflicts during that rebasing operation.
> > > > Does that make sense, or would you prefer to send me a rebased stack at
> > > > that point?  Either way is fine for me.
> > >
> > > That's fine with me, thanks!  To avoid too much additional churn on
> > > your end, I just replied to the bitops patch with a version that will
> > > apply with the change to bitops-instrumented infrastructure.
> >
> > My first thought was to replace 8/10 of the previous version of your
> > patch in -rcu (047ca266cfab "asm-generic, kcsan: Add KCSAN instrumentation
> > for bitops"), but this does not apply.  So I am guessing that I instead
> > do this substitution when a rebase onto -rc1..
> >
> > Except...
> >
> > > Also considering the merge window, we had a discussion and there are
> > > some arguments for targeting the v5.5 merge window:
> > > - we'd unblock ARM and POWER ports;
> > > - we'd unblock people wanting to use the data_race macro;
> > > - we'd unblock syzbot just tracking upstream;
> > > Unless there are strong reasons to not target v5.5, I leave it to you
> > > if you think it's appropriate.
> >
> > My normal process is to send the pull request shortly after -rc5 comes
> > out, but you do call out some benefits of getting it in sooner, so...
> >
> > What I will do is to rebase your series onto (say) -rc7, test it, and
> > see about an RFC pull request.
> >
> > One possible complication is the new 8/10 patch.  But maybe it will
> > apply against -rc7?
> >
> > Another possible complication is this:
> >
> > scripts/kconfig/conf  --syncconfig Kconfig
> > *
> > * Restart config...
> > *
> > *
> > * KCSAN: watchpoint-based dynamic data race detector
> > *
> > KCSAN: watchpoint-based dynamic data race detector (KCSAN) [N/y/?] (NEW)
> >
> > Might be OK in this case because it is quite obvious what it is doing.
> > (Avoiding pain from this is the reason that CONFIG_RCU_EXPERT exists.)
> >
> > But I will just mention this in the pull request.
> >
> > If there is a -rc8, there is of course a higher probability of making it
> > into the next merge window.
> >
> > Fair enough?
> 
> Totally fine with that, sounds like a good plan, thanks!
> 
> If it helps, in theory we can also drop and delay the bitops
> instrumentation patch until the new bitops instrumentation
> infrastructure is in 5.5-rc1. There won't be any false positives if
> this is missing, we might just miss a few data races until we have it.

That sounds advisable for an attempt to hit this coming merge window.

So just to make sure I understand, I drop 8/10 and keep the rest during
a rebase to 5.4-rc7, correct?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115204321.GX2865%40paulmck-ThinkPad-P72.
