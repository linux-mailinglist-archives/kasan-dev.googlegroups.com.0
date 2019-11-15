Return-Path: <kasan-dev+bncBAABBWVKXPXAKGQEQNOQOUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 73643FE2FC
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 17:42:03 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id bz8sf6990896qvb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 08:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573836122; cv=pass;
        d=google.com; s=arc-20160816;
        b=zF2pu53LsvnchGkGkyRuRTdLUdzML0twUXRBZje8FRE4BB1ELmu2uu5t0zH96M2sgt
         wCfJuDVDQ2bNoAUoIF8qYf7xLLxUPwhDk7otkmme71gAVY3vVilyzMMGls6lEHgAAbNs
         w0JesMkXmku3qYSgNqDa+29AsL3BKAFMgJiUPULxdGHqFuL0cFoaYfpu2H6d0Gg0KwGg
         0TiuJp2XbauVx72ST5H8kL6qx/bbYoSbgF5eEC0BdH2tu9QaKyzHYQKThkuUgmo4bnNh
         46fWUVVs5mys7/oOnoePcE72bvadEWPB3EgomewdrZkjE6iMBF6JTfdjFAUZFcMVW7ZN
         RQ6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=w+9OMrAzDboEyFHewZrwznbb1U7O/bQc1VZX67pRSOM=;
        b=P1sxoHq0ElcEqn0ftRNlwKX6TMEpyyPXsd6JN3+yVX5/59kbsTbEaALPquueZMtyxo
         SIt+6ImOqNF+ic5Jdm1co55zqKwXDrRZroRYBXlk5+Km4PXuLDyy5DHVD1UdGCzIz1bF
         LzjrnMuEmHHq4eO9Dyh3YK+QwY/OWois0NAiY9PICSzH9tNC4ikJD4KsssCs6PNSU2Ng
         8LgLTC0qd6IdAoTk23WAVdXNZY4qbLBOtFruKeLy1MaxeJ/fTDKwwX0i8JqA6CyTgToQ
         wxr77fHzpQhf4Ryf2+TXqOGTkHR00Izubz62l7JBAobC+p4DfvnY+R6dQS/dNNuFekbO
         MQMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jKeRzm1C;
       spf=pass (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=oSPD=ZH=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+9OMrAzDboEyFHewZrwznbb1U7O/bQc1VZX67pRSOM=;
        b=WpS4PGKWarc3rm/7yReRPX/YKe0DxgRW1YCjjB5Oq9QD4KPxSUDOoG8JMars3BFDm2
         GeA964sfc2GbHLGTju0Dtn5XNtBDq8aQy15SL2opPs7UVd6OUMl6EjVa7aTOidcXOEh2
         R56Mvee1YWnJ8PsSM9LNsf7eeWWAGr1/i47B8DiFpp80z0+N70VcvEKUlVPsM5B+cU4I
         g6M/XV+6pYRqZW3sQPQlJXOrY9ddctJO/rUsOU93cgeVK5oE64sQiBDskWqowMEL+IYo
         Gdt2uT2pDJoMxetNg3y8b5OqWV1m0WjwwfXPLl9953lR+y/rN8sW5bachsd8SzZChE7C
         RR8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w+9OMrAzDboEyFHewZrwznbb1U7O/bQc1VZX67pRSOM=;
        b=As+M7QGGMExhLmX9zQfq3ijMlrbcnVcFSrSBuvndbvg81o9ERFYOmIxhZAP2zpZYbG
         YJPfEe+i2byvDLcYyrpq+R2frfToHF5VAdVU2ixAnBe9SToDkicJs62b8Zbr8PkuXZaO
         gxy6sbugJr7jp42/TGmx95sDs2mkH7TXiJhi3QbATkkdiIxCnS8WRS72Z7QJT+SjD4rT
         Mp8BGILdp9hX5fpNSsZ5juqfI2i1oJ6pnGA3qPz8F+8XLqOAymLVHZuuzpDoxtbpTLf2
         ChTd3kNdDVG68x9wdMqBak4L3ovhPYS7LsXqIwEnTB+/CLp4LvXxlh7uBj52hTYvt5bz
         DnYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW+SdTrjgWfH5IXtSHyiQ+ojiFXtGfNvOTW3Xl2I9pRjYujvZhc
	VINNfh5iheR3OKT9PfeM+/0=
X-Google-Smtp-Source: APXvYqxOg/f8b3qTrTOV/K+X0gx5yV+y+5OFm4O/40vrnSuHmMce7dgnnmlDoe9kF81YrqC9vy1iDw==
X-Received: by 2002:ac8:7492:: with SMTP id v18mr14690354qtq.282.1573836122329;
        Fri, 15 Nov 2019 08:42:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4f02:: with SMTP id d2ls2369260qkb.9.gmail; Fri, 15 Nov
 2019 08:42:02 -0800 (PST)
X-Received: by 2002:a37:ac09:: with SMTP id e9mr13492089qkm.63.1573836121922;
        Fri, 15 Nov 2019 08:42:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573836121; cv=none;
        d=google.com; s=arc-20160816;
        b=vQYDLWiQel8gsH9wSrGtoTsv9MF7LwfzTiehY5Wy/8cFH4zDathnFGplOPSd5F4t8f
         Jj06QEN/mgkbTRmXfGf8is0lsMshV3sQroRdJxYWzOB6kbhdL3cIRQbSEJZ2h8i/xVHB
         kdDwwVgwb56Gr/iJOxKB6/SmV6vCfauFiNIzqbWIwYb48c4t1OcNvZnUcgGG64ucudLU
         ny6T+gg4x/nuET/JVcoHQGKU1UctAMkZ+RtIrDH6Q8EshspmCxFuTtFiB8xoxXxWhv9P
         ELNj2287yl9XWcX0ZQdVu7x8NRyb5ocY0HoymE23kSqebx/Iu1Bn7fCsSjtHb/fe7C/X
         BENg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+wuETr7391JOEs4yPHwh1LXxyKt5Z2XjOovANARdLD0=;
        b=dQpDxz+hrblkiPAIjTCHgWqBsmrw5vcpGxT2xKCTen6hjVubJ6dJA3C6JLYCE0jKfQ
         22Gucs77JMbvSrjyfGifNp8V0gxVP9yN9x+7qo3kq7bX9cc7AkSUcrz1XDW90feVbTNN
         L+h4mkflm365Afm4QBw+nJsAYsOqu0KB8K2YyqCNDzfJNDZ+PFyZN4SbKUoCRRpNr6Bm
         KEFB/GbezYozbn4vR7ckAQvZCS739YExrcKp7+P5UkYHNOoHTSlZbYn98iys2vIFuxH1
         kGYajO6/JH66c4TSwBI43/cS1ob/sG0U21oCaIs6Qo0oSueO0VQOjPO9aNkCTTdB1xnU
         FBNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jKeRzm1C;
       spf=pass (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=oSPD=ZH=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x6si491415qkl.7.2019.11.15.08.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Nov 2019 08:42:01 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ospd=zh=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.129])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9D54220718;
	Fri, 15 Nov 2019 16:42:00 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id F1C0035207BD; Fri, 15 Nov 2019 08:41:59 -0800 (PST)
Date: Fri, 15 Nov 2019 08:41:59 -0800
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
Message-ID: <20191115164159.GU2865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191114180303.66955-1-elver@google.com>
 <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com>
 <20191114221559.GS2865@paulmck-ThinkPad-P72>
 <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=jKeRzm1C;       spf=pass
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

On Fri, Nov 15, 2019 at 01:02:08PM +0100, Marco Elver wrote:
> On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> > >
> > > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > architectures is relatively straightforward (we are aware of
> > > > > experimental ARM64 and POWER support).
> > > > >
> > > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > > integrated the feedback where possible:
> > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > >
> > > > > The current list of known upstream fixes for data races found by KCSAN
> > > > > can be found here:
> > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > >
> > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > including several articles that motivate why data races are dangerous
> > > > > [1, 2], justifying a data race detector such as KCSAN.
> > > > >
> > > > > [1] https://lwn.net/Articles/793253/
> > > > > [2] https://lwn.net/Articles/799218/
> > > >
> > > > I queued this and ran a quick rcutorture on it, which completed
> > > > successfully with quite a few reports.
> > >
> > > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > > you mentioned, we're fine with your assumption to targeting the next
> > > (v5.6) merge window.
> > >
> > > I've just had a look at linux-next to check what a future rebase
> > > requires:
> > >
> > > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> > >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > > - bitops-instrumented.h was removed and split into 3 files, and needs
> > >   re-inserting the instrumentation into the right places.
> > >
> > > Otherwise there are no issues. Let me know what you recommend.
> >
> > Sounds good!
> >
> > I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> > approach is to fix any conflicts during that rebasing operation.
> > Does that make sense, or would you prefer to send me a rebased stack at
> > that point?  Either way is fine for me.
> 
> That's fine with me, thanks!  To avoid too much additional churn on
> your end, I just replied to the bitops patch with a version that will
> apply with the change to bitops-instrumented infrastructure.

My first thought was to replace 8/10 of the previous version of your
patch in -rcu (047ca266cfab "asm-generic, kcsan: Add KCSAN instrumentation
for bitops"), but this does not apply.  So I am guessing that I instead
do this substitution when a rebase onto -rc1..

Except...

> Also considering the merge window, we had a discussion and there are
> some arguments for targeting the v5.5 merge window:
> - we'd unblock ARM and POWER ports;
> - we'd unblock people wanting to use the data_race macro;
> - we'd unblock syzbot just tracking upstream;
> Unless there are strong reasons to not target v5.5, I leave it to you
> if you think it's appropriate.

My normal process is to send the pull request shortly after -rc5 comes
out, but you do call out some benefits of getting it in sooner, so...

What I will do is to rebase your series onto (say) -rc7, test it, and
see about an RFC pull request.

One possible complication is the new 8/10 patch.  But maybe it will
apply against -rc7?

Another possible complication is this:

scripts/kconfig/conf  --syncconfig Kconfig
*
* Restart config...
*
*
* KCSAN: watchpoint-based dynamic data race detector
*
KCSAN: watchpoint-based dynamic data race detector (KCSAN) [N/y/?] (NEW)

Might be OK in this case because it is quite obvious what it is doing.
(Avoiding pain from this is the reason that CONFIG_RCU_EXPERT exists.)

But I will just mention this in the pull request.

If there is a -rc8, there is of course a higher probability of making it
into the next merge window.

Fair enough?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115164159.GU2865%40paulmck-ThinkPad-P72.
