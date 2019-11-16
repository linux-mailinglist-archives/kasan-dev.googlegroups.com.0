Return-Path: <kasan-dev+bncBAABBH5OYDXAKGQESPP4YYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 722C3FECE8
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 16:34:57 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id x9sf8276567plv.2
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 07:34:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573918496; cv=pass;
        d=google.com; s=arc-20160816;
        b=ukExJATValciwbbKrdDue5n3ehXQXy9Nl3RVQ3Fb7cQejckbw7QSUEDjNuaD6GSAxO
         siazZJ/1s5q6FnfrzgRcv7ZoggATujjxFqSu8cgAz2F3JOU7lfEHFNuSaNh0T8Rj1BoB
         671Bi6MmNBJAF8arKwIvnVHmnRCiip9syx0TsSFMbtK5Waf0+ravRkX2KvN3wH5VZxKb
         ZkYwVJzTj7CXu3QOdVediGP22OvCN1WaxdLyd5TlhiJ6baLeI5NowteUYd14ofN16tgK
         PmZcI2nr9eaHoc/kwlXuGofgxOVIWO0PQUtmQllzU9PY8DWPmbzwMOuWpUv9Aul5X03C
         iRvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=BUYRTKudYPYcYMBkuETdF/LtuVxrUvwDyj7WhRgawSM=;
        b=cblqfar+0vlg3cew5/JovGgo/Retq3fD6x+F/EFKA94OLJvfsOc/7ok9H1usOwSNvX
         Lw+c12uZm9xZKTUiEYNjGj4y/XWwfT0sYsezavZecOrFU/wfbFx5vO210/BOcTJZNo4p
         Lxe44i31k/v5tJYqzu2EwKW1p3NvPQYbIH7CRxnyes8BDEBDuHGVJlw48uMfCwn2eaXn
         o06lQL9JfwDY4Dgzu/CtRoB3Amzwi3eJTlLd9Ld0QBmJ9nLcuD0XlPTowe0Wv0Edy+CU
         pcOSSkLzm0FQ2PpurqSQczFGGg+wFe20phDW00fomasy7N6w91XdymP9rsjfWMNuE3sN
         Wupg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=X3NPg89c;
       spf=pass (google.com: domain of srs0=wwul=zi=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wwUL=ZI=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BUYRTKudYPYcYMBkuETdF/LtuVxrUvwDyj7WhRgawSM=;
        b=I/3iN/SxqOQx8cCv3Hgoh8HY2k/kR+hDBV8nI+5snFgccifmJtTml6MdLjQLrMj6E+
         vROmB76LGvKm9qeKQj0sSbARYOMvEPzZKsYXO9O39F6LKc2VBZIjx4HMK00kibAHbxWs
         vcnemwZ83VTPxyucL5Z8gpuyM7VtOnB0iJOaKGnO4r0DpYsOGzohm5zYgIwT1mDSpEg/
         /fNXjqCDDcFvLUlE8J1WHnsW4tJc2u9ujR5R+joALf64SMxjKWTgPtL1ddFHZ9eHBG8K
         xU1QeqXXP2F8ui8y9EP/i1y2siWQb7AeApF9tAeQA0E3vmENVOsnCMmuECDLZQOXHeKw
         yxCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BUYRTKudYPYcYMBkuETdF/LtuVxrUvwDyj7WhRgawSM=;
        b=Z4leyZ4pLi+UrLOOPoq/FK6As7wKIgo5S1C4cDCyC7kXN6y/NjkV3N/OnJSnWdH1NS
         ZLgtgQCxFECkWXjpTbsdHbWI2MO8hZdWWDoX6M+n052syTYAK5VG3k8AT33aKqmzQO7U
         trLPGeITx6zSaEQH3DxbWqWxd4kl/fFyZV58FutIPN/a6NShNPs2PBq9VjYGsC8dS3QM
         JB/BAuTIedi24+od1NHBEACrh4zjlEP29uykjgK7mRplkcxV+p6PuYE+e80hO+2FvMwS
         TlhSMkAy+I1/XFMKWCYLrLmR/AKydB6JZt8WHtWMXo3XqekshG+aI06BqRgXdd0seZ4T
         HFnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV3eCpGHJfWie3nybrf2xVtUs+hQ2J0MgeYaIy3bKZPBTZi7gUp
	uxdzykje0JldtvXtcYCsmQA=
X-Google-Smtp-Source: APXvYqyV1JnB8lPCznWq+5Hq6Z77qTjCQsiiGXlfYTGqh8tBt+NJTioUDFydUF0rVCb8S6ekSQ8R+w==
X-Received: by 2002:a62:7dce:: with SMTP id y197mr24152179pfc.164.1573918495639;
        Sat, 16 Nov 2019 07:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:216c:: with SMTP id a99ls2802042pje.5.gmail; Sat, 16
 Nov 2019 07:34:55 -0800 (PST)
X-Received: by 2002:a17:902:bcc6:: with SMTP id o6mr1027742pls.1.1573918495205;
        Sat, 16 Nov 2019 07:34:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573918495; cv=none;
        d=google.com; s=arc-20160816;
        b=NDacCNycgMSXjaYBAKBsI9UypaO91dBs1KVsy2BMrC8Zg+Ilm2vMRpdCrMkFoFhpka
         wptW/LFEynYrimhoU/Wg3T8TIxgG/AR2FLe2RUoAG9RowT5xva/thOVdNkU6AYaqHJdj
         58T27oNy64X4wnJTNWYkdNftuhPaetTGWrFOyYlF7zKo+aRCtyNoExERYCeexUQHEh7f
         SbaRbzzRq04OdSu/Ec1gREJCRyGR0xXkxbOLJsY80hIk8QPnRJhM7PtQ/hx54stcNkEV
         en5ZyIDUoVlxSdLHsR9c4AGqkLy41C1SJbj0EuE1t3KbUJakLZ9xTYrw3UBmW/bi5PzK
         gM1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=UvTxC7IxJAhWwWkkbdg3qS0FuqKtvfnyWHddp9gYbqA=;
        b=0xlQ3HrdYN7hHUvI3exeXir3M0bSoCJUHCuV733LEffSw8yK0vRBYVjvYF+75/C10P
         k06iZpHMHp1suInCRlYp3W+/ZaRz7kIrGmG7IPYMUgmoyzGqe1DwXMclta8WWLqazRjB
         xyE73zrya6Qa9ptTEhzHW4DpJy769HF6YUmFUxSnylVDJd9x1nqVOgll1ccLVxGWptRg
         0SKGkjTSQ1JRlFBi79yaDjnwcfs7pwSENEi4WijcYErbv8bRbcgwmKvtDXlcQfvg8y6n
         wu44FYqzfdDZj3K+OJ5iNH7fCH2G/WNW7H/j/Q4Fh4Q2wIJTi1IW8bzRq0vdraUjKcrz
         vH0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=X3NPg89c;
       spf=pass (google.com: domain of srs0=wwul=zi=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wwUL=ZI=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r20si701208pfc.3.2019.11.16.07.34.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 16 Nov 2019 07:34:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wwul=zi=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C127720700;
	Sat, 16 Nov 2019 15:34:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 940BA35227AD; Sat, 16 Nov 2019 07:34:54 -0800 (PST)
Date: Sat, 16 Nov 2019 07:34:54 -0800
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
Message-ID: <20191116153454.GC2865@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191114180303.66955-1-elver@google.com>
 <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com>
 <20191114221559.GS2865@paulmck-ThinkPad-P72>
 <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
 <20191115164159.GU2865@paulmck-ThinkPad-P72>
 <CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ@mail.gmail.com>
 <20191115204321.GX2865@paulmck-ThinkPad-P72>
 <CANpmjNN0JCgEOC=AhKN7pH9OpmzbNB94mioP0FN9ueCQUfKzBQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN0JCgEOC=AhKN7pH9OpmzbNB94mioP0FN9ueCQUfKzBQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=X3NPg89c;       spf=pass
 (google.com: domain of srs0=wwul=zi=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wwUL=ZI=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Sat, Nov 16, 2019 at 09:20:54AM +0100, Marco Elver wrote:
> On Fri, 15 Nov 2019 at 21:43, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Fri, Nov 15, 2019 at 06:14:46PM +0100, Marco Elver wrote:
> > > On Fri, 15 Nov 2019 at 17:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > >
> > > > On Fri, Nov 15, 2019 at 01:02:08PM +0100, Marco Elver wrote:
> > > > > On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > >
> > > > > > On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > > > > > > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> > > > > > >
> > > > > > > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > > > > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > > > > architectures is relatively straightforward (we are aware of
> > > > > > > > > experimental ARM64 and POWER support).
> > > > > > > > >
> > > > > > > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > > > > > > integrated the feedback where possible:
> > > > > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > > > > >
> > > > > > > > > The current list of known upstream fixes for data races found by KCSAN
> > > > > > > > > can be found here:
> > > > > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > > > > > >
> > > > > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > > > > including several articles that motivate why data races are dangerous
> > > > > > > > > [1, 2], justifying a data race detector such as KCSAN.
> > > > > > > > >
> > > > > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > > > > [2] https://lwn.net/Articles/799218/
> > > > > > > >
> > > > > > > > I queued this and ran a quick rcutorture on it, which completed
> > > > > > > > successfully with quite a few reports.
> > > > > > >
> > > > > > > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > > > > > > you mentioned, we're fine with your assumption to targeting the next
> > > > > > > (v5.6) merge window.
> > > > > > >
> > > > > > > I've just had a look at linux-next to check what a future rebase
> > > > > > > requires:
> > > > > > >
> > > > > > > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> > > > > > >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > > > > > > - bitops-instrumented.h was removed and split into 3 files, and needs
> > > > > > >   re-inserting the instrumentation into the right places.
> > > > > > >
> > > > > > > Otherwise there are no issues. Let me know what you recommend.
> > > > > >
> > > > > > Sounds good!
> > > > > >
> > > > > > I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> > > > > > approach is to fix any conflicts during that rebasing operation.
> > > > > > Does that make sense, or would you prefer to send me a rebased stack at
> > > > > > that point?  Either way is fine for me.
> > > > >
> > > > > That's fine with me, thanks!  To avoid too much additional churn on
> > > > > your end, I just replied to the bitops patch with a version that will
> > > > > apply with the change to bitops-instrumented infrastructure.
> > > >
> > > > My first thought was to replace 8/10 of the previous version of your
> > > > patch in -rcu (047ca266cfab "asm-generic, kcsan: Add KCSAN instrumentation
> > > > for bitops"), but this does not apply.  So I am guessing that I instead
> > > > do this substitution when a rebase onto -rc1..
> > > >
> > > > Except...
> > > >
> > > > > Also considering the merge window, we had a discussion and there are
> > > > > some arguments for targeting the v5.5 merge window:
> > > > > - we'd unblock ARM and POWER ports;
> > > > > - we'd unblock people wanting to use the data_race macro;
> > > > > - we'd unblock syzbot just tracking upstream;
> > > > > Unless there are strong reasons to not target v5.5, I leave it to you
> > > > > if you think it's appropriate.
> > > >
> > > > My normal process is to send the pull request shortly after -rc5 comes
> > > > out, but you do call out some benefits of getting it in sooner, so...
> > > >
> > > > What I will do is to rebase your series onto (say) -rc7, test it, and
> > > > see about an RFC pull request.
> > > >
> > > > One possible complication is the new 8/10 patch.  But maybe it will
> > > > apply against -rc7?
> > > >
> > > > Another possible complication is this:
> > > >
> > > > scripts/kconfig/conf  --syncconfig Kconfig
> > > > *
> > > > * Restart config...
> > > > *
> > > > *
> > > > * KCSAN: watchpoint-based dynamic data race detector
> > > > *
> > > > KCSAN: watchpoint-based dynamic data race detector (KCSAN) [N/y/?] (NEW)
> > > >
> > > > Might be OK in this case because it is quite obvious what it is doing.
> > > > (Avoiding pain from this is the reason that CONFIG_RCU_EXPERT exists.)
> > > >
> > > > But I will just mention this in the pull request.
> > > >
> > > > If there is a -rc8, there is of course a higher probability of making it
> > > > into the next merge window.
> > > >
> > > > Fair enough?
> > >
> > > Totally fine with that, sounds like a good plan, thanks!
> > >
> > > If it helps, in theory we can also drop and delay the bitops
> > > instrumentation patch until the new bitops instrumentation
> > > infrastructure is in 5.5-rc1. There won't be any false positives if
> > > this is missing, we might just miss a few data races until we have it.
> >
> > That sounds advisable for an attempt to hit this coming merge window.
> >
> > So just to make sure I understand, I drop 8/10 and keep the rest during
> > a rebase to 5.4-rc7, correct?
> 
> Yes, that's right.

Very good, I just now pushed a "kcsan" branch on -rcu, and am running
rcutorture, first without KCSAN enabled and then with it turned on.
If all that works out, I set my -next branch to that point and see what
-next testing and kbuild test robot think about it.  If all goes well,
an RFC pull request.

Look OK?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191116153454.GC2865%40paulmck-ThinkPad-P72.
