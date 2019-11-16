Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXWYDXAKGQEZKTA2YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF6D7FF489
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 19:09:35 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id q78sf6802913oic.0
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 10:09:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573927774; cv=pass;
        d=google.com; s=arc-20160816;
        b=yC0nGPqF+szlJF1W+4UAgp4356LfLyUBbEmZJLeut0QRG9G2x1UePYCoBiyAWRdNEI
         dAJWaoLLNsan/sbPu9DRArb8t54H31/Rzgr5AmnGp+QZUSjNrdmYY02nj6F7/40SUwxE
         EQS3ciDHOs14gM8KGPppc2YqUoY8nXNTxBoii4+lE9uYtWdWEqhACBxxywD06sBVezTg
         MJJRrfI2H9hYNyZNkQspjIBtgdNgDnrsy2ibY0L4mucOcFtUv+eHUSeyWr7Sr8plKo4J
         KZ887CvYJRwKAUt4jcPNqnqvSIB5lkZF7n/brLZbx3ndazh2kLZqw5OOOuePL9OlWFZi
         JyVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+yrt/0VPf7w48gBDf0e3EzZSyWaUsnGACNE732z/jtc=;
        b=iefgaeYYj1CsH9ZjKqSkJrZM73ut/ev4EDuwdbepeRGTh7nk6+ofyFdeZGtU3MzMnZ
         /zcq5oVU6lEtvrK/GlZPAkRrLy4r/ckGj0Ql1Rfr/tjWI0wNl3EyopGrFcexOa4yduPD
         xIyT0CAPeBC6dOAykxHrUyBx2Hyzv4vMO8JL42ilshY6XhCScJIEiAS18Tt6N0lKsCry
         NQR2J8+n/zcZOCPRu/7//hWwhPHFxyT8XI1sIVtY4GqOSkSOKiqgmt+3Vx7Tx02qpkBg
         JU7AslZgYfDPE4XVUbO/ybI+c5rZD6ueWU1OJPY4fUd0myuwHa73uda2SipaZfGLBMw2
         BwwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dQ/Yo/q5";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+yrt/0VPf7w48gBDf0e3EzZSyWaUsnGACNE732z/jtc=;
        b=B2XWmeqpOD70CJt4n3eQ/5/BTYLsfN/mUaPGfy8r+U0bA3MsakZcxtlq5s2deTmJ2R
         if7m/C4JxzUEeJM+uny63hrg2VL7O9F4kqBoA9S6DPMGjV7BAJ7rymau7fwVBQJE6pFn
         XIHILxCu0R2JijjHSqunxbmgF0kBcEBpsfmNY3CcW6TA9O4s2f5IMFyzP+D+shq2UBG8
         UpBhlpdHeug1tjf6vDqGz9GFGZCaW+UX0Gux5lCtfhAsibSMnbL764mZ9fEUsPJExmyh
         kwSvGzGDxRvEFjeE+gSeXmGF5riXg6oAiH1iG/CZk5kOMarBl6ViwCwCGbzI1NwQJGra
         h4gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+yrt/0VPf7w48gBDf0e3EzZSyWaUsnGACNE732z/jtc=;
        b=Qe4J72yk5N7ftq670lCR2QrXnuRnL3EZk45e6CiVmXGNhJfKKcgKro+vJ7naP0GMSw
         0x7bVgZzpn3yEhS59uj2GfuadhQdaNHjUUl2QqQ0vUJ4npEcR6nJNFHvygiKcaMvkeFl
         UHwYtFQxAwFXJqGysxbYXDwbIOriCdvmkn22C4Zj1Bs2loYNX0nkfTHLa5ctumbhIkkc
         VCAfKa6RizGwrRtdO981HwRjY3sFDgSqcVr59QiexYPW/PlvybZuspfWW5u4Nw/UQCA0
         +Ap6zJFpaOt4klCPyaff8rC1OwXGN29pnjAHyBJkz6DMjE5v3ZjbamLZ6lo4mfwiBkHf
         o8lQ==
X-Gm-Message-State: APjAAAViZ8djDlL5DlxqjOr9OiNcfpDULXqoayo7ZtH9UAUxcu7UGLLR
	VBCccrt8Cr7Op6WOQXvoYbk=
X-Google-Smtp-Source: APXvYqxExZys4T2hQjIXKydttTlQ9bMQByDHHTwsFSmwLOp02AMi3XTyLulfaQueVbwew/YCzA3Vqw==
X-Received: by 2002:aca:f0c1:: with SMTP id o184mr13458723oih.2.1573927774661;
        Sat, 16 Nov 2019 10:09:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:68d7:: with SMTP id i23ls3357960oto.15.gmail; Sat, 16
 Nov 2019 10:09:34 -0800 (PST)
X-Received: by 2002:a9d:61cd:: with SMTP id h13mr16705521otk.196.1573927774165;
        Sat, 16 Nov 2019 10:09:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573927774; cv=none;
        d=google.com; s=arc-20160816;
        b=NmW84JbuiV8kNWk3CU6B6nR28hmO9ywD0NwK+wcdUmSDX34rAGDaTxOGwf69bUgark
         j9sFmrxnGoAcweF9Ybm0p9PJMPErOrV/5dpJGbzKkWgIERGijhYpl0crjrS5EHBdUiQS
         Rzccm/28w8mJR4qFpXhQMYf55YQYiJDYpMfdD++LVPYtytqQCGowdOkASIXPNftfXO8y
         Q7nDekdZIHR8pcHBFw/tyjqPXmWUGhlvdPpCx2VLsd0NXP9hBZ75xWox8gaGZUKFOJb8
         hZ0Bu8NWOhR0HsvMRWeDYGU4U3OmFaRbvg1C3un0E1Lil17cFsDlXeTL/pftUO/imliZ
         5Y3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qrMbgYVfZEtHoZFiDZ3fpmazBC6XO24Xvng1lx97mZg=;
        b=ToK2vIC0SLQdXWs7361GvDhyD7sM7/ux+aP+2d1PG6jDWz+dogicQfhBHFFxisy3Uh
         vm47HpG0eo0plNoD+V+8rJpIONmVnlnNKHAaJROToUC0In7ea0+jF0D+dFVlWqPN8Mt3
         U9zIPoZWAIfUcb2xSRZmh/Fflm3L/jf2OdUltE+VCYLJbinBtMC3ijON84XE1P2KFpAe
         OAkxdTKPFTp+cjfgTQKgsgDIHpXYTLSvv3LDGyS1kTtBlLWU2ldoNcOSzdUMmMXkV5eX
         lJhKp6KPy1Qk0sLmEIXo/So03Ug3eWO/Hi2fRZzcLC7Uw7E+oV+ykqZrLKe6jdrDPB5k
         JNxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dQ/Yo/q5";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id 144si681185oii.2.2019.11.16.10.09.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Nov 2019 10:09:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id m193so11622123oig.0
        for <kasan-dev@googlegroups.com>; Sat, 16 Nov 2019 10:09:34 -0800 (PST)
X-Received: by 2002:aca:d80b:: with SMTP id p11mr9329370oig.83.1573927773330;
 Sat, 16 Nov 2019 10:09:33 -0800 (PST)
MIME-Version: 1.0
References: <20191114180303.66955-1-elver@google.com> <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com> <20191114221559.GS2865@paulmck-ThinkPad-P72>
 <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
 <20191115164159.GU2865@paulmck-ThinkPad-P72> <CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ@mail.gmail.com>
 <20191115204321.GX2865@paulmck-ThinkPad-P72> <CANpmjNN0JCgEOC=AhKN7pH9OpmzbNB94mioP0FN9ueCQUfKzBQ@mail.gmail.com>
 <20191116153454.GC2865@paulmck-ThinkPad-P72>
In-Reply-To: <20191116153454.GC2865@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 16 Nov 2019 19:09:21 +0100
Message-ID: <CANpmjNM6NT3bA07h5L9HNMzFY83Nd-yZRzum9-ykd4pW58kNOQ@mail.gmail.com>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dQ/Yo/q5";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Sat, 16 Nov 2019 at 16:34, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Sat, Nov 16, 2019 at 09:20:54AM +0100, Marco Elver wrote:
> > On Fri, 15 Nov 2019 at 21:43, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Fri, Nov 15, 2019 at 06:14:46PM +0100, Marco Elver wrote:
> > > > On Fri, 15 Nov 2019 at 17:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > >
> > > > > On Fri, Nov 15, 2019 at 01:02:08PM +0100, Marco Elver wrote:
> > > > > > On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > >
> > > > > > > On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > > > > > > > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> > > > > > > >
> > > > > > > > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > > > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > > > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > > > > > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > > > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > > > > > architectures is relatively straightforward (we are aware of
> > > > > > > > > > experimental ARM64 and POWER support).
> > > > > > > > > >
> > > > > > > > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > > > > > > > integrated the feedback where possible:
> > > > > > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > > > > > >
> > > > > > > > > > The current list of known upstream fixes for data races found by KCSAN
> > > > > > > > > > can be found here:
> > > > > > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > > > > > > >
> > > > > > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > > > > > including several articles that motivate why data races are dangerous
> > > > > > > > > > [1, 2], justifying a data race detector such as KCSAN.
> > > > > > > > > >
> > > > > > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > > > > > [2] https://lwn.net/Articles/799218/
> > > > > > > > >
> > > > > > > > > I queued this and ran a quick rcutorture on it, which completed
> > > > > > > > > successfully with quite a few reports.
> > > > > > > >
> > > > > > > > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > > > > > > > you mentioned, we're fine with your assumption to targeting the next
> > > > > > > > (v5.6) merge window.
> > > > > > > >
> > > > > > > > I've just had a look at linux-next to check what a future rebase
> > > > > > > > requires:
> > > > > > > >
> > > > > > > > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> > > > > > > >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > > > > > > > - bitops-instrumented.h was removed and split into 3 files, and needs
> > > > > > > >   re-inserting the instrumentation into the right places.
> > > > > > > >
> > > > > > > > Otherwise there are no issues. Let me know what you recommend.
> > > > > > >
> > > > > > > Sounds good!
> > > > > > >
> > > > > > > I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> > > > > > > approach is to fix any conflicts during that rebasing operation.
> > > > > > > Does that make sense, or would you prefer to send me a rebased stack at
> > > > > > > that point?  Either way is fine for me.
> > > > > >
> > > > > > That's fine with me, thanks!  To avoid too much additional churn on
> > > > > > your end, I just replied to the bitops patch with a version that will
> > > > > > apply with the change to bitops-instrumented infrastructure.
> > > > >
> > > > > My first thought was to replace 8/10 of the previous version of your
> > > > > patch in -rcu (047ca266cfab "asm-generic, kcsan: Add KCSAN instrumentation
> > > > > for bitops"), but this does not apply.  So I am guessing that I instead
> > > > > do this substitution when a rebase onto -rc1..
> > > > >
> > > > > Except...
> > > > >
> > > > > > Also considering the merge window, we had a discussion and there are
> > > > > > some arguments for targeting the v5.5 merge window:
> > > > > > - we'd unblock ARM and POWER ports;
> > > > > > - we'd unblock people wanting to use the data_race macro;
> > > > > > - we'd unblock syzbot just tracking upstream;
> > > > > > Unless there are strong reasons to not target v5.5, I leave it to you
> > > > > > if you think it's appropriate.
> > > > >
> > > > > My normal process is to send the pull request shortly after -rc5 comes
> > > > > out, but you do call out some benefits of getting it in sooner, so...
> > > > >
> > > > > What I will do is to rebase your series onto (say) -rc7, test it, and
> > > > > see about an RFC pull request.
> > > > >
> > > > > One possible complication is the new 8/10 patch.  But maybe it will
> > > > > apply against -rc7?
> > > > >
> > > > > Another possible complication is this:
> > > > >
> > > > > scripts/kconfig/conf  --syncconfig Kconfig
> > > > > *
> > > > > * Restart config...
> > > > > *
> > > > > *
> > > > > * KCSAN: watchpoint-based dynamic data race detector
> > > > > *
> > > > > KCSAN: watchpoint-based dynamic data race detector (KCSAN) [N/y/?] (NEW)
> > > > >
> > > > > Might be OK in this case because it is quite obvious what it is doing.
> > > > > (Avoiding pain from this is the reason that CONFIG_RCU_EXPERT exists.)
> > > > >
> > > > > But I will just mention this in the pull request.
> > > > >
> > > > > If there is a -rc8, there is of course a higher probability of making it
> > > > > into the next merge window.
> > > > >
> > > > > Fair enough?
> > > >
> > > > Totally fine with that, sounds like a good plan, thanks!
> > > >
> > > > If it helps, in theory we can also drop and delay the bitops
> > > > instrumentation patch until the new bitops instrumentation
> > > > infrastructure is in 5.5-rc1. There won't be any false positives if
> > > > this is missing, we might just miss a few data races until we have it.
> > >
> > > That sounds advisable for an attempt to hit this coming merge window.
> > >
> > > So just to make sure I understand, I drop 8/10 and keep the rest during
> > > a rebase to 5.4-rc7, correct?
> >
> > Yes, that's right.
>
> Very good, I just now pushed a "kcsan" branch on -rcu, and am running
> rcutorture, first without KCSAN enabled and then with it turned on.
> If all that works out, I set my -next branch to that point and see what
> -next testing and kbuild test robot think about it.  If all goes well,
> an RFC pull request.
>
> Look OK?

Looks good to me, many thanks!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM6NT3bA07h5L9HNMzFY83Nd-yZRzum9-ykd4pW58kNOQ%40mail.gmail.com.
