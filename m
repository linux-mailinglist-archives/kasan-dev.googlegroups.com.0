Return-Path: <kasan-dev+bncBAABBMXKYX2QKGQEA5DMZVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 441771C5885
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 16:16:20 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id t23sf1760883oor.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 07:16:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588688179; cv=pass;
        d=google.com; s=arc-20160816;
        b=tfthSutJs/m/XSAiQSYsLUz42ztxW5q1f7ASYi/fEAfn34mGBY5FEscYatv45G4BvK
         EYTnvTjaWyR9ZekuG+kPPMJOrOaNlKeW3/bDAE0zu7JGhj6K0IDGqZaYPwKuIcFfY+ml
         MU6pH/POJHJBjwD7AjSC4kGVMcTuWo6Ksia2NB47cjT3IZcW5R1Sw9uPrybcQbcsy+gF
         QeTH55eNrccMinZn1kHHNfnuMmKemTXa42VnnfL/L44b6TretnYCierxZljNueLjqu+U
         1OvWlRS1BV8ydYIou/R7gbI91j4jxMr/E/TqHDU8nA0zjG9qqgy7h4ITQyzXUAAOGnde
         sHbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=cmV0hQWJl092dCYmvI6LzeuLGORrn8zLRMMCkWJb3yA=;
        b=tT8NdxWGrSqg60nVjc9NeBREpFJyC6X13Sn3Q9I5wE9ahcQGx1K2ISTe+MiBY8TIvp
         xtRh3jmQHx0oY0Wh/4KuY2HUQVkoIy/6iL+Xjc8qsCv3wEAz/9pQZoqeJN7KmEAYtYfA
         /1H3ltrrUSeWyF5Opes/TJoT9bh9ABzdU0RrABIp0w2E//oxAjjX359CbfJwfUatc+RL
         9w83Ow5Brt9TZJycVyy/AkyMWOtMeepURBkvFUHMLVXcpZvGeilzBodeXUycDaoleO36
         sdl0dK/aSOU//tRuxst4IH8kZl1zuiKqM4DmiQczk5XskVwXb1rBfDcbhcBuYq87JM/n
         gi5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TrSglO9H;
       spf=pass (google.com: domain of srs0=s9up=6t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=s9uP=6T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cmV0hQWJl092dCYmvI6LzeuLGORrn8zLRMMCkWJb3yA=;
        b=Q4iX9zXTK3bFXnH8vAmxdPv6LAMvZ9n9PJHw+NaMSHx9SHnedvHMR9Es6ClIvUvdBw
         O6pVvASEtro1vlzd5JmtSGzIRa1oqjZydS+gOPqnib2uZxuA6k6gxbCvR7nj2IQxSjpy
         nklbk7duj/Z3/U1KnEgUr82hNXahElX3EUOxumzsLCUxV4r8/ejwMHwjCo0s51UQdNqt
         /ukob7GZxg7xdEgOT/U/mMJ+FtU24flqfgJhzPFhL/1w+dsdAdNC8bVrJQ6eQtXy71eU
         6J6RH3XIap1e9BKNa9+RoTkDxQsC91JHa38mLsUa0qBwvpIcdnRoqAOayKj25DnlhDp4
         KbMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cmV0hQWJl092dCYmvI6LzeuLGORrn8zLRMMCkWJb3yA=;
        b=KRqcn1lbbGf+fWcBsv9T1MBJiAsW9I8TomKlIaHO2XeuOmcl4kQ9EQN4dCg1rbtpB6
         hAg/HlDRp3PZL+vKfso35Rebe1acp3FvPUoWlfcoR1IHoaOacd9CHppbs283QAfGtpGN
         cqjg4myjZKvIgLiCOvTs74/8OTFuU15dtYJkYasYAPDszrW+VPLIva0FBhRqnjXUD+y2
         IGTmn0CXYFEy9BYK3B0nJcuFaAg7zKMuMaKCXZ81yhJLjxEJblkFXetA2zpviByybVgI
         BM5L5Hxc5J4QT59f/owzGDZQLNCOAv2moSNBP0fis9bSeMI4zFNe0GWnsnN5jM7ne1tK
         rMnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZtWKu6CNFqRx8IIvjNjtjsXvfmCtw22/4f/4kVaSP2rR3cyrCj
	db50zy9HafPnkR2ERbWQs5A=
X-Google-Smtp-Source: APiQypKOR0EQRf0uK2iMpP5IDQOXk55CwYMCb3UZ571nzzuUf0PqIiEWa8BsAHPAT1QKq/oanrQwtg==
X-Received: by 2002:a05:6808:49:: with SMTP id v9mr2504909oic.41.1588688178845;
        Tue, 05 May 2020 07:16:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:150:: with SMTP id 74ls652368otu.8.gmail; Tue, 05 May
 2020 07:16:18 -0700 (PDT)
X-Received: by 2002:a9d:6282:: with SMTP id x2mr2767538otk.52.1588688178220;
        Tue, 05 May 2020 07:16:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588688178; cv=none;
        d=google.com; s=arc-20160816;
        b=xs8IMuvEXIarl0yqj9Bkt5AG2dLPOIS9CK9DZJxlPtqvq1LV77RfpnjeQ/prBLUf5O
         VZFKPsjgIb6zHvgWq/OEHDGnsdSFV8ZLYOGbF1dKYQ40kYV2Subf18w5y5AZTAf+KUhW
         LQ27n+4ouH1HlnsTvPl3Hp9NxDkPMTwSiGA89KVcoL/i/bRCzb2g5AKptVnzfFZubbJd
         KTPl/IfrHLMm4Lvf91RbzGAYjkSwNvGYvQGLM129CNA6gnblf17OaqZRh1cyE4ESPSo8
         tkAQcD8vW9l86xJ/c6fAUBQaRp62aVtg7YNlQioOG519SzIhwDh4zfSQi/bYv8Uy4PvU
         18qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=m1fLayl/w7aKQZpbO5RkmXQrax0FSFbLy+2B91mIMr4=;
        b=sYIAnUO3G9xLAIb5hhyhiex5ok/VTFfzFVmSLwezTTY43lhTXH4HvR+gTkIYHrG2/3
         YfkZIKfim7QhBb9q4wokLTJAe5D6J+mN+tx4IMR9LbJmgG9vBM+hWZAs8yn71PqBse/j
         myGaw0OJyDv7qSecmJPs8ukV/3K43QVyUb37hcsyuX4Vy148mn4RzNl0Qkd7dD7qAD5O
         wLK661zbz/NNbj0L5DjPA9mdRJBxx8zu8l73ABGuz0gHiKfaq6yOJKFy6VjU+gmm7P7G
         lS6FgSZyC3KjwYXjOe2EWg8mmh0b7qGSz/59Z6O78Hzt6xfhTp/XCYZCmHehZmUrBLi8
         abNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=TrSglO9H;
       spf=pass (google.com: domain of srs0=s9up=6t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=s9uP=6T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l22si158313oos.2.2020.05.05.07.16.18
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 May 2020 07:16:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=s9up=6t=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5ADCE2084D;
	Tue,  5 May 2020 14:16:17 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 38A4F3521001; Tue,  5 May 2020 07:16:17 -0700 (PDT)
Date: Tue, 5 May 2020 07:16:17 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: David Gow <davidgow@google.com>,
	KUnit Development <kunit-dev@googlegroups.com>,
	Brendan Higgins <brendanhiggins@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add test suite
Message-ID: <20200505141617.GY2869@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200427143507.49654-1-elver@google.com>
 <CANpmjNOv7VXv9LtWHWBx1-an+1+WxjtzDNBF+rKsOm+ybmvwog@mail.gmail.com>
 <CABVgOSnr8CX5tN9u_wafxSiyyVcM9nL_nX2ufrSdRi=jdWjerg@mail.gmail.com>
 <CANpmjNMhVcR6TiLv29HqSvVVurUMwtHiokodPyzvwFSeE6UpZw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMhVcR6TiLv29HqSvVVurUMwtHiokodPyzvwFSeE6UpZw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=TrSglO9H;       spf=pass
 (google.com: domain of srs0=s9up=6t=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=s9uP=6T=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, May 05, 2020 at 03:01:45PM +0200, Marco Elver wrote:
> On Tue, 5 May 2020 at 07:00, David Gow <davidgow@google.com> wrote:
> >
> > On Mon, Apr 27, 2020 at 11:23 PM 'Marco Elver' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > On Mon, 27 Apr 2020 at 16:35, Marco Elver <elver@google.com> wrote:
> > > >
> > > > This adds KCSAN test focusing on behaviour of the integrated runtime.
> > > > Tests various race scenarios, and verifies the reports generated to
> > > > console. Makes use of KUnit for test organization, and the Torture
> > > > framework for test thread control.
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > ---
> > >
> > > +KUnit devs
> > > We had some discussions on how to best test sanitizer runtimes, and we
> > > believe that this test is what testing sanitizer runtimes should
> > > roughly look like. Note that, for KCSAN there are various additional
> > > complexities like multiple threads, and report generation isn't
> > > entirely deterministic (need to run some number of iterations to get
> > > reports, may get multiple reports, etc.).
> >
> > Thanks very much for writing the test. I do think that it goes a
> > little outside what we'd normally expect of a unit test (notably with
> > the issues around determinism and threading), but it's good to see
> > KUnit being pushed in new directions a bit.
> >
> > The biggest issue in my mind is the possibility that the
> > non-determinism of the tests could cause false positives. If we're
> > trying to run as many KUnit tests as possible as part of continuous
> > integration systems or as a condition for accepting patches, having
> > flaky tests could be annoying. The KCSAN tests seem to break/fail
> > as-is when run on single-core machines (at least, under qemu), so some
> > way of documenting this as a requirement would probably be necessary,
> > too.
> 
> True. Although note that we require CONFIG_KCSAN=y for this test to be
> enabled, so I don't think it's a big problem for a regular CI setups.
> For a KCSAN setup, I'd expect that we know that running on a
> single-core system doesn't yield much interesting results regardless
> of tests being run.
> 
> The non-deterministic nature of concurrent tests will never entirely
> go away, but I think with the right preconditions met (at least N
> CPUs, where N depends on PREEMPT_NONE, PREEMPT_VOLUNTARY or PREEMPT)
> the tests here should not normally fail.
> 
> > One possibility would be to add support for "skipped" tests to KUnit
> > (the TAP specification allows for it), so that the KCSAN test could
> > detect cases where it's not reliable, and skip itself (leaving a note
> > as to why). In the short term, though, we'd absolutely need some
> > documentation around the dependencies for the test.
> 
> That would be nice. For the time being, I will add a precondition
> check to test_init(), and print a warning if the test needs to be
> skipped.
> 
> > (For the record, the failures I saw were all due to running under qemu
> > emulating as a uniprocessor/single-core machine: with
> > CONFIG_PREEMPT_VOLUNTARY, it would just hang after creating the first
> > couple of threads. With CONFIG_PREEMPT, the tests completed, but the
> > majority of them failed.)
> 
> Right, let me try to fix those at least. I'll send v2.
> 
> (Paul: If you prefer a separate patch rather than v2, let me know.)

A v2 would work well, thank you!

							Thanx, Paul

> > > The main thing, however, is that we want to verify the actual output
> > > (or absence of it) to console. This is what the KCSAN test does using
> > > the 'console' tracepoint. Could KUnit provide some generic
> > > infrastructure to check console output, like is done in the test here?
> > > Right now I couldn't say what the most useful generalization of this
> > > would be (without it just being a wrapper around the console
> > > tracepoint), because the way I've decided to capture and then match
> > > console output is quite test-specific. For now we can replicate this
> > > logic on a per-test basis, but it would be extremely useful if there
> > > was a generic interface that KUnit could provide in future.
> >
> > This is something we've discussed here a couple of times as well.
> > While I'll confess to being a little bit wary of having tests rely too
> > heavily on console output: it risks being a bit fragile if the exact
> > contents or formatting of messages change, or ends up having a lot of
> > string formatting and/or parsing code in the tests. I do agree,
> > though, that it probably needs to be at least a part of testing things
> > like sanitizers where the ultimate goal is to produce console output.
> > I'm not exactly sure how we'd implement it yet, so it's probably not
> > going to happen extremely soon, but what you have here looks to me
> > like a good example we can generalise as needed.
> 
> The fragility due to formatting etc. for the sanitizers is exactly
> what we want, since any change in console output could be a bug. But
> as you say, for other tests, it might not make much sense.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200505141617.GY2869%40paulmck-ThinkPad-P72.
