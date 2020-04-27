Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNUXTT2QKGQEOZZEMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F3DD1BAA34
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 18:43:35 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id z2sf16687603ooj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 09:43:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588005814; cv=pass;
        d=google.com; s=arc-20160816;
        b=he5RWvQH1xT07hmyyHSIu2hK00zBJ68MRIbCNRpqHNL2eCVFkXL2b+/x1d6sat6HFj
         WEKpe5N/PpX9g0IfASQ8/kp/QeR/crKwd0wqalL8mmng6K9RwL591s5YHN1a9ZNaYzsf
         mX8Hw78OSXU72CGceCiS0r/KJoeED6CWgllwKdne7ixrIKv172rRUxnJNd48qNQlfiDU
         bOafLo8YB7xYg7yrXyWSjSjNAZcm9xRvIO8p3G0Hrxyo7RefwcqSg99qq/hz2W12rruP
         FKCiM6U0nYuZgrmrWcpTgioQ+QFAyHYT1x1+mHRJSgwPl4wx4ujT9rYa/brTx7cs/Zag
         cUIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gHlaS2/d0Cht2e8rEfhoQomPYWRl8anP5l7VrNnRyo4=;
        b=MqDVao5KOF5RsHd669Q+dPlDoGLnFhVNIX1KYp50fhgOnb0qF7mz0gJL0g+R0jlBSZ
         Lgkld06ub0An7nd+0QScRMKG4+gRG3YY7+7DqMY8hf1qC920UcSrZE6B1OKciOy22cMC
         sm5Beai+CDf4O0ovr5Q3tykWcEmRYGl2Bs6MBr62Pg3ihhlxzhsU7yBPLmkh2kGJKUJe
         LuzG9h7SsKLSfo9SlhMF4OOdFFAUv6remUgrYoksKajAkAkV6qtePULMv2LRGtK36Hdk
         zIs+MMHXC05DCPIFs86jkyfjFkLrFk3lSanzH5TRMFttYswwIdTNjeEXxUDByiBWfU5g
         IqCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SAmwxbLq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gHlaS2/d0Cht2e8rEfhoQomPYWRl8anP5l7VrNnRyo4=;
        b=JpFj5p2WxnQZi6nawrwGsupkUXMF3C5HVwr+gapJJgOi+zY6YnGTau3FUYMN5xI6vp
         nNRqvic57pm522wOtSHsFyfgP1bUiT5yeND5hiozoXvfji16Dgpi5Q5vOKJ0uBi0HOaa
         fZjAWR0POdOGXE+/+4BqyJQ6DRdypgfKgp8mpoFLn0cnaSHdX2EQgStMawF3YhuBqr/T
         INw1WWgsTl2Qe1Z5VzjVrVCstwFHwOT/2MgBNl2PwKbJ7VqaMyu/Ay/HvNW/ENVPQlen
         A44eBU/kKSKfV+GiAB3S2h5Tju0uJSdnLRrUe87c7D8iwZ7EA9n+pIdiIPAAt+1MuWXB
         Fqsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gHlaS2/d0Cht2e8rEfhoQomPYWRl8anP5l7VrNnRyo4=;
        b=R2fjJCMVqLz3pwCXlVtxneBL5UiOD5kqTgiZTK6AgGzFwE528jZ4YARvI6yRsD9H42
         TG0XwvnwmyPN2lv9t4M2spyIA4dw6+eu0e1ZX793sjUiYoEaLCwVPsDBHT82Vr1SteDO
         YtmFpVxwY6mArqTRs7Hg42FBNgHHNKUjSY3QlXdzn80rpDQEtEM20Lft98zH8sczv3x5
         EBxNHDf0de850owRivkj9BhVA0XdYxLoqbc7w+nmP4iWZ8IIODe6ZhMORnCfu1Fshur7
         +6ZF28oIXs51x/tq2jWSw1z7Qa0dCw2Nw1k6NhdDgz5Of6AfFGxXqURmUW/+uee0moo+
         nuNA==
X-Gm-Message-State: AGi0PuZ/ngDjaXTVd3fF9C1rZedSjerSSPDdhRCLpPrdBJcCNUUVVL9z
	CmgNo4fx1I0WDKiC7Hn1zj0=
X-Google-Smtp-Source: APiQypII9Ys0z9Uv4lbqle6hPNO5upnKYgj/eA9m08rarsyheFw/intCVFVp5O7Zp/FJq/wjCkB9kg==
X-Received: by 2002:a9d:7ca:: with SMTP id 68mr19562271oto.267.1588005814228;
        Mon, 27 Apr 2020 09:43:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3b23:: with SMTP id z32ls4737273otb.1.gmail; Mon, 27 Apr
 2020 09:43:33 -0700 (PDT)
X-Received: by 2002:a9d:2264:: with SMTP id o91mr19306106ota.258.1588005813727;
        Mon, 27 Apr 2020 09:43:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588005813; cv=none;
        d=google.com; s=arc-20160816;
        b=cZmEermUXUZWT0GNIXcs3JTRFdpcbwTl4cQLIiCrip5RNsQTmsk5kK0dIf/TB2g5VR
         6Mrxlfg9dser3p/4RXOeMWJ3njLH7XNLtYSTj1p3hMZRyG/hjr9uwvyjQ/4RA1c9d7BJ
         cLJr5koF4MbTNpue9E02eWd+1rsZRRFj8Rv+Xch82bFDwPU3OqSWY3Tp2GybIT5WLdOX
         oQpEkyb7CQiaDAOuRmVbFW2Z20iMTYWjRcQ4VTW3DK5cpIzr47PiGZSic1XdHia5sB1s
         HS+ZnwGJy2PG1V2lGnbfQsqqR+EYLih1xyOTnf4Eh9MaYmeEse5W21nTLuz3FniT/Jqn
         U5Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0l3NqzV2IWIFuQGrqE3G+AwPymiYlsU4oik6jzyoVmg=;
        b=rp24ArFb+wXpiBP4RsrQgWAPq0tY5fZxEIcCKKNj806UjaCDvyGbFJIb21aNFRFw55
         ocHrFHhJzkCVUrfppt0DRaP2jYrPMhYAIdZwS9m6sdDGuMD/Lz4hCSXjc1wLnrAxIvU5
         vXpUYwMf1mG1EtD0CIKU4hTiGBl/Fmv3yQz6ZXMastLBiYWrCH+M1ZUUpads30kjxUgj
         k4zqTNcsEjLEG5qbP2PPCdIbY6BMR9Q04Q5YCyb7I+0LPIHLO236OjRuwUNUC2qP3kNL
         /a7Wc+W1/aCFkHnDQNQPEul/HUd2vb4wL7DjIzhmtmA90KM7u/4su6BAIY25NDpMJ88H
         19IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SAmwxbLq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id f139si1641632oig.5.2020.04.27.09.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Apr 2020 09:43:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id c3so27283670otp.8
        for <kasan-dev@googlegroups.com>; Mon, 27 Apr 2020 09:43:33 -0700 (PDT)
X-Received: by 2002:aca:1c08:: with SMTP id c8mr16511350oic.172.1588005813011;
 Mon, 27 Apr 2020 09:43:33 -0700 (PDT)
MIME-Version: 1.0
References: <20200427143507.49654-1-elver@google.com> <CANpmjNOv7VXv9LtWHWBx1-an+1+WxjtzDNBF+rKsOm+ybmvwog@mail.gmail.com>
 <20200427153744.GA7560@paulmck-ThinkPad-P72>
In-Reply-To: <20200427153744.GA7560@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Apr 2020 18:43:21 +0200
Message-ID: <CANpmjNM7Aw7asb80OqZ0vmgQYY1SwM_Pnvf7ZHHvyFfsc6ZjmQ@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add test suite
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: kunit-dev@googlegroups.com, Brendan Higgins <brendanhiggins@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SAmwxbLq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Mon, 27 Apr 2020 at 17:37, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Apr 27, 2020 at 05:23:23PM +0200, Marco Elver wrote:
> > On Mon, 27 Apr 2020 at 16:35, Marco Elver <elver@google.com> wrote:
> > >
> > > This adds KCSAN test focusing on behaviour of the integrated runtime.
> > > Tests various race scenarios, and verifies the reports generated to
> > > console. Makes use of KUnit for test organization, and the Torture
> > > framework for test thread control.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> >
> > +KUnit devs
> > We had some discussions on how to best test sanitizer runtimes, and we
> > believe that this test is what testing sanitizer runtimes should
> > roughly look like. Note that, for KCSAN there are various additional
> > complexities like multiple threads, and report generation isn't
> > entirely deterministic (need to run some number of iterations to get
> > reports, may get multiple reports, etc.).
> >
> > The main thing, however, is that we want to verify the actual output
> > (or absence of it) to console. This is what the KCSAN test does using
> > the 'console' tracepoint. Could KUnit provide some generic
> > infrastructure to check console output, like is done in the test here?
> > Right now I couldn't say what the most useful generalization of this
> > would be (without it just being a wrapper around the console
> > tracepoint), because the way I've decided to capture and then match
> > console output is quite test-specific. For now we can replicate this
> > logic on a per-test basis, but it would be extremely useful if there
> > was a generic interface that KUnit could provide in future.
> >
> > Thoughts?
>
> What I do in rcutorture is to run in a VM, dump the console output
> to a file, then parse that output after the run completes.  For example,
> the admittedly crude script here:
>
>         tools/testing/selftests/rcutorture/bin/parse-console.sh

That was on the table at one point, but discarded. We debated when I
started this if I should do module + script, or all as one module.
Here is some of the reasoning we went through, just for the record:

We wanted to use KUnit, to be able to benefit from all the
infrastructure it provides. Wanting to use KUnit meant that we cannot
have a 2-step test (module + script), because KUnit immediately prints
success/fail after each test-case and doesn't run any external scripts
(AFAIK). There are several benefits to relying on KUnit, such as:
1. Common way to set up and run test cases. No need to roll our own.
2. KUnit has a standardized way to assert, report test status,
success, etc., which can be parsed by CI systems
(https://testanything.org).
3. There are plans to set up KUnit CI systems, that just load and run
all existing KUnit tests on boot. The sanitizer tests can become part
of these automated test runs.
4. If KUnit eventually has a way to check output to console, our
sanitizer tests will be simplified even further.

The other argument is that doing module + script is probably more complex:
1. The test would have to explicitly delimit test cases in a custom
way, which a script could then extract.
2. We need to print the function names, and sizes + addresses of the
variables used in the races, to then be parsed by the script, and
finally match the access information.
3. Re-running the test without shutting down the system would require
clearing the kernel log or some other way to delimit tests.

We'd still need the same logic, one way or another, to check what was
printed to console. In the end, I came to the conclusion that it's
significantly simpler to just have everything integrated in the
module:
1. No need to delimit test cases, and parse based on delimiters. Just
check what the console tracepoint last captured.
2. Can just refer to the functions, and variables directly and no need
to parse this.
3. Re-running the test works out of the box.

Therefore, the conclusion is that for the sanitizers this is hopefully
the best approach.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM7Aw7asb80OqZ0vmgQYY1SwM_Pnvf7ZHHvyFfsc6ZjmQ%40mail.gmail.com.
