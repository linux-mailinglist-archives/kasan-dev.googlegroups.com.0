Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWHYX2QKGQEC665IMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DE201C5625
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 15:02:00 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id l7sf1190628pgb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 06:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588683719; cv=pass;
        d=google.com; s=arc-20160816;
        b=EL7+v94GTBvqxvIl10Il9MJIbvtnG7DGz14gERSH05i7p/AeTcjy8UttuaaiNFafBW
         /2/CLRwgECA/oNHJb/Sm/WSiUEGbA2kx/iK/TvwFm0FLhDVOrsxz/BCZKjmckxXpFZMR
         U6bt2m+QzfcPFFY3KwVT3URsyl90WPnnLV8b4B5042eAtzk7Ph2Zp9tMOx0PDnj6p/RD
         VJydFr1Ac2PeQqyDSmlY8QzCSmHIL1PaCsFM+sflusQz22PHAB1qrBY23DTDX7mQWFwy
         OtD4NXOzhplexVWOMKlxXqjhMe2+ZB519fSAYuRJ2x01TK0TCrTs2sitocwBspcb0Ikm
         hkRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9V6MxrF/7EBLhYptosA0wG1K5hPMIveMOHQxQ43WB1o=;
        b=OPp092pt46TsLe2wFZIXQCHUBrHRWSeGeb1eOtzPGfi8Erv6oNggp6JxQNvNQ2i67h
         zW/kEL+Knvd8EOj5bpr504jUrKY8cITOQySiUlnrel+nSnxjfm1EOgfxjvQXPq3AvMmi
         MyP9L3QJUZNcym9geikKxiTOa+sF8/dP3fSCMSfgToW/isSR9zt0UctCak8pqz3MR2P4
         Wmz6jK8TY/4J3UPIE1puUtpAuCPE+6MmAaZMj5COioGdj6VVFJxCLuQ2lX0r7HUeOjzP
         xD4NUKxTBSq2cKcPsh1OrNEcB63KtPMJxO7+14zJgO5YwHlDxfLUWJkRQvO6vpqVuKVH
         rC3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W1VfS4vL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9V6MxrF/7EBLhYptosA0wG1K5hPMIveMOHQxQ43WB1o=;
        b=XhsbmRibR75aymKhNxgccWyit9mxk2epZ7/ufE0KBbhsFKhaZnzdla+6NaYNxKsfmW
         vgMx0/wvBOiiM3bEYvA4MyM2bBVAqJH28U5EusbX4yz8cc6ZEiYeQJdYeL8NHGqUFCuS
         fF5NJSqhegd5hTOtm68dBt8rzhl5pWvrHiqmR0t5JfauvPO3tz9qVHKvNtVzhni9TpaJ
         x5g3t425z42YqoBOjjiXsBt0YpmBBvCinrvOPOzOv2J3p5w2v1qifJMi2GapYVLhWZYn
         /jY8M9NmU2IkuUsCsZCAklTAPnnHpdHsLbo4xbsX3ip+bXFMiKltfa9DTQPntemBVIIH
         I51A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9V6MxrF/7EBLhYptosA0wG1K5hPMIveMOHQxQ43WB1o=;
        b=CkjFoetVAOALafxtHsWP4v3Jgj1lz2eIfzELQ+BprWsL9UqVAzRnE88WwgRJ4VxPR5
         D9JqzT5RLQcB9G69XY6gbQywbHEcWJ6mEdNfZegHMpF3aximqwayCQWjYAgcgDFhdE4N
         LBgM3OQbALcnSu3NcrffdxVHtFEwICG2h2CvGTllmQ6qN6Z6Vckh68XUAQXnV8sWz5QV
         uRpkpd6iu3xTmlsqf9HYKjjxpJvHXRBe0MDx9uwcj6UEoLLqZTG34Y21D1gy4c47PxlX
         2/fmF1rjobukpYpfSvN9aLrlmpvdCbNgdyBSZC6lKiHtLN8975REkxTF9FDcd8v46V0h
         pIqg==
X-Gm-Message-State: AGi0PuZMap3fPm8mkgR1q9YSKNNgWAVf67uDMg6x8yQlY2MXKCp23jUm
	IEhnf3IYfcVPYSSshTwsK6A=
X-Google-Smtp-Source: APiQypIPoT4ijHYr1O+YxWx+qHjgbCNo8UdjoXeT0sZWfOWi/yN4DSE5rcs3J7zABCcnsYOaHondsg==
X-Received: by 2002:a63:4c9:: with SMTP id 192mr2838636pge.207.1588683719041;
        Tue, 05 May 2020 06:01:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ea0e:: with SMTP id t14ls1173478pfh.3.gmail; Tue, 05 May
 2020 06:01:58 -0700 (PDT)
X-Received: by 2002:a65:5a8b:: with SMTP id c11mr2848101pgt.215.1588683718467;
        Tue, 05 May 2020 06:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588683718; cv=none;
        d=google.com; s=arc-20160816;
        b=IrRLnQdIRHcOHsyO4wNeNZfgEUeNWHn57dSj2yxSrVadLBjr08GNy3QAXFQcJR1ofW
         j283Fk4v36iDQHzgjXB5n1mlbKOkKP+IufRpUzq9CzL/sYujzr1/OvM0lwOQVlo83S4D
         jmv7xkaMVCwQcWYkj88TTefkaVxpNBfgww8XcIdsVofOg4Ay9yuv7lpWAi+DlbFxBb1h
         KOPOcsm50cBmHVocjHjmhgYSzcKjyjTZ6koygQ89XbKHHLAvHeUwqu7/+UGJ9nKzB1rk
         xqzISanA3yq1JBNpIHK5GJMURPVJHlY6DCeHOWLtiIZvWXS4cMiUn/00fh1rDC2lqDrU
         Nf9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JTDmSdSSqcf0820VG99rQzpJRdzBGuHIvjHK4wifur4=;
        b=weUQAhtMAXvB5TDP4tBsgreyisZiv+T0EkMsI2TCCtiADnJsq5/PDFhzc3+2lNBRvw
         /jeKtw+hD5Zc3Fow1zCu1G1rFrvTbTKZWSj7RDfIMWo2l3czfa/2CNhJe3N/8L+mFF0f
         FBdr39Yrpsf2MlXf1fAQlVXY0U2VXBySqxBeQpvqVBcz8eLdFo3B0U20LASPY92MPNkf
         otYTddu3QPUQ5xZlGzvYH/wKyfLeBfIMPITOjj/Kkwd6oJuslgXjhMSXILBLz0XLwij/
         M9pm7+Sxj4bW7Gj+Rkp9K3Sa2YjY5iSPTdnXQbSiZNMOiAKxswKuVKj7CisYmUvgADUo
         wLig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W1VfS4vL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id c17si140337plc.5.2020.05.05.06.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 06:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id c3so1507020otp.8
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 06:01:58 -0700 (PDT)
X-Received: by 2002:a9d:412:: with SMTP id 18mr2181834otc.233.1588683716950;
 Tue, 05 May 2020 06:01:56 -0700 (PDT)
MIME-Version: 1.0
References: <20200427143507.49654-1-elver@google.com> <CANpmjNOv7VXv9LtWHWBx1-an+1+WxjtzDNBF+rKsOm+ybmvwog@mail.gmail.com>
 <CABVgOSnr8CX5tN9u_wafxSiyyVcM9nL_nX2ufrSdRi=jdWjerg@mail.gmail.com>
In-Reply-To: <CABVgOSnr8CX5tN9u_wafxSiyyVcM9nL_nX2ufrSdRi=jdWjerg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 May 2020 15:01:45 +0200
Message-ID: <CANpmjNMhVcR6TiLv29HqSvVVurUMwtHiokodPyzvwFSeE6UpZw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add test suite
To: David Gow <davidgow@google.com>
Cc: KUnit Development <kunit-dev@googlegroups.com>, Brendan Higgins <brendanhiggins@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W1VfS4vL;       spf=pass
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

On Tue, 5 May 2020 at 07:00, David Gow <davidgow@google.com> wrote:
>
> On Mon, Apr 27, 2020 at 11:23 PM 'Marco Elver' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
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
>
> Thanks very much for writing the test. I do think that it goes a
> little outside what we'd normally expect of a unit test (notably with
> the issues around determinism and threading), but it's good to see
> KUnit being pushed in new directions a bit.
>
> The biggest issue in my mind is the possibility that the
> non-determinism of the tests could cause false positives. If we're
> trying to run as many KUnit tests as possible as part of continuous
> integration systems or as a condition for accepting patches, having
> flaky tests could be annoying. The KCSAN tests seem to break/fail
> as-is when run on single-core machines (at least, under qemu), so some
> way of documenting this as a requirement would probably be necessary,
> too.

True. Although note that we require CONFIG_KCSAN=y for this test to be
enabled, so I don't think it's a big problem for a regular CI setups.
For a KCSAN setup, I'd expect that we know that running on a
single-core system doesn't yield much interesting results regardless
of tests being run.

The non-deterministic nature of concurrent tests will never entirely
go away, but I think with the right preconditions met (at least N
CPUs, where N depends on PREEMPT_NONE, PREEMPT_VOLUNTARY or PREEMPT)
the tests here should not normally fail.

> One possibility would be to add support for "skipped" tests to KUnit
> (the TAP specification allows for it), so that the KCSAN test could
> detect cases where it's not reliable, and skip itself (leaving a note
> as to why). In the short term, though, we'd absolutely need some
> documentation around the dependencies for the test.

That would be nice. For the time being, I will add a precondition
check to test_init(), and print a warning if the test needs to be
skipped.

> (For the record, the failures I saw were all due to running under qemu
> emulating as a uniprocessor/single-core machine: with
> CONFIG_PREEMPT_VOLUNTARY, it would just hang after creating the first
> couple of threads. With CONFIG_PREEMPT, the tests completed, but the
> majority of them failed.)

Right, let me try to fix those at least. I'll send v2.

(Paul: If you prefer a separate patch rather than v2, let me know.)

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
>
> This is something we've discussed here a couple of times as well.
> While I'll confess to being a little bit wary of having tests rely too
> heavily on console output: it risks being a bit fragile if the exact
> contents or formatting of messages change, or ends up having a lot of
> string formatting and/or parsing code in the tests. I do agree,
> though, that it probably needs to be at least a part of testing things
> like sanitizers where the ultimate goal is to produce console output.
> I'm not exactly sure how we'd implement it yet, so it's probably not
> going to happen extremely soon, but what you have here looks to me
> like a good example we can generalise as needed.

The fragility due to formatting etc. for the sanitizers is exactly
what we want, since any change in console output could be a bug. But
as you say, for other tests, it might not make much sense.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMhVcR6TiLv29HqSvVVurUMwtHiokodPyzvwFSeE6UpZw%40mail.gmail.com.
