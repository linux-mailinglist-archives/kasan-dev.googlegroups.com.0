Return-Path: <kasan-dev+bncBAABBHE2TT2QKGQECBE4RRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B45B71BAA64
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 18:49:33 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id c7sf14778233plr.11
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 09:49:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588006172; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbFgUZBlkVtcqdjw8XLYqBbvUW8qVQNZUYnUiQdRboYN2U8P4s2hceD+ZfucKww5og
         l/vj9ILL87Kj7s2/IfsnHmIBBucBBqYd2YVXYDdSvw3H22pLFTiFDpIWtfXiicPoiZzP
         atzMEm/B9sVWGPefRnWGGO9AvVUqIz8MAZ6Hv5MEPbmVd1UffzdQoyGg9AUZyCxvPnvZ
         zCGPpeotlfMMGZeRacmeUFVfaIE0eKzWK5C7NyGl9LpcAe5791ZaDLfskI0xfaiqUIup
         S45fy7ntnbf2f1DU/5mGAFojnOscXpAQKbYynsDJe9+Fx6P1ahHQ8s2zy3anxNLZRHDI
         OyLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=QRJqV1A/GbhxhF+FtJD9GZWT0XviryV+cf1xlRG2cXo=;
        b=zoqq/nw0B0VuH2DVv/GeBwYRHuFwtShVScnKAVCzhNQRtNIltPRqoD6Ow06j3O+7Ln
         nEZCCOjxJByK8SmAZkcGuisz3gkHusud/QlMNG16Dm8XYGpNcfglot9p/aQkGbUnH34N
         /VY8yKG8mKNaMOAn56Q3Q8os/zQ/nB9mAhywdFkzPjIkrcubxMTGxL76ViLbDfxQDf4m
         Iy4u1AsqVHHHS9xRjgzkH3ohZHnzp005ORcNQZH0YC7f8w/xgSFwZ4npcq4wBFbQOesr
         6WJ7N3NBDAL4awJ9bAHWpUrhtc/0fGh8Kv1UX6QCXSYE/vk5nju0/GCFMZlHss8e57sf
         Ol3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=c+phBkdh;
       spf=pass (google.com: domain of srs0=szdt=6l=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=SzDT=6L=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QRJqV1A/GbhxhF+FtJD9GZWT0XviryV+cf1xlRG2cXo=;
        b=gdSuapOl2LQSGPyuGYNfUbWrxvyLiyjecfCEekgjqp7O7LL3ArE9g8eIyDTiLgq10n
         kHjD1dgYiD1JXbosM0rz0T15H3yyjmeJ209F8HVCKCa7vfbUUCprshVcI5X1uInWkZaM
         oTBzqMj2Wa455bmX0E1sFytWObTSLPq2sieK4av8XOAxYLL5g+PsbQcM3HnwoJQuwpQB
         YOUMMvOruFnHjZTbS8NCQvDGecMprEuy6SS6X6bHaGf3KljHrarXsZkgCb5Le83Wc44Q
         42h+y3LsSYRXblM+S3IjLwnkPA5iPx91hYLj68ec5RXrDTsL9TWDnZIhJIZWaBQi2v10
         XgGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QRJqV1A/GbhxhF+FtJD9GZWT0XviryV+cf1xlRG2cXo=;
        b=asFh3yNKO5/7o6PVoQLJFaJ5xmCeuaHxYz3szMw5EfwVuufE66jqw4J0DUzPI39HE6
         /rAAkIWsmU0pY/nMgWlPsfs9gYU+HA9ZVA4XPDsd8W8E3Or3+fOugH7BHokSbb5b5liF
         UE7x+DeEdgjhG3pIix/Ug4GCen0JydVqXnfZ5GeU9sSnFIdtcHN4xViqdCqv5VNHZJ8T
         osyZ8pdtxnjuOsgDzTZ6GHVNmy3nEkiUKY7xabsbD9Lv3GpYI6FvuCIzu7NtvdbrhC/8
         kATBPu6ZSe7yF96FMGkaAgo3EQVSc2zPNx/AAaSgs7z5PPdsnJZcZRz1oT+ZVFoKRNdG
         PF8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubzdkdTsHUbzhhIJiGKmRpPATSl8Mt3wTbZluMz/54FbFWgpJi5
	BNELAs7/Z5Qj8BmI98q61hU=
X-Google-Smtp-Source: APiQypJuGaohWlw6VJ7qVnJrjo3HfHO3Hyqc3KWYXB8kmXJDn37mGo1YsbC5RffT5d97iwZuvOs7Bw==
X-Received: by 2002:a65:5509:: with SMTP id f9mr24273673pgr.70.1588006172261;
        Mon, 27 Apr 2020 09:49:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:32f:: with SMTP id 44ls16303707pld.1.gmail; Mon, 27
 Apr 2020 09:49:32 -0700 (PDT)
X-Received: by 2002:a17:902:a40e:: with SMTP id p14mr24676616plq.132.1588006171930;
        Mon, 27 Apr 2020 09:49:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588006171; cv=none;
        d=google.com; s=arc-20160816;
        b=h7sdf/X2840W9N670kWnxmXTLszmM6eYHoR8tb6bi4/Ir4amdQ98Mllssj6J3ne/KH
         8WYb4ORY5hVx/zLKU/mxRIfKYko+EFFwUy7UpTyjqGWr8YoWztgLcN2BfU8UecfrkaZ5
         xQHNqAtLFo9wgR7WPX1EJCtL87Nw/GZly8SzRup+B9DyHuDwtvZTX8hpSLIDYpD2Z9S5
         NPSoT7OdBBLQXWdE6RQR264kMJVps729/dg62V/BZa2VyrP9bdcvzJ6AVKTxcIH2obH9
         7/ICK40vvAziXhCp0JiNReOtoxAtO/RdzGropX3CqngPvNufnu8m1A3TA6JGox/IYZ9h
         szAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=OtBcOYsWExj6TGSE8Lx2l+3BYV0OL+MKS6AIwQ7aHxA=;
        b=fL9Nlogw66zKefBsN7oCnK3yYQLZwpckwTmI2WVaHhjvYcJg6gG2LyAXrql8XdF+NA
         jFcPhzkjevCVaLE25fpcxZUR3S9JiyNGxZtnFyrla3Ml+w4AcvewbVQetkbfByzGFLJs
         ZdKB8PDcjubH5DK/XqGFmQZ04mags4rYrMaoae75ITRyXBO/eSbMqpkCrBR65/6R8lOM
         4a3Y6sTVpS8VnQd1NfvLbVpHv8XucZZFg7WAzk+pOWEhtaXCtLPQZgUv82jTXqLAUbWF
         dFS2au/d/swD1zeZU4vrvlXoBYV2Nc8S+amWlG0Oi/G6DqJHUyOI1ei/HZE3S0WXL1gd
         +L6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=c+phBkdh;
       spf=pass (google.com: domain of srs0=szdt=6l=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=SzDT=6L=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u18si195116plq.0.2020.04.27.09.49.31
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Apr 2020 09:49:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=szdt=6l=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9BEEA2080C;
	Mon, 27 Apr 2020 16:49:31 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 753AE35226DB; Mon, 27 Apr 2020 09:49:31 -0700 (PDT)
Date: Mon, 27 Apr 2020 09:49:31 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kunit-dev@googlegroups.com, Brendan Higgins <brendanhiggins@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add test suite
Message-ID: <20200427164931.GF7560@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200427143507.49654-1-elver@google.com>
 <CANpmjNOv7VXv9LtWHWBx1-an+1+WxjtzDNBF+rKsOm+ybmvwog@mail.gmail.com>
 <20200427153744.GA7560@paulmck-ThinkPad-P72>
 <CANpmjNM7Aw7asb80OqZ0vmgQYY1SwM_Pnvf7ZHHvyFfsc6ZjmQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM7Aw7asb80OqZ0vmgQYY1SwM_Pnvf7ZHHvyFfsc6ZjmQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=c+phBkdh;       spf=pass
 (google.com: domain of srs0=szdt=6l=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=SzDT=6L=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Apr 27, 2020 at 06:43:21PM +0200, Marco Elver wrote:
> On Mon, 27 Apr 2020 at 17:37, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Mon, Apr 27, 2020 at 05:23:23PM +0200, Marco Elver wrote:
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
> > >
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
> > >
> > > Thoughts?
> >
> > What I do in rcutorture is to run in a VM, dump the console output
> > to a file, then parse that output after the run completes.  For example,
> > the admittedly crude script here:
> >
> >         tools/testing/selftests/rcutorture/bin/parse-console.sh
> 
> That was on the table at one point, but discarded. We debated when I
> started this if I should do module + script, or all as one module.
> Here is some of the reasoning we went through, just for the record:
> 
> We wanted to use KUnit, to be able to benefit from all the
> infrastructure it provides. Wanting to use KUnit meant that we cannot
> have a 2-step test (module + script), because KUnit immediately prints
> success/fail after each test-case and doesn't run any external scripts
> (AFAIK). There are several benefits to relying on KUnit, such as:
> 1. Common way to set up and run test cases. No need to roll our own.
> 2. KUnit has a standardized way to assert, report test status,
> success, etc., which can be parsed by CI systems
> (https://testanything.org).
> 3. There are plans to set up KUnit CI systems, that just load and run
> all existing KUnit tests on boot. The sanitizer tests can become part
> of these automated test runs.
> 4. If KUnit eventually has a way to check output to console, our
> sanitizer tests will be simplified even further.
> 
> The other argument is that doing module + script is probably more complex:
> 1. The test would have to explicitly delimit test cases in a custom
> way, which a script could then extract.
> 2. We need to print the function names, and sizes + addresses of the
> variables used in the races, to then be parsed by the script, and
> finally match the access information.
> 3. Re-running the test without shutting down the system would require
> clearing the kernel log or some other way to delimit tests.
> 
> We'd still need the same logic, one way or another, to check what was
> printed to console. In the end, I came to the conclusion that it's
> significantly simpler to just have everything integrated in the
> module:
> 1. No need to delimit test cases, and parse based on delimiters. Just
> check what the console tracepoint last captured.
> 2. Can just refer to the functions, and variables directly and no need
> to parse this.
> 3. Re-running the test works out of the box.
> 
> Therefore, the conclusion is that for the sanitizers this is hopefully
> the best approach.

Fair enough!

Perhaps I should look into KUnit.  I don't recommend holding your breath
waiting, though, inertia being what it is.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200427164931.GF7560%40paulmck-ThinkPad-P72.
