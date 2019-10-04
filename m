Return-Path: <kasan-dev+bncBDMODYUV7YCRBM4V33WAKGQE7REB2VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6138CC24D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 20:08:52 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id i187sf5286344pfc.10
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 11:08:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570212531; cv=pass;
        d=google.com; s=arc-20160816;
        b=AZfgqUQcsac0FJ5GAVFHbLONSXUZoQwE5idWGO0bqkBT1zgx6JD9MMZsY4ptcS2p1M
         0hmYFGJZq+yESf/vD6jJX44eaKyAwkXTSZFQBuZWW8cBkwyssm+DRyoRiCRVRk4z+z3S
         m42yS9pXf/zfYVOrGzLZ3FJmPCo85UhqIUKN5PqbMr4aDZf2KM67MDGPPJTuhB8sdYZc
         S8wUwlGmtC01uHHphXnQ9Yeyv8vT2b2tsikSUiBUKL2Sg/YEpnqHnUXoy8ec0E/YmxrK
         RaUa4X0U+nv3ZrHcu+6tErFbCSquL/30rYgk0RPLok0DRf+Upxa78xRgQmAs8jUB65VX
         Er8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Hlk3vbd0U+S6CcMLSm+vy3rK1Jw/xsCybcBXzAdcfiA=;
        b=IkADCrcz2SNglu/K7y7k9AH53eubMcgnwCmhxojcqXKgivSfGNZzCfq3Md1R67ZZ7x
         bnR/DNaICgRB91FhxFgcvBFO97oPrmocXeFaahiXn6yqniFkPFl0Xz7UW7ZWaudOZalq
         Dff8pQlOp9Kjry9gO3lfFopK3KdNxS6sr5ntRHsB4/yirtsv1coB6pHW9r72FJLlzkay
         uqevde4oEOfWvzMclnEO2TwJ2zQzBh38Df8f1dDYHiGD413SWhX4og5LgOf0hIQBeSMZ
         rRE+PVUMsx77UfW1IcbLJMdz4t8IpUyVHzOSfDQ5ZB/J/DwtIzRQRZZj/YTL1LQEDVu3
         tvDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b="k/M11Dz4";
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hlk3vbd0U+S6CcMLSm+vy3rK1Jw/xsCybcBXzAdcfiA=;
        b=ZTAbkvbyFS2t8ixWr1bA1fJwDOh4+EaL5UG3+gwMtobfvBxoOhr04wnjso5xacZ0t1
         mAmIuqaIdt6vc1cNYRSnNDa3lGzxDaquMVCu9QVoyrTSmRrQZUK1+1SS/ypEFoHzlAzB
         wn4ztPpOFBUTf2hNP/3MQCDze6zVAKeUmdmc9eAsTkvNU8583CdBYRb5FnW4VfWUgj3+
         crwjJQvmYonyVfQsTMuQqqwiBudHoEvlujSjhTnVYLh0i5Ays6MNVX1EyXYCryE1ylCf
         7WpzpjBtyyw+fTVhV/eYj1R+iAwlFBIr8GdOqPDWb0iZLh97D9Df3R1Q+oP6CzadtSqb
         +vSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Hlk3vbd0U+S6CcMLSm+vy3rK1Jw/xsCybcBXzAdcfiA=;
        b=X9rEhGEzk/xt8VbTymVxtuCrhwNe1rpW60s89cWFby247P0vBTrPRaSW+1qbHds2JQ
         iqpFSwvBjhDdbLVyW2OZqOb+9jUAYlnosHkFcmYLWcA97xzWOSSM2GstylIInGdVpA05
         xqVMFL1oQmJ4V+odhCaQk3mpYqmmup2Cg/OWS+jLG0iZZ0Uv7apQ6nIhSmf7DcmxIDJT
         TfjrN4e+ax+zLPUP2JpfFDXFTSgcaAPfh9IdECla1JLS5H56xFFpymr0NnDoWajnoIBM
         b5ll0urQ3wDcTVW/LpG7hRrCv2rXIEJnbt+sFdz54hkMLR5QYXDkpoFpKyUm3gAWvIQ3
         AaSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVE8xcPNkEYXUNQcoddAUbnfvDqVEthZSJg2f+DMGZNF7Yn4ttx
	fYOx7r0dVUNR2N1nTEvg1CI=
X-Google-Smtp-Source: APXvYqyf8WioQT58qiq3tBX+dtvEbgrgH63c8JjR23RP/ndDDdQp2g4+f5QEOTf6Q98RVW3flXGqmg==
X-Received: by 2002:a17:902:9044:: with SMTP id w4mr15954877plz.228.1570212531256;
        Fri, 04 Oct 2019 11:08:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b46:: with SMTP id b67ls2607524pfb.8.gmail; Fri, 04 Oct
 2019 11:08:50 -0700 (PDT)
X-Received: by 2002:a62:2b4d:: with SMTP id r74mr18837647pfr.30.1570212530593;
        Fri, 04 Oct 2019 11:08:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570212530; cv=none;
        d=google.com; s=arc-20160816;
        b=x15L1kuxc0TYds8GjxUwf7EBZ78so+XrDzJxefK3ufa1F7vsH94bqp4pE2zhucWMBA
         99hVGtfFClIsQTGG5nGfiqvcaZuwaiaM7vw0Oelo2Ltsw5JmcwZkJ1xgcO6HqYUehBDW
         64CUNWEDp2Q8YnSyoE3VPxQQuZpdkFRJWeKkWmJwJNGx+rpBjOYg3W0hyUB/T9kMRQLy
         yr8qXrhsUQQkbjb5pddwa67doPwO3kj57T8DbkmZqbm/bQ2GZ/IWbqU+H5mabzY/RVSu
         oc2Opazw8NxhAlUYKJSTbJVZEGOwboMn6KD2juW7B4vhXy76e9q6GIfDaxNmj4uPN060
         EcGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=bVhECVgYWcYWc1m8uEzWurmTDKJi7045y3cu4mRFVAc=;
        b=gJjGL4dNC7Ub/OzMdt2Yu4cO/P9uq2Sy0Oak50Hyb8qytK5rFVuh8DZCUsTAu7aTLI
         xAlb1AHxJbO/4WAJDGGQ6yf4fJ62Ik9xf1WX2wFHx9olYo0ixO80Pn74xSe8Lg+b+P+I
         kqQRmYpi4UCrgQdtwFxclonw7ZByo6It6zinDvxMzJ7Z74t/mfdibi95EcTxTz+dZAbf
         JEIplY7UfhJSUJf2POv6LyL5OuFhkSmE3PnUJ8pArbzHWI4bjdJ1mLfzGkAuHYZGtnG/
         a3BXuKyhvMB1lg+mH7Bqjg91AR9UD5ssuEODeWWbDjEBjhBVkF7VSUwprRRb/ngESp3F
         oktA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b="k/M11Dz4";
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id x197si562246pgx.5.2019.10.04.11.08.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 11:08:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id v4so4361065pff.6
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 11:08:50 -0700 (PDT)
X-Received: by 2002:a17:90a:fb85:: with SMTP id cp5mr18637692pjb.42.1570212529974;
        Fri, 04 Oct 2019 11:08:49 -0700 (PDT)
Received: from localhost ([2620:15c:6:12:9c46:e0da:efbf:69cc])
        by smtp.gmail.com with ESMTPSA id u10sm6955967pfh.61.2019.10.04.11.08.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Oct 2019 11:08:49 -0700 (PDT)
Date: Fri, 4 Oct 2019 14:08:48 -0400
From: Joel Fernandes <joel@joelfernandes.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Daniel Lustig <dlustig@nvidia.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191004180848.GH253167@google.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20191001211948.GA42035@google.com>
 <CANpmjNNp=zVzM2iGcQwVYxzNHYjBo==_2nito4Dw=kHopy=0Sg@mail.gmail.com>
 <20191004164859.GD253167@google.com>
 <CACT4Y+bPZOb=h9m__Uo0feEshdGzPz0qGK7f2omsUc6-kEvwZA@mail.gmail.com>
 <20191004165736.GF253167@google.com>
 <CACT4Y+aEHmbLin_5Od++WVqgiFX7hkjARGgVK0QUj7eUpFLVeg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aEHmbLin_5Od++WVqgiFX7hkjARGgVK0QUj7eUpFLVeg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: joel@joelfernandes.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@joelfernandes.org header.s=google header.b="k/M11Dz4";
       spf=pass (google.com: domain of joel@joelfernandes.org designates
 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
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

On Fri, Oct 04, 2019 at 07:01:37PM +0200, Dmitry Vyukov wrote:
> On Fri, Oct 4, 2019 at 6:57 PM Joel Fernandes <joel@joelfernandes.org> wrote:
> >
> > On Fri, Oct 04, 2019 at 06:52:49PM +0200, Dmitry Vyukov wrote:
> > > On Fri, Oct 4, 2019 at 6:49 PM Joel Fernandes <joel@joelfernandes.org> wrote:
> > > >
> > > > On Wed, Oct 02, 2019 at 09:51:58PM +0200, Marco Elver wrote:
> > > > > Hi Joel,
> > > > >
> > > > > On Tue, 1 Oct 2019 at 23:19, Joel Fernandes <joel@joelfernandes.org> wrote:
> > > > > >
> > > > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > > > Hi all,
> > > > > > >
> > > > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > > > > >
> > > > > > > To those of you who we mentioned at LPC that we're working on a
> > > > > > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > > > > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > > > > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > > > > > >
> > > > > > > In the coming weeks we're planning to:
> > > > > > > * Set up a syzkaller instance.
> > > > > > > * Share the dashboard so that you can see the races that are found.
> > > > > > > * Attempt to send fixes for some races upstream (if you find that the
> > > > > > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > > > > > point it out and we'll prioritize that).
> > > > > > >
> > > > > > > There are a few open questions:
> > > > > > > * The big one: most of the reported races are due to unmarked
> > > > > > > accesses; prioritization or pruning of races to focus initial efforts
> > > > > > > to fix races might be required. Comments on how best to proceed are
> > > > > > > welcome. We're aware that these are issues that have recently received
> > > > > > > attention in the context of the LKMM
> > > > > > > (https://lwn.net/Articles/793253/).
> > > > > > > * How/when to upstream KCSAN?
> > > > > >
> > > > > > Looks exciting. I think based on our discussion at LPC, you mentioned
> > > > > > one way of pruning is if the compiler generated different code with _ONCE
> > > > > > annotations than what would have otherwise been generated. Is that still on
> > > > > > the table, for the purposing of pruning the reports?
> > > > >
> > > > > This might be interesting at first, but it's not entirely clear how
> > > > > feasible it is. It's also dangerous, because the real issue would be
> > > > > ignored. It may be that one compiler version on a particular
> > > > > architecture generates the same code, but any change in compiler or
> > > > > architecture and this would no longer be true. Let me know if you have
> > > > > any more ideas.
> > > >
> > > > My thought was this technique of looking at compiler generated code can be
> > > > used for prioritization of the reports.  Have you tested it though? I think
> > > > without testing such technique, we could not know how much of benefit (or
> > > > lack thereof) there is to the issue.
> > > >
> > > > In fact, IIRC, the compiler generating different code with _ONCE annotation
> > > > can be given as justification for patches doing such conversions.
> > >
> > >
> > > We also should not forget about "missed mutex" races (e.g. unprotected
> > > radix tree), which are much worse and higher priority than a missed
> > > atomic annotation. If we look at codegen we may discard most of them
> > > as non important.
> >
> > Sure. I was not asking to look at codegen as the only signal. But to use the
> > signal for whatever it is worth.
> 
> But then we need other, stronger signals. We don't have any.
> So if the codegen is the only one and it says "this is not important",
> then we conclude "this is not important".

I didn't mean for codegen to say "this is not important", but rather "this IS
important". And for the other ones, "this may not be important, or it may
be very important, I don't know".

Why do you say a missed atomic anotation is lower priority? A bug is a bug,
and ought to be fixed IMHO. Arguably missing lock acquisition can be detected
more easily due to lockdep assertions and using lockdep, than missing _ONCE
annotations. The latter has no way of being detected at runtime easily and
can be causing failures in mysterious ways.

I think you can divide the problem up.. One set of bugs that are because of
codegen changes and data races and are "important" for that reason. Another
one that is less clear whether they are important or not -- until you have a
better way of providing a signal for categorizing those.

Did I miss something?

thanks,

 - Joel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191004180848.GH253167%40google.com.
