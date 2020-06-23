Return-Path: <kasan-dev+bncBCV5TUXXRUIBBOWUZH3QKGQE425DW4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 90899205FA1
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 22:46:50 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id a7sf31632wmf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 13:46:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592945210; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z9SauMw3jcm1fEcYgtvqIxmHZWSC4IhH2eCEwyzM/iM83YB33EA7JIoOi7v+iar0u3
         wU2Jdf+frV3ANlo2CkNyi9fh9RgUFD6+Yb47wd36A3afpkeo0Qd2gQ7uUcz5F6IIzdu7
         JyRYqBUbPyQkEyCMZ3NVJ8O/Jpa0JdIGXvG3YfSTswwq+Kwqb5WwLGeJdD/WUOq08WFL
         WXzLI9u4N37C04/ZczMJxJtQVjEv4oF0G7zISWUhD7hQvvwrtQYnYzCGnsEkS+hNhkt6
         JcsZp7z4HZ6VtKNSdx8Hy31A1QWSKwbvg5BZSovVyjYCfDd9wNhWblMLAkNFPVthLLyw
         Xvag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4qBKS30rG+kGeaiDiJJ/h+Sr1z0uOWHfRz005bbL7jc=;
        b=LMRhiPcotLfeveVmkiAmrV2hnfxFt7IQlRBCxYsXGsafg9+Ezbcvve24Krk/DJfp+q
         PnzvjxTxORM3GsimRO0FHC23e+lOIKG/WSJ6caEtafUM1UUh88BLO9kH7Oujni6XXXkt
         s5PYZJRt+Q/lVAU2hPw7NdokayZpRGRrruyZUfE8FoQ7Viwd9u2Qfz3l03+HpenQ3oKe
         /rYZUC+Pyf9GeE2qXqjPuVs15hkfw5/MCuhdiQmXIlYtpvJ9szICrbUCLAf2XGxsx8jY
         m6Hg1+VmWODApb4jHiZDk8S+1PD0oMwCGgGDBYwv0m+hQY6FVABHaJZnqhpAwJ+LkgEA
         5oGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=seG8hXT4;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4qBKS30rG+kGeaiDiJJ/h+Sr1z0uOWHfRz005bbL7jc=;
        b=pbCWtPOJqqxxixnmYGlSjJpyQ4L35fayDvIXO1DOqdngkK1DekZ2h7i8rBbihegph+
         AdEBTc6cBf9e3+PokdxSJD1BQ+mKhqzpyRD59sLziMQpud892FuN7k9JUJD2Uukox+Vh
         7k68GTSqgJfyEJcmJLC0xSzLXC1STfDpHhTDCqQc1Mf4NwJyRNM+CxeGyRcPnUAgrst2
         GOHRAQ90tu+KEOPqWKxTdUphlvMdjvD7K8DqXPSBhzjB17lXEoGMF5cDDOHnLjF/rYCX
         /5e52JgaZoRNyWXxzQLc4gnOiS1lt9tHAQyQKm4oZz551dpM0/FxT/J9aQLyIJ9/VaOG
         biBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4qBKS30rG+kGeaiDiJJ/h+Sr1z0uOWHfRz005bbL7jc=;
        b=sUQel2oTe0ZR+U8O10Ri8+lWCe9F9PL435px5qXUPO2auBBv7YGcN8rOZ3Ro1QT56j
         sEFCQBr+SvfHsst2x3hIxLrZyDcIJGf93BZue3n04IgeluYRcLtMKEvgNdRbWkKI67FF
         vqrZuVd6LuHJ/L6+RoMGNId14XRKd8YLYTVIOPuAC5fJaSGprHub7lj4vj7ekn7NX1Rx
         j/bfDc8D0lgU1sFogUJ/qWHfnpOY2TT4SVn/d0CYM0aii5AwWNAX//DrsZAeg8aHxek1
         XSPa4PLQXkKkebue3RVxtXXbtRtybh45EfoQegHzbGCA+hqA1Ecr3x3O8/4W+IHoWp1X
         nNyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ecHqLkdSMmBT+djLoiTQECa8N9tsUV8WI2KVtqhp/rDwJdgsD
	WQ3qqnRsvAP5HhoxZR+aA9g=
X-Google-Smtp-Source: ABdhPJwnheFNpVK74jHGdM/8JZRopygR1yzlPBLxH5RXbsSy2M4n1OKtDql61MYuOfmqmGGUTDT1VQ==
X-Received: by 2002:a5d:50c9:: with SMTP id f9mr28321425wrt.9.1592945210308;
        Tue, 23 Jun 2020 13:46:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aace:: with SMTP id i14ls139563wrc.3.gmail; Tue, 23 Jun
 2020 13:46:49 -0700 (PDT)
X-Received: by 2002:a5d:6748:: with SMTP id l8mr29902471wrw.347.1592945209881;
        Tue, 23 Jun 2020 13:46:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592945209; cv=none;
        d=google.com; s=arc-20160816;
        b=p0u4dddOfsg/BMGfXRQoT2Z+G4+ijcq0roEV2G5RkZmsYTbBblT0ifHQjLEvVAVpRt
         0OYRPgFyO9uNBye3VelcC5/jYAyuISs+QPh4GQIySDFsVuPUlgqwCbW+GmaPg8DOIZlI
         j2YJ4cCsEeafzO0Kb6dAq1c2AsnHOYjhKmSXBsBVzepcCEpoFbaRZl/6WODIfjYnre4L
         hVNlcok3PsqBwQHpAiGrWAxCuayEdOaojcxyEgOWLpnhhf5J9IDcT0WWlPyUZFDjTpab
         trfdycl/QA+04+xaOnAjcAnvWJLOh5dz6/lHxiVzdDl/Sf8Li9hJxv6SCaUPpBonkIHJ
         lgjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Sa3zU/E2E+o3LzbXQSq1d8ASG89gLQ+b6CLyD1I/MBY=;
        b=Wacok1QUN0wVv9Kt/4EYUuntVOjDtZ9h5O89j6XkjNBXJC6y2omtsopIJHjvO2DddQ
         wwnFdKQRs4xmmpaE30qBexEsJYS5uXY1nto6dWlZR8cdmf1J2c9lPEIkvPsOCoBDr0Bv
         lMVk4klprkYU1uZVLKIfmk6eATIGYb+rCUzDzo8KGrU0fRg00ZtcEDfdF+GL5v3Czx5L
         G48Y2qTEqClvVsYvzWXaMIPpIVGZzxwDE9ejCvK7vGLkg1ZYBfNqvkGBnZ5O5NxS1oC9
         vGxRq/IYrEq4GVZ8bPd1xv9ZZwEOAsLEVH97SINOqhwKm9MpA+oiYBkZQKCtZYJsIxeF
         Vz0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=seG8hXT4;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id q12si204564wmj.0.2020.06.23.13.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Jun 2020 13:46:49 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jnpod-0004zR-4d; Tue, 23 Jun 2020 20:46:47 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 450AD983A87; Tue, 23 Jun 2020 22:46:46 +0200 (CEST)
Date: Tue, 23 Jun 2020 22:46:46 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: tglx@linutronix.de, x86@kernel.org, elver@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 2/9] rcu: Fixup noinstr warnings
Message-ID: <20200623204646.GF2483@worktop.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603114051.896465666@infradead.org>
 <20200615154905.GZ2531@hirez.programming.kicks-ass.net>
 <20200615155513.GG2554@hirez.programming.kicks-ass.net>
 <20200615162427.GI2554@hirez.programming.kicks-ass.net>
 <20200615171404.GI2723@paulmck-ThinkPad-P72>
 <20200619221555.GA12280@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200619221555.GA12280@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=seG8hXT4;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 19, 2020 at 03:15:55PM -0700, Paul E. McKenney wrote:

> Just following up because I don't see this anywhere.  If I am supposed
> to take this (which is more plausible now that v5.8-rc1 is out), please
> let me know.

Sorry, I got distracted by that NULL ptr thing, but that seems sorted
now. If you don't mind taking it through your rcu/urgent tree for -rc3
or so that would be awesome.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623204646.GF2483%40worktop.programming.kicks-ass.net.
