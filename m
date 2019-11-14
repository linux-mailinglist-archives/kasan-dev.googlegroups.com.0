Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEQW7XAKGQEK2VTWVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B4040FD05D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 22:33:12 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id f11sf5089182wmc.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 13:33:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573767192; cv=pass;
        d=google.com; s=arc-20160816;
        b=xfUphNCcu+iIrqTqnlJixfpWHgQ5Uz/dGmo6ECDmn2d6HXFE5NcQAyHjTbBUuihOVb
         MXjGDjOu8stIEiMzi/0YfWwI8X+ejXD843iQCbpI5vme4JYh4M70SCG3d8nRBrKgRrGe
         MS7ilHyqANJqM1TlL4/kmiZEhCKefjOUjrEms5MoKFuXJao8+YURi/G0ZX0lhb0ecGzo
         rOEGN4s/3FiqNWRStjK4uxQuTwoiF6IYFf/G2CEYbqsdOmv2nvMKV22aTtN+dXQ9JGio
         rkX83z6+OF7mbl/TSvPrMAeJRLkw2lWUFHIYwlpcDFtG3qkw/+pJtZPS64t2SBAtEU59
         LCFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=im+iOfJhn09zFP/zkwkLNJppXqQ+A4jOeOmWIRvQAzA=;
        b=jeB5CS98BSFYEk9XecvKDAgaGwU3s+r+FRYRsECp3irw+cMP31Jx/K7KmOZKIH/ziE
         dhaWGDEUacLNFpdVyEXmrRFOrgIX7DczgFKRa4JHjPo6wX8SLe19I2in0xpxMX6eoNrS
         xfg+IkRfwrzhsMInJWfS71KtABNxn6xI6AAgoGwuWFp6HE+CX/Bii7kkikMloucFCytW
         qsGj0WkAVtOzKMcGxtXo7jk0wZk8imt9s0tfCtr02MqMw0szPPzi4bcSzPQJMFO5lly1
         v7HgaJ+cM80sxzEpoIlL5ErmRCNmYxOfWenonJg7/90D6Ql7BlVyrzwherEgbmlu8HDC
         uB1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KkzxVX4K;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=im+iOfJhn09zFP/zkwkLNJppXqQ+A4jOeOmWIRvQAzA=;
        b=gbIGdExylDkV/DTXf5H6+GNCmCMvClKMQxI/e381JrDcvge7kc++oW6/MuBK4SMaNC
         rkvKnHaMZETJYFOMOF1C+PXABolkrFXF76k2XYMpbJZA9t3X/8w57Fv8CsrHk95iTZs/
         tKALLjwnbujY7CPOVOjFEUVfdry85bTwlXXc96IdFAOvXDCQOGtVOcq7N2gcR774JrAE
         04c0yrspKR7IQNekjKZ30Do7RA5NCZALvJVRmKEa8wrLELFJkMSBuoHpQd88Kf99S3ow
         3N7CF+d5dD9HwQCczyV1BNL/A+j1Z1mDY54mUQNn9/vY7e0hZb9WLGqtD4pn3ZKRGpSe
         4cbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=im+iOfJhn09zFP/zkwkLNJppXqQ+A4jOeOmWIRvQAzA=;
        b=Kvo6PfADwrsFzrbeYC2thSnqYOkLTLs7psN5PnXfn9/+Z39eEjxuPQSSVUfDnTl2RV
         TOgYd0QCGZWA58N4DVj48SAzh9XXOVmSblzdOyZzFfKqSGysNt3H0h9SKqKQ9Al4NME3
         QV5SRBwMfgfTzH1FYJYvExP72n83N8gul5ddgDWHQmf6PSqK0pX5Ytqa/8mjBK5ILHTr
         RZcc22T5aeYTP//7OcuItRG8ESVQ113fYpIkPBCixUsNTkR/oHVziYFb/N3b2tygPGW7
         XWomJXtzS2BHm9kVZ447lDx1psctnSFg+ECocGlLRTfLScxuzUfrendOW6Gwq2fPnueA
         gffQ==
X-Gm-Message-State: APjAAAXCoXSkWOM0eVWCK4VAD3SjadfaWXiaFZwGqXXOymp7End5Ndf4
	8mDAPNwpjaiOzgVw3aZqfHU=
X-Google-Smtp-Source: APXvYqzZTRLyBF1czq9IROxpy0+9fnx6uqiuPLdfNR8IXa6p9vcgByEBrSRBXUOTOogJ1KJalKKl2Q==
X-Received: by 2002:adf:df81:: with SMTP id z1mr10707039wrl.278.1573767192320;
        Thu, 14 Nov 2019 13:33:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f74c:: with SMTP id z12ls11069477wrp.10.gmail; Thu, 14
 Nov 2019 13:33:11 -0800 (PST)
X-Received: by 2002:adf:ce05:: with SMTP id p5mr1176617wrn.48.1573767191682;
        Thu, 14 Nov 2019 13:33:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573767191; cv=none;
        d=google.com; s=arc-20160816;
        b=WZ7nfqmK9p4eGphuZDO48F1+TJzu5am/tVXh3rwqXVsSRv11/Xx+OqNoljldnAIV6p
         KhuqvREXeMws2YaVJg5OA9LEjSEa6yRdX+F7c6gxZZxd8XTyLp2iSm9tRxBCLq9kXcEV
         xw0ov3+XNaZhREIMSow/hH9QGcAa3Eka0L6kCpYVhLeryddybgktT+iRLlLb/oIGRDaL
         gIKB71tyoNyJe9915h4wXHMgqmsfWCAb3STuLJ8HkuhQldtt+6elyb3XmiW5e0Ajf5xS
         WDB/jYrYivz19u6QgzuIU5AtgxjJBPdzzMMbbxmYzMwZKNXcS0iplFWQWoc1yJhPSabe
         01eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NJ5AXjvvGN3rmW3ly7bYsvI92wsOVyTwzutsVT4lLNU=;
        b=S7L0HZekh9MOBxjflA27UOhzZ//VKOwoTedObmr8KgTVrn4sUnLZujnHzdGgVcbxDs
         q+DcOB/o69V/YpmOoQWgWIL4uVdWEgOz2ziz+4JEWiMO7OJbBGZZQpB7q3Dzi1+XvNQY
         5lTmqkdvQIjj6pU/yjWri4SON+0vQuwzOraH6eX06pce1jlpf8GG+I3z3vvCMeLUNz8m
         owYIEZY4LkOhME1oQhiSyVITUFMPAoGYUAgeivS/O6f7GXTjqLeBwygy9heUBqBnnlNn
         J7eKjG6N5+dREiKIrcYXHjV+dBHgL4AfV+wgJhSxD3SHGUCtk9lGMZ8LeJb77MWEaUP0
         J/iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KkzxVX4K;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id x8si347872wmc.2.2019.11.14.13.33.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 13:33:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id r10so8483036wrx.3
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 13:33:11 -0800 (PST)
X-Received: by 2002:adf:ef91:: with SMTP id d17mr10599325wro.145.1573767190754;
        Thu, 14 Nov 2019 13:33:10 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id i13sm8361956wrp.12.2019.11.14.13.33.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Nov 2019 13:33:09 -0800 (PST)
Date: Thu, 14 Nov 2019 22:33:03 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, edumazet@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191114213303.GA237245@google.com>
References: <20191114180303.66955-1-elver@google.com>
 <20191114195046.GP2865@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191114195046.GP2865@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KkzxVX4K;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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

On Thu, 14 Nov 2019, Paul E. McKenney wrote:

> On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > only enables KCSAN for x86, but we expect adding support for other
> > architectures is relatively straightforward (we are aware of
> > experimental ARM64 and POWER support).
> > 
> > To gather early feedback, we announced KCSAN back in September, and have
> > integrated the feedback where possible:
> > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > 
> > The current list of known upstream fixes for data races found by KCSAN
> > can be found here:
> > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > 
> > We want to point out and acknowledge the work surrounding the LKMM,
> > including several articles that motivate why data races are dangerous
> > [1, 2], justifying a data race detector such as KCSAN.
> > 
> > [1] https://lwn.net/Articles/793253/
> > [2] https://lwn.net/Articles/799218/
> 
> I queued this and ran a quick rcutorture on it, which completed
> successfully with quite a few reports.

Great. Many thanks for queuing this in -rcu. And regarding merge window
you mentioned, we're fine with your assumption to targeting the next
(v5.6) merge window.

I've just had a look at linux-next to check what a future rebase
requires:

- There is a change in lib/Kconfig.debug and moving KCSAN to the
  "Generic Kernel Debugging Instruments" section seems appropriate.
- bitops-instrumented.h was removed and split into 3 files, and needs
  re-inserting the instrumentation into the right places.

Otherwise there are no issues. Let me know what you recommend.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114213303.GA237245%40google.com.
