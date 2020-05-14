Return-Path: <kasan-dev+bncBAABBYGL6X2QKGQEM4URIOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 487281D3540
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 17:38:11 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id w15sf3864318ybp.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 08:38:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589470690; cv=pass;
        d=google.com; s=arc-20160816;
        b=wg8mvprDzZbChp/dDHqGk68A776JoVhxL7PjKnWv/tZvLY9hSJhEF2Z6M6470QeYyp
         /GhPqCvx0Nj7dJnIuuo2fBx7PLGw69YGrIV+sEp3JfFR4uO/UqNRBfsYpzaWrvvNhsH1
         lKwJ8XXIJUfpKfZD4jGs3xFW0Iq6CRmNn9R5qxMAJF77TVhlRGgsaL4FiFvJ1H8pcoXe
         6F93nylzCh7dX3GvoCHFgdneNIgsSefah61HWnAjt8vO22qdnkuNZYU5UKTZL4ZjMbum
         V21n+rdsWXKq5HMoexQFJX4VqrKuTdSJy2U0hz1fN0QKF1fIkQRzeruu/IWJ7w8omkWN
         WePg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=byGbYRHMh1Hy3IDSzCLAhUWSnHSXSFpcFeLzwU6+4I4=;
        b=G+4cUJniJi6v0VEbT6AkIDNpWJqel2bSIdCSOzLVJxPNooGRVpASoZl5FjLsm4XNgO
         nnGLMTGdFmIFb1BQpVRYEeddFBaNzpnqs+amAx5lsRd0PqB0ZFZINf6E/SuDoCsTlEn2
         0gZ9aMNpwlni5Otgd2javxo++TZ5fajMyzPN6ix0X85LninDngq1H4tsOrXfqVy1IdvU
         fCFCMzbMSfqrWiQ73oee8cbjCq0VRzrPnsoGBW9++y2sp7MKpZQ76VY1RfVpqsE9kJGo
         VMKHuLE53qnfw9JMVFbnLoGXj9C1iYcO8pA1qHis6bfZmAbM5X/dpu5M68ddmJqvbnY6
         5RrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=sxhaAf1C;
       spf=pass (google.com: domain of srs0=l246=64=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=L246=64=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=byGbYRHMh1Hy3IDSzCLAhUWSnHSXSFpcFeLzwU6+4I4=;
        b=l3Z8bK9ubDbfknXrrfcH/pJ368jTHWKRl4mVWrd5PEelE21BZcw0T27podMnkaqvNz
         ec734gqDXjwNv8S+iN9pLZXu8LuI8lQZBDS/5kXtFvxCNSdEavofgS9CbXmuVm3124N+
         QDK0Ca/+HEsUZcP2buqM4qQRqo7mW5wYmvyC1OZXKP/L3hT69EM3zOqwkYUqQEBP/QCj
         NMZ5x4TncWoOmpcKzdIcFtWbshkGyKVNoLVU1BtJXx5ulVIUFipM3e+GKyV4lnWvmCKB
         ctOKiUjDwkKJGehdi5kTp9yepXAFi+j0eTiwGrBYboEMsJ4HkT1QYtjnbECvgWu7+n3Y
         pbVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=byGbYRHMh1Hy3IDSzCLAhUWSnHSXSFpcFeLzwU6+4I4=;
        b=T9Y9XObKKRFL32MEWEu2TSjDL7GzwE2Fg1ztwUg2HgumyJR1HltE5AmDYlNlpUhmND
         r6ccV1LFBd4Qus4xSoSYLb3bSH0Waq1SzWmnPPaq2942sTIFIKaytbltNfvvAf0mYSnh
         Y3rVEZhYFXOdKCDyW2TK6ro9ugOEsnEs9qmHkDDt2fIHoh3KwXiJHPwUEl/UNGxv5F7X
         COrsxvKpT1Io2aMW782QZIUj2HTohYOItouSBrMAkuXMEk1kwfH+c1NYDm07nZj0uHYq
         0DBldY8QTYMcgrCEtKkp+nXuczW94lEEmOjpdUfRLhbhGyYoX6eWTXR5JxIaydpq59Eb
         4QHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LHbGSy6a6YppoX4JW4rjXqxQGuUduSoNUvUGFZwUrt/cq+p4k
	QePI8kZymD750vFXeAmWWo4=
X-Google-Smtp-Source: ABdhPJwnr+5wLapYpzBIEBYVZJzr/1YOYnHEBbe/65mfUnnIVmmRal+kwwio0OPD+ZpKRI70xQBTSA==
X-Received: by 2002:a25:4f44:: with SMTP id d65mr8576915ybb.149.1589470688416;
        Thu, 14 May 2020 08:38:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:50b:: with SMTP id 11ls1359958ybf.1.gmail; Thu, 14 May
 2020 08:38:06 -0700 (PDT)
X-Received: by 2002:a25:4984:: with SMTP id w126mr8337922yba.20.1589470686442;
        Thu, 14 May 2020 08:38:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589470686; cv=none;
        d=google.com; s=arc-20160816;
        b=s0tXmduiQZvh+73Bx4XmEquv3iegFu3ETxvlXP6DP0HgWjXOhXSvsyU7mg1LEUHKO/
         8BPfUgjAnL3fcgkllzKSf5AIHUgpGmV+htnmJ0l/SMB+1cjoMQpv4XfvVOm+Ml80omix
         7kkZ96YOb1NyecJsgTfBTdsye2AiEGCH05p9HyioSS4TdtmH0GYQa5S0N1c5E7kXmxYE
         Qlmr1+7CIvhUVjHAMWGqaYa5vmNE3Y4f6CdUuEjTYW22r8vC7I2tDY1P9spMeDawuEVG
         azfU5+crtm7K4pHa7Uh7h6cAvs+bf/waRUcCiABSaKhLma7UXiVcg1SdJUCXsyEYEaCR
         fcYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=F31jSHlA21mus3PtHDeK9HJ1gg7yt8Xlu4/JqvFXsGc=;
        b=v9VbsWS9n47sRxjSEO720UHziNZjIHg6seW/T4D8+BP1lWlUygpObC+RXiBL9kgvnE
         bXemc0+vg7/MN4KgBmUH6oDmOF2tAkmzQU0nLNjTgeJ+x6RaTradg1rWupENFSiTluzk
         6u87OcJvXG/0AcNLPazWH1qzfJq3YsKeq+JUpKMKL06qSmsAp8ut5LCqafH/HmArQd+Z
         bGMnC+sUUkAhCI5zOA2+dOqK22+RzTyQN5mMBlNCBNnDUXPj1SYQZwAS3Tb1UQiIClTM
         nJ+Y9AFF6BYY5biwvA4oZkEOXCTuxmkSdQ6E4YqH3DLhvX2vYiPqEUiK5wwP/WS/q/KI
         p0Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=sxhaAf1C;
       spf=pass (google.com: domain of srs0=l246=64=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=L246=64=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m9si242843ybc.3.2020.05.14.08.38.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 May 2020 08:38:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=l246=64=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6BEA42065D;
	Thu, 14 May 2020 15:38:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 5620435229C5; Thu, 14 May 2020 08:38:05 -0700 (PDT)
Date: Thu, 14 May 2020 08:38:05 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Message-ID: <20200514153805.GK2869@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=sxhaAf1C;       spf=pass
 (google.com: domain of srs0=l246=64=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=L246=64=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:
> On Thu, 14 May 2020 at 13:05, Will Deacon <will@kernel.org> wrote:
> >
> > Hi Marco,
> >
> > On Thu, May 14, 2020 at 09:31:49AM +0200, Marco Elver wrote:
> > > Ouch. With the __{READ,WRITE}_ONCE requirement, we're going to need
> > > Clang 11 though.
> > >
> > > Because without the data_race() around __*_ONCE,
> > > arch_atomic_{read,set} will be broken for KCSAN, but we can't have
> > > data_race() because it would still add
> > > kcsan_{enable,disable}_current() calls to __no_sanitize functions (if
> > > compilation unit is instrumented). We can't make arch_atomic functions
> > > __no_sanitize_or_inline, because even in code that we want to
> > > sanitize, they should remain __always_inline (so they work properly in
> > > __no_sanitize functions). Therefore, Clang 11 with support for
> > > distinguishing volatiles will be the compiler that will satisfy all
> > > the constraints.
> > >
> > > If this is what we want, let me prepare a series on top of
> > > -tip/locking/kcsan with all the things I think we need.
> >
> > Stepping back a second, the locking/kcsan branch is at least functional at
> > the moment by virtue of KCSAN_SANITIZE := n being used liberally in
> > arch/x86/. However, I still think we want to do better than that because (a)
> > it would be good to get more x86 coverage and (b) enabling this for arm64,
> > where objtool is not yet available, will be fragile if we have to whitelist
> > object files. There's also a fair bit of arm64 low-level code spread around
> > drivers/, so it feels like we'd end up with a really bad case of whack-a-mole.
> >
> > Talking off-list, Clang >= 7 is pretty reasonable wrt inlining decisions
> > and the behaviour for __always_inline is:
> >
> >   * An __always_inline function inlined into a __no_sanitize function is
> >     not instrumented
> >   * An __always_inline function inlined into an instrumented function is
> >     instrumented
> >   * You can't mark a function as both __always_inline __no_sanitize, because
> >     __no_sanitize functions are never inlined
> >
> > GCC, on the other hand, may still inline __no_sanitize functions and then
> > subsequently instrument them.
> >
> > So if were willing to make KCSAN depend on Clang >= 7, then we could:
> >
> >   - Remove the data_race() from __{READ,WRITE}_ONCE()
> >   - Wrap arch_atomic*() in data_race() when called from the instrumented
> >     atomic wrappers
> >
> > At which point, I *think* everything works as expected. READ_ONCE_NOCHECK()
> > won't generate any surprises, and Peter can happily use arch_atomic()
> > from non-instrumented code.
> >
> > Thoughts? I don't see the need to support buggy compilers when enabling
> > a new debug feature.
> 
> This is also a reply to
> https://lkml.kernel.org/r/20200514122038.GH3001@hirez.programming.kicks-ass.net
> -- the problem with __READ_ONCE would be solved with what Will
> proposed above.
> 
> Let me try to spell out the requirements I see so far (this is for
> KCSAN only though -- other sanitizers might be similar):
> 
>   1. __no_kcsan functions should not call anything, not even
> kcsan_{enable,disable}_current(), when using __{READ,WRITE}_ONCE.
> [Requires leaving data_race() off of these.]
> 
>   2. __always_inline functions inlined into __no_sanitize function is
> not instrumented. [Has always been satisfied by GCC and Clang.]
> 
>   3. __always_inline functions inlined into instrumented function is
> instrumented. [Has always been satisfied by GCC and Clang.]
> 
>   4. __no_kcsan functions should never be spuriously inlined into
> instrumented functions, causing the accesses of the __no_kcsan
> function to be instrumented. [Satisfied by Clang >= 7. All GCC
> versions are broken.]
> 
>   5. we should not break atomic_{read,set} for KCSAN. [Because of #1,
> we'd need to add data_race() around the arch-calls in
> atomic_{read,set}; or rely on Clang 11's -tsan-distinguish-volatile
> support (GCC 11 might get this as well).]
> 
>   6. never emit __tsan_func_{entry,exit}. [Clang supports disabling
> this, GCC doesn't.]
> 
>   7. kernel is supported by compiler. [Clang >= 9 seems to build -tip
> for me, anything below complains about lack of asm goto. GCC trivial.]
> 
> So, because of #4 & #6 & #7 we're down to Clang >= 9. Because of #5
> we'll have to make a choice between Clang >= 9 or Clang >= 11
> (released in ~June). In an ideal world we might even fix GCC in
> future.
> 
> That's not even considering the problems around UBSan and KASAN. But
> maybe one step at a time?
> 
> Any preferences?

I am already having to choose where I run KCSAN based on what compiler
is available, so I cannot argue too hard against a dependency on a
specific compiler.  I reserve the right to ask for help installing it,
if need be though.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200514153805.GK2869%40paulmck-ThinkPad-P72.
