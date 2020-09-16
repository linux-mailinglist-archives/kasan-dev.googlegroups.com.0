Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVVLRD5QKGQERS3SGLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A53DB26C354
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 15:40:38 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d9sf2557710wrv.16
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 06:40:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600263638; cv=pass;
        d=google.com; s=arc-20160816;
        b=e7kMvvUzmex6OlcZTMUH1+J5lr5/F9SyMRDhO67J7yCOXafC3mctdrovrQiQ9T9BQB
         t4tTOCDdQQwt6+Yw30fqjY32AG4O5o7CNftYVr86fcqGxi1J8Q5aDrmH9le9pO5bDLB/
         k4R3XfLQFR7Ltl8pymTf2BdI60Wf/XQYUnvgmcYOAGx2SCp7j7TocKyXp9xpmXz/rj2L
         WH2+lsBxC2O1OX5scyGXgJFLhXBAbEtd88ErEdjX7A2qXdRLOpiOUHRwvqTNnjtkAX0S
         x/6k9Pr7J/T6ui65bqv0gAWZcRXHI4mu3HCQdfwC2AwZDsoQe5M6vw1T2xM4xifbUNK0
         gSXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9lCslFw/tMGCi64bDhO/kToNBALI2bvtF/qKT5VQZNM=;
        b=xYjBdIiQ0rCM6tE/26O9CgrdB4Rcp+0f3/CYNTfpTT+5tONBZYJEisXb1FipxY/uz7
         tFGtvf/yT+qGTerpkgI9TwRx755UaPNJHf45TV2875sPZEAQGG3LtHJxhzgDmqHDW0Xq
         im5QRhSR/j2h2yh4NRH3EX+WyejDSzm+c/TvCWbOVRmIxvuLzD+yEIksSK3xRDFemBIv
         mgCTKnGqFUbUXvt2MUrpEJ8sPT8oZHekzP0t2Wzcn6PElqsidPTVdTy+bgK/IsTkFGlV
         +wab2kBGXevuF3mIkKYqKebrKW85nyeEUlDfwRdEHVIl6fzA9hR8gNS6o9HwCI+zy5MW
         EitA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PUU8fv2n;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9lCslFw/tMGCi64bDhO/kToNBALI2bvtF/qKT5VQZNM=;
        b=NAzUj/Otrrq//OWSn2NfkAn4jbx3/mE1AE4wkaN5S58NcosJaJPCMejhhH6GkfcN2S
         rXivDC8GQxhaF6nRBF0CGZbLSUyMoEc2oK4QOzg8J8y9wFHi+F2vjLVyPAqw0zRaggOO
         jcnn3RqGla1OM6Q0DTBPZ/xXf99eV5Zio1OqOc2DXub1ByYBPU+hXei6bo8K3fYMo6Ed
         53LJkaJzcAquh1X9FDZ8/G5P0EvqJCdB+1DJWKvJMy5fM8wKxR8FED9PU237Nppw0x8+
         /BBVxa/hNz07US4NaQO7454JAHKReJN6C/E82pDRMBMXcD0AtmuHP2l6Uz9edlHdN3Hf
         zEgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9lCslFw/tMGCi64bDhO/kToNBALI2bvtF/qKT5VQZNM=;
        b=t3DySu6lju2WQNDdYDnHsh+uo9NjNPjhbg+CO7tJF0eif9Qe3mEjfhuSWexuziphsX
         tmwm2vuJUqPDLK5p3NdigYK60RiOrYF5t9hQ4c7dhchNU+X608aplTjFv0XAd8ndx0Yu
         K2qdEcFFpv6BJRjiG1ZIC2UhZn2QBetiOjwtdJdtXvockIIZLY3uEcnd+rO9IZxfsOtg
         12tdsnAT7bisX+E+cjwK8OLp1KRuErzHYF2vvdzW2PlDNR8bjWY9DhoAatYlGReMUZIB
         D4dwqwfySjF6xQP2toV/jWhCJzHcdbnIY3hwLZnd5CAcVeEBv8/WDpdpeJD0FodqS665
         +R2A==
X-Gm-Message-State: AOAM531z30PwRm1GOVhDU4erZUtNa9Snl21wn0DOMD9T/fIx5Xb9PFXj
	u5CFJY1GIMx2vKaeMA5HiZc=
X-Google-Smtp-Source: ABdhPJwyV6sGvGS1KbgVFJ4y+sFqKBtmseAq9qDYBDRIeOW6F/REDdRhXXbfobECo30XXnXcJYFC6w==
X-Received: by 2002:a1c:bbd6:: with SMTP id l205mr5038565wmf.79.1600263638386;
        Wed, 16 Sep 2020 06:40:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4154:: with SMTP id o81ls1135225wma.0.gmail; Wed, 16 Sep
 2020 06:40:37 -0700 (PDT)
X-Received: by 2002:a05:600c:20b:: with SMTP id 11mr4977873wmi.147.1600263637297;
        Wed, 16 Sep 2020 06:40:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600263637; cv=none;
        d=google.com; s=arc-20160816;
        b=N1PabL4wFqWtM+Eq1YT67J3ev3t0pZEb1lujgNJe5TZ6bar/iaFu81CHWJkoJaDqGD
         T+v4Ci94yT7n/P8TdSq63UpDI9fmPn9ohWGlNBfQ1tK3FAr1SvCWhG92udnGIoizEn9v
         Q4fEN3MbKxT0mJAdB0Pkm58HKcix2dlLGjSMQKscX+o6ki5AniAKpwuih6TIJ9he7Jvc
         ZbZrkRj+Js5f0kaqPBEiLAQAcPznW20MTWNhhtM5Y0yNwTFsIMg8pCcY2Tz/HDa26nt9
         7yvyRsRqs7jrYaIcKhbI4B7OGZeX85pmi5ifHLx6fbB3UdHr3UkrZnY3rk77tJeg1/bb
         zg5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uEjVdCuhEoV9lb5ls6kMmq0ECr43Rh1pbVRxVP/xc0E=;
        b=OY8AZsf0b1LZGKLoOt98sunM1MF3z3Yi+yBkAzZxwprld+x1B3eQHUYHBOV7UsudSU
         3Ny1L6sY6TGbFNhWjZ0JaYAPfK4HbUifb/16TpE3mThY8zmb5eoXc91HXjMIHyws6s80
         9ZqIV+hqUVwKyrYe3hSMaXeDvgDA5pHwCRlofuT4jE3jFAX8NnNFRrj4vJTf7ZYdIRrD
         AVMBKjfYfqtNJjCS/r0lPj6dbe/1iVk9wwvv0MxwWBJo+p6w9DqH+oqdaH5ieoNGxlyp
         nDrb5+8s8P+dRc9nnsIqYhvxo8B1kMbA3yFzZ1AkfDwNmGBNo+7hYSF816KWtx1UrMIW
         ziNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PUU8fv2n;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id k14si458003wrx.1.2020.09.16.06.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 06:40:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id y15so3112367wmi.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 06:40:37 -0700 (PDT)
X-Received: by 2002:a1c:7714:: with SMTP id t20mr5048312wmi.55.1600263636710;
        Wed, 16 Sep 2020 06:40:36 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id o16sm31108612wrp.52.2020.09.16.06.40.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Sep 2020 06:40:35 -0700 (PDT)
Date: Wed, 16 Sep 2020 15:40:29 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: George Popescu <georgepope@google.com>
Cc: Kees Cook <keescook@chromium.org>, maz@kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	kvmarm@lists.cs.columbia.edu, LKML <linux-kernel@vger.kernel.org>,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	james.morse@arm.com, julien.thierry.kdev@gmail.com,
	suzuki.poulose@arm.com,
	Nathan Chancellor <natechancellor@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	David Brazdil <dbrazdil@google.com>, broonie@kernel.org,
	Fangrui Song <maskray@google.com>, Andrew Scull <ascull@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, Arnd Bergmann <arnd@arndb.de>,
	kasan-dev@googlegroups.com, andreyknvl@google.com,
	glider@google.com
Subject: Re: [PATCH 06/14] Fix CFLAGS for UBSAN_BOUNDS on Clang
Message-ID: <20200916134029.GA1146904@elver.google.com>
References: <20200914172750.852684-1-georgepope@google.com>
 <20200914172750.852684-7-georgepope@google.com>
 <202009141509.CDDC8C8@keescook>
 <20200915102458.GA1650630@google.com>
 <CANpmjNOTcS_vvZ1swh1iHYaRbTvGKnPAe4Q2DpR1MGhk_oZDeA@mail.gmail.com>
 <20200915120105.GA2294884@google.com>
 <CANpmjNPpq7LfTHYesz2wTVw6Pqv0FQ2gc-vmSB6Mdov+XWPZiw@mail.gmail.com>
 <20200916074027.GA2946587@google.com>
 <CANpmjNMT9-a8qKZSvGWBPAb9x9y1DkrZMSvHGq++_TcEv=7AuA@mail.gmail.com>
 <20200916121401.GA3362356@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200916121401.GA3362356@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PUU8fv2n;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Wed, Sep 16, 2020 at 12:14PM +0000, George Popescu wrote:
> On Wed, Sep 16, 2020 at 10:32:40AM +0200, Marco Elver wrote:
> > On Wed, 16 Sep 2020 at 09:40, George Popescu <georgepope@google.com> wrote:
> > > On Tue, Sep 15, 2020 at 07:32:28PM +0200, Marco Elver wrote:
> > > > On Tue, 15 Sep 2020 at 14:01, George Popescu <georgepope@google.com> wrote:
> > > > > On Tue, Sep 15, 2020 at 01:18:11PM +0200, Marco Elver wrote:
> > > > > > On Tue, 15 Sep 2020 at 12:25, George Popescu <georgepope@google.com> wrote:
> > > > > > > On Mon, Sep 14, 2020 at 03:13:14PM -0700, Kees Cook wrote:
> > > > > > > > On Mon, Sep 14, 2020 at 05:27:42PM +0000, George-Aurelian Popescu wrote:
> > > > > > > > > From: George Popescu <georgepope@google.com>
> > > > > > > > >
> > > > > > > > > When the kernel is compiled with Clang, UBSAN_BOUNDS inserts a brk after
> > > > > > > > > the handler call, preventing it from printing any information processed
> > > > > > > > > inside the buffer.
> > > > > > > > > For Clang -fsanitize=bounds expands to -fsanitize=array-bounds and
> > > > > > > > > -fsanitize=local-bounds, and the latter adds a brk after the handler
> > > > > > > > > call
> > > > > > > >
> > > > > > > This would mean losing the local-bounds coverage. I tried to  test it without
> > > > > > > local-bounds and with a locally defined array on the stack and it works fine
> > > > > > > (the handler is called and the error reported). For me it feels like
> > > > > > > --array-bounds and --local-bounds are triggered for the same type of
> > > > > > > undefined_behaviours but they are handling them different.
> > > > > >
> > > > > > Does -fno-sanitize-trap=bounds help?
[...]
> > Your full config would be good, because it includes compiler version etc.
> My full config is:

Thanks. Yes, I can reproduce, and the longer I keep digging I start
wondering why we have local-bounds at all.

It appears that local-bounds finds a tiny subset of the issues that
KASAN finds:

	http://lists.llvm.org/pipermail/cfe-commits/Week-of-Mon-20131021/091536.html
	http://llvm.org/viewvc/llvm-project?view=revision&revision=193205

fsanitize=undefined also does not include local-bounds:

	https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html#available-checks

And the reason is that we do want to enable KASAN and UBSAN together;
but local-bounds is useless overhead if we already have KASAN.

I'm inclined to say that what you propose is reasonable (but the commit
message needs to be more detailed explaining the relationship with
KASAN) -- but I have no idea if this is going to break somebody's
usecase (e.g. find some OOB bugs, but without KASAN -- but then why not
use KASAN?!)

I'll ask some more people on LLVM side.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200916134029.GA1146904%40elver.google.com.
