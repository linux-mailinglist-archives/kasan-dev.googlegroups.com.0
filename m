Return-Path: <kasan-dev+bncBD4LX4523YGBBAGZR7FAMGQEIVLZB2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A479CCBB30
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 12:58:57 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4ee416413a8sf5471131cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 03:58:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766059136; cv=pass;
        d=google.com; s=arc-20240605;
        b=FQ82lWt7HevptH+8Ns44TZ19ZpAdS+cVMdxHumZbqdvoGYn0wgQZlL/k9fV6FuSDBV
         rixVv3emQx/0F8FUguP7fbv32JTV/U9PRboLaEfrnklR6VGpkbhJhYlJSDBMRd5V3PV6
         iOW+dkeD3qqoQFeNzGouvK003k/RrR/RMfFDlHCxzn3Q8wRhM8eLN8x+60wPnK+5MKOz
         1DCtKVRNZdP+DR4+6Q+rM9OU0j2Rsj/24YuR6GyMHpkbjOVZD/rYVBSkQpfuxs5yVjpn
         wDMX58E2/hqtexGkq9bKEqH6vt866SzE+Sy68d3CB3P/A8KRTuKWn3FpJEKhfX4+91VG
         FRwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5nP0dC9W3XgBa4WQNaW9uQUOMrxT6EKastzIlwXG5IA=;
        fh=NI/7NynGnWGHP8qNEEyxy+LEmeO2y9p7YJ4/Hmljn68=;
        b=h0cAGoplfh/QQ+0iRp4fxOg2FaIHxIyZOU+dKk9yWctySxM5hOp2Fc7zUw8WA87Kaz
         HPJqRD+biYmN5VPrexC4xNiEhZKTp458yvw0ZsAVmlHUVIThhaAOUY9ATuo3gjXMTiHe
         OcPwaB9mA9+cXAXceb00uXuamzxQIDiSuC9vNqqfbDOcc9TY/U4ZQQfVsoJ9fkQtWTUP
         p9EDcfOUcnRPlHFvFWYRAM9fihEVeJhWP/HAMrDuTPOTthuRbHs5BK4lJKKAeyb2jrRW
         OQwRG6jNHKYLNJlUQ91XaTnT9paDjIKd6V37/nC6cJQre2KKcjqgGGubjchu5IhVXUIm
         izKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766059136; x=1766663936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5nP0dC9W3XgBa4WQNaW9uQUOMrxT6EKastzIlwXG5IA=;
        b=FHzYGyqcjsdYMnzI6qB24/rRfgU4/6ccRGLa6M6BDtM4Z+icxVTpFpi7/KHIE9nLgb
         x2EaemkFHpwRjl8pcEo+OM+4Qi2/2/TELyPBy9Ub26SpBVGV41R3wig7mbFvsM5ghcFf
         KHRQmETkCgDHPw4vpBtv88j6B1dH+iYWNrkNuj2aPYcAn9HHepmTI216qWd83FMBMFSG
         pYowmTtIHJciEWABCMTxa69//qVo4glrMLkylSBiC3tNrQI/pLCRCgTyKIEUm6kxugZc
         1FNa0CX/cpCnXWk2EOo6TTSOLKgCEDqO9ESc515zrTrraZBqcju2yihhOUcjCEO45ylw
         a/EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766059136; x=1766663936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5nP0dC9W3XgBa4WQNaW9uQUOMrxT6EKastzIlwXG5IA=;
        b=pK543gzA9aBG3/Ktm8q37zfDZDRD60z3WpQ6kvs9TTl/SvFk/yitqQF+gGqyIqQcaP
         KElm/mwgMPa3JR43RNFhve47JU4DfQHhNNlS8hP7hg23rYddg77WA4ZtpU1EkWRiWuyR
         yzg4HCiECekHj1oCL0iEpEAR4gyD/TTEeIWPV7z2kdDNM21vp7vxC1uHXlNtqGaesmkK
         Lei6ddUWnJyqDnRaDZFSs3bWg5P02lxtfiUi4s4c6T/EQL3h2AZ7X7aW2Vp1nl5kXT9o
         ZEmrRZZhgu95nZrXd5kd5eGsIZ6Yi2w8w4s8e2EAtdERio+qVZ6MxjsD56aM7fk+U3Jq
         HAqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWe8pszL3cCLOmu8QVXQfw+W3adweb0fuxY60Uf05P5hp5ijiiQuw12vskZn8V9zvA4qywLQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxn+RSIvHJEpZNyKHjPQ2ryyVM/TOLi2Qts9HRP3fTT8AUW5vyD
	78fv5HXBusqk/S+U0hntN6bbH9FzZTAvNB8TTHPHMa6CJBkrssJ/vXK1
X-Google-Smtp-Source: AGHT+IHKDLyGA5ebPAbKALm3yGL23n5N/oh8dTEmrP8EfKr+ghLpU3Sb7Xqxkxe5LBBrjfVytN1QmA==
X-Received: by 2002:a05:622a:60f:b0:4ee:2984:7d95 with SMTP id d75a77b69052e-4f1d04ac58cmr296207881cf.13.1766059136378;
        Thu, 18 Dec 2025 03:58:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb+WA1ICSEzZu+4syRlB8oWbgHdRlRhydLDik+0rXyX7w=="
Received: by 2002:ac8:57d3:0:b0:4eb:7676:b2f with SMTP id d75a77b69052e-4f1ced8f7a4ls102906591cf.2.-pod-prod-08-us;
 Thu, 18 Dec 2025 03:58:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX11OtSK3ajqk/eCfC/TzMvnej7XzOrzD7Z2qU9UXna21KNVITxtAV+xYzYXHCZSDLtisXgq4MQsK0=@googlegroups.com
X-Received: by 2002:a05:620a:1994:b0:8a2:689a:edbe with SMTP id af79cd13be357-8bb398dfecbmr2933145285a.3.1766059134995;
        Thu, 18 Dec 2025 03:58:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766059134; cv=none;
        d=google.com; s=arc-20240605;
        b=Y0/6iNtVJP+lzTI8ErqT6RkSvxnw+xgRqQKZ4dFIu2zQrDlJBLkOLU87lRvKTn5s/i
         A/d+wFjodB1V/PrMZW1Y4kakXV9Kz7R92t5zkNpXp4mkpSEpKdaTVBl0n35vc5ro/AsP
         S+1Wh/NzWhNZCRKIykEU/kHTeHmseWHrqlEggMvKgsuBtTrafFxgOX52zp4C+AmzJONN
         GSGCClxM/At0m6eq5affDbjGHVI11KaF7ibZKh6qIWo9LCs/b47NXG71aqsyI/+o+mbm
         H0X7RQ3Gl21oIrXnukFHJOobDd6AhWdXt2ESm3ZFQ0PZesMLwQHDnN2xeyxYiC+p0nYU
         9PaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=n5VPtWcfPksBCcbueLtjzdMlBt4kj+8R+mUY8Cxtw6E=;
        fh=T3wClaat+dN+UoRLVQaTbO3ovvkWv5kT355pjJgL6lU=;
        b=fNhSpY+e2C+Gh+dJgTHwcwfXZglr3YGW40wqf/n2eP4s6lSi+0Byy95/OlsQzuy/Xb
         DGmrwzDec0PyufXMS/w3g6jfys/JABox9qoV+TrXmilKkVtZjWAB/0NN3Jd1eie3Bnov
         +xMKNbZuEugoVoAVSh7usuBGquqr4FWX709/AhlGDtThEqOa8w7pPdsRwtTQQi09MmWV
         zy7C2bcGZT5izceX3ELNp5Gb2BCOgonISuA6G6ZrGT1PFpsmg7f/BGD7YiYqf7HTZ0bB
         AaqNjmLsKf01VMRynEjBbqAPP4ijkrnsNNeIt6XJz3rCf/5Lom5NwdD4LzlYq6cG4E5p
         wMtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id af79cd13be357-8beeba3a74fsi8540585a.8.2025.12.18.03.58.54
        for <kasan-dev@googlegroups.com>;
        Thu, 18 Dec 2025 03:58:54 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost [127.0.0.1])
	by gate.crashing.org (8.18.1/8.18.1/Debian-2) with ESMTP id 5BIBwjSG450725;
	Thu, 18 Dec 2025 05:58:45 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.18.1/8.18.1/Submit) id 5BIBwi3N450723;
	Thu, 18 Dec 2025 05:58:44 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 18 Dec 2025 05:58:44 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ard Biesheuvel <ardb@kernel.org>,
        Kees Cook <kees@kernel.org>, Brendan Jackman <jackmanb@google.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        linux-toolchains@vger.kernel.org
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
Message-ID: <aUPsdDY09Jzn3ILf@gate>
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com>
 <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
 <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
 <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
 <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
 <CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC+4BdXgLLf22Rjg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC+4BdXgLLf22Rjg@mail.gmail.com>
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

Hi!

On Thu, Dec 18, 2025 at 10:56:48AM +0100, Marco Elver wrote:
> On Thu, 18 Dec 2025 at 10:51, Peter Zijlstra <peterz@infradead.org> wrote:
> > On Sat, Dec 13, 2025 at 08:59:44AM +0900, Ard Biesheuvel wrote:
> >
> > > > After that I sat down and finally got around to implement the builtin
> > > > that should solve this once and for all, regardless of where it's
> > > > called: https://github.com/llvm/llvm-project/pull/172030
> > > > What this will allow us to do is to remove the
> > > > "K[AC]SAN_SANITIZE_noinstr.o := n" lines from the Makefile, and purely
> > > > rely on the noinstr attribute, even in the presence of explicit
> > > > instrumentation calls.
> > > >
> > >
> > > Excellent! Thanks for the quick fix. Happy to test and/or look into
> > > the kernel side of this once this lands.
> >
> > Well, would not GCC need to grow the same thing and then we must wait
> > until these versions are the minimum supported versions for sanitizer
> > builds.
> >
> > I mean, the extension is nice, but I'm afraid we can't really use it
> > until much later :/
> 
> Unfortunately, yes. But let's try to get the builtin into Clang and
> GCC now (for the latter, need to Cc GCC folks to help).
> 
> Then we wait for 5 years. :-)
> 
> There's a possibility to try and backport it to stable Clang and GCC
> versions, but it's a long stretch (extremely unlikely).

We (GCC) do not generally want to do backport features; even for
bugfixes the risk/reward ratio comes into the picture.  It *can* be done
if some feature is important enough of course.  If you have to wonder or
ask if your feature is important enough, it is not.

The reason we do not want backports of feature is it increases
maintenance cost a lot, and so, development costs as well.

I guess LLVM has a similar policy, but I of course do not speak for
them.

You might have more success getting the stuff backported to some
distro(s) you care about?  Or get people to use newer compilers more
quickly of course, "five years" before people have it is pretty
ridiculous, two years is at the tail end of things already.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUPsdDY09Jzn3ILf%40gate.
