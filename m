Return-Path: <kasan-dev+bncBC7OD3FKWUERBDPWXKXAMGQEQYP4WII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2032485736F
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 02:31:59 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5952618dad5sf1648510eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:31:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708047118; cv=pass;
        d=google.com; s=arc-20160816;
        b=FrZkTf4ErdPiEtve2FfC4mLD9r6vcqxUHNesAqlsi2MXneyvCH5SSo6gyZTiSSV20h
         euFZ1iIlAg9wl0M9ebf8p0/S9YXKaeA8rmQ366xB+tNH0M/kPIk20u/YOvbVxTa9sew3
         YI7nFfXWMPYq+Ytqqi6NK14ljRH0JOKwQTf+udVMDvzo+2PGdmt8UXMLFFKMU1HCDuUc
         N0rKqIltRLwsqo41eMB8kvGRMFl+TH3eZFCvd/rFmkzFmvs3RwyeO9d3n2v09YBnafPf
         arNQiq7MbiypZQTpThX2fx++K/prGJqOW9OfYcgSc/5WLffj6bWPxB1cKCc4JpnFp4E0
         zhdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j6xB9ZcaAIBzNdyY6ZhfK99u2Dcu9a2EoAOSoFapD+g=;
        fh=W7NouwqT2NFzo3NQod3ovm47X3vgCjF6cTUhJfaFTis=;
        b=P8UCTHVuEF3ostJwYehFpsNPb18Rsu4HESXwcUaTfZNFSJdYG2NMKqtEr2aX85cDPU
         UGv+zCD6WX5k8O6UeW/edBHORVNrR/1B6/iYpB3VP0Yb/x1W3yxkhWB1tzkxnsALpQkL
         CuGICa/DiX1kLMd8io6u0KewZMpWtGV8gVU4UD384kLrZ7o7QWK90rHPR/ChYEpAzE/L
         dAqF446U3f/BPFN+WYC9Z6m8wQk0LyWgwfIGj5k+1TQlMz/MsotyilH9RrjerrmISbTo
         waz4wUs27w5UziZVaDk46aPYk292+weDdpwY8SOnlDvmg2wE0yE0cLBBCAyM1ciCwACK
         vBEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Vkhz5hyV;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708047118; x=1708651918; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j6xB9ZcaAIBzNdyY6ZhfK99u2Dcu9a2EoAOSoFapD+g=;
        b=g5bmUD3t1vGEsP0W+JUNCHrqsurkBF3qW3JH4No1EXwbWPXtcQSpI8Z6JhzJk9cLzE
         wqT+eQmy+DS74FpRQ14J5lzgFoU926e+yOkmbTuxbRgXKNw34I09ByzEmXzvYnXdnQno
         OFdafQ6FeEelI1OivGz/ylvPh10qjBM7Yz3M3iyW2+GBACRt+ou6mQuKVhsy+1ajJY3/
         i853cma1GItltrm99JCjb14i9m6VDykLLe/wjAJ5YTqXvxD9MWb+VKQssz4l5CZmWXzU
         VE/1fqxkQXYbN3uOOlbAhlN0gWfWb2SRvGoGb5ILIrhbegAIu3UbC4nxuubckvTowq1x
         YxIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708047118; x=1708651918;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=j6xB9ZcaAIBzNdyY6ZhfK99u2Dcu9a2EoAOSoFapD+g=;
        b=puunCmINBSBy9tDZBhmQskc3lm3YcIiiNx0iiDUelj8DBWb09c+nw/s0/U7yrFEf/D
         mIi9bPnPFsiR/wmOkgQjpyGXA/G34FX8VclH9T6o322R/sc+llAfWkoBYOzvcKsXcb8q
         taVAyqO85I71j/LvudCyaLjXau5gUqB5+BZatsUFyYnYF33s2/B570oxsaLWUAb9iHPB
         0udC5SSP3R4u+2dlQtGH/BaxU4dEJCL8YUPdcx5ucCuouKHF0SNFutG3FSqtS+pNs2aN
         YqqSQnfVea3bX2MDW6tTGY6OiFo3j5yG4RKfNnRFqWYLFdMaJZbjoexfVB78cJUIAyjo
         JI/Q==
X-Forwarded-Encrypted: i=2; AJvYcCUS6NM22gcIlBPgljAmZDAIKPZhjyqkiWAvJKnGtewqfzaBUGTl1560rNhYj++7ztlBVNqTrYszPjV/xjBtndJyuXB+vRpEBw==
X-Gm-Message-State: AOJu0Yzm05KJk/NSFESyPvEszoeJgzFwlWUs+ctEqiwOqv49zgmnMTwM
	pen72EFDcbcMjQHq4yq5jLHn1Pl4/aN9KHfh0He5eztkCQm+zvpy
X-Google-Smtp-Source: AGHT+IFCf1hTv6y5WXN0Ba6glrqfuQA2KBCZZx1ZhoOZ9ljBdR436GGvt7o+ZFNDQ9cKjVniAtgx1g==
X-Received: by 2002:a4a:9b04:0:b0:59d:3b20:f1c8 with SMTP id a4-20020a4a9b04000000b0059d3b20f1c8mr3807539ook.1.1708047117903;
        Thu, 15 Feb 2024 17:31:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5703:0:b0:598:c95b:c3bc with SMTP id u3-20020a4a5703000000b00598c95bc3bcls312459ooa.0.-pod-prod-05-us;
 Thu, 15 Feb 2024 17:31:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVUtwSRm06h/mTIYf8RDnIFlvwi8x1l1Of5Csb74QzvlanOelKJzIef2VQxz6BL1E6fssrz8FVEGRR4FOwYbHjphfvsSUvCp4zvUg==
X-Received: by 2002:a4a:9b04:0:b0:59d:3b20:f1c8 with SMTP id a4-20020a4a9b04000000b0059d3b20f1c8mr3807455ook.1.1708047116493;
        Thu, 15 Feb 2024 17:31:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708047116; cv=none;
        d=google.com; s=arc-20160816;
        b=FlE3WxAu0+7B+wtIYvTB2K6OYd60xoEuF4wWZwykpaobA4pfzNIHsRwGIFOGuZaKdS
         8C4d4oi7goDCC1zuboLoY2Mk3AqsooLidNgAps5WbDJxseCmtYlnXRwdqdMqHeKf5sFS
         vOxYuPtLELDQT+Qq8WFJhntZyQAYpDp0ZGlRnqaosWRA99UoBImL1wRy0hPxMYvOLDAD
         eSlCCjQzmsOt66yNz7FuUfanSEGBC+cWb7Zq6XS5B00CbIqOBkbzrkJG0f7SvRRMyrWa
         nbN5yIkaNmvlgy4KdENY9wlTxKuFjw/wBKTZ/vs2650zqTTRatRf0Ed9Wd2y5lV+XFX6
         2E4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vQYZ59CBPJ0zZaKxUafJy9oOl819GTZex04PI7LYJTI=;
        fh=rOxh/8cm7cP3sfqdcSsbWjaMSuZIRcfC1Atu7Z91y70=;
        b=pgR3R+bTtsqKX2hy6x/2vRkbCefjRgxFf9MaKDEQHZEJLKrv9ia9U6jkAvwJQNPpD4
         YCgWPYNlLrRoz6s535AHf67BopQ5ca1OKXYqKdCX68Pm/QtlBLbtNDghhNoW5PjfEkZy
         hlOfD6s/vUNNodr1YklJrgJz2W5LVVfEU1aariVIFBJakvZL/Pbf0Na0xtI3iR1TOzCe
         XAcUtwh56doKdmEE4JkuKt324xKlGa6cSZ7200vbttyvESAgjTKhAdxBzudJhxWfYYNr
         MkhsFx1Xodxj1JqofgWsJsDnCGFI2ugiQKI75Q3kD9wypjI0fgaOZDB1HRdq4So2IHMc
         dttw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Vkhz5hyV;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id m28-20020a4a241c000000b0059d6fb96189si313833oof.0.2024.02.15.17.31.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 17:31:56 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-60777552d72so14654797b3.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 17:31:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXXBRF6QSQ8TWn/yvNftJz7000X0bdctvlgdbRLODzvm1VXkMJsAsi5QujFubDGlgmyMenQIMa8mWUB0aR6cM42uIOotQCK4CjKRg==
X-Received: by 2002:a0d:d905:0:b0:5ff:9aa1:8970 with SMTP id
 b5-20020a0dd905000000b005ff9aa18970mr3787864ywe.34.1708047115685; Thu, 15 Feb
 2024 17:31:55 -0800 (PST)
MIME-Version: 1.0
References: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz> <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home> <jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
 <20240215192141.03421b85@gandalf.local.home> <uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
 <20240215193915.2d457718@gandalf.local.home> <a3ha7fchkeugpthmatm5lw7chg6zxkapyimn3qio3pkoipg4tc@3j6xfdfoustw>
 <20240215201239.30ea2ca8@gandalf.local.home> <wcvio3ad2yfsmqs3ogfau4uiz5dqc6aw6ttfnvocub7ebb2ziw@streccxstkmf>
In-Reply-To: <wcvio3ad2yfsmqs3ogfau4uiz5dqc6aw6ttfnvocub7ebb2ziw@streccxstkmf>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 17:31:41 -0800
Message-ID: <CAJuCfpE9gys=A8A+A9ie92uJXLeYVNyZGGVgxizjEjmRGtjdvg@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>, Vlastimil Babka <vbabka@suse.cz>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Vkhz5hyV;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, Feb 15, 2024 at 5:18=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Thu, Feb 15, 2024 at 08:12:39PM -0500, Steven Rostedt wrote:
> > On Thu, 15 Feb 2024 19:50:24 -0500
> > Kent Overstreet <kent.overstreet@linux.dev> wrote:
> >
> > > > All nice, but where are the benchmarks? This looks like it will hav=
e an
> > > > affect on cache and you can talk all you want about how it will not=
 be an
> > > > issue, but without real world benchmarks, it's meaningless. Numbers=
 talk.
> > >
> > > Steve, you're being demanding. We provided sufficient benchmarks to s=
how
> > > the overhead is low enough for production, and then I gave you a
> > > detailed breakdown of where our overhead is and where it'll show up. =
I
> > > think that's reasonable.
> >
> > It's not unreasonable or demanding to ask for benchmarks. You showed on=
ly
> > micro-benchmarks that do not show how cache misses may affect the syste=
m.
> > Honestly, it sounds like you did run other benchmarks and didn't like t=
he
> > results and are fighting to not have to produce them. Really, how hard =
is
> > it? There's lots of benchmarks you can run, like hackbench, stress-ng,
> > dbench. Why is this so difficult for you?

I'll run these benchmarks and will include the numbers in the next cover le=
tter.


>
> Woah, this is verging into paranoid conspiracy territory.
>
> No, we haven't done other benchmarks, and if we had we'd be sharing
> them. And if I had more time to spend on performance of this patchset
> that's not where I'd be spending it; the next thing I'd be looking at
> would be assembly output of the hooking code and seeing if I could shave
> that down.
>
> But I already put a ton of work into shaving cycles on this patchset,
> I'm happy with the results, and I have other responsibilities and other
> things I need to be working on.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE9gys%3DA8A%2BA9ie92uJXLeYVNyZGGVgxizjEjmRGtjdvg%40mail.gm=
ail.com.
