Return-Path: <kasan-dev+bncBCU73AEHRQBBB3FRXKXAMGQEGBN4EXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B958857125
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:06:22 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-35fc6976630sf1008885ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:06:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708038381; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqKS+dZ7PwoBFNP5/8oOOU02QDiEwgSay4o+1Rda4f6p3NGNH7E3ItBUzhrcTWi0KS
         cF53UlOaenBfqCktYuLWD/uRc9SSBndlCdf8pAfw03iP/uOwnd+OYpIf6SmNz5qADaOV
         VFcV4bw0tMghue9+Rjg3G8znO3WZZmVj6q2Hbqkieyzo63wO/49Ytw8cPGtuP5IQSfDX
         DFhVDrwlFQpTaM4faaoRptvGeAAADlFSlVheqQbo6YE8+wCj406VUXGYtKE4EepXbkrc
         utmgIfOmJwDQTKJ4/EsgLnWkQ+ulNkIgJwP4zlTu1wLZvaHFresAyMTYExsvNbEMpWYD
         r8Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qge5HismFr4h2KHQkGdgG68izyz5vUZZsr5z0thWHsc=;
        fh=MAQo1I9V6WYjSdtrPjFTcOOjm/ni+3428pSR3bc02Dk=;
        b=FaSAZxIqQ8UymZ4Zf+3bsezy50OVNpcRS6TMBA00ZFECGtP1IOYwJJC6jdggMQUOWQ
         2g6EeVGK2KjNeRoCdCAZL0e++9BQoRtXMAKXK2+rP3SY2ydum+yvd9sig1EG8d54FywJ
         qBxic6qCs/jp6eXgoeamkQkbWPo0mUdUetXiREeCqAQtNpEacA0iX4UHXuvl3JqHpIS4
         3Hse04UpWxzLs8gTSILryFWSzWDOz8fQ7KloJ4ssPgCvL3OznHMNH2Y2nnBC0jNqhMKo
         gKEOAzJY6G2TzW1ZyyRTiIW2E3BgKWF9uM1nTEmjlr8+ItZDXAWfz9LN4re/+J4br+Fh
         MjHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708038381; x=1708643181; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qge5HismFr4h2KHQkGdgG68izyz5vUZZsr5z0thWHsc=;
        b=HWsTlW5v2MjW9uTFkmFzAFzWGW0IK4Q3l7zzeTYEYLYu30RUDZARiwsxAAs54A6xBK
         eb3BvsXS5AuzY0vfde7pTtpH9j2umdUBuyGqST1zUo4+3sQb6RBYEf80SExY0jsUaCf9
         xSHSLVjGeeh0Xb17Wdz8e9y/f5DSr0O5rfsYWXxxIjJJrWYoIJGB/QP4XxdAMYciiKaV
         9VKjP6A+OpdaKLg9bDL5XOI61+1nfmdgGP+JvgltV1K+8/+RpzYgscn0yS+Aq11gf52I
         /WAt2lmW+6B1ra/jZb4UHLE2bOU8RBQGLQ86CgpmOjvrbgf5Jd3i4D6R0W/uq5AdLzYm
         +oTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708038381; x=1708643181;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qge5HismFr4h2KHQkGdgG68izyz5vUZZsr5z0thWHsc=;
        b=f+9/3Xc91eMwrs842JM7MfjYLYchPvuI7LQhzFQxRW97dC3BgTjg9Ho6e5aVRBT2Jn
         YOTERM6xn5SXbFJLyFAtJUQlCmavzUNo5TBQk67TkEvF0KOYBP+noSXerQjMEjSatO+R
         FHksOrbrBMrHKttDA0LvKzZZ4J3tKYXkZOkKdfdN7sXSozpCo+TXDWeNfpPt54ZUvOvq
         Z8JTbFnCYs45rSw5SWHgpnkapYEgFM9b0qD+MeBylZwuRWQFTxxECMBryolZlQB31857
         bDIGzQh5s/hBg9NKPrSSTLDnRHyfZccYKsg5eovVbhDd4QvZZNZxhT7mNOQSyrGWvvOj
         Mv0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvUOj/u42zObM39vxnL0+cVyLWD9rcUBlplzO6LF45U5N/p2wMJn9cwly3tPcuACgpCN4uOB4ltOLqPsazAeLVk1Hi+tTouQ==
X-Gm-Message-State: AOJu0YwK78Oq/p3qLgZAdNJ2SWz1NYTgpg75sBdoPUzOEVeDnpcd8/rD
	qOsC7hdKRqsqKtePPVfLVRHrMYD6WSsTOFybeb0uEtSTKflNEO/m
X-Google-Smtp-Source: AGHT+IH5FkfC9kjcLWxPjjng9rOs/O16g2haOJ4eJsEKyxC2Q5mF9ylHp5GZBq8ClcpGSDiNc4lF/A==
X-Received: by 2002:a05:6e02:2167:b0:365:b9e:bdb7 with SMTP id s7-20020a056e02216700b003650b9ebdb7mr244720ilv.22.1708038380796;
        Thu, 15 Feb 2024 15:06:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:68c:b0:363:7be8:179c with SMTP id
 o12-20020a056e02068c00b003637be8179cls136257ils.2.-pod-prod-04-us; Thu, 15
 Feb 2024 15:06:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV/lCfqrG0pGsCV7U2zRScAyRyKCurEyLP/VAko7PslIGynmGFFAb7WAm3cyjnpO18Jgek3dlVPTojfE+UEV7ajNSMXQmYdouac4A==
X-Received: by 2002:a6b:6503:0:b0:7c4:9579:347f with SMTP id z3-20020a6b6503000000b007c49579347fmr3264214iob.12.1708038379170;
        Thu, 15 Feb 2024 15:06:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708038379; cv=none;
        d=google.com; s=arc-20160816;
        b=h/1z4ZxAnPG51YQmSSqvF0qQCx/ZeOWp3iQ67n+KsmpRr7NsesPBP8SQ6bKqQyXnqz
         08Eo1jR0M/HVVYrI1WXxZySI2UtHB5L/XZ4UqGYmd2QkvbuePj3iHF8ZN7jGEdHbtIt5
         Zf2IJWpPI4c0DMpB8VFW5i2kTXSk6DKYqJDZjKDX7vMnt2ikd+gindQ60C7Ak+BaOtvJ
         9SUTQqi/2soH4WVrcadebKermKqAIqQ9z/W5I4eXNKHHuq8gdx3C2+V1MbafhbB61Ohf
         8rV7qFVrFLesKsAikcckOvQACeb2mifPRZ2hn9lO2cTPVPpNdSRly1Hu6aWaK5Koy0vR
         gXaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=IZUtmnHHr4//gHhVNpU2+waR+9Cf4jOGCd0c5jSjL/g=;
        fh=yAsR8mz6OHt7FqUIcMxTq2xSLRkYQrfOXi2SdkYqlko=;
        b=0J333w/gzZxuLosOHAucCVbRth9S2As/l/P/KyWnJRHJlwlshId27TLGp1XQGZgUvF
         VhF1rc8PjipEEVL1NvwRh38j3VEbJThIe7NdURJSdxm04S63LjYo/NuzDieA56qvxQ76
         LgvMWhllJm1ISmevR6g0lQGnYw6vsfX+XrXQzmVXKRTr3n4IJX9C6KmzqORVLj5/ngxD
         X2q9JUNbbcOqzrCya+rqbUH2tKsGv5zbItS2XJOHRbBoCidLupNftZ5gVwm9rRgA5IBc
         KUWGdr+NybTIlySMxLzO7gQU6lGX6qlV1MKHcW1p1kGvB5YAs/2fXnCBxInGaXkqWXpD
         nj/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id q9-20020a02cf09000000b00472c7ee34e7si178700jar.5.2024.02.15.15.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 15:06:19 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 3C1D0CE23FB;
	Thu, 15 Feb 2024 23:06:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 28195C433F1;
	Thu, 15 Feb 2024 23:06:08 +0000 (UTC)
Date: Thu, 15 Feb 2024 18:07:42 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan
 <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
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
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in
 show_mem()
Message-ID: <20240215180742.34470209@gandalf.local.home>
In-Reply-To: <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-32-surenb@google.com>
	<Zc3X8XlnrZmh2mgN@tiehlicka>
	<CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
	<Zc4_i_ED6qjGDmhR@tiehlicka>
	<CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
	<ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
	<320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
	<efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
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

On Thu, 15 Feb 2024 15:33:30 -0500
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> > Well, I think without __GFP_NOWARN it will cause a warning and thus
> > recursion into __show_mem(), potentially infinite? Which is of course
> > trivial to fix, but I'd myself rather sacrifice a bit of memory to get
> > this potentially very useful output, if I enabled the profiling. The
> > necessary memory overhead of page_ext and slabobj_ext makes the
> > printing buffer overhead negligible in comparison?  
> 
> __GFP_NOWARN is a good point, we should have that.
> 
> But - and correct me if I'm wrong here - doesn't an OOM kick in well
> before GFP_ATOMIC 4k allocations are failing? I'd expect the system to
> be well and truly hosed at that point.
> 
> If we want this report to be 100% reliable, then yes the preallocated
> buffer makes sense - but I don't think 100% makes sense here; I think we
> can accept ~99% and give back that 4k.

I just compiled v6.8-rc4 vanilla (with a fedora localmodconfig build) and
saved it off (vmlinux.orig), then I compiled with the following:

Applied the patches but did not enable anything:	vmlinux.memtag-off
Enabled MEM_ALLOC_PROFILING:				vmlinux.memtag
Enabled MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT:		vmlinux.memtag-default-on
Enabled MEM_ALLOC_PROFILING_DEBUG:			vmlinux.memtag-debug

And here's what I got:

   text         data            bss     dec             hex filename
29161847        18352730        5619716 53134293        32ac3d5 vmlinux.orig
29162286        18382638        5595140 53140064        32ada60 vmlinux.memtag-off		(+5771)
29230868        18887662        5275652 53394182        32ebb06 vmlinux.memtag			(+259889)
29230746        18887662        5275652 53394060        32eba8c vmlinux.memtag-default-on	(+259767) dropped?
29276214        18946374        5177348 53399936        32ed180 vmlinux.memtag-debug		(+265643)

Just adding the patches increases the size by 5k. But the rest shows an
increase of 259k, and you are worried about 4k (and possibly less?)???

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215180742.34470209%40gandalf.local.home.
