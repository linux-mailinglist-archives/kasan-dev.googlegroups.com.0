Return-Path: <kasan-dev+bncBCU73AEHRQBBBNHMXKXAMGQEFJAZE6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A3EB857325
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 02:11:18 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf329995ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:11:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708045877; cv=pass;
        d=google.com; s=arc-20160816;
        b=DR4bMFQyz0x/DJQh0FTN30qk3siqHJVV/3MoC30wPtfip0+lCbXkPmaw3og/v1+NPH
         vJKevrr7hPQmEI0zyFrtoygBL3txrjkaRwWqu9iwUfJTr9fbEVKAx8okmVyg4nVq0soP
         SO1t8DIa0PNEEh8J2W+Yj0AZSSkCv8U600bSvzitv1Ozrx4mP11Iv2FEjSiKHW6T8vfi
         rjH0JAUs7vaSyhLtJLUQMdtCuZXtN4QnlqmAJO3RboQAGkqrSGb/9wjyNqz/BbId4oJS
         6QLN9VM2xQpEK61eVTY1u+ggEB5JcOor3PY/PD1NL6wKQZfS90g/bpBONvg/1uUBkxck
         yYAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Xz5cYRpMN8OIFdkjcbJQWH2eGW6QH1eXD5itClF8ntw=;
        fh=D5yHMTzWw5l88aZBv/Sbh4/RMBTLCAKF9xgAvekTFQw=;
        b=OCWLKm/SKqyACUXgdDlIhdI1gdJTl42RbUt1mNjTQjSVhR1XIde2XwOBVBrR4Av5k3
         bXufPJA2tdqgr3hTDcukfGPO1m9yqfDfOkenUnVYN1ge6JO/6Jj2v04I2hYsPG4/koTy
         nZi0tGjzZnzzVaS/te6fyWXCwnn7dpLuKWUWjOO43WZF6KKX4q2FSYhuMKSgsYT/sAT/
         BTA29g6mq690/RIJvyphxBBkOoWvdfm4X2seYHQ9pPFgyQVu20RG7oxsLshbgV9OR4Qz
         ns+uF5io4QOSQ1ZqUyizPF24z8fjrHJQY85RzXESmBRJk4OZzVGcX9J1vBPfeCNPog4+
         VYiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708045877; x=1708650677; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xz5cYRpMN8OIFdkjcbJQWH2eGW6QH1eXD5itClF8ntw=;
        b=chMAtH3FfzqdljepsVSlcwRosPQLygrLVTDWHlF04olt5Tg0ywKyNhDJH15hMK39dW
         GdWip6W5m75GKKi2aGVNke5kRKGYwMzf1ZY4TM0RTd0zAU46l+6JW7Colgya9ZgxOsTc
         Xw/WkzyY9nltFaF7tIXyTxDXKOz5SXST5HFlTZDRLD3i1G3tQYAk18HHwsYY+Nc1jPGC
         h0w9tYqK3FBYvyU/Nv30a21pGOYEl8BnSFj5W7CspeN91KIk976RPzEtFmpN9SMx9a4z
         pRLZgt8rpG2wLwJ6Dr0ameWO3fOUE3dwUKnHW/hVVKs9ILb1noyD+0Dq+JopV7gLbs94
         NNGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708045877; x=1708650677;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Xz5cYRpMN8OIFdkjcbJQWH2eGW6QH1eXD5itClF8ntw=;
        b=w+CAND9kfT8ttVJVXMyFTBs3sWs1aJADB8aKCKg6gti2SKmHi0cHfuGryyl65QQRJd
         gXLR875RZ7PWz66r+I4IxxdWfrBZqYQomJf7LUsv+5gir7sBUjpKflwuYh3EnWOYOlrM
         Ia/K8OPAbLTy+iEKTU9npKTVi9E1TkAJTkkocEi8fxFRLJ1SiYDD1nMPbFxUvXXgtCqQ
         yVhGTE7YUYi5cmbbXBm5U9B69arvvg9I5jYXKGkneJyoWOI1iLGNTEY+JUcQ53GhCBTY
         AQYl6pW/UMtbpo5062Vei5qaJJ1eZBDrqC5mFvgBIczkypA9KipSV6WU0B1/ltHfywy5
         Hw5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMXSN44h+jrl7T86nXqQ6wP+cBHBh/j5e/PTMuMVHiYEhXFyHbUOBOXGkj33qfAafdcC7D5yj2q8SODZHABjhtfEdA6NpQsA==
X-Gm-Message-State: AOJu0YxcZF8LyYcVCdLSS+3RxoclgQD35iHxZxnjMSNwsFAgQfZpyH35
	3Wgz6jNSL69DlA6oSYFaH1+rFRgrBn4rQ6uRfqOM6IjPKgvotz4R
X-Google-Smtp-Source: AGHT+IFpC42XADz515zPFtjd0V6TVCw0MkbjuVDtl56IDPrX78GUW+UHUzCTs2y37tHynUpuOIEKkg==
X-Received: by 2002:a17:902:ee06:b0:1d8:d90d:c9ae with SMTP id z6-20020a170902ee0600b001d8d90dc9aemr128542plb.1.1708045876716;
        Thu, 15 Feb 2024 17:11:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:6c83:b0:6e0:e4c8:6ed with SMTP id
 jc3-20020a056a006c8300b006e0e4c806edls261397pfb.1.-pod-prod-04-us; Thu, 15
 Feb 2024 17:11:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCViLeq7cOlHcIkIfybhqpqJiWn0KiUZwRz8OrQCaefXSTkKMNe6SlyPruyaNJbAF/ZFTcIyQGGpwHhoDBOtcrHAMk0XI4cVT3tIHg==
X-Received: by 2002:a17:902:ced0:b0:1db:94a9:f9fb with SMTP id d16-20020a170902ced000b001db94a9f9fbmr2734561plg.21.1708045875512;
        Thu, 15 Feb 2024 17:11:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708045875; cv=none;
        d=google.com; s=arc-20160816;
        b=RrO7J/ot+RUaq41iDjhfu91davmT564jWJtkIZRY1o18zIWloTnIs4sPbX/1VARvRX
         kFcgrTgWViAczaxzEVpMYNUnC+o/m0R8pj4SmY976DyaXNuzgUnhglMPGQL5VD3Ieq3b
         X44PWWMCIQUqw7/fZMiYGnGJZ6Ubtxd+g0TnSeRhHQY4tcS6m1xv0RbaNUtRWljv4zHq
         0ZQ1PQ28KtNbvaes3NpMst5NAIzOjo4BAFdi65b5oqhu8et3/bJVMkowbywgmKsJnoJ9
         lNMP62j+pm7ANR+cUb+xdUH4Jh/vR7ckdUYVbC/um9No4lJYP8P3nWKwAEb7VCBEk4hZ
         I+kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=lEO1Oc9FM3ZOYbA0NQJh7K+ek6qTDi64NW3cYNWhgBc=;
        fh=yAsR8mz6OHt7FqUIcMxTq2xSLRkYQrfOXi2SdkYqlko=;
        b=sNPeGVb6ijoUhk7wPeAyXbW0Xnqj0TJyg2H2+Z75DlgBQ0fCGFm6CHaLibQvGAull+
         EyG47Lj7ZistgE7wBhFXu+VQSTyok3bUhlrqoI91ZD9dndaefXNvclVRhXtzzSvttDmq
         apePScSAYC7dVSSguPreOsjcg//4Avcw5DqhQ63G/zXlhX7AvTs9+erKfmBy3QCWULDi
         SOYMnAAzAUyuQqDe2FcUCzNv/WK3FNK/diSA7W38dgI6+11zlbQSoYEnmi3o/vPTldss
         s/HOTn02fq7ps7eemgkTaCijbBu+wl+5E2Dc4PdDIjLUSQ+MVczZHFpU42uTysD6836T
         eixg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id p10-20020a170902e74a00b001db622810f0si124977plf.9.2024.02.15.17.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 17:11:15 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 360A1CE2976;
	Fri, 16 Feb 2024 01:11:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3C847C433F1;
	Fri, 16 Feb 2024 01:11:05 +0000 (UTC)
Date: Thu, 15 Feb 2024 20:12:39 -0500
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
Message-ID: <20240215201239.30ea2ca8@gandalf.local.home>
In-Reply-To: <a3ha7fchkeugpthmatm5lw7chg6zxkapyimn3qio3pkoipg4tc@3j6xfdfoustw>
References: <Zc4_i_ED6qjGDmhR@tiehlicka>
	<CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
	<ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
	<320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
	<efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
	<20240215180742.34470209@gandalf.local.home>
	<jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
	<20240215192141.03421b85@gandalf.local.home>
	<uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
	<20240215193915.2d457718@gandalf.local.home>
	<a3ha7fchkeugpthmatm5lw7chg6zxkapyimn3qio3pkoipg4tc@3j6xfdfoustw>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=rkxr=jz=goodmis.org=rostedt@kernel.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=RKXr=JZ=goodmis.org=rostedt@kernel.org"
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

On Thu, 15 Feb 2024 19:50:24 -0500
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> > All nice, but where are the benchmarks? This looks like it will have an
> > affect on cache and you can talk all you want about how it will not be an
> > issue, but without real world benchmarks, it's meaningless. Numbers talk.  
> 
> Steve, you're being demanding. We provided sufficient benchmarks to show
> the overhead is low enough for production, and then I gave you a
> detailed breakdown of where our overhead is and where it'll show up. I
> think that's reasonable.

It's not unreasonable or demanding to ask for benchmarks. You showed only
micro-benchmarks that do not show how cache misses may affect the system.
Honestly, it sounds like you did run other benchmarks and didn't like the
results and are fighting to not have to produce them. Really, how hard is
it? There's lots of benchmarks you can run, like hackbench, stress-ng,
dbench. Why is this so difficult for you?

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215201239.30ea2ca8%40gandalf.local.home.
