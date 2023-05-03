Return-Path: <kasan-dev+bncBCKMR55PYIGBBGFFZCRAMGQE7KYJZUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FB476F524E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 09:51:53 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-30633990a69sf793877f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 00:51:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683100312; cv=pass;
        d=google.com; s=arc-20160816;
        b=0MTZfFun/Eyc6yzV3lOaObt6sddlCviXuuAr4H6GPLmOKiSSGPFkqrfyIDeO6JMQbE
         UJ19oJSO0mctZ9lmdVOV6runKMKQ7Kv6tf6wlsZ9SUFpYYWuzTreB4697k7d+J9ZlPss
         y9cbWinlN7f/OJ5Z9+bceKsfE3d213JaU7x/SjeXOVkqnIipJA28KG45WZhOvltQ4j0r
         gPJ6jMUM/o/8T7hOHmGGmAiO0tgf/MpEj4/ptlaW0xtWT3bMpDhCCJtPEVeelhkjT6m7
         FmC4s9XdqX9ssYEUcxJSGfFB8usTk0PgbbS6FFV+iEdl0im/jEN3BPVMgJqSNIpaOuIn
         VkjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=loaO68WZdI6NYL+SEouK8lPdofOO+IlL7TPygek5QpI=;
        b=zuiPAteJK6EBKhARUCie5TvixBt+wFXj5vCpyQBntkWsYjypwE+wYIdakpgcZkW+/L
         UvToJE1eFfHIp2gdeuXZJoOsfQZCGTJJZXJCZ9hYuI8ZGOTZ6Yaos6j5ZsXpzspNNug/
         Pqx6fPgbjy8KBNJz0faM1sLI8YpwuUwgMqZMqb3S0B0svfiowhZBDJfYcm3CXoD6mMKk
         VVNi8EQGx6oHj0jv6RAnfbvDKfqwPzn8fbphXNrUsIPAfLF0qC3bxobVsmKKrBao/EPV
         hSz84z1fSUM1CH5+xXMjPUv772KaUHUqaG9ws+d02SKPAwXS7dIdZHCIQrObtgqFwDyy
         BzoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=u+JdKhxm;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683100312; x=1685692312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=loaO68WZdI6NYL+SEouK8lPdofOO+IlL7TPygek5QpI=;
        b=H9Xxo5+v2x9/NAFwm/cDOC3LwdHFnmHM8uKa7XdQo67WA3CUrjyCCRsKfsjO3spN3M
         /LMz2yRcyd65PAmuDbHjxxkh3vu+nuIXvRZQLLZ5v1LgVuWWFQA8aUSXik8d59Ty9dYs
         cgE5V9EkZj4207lixo7glesxYBW8NGgyBFlkKxgfw4jU5ih4QiBbn7jawd1jwR0EEgHL
         8EnZxtGwdDaLPQb6f+m53fUyclbx1tSGn6/9d5zln5hPa/yv2lDthGiWLq0IzteB14zU
         QmSiyBm6jdL7Z/+DK4CdF5OiPyiizoKQvUOjiGJpz8mf03wwZXnIjRG2VO7rTM5y5Wst
         7xTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683100312; x=1685692312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=loaO68WZdI6NYL+SEouK8lPdofOO+IlL7TPygek5QpI=;
        b=J+gLZhRxFUrkireCp4RIGWnXoaGu/XMY+Yb/E5f4MalWPsbCk3pcJXvdM46fUW0Gpa
         4+TV5ZdRQJZbVwYptk+ki7e4FtA970p40Oi/nPdFfPQeFR75eWaUCsjq4HgK8FXFp/m9
         RWG/ymjaGVJc9a9+MMZMDWKFa0qU1AlJJnz4Mu+omntYDvJnogopciwl+mWxy1rvlKVm
         k0Wu7fpivPdbpOQw4fiYTOQvmTbzfO4N1HE0NOl+IWg0Mg12/3B79h66bxdeymArA9Cv
         bOuQIhneE2+nTir6HcuvoPEM+JHi877kIWxNPv8agoxk2yTv1a5V4URcHGUD8MMwXnzs
         nDbQ==
X-Gm-Message-State: AC+VfDxevvW4PC5hbGNXfzOJMOSLctDk+5OjzjGoB+LLjo8BvQNegrMH
	WvMZheb/DDiikwyNM+lcDJ0=
X-Google-Smtp-Source: ACHHUZ5R2zpSd6iZQYe1q7l4ZM9pjg6gGbHcDdZ82zctc0KlQFfEq1f4bKoGISYy5GUW+nDmK77Qvw==
X-Received: by 2002:a5d:510e:0:b0:2ff:f37:9d08 with SMTP id s14-20020a5d510e000000b002ff0f379d08mr2349478wrt.14.1683100312232;
        Wed, 03 May 2023 00:51:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1c0b:b0:306:28af:9a26 with SMTP id
 ba11-20020a0560001c0b00b0030628af9a26ls4241536wrb.0.-pod-prod-gmail; Wed, 03
 May 2023 00:51:50 -0700 (PDT)
X-Received: by 2002:adf:f7cc:0:b0:2f5:9800:8d3e with SMTP id a12-20020adff7cc000000b002f598008d3emr13443803wrq.47.1683100310728;
        Wed, 03 May 2023 00:51:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683100310; cv=none;
        d=google.com; s=arc-20160816;
        b=YadV7fP2IAZsCinMw4Zv8ZzCNxm2qW7WkzW/rjzHSvWL67MWoWx+ir6iQIu2Ep254H
         PW/ZLYPQzm44Q+9qosfPQKtWW+UKDAu6OHQAKgh+9QSEn+J4RbhO6nMqbARWZMIpBQAy
         706jTpP7EEvlRqBF2+W4igS8zVSwIKbvLCpSWBXNiQJnGEObjDc9vDgDpX36be5QDct7
         cZIeOWeQ2ZdS9QyO2IpDUkzj8an29OUKh2pdAbEoN72uDOHj8hssOimgp4TiHMCdcACy
         qF/RjhNt1EDGz+s3qv8twiCegXioOVoYUXuEX5xK8bEayBG0p+9dvvVg1XQeLSR9r6wB
         rpFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LbOettp3UaJGbcC185AxqMHgcSABvOiPPaXvjwmoDVE=;
        b=oZ6ZnvNTEkhseKN0r4g+/iJhwbhzymnyFWLtCL/eXbO7QfYQJyqQdvheKS8ZI7/o08
         0e99ch6pm3f/1R4i57/fpoWB0WriGo+R5QPd920r55AaDimdYndkI4vp5Q1tdM171thB
         sanz6/SH9PRZOWjWIXCnlIlgNGK9VDPwHL3kvSyw6WN7Qo0ftKYlLh0W4X6GCF5r227H
         bCpIZVCSEDLZ4iaOaKA7ZzhmaPj/FtqVKUSF455bicdN/SnNnHQM01WO5FNhMadcuG3d
         0GO0P0/kFk6jopN/50js9Uoq4uQvfrs+kUn/AMx2IxADryPTcAPAnr25OKgiu6QqdHLn
         IEIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=u+JdKhxm;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id a22-20020a05600c349600b003f189de7e3fsi54878wmq.0.2023.05.03.00.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 00:51:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4CCCC21C30;
	Wed,  3 May 2023 07:51:50 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2480E1331F;
	Wed,  3 May 2023 07:51:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id YvrlCJYSUmQIXAAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 03 May 2023 07:51:50 +0000
Date: Wed, 3 May 2023 09:51:49 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
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
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFIOfb6/jHwLqg6M@moria.home.lan>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=u+JdKhxm;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 03-05-23 03:34:21, Kent Overstreet wrote:
> On Wed, May 03, 2023 at 09:25:29AM +0200, Michal Hocko wrote:
> > On Mon 01-05-23 09:54:10, Suren Baghdasaryan wrote:
> > > Memory allocation profiling infrastructure provides a low overhead
> > > mechanism to make all kernel allocations in the system visible. It can be
> > > used to monitor memory usage, track memory hotspots, detect memory leaks,
> > > identify memory regressions.
> > > 
> > > To keep the overhead to the minimum, we record only allocation sizes for
> > > every allocation in the codebase. With that information, if users are
> > > interested in more detailed context for a specific allocation, they can
> > > enable in-depth context tracking, which includes capturing the pid, tgid,
> > > task name, allocation size, timestamp and call stack for every allocation
> > > at the specified code location.
> > [...]
> > > Implementation utilizes a more generic concept of code tagging, introduced
> > > as part of this patchset. Code tag is a structure identifying a specific
> > > location in the source code which is generated at compile time and can be
> > > embedded in an application-specific structure. A number of applications
> > > for code tagging have been presented in the original RFC [1].
> > > Code tagging uses the old trick of "define a special elf section for
> > > objects of a given type so that we can iterate over them at runtime" and
> > > creates a proper library for it. 
> > > 
> > > To profile memory allocations, we instrument page, slab and percpu
> > > allocators to record total memory allocated in the associated code tag at
> > > every allocation in the codebase. Every time an allocation is performed by
> > > an instrumented allocator, the code tag at that location increments its
> > > counter by allocation size. Every time the memory is freed the counter is
> > > decremented. To decrement the counter upon freeing, allocated object needs
> > > a reference to its code tag. Page allocators use page_ext to record this
> > > reference while slab allocators use memcg_data (renamed into more generic
> > > slabobj_ext) of the slab page.
> > [...]
> > > [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/
> > [...]
> > >  70 files changed, 2765 insertions(+), 554 deletions(-)
> > 
> > Sorry for cutting the cover considerably but I believe I have quoted the
> > most important/interesting parts here. The approach is not fundamentally
> > different from the previous version [1] and there was a significant
> > discussion around this approach. The cover letter doesn't summarize nor
> > deal with concerns expressed previous AFAICS. So let me bring those up
> > back. At least those I find the most important:
> 
> We covered this previously, I'll just be giving the same answers I did
> before:

Your answers have shown your insight into tracing is very limited. I
have a clear recollection there were many suggestions on how to get what
you need and willingness to help out. Repeating your previous position
will not help much to be honest with you.

> > - This is a big change and it adds a significant maintenance burden
> >   because each allocation entry point needs to be handled specifically.
> >   The cost will grow with the intended coverage especially there when
> >   allocation is hidden in a library code.
> 
> We've made this as clean and simple as posssible: a single new macro
> invocation per allocation function, no calling convention changes (that
> would indeed have been a lot of churn!)

That doesn't really make the concern any less relevant. I believe you
and Suren have made a great effort to reduce the churn as much as
possible but looking at the diffstat the code changes are clearly there
and you have to convince the rest of the community that this maintenance
overhead is really worth it. The above statement hasn't helped to
convinced me to be honest.

> > - It has been brought up that this is duplicating functionality already
> >   available via existing tracing infrastructure. You should make it very
> >   clear why that is not suitable for the job
> 
> Tracing people _claimed_ this, but never demonstrated it.

The burden is on you and Suren. You are proposing the implement an
alternative tracing infrastructure.

> Tracepoints
> exist but the tooling that would consume them to provide this kind of
> information does not exist;

Any reasons why an appropriate tooling cannot be developed?

> it would require maintaining an index of
> _every outstanding allocation_ so that frees could be accounted
> correctly - IOW, it would be _drastically_ higher overhead, so not at
> all comparable.

Do you have any actual data points to prove your claim?

> > - We already have page_owner infrastructure that provides allocation
> >   tracking data. Why it cannot be used/extended?
> 
> Page owner is also very high overhead,

Is there any data to prove that claim? I would be really surprised that
page_owner would give higher overhead than page tagging with profiling
enabled (there is an allocation for each allocation request!!!). We can
discuss the bare bone page tagging comparision to page_owner because of
the full stack unwinding but is that overhead really prohibitively costly?
Can we reduce that by trimming the unwinder information?

> and the output is not very user
> friendly (tracking full call stack means many related overhead gets
> split, not generally what you want), and it doesn't cover slab.

Is this something we cannot do anything about? Have you explored any
potential ways?

> This tracks _all_ memory allocations - slab, page, vmalloc, percpu.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFISlX%2BmSx4QJDK6%40dhcp22.suse.cz.
