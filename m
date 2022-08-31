Return-Path: <kasan-dev+bncBAABBMFVX2MAMGQETD7LBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E0CA5A845F
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 19:30:25 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9sf9955206eda.19
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 10:30:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661967024; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQrYKHBUp8OHAK5mhzl5a/bXf8WdVqMdsEhh9XOLmybGhqrEttTGJSkFexE3n/M+bL
         gK2FS88A9fb5e64SToS6nVKqk1o2tE+N6pgbrLqqwF6s3MCISuPyLKnnRyCwBcoOVbTg
         oXARc+oLmOyoqkr5ave9MFpCTaEnTu2L5K+KsNWmU2XQYp3i1bXi0XamKrUHAK89Z4o9
         O8JJiOLzb/r9HD5xZ/d57gSwpNUho4sxpkkRE57FF+rldCRe15ySzKgr6/dVFu+fUqV3
         I3SC7iIi4w8/QcpRKhCBGVfQK6aZK7IwqAnAXT2CQsPod/avy2r0u/AavYVL0LQ4xg3p
         MZtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PL9KSWXZSXA5OeClVnPrRMGR8inEB+3444+4HnGgvyY=;
        b=JAdHsxTJjZLFaMEYtwrQr/moo2HlGLczpSx/bMNvwX30jJP0rR5xfPvQu1cQvk77/E
         EpuBaeb4h4s8okMDcmikbHt4qq+746RYfy6FaoC3IQBDZmv3I1fc2RYSzWQYQZVa3ujp
         pX5VRkS5czOVJB3G7TOZFm8PoVw+vicKFOPdd2zzi85tRGshOeSY9uGjlsmjzDaJWCPb
         ZXd10oRaVcaLwG8z52BPC0JetU3EHJDl7k07uP5kG7ziuA1TGvHT+izy/wle++nJSw+8
         WHEzmi3FfSDFG5drIM1V9Eaya44GXxl0zE03FVwTicDHK0vSjwOKQkUYqEaZjMAKbX35
         XX5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vE3CF/hY";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=PL9KSWXZSXA5OeClVnPrRMGR8inEB+3444+4HnGgvyY=;
        b=iAtqQ/QIKSk5wGONVJr8dqsL4MIfYsXbM5sJmQYlZ62oUcX3f4+Z0/RCxD+uAkS99b
         WolBHDot93hUh8LxBQ+zyPYB2pXsIiC83rFbR+HG5CWc9LQ073qsuHk5pPf4LwoN3H5Q
         kNyMqSGeuo8dY2u580iv/qRlYnlZ0w9vNZ5Us4vqso3TPjNDXxzSnNgrpZVgDQctu6jp
         DkkN2fSqwiX0hE27eHh0YL4yT+s/lIORxZVaOxrdSY68tBOgPTRkreKCcAkV1ATSozhL
         ABAt3/Vyb1WEQY1aEOcMtsbG3Edz3U1ISNtG9h85gD5dCapQGo8l7PDLIMxcwKoMzd9w
         Aq/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=PL9KSWXZSXA5OeClVnPrRMGR8inEB+3444+4HnGgvyY=;
        b=WHX0IYJu59N5mo1k0QtB9bDXn7gV1y2BzC3mwPMGXSnvKvcg3RJPkACESr9vf/wIin
         WMLhRQQyeCwip6/vlPEAtI8e2TUPssq6+YFdY3y3avOwM5mmuDNedm5D/Vd9ot8vS/rE
         5rkwwVYkjLLCUBhHpH8qjU1OeovB940CLgo24SUUN/9n1L7x8hFtEcWg1ZSnzr6xzCPP
         wIk1clQ9q/exEmraLp27ZGltR+dcoVlCKHnH7a5d91BUu8EHs75wNNM9VbiooSZkfdDe
         I+T3I1pu+pqnkQlhFJEMrqfrro520qmad1AtQXq1707DNOHAN891ZzrfJXVAp/h5q7G7
         xZ2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3I78mtVXUOLKEqkj9BgLd4qR+LKU0W+AABoqbPml2t6mtGv9aY
	bKtvb6v1SselR7v4HmKvw1w=
X-Google-Smtp-Source: AA6agR6gzjSTxuWa5QNehhCxBNe137oi9UgfmGz03UKgt7+thg6v/VVHjTKxCCqeJNr6IKCE8a1Qsw==
X-Received: by 2002:a17:907:6285:b0:738:e862:a1b with SMTP id nd5-20020a170907628500b00738e8620a1bmr21915942ejc.70.1661967024583;
        Wed, 31 Aug 2022 10:30:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4408:b0:43d:b3c4:cd21 with SMTP id
 y8-20020a056402440800b0043db3c4cd21ls6336777eda.2.-pod-prod-gmail; Wed, 31
 Aug 2022 10:30:23 -0700 (PDT)
X-Received: by 2002:a05:6402:51cf:b0:447:2c7d:4dc3 with SMTP id r15-20020a05640251cf00b004472c7d4dc3mr25296296edd.369.1661967023777;
        Wed, 31 Aug 2022 10:30:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661967023; cv=none;
        d=google.com; s=arc-20160816;
        b=Fi32CrtGv0wfjAW3FaEiD0PXiMzr14vaBHwiV+RvrOB53Uu+UDMOk9ANrAtrDOQgDL
         1ROTnUzG4Ci9Q3t9+nKk/nTREAh+hHvAS8HRxzHPfewEcg13KbZWvEKu0Csgotcqb6QO
         DQ3PhoB6KnrkSORrkDkmoFkeEIVaUYWD9dDYG8o5i/IOfrPJQCYKQJ9LGr9oCduzLqbj
         6JNkcwu6fzRYQ0duvZBdUiuaz0OZAR3Aoz+d5jDCVJikrSbb9TO1Zz9Jq3NQOIjQWUtz
         d09JG43hZyw9+kE+DeyjgJP5AbPTypWFPmPbDwectjVq2/9NRlgOt0lqxmlg34DISkMc
         hkSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=akPUYJQ75fwIwMQFIb22LwWbtwnw5UTZVlPBgEDeTMs=;
        b=nwTvzMxo6uKyJ06PvsMmePEgrre0Jiuk2KJ/C1PlS84jv13B67BX6BKpM+VtorWH+W
         y6paZHQi628BdUjb6EGSDiSqQ7BOlP+YZkHf5a62KYDgEzeRy1Jy0Td/EcBw3wPTdiW2
         mRNAZOF6VHvbf3PshTVHQDawWjHFw4WeIbqcmpOgicQxZ2jYvm5VzwBiRv5MuCxORZEb
         qLW5LAUEsigvZAgsGC0GD97saaXqlvCnp73yS24Mz1q7mCD0MFBU2anfL4y10qyruO4R
         bI/NoGClheMbdIyDovLw5cMdhfRhTtiwsNBpqk1qPCM1xH2enIvPIpq4MhZOGBqhLiq3
         FFvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vE3CF/hY";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id y26-20020a50e61a000000b00443fc51752dsi801689edm.0.2022.08.31.10.30.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 10:30:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Wed, 31 Aug 2022 13:30:10 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, shakeelb@google.com, songmuchun@bytedance.com,
	arnd@arndb.de, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 22/30] Code tagging based fault injection
Message-ID: <20220831173010.wc5j3ycmfjx6ezfu@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-23-surenb@google.com>
 <CACT4Y+ZX3U1=cAPXPhoOy6xrngSCfSmyFagXK-9fWtWWODfsew@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZX3U1=cAPXPhoOy6xrngSCfSmyFagXK-9fWtWWODfsew@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="vE3CF/hY";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Aug 31, 2022 at 12:37:14PM +0200, Dmitry Vyukov wrote:
> On Tue, 30 Aug 2022 at 23:50, Suren Baghdasaryan <surenb@google.com> wrote:
> >
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > This adds a new fault injection capability, based on code tagging.
> >
> > To use, simply insert somewhere in your code
> >
> >   dynamic_fault("fault_class_name")
> >
> > and check whether it returns true - if so, inject the error.
> > For example
> >
> >   if (dynamic_fault("init"))
> >       return -EINVAL;
> 
> Hi Suren,
> 
> If this is going to be used by mainline kernel, it would be good to
> integrate this with fail_nth systematic fault injection:
> https://elixir.bootlin.com/linux/latest/source/lib/fault-inject.c#L109
> 
> Otherwise these dynamic sites won't be tested by testing systems doing
> systematic fault injection testing.

That's a discussion we need to have, yeah. We don't want two distinct fault
injection frameworks, we'll have to have a discussion as to whether this is (or
can be) better enough to make a switch worthwhile, and whether a compatibility
interface is needed - or maybe there's enough distinct interesting bits in both
to make merging plausible?

The debugfs interface for this fault injection code is necessarily different
from our existing fault injection - this gives you a fault injection point _per
callsite_, which is huge - e.g. for filesystem testing what I need is to be able
to enable fault injection points within a given module. I can do that easily
with this, not with our current fault injection.

I think the per-callsite fault injection points would also be pretty valuable
for CONFIG_FAULT_INJECTION_USERCOPY, too.

OTOH, existing kernel fault injection can filter based on task - this fault
injection framework doesn't have that. Easy enough to add, though. Similar for
the interval/probability/ratelimit stuff.

fail_function is the odd one out, I'm not sure how that would fit into this
model. Everything else I've seen I think fits into this model.

Also, it sounds like you're more familiar with our existing fault injection than
I am, so if I've misunderstood anything about what it can do please do correct
me.

Interestingly: I just discovered from reading the code that
CONFIG_FAULT_INJECTION_STACKTRACE_FILTER is a thing (hadn't before because it
depends on !X86_64 - what?). That's cool, though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831173010.wc5j3ycmfjx6ezfu%40moria.home.lan.
