Return-Path: <kasan-dev+bncBAABBKPIYSMAMGQEXOGILDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 42E445AA32D
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 00:37:30 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id i7-20020a1c3b07000000b003a534ec2570sf1914619wma.7
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 15:37:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662071850; cv=pass;
        d=google.com; s=arc-20160816;
        b=nycjbyDlgMPG9NPY4nOpaMtquk3N+Xfti7avqFMfETB1ywEonuEbdefPCiYFaboFM6
         151JLQ85lPXQ/EcxUkrwbETJ2G1i0cfOuGITWJyAnvdlVeEbIQxKPtMZxAUwHLm0WgND
         RgRZ/iPqWadT3pNKvBVypoXAmIuA630zYgVfEjIa96eTfLIKFSojJINHl9aPsok7M+rd
         MnTMOnR8mTaQslPndNggdWSRbkqQr6o9cYUFOWDt9GxS3rm6V+zHeBKE/iXKDZrs9k4R
         0T8WV9SLtEQigq3Dn84Vb2kn//n5tu+dhOyEVQVDdzf85I42ZBxLx5YowyO0cmhcDLu6
         llzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bkNpCLFS+CSwkkQavZIR970A1UvX7zLMPoDgdHxndoY=;
        b=wIBaK/W/4GlK4SgOnD+wMY9rcQtX7KHZcSWQymge0SyZXqFmG++vGap0JzrN95eWrl
         FSU9TBezscOWxPiKl2AovE/kg99qbA7JRUaTkk4lWQBSS8V9fuYM6Jx9u69kwKg+aZRQ
         L0+H6u0olC+O0xhk1Ep1cC1HpIEpyn1vAV6k6wBpzngIQXk1NS2HYdqBFR1f5L2F7OoI
         Na2aAOIJopq8ivOqS9zQMED4fw3HeEWhz0VSdYvR3dPM0MZk2RdaiVSMSwy2HGk2iggN
         nqNx9ZSaHgbE3m9V4/gbTP11jYhJiYc1OUUTM2VGLerLD21I8iR5A8CFI6ulzR2IyrFZ
         Ic0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RyUvH2zz;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=bkNpCLFS+CSwkkQavZIR970A1UvX7zLMPoDgdHxndoY=;
        b=ERBABxg2EOvfkej065rCpHH9KL2UB3MPLazKoU2bXdXkEscTwNTo0OPm60AGT7HdCf
         O7l39nTeUTCyx+pFtfgbBC+oOjkIE8LSGehbcPay4bBzYxXi5D2X//QIUvAgUQrM018i
         s9VepV/3VrdbtL9Qz58qXUi3yLinFqBZQL8+t3Fyzcxj7X3o0/9vm2yOluYghEvqxkiR
         0tS0b8l8J5TLD1PbftNjC+rPWfg/33ZdQzyX0aU8WzKeJP5fPbEnjhxPd44DmDGo+JRq
         Et15K5iJojZB5aiQximZnXqtbDGrhFbuUUZtFbe+wWgnmZkoOvnXJ2S9HDLTt5TXNXO0
         PVkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=bkNpCLFS+CSwkkQavZIR970A1UvX7zLMPoDgdHxndoY=;
        b=o6ihyokmhPukuV8GiuSzSihG9pkgkqpwfrZtEVc12OnSnfl+3QS0ye7Pt8URAxI4kN
         zoxqP+O7su/WC5fRHD11JaILGivF/WoSi3W0ZoTBLhPNoW/VmLvwG+AUWJQCyRbZitKk
         5nMu+WgcukrejNqWi0wzOpFt9G7ovCsgBvfu+VTCV8QihKIctzGTyoRAaxMmiYKJULrl
         56TFKAGZK6zu2JPMlQ3i+70w9e3sUYsKgOepVk6370rIoyOMX+2qvwGS2CAdBz1Ztmus
         x6uyF+9uMfoLTsMkp4NQF3BCckMlgRBud+LFOuXgxjq/8BvgRE90Awi2JDWk/q+jFv4l
         PmbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3t1445XuVfIr5Y7QlHA4abhcC85sEcywGWHb2ak6rHw2wwaumV
	2YZ5WbRL8zscKWDBM/g4xPk=
X-Google-Smtp-Source: AA6agR5ouFb4Z89f90MELUfiCB9GWfFQOVW74eEtWOO9PntAuikxyJKYEuj9L8HjQGuJ0/UmMcPH5g==
X-Received: by 2002:a05:6000:604:b0:226:d2b8:504b with SMTP id bn4-20020a056000060400b00226d2b8504bmr15013833wrb.592.1662071849683;
        Thu, 01 Sep 2022 15:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c92:b0:3a3:13cc:215 with SMTP id
 k18-20020a05600c1c9200b003a313cc0215ls2120771wms.3.-pod-canary-gmail; Thu, 01
 Sep 2022 15:37:29 -0700 (PDT)
X-Received: by 2002:a05:600c:4618:b0:3a5:f3f0:3a60 with SMTP id m24-20020a05600c461800b003a5f3f03a60mr731720wmo.11.1662071848984;
        Thu, 01 Sep 2022 15:37:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662071848; cv=none;
        d=google.com; s=arc-20160816;
        b=Odz+jLo7jMY0DWiSNv55U5qT/MbwvB1wGZXRC2746bpeaKJUs0i6R53215TRy6Eatl
         XNPYBU3hMle2KhhwLmb9mtAIm/KjUqUvMeWjKG74UpnOImQkovAfAt9mg+94On4XfqEp
         5kij2TIP8HGTAGl97N1p+9zQRk9tg6M43dYOk4ox+c3b6zRWjij7/tnS5h00N/VaiNGD
         GMih9+k8gHx0/BDxYeaeUtXoBi9V52WfMg89b4cLDa0CiGuUchJMb3TmvPLCHX+2MNTd
         ajlJVTkTCw/SQMBZbzeMZsYJ17wjdgWkOSctnDRhtMh0tMZm5TzFL0Bvt/cHpidn53HS
         9PLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=V/P7j4Y+xJUBAt6fEYfNoKfACstBZQ8E1OFd7bHElGY=;
        b=EO/r+TuMpdWT0R3Nk9WHFapcwq5Y1kJiGkmvFsRonCJEjglP5OmBm9VUXsvpiPzE4l
         y/PJ5R/qBwyRdBlRhHL1sEkVjjGo6rGwtPzgF10Ddg9qf0fQsiXZ1NboEzPaDfqzXCMq
         mYTWSR9GxVjESrcyrN9hUDbGS4puj13oCjpF1TlcuFwD4YchleObk5JFQWXXclvAN7NP
         +reHCPMIVc2ZwpS7lQMgATqXCJ1ZdnCm0N2qCAfOzXFcb0IIYafB2SSoAxVflPXbNEG3
         IMFhq+tDHEqwabpi+xNG27khsTJE3f+yY2Z8qfHWV3FX01tVs3pqgZq6696L4tFmCgdv
         XZDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RyUvH2zz;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si25023wmr.2.2022.09.01.15.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 15:37:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Thu, 1 Sep 2022 18:37:20 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Yosry Ahmed <yosryahmed@google.com>, Michal Hocko <mhocko@suse.com>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>, dave@stgolabs.net,
	Matthew Wilcox <willy@infradead.org>, liam.howlett@oracle.com,
	void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	Steven Rostedt <rostedt@goodmis.org>, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	Linux-MM <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220901223720.e4gudprscjtwltif@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RyUvH2zz;       spf=pass
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

On Thu, Sep 01, 2022 at 03:27:27PM -0700, Roman Gushchin wrote:
> On Wed, Aug 31, 2022 at 01:56:08PM -0700, Yosry Ahmed wrote:
> > This is very interesting work! Do you have any data about the overhead
> > this introduces, especially in a production environment? I am
> > especially interested in memory allocations tracking and detecting
> > leaks.
> 
> +1
> 
> I think the question whether it indeed can be always turned on in the production
> or not is the main one. If not, the advantage over ftrace/bpf/... is not that
> obvious. Otherwise it will be indeed a VERY useful thing.

Low enough overhead to run in production was my primary design goal.

Stats are kept in a struct that's defined at the callsite. So this adds _no_
pointer chasing to the allocation path, unless we've switch to percpu counters
at that callsite (see the lazy percpu counters patch), where we need to deref
one percpu pointer to save an atomic.

Then we need to stash a pointer to the alloc_tag, so that kfree() can find it.
For slab allocations this uses the same storage area as memcg, so for
allocations that are using that we won't be touching any additional cachelines.
(I wanted the pointer to the alloc_tag to be stored inline with the allocation,
but that would've caused alignment difficulties).

Then there's a pointer deref introduced to the kfree() path, to get back to the
original alloc_tag and subtract the allocation from that callsite. That one
won't be free, and with percpu counters we've got another dependent load too -
hmm, it might be worth benchmarking with just atomics, skipping the percpu
counters.

So the overhead won't be zero, I expect it'll show up in some synthetic
benchmarks, but yes I do definitely expect this to be worth enabling in
production in many scenarios.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901223720.e4gudprscjtwltif%40moria.home.lan.
