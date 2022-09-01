Return-Path: <kasan-dev+bncBCX55RF23MIRBIHQYSMAMGQEHERFYDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E4385AA355
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 00:54:25 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id qk37-20020a1709077fa500b00730c2d975a0sf84999ejc.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 15:54:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662072865; cv=pass;
        d=google.com; s=arc-20160816;
        b=zhny1IVD9Qmy4rrQaG5qWQfjtQWjIRBIYAciD2qoNandUJKqcdPKGPTzdF4qSq83xI
         sSt0M2++S8QxDFhxzzbeHkvVpINA0LRTGiwsORWMQBugQFziv0RIu5ydXI3rcWqFW1yr
         7TD0JAWcrzeykN8rx3jTkYfl6h7/ePxmbMwlzCmloJtuyLS5sljhQsqkMSv301oX9hu1
         kdprqNkaerZ11rb9renMihsTJqFtDYoosVDdIGH714Hv9SSQcgoi5W95aprzqPJB04tB
         LjYTLq0/CZDHLFMHqe6hxGnAdVQVCpn812eofNBZUhD1hhyMdnpLWvKST/PB0PmiXnAT
         +i/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/zteYM0GZDkX9znezGpdgC6kJJQstUPaqmbkDUJvFjw=;
        b=DNl3FamcdI6k5GprTUnmIKXrxS3VX00kEspQWKGE1fQ6NIvbn2O0R79UbLEMHET1C6
         BmkwQTTd3WuHoWeEiE/1Xbwr6fnaNoIq/a9qvZDVZXDL8ZDyYfYdxCEw0Kmqrv5Pvinj
         ZJfTxdB2pXp6g07aATSpslsUyL/KkIa5P5JMFr7k5gTRGLpPCAoRUBFMqUWR3tkQ5D3/
         mwDapOVug2n1PIIlRJ9HO/iAkBloyyco2eFTBgyxhyNoRPglvc42xnUcTgAJOU38SX9k
         A6VWs9iCa2KetbW9E+9Br1hACg8Tg4RnH5UgQSsAkFK+9ZXprazH3rGKfD8lCr63L6pC
         7sZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oPzrWlMu;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=/zteYM0GZDkX9znezGpdgC6kJJQstUPaqmbkDUJvFjw=;
        b=Rzu/1NaV9ljfnVRGKHzBHifsB7HtzueiQh5c8QQGBD0E2zzUQSrVYdIkyBr7zLhjgj
         o4p/EeV0/g0FUa0Njtz0LXbng5fK9dLwcRMit/7sJAMv05gr53vQH3w6BkWJaxVI6l5q
         P7XeKwbBYFr362WfZjq9QCMA8SZ+UI3R0NX+OdyPEc0Ru+NDdmlzJHEIjbsXnTawUmRn
         3vu4DXiwkYnrdZQCa4PzlhREClITDjafr5REy3gL6KdL4mZx5tEdbHqdsGJ3qGVE8cg6
         mgTJmsKDVUs+b2GVaqJp1zueS4cqZgGe+15rjaNRmpd6Il576UQZof3EurkkyJO+a3QP
         Jbbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=/zteYM0GZDkX9znezGpdgC6kJJQstUPaqmbkDUJvFjw=;
        b=s2DGWCPVzvx3nLP26mfGGd3vhVaE6lPvNUTS+xxCa8scVE0ZvxLm2oMZjBjEn6aLmB
         drDC56ARHWkS6CZ8tIRM36GPlC+TCTQ7btgnS0iy8K2J2vV9h9pBetUzi2cQ2bKBpmtS
         PmAOLz2YNY1ejf9udliAko00q32lPj+2PRM2lpdtxfr/B58tLT+WoNUhYbnuxxAGXTjg
         OHpxGyxDZZFlwlD9PsowKr7HDmlRdBK+W5CqbnIyKEhrCZge0grX2ebF8Fv8uqVD1TO7
         rYNyQArccuJSLYScRWNK5m2IMi396sjrPkf3WXf7O/+fhE2c56rOe7+tvkjh0TN77Of+
         +FOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2ZaDseuXhkfRSj/UC1W2GTKg2p6i6ywLi6LlEzlWXkIm+cj8aA
	w2Oj/Gpyy101WfEtQwzauxM=
X-Google-Smtp-Source: AA6agR6m2Flphs1m4g8+HI+GnxHcE1FUP2OPSd55igaf6v26AmmPI1vk2+s2Oz8ynqrARJkbX2t5Xg==
X-Received: by 2002:a17:907:a046:b0:730:9c7a:eab3 with SMTP id gz6-20020a170907a04600b007309c7aeab3mr25812068ejc.285.1662072864877;
        Thu, 01 Sep 2022 15:54:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4548:b0:73d:6af2:48f4 with SMTP id
 s8-20020a170906454800b0073d6af248f4ls2120991ejq.3.-pod-prod-gmail; Thu, 01
 Sep 2022 15:54:23 -0700 (PDT)
X-Received: by 2002:a17:907:a0c7:b0:734:e049:1af6 with SMTP id hw7-20020a170907a0c700b00734e0491af6mr24939153ejc.439.1662072863877;
        Thu, 01 Sep 2022 15:54:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662072863; cv=none;
        d=google.com; s=arc-20160816;
        b=DpT+vlkAMHZq7bOj88P7l0C8VNWpX54FmN4R5l/j91NKqha/5QbMorjWbv1UEMPVfq
         EPVCTjC6mbcQwpZh1EXH6/oG9MJMdkNereOVEg9NemMOcEdgIxV/ZQePBr0jVb+G5dGo
         owcYNGGeVpqS4al8nZkl8ySa/s+oF/vvZXVxc/JaGpm7DadGYHoeBt/AEW2tEBv4s64J
         uqB6Md9csYwo9rB3C6Q4r4X2/B77o6E5q6qSwdBhKzaCqTvUdfwFOfFYk+Evq1EaOrmI
         ZT9IlW3/2kkJ5mrIlbBU/1MJRxMUY2VlNCWabqWDf0rItBppjjJGI2Hoz/3vmubBUXAn
         8rpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=HsNTuFQ7XbCclBZlUbN3U5MkNcD4kydlxiKj9ag/mqM=;
        b=pW0kIHptzR/j2Ayim1ExDN1/mb2CuQG8CGfjJZ2HrPeEwpFZT1IfliFK4MwqHhr5oz
         Ug1DuEUle3lQahcWvubq79q2Ieh5TV/9d7iEecI1P8wrV1IXFN8CO1A2SWJTj81yme2/
         0/y9G0CdH9LkDstAcawEmb84FwVtw0PXgMfJok8L6eEiwOPmlPJzpFM/kXN5xfsZy7Go
         e6mnX6PEpUFhp9m2imruK30gD3SLGctKvdZaU+50472E4aJXhmbstg9nZi/gwt6aM6Or
         X+ZP/nX27sLWQ6TmCjkAJrU8gkW1rL4fnD7eznT3vxaC1HLqU2+EH0Dcfeffk1c3G954
         hKng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oPzrWlMu;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id hx8-20020a170906846800b0073d9d812170si25613ejc.1.2022.09.01.15.54.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 15:54:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Thu, 1 Sep 2022 15:53:57 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Kent Overstreet <kent.overstreet@linux.dev>
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
Message-ID: <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901223720.e4gudprscjtwltif@moria.home.lan>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oPzrWlMu;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f::
 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Sep 01, 2022 at 06:37:20PM -0400, Kent Overstreet wrote:
> On Thu, Sep 01, 2022 at 03:27:27PM -0700, Roman Gushchin wrote:
> > On Wed, Aug 31, 2022 at 01:56:08PM -0700, Yosry Ahmed wrote:
> > > This is very interesting work! Do you have any data about the overhead
> > > this introduces, especially in a production environment? I am
> > > especially interested in memory allocations tracking and detecting
> > > leaks.
> > 
> > +1
> > 
> > I think the question whether it indeed can be always turned on in the production
> > or not is the main one. If not, the advantage over ftrace/bpf/... is not that
> > obvious. Otherwise it will be indeed a VERY useful thing.
> 
> Low enough overhead to run in production was my primary design goal.
> 
> Stats are kept in a struct that's defined at the callsite. So this adds _no_
> pointer chasing to the allocation path, unless we've switch to percpu counters
> at that callsite (see the lazy percpu counters patch), where we need to deref
> one percpu pointer to save an atomic.
> 
> Then we need to stash a pointer to the alloc_tag, so that kfree() can find it.
> For slab allocations this uses the same storage area as memcg, so for
> allocations that are using that we won't be touching any additional cachelines.
> (I wanted the pointer to the alloc_tag to be stored inline with the allocation,
> but that would've caused alignment difficulties).
> 
> Then there's a pointer deref introduced to the kfree() path, to get back to the
> original alloc_tag and subtract the allocation from that callsite. That one
> won't be free, and with percpu counters we've got another dependent load too -
> hmm, it might be worth benchmarking with just atomics, skipping the percpu
> counters.
> 
> So the overhead won't be zero, I expect it'll show up in some synthetic
> benchmarks, but yes I do definitely expect this to be worth enabling in
> production in many scenarios.

I'm somewhat sceptical, but I usually am. And in this case I'll be really happy
to be wrong.

On a bright side, maybe most of the overhead will come from few allocations,
so an option to explicitly exclude them will do the trick.

I'd suggest to run something like iperf on a fast hardware. And maybe some
io_uring stuff too. These are two places which were historically most sensitive
to the (kernel) memory accounting speed.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxE4BXw5i%2BBkxxD8%40P9FQF9L96D.corp.robot.car.
