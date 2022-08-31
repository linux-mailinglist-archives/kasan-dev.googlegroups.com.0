Return-Path: <kasan-dev+bncBAABBLHAX2MAMGQEW4HTZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 398605A8655
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 21:02:05 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id m18-20020a056402511200b0044862412596sf6823281edd.3
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 12:02:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661972525; cv=pass;
        d=google.com; s=arc-20160816;
        b=pPyydE6o475ojeiOHPhGegnmjxEWs9802oXp1blWqCEBSsVAJJaTSkPldWUxp1wSjI
         UMsVafg/B2/318gBwmbxTo0dFNSZANK+md9xPqVd+BHgOzR3qpO+bgo9yp8sX4LyqowE
         ibteDR8tpfPLMLXmcnm09hmlDje1Q26o+tXD3cDfudu6m+bDLu072WUnbBmPKjyN9lPy
         6ocOTsvDabXqYeHBiUyxGsJ3G4dmcv9iCCOsllDtRTY6goZ6TkaSQYwuRxYusR3FJsNB
         Oqg1npumbxyRbjDjbBega99V/hoJoPLP3f/UV4EBdKeV2IYjbwRNZRaqCo0ikRq+JzjF
         OhhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8a+yAaYwOe0HSIngV/+URlATcBlEfErssC0VARTjlNI=;
        b=GdPAf3B+T2zBm/JCJBA2tps1HByEgOiM6BRdDFdiXtAw0tJJCYYBSkMOYJ0OhKA5aS
         1WPYZDM1+RrIo1/rACGwMC2aBwrVCplDygFEYRiyiO4IOjurVFNEzGRgV10qZ6IPcn5q
         OXWHeBRGCFdHKztUl8yRZGJ/Qw3lK/hXovbb9oT031RMuMpti/4bgZUyOpVerO1YbbK6
         peOwjJ+iU4JnOPSflbGu3nj4Y6EFvxYlOFH7MQwddx7bPH7dpV7kcszw6Y0b/yTWTo3O
         zZqIAFDT6jUZYNrywt5KEkI6dWEEgd3awafwA81JIY76afSjF/ZeZw2rEMhB2jfe2RpU
         ziCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="sF/L6oga";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=8a+yAaYwOe0HSIngV/+URlATcBlEfErssC0VARTjlNI=;
        b=mNLvsaT/D1B7JUx/8CsUBqLbvl9zSg6uJEEThi/Gte95zmdXEmFu43NA30PoVVfYwC
         EzURMAVD/hnsZLGfWgc1UcZ29XfZRvXFPG/pDBz81iB0CXKx7gLVsQyVD7SWjwcyigN2
         JV2+KJOPtOXitlqi2ukuZXKtzBV6bIYGgulovWXgxcVDNRDiV725In5lAzelBDb/iWci
         IZ49DLExvjNvmF4V5psql84lpX+A33vgNWi0v6bqyBeJMnvWnq0Hu1surXBISRwbCB2E
         y4h+tmQG0WfJ+wc4v1ANeV4YDnm79hhh5MkU09x7WKzKU8sSMMwZFRVDF5OkgxyhA3yp
         mSGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=8a+yAaYwOe0HSIngV/+URlATcBlEfErssC0VARTjlNI=;
        b=cdNH+maG1Oz2EbizWpRoO71jc8JCttTolHmKDpJIQBSTv62RHHbhsbFNHP+2S+kvgj
         +iOFfN9+9HQgtuJrIB/M83dk6umak3O/i2g9QzQnsyhMKbJWLLt3Y8RWUFVi75Pyp6wj
         ZTgvTJLr0QZOFXvZGgJpFt5XvbV2HkveaDoKUdvz5exZS6duAXn8Lgt1wx/EPRW9Ihxa
         kn+0PhuiXyC1wDLAffST6RszQ7QEJ0bHGNk4+oFzViC/gLDGmP4VQXU0TNo4Sqfyd4kH
         bIX6k7ovtCB1IreNrx9afXFeisU4MnHHdyU7zUXLoJgYttUJfPhXyZWX2NNxCuldYBgy
         qb4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2Z2QhVqVbL7BsUk3GqGzRT4Ui7We6r41JQPceJo+pj+B+qs65m
	sws7cwLUe0qb3QA+GUMqW0c=
X-Google-Smtp-Source: AA6agR6N4zbdXfwEVS8/6D3+ixw6jPN4VIA2NobEpBR2Ngo63LsAQgV/r9r5dpe8XvAOensbcVidjw==
X-Received: by 2002:a17:907:da0:b0:730:d0ba:7b13 with SMTP id go32-20020a1709070da000b00730d0ba7b13mr22074373ejc.332.1661972524941;
        Wed, 31 Aug 2022 12:02:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5241:b0:448:77f2:6859 with SMTP id
 t1-20020a056402524100b0044877f26859ls6582434edd.3.-pod-prod-gmail; Wed, 31
 Aug 2022 12:02:04 -0700 (PDT)
X-Received: by 2002:a05:6402:354d:b0:448:1f80:e737 with SMTP id f13-20020a056402354d00b004481f80e737mr18301018edd.69.1661972524154;
        Wed, 31 Aug 2022 12:02:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661972524; cv=none;
        d=google.com; s=arc-20160816;
        b=t/Va0k/1HsasRFTo0HCdBjx57RpB8PadhdAHSouFw/TktJ3UsbA56jjc7+m/yEhd83
         4vIalHyUQHEllGu8JlvyaFO8rCWvIuNw9NcAbiudwIuYwwaf77a+oSXcMM9QBfIRkrtg
         k0xuh30o2R3SnRwSJNhDUUXEvTP/dWvFIxPPNjIz+Ap9lfalGmQ7L9tJbS9Ph1anB0op
         eHXnxvp2m+8JMo/A+kr5KFy+GSve3ZHaINMf4XyOw3Y6oPmAL3+jovf1TKnAsEyJbRsx
         JEBFo23LwNpGpt4IfNe6Y07kPYRKoQUI6fjbUvjnE0UvtfP+yo9HeK1Nws+FYqEVSuTP
         iQuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=/S1Z12zwQROoKfTz1twMnESk8KqrSv9O32o/CoebBns=;
        b=C+GdOOjMHDHHDOw49ASqRUPRJC7BuMeP9K7+Qf8nb8vGJC1aENtoDXIaUj5NjZ4NfI
         2E+6PP+NOQEgBVKq/gyW0NgFAhR0XhM+VmysWflTUVu6YnIddqP9jZ0rGx1fmgFSZwcN
         UnQf/xk8ljL6RFLDbMKnnMtngBLT5c7ycUzngZ6ICnUeF8Q1fvGRivavGGNd8XvlNsM6
         /nLDfMv24LG3mfeM3mo8658n4h/+91YVCjvr0UN2fHUP1pgpVRSIWlue3r+AutKjEZZs
         klGaEHdyOO6YCvvl3BkFKsGJfLPWRLRRzHP86BCIc6/tsSiU56ZWnFX7EbiOaSAMhZFY
         1dRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="sF/L6oga";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id u15-20020a056402110f00b00448552ece6asi3112edv.3.2022.08.31.12.02.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 12:02:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
Date: Wed, 31 Aug 2022 15:01:54 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="sF/L6oga";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > Whatever asking for an explanation as to why equivalent functionality
> > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> 
> Fully agreed and this is especially true for a change this size
> 77 files changed, 3406 insertions(+), 703 deletions(-)

In the case of memory allocation accounting, you flat cannot do this with ftrace
- you could maybe do a janky version that isn't fully accurate, much slower,
more complicated for the developer to understand and debug and more complicated
for the end user.

But please, I invite anyone who's actually been doing this with ftrace to
demonstrate otherwise.

Ftrace just isn't the right tool for the job here - we're talking about adding
per callsite accounting to some of the fastest fast paths in the kernel.

And the size of the changes for memory allocation accounting are much more
reasonable:
 33 files changed, 623 insertions(+), 99 deletions(-)

The code tagging library should exist anyways, it's been open coded half a dozen
times in the kernel already.

And once we've got that, the time stats code is _also_ far simpler than doing it
with ftrace would be. If anyone here has successfully debugged latency issues
with ftrace, I'd really like to hear it. Again, for debugging latency issues you
want something that can always be on, and that's not cheap with ftrace - and
never mind the hassle of correlating start and end wait trace events, builting
up histograms, etc. - that's all handled here.

Cheap, simple, easy to use. What more could you want?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831190154.qdlsxfamans3ya5j%40moria.home.lan.
