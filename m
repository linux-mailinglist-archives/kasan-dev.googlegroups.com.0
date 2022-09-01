Return-Path: <kasan-dev+bncBCX55RF23MIRB2PDYSMAMGQEVK6WISI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB735AA2FE
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 00:27:54 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id n7-20020a1c2707000000b003a638356355sf177972wmn.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 15:27:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662071274; cv=pass;
        d=google.com; s=arc-20160816;
        b=R7OMFZmXEr25BS5lnMAw5eaxrRspmEOQU1WZUNyxBDpfH87i59FHsgbBNno28KQnTk
         Zsk8Hjyrrzf13dSPzAzAJ2D0PmRUJudtlPEf0H064uMhDt+8lWIlWxzpTQfw+tfwetXW
         uK65+b00PRAMvJj/tqjOj0IyfJDoDsCXcorDyKsy6z6Dlm+bFV1CNAHLXlOBQ8WnhNL6
         fvLYQJZ2CrhUpLQUMqSkE4D8+IYiQkf5hHuHFpDFsCYTLG6iwGCE4WRwF7GqODGUG4qI
         misevSRcSvlCZeW7hLz4oNRlxXPuQeDpXSCqB4jXJ9wduw6rnmlUzVLZT8916EakH/ms
         9TaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LBHoihua+OpCpVRAHrDntZzfuKOljw5bnvzLmXwb+yU=;
        b=lMR9ofQ5v+0mWL38nrOHVCJemFmeUFzseu3qseC5tDc9VNjAraMIcbc4wdL/FH9N+P
         nD1D5VuDO0Ul0H4R5pY2BnzOLAy69VlnQNv0gCAoB0spssci/MedZKi/wQMU0y4mZDPC
         MCWY6wL+GpfPn3/50IEQfVOEyTJojCPf/TUjXiLivTTucY9iPIGOpwhNvgWAvch9UirS
         oc7PdlbdFA2WetCd9HJSNqe29ftfAH/cYytJn7xS5bnqv6eKfuIzaNQkHe41CUMFO+xz
         P7vg0MNtmxKp08HVYPJz6p3zSASg0P78bMZHV092jcymoPtlstm7F3cVddAuIuGRJrPh
         onbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bPfcK47f;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=LBHoihua+OpCpVRAHrDntZzfuKOljw5bnvzLmXwb+yU=;
        b=L6jFbvTmAqfyE6nz0GTyBLUcY0sDkir3PI2C7kSaCZPb3RusVzVrV8mky9oh3etVA+
         mGFjmfgLSory9oQQqzgeqaXnS80GS0UrpJo3ri3KC82ucg3c3BpWnzkJuOViGSacgmsW
         x1hQHcZgUu9Pj/ZJJ/32DEztYU5SO1jvtlueOKfL+AFTck7tvnV3+QQVO0TNncJlCRnS
         5cGnWin/HWhplGtubu1eHmfxAXUotdUexppJyzeffaEziiq6m6wEjCU2ZAxKhf8aQ2m9
         LIb7p4pU602Hlutc+8Rikuspc9qsPbGbVbixBXIdkQV5ijo/av4GKXenUmVcOkBcVloe
         7bXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=LBHoihua+OpCpVRAHrDntZzfuKOljw5bnvzLmXwb+yU=;
        b=oK0fa1yK1fz+Rx/lq4Tdz80WXDm3UUuBHI1Lw4IbykdzyFfzA+UKuaqPEimiSigLUg
         3FP/q0feBQoAU9c8OMIwSW8JWsH7wmWwKd0S8s10343TehaBh9RbqFnirbrii4kxja1u
         FwjI3pYfXla5XgqBnv8KXIfzj0MZEiwSeGMMtJvot8WbbRF0rpJdleOa5Bpix5KxaTBF
         FkCEsnigyfCZpq8iBN57yMR3NosrzjdpwPGIfCFn3dCm6nxj82sO7UqSCd9221sLGQ7H
         1CY0XIbjtMDrtUq+e2udGw3kAnfnm5qmJo4Xlw8cB/V4SqUZGM64Lp0uHT+F1WT9NPwd
         Rrpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2DjEHeorg8n+KxGD32hYMf3WNXEY61oa3WVXTnqJZc9/ZGMm9C
	JIP1KXZrzz3bypq2lgHNDHQ=
X-Google-Smtp-Source: AA6agR55ubp2tgf3aVERZNCZVLS0CZnsn7pFWQXPAs+tTUtcjKKUWCOKyypZVOW8VfP1pcybTu5MBg==
X-Received: by 2002:a5d:47aa:0:b0:226:dbf6:680c with SMTP id 10-20020a5d47aa000000b00226dbf6680cmr11788088wrb.581.1662071274100;
        Thu, 01 Sep 2022 15:27:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5b08:0:b0:225:6559:3374 with SMTP id bx8-20020a5d5b08000000b0022565593374ls4958809wrb.2.-pod-prod-gmail;
 Thu, 01 Sep 2022 15:27:52 -0700 (PDT)
X-Received: by 2002:a5d:58d6:0:b0:226:cf81:f68d with SMTP id o22-20020a5d58d6000000b00226cf81f68dmr16189107wrf.131.1662071272895;
        Thu, 01 Sep 2022 15:27:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662071272; cv=none;
        d=google.com; s=arc-20160816;
        b=GC2MPH4gFLi7ZagHMHP9b4+vUQSf0HE4kxvNsT2KqL2FB/IyRypL2D+h/anNRTxNZ8
         +WEBUG+pJKKGInj7Vo9rEqXiJyqw2h5af0Mt0lMTAJJ/ryNOA1yIEhRCYaUpewebbTwO
         2OUxk/yRcDP2EdGNlDCOW9NqpwVhhfwguqFQ0Kt3Ac89qbWrsf78JxuJscgmowcYcU+8
         CUk443M/RXlk5H/zW/gvIdB1OBiuxR/eitPAH36WU2s9LhrtLTdfg4kVYsBEroqgxZI4
         KQeinAKePYVrHzsgSmsCPT+nq0fc5W10ltWGP9vIE/EKzi32deX0gWoBOeDgdSpmzISK
         OI4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=b1dqv/ByZCeKtjIN7qAh4WTPe6OgIYJaSbL14h63ejE=;
        b=DWqKFEiuqczj3wFZfjnAa7zb+GmAfQFyyXql3lZKKJ2wfgpTc4B7+hNm6nOZlNeWFS
         aPZkbarolg/jYOjxjcDKFHvP5Ljhsa5wdGNauWysM15TyMnoMCjhh49aKMq9LdmFkcvU
         ln+i4fKmuYX9/3sBwkhnIq0gYCbknBFNnsXc/siIFIFIgjnQ40GB2jkKfmQTbODWaHZG
         DgW2qAEPVZ6H/Bs2mC+xnVDCipwozGI+DYX3x+UXEzBn6hUXZUIm70aT2CyKXhbGFh3l
         9bm0abHO2T2EL27Wa6S3ftuaiUgDwSadVI+/SMu8kBHiCKwsIJK32SZmDXPMFfEgl/T3
         iBSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bPfcK47f;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si273897wms.0.2022.09.01.15.27.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 15:27:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
Date: Thu, 1 Sep 2022 15:27:27 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Yosry Ahmed <yosryahmed@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bPfcK47f;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:aacc::
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

On Wed, Aug 31, 2022 at 01:56:08PM -0700, Yosry Ahmed wrote:
> On Wed, Aug 31, 2022 at 12:02 PM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> > > On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > > > Whatever asking for an explanation as to why equivalent functionality
> > > > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> > >
> > > Fully agreed and this is especially true for a change this size
> > > 77 files changed, 3406 insertions(+), 703 deletions(-)
> >
> > In the case of memory allocation accounting, you flat cannot do this with ftrace
> > - you could maybe do a janky version that isn't fully accurate, much slower,
> > more complicated for the developer to understand and debug and more complicated
> > for the end user.
> >
> > But please, I invite anyone who's actually been doing this with ftrace to
> > demonstrate otherwise.
> >
> > Ftrace just isn't the right tool for the job here - we're talking about adding
> > per callsite accounting to some of the fastest fast paths in the kernel.
> >
> > And the size of the changes for memory allocation accounting are much more
> > reasonable:
> >  33 files changed, 623 insertions(+), 99 deletions(-)
> >
> > The code tagging library should exist anyways, it's been open coded half a dozen
> > times in the kernel already.
> >
> > And once we've got that, the time stats code is _also_ far simpler than doing it
> > with ftrace would be. If anyone here has successfully debugged latency issues
> > with ftrace, I'd really like to hear it. Again, for debugging latency issues you
> > want something that can always be on, and that's not cheap with ftrace - and
> > never mind the hassle of correlating start and end wait trace events, builting
> > up histograms, etc. - that's all handled here.
> >
> > Cheap, simple, easy to use. What more could you want?
> >
> 
> This is very interesting work! Do you have any data about the overhead
> this introduces, especially in a production environment? I am
> especially interested in memory allocations tracking and detecting
> leaks.

+1

I think the question whether it indeed can be always turned on in the production
or not is the main one. If not, the advantage over ftrace/bpf/... is not that
obvious. Otherwise it will be indeed a VERY useful thing.

Also, there is a lot of interesting stuff within this patchset, which
might be useful elsewhere. So thanks to Kent and Suren for this work!

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxExz%2Bc1k3nbQMh4%40P9FQF9L96D.corp.robot.car.
