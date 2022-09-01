Return-Path: <kasan-dev+bncBAABB6UAYOMAMGQEEHDYTFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CF515A9A11
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 16:23:55 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id h35-20020a0565123ca300b0049465e679a1sf3981559lfv.16
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 07:23:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662042235; cv=pass;
        d=google.com; s=arc-20160816;
        b=I2BMxaRSVwKS6uQVevYUQgwHI5nwUoLgZabYN7CAj/42h5nhkv/iQBZkisedIzXjLp
         2Fl7MlYHF6KPy7guojs/nIRBnKDXmTDaxr1TcZpH2GArrfLA9Hx8tODaJXGDYSeJxhbK
         ynrOdZkvxQghio0snZ1ykg5FdsjpvtZkC2Lfkxc0wvgkasduBNndJe7pblozIIqos89a
         eZBwJr8M56CqJZrOd9qYS1JE0rYiuRIonoqx2JCRvULh++UkRII6shhL80B78bRoqTFQ
         YHvmqsr3BsLl7BAwJlItcstI3DKtjxaZyTYI0DQxZ8BP7tAYXNw/HnEW2lpcm9Ln7wli
         mt7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ywq8gMPhgjwgbCX+mHjCpKobDMb/uPeBf6Q95Lh8Z38=;
        b=A+pxwv1ML/bvJ1yFLDxgD/Z+VydgJte/Zx0GisWZKm8enghgASc3rKj8WdouHIucEb
         nhQL1/SCmiKyZyPxADrhSKi1XdyPR2LL9gxYDoj7ULVVSH3OtazCCwIEVhtz5foQQQcu
         Yy2HsnU0Wd94ZmYnjJrL12bS2u+SXpzSgEE7kxTwFCs9DOULVkdZecMfzdNXU3nDVWtX
         uJHMZkxiKPRhnM472O8V5bsRPuzGPr2ee71VNbtn99bIyWNOeyHJjG/qgmg+OG1LnW50
         5dGBlORbm1du/01LfnrNH4WewZy45AyFt2Zi3Hh4LkHyYxkX2OFEcA5IXzID4+gjjSBe
         BcJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=P+qdlVJW;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=Ywq8gMPhgjwgbCX+mHjCpKobDMb/uPeBf6Q95Lh8Z38=;
        b=oYLkOAsJngn8YCgx2Ko1Y51+qpC5Om6sLFP0dwX8sN+ssRmPjjeJ7q6Wtymdr2L5je
         xTV3e6vjRhWsN1Zpd6aVoZI0z0LlchC5Jp1PUoqtYSeDWy3BbybUEinkPkWmPomKHGST
         USPZ1tE/sCAcnyR1slvd8ixFN/O+tp4XqbuUFbDasPkANUtVuBSjg/wopsAZqtTN60Q0
         XmdMt7J6nFy/bMGyIWPu7td/O9736dlgi62jNmGdn27Uv94YUcHvYRVIHnA0VOWDrHlm
         PKERDCi68lMrgpLXFEYi7/BTAT1bqUwgVgeaa6emE9h+v063MzpEnz6qz/hbdY+fYg6z
         S0aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Ywq8gMPhgjwgbCX+mHjCpKobDMb/uPeBf6Q95Lh8Z38=;
        b=Fjq5Kd+fGkQqG4bFV25/i3IZsRQ9yjd9CZOvFqjcPIp09h3BRPvHXtJVPmDOqfXCFN
         eZaP2VaaJ1qmDaiy+lTAVJu1dgFYLwzV0rDr1SL1UfwBvz3aRYTzP7mYKi+UdIWlmW+6
         j6S7EPsnlMcpseCJZeotQ9VH6bl3FR77GHFcSnR7aTinIa5sU2cofdzQ8NQGyntIUTFg
         iDIoYwwAz6ZAazJyuLK0UaY9A0ZvnQSrv0HEbAUwrwkrwU8TyRQNt+ejBFO1nWsSCRej
         AAYj2yT5pIJLaGTNaWO8Ei3WYA/DzMdoV7/Mx30k2XKoY5pCKrRCMNAyG6jW+m5JGSvA
         egVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo15LEbpODXLn30916aga6LtyXaR2TcsKlpyaMjjX2DCQ8xUzu9E
	K48BfiZZEVoSIuytB8Eht9M=
X-Google-Smtp-Source: AA6agR5v7uWIeg9tNlvzpNj0twI01POEIzdYsFA3+jtaWSn7JwHNyCkU4ysOQBbWUuibAN5WaPnnpg==
X-Received: by 2002:a2e:b892:0:b0:25f:e0f4:8911 with SMTP id r18-20020a2eb892000000b0025fe0f48911mr9307324ljp.25.1662042234919;
        Thu, 01 Sep 2022 07:23:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls1603657lfr.2.-pod-prod-gmail; Thu, 01
 Sep 2022 07:23:54 -0700 (PDT)
X-Received: by 2002:a05:6512:1309:b0:492:e273:d800 with SMTP id x9-20020a056512130900b00492e273d800mr10221193lfu.93.1662042233994;
        Thu, 01 Sep 2022 07:23:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662042233; cv=none;
        d=google.com; s=arc-20160816;
        b=mpI45TIOxRvFydfzzmHiePHilYjJ0Y/Iu10OXY6P0q9KmcQr+s3JeWr5LegHsMir/I
         7dkJCBoBrG7o6+ba4MjkTeGYR7O3AObxyo6joLdbNAlDgefrikur6Tf97ZmDvQOgFA72
         NSxnJhKqGJ03ad86iyc4jHQpUTW2VkJmnZWRvKgMZbQD0a1qPcwOerPQyh4IgPtznxT1
         grfbcEXxNlfRy/bzupBCCZCPEzg05bzXxbMmVLsPRcr7Nc0/DIAmcm7f4DSiHbua8jKm
         dyBsz3SUDI1NkIYSM9gsENjMFfCa5j06ovC1V3we24YjnX6yENoIj8n5cacuuGu1FBDq
         8iSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=JsB2G8WqLnYprEF0GcA9GFFIGkQht/MFH67dN0NC9t0=;
        b=EgqfompP4L3rflhL7eWszjgyyTTwhPMklS2sCJ17aGs56Se9CMhgfXSt6gLwPjnJ3j
         xOgiwMVb4urEkwW0jC3GFRksOX8e+DZnx1OJUIrs5rjsIdSS9J/i7xCrk3qxHBk5PZJE
         l9Jiqz1/ifLxtNnZ6b2yJNKCatc4IBUjdLwn9Kb6kfU5chxIalS23NTUD4t4SYyMCqXd
         fLxPoMWbJLh/5dQhozS9m+Bbg4be2Cnbsf/kP6vcyW6yLueXocoLyeR1jq/spdKYn/ku
         1X3X8s1k86DI7vknSdJcjo7D90vedDk723Y4zBjRG0yAEmAXjHnbqmWgE1zkSEAZ+D7p
         M+WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=P+qdlVJW;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o7-20020ac25e27000000b0049469c093b9si597973lfg.5.2022.09.01.07.23.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 07:23:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
Date: Thu, 1 Sep 2022 10:23:45 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: David Hildenbrand <david@redhat.com>
Cc: Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220901142345.agkfp2d5lijdp6pt@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <404e947a-e1b2-0fae-8b4f-6f2e3ba6328d@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <404e947a-e1b2-0fae-8b4f-6f2e3ba6328d@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=P+qdlVJW;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267::
 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, Sep 01, 2022 at 10:05:03AM +0200, David Hildenbrand wrote:
> On 31.08.22 21:01, Kent Overstreet wrote:
> > On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> >> On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> >>> Whatever asking for an explanation as to why equivalent functionality
> >>> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> >>
> >> Fully agreed and this is especially true for a change this size
> >> 77 files changed, 3406 insertions(+), 703 deletions(-)
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
> 
> Hi Kent,
> 
> independent of the other discussions, if it's open coded already, does
> it make sense to factor that already-open-coded part out independently
> of the remainder of the full series here?

It's discussed in the cover letter, that is exactly how the patch series is
structured.
 
> [I didn't immediately spot if this series also attempts already to
> replace that open-coded part]

Uh huh.

Honestly, some days it feels like lkml is just as bad as slashdot, with people
wanting to get in their two cents without actually reading...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901142345.agkfp2d5lijdp6pt%40moria.home.lan.
