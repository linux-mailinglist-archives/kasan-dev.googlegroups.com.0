Return-Path: <kasan-dev+bncBAABBIN4ZGMAMGQENN6GLGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 236E15AB8F0
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 21:48:50 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id b13-20020a056402350d00b0043dfc84c533sf1943533edd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Sep 2022 12:48:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662148129; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ns05Ptu6XlUWfBbveOPMuEuu+1ZKBnCCo0Y+Ig1/Rt7dvYMLHDjV6SKjQ1iCJ2lRtM
         xCj+OfwNHdunsXX3FcL9Qb35h1K9xwrJn8DTWpvPH6ZBFTHZwY7SP2heL8XsM6/aNyc8
         wse2beuPU5f0DkqId2Nz97Cuz5e7WbT9xTIZUPA+iy3/xTxGv47wFCFRQBqkMDZjaw/z
         Er7bEqqbFJyiuvHUZY5OJwrjPEHNhYanDTP6hfv/So5JIN5XbD4Y+t7ZUQYOAfzmrZu7
         CDgJCvjTE39pJsE7Azt314FrZOrOWRMSdKMS16aAz3U90OQZ/2gpZYZmKtUnrPJlhNBm
         yeyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XAnQvhFzyH3jwkiYWGhXptHPHsKgxemir+AUgtJ0/s0=;
        b=JV/kWTcmzprAjLjwqZD224nr8KEqaSsI4IXXVa3CEJlNL29xkjDCMz3b9YIQAny/Fg
         vhMo9+pHy6+y2+QGP7h7Q2hfmxxqn+WV/KfRZwQSrU6lBzsx2HrEdawYxhXH+2pDNxGB
         uu3eXTroHwT8Iq8CLQ3fcCJ3ouQT2YhOBXqAyA46d6ITli39RljoqFyhtqIdqGf1CgGL
         RmoDSbtp9p5bcfv6W3tuq+Wne/WhuAaWy3ukqD64Ve73AYj8tuTii2Z9eg17ca9UvVVq
         ylyXO4Kq0K9x8ARMTHVWTJoTX6xsKiLQsx6RZAxcGgA/vqax3uY/DkhHTThe17/whdaI
         Howw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mPyxzHSC;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=XAnQvhFzyH3jwkiYWGhXptHPHsKgxemir+AUgtJ0/s0=;
        b=e9x+3XXMil+eU+AAYMU/JOhTvbb98BWDxaV9Wx9OiJxOR5qjxWtExWO0ZqC97uM0zH
         rt1comNb+ihix8zKu5hy1WjgHo58s4oXJS2XaqJ5P+ZFdYJrcIIv3nf7BaAa/GMi5d/e
         I8lMfdKeWSeOr0f8rqmUcpPLALuserQGUXe9J7LipXsEKDsfbX4bw/vtVaRcngcG+EBd
         U8Hi1ahnk2PVEGagNXInFVMbEtlD1Pv+adhzWtqpfaTlXu/j+O4n+AxgnHqavtcXrL+y
         U9I8aw4z4fh87Nx13tLKo+pEPtOfkBuo4SigvE/SsTwpmW+mv7dlmrJpb6ilnIVxMR+9
         NFTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XAnQvhFzyH3jwkiYWGhXptHPHsKgxemir+AUgtJ0/s0=;
        b=fbB0uc6Emw/D1siEjWxfxodJ/LEZQMTi2dJue1nDQ3NZ2twAiK9lXF5jU3yhxv5Rbt
         AhRNtGL8Dee4CMFKLDAm638jVqeJfTh19IJBoulA6qowTzhQKV5ZUWRUG3Z/lusTVk2d
         V4CJpiX193JlTeesIHsFUuuegQ5+YFCWVTCcRqM3Ch/3n576YvnvH4KavT9NGXIBLuaE
         n2GgD0SzZrH0h6lnNSnEiBrywQflp3CRC8tii6BhRxeNGInsnKlO7K0HTlGyFG7/zz7A
         nLX22hz14bWV60bobM3vkeizlP+WsWFq2w4KrGeDKCmZOMZxslRpXuM3N4TfOKiGM1Jd
         Vryg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2IImVEk5Qmf8Gou+sPZhEVhrCGbJNxHSB5zwDe5mVq5r4tXCGX
	YJQ86TH0unBfpy7lOCTbAQY=
X-Google-Smtp-Source: AA6agR6Hn8MBAwz85AGNeo4FvfJ+mljcNbPQ8YeIh1Z9vQ+pLBUq6+wKQ7SKFPTckdGRovht6j38+g==
X-Received: by 2002:a17:907:80d:b0:73d:a576:dfbd with SMTP id wv13-20020a170907080d00b0073da576dfbdmr28075836ejb.402.1662148129530;
        Fri, 02 Sep 2022 12:48:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3819:b0:73d:75ed:a850 with SMTP id
 v25-20020a170906381900b0073d75eda850ls1372537ejc.2.-pod-prod-gmail; Fri, 02
 Sep 2022 12:48:48 -0700 (PDT)
X-Received: by 2002:a17:907:75ec:b0:741:484b:3ca4 with SMTP id jz12-20020a17090775ec00b00741484b3ca4mr21895868ejc.316.1662148128705;
        Fri, 02 Sep 2022 12:48:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662148128; cv=none;
        d=google.com; s=arc-20160816;
        b=Srk79W3oNyyhxGZGWt4CXfxRnKxnA0dWlVkIDMZmSDGesWWf5W/GU7dzl/15bYutsA
         /WBnXlnMM2ulrcGwawqd4o8iQbS0AOdOeLabdr4tQH0UHi6g/VozByntFO25qVflqvlA
         pmjVcib4nl0w+vv8GbUTHxNp1aStKaWTh5sCMKJ90i0wzWKFIM4697IjyCVXYzpJlKmR
         f8mON3caHo1OkRn6KXvaovGfBEKMnayZmTwdrQiUZKYHT5O9qonCUBc4vkYMAc7ro6y0
         htBdZWxtoLcAEAOjJ9yzk7fEWt/Ni5Arox0PgpGMJ48pSknq2iRaP7TbMUX3s9cxt5Q+
         S5oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=n3Vt2n+PBD0eNIsvGTR1l3JrOeVtWEjP88FVSBBEvEY=;
        b=uax+AEiN5Uk44Gy7fdkpFo1ASsVHmnzNXUlRCcO+uKj9ZQ3FdpXvPxD0/Pti7kAPji
         QQYzz5pN1r+ln+2kjS/P4JeFcCQAnASIn93oFKioDrOeo6YMvCYcGt2txd3tS3RVSvpQ
         evu/aQ6SYBfKwHXhLvL9IGesJNZ9XFNwsXsCaikRT+nG4YhXqxKYsi/V8fqc2lggaSpu
         g/u/cIoBuZ4SP9g7+qB3vUe3aeRrq2UCNiJ1hWBplXDMT+uU8aFWwvBIhqPKWTpFtFkk
         j/9GVadkfPKS4TC4DG5mUi60HRP2i3HVJMaCTCAMAtTIetqT7YZGIA2qbEHJzcGig6k6
         rozA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mPyxzHSC;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id my7-20020a1709065a4700b007420a3f34c3si142441ejc.0.2022.09.02.12.48.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Sep 2022 12:48:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
Date: Fri, 2 Sep 2022 15:48:39 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Jens Axboe <axboe@kernel.dk>
Cc: Roman Gushchin <roman.gushchin@linux.dev>,
	Yosry Ahmed <yosryahmed@google.com>, Michal Hocko <mhocko@suse.com>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>, dave@stgolabs.net,
	Matthew Wilcox <willy@infradead.org>, liam.howlett@oracle.com,
	void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
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
Message-ID: <20220902194839.xqzgsoowous72jkz@moria.home.lan>
References: <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
 <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
 <3a41b9fc-05f1-3f56-ecd0-70b9a2912a31@kernel.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3a41b9fc-05f1-3f56-ecd0-70b9a2912a31@kernel.dk>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mPyxzHSC;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
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

On Fri, Sep 02, 2022 at 06:02:12AM -0600, Jens Axboe wrote:
> On 9/1/22 7:04 PM, Roman Gushchin wrote:
> > On Thu, Sep 01, 2022 at 08:17:47PM -0400, Kent Overstreet wrote:
> >> On Thu, Sep 01, 2022 at 03:53:57PM -0700, Roman Gushchin wrote:
> >>> I'd suggest to run something like iperf on a fast hardware. And maybe some
> >>> io_uring stuff too. These are two places which were historically most sensitive
> >>> to the (kernel) memory accounting speed.
> >>
> >> I'm getting wildly inconsistent results with iperf.
> >>
> >> io_uring-echo-server and rust_echo_bench gets me:
> >> Benchmarking: 127.0.0.1:12345
> >> 50 clients, running 512 bytes, 60 sec.
> >>
> >> Without alloc tagging:	120547 request/sec
> >> With:			116748 request/sec
> >>
> >> https://github.com/frevib/io_uring-echo-server
> >> https://github.com/haraldh/rust_echo_bench
> >>
> >> How's that look to you? Close enough? :)
> > 
> > Yes, this looks good (a bit too good).
> > 
> > I'm not that familiar with io_uring, Jens and Pavel should have a better idea
> > what and how to run (I know they've workarounded the kernel memory accounting
> > because of the performance in the past, this is why I suspect it might be an
> > issue here as well).
> 
> io_uring isn't alloc+free intensive on a per request basis anymore, it
> would not be a good benchmark if the goal is to check for regressions in
> that area.

Good to know. The benchmark is still a TCP benchmark though, so still useful.

Matthew suggested
  while true; do echo 1 >/tmp/foo; rm /tmp/foo; done

I ran that on tmpfs, and the numbers with and without alloc tagging were
statistically equal - there was a fair amount of variation, it wasn't a super
controlled test, anywhere from 38-41 seconds with 100000 iterations (and alloc
tagging was some of the faster runs).

But with memcg off, it ran in 32-33 seconds. We're piggybacking on the same
mechanism memcg uses for stashing per-object pointers, so it looks like that's
the bigger cost.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220902194839.xqzgsoowous72jkz%40moria.home.lan.
