Return-Path: <kasan-dev+bncBAABBM4XYWMAMGQESROW7KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B7CAE5AA428
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 02:17:56 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id b16-20020a05600c4e1000b003a5a47762c3sf278497wmq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 17:17:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662077876; cv=pass;
        d=google.com; s=arc-20160816;
        b=z2SJx/Jee7uxyDM3Oi1I3x1G7DrmSGVg1oH63On38aEb0rirVKZ9v4QZCZpISYzpJj
         FBQbn3AejbfhcOEwOmqn/2lM3u10xvc9ZY3lzarqiQiR2H9fo/p9ZLOUBm4TKjkMNxvs
         fvhv2LOXXb0LA4OtrUmFiwlC40Ow6wjxDGBVzLkC5KqSANJ6Y6mw/OFYTw0mR+ysiBYP
         +c7eptSsbMllc+hrvLyZcpWQSEUlAgtyRQ9SQnej9C95lbFH4PwElMGq/pgYg3q9A7VG
         l4VTMuevic2bqWUBYy6BMJkGsLC4yb+lfIUjZpUoXtn4dfT1ytqbnbDkA6WvsMPDm6PC
         I8kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wUV/6hDfDAmO8z45RaVEExHGXgQdl75bEzlOzjL934g=;
        b=pr6vI4KpJuycwCbpslXEgy9OSX7xfrpEoO1qGK/Jm1ehr7IB21ISxSQDh3RisuWwlY
         8Y/O6EQ3db8VubmOzhntW/8uadxRWLi/pdNUCKC8xTmChzqFpTpkTGc/sKxQ5U1O+Oej
         BRwnsqoj2KkPP80Wo5aOsIlBQQtCWruef4UxKgUO1+Qw3YReoZRpb6jTAEidi6ivNskK
         NwgEq0NLv1qR+cflxHDNz6G1sEbBLNmtWMEcNA+CKP55h5xD53e+HVxsP+cdB5/GHwI9
         uP6Vu2dMoqwEOW7RU7Wjm+uh580xJ3RjdDT6VkrfKogmdSB/PwqBborBL0WVRsavgLTl
         pVOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vjeyKYOO;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=wUV/6hDfDAmO8z45RaVEExHGXgQdl75bEzlOzjL934g=;
        b=TbrxyEQCrmVExhoH70pDLcLEPma/JwoGvMUvWk+bYxeY789lC9rdI3qTUIKCNct2Zj
         ipJXcu+JWyUHz10UhqWI5gTXPOTQnpWFIjIjinPFkDrZgmK9981c2uv8EcV/9PA9Fhb8
         rZ+iGknZnfhHk3R9pfG1yqi8fUHsfisoTnRHJJ9upyCN7CSxZMZl7sv/c2kp3GuoJJUh
         WkavOQ5c1ybzvw1SYGzLxa2QSJ6bMetPkIv6SgtZtqU1DdG0UXo89R14+X3RuPm8KXtP
         delDNmPkosT9RgZR5lY5nUIYqxL+mombQXYGXnxqo1PVrFP5fHzBKsnor5M356+6K2c+
         TbLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=wUV/6hDfDAmO8z45RaVEExHGXgQdl75bEzlOzjL934g=;
        b=xRJ2ZIwo2tRd39lHol41bPWCws0z0tk+qWoNcAnbbUEq4f0vPceTlAOioTnephVZ8c
         Sk8m+4Z5oBHSwj/YfiTEw+2ERiA/jY2f+EinLXCV58md1b5JbiVGBXU0Pf2IGk61xA10
         HBPAzq+hC6rHBTb3mGphNiDdgVQudxC6gHUqymS5QEROXadr4UFkVfoaYKMyBebfHaan
         FiboHxEmPsOSYFc788QozmvJ/ABmc9QiWfYfTKO60pjn3AdhwN9XRzF+Fy0WJLXIbq20
         D4hC0K5vOnfwvEc6ycGbYpDWyW9HX2294UaPvX8WfFZ88V9ybF9TBv1ToNOcD324c/MW
         ZmGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0s43LKYCCvOromlh863xk/bPTj/ax0kPenfAJUqxiY9KMSZDwF
	3GmEXE1l7OBq/pUjsrlusVM=
X-Google-Smtp-Source: AA6agR4BYVXXocG5nO+wjd+BbQX9uxswv0xzJZcs51ul7zbMS4wAC8UMW8mdw3cLV/85TQsfTnZnSQ==
X-Received: by 2002:a1c:241:0:b0:3a6:655c:391b with SMTP id 62-20020a1c0241000000b003a6655c391bmr907858wmc.67.1662077876202;
        Thu, 01 Sep 2022 17:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6018:b0:3a8:3c9f:7e90 with SMTP id
 az24-20020a05600c601800b003a83c9f7e90ls2181601wmb.1.-pod-canary-gmail; Thu,
 01 Sep 2022 17:17:55 -0700 (PDT)
X-Received: by 2002:a05:600c:1e88:b0:3a6:2ca2:e34f with SMTP id be8-20020a05600c1e8800b003a62ca2e34fmr958078wmb.146.1662077875410;
        Thu, 01 Sep 2022 17:17:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662077875; cv=none;
        d=google.com; s=arc-20160816;
        b=zTfQhFlK7PlHzYt03BZVd4MR9HndsyG3eCe7An46ZZzqddiuv8zPTi5XF1s9OutRwz
         Gxkbhr0R0LlZG1ijksDNO0p5PVydnqpgGJt+AHGi+suztEUBYnqJbaBf2we5uOp2p0y4
         fgXiuLjEu57sGlC6mnWnPxSazDXJXZHM4Vr4J75qhmAFzslTaoHZE6vIP5nE4TuvUetU
         ELBGzbLBk8nnX7JZ324EsiW3DkFV8KfoDaLjkjuyW8IB/xRlYppgXvHTVsCJooXYmkOu
         0Hs9kgb+wH5jFkHBFP3VO4OjZAvMfdNOKvK/M6iJP56rd8j0xTSV/co6/NS3sAaW5dg2
         WWQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=sH0J8UqLRGNNuqRGsl3/vKnq+Ig43rrwpYa6HCIFafY=;
        b=YNmeTU4W7vrLz6ZTQwptmzEC+UCkrg30sa01n38pxSXqlUBInSSrO81PK7e03A0m4Y
         lkUGFF5joE17aA1h74n8hE+Qb0qFo+WZjGtwfBPzSlMkKRcPAkqXzTWXE7TZwqDAPgmb
         bursO6Np6GFtuCu9Bl43tk6J2sdbfL+7K+J3caotpBy2d1Ku8vVPo3BZruvTx1vPMO6m
         eSRK0ryxYMy/Sh9vmKzEehBUVBmtf4OZNQ0lBjaAxpSAjQqVinGe6g5EBDZMmmmHrI1F
         w+62TM2i3o4Tpu4Gcb6MYZfAnHHE4i4CmTunKOhN/MZ7oJIkY8f1KM/Of26UTBf1Ubs1
         5ucw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vjeyKYOO;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id n186-20020a1c27c3000000b003a49e4e7e14si559227wmn.0.2022.09.01.17.17.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 17:17:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
Date: Thu, 1 Sep 2022 20:17:47 -0400
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
Message-ID: <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vjeyKYOO;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204
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

On Thu, Sep 01, 2022 at 03:53:57PM -0700, Roman Gushchin wrote:
> I'd suggest to run something like iperf on a fast hardware. And maybe some
> io_uring stuff too. These are two places which were historically most sensitive
> to the (kernel) memory accounting speed.

I'm getting wildly inconsistent results with iperf.

io_uring-echo-server and rust_echo_bench gets me:
Benchmarking: 127.0.0.1:12345
50 clients, running 512 bytes, 60 sec.

Without alloc tagging:	120547 request/sec
With:			116748 request/sec

https://github.com/frevib/io_uring-echo-server
https://github.com/haraldh/rust_echo_bench

How's that look to you? Close enough? :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220902001747.qqsv2lzkuycffuqe%40moria.home.lan.
