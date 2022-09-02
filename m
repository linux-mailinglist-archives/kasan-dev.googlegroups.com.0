Return-Path: <kasan-dev+bncBCX55RF23MIRBO5NYWMAMGQEW2KGHTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B1A35AA4D1
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 03:05:00 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id x7-20020a056512130700b00492c545b3cfsf173315lfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 18:05:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662080699; cv=pass;
        d=google.com; s=arc-20160816;
        b=RNag6G7LWai2NCw//JGZC2/uXvO0sgNDdK3w+bBGyKhfFnZtzISgDHlsWU1doPIgPv
         CUTr4IBa/8ygXIgWCzfIHabEj3+wTakY/55OXWyGJdkIB1pXErEmm6Nh26tb90hn9IL8
         WjGyT/xN3eX7iVfwow8lW9yjQLKYoPcEJ2Vd9/NgSSgBaIyXqjnabjpOjKXCIW256UmO
         vYOvRo4Ecx6+8xNRcrYa8ocHvfcIQrQo3Ww9yEejvxjny0JXiqmijpZ/mS6n0PQm3W/o
         28bl0Kq8eFmB4MGiqniFqG23r6Hmy3zRymptyDgulAVVPjAjnNyaog0PVfykDPDGaHxW
         vtIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MEs30+bJ66FldX6DrZqfhhO7zGXdchFSy0klvP97B4w=;
        b=cNb7nFw2O5eCksiChGSQr+i91ck4pZAtED0tmLfdjFKYQIPvEc2pNw8U2YlXVx18W2
         WzQwCLlhQYYU56IS7y7vZKSM71otxQ5s7s+Xio48GK1xba+j+7KVW68Il+r93qZg1Rn9
         4jWwO+TWRnm9ApGcQdepAogr+l7H/+UqRS6t11PQBUkR8BSbhxP6VtEqcU+8U7f1B1Aq
         lElDN5h+lrcR9/TOSN0Nsw4p5qlQKvqYeSRNpzPBzkg0POXe8XI0kLxK301TXTHrIBwZ
         pcbHJSl5X9oZVjyBNvtf/aNWZ5ev7BZ+e8LdE67OUyUpmaXkGrbhBs8/otGgjLSjsO97
         3Clw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tb82WN7u;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=MEs30+bJ66FldX6DrZqfhhO7zGXdchFSy0klvP97B4w=;
        b=fwm59lLdpwdh4SvCOPB1GTzkt/GIyy2mx93/4XCZqK896xkxl1jD7OU4gGRWG9zPln
         9bzS0bDoTQyOLktg+G5Y+KHxl8gBIuvYO+NAH+rQp91LCIQp74626u0hJjAve8pqcmj/
         fPRLAwLpSMygyC7Q3yCHfoAY2sWBc3NcQepSLhEnoQ7jCqthGxQHcPXueT87t5wf5KWH
         bFO/Z4qT5v2TY/+eQR3CZtkUA/3hpuoEKYZbaqMK9nkVmuoYbFpT3G0T5j0onZ7yBinH
         4sbXWbgE/Ru/vABSbZ6KSFXuHM6RkF96CECgi8bX9WKWINOC+WP+wWEh2MnqQ6r0gv78
         DCRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=MEs30+bJ66FldX6DrZqfhhO7zGXdchFSy0klvP97B4w=;
        b=7P/lz3SlakOoccjUZ+Tl0ZvsigNg83xOJHtcr83MBHnUk9AyWhkhE8W+aUzST5OqjT
         mBJTkxPRzc9uLavLah7m29MZmBxAi3uv3uWhjTrAK524aR426mgdITxWkonnah/thzp5
         Ygf79QF6my+egVyZ+1q0K2RJ9iaWERGw+orkiKnEgBGOwv0FEjNSsBewGi93EznrkVnk
         9sYr/BrOazGs9Sz6VipsecHmELMDWeLbrSzGRnsi7q3940ezMXO8uYgvaLKdVoAnjD/S
         AKA1H6aba1PBqguHG8rlyZWkHlMIfvKrkhNZi35kuVi1QowoaGhJjuEO/Wbj2uJ/+epN
         W0cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3jjZvssglFH9+Vgb4tsoNReQx9dIjty3nRjTkHQB8haGZ90V8L
	LoduqwBC7ED09wa6lwX1GuA=
X-Google-Smtp-Source: AA6agR4tHqNi4MEkW2bZi2iYciUO5hvrgI2EL4JOHUsuV4U1zALBtrkpZp7IC9+WdD5/YrPXpWU0Vw==
X-Received: by 2002:a05:651c:10ba:b0:266:ee76:26a9 with SMTP id k26-20020a05651c10ba00b00266ee7626a9mr4652373ljn.382.1662080699438;
        Thu, 01 Sep 2022 18:04:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls408100lfr.2.-pod-prod-gmail; Thu, 01 Sep
 2022 18:04:58 -0700 (PDT)
X-Received: by 2002:ac2:4314:0:b0:494:a300:fa95 with SMTP id l20-20020ac24314000000b00494a300fa95mr825832lfh.520.1662080698199;
        Thu, 01 Sep 2022 18:04:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662080698; cv=none;
        d=google.com; s=arc-20160816;
        b=JcXnahvd4Mo5dRDuVHRHSUY+7T5hJlqi2YnEf3/YtzPjNRoWDHz6chZ5VuRRsKJise
         h2gyXD6gHpnpaWrLJX52FpMYZpppnxAyUeQWA+VAWCXWhyrwxWEMIuin4AXr5eu7/MzU
         yFTknykahr1Bjx6JHMGVM8NBJD85yUjf1M4AHR2e0a4erpY7XAJEFO3aZnOoPxYlyZ1h
         Bs7laOMhgOAGGEPub7MHw+u1HIvoqeZYFBBsI3fnm9oRXvLiurDLQsrG/mxxqCl5B07E
         PsS7D1hBXkIz6oPKOSrNu6k8+rrL9DK/pSUSeyYxUdo7zfoNa0XN1AU5wNUJSs9Ubqy5
         77Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=oRI44dmgZNXvCbxbx0ytBb5MNkpf1qBSJsTY6pAYXVg=;
        b=DScBgAqyXVZFSGvjx1ywCHRdim8cqAObLHOgWxB3IKd5dskQjAwi3FOIUQLPhhgExN
         IkS20xpmfEbh/YPOfIfmxTHc1uFk5//n6AUF8UmJ0yEuvtbEPTnSAt9omTT69pbmzjJI
         EvHqOKJbITB3ISv2em8tQ+iRqgOAGaZHULsNiLOjHF+q6YA4IuMG5RK0kdeJJ2lifOyY
         NfQbkKh3UM+425dWhJLYdj7Qlm1UojkvWhn0F+06EmbNQmAlePPo2moLdIbZH752fnen
         DFXY6x7oSvG4dyXZxuBTU8reA3aqA8PvUPk3y7wWnYlcJ9G01k8kiRHoULwwWim9cUHj
         9ZRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tb82WN7u;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id h3-20020a2ea483000000b002689a3549f7si35796lji.0.2022.09.01.18.04.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 18:04:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Thu, 1 Sep 2022 18:04:46 -0700
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
Message-ID: <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
References: <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tb82WN7u;       spf=pass
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

On Thu, Sep 01, 2022 at 08:17:47PM -0400, Kent Overstreet wrote:
> On Thu, Sep 01, 2022 at 03:53:57PM -0700, Roman Gushchin wrote:
> > I'd suggest to run something like iperf on a fast hardware. And maybe some
> > io_uring stuff too. These are two places which were historically most sensitive
> > to the (kernel) memory accounting speed.
> 
> I'm getting wildly inconsistent results with iperf.
> 
> io_uring-echo-server and rust_echo_bench gets me:
> Benchmarking: 127.0.0.1:12345
> 50 clients, running 512 bytes, 60 sec.
> 
> Without alloc tagging:	120547 request/sec
> With:			116748 request/sec
> 
> https://github.com/frevib/io_uring-echo-server
> https://github.com/haraldh/rust_echo_bench
> 
> How's that look to you? Close enough? :)

Yes, this looks good (a bit too good).

I'm not that familiar with io_uring, Jens and Pavel should have a better idea
what and how to run (I know they've workarounded the kernel memory accounting
because of the performance in the past, this is why I suspect it might be an
issue here as well).

This is a recent optimization on the networking side:
https://lore.kernel.org/linux-mm/20220825000506.239406-1-shakeelb@google.com/

Maybe you can try to repeat this experiment.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxFWrka%2BWx0FfLXU%40P9FQF9L96D.lan.
