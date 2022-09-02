Return-Path: <kasan-dev+bncBAABBAFTYWMAMGQEJNYNOTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D1935AA4E3
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 03:16:54 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id j36-20020a05600c1c2400b003a540d88677sf366985wms.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 18:16:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662081409; cv=pass;
        d=google.com; s=arc-20160816;
        b=mUkwv0KkfV5fh2Nd8S/QKP09itWRdcM9L7Xc9zlR5gubCRJH1hTXXYH5jdLrchTZsC
         9a/g19b4Itaqj++ROFt/Tz4xg5XwLfa/0zGKYRqkTSLb8LKIwW1UuzIEs7qm7dv04Ioa
         gLQLQRJO8fsVf0Ck9pMEuH7wDye/PjU69hzU57efeGTehdqJh7SAXt6mLj3fgMKApM+2
         wTioHOoDz2vm7oq3j5X7Fjuzv79TYnJ5mcntGw9jaDh+gga+OA9ayiuKgqsiBzCnEXeq
         yVJtdygibJEMz0TxS73GEM4a7y0SYVUgFqDlAtwvfXQ/VGQxc/B43ngdurEI5Og5jj+M
         AcQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+ViIKGW3BhpfisIQNfzjoPlqrNrSKSi0MWElkZxeo4Y=;
        b=OguSza0E9GTeebmptDLeP5hjcGRmUtVGn/CeLWmW/RT8OZs0edeQMavEtlYtCTdMiN
         bxhTsIvZxRLJ+jFB6K6D/lrrdcrSxQon6a+UdemWiR23pH14lS6Uhwurq7QaGcv5oeY6
         i87gxQpjJVguibcHk4j3gAM2lPYx7di5vkhY/LQPmpvZsROFVW92Z297g84KIh/bkFVR
         ptV8cVPBHM7UlIqmyzI4WgQywo7xFBvaAgst+lkWeEOsRxOZWU7eNPHzTNkMd6oGQOHN
         w6JNscRZw3XcWX9h1L5b1Fz04wDjM5zYNEo5iULSQZ8R7FW5koTh4FMBLU9wy9/9/BUZ
         UswQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xsMsILmj;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=+ViIKGW3BhpfisIQNfzjoPlqrNrSKSi0MWElkZxeo4Y=;
        b=shnUURjI0vBPwb/fLs0KmONRZGqgcFUghrX1mriz1jAg7ooxXK2IlD8WhMssr2FIpP
         lkvFnGb9uKb86mDWitmusGXxM90kqJWvP77otaO0HNCj7JOAgN4b1i1skaafHLvvko4u
         y1QysfNunZmzn2ja/fRMbKyLPi1p7bpvDavhGiqb+UqXWW6SexK2MfxJkvYQ/Gr2vgtQ
         d/mSkV3Tm5Y7re57PkkHytLXCubXcZT5bygaAfL1/ha6TplBntBFseWY1s7DYPnSim5m
         NsoHUkP7iPS1ElVKpvRYLoeQyiOWeUCKoyvfB6BoONWYCje9QBtSRNIt61uWedl83Tx9
         FVpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=+ViIKGW3BhpfisIQNfzjoPlqrNrSKSi0MWElkZxeo4Y=;
        b=GLi8przhss5k3IN6JQ0tTbhGLG/ZL3NJtPhFK5rKyPV76Je4HUR7R8cfy9sk8FeyM3
         cdLXctrQ9W/97wa/z8Ki43D71E4obtAm42LGw3eUvix19pWqjoPSJ2aIcvAWIlkzVCCl
         YZAFwutoHNP8QG745JKvlGFpDvpCOVGs/D0NPKScVuZuFrqbRi0ZOR8zM/nmbYe89jrd
         AgrBOnI9cCsHDTcTBlDJOshIlYXwBQ7/aHGcjBAuJBsKG4YADoxrCEXpjG6KK6bUUMp8
         ofqHrvwRBypmguXDZPwY69BQ1h1bzRkfCvb1aNOC2DW2e5pE3GupC+StuITzeP88RD9M
         inEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2OW0stX5cd3OSsgNh2Ygzjk/K2KpTcP7Nj1tHFbJU8eGB3M/Ke
	Ggr4C7H7x6Cb3Ebz5dT8ggc=
X-Google-Smtp-Source: AA6agR7Lf11Mkg3oW0MszCtIBPsmhu7DlUqrGcjsdnsxbW51DW2IJFH4eWvfSe3wQLxGR0URfaGTFw==
X-Received: by 2002:a05:600c:4e8b:b0:3a5:f5bf:9c5a with SMTP id f11-20020a05600c4e8b00b003a5f5bf9c5amr1037074wmq.85.1662081409041;
        Thu, 01 Sep 2022 18:16:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:721a:0:b0:3a5:4532:b3a6 with SMTP id n26-20020a1c721a000000b003a54532b3a6ls1246432wmc.3.-pod-control-gmail;
 Thu, 01 Sep 2022 18:16:48 -0700 (PDT)
X-Received: by 2002:a1c:6a0a:0:b0:3a5:bcad:f2cc with SMTP id f10-20020a1c6a0a000000b003a5bcadf2ccmr1043791wmc.74.1662081408312;
        Thu, 01 Sep 2022 18:16:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662081408; cv=none;
        d=google.com; s=arc-20160816;
        b=dU/O+aMQFJUpIzn7RrnTQA1GGal2KwUoF3ZwMCWFTHK2vXjQWsHebfeb9Ne7pJMCa0
         fR75wzNBfmNwI0U/77TQf1NrVKDGfIudonGne5RMXRHoGIrYnCfW6ApLmFZJeTiFQbDG
         P1Tkl1uCgOgOU6jGlzrVwk8erRCsDTyZihJqIyxPb/XvaJ/BWp12aa8pIO8a5RUl5DjX
         PAp1TtKGOLUo3C582YMyo885BqDlguNHyv7X8ccZvMe/6YB24CE9Efc3WT7N47EZxBI0
         +rk2bvbbylNNyeyQ7gPnFzUahuKFGjivsQB202LxbyP7RVRphem92zKGIbnj4Hksivei
         GpDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=+xwXm91t+47a+o+KD4FaRYzGqxlSaFanxZJX5xkrYrg=;
        b=lNo2Nl5GqNIONmbxCcTqd97yysjc7aE6mJlmai8ociLBMGUN/KL5ax+xyD9wLUgBNn
         8nTxPzUVo6i1+7uLHkZsn69IQKZA9a+TqWzdlilI1fEwSujowqFNGAm2h2w2K2hqcz0y
         gQOn5w1vvISKGZ8eJ70gwslm70M73f3/GFQu9FuoGx+umxFmZc6lTlynbhi9H7mIpD5c
         5Q9vReZgNhhHnSdg7CG7z6K5/pTS2aIpwAOVeTroRKykn9qTfc4f7yu4I1+Fl8vWN0J1
         Imbbw+qceiNJcSvYXslK0eirOubm0qkDsDex5hVb0+nKZDTbFEZh9rmKq1ijFVW5lHOh
         oUCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xsMsILmj;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id y18-20020a05600c365200b003a5ce2af2c7si31436wmq.1.2022.09.01.18.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 18:16:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Thu, 1 Sep 2022 21:16:34 -0400
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
Message-ID: <20220902011634.6yfeujhzopepspm4@moria.home.lan>
References: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
 <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xsMsILmj;       spf=pass
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

On Thu, Sep 01, 2022 at 06:04:46PM -0700, Roman Gushchin wrote:
> On Thu, Sep 01, 2022 at 08:17:47PM -0400, Kent Overstreet wrote:
> > On Thu, Sep 01, 2022 at 03:53:57PM -0700, Roman Gushchin wrote:
> > > I'd suggest to run something like iperf on a fast hardware. And maybe some
> > > io_uring stuff too. These are two places which were historically most sensitive
> > > to the (kernel) memory accounting speed.
> > 
> > I'm getting wildly inconsistent results with iperf.
> > 
> > io_uring-echo-server and rust_echo_bench gets me:
> > Benchmarking: 127.0.0.1:12345
> > 50 clients, running 512 bytes, 60 sec.
> > 
> > Without alloc tagging:	120547 request/sec
> > With:			116748 request/sec
> > 
> > https://github.com/frevib/io_uring-echo-server
> > https://github.com/haraldh/rust_echo_bench
> > 
> > How's that look to you? Close enough? :)
> 
> Yes, this looks good (a bit too good).

Eh, I was hoping for better :)

> I'm not that familiar with io_uring, Jens and Pavel should have a better idea
> what and how to run (I know they've workarounded the kernel memory accounting
> because of the performance in the past, this is why I suspect it might be an
> issue here as well).
> 
> This is a recent optimization on the networking side:
> https://lore.kernel.org/linux-mm/20220825000506.239406-1-shakeelb@google.com/
> 
> Maybe you can try to repeat this experiment.

I'd be more interested in a synthetic benchmark, if you know of any.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220902011634.6yfeujhzopepspm4%40moria.home.lan.
