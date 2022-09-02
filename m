Return-Path: <kasan-dev+bncBAABBLGEZGMAMGQET5OU2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3813D5AB924
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 22:06:05 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id q10-20020a1ce90a000000b003a60123678asf966981wmc.6
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Sep 2022 13:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662149164; cv=pass;
        d=google.com; s=arc-20160816;
        b=nRmuDlCu7cfQma5SGFv2tSlnSHP0RAO2pinsEFBCHP2JS/+cT2/wLbBFBkOt8BqHCA
         hYAJPiDJG2xKFf1d8VinEsFUcUt9pdb91svlaV3IKeNibgBmgQDzNIc9ObEt91q0xdsT
         L/GzFdVjhtCrEuGqunWLrqNfLRgAu9KKRirCYXTEPeca7OA7JqXBX9NB1BXYW4UIChpJ
         uivfcgyv2w1aVF6IOZYDEq+2J4q0Ji9kSqqZsND3R5IOkSFo9zMgI/1f80iCHV39Lb7/
         RWOf9RclEORUwp1/ZviVP8vYBNjws2jEVAOlM0yz4u/vIPusb/VSM0mRj6To6u0l2H7g
         51sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=L94PG54eOMjCUZDul71APHwdAtnUssYSwi+qPvXN04s=;
        b=P9H/7srkOLSR+vkiTEj7Hy2PiMaw7A0MHjIw5WBi6CEu7b/ohbVGsBKFAa4BK43Hsa
         EDlnOEfatp2mPGLwg1CNFdCEJTrg7qIkdpzpOxrv2M4Do4gnMMVX4qqWusJsqahZkBCE
         51N4vp06ZOJtxM3XGtoFJeteDUBzUL2RB2NHkmwYdqAAqyDQlVaVk5WnVTpq9kqCbglp
         3cOFkqtHo3CaiaUA0tTVxgwfVjL+3BEUHH4PBgLgNVlua4UJNPE93vrGrQUCtB6c7yoN
         vOS5GPFmoVBTVVqizMf6h75b8Jut0e8E+D+EH2ooTx5u+oBddi58d345DeMpl8I1WARZ
         urOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DkqxrENv;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=L94PG54eOMjCUZDul71APHwdAtnUssYSwi+qPvXN04s=;
        b=A77uqgk10zoHiO9RRQzt249X/Br2CW/6CE33si4MIaVS2QqH1PAVFoEn27ZzyxDqEv
         gwdqbpwl9jBHV6n6f4HN5J5WSvNeWTB+VA4WNvztJppErbV09HVq7eL2dBURWZ1rdx55
         2gCWj7RKqcHDxsdGYgHDFnN4ZuWCRdU77/ar7FltKXJw3jP4cwsdFhcmtgRZWElGzXJ4
         Jj9Ef8GoWSB6DGVqTBicVM+lFR++r+rJZKs7VB751S1rs0NSVVK6zvxcO2EMXL3Z65me
         SfqY65qSomqBdnE1PSt0nXnOLnGfEeTE/1Jf0YQ+xFDxwTAwEsKTvWGRDMjJeZa3JaNr
         59zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=L94PG54eOMjCUZDul71APHwdAtnUssYSwi+qPvXN04s=;
        b=43ZrbMKTW3Ws1X6Gag84hXZXs0CENytCoTU2i9MC1+MNl7xqs7Ok114RxY2xFT4SBv
         W3DyFOPnp5h8Qlpsev7KBbyPnXphm8+2ENz8d8XI9AqXuCT0WNDbVJgjN8KkTVGV4yyv
         WV3Ivm1knRv/H6Hwklob5j87sd6va1R1/8nq592eoARDJtvfSoUrY9fmm03838juGkJg
         iEwB75Wo1w8yK8DD4oNprcSbF8Y6T9Lzhhe4YcWlKr78EZgBmIwkL5V5sxS32M59lzzw
         ctmdmT+iy8S8wimUyVciXXiv4YNcnKwvpfI8zY3Z7NCmDF0FmT22pLOy5fw8MzReAf3N
         UwDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2J0IFLaTC4wOhMhXue4rlhPN0RYUtKNHLYJIx2400nP6QJo5iY
	y0m4/iqmsAnNCA1BrzI0LUI=
X-Google-Smtp-Source: AA6agR5fPTbDrD2pFMHQUtBMBdaAmtrdIQQyaxQD2wWPMsXuZ4SZQcJjZBycn09dAl509QnsjyFBsA==
X-Received: by 2002:a05:6000:18a1:b0:222:c477:e919 with SMTP id b1-20020a05600018a100b00222c477e919mr18651158wri.301.1662149164774;
        Fri, 02 Sep 2022 13:06:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:247:b0:221:24a2:5cf with SMTP id
 m7-20020a056000024700b0022124a205cfls8963716wrz.0.-pod-prod-gmail; Fri, 02
 Sep 2022 13:06:04 -0700 (PDT)
X-Received: by 2002:a5d:588a:0:b0:228:462f:a49 with SMTP id n10-20020a5d588a000000b00228462f0a49mr2505053wrf.616.1662149163999;
        Fri, 02 Sep 2022 13:06:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662149163; cv=none;
        d=google.com; s=arc-20160816;
        b=s7hDaTR7GuMcNEOcj8gHA36Fj4mIb7oMPnlGW+deD/hPNzDXC1/xCjwMRWXXfXP+i1
         uW+1hI+exXpzAg+oRDgBvQoht0BpUnj7W0PQJanhtNrxgaGbY9mSoGYQP0unQ+3UF2k5
         GBZrBhnYQJ5x8pS8WbSjT0wooo+BuSCD3J/zqm10yFs5L535yoh6OfrzUx7rUMan2fYT
         wu8d4FztHLoI9eRCPj8qjNoqr/BGyTW1wtI9Gjc733afwjkjewHhHONmQ04T8e7oo+vp
         bmtPQklB9wlcHdo+sCA9mNzXS2oDtEFsAPGTBb3nEDrhjufadxWLBDBMAYH5C0g3+hQJ
         OSBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=SemCjjx9bqrqhFAABAkUIroCfCc94PYvIF1DVQSZFl4=;
        b=0g/u5owv5Dv0GEZ2XUiavAwGIlely7CRLQigyRK6Y/4Ib953bgpwf+fFzct0Ndcyjt
         j75UjPtCbIgEqHcLPsm7H0wAHAKEA2GC/fTjcsotzMwEStS2EUTOSHMm6L2ox30BWCRR
         6GQywUSp54+IWd77cZKizkVCU1fgJWobzhBnje5EE0Z/PvEOj4GBsKJVDqSwuXVFvh95
         0hRFqvk8X9KEHAZPTN0MAe18YJ/BscfjxTSIYGlVjvARgLN5MKpspQpVnfyrTaO4W94J
         W7lrAcePa0kz7L1BzT6QHg9AjKLSWaDbdi/SVLUN8Terfw3B6VJZLdZUyy9FP4YAda5V
         04eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DkqxrENv;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id bn15-20020a056000060f00b0022560048d34si126940wrb.3.2022.09.02.13.06.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Sep 2022 13:06:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
Date: Fri, 2 Sep 2022 16:05:55 -0400
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
Message-ID: <20220902200555.h5fyamst6lyamjnw@moria.home.lan>
References: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
 <YxExz+c1k3nbQMh4@P9FQF9L96D.corp.robot.car>
 <20220901223720.e4gudprscjtwltif@moria.home.lan>
 <YxE4BXw5i+BkxxD8@P9FQF9L96D.corp.robot.car>
 <20220902001747.qqsv2lzkuycffuqe@moria.home.lan>
 <YxFWrka+Wx0FfLXU@P9FQF9L96D.lan>
 <3a41b9fc-05f1-3f56-ecd0-70b9a2912a31@kernel.dk>
 <20220902194839.xqzgsoowous72jkz@moria.home.lan>
 <d5526090-0380-a586-40e1-7b3bb6fe6fb8@kernel.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d5526090-0380-a586-40e1-7b3bb6fe6fb8@kernel.dk>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DkqxrENv;       spf=pass
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

On Fri, Sep 02, 2022 at 01:53:53PM -0600, Jens Axboe wrote:
> I've complained about memcg accounting before, the slowness of it is why
> io_uring works around it by caching. Anything we account we try NOT do
> in the fast path because of it, the slowdown is considerable.

I'm with you on that, it definitely raises an eyebrow.

> You care about efficiency now? I thought that was relegated to
> irrelevant 10M IOPS cases.

I always did, it's just not the only thing I care about.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220902200555.h5fyamst6lyamjnw%40moria.home.lan.
