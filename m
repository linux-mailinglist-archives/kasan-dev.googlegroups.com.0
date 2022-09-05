Return-Path: <kasan-dev+bncBAABBJ4V3KMAMGQERX7I44Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C30705ADBF0
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 01:47:51 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id c64-20020a1c3543000000b003a61987ffb3sf5814190wma.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 16:47:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662421671; cv=pass;
        d=google.com; s=arc-20160816;
        b=YWD/GO/CZS/5KoCO/7fwHK98E+IK/6NTYoOipTkmdldO6NL/f4/1yjekKtmZe3ZEHc
         EsiCwJc3cVKJC6DokANO9GVzLWhhp5QGPI/TpiLQ/Qv+3vgOIJP7NzsZICTut2G0Zevx
         23eO/LFup3lL5d5PybM2mFd9zY7Wxto2i0/3iivNs7sCo12UHMR54hQg5uR6o4zwvzT5
         YhRTKcDFQu2TyZ1v2xTNNFNUVlRBE/CXbTS6Neo0bFP/vNLHUrBY7Sx//2hT4SONdp6d
         h6DeYrtX3DqrV32i2/GaOSLC1ZmmoBl7hcmc+Ad8n5gXcboKBuulRQNjtiIGfUlhS8j+
         iBhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YXRUg2ZM/gq1n1JqZJSXihQ++EuEm713YmHRv6bnhQU=;
        b=TD+aL2rM3Tp31V0mraB+yDHBbfm2rlP9aoq7gJTYCxDyjJjIDJdj5So2jCbvg34pwL
         koyft3WlIC6tr6zxqYceYcuSiPo0H8Zqqg/dSpghCdicH3qPhnWZcw4Bm8Z/XA47zQqR
         tqf+KnsI1t+++KfwvuqwLXZVOmdkcpVO6kNJYdpsnZXfUPrnlhDMnDJmtteGKtnFSJ4s
         axqokne0x1PkCs7Iocf/o6h2t2Wkq5fiEDem+1D65GhrZD/eGVDf5QRO0VMhUtl2yFSZ
         g3uOjhlhEYp4jMxuJ2+XVvBt4DliZLnGCMN/zeE3GOfoN+nAVGO5pxAkl67qt0NAdRBR
         H+fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="g/enLV1J";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=YXRUg2ZM/gq1n1JqZJSXihQ++EuEm713YmHRv6bnhQU=;
        b=L7GDYeyDOhIz1QrP0agYLbIelFZa4VzLETPFtC0oUdT35vvBMQ7RkGjOL5DdOGw138
         2hVWw95ubj3ck+4pLNT/2LSHTLNZp4YYE1D5EOkZY1HFqyfhQaqic134sgUMqxl8RaP4
         J0WhAZXGZWCwlwoI+fgTFgZZ/l683RCCGLBX5XYSXA3suDeQM8Yyjg0/7Heb13jeOR4P
         /s4np/nacPmLTXc9/3Y9bRertdFkbeFG4HnGa4+nNz2h11MiMwG/cxkr+xKi08xvUy8l
         uvaiYvhWjUOSErPuB7U4LQP7AwaBGiuQstDdQPd6wtWjghEYGP2Kv8bk0PLW7Mc8NYaV
         6nlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=YXRUg2ZM/gq1n1JqZJSXihQ++EuEm713YmHRv6bnhQU=;
        b=a+0eXBe98KvZ/iS5AtW1LM+cN2DHp31ISQB771UWP7nSuXDbrDy/he1fTxO8pgZ1Eg
         e9XL00JNc5vdTjgPuyh1EsZnL90FEQpz49UzeSbkukPoGpTIDGPBKqaLZZDrPWcETL+U
         Vd/8jb1bY93ZvBZVJVqCYxTx3/bdHvnlzVXz9F6UHKj7XeHiwrWQKi2DvEZLcj+ErmTg
         7VbENmrjz81AbpqXghnadk884tpYSS62u1W5VlEeALyH1sztLSqxW0kGGgEI5SSGUjin
         dsttaLLhsCuZWu00rBExphtoe8YegqX4/yV9Bs3Yf8iLnKH3vdv8knBPlrt8rrwaODU0
         oraA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1Y7eIqZ7H7bTIqu3osahP7ToZ4BXrf4Soq6YpTUQ/gY7hnm64R
	I9JdjNYbRocbXPQFmFdNpzQ=
X-Google-Smtp-Source: AA6agR52Y7T5BRHnYSLAx2YfTSXSEjW+zQJvO/zulH5EeUX1ZCFeVfRGL0e+lfKu7iJi30pHkxDLxw==
X-Received: by 2002:a05:600c:34c5:b0:3a5:f6e5:1cb4 with SMTP id d5-20020a05600c34c500b003a5f6e51cb4mr12211618wmq.71.1662421671457;
        Mon, 05 Sep 2022 16:47:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:220b:b0:3a8:583c:54ed with SMTP id
 z11-20020a05600c220b00b003a8583c54edls4204727wml.2.-pod-prod-gmail; Mon, 05
 Sep 2022 16:47:50 -0700 (PDT)
X-Received: by 2002:a1c:f217:0:b0:3a6:61f2:a9c2 with SMTP id s23-20020a1cf217000000b003a661f2a9c2mr12021797wmc.88.1662421670687;
        Mon, 05 Sep 2022 16:47:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662421670; cv=none;
        d=google.com; s=arc-20160816;
        b=DFKNcRVqooNBOzvXsStf2uZxeoioTFyOwcLghhFc93ovUYrtEvJaFreSpM/VaMHCML
         OW3fULrNHUFEiB+RLfxXw5VQjUruJ1UGfAOS6pPdik18yoz/TEwT/KaNmIPrJQVdvCA9
         /fwOg1jYXT0emwu1Ju866x+Dh/LDq/DX7WEDVxs5u3oHxrNz5i5a9iPOR6bZwt5OgwwY
         TV5Ld9QPxZdPd8TvtdFJMC/BbDJy7Vsm+6lJC1YHO60ocEMkkmbDH93YYf4slmHDlAdk
         SPxa3GdaPkCU962Ck2rY/ZPEf+PpSLbxiT3LFC2R0/KnmSsdg8NtODUUooD/1STzomGP
         b2dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=aV58+8xM7vZiC+ARHrNwrMa2NOiuYoscS5I3pyUTgBc=;
        b=Jq8gKSbP9+ZirPiv6lSoKa+TqEIcc+28Ae1Yb/u30m+UOFKEJ+NppOoikC475ZcUZp
         vsQBunWqpZInePyBMX3RpWZhDg5eucC67mbNyzlbBEubq9X+yXv34rwR7Et7kJbAUGO2
         3Duks7gt4Yq25KYIEgjG9p57PA6hTkeCXdXXf9sbEg0oc9QxjYbJD2bgihUHn3MsPRor
         C9GD3pQJcI1WPhDyH0R0382qYTIANSEGKFV5M5PJLrN5N5A4ltkqm+uLnI/J7FnYUgBC
         rjuwV7u/rmV73ZJG4Xol2JqJeJwkLpcSoIwPA7L3A/2Zz4EeIi/ylYj0nBmKMHBLR975
         Gi8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="g/enLV1J";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id n20-20020a05600c501400b003a5b20f80f5si916018wmr.1.2022.09.05.16.47.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 16:47:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
Date: Mon, 5 Sep 2022 19:46:49 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220905234649.525vorzx27ybypsn@kmo-framework>
References: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="g/enLV1J";       spf=pass
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

On Mon, Sep 05, 2022 at 10:49:38AM +0200, Michal Hocko wrote:
> This is really my main concern about this whole work. Not only it adds a
> considerable maintenance burden to the core MM because

[citation needed]

> it adds on top of
> our existing allocator layers complexity but it would need to spread beyond
> MM to be useful because it is usually outside of MM where leaks happen.

If you want the tracking to happen at a different level of the call stack, just
call _kmalloc() directly and call alloc_tag_add()/sub() yourself.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905234649.525vorzx27ybypsn%40kmo-framework.
