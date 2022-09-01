Return-Path: <kasan-dev+bncBAABB64EYOMAMGQEGVWHOCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 609545A9A5C
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 16:32:28 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id ay27-20020a05600c1e1b00b003a5bff0df8dsf2843160wmb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 07:32:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662042748; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpWTU9hakSfG2focnyKj90B7T3QuovU4jB32lyHsYMQKR58QQ5OdV91Ua+Jltngsas
         3juvfziLjnKxv2fvtBrWB01tg2BHU9eZB3Gw7lgg3iIOtz8TmeXJhASrrunISjTxug3Y
         fdGT731sjGqeEVoGBT5Wr/Otxc9BFltVqvz5yJUB2rU/dHRAgol7RbWVM+RLRSNczMdn
         WuWh8LfqRMEuflvxuKcof8MbOaPA8/DlV/23ETXhF1LHlqbBwki/kbfuYTMkRd1E9wI0
         g3qhc5OITaY2kHpbD93LLi5PmZPvipZeHWgdwHcu3hb720spNNsRKG+Z9cM9/nA7ZD6i
         fDiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Vi67n3n3rl++TZ5cRNBa2fCQ1lRF6UQiTGihjPam9t4=;
        b=e4TqtPi9WhuOyB+6eO02KDDJpZQxRJF48EcI2CN2slkgEx0SLMKE6l3pS/rGb7JDs2
         kmPfN8It5Si3oqogqj49FrGxYJko+5uuz7EpW5j9Abq7GRNqXNFF+Sh9byvO0VXdLnti
         cfNs23sQlIBYovX/wIjhW9iKls6+iohJUFK28CKR6GnJxHcB7S34mVowO5Byr7u+0Ox0
         Kvrh8K+y7qDhbUbIqmS3SnrvDIlINgTmuC9Vleb/4pSUjFJDaiF3azzlxGZjLeOZKUA5
         uVJx/UHfAlJ5mrFRcqzK9mYVZxBJI6Kue9aB+G1TNlPpk/ChRzAns0Atylwl0juZ7aeM
         pcUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NZoXkZHK;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=Vi67n3n3rl++TZ5cRNBa2fCQ1lRF6UQiTGihjPam9t4=;
        b=i/eVOUnxUflAirwYMSB62R8BNtHOJO+OFmkECCYfdn+qCD3u3auSA5iduYuKhBskJn
         wja1OshZKCYjzKtgIq5egkyL/b95M3HOZa0dRjFUSW4wv994AMzyxOPI6dhcO/4QkNbF
         PPGPapxLVE9xtmov/pgSetvpfXln508624ASCWuyt4hZ5RN9ibSwoQLD2/kyi3AFVoxZ
         bbDh1dcjB9dUsarWF9pZVn8yOkPwJMOqgmLLvAWCoVJ+hID7+u+DDgiJgrGzBKFrIkbi
         B5Vpj8RKM2TxB3K3liqZrAtpibDbnSzVlaVrNI32dCQ86fGm8xncPyiose59xFz9OIt9
         C66w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Vi67n3n3rl++TZ5cRNBa2fCQ1lRF6UQiTGihjPam9t4=;
        b=jCRt8OVzrRC/wC3LOpd/xEqYXENTvNLh7MGplfCQoEVwFclvFQmRhOK4TSPgoWjZ+U
         wet9G7nxFQuEYESUClg/pqPBVTQ7TuqjMQlcvLGIcMcFPaSdZW+CtvyVWjN95kc7J8zX
         AuzIsmzwHfNhs7lc1ZuO+EJM1Cuh8MTcnHTe+Cqry6IH20RwN6f5KbeJr+8LAR90+OaU
         ZfdAmtelQBomVxLxTiCYv0VVsm6Ja4bBEV9fQqk/qx3naiJJagduWpYEbKehb5OC+tkU
         /EuexH1Y5WgUlugOR4bOjL3sBnV2YmlLjM7fjcC5FUJ6Vuh9oHjXjPZrIRYta7F3OGCp
         rudA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3yGcCaYwxMnnof35tKyYz5F3SxOB7odCnTtwyGBO15EhIeVeG3
	3HUdRUh14YMJomaaV8UaDlQ=
X-Google-Smtp-Source: AA6agR6eVUoYBQfd2hOhZtcqnaMe7QnRqdF9RIZjv4GDGSyI5IMbZmRqUlHf1XI1B0IOhFiexOLYeg==
X-Received: by 2002:adf:dd0e:0:b0:226:df82:dd5d with SMTP id a14-20020adfdd0e000000b00226df82dd5dmr9827673wrm.672.1662042748075;
        Thu, 01 Sep 2022 07:32:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c5:0:b0:3a5:24fe:28ff with SMTP id g5-20020a7bc4c5000000b003a524fe28ffls809645wmk.0.-pod-control-gmail;
 Thu, 01 Sep 2022 07:32:27 -0700 (PDT)
X-Received: by 2002:a7b:c046:0:b0:3a5:ff4e:5531 with SMTP id u6-20020a7bc046000000b003a5ff4e5531mr5387688wmc.104.1662042747379;
        Thu, 01 Sep 2022 07:32:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662042747; cv=none;
        d=google.com; s=arc-20160816;
        b=jOovmit2PE/xO2PlPW3NtZ1KGjSkj9LIiBgCfNFHz8qT3lu1Pt55/8nZ6kojA3IIqk
         ObHlxImGXYGGvUcyXhuqvrERtZ15J4Ti9pVqlqUV142HJ79WMqFYGOcPJUZjR+3JCjJm
         2cUARBHfxW9vFN6pESeMpzFGAD/Q6Todk/kCMFCaB7hB+Z0jqBEUfoQ9bSyShhRQW9jR
         LicNXXI0GR6xCSs6M/fUOTrdpwJdZ2FHGYamc1Qw4Yq3DAKpwGop1poJTsEKyPN+NxsX
         E+seZfS1ypWPFBZh+L3IFd5qggVbLiog0xfuMBqmsEOryqwfPhCALu+GpYDF2KTDLmmK
         R2bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=hzpqzF+cHXDydzBO/Ouha4xSMTzYETXF6uFA22HjvEI=;
        b=0f7GYDDEnUgahweI21zPNWuQe2/xBGe7tcNJPRa7nKdLnAKymeitPpPHRNwyKO6hXv
         NN8jnbIMx8zRwhdL37Wk8+mZX4YXv+HVIKnjLWrsbMqi/GKFxQBGpROdG9n9qHJBWL5f
         vNwZCGCp927H9MAJjElNxharJHQdbfqnch6phDwdOcd7qe6xfbvaQI+HZvS3GbPntt4s
         boYMhXtmWCLLgIPJ98NWbgBFjvT2rluZ5A0KcvgUCNlk+NzTNoUxBuSN01W56Q8YO9Hb
         RQq2vnkT+RELu3r5qSYgkL2P6W65P+s9jNgs70ROT7yDqJ3lQsPnVI2iRx6gTXZFc6DK
         dWpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NZoXkZHK;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si219200wms.0.2022.09.01.07.32.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 07:32:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
Date: Thu, 1 Sep 2022 10:32:19 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
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
Subject: Re: [RFC PATCH 03/30] Lazy percpu counters
Message-ID: <20220901143219.n7jg7cbp47agqnwn@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-4-surenb@google.com>
 <YxBWczNCbZbj+reQ@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxBWczNCbZbj+reQ@hirez.programming.kicks-ass.net>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NZoXkZHK;       spf=pass
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

On Thu, Sep 01, 2022 at 08:51:31AM +0200, Peter Zijlstra wrote:
> On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:
> > +static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
> > +{
> > +	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);
> 
> Realize that this is incorrect when used under a raw_spinlock_t.

Can you elaborate?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901143219.n7jg7cbp47agqnwn%40moria.home.lan.
