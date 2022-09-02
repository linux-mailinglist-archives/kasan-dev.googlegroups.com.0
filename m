Return-Path: <kasan-dev+bncBAABB3F3YWMAMGQE5Z3UY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id DB7A35AA523
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 03:35:40 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id h6-20020aa7de06000000b004483647900fsf406738edv.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 18:35:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662082540; cv=pass;
        d=google.com; s=arc-20160816;
        b=W9ESi/p3ycC9s5px14ifJvWjCvrpVu/evSMEVPeYb3yzaQiUx6ut2zZh4TnPoXtvVG
         S137CaQAHPlenj0XSYQdpsbXTkHrzOsUONQU0H/yWcWQ8So2HSfGK8ue+1HajIdXp/Lo
         9cO+FwkMiepkCa6HWsy0pt9WSjgL216ZKgjgvvFVbX7myppgCOjapc6rofkY/01dtJvL
         /Z0ByvwiCBpfIKutufAg+rRMLqttQaBvVXj0yKHKhwrxwN2cEzAcOJ7WY8jdxBkKXbu6
         2pXAPZdilDFuWtQ7rx/GDjtdnmyJBFhtMM/QccX8vXhJ4q0W7tAMEon++JUtmJlP0cqW
         gxWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7810S3i09PjcrqSmCt+6gubyHGH8e/eZRsONYf44QQw=;
        b=aPyg5vIjBI/jOppUgPmehoA55v9VbTthVt4PagPpwNLjwPSdCivAwSIdiQhQeR+lbQ
         ml6O/yon3YYnz96syeBttr+QBoj3+sC6nPAtbUnHEPEIGWmBNmrqvB4aq478GMQelh7G
         raglp4AJalyhr07vr6HBRaq0g5sgSNY/Zk+ZTHZB3EMOB5AAzk151viARAVBPG3xB0+P
         oyib5d1yu9fV/l+V7cLJz3Z9Z6C72sXyJf+MQVoprBGobqcD3etvNGBBqA+JnqLZrJiO
         Nj9mYALyX1PsBo/ggHiVFop3IuqgYrWTaHK1EKAcVwRsBNqU+wE9IGvTEljmu0At+qQ9
         Yspw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="djK/rzc1";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=7810S3i09PjcrqSmCt+6gubyHGH8e/eZRsONYf44QQw=;
        b=LmwkBZf8g7z9n/bFUFGiYWuMGrKlykujxGFs/YD6JFsceRG5bIEV3S7x+GZp3SvhfF
         sRPAdRc8mDVfqZgAXbniFXsIn1cU3PObS9MyDVxVn7pnOuP/KOK6I4CyMSnkgKspfaqC
         15OKfpJkPhvLrSOdMENQZXtCvy5sV3QIUqevjG6nAddIvsd6xkqiQlxj/q1LIThvfvug
         orqz34TKr4WahTGalmKam6ZXDNNjYIYH1M1kG4EJOFsPkEDZ1PLZAwo6MmwQiczRMryb
         yMKURkdj8WPfCI3rB8C3QHi+SypvwBGKpVIJxx/PZWSujlqvcJmkVl7HNaQFxC+XS2L2
         dJMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=7810S3i09PjcrqSmCt+6gubyHGH8e/eZRsONYf44QQw=;
        b=6q+zfJjmnxWMDN5tqwLDL+mXtWl0nLcfeEciHzaKGr9HStVAkBXKGn7uYtcpx3vz9/
         NxL+XEMVvOHsSImYqIz/88RmFMjCWSB+/RDlh10r6zXdcvfJIespXhe/4DUYzp5QYfPx
         JoXiOgB3hVhPCXL/a/rHSxd9h7OaeZXy7h4vXrAADWq9qIvdQxbvF/ZbL/0d1CFGtPAu
         aMriwxonUlv7Ex+AoJrj7Ul1T/tavNgW5xbmETPGL4X/d+QwZiZUPBW+MX3ArGuKaaLH
         ECzhlvz4hayrUxCCORD+mRMM8WTqyefv/iH+f2s17otX5MH9WvvW4OYqAQ9wEufQUSgX
         AE2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2R9vbSex8KlXS/zGMclFy+IuVMuJM3LwIzNXbADQghr9neb7vv
	6hh5DjdRPNO0O0s34DRP1LQ=
X-Google-Smtp-Source: AA6agR431ZPqcduXurZIU8TlDsnC+VG0IKUj6ZTskxjB9fypjl3FfzkIP8epew5JPwjZG+J07woTGw==
X-Received: by 2002:a17:907:d1f:b0:730:95c0:6cbc with SMTP id gn31-20020a1709070d1f00b0073095c06cbcmr26060164ejc.395.1662082540508;
        Thu, 01 Sep 2022 18:35:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c8:b0:448:77f2:6859 with SMTP id
 x8-20020a05640226c800b0044877f26859ls105651edd.3.-pod-prod-gmail; Thu, 01 Sep
 2022 18:35:39 -0700 (PDT)
X-Received: by 2002:a05:6512:33d6:b0:494:9260:8ef1 with SMTP id d22-20020a05651233d600b0049492608ef1mr2893219lfg.507.1662082539640;
        Thu, 01 Sep 2022 18:35:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662082539; cv=none;
        d=google.com; s=arc-20160816;
        b=FIa1//FxW3LJxqLbKcuPod+KIRYt0GnYsORffDpMiYcdAmYQYmbt5LtNgvyWjztjYP
         iln9vigeyZAai/dBmox5TLcaEHXRZ25iGX0GHNq7n+lFVcTbOjhLNDNBgRQQ9DuuPtUv
         gz4u6u1PY0dcHzqVmWfQ6uu353KOF+8JwXVRAWYh47nImXoPAc6jspEHeNJYrZgMzL9Z
         wRXtm9NZ/nBD/JvwKGolLEWUEI9dC9TMiXh8Y9OVYCJ77iQL1yUCzizVoM/6rDd5Du+V
         2JUxh/J2uCsod4YZNErIPkTKvSV9AoQ8V1wxQjfnnfnTggHzkFsLPXq/PvhrsMT54DwP
         MLJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=DKbeuQ0KEVmGJmd1nxH6IkYl6hlcE8fBK782zCfa3dY=;
        b=R3w/vsnjt6xXjSGA+PJkFoi10AT30ardNLt4YOvR36H6KkonqZdpP5OoQKCXqSfB/K
         eXtn/L51lsfTM0NAP0lUNC/+I74i7Y3BNuqIiXGmCoDfQuIQSsI47dgN1FBaZs+nacfu
         1/wU3Pu7KDY8dp88ncW2BtoBqmN09CUHFuAjfgYX0Xh/K++SXRAyIJGKfisVU8P3es7i
         0lAgQ7xD3k45pLhDaz4vwods6wXa10lP4d0Lp+0TMGnByQ09R5/pC0nKyFY5nBS9l1ak
         F1G6FrFaVPZay2Ye0D+xB66aJ7IgFWwy5EGEEBsUMMTOW1nxcE/UnheyQDDXs3dKUcTs
         Smzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="djK/rzc1";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id g28-20020a2ea4bc000000b00268b15f80absi35182ljm.5.2022.09.01.18.35.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 18:35:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
Date: Thu, 1 Sep 2022 21:35:32 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com,
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com,
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com,
	dvyukov@google.com, shakeelb@google.com, songmuchun@bytedance.com,
	arnd@arndb.de, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <20220902013532.6n5cyf3oofntljho@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-28-surenb@google.com>
 <20220901173844.36e1683c@gandalf.local.home>
 <20220901215438.gy3bgqa4ghhm6ztm@moria.home.lan>
 <20220901183430.120311ce@gandalf.local.home>
 <20220901225515.ogg7pyljmfzezamr@moria.home.lan>
 <20220901202311.546a53b5@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901202311.546a53b5@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="djK/rzc1";       spf=pass
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

On Thu, Sep 01, 2022 at 08:23:11PM -0400, Steven Rostedt wrote:
> If ftrace, perf, bpf can't do what you want, take a harder look to see if
> you can modify them to do so.

Maybe we can use this exchange to make both of our tools better. I like your
histograms - the quantiles algorithm I've had for years is janky, I've been
meaning to rip that out, I'd love to take a look at your code for that. And
having an on/off switch is a good idea, I'll try to add that at some point.
Maybe you got some ideas from my stuff too.

I'd love to get better tracepoints for measuring latency - what I added to
init_wait() and finish_wait() was really only a starting point. Figuring out
the right places to measure is where I'd like to be investing my time in this
area, and there's no reason we couldn't both be making use of that.

e.g. with kernel waitqueues, I looked at hooking prepare_to_wait() first but not
all code uses that, init_wait() got me better coverage. But I've already seen
that that misses things, too, there's more work to be done.

random thought: might try adding a warning in schedule() any time it's called
and codetag_time_stats_start() hasn't been called, that'll be a starting
point...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220902013532.6n5cyf3oofntljho%40moria.home.lan.
