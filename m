Return-Path: <kasan-dev+bncBDBK55H2UQKRBKNWYGMAMGQEZIPZN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1036A5A8F6B
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:11:38 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id e13-20020a19500d000000b0049467449c44sf3484854lfb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662016297; cv=pass;
        d=google.com; s=arc-20160816;
        b=kd8AJcQpoGgXceUHGYgXhDql4rNF+/tP0dCkufGzdx7J/QDZqCo962DIbzyjnbnFaD
         Fek0knFfB4Q1aVqi99EY2D/MxJhFb09JII/31v9kjA8vZFBLmW4ar+59uTvWXXM/Vs65
         si7eoSWMQXy1hPAf9FZeKAdW2ywHn1n6MTioKlhjtFXFAv40bSuFHKS9kQNWB1nJShyS
         K4wYS2aJndiIMGkJWI1ax+H+G8Ag2IRi4CNSihkQM6RcUkHGj2IdloF2kvW3b0nit0Tw
         5HPqejpnGCYFD9EpfFcSHl4+hGDcSYhpOQwrCLXxmFg0swbV1mhZJSS/ZGyIEW1/nwDH
         uoBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jUh+3ZNh/hCTRpMgzlDsqPxaNofVimP8rWyuoK21zuE=;
        b=oxBoYY8t5GODQtGc4Nn/bq0ArC+/V961uBVHXhIrDhbf9UpCYQQdbeSAcfgAMuAIom
         1mUugYLHNZ6aUxHynLaMfhTDvbYVAFIO6gB3xukCwvhraVpkbAV/yvXRwSi2I7IkcV+X
         Yf7q7HW3tcrppWijBIlRSooEwCzo9FB9psBTwdStoc+kx6sGEH6X7kV2v9qQV7lL+406
         SWDyAwyBuH6y57xP5LjTX8gbqMdFGJYkh1CeIfWDA6jgXkTlK8M5t8BGxVPfI2B4In+Z
         qMV8w4shQi9MJfxUZYYk/ZJGbRWFI77uOg6mEfq5lvlgoynLhNm66v2BVFnGz6zLBRNh
         21iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=neTNuYxo;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=jUh+3ZNh/hCTRpMgzlDsqPxaNofVimP8rWyuoK21zuE=;
        b=U899TBGMslxBAHrt31Kbgheye/h2jOok3/ki60bJT6XnoPLt6DhCxh2XXlg7K9mWCI
         PqOJ8yEymiKFKVl2AUF59bDMOUMKXz6RR3OwfEHYYWspePKaCYPDKdefa+B5wG+cqNqI
         zwDDpgKvAV3WTtLbz9Jx0MCAGvT7ou2vvOeArFE19OJk1G9fQOs0fAsQ5AN/k0Oh1yNC
         QVHzcg16q9sXsw++HcwOs1V74ZJnq2qyyBPhwp0ajfls89ldI4eJdWmXkLJV+u3TDAU1
         Sfvr36Gs7S1isNDyg2XBsAkpuPbOEYbXdP8P4sD+AQScqSdUmQs7KP7+67Yb7jUI2OW+
         H/0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=jUh+3ZNh/hCTRpMgzlDsqPxaNofVimP8rWyuoK21zuE=;
        b=k/xvPi6iOVee4e5QgblIVAVixwzmAqHFuRqS78L+K3hzhYhS2iiWZzAT9TqXV952Gf
         wL3TRyLeW4QVxmZ+OyvOJPAB//bjLFiYbYsPbIYD7BsbZ89LWfCz4zvvqyMOi0zEep30
         XKDV/WhUB+kUeUgCAbSJe6ydLSC/dPxpnfUAz0IYtCcCIVgRjL5YIesStj9wfY8mOsl7
         Qc1uuyTXzU/iSFQ8aXnol5JiNoZ1p5PKxd7uontpSj6bVVB2qR8ENyW5Z3eU9XRX11mP
         YTT5jP3KILUuHaFGPOcGWdHe0mMUTItLFShx4iAhGDHnb6f/gbPOauHah7o7v9qctsXN
         HTHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2zrjQffoC5ajvq7SyzcvkfPwhpu93h/jap8Wsd6UTCnHPG5yH2
	J6eiGNPFaVpl+tAO7YCKXWE=
X-Google-Smtp-Source: AA6agR5lnoUJngXV9GHwaRTODq0sPaMpnxnR2yOwEM+b8vwZnPRdrl7THERGvEtJNTqtqFSBLpTDXw==
X-Received: by 2002:ac2:4e15:0:b0:48b:3ad2:42c8 with SMTP id e21-20020ac24e15000000b0048b3ad242c8mr11383972lfr.391.1662016297452;
        Thu, 01 Sep 2022 00:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3fa:b0:494:799f:170 with SMTP id
 n26-20020a05651203fa00b00494799f0170ls791100lfq.0.-pod-prod-gmail; Thu, 01
 Sep 2022 00:11:36 -0700 (PDT)
X-Received: by 2002:ac2:4f03:0:b0:481:50f7:ac07 with SMTP id k3-20020ac24f03000000b0048150f7ac07mr9648647lfr.422.1662016295997;
        Thu, 01 Sep 2022 00:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662016295; cv=none;
        d=google.com; s=arc-20160816;
        b=RzI3wVSAHqSU1TrfAJQUB7DeJHzmMErwZtwFcA50RFs6Kd9kBscNlH7z1xWwaAcPvt
         TC5yFAfFWKFYBUYFMqUtNuVXIyeFaO83JJXKW+1FI8aoCHEXfsHIeJOD4BYSe0h0fZT0
         el3KjoUh+gU66STYffhi6eoI7hXkwUGOZuDkxZK7+ZD8fu3hC/FWbiaM6WoY9vr0WB7b
         x/uL9mkdIY+ynqJUpqpNXKcW0pJBIOCoRyAKwJn2MWpmYJohhHqsvC9i64TJDby4QoJA
         718jGAIImv9tiU+v1n5+V/4xwLTi0SoIW6oOG7clWwmotVQOSlvJjRY+jeMre1ebd2Hq
         mAqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0alPrNIyXUGsDd/lDjKfjoAzSlLEpkpL3yJZZ94RPpk=;
        b=D2unET8oQ5fyyAYQPphO3F/ivAngylLdmvXH0EPkJq7SKpeoWWLyT+lwj2YpZDhYss
         /6UgAfj6SZGYp4LMYanQbFCGN/ptwUvpGRfMWWemviVWdjVF3QeiuLxe1UL6umiAy4Cr
         Y35fd8QkZZdQTC3WIJ13AqQpTHowMGXN/7nLPaHldKRUVKl4PWWUCsiG0R3bQAirDegI
         1ryg5BIhoFRLsa83H9yUi2tDA3Kd/DtSHljkWa1rTauqX/J3WWyd8xdJf8VQu8dcOp7a
         6OsoN5x+971kSshQGypH0Tj1+kjJg+jEyW3rJ9tCioKtFYFtfOTW2hjlMG37rIEZGhue
         5osA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=neTNuYxo;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id m8-20020a056512358800b00492f1480d0fsi76976lfr.13.2022.09.01.00.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 00:11:35 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTeMD-005p99-An; Thu, 01 Sep 2022 07:11:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D2B58300431;
	Thu,  1 Sep 2022 09:11:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B51EF20981381; Thu,  1 Sep 2022 09:11:17 +0200 (CEST)
Date: Thu, 1 Sep 2022 09:11:17 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 27/30] Code tagging based latency tracking
Message-ID: <YxBbFUirdlbXDaZA@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-28-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-28-surenb@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=neTNuYxo;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Aug 30, 2022 at 02:49:16PM -0700, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This adds the ability to easily instrument code for measuring latency.
> To use, add the following to calls to your code, at the start and end of
> the event you wish to measure:
> 
>   code_tag_time_stats_start(start_time);
>   code_tag_time_stats_finish(start_time);
> 
> Stastistics will then show up in debugfs under
> /sys/kernel/debug/time_stats, listed by file and line number.
> 
> Stastics measured include weighted averages of frequency, duration, max
> duration, as well as quantiles.
> 
> This patch also instruments all calls to init_wait and finish_wait,
> which includes all calls to wait_event. Example debugfs output:

How can't you do this with a simple eBPF script on top of
trace_sched_stat_* and friends?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBbFUirdlbXDaZA%40hirez.programming.kicks-ass.net.
