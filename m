Return-Path: <kasan-dev+bncBDBK55H2UQKRBEFNYGMAMGQEPGD24QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EF4B65A8EBE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 08:52:02 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id dt8-20020a0565122a8800b00492f7025810sf4105753lfb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 23:52:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662015122; cv=pass;
        d=google.com; s=arc-20160816;
        b=hbLKF5jNp/l3fFdwP++2UMWnCUjcvBruRql8FYB7H9sqcs+SNOmCst/GbLwC2P6A8u
         winbvUN/kW95xOM/YLArucND+Oel9QvDDjSkZrry7N58VYMGRamqJKrme2DaUEfy8MBH
         CQdprg/onfkMx5ceUZ9Ta1HiRZrVhn34oUwTfBS7F1GAt4ZjRsBHFYtzAsDLw1HVXUp9
         07b4rInf1Sj6SpOXlUAsV4Na1fG8n2LRe9RAodn4pm4HJYuBLpQbv9sVBaV0TH9GwGHg
         OesAkVFKd/O5UAtEq+d36T9fdR8U6kVEJE8oGqTQ1RTiPZTAn9uSgvqhT5a2X4guJHn0
         jKgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fGHtcA5vJDaz7i1YRoS23eGpBH3FxfsuFsuCloT9qvs=;
        b=S194dh7pzI8BKdeswx+FllpyfWfH3kC3lODezU30PU5oPwOhImXXYfU0zpYwb1fdQR
         gCSlQq2OqFmevH7PTyudeMHuXZcNhLXEY5EPTfSf4V5sGu4y3y7yMjWCJWHNOQp4aMyo
         OT3hsRD3cWvHm5tvxT3BckE9K3jmFBjpzPcrpAacMAnHCeuKr7Vza24o8ivOGCZqiI2K
         6xeyb1V1MYDJ9wQ6DY2yk6/pDhNXHsgBGifFiCxKEm+Bjw/IYvNc9ALFkry9uJUSPslc
         MYImpg8tWxk1pz0Aj1SXphdIy4EPtBGCNp2hKtxdMcxnuM56XrTKOo5/54gyhuU0y8ql
         Yw5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=eDO+GXur;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=fGHtcA5vJDaz7i1YRoS23eGpBH3FxfsuFsuCloT9qvs=;
        b=EVeM3/3/fyuw+uuJbSqL9mCAStdteZJRm3ncMYlMT0n3JPhujx1PAKuMm5vPIdP1Ic
         FA68b/fms/oyeI9BYHEVfsnqBlqXkMmjsnpDL37hHKbhpwqySrKwieSNiPnp832uAen4
         dd8pW6vU/rA7j724dNSrelBuOJSI/1k/B5MkgLpCFT9b3Cn6kxPKrGN2T2g1Suygpz57
         JJEsEEY2HpbAr3sQhM5JrZNprUwXiyktkp4SvV7YcRnj8xa2H1nCY39IMR+hJufhswQi
         mnAKQudp9z77GZcQDi7/EOqvuH134TjeVdjDwYQGW2P+pznh+ggwJrijiLKVcOK4DyKe
         MgEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=fGHtcA5vJDaz7i1YRoS23eGpBH3FxfsuFsuCloT9qvs=;
        b=b3p7aMqJ3w2gLV1utex5PTBwbafG1utTlyA5wdD0+8mtHxiXrikmCO+40/3V9tR62v
         21+99dsZLH9biH6PvAP4gsolLYfL4PXYQLkHL+EDzVbcZbAwkL29AbSp/M2QbaHRvr2P
         xrN/MBVumbZAe7WKuNj64GBp5uRUj3W54qtyKQqF5nrQwBgtIg5ZdO+0lZZAf2+QaHaw
         TO4KOr4Nh3sjeDTkRg0Qvg+RJ1czsAmhaSW0kzQFXZXR0MQpNzziwDAHvpZ+r0D5fRRI
         th9/D1J+sT1zeKq8G+GHNCTMr3fHgoL+8BoPVIH7Se+LlhAPzLSxMcNsSsnZCoX6XWi2
         +6EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1xb2ccRxPPJfiQxrQdqRtYmXfindZfl+1iverABZ1LyT0J6/40
	GEWnOkKPv1i41l7lCnhftKw=
X-Google-Smtp-Source: AA6agR4exPR/PWGzZlrLToJtaGp1ftggv8XCmZ4rwaaCzMi2PfT5Vsg0/XbT1lBjMeiRfx7YHSro3Q==
X-Received: by 2002:ac2:4e63:0:b0:493:20a:be3a with SMTP id y3-20020ac24e63000000b00493020abe3amr10139258lfs.114.1662015121439;
        Wed, 31 Aug 2022 23:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:880c:0:b0:25e:7450:b825 with SMTP id x12-20020a2e880c000000b0025e7450b825ls152116ljh.5.-pod-prod-gmail;
 Wed, 31 Aug 2022 23:51:59 -0700 (PDT)
X-Received: by 2002:a2e:a483:0:b0:267:982b:6988 with SMTP id h3-20020a2ea483000000b00267982b6988mr3033230lji.269.1662015119620;
        Wed, 31 Aug 2022 23:51:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662015119; cv=none;
        d=google.com; s=arc-20160816;
        b=BAo4YHcJ9OFd48kmA4sRdN2gZXFmuemGowfb/wFeBaX+w8Idd47UvqYUGzzPmWWhEY
         DN3LpqdtrdHyDsr9uQr9IlBAHpdmFsRw9IJI7pB0RrZmna6EuoAl0FnlRxmpxKtEpuPQ
         TBwGIhFK6kGmdMRHLDmkuBgeDV6vPvO5kR6uKtD78KDb+qRyCjR7xfI4DZj0bl9Uaqg6
         YKSEtsdQqgg89MMmQuGfOy8cFN98q9c6/uhNvZ5p2pyeqCG/Dc6rx4KcIaydi+T0HFan
         UWrYJduluSLpdA9uDr3AVEt48i/rYJn51j5bT9OjLbfKst3KAIPkqaZhxyfCgHsahQze
         vSzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qvwvxWbXfnEQ3IUNjSPCWfkqNnnfffGD2A+a/tILXCw=;
        b=0mFrU7LNAf0x26bTF4uyzYy6jk/uTvMJVOJ9jlQzDQMh0fo95MVjakINwwKZW0r9jE
         3MCTPdx7VJFT5oMgSqxFf1yXi2ZCK8gQiECkBIUd4P+1ul1wsblurxS1Hj5IkcIQBFfh
         ccZxqlv3hec1LmVuVNhH00EKsGVzRLZQ43lbJukXb8RNBVX7VKUYa97Q6tyGovnbCI6q
         JAw4HGcNPQvtPCa8hSFlNYJ7b5wRCFRA8YtO36HB1d44gHK9SiBRQlM5UnmwM1oF63bj
         LC4k4bGszonVAQdp0hUn2TEyPJueGj6lpMzrVIJ30RRZdgZHlhu5jajepAX4Hx8OUxpc
         9V/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=eDO+GXur;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bi40-20020a05651c232800b0026187cf0f12si171664ljb.8.2022.08.31.23.51.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 23:51:59 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTe36-005oCV-6V; Thu, 01 Sep 2022 06:51:36 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EFD5E300431;
	Thu,  1 Sep 2022 08:51:31 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id CFCAB20981381; Thu,  1 Sep 2022 08:51:31 +0200 (CEST)
Date: Thu, 1 Sep 2022 08:51:31 +0200
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
Subject: Re: [RFC PATCH 03/30] Lazy percpu counters
Message-ID: <YxBWczNCbZbj+reQ@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-4-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-4-surenb@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=eDO+GXur;
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

On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:
> +static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
> +{
> +	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);

Realize that this is incorrect when used under a raw_spinlock_t.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBWczNCbZbj%2BreQ%40hirez.programming.kicks-ass.net.
