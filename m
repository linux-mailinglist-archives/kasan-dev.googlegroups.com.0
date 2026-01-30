Return-Path: <kasan-dev+bncBAABB6HL6DFQMGQEHRC47GY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id UZMaJPo1fGmvLQIAu9opvQ
	(envelope-from <kasan-dev+bncBAABB6HL6DFQMGQEHRC47GY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 05:39:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2683CB71DE
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jan 2026 05:39:22 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59b77f5f4cbsf1124337e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 20:39:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769747961; cv=pass;
        d=google.com; s=arc-20240605;
        b=TuNSIHo4Ad976T5ta0ymEF1pwnrLbeGFQ1xI2SW5YUEKZfH/9ANasSGM/d/0RNCyWq
         gWNCG0F1AO0nXoiSKUf/XSYe23i40Rhl7WUABLaSEWbtg/tHWSPs9zg+p5i2COHwzQRI
         +zbZbi6CfDR4z9eGD/hNX0aQnuEs0Tui0SyWKP7o6K4ubn9aqZK872DI6Nk8v+4ErkXX
         Nwq76B5qqbRU6CmoQxfzhsAGTSdllUxfQ5fUJ12lvxMgqlHGzhY0hAmUbafV9IZTG3Rw
         NWquaKwi1I8HmUyDsw3nwvVbSPBGYAwJJqNvn7bMjBQnfahPNzPnonu4mOkHOZNcXBRR
         ieCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/1ovJifGqMiwpfVLzl/NNwmVU6tKoMaDlcLQRhmQrds=;
        fh=+UFukJzfk2wgwPZbdoI1VMQWpbto8DOb2A9imM7NAuk=;
        b=O09mPlPT8Hm7mN+naCoYYQUowD98KnG3WLYYlxT4zsrnoQrJJq0GSXCMImAaODGI32
         JSvVophGuN6uQSMq3Neww/VVQUa24hL7svUw3hOEio4s8lhSE+U8Ouv/fxC9NoWHboRv
         dCCgXoLEv4mAOfYWwW21S6HGIS+GJmfmerXngB2X0ppjuxUvr3DrA9W24Umhoz6UKo1z
         zoNDpSAuQL4T9zNeKTzI67dL9dBMsY32PTp12kZYrTbUafrpWhoLmk4HQmddhBpFmyGh
         fKU/GocWPG+zZ0TjsDOmrZjEXh4ei091Tpfmk3sqhHPmmh6reNlPJ6XaY7pLV/51+Sk9
         StaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OyHEYLJr;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769747961; x=1770352761; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/1ovJifGqMiwpfVLzl/NNwmVU6tKoMaDlcLQRhmQrds=;
        b=IaIrSKR2f1dkQhDEH/M3bcHxqqEz8oVktLLja3PB1b5UKmj2ONm+J6I/qd1saZivrC
         uOPwKjdyoCdL6MXl0McnXw+exzuNPDOUGVMdeXvpcObJkn4DWXh6trEq3ww8ILzwhKVa
         1WO6da4iDsgDnC3idlgEJksj+P0pLno4l+nYle/ZSsNDHuVUj/ZDwCu3z8WAjgF4ovMX
         ykjdugZhhmpgUWrAQ2IS12vVcqTC697h3bgb/gRFwMRmN3hvx7hTBpJKiTlWlzM2rmMH
         iKp3SrOJuZO8fb6t7chv/wLMQ2Rm0e8jWUN3r395OrJ/TPgBmwSWQrT0sjWK2v9SNGJO
         qhbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769747961; x=1770352761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/1ovJifGqMiwpfVLzl/NNwmVU6tKoMaDlcLQRhmQrds=;
        b=Lg27uY7LX3cwwdKkZ8uGnsgnWIhW/5sQgq2pusTYzpZ8ZHqxBYaBp7h2KO1bOKLpFV
         rx0bFPVACfqaryDeAYB4LIE3UQ/tEp5bIUWy3hC4khafhaTzrN7dUNOyg1GAqjTDRWQl
         GYaPTtFbfFMhc44rbKztQA1G1fo1cafcI+9wWHMwUCZ5ajyvgTe9A799tBmjzCb8vwJu
         dnhWuqHlUxeQFj8RkIznovBajEUJjkqPzfKXUfdqhlC0HY7qsW9b9coi8IIP9EzZyZAm
         MaXd3U07X+cDM00tHHzSeEzoBNw6fd7iRiwFlljU/WlMRkEPGmaGqQccsl2YQLiqpNN+
         wOUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUj592poY//eEPjT3pErqTDCEdiZO+e4yQfNUWyqu3hpdRI6Ar0QCO8w/9XL7JzoqF8Ey/W1A==@lfdr.de
X-Gm-Message-State: AOJu0YyqTwe9rpkAsWvosGiXSAwbTJ5jVhFrveujL7uqhQPcis/FsDsD
	V4g7g5gGm8ghNK3qhyMU6uGtXZgd2pDz6ovRRYfUnt+37v+RivuV3RQN
X-Received: by 2002:a05:6512:3b95:b0:59e:a44:1b5d with SMTP id 2adb3069b0e04-59e16405e54mr463358e87.25.1769747960852;
        Thu, 29 Jan 2026 20:39:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FBIyWEDtgOdCOVRnmPUW+hD4lyy5jzwMyhjurQ4SmAXA=="
Received: by 2002:ac2:4c46:0:b0:59b:a3bb:9e0f with SMTP id 2adb3069b0e04-59e0f1ead61ls658729e87.2.-pod-prod-01-eu;
 Thu, 29 Jan 2026 20:39:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXTFaRJLPp9mMBSR7qHtJID7wE2Ra8HLAZXlSbFCUtoRb6MQTAKu3fL37ZKSKTKqBRxqLzwI3L/Cgk=@googlegroups.com
X-Received: by 2002:a05:6512:2394:b0:59b:83fb:45df with SMTP id 2adb3069b0e04-59e164162ebmr490474e87.47.1769747958795;
        Thu, 29 Jan 2026 20:39:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769747958; cv=none;
        d=google.com; s=arc-20240605;
        b=ln8RDD1GaxNM3w44yGnCXcpffojKRqp3t0RMcuv4RJ9WlxRC2Lc5aUNBEQp/ZeDvJ4
         PUjdXGigfFqdlxbt7NmH8W2JJYoNMHvcRfQ783OG5C7b+1Ohkm21ruK74wZR9+3gg68U
         FBtqqLviQpydarJQNvJkuZLFN0eZ8A142U60p8HPdS9D4ld1CXGCNAGXte/inJOGRxrp
         LXwZEh5hQSn54A2IsN+sY+c7RjtXeVe4Mi1I1Qa7NEELcqwzWY0IBlO+7OXDuUJP4Jic
         6kP2aMsqQCDftK3z0fjpzHavqa+nIMOchtOT2Q91ZPBBqKH1A/IJfMoSxT1A4h+hd1HU
         S8KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=HsyA5AueEdtbE5hLH2TKuJN9cYQD6jVv3ixFrefE5Z8=;
        fh=agRXbVNQGOKBu11WQmGmkekI6pUXT8WkqqmRVu8hwyU=;
        b=U+Zt58+pMwnN8zhqh+05RPvPuz7Au5zxY2KCGjGP+nv1FpJKejAR3tLeSVFjokvAzJ
         KWKmiUykMH7K6y2VUeBVWvv2hLJ/MxUcrsC5PaLLhH6nW9aQw04oX1R+6ZEb1HkQSCZN
         yFST2ht9oOZjNmPOGC/44hifoQL28cUevJPeRkoAo7nxs5mrDgWV9u3Ee1iGjbaDVNPU
         Q6UYwksaHW+2iM4Btdl1QoCKmpHx5AlHespX4X8qjga65j9k5h/c0f8QiCKiLhpVF41H
         9tLD6wjRfVRe6o06f+hFiwP/Peo8tide5LmyYak4M89lxlslluSJBH29bF8KTTgykVHb
         bcdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OyHEYLJr;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.173 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [95.215.58.173])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38625c5e831si1739001fa.2.2026.01.29.20.39.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 20:39:18 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 95.215.58.173 as permitted sender) client-ip=95.215.58.173;
Date: Fri, 30 Jan 2026 12:38:48 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org, "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
Message-ID: <k3ntrr6kyekjwh2yeawk2pvtiilnoltsxipdzdgzaby2cdon6c@yknpymvklz4y>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
 <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
 <aozlag7qiwbdezzjgw3bq73ihnkeppmc5iy4hq7zosg3zyalih@ieo3a4qecfxg>
 <aewj4cm6qojpm25qbn5pf75jg3xdd5zue2t4lvxtvgjbhoc3rx@b5u5pysccldy>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aewj4cm6qojpm25qbn5pf75jg3xdd5zue2t4lvxtvgjbhoc3rx@b5u5pysccldy>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=OyHEYLJr;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 95.215.58.173 as permitted
 sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABB6HL6DFQMGQEHRC47GY];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[suse.cz,oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 2683CB71DE
X-Rspamd-Action: no action

On Thu, Jan 29, 2026 at 11:44:21AM -0500, Liam R. Howlett wrote:
> * Hao Li <hao.li@linux.dev> [260129 11:07]:
> > On Thu, Jan 29, 2026 at 04:28:01PM +0100, Vlastimil Babka wrote:
> > > On 1/29/26 16:18, Hao Li wrote:
> > > > Hi Vlastimil,
> > > > 
> > > > I conducted a detailed performance evaluation of the each patch on my setup.
> > > 
> > > Thanks! What was the benchmark(s) used?
> 
> Yes, Thank you for running the benchmarks!
> 
> > 
> > I'm currently using the mmap2 test case from will-it-scale. The machine is still
> > an AMD 2-socket system, with 2 nodes per socket, totaling 192 CPUs, with SMT
> > disabled. For each test run, I used 64, 128, and 192 processes respectively.
> 
> What about the other tests you ran in the detailed evaluation, were
> there other regressions?  It might be worth including the list of tests
> that showed issues and some of the raw results (maybe at the end of your
> email) to show what you saw more clearly.  I did notice you had done
> this previously.

Hi, Liam

I only ran the mmap2 use case of will-it-scale. And now I have some new test results, and
I will share the raw data later.

> 
> Was the regression in the threaded or processes version of mmap2?

It's processes version.

> 
> > 
> > > Importantly, does it rely on vma/maple_node objects?
> > 
> > Yes, this test primarily puts a lot of pressure on maple_node.
> > 
> > > So previously those would become kind of double
> > > cached by both sheaves and cpu (partial) slabs (and thus hopefully benefited
> > > more than they should) since sheaves introduction in 6.18, and now they are
> > > not double cached anymore?
> > 
> > Exactly, since version 6.18, maple_node has indeed benefited from a dual-layer
> > cache.
> > 
> > I did wonder if this isn't a performance regression but rather the
> > performance returning to its baseline after removing one layer of caching.
> > 
> > However, verifying this idea would require completely disabling the sheaf
> > mechanism on version 6.19-rc5 while leaving the rest of the SLUB code untouched.
> > It would be great to hear any suggestions on how this might be approached.
> 
> You could use perf record to capture the differences on the two kernels.
> You could also user perf to look at the differences between three kernel
> versions:
> 1. pre-sheaves entirely
> 2. the 'dual layer' cache
> 3. The final version

That's right, this is exactly the test I just completed. I will send a separate
email later.

> 
> In these scenarios, it's not worth looking at the numbers, but just the
> differences since the debug required to get meaningful information makes
> the results hugely slow and, potentially, not as consistent.  Sometimes
> I run them multiple time to ensure what I'm seeing makes sense for a
> particular comparison (and the server didn't just rotate the logs or
> whatever..)

Yes, that's right. This is important. I also ran it multiple times to observe
data stability and took the average value.

> 
> > 
> > > 
> > > > During my tests, I observed two points in the series where performance
> > > > regressions occurred:
> > > > 
> > > >     Patch 10: I noticed a ~16% regression in my environment. My hypothesis is
> > > >     that with this patch, the allocation fast path bypasses the percpu partial
> > > >     list, leading to increased contention on the node list.
> > > 
> > > That makes sense.
> > > 
> > > >     Patch 12: This patch seems to introduce an additional ~9.7% regression. I
> > > >     suspect this might be because the free path also loses buffering from the
> > > >     percpu partial list, further exacerbating node list contention.
> > > 
> > > Hmm yeah... we did put the previously full slabs there, avoiding the lock.
> > > 
> > > > These are the only two patches in the series where I observed noticeable
> > > > regressions. The rest of the patches did not show significant performance
> > > > changes in my tests.
> > > > 
> > > > I hope these test results are helpful.
> > > 
> > > They are, thanks. I'd however hope it's just some particular test that has
> > > these regressions,
> > 
> > Yes, I hope so too. And the mmap2 test case is indeed quite extreme.
> > 
> > > which can be explained by the loss of double caching.
> > 
> > If we could compare it with a version that only uses the
> > CPU partial list, the answer might become clearer.
> 
> In my experience, micro-benchmarks are good at identifying specific
> failure points of a patch set, but unless an entire area of benchmarks
> regress (ie all mmap threaded), then they rarely tell the whole story.

Yes. This make sense to me.

> 
> Are the benchmarks consistently slower?  This specific test is sensitive
> to alignment because of the 128MB mmap/munmap operation.  Sometimes, you
> will see a huge spike at a particular process/thread count that moves
> around in tests like this.  Was your run consistently lower?

Yes, my test results have been quite stable, probably because the machine was
relatively idle.

Thanks for your reply and discuss!

-- 
Thanks,
Hao

> 
> Thanks,
> Liam
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/k3ntrr6kyekjwh2yeawk2pvtiilnoltsxipdzdgzaby2cdon6c%40yknpymvklz4y.
