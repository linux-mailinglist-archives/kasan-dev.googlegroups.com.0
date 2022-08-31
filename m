Return-Path: <kasan-dev+bncBAABBVUUX2MAMGQE5IKB4FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C1CBA5A82F8
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 18:20:38 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id ay27-20020a05600c1e1b00b003a5bff0df8dsf1954414wmb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661962838; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0v4ODvirA5wfE9pIO29uqrPHwWs15YpD1gY3hqRyuZ46QTqwTRwD4W/wrV4dcjUBG
         tn9DXviggNmJ1Rwwqop2tGW2OKvOUd2ZWQKxeeGedYJvsirab0FONKpC0KM90UKIk9f/
         jEK0dEdzFdaoFg+n6aODiMX4MiyCNQlaNJzDXLQAkpvOHmNY+7kp0MUWOOvjI4E/xnWk
         T3juBVr0lDyB1ZT1soOXvHVSCxAK6qrQAva8o89ZMyDMoVdiXuV7y9kow9q4WG2aAItP
         k5s3eXJU9JGsIzDZTQREiLSOjhh/XJ2yEbqA8x5nB85wMupu3ijan7GcOnpDgY5eA0/A
         XOhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eHpRZmfJEl9fDy+kM5WQW0CDtkAWjB0jirdOmlrj1to=;
        b=YuY1BLFnA0MxEbpMZY+DyF3BKNd5grn+LxfgPyFAwq0jeCGyceAHWUkyrcHMnbkEkP
         1njp/F79fxNs7lZHL3n5525EFTYVbLCZCh8zwl1YacYIlER+eK0GMUC2l1VDfh7rw8GY
         5JG2Th99U658rFefSukTRsOQ2InxjGsb/vl3jxVmbxNbDFT1985Q6IUz6JIP4J1fFQW1
         B5xAKmgb9+Ni2nbl75/HKSa3+Aa/qcLLUtoNCde6CljQ9cCA5nAYJtgzn/g+RMnoyMI1
         F3m4TXb75sxe8o4/9cd3wp1TJS3tMzWkLIHcq71a1BssQ+KwRDiOcWdrTuyNh9ZaT8J+
         +7Vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KVP2c5IA;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=eHpRZmfJEl9fDy+kM5WQW0CDtkAWjB0jirdOmlrj1to=;
        b=eABP3whdntanYHenE6Vmomhp9R81+52QX3SN339OVXZA2MmBaiMk9iJar4AceHqhPS
         kWzWJpGakkXqdYswjv1ipRgtLjC/ftbZ71ORdcCI5tGx4ScGjscpDRnlL+yU9JAUmhHt
         deAzMO6XIOflVLL1KvEuJXYk5tRDG4AJpTfgKzKAFKo/ZoabhIN6eV/x7H0wmp+BDbLE
         N7t6GlzgoZFMwh59yUvM7ajNqW7/imUv9UcG/3tJzxGmhwGPRaVVRwMZxDqLjeSqsCVv
         qrHb/03N5KpiTO1YYnmIimPKLWBAXTmnXL45uJedhVCUpxEB+UT+jalv2Q+Z8a9d7nwI
         g3YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=eHpRZmfJEl9fDy+kM5WQW0CDtkAWjB0jirdOmlrj1to=;
        b=3FPgzvSthanmwmlfCMw75mpx2ndd1PJ1bvPjEfLhO46HJe6BnHozwLmRYBxSzm3t20
         eDdwEZwgDo6ppMOgQjtFI4fwMIHiYdUjVDAkXW56+qYIAmke07SoFNGoHVvbp2Cje68k
         d0mp8R1Yt2zi3UunFYTodFqyemiXk9CNNgYvLd3H0tG9duc2kVBzd2YQhi9sxbNQAbRl
         9fn2OQ5JVnHhjrhZ145Nj5CopKVAFHMNUGXwJEvws02LuI0ADcwYP7+jzSaPlhw22Ka5
         G78LVtBKOa4fEJpTcqFPBM5OxlcgrYtI5s8La3sLPRaHJz9WPFgxYD94B3/facARvRo/
         wFLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0uS4HT6H+aljsq94ElIJinkCwrzP9ZTvGmrr2dcB1RpzWeMDmC
	nKhIRhg7pAqbjm/hxuUkIf4=
X-Google-Smtp-Source: AA6agR6dTPnOVg2RzvYCJAl+okQnlXKspQ4ognDBQj+DQfg1AnbEqMQCJ0cgjztHzZZoRkJw8QwDsQ==
X-Received: by 2002:a05:600c:190a:b0:3a8:43b8:53e3 with SMTP id j10-20020a05600c190a00b003a843b853e3mr2607675wmq.4.1661962838295;
        Wed, 31 Aug 2022 09:20:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb03:0:b0:3a8:583c:54ed with SMTP id u3-20020a7bcb03000000b003a8583c54edls965496wmj.2.-pod-prod-gmail;
 Wed, 31 Aug 2022 09:20:37 -0700 (PDT)
X-Received: by 2002:a1c:7209:0:b0:3a5:c069:25d1 with SMTP id n9-20020a1c7209000000b003a5c06925d1mr2583163wmc.71.1661962837525;
        Wed, 31 Aug 2022 09:20:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661962837; cv=none;
        d=google.com; s=arc-20160816;
        b=E3vghnU4O7HdVmdhKz6h1Dk21IK8XkA7M5Cl6HF6m+6HnYLO7B2kU6hs3EwBFxDK2S
         O9cPrQ4z4gCaulQoj04BVGwxtWRkDH7WgQGmJBkJhY7s280Atg1i4EiEQNR6Dyg1OkrE
         oF4RfzzUUdxGpKmGQo3gC+7xhkTaihjYkdKziDlrE/skGcvgt7iH1gsPX6BOj2FXGA5T
         jXfscGkINoHGKEjd/HrPQAj5sWTnL80OiYvJp/Ag4O7Gu9m3euHSQkfc2tWRv5yZeRbs
         z9b2B/YO9PqL0GKhGoxKExHdvsI2i/NLa/rukSh4j0UmjoC13PJeau6c9kuXUBdAIl9s
         GbEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=iGyIm0136Cqvu8OauWzfpc3vydsg6hlY8VzCbW2wXJg=;
        b=qP728MgOdmqa25CZOeJAl+yX+/SO9e0XmkGvf6Iwa1X5QLFb60TCptGUdW9Ucs722N
         sD301hKVJ8AXnylCbPwSFqGdt1F8DxQd5+maXKcb02sf0ufhL/eG2gIcRKoIbhUCh3Q6
         y5mzURPzIgH8TOFcat6uloZlTHl8hpnvUFIv7AlAm6hjHWh9k5v2mTGCm6bUFfQB+q2+
         eG4V6ow4fje858i7GjnwPOp51WVmu6bu98rwC1zeJ3T/sAys+X3pnE6c9SH6/3Td/yYX
         irT+ub8riEeKiuzXqadcwfcsZAePNAkn9UusITV7LjRLMUL5RT14YZD+wzTf+YA8DLCg
         uEBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KVP2c5IA;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si440338wmb.2.2022.08.31.09.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 09:20:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Wed, 31 Aug 2022 12:20:30 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Mel Gorman <mgorman@suse.de>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, peterz@infradead.org,
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
Message-ID: <20220831162030.hzgzhxu3qn6g3k5r@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-4-surenb@google.com>
 <20220831100249.f2o27ri7ho4ma3pe@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831100249.f2o27ri7ho4ma3pe@suse.de>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KVP2c5IA;       spf=pass
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

On Wed, Aug 31, 2022 at 11:02:49AM +0100, Mel Gorman wrote:
> On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > This patch adds lib/lazy-percpu-counter.c, which implements counters
> > that start out as atomics, but lazily switch to percpu mode if the
> > update rate crosses some threshold (arbitrarily set at 256 per second).
> > 
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> 
> Why not use percpu_counter? It has a per-cpu counter that is synchronised
> when a batch threshold (default 32) is exceeded and can explicitly sync
> the counters when required assuming the synchronised count is only needed
> when reading debugfs.

It doesn't switch from atomic mode to percpu mode when the update rate crosses a
threshold like lazy percpu counters does, it allocates all the percpu counters
up front - that makes it a non starter here.

Also, from my reading of the code... wtf is it even doing, and why would I use
it at all? This looks like old grotty code from ext3, it's not even using
this_cpu_add() - it does preempt_enable()/disable() just for adding to a local
percpu counter!

Noooooope.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831162030.hzgzhxu3qn6g3k5r%40moria.home.lan.
