Return-Path: <kasan-dev+bncBDBK55H2UQKRBJMCYSMAMGQEJLOQHLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DC385A9F7E
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 20:59:50 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id h133-20020a1c218b000000b003a5fa79008bsf1670334wmh.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 11:59:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662058789; cv=pass;
        d=google.com; s=arc-20160816;
        b=R7475bWADUPLTNPeouvMu9b3Q/ICshBX+qCslP6gU3aNz24cbO7+Nk/Zaop2KGxfe7
         x5eLIky1EsFl2hvnSV8BLMg0qgN8z+MJ0crgW1pbIS6MfBVaTG/KUMnQB5yUUpFIEw0O
         HhzLbAQyO4qNJi5q9RF2jNMcf1EWHkH35QDteCt7LGzicz09BwRZvt/qXXqLslOc9X3i
         Zur4h5P1vetkmWnaVZEmfUh2hO7wxrSxZsVMw3I4PvgEdsudgNHtCiLbsAcp4ptLDVhu
         /F203oN30RKcMgNoZjjLVOxz40AjE8vCQbgi6yVRYaYZOgQKCW6Qqjmyi/1USId0tbn9
         Ki6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BkxckGIM9I9cMdeLGjEPKvqsJ79R98awFnel+hoPsvQ=;
        b=q7lvwjnhDL1KOQtbCEBFwaHpcR86GuzejfDMownCDNMwdg4/lXPDH2Ism7y+8oBFaC
         9r9n4plDOvjTPV0Ru980aRY6APp42m3aM+6yQ2J3NBXFgXnVHd5AoqRSR+hYj5nK/TX+
         2QQy215hdcIWQgIj1zn0HZh+Wha2DBpJ67tsq1HnaiSlGAGIHGenHlxHgAnm10VcgbVQ
         sWReZzRGCYHSNqCIHoNKUJu13U0QEdTCGLHRbM2nVfu50RcHH2zyCZzP8QqFuEniMjNT
         NqD0uDB0NDwVGyveG1thOwX5uSkCLtDgaCbKooY5wApi4dgeMjGQEapPQDXAGNvrvLuU
         rucg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Cn40tdhd;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=BkxckGIM9I9cMdeLGjEPKvqsJ79R98awFnel+hoPsvQ=;
        b=p0zqTGQmfTp8PvREpGuvMupVOda7wT+881jAt3Sfh7bV2YMCseXEuO5l9EAeiHsj6J
         dnIykw6p+dT+zqezrFgeY2zBnEuMUGcCtUU8l3z/6q5QKOzD6cuWnAhEcSC9cNnUCgZp
         l1sBOkw8J1VUb74Q7bIMB5LhTA9KesZ5Og0YXnECMvy4Irn4fJ4B31261SC3o1gcE09/
         d4Jet+otMk6HVKAGeC9ePQxqh7mFDsy4GFUaBI/6VreQrxcC/t0c53aBo/Cm/kglur+7
         WVIS6Y1sE7PkYdf2DR/CDrvXcuniVKUVpqdYYA3gRGayeuDB6G1QjHV+dVfrpfkY7G9y
         /cKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=BkxckGIM9I9cMdeLGjEPKvqsJ79R98awFnel+hoPsvQ=;
        b=qnd0fnlX5i85LpQ+v07fnY67Cq1carGawkDc++btNtKWz7MGoJpyFJ0CHKR1faNoNQ
         nHHp9PBJdugYF2TPdRB6gPDDPA2IRHaqlstLZtTukT1PxnnxKxloYAsiYBI4URFz91Oq
         sjnIbDsGA4J6JDphPt2jd85+IdCCOqdir5IICFx/kL+2kKJ9Gnd576bb0sfp5zfI6jdD
         eW1dxoDUXHb0B8Ipub+1tG4v5qTyUnlNFJ3SiOZ8W9JNMCLrBtWWAO8RzRoSWLwkOg3H
         dj32PLt8eqyyHOa2Agjhvv6Hq8bdHQDl5gewg7WrmwJwJKGFwpv/Dt17mpvmms+FQTrN
         Puaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2abODxUAVWB1MAwtNehnzK9PpWBHlOjr9Xp+bzHgD0L2k8LpcT
	R8x8MMM6B/bQQ4INaYYJUWk=
X-Google-Smtp-Source: AA6agR5ULHqMFtREhQSDVrDdxXja82jVNECiLJqYroj9wZB1rzr218GHsRHd/PDvBUXN1874+ftExQ==
X-Received: by 2002:a5d:64e2:0:b0:226:e902:6b71 with SMTP id g2-20020a5d64e2000000b00226e9026b71mr6473579wri.289.1662058789729;
        Thu, 01 Sep 2022 11:59:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:247:b0:221:24a2:5cf with SMTP id
 m7-20020a056000024700b0022124a205cfls4426307wrz.0.-pod-prod-gmail; Thu, 01
 Sep 2022 11:59:48 -0700 (PDT)
X-Received: by 2002:a05:6000:1883:b0:205:c0cb:33c6 with SMTP id a3-20020a056000188300b00205c0cb33c6mr16230287wri.39.1662058788445;
        Thu, 01 Sep 2022 11:59:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662058788; cv=none;
        d=google.com; s=arc-20160816;
        b=KOxLZp+JX4T0CHfrfXbfR/yoO1y8/Y59w1d/obqKlGdMEJ0NcN6MUUGkPqWqPql7g8
         mTswXrU3XCQ/C1uKjMqH9JEFV8/x1pMx7XKDqIIwJcOgE3MXWZNK6p3+wxr8h4amzaR0
         6b2lgH0UY3aYE2aTDZlY1zw5LfF96gsq2R2i2jYba//dcIqzwVc6tO1nljVMd4qgQiZC
         5JSjszEZ9Zm09mZV0CU9pqsjeL6CKCJE0DhDCRfKNDXjog01Ghp6qrCiCT7vDzxJsFLa
         +THCnmrEWcfSAI+XF3l5sqt+0Zjh81cYC6yOF3sv7RzxA88gMLsuXZU/V0p4d8j4eWFO
         Lpfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qo1Y7wjVRM1IPrvgDfwSP6kiSpx5CHm6THH/U/nXDvQ=;
        b=eDHSSX74IAKpy4zw6C4/cgobMkLL0N1OHPaIe1X31AevSzEEP8uJ7VOxbhUse/+1/d
         1j5wzXEZbJ/vBpcSLbVBxpuRR1fHxuASFn67YAqeVLMh1WM9Fg9VQ+eryVqck/WmyoVu
         1zYVZr2S4iMtcN6OVjN/GAyCZbceKF/r5rV2vSRp6x22C+2IPrCKo0hwz2+Bcs9K4/xl
         9pbxD+A1Q8GC0ZwHG9qqEdO8bvYsOZ08xO5BOiTclSxQae9eltBLj5qPO2NLfl6cqcrS
         v9M8Bk7w97L9lAIxrXY5CxcrLu2NghozQVRy0s4oeAXjqjKMcbjVBi6k5MltpH6zW4/8
         8PWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Cn40tdhd;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si252636wms.0.2022.09.01.11.59.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 11:59:48 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTpPP-008Swy-VE; Thu, 01 Sep 2022 18:59:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8F5993002C7;
	Thu,  1 Sep 2022 20:59:20 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 729172B8B840F; Thu,  1 Sep 2022 20:59:20 +0200 (CEST)
Date: Thu, 1 Sep 2022 20:59:20 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
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
Message-ID: <YxEBCCA4qaMbbKYA@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-4-surenb@google.com>
 <YxBWczNCbZbj+reQ@hirez.programming.kicks-ass.net>
 <20220901143219.n7jg7cbp47agqnwn@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901143219.n7jg7cbp47agqnwn@moria.home.lan>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Cn40tdhd;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Sep 01, 2022 at 10:32:19AM -0400, Kent Overstreet wrote:
> On Thu, Sep 01, 2022 at 08:51:31AM +0200, Peter Zijlstra wrote:
> > On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:
> > > +static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
> > > +{
> > > +	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);
> > 
> > Realize that this is incorrect when used under a raw_spinlock_t.
> 
> Can you elaborate?

required lock order: raw_spinlock_t < spinlock_t < mutex

allocators lives at spinlock_t.

Also see CONFIG_PROVE_RAW_LOCK_NESTING and there might be a document
mentioning all this somewhere.

Additionally, this (obviously) also isn't NMI safe.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxEBCCA4qaMbbKYA%40hirez.programming.kicks-ass.net.
