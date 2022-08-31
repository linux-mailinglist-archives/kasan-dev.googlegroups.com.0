Return-Path: <kasan-dev+bncBCX7JJ6OTQGBBU7DXSMAMGQE4BIJZMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 59B0E5A7ACD
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 12:03:00 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id b16-20020a05600c4e1000b003a5a47762c3sf8054805wmq.9
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 03:03:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661940180; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWjWMgJ1J2S/wHVbcTQ5/2jfDT2EYSEtwQJYtn/JjEFDRsDgyrcqjP+NBoY6Ap6e1K
         2+6tGs4+XGTur1DMlYwKQSNrp6r9BM56ZNOPjP4HCDai3b4cqQeWwqQcJvlXNlsroDrS
         99asy+ru9NZyrhf6F8EujwTqagIS0PJF1tTjagdsAYiHojfD7JzzY4iTwh9UOD1F4O0a
         8Bo7pYj9Nuyo5oophELP1tvibNS9v2zhnCCgsnvNtZo1VoTKHAU8NEM7V39Kk6wAEnuw
         4vh7XIKnAy0s/eTwhPZ9JymxrBEnCCHOwE/p/nXbP3qU8SxfEntyHADnOUYAsa+twHwR
         9Hxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=clyTAMtugS86NX1oj0BEOA3A1OuvkUBitBk6+hfMWXc=;
        b=f+xRiQ8mBXGDN3YEMcoL/4N5u8PM0kPwJj8X9n7G0578BpJfN4dOHC139r8k0Ef/H5
         L+DaxiJr+baw40PeQ8bM1hHci0my3rUpJ+zkB0t+MuF3g6NwIf69vPXZo5zWKAfTNPdo
         m6dBqJ9CR/ukFLw9JENhn3VXZOEGNzmjzM2fbDiW0h/MrfWwSyZlRgE9fTLBxqdvKJQ8
         moPbwabJ+E3g6RfMJaQmTZVJ91syBGghH3EPX5pIH4g3oYUaCTssATIZokXIH44G3Mpv
         sGZ5ArIOzQAy3sUeyamPyK4we/AsaUtA8u/GVL6l8tgSVEm15ZciJJcXFvPHE2UN+1UG
         YGHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=PRBKEeRr;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of mgorman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=clyTAMtugS86NX1oj0BEOA3A1OuvkUBitBk6+hfMWXc=;
        b=Onh8ZTEx7eOQV8E4Qx67+ixrO5IQ4J+izgNo1QaioQE5dzzbtgT5Kk3O4NPFR8uWux
         vBWdbWJ6tLQy4GIkTYQbQAZu8RZVD18I4iNGgLPHNVS1J5itWlotqIc5xw+V4gC8ZmE/
         0SUiThOIj6xuVNjmQMN45BfUhDA5n2GdvsRZNLTSU2XRu+JKFaoo0QbcPDxN0q8Xxx2Y
         0BVH8mIXViXcS2Ufv2avCE9M/zMr/ts15R6LGEG33sz5d2prtO5aHVb4kcY8ymcgGUqC
         51b0ty66dD6HaXGsExpSQk+O8gauiG5M43QXVM++RzVDhC7CR+ag0+1R6823ma5quEY2
         aoWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=clyTAMtugS86NX1oj0BEOA3A1OuvkUBitBk6+hfMWXc=;
        b=eF4Bcin84Azeg7O5SX88FLhdQynx5/pJVDloX6FJ/UljrYEXa7kPsAYndP+LLyaLbA
         U415odZLgzNVy9afApbGmofjLb4f5tu6GJPfn99vK/t8G2x+KIXjR9Pc7ZB959oLWHJH
         v3/rHVneZfcpi4tFk2nKmiBIdlKmzBPKQYARkxr9FA34klvjZ4uKBkWlzFhS/EZDa8+O
         wD4BUbpLJ9lN4eYVXFyOG3cTv1Tz5P62/GHlggqawebGpbsDFwGJk+gj0vL2JPOHhRBb
         JSofUvwwAhSsIC9UxWSyo/JUTHGzvgs1R5YQZd2OSgT2rK0izpCKyLmt9Pg2hnuIW33p
         BvkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3mdrYtQNTz6Fuh6+QMRo6EMYEu/koOenS3ETKrd+c5k+4aN0WB
	Bo7WSeWpL4TzpzHyUKhTNSE=
X-Google-Smtp-Source: AA6agR4RJ509Q3KQ5Dq7ijEwtBV8XgMb/PvUChOrWDQYHYtWkEH8M7GLVEEgBfPnw2PQPZlD0mekVQ==
X-Received: by 2002:a05:600c:600c:b0:3a5:abdc:8ce4 with SMTP id az12-20020a05600c600c00b003a5abdc8ce4mr1445946wmb.144.1661940180021;
        Wed, 31 Aug 2022 03:03:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1146:b0:225:6559:3374 with SMTP id
 d6-20020a056000114600b0022565593374ls10321887wrx.2.-pod-prod-gmail; Wed, 31
 Aug 2022 03:02:58 -0700 (PDT)
X-Received: by 2002:a5d:5143:0:b0:226:de76:be7b with SMTP id u3-20020a5d5143000000b00226de76be7bmr6571612wrt.308.1661940178792;
        Wed, 31 Aug 2022 03:02:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661940178; cv=none;
        d=google.com; s=arc-20160816;
        b=EJ2JqzLHqwTNRUhB+Wx3Sdi+PET24HWjXt4mRhGHhAClGYHcqGlpCXSkXRMZDqMZTZ
         Nj9EBNOr5fN703jnP+YbOkeIeZsZmOTM11xTm4BJlSIpcsvcb+ERpX6k3LEqUFJKXfIu
         +vm/4ORZjzxJxUNb9u5c1c4FSQxBwKfBceE75eIAzqLA2BSPJMCYf/wv3LdPbPkVzj20
         oJ1s70kdpBtjIWCY7FsWKrURxwnauFQHlNkP2/Zb1X7L9D0Jxj0/VMBfOCl0PAnemDCx
         AkO2SbMk85i9PLwyGBzC99uuzDjC1SFkvEsL3deGslDlqMLKFw665sZfszEtPLXPt/+o
         gQmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=UghZOtEbbNtkuyHw6OG+q34Eguh17rpI6TW2xy+k26s=;
        b=H8v+cI0e5EfMmxA1uBsYbliDYmUl/L1ordohjtphs0qDKPZ14MrpzVFnG2yP+gzrrD
         jEdnMgDdzFIi6L8qnP/yU7BQHwewRPbWdnBK5JyBtmWSy7eP5Mh6s58Cn4NZ6tE2kcQv
         L8EIAtmGRHO6lRYcJyFC2NbU80N7EU7B5R0BtRZZK7vvi+oXez8sVIPDeFYVHxgFrpYk
         5YGIV4oGyurtOov27Lno79wLCoVZ6/poLr7CyVqhnRPguHwNO/Qvoaip0C34sIbz1Juk
         DrSIN/S9CysoJWeN28Dxl7QeC6NDeT1YasVMT1rGmK8Q2x2x+s4pHlst6+I0aIoZKV0p
         7iLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=PRBKEeRr;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of mgorman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si119229wmr.2.2022.08.31.03.02.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 03:02:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of mgorman@suse.de designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 60E182226F;
	Wed, 31 Aug 2022 10:02:58 +0000 (UTC)
Received: from suse.de (unknown [10.163.43.106])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id C064A2C142;
	Wed, 31 Aug 2022 10:02:50 +0000 (UTC)
Date: Wed, 31 Aug 2022 11:02:49 +0100
From: Mel Gorman <mgorman@suse.de>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
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
Message-ID: <20220831100249.f2o27ri7ho4ma3pe@suse.de>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-4-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-4-surenb@google.com>
X-Original-Sender: mgorman@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=PRBKEeRr;       dkim=neutral
 (no key) header.i=@suse.de;       spf=pass (google.com: domain of
 mgorman@suse.de designates 2001:67c:2178:6::1c as permitted sender)
 smtp.mailfrom=mgorman@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This patch adds lib/lazy-percpu-counter.c, which implements counters
> that start out as atomics, but lazily switch to percpu mode if the
> update rate crosses some threshold (arbitrarily set at 256 per second).
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Why not use percpu_counter? It has a per-cpu counter that is synchronised
when a batch threshold (default 32) is exceeded and can explicitly sync
the counters when required assuming the synchronised count is only needed
when reading debugfs.

-- 
Mel Gorman
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831100249.f2o27ri7ho4ma3pe%40suse.de.
