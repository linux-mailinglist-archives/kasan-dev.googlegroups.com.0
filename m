Return-Path: <kasan-dev+bncBDBK55H2UQKRBUNTYGMAMGQEJE4SSRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DDAD5A8F32
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:05:54 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id ay21-20020a05600c1e1500b003a6271a9718sf9453773wmb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:05:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662015953; cv=pass;
        d=google.com; s=arc-20160816;
        b=ebjdv45TgvlXp+yfY2dDu8mRFW8ubeB87sUG8o6+uLIErft+2KSZmqicVl/FDXe0XO
         xlDG+3UkuFZYEPIpm8mK5dCzlkj57NQqHIihud7fhStKLQ+VXUcWbSoPHSoKyi1vDQRl
         HEgMEf1fI8ux6v2AdwQtP6G7lLL3KCOdg7IUlfhtk4PsutJofd3ZHdHpifPVlCONHkie
         50ORQwaxJKsZa4FClX6nSOfAEIq7ZKlmP2m8T9LRHYxb7VS/tXCk37AMgmSN474Jg4hj
         AWYoPe2lkU7hfa/CCu+U1yskIYtlBF95zbvkmOGwK1xR2fjoQ5zfJTLyfZ5fP4DMxQ9K
         Pxdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CkEoAcWC7TSR6jJlLJYQcENcGgJEC8TFDJ038sHq1TQ=;
        b=D8hFnp/JuvDlyHjBeqOw5SXNliqTjXp0/4KfCg56zaHM3NspW+CFKSc8tIK1sS2Cor
         kvZvJzEme7+ko3PeLBrEx4hkUxmGh6OUoCf2oVRkAPlish3uh3CmL3qlfUp243TqaoI/
         SsPk3oO6c4c8t60SfSz3rnfOFoKHSOCw9R6g5O8nTSW4+pVEuadaT5W85ChQM6ksv6Wx
         I75pAiY7JvO+4CxirhusCWzhVbnCpXnvmuMiew3WqNW+DzqRx1zMsn5SGBpSSycDkjsW
         DN12hXlTwJ3aNHCw4ZSXfa09yTMjyvUH9xiUSTJDf9Z8dxgn2J//LBQngMt9a3E3MZpx
         3s3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=CRTVAsmA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=CkEoAcWC7TSR6jJlLJYQcENcGgJEC8TFDJ038sHq1TQ=;
        b=c3q2VOrTTeL3DMFbofeQf7T3/i4Yqcpbs/WP0/NWalvlh3Ma+O2mqWJRxmrXGzIeMY
         dQ+VA9M2hfIW56pYbmYZX2QOVCjgv7X4Cdks9v2r7atxFmoHjlz/+gseWbCm9r4/oA1K
         CXbOUoDdQ8Mi4rjnNUQ3rDm03liuE48gqmP34oc459DWkeJvFOp75t9mTCcCfi2IHDJh
         r0esD9TFCAHqMViVYyJjD4j1njsVLznUZAmSsBXtVxgKcnOX5mSNf7tpRnolS+E4y8ph
         tUzohPzwXBGF+hoNa3GUkyrCD856sHVCqjUEtWHPt5ck3OMQuIBNGa2GjmZh1HvFzG2s
         0k7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=CkEoAcWC7TSR6jJlLJYQcENcGgJEC8TFDJ038sHq1TQ=;
        b=pvE61Zt3T3aiNbp21jM1FCJ2rLCFohiixx0HQY3E52TvizTfE3cn5hi9aCxa+aOgx+
         PkcOGPESwa4gXiSJyxpMlTJ0wEn3DSG+C2sDaW7fYGyVMBiYfCbXx5pt/6Ia0jRR4Lcd
         f63u8IRQcv9igRHYxE0rUH8XqY+/kZR5411V6GWINUYvC7CiOzLh+hAAEvFFlOdM/kek
         eLaHqU6at4hEEskNMUwrYOn+ftlg51hhOUUMceqlqVqo+W5ksEf0tEjE5qMkz4B8BuTs
         LCzkqI1V9CLnxOeRKyl3ZZ+vJOqWKDDTXMAD78CYUuKm6m775Sc+EUzit2pEax82lX/T
         X8Sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1xuCgr+LWyjs5sGC4N5ZBAZ3lw/i5fT9DqXxmk/fsnlWJdqNa0
	9VgACKVkwaG76U2vzdy6Suo=
X-Google-Smtp-Source: AA6agR6I03lt1rytmMHUcoW79sO4IT5ec+RgE3AYnqJn5vAH8ZAbXfywSzKDHS0S4rlOrcaR6nGnKg==
X-Received: by 2002:a05:6000:1292:b0:225:4a8c:3ad with SMTP id f18-20020a056000129200b002254a8c03admr13296725wrx.684.1662015953536;
        Thu, 01 Sep 2022 00:05:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls1477804wrh.3.-pod-prod-gmail;
 Thu, 01 Sep 2022 00:05:52 -0700 (PDT)
X-Received: by 2002:a5d:684d:0:b0:226:e65e:56f9 with SMTP id o13-20020a5d684d000000b00226e65e56f9mr6081510wrw.11.1662015952302;
        Thu, 01 Sep 2022 00:05:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662015952; cv=none;
        d=google.com; s=arc-20160816;
        b=gYz/ToiyH9drKl3hXWzl4gNBzodVxlpYNDSsC2spv0FoIWWvRsrO+zwMk3dqPxPtJI
         nwhyQTUZ4IGiOe4simaws/FlGD2ey67eFW68+UOz0S8NOCdzD4aDJf0LISOypqT2WD6s
         l27UmqVPRHy6dDk0/FHMz8qAFozF4ex55SbD5dkXHgNTzfaOT4Suwhar4CSmDUiFaHYn
         bbVwZl1qfXwriJoCdkNwXtOUr9AyZz+gOzUtbW4UfPNCUeMzLWbSwudBnlM0uXFgsk6P
         Ot85b0K296DIkpT6dY6u6UeuudjCVQlF/3Jbqz30yD2lBN9cjAi/u2XpDdEXHmjvhQXO
         q07w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PMcMlRof4aBmW9ZRc+eOO/2dgQwguo+jd6/zOIwkXz4=;
        b=ifcNXOqMzitQSagUYd9/0OpqHKaGI6JWWBWYjbDst7kwnIEo+DAXj2Ys7Tr8W6JpNt
         nYXhezU15yhkPT3lw8CXpZ6/6LRLSJfT/3bkMQwQ/bPZAul78g0P0sjpelY5SESnG2W4
         0hyk9jqYvrHiNKdth8tkfEUGaVFUsp7J32BncnlQb6vYq9bdLl7kytpsyC1Q8kWtf5Vg
         wZKXRCWuCl5kSWxoGDPVZN6DddzMa0nArZHoZCir47+OGyISuI/s/exDlzLXsg1XwvrX
         JqPecrEunScpM8M04LTAm1i1rh83h2ae07q5wszPF6UjMjFexgTf4m8aWl3+WURT7CCz
         7HKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=CRTVAsmA;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si301143wmr.2.2022.09.01.00.05.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 00:05:52 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTeGh-005oq6-Bs; Thu, 01 Sep 2022 07:05:39 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 417C030041D;
	Thu,  1 Sep 2022 09:05:36 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 110AE20981381; Thu,  1 Sep 2022 09:05:36 +0200 (CEST)
Date: Thu, 1 Sep 2022 09:05:35 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mel Gorman <mgorman@suse.de>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, dave@stgolabs.net,
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
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxBZv1pZ6N2vwcP3@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <20220831155941.q5umplytbx6offku@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831155941.q5umplytbx6offku@moria.home.lan>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=CRTVAsmA;
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

On Wed, Aug 31, 2022 at 11:59:41AM -0400, Kent Overstreet wrote:

> Also, ftrace can drop events. Not really ideal if under system load your memory
> accounting numbers start to drift.

You could attach custom handlers to tracepoints. If you were to replace
these unconditional code hooks of yours with tracepoints then you could
conditionally (say at boot) register custom handlers that do the
accounting you want.

Nobody is mandating you use the ftrace ringbuffer to consume tracepoints.
Many people these days attach eBPF scripts to them and do whatever they
want.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBZv1pZ6N2vwcP3%40hirez.programming.kicks-ass.net.
