Return-Path: <kasan-dev+bncBDBK55H2UQKRBE5RYGMAMGQEF7CMF6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 40C435A8EFD
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:00:36 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id i132-20020a1c3b8a000000b003a537064611sf9416110wma.4
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:00:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662015636; cv=pass;
        d=google.com; s=arc-20160816;
        b=JzENF7M+k8M9R6sG+sdGVI59mMVesm8+215oaw73ATyFmW8Rwu1BivrUQccAc9JAKt
         /m+cjB2G+FOSLMcfGlOAO2t7rPoGUbWdy7CkaYNyut8hqP6+F2+LNoh3RUW3wCe5m+vw
         aYodWab5nolul7QQjLQeb+7cmDMDRxNy6tsXIVlYy789tg9OLSn4y4bwgDwWJLghNL4Q
         jZavc7HwooAjwtIYnL5Ce7KUpFEoAJCYiOWvv+GfDNkUFHOLpb5aCNsyq/WHCid1jFjn
         kkuQwfl/bq1gVNijMlGX/Q5pYl+tkFJNxkEK+xwmLx6+33ZMyc3LXrgT19nz4EzQZ8s+
         dwyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b01nY8v9O3dwJ/vSVZpEezQbFJUd3M29AIpVyGZ+GeY=;
        b=IBdQyaW/lExL6/9fBXkgb2mTreiLh/j9iGUKGKWTiIxpgmIGAha3Gg3PK6KovHuuKL
         pDg0ENHPAP4ll00XmAGDFEChilwMFC4YEuVabZd67G8kXc0nwHQlepBkoVIyIHqPnYHU
         lhJT7gdOiBJRGVffm07oEi/W+qP7z4ynk6jIs620/czYeW8K4jkIfDERHKkOIscz8XXp
         qQJXfLYG8H7o6p/OOvT/wGe4mj7GebaZX8/lwz+40Bu1TCsMwHPMiqWRwQiXAAN6aCXt
         NC4hAfDDxYbslFZGeOBxL76zEiFXowAcwLLO19V3nHR2ItCROjOEpS1y8EsMYiUhB4mO
         xuig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DsovPIHj;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=b01nY8v9O3dwJ/vSVZpEezQbFJUd3M29AIpVyGZ+GeY=;
        b=e24MZ0esXia7WbYV8NN3tMq+h97N/QesklurM9bmM6ns8PuabQRQD9RBs5J+1MsATE
         DoKZMI2Cdg5LPxzGy8xIGfjl12wGUUc6gPy2WFtqaQO3xn4DvK2pB6iYoBRCV19jBM6c
         hQCF4MKYtz+lx+vmC9wuWkuuZIMKw16DxOqXa0nB2gziftngegT05uhOrbi5j/+2StLS
         RrVLU2LZAg67O5luHzsEKd6310T0XdU/OAYworSMbqejRdNwWnbuUM0v7wep89Kr6K94
         dYy3Q2RBAHwoBPb8wsVoHLRXMLLHsocU125u1gNKXezT0LkKLOj7ejSXDzUZN1fV1X4x
         mCtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=b01nY8v9O3dwJ/vSVZpEezQbFJUd3M29AIpVyGZ+GeY=;
        b=7zbROKnCEThGOBYT6dXRnuGaPVSSt3K0IL8llOMS45L4xgqaGKQBAyW6ik2/tcJuzC
         fUWhaNmWry8CaTuEQPlXi/fYGttPXLzZ02lNpNJ4vz++B8jAeeDQTLXRTtBODfEmftom
         s6Rq2raK0vczhEfmbnKFGF7LH8MRDcudrsVWz9X851cK7CPyv5gmOhHhmqzdoW1wl3TX
         XX1LbzNkuNg+erSt+s0gcTU2uXMwZK5N1dTRLfBpBPdljvnWWp5b4VuT1MRCHggyC6wY
         xvFlgl0Ng8ji4vS8W0JbtEE6WzfJiklpAT0gRG5/IAmiFyMIXvvRMNQohC8oi4lvpAyi
         yFAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2fFnn8C23NlyfiWBIDR5Wpkl4DNzrFAqMH9KJhxjlP/+FoqK0R
	JROWNSwdPnXRlVk8OKLbNyk=
X-Google-Smtp-Source: AA6agR439qhPjn9aHaydBG9R5Jbq2MmN7OIwhddVKYyo/n+d85u7AAE4ll0r2p4xQOlIZka/1xPn5g==
X-Received: by 2002:a05:600c:22c7:b0:3a6:68e4:1e5f with SMTP id 7-20020a05600c22c700b003a668e41e5fmr4143881wmg.46.1662015635725;
        Thu, 01 Sep 2022 00:00:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb44:0:b0:3a5:2d3d:d97a with SMTP id v4-20020a7bcb44000000b003a52d3dd97als344106wmj.3.-pod-prod-gmail;
 Thu, 01 Sep 2022 00:00:34 -0700 (PDT)
X-Received: by 2002:a5d:434a:0:b0:21d:aa7e:b1bb with SMTP id u10-20020a5d434a000000b0021daa7eb1bbmr14538853wrr.619.1662015634539;
        Thu, 01 Sep 2022 00:00:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662015634; cv=none;
        d=google.com; s=arc-20160816;
        b=E7PKpHiT+kn2zNsybVmJnIoN+n1ip/TIeUiu7eWmeOHXs5v4JYUQbgzpqOa6gywHG0
         djxQ5nZId+WhketPu3si0cy43TtAMnaZKXSlU5TGsxQzmXsagbr+l8OftIe9765+skeo
         j/a2mHDhqo7tFW1kaiINVMV2oI/gNBF9TUuXM3dNmZHuIs6yzw1CqQRVraAYiURxAWEP
         OTTR6bDTmj7RpGfTOXUyUDzoJ/RHuqJZtjh50l+LDjF7OnNmJU0uhSpV+sV+LS5peRG2
         DuK/4P9z6kIuVF1JZ8BARRIqL9M2uCTuzBuYMZxDm9gBWOO7iI/9NszKyn9/dPcctVQs
         ZK8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lP/axgW6wVbLw99T8GY0xIMHkeiyf6aNs2WovZZWBOY=;
        b=Q51RmQ4GFJl+mmUsbXKFQmO08oVqeFydjUZHMnobI00d80/gdy+llVosDlXy7ymVAD
         xj87Eq+3d99mGUZrmdaGMRA5+nqAUz/680I/le3OJs9UtRl2gC9uh8zF55kcDxKrgt79
         yG91Y9Z9R9EY8mFkqpKi6P9/FrcuKaz7Y3sOLsw6LvXrvzaPKryL5Jbf0BZZ95B0pCRd
         ee7IgRanHsadUAsx52DlRguQl6Lo3SpmEuIhsxOLJIuyNoeVtm7LVcME3N1OHM/N9Slo
         a3pGn5ioghzy/kpkb2FuOc2ysO19jyG8WnTR8l4+Cx66TJxcSk7wDSz/MEWBQ33AuhW3
         F4Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=DsovPIHj;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ba13-20020a0560001c0d00b002206b4cd42fsi534620wrb.5.2022.09.01.00.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 00:00:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTeBY-005ocA-Jf; Thu, 01 Sep 2022 07:00:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id CF2673004C7;
	Thu,  1 Sep 2022 09:00:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A749520981381; Thu,  1 Sep 2022 09:00:17 +0200 (CEST)
Date: Thu, 1 Sep 2022 09:00:17 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Mel Gorman <mgorman@suse.de>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, dave@stgolabs.net, willy@infradead.org,
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
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxBYgcyP7IvMLJwq@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831101948.f3etturccmp5ovkl@suse.de>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=DsovPIHj;
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

On Wed, Aug 31, 2022 at 11:19:48AM +0100, Mel Gorman wrote:

> It's also unclear *who* would enable this. It looks like it would mostly
> have value during the development stage of an embedded platform to track
> kernel memory usage on a per-application basis in an environment where it
> may be difficult to setup tracing and tracking. Would it ever be enabled
> in production? 

Afaict this is developer only; it is all unconditional code.

> Would a distribution ever enable this? 

I would sincerely hope not. Because:

> If it's enabled, any overhead cannot be disabled/enabled at run or
> boot time so anyone enabling this would carry the cost without never
> necessarily consuming the data.

this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBYgcyP7IvMLJwq%40hirez.programming.kicks-ass.net.
