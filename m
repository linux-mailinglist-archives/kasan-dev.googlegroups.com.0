Return-Path: <kasan-dev+bncBCS2NBWRUIFBBU534CRAMGQEB7MIPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D9FD6F9C0C
	for <lists+kasan-dev@lfdr.de>; Sun,  7 May 2023 23:53:24 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-30629b36d9bsf1370629f8f.0
        for <lists+kasan-dev@lfdr.de>; Sun, 07 May 2023 14:53:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683496403; cv=pass;
        d=google.com; s=arc-20160816;
        b=tAXCqTWid0RYDHPpn1IDBoho30bBDAtiwFypA/NNMey8hDmGFpClU/MGgFIW8rr1UY
         T8aZq5gCp+q2TAC2xuIPwwEoOqaex1YzoaJg9fTb8I+/0PDuFxtj58VyWDpQNoP7E3qi
         PfGmbuHpk0xxfMOyU7+maDaR4NEL9T1EFXPWC/4OxtTTSueVpTRN0ySONM44ahHWx4KH
         EJPoZ99tIZsvap7BG3ehZCMw+7nTwMVY39MmVUFLUoq3CwmaZYkTR7Zkz1GTVLmwvr3f
         dbsOLhOfOjyE4qkk9oMlcMU54lTtNdm3l2yY6i4dPSFwa3iPnIstXRkPA9f+fVTg6VFA
         NypA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mvUKzZorX6lSZGQxqWtKy078PRaBZjOtQlj5VEv0nBw=;
        b=CIZL7TTSNLBV2o2/g3gz0ORvQ1EwkxolFPaEE2W5fe/fzpVPW5Pg9ZAqeSuju4+lYT
         bDZkzvwFNl+I5JsVoUYQKK9fNWxzeVWlu3qs/G0a2QsTZZl84KSFuHTZ2U7pjsLgq3On
         BCHkT8eBrlAZsXVNKLbPtx4c59r1awMyvTxRPjTg81lyJDObur4gMOju7WrydYgeKd4k
         j4zzAZAnqFpJmPTAvP6ESkR69qzdQNKrylhQjT1GBJcm4gqiXQyfmAQDjoWAIgREl50+
         smtaP4sIP6LDoapqgUzurelcKA652t5KwZi8vhbhuXV4GLC56qgy2g6uWXuAY2aHQJMz
         TyhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aZwHReiw;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683496403; x=1686088403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mvUKzZorX6lSZGQxqWtKy078PRaBZjOtQlj5VEv0nBw=;
        b=jgKohfkEPJMQ2XDnAEvt7NeNfeC6i1w0vyXGXoKm2wdK+VtBoz8+HGn+QS6EdK9x06
         14mwAJaPSO739PMM5Kwv1NVVLQGXpumFNd0kXG9GYehukNR2ItKIqVa6YoTdVTKwkc9H
         p38u5hpNFSY3v3dcYalkGLYwX5rtJ/fM49uwAIfiAqZElElQ0C1ePMxhn/mKFe7KcH0/
         NXB+0T+IPoO7RiF+Jgm3ldhYFOdYkhhSzWzAXjZU+p6CqYSt7XWFLzND/1arfjQMkths
         IjAH7Yp6P4rfksMsP5WG7L9Yr3VEcRHzaYKsFrrQ1NZX76WcfWHNKyU7L5YUd3VQAlI9
         HTsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683496403; x=1686088403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mvUKzZorX6lSZGQxqWtKy078PRaBZjOtQlj5VEv0nBw=;
        b=GTMJTVVfejPs/PjtnpOWTqCwM/JU+YFX1fN9k71EXz5iT0jx5qFT0+5WyLJJxAnO7b
         N26mn53r5mKaX7bh/6zZJtPLdRmwvydO7+R9wHdgJnZX2sF7AHyp5UDoQi70IpVZzBYu
         AAlUtnAcQLgKohRwoQTxHRvOyYi86LVxiddAEbaXjvnL9+oVm/JpKdYUt9CuX0KEIFCb
         xonN0sijKgHqyWBJTW3cE4+Ck4oq/JUJwWQi5uxBMbrwBff9IcNlOIF70Dd9anUq5LwY
         C5MUSxW9z90N92ZNXS4mDHAZ9o4lzbeattYRM+lAX4BfZxo+zDRH5H142WD7jhNm/Jh2
         19hA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDz5oVOQiL6i6hUuuG6M37gJ4IK8s80oI+9BYfTEFNrTOyi9osw8
	y4AUDE8G6axVsT4nj+tPvZo=
X-Google-Smtp-Source: ACHHUZ6sIwsokvYYTWPkmUSGLRx1SMSOeyWvE9c0yfNdWzUkis8Rl65jVxPxerBo6Cc9Y7Af+EbwNw==
X-Received: by 2002:a5d:4a51:0:b0:307:7cd3:60e5 with SMTP id v17-20020a5d4a51000000b003077cd360e5mr1349278wrs.5.1683496403411;
        Sun, 07 May 2023 14:53:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34d2:b0:3f4:267e:9f with SMTP id
 d18-20020a05600c34d200b003f4267e009fls122660wmq.1.-pod-control-gmail; Sun, 07
 May 2023 14:53:22 -0700 (PDT)
X-Received: by 2002:a7b:cd09:0:b0:3f1:80a7:bfb2 with SMTP id f9-20020a7bcd09000000b003f180a7bfb2mr5683009wmj.32.1683496402085;
        Sun, 07 May 2023 14:53:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683496402; cv=none;
        d=google.com; s=arc-20160816;
        b=EMUpcXUHd4/7dzHCdeBP4BaC292zZPqUHfdArDOHxYwwwq6IRWea9t2l0Q0NQ3uxXz
         sEh7aRU0ba3pfOZDoFqjb035ohJLjLJBJJqGC23JvxrgK0swXYr+D5kgWAwXCYb7qH8A
         1v2FWlGg3dgr8zhbS/CX1mWtvKokuP0D62KJgdL5HBeyewD6Bfb9UxEsjCQ4zG46duoA
         lyOsWg2c/pxqvxUhBfiabnzV6O24xUwZLQfL7jydcDu1MPfB/6D7O4cepFnndDCUg2Bo
         uUIL/nACCbNhKzD454eFm39SpEQE432XUFI67dtGPtiwm3PnbZeSQXR1dw7i1A0x/y90
         5AeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=40BqnBW4/FlB5TIf35hpUldm+3Y4zBbG09TnotWsOUQ=;
        b=DfVXN4rVYIQZ4Qi8dxrtonhho2vZz6lCYyOZW0059Lsg7VHCuC7tZeqzOk4JqonBXS
         u0jRD/illVvBSa62dngv7xZrDvqXVakrO/eW5ACRGhsQjXdZpGK/FmijxIENbM1+qnkC
         OcggrejEKheWi4kWPkwKbSsKh4PwLLZ+d4+0ZoxZujE4HY+7Y8uvZm5HLuy5eGqfITnG
         dkrSznWKxRBMEHcBgzt7SqeZFAQIFTaJCn+jXnlRGFP7V2hTz68i6+V3txEABwKOi2ln
         l4X8N3jpPCl5LJEoxgPNqWbzbTeIpNC8fA55kRugYdN8o5AIpuxxxk4GcPG9BRLqI4PT
         LM+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=aZwHReiw;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-42.mta1.migadu.com (out-42.mta1.migadu.com. [95.215.58.42])
        by gmr-mx.google.com with ESMTPS id ay23-20020a05600c1e1700b003f17514c7b3si813255wmb.1.2023.05.07.14.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 May 2023 14:53:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as permitted sender) client-ip=95.215.58.42;
Date: Sun, 7 May 2023 17:53:09 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFgdxR9PlUJYegDp@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <ZFfd99w9vFTftB8D@moria.home.lan>
 <20230507165538.3c8331be@rorschach.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230507165538.3c8331be@rorschach.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=aZwHReiw;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.42 as
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

On Sun, May 07, 2023 at 04:55:38PM -0400, Steven Rostedt wrote:
> > TL;DR - put up or shut up :)
> 
> Your email would have been much better if you left the above line out. :-/
> Comments like the above do not go over well via text. Even if you add the ":)"

I stand by that comment :)

> Back to the comment about this being a burden. I just applied all the
> patches and did a diff (much easier than to wade through 40 patches!)
> 
> One thing we need to get rid of, and this isn't your fault but this
> series is extending it, is the use of the damn underscores to
> differentiate functions. This is one of the abominations of the early
> Linux kernel code base. I admit, I'm guilty of this too. But today I
> have learned and avoid it at all cost. Underscores are meaningless and
> error prone, not to mention confusing to people coming onboard. Let's
> use something that has some meaning.
> 
> What's the difference between:
> 
>   _kmem_cache_alloc_node() and __kmem_cache_alloc_node()?
> 
> And if every allocation function requires a double hook, that is a
> maintenance burden. We do this for things like system calls, but
> there's a strong rationale for that.

The underscore is a legitimate complaint - I brought this up in
development, not sure why it got lost. We'll do something better with a
consistent suffix, perhaps kmem_cache_alloc_noacct().

> I'm guessing that Michal's concern is that he and other mm maintainers
> will need to make sure any new allocation function has this double
> call and is done properly. This isn't just new code that needs to be
> maintained, it's something that needs to be understood when adding any
> new interface to page allocations.

Well, isn't that part of the problem then? We're _this far_ into the
thread and still guessing on what Michal's "maintenance concerns" are?

Regarding your specific concern: My main design consideration was making
sure every allocation gets accounted somewhere; we don't want a memory
allocation profiling system where it's possible for allocations to be
silently not tracked! There's warnings in the core allocators if they
see an allocation without an alloc tag, and in testing we chased down
everything we found.

So if anyone later creates a new memory allocation interface and forgets
to hook it, they'll see the same warning - but perhaps we could improve
the warning message so it says exactly what needs to be done (wrap the
allocation in an alloc_hooks() call).

> It's true that all new code has a maintenance burden, and unless the
> maintainer feels the burden is worth their time, they have the right to
> complain about it.

Sure, but complaints should say what they're complaining about.
Complaints so vague they could be levelled at any patchset don't do
anything for the discussion.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFgdxR9PlUJYegDp%40moria.home.lan.
