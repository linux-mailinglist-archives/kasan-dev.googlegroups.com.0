Return-Path: <kasan-dev+bncBCX55RF23MIRBTMKYWMAMGQE3HL7AGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id ADFCD5AA3E8
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 01:50:38 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id f10-20020a2e9e8a000000b00261af150cf0sf245460ljk.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 16:50:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662076238; cv=pass;
        d=google.com; s=arc-20160816;
        b=elFH0jnuMQOs1S2mJmGR8vLaE7X7VUwPFZCxPwxbmySkRsmzYdgWIFZtnVbbipJhi4
         bc+69Ea4M+qb/hjBZxUEDOCWwZ641DpCIv3DCMWKBnJTKuLtMvI0NsdEThCjeFnvftwa
         NHikMtn1tylV3vX0SMMqozd4s83j07cu49Qlyf1yAVoFgCURux0DgWUEI2piMFd4gi2z
         x5T+CAz8oj9pgvQWamAOjJ+r6wxDdBTTR/tT1hl2rYR7Revzg0A+vb6lQiCwcjKr6ImQ
         nYCLb1gNVglPOqxq+6/Q3gN3K2cXjb7Q63eGH33BvfHW+4ehHRYxEFLTUUDbeVUm7WpI
         Ffow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=paO2SLzgxHGKCE5jHfcT/pjT3kp+Uoq5KAIOnCgxYlo=;
        b=NfqQ+PcawUAi9+zJxXbbh82UprIOAkzgdDwmvSWjUSB4GCw6DiMiUf9SFb/OG5t3wV
         vQ5WJEmFny4PgJiuZQwRi1ijvcZJCrE8rbVRS/y07KquYVtMoWrgznYgVYb72dJv/bzl
         ecXwMQKvbeyDgxeG7JbSYvUZ1SQ8MiZejX2jYrmen9pspeit0N72PCug7Uu4SBZpWEnA
         Ha+vKu8Gk8lkFuJ8chx4qAQFJyRQEM5GGInwZNw+Bbm4qGrSwfSbdr35d13lP0GcNZhA
         po8hmACB3YtVBIvGh/bO9L/hGW5LAexfe3JGy/6DLf8sKbD/5trSI5jvPxj0/XXPqkOz
         Yr/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sadkhbMj;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=paO2SLzgxHGKCE5jHfcT/pjT3kp+Uoq5KAIOnCgxYlo=;
        b=c5A6Ei8WeoZUgBzQn5qZSGBeIjST5CNEBUiImUEmX/9PiYPzPeIOrt5vNdBh1GmXjH
         h6WeiGUPGX4LQshG0iRl+sacQ4jRgoxvkXa4MGxRgwW7fkV5deeEtLVDjlDuhkKEAKvL
         ceGIE1RfAVw+CKmwIWjj6yr0AUsiAMoOtLL/moi9oJYAfUTiTyS0zk1afMBPHdgg2C4i
         FPe8eF73w7YmKp58N2Oi2/rCuqBK+c4nKxeagl7+Un+53/mwwvkQsOVpCVK0bFg02JmM
         IZlxav0uyzt8vUmjjZatSs1uTmRkQhmqG18ZxO5SFqVipWYTRbj/JK0I4BeW8eFjKV94
         1mUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=paO2SLzgxHGKCE5jHfcT/pjT3kp+Uoq5KAIOnCgxYlo=;
        b=JMAxfhNHsA/SjD0QnsUdzYW3EMfBMYPq6qgt/gg8SuAffB+KSl7SEisG8fvo2UV2MJ
         baeMxvEXlKhErL8fXGsfnh6CiTPgvqUcjSn+/20+/9cFK+gWZGxIuJvmfhQkYnQCzGaC
         fcVEV+EGDI5GhRv8em0LkdRiPaN+qm4EbyxIf2/RlxV6+M9Eipzxl5Uz8BYbIJTZanWx
         B0kqD6p+38UOLSBWrqDnnWS3gL1MmItrvrWIEL8xnuxGdlGwDXQWnrwvBz7Y6pnT0kJK
         N0II8MyeYsEcdG/wiCKx5pm1VGI6Xo8EGV/7/X/CQV5UERmAjUDWTbd1AozSmu1MGdBv
         3pvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo39EEUYwqKH/LoYAxZpawCyNy1IPdBRCp6v/okCmq4GwgXXekHj
	gRHNXdunhgdPLMe9vgbuYnQ=
X-Google-Smtp-Source: AA6agR7AzDDduaAIcMy6I14HYOuyBQlnatMNU6MVEXaUxxTS1vITC8GKJKa+fns14FaxYhkphv4ZMw==
X-Received: by 2002:a05:6512:318d:b0:492:348c:5cd1 with SMTP id i13-20020a056512318d00b00492348c5cd1mr11010613lfe.94.1662076238028;
        Thu, 01 Sep 2022 16:50:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:80ce:0:b0:261:ccd8:c60 with SMTP id r14-20020a2e80ce000000b00261ccd80c60ls555306ljg.10.-pod-prod-gmail;
 Thu, 01 Sep 2022 16:50:36 -0700 (PDT)
X-Received: by 2002:a2e:88d1:0:b0:261:872e:b09f with SMTP id a17-20020a2e88d1000000b00261872eb09fmr11055636ljk.375.1662076236922;
        Thu, 01 Sep 2022 16:50:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662076236; cv=none;
        d=google.com; s=arc-20160816;
        b=VgrspnvGn9PwYCOpPdMDas56C70KFYtnpPw2y4fff7eTQHu2NXqHUkT2zu+pTsGxba
         4OHzkOl2X0yxRWpr3io/GNUr3inCCrwkaMnveXXQYyxmPJ6Xvj3TCDp8PwsNUjjrL2sc
         MpmNaOuTk/cJioyvFsonpj7lP2Fu31Jc9kCUrlBbLYQeLzE59NPPkPxdsVD9y9vc5Ila
         ALSyiQBSA0Njncc9NqHTBm7P/21zEBImeDb6mfrGIhxl5is4UfFs/Z5F+UhOhC8E/pAV
         MnMbFOpGlPuSnteN5akpAjGQNfuH0XZAvse+24Pnc43iA5ryAhxM2QcdDPkwrgTezrQm
         36Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=QeZ3ywOHO+ue61+bhlHhVrcPOQCnKvUeLhu9G4GOySc=;
        b=UKAuaJfJ7DPj/pI/mp6jOsPVxBu6yIKrIuSs8s3s+vo4hHpqmzI8YiMtLrByNL8nUc
         odq9y/V2P8Mce1Az62AVWV8eBn78TLwyYgLlO3uLg35UTHxWvD6U8WTygeoBdg8aAQgp
         kRobgLxC8KqpVzg79lVnVZYQu3Gqle3d3dqNrS5tX2Hx2P7oLxOapFn/d6QpAWQ1i6Sw
         f9ICUqBr1oavCmH+0BK1UGV6KHwEEyQA2Yg6EdUvSCdq8dZw5+3fzDmZog9F1MZ97Ebl
         jmMy0HNv4N+370yOUcJwnsGmHLC/pFbmySEPKQUSHDQliSOc8IziLukH4FG6NK65v00a
         jVBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sadkhbMj;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048b224551b6si17682lfr.12.2022.09.01.16.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 16:50:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 16:50:10 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de,
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
Subject: Re: [RFC PATCH 16/30] mm: enable slab allocation tagging for kmalloc
 and friends
Message-ID: <YxFFMtvI/J3VN3pl@P9FQF9L96D.corp.robot.car>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-17-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-17-surenb@google.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sadkhbMj;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
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

On Tue, Aug 30, 2022 at 02:49:05PM -0700, Suren Baghdasaryan wrote:
> Redefine kmalloc, krealloc, kzalloc, kcalloc, etc. to record allocations
> and deallocations done by these functions.

One particular case when this functionality might be very useful:
in the past we've seen examples (at Fb) where it was hard to understand
the difference between slab memory sizes of two different kernel versions
due to slab caches merging. Once a slab cache is merged with another large
cache, this data is pretty much lost. So I definetely see value in stats which
are independent from kmem caches.

The performance overhead is a concern here, so more data would be useful.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxFFMtvI/J3VN3pl%40P9FQF9L96D.corp.robot.car.
