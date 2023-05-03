Return-Path: <kasan-dev+bncBCS2NBWRUIFBBC45ZCRAMGQEEBZVIAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D9AC6F51B0
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 09:34:36 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4ef455ba989sf2785746e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 00:34:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683099276; cv=pass;
        d=google.com; s=arc-20160816;
        b=qzJZxgUb+7B3nMLW2Sz+HTNCp5aLNUXFtHk+NgCdOcpFiYf6PlsZEzq5TZHdGw5cM/
         /8rTVH69Txy6neb3tAYh/eSkXKjnV6zVsYo+LDar4oEFYSjJx7ZGiDGd3sp/QZj64omh
         DQlbJc2lyxSUzo3I6x3QXicm71VAEBt/qCWOThS/xMBg0rtVzc7fKv6qaEZodxrk/ayI
         Qm6fpE9fSIgcydosqryDZEJHtgazjNRMoEr4KF+llf2KmLAX1OpbFY6xWohdeEAaz2SQ
         wItz9RaTgTULxzwUCSftlBrVIRBNNznf1beHsIUG87EzWLQ8x/3MOf5QaQkFjar+AF1G
         /QZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kLxfYG/o44pmfI2YO83QhQRRgulqc+NXCES8DNKjhzw=;
        b=qsco611biMzXCASlFxnuTjfM0IkhY1uGOrI3TcsQ6l0g1aTrX+e9M9YLStMPz6+GY5
         FK3ESH26AsODHstt6T+K7EBKPDnmZG2DO71RtAnyKCBpoIt1jJ/8/5xGwTtNKnfVp4Bs
         oBz5rBboL45o96Wh+lLXl2q8hnCLhAORBKIaAcaEgyq9IPWfFMI5nJN7i5SNlgPCVZVu
         tZ7uPGKqiyFIm+9gjIH7I7t9qIu0g6Hb8Qdc2nQpilYz8jHNQg08YXM6Zbu6aRHnizdh
         kEc75fCmLx+9jHsggF5k6kICLXxgJXk2Tf6VkGGkQbCGT3/Q9E/4+vWKiHO3sHgY1M3+
         oU0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="bGxN5mp/";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::19 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683099276; x=1685691276;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kLxfYG/o44pmfI2YO83QhQRRgulqc+NXCES8DNKjhzw=;
        b=dsINdZ+UztMnQwhnR1G7egxGJL7iTuAap1j7yMilSOVixWml+OJ5pGUEdlhUNrSkKP
         InUC5FATfvE3EbTfNE+Or//bnnH6V9f9xJr5vMFpkpjUsFo2dvc9KSyGy1iR8JtkqAjR
         5U/XDm17IlJmyP1trFMcBdNDzhrJTF+s4dccHgcystO7IP66JfIV9n2lcIPtoN5SXVK2
         bSaXRsuwzKNtXvztwTGogZZ3BxCi5ZY8dMV6Sfloa5UtP5th1t/d+wk0AC9hZC5nNmdw
         Uxiu1Oe5ipFu0NOOGJ2Hb9HAr7Ur1zmVJFITj6KVu8NvHDHIreTAnDr3XcywNaGft8cF
         DBFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683099276; x=1685691276;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kLxfYG/o44pmfI2YO83QhQRRgulqc+NXCES8DNKjhzw=;
        b=Xl+CtN2C3rt6YZsG82AAEUogBJm5+yQ0jglfhZCntkJnGd3iY85K0BanB0016NQyFa
         lxNAO73CZbmfmOLu/smlqOp3UC9YBOK4F3gydR2u69F4HcqMMs2FdbMZXV4HPVG8PuU2
         epCzDSEaxWmRS4cg4qnP4/TN+wRzX9/F1W25dKyZ7E9f85gRIbv1FSUy6fTirdyPg0pu
         P4Gxt/5nc9kOJlNsDEYetchn4Ujjp5Ft8PfrzU3XTQKiW/Vi+Saq5r4Ss01scaRGvAor
         fCvoUVzIp/cb+ltE3gkDwVtLQvcP7BiGWUJySuvbJOgiwXuqsoBoXfc/Olybh5EVrRYY
         HxxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDz1+MXFFAoj9zgcaXJ3d8wAdW9eaOQ+WkUniTSkkv3gogOtnTIH
	hql7IYjpqphgI6y7cfASShE=
X-Google-Smtp-Source: ACHHUZ7QcBRA/8dzFZeO0O+vG/7v1G6LG4/MUoARFuVmgFpK21f1FSLc9USyaCc+40Mu87MG4G68sw==
X-Received: by 2002:a19:f60f:0:b0:4ed:c79e:790b with SMTP id x15-20020a19f60f000000b004edc79e790bmr581922lfe.5.1683099275591;
        Wed, 03 May 2023 00:34:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b15:b0:4e8:c8b4:347a with SMTP id
 w21-20020a0565120b1500b004e8c8b4347als22206lfu.1.-pod-prod-gmail; Wed, 03 May
 2023 00:34:34 -0700 (PDT)
X-Received: by 2002:ac2:5fa4:0:b0:4f0:18e2:c0d7 with SMTP id s4-20020ac25fa4000000b004f018e2c0d7mr830382lfe.60.1683099274258;
        Wed, 03 May 2023 00:34:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683099274; cv=none;
        d=google.com; s=arc-20160816;
        b=EU2hDbQ1H4waiTQNQ1aCet/DHDwc7l8tN5Jfa3hycW/vVpMR9sCEFXOszcg98lyhKu
         7vTEE19Ci9tW1vSvz4gD3pkDu1eju/VOidwM34UJzLc37uKiFks5/fEk5txOk2LbrNxk
         RERA82OmprUouOYplUhc1pggxtw4ywGvDIiYZi+t7RlsRvuR6cc1xlW9KMcF8L4HZdvr
         vpizSpi3Qeyc+0syRIhCAesuvqL2ESnqWqXfFYO+J/yU7PfVp4mGNC7O1a2j2AB1vuGk
         5a7yfa5xDeV5gXe0bCNdHvi3o7OLbl/JrAPGmV6st/5V7KzxZYplLmsAKQTm6I/RdnoT
         TaRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=s9EZJlB3VZSe4j+j4v+6Zbzhwi3+mz+obiIs+oTi9qg=;
        b=FkE0Emo7SDuTJanVOCtnABNS+wyI+VTf+hnnK63f7GxqEbMxJTPE4YNFzgmHPXgLNq
         FtCQxFNFXbWWL0K7Ra1ljQPNkUsoK92Pjq2WlzPgDH0tzvG+dx97BGZIx0TXP+x9IId2
         wGRWhtG3VxLUrkIH8HtInLQnEBKmgGIlHvN41gFGYL23LXsREvZa6tMThBxkw8DLeYGt
         YdermCg/kxNffxLnmj8gEKhbk5gVYtBMK2Sa9pth8JjQuW/twilBlIIsUNSpODRDulDh
         00EJoGkwvr/YU3Mqh96H09/EnOIZVD1b63CGvfbo5kg3HirR8zNoZPKKHLdqjEXxIjJQ
         A6uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="bGxN5mp/";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::19 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-25.mta0.migadu.com (out-25.mta0.migadu.com. [2001:41d0:1004:224b::19])
        by gmr-mx.google.com with ESMTPS id h6-20020a056512220600b004e9d34ac318si2083965lfu.5.2023.05.03.00.34.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 00:34:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::19 as permitted sender) client-ip=2001:41d0:1004:224b::19;
Date: Wed, 3 May 2023 03:34:21 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
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
Message-ID: <ZFIOfb6/jHwLqg6M@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="bGxN5mp/";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::19 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 09:25:29AM +0200, Michal Hocko wrote:
> On Mon 01-05-23 09:54:10, Suren Baghdasaryan wrote:
> > Memory allocation profiling infrastructure provides a low overhead
> > mechanism to make all kernel allocations in the system visible. It can be
> > used to monitor memory usage, track memory hotspots, detect memory leaks,
> > identify memory regressions.
> > 
> > To keep the overhead to the minimum, we record only allocation sizes for
> > every allocation in the codebase. With that information, if users are
> > interested in more detailed context for a specific allocation, they can
> > enable in-depth context tracking, which includes capturing the pid, tgid,
> > task name, allocation size, timestamp and call stack for every allocation
> > at the specified code location.
> [...]
> > Implementation utilizes a more generic concept of code tagging, introduced
> > as part of this patchset. Code tag is a structure identifying a specific
> > location in the source code which is generated at compile time and can be
> > embedded in an application-specific structure. A number of applications
> > for code tagging have been presented in the original RFC [1].
> > Code tagging uses the old trick of "define a special elf section for
> > objects of a given type so that we can iterate over them at runtime" and
> > creates a proper library for it. 
> > 
> > To profile memory allocations, we instrument page, slab and percpu
> > allocators to record total memory allocated in the associated code tag at
> > every allocation in the codebase. Every time an allocation is performed by
> > an instrumented allocator, the code tag at that location increments its
> > counter by allocation size. Every time the memory is freed the counter is
> > decremented. To decrement the counter upon freeing, allocated object needs
> > a reference to its code tag. Page allocators use page_ext to record this
> > reference while slab allocators use memcg_data (renamed into more generic
> > slabobj_ext) of the slab page.
> [...]
> > [1] https://lore.kernel.org/all/20220830214919.53220-1-surenb@google.com/
> [...]
> >  70 files changed, 2765 insertions(+), 554 deletions(-)
> 
> Sorry for cutting the cover considerably but I believe I have quoted the
> most important/interesting parts here. The approach is not fundamentally
> different from the previous version [1] and there was a significant
> discussion around this approach. The cover letter doesn't summarize nor
> deal with concerns expressed previous AFAICS. So let me bring those up
> back. At least those I find the most important:

We covered this previously, I'll just be giving the same answers I did
before:

> - This is a big change and it adds a significant maintenance burden
>   because each allocation entry point needs to be handled specifically.
>   The cost will grow with the intended coverage especially there when
>   allocation is hidden in a library code.

We've made this as clean and simple as posssible: a single new macro
invocation per allocation function, no calling convention changes (that
would indeed have been a lot of churn!)

> - It has been brought up that this is duplicating functionality already
>   available via existing tracing infrastructure. You should make it very
>   clear why that is not suitable for the job

Tracing people _claimed_ this, but never demonstrated it. Tracepoints
exist but the tooling that would consume them to provide this kind of
information does not exist; it would require maintaining an index of
_every outstanding allocation_ so that frees could be accounted
correctly - IOW, it would be _drastically_ higher overhead, so not at
all comparable.

> - We already have page_owner infrastructure that provides allocation
>   tracking data. Why it cannot be used/extended?

Page owner is also very high overhead, and the output is not very user
friendly (tracking full call stack means many related overhead gets
split, not generally what you want), and it doesn't cover slab.

This tracks _all_ memory allocations - slab, page, vmalloc, percpu.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFIOfb6/jHwLqg6M%40moria.home.lan.
