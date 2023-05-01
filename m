Return-Path: <kasan-dev+bncBCX55RF23MIRBLWZYCRAMGQERENSJSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 22ECE6F399C
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 23:18:39 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-30629b36d9bsf626510f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 14:18:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682975918; cv=pass;
        d=google.com; s=arc-20160816;
        b=fw8sRBn5V/YXjSx9s6IknoQtWs36ZtZClvXL2PrViA3ckz+wUOJzmVVOejoRa9BlTM
         Ovh1AurYDnGEncDjxqnLcLp1a3l98yjx3pgIAorT4vudc7IgFuNV84VLtfb8oF+rjPgo
         JHG0feXF9gOb+AJFCooNUqu9ZpPz7X6mJ5WWWfIzqpgR2jrNysATTAQME+y+zomOI0ED
         6WJhh6VYgr6o9A8D/g10GWaBneaEq/0ddVwJ4lB0WR8qdHxUItIAK8Sky8YExGms9Pjd
         LSsQVPQXwfbkfWHPbflLkmtJzacGEsvi87HkmFAjpuFJ5JoLbfM1wUivTBF/Y69PylVN
         gX8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=a3n8GFUMOt9V864qB0KVPUxlR7EQqzGz2LRq6X2lTig=;
        b=w0+cgR8VjvOa9HiO5MKCYwtWkCKsvbbVNb7dO/HF3fAG6iLGTJCknd6HyfJd+KJwXY
         atiaeINcK0l04s9Lp4Bvb3dWgm7qx4DDHIOx8qSeYSYVqREkFzq6ScXmo2dmMfdZM27Y
         BRQ68aTBDWmeO8Qw6Udxdl4LPnMaadn+4q7ldFvvdXKY7eaJQAMACd4olxZlyWmtlKQu
         LPii9trHTHUdHB3aT5l6UGhxqRrflYQrGfNmTjNvw+Ht906xA0BQrEGE4U1zdiX1E1Vp
         P844Er2QNJ045bYZn5+zEaNbtPdUMZXQFGeHkWlGaRfQTQJy321YuX5tI6/CPWMUa3+j
         +I7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="X8e/zveM";
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:203:375::2c as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682975918; x=1685567918;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a3n8GFUMOt9V864qB0KVPUxlR7EQqzGz2LRq6X2lTig=;
        b=XYNY0TfxVY0WE3Mcd8bo1/cjn/xyD4qsMsVKZZumlFlH5sdK3J8KdaT02C0OFK8lYi
         Ee7xL/7kTqp9CdgMGRk4ZOmE9B28AVlTSK3bcdb8sRFnkoytXOuv3P1B5C0dyyljObiy
         JUJiy3cPtV5Pls29sL64CYirxFBlLKTntSUQ9zfrqtCKyeTUgh5OvPL3otc2Q8VAtAlm
         VaeFCKpvSOsne1EuU77RtqkuNYwZQ6636DVRtG95/+T9mWdJcCTRE+X9+OAkHothMVEA
         zsQr4N3K0/j1u0oMpUrnRAizVbK1C7Kf644SRf78u5t1OQkq9OHvfRPS1PJ4rVTsGUsl
         OMQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682975918; x=1685567918;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a3n8GFUMOt9V864qB0KVPUxlR7EQqzGz2LRq6X2lTig=;
        b=jyaeNDZVO8e5bCCKLi2XCbzE5SroVEDbHwtsY7S/jfNM04U9s7sp1o0HkEu22qVWZu
         gWGolQV+1KnaxoTORxYoQ3OfxKDayMpHJNijlNUwqVGMtsHIHR+Z8662FfAHpSs+uJvR
         yJiuZY2bak64SQ3qOWxp2RI6pgw9PvMxbDz9VfaPHHk1iAABSUVz6MCmvTHigu3Stww4
         fj/HVOGKRosf+peXnPJt7izEWGMqv90byb4rkmmrG2Wrd+BzbPR3qeXuFUQ7lNkgWxeO
         7TyYw4krQRsbYhs2d2GufVs/7uNdlFpKoQxVZYesEqHchy343Pu3BQlfgMRaMd/bwod7
         Bnng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyk3jKibY50ae8mLckDF/FpoI5fpZZWNH8ZJ6/6aUDH/TB+dsQE
	4VkuFRN/AKjJT1ElPXG/4EQ=
X-Google-Smtp-Source: ACHHUZ5EnnVCJ53q3VIJuiGa3JQgtaE4U6y/KJKDyeVSsEpvG6e4n5QUk/1098E4uw5gOWoVXiY6Sw==
X-Received: by 2002:a5d:5081:0:b0:304:794c:1525 with SMTP id a1-20020a5d5081000000b00304794c1525mr2433102wrt.2.1682975918487;
        Mon, 01 May 2023 14:18:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5a18:0:b0:306:35d:2f11 with SMTP id bq24-20020a5d5a18000000b00306035d2f11ls9270434wrb.2.-pod-prod-gmail;
 Mon, 01 May 2023 14:18:37 -0700 (PDT)
X-Received: by 2002:adf:ed50:0:b0:2d5:2c7b:bc5f with SMTP id u16-20020adfed50000000b002d52c7bbc5fmr11375424wro.58.1682975917247;
        Mon, 01 May 2023 14:18:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682975917; cv=none;
        d=google.com; s=arc-20160816;
        b=RHNeE7Y8Ki51dS6Lp/QoPBOX0qc6Ig+UgEyzWNcRd0gfbST3K8KICn6/S5ze4xjvVj
         CSYw/2nEu4+7dISIYsDNJe9ySWWyIsh6rpPJ6qOhdVD/l/FnqiuLnQyuJEvrb/C3lotW
         /kcavhmlSZDQZhT9FSupDWRmqGGeNGP1apxJiDj3M2MihTvJk5D5h3HQ4c5d0Ykffx0K
         fsWKoX3dfl3NmHrx+BlaElHbNS/KZ7+dDPgeLwUR2V00hcdQETUrwXNXcAcKeIt/5axP
         KU2BAnUY5a9YhlvaGfbU53To9gNJL8Q58hmxbfOediYXMTpEt6uAp8MMBJLCxabWsL/y
         B6ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ESr9I0e8zhQfwnabaXWJmwqboN5UgcpvA4HHb+DuoSo=;
        b=Stuv+AoGOQXAtvhXdeyVp0fFjg0ah7mA+6wVZG+seFNRwSRbIYY6N+uPgnJEhOXTQA
         bWPdjlgtoze7fwVdFf1o+9P2MMVFLn8Sy3/GI72oacYOSJk9ktrSfK8RiXXLI93qjuj7
         WBxJeGhhm1MkM+XAJKNdOLxCApQlWYh3XOpJzL1hQrSHa8tEXfdhagwKEVtjgTdgr+Mh
         HYh2CmPfSCihIRCkHyBq+121AaBQ0JQTxra12r5gdg4aeWFlgzLcLAWHJ5aY4RySfnle
         XTpqBAu9R74FqeE+A1rxVDPUtP3K8prQ/FC8Vxy3V+oio43DHCK8dJoDJ4VtfFUjDUFm
         ok3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="X8e/zveM";
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:203:375::2c as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-44.mta1.migadu.com (out-44.mta1.migadu.com. [2001:41d0:203:375::2c])
        by gmr-mx.google.com with ESMTPS id n10-20020a056000170a00b00306308f0003si147357wrc.8.2023.05.01.14.18.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 14:18:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:203:375::2c as permitted sender) client-ip=2001:41d0:203:375::2c;
Date: Mon, 1 May 2023 14:18:19 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
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
Message-ID: <ZFAsm0XTqC//f4FP@P9FQF9L96D>
References: <20230501165450.15352-1-surenb@google.com>
 <ZE/7FZbd31qIzrOc@P9FQF9L96D>
 <CAJuCfpHU3ZMsNuqi1gSxzAWKr2D3VkiaTY0BEUQgM-QHNxRtSg@mail.gmail.com>
 <ZFABlUB/RZM6lUyl@P9FQF9L96D>
 <ZFAVFlrRtpVgxJ0q@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFAVFlrRtpVgxJ0q@moria.home.lan>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="X8e/zveM";       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates
 2001:41d0:203:375::2c as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
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

On Mon, May 01, 2023 at 03:37:58PM -0400, Kent Overstreet wrote:
> On Mon, May 01, 2023 at 11:14:45AM -0700, Roman Gushchin wrote:
> > It's a good idea and I generally think that +25-35% for kmalloc/pgalloc
> > should be ok for the production use, which is great!
> > In the reality, most workloads are not that sensitive to the speed of
> > memory allocation.
> 
> :)
> 
> My main takeaway has been "the slub fast path is _really_ fast". No
> disabling of preemption, no atomic instructions, just a non locked
> double word cmpxchg - it's a slick piece of work.
> 
> > > For kmalloc, the overhead is low because after we create the vector of
> > > slab_ext objects (which is the same as what memcg_kmem does), memory
> > > profiling just increments a lazy counter (which in many cases would be
> > > a per-cpu counter).
> > 
> > So does kmem (this is why I'm somewhat surprised by the difference).
> > 
> > > memcg_kmem operates on cgroup hierarchy with
> > > additional overhead associated with that. I'm guessing that's the
> > > reason for the big difference between these mechanisms but, I didn't
> > > look into the details to understand memcg_kmem performance.
> > 
> > I suspect recent rt-related changes and also the wide usage of
> > rcu primitives in the kmem code. I'll try to look closer as well.
> 
> Happy to give you something to compare against :)

To be fair, it's not an apple-to-apple comparison, because:
1) memcgs are organized in a tree, these days usually with at least 3 layers,
2) memcgs are dynamic. In theory a task can be moved to a different
   memcg while performing a (very slow) allocation, and the original
   memcg can be released. To prevent this we have to perform a lot
   of operations which you can happily avoid.

That said, there is clearly a place for optimization, so thank you
for indirectly bringing this up.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFAsm0XTqC//f4FP%40P9FQF9L96D.
