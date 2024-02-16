Return-Path: <kasan-dev+bncBCS2NBWRUIFBBUW2XKXAMGQEPJNM63I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A8550857292
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:33:23 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-40e435a606asf8257715e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 16:33:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708043603; cv=pass;
        d=google.com; s=arc-20160816;
        b=IgRtiJBfi/5M8kaYS2dLpTmYTEDl6wz7CFFCOkPsiaefjhpMkmae2twucGv6M1P9Wu
         P1AJMcBac9mwPhjLdmJ6Xnd+TnAJSt4wDVygzigOqwFQHuqk4bc+UP2i5GLuEUtx1ehw
         KVhAeJ7qEh5JSA3nhKSM93lxwgon8ozHrKVq1k6j7wN7iZeTuGB8rcMCAt8WvG1Eey7Y
         yyzKmnbVEIGJQQg/ex54Cse/xPWum1Hn8xgD/QSjNg5L1Nq3eSdBIDcTDkehGZx3WamP
         87ZAYLuYUXM5jxTqBYdEyAI706QlK49M0PyO95uOPcKh5Ku/sgsYGYc9ZrVrUNQcQk3q
         h15w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qJeHtQSQoukUlub81Qw9KaAeLIr6c518rjysSIUZVyI=;
        fh=R4H80BVMh/kaES4En1u+4laLJIJb5rRhdFm70zrlv2Q=;
        b=NsErt9/BI45QcWh84tQbXp/+cpfxts4w4EphQoGltsIGGnZXSZeiEeb4lzhS5A28Br
         U9VHRcpdfrkPqSwkJAuKRHk86qwHPS35fOY3qecNzpHpAN40CstmV3IJ5YBu1J5oZnil
         rGwUY0FQL7ysJ5i51lOzFFNfbMZIH5L2FQhzBiGNDKOMA7q0UNMFkqXwIHYy8hbjLKMa
         pBGn16RNyEWu+b8aQ395/MEjoISG1tl3qQApWcFrTkTNR54mJT339uG0MD2p5Tr4lgrS
         N+jnY4wfvFculx5CSMVqVjCozR0w51UWzK65p8Ykg+vQhOxx4Fk8uDOx8WFcAON6Y0EC
         ++1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TCBheLyH;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708043603; x=1708648403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qJeHtQSQoukUlub81Qw9KaAeLIr6c518rjysSIUZVyI=;
        b=kdAANXV+ebhqi1QQeZcmJlw2g7Jc0hzZKJhUx+93cx7XlQJzreQ/TtVp2zjFVNg/Sj
         OlABzyLL/PBPbqbX+i2G4y9CbvhnnZMpM/JwX6ksqMokgV2qxgpntMKepxd4QQ72/PCu
         Db6GbYwnMud36DqZouUySCmjX0qzjQXuAVbLzNSpzB6v6IEfTNIFeIVWFvqJ4OCMtuKk
         Tv1190kXdV2mLZV6hwgpc8Txs6Kh9OJ/puHqohS5DrICUasz+KmKv1z6kZMLo1HOANWE
         v80EJss8crbiOZ5i7nqYKkz5fGM7AkANVieA3ZnYJ1cQJSimudT2mjRvQMbwF3vYv/en
         I2Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708043603; x=1708648403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qJeHtQSQoukUlub81Qw9KaAeLIr6c518rjysSIUZVyI=;
        b=qVlTMRaeHwykQh5OPreymJvzbg4xP2h81rvJAjRmXQ+dlq03i+TjfEbKhSX0fW/ulg
         Yu98da6c3hn8L7vPaG7w/gCMgaCbGd5HRtohVhmm+2xjODhwu7/FS9zI+RUSHkEgOv7W
         W8stokb6BnGzjkMAP50oBQYuVFGOYN/LkHmzs5g37q2oCxHmLW33zoQQycmj8kTiXn5V
         IKBoZoWjkHQlZx8JnKWgX924loA7eiLr+KbH1wzgjJon486OKrNXSVb3tt6/dXXFDWsi
         0oSDYxRDJi6HYjrcdbrDT3lvaobSOi6hskr1V5DP+D35u9TodR5zlzozLN8+RU8juk9d
         Ta+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdsdQcXebWczzXiifo6bKGQRZ7QnsmH1CaeEiYELxlWuDLfYL6K1G0Xzgqtu39xUJel03dOc4RHDdA9c2QfQEJJDoj19Lm0g==
X-Gm-Message-State: AOJu0Ywaf7DekJ1RzbA1tndmT120CvczpXL4k138m5BsN7wqyKVzYXrT
	X+oyWk9yq6fnWNj7Ma84T166hLZ8SHs2Budnaj9XikeX1MNdY/aY
X-Google-Smtp-Source: AGHT+IHFxy1ABu/9+XfqQpKlAvCu8ET0dlOj/uGg01tYRlTbNSHEos9fizAa9zc4AlxMPnlvj1eJFg==
X-Received: by 2002:a05:600c:a47:b0:40f:dd3f:ba10 with SMTP id c7-20020a05600c0a4700b0040fdd3fba10mr2434679wmq.33.1708043602637;
        Thu, 15 Feb 2024 16:33:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d9e:b0:412:40fc:5147 with SMTP id
 p30-20020a05600c1d9e00b0041240fc5147ls61432wms.0.-pod-prod-09-eu; Thu, 15 Feb
 2024 16:33:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUY6rvTwwthtUUN7zIenYzxcqKydvmFtOaNYGdeIaG68dPAeK1mxXrC2X3sP/IpkBQ5Z+2+qhW5mgoj+i4xhPi87G2pLWAiqQkieQ==
X-Received: by 2002:a05:600c:1384:b0:410:c128:2bed with SMTP id u4-20020a05600c138400b00410c1282bedmr2388583wmf.20.1708043600947;
        Thu, 15 Feb 2024 16:33:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708043600; cv=none;
        d=google.com; s=arc-20160816;
        b=dl7e6ivxNx6hJmfW1tTxyRwO6WCzRQk6YL1xOrhfQ0eMrlQVmwhWSr10gcYgtLNEMj
         p55hZLFM1OuSqrB6QcQDZvkgW/6p+AtK9O7v+mlI2j9b8KsglKYJ3vXbglSI4MUSroBs
         kjOuWbPFiLz8rjYVw55raj2r+5ZtHMWpj5a3ThGt+y/7gwb5TRTtz3AUAVhQq7Sc+TbT
         cxdKN+0RyZ5MgYhpgWS/WZc3AlmKKfQtEGKJd4Z6m/G1SOVipmZ1KYr8Tw3FoZ4lCyQ7
         3F6f9H9SUkp7JPXgn4IG9ULt03Nz7dyqX2utv7GDMrZzwCzmwVJ2RjKx6RDaolU2t61p
         y+cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=BwLdbKvwbuT7Py0w8ufFkW1cCk4JPEqYMR9dx/1h65M=;
        fh=OiwBIvYIPHGDMdlNleqgT10F8L7VFJzUbQ6V59nSWw8=;
        b=PkqOR9DkPB4hEQeY3i+h6XONaiNkjiMnhXNZooH+CHqtnNzhGppAHWBlhxMDkJ4MR4
         io0jGZxcINowV5Mr0Y4un3HkZWVIsUuv75UHYzebUA0ytGd3KRgAj+1zQvNoMJ1ThURD
         Pq0oqbVc38Bs0D9rH0wfZ2u6p/mDFPAOj7+MPB8qyS+RJD+OcUpNwUqenFKEtdY5+3wn
         DJrro6FKtUij3ooB9T7vePnzZzsTlmMVjyLQ+lYWzsU09G6gTataoBUheRpRqVPqNWP+
         wc9KC1g5p0qa+srcpI6MNZWX/dYRJcp0+dg/zbTo5ZaKuIAmdl8GwelQiDtaNrBPl35J
         kviQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TCBheLyH;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [2001:41d0:203:375::b3])
        by gmr-mx.google.com with ESMTPS id e5-20020a5d65c5000000b0033cf0df3e81si21489wrw.0.2024.02.15.16.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 16:33:20 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) client-ip=2001:41d0:203:375::b3;
Date: Thu, 15 Feb 2024 19:32:38 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy@lm46eypwe2lp>
References: <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <jpmlfejxcmxa7vpsuyuzykahr6kz5vjb44ecrzfylw7z4un3g7@ia3judu4xkfp>
 <20240215192141.03421b85@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240215192141.03421b85@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TCBheLyH;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, Feb 15, 2024 at 07:21:41PM -0500, Steven Rostedt wrote:
> On Thu, 15 Feb 2024 18:51:41 -0500
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > Most of that is data (505024), not text (68582, or 66k).
> > 
> 
> And the 4K extra would have been data too.

"It's not that much" isn't an argument for being wasteful.

> > The data is mostly the alloc tags themselves (one per allocation
> > callsite, and you compiled the entire kernel), so that's expected.
> > 
> > Of the text, a lot of that is going to be slowpath stuff - module load
> > and unload hooks, formatt and printing the output, other assorted bits.
> > 
> > Then there's Allocation and deallocating obj extensions vectors - not
> > slowpath but not super fast path, not every allocation.
> > 
> > The fastpath instruction count overhead is pretty small
> >  - actually doing the accounting - the core of slub.c, page_alloc.c,
> >    percpu.c
> >  - setting/restoring the alloc tag: this is overhead we add to every
> >    allocation callsite, so it's the most relevant - but it's just a few
> >    instructions.
> > 
> > So that's the breakdown. Definitely not zero overhead, but that fixed
> > memory overhead (and additionally, the percpu counters) is the price we
> > pay for very low runtime CPU overhead.
> 
> But where are the benchmarks that are not micro-benchmarks. How much
> overhead does this cause to those? Is it in the noise, or is it noticeable?

Microbenchmarks are how we magnify the effect of a change like this to
the most we'll ever see. Barring cache effects, it'll be in the noise.

Cache effects are a concern here because we're now touching task_struct
in the allocation fast path; that is where the
"compiled-in-but-turned-off" overhead comes from, because we can't add
static keys for that code without doubling the amount of icache
footprint, and I don't think that would be a great tradeoff.

So: if your code has fastpath allocations where the hot part of
task_struct isn't in cache, then this will be noticeable overhead to
you, otherwise it won't be.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/uhagqnpumyyqsnf4qj3fxm62i6la47yknuj4ngp6vfi7hqcwsy%40lm46eypwe2lp.
