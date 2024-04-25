Return-Path: <kasan-dev+bncBCS2NBWRUIFBBVE2U6YQMGQEZ7256LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1020F8B1976
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 05:26:14 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-419f4192efcsf7037035e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 20:26:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714015573; cv=pass;
        d=google.com; s=arc-20160816;
        b=fnYTdsrtfvnsUDXMSpPlFVuoUBc5UAiLnAc6y2k7igGKWFC/m5nrc7/kQsATsjtHIZ
         OsgB0OzrFpfvb/h0sqTVLLDypj4XzrGVk/wTxbCTkc3MRxftZR0zw8LjiT4RjMT+RpFS
         piXVg54XB9Z0RCyuWsv9UeN8DoGy5++02QEyo1AuRYD+ScnrLKOXtjhyMGvF0OEi04wK
         STldhyW9J5LKX1b2sPvs3H+8CEHMYQEXLIKTQZw9EOU24a6ppbtUQkCBwL1bUF18Ttsc
         yDcvaUgcY0SBGnXDCUQyBOK7C4FIrHEt3QRIp5/Cs2qBbppwdUttS98p7/EnBu4VemGO
         1efQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9tK5LkOoL5uBFVoo892SBb2nrmPlpkYkEiEARa91HBI=;
        fh=+il9wZ/ImH9Lk3TuGxh+fLP/fjcWNRTM+hpmf2McHCY=;
        b=WnHNprbmJLrNhYyIVfnebaitCASmYLrz0flNjE8q1rPwpok/M0TuD9jIK1a+8zsVZa
         DraIRcW5DLgfXRvR9Ki3THeUN7hNhhnxBe1GOy23/40MELpYk6i1G2jbCxjZp62AgI5s
         ZUoq6ULgynho5npplgiiCgIcciZt6Zbn16W7/2gnzbFyxtcoQYWXI1n6lyabxKVgULaT
         2A46pzMMgr/076dYuv38eVP6zGK6VeH/8jD5d25FdBo25BrDiwZ4dQLNOBlCWLCDGb8+
         AzyjgJR9faXVEtG5WbmoqbIeh3k/FrSufgxYFdB+Vs+TkAPsQQ9IWE6KK8Tf55O0DDkV
         6KbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="SB/UBFh9";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714015573; x=1714620373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9tK5LkOoL5uBFVoo892SBb2nrmPlpkYkEiEARa91HBI=;
        b=B8KrGoS+5WKaSwJiKEKyjzNJX8W3cbRcl85OLEHwBiXzI6O8XVLZF/lHHljIVlMimh
         CBG2o/OarfhWp4MSHcpmQw4mimH+aq6HocIvsc/sp98DVUcOP6pPFEi3eSCj0ddvk7kT
         eBd+016MKLbVDuXlNRNAlCjux4j8hT9pIkwZNxesGS0ThzeA+I087Jh4fshuIR6AehFB
         tw6RYckPQXCOdEclonyWA7/+3SzVdjYkb4FZAHg/zlB057kmF6UEXJbc2hgm3sImTvLx
         hHhmTg7XWtY0KKHKUBTRTAOQL+/qHIS31WK/3WgNn+aHWeq/uXR0QFxDvU6rwFnIH5fS
         02gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714015573; x=1714620373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9tK5LkOoL5uBFVoo892SBb2nrmPlpkYkEiEARa91HBI=;
        b=QdEcB212RfmS2/621579TcEMIifvijbCnXUGxqTNS0GpmEMDH4ab8Fh6VyKR4sghVI
         rpp4PkxcUy0NBOKXfdLlkpXbJkukYTcaMKXnwoFO9Mhhtt83///TrOONP81YNxAfKwxW
         UdIn47CwRBFi2+C76KVTZckj10mTuQBpIyqUEvmHwP54giO/yXqh89ak1nYAykurXzki
         64LrHEFnSFPx5PhxcuDwE2ahqs30hWU9JFDOyI957F4wifrvaVODtQQfqt1VVIWLMD0h
         Tfr1UGVQUwiiY5wAxDxGrVsHc4c3EfYmAaiAlAbj8ZlFhOs1wPbAgHd8PfcOto20UwJO
         M+oA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsIH5/5aH/576rCPz4BmZmLkNOeqE9yATCEWbMcIsLTrIFNB69RybW1EgkR11aSsAAcdfkakERrmCSoRYUfFlpI9YJ8rboOg==
X-Gm-Message-State: AOJu0YxpaZJ1eeKs5TAoADPwZHrik8eBKu4tdRxZ6B1QjRfzbc9ypwcc
	hASsG/K562umkJL8qUsLa3zJ6s8QHT50s9/476DyFBfCRZypxGRZ
X-Google-Smtp-Source: AGHT+IFYcwFeKflFToCvSwom2ivEXXviJicAEx3lf4HDhrrr1qXb9TgHPo4X2rWLBImYAgKbIgGXSA==
X-Received: by 2002:a05:600c:4fc4:b0:418:98fc:a46a with SMTP id o4-20020a05600c4fc400b0041898fca46amr977956wmq.15.1714015572872;
        Wed, 24 Apr 2024 20:26:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5111:b0:419:f600:c566 with SMTP id
 5b1f17b1804b1-41b327820f2ls1407565e9.2.-pod-prod-00-eu; Wed, 24 Apr 2024
 20:26:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQzSDn6TXSateKFbwam4GUgzS1oIGaM75JD6CYDYsQhfUWJtw/sYYxjHNm4CYEZorQrSo92pjayZoEQQwmY7ZaZnKfToV8pBKslg==
X-Received: by 2002:a05:600c:3c8b:b0:41b:34d3:42a5 with SMTP id bg11-20020a05600c3c8b00b0041b34d342a5mr798093wmb.1.1714015570916;
        Wed, 24 Apr 2024 20:26:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714015570; cv=none;
        d=google.com; s=arc-20160816;
        b=jvFW0G/9g50sCRkSxGUtVEI1Khy8MmzjwB9FXsgQBDA2rte/ew3qks7ZIortbXv4Ax
         6u41k9PYuPe5pXvVcONF3zXEHqG1KnG9t1B3HH5Jf2yeD5OKFq8aE0WH8IFepVGSTQNa
         iopKRwfWLxI84wTsutkFcIQe6KLrHvVveMZLYp4Kkmjkhxgb6QSOym7fYamSWM3ThIR/
         xns0a5fYOoZJicN62GI7nm/cPwAOq1RzXEhjrHs+QVjtwl2OfRbruK+OpINE0vcYNatm
         5yvRogybqlRLT+ae/h6nrVAj/cNmAbrKQsDGiWp+ka/t0SvAGFjqOjdhMlG+mXqnbEea
         MAuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=B4E11bh0mnSYCbs7XlFu6X7DBUDw+NgzQF2QoLRfZq4=;
        fh=77LLyW1dlUNu7NwY6XTVihyowrlfxy9OIGb7ziNH6XE=;
        b=OPaP5x3pgjKUQO+T9Svjgb5GI8ouADplmIvMUo1zdt80d7evkfOiuSWKVnTQ3g76Yn
         UDsqjLS3C+8O3Lfckc3Rg60ghUWVwp4f2sb3Yr3zyyKQQ2UVJ0nT+qEO5Dw/xMx2YbFR
         6qucw1LkqcsNuJZx0LrMpNSwTsoHP3yl+Sk+JR/JhEsCdiT5sjp2UWQK10BqJ9jylJa2
         KQg1MylHRanS/dACSD4c1m8XkKZwvP0FC9+vMSWziMw9KU7e13kETKhY3tJeNVUMerVF
         WFUgk1xJiH+wkzl/pTFW6TlKhaGoaiAdgSGVZDIBsBIjYmbQf5pl3RFucuKUbjq+MuTj
         x4Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="SB/UBFh9";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [2001:41d0:203:375::bb])
        by gmr-mx.google.com with ESMTPS id l22-20020a05600c1d1600b0041ab32f333bsi108619wms.1.2024.04.24.20.26.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 20:26:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bb as permitted sender) client-ip=2001:41d0:203:375::bb;
Date: Wed, 24 Apr 2024 23:25:56 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Kees Cook <keescook@chromium.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	aliceryhl@google.com, rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	linux-mm@kvack.org, linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
Message-ID: <3eyvxqihylh4st6baagn6o6scw3qhcb6lapgli4wsic2fvbyzu@h66mqxcikmcp>
References: <20240321163705.3067592-1-surenb@google.com>
 <202404241852.DC4067B7@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202404241852.DC4067B7@keescook>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="SB/UBFh9";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Apr 24, 2024 at 06:59:01PM -0700, Kees Cook wrote:
> On Thu, Mar 21, 2024 at 09:36:22AM -0700, Suren Baghdasaryan wrote:
> > Low overhead [1] per-callsite memory allocation profiling. Not just for
> > debug kernels, overhead low enough to be deployed in production.
> 
> Okay, I think I'm holding it wrong. With next-20240424 if I set:
> 
> CONFIG_CODE_TAGGING=y
> CONFIG_MEM_ALLOC_PROFILING=y
> CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y
> 
> My test system totally freaks out:
> 
> ...
> SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
> Oops: general protection fault, probably for non-canonical address 0xc388d881e4808550: 0000 [#1] PREEMPT SMP NOPTI
> CPU: 0 PID: 0 Comm: swapper Not tainted 6.9.0-rc5-next-20240424 #1
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
> RIP: 0010:__kmalloc_node_noprof+0xcd/0x560
> 
> Which is:
> 
> __kmalloc_node_noprof+0xcd/0x560:
> __slab_alloc_node at mm/slub.c:3780 (discriminator 2)
> (inlined by) slab_alloc_node at mm/slub.c:3982 (discriminator 2)
> (inlined by) __do_kmalloc_node at mm/slub.c:4114 (discriminator 2)
> (inlined by) __kmalloc_node_noprof at mm/slub.c:4122 (discriminator 2)
> 
> Which is:
> 
>         tid = READ_ONCE(c->tid);
> 
> I haven't gotten any further than that; I'm EOD. Anyone seen anything
> like this with this series?

I certainly haven't. That looks like some real corruption, we're in slub
internal data structures and derefing a garbage address. Check kasan and
all that?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3eyvxqihylh4st6baagn6o6scw3qhcb6lapgli4wsic2fvbyzu%40h66mqxcikmcp.
