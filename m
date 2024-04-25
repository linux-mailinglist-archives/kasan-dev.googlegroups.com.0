Return-Path: <kasan-dev+bncBCF5XGNWYQBRBZ7RU2YQMGQEGH55MPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CE5C08B18AA
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 03:59:05 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-36b31fda393sf5413115ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 18:59:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714010344; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBKZGoTkK4MljILk69P4SmdeqojXmjrZo1nX3LMjvSJZg6w/UCfS+ute9DmJq0IsGg
         VRzFRMJ+yhzzpzkYC9ekzkjEMgdMQI5bf4to/wQNINtlZT5xsi9Z8lNbfAFjs4IS4exd
         +jqVoV3VBBEEAiV1zZBO0Go5h2hgHmQPhKepCwuK5vPQKT+2ArP5BTmjxpIMqjgy34C9
         YiEJUbTaT0c4hqzn+ZGmfZAD/NQvEddYja6/pjPyl07Rf9f/m09QKMHBRQw/llotggeA
         Pz8jc/fwkg3ScUhVUJlJyZtN1vjxs/BqCh0dhxHl0KNJyhPDY5uNWWBBdkNp/bGIJWS5
         j0QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KuQmcmCRVA8LIyi8PnqnLrwAPbL36RpDFP43jdzTfJo=;
        fh=RXqNM5U0CkezHArUARgjgR4rz7Fd74zyiaSjJgGEWV0=;
        b=fn6WY+UR6tWZG76D2Dg/FMGX7HjTk7FmeEsc9C2echDL6B7kCTHWEIQYYZziIme5im
         B8JNH8ie6u9OkEMnzu5SAfdCi5p7EdsuQk10cQkAqxZELyyhuoYVdt/KE4mgA9Yb5Q1K
         PxfKX0b0D9TIqg52ACCOH83nuYb0Hpn2unTdCQslKJT+sl7H4oH5iPxSyrY5w2k8ZsWO
         pcbSXk5WdXubwMftL4YWQTrzdADhqsYlFvR+Jwavnmc5HjMTyrWYjoXd9AZGuW/UVMjs
         oHXvEqe8BnKGfnmBd6KJLdOVU9jM0kOcPCyw+s4LP5sv3DC1zi2NOXwxWwTcs92aqlBb
         GxUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ErA+roiV;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714010344; x=1714615144; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KuQmcmCRVA8LIyi8PnqnLrwAPbL36RpDFP43jdzTfJo=;
        b=j55eNAKjn894cNF2ajrt+kiKtt9UyH0BomVruCg5wI2FfgnTtGmnq14wNl3lBAsb4v
         IZNwmdam+b9rgCo/a9sfuMs6vp3kSp0WsUpAh1kfNPH7hgLO7gA0Ka1yRMfFOu7OSieA
         HznGsqzFdEktCdGllsZKACW6YioCZlVbhe41+BDfdVDbztsTolR+3sdeFXA8voNdH5Lx
         W5HESMFrOkOJcZtj3YnZJGOeO5LKK62EAdz/gcy1wHEHtmE4DFv5wLNYP8oR/EZIBnjr
         IAF9KinW1C6e1kjHvN7L7MR/AYtXApnSfL/14FI42Bq/fL+pjEi/+yVsLPQswkKnDujI
         ys1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714010344; x=1714615144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KuQmcmCRVA8LIyi8PnqnLrwAPbL36RpDFP43jdzTfJo=;
        b=q4uO8mK7n8W3WcTLZc4MGtOA1hFW70c5No4h60+BrLx1cdZZNxOT43DbfSR06LN5XY
         Hd2ZAME+d0hBjzyxSPh7SvUg3Su8H/Z5i9B4CLRzYQ+ZhYcqfh0jg69WcyJvtS9jFno+
         kSMym4uYi7c01u29BbhisYtHKwuqP9YwE6P3QRKyBPZmbqNnSRrNqDsc0cbUaEfq2KVU
         2vDty+dqZmSs41MiNkAc7HU/hBVhbLsLhxD7iRwXypJjpcS2jnbOLLWPq/7q5E4KME3z
         YAnu2WHmeRZbrBqBfvVh0LXFKDUDv67mNnctCrzDs1YkYYXrJSr/JGR1+WUchLn0JK1+
         u/1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPJjdZbl1wQpVZYqg/Uv+Sj+HVMuTJcU5EHk6t2nvZQyyz73eH92DkcfqzhStkutUhw0Wp4U9pJxHBhCafh7nib3qm+E2WXw==
X-Gm-Message-State: AOJu0YxHCbooTyD2c68vKH9WGmVjPgm45S1bRaTpN4Xx/bhKIMoRe9+c
	T46631tyGVyJOJTpe6gZNDVYC5LC7K3aotI9LetEHq2MWrqRi0xF
X-Google-Smtp-Source: AGHT+IFZTQTYf3ZPZsOtGS7KVlxMZmU6IBMUbmHKCKe1CBFn03PzMjFoEm8LhOTPVW3CEh83PPsNYw==
X-Received: by 2002:a92:cd8a:0:b0:36a:2245:205d with SMTP id r10-20020a92cd8a000000b0036a2245205dmr5812379ilb.15.1714010344136;
        Wed, 24 Apr 2024 18:59:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:194e:b0:36a:267d:1cb9 with SMTP id
 e9e14a558f8ab-36c29d88388ls2807575ab.0.-pod-prod-08-us; Wed, 24 Apr 2024
 18:59:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN+1W+SMG/zKVMbEC8OJFtgwQ7aeTi/+KNEAnan4vU/Gt1gzffSV9a06pPFQJ+aVnPXdcm0Oz2fnmjQ+vGAuiADx3amjM6izgeUA==
X-Received: by 2002:a6b:f616:0:b0:7dd:8432:6afd with SMTP id n22-20020a6bf616000000b007dd84326afdmr5906912ioh.14.1714010343295;
        Wed, 24 Apr 2024 18:59:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714010343; cv=none;
        d=google.com; s=arc-20160816;
        b=ovQhD7CwzHvKQgHe6j3kJO21q6kJlm0T9cVTVd3QH1uhY1GHuibZZ/II1Hf4suc6Ax
         0lAB9ESNZg4oDvSwtvnZ3XwCUZekKJVfn08wp34XMFxtqFBWAepY+sCxK2RLpAOo4Xsy
         KIVZngZfVtsXxhmdFma6tFSnN4g5qTslbCg5NgoN6VUdRNFfctqSDEJ/jWV8L45chS1P
         J/3w/xEPPVR0dW6NO7p4bKeXpgoXdjlU+yEVDwa2jbz+OAfEU0docGP3MnjnHMY/Jszq
         K6Sq7OjkSHegRt/1xicQItsQLBWe0fzrHM8zemVK3CRe1D8Bf5rNuymXzJKfTEnV8UnH
         tu0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=S4qlJ+DG6HoUrdCik4e+F/ZipKmWdndDCcmvcXd31J0=;
        fh=vEpu7V18oBxZ7wcqZGr7+K7ZYhvlTYRvWSciyu4dwE8=;
        b=DfiX2tZgCmZGEhucc9yt4U2afg3A8CocXoRH9zbPHn1uXVjcpiqSfeaZULTsSjWLVu
         TndPJeeKRx9spt1QVHStV88rt3GTt01fpnSnTAtJMb2K+2kK6NXzhOrT4GDIBv7fEIdl
         nUA2yKAZ2vt/QzoZpM+9mcIFyUL7eMI5/QZquL196HK12URwLLNNpA81bb9+wR1mut1C
         vpZJLX4jEUAnNtnshlo2mM0++/fl3BU4/ZtBF/ZVOWiCcHq+V3JOgy0aXkhbUmxrzulJ
         kWtQzgnMsHR6awcFFisK9AgDvw0rLbEzg16S/ilp903gEJMfC/kNfxBxM8EeFrNk6q6G
         T4Cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ErA+roiV;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id w19-20020a0566022c1300b007da85bb8139si576377iov.2.2024.04.24.18.59.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 18:59:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-6ed2dc03df6so496958b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 18:59:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfE1tYPv3nbwLpjYXpbEHZepT/Vt40zki8gWjVWm5bVOub2qhAUCEdzTlLTvcTPI4PsBP1GTcx5PydgBbYnsgDhLo5V4AjkgNpuQ==
X-Received: by 2002:a05:6a00:3ccb:b0:6ed:de30:9e43 with SMTP id ln11-20020a056a003ccb00b006edde309e43mr7198156pfb.32.1714010342547;
        Wed, 24 Apr 2024 18:59:02 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id v28-20020a63481c000000b005f7536fbebfsm11567520pga.11.2024.04.24.18.59.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 18:59:01 -0700 (PDT)
Date: Wed, 24 Apr 2024 18:59:01 -0700
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
Message-ID: <202404241852.DC4067B7@keescook>
References: <20240321163705.3067592-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ErA+roiV;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Mar 21, 2024 at 09:36:22AM -0700, Suren Baghdasaryan wrote:
> Low overhead [1] per-callsite memory allocation profiling. Not just for
> debug kernels, overhead low enough to be deployed in production.

Okay, I think I'm holding it wrong. With next-20240424 if I set:

CONFIG_CODE_TAGGING=y
CONFIG_MEM_ALLOC_PROFILING=y
CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y

My test system totally freaks out:

...
SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
Oops: general protection fault, probably for non-canonical address 0xc388d881e4808550: 0000 [#1] PREEMPT SMP NOPTI
CPU: 0 PID: 0 Comm: swapper Not tainted 6.9.0-rc5-next-20240424 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
RIP: 0010:__kmalloc_node_noprof+0xcd/0x560

Which is:

__kmalloc_node_noprof+0xcd/0x560:
__slab_alloc_node at mm/slub.c:3780 (discriminator 2)
(inlined by) slab_alloc_node at mm/slub.c:3982 (discriminator 2)
(inlined by) __do_kmalloc_node at mm/slub.c:4114 (discriminator 2)
(inlined by) __kmalloc_node_noprof at mm/slub.c:4122 (discriminator 2)

Which is:

        tid = READ_ONCE(c->tid);

I haven't gotten any further than that; I'm EOD. Anyone seen anything
like this with this series?

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202404241852.DC4067B7%40keescook.
