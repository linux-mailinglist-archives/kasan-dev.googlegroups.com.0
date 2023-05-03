Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBFWFZKRAMGQE2NGO7WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B10A76F5D7C
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:06:15 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-61a5789551esf23375366d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:06:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683137174; cv=pass;
        d=google.com; s=arc-20160816;
        b=UlOIlGsheJRmmBKNezydWA6np7C/4yhcAVGCIKwDj/54uNuWqF7JqW8lUlbMw/Y/qL
         NeCBerObaGZn9L9kg3O9h5HuOsL5IQhorKMIly1bZMtdC2jfef6/Dnj83/fs14V3pOel
         MQL1kJgQ7SxrvesVAQC0/aUgQ49Fri9ngoNakaxckn2rGKDKCdevsrqeK0m2U+qrVtbr
         so0BnlwMnCnR3gxBTuVLPdmvRtXVzh1HfJBSGNaljhM9Ly8uHdtszTEH6tMv9M+OTZsy
         wEgj5vQgOtK3W3L89CGttwe41bGPeQK/p6p/L3l/7kgrieGsYhokqt83O9zldhKKxCis
         DYCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qpBtC6KRFLrykYYuJPIla9CwIJSYhc6DtBnvl5sb+64=;
        b=drztTEhEdyk7zONlN2HRjAyWDIDV0lpYjRAJstVSNyb817YqacLNw43oMrBLBX4Jr2
         KDHVD+Qq7Z02DJUa8qIjiO5eDuFalCYFNGjIY7fEXyeE6dsH9mUb/5zYXsQ6of1SQBe0
         q895pVm5kMwZpcxlaRAtocThMU1oWkxlgbHHDuH1wxkGrl/kEWA3sxa3yvd41BMlDjOZ
         tNfOAqxq6aWbtzEizf9O4Y6lloLaZOr4UAS8D9OjAKzmugNQuRH1EXXMl+Ck6jWQy1v4
         +Uz3vweTFWGS/SwcNmMH+fg+bUG/C3QZl4hlou41u1gTl4n7jnvN2EqubuEAhLBG9JGj
         8OKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=kBIOUh53;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683137174; x=1685729174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qpBtC6KRFLrykYYuJPIla9CwIJSYhc6DtBnvl5sb+64=;
        b=sF8g9J9pmrlulxvC442C7uBNGD2R3Hp9eC4BrhHOJ1PndUBiwYkznPoLCtgdWJO8Oc
         qFIPTj70uD1utsrIbR9YDSZeR2Jad57cyVs1VLkhSv3oJhfLb7CloeW6hYOu7OYSNLMo
         0KI7VbNhWdj8ETS0x6fR84oiE0EZJLxu1URvh6tWdwluXBb0RXVvCJlvV76SrXxQZsUT
         d5qAXboJLJTJ6hmysUt/F41fux+Ud4aKRkgvHQeFuZLz0tSylujKynqb2b4cLFJWBU0M
         cYhx2LK7wtIw9V7Nq7GbKvX0dGdWgxUhuCOigN0v+/ksgy/c07qd7+PLBgOe7b1lwHO6
         gwEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683137174; x=1685729174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qpBtC6KRFLrykYYuJPIla9CwIJSYhc6DtBnvl5sb+64=;
        b=BErhTRMR0Yacmcmmn5M+82Ys7kYLy7zfoB7T4rDtBf7YyuD5UA+SJlIwxJMcekD8HG
         6Y3+SrsEsX2PKxn3UjHMrYDBTTqDVc+37jzPFsovtrXdNWWL3Xxzf7IpMO54Ub/TSTQn
         7YDse+zp5m4bXbktcYITRMK7gOq9BNP3LtoGBibffpdIDfNNogwOJyMbquLnD7tRWYDr
         3tDqELChHqulJN/AVqND277ObTeZ/HXoJmxp3CP8B6UEyeYuuJ6mhdtt51sbg6qZo0+n
         B55RuhfBh9M05DY4jrnanE8O/hBJN9bWbBzAAyWNTMacT2t77iyAwSskcUd5p1AQzYZg
         CtOw==
X-Gm-Message-State: AC+VfDyGMvde8UnHOUeQcMr2TNQKl9lNldsN6npzhVjEVVfWisakBehN
	xumBuitoSJk9QukmbdsxwZw=
X-Google-Smtp-Source: ACHHUZ5SFirnQxYEgekgaXwH+KsogxgSUQw6X9kIEI2ynV1l1IxBQjxhS3R3vK0fotziLtF1lr4z/Q==
X-Received: by 2002:a05:6214:560a:b0:5e6:4193:996f with SMTP id mg10-20020a056214560a00b005e64193996fmr1475138qvb.9.1683137174500;
        Wed, 03 May 2023 11:06:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:58c4:0:b0:3ef:1ea9:acd9 with SMTP id u4-20020ac858c4000000b003ef1ea9acd9ls15825516qta.0.-pod-prod-gmail;
 Wed, 03 May 2023 11:06:13 -0700 (PDT)
X-Received: by 2002:a05:622a:1447:b0:3ef:2db1:6e67 with SMTP id v7-20020a05622a144700b003ef2db16e67mr1556179qtx.17.1683137173799;
        Wed, 03 May 2023 11:06:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683137173; cv=none;
        d=google.com; s=arc-20160816;
        b=yJxxKTCedHUqYNuWGao3z+YzEkj4+fgFV88Q+nyGgjkSQYMSltFDjNTxHlFGL97Hr6
         yLvx3zq2eQxsnhcLgpiblmA5DwLTub8SUeSEx+JEEIuSk2mg/gGVH3gl5vwX4JXwe3Vc
         779tHze3yVdKcBkvf2iInITS2BZTFtqo6CT6tSeBHMZFG+OwW7yhaIb1UMwyO4wpp5lq
         eNL2hd/+EvOxEySHODxz50TxcqFkzd1f3BrlSLyRtdYdhgYCJx+lh6rUbLM9wqxVnK64
         BY4GvOaDeCE/qH/zg4c0VcXiz9jS8ConW2DHQYz2kNyasTaNF6hzqRSAF7fcpErwVUB6
         7l+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=4cv7r3p/uGjVZzfVGJD3+oUJmj97nEyjDPWByIKN3z4=;
        b=U4LYvpomccvjh4oOvIofqG9I5Q5KeyypEM+SbHQyvWJlohC0xngup2S8GgM1VtPxCH
         qPf5hvHliCC27wmc/yMbTlMaPkyqmL8g4lJ3coop+cRVtNlBMFw+mr6BCVLwv5QuwU0O
         dC+LXZpFQPi8D0L09rlTYPsB8UU8Iz1wJHDjjdjf0/OWBGDbciH1ORbdpkvn1A/OVj3H
         puTMGS7R3Lz3PUBiSURodtJ1o6S8ctNm8zqVdSpwkHDDgieLDKrzmrp+qYUB0glXZyq6
         EuUhnlB7sO//ueByFE1ITqanwCR2i7PuN+r+dhFyxR0z6/dHepvT7cY0Q3wfEekSgOv2
         axmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=kBIOUh53;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id ra22-20020a05620a8c9600b007537d2c1128si109484qkn.7.2023.05.03.11.06.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:06:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-24e4e23f378so658284a91.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:06:13 -0700 (PDT)
X-Received: by 2002:a17:90a:850a:b0:24e:1f8:b786 with SMTP id l10-20020a17090a850a00b0024e01f8b786mr11008096pjn.19.1683137172717;
        Wed, 03 May 2023 11:06:12 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id g4-20020a1709026b4400b001a183ade911sm21931204plt.56.2023.05.03.11.06.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:06:12 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 08:06:10 -1000
From: Tejun Heo <tj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKikp0Poqen1kNv@slm.duckdns.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <CAJuCfpEFV7ZB4pvnf6n0bVpTCDWCVQup9PtrHuAayrf3GrQskg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpEFV7ZB4pvnf6n0bVpTCDWCVQup9PtrHuAayrf3GrQskg@mail.gmail.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=kBIOUh53;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::1029 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hello, Suren.

On Wed, May 03, 2023 at 10:42:11AM -0700, Suren Baghdasaryan wrote:
> > * The framework doesn't really have any runtime overhead, so we can have it
> >   deployed in the entire fleet and debug wherever problem is.
> 
> Do you mean it has no runtime overhead when disabled?

Yes, that's what I meant.

> If so, do you know what's the overhead when enabled? I want to
> understand if that's truly a viable solution to track all allocations
> (including slab) all the time.

(cc'ing Alexei and Andrii who know a lot better than me)

I don't have enough concrete benchmark data on the hand to answer
definitively but hopefully what my general impresison would help. We attach
BPF programs to both per-packet and per-IO paths. They obviously aren't free
but their overhead isn't signficantly higher than building in the same thing
in C code. Once loaded, BPF progs are jit compiled into native code. The
generated code will be a bit worse than regularly compiled C code but those
are really micro differences. There's some bridging code to jump into BPF
but again negligible / acceptable even in the hottest paths.

In terms of execution overhead, I don't think there is a signficant
disadvantage to doing these things in BPF. Bigger differences would likely
be in tracking data structures and locking around them. One can definitely
better integrate tracking into alloc / free paths piggybacking on existing
locking and whatnot. That said, BPF hashtable is pretty fast and BPF is
constantly improving in terms of data structure support.

It really depends on the workload and how much overhead one considers
acceptable and I'm sure persistent global tracking can be done more
efficiently with built-in C code. That said, done right, the overhead
difference most likely isn't gonna be orders of magnitude but more like in
the realm of tens of percents, if that.

So, it doesn't nullify the benefits a dedicated mechansim can bring but does
change the conversation quite a bit. Is the extra code justifiable given
that most of what it enables is already possible using a more generic
mechanism, albeit at a bit higher cost? That may well be the case but it
does raise the bar.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKikp0Poqen1kNv%40slm.duckdns.org.
