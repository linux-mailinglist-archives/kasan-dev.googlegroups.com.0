Return-Path: <kasan-dev+bncBCX7JJ6OTQGBBS7LXSMAMGQEOTOVQ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 39F7E5A7B38
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 12:19:56 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id h6-20020aa7de06000000b004483647900fsf7217614edv.21
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 03:19:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661941195; cv=pass;
        d=google.com; s=arc-20160816;
        b=nPMPIG+RQ1bW5Vb6b4LDVUjvE85q5E2krk1yNVQGHkNBhYboRZAWAlTVeNUSW+VhAb
         KPYnFO8xUOrmLr39SCv5DHHWu60UftkKuSnD9m1NWlZR8PHmsI4EyiAVcjYMYe9GnDUW
         Ka0hPSVUOpb/SqwaBLcJ1d47c7xLCi+Z4zfWpi6CZaFkgVuEGqDs+XxEPTPf2LIOaHom
         3qASYD/cNrcLu2IZRaTbfGlXK9eEU79YfiyCyyB5zZV8uRpgqz4d7cocBViElIpnB5n7
         +6GArV7j4/Y0m8LOiZLUDzCEjIuhXhBGfwLvkOGIkBWmtN5I2e5qmqJ8GvY5NkC7SLPK
         I2pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=f7ObHSGFhEmOgTUItL9kb6on4ndpTbp0jm3MziTHBzs=;
        b=WjZYZ6SnQmR0wc94P3hd7nYXoXRdCgC1fxq+vWxOt/QO1yLMam/ucFcKATuFUa6oLf
         +QmDsG6YVKXEzeQEOR4qEIfx1ITMcqzNIRuGi9AfJEZKtSkC2nIyXeIXIRRZWTWQ5jHp
         vf9w+4u7Fj63laq5KW2M/CZltd1AHpP0T6J2XieF/K2xVnMGGL5tPrRvPQ+RHUxM4NCr
         8XVR3t8+3wtou2eDY+IKrfg4pOaiOoLuPCynJ6SGG0l6q9CjWmy9l9Bxa9W4QItUpPtI
         Yc8yBFYN+YTmPLq0+PjV7UnOPyJZEvHWp7q4spLkEG4CdCmfaHSJasb7ysU/qysFTroo
         7b1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=xpV4nSzh;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of mgorman@suse.de designates 195.135.220.29 as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=f7ObHSGFhEmOgTUItL9kb6on4ndpTbp0jm3MziTHBzs=;
        b=NE9E8ZeiNT7gfUnIjilMCo0RigxX9Vsqt+XthqqtPqzEr/ZUpP4RVr7EcO/nuTZm3A
         UuUHp3doXluFGZJy23v5zM2U2/jYa04q2/tFybBszJXfmLZh25kuaJTX/sR5FyH3WMDJ
         ZtTTL/DSkeazn+WVLcTQPuZHa55rPbhewSODqjEbWy3uuFoqTXY5u7I3cB2lbrHcTcC3
         Rjb4FhOuF8IGa19IYngvb3hugCVy8cuaSQjI4uoF0u8ZYgxpbpCUIjoHIbwMxwVVlOz4
         MpMp9/3ZYrxM3pbo5Rp1HavSYugnpPzHtU8bNCeffRTSA3Ef0R2ODZoeK03GL1RO1OO5
         x/Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=f7ObHSGFhEmOgTUItL9kb6on4ndpTbp0jm3MziTHBzs=;
        b=TXNSY4vCMJ9nWxy9RpmgWng1VwdZt2ouCrLJc1N+PL4c6MjUWk/LDRyc9ub4eBrkfQ
         2/lCZ69s8sXDGsVbNPX3rLn06eyRyZOJKYa5MiTFHB3DEf5TvRUBSS83L16KogtgmSSB
         F6HiVe6iY146tUdW6l4QL2k3p3jTzyiYhff72GxLFjnsSr7UtL/z34pY/CDoG+0F7oma
         VLGJLAoEga0HOBe7mFHtlPhJqSYmkVRz/rxMFbPBQcEOBHaRuHl6kfda3kQ4blkDeYKV
         xarcOgsmMdQTkXzJaJclVcWKYDz8WZU2jfIO//RQmWpirufwVuOnTW+QccJfR8AM4lhy
         4dqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1TOIIXAJ1znWqzKjywRqrogkIvilyA4fxeFE6VUzNUbgXYYi4I
	+YLILHt4MvWHejJug7roCHQ=
X-Google-Smtp-Source: AA6agR6j0gJwa/7sP6l+5octvXJXVgctDbGccD2mD7XdDcQ6xfOuesXB3mEdKsSai2EmwOF13y2dJQ==
X-Received: by 2002:a05:6402:2b8d:b0:43a:5410:a9fc with SMTP id fj13-20020a0564022b8d00b0043a5410a9fcmr24015585edb.99.1661941195886;
        Wed, 31 Aug 2022 03:19:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:11c9:b0:73d:704f:9649 with SMTP id
 va9-20020a17090711c900b0073d704f9649ls2458051ejb.5.-pod-prod-gmail; Wed, 31
 Aug 2022 03:19:54 -0700 (PDT)
X-Received: by 2002:a17:907:3f98:b0:730:cfce:9c0f with SMTP id hr24-20020a1709073f9800b00730cfce9c0fmr20237626ejc.475.1661941194769;
        Wed, 31 Aug 2022 03:19:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661941194; cv=none;
        d=google.com; s=arc-20160816;
        b=G/Yoy9Bvcm0eflXGBCTwn/Y2oTq5+EcstxM9UTehDAmeYETAMPspQ8UNAPMX71B31q
         zO3im3p9vWWSVzNZjRxKOSXPjVHYIhIyeHG9wEvswzNzL0z118REnP5U4odKUrQMKMZP
         npmyUt7w+EKuemVmuyXeIjFcsEyRLyOd62YsVqCXnxob1ppkKdrZQTJtxXT9zSrT5afj
         /DgKFK2NkHUUc8rDVOv1v27XghwyNn8V4z/Z5UD8n+eS6mNQA7za15Uat3w78aFTmJBo
         sbv9hVhecN3idonVwTwReAPVr64LcYhH8nl6kot3VhA1BeTZMe/0hXctAquxnpPMUyih
         gWZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=MGhHW6rYwZ48K8Xu0V7K4ggzBnb/NvfN0ZoK0gCAlbg=;
        b=HzqSh9pgRuVvjIdmptEIuGhMAvcf5pUhAZHzlIhExy8LfqWKAHKekiRHKCf7Zh3LB9
         PT/U3itFAFn1r63hQhZx+c0ZGl8o4lLBrlJS8kCrRXsn8bK6cH5rfYeKDwsZENwCqQo4
         0vuRE52ivgEj041ZsVQOqfxKud1E85SPrWb7AwDKl9ZE1cDzVjpu2nZWPAYLnFZ7qZGm
         Pl7cZMHDi+QlrQ1fAI9xGbqJmEgRhZvgC+bz6MMMUsZsSXzj3dMHCm8BUbPsVZvkepJO
         0yAwwEQG6ieF4aNHPLXdgk3JGw8l2p3p0F1gb6crKpRXlG2I1UmUcsKjCO5VkPtm081G
         PbEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=xpV4nSzh;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of mgorman@suse.de designates 195.135.220.29 as permitted sender) smtp.mailfrom=mgorman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id c2-20020a056402120200b00448019f3895si558379edw.2.2022.08.31.03.19.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 03:19:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of mgorman@suse.de designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 4C44B1FA26;
	Wed, 31 Aug 2022 10:19:54 +0000 (UTC)
Received: from suse.de (unknown [10.163.43.106])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 085222C141;
	Wed, 31 Aug 2022 10:19:49 +0000 (UTC)
Date: Wed, 31 Aug 2022 11:19:48 +0100
From: Mel Gorman <mgorman@suse.de>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <20220831101948.f3etturccmp5ovkl@suse.de>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
X-Original-Sender: mgorman@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=xpV4nSzh;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of mgorman@suse.de designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mgorman@suse.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=suse.de
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

On Wed, Aug 31, 2022 at 04:42:30AM -0400, Kent Overstreet wrote:
> On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
> > On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > > ===========================
> > > Code tagging framework
> > > ===========================
> > > Code tag is a structure identifying a specific location in the source code
> > > which is generated at compile time and can be embedded in an application-
> > > specific structure. Several applications of code tagging are included in
> > > this RFC, such as memory allocation tracking, dynamic fault injection,
> > > latency tracking and improved error code reporting.
> > > Basically, it takes the old trick of "define a special elf section for
> > > objects of a given type so that we can iterate over them at runtime" and
> > > creates a proper library for it.
> > 
> > I might be super dense this morning, but what!? I've skimmed through the
> > set and I don't think I get it.
> > 
> > What does this provide that ftrace/kprobes don't already allow?
> 
> You're kidding, right?

It's a valid question. From the description, it main addition that would
be hard to do with ftrace or probes is catching where an error code is
returned. A secondary addition would be catching all historical state and
not just state since the tracing started.

It's also unclear *who* would enable this. It looks like it would mostly
have value during the development stage of an embedded platform to track
kernel memory usage on a per-application basis in an environment where it
may be difficult to setup tracing and tracking. Would it ever be enabled
in production? Would a distribution ever enable this? If it's enabled, any
overhead cannot be disabled/enabled at run or boot time so anyone enabling
this would carry the cost without never necessarily consuming the data.

It might be an ease-of-use thing. Gathering the information from traces
is tricky and would need combining multiple different elements and that
is development effort but not impossible.

Whatever asking for an explanation as to why equivalent functionality
cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.

-- 
Mel Gorman
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831101948.f3etturccmp5ovkl%40suse.de.
