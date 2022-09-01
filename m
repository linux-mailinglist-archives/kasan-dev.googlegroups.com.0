Return-Path: <kasan-dev+bncBAABBWMDYOMAMGQEQKVWPAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B52265A9A40
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 16:29:46 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id f7-20020a1c6a07000000b003a60ede816csf877762wmc.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 07:29:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662042586; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGetpwgOY63MQXGqipAZc1+Vxo3HtsXTSsQ7a4pVLZeH7pZt+15GkRML7rP6cejSfy
         5Qn/PdM8Anm1JQLCQaNsXlHkBKmIhCnhAlnLZqAiMc7uqnlEnWVWMRpHYFcTCZG04S9P
         Hp0JWto+5Qs2Wrl3T6bkqj8IHwnKWrZ/Zp8/VxjiUi5p5ol1Ts67TB7pfvSGdVpAcM6c
         K/l0prRnq2xKWo3jNcBgkhfPGUHSBcMuttsaVyoCwgt3L0MMYm65rQLZKjzMZgy9d+A9
         RTs6lQ3Fp3jMgZ6VK0LJoOdV4dlcwZ3C0NR0jTZE2iwz+iZNuYZVu+Rjazc2Ksj1lFd8
         F7jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=o1pcUDs7yzvyytfVC+DZl2zwgNzgTGnZVy29A6i/vkk=;
        b=wSe0ELpDBBk6kDpNSFttI72WIHQmlETHuo5k5kOz9ku1LP7qkb51gm8L0sqpkm16C9
         daaUE9uIBZUS1pUlfMYFEhspRs7dU8VVm16fl7oZWe46rgpxykwPfmsPzfJOnJ4hJDlN
         lodGpllYsDyq4VbxcKda6NXym0zOsHUESw3WzDJm6bFklQOCc6jcl6ZkXU2EKxSsM0eE
         LOo6F4wF2NKmLvJIGw43qJxghgfeMMiVNy6RhShjqWga6pcGxGGON3OPckDKdSnRdU6+
         Z3JYyOJ/0hwDu/6aXj3KFoWs6206BaC6VVp+sBCcKefN/iKSNbhfXbhQ/+Xq/baAdBAa
         5cnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IK9QhIOZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=o1pcUDs7yzvyytfVC+DZl2zwgNzgTGnZVy29A6i/vkk=;
        b=KzqueUw9256+sgMgf5ZuENl99JGxycbjGuWK5rfOJf3cHPWHiZ0jMcY7SnNH8Vyuih
         WaglFCsEh9aM/7KOQiA8kmqsJZepWp4r0UkrsuT0tWJz16VyKL3AFBX+wXv/YecFpOhN
         CLTc7pyFINGbxX+yZ+Cu2o7Bw71xYzIIYwdDJjceU3vIMMW0SCA8GQ13p2kuat+sKQEY
         n1A97Fs9/UDMmtKT2Cv9exvlR9qz7uXuUwVct5cE3macVXjwDne594hOtfn/6iAGenHD
         nsXyqnAPjJph+We37ggr/Q7gmbSnPA5OgT21/39IjNABpFMDjL3O7qpLGpAksWGY+a28
         d7xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=o1pcUDs7yzvyytfVC+DZl2zwgNzgTGnZVy29A6i/vkk=;
        b=7bfR6bf3fTpucCluqY08NteI5rr0NyP7UzXNZLPhHohnKi7KyW1tY4+PhSQ0e3Rep4
         80BBKZMk7J5kbPx0CWa8zfMcFI9U+9FOdSUzE1ZOOw5BcyYhdtaRPe5u6LbfVwSJ62rG
         9h8LLX6nRRJd91fpeuMKsu1n2iLADUtfsx6kTkatu3zkLfHGS6l8//P/3dhAt6o10JAU
         iukI/BpL4/L0qbjNnYorcM4V3sZ86haarUpFT37lsl2A0eHbniAheodUR4gq9TcMe5LW
         f9NoIX206/F0+mH5dYQJRAaH8sDIek7Bwnw4EI364vqAvFmfXw9vJ8yY8bz5LvIYG6ye
         qGrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1foAHAUexN3G+4vgbZ6UH0VsPTmvptm2PD6EqCyhjBv7fhWCyk
	2i2MR9Wq1FmUUujcpvlyevA=
X-Google-Smtp-Source: AA6agR4pXOQvvUYuh3Zp0RwEB6nctXZv94QzaBfQYq0VpzydraqUPM2Hbv6g8Q1yc+KI26tnPJdzLQ==
X-Received: by 2002:a05:600c:a09:b0:3a6:8900:c651 with SMTP id z9-20020a05600c0a0900b003a68900c651mr5404370wmp.145.1662042586068;
        Thu, 01 Sep 2022 07:29:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c92:b0:3a3:13cc:215 with SMTP id
 k18-20020a05600c1c9200b003a313cc0215ls1755655wms.3.-pod-canary-gmail; Thu, 01
 Sep 2022 07:29:45 -0700 (PDT)
X-Received: by 2002:a7b:c051:0:b0:3a6:36fc:8429 with SMTP id u17-20020a7bc051000000b003a636fc8429mr5271784wmc.78.1662042585291;
        Thu, 01 Sep 2022 07:29:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662042585; cv=none;
        d=google.com; s=arc-20160816;
        b=J/BYq4mOwtXs+veFhJD8vEDEm+Y7+NxFj79VsdGlLN1Bcrix48SVDkLw5mwv4U5fUp
         tnsbxpMwqODx0rpy9ntNTzDUl4T1UKfT1wfMN2LjtDxGq7vw0dxGyeDaug3vDjXF84zQ
         P8X/dNkzMZ6yXK7y2ih6p5enNqA9LNniL5wGbwhsQurEMoxRvgRZWalDcE69Qh7P+RwH
         7fu0P3DH1/6O4gS2qR/3Ag7kNgUky8HmzQAA/kQQOOf1Zx8uVLCKDid2SLBadXyccFJi
         m6HerDghvt3H9p2uz7fjFsqZKiSps2ULK9o84lWNn7L/fIBlxjAhUc1nq3xfatoe6Rox
         w1Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=M1aDaZlKYEwz8CxoGUE2hJszPL7mnQtqrJRQw3RcAgQ=;
        b=Go9aedRS1iUd2JuPyiN75BpDawTrC5//JURcWvsG+rIAxbCDW6+PEHl5ML7FpDc4ce
         YkCYp339E5RfAW8t8OPSEG0p9FWSojRHSNk6uxTUw9rIgQ3A0/6AUZ4y4tcxNk+ieJ/3
         Prd+NMohTjz5RdN5SveYGJ1gRDm8WCe28SqLdEHrwRx33jYzNwMlenpfn7v/JY28svzG
         vt3GN1KD6XqZQZ72qYreKyI1L6re8leZwQHW+MZMEDBGNoAYWqsqytRHniIK46AhOhH2
         aK6SWC/kVUFdxeqDvS0py8ncHlh6hqnCA5dsQwzqL7bbvhQ+4EF9vhJV+hj4ueXuo5Ga
         RE7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IK9QhIOZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id 185-20020a1c19c2000000b003a66dd18895si482761wmz.4.2022.09.01.07.29.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 07:29:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
Date: Thu, 1 Sep 2022 10:29:37 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Mel Gorman <mgorman@suse.de>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220901142937.vsnq62e6gqytyth2@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <YxBYgcyP7IvMLJwq@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxBYgcyP7IvMLJwq@hirez.programming.kicks-ass.net>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IK9QhIOZ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 94.23.1.103 as
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

On Thu, Sep 01, 2022 at 09:00:17AM +0200, Peter Zijlstra wrote:
> On Wed, Aug 31, 2022 at 11:19:48AM +0100, Mel Gorman wrote:
> 
> > It's also unclear *who* would enable this. It looks like it would mostly
> > have value during the development stage of an embedded platform to track
> > kernel memory usage on a per-application basis in an environment where it
> > may be difficult to setup tracing and tracking. Would it ever be enabled
> > in production? 
> 
> Afaict this is developer only; it is all unconditional code.
> 
> > Would a distribution ever enable this? 
> 
> I would sincerely hope not. Because:
> 
> > If it's enabled, any overhead cannot be disabled/enabled at run or
> > boot time so anyone enabling this would carry the cost without never
> > necessarily consuming the data.
> 
> this.

We could make it a boot parameter, with the alternatives infrastructure - with a
bit of refactoring there'd be a single function call to nop out, and then we
could also drop the elf sections as well, so that when built in but disabled the
overhead would be practically nil.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901142937.vsnq62e6gqytyth2%40moria.home.lan.
