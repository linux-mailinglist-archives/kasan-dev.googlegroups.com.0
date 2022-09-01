Return-Path: <kasan-dev+bncBCO3JTUR7UBRBKXVYCMAMGQEO3KSPEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 70E2B5A8CF3
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 06:52:59 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id v1-20020a056402348100b00448acc79177sf5780211edc.23
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 21:52:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662007979; cv=pass;
        d=google.com; s=arc-20160816;
        b=rzyrQNJoq7kIgeOFNeoKC6dPBVlY271oJS6uxHGshrfEH5SdGcP0zLXx1+3Sv3blTd
         viF4Fy2Dcw8uKb85ZQ9XHl9MW5uI9/DsmTN+n8SD7XdYk7CQagmoq8pUdo5q+al5vi7u
         IGDJnpcQBquChTt5oqqphXPyJxMzkdWWOiZEv61H+RV8ZIv8/JmTGdVFZtgKZH5RXFFf
         +tUMrg5gTNswaiUoFcYNnhydPo49Ik230qE3wKiS3xiy6CvHZ9u56LYDZtWrV66g5tky
         yo+yadsgIO++Tku72/alwz27bSqcaVT0BlwTsCFs9cjTWRw5YLEbWvPlOXujv4Vp80ke
         zAKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7QJQ4wkfDd7usEhW3FvVCTo96Xf7KjETkflO1Dz9ZYA=;
        b=lXrHHiNY2Jc7qX52e6BCzdwTl9jSA+TEQX6wJ0fh8WAbR4ymNc3/DOfwVshV5foCvj
         /eJTddTJD3hZHagVp/KOTjauFRsEqITxrvCB4O4Fh+Ka2zkjQy0y0vjt8S89ugojBN73
         WPsfw2wIbacKMxrFV3O6Zq/uJvBd/Om5yFYzRIF6oGRlIXOHOtqjQqThQZKEs4zI4ex2
         NWRljYFnuV4x/pp4ppZ9k5PmU6znhJdtTiz2NfZizAmebQeKnvosy9tFmJv+kkhTks18
         YW9sNZ3BNJgXlioaq055PYbGontREmtfuVHPs8JI/YcaATnZQULjV4+hP16SHfpu7H9B
         NWkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=MXuVo2yV;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.220.28 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=7QJQ4wkfDd7usEhW3FvVCTo96Xf7KjETkflO1Dz9ZYA=;
        b=WHarNR/fz6l1QgMIkHXjtQkhzPcc960ow4aaiAPdiIWYtyv0zD4kps5eVr9FTuTd6V
         So8nLCMcByMSs4x8qbDVyClpz8/hTh3aHaw6xERQ2kExKGWhqrGadga7976qgIOFZxHZ
         BfCMWHbSBAJn/nupYl8gTbbgqESRHJEIC/VpMiPC1cVgOxX6PgswMx3NqCDYCnG0babk
         tjnsm9JSkvH346qmeX/Ixdn3Nxlp0N2+Rsx1EVyL9rIx46jYdG+N92dHXbUpCdJ1LIsy
         vhmppc35ACkGXlGt6xzomR/kiX6+VuJWSUn/Gy1dXSKrRtZ3ROh2uSK8b74jJcU5Uvv7
         ZkZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=7QJQ4wkfDd7usEhW3FvVCTo96Xf7KjETkflO1Dz9ZYA=;
        b=fwMCvv2lppNKiyj8XN83GhP10vPpvGs7OMSeTKO7fUN7XiChaIJKaNPDyU+BROTWEC
         JSR/j2Ep4tVnka0WEe7v+/dRs3NyTKHgIybCN0I8iijnb8Lhxu1PpVAbHQpRw4nePeFJ
         K0DlTDqlnijNxs538JUm0OTrXXrbLXa4Yb9ZyvkfvqOSNEDMIQM75SMQf4sbyHjqznQD
         W+tH0+jZWN2pFIfjUXMBwnwLTtooxID0VMnttKjkf+Gna57vyQTF8U4DzRHJjypAjVY9
         mUaGWagxUUICSJIA6w4T0tlV2qIy9N402jO4wkxjIrnOPx65RdVW3tWKkXoqK541aABu
         VfTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3s4lQXI542fbteuZWxiNZOCdYiC+UiFeun/dDCVLOR57GvTZ5d
	r+hV0WGVKbz8B07pNCDVZ5Y=
X-Google-Smtp-Source: AA6agR6IrY8+hitDu1TVoSnXZ478D+R1wcaHhgnU+0V96E+OhjGaPsomFR2HoNCYl8C2XgbXtaxWhA==
X-Received: by 2002:a17:907:c24:b0:73d:7c20:cc45 with SMTP id ga36-20020a1709070c2400b0073d7c20cc45mr23180327ejc.294.1662007978946;
        Wed, 31 Aug 2022 21:52:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2803:b0:448:5d46:86b6 with SMTP id
 h3-20020a056402280300b004485d4686b6ls1243673ede.1.-pod-prod-gmail; Wed, 31
 Aug 2022 21:52:57 -0700 (PDT)
X-Received: by 2002:a05:6402:4411:b0:437:b723:72 with SMTP id y17-20020a056402441100b00437b7230072mr27933304eda.38.1662007977784;
        Wed, 31 Aug 2022 21:52:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662007977; cv=none;
        d=google.com; s=arc-20160816;
        b=UXlVhdShh99tSE9nu8w/phRzWfP9AkML1BhS2FMDUgw876iSthskOvlrKyTL16qD3N
         iPYeabFJZOjdefVFTkyO70fGlm6XZfxyNCvRqpxMy3RwG9mVZULw6crfTQ9/3aEq/OTy
         bogLTrSkyqXr4RvUMwIbD2EWGwla9b4xTkoXavfNGyBBBLmnVS7O+PKOaSJLAsW/0ifX
         lnYV9HFvXQwcPnqNTGqMTfR73401vQ1XT1QXXk9arVbKy4oWZ8Plm3m4rUFQ62h0o+Nj
         5lM0e3C8QyNAi6vkS6E1v8y9SHPHVswj6Hvu3W1NeOPumE//MGccJAcotRDlJorC5F2X
         txcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=eTDe59i5UNhXbLPqqFo4WrMbXbqRlxGLfSkkAQ8Fk/c=;
        b=NefzsavdtlgbeMaP+dijVTdIns3uxHj3Mtxea6gY6NvHpy9eqptyA2iPPQAdblULDy
         C7RlQk0hDKzQemTsOH+y3hulySPD1d4KoXHDX/Z+xzs9GLQTbhZd+FtCATROa/APKx95
         A8RNnff8jQqmJB8q2c2kjDsPyFBF+oLv5/zUo9vZpm08gUOaezFis1RofuTWTg7iZ6o3
         ijXH8At9n2rSxL+CNefJcwYmFZXyoVfYPoXwBBtk8uhCctVyvYksQrl1tdDc1t1O1llp
         ECuA2Wi0J5Rteq5KycSqFEt9kQSRfMrR1huL5uw5LmYGoGu6QQDG9ou/PcRGgbBhjcaO
         pr2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=MXuVo2yV;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.220.28 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c26-20020a056402101a00b0044608a57fbesi59800edu.4.2022.08.31.21.52.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 21:52:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4811C221FE;
	Thu,  1 Sep 2022 04:52:57 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 67DE3139C4;
	Thu,  1 Sep 2022 04:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id E7aqFqY6EGPsewAAMHmgww
	(envelope-from <osalvador@suse.de>); Thu, 01 Sep 2022 04:52:54 +0000
Date: Thu, 1 Sep 2022 06:52:52 +0200
From: Oscar Salvador <osalvador@suse.de>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, peterz@infradead.org,
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
Message-ID: <YxA6pCu0YNIiXkHf@localhost.localdomain>
References: <20220830214919.53220-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=MXuVo2yV;       dkim=neutral
 (no key) header.i=@suse.de;       spf=pass (google.com: domain of
 osalvador@suse.de designates 195.135.220.28 as permitted sender)
 smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> ===========================
> Code tagging framework
> ===========================
> Code tag is a structure identifying a specific location in the source code
> which is generated at compile time and can be embedded in an application-
> specific structure. Several applications of code tagging are included in
> this RFC, such as memory allocation tracking, dynamic fault injection,
> latency tracking and improved error code reporting.
> Basically, it takes the old trick of "define a special elf section for
> objects of a given type so that we can iterate over them at runtime" and
> creates a proper library for it.
> 
> ===========================
> Memory allocation tracking
> ===========================
> The goal for using codetags for memory allocation tracking is to minimize
> performance and memory overhead. By recording only the call count and
> allocation size, the required operations are kept at the minimum while
> collecting statistics for every allocation in the codebase. With that
> information, if users are interested in mode detailed context for a
> specific allocation, they can enable more in-depth context tracking,
> which includes capturing the pid, tgid, task name, allocation size,
> timestamp and call stack for every allocation at the specified code
> location.
> Memory allocation tracking is implemented in two parts:
> 
> part1: instruments page and slab allocators to record call count and total
> memory allocated at every allocation in the source code. Every time an
> allocation is performed by an instrumented allocator, the codetag at that
> location increments its call and size counters. Every time the memory is
> freed these counters are decremented. To decrement the counters upon free,
> allocated object needs a reference to its codetag. Page allocators use
> page_ext to record this reference while slab allocators use memcg_data of
> the slab page.
> The data is exposed to the user space via a read-only debugfs file called
> alloc_tags.

Hi Suren,

I just posted a patch [1] and reading through your changelog and seeing your PoC,
I think we have some kind of overlap.
My patchset aims to give you the stacktrace <-> relationship information and it is
achieved by a little amount of extra code mostly in page_owner.c/ and lib/stackdepot.

Of course, your works seems to be more complete wrt. the information you get.

I CCed you in case you want to have a look

[1] https://lkml.org/lkml/2022/9/1/36

Thanks


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxA6pCu0YNIiXkHf%40localhost.localdomain.
