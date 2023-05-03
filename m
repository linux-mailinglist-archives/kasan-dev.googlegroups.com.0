Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBSONZKRAMGQE2E5L6OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 62CB66F5DD1
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:24:10 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6a5db79c525sf4194031a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:24:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683138249; cv=pass;
        d=google.com; s=arc-20160816;
        b=vYEpMhjC7M9cEcq7ZF/hbBNSHlGyxS636cH6aI+fkrXTmA4zvWRysAojrmUECWpswN
         ZAaIb5c52xxnhAars3qCs7sauDecK+hbgEAycqXtCzce5hT4MMZMIA/MQ5jG5ErRuUdh
         gaIzwnYtwG0+7RDzPdq3ctuxIEvgw4ISTi8LcmfzNtsfoB4Bfszs0ivCqTwcv6a37MFg
         jgGfAxcvFI3s6+Gk+27Nu03arqy5sMHpqY0IshY6LPHGBIaGAR7esVGBeKJmUwLamrrR
         djIqJRYPS6lfhPBPVJfVR500iyx+EJ2Up8AuTHFsv8duZrMC7Z6KFXEWx0xHLGVC+Ezl
         bzIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=joAML1r/hjvS9ViDUzQcw65tA1AavxLL6wg63eHS8AU=;
        b=VGEtQwqpbT0YYGcry6ijclmBK342Pomfaybyx3y6y6Gnvp6CAjxjYmXSTTQMCUFXx0
         RoMDCSURGkoFl3iO3jWIWPsMbF3M9ayw06gruXNXve1iXtuOGMOsm3mmO0j45Y8kZJhM
         iQiFi00UXbfewIwSDb3HlDYurTp9jmKpFYUTiJlhEALjsScteyy7gj9sT+/I4o+/G9C2
         6N/rAc20pUrVn2dSXB8GJb8oRaOVolYNYWIWuigMXvGao6kdh7GJryb58V42QYHyAZZ1
         D8gBvw3Y3AduwW+8CBYx3VxFthXoYuvkm0JpNHnlYKfozz7dkfSWuRn3ctzjMi76YBaR
         QH3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=aB33hUnZ;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683138249; x=1685730249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=joAML1r/hjvS9ViDUzQcw65tA1AavxLL6wg63eHS8AU=;
        b=Ee/ziGeH/Cgml212ipm3Vkt+Eh2Q/OrSOfd1P1sT+jJw9brJcCh7Xt/nLQI/F0OZSv
         Np+SfSI0JMLxNyJs38KyLyMIhfwhTxL1qbS93rBDAOWEeZGGjgVwLHlAFERlVok1LxN7
         kh/9i+XMSFMnadj+I5pYjA/NDpAqPVUXSsPeO4boUoTNrIhZExW/I6EBBXw70NrO/2ax
         Dp6aEdim6zgbqgma31dIO0+oMPUWhxppwnkJPgE5uN61mnno0PXS0s4/9p+/7Ggv8qWf
         z1QXt2+UKeraG7J2o4K5CKg/L/E6KT6wHznQ3Yp1icoFGPMaK1BcQDhwqZ7krO75LkRj
         uTTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683138249; x=1685730249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=joAML1r/hjvS9ViDUzQcw65tA1AavxLL6wg63eHS8AU=;
        b=AbEcLddEbownqMDSXh9NMyFbxfcAC5zGXiug33e4uSW1fVaFKslWlgEOKYGF+U415x
         qQYo/YEbAM5ONGou0wur9Zds2DcmebQVw7VChtM3QGmNjCNtqduk7zxNTNjfC8J4cL9v
         ooazfg1qrKOjm18gBrYg2Dzgx4nPFFgu+9oefao0hAsSSdfvZIRZ4pzXRiYIckjaAMPq
         0AkUIXj3S7g4Im8LiHTAS82DMbAu/hksaSnpN+J27Jtvh3qhKGFzEmc1NNC0bN13pklF
         V7mb+5CqMMhoI8o7utyx0yD+8YsXR3q8BdVOSHQX91ewh3jAD3guRJq5l2BDIK4p2z8B
         SNbA==
X-Gm-Message-State: AC+VfDyNaW1oIn/kDzvNmUaltanNbnu6ylWW8ES/quC2q0v8McvkkOXY
	//bfS2XdoSXsI4kihfq1cRo=
X-Google-Smtp-Source: ACHHUZ42CJShYniSz+A+RsAtrMRwtzP1BMq78/tVI4wu8wFEmpk09RldG8V+cymUNfAWQOlKi4cnEg==
X-Received: by 2002:a05:6830:10d0:b0:6a6:38a6:e1b1 with SMTP id z16-20020a05683010d000b006a638a6e1b1mr5596130oto.4.1683138249314;
        Wed, 03 May 2023 11:24:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d111:b0:192:954d:4ae1 with SMTP id
 e17-20020a056870d11100b00192954d4ae1ls1315572oac.0.-pod-prod-gmail; Wed, 03
 May 2023 11:24:08 -0700 (PDT)
X-Received: by 2002:a05:6870:5304:b0:188:272:2f78 with SMTP id j4-20020a056870530400b0018802722f78mr10079396oan.41.1683138248762;
        Wed, 03 May 2023 11:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683138248; cv=none;
        d=google.com; s=arc-20160816;
        b=vb/RrWtT5NF0QPYdB617g4PMCzngfIls+VAqr50dn749BBWEbl3W7fF94AvO6sEteL
         R7gd0Bp1tiF1UluTG0SpaIzNGcKEUUMe6T7EeJGCAMl91w+WGaXzOy02e1t7I/7sgCrP
         eSWV6fxBYM7+ShG4DiBQeHmQihvtGRR92oCgUNTn/jJLZJm5Ofx/8BceL2biil5O05tl
         whkiHBj3lk5IQYzJghkbBH5yc40eWpuCBPXd4ka4EnwW5yFFRkOB8UESDsWNmqHF+1Md
         5fpLkvrm5goOSHCQ1qKuQIjB98ptVOwmNe5dGTaJvcLOZ+vVuB2ZBX3Vvs5tkIqvUpr0
         TkSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=HAaHXuopg20H7kDrY4ngFywwBOIWWtTHOJdh9Kk4ti8=;
        b=pHRguB+NaCEZzYAfHG/RXy0xNMSqbA8PQ/y22rWu2dCofBqMZ+7JfWONTyux9P9IVf
         49R63urP/zQfo7SDHLH1QHd8pRmquU7pm+XvWwstd2uhy6+OU6mYbh/wnTETgY7F3y9Q
         DTZAFJfos2lyOlrEwimCRIFhIJK9CsQ4y9Tn1xQj9dbMF76nb5JnNvyoYg4HnQnUBXeT
         kShRx6GygE1fF7fR+1IlxeD+wX/l8FnO2TliDz3nRZlvB5FnV2L4cxWlpLw+CibAHhz7
         4ZK+gBSoaqnnZA/kY2DngP0C7t9jI64kFOGuu1U8K25o1f3gsP0OutQ7ylvj48ywo+88
         k2ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=aB33hUnZ;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id ce7-20020a056830628700b006a5f36cbbb5si143551otb.4.2023.05.03.11.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-64359d9c531so487092b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:24:08 -0700 (PDT)
X-Received: by 2002:a05:6a20:1616:b0:f3:b764:5de3 with SMTP id l22-20020a056a20161600b000f3b7645de3mr27371733pzj.48.1683138248162;
        Wed, 03 May 2023 11:24:08 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id c17-20020a056a000ad100b005ae02dc5b94sm23989633pfl.219.2023.05.03.11.24.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:24:07 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 08:24:05 -1000
From: Tejun Heo <tj@kernel.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
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
Message-ID: <ZFKmxVXlk9xkQoPB@slm.duckdns.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <ZFKfG7bVuOAk27yP@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKfG7bVuOAk27yP@moria.home.lan>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=aB33hUnZ;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::42f as
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

Hello,

On Wed, May 03, 2023 at 01:51:23PM -0400, Kent Overstreet wrote:
> Do you have example output?

Not right now. It's from many months ago. It's just a script I could find
easily.

> TBH I'm skeptical that it's even possible to do full memory allocation
> profiling with tracing/bpf, due to recursive memory allocations and
> needing an index of outstanding allcations.

There are some issues e.g. w/ lossy updates which should be fixed from BPF
side but we do run BPF on every single packet and IO on most of our
machines, so basing this argument on whether tracking all memory allocations
from BPF is possible is probably not a winning strategy for this proposal.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKmxVXlk9xkQoPB%40slm.duckdns.org.
