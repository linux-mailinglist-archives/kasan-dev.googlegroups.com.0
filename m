Return-Path: <kasan-dev+bncBCS2NBWRUIFBBCHAZCRAMGQEJ2Z5U2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD566F556F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:57:29 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ac76a31d08sf1158121fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:57:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683107849; cv=pass;
        d=google.com; s=arc-20160816;
        b=yMbeBCR5YbSSJCgsmGtjaKi43fSnpwQ1KfOKyGCxbB1VvJNBKauwkgkTNQs6NqOcb2
         xr1n2F0e1z0ZaxQCmlqAGzVe9Aqd8aubQM2eqRhJz3RlpPnSu0giy6qW0E+bdEyemwci
         6HEf/JQf7gfF4nQxamWzNHW1oN1VejBRh49A0iM7A1PIajFfdzuzepEWEUWlqNtsLVAw
         PiD3Li+271s1Wvbt+EzNj6Vrbi3ZnYtQ2Q7QqDBttI1RVI5+0JQDwnUHUv03AswjW4Vk
         y0X1nnSDjw7oDfTldv8aaA09ctO69aQ7Yaz4tE9nKIPQn2KhRNqmRcSdj0DDrweUmh9/
         FyFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=m1g61kUNieYODC9nk9u+ijHTJxVcW2tY2FBLghjt8sg=;
        b=OgKC5aAmt9szV8GGxxnLt87qJ9ebYGZMW4OTivshxj6KpFb5ZUafj7UQj9e+9Nbhc1
         +nWP7Y8q3+faJizofyNocufNok6OY8VUS0/Y9tKAB542R+zV2SonIB3ICc3FQm1VYPXs
         n/iBVcMAbm98nhhNWDcNL63RqdOrkk7YVKpCLYiopflJgK/IMqL+zp3G2MAWWOk4oNDv
         1Lpd041JmW4BS1/3ACoauX8ILOxL5zZUeBDmgP06/39utPHrUtoHcbU3oYjdjqN/v38X
         F0+wZO9N5/dQI0uvkaQ/R0ilT70lKKWDHbce7fR3EcUPKLdnXgE/si8Hrd1mPUrNBYMw
         +3uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="HUCOH/N8";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683107849; x=1685699849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=m1g61kUNieYODC9nk9u+ijHTJxVcW2tY2FBLghjt8sg=;
        b=gSGSnWS7xaMXwLq26fdKvtDV7DD2T0yiFVbYM2b5JS4DdirHHBvi7Cf9ohtC4KHst7
         X2DaxNAgxn6pwLoR23KiyWR3UcaAwB6s6bq6csS1jltyG4SsARfJr1AgxoxBFPBkEelB
         2hqPx+cfcn0j7auHWntd1VMe3EAc34HU58z1N5NdS7wWQQEP9a4QJuCaYkZoJrKkzomq
         W8SP0OG93uxkiD63rjuHC2hoz7DagLSr8QmtgLHLl8zWYsd2sfXBfDM2wupi+KzUhGYn
         EvQPD0W4hsrJ1Tv8GbqWeA5C4bO3qf/6a4RsKxJP+LN7D02s44YfQR+93jFHpveCdQdJ
         tHLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683107849; x=1685699849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m1g61kUNieYODC9nk9u+ijHTJxVcW2tY2FBLghjt8sg=;
        b=MN9NxZJ7Q42tCuoYCoJp+FiOqNcwCqFscq1Dt/7W9Cbbob00C+GMLxEY36BkiwcW0u
         XP5iNSLH46+mBnACxl6tTRfQvhhhHCoVtT4Q7NnhTVtjnUEdYEkuDb5OCCDPg9r8euVv
         HJZnyKa6df2yu/iyZrViCsk0aQ0itYflFicUpcwsuHhsCZRwGfWd/GdU0rQIpYITm6aS
         Vvplj+kBhPTzVV16aDIv3PKkJSW5lF7VjHy99CWBsEgWscTajx2IVjyAL7h3C7APWZuX
         erdlgV4d293na9MyQhQEtqfQEl/sfaksOePhMbXVjwzL3sVfgf9P+VVKwKgP8PEyMLEq
         Ba0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyBRwZ6xwWpcBu+YRcub/qsgJGuEn0qRVVySzf2WHPb5U9v5Rat
	aNwwHKhqV8YsspFJWfTS21Q=
X-Google-Smtp-Source: ACHHUZ5A01dB7JVZiO03dWd29J0UItfOFkGm08duGhvePFY3w0iCTVykuCQrFS3PNOoR/6VsvAwefA==
X-Received: by 2002:ac2:5926:0:b0:4e8:3ef8:8b5c with SMTP id v6-20020ac25926000000b004e83ef88b5cmr674639lfi.8.1683107848790;
        Wed, 03 May 2023 02:57:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c2:b0:4ed:c108:7214 with SMTP id
 k2-20020a05651239c200b004edc1087214ls248332lfu.3.-pod-prod-gmail; Wed, 03 May
 2023 02:57:27 -0700 (PDT)
X-Received: by 2002:a05:6512:11ef:b0:4ed:bb8c:5058 with SMTP id p15-20020a05651211ef00b004edbb8c5058mr355114lfs.6.1683107847480;
        Wed, 03 May 2023 02:57:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683107847; cv=none;
        d=google.com; s=arc-20160816;
        b=rfwqJ2W9c0tIqX/3U07Xi0PpRLej3FWjwvv2EtsnqPKXljXqoNU27WGTp6vzCIRe1x
         Or55lRktRzPidvnl/WhtY61dRNVUwQk9YmDGjtd1nFctBZIH+QFTxPiZi0mNaZTH6kyd
         +zmVlxTuV/18PH+CnqjL1hNMCk/5NXW/v4e+esGAjYoHNdur3sKSfx454MxFT1NIEfxa
         yNWZo2LPY3CIyprKfPpRhKX9MEHHSvFNRtiqqKQKYwI3ys0Z3UxXw5yQP2Y1NJCg/ZQQ
         zVMfXtn9sogh9HsFU4wv1h1mJwYEdDYrCoR4fyH0802r9daa5IFFuEYHFlzxcqrPnLsI
         E2cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=sUxQsWcAayZPSDpvKJX6MVjvEYhxJEaesagDt8ESMoA=;
        b=A1kSuIcCXMPFzNkbzR5DFx0B1tFilOpCoXe0HTIsvhV7G4xbIqEvENnGAWU+hjdfk5
         rwUA2Ob6g9w7tS3CnxqaUGlmRIf6Sjl8kQWGaFdvhe/DR1X9+H8LqwK53t4tBjtpwoZo
         aXg14Ec12vUcqacmuoNz1/jy77E94yAXC0rVkhy+7ztH0KJv2TA6HLApJNuB98OOc4Qx
         qyOVeA+5H2AnC9MwA3ics3Sj0UxgA/65/fMZX2GQ8udpV+9JXtDatEaFySTT2drzeZ8l
         owMemgNhKafJoxEw6HEQOaE1OBWJWC5cwZN51BkTAGiC3PH+rvQNPBV6EgddNgG/cKqG
         Y2Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="HUCOH/N8";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-9.mta0.migadu.com (out-9.mta0.migadu.com. [91.218.175.9])
        by gmr-mx.google.com with ESMTPS id i16-20020a056512341000b004f1371664bfsi93382lfr.8.2023.05.03.02.57.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 02:57:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.9 as permitted sender) client-ip=91.218.175.9;
Date: Wed, 3 May 2023 05:57:15 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
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
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
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
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFIv+30UH7+ySCZr@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230503115051.30b8a97f@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="HUCOH/N8";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.9 as
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

On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> If anyone ever wants to use this code tagging framework for something
> else, they will also have to convert relevant functions to macros,
> slowly changing the kernel to a minefield where local identifiers,
> struct, union and enum tags, field names and labels must avoid name
> conflict with a tagged function. For now, I have to remember that
> alloc_pages is forbidden, but the list may grow.

Also, since you're not actually a kernel contributor yet...

It's not really good decorum to speculate in code review about things
that can be answered by just reading the code. If you're going to
comment, please do the necessary work to make sure you're saying
something that makes sense.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFIv%2B30UH7%2BySCZr%40moria.home.lan.
