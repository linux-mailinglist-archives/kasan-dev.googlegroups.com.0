Return-Path: <kasan-dev+bncBCS2NBWRUIFBBFP3ZGRAMGQEEPLR7UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 148506F5B19
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:28:23 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2a8bdcf87c4sf23203201fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:28:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683127702; cv=pass;
        d=google.com; s=arc-20160816;
        b=QgbRsDTlBjmwur0Mer20bceG9S8tmAcUafzhA3H5UZsEFrZbf4L9caSbUF4UIRzchw
         l1ov8L58hSKT7QajXBZHMgSSwWXajaiw60z8aAiWZNmrRfgmz7YKXasfX/AD9KBjj4Hm
         qBIWNASw4E4/pk0it+2LiL/7EhySZ1FBSsX4nGOaM9Zl5zWSEABxnDlMIAenIAvMuzym
         m1Jw9zJGxt/PAsvUYMdgN5kSGkTOKLcKNUNS0M4xGWWwblIpXTH9JUpAgDWMG+VanabX
         BNNrEK6nXTGpJA6hJsODVWfRtE2BwCMAwYS/BpNlnO4UjpP4efN9pPf7PY5ZRmgt8ZZ9
         pjcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=l0wVwmLv3BKWZOotgoKX6XGFLROZGMw9vUtxEDzKlc8=;
        b=1BRG0s6taZeBsNOkwIByVBoFulxaWg3xZuczEDwo2BZspAXdlaQQOHEEL+qSH5PcNd
         eMVcptQjtIntMiXX/4fAyzR1C7uYlJUls+i2GcgkP/Qu2GkRPcf1vtLweDxo2WjMxda/
         BB7jS1zJDkk3UKZTSbaG8Dj+/v/eAGcYxbrOs1ff+wMD45yiFBJYD8c1RHoCqUzqkD8w
         hJ5NQXwfJHnIB0Z69GRG5Cmi8Bx+C7kY24kZGjJjspwGDvMPyMi7EzelppZEwSF3wSJt
         +BV4a7wGCYS6gKal76hJIGn5ElYW9d5G+GNdiOkw0JGhrwaXS89OGhSwtHj1djHCQ7LF
         V69A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="boB83q/e";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.21 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683127702; x=1685719702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=l0wVwmLv3BKWZOotgoKX6XGFLROZGMw9vUtxEDzKlc8=;
        b=W1q5um6pGoh7gBYdyN5ZJlOtTjC8tvU3t1y030veGEAgPdzr5JDRz4Viym+mMbM2GP
         bdEVzlh3OZ8+IgFf5f4ZpN28ex8lRuez9+iokiZ+MIKlSpTNrLeF7ie3CzTuJRn/hzTm
         DPlyityDjikexzGsy3bcqI7XCWlFHcxrG0Xuz1way+eRqKPMgDHJzJkV9wm2wNJ9unUo
         tEc9htchixiAnFlTcpgJK4LchxzgTNAAm6foM94r1t5KtJ7PuF/xT7rvV25pB5eoQVfH
         SLRAk11/egkjsQBHofz9bouHVS8eSLJ3g97Pv8mA6c1dvgoj4deGjfRY5dmhoL8RdllK
         +iQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683127702; x=1685719702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l0wVwmLv3BKWZOotgoKX6XGFLROZGMw9vUtxEDzKlc8=;
        b=TANkj5ws+29ah74W8XzajGUMaTgD5eg4yHwyei35eIVgn+busvIg6krB+tm0ZJmOOh
         yA6UaSU5b2CQcGEcjZXPbIR9yj1pxmJKH3D6xFn0RelluCaYvUmBrAt1mFR14fSMugKR
         seE4S9OE8GIzjl6sZJNmORy4l4NADwbx+8SRMS+bXhHjfMSyV9TR18X8y3uG20/cZFeM
         jVcnSNTwhHiPhl5fVv8LW323uDyxiTuVJuP/CX10AUzv5GrIR89bj/PZ0RSfoK+YBPMj
         K/t0X1stzIMjTsEWM/ux9Fp5sBreW6vgzK+uDnaj2u2UOQiDSNX0AOAhRruTMUg4f1B5
         5FWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxENNpvNjOemrJWes90hHOF5nPg3D9eVyzQwXlOPtCUFJTeDyHS
	PVyfCf8oMkbTZc/fqxtzIOw=
X-Google-Smtp-Source: ACHHUZ7CCS1Sfdztx3cQ3miv2iYla3ofiDy5L11YY8QN+vKT5i9Q/3Jf7aZLaZSjTMmsfh3i1aTZ7Q==
X-Received: by 2002:a2e:b048:0:b0:2a7:a248:6840 with SMTP id d8-20020a2eb048000000b002a7a2486840mr106177ljl.8.1683127702142;
        Wed, 03 May 2023 08:28:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b15:b0:4e8:c8b4:347a with SMTP id
 w21-20020a0565120b1500b004e8c8b4347als979724lfu.1.-pod-prod-gmail; Wed, 03
 May 2023 08:28:20 -0700 (PDT)
X-Received: by 2002:ac2:508b:0:b0:4eb:dd2:f3d2 with SMTP id f11-20020ac2508b000000b004eb0dd2f3d2mr1191663lfm.43.1683127700873;
        Wed, 03 May 2023 08:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683127700; cv=none;
        d=google.com; s=arc-20160816;
        b=JWsz4IcdIJndBSTbKQjt1e5l7TRTZKiJB8w4lL7PjQylMO3n3CPt31I9ne5sanjvZr
         A+K7Y4wwCWmz1RO6gaZbAPkRYoSUpngFT0b9iqJ0l8b+udYYzbojgiFYprRmPfGMExRI
         qp8vyd3WvHBli6VrCNoLkimJqz2UeWW2/mYvmarefzoIgSas9izPienIaENOMOFt5mEl
         PyJRnQg+ZkqOs37WXqmq+6FUBszQE/1wG4gvrI7fuT+/2pDkU1QO/TUtMmWM8tw1PFmU
         0eLkekGlqc5FAQEi5Q/Q2jr8Eqd7jgfa/rtPqp6Jz6ypfQVoLDXRk0VNEtquZ4jj7Osk
         O6ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=rFYIJmhJAvKFo5pe5s/5UJk4QkyDXcesgOEFEoMRDNY=;
        b=xiPl133pLOFM7EFfJn3YjKPXJ1b8TrMapD3NehZug1GYE4sLcJql5XrOorhNjn2Fa4
         YVLjsM8qoS+acvIzcIVy5GQpuL/DQ3A4ifgR6JNSvqY0O+t5VBBBUPZJTCEX6XpJq19Y
         8i9t/GMm8wvK26UNiTLCgwdvnQYZd7r8PJD+1Gd++UdvPGHRYw3NkxQg2wRuOqpY0C3I
         s9Ya4CCXemUwv/oiCuhiT+Uz8xH2ai++mDp+i1Nf1D5gHhhd/iK83E3AkDNLvwy2KTuv
         sFVuMXyTjoBvexbc2STZ3IkcG5xdYX/lHgJAfJRODCNzqzE+AGrY88MgNAVQOxpQ6llQ
         fUVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="boB83q/e";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.21 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-21.mta1.migadu.com (out-21.mta1.migadu.com. [95.215.58.21])
        by gmr-mx.google.com with ESMTPS id be19-20020a056512251300b004edb55cd1e9si2484996lfb.1.2023.05.03.08.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 08:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.21 as permitted sender) client-ip=95.215.58.21;
Date: Wed, 3 May 2023 11:28:06 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: James Bottomley <James.Bottomley@hansenpartnership.com>
Cc: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>,
	Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
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
Message-ID: <ZFJ9hlQ3ZIU1XYCY@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <20230503115051.30b8a97f@meshulam.tesarici.cz>
 <ZFIv+30UH7+ySCZr@moria.home.lan>
 <25a1ea786712df5111d7d1db42490624ac63651e.camel@HansenPartnership.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <25a1ea786712df5111d7d1db42490624ac63651e.camel@HansenPartnership.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="boB83q/e";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.21 as
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

On Wed, May 03, 2023 at 08:33:48AM -0400, James Bottomley wrote:
> On Wed, 2023-05-03 at 05:57 -0400, Kent Overstreet wrote:
> > On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > > If anyone ever wants to use this code tagging framework for
> > > something
> > > else, they will also have to convert relevant functions to macros,
> > > slowly changing the kernel to a minefield where local identifiers,
> > > struct, union and enum tags, field names and labels must avoid name
> > > conflict with a tagged function. For now, I have to remember that
> > > alloc_pages is forbidden, but the list may grow.
> >=20
> > Also, since you're not actually a kernel contributor yet...
>=20
> You have an amazing talent for being wrong.  But even if you were
> actually right about this, it would be an ad hominem personal attack on
> a new contributor which crosses the line into unacceptable behaviour on
> the list and runs counter to our code of conduct.

...Err, what? That was intended _in no way_ as a personal attack.

If I was mistaken I do apologize, but lately I've run across quite a lot
of people offering review feedback to patches I post that turn out to
have 0 or 10 patches in the kernel, and - to be blunt - a pattern of
offering feedback in strong language with a presumption of experience
that takes a lot to respond to adequately on a technical basis.

I don't think a suggestion to spend a bit more time reading code instead
of speculating is out of order! We could all, put more effort into how
we offer review feedback.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFJ9hlQ3ZIU1XYCY%40moria.home.lan.
