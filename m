Return-Path: <kasan-dev+bncBCS2NBWRUIFBBCXNV6XAMGQECFGLPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id B642C853FB0
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:08:59 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-410e83001cbsf13165925e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:08:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707865739; cv=pass;
        d=google.com; s=arc-20160816;
        b=Me70f/WYYV9tecto1HwA7v/C4YgNdai28nBgbGqy0N93KJV5rVpy5xyWrw5ac2Qqy0
         nnu+xQhRe2v7bCemPye/NpVqFK8alH0YUsHSpBQ9DHk3Y75AhsHRbFNHDaiKaUApyx62
         A8DBjbnGN95tp2KoyLIo70rSGy6UZfLYy3mKVEpEYwEA1BSRedFcWpILTIyhvvy0ZOCY
         CG9hmUg9thoaAUXLmyZo95v3xujc3a7fclVux2TpOJaaTUX2JtClUZKJuIrUoXn57L4P
         xKIMxKvzsPKo0HG9reMSM8WSJ6qd4f/WJOOb2oS4xRDyaXyjpu8XNiPxB8Uv9JiSEfBY
         8XcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DZFZfREXa+eyB9qyzkYnscjCWWVMkjqxfv5C4+/Cz40=;
        fh=MQvsDG7yyfd1AUfewkjYUMtZ5k/1RmZ4C5n/iN1dUgI=;
        b=TXJwYNTC6sV0J58344K1g8uZJTwxWncmEZWOPtd37Y2VbFBUSRTw3JBy9tFubcjAan
         oUF+iRiJhdM9GaCsd1HH4EvncKxYXbLf26zxi/SS6idx4osucDuRTrbyacLpM2juI+NA
         UQerN7mTQW4657PEelo7oN5TZK7xk+FDjDjHXaNaTGFNJmt/rE5Gg8/lkknnjNEUW4l/
         0D62IKHNfvurss4DXEgqIeDtvmeH0UG84p2++61PSP+3q1y0/WYZ4m1SERuafTu28V2x
         DJhAO3uEXQ5rcbyZPyHUOThr5GmdncI8jFQNRPfPeHuyZ9i1Dqq6zBrhyPz4DuGAEi4p
         AzUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fgDMRJQx;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707865739; x=1708470539; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DZFZfREXa+eyB9qyzkYnscjCWWVMkjqxfv5C4+/Cz40=;
        b=vbOXXi15i047YsEZyeDFTpco6O5CJisnXyA6SpY8+QAHZ5EO459QeIFF9ttAwm20Wu
         ZmtuOZuFNPZB90HdVvQ27qY7C8FRe6VNHf4zALBZn33AetmOWiTCMhPdTkqrzhYQHPPm
         qkbVxDm01hu/579aH91ZHioZRhKVLfTV9SoqVHD9JdRD61GKPYMq4AoVUzyz/2rfymxE
         NNgdgYyO5IiWzCpRSEI+Q9dmy+/QunGGe2EV124uz94DA48Lmuq7dA/CyOnxj/6BIp0n
         jsj/c6YGk+vNRiRSsVkMKN4+gesNajqVg8aosTUtPjYWVtepwODAAfIdAqSC0WXOpP8U
         56RQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707865739; x=1708470539;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DZFZfREXa+eyB9qyzkYnscjCWWVMkjqxfv5C4+/Cz40=;
        b=EWOmkdrMcQjuMrdItb6jmm1q61a2fQBuGl3xPUOHZPDWcwo8PloE1z+wnMuLHhCj+m
         jShl72zIcMyx5Wj9aeWa798ru5JC8wQMfP6rVmRrzkjxpggsQD47P86CU/U8WycTqzls
         QJZ1H5OEEo9H95WHicGXHw0p1wMkDsNrn141ZWThoEfDD0ni+DAski7h+o164J70q8TS
         pN60ajUzvDOqwdcqnEIgyOpu2WDF02iEnY48/0xbfVtBBd+Sq0guQl7nk20o4kQJ/W34
         GAL+8COSMeciSUIFePjEK3MpNOVLiE37B7pRtqAzJY2/4oMK/xLDeVVfgBg9jFXbBlEJ
         Pgxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXthFMP74t4AkSu0Ppx98a0kgtstHlr0iTqZorNY7Wfcbm4K5p11XpLqJ1QNRBNg7GCw7Wr1M6rdr14HfjEfjgPebC0S7/JfA==
X-Gm-Message-State: AOJu0YxVCqUH2kSDUrdcSSDrzUrFpViOgd4Nu9/zWsjcUcy7Yl8hL75W
	YD8etyey1J0U9EpE1wg5WZoucw4BnzUvexjaq9zGgvPF5ZXV/0mR
X-Google-Smtp-Source: AGHT+IF/LnJzlWtrUZSWXGQC6bJOmxLyUdKtqpGst8i3WrnLkX0UdTARw8fTunNJK5btaeJMFiv2TA==
X-Received: by 2002:a05:600c:4f0e:b0:410:e90e:8317 with SMTP id l14-20020a05600c4f0e00b00410e90e8317mr907260wmq.27.1707865738732;
        Tue, 13 Feb 2024 15:08:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:690e:0:b0:337:cef4:7269 with SMTP id t14-20020a5d690e000000b00337cef47269ls1565455wru.0.-pod-prod-07-eu;
 Tue, 13 Feb 2024 15:08:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXkW6fs6Xpov2wr8fkEn5fJ5H6XXzPQKQCcAKNZn2AceBbpy39K08TQpTWr88B1TkabViSUKaK1y95OHMaLD0TgxxILq1jd6/LcYA==
X-Received: by 2002:adf:ea03:0:b0:33b:68fd:aff2 with SMTP id q3-20020adfea03000000b0033b68fdaff2mr469302wrm.24.1707865736908;
        Tue, 13 Feb 2024 15:08:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707865736; cv=none;
        d=google.com; s=arc-20160816;
        b=jLRPzoj51j3A0gem35LkuTyjGWufN7FslqFnbLhZC7e5ZE5RcSeFJJxpv0PXwzN2+4
         Q1eZCSX5aNWyPkWeBgOUzkS35MNdtCqyhvd8Cdyw4s5zBFhF2cDHskUbcqxav5hPmpDn
         A6QNvI9BbNOB5Lqc+MjYQrUx7sBkHFXvmkKNZr7yFcJD7Q0H09AoDNB27jXPMw1idu4v
         ZQjOmEz9yrqHIVpAkvi3eaTJttmgjgc1seV4TN0C7VsCa92tgEwDLyZEF/Xx36getMe+
         wDaWhEXobX7gLY5evcQ7gsGqyHSp9MYZLPWjKBUJbC838PQBGx2wGKdk0VFtdI3HJTwG
         ifig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=Mzqjn1+my5U+9pn6lTJcYt1NGpNIWi5Z/k5UXgeN0+U=;
        fh=bQU/oP/8Suw1kkT3RWCFpzVGasrX1tEzoW4HasrKFEU=;
        b=Kk9n2tFlI9TcrfCG/QY7K4W09O1GmbblRAjpltXmkttZ5d2L2ugAYLSRRT+JAeMHzG
         MbwO7/iBbpyZwNxlNT6GTB8COJElrqTXX7SHPoCisjm9u9Q96l4/jx065WQ0J2kR5VeB
         CPHkLc9UK9Y8dQ4Ynepp4gLLd5mAO1EXyPCydzrImxQEpD2oBad5BSjT9Ssr+6ji0C5R
         4CkGcKPvUCRm89wwtQZLQ61cSIMt7N1boktNuVrbO+lOGRWMthZmWnPvVNCJPrRTPAjb
         ZkiQpIhIAdU7VVJCRFhNExSPL9PUsezpXxAIALOsQnK4oRkqam0ZFs1FsAuXAr1IM+to
         Y3OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fgDMRJQx;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCVqKOZdx7ieL8WrMXzP5ZJUD49nGaMdYgQnBre/OOP9sDTL5xZ8Hhj97pIFPnjnru6/S7b9ULvGYDJX6cefuCS7Cyr7VnxaoJq2/g==
Received: from out-181.mta1.migadu.com (out-181.mta1.migadu.com. [95.215.58.181])
        by gmr-mx.google.com with ESMTPS id u3-20020adfed43000000b0033ce867f703si15100wro.5.2024.02.13.15.08.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:08:56 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as permitted sender) client-ip=95.215.58.181;
Date: Tue, 13 Feb 2024 18:08:45 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um@7rz23kesqdup>
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fgDMRJQx;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.181 as
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

On Tue, Feb 13, 2024 at 02:59:11PM -0800, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
> > > On 13.02.24 23:30, Suren Baghdasaryan wrote:
> > > > On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@re=
dhat.com> wrote:
> > > If you think you can easily achieve what Michal requested without all=
 that,
> > > good.
> >
> > He requested something?
>=20
> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> possible until the compiler feature is developed and deployed. And it
> still would require changes to the headers, so don't think it's worth
> delaying the feature for years.

Hang on, let's look at the actual code.

This is what instrumenting an allocation function looks like:

#define krealloc_array(...)                     alloc_hooks(krealloc_array_=
noprof(__VA_ARGS__))

IOW, we have to:
 - rename krealloc_array to krealloc_array_noprof
 - replace krealloc_array with a one wrapper macro call

Is this really all we're getting worked up over?

The renaming we need regardless, because the thing that makes this
approach efficient enough to run in production is that we account at
_one_ point in the callstack, we don't save entire backtraces.

And thus we need to explicitly annotate which one that is; which means
we need _noprof() versions of functions for when the accounting is done
by an outer wraper (e.g. mempool).

And, as I keep saying: that alloc_hooks() macro will also get us _per
callsite fault injection points_, and we really need that because - if
you guys have been paying attention to other threads - whenever moving
more stuff to PF_MEMALLOC_* flags comes up (including adding
PF_MEMALLOC_NORECLAIM), the issue of small allocations not failing and
not being testable keeps coming up.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ea5vqiv5rt5cdbrlrdep5flej2pysqbfvxau4cjjbho64652um%407rz23kesqdup=
.
