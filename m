Return-Path: <kasan-dev+bncBCS2NBWRUIFBBZV5W6YAMGQEX44Q6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C8F897BCE
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 00:57:43 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4156e6f39c6sf1656155e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 15:57:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712185063; cv=pass;
        d=google.com; s=arc-20160816;
        b=qre4Na6eDYfjwdTMDPCeW5t0DH7HmXPV2otGHUVQkcrChLIOp7/1M1zAKk1/t55x4R
         wk8NokZ1TFDPlbjjreoV41ITyOWn9NCSynJIu/FPOT/rHWbn/vn0Qa8wU9/gS7pePijR
         YJLX90e4nhBg26PEBd5IHOe7/fQaofevLdAFYir4BtOhjMvnpr9L9k8GdtD/kHEjHIKc
         P7G9Ug7xN8bZJ+yelewoLdlotvCsuzcsVphogyG9pgoGk3agBx0nPOYDTClmssy14y4i
         zHtPtjGkF2Jenf600kSlFkZ2jb2Ruzg6BjA7kAhcDbq+wmVtRevu55ne1drEj4Qs8SAI
         UpXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zh97zTVWjlKJP9XxxakVknL//raZ9HfgSPX+sKTFWBU=;
        fh=LkSJ4ah5Qx7InIuyff/2SbtZQ+0oaA3L+JU5HcK0a/s=;
        b=HUslOCOm4fMGNqnAhIpuP8l64w5GBVY/1ichiLI7o++7KxVKId9wG/Fnc+WYNk0GEF
         SmSBmsQb86oGIHWp63Baf9V4m3TuCnk1KkT0x/dS9qskvfVrVT9fLg0CXcefzLPPt3Gw
         R8EKppLN404zA2R3jWvI+GEdOVSsu7yyXpW4C86xq+IVjVLhcZ+sKwj9+EwmufdeIbKU
         HLs1j96vt0NOjkn6pv7kTbYHXYYGNlTPacM1kmsHS8skySLdMNhZf6sptvb/eq9zz+yr
         3Ydl8CkJyeEpFZnBdWA9Yo5GeLgNFKghNuWl6N9nK1Oza1pEqaUBqtQV5HSQ99+30VdN
         ynLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=altBgIa+;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.180 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712185063; x=1712789863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zh97zTVWjlKJP9XxxakVknL//raZ9HfgSPX+sKTFWBU=;
        b=dgnRw/PrPqNmJ3Wsi3Y7NHGFPqSHPXHOa4GoCDvwVmtw5U5ggeyHSS7TWakOwHhqBV
         HglNtdaehj5WmW+z8KL55cBKP0C455IiooPhtl3lkwdyIlHQGwIREiJu476cOBJnIuTT
         bEd6SVyjpwic/zLv5jUa4sRF291I2zo4B8oaZ3iIuNThRsUEftYDXN9DHHHJQ7DZrpTZ
         3vbyxuUvBwXHtC1zqk1Xe+Umsyp/2NBUg0o37+MM8oGgosGR7Da/VBN10avPUSgUYQr8
         S3Oq+17wfTHNFhD42cHWPuU+s/VLsu3dOVCFjLfrJyq3HJ2TgdhONhBRwr6faNP2W49z
         KR0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712185063; x=1712789863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zh97zTVWjlKJP9XxxakVknL//raZ9HfgSPX+sKTFWBU=;
        b=nMZtUkBmxr/94VifxgZkil6V4+1H2ErmITH9DQeAfsblxsPqPKSdj4U2zHSb/1cG0Z
         UWJY8fQE4EGCgsQwZf0vDWdi3dBAHosyU3ANbqT8UgvuD5BRYLBU0Nl4FvdJcfgC3QGR
         2AgHc8poEmH3OSfL0QB7jjnLX0B/x/1uXRKcYBBvMkFBR4LrnRuLehNTLKfYxB2y5LIt
         hJWuW7lHwQ69U9Oqlm6cYtdeLw30zenid0ZWuZLOc/WDBVb61OHIhs11JbRGVNN4nKDk
         zypvqwtRV0Pz93JjyMBnl0dEoH49r3bY6YHaFpVvIcpUeD2fYBwt2/QtJTEYCZDyd+8H
         10Xg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXIOi36RQ94T5lgxWiw1k3wdg0dQqw159gjUfQrLthAZXZHXgT2UsvX6k2t839RydRvD1prr7KXU04SV9EG9L3xp3qlcb4PQQ==
X-Gm-Message-State: AOJu0Yx50f+XS85OBeZSKG2056seOM1Ir/rpogK9358sjrTXvc/i4Rdy
	xDzRSHQRqCLn8jfsYq5R2w9j7gvMwKV7MeZLvfRfTeYzjsZ7T64b
X-Google-Smtp-Source: AGHT+IGVMU6a1yDz76Ij4kjgG0BcIUmRdTxXvNQKl+nvlWb3WB608Q/ulDhBIqyI2BFR2mk0ry+lAg==
X-Received: by 2002:a05:600c:5594:b0:414:8e02:e432 with SMTP id jp20-20020a05600c559400b004148e02e432mr763608wmb.7.1712185062819;
        Wed, 03 Apr 2024 15:57:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5119:b0:414:8085:fba3 with SMTP id
 o25-20020a05600c511900b004148085fba3ls235625wms.1.-pod-prod-09-eu; Wed, 03
 Apr 2024 15:57:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVY/hknCyvZesMZV4BlybAwqlD2VTYRMR4up0qc6gnN5+MOWJ/qdqMvl1Q0t+S3WYtZErHVuAanOGExD2VWe63FuU3XaD0g3XeDWA==
X-Received: by 2002:a05:600c:63c2:b0:415:611c:cb1a with SMTP id dx2-20020a05600c63c200b00415611ccb1amr659442wmb.1.1712185060800;
        Wed, 03 Apr 2024 15:57:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712185060; cv=none;
        d=google.com; s=arc-20160816;
        b=ycAGNiglblDGoSDxDnU7mU4M/mCqSsIXWi89OusS/5ESWOURmCkikTacTl4YjyESRm
         q55HJKXns1iWaHZYGgXESSY/KkiWeNJHz7X4tj1LKd0T97F1FHAd0LHie2UvXzpr+c+1
         /h2KvA7u20k4XEyMwFaDDTuRnQDEDFAhiEG9P0GcVKL+jYHtV5t/IzMCKSh3HHmeZoYz
         WJ3t23e0VsTjJDvBf5lqIO+lNsySxKJO/UrnEnzFcmd6S5rOeT1exjnCQhJFyWd6KjzO
         VRILWGHNWZXb1CWpqLLUg9aHLiEagI8E7CNIAgNhyeJw7SL6lEaDrbUMwfBtEzhaBndn
         yNyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=AWtiyFTqYKwdJDHyaCD82L5617uAdz2F4Sz0PAghbhE=;
        fh=Cvd2qU/n69ekUZ5C/BVx8i0k6HqFK2TNJpIynkT6Ch0=;
        b=gI8+ykTbl/kq6q8HjBuj79UscpMhmoNmdfwvgc396q52+3tt8MDjsowGLLbXwnoT/z
         UFhRI/Z5DknUM9TvjkQaUK8eKuY8UDZfeCzzd8v/FH/rV2kLrnZkwf/vtLYXEYjsasGb
         hV8GEGMwFvArCEWw74ygf//JvYhk/cL6UVYTbWZHVRXJ9BVBwKfg799tIV9uyecSZ5Pr
         XaWPtQ4GdzeQRKBCWwOXJHfcILok18POqUmdUOTrk2iTg39e8QsIbRxoxe3A9sk9p4fV
         nfbiJiA3o/fckYXz2YVW5ckZj5KFb12wW9xSlvGFoPDFD9wv5yENCQIOHqWBAKCgdh1d
         HH0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=altBgIa+;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.180 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta1.migadu.com (out-180.mta1.migadu.com. [95.215.58.180])
        by gmr-mx.google.com with ESMTPS id b11-20020a05600c4e0b00b0041496b15bc4si216943wmq.0.2024.04.03.15.57.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 15:57:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.180 as permitted sender) client-ip=95.215.58.180;
Date: Wed, 3 Apr 2024 18:57:28 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: David Hildenbrand <david@redhat.com>
Cc: Nathan Chancellor <nathan@kernel.org>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, dennis@kernel.org, 
	jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
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
Subject: Re: [PATCH v6 01/37] fix missing vmalloc.h includes
Message-ID: <qyyo6mjctqm734utdjen4ozhoo3t4ikswzjfjnemp7olwdgyt4@qifwishdzul4>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-2-surenb@google.com>
 <20240403211240.GA307137@dev-arch.thelio-3990X>
 <4qk7f3ra5lrqhtvmipmacgzo5qwnugrfxn5dd3j4wubzwqvmv4@vzdhpalbmob3>
 <9e2d09f8-2234-42f3-8481-87bbd9ad4def@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9e2d09f8-2234-42f3-8481-87bbd9ad4def@redhat.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=altBgIa+;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.180 as
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

On Wed, Apr 03, 2024 at 11:48:12PM +0200, David Hildenbrand wrote:
> On 03.04.24 23:41, Kent Overstreet wrote:
> > On Wed, Apr 03, 2024 at 02:12:40PM -0700, Nathan Chancellor wrote:
> > > On Thu, Mar 21, 2024 at 09:36:23AM -0700, Suren Baghdasaryan wrote:
> > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > 
> > > > The next patch drops vmalloc.h from a system header in order to fix
> > > > a circular dependency; this adds it to all the files that were pulling
> > > > it in implicitly.
> > > > 
> > > > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > > Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
> > > 
> > > I bisected an error that I see when building ARCH=loongarch allmodconfig
> > > to commit 302519d9e80a ("asm-generic/io.h: kill vmalloc.h dependency")
> > > in -next, which tells me that this patch likely needs to contain
> > > something along the following lines, as LoongArch was getting
> > > include/linux/sizes.h transitively through the vmalloc.h include in
> > > include/asm-generic/io.h.
> > 
> > gcc doesn't appear to be packaged for loongarch for debian (most other
> > cross compilers are), so that's going to make it hard for me to test
> > anything...
> 
> The latest cross-compilers from Arnd [1] include a 13.2.0 one for
> loongarch64 that works for me. Just in case you haven't heard of Arnds work
> before and want to give it a shot.
> 
> [1] https://mirrors.edge.kernel.org/pub/tools/crosstool/

Thanks for the pointer - but something seems to be busted with the
loongarch build, if I'm not mistaken; one of the included headers
references loongarch-def.h, but that's not included.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/qyyo6mjctqm734utdjen4ozhoo3t4ikswzjfjnemp7olwdgyt4%40qifwishdzul4.
