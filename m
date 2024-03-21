Return-Path: <kasan-dev+bncBCT4XGV33UIBBCPA6KXQMGQEIP2NRPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id EB0E28862F7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 23:09:14 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5dc4ffda13fsf1748795a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 15:09:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711058953; cv=pass;
        d=google.com; s=arc-20160816;
        b=xLR7TX+Q1zZhtuWX+nFAQfSh+amAfle3pqFIhwvvvd+LFSJnItuO+7dCAF9E7GlrjX
         d0KfwXdrI+7NDr2AcA5xekhFPhma+VbX+EpcgeEsGvVT/UPNEZvTrtlk+/hczXpVXRmQ
         URK8MOoRzCZ5FGXihQEonAEsfNRtCW4mqUSq076A6kdidnzF32WYRvI+IXNHCv2UieIC
         JlN7CWzl6xyFJyqook+PqZ0UTT8biGrSuymlzyqznWqX0uJakrG28xgoLUnAO6hoCazi
         odJ08y4I06k5ECR9RCZm/uqLScVzCx1/nJbbNRTf0CuVSxAjTS5z0iMas+xF3kXK5qCk
         E0UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ZCwLWX+7dUY797uJd63g2o4iNWRn97Hq3SkK4HnNcDU=;
        fh=IJMRSPATQA8Zk1hYnPYz/uJ4MUU7DSQ16PxF2OKlVsU=;
        b=iT8yFH1b3bZo4BzhWQGzVI3J3zc68bTgTAkAsLof1TwwZTCZwumC9Q+D3Sit3DZrx7
         nX2A1mVHxp6aQ4O2fW3oqD+CBRKlb0/Girpa7LyGXXxGMt6NjR4YVzD1KXaRvaTGRyX6
         vTgZzF1oS/QQIRFRPgr/pZgdghNdhwkLuLayew0NIGqmWBV/5yGSIbaVwSowq6xtBaQL
         2JiMfYzl7AxVGHf/qsAhJOBCEsJN18QlQci16+2ywflATl4PCbv/YOCnYI8vQs9eqK0a
         cJYD0pi4kPCYfGsMVotreuNWpYqbRKQs7wvIzbfFFs8k13+8FOSXw/AxbdV5lj7ZsfXM
         cn6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=y9CgARli;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711058953; x=1711663753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZCwLWX+7dUY797uJd63g2o4iNWRn97Hq3SkK4HnNcDU=;
        b=Ah7S11zy5X+huvjxaYCpxkkXCzCz8DPoOu+0FKz9NsBawonURimlf1ks00egSY2XPI
         Qm5Jw6Jiy0dmftYLvRTa7yydnWnQPrGNiFgi/kTc8E46uTtZYFcxE5rKsmUNBNz7xBZa
         WOm7R27IgeJUVFQ20zqUh0ivcO3AuRwLrNmXNzVjYSqAmofF+oeQZ7IZS+wSe6Rv1bLN
         DeERRgSTZjCG6IA3wyvgHPuKKaAtQJ2S17bdplXVfstChtC9mYitrkZgZGzo0HdJF4Pa
         jGrKT/EAhJatqgIM3YF71jmj3NBllPeUm18fnPg8+vBk7Z2tnX2eAtK5LjEtSQ4QN8Zd
         5pLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711058953; x=1711663753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZCwLWX+7dUY797uJd63g2o4iNWRn97Hq3SkK4HnNcDU=;
        b=auBsS46z3/3kIsLWKSWtPAS/FS+hU0EnBv+PgbwRI35cuGIgJWcqLx7QzeT2/jRV4X
         HQPHIc1Da2pkXiA1xndamNdVaFZSSPgc6eP0VdaEP8VQjAUj2w2DE7TxJy2OnGfu/mKm
         0oeHiGuDr2k3Rr8anRXLfB1mmGzuH1dRaMIMUJXaIFlfbrKM8339Ys31FXW4EIOppvSo
         6K6JYA0iKtBSIbXULxu3kBaEOCzSYWgHcyg3PUZtDrGtN+AK2NAil0L3jnHPqRvzvzki
         5rxPRYTh3KbGxug+K98P6m9L9wlOKH5Ytcue3byXdjuSOeJ2UkrpcLH4LXY586iYAcLO
         e8+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWR+jFnsTJj3UnXpjnn0R3oqwxiEBhoxrNd1vj8m2FmWcTLzfalPEtHgC7mfR8eafJ/yTsOpAHJnnFC+hqfG6lo2DNNcDMX+Q==
X-Gm-Message-State: AOJu0YyNBT0tTWLkYrl2hx7HWdFzvXCZuwvUxcnFtWmzsdEwLVTU6TEl
	Asn8iR/chLubKx0sFLN9ug8PoYUzGHn0YMaiwv+DPx2BrB/TUaDu
X-Google-Smtp-Source: AGHT+IGGN38yaSgdMpF9BW0HNSbp4euMva95ukqGTtfEcwFLngPB+c7uXe8n+n1QTYZ3bQtTuEt5dg==
X-Received: by 2002:a17:90a:c292:b0:2a0:298:536 with SMTP id f18-20020a17090ac29200b002a002980536mr428930pjt.19.1711058953378;
        Thu, 21 Mar 2024 15:09:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:f86:b0:2a0:2fa1:c5a2 with SMTP id
 ft6-20020a17090b0f8600b002a02fa1c5a2ls254518pjb.2.-pod-prod-00-us-canary;
 Thu, 21 Mar 2024 15:09:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRn5EhIa4lXRLF0v4C7Wq4QT9bJw8SkBpOwFnENfPvrJZBV4nXxy2Ud6oG4ZH4iO1j4HLNzwRDHWjhK7ZPa20+rRi7unUezXmgww==
X-Received: by 2002:a17:90b:3b41:b0:29f:7cb3:2fae with SMTP id ot1-20020a17090b3b4100b0029f7cb32faemr414647pjb.5.1711058951744;
        Thu, 21 Mar 2024 15:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711058951; cv=none;
        d=google.com; s=arc-20160816;
        b=KD5GD75kDfKtVhKKM7knDQRIkxQG5qinbA+8/kRxfQ/LLDLr0GFLrI+gw0CgBS5CNy
         nnRvUKvdSKjCSAu7iGWVlgGRmoGSeBQzaDsTlpi3a9p3TyGJ77ECPVk3yprszNyi1Rbj
         vJFpXyiitgkF6QL7qrrFLlOsMfMF4cmi8MzeTsm1k7h2RWcf/NaodDtPl7SBkedAzup8
         SsP64bH43I7CsMNeMaER1GVKOfP9ZbZMgWIxv24kOiriNKUZjxUZeLP3ogKrbQIk8vp9
         /fftrflO8y2QW0FqfjC523I14XbiVyWWa2An5MOZOQ2g50WbrT+Nd/MTcdqWfP2wL8v2
         dcbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HRQb5YRTVlNIAXd0VIxCSMS0uNvlXeeI/wipFWf3bZA=;
        fh=tq7onE5PvlRzb65pa9W5SWrr92xW5Gbh89TEHB7HKjs=;
        b=tithBcydyLQEzJER4m7Rn3De2NZ+2MDWCZYr1H3yLIYcODj5e+Hg1xVCvOuV0z5Ols
         J4t6JQlO6Mw+0bfTdPb7aWFuXOuG0SMxrXyAeUFEvWfqplQVKWORCMGp7V3Gw4jjvGWl
         r+Da0Td7Rx4tsq2Xl7F14mc6qrRSrH5c5VI80YLyJgo1mVYMlpz7y7ACXRRCvxlUM16Z
         L+7/CKNcJX8yWL4QiP+rhSX+30llPTRFHOwTWOJCcyPRT7+7UVqnfKUtJr50Nn1AFd/X
         YNnDVBerjML9kaP+yda5b0Kk1cj9kvKMIRzpdkcUZjUWQMVXbRkn+ohAM+sg2Zd0Kgml
         DvLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=y9CgARli;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x20-20020a17090aca1400b002a0251d08e8si215166pjt.3.2024.03.21.15.09.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 15:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E955C61248;
	Thu, 21 Mar 2024 22:09:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7C8F3C433F1;
	Thu, 21 Mar 2024 22:09:08 +0000 (UTC)
Date: Thu, 21 Mar 2024 15:09:08 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Alexander Viro
 <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
Message-Id: <20240321150908.48283ba55a6c786dee273ec3@linux-foundation.org>
In-Reply-To: <gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao@dpstjnacdubq>
References: <20240321163705.3067592-1-surenb@google.com>
	<20240321163705.3067592-6-surenb@google.com>
	<20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
	<gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao@dpstjnacdubq>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=y9CgARli;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 21 Mar 2024 17:15:39 -0400 Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Thu, Mar 21, 2024 at 01:31:47PM -0700, Andrew Morton wrote:
> > On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@google.com> wrote:
> > 
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > 
> > > We're introducing alloc tagging, which tracks memory allocations by
> > > callsite. Converting alloc_inode_sb() to a macro means allocations will
> > > be tracked by its caller, which is a bit more useful.
> > 
> > I'd have thought that there would be many similar
> > inlines-which-allocate-memory.  Such as, I dunno, jbd2_alloc_inode(). 
> > Do we have to go converting things to macros as people report
> > misleading or less useful results, or is there some more general
> > solution to this?
> 
> No, this is just what we have to do.

Well, this is something we strike in other contexts - kallsyms gives us
an inlined function and it's rarely what we wanted.

I think kallsyms has all the data which is needed to fix this - how
hard can it be to figure out that a particular function address lies
within an outer function?  I haven't looked...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321150908.48283ba55a6c786dee273ec3%40linux-foundation.org.
