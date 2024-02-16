Return-Path: <kasan-dev+bncBCS2NBWRUIFBBTPHXKXAMGQEMZRI2MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9767D8572FF
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 02:01:02 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5128f949164sf316917e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:01:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708045262; cv=pass;
        d=google.com; s=arc-20160816;
        b=rHtR/1lueIxjHfJo9DJnbEVkUJctGIr/gsqEsO5MA4SoD6QJDMp5uRGNeCVOr+VsJf
         gc7MRVoXZHPasuYpK0D3f+6fLFBht3R+ZMquBYpXE0TY+Fpp2o3OKzpnzayPEyzVCTck
         pAWVg+u/3wQWl1vLNyVg73UB/XldLWCVQhHgyzmtgY34YmtGefqzbCQVyfl/aX1xbHpv
         mOT5FViWTbcCxZGdiJHFp80Q/v6AgJOgTtH0GDyeifnsuQ7Fn82fPysdWOf9DnLSXKbd
         MAXf0SVjVDXfZQ5LIc6AVLiP9pO7G9SSTYJuRRsaPAAvrSTbnZgJOdnbnfiPIidmumyS
         XYhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4Z2MzhFx1D0qW8g5VsG3jle71WFR7heIq2BP/yTgKKM=;
        fh=1kDz8VDimNKYjJzTCEIgn3Zbo/5gm+9QioBlmyBWEm4=;
        b=TMyEkX6AMD8zMDxJL2WzCe9eguXz1SNBU8csn/1FI/obmYto+zNrUcWE1z7Qoylojk
         aCzQ4kEUiq2eXPNx5NVdrDaG3otJpL4Wos0E+D6EUCNtd5fLQaWDv583zpaHAtLq78X2
         4Pjz21irLNxRX53CaNutc7AUqDzb43I3GryiNGDCgZJt5RPybnmG+Ef+O3JIiRRsbMrI
         PaRyfRIdra7mlwPlOwiL9kg49YiaptGCvgbgA+u9vK2TBHqg7IxCfgtY6EGliYKxs3lb
         XfOg1rYEcm6xXLuta+fv1qa3Gt6CvIlvn9hmG2DEimjLR1OR10qnFRApZD9R3sBS5MUY
         lB4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VwI1BtmZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708045262; x=1708650062; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4Z2MzhFx1D0qW8g5VsG3jle71WFR7heIq2BP/yTgKKM=;
        b=x1HWaOcPOaHJT5/wzCyYGd0PHO0dYzfegiCWWnmrHtzUpqNmRpde5jev+/GDoEPfMt
         /qyfsYZ/5hTYL40omp1Z2t6oFKTFW5mCX8hf5kA5+XqWyGEl/jJcVcpwwenEmE7Nv92K
         nVw1jthRUCbzHvNtmGRACymblzz9cYXIBoG/Wqe8alu5ms3ByVCMSlGpwgcINPfN5gYQ
         cWZ3AzrhtKfZslOHlBISeasOPCGQTBqovhK/M7v6ZvilqhG0a+UrhZJe/l8b3SvQnfbL
         3g/+OceZbBRL75lHOOx/UlHoBSjkc3mgOWv6CKRRwb/eu3TFho7ZtHDiC93w7RXCcA1q
         Sa8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708045262; x=1708650062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4Z2MzhFx1D0qW8g5VsG3jle71WFR7heIq2BP/yTgKKM=;
        b=IGdrzgH9TsCnQuv3iENi2hHJBEA7RgYDgVVOMuyN3uQDDuBjWfGcMh/FPpBuOVm4o+
         jCPjukJPXe5RinU9sr1hzlENFHRkzbQ4NJai8cR7ehCIHZR8ryUUHMfJJ1urHXFWBqcf
         7ES9NeZry5BU/3cWRvGqyTq9bNDWu+G1nKoUMbNWuDCGZuMx7ZKRsTUw1GMNF44BYuvv
         8S57OgYp6Ay4D09nXxoyTuaSwvulNQG7opSwDW0kS1AsnF5pXhRyz9X3Ngnvnq4eAaRy
         KDVGR6RVNLtQAUpqVKpbvTUFa7I5PdvqvEQ9tMvb2QG1aHgUdEgr8vt6XmzMA7VavLIn
         gNtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHbM6P893VfJ4JwrbJilMxLPSUuBPYHuNppoV6cPiu0K2AQ1+ZbS6wwzBfbTLMogZsGT8tLdPl+z6pRB8zTkZvOKTPRsMihg==
X-Gm-Message-State: AOJu0Yy9Wf7CtRoA8ynRo1vzMBGjQGh8VxC6Caldm/s+r8W1Nloe5qs8
	j8f0bf26jUb3Anvz03pbBywTrUgqF6E769lguL1YTlDi5N+3tTrM
X-Google-Smtp-Source: AGHT+IFtLEglw47xDFpG6MGk9Mhcd2fAK9efrL53LepjfwK+0+WGV7a9wguGeK7sNMixOWd17mlx4w==
X-Received: by 2002:ac2:4156:0:b0:511:8124:f1e0 with SMTP id c22-20020ac24156000000b005118124f1e0mr2206048lfi.55.1708045261561;
        Thu, 15 Feb 2024 17:01:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3705:b0:561:f0f1:15bb with SMTP id
 ek5-20020a056402370500b00561f0f115bbls115869edb.2.-pod-prod-02-eu; Thu, 15
 Feb 2024 17:01:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxSXhnJ+CHSZ+n1Oju6ofC3miHQcRc//2ym+seJ9S3/ZH5az+ZcBuAxuZgxPTmNkTEE6s/0BNl/wstnxu6xgNk7Hib90qQxZmp0A==
X-Received: by 2002:a17:906:370b:b0:a3d:254d:5aaa with SMTP id d11-20020a170906370b00b00a3d254d5aaamr2426999ejc.63.1708045259720;
        Thu, 15 Feb 2024 17:00:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708045259; cv=none;
        d=google.com; s=arc-20160816;
        b=v4wgN7lkOSChwuNQQIUOc3gNrlU2bXiBKD7Q6aDthhNYuSd8ECNSysB/LnPC9xilgM
         9chtEKKuE5ZZrQDCa0pDCUP+6be97Ip8PLpTQoJk9DUihDw9MUYtBGpdEy1oNfke+PwL
         /L/X0vOtobVIxH9aPqoK/L54JJUQVPdSNlJpQ0OZj3lA852wX1QS4EQrTicaM2AktnFR
         UxK2V5Z3rm3i0nKcdHlv01PCsFlwmovXypIyKFX8K14cGZozH4YFegVzA+pLEkoqcwwU
         lZClH85fzAdwYG15bErJK/jQiGv3NE5GQRWRm8vcvQNSIp0xf3647o+ZOaEnKWKCwKI9
         54EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=BBDDxkjYnEavfD3mPCDXRmZmPfVkLnkDBgf+7vi9zKM=;
        fh=xYP8sXCjEJ5CP51l6T9LlZfmVzY6xy06tszhu3TuQ5s=;
        b=N8n0J4GpckIbm686WPncmp4EgxOr0Mh/Ezf6p1m6PxtCxxMhzIVirc6hsaSFGBcb4z
         EYN9D1+2GZVoFaVm5IWN5BM1tKMnBPBYcKip6dC9LdFnxaDZcZ6NGeIFx8a4FHMAm4Yu
         DFmYZuds16Opf0+0tUaX244M9KzAdgtPKsGBEgZv7FV82UU+PDokl2UTu/Haz/1jx5fk
         1B+/0cyFXosskyFBdKPs8vM293jhkTFAgxDAJtaQaQMl6vlID6UAhhfgoO4Cg7tKzLeB
         TmXGcILXWfsz9dXMg/1wO3MKyNOmJWKcdicBRVCzQgmSdeJgzfNZPmBB1mSvN8OwajF8
         5MAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VwI1BtmZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [95.215.58.170])
        by gmr-mx.google.com with ESMTPS id qf11-20020a1709077f0b00b00a3ddbfe5347si4943ejc.2.2024.02.15.17.00.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 17:00:59 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.170 as permitted sender) client-ip=95.215.58.170;
Date: Thu, 15 Feb 2024 20:00:44 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Suren Baghdasaryan <surenb@google.com>, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VwI1BtmZ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.170 as
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

On Thu, Feb 15, 2024 at 04:54:38PM -0800, Andrew Morton wrote:
> On Mon, 12 Feb 2024 13:38:59 -0800 Suren Baghdasaryan <surenb@google.com> wrote:
> 
> > +Example output.
> > +
> > +::
> > +
> > +    > cat /proc/allocinfo
> > +
> > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc_order
> > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_slab_obj_exts
> > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pages_exact
> > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
> 
> I don't really like the fancy MiB stuff.  Wouldn't it be better to just
> present the amount of memory in plain old bytes, so people can use sort
> -n on it?

They can use sort -h on it; the string_get_size() patch was specifically
so that we could make the output compatible with sort -h

> And it's easier to tell big-from-small at a glance because
> big has more digits.
> 
> Also, the first thing any sort of downstream processing of this data is
> going to have to do is to convert the fancified output back into
> plain-old-bytes.  So why not just emit plain-old-bytes?
> 
> If someone wants the fancy output (and nobody does) then that can be
> done in userspace.

I like simpler, more discoverable tools; e.g. we've got a bunch of
interesting stuff in scripts/ but it doesn't get used nearly as much -
not as accessible as cat'ing a file, definitely not going to be
installed by default.

I'm just optimizing for the most common use case. I doubt there's going
to be nearly as much consumption by tools, and I'm ok with making them
do the conversion back to bytes if they really need it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt%40pm3d3k6rn7pm.
