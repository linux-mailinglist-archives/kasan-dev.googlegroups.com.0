Return-Path: <kasan-dev+bncBCS2NBWRUIFBBZP3WOXAMGQEIFFDAJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C66238550D1
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 18:52:38 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-51161bd080asf1835561e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 09:52:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707933158; cv=pass;
        d=google.com; s=arc-20160816;
        b=pnmG+3l62UX/PfAJkJQXf8w78FKPAdSPXDmyQyv5fMguHMuPaY9d5nVJaecJfP0Lyi
         Dm6d8tVql+mmUIzFQdgsJkiQ3CZS9UYWohHYZY6J5pt369yq48JM02ixvETqBaJWdTLh
         UsOd5l2xjl2Rl1OKLnVvv4P1h1d79dsAzfqjK/LZDhVPN2qUgEjVjuL3U0s/VMqUxGVR
         +nCYMNJQNFisJUg+AkGgdVVQ+W6A9Be63aYRejsY/Vo2fyKGkKqjncuXpVXKEUEEWLdf
         48e6sDeCnGK//zzE/hdxvfWNAeNZq+4fYKxoJmNgkgbZoKwf64ZFnRifxKOjNoZE9azX
         Kreg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tDOKgI6aSPZHa3pzNse1heGwAYCNP712Khr07mzfzcc=;
        fh=htaWqqjlav3Qp722T4k3u7Hl9WuvkWAHlzxSw299Dwk=;
        b=f+cLFKrNjNXrKIrZNGVt2Netj3V1P7QOk4ELippgjUT1Gucdqwu58yp/zsJeYJ9Jec
         AGdRGxBIUUPPXCkF4P5tOySNiOQdqKbSyYaF6EI0x3KNivaqSkPmn7up+qHK9VNB7Gco
         0tVanyJ1uOoTc186gsBff70npFVFxO6jJaCSj6GNFseoNfi2NP1N7GbqKdA7tK37puVC
         hqrUcp0sb2Saqkc6+Eob8tHi33aRGOUzWqgtWDgqSjH4LCeqtLuhXM5MkPxzB6k4wGtI
         Om1ev+x88mgysyYYgNUVPiT9WUJrqu9Ne+LeZrM+WrAyXFPccbzM7fDjbZfItccMrp7c
         uyPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IUp0RzOj;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707933158; x=1708537958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tDOKgI6aSPZHa3pzNse1heGwAYCNP712Khr07mzfzcc=;
        b=sxE+GGFHGerWxAf24zNpE3v4pNKdEExokG+FIU+ktKlNbSI9+9A7S08ED2PdDqpPpe
         gVRDQzaJhFmWGxoK+gEsAO0FuOXPWacigWe6lazsEyqTv+m7qiw7cDcgaPm5DrodmKWF
         I1W0GlKyTr+8PHRnywEhlEihCNWTazWIXQJI7lsBH/CYkqejVx26b2mNicL9Y3yKqaqU
         bm4wUY+56H5DA2qd46sFuz4y0GyxKJf6Yu7jw4nSfkcb7yo3tLq4vTdb8R53JouKoKzQ
         b2JQ/9jBgE8aUVnDoJbp6nIYX/ybk/t0WAz6ScSeVpZLhkzo8st1GCktKfrD0x6r1Zhq
         fLmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707933158; x=1708537958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tDOKgI6aSPZHa3pzNse1heGwAYCNP712Khr07mzfzcc=;
        b=Z9MyAjg23eIpJQmag7zbYsuVX+p3ENIdgWMNygBk9IUSqvMQlxF8CznBYbywFNxPfZ
         QEQqRjOlcevBlAaoFjZKTL1L5YOKj1kPKiM6b7p8CcOVMUMKtr+LISilKVYR9fEvhs5Z
         HkZ5ZqRcSOCK5ZqjG5bgDAKsOUd0jM22spOJZMsZnUFkJNLxvV6ASb4wQSh9BI5uRAff
         KFK12D94xyB2N6tXqom+n6gIhbyz3Y+EW7ShB/eUeDC0tDmaIQ65kTAy/Mtd1tRWwr9P
         V5GI6RHdpaNo5khD69mPMejvZfOX5tqMc1B8eDpJe6XF6vGWAz2Nm7+K5LGpwzmCcaZ5
         tI5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvySp9TSuaxBvT/5ZkFQrJ1qHRszq/u0s3AfWb/9oFa2tUQVTRHvm+RkALk6Uo3Gz+DTXYMjVEsEd4ah1ojIUoTlevvHluPg==
X-Gm-Message-State: AOJu0YwtOTH7HjswLnwLLcv7Sm5FF48uz5R2yZvLh4W8pf0ieUw9COff
	x79z5Lth+Mb4yac+NE7q8nDQWjtFY0xBaIKhBENJo9HKLo+ai2a8
X-Google-Smtp-Source: AGHT+IEaUVicnEIF9ypE2cMYzhXtNJ6YvK0pZJO+URuEkQyZUETYex8TlgC8Ole9qtzVy7ekjmrD2g==
X-Received: by 2002:ac2:58c2:0:b0:511:5b35:d118 with SMTP id u2-20020ac258c2000000b005115b35d118mr1496197lfo.2.1707933157776;
        Wed, 14 Feb 2024 09:52:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c89:b0:511:3755:63d with SMTP id
 h9-20020a0565123c8900b005113755063dls191071lfv.1.-pod-prod-01-eu; Wed, 14 Feb
 2024 09:52:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU11YhIXmBoOFwkw9ZsDixTUca1A69nHZsifbHnazvkDmjzDcqMnotJVwFHBo3P4JpS65M+CfbQ4UMKALZya6CHlcZHVUBVVXVvBg==
X-Received: by 2002:a2e:be27:0:b0:2d0:ca46:46be with SMTP id z39-20020a2ebe27000000b002d0ca4646bemr3050772ljq.20.1707933155891;
        Wed, 14 Feb 2024 09:52:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707933155; cv=none;
        d=google.com; s=arc-20160816;
        b=nZt4M2tJNqGYRuDyCrv4et8BTPAHTpbMmJZ7Qjen2f9UNYMWd+TIo1ngZ0uN8hmNuH
         78hkqkyl/jt9YihUS2b9YsLRHin7LU7G3aGnpEZZprJNn0jkpl5UqZrFdLEjWRciGDB3
         L+qETuTTmQxY+s6rabRtlH0hK0Z1zSzCRAA/ONrCDBAFUBHBOqht039xocVSeqHIjF0z
         FntDOydWtqpX3Su97qM0AGfUCZcKwDO1EMJUkaSRrGoieU/Q4BWwt6UCryUkVtiV9/gZ
         zYa2LbwGI5eBJHQGJYC5CQby2QhMV625C+HnPYSDaOUffcsfTmWKzw3DDfADa7XfkpST
         /gkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=leY9N3alrQ22C+fXPazgCJacTsU7ND5Lt0yRBT6Nl7E=;
        fh=FtpaKwUBM5dl5FwjRZOwc1U0qAFKTRdrGTarPglPFRw=;
        b=r8jyf9az4nAvcSWY9d8cqWnxL8oKZElapvle/tfB0Nvwc3vA+DayKkEFcGUlQ1Wv4W
         y9ahf7BLXsWKVR+6sNa1b6BcU624DsCt2EvFuzTY8a4EgilJPK8qP49J95eV14DWpqb4
         2TLb1FSIV2rAYRxAYyHnX0hLWgbeNcaLz3+jrWNbS+L42oK14/rHM+jDp4IcR/lM2NdX
         UxTGtIeCFoDpqSeDNet8F+7cZ5ruFAp93/2e2KAXxH/Cq2JCJXwxLPliiejljCG6Fh3K
         5SSjui7lufQPfO6wu9amddx8dadSd1dKF8ZxVXRDqP3z5CxvX1hDRdeSV4c6iQ8+YH9o
         yhng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IUp0RzOj;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCXXGuHKDGvfl75vh8Zlqw9rExpGGJUfS9cDpNUm/k6REN9MhcgKfA/8QM+qpYL3ObuvspQklqWCyLkhvbkG93oJ5BMfdhn55ws46w==
Received: from out-170.mta0.migadu.com (out-170.mta0.migadu.com. [91.218.175.170])
        by gmr-mx.google.com with ESMTPS id i13-20020a2e864d000000b002d0a7814671si384680ljj.7.2024.02.14.09.52.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 09:52:35 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as permitted sender) client-ip=91.218.175.170;
Date: Wed, 14 Feb 2024 12:52:24 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Suren Baghdasaryan <surenb@google.com>, 
	David Hildenbrand <david@redhat.com>, Michal Hocko <mhocko@suse.com>, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <7c3walgmzmcygchqaylcz2un5dandlnzdqcohyooryurx6utxr@66adcw7f26c3>
References: <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <20240214085548.d3608627739269459480d86e@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240214085548.d3608627739269459480d86e@linux-foundation.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IUp0RzOj;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as
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

On Wed, Feb 14, 2024 at 08:55:48AM -0800, Andrew Morton wrote:
> On Tue, 13 Feb 2024 14:59:11 -0800 Suren Baghdasaryan <surenb@google.com> wrote:
> 
> > > > If you think you can easily achieve what Michal requested without all that,
> > > > good.
> > >
> > > He requested something?
> > 
> > Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> > possible until the compiler feature is developed and deployed. And it
> > still would require changes to the headers, so don't think it's worth
> > delaying the feature for years.
> 
> Can we please be told much more about this compiler feature? 
> Description of what it is, what it does, how it will affect this kernel
> feature, etc.
> 
> Who is developing it and when can we expect it to become available?
> 
> Will we be able to migrate to it without back-compatibility concerns? 
> (I think "you need quite recent gcc for memory profiling" is
> reasonable).
> 
> 
> 
> Because: if the maintainability issues which Michel describes will be
> significantly addressed with the gcc support then we're kinda reviewing
> the wrong patchset.  Yes, it may be a maintenance burden initially, but
> at some (yet to be revealed) time in the future, this will be addressed
> with the gcc support?

Even if we had compiler magic, after considering it more I don't think
the patchset would be improved by it - I would still prefer to stick
with the macro approach.

There's also a lot of unresolved questions about whether the compiler
approach would even end being what we need; we need macro expansion to
happen in the caller of the allocation function, and that's another
level of hooking that I don't think the compiler people are even
considering yet, since cpp runs before the main part of the compiler; if
C macros worked and were implemented more like Rust macros I'm sure it
could be done - in fact, I think this could all be done in Rust
_without_ any new compiler support - but in C, this is a lot to ask.

Let's look at the instrumentation again. There's two steps:

- Renaming the original function to _noprof
- Adding a hooked version of the original function.

We need to do the renaming regardless of what approach we take in order
to correctly handle allocations that happen inside the context of an
existing alloc tag hook but should not be accounted to the outer
context; we do that by selecting the alloc_foo() or alloc_foo_noprof()
version as appropriate.

It's important to get this right; consider slab object extension
vectors or the slab allocator allocating pages from the page allocator.

Second step, adding a hooked version of the original function. We do
that with

#define alloc_foo(...) alloc_hooks(alloc_foo_noprof(__VA_ARGS__))

That's pretty clean, if you ask me. The only way to make it more succint
be if it were possible for a C macro to define a new macro, then it
could be just

alloc_fn(alloc_foo);

But honestly, the former is probably preferable anyways from a ctags/cscope POV.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c3walgmzmcygchqaylcz2un5dandlnzdqcohyooryurx6utxr%4066adcw7f26c3.
