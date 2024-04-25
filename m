Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6PMVKYQMGQERIEDPHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 091FF8B2957
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 22:01:04 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-36b3738efadsf15028745ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Apr 2024 13:01:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714075262; cv=pass;
        d=google.com; s=arc-20160816;
        b=TUXiF4m+qKvei2CLKNqCK0hiAB3fHD+ZzXGoulEb9c35Jc4joRAMtyhNjzKVVDKgYa
         LWsyu+tvtvkphVd095Q5dxk+j+0oAUSSvv/Ha+TAUNO2Rz+1hwsz6b0tIbhDhE7f1Lhl
         TwhC5SEErxgPf47SJi0nchrjdOESsDcz60vZSAO4mLA6eXDTDOjLopKpYm+FY06133Jz
         iXWw1DSKnnBt0KTUGMFJ59nzUoGfIvpZFQwbhJO0NlBCj2HgUXu4RFQPNxZgUl5ldgnj
         7JoHt4y2QH1oAui0n12GPt5NAd81FH1gzrdKtp1tkzzGt1fFHYjBGMkKX0F86NrCITli
         XugA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=N7bsj9SKvcqhXqrViLU6Tk/oaF2r03yVwlNAj3lqYoU=;
        fh=YY0weJyC10OT7Bo9MVXu7Wf/RRgMx3rCB34gF15ODSc=;
        b=LZ+08YKkMHKCsryTdMGVx02r8QwVcHy8bN+S5VbGDWe8KaVS4zcoTF5crg5uF6M2KT
         gJc4YodPU39tU5ZLlM2l4h4l4k9SyLVlwi3P2SzyFa9iOXCINCzEYi5wVkuhSD1B3e6y
         w7vPPY/45NEcyxLdZ0Zm1mZ0xBcW4Dhf/SpcG8OiNKnrSiYlPrq/Wo2pTWkc1oHXT0r8
         Xh8zkw4Iav9XfvhxwLDkxwPHqRvf2ATYDFGCcjGnZGO8us5Oj2ZPlWyHNdUJCjf7/6Vo
         5NjsOE7jHeOJ3bfPU+PnF3Ej0yVAJMRoi664p6A852MxMU4g2xiKXWkKdnGC1HfjCJtC
         V7Pg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Rgn/hOYN";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714075262; x=1714680062; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=N7bsj9SKvcqhXqrViLU6Tk/oaF2r03yVwlNAj3lqYoU=;
        b=Y8S7j6AGVwbrxsIL+Wj0ueI+x68euu7RP7zYPe94qJSu63NzG1ByI1VruKIw7x3dAE
         EeoOy8b+MFvx+XHCd7oZrU30rpK57HVGFssYOUdRB+0vuZfUQ0RTRO6CD6Y6q1RnIYFZ
         ZCW3GnSelSYpJxI0qz+yY6P/WEf+npIoLki9KBBslRzo926ZjtZxVO6Q5/mY5L0MWyUH
         CXaiUSVClXYG91tq6K6/YS4EzluTGsgCCye/xzrOHgJsODYkRCEguBB0ELdZ0GJo3Ke3
         dSTiwUislNprHkKaMylOYWJQqIuHMNFaZlOH4lBY7LM3AkwmWg6ybNY3cA4WMlO5WSlU
         3Fmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714075262; x=1714680062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N7bsj9SKvcqhXqrViLU6Tk/oaF2r03yVwlNAj3lqYoU=;
        b=TQUwxWBM0QmWjdbaJclyZ2rLHZHGqZmisAyPGm7o11JlQ/2NqRVPRCePWYsJLK/w/j
         DWxtNHHCf0guOWWoiMl4tecp1GmyIKfDPID+PdkETJQpD+MLn+lBDRoiCUPRWlCg+xvi
         q0tAjCHQmHEkn0ta7GoArfRbsmyMB0w8UXs3OK4zhp4wMEGR6g/v8uXEbkNEucpdzD4E
         fYOi7ag8Us6sksDxuLmAqU7h7/q4mTD5fkxeDbJhCcgVaPoT2d8oW29OSSvtH9lbDvlJ
         88rzBzmeXRKQbSLQBGQc/P0to3c/9t1oJAR89+XETW6s7Ftq+5jWEniz2nFdr/rwVjBC
         XnKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeKnsPZMENt/Bww0qdWEY4DjUf7eCxZVFNz2EjdLUMVmrQklokBboHXkAEHpaqeNAN5o4RuGqEGqWm9vSEohuIvpw+oEUSdQ==
X-Gm-Message-State: AOJu0YzGpxih1XzD9CFdfJv+b5Ff8frHsExJL70R0cLew1WE8F/mtCD0
	wrfx9vZoNAPoEES73IaJjOi+OKnTaJTq6nfNfkgipdjH9myKHkyW
X-Google-Smtp-Source: AGHT+IEYnaPEIc9C+Yw2CO6O9aMUekcZX5g3H03K+Yi+8nFi3oODAl3u061Oh0jKLOL/34SAfmnhLg==
X-Received: by 2002:a05:6e02:17ca:b0:36b:3bf8:8caa with SMTP id z10-20020a056e0217ca00b0036b3bf88caamr1059284ilu.10.1714075257461;
        Thu, 25 Apr 2024 13:00:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:17c5:b0:36b:300b:3a61 with SMTP id
 e9e14a558f8ab-36c29d8837bls6573605ab.0.-pod-prod-03-us; Thu, 25 Apr 2024
 13:00:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWwHYiL5uRb0QmnvqvvG+L2oZIGay70YD1Lri4w4KwlQgzfWv7kUgHPL4xnCAvutr5Gqnf5A/1PSagKEtQEf2HnnLQyDQoor+VmA==
X-Received: by 2002:a05:6602:21d2:b0:7d6:6799:45c3 with SMTP id c18-20020a05660221d200b007d6679945c3mr897495ioc.8.1714075256505;
        Thu, 25 Apr 2024 13:00:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714075256; cv=none;
        d=google.com; s=arc-20160816;
        b=lAOPmHPrRofPAr10n305fd0gbvEikhgyXgyhNwiwI2YfpsB8DxB/0Y1aECu1v/PxBM
         E9AjLUdPBxPSdllsgpgSckqlmQIAja743WTgG71nYz7Lc5DCD8/0xZvu8P59x1rTLS/Q
         gUcVEFXtM6TZoPcXMds4ZbuRGPg21lgHvETjYGyO2wJ8k6L4T55+0RgK6NxARC1Hr68K
         tmTp0Fl/nq9abK0pAVQbrResVb//FFrYmJ6mEQHdeZbufX6eAkMZbWRva1+YfKWHSgKl
         cfDOXbshcUEJ1FJ21COI19LEtUFEY8dILI0aCumTR4A6fWwtnKXnxF3XCQdQj8gED1Wo
         ddbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MPiDO/NuWlBDCPQueU9revoy2ZKV+QsKTFlIIgwR/BM=;
        fh=yFgVyZTcln2qtKIIHHwW9YTBYyyYH6tgpE7WGbsRGr0=;
        b=UMheLJ5cWyLKPLAvZWe8a0hUPMOBIQp1NoBdjWgGvzMAdy0z8hTxxwxvKOO1C5VL4i
         w6xuWcBHTw7Oy2MlyMchcx8xt0/6B50c3SAPSqqJa7WnqyV14mVVthdSXPNMOYYXN3Wt
         /37EZG33F27ZizIG37fhVK5mmfPEC7gpkMgCDVNEwPNFoBlHdXe784RQqXKdq2qGlmbx
         JRyKEkqJQPDj7Hy3NYpYEfHsJG9DR9pmwqwiYmmJ4xBvEcn7u6JxmOj5jcKo1vx1hCt1
         bqVKo/ymx2OhFuBJIDeVx0GLtvjKcsmnVIWEH2oC0vP9hEb+rljtWIUIjrZqgjjTfSy6
         jkig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Rgn/hOYN";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id kj4-20020a056638a88400b004827c66cfa1si1076580jab.6.2024.04.25.13.00.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Apr 2024 13:00:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-1e8fce77bb2so11072595ad.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Apr 2024 13:00:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUdqsWMXc9Q+IG5oWRNh08hDPLvT+OGn5zNEVMUMYF/4tPLJ3hcCuRFaaXG0e09chsJ6l4IfZhQiPko+YGiPAY/dm+UxlnoOKc3Gg==
X-Received: by 2002:a17:902:b097:b0:1e4:6232:367a with SMTP id p23-20020a170902b09700b001e46232367amr573515plr.22.1714075255642;
        Thu, 25 Apr 2024 13:00:55 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id q4-20020a17090311c400b001eab3ba79f2sm1827250plh.35.2024.04.25.13.00.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Apr 2024 13:00:55 -0700 (PDT)
Date: Thu, 25 Apr 2024 13:00:54 -0700
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
Message-ID: <202404251254.FE91E2FD8@keescook>
References: <20240321163705.3067592-1-surenb@google.com>
 <202404241852.DC4067B7@keescook>
 <3eyvxqihylh4st6baagn6o6scw3qhcb6lapgli4wsic2fvbyzu@h66mqxcikmcp>
 <CAJuCfpFtj7MVY+9FaKfq0w7N1qw8=jYifC0sBUAySk=AWBhK6Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpFtj7MVY+9FaKfq0w7N1qw8=jYifC0sBUAySk=AWBhK6Q@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="Rgn/hOYN";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::634
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Apr 25, 2024 at 08:39:37AM -0700, Suren Baghdasaryan wrote:
> On Wed, Apr 24, 2024 at 8:26=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Wed, Apr 24, 2024 at 06:59:01PM -0700, Kees Cook wrote:
> > > On Thu, Mar 21, 2024 at 09:36:22AM -0700, Suren Baghdasaryan wrote:
> > > > Low overhead [1] per-callsite memory allocation profiling. Not just=
 for
> > > > debug kernels, overhead low enough to be deployed in production.
> > >
> > > Okay, I think I'm holding it wrong. With next-20240424 if I set:
> > >
> > > CONFIG_CODE_TAGGING=3Dy
> > > CONFIG_MEM_ALLOC_PROFILING=3Dy
> > > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dy
> > >
> > > My test system totally freaks out:
> > >
> > > ...
> > > SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D4, Nodes=3D1
> > > Oops: general protection fault, probably for non-canonical address 0x=
c388d881e4808550: 0000 [#1] PREEMPT SMP NOPTI
> > > CPU: 0 PID: 0 Comm: swapper Not tainted 6.9.0-rc5-next-20240424 #1
> > > Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/=
06/2015
> > > RIP: 0010:__kmalloc_node_noprof+0xcd/0x560
> > >
> > > Which is:
> > >
> > > __kmalloc_node_noprof+0xcd/0x560:
> > > __slab_alloc_node at mm/slub.c:3780 (discriminator 2)
> > > (inlined by) slab_alloc_node at mm/slub.c:3982 (discriminator 2)
> > > (inlined by) __do_kmalloc_node at mm/slub.c:4114 (discriminator 2)
> > > (inlined by) __kmalloc_node_noprof at mm/slub.c:4122 (discriminator 2=
)
> > >
> > > Which is:
> > >
> > >         tid =3D READ_ONCE(c->tid);
> > >
> > > I haven't gotten any further than that; I'm EOD. Anyone seen anything
> > > like this with this series?
> >
> > I certainly haven't. That looks like some real corruption, we're in slu=
b
> > internal data structures and derefing a garbage address. Check kasan an=
d
> > all that?
>=20
> Hi Kees,
> I tested next-20240424 yesterday with defconfig and
> CONFIG_MEM_ALLOC_PROFILING enabled but didn't see any issue like that.
> Could you share your config file please?

Well *that* took a while to .config bisect. I probably should have found
it sooner, but CONFIG_DEBUG_KMEMLEAK=3Dy is what broke me. Without that,
everything is lovely! :)

I can reproduce it now with:

$ make defconfig kvm_guest.config
$ ./scripts/config -e CONFIG_MEM_ALLOC_PROFILING -e CONFIG_DEBUG_KMEMLEAK

-Kees

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202404251254.FE91E2FD8%40keescook.
