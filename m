Return-Path: <kasan-dev+bncBC7OD3FKWUERBEMT7CXAMGQEDBZRACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F741869BAB
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 17:10:59 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-21f6e3f69a0sf4092272fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 08:10:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709050258; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+J8ouaB7ahGGhu9yM+gl/ioeOuK5FgrNzQQ+8aUkGZVpWdYcTaMLs7orFVpynanAu
         fARYJT0CxFknBjPzmbRUzMxwgXGJh8XD0OIh+eJMobzPlSBcmCqyY+QWOqvl8RSK657k
         +2VYMhhEk4wLSzruCEIWqG10jzpTf3RPyD+1DdkG0PpXX1spdeFur3BnV4BYZ62gmD7l
         YMjFs30mWiiF40Mtez6CJgEF4Inx2oai1uyyjwafVKkWpJ8/qjJHBScxN28nNO4fm98Y
         78pisn8fZ9HZJOLU8GigzVs01MOPg/5FS841mLQClZW34ETJfPx8gl2LYmGIFi3q1xsW
         1d2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OLSVj6Rwxuiw1YXuygttpK4HmZ7SWpVZ4ZCp4TMqeRA=;
        fh=SmpfwLekDdTRkzM8lQzqB/Jo5uI/4UkbDW0gu9WPMqg=;
        b=zlOOxs6jbHDU42VktMu4NjNOXTlUx61JlKY4xFNxVzydfZjOdMe9yFX3I5MyqK9dEQ
         9WQPUFXmR1RG9cBTeu4embyilFM8es2GxC4EGvthVdRt/S4r6vVaMOccYeuKgoBwPiXE
         3DCiMsVJakceDLAfjX6ehrH5cCXfiXqnPSv3lRLEBm3wykUpPHkhwKmKTGRHQN1tAwc7
         yYXPpFsubfQ8KSy52jPqRiue3kcR8tZkfCz9rOzlkY38JkZyTqcZzelOMX9RXgDVXlTl
         RY6ej97FmqXUAxJD4ZbDeS2oX0Se1Tpeo7wx6XOXkhmauDqGNtLVDC4IJhea5sFlFbR9
         mHUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zIOkReGU;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709050258; x=1709655058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OLSVj6Rwxuiw1YXuygttpK4HmZ7SWpVZ4ZCp4TMqeRA=;
        b=jbsEhMHio9Q/sx8TZpXqJ8h1LQRM2Z5ag2scH2bXcgAdXte+8ettbExZxXy6pgo0Nz
         sDyuEPS0XKibqzBFNlFTOEgpcEWf3CSrAld/ge8XlVsmYO6JO37ozd/WSAq24BX3pqgC
         Ujq6tQ6aifLjvvtV6giqP1TZkFMnc0TWvES7aGMneElViExNtgXlatTDxc9Kvh7rQN5U
         gNu8oLcYODC2kbac/+HkFEI8f5LLHP2ob0/laATnsYamzuv5FPDizDqNYCTXUVHSPZiI
         d9ZhKeFk2jpClhOiRx8bFkYRDLpCaFVEe8wIXnnzPLVN2WQ7Jf/ut2oAu6RUz3zaUHEd
         cXgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709050258; x=1709655058;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OLSVj6Rwxuiw1YXuygttpK4HmZ7SWpVZ4ZCp4TMqeRA=;
        b=r4ndY30ntxksNGVOCCjvxaQyYnU6osW4ex6qsyQSJ2xoNqNRuBFjaAiZws3BATesRx
         b1rvdcgw0XC66BNwCQunyrzqx0usoM6mh0B30bq/ml3aV71wfpu2fC75aXQEyAuM3wfX
         mZCrLhq1CurgYVn8Yg++tsAfcDwKRiQv5iySoqC8uMsKMmd2BJoFxrGdfReGkGIZlrtP
         OCeiPkfkvx7RdV210OUKbQNkG1vOI0ZMTYrgYLOJX6KWqjWlMqJTjeTlfVR+wMo9qafu
         EPeMi3s6kKMwbRdQPCvpiz/O/JMx6D66qU0pt1Z+sAx1aXK5lQ1MFGxzJSfL0+ofqLh3
         2aWA==
X-Forwarded-Encrypted: i=2; AJvYcCU5S+hAX/TkuxGVe9N3Jh3f38w9bfgXcyqhvMo5rRuQu2uQ82KK1QrEAQLf3OFV5Rl82cdBpGMHwfjMT0IO8CCEKkGfTOLUVw==
X-Gm-Message-State: AOJu0YxR0KNfA+ToqXZgvPg7lcR+mmE/nProhh/MXvWPpxZy/Fkk0YaS
	GYQ9Q/TdbcbY4qlqj3Zo+oqtg6epz4OrcrChR+7C46cJmGZnEs/1
X-Google-Smtp-Source: AGHT+IESBrl6saRvYF8bvYFMC9wzGoehN/omn2nfHv8RhD/Jp57nE44OHATFLGxf37xy34uKVxnhxw==
X-Received: by 2002:a05:6870:524d:b0:21e:90a3:1871 with SMTP id o13-20020a056870524d00b0021e90a31871mr10520720oai.50.1709050257891;
        Tue, 27 Feb 2024 08:10:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e3cb:b0:21a:216d:4818 with SMTP id
 y11-20020a056870e3cb00b0021a216d4818ls5653713oad.2.-pod-prod-01-us; Tue, 27
 Feb 2024 08:10:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUfrcPmdSf6nHEV2aOEIWtkDu/dZiFrhESbfv53bZvounURDiLp9Ucq4ZcUKSbL8h/7hAJxvEl86M53sKsL7FxfUvqOj2KwF3hvoA==
X-Received: by 2002:a05:6808:2a6c:b0:3c1:5d31:3bef with SMTP id fu12-20020a0568082a6c00b003c15d313befmr2143822oib.25.1709050256699;
        Tue, 27 Feb 2024 08:10:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709050256; cv=none;
        d=google.com; s=arc-20160816;
        b=C8CFWSgA4DXjIUSFeysb7mUUjlsNAWfruyJzjmzXP4Cdbukc+by3eUV8DzvOiiUmHK
         1xEiUZXR8vabfl5hZDQgSQYDGoxV8WYZs9CZoPsGd9acFRpbkJl91RsCykmh5Mrh9vgN
         fxhsosHwYv0kr2yATiARY7ZN9l2nnT+W8XTprrJvWQhLU+WUKENh3kFnkpzQJdojLUBc
         GDNWjsMr6u6gj5x1lgIV3A8mTjS8Vy4WODd5379PYpHWryj8wm3H1ZY0SRSQnHKwnPK4
         DQF+lQLvwGQjd7nXfEmkVTAnkeV9/DTS3BQszr8QCSq6dxd5gOsQyCCF6rlX9pq0ZZcM
         6gYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3997VUdAcSrw6hJXGBCDEHFxh3lqzFAtRC+eH0EMEcI=;
        fh=QGCiZeuWCfZ9SYQ00RwM7u95a/sGhgskcw4n38SrxJE=;
        b=epWYHF24BjQ9mDZhLVMr6m5SnewekoODCVwtz+a92uRFV24UPzrPlFOFoYorvARORI
         dWjnSXT3X3WiwFxQrHE1ggE3Sxmx/Zv5WkC8TSigjq8Snt4hUqXj4+AhjuX7f5RCJoH/
         fNt0B9jiuHBsTbJDUPTPAp/4lYFYgjcL56Q6L64zjOsLWiQq+x8+MBtMAk7g3+xxVlE3
         ARKN7mJjMgueteI/9Oz6X0blhj2fbwtzDnnWx2F/9TZrKlIZhHSVcapFWL0NZKU9liqF
         Oq11QJci5EesV0LeBwW2+8lJOO5vj64Z0BJIvxYPNFUba9ziUGSzsIDvLjbUbgE1a4ma
         osbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zIOkReGU;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id ay10-20020a056130030a00b007d9bf934919si981585uab.0.2024.02.27.08.10.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Feb 2024 08:10:56 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-60822b444c9so29302827b3.2
        for <kasan-dev@googlegroups.com>; Tue, 27 Feb 2024 08:10:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXMIKuiyMuGYzD1p5RgZW6pSzaQcFMu5868eyC3fnsTFkRzY7klNmmnBcwoKSZg6Z7pIQheBw/E3G9yDhHsJVqgHFlCcOo36x9MBw==
X-Received: by 2002:a25:874c:0:b0:dcb:d8d1:2d52 with SMTP id
 e12-20020a25874c000000b00dcbd8d12d52mr2322309ybn.31.1709050255947; Tue, 27
 Feb 2024 08:10:55 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <67453a56-d4c2-4dc8-a5db-0a4665e40856@suse.cz>
In-Reply-To: <67453a56-d4c2-4dc8-a5db-0a4665e40856@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Feb 2024 08:10:43 -0800
Message-ID: <CAJuCfpHLEzCzATZ2ZP74--9mfYh-g-2csZ9A9oyaWWEQGNuGpg@mail.gmail.com>
Subject: Re: [PATCH v4 00/36] Memory allocation profiling
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zIOkReGU;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Feb 27, 2024 at 5:35=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Overview:
> > Low overhead [1] per-callsite memory allocation profiling. Not just for
> > debug kernels, overhead low enough to be deployed in production.
> >
> > Example output:
> >   root@moria-kvm:~# sort -rn /proc/allocinfo
> >    127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
> >     56373248     4737 mm/slub.c:2259 func:alloc_slab_page
> >     14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
> >     14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
> >     13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
> >     11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
> >      9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
> >      4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct=
_alloc_hashtable
> >      4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] fu=
nc:ctagmod_start
> >      3940352      962 mm/memory.c:4214 func:alloc_anon_folio
> >      2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
> >      ...
> >
> > Since v3:
> >  - Dropped patch changing string_get_size() [2] as not needed
> >  - Dropped patch modifying xfs allocators [3] as non needed,
> >    per Dave Chinner
> >  - Added Reviewed-by, per Kees Cook
> >  - Moved prepare_slab_obj_exts_hook() and alloc_slab_obj_exts() where t=
hey
> >    are used, per Vlastimil Babka
> >  - Fixed SLAB_NO_OBJ_EXT definition to use unused bit, per Vlastimil Ba=
bka
> >  - Refactored patch [4] into other patches, per Vlastimil Babka
> >  - Replaced snprintf() with seq_buf_printf(), per Kees Cook
> >  - Changed output to report bytes, per Andrew Morton and Pasha Tatashin
> >  - Changed output to report [module] only for loadable modules,
> >    per Vlastimil Babka
> >  - Moved mem_alloc_profiling_enabled() check earlier, per Vlastimil Bab=
ka
> >  - Changed the code to handle page splitting to be more understandable,
> >    per Vlastimil Babka
> >  - Moved alloc_tagging_slab_free_hook(), mark_objexts_empty(),
> >    mark_failed_objexts_alloc() and handle_failed_objexts_alloc(),
> >    per Vlastimil Babka
> >  - Fixed loss of __alloc_size(1, 2) in kvmalloc functions,
> >    per Vlastimil Babka
> >  - Refactored the code in show_mem() to avoid memory allocations,
> >    per Michal Hocko
> >  - Changed to trylock in show_mem() to avoid blocking in atomic context=
,
> >    per Tetsuo Handa
> >  - Added mm mailing list into MAINTAINERS, per Kees Cook
> >  - Added base commit SHA, per Andy Shevchenko
> >  - Added a patch with documentation, per Jani Nikula
> >  - Fixed 0day bugs
> >  - Added benchmark results [5], per Steven Rostedt
> >  - Rebased over Linux 6.8-rc5
> >
> > Items not yet addressed:
> >  - An early_boot option to prevent pageext overhead. We are looking int=
o
> >    ways for using the same sysctr instead of adding additional early bo=
ot
> >    parameter.
>
> I have reviewed the parts that integrate the tracking with page and slab
> allocators, and besides some details to improve it seems ok to me. The
> early boot option seems coming so that might eventually be suitable for
> build-time enablement in a distro kernel.

Thanks for reviewing Vlastimil!

>
> The macros (and their potential spread to upper layers to keep the
> information useful enough) are of course ugly, but guess it can't be
> currently helped and I'm unable to decide whether it's worth it or not.
> That's up to those providing their success stories I guess. If there's
> at least a path ahead to replace that part with compiler support in the
> future, great. So I'm not against merging this. BTW, do we know Linus's
> opinion on the macros approach?

We haven't run it by Linus specifically but hopefully we will see a
comment from him on the mailing list at some point.

>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHLEzCzATZ2ZP74--9mfYh-g-2csZ9A9oyaWWEQGNuGpg%40mail.gmail.=
com.
