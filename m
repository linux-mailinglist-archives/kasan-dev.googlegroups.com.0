Return-Path: <kasan-dev+bncBC7OD3FKWUERBCXBU6XQMGQE24LJE2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A76087548A
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 17:51:23 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5a0a19006a3sf1062976eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 08:51:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709830282; cv=pass;
        d=google.com; s=arc-20160816;
        b=GxRod5/l6DOCUm2xj+S1/nNqE9DMm1xv1N19B5UtYzOQ7hqBeyI/ojN1D0BQ+w2L9n
         kFjroCFfHVARUaBHQcgVxH7BRCbW4LhLJqKQ2tAvyGt1VgqOIgtBGVYP+nAoOmwhpvxh
         uFDMfR3nsglPkDdmaT9HrR+v3ri6F7ZE+gtQoj40FOpNzZ4Zmj5fWKw/kvWggSZqHOYh
         cV6yswaZ3LjqDCy2ujCrsLLFa3Bm2JW6A5yn588l60oZxQ3PTedshsmhKzQ/jqaKMPEf
         sQak0JsIjfstkIu7qGHPQNThbozYX9S3EqCMXkFbU7jLroIAmOCY8LlpD4GTzD5vLJVs
         AMVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DfsXRVDBgeEnssBHzCV1f6PdgEzFZChT5BdHFDMahYc=;
        fh=DqHE4UN4y+0TAgz1KA6XsL1gfTIaCQE5Df374OGsXng=;
        b=RFfCPW+91LxsI2OEKOyuAFFPHVadClEizWknIojQKST7uqJwF7YS3E/e3zwXc8p7Wj
         giJ0AZyri90WPk4djg1B9i36njlreRy/EKBqE95o/+9mxbNGbjd1zJGOdZm1iD2GjcBa
         gK0XXqA1RPhYoIFGa/+bKXOKEc9PeZS56yfsi+Xb4iUhe+haDPvkhPlCjyhHwY5b4idq
         Zp7cwYcngM5UYzSCeKXzbu5a+ypWAQ+YyQg/hHLWKdX0/AzH9l83lU5TOe+Wjmertjsl
         eGT8Vpv+Pene9Gol7Ir0V1bwlEdmnxFuWPYOVonAVp+/lNNGJt0ceHj5w0MJlWk6sUTF
         WHJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YxJ8GyKP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709830282; x=1710435082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DfsXRVDBgeEnssBHzCV1f6PdgEzFZChT5BdHFDMahYc=;
        b=qsr27RVlLhWfn6HdseFVvtDaPw2NVLzjtLe04mm9ukUAukoYaTCxTIhXXYmQtC4apR
         YAiNZtjds9FF1fE19TQ+DuocqpCRPthcQEvHWqoNUeKwuJdlE772U/WbD+R9GiHGbxzu
         e1t21GamVz37nUaHmfKp3yOYNV35917LfcuJTHHsi53HLTd08SJhLTUNNzyS5Mb4diEy
         f3dBk44OCiz3I4mLKbC6/Hv6H32Rm50UTTbtsV23imxhJxG6pEyxXz2jm8wmayE+qnXg
         77Gb4qWmOmvwNUnsOCsEFKMENG+y9rDyhsSZdn5tFDrXufHzde7FvWxbIVUzymuh3TRq
         JZmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709830282; x=1710435082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DfsXRVDBgeEnssBHzCV1f6PdgEzFZChT5BdHFDMahYc=;
        b=QkkhNpE0glp9EvhNuW1QUnRHs+dO8t2u3+XYMW5vw9WTS91fGueX2+HhN5skswuKQb
         oGEHzTeJlN4wXfrPFDdY3DyfOSlMsPknXvzs5+LtOvxaQ40O/dYpI4bVc2RFFbjV+ETH
         qUxGRsqoPcbL4d6GadIVTiwjaeRNPDOfcW8SmK0sYdSsxQUwn+hHDwbEU+7NyfEFSlBq
         D1eK+DBjloV++WPa4biw9+0V4W1M7H8Up2jH80fKdlzmlYNwsGQDZRprXovQ6YY+EOEt
         IF2dtZ5Tx5ugg3TgTX0Potacfdsi9JCvJPsKwVb0s5fHGYa5ebyWNDtYm13Vhvm8UgzC
         wRuQ==
X-Forwarded-Encrypted: i=2; AJvYcCV05o/SBdw+jgvmwBlCv+GHDH5K+9IOWejYC4n9eMw0jtPCQPZAC+iF/Qii3BLo/6ouV6JNcEojQ011zBz97AnvXhrKy6eYxg==
X-Gm-Message-State: AOJu0Yzhr2NxR0Sc//qun+ggTsFhazcX7o3c/MLk1/HQoj0CveuRpcEr
	i7GVmPE4hoDVDI7mk1RVmXexWuYNt4KdMUb4G/JoIvJxmj7Dlb/a
X-Google-Smtp-Source: AGHT+IFqSM1CjbpJHAFkeYQHYyooyOXNfd+GGhjKuy+z9qVS/JziCdZpgm/HDjW0ROdtdfNJl8DH2w==
X-Received: by 2002:a05:6358:2614:b0:17a:e13b:3a4a with SMTP id l20-20020a056358261400b0017ae13b3a4amr8833375rwc.29.1709830282196;
        Thu, 07 Mar 2024 08:51:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:411b:b0:68e:eeaa:8248 with SMTP id
 kc27-20020a056214411b00b0068eeeaa8248ls1408965qvb.2.-pod-prod-06-us; Thu, 07
 Mar 2024 08:51:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV6QyRTM4uxGNHhdrrx204m5iaH1m42uXyFx2KqccfQtHomBBUQVQBlRZmKeZojEOXdwmmnIkDOmEuxR0b1LE/CZ6jCyQNk0q6fCQ==
X-Received: by 2002:a67:ffc8:0:b0:472:ec8d:9586 with SMTP id w8-20020a67ffc8000000b00472ec8d9586mr5511341vsq.25.1709830281403;
        Thu, 07 Mar 2024 08:51:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709830281; cv=none;
        d=google.com; s=arc-20160816;
        b=kavevLAveejtlwLDc2bIfbWkShZ11ARHgnnnRj/DRYefKhP40wGVvn8kcPQJiElugl
         HdByoMJ94hGIGIzP7ZulOVSOCMgJcwVwQKBgqEJkUJTs1W3eOewSLzOGQ0Lo90XDP3u3
         EJIi/kqqZFEtAY5HD/he6/WdYDiEFzdDWLCWcJsEjIZeQ/1M4C5x4soYrisxliG6FWnr
         T8N7u7S5Bh7DqaJ2MMTUMn2HpmTDBaDKsDDQBwoGmiRx6DjYAJcSxayYfrnL2Picr73T
         3qoTQ8GTTw8W+dI/REcWnk7E8oIzWiPTvN4u3neA1R0z2r2zH+iObs9IpVjh9ojErhkk
         tslg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+Yc7CaZYI+aOfiJp3dG8X2zo4+LoYMopU2pW1vALF2c=;
        fh=urLcI8y8MKhSTkWmqVn0iUzxmzav+TCz+W8QA7YsHuA=;
        b=XOdcnEcyywQJW/ZWUi6ozBT5x6xpfWMUaUpITPtIuFlsQcuFo66JG48iZBwf9jNfds
         R7ePSoj+5S5zqMkKWhppTinWYoS8s7QOSywBo/Tv7zN84SPjiBWigz6aWlh6MAHx7CIW
         2+AbQWUTEwnom53DzGl/h3guh5eBjtKzArVzGC1TYE6yThPoHpvblg7V5DPcL5fkksnr
         HH6l+1HpoC+kLw3NIocBG7p3Z4+0WHJVZP5XPg6xDBoafhYrvjyO+0KA4uodzlP27jvA
         jlZJTP28YiJJIpM8KHgpt3FclpzE3h8PeBJXhjhyCIYr+3i5HZRU+aAbxrNX3UUDhkGv
         oNQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YxJ8GyKP;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id fv2-20020a056214240200b0068f6c8ab31asi1333896qvb.5.2024.03.07.08.51.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Mar 2024 08:51:21 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id 3f1490d57ef6-dc745927098so1020144276.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Mar 2024 08:51:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWWB/kZRxfh4yvSve+4BGyYT/kU4SG2exxprhKDLM4iuE/Xwod6Kt4h83BL0Gn3WMt9+FIQgEc8vpREXplV0RybmBETwhM/zxpWeQ==
X-Received: by 2002:a05:6902:160d:b0:dcf:56c3:336e with SMTP id
 bw13-20020a056902160d00b00dcf56c3336emr17705298ybb.35.1709830280572; Thu, 07
 Mar 2024 08:51:20 -0800 (PST)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-38-surenb@google.com>
 <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
In-Reply-To: <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Mar 2024 16:51:08 +0000
Message-ID: <CAJuCfpFN3BLsFOWB0huA==LVa2pNYdnf7bT_VXgDtPuJOxvWSQ@mail.gmail.com>
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
To: Randy Dunlap <rdunlap@infradead.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YxJ8GyKP;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2b as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Mar 7, 2024 at 3:19=E2=80=AFAM Randy Dunlap <rdunlap@infradead.org>=
 wrote:
>
> Hi,
> This includes some editing suggestions and some doc build fixes.
>
>
> On 3/6/24 10:24, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > Provide documentation for memory allocation profiling.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  Documentation/mm/allocation-profiling.rst | 91 +++++++++++++++++++++++
> >  1 file changed, 91 insertions(+)
> >  create mode 100644 Documentation/mm/allocation-profiling.rst
> >
> > diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/=
mm/allocation-profiling.rst
> > new file mode 100644
> > index 000000000000..8a862c7d3aab
> > --- /dev/null
> > +++ b/Documentation/mm/allocation-profiling.rst
> > @@ -0,0 +1,91 @@
> > +.. SPDX-License-Identifier: GPL-2.0
> > +
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> > +MEMORY ALLOCATION PROFILING
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> > +
> > +Low overhead (suitable for production) accounting of all memory alloca=
tions,
> > +tracked by file and line number.
> > +
> > +Usage:
> > +kconfig options:
> > + - CONFIG_MEM_ALLOC_PROFILING
> > + - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > + - CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +   adds warnings for allocations that weren't accounted because of a
> > +   missing annotation
> > +
> > +Boot parameter:
> > +  sysctl.vm.mem_profiling=3D0|1|never
> > +
> > +  When set to "never", memory allocation profiling overheads is minimi=
zed and it
>
>                                                       overhead is
>
> > +  cannot be enabled at runtime (sysctl becomes read-only).
> > +  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dy, default valu=
e is "1".
> > +  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=3Dn, default valu=
e is "never".
> > +
> > +sysctl:
> > +  /proc/sys/vm/mem_profiling
> > +
> > +Runtime info:
> > +  /proc/allocinfo
> > +
> > +Example output:
> > +  root@moria-kvm:~# sort -g /proc/allocinfo|tail|numfmt --to=3Diec
> > +        2.8M    22648 fs/kernfs/dir.c:615 func:__kernfs_new_node
> > +        3.8M      953 mm/memory.c:4214 func:alloc_anon_folio
> > +        4.0M     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] f=
unc:ctagmod_start
> > +        4.1M        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_c=
t_alloc_hashtable
> > +        6.0M     1532 mm/filemap.c:1919 func:__filemap_get_folio
> > +        8.8M     2785 kernel/fork.c:307 func:alloc_thread_stack_node
> > +         13M      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
> > +         14M     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
> > +         15M     3656 mm/readahead.c:247 func:page_cache_ra_unbounded
> > +         55M     4887 mm/slub.c:2259 func:alloc_slab_page
> > +        122M    31168 mm/page_ext.c:270 func:alloc_page_ext
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > +Theory of operation
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > +
> > +Memory allocation profiling builds off of code tagging, which is a lib=
rary for
> > +declaring static structs (that typcially describe a file and line numb=
er in
>
>                                   typically
>
> > +some way, hence code tagging) and then finding and operating on them a=
t runtime
>
>                                                                         a=
t runtime,
>
> > +- i.e. iterating over them to print them in debugfs/procfs.
>
>   i.e., iterating
>
> > +
> > +To add accounting for an allocation call, we replace it with a macro
> > +invocation, alloc_hooks(), that
> > + - declares a code tag
> > + - stashes a pointer to it in task_struct
> > + - calls the real allocation function
> > + - and finally, restores the task_struct alloc tag pointer to its prev=
ious value.
> > +
> > +This allows for alloc_hooks() calls to be nested, with the most recent=
 one
> > +taking effect. This is important for allocations internal to the mm/ c=
ode that
> > +do not properly belong to the outer allocation context and should be c=
ounted
> > +separately: for example, slab object extension vectors, or when the sl=
ab
> > +allocates pages from the page allocator.
> > +
> > +Thus, proper usage requires determining which function in an allocatio=
n call
> > +stack should be tagged. There are many helper functions that essential=
ly wrap
> > +e.g. kmalloc() and do a little more work, then are called in multiple =
places;
> > +we'll generally want the accounting to happen in the callers of these =
helpers,
> > +not in the helpers themselves.
> > +
> > +To fix up a given helper, for example foo(), do the following:
> > + - switch its allocation call to the _noprof() version, e.g. kmalloc_n=
oprof()
> > + - rename it to foo_noprof()
> > + - define a macro version of foo() like so:
> > +   #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))
> > +
> > +It's also possible to stash a pointer to an alloc tag in your own data=
 structures.
> > +
> > +Do this when you're implementing a generic data structure that does al=
locations
> > +"on behalf of" some other code - for example, the rhashtable code. Thi=
s way,
> > +instead of seeing a large line in /proc/allocinfo for rhashtable.c, we=
 can
> > +break it out by rhashtable type.
> > +
> > +To do so:
> > + - Hook your data structure's init function, like any other allocation=
 function
>
> maybe end the line above with a '.' like the following line.
>
> > + - Within your init function, use the convenience macro alloc_tag_reco=
rd() to
> > +   record alloc tag in your data structure.
> > + - Then, use the following form for your allocations:
> > +   alloc_hooks_tag(ht->your_saved_tag, kmalloc_noprof(...))
>
>
> Finally, there are a number of documentation build warnings in this patch=
.
> I'm no ReST expert, but the attached patch fixes them for me.

Thanks Randy! I'll use your cleaned-up patch in the next submission.
Cheers,
Suren.

>
> --
> #Randy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFN3BLsFOWB0huA%3D%3DLVa2pNYdnf7bT_VXgDtPuJOxvWSQ%40mail.gm=
ail.com.
