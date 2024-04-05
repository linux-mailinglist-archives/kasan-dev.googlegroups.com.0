Return-Path: <kasan-dev+bncBC7OD3FKWUERBQUOYCYAMGQEPBXVJYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D9D0899F2D
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Apr 2024 16:14:29 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1e2a1977d5asf1467005ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Apr 2024 07:14:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712326467; cv=pass;
        d=google.com; s=arc-20160816;
        b=ykc2EmZP+7LOGUjhQ7FVTS7Vd8P4Dgs2uXClpfBuE5N7o0G4625d0DwVBSRacTm013
         rsVR6qKoJRRvalCbSfksqDEDnt1y/sPX+xxbRccPfHO8PQKf131dEpF30vJ5tgi2529h
         jp2DDv2WQdszzJh1B/MTSF0BXRenVpvp9YNz2kPOMQP2sZldgQc6g+HJa6WWXm1yoSM9
         a7fLRryWqF3KA0nA6pWS0jCYOfSPfRwKHdPvtFLVI4XhAJfohhH/JZGZ6Wes27I2lnOS
         z3y0+BXcxda/bHkdLdJ5Y5Mefn/1LrV01nzHMXRae0im6VgJCFa3xJjZcienMawIKLVy
         lx3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fdpDOoHnc4uWZGo9BmBdU7SxrLk8Chx2Kek2lMoOOL0=;
        fh=IYYU9hh21vBCsA/oXewpXkEbfMSmmoL4ckfo4K+SPnw=;
        b=SZleYUhaMi/+IcYzeH+JKhphsFz+npJuDdW+6pJ5bgG1/euRI60EtkiAOBGoerUL1R
         E0YDRrJSToviMSq4rChzAT7oSALxke2dMD8qWzse/ot+IPN6vF0NMSqig5n64opwgSc8
         wsAFpKcRVf6lgaVn7hzSkpNxjsraTaroQqDOrvoPJDJcL2w3170tQpVdfKHyUl+DyJSa
         of5PBw0stJ6C1DuAvSYw4AlqbJyC4jPJRrBcbiH1ZbaDTstIGusYI5bMGU2UAmXq31IQ
         tkPxAQOqwReughWDEfbjH7fQzmvNjk4doah7eN2hUqEsrnoF++cpWHTdzEKaJvlO6jey
         UWaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0SFLdK7U;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712326467; x=1712931267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fdpDOoHnc4uWZGo9BmBdU7SxrLk8Chx2Kek2lMoOOL0=;
        b=CMA20qgY0go58+z4+8IbDJgMmqxK6ifFCNjtIN0dTdP3CVizq+2ptD1pK+uhf2s31q
         il2wc0F6EmgkpJhwztaNDph89tEZuFBW+Vnu38HedAiHMCHidfyNHKvLFa8ORxGr0s5Z
         F+nFBl9k5UZMlqDjMigsUdh5kOFqo5ZRDhTgopolkoLmFOvkq15gKkk1sIdnaysAbXWt
         PT6q00oTuk8Z4F1RiTQHCRk71PIO2Dlclhik51SOwHT9eIBQ0o+50tA2sZmTJK8q/OWT
         OoqqFGk6WicE6azBKNrQWfOVVjY6gNvYfdpnwZNOIuttSWwRESrxGwevq32FzYgAHVcT
         aG9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712326467; x=1712931267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fdpDOoHnc4uWZGo9BmBdU7SxrLk8Chx2Kek2lMoOOL0=;
        b=nzd0Kev/WvpyStaQa9kQyod4YOFijBqKqbyAg7U5lhHe1utyHh6IISmPsOECX9ELWQ
         +tcqnTV+5u1n3Mk81l+49F6+5qLQnJdX6PZ4eHMsSzZm5OZw/LZqp+4+OdwMLKEdIR7X
         8lYPmw/PjmxFGgSQyPvHJRLxqLODPGFUZSwoCobteOSCErODmcGDEItbL/x77MYIhszG
         kxOSVLOM+ZD2O8ZG8fNEsAdU6jY101K/C3eMBPg4O40lp7qDXEam9uLAfGR963QxS1Fp
         W4iV/Q0N4oFV8Bd6LBO75p6buQTMVIZAmnkBwHbquLL7uWr51BrLAL+X4ktNjuiFmyjJ
         HLGw==
X-Forwarded-Encrypted: i=2; AJvYcCUdpg19TMiFhfd2wrfERtGqqWeFsrPlj2cc3n1Ax+FuNzfQtngZPWMPwVbiCe/SYlO0IJSYNSZhCOWXlaE0dD6vgRINMbASWA==
X-Gm-Message-State: AOJu0YybzuEEr12EIJgqNnd8cSawqAQLWYrCqVmAPOkDdp593s1Qlybu
	KwK4rxwo42uQaiKBBsc0r1YIZ0P35swRz8qdirs8ICZA4+uCwd+g
X-Google-Smtp-Source: AGHT+IHRLJ+b+iAo1uRK8Oj3zUcy6OX429x3dCOkrAITf1VgTW4i0gxRulpu0dmUJbw/c0eW7CMVAA==
X-Received: by 2002:a17:903:1209:b0:1e0:984b:6215 with SMTP id l9-20020a170903120900b001e0984b6215mr387582plh.16.1712326467239;
        Fri, 05 Apr 2024 07:14:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9cc:b0:2a0:9806:220f with SMTP id
 70-20020a17090a09cc00b002a09806220fls1191518pjo.0.-pod-prod-09-us; Fri, 05
 Apr 2024 07:14:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWe7sBlP71pQpHUGfUF3OnhjJGEBMJfq+SVRIWu/51/K1Noj6tC4T734Ta5T8tuF9BHUAmmNWzh3L/eIFnAgq1LhKYnDP3sebmqg==
X-Received: by 2002:a17:90a:ea14:b0:29f:c827:bc8c with SMTP id w20-20020a17090aea1400b0029fc827bc8cmr1468849pjy.18.1712326465854;
        Fri, 05 Apr 2024 07:14:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712326465; cv=none;
        d=google.com; s=arc-20160816;
        b=RpPwB4gGhoSY3M91369PhLbBwC0xyKXkZcvzzXxMmt1h8QqqOFFkbh6Cb3CTuy8O3U
         wqpyRQ6KAurCZASWlq4NQKnrtBo7JSlPwVEjBweQxU3Oh2EuI1ilRAIg8kmK4NmjXMKj
         JSQivZTuuuVgNZzhq2VMK+Cvgk0ledOo312U0nl6pRu1HhHI33jPyDmsvyaVHv6N2jXy
         0kv/T50XgGQpSHQSsTHhCH/4ulDarl0Y7K6Nz72RlHTURK2dSnYnC0qs1WJ6rGQXqnCo
         fqP717C8YDzdsCVJUFZUw7g9EXMKUVpR2pNu4eQz4k9un+wHR99ARexz66juj+Omt9WV
         Tqkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hpu1q6SRpmnX63rYNMcOKU3gYj7mEiDBoir+Gp671n0=;
        fh=vc/uyyen/FkSt5rKrhQPjV9TSIU4/c4EwRsrQ+ZAPtU=;
        b=OelTKQNN/zQuShLqL98fCdxCz3kD029rnRS9Vg15kgmhFSFwWbZhzUpHPgVQHMZSck
         Q+cRjSssotMmguW39jIKYxK+Ord/pYK+Ackpj3GLTjAAqJZPwaBMdEGkyQxiO2LkVkmT
         RLu0lT6eVmH+uB/5c2z/oA6XCNicpdUaM28TWCrP8dkT/vMS8Pq1fgByGSgDk086V+x2
         ASDcbh5Y9zoWzk/pkBbuRYPhb+3kibv23W1l4iGCVJx0b7VOIwzs16PWLjc+8QYDMxb6
         g9wGDCDHji6+7Hv0uEbPmBzcC2L06g9IngPTAeVkd3xI+GJWJ9uBPFBNs+J9myTqavCv
         P2ug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0SFLdK7U;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id c12-20020a17090abf0c00b002a47f370cc5si79330pjs.1.2024.04.05.07.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Apr 2024 07:14:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 3f1490d57ef6-dccb1421bdeso2302922276.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Apr 2024 07:14:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzBmA5/ytZ2OD/ED6WwvaHFD8lm8rg0pyYgmHPFvJvYQzbAyaii68nQw1fi/9DyY95iFuTIAZNIdH0cy+LZ3Osds54+OwNHfTEDA==
X-Received: by 2002:a05:6902:4a:b0:dc7:32ea:c89f with SMTP id
 m10-20020a056902004a00b00dc732eac89fmr1241871ybh.15.1712326464281; Fri, 05
 Apr 2024 07:14:24 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <c14cd89b-c879-4474-a800-d60fc29c1820@gmail.com>
In-Reply-To: <c14cd89b-c879-4474-a800-d60fc29c1820@gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Apr 2024 07:14:13 -0700
Message-ID: <CAJuCfpHEt2n6sA7m5zvc-F+z=3-twVEKfVGCa0+y62bT10b0Bw@mail.gmail.com>
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Klara Modin <klarasmodin@gmail.com>
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=0SFLdK7U;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2d as
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

On Fri, Apr 5, 2024 at 6:37=E2=80=AFAM Klara Modin <klarasmodin@gmail.com> =
wrote:
>
> Hi,
>
> On 2024-03-21 17:36, Suren Baghdasaryan wrote:
> > Overview:
> > Low overhead [1] per-callsite memory allocation profiling. Not just for
> > debug kernels, overhead low enough to be deployed in production.
> >
> > Example output:
> >    root@moria-kvm:~# sort -rn /proc/allocinfo
> >     127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
> >      56373248     4737 mm/slub.c:2259 func:alloc_slab_page
> >      14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
> >      14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
> >      13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
> >      11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
> >       9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
> >       4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_c=
t_alloc_hashtable
> >       4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] f=
unc:ctagmod_start
> >       3940352      962 mm/memory.c:4214 func:alloc_anon_folio
> >       2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
> >       ...
> >
> > Since v5 [2]:
> > - Added Reviewed-by and Acked-by, per Vlastimil Babka and Miguel Ojeda
> > - Changed pgalloc_tag_{add|sub} to use number of pages instead of order=
, per Matthew Wilcox
> > - Changed pgalloc_tag_sub_bytes to pgalloc_tag_sub_pages and adjusted t=
he usage, per Matthew Wilcox
> > - Moved static key check before prepare_slab_obj_exts_hook(), per Vlast=
imil Babka
> > - Fixed RUST helper, per Miguel Ojeda
> > - Fixed documentation, per Randy Dunlap
> > - Rebased over mm-unstable
> >
> > Usage:
> > kconfig options:
> >   - CONFIG_MEM_ALLOC_PROFILING
> >   - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> >   - CONFIG_MEM_ALLOC_PROFILING_DEBUG
> >     adds warnings for allocations that weren't accounted because of a
> >     missing annotation
> >
> > sysctl:
> >    /proc/sys/vm/mem_profiling
> >
> > Runtime info:
> >    /proc/allocinfo
> >
> > Notes:
> >
> > [1]: Overhead
> > To measure the overhead we are comparing the following configurations:
> > (1) Baseline with CONFIG_MEMCG_KMEM=3Dn
> > (2) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >      CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dn)
> > (3) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >      CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dy)
> > (4) Enabled at runtime (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >      CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dn && /proc/sys/vm/mem_prof=
iling=3D1)
> > (5) Baseline with CONFIG_MEMCG_KMEM=3Dy && allocating with __GFP_ACCOUN=
T
> > (6) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >      CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dn)  && CONFIG_MEMCG_KMEM=
=3Dy
> > (7) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >      CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dy) && CONFIG_MEMCG_KMEM=3D=
y
> >
> > Performance overhead:
> > To evaluate performance we implemented an in-kernel test executing
> > multiple get_free_page/free_page and kmalloc/kfree calls with allocatio=
n
> > sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> > affinity set to a specific CPU to minimize the noise. Below are results
> > from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
> > 56 core Intel Xeon:
> >
> >                          kmalloc                 pgalloc
> > (1 baseline)            6.764s                  16.902s
> > (2 default disabled)    6.793s  (+0.43%)        17.007s (+0.62%)
> > (3 default enabled)     7.197s  (+6.40%)        23.666s (+40.02%)
> > (4 runtime enabled)     7.405s  (+9.48%)        23.901s (+41.41%)
> > (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)
> > (6 def disabled+memcg)  13.332s (+97.10%)       48.105s (+184.61%)
> > (7 def enabled+memcg)   13.446s (+98.78%)       54.963s (+225.18%)
> >
> > Memory overhead:
> > Kernel size:
> >
> >     text           data        bss         dec         diff
> > (1) 26515311        18890222    17018880    62424413
> > (2) 26524728        19423818    16740352    62688898    264485
> > (3) 26524724        19423818    16740352    62688894    264481
> > (4) 26524728        19423818    16740352    62688898    264485
> > (5) 26541782        18964374    16957440    62463596    39183
> >
> > Memory consumption on a 56 core Intel CPU with 125GB of memory:
> > Code tags:           192 kB
> > PageExts:         262144 kB (256MB)
> > SlabExts:           9876 kB (9.6MB)
> > PcpuExts:            512 kB (0.5MB)
> >
> > Total overhead is 0.2% of total memory.
> >
> > Benchmarks:
> >
> > Hackbench tests run 100 times:
> > hackbench -s 512 -l 200 -g 15 -f 25 -P
> >        baseline       disabled profiling           enabled profiling
> > avg   0.3543         0.3559 (+0.0016)             0.3566 (+0.0023)
> > stdev 0.0137         0.0188                       0.0077
> >
> >
> > hackbench -l 10000
> >        baseline       disabled profiling           enabled profiling
> > avg   6.4218         6.4306 (+0.0088)             6.5077 (+0.0859)
> > stdev 0.0933         0.0286                       0.0489
> >
> > stress-ng tests:
> > stress-ng --class memory --seq 4 -t 60
> > stress-ng --class cpu --seq 4 -t 60
> > Results posted at: https://evilpiepirate.org/~kent/memalloc_prof_v4_str=
ess-ng/
> >
> > [2] https://lore.kernel.org/all/20240306182440.2003814-1-surenb@google.=
com/
>
> If I enable this, I consistently get percpu allocation failures. I can
> occasionally reproduce it in qemu. I've attached the logs and my config,
> please let me know if there's anything else that could be relevant.

Thanks for the report!
In debug_alloc_profiling.log I see:

[    7.445127] percpu: limit reached, disable warning

That's probably the reason. I'll take a closer look at the cause of
that and how we can fix it.

 In qemu-alloc3.log I see couple of warnings:

[    1.111620] alloc_tag was not set
[    1.111880] WARNING: CPU: 0 PID: 164 at
include/linux/alloc_tag.h:118 kfree (./include/linux/alloc_tag.h:118
(discriminator 1) ./include/linux/alloc_tag.h:161 (discriminator 1)
mm/slub.c:2043 ...

[    1.161710] alloc_tag was not cleared (got tag for fs/squashfs/cache.c:4=
13)
[    1.162289] WARNING: CPU: 0 PID: 195 at
include/linux/alloc_tag.h:109 kmalloc_trace_noprof
(./include/linux/alloc_tag.h:109 (discriminator 1)
./include/linux/alloc_tag.h:149 (discriminator 1) ...

Which means we missed to instrument some allocation. Can you please
check if disabling CONFIG_MEM_ALLOC_PROFILING_DEBUG fixes QEMU case?
In the meantime I'll try to reproduce and fix this.
Thanks,
Suren.



>
> Kind regards,
> Klara Modin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHEt2n6sA7m5zvc-F%2Bz%3D3-twVEKfVGCa0%2By62bT10b0Bw%40mail.=
gmail.com.
