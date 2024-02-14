Return-Path: <kasan-dev+bncBC7OD3FKWUERB547WSXAMGQEUPKRNLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id B90348552ED
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 20:09:44 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-68f11abd7acsf1545336d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 11:09:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707937783; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQkyLen8nA3v18ixIl7qH+4OE1PoxkUzh1WNDyvc9ilk4A2+YoVCU+1mjS898UCa7V
         QMtY8Q7dA0SOaqJBWDvumIItsd8sREkyf+SifOD+Wfq/TD2Mp349i90lcpNCTle2Gf5j
         1lEXJxBcchYw4FGvD7ndPesjFGhUvFEQU50mSiutw7JRdu7qn/lVlzM09amHOo9wqQ/g
         Shbgepe3k3Y1UtGLiU+oV6Dpr+hAzN4uPc7QNgf5ijYAErWKwA0ItyY6D9+dLe2gTT12
         Gt+QuBx2hlwsABfN48+GzNmh+XVpxYLEPyetBIL4lUgH3SRwwbcRifYzgyCiW0fzzcNX
         MxoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f8VwCUr/4Ea+4co3cx3meGslVKs2Xwp2+SsgI/acSjM=;
        fh=U4f1zsrGmuW+ddG43Vz0QkMyQ1xZP91/j+dNWdGwiSU=;
        b=FQJDJmgGULJE9uulZtbUg76IKqKqO63ukAL3EBB0MyWcgnsw9QD7CKMdX2SxPuFqJM
         /Y4RPTknMtxQK0Q/kJ/CKPQV+X7GYUkyf+Crlxac2lZ95ABiC3iuwEvhWklLXa9LWWy1
         8DKWa+RTDS15qD6FIn6mGGCjw5BJitwTJySmlzP0gWyWKyif9SK1xuQ1yUT6iV0Z0vDi
         gAZWve7/WsHxLYHR/RZw/ouE5g7N9kUQMbjbbjzSWwgIkkHztibUqGX9vUy5Z42Pzk8+
         h4Y6ytwX8m5Wlfhh+SVfVM5/M2+5jitkKWICPwgPjOv2sB0wAB/q0ukf+trxv2aa+KAm
         LIsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DteTzf9z;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707937783; x=1708542583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f8VwCUr/4Ea+4co3cx3meGslVKs2Xwp2+SsgI/acSjM=;
        b=rj/XFBTSbViR/nvImaAbfxeJhKRFEdoZEC0l/77qR4qGWopNxzmHwEOepY/6wwSnuX
         2pKlH+EpP4sReAtqaEFhwFe7+CnwwkuoRMf8QJuWVdUmcaGNrwUWQfTr+SWN7ViKjwPk
         gi9P37jY9yxvdVAErz6bhX7QJFZLeQM4wPyorfXe9VX48RUVP4DJ6JE1rQ2nco/rQTjY
         /C6UFdOLAUs1dZ6I0wyjAWUcb4GSH/4LtWyF5QmZ6i9x6nhVgwXtW45lrhQ3g7pBAxAL
         6wF1x/HxH8OhrTylaOSyet47EqveGfaYW4Cdtu9jGDWOhp+ybpgUlYCQ+D9qzxlk0Kq5
         /3Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707937783; x=1708542583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=f8VwCUr/4Ea+4co3cx3meGslVKs2Xwp2+SsgI/acSjM=;
        b=b1DjGFc1wQK7F9qk1N5QCYm6pJ+p5paNtyHEws3ct5fcjnjZYY+WW/S3Cxp5woONAj
         H5tc2+NbOImHJigVx5uwKBGqklQbqWCi9UKJCjhKNRyYTEoj3HSpoWF87spuWkLJ6rDB
         /78yJG99zAwmFcpqNtVEd8Flh3Stmj63XtOj/ps/81kBSD7rvzkczLVtgP5uKV0E579J
         gDTs0CxulrY9p66Y6IudcKka3UIyuDGY7DfvbL5371kQAv+pQ2152YwF3dmM8b0sM8eG
         +jZjphwCr4a8L6IyESCk73PlOd20/lneUeEF8+a4yO8nl+ojVrYdLuGw9ozj+weceLcJ
         wJ3w==
X-Forwarded-Encrypted: i=2; AJvYcCWJDIdB0Mj4Av0ZqfBcQToGI6NziqNXsbD0AS7hp7FR2qdeNn5+9pdoq83aU8zHB8rG/CRhYDR+wu/PqKe7kRjM6QPHo+xwRQ==
X-Gm-Message-State: AOJu0YzH5y9FRoqpZsXlYTiWKX0a/IpmKwO9y2mWoZ4y7tsve8C3+xWz
	w9onGjtUqBIBOPP3mA3w2+onOp4z5NE8yKCRlsAl8deEPuJspvf8
X-Google-Smtp-Source: AGHT+IHx30dupV3Esvwc+J8JOSoANtZccGxqeJ6pjzbQqXrQz2hytgu18V34+IZU/ggpNBSqiBBgsw==
X-Received: by 2002:a05:6214:2029:b0:681:77d9:c405 with SMTP id 9-20020a056214202900b0068177d9c405mr3905297qvf.33.1707937783569;
        Wed, 14 Feb 2024 11:09:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2505:b0:68d:14e8:40bb with SMTP id
 gf5-20020a056214250500b0068d14e840bbls5955476qvb.1.-pod-prod-01-us; Wed, 14
 Feb 2024 11:09:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWOFthK+UYt8anEB3dtj2shvabyDzwEn2SBtydEdBYc6JkReMc5/3FWf02vlWqaZq4tB7w/a+vc47CibCfAW6dmKC88YI+i4lfu+A==
X-Received: by 2002:a0c:f3d4:0:b0:68c:a9bb:25af with SMTP id f20-20020a0cf3d4000000b0068ca9bb25afmr2641335qvm.11.1707937782926;
        Wed, 14 Feb 2024 11:09:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707937782; cv=none;
        d=google.com; s=arc-20160816;
        b=lb4YOxx+LQQuDUFWE65zZajnXTs5pU6Evwq76iTgQy3Ss7QPUTHgGZUPDznYsQlewV
         spll9ZYHt1kLhzAvwOLQAezhaOh6ZKtvsVqAHJF9SiR4p9LGusgHRdHYyEARcbhqnfae
         wjIcG2tqC7s8h48lbcsF9uxisBNhN9xGVBTE5lB2P3Nfg+/tjedaB6bNDiohNl2E9hFq
         yYZbsi9NA6bOjsYfUlwOwa6W0cs4LfSruIRxKKmwCBklYtb5EkKEQtHYuIzCkJxwhtrn
         8rwJjWvAvktF8RkYbME+eAh3xtwEmfYOksyylf231x7rVIteYOYMOsRvPDi2kinWSzdP
         GVtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YYQ1iEqH1bC/aeDNG7RWtd5Zq4jRnkeS9Y1nPQkLhuU=;
        fh=Nd5pRnc1EX41tFGJ0Winxiv9tp5sueHKFHJ1eKZMPsU=;
        b=xZu9xW9D6sXkHVLzaX0XqJlQi5Qko6UpOrbV6cZMAb+Hv0wgShbFLIjGjQOWQwNGX9
         bWJ9mW8CleCqri64LzluE7uB2xURncTY6o7hn+slmOQb67+eC+c29jCjV+iBi++wldKp
         /hKnK82GZ7oG6kDif+u/8ASpLUW6kEmHU+vXPS/taFVtAVh2drxyXNpxZsZHruEDo9ar
         wWhOH6yjJQUwquyJDLv0x6Kx7jvzusPBTv2NwxPuV6oTWcdW/jJxBiyh79jbtjTjNkWx
         hix+p/Z3/Mr4cVrWlNTbM71e/fU9k8EHixP/JEMAZNrqVWowmqYOYoU3g0t7azvmCPo7
         Llcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DteTzf9z;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXF7VfRGX9oXg574N7nZ91QrI1u4H/Q7ok6RzkdgHmoNxzLoWx31H0flWUSeqQfgVKXzqNLTUmo4HYuXqvJsh4Xy8RJDXouOR6pUg==
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id w12-20020a0ce10c000000b0068efb69f5easi186522qvk.3.2024.02.14.11.09.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 11:09:42 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-dc6d8bd618eso6083168276.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 11:09:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpXYaQbhEvQStlFJQ5e7EAhBMWZS3BnzkfgIaOErXlEnxEQ+JM6ORCVsKZ4e7DZ+stqpoHWAourREiR4MkBCooXRjbRhc8YxQF/A==
X-Received: by 2002:a25:2d01:0:b0:dcc:8114:5a54 with SMTP id
 t1-20020a252d01000000b00dcc81145a54mr3243973ybt.43.1707937782071; Wed, 14 Feb
 2024 11:09:42 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <4f24986587b53be3f9ece187a3105774eb27c12f.camel@linux.intel.com>
In-Reply-To: <4f24986587b53be3f9ece187a3105774eb27c12f.camel@linux.intel.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 11:09:30 -0800
Message-ID: <CAJuCfpGnnsMFu-2i6-d=n1N89Z3cByN4N1txpTv+vcWSBrC2eg@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Tim Chen <tim.c.chen@linux.intel.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=DteTzf9z;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as
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

On Wed, Feb 14, 2024 at 10:54=E2=80=AFAM Tim Chen <tim.c.chen@linux.intel.c=
om> wrote:
>
> On Mon, 2024-02-12 at 13:38 -0800, Suren Baghdasaryan wrote:
> > Memory allocation, v3 and final:
> >
> > Overview:
> > Low overhead [1] per-callsite memory allocation profiling. Not just for=
 debug
> > kernels, overhead low enough to be deployed in production.
> >
> > We're aiming to get this in the next merge window, for 6.9. The feedbac=
k
> > we've gotten has been that even out of tree this patchset has already
> > been useful, and there's a significant amount of other work gated on th=
e
> > code tagging functionality included in this patchset [2].
> >
> > Example output:
> >   root@moria-kvm:~# sort -h /proc/allocinfo|tail
> >    3.11MiB     2850 fs/ext4/super.c:1408 module:ext4 func:ext4_alloc_in=
ode
> >    3.52MiB      225 kernel/fork.c:356 module:fork func:alloc_thread_sta=
ck_node
> >    3.75MiB      960 mm/page_ext.c:270 module:page_ext func:alloc_page_e=
xt
> >    4.00MiB        2 mm/khugepaged.c:893 module:khugepaged func:hpage_co=
llapse_alloc_folio
> >    10.5MiB      168 block/blk-mq.c:3421 module:blk_mq func:blk_mq_alloc=
_rqs
> >    14.0MiB     3594 include/linux/gfp.h:295 module:filemap func:folio_a=
lloc_noprof
> >    26.8MiB     6856 include/linux/gfp.h:295 module:memory func:folio_al=
loc_noprof
> >    64.5MiB    98315 fs/xfs/xfs_rmap_item.c:147 module:xfs func:xfs_rui_=
init
> >    98.7MiB    25264 include/linux/gfp.h:295 module:readahead func:folio=
_alloc_noprof
> >     125MiB     7357 mm/slub.c:2201 module:slub func:alloc_slab_page
> >
> > Since v2:
> >  - tglx noticed a circular header dependency between sched.h and percpu=
.h;
> >    a bunch of header cleanups were merged into 6.8 to ameliorate this [=
3].
> >
> >  - a number of improvements, moving alloc_hooks() annotations to the
> >    correct place for better tracking (mempool), and bugfixes.
> >
> >  - looked at alternate hooking methods.
> >    There were suggestions on alternate methods (compiler attribute,
> >    trampolines), but they wouldn't have made the patchset any cleaner
> >    (we still need to have different function versions for accounting vs=
. no
> >    accounting to control at which point in a call chain the accounting
> >    happens), and they would have added a dependency on toolchain
> >    support.
> >
> > Usage:
> > kconfig options:
> >  - CONFIG_MEM_ALLOC_PROFILING
> >  - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> >  - CONFIG_MEM_ALLOC_PROFILING_DEBUG
> >    adds warnings for allocations that weren't accounted because of a
> >    missing annotation
> >
> > sysctl:
> >   /proc/sys/vm/mem_profiling
> >
> > Runtime info:
> >   /proc/allocinfo
> >
> > Notes:
> >
> > [1]: Overhead
> > To measure the overhead we are comparing the following configurations:
> > (1) Baseline with CONFIG_MEMCG_KMEM=3Dn
> > (2) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >     CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dn)
> > (3) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >     CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dy)
> > (4) Enabled at runtime (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
> >     CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dn && /proc/sys/vm/mem_profi=
ling=3D1)
> > (5) Baseline with CONFIG_MEMCG_KMEM=3Dy && allocating with __GFP_ACCOUN=
T
> >
>
> Thanks for the work on this patchset and it is quite useful.
> A clarification question on the data:
>
> I assume Config (2), (3) and (4) has CONFIG_MEMCG_KMEM=3Dn, right?

Yes, correct.

> If so do you have similar data for config (2), (3) and (4) but with
> CONFIG_MEMCG_KMEM=3Dy for comparison with (5)?

I have data for these additional configs (didn't think there were that
important):
(6) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dn)  && CONFIG_MEMCG_KMEM=3Dy
(7) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=3Dy &&
CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=3Dy) && CONFIG_MEMCG_KMEM=3Dy


>
> Tim
>
> > Performance overhead:
> > To evaluate performance we implemented an in-kernel test executing
> > multiple get_free_page/free_page and kmalloc/kfree calls with allocatio=
n
> > sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> > affinity set to a specific CPU to minimize the noise. Below are results
> > from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
> > 56 core Intel Xeon:
> >
> >                         kmalloc                 pgalloc
> > (1 baseline)            6.764s                  16.902s
> > (2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
> > (3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
> > (4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
> > (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)

(6 default disabled+memcg)    13.332s (+97.10%)         48.105s (+184.61%)
(7 default enabled+memcg)     13.446s (+98.78%)       54.963s (+225.18%)

(6) shows a bit better performance than (5) but it's probably noise. I
would expect them to be roughly the same. Hope this helps.

> >
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGnnsMFu-2i6-d%3Dn1N89Z3cByN4N1txpTv%2BvcWSBrC2eg%40mail.gm=
ail.com.
