Return-Path: <kasan-dev+bncBC7OD3FKWUERBIHS6KXQMGQEDFB36UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DC8D886370
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 23:48:02 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-229b412e738sf1774014fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 15:48:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711061280; cv=pass;
        d=google.com; s=arc-20160816;
        b=SsSHIdn5ft6XCWld/9jnR19oGvD65n6rN9CKXnLI6o2CFpQmc4Yk2sg8lqrH1qxhOw
         Sjh+/ZlqufD7gmcCuKrP3sZIcIQG7lURwNgyW+ju2Ut4PYu5jjFPPF+4H11P9kHC+gIJ
         Y2BXjzB1JLeElMW5xkL7wQgJzuEVCTfhS6XByQQr/s9zbKKYjkeczwyQB2ADLTzKH6/6
         4u/ORxvTF/E08fDbMJ4wT+nOfDYPC+Ijet6H8uav5C7WDQH7veddLWjyOXnVxeDfgTPN
         8cw3pktWkOHsCLb2KHqMPiyq/YMhmYRjNYcJOjsq8Ve/U9bqQHqXOW7bbu+uxB9cuUO2
         GrpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OL11OfVotVl9x4vJCrjErySDZQFBKKZPrd+IW6LbKu0=;
        fh=fP6ZoXUZHn4oHknC5AqgOM2r62N1H5qA3C93RqLxyxc=;
        b=HGC/86n3JYvScaVax+IVaQUi190nWTBmYHpBAnR18Xgx6co5/kKMnWs/Gc3QvMK1vL
         9E1Pxgit12lTxcD59NXNHC3kMsr4CLVCS+bAHvGOrj+TcVHN5DMbI7ZBvvzeC6GqW2wc
         BVwbK3P9f1SbcvJliEGNW2S+RnOJDZ5aZ4tDcgX//8WIbJSQplLXbsWsDXHqEs8RdjMf
         4RYq9Ay9k/OF6+6lkwchlH/NLUOUcwnY1SGWRL7iJh+blountVNsfvjfpJSyPppFfhhZ
         kIi1bm8TmTbwsFQRO+cSiELsRsSE9MkALVRdT6mlmSHfJYKg5zUcWv3naAapeKGuDuzE
         Jd9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w8rRI56b;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711061280; x=1711666080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OL11OfVotVl9x4vJCrjErySDZQFBKKZPrd+IW6LbKu0=;
        b=Oy9z050WjUvXNsMN2BcnEYweU+HaURqwcNssk0zxbvK3R95mByHogk0PBm9pJoLEuT
         xQzq+KpA4U3aBtDmSkQpeJ5su6odDFyTtwbIGFPtGL9Dku+/eKPBHU95hIy5Gv6iDduX
         xEm5zIILjfJ8z15hYTDcOUWCrqtqVU0U+pdt6gLTRXVhbruNHXn3a5oAx2kciOKRMwQO
         Z7tragss9GWSBnMoAoJRV01tDzl3J81DfCOuAUf+WCJQLEfO0U74E6oc7nF0yIzIGBTh
         +mvvn2mV+gmywlCC09QG6OR6zBC0V9iTnaSa1nE00vWqtPMrO8eYdYUr9d0oSi1ogkTd
         cFAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711061280; x=1711666080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OL11OfVotVl9x4vJCrjErySDZQFBKKZPrd+IW6LbKu0=;
        b=N7xvmsn2DRKVYGQGqG5qfDq1OHwn0mEuvrUK5GP2/dJn9pPqbxhGOp+xFP8l2pfhTF
         K3ZwUkLxfCk43F2vQf4bpvOcjvmT3w+eFfpDsIPHa4fJFQN46rfLId4ffzqiAlonqaX0
         k5kjyKlWRd4JG02JXa94kCYbUTaUPsE0ZD0GuiVNFjRXnXDNC0AFbOuEFS3kGTwgEC8q
         ecI741UaL8GgPwLcnfOA2RiZSHf6/cIpFOlUNAuTsh2H6NrNoYISOhgCMjtYQdKzBo9V
         A2dclEYqTgBrXg5iU9xkz/+TV/6JaSn+YFqEGsqjUQo7h+jO/WrnY1QHtSlQXcQtLlsN
         C27A==
X-Forwarded-Encrypted: i=2; AJvYcCViwRAMItoORauTIGt+4ZJLDouWBmMpd4shDlStasE8M3NM5CVtu/3kV9lGGOS+iUffHQxvGSBZRmOQSztkPZAND7rbUVKOPg==
X-Gm-Message-State: AOJu0Yx67NQ+EAqiBBcccDMzUIzS3TbNf4IjUYl2m2vBccASlpzYqMNE
	Kcyrv5gtfHf7ndfT4wanZ0017QPh0iGu3uJcduHCAN/XBnb5nDKB
X-Google-Smtp-Source: AGHT+IENg6qXevbshjqxXFeZizzsFG8Y6xs5iqYSB540RAGFXYBuRyOFT3v0riWnwCPSyIcumXkA3Q==
X-Received: by 2002:a05:6870:470f:b0:221:bca9:3b81 with SMTP id b15-20020a056870470f00b00221bca93b81mr712336oaq.22.1711061280606;
        Thu, 21 Mar 2024 15:48:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:93aa:b0:6e6:f6ed:5daf with SMTP id
 ka42-20020a056a0093aa00b006e6f6ed5dafls1058543pfb.1.-pod-prod-07-us; Thu, 21
 Mar 2024 15:47:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVheGf3exQKB6T+JvLcKSf5EfS/V0B57BXvxmubk+472gO6JwUMhs00xrK6qQAos9ik5cWgHhKfmThxs4N8YqgAtfcHYqacaSTPnA==
X-Received: by 2002:a05:6a00:1a91:b0:6e6:7b17:7f21 with SMTP id e17-20020a056a001a9100b006e67b177f21mr841986pfv.19.1711061279335;
        Thu, 21 Mar 2024 15:47:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711061279; cv=none;
        d=google.com; s=arc-20160816;
        b=fRXLULX7WRSQISxSPD8vhTFQA4PNbIh5RTOKXS9Pd+Zft6TECJAO6mRF/RVqH19DDX
         eNyPCOelzKnHEtIUVphqx2lk++L47kDhdHAWP8vGe8LaBpNBE3kfdhzbswMBa9HkFFAl
         DYO36hTG6Qz9w/nEkflopd3lAuGmCS25UMuc8TXtVzGNhYTs3mZQuEi7h4KEmv8ypCC2
         YpLp7Qpickd1sKYDxcYvjK7g3sX8jU5fVnz8/umJKXJretegynxfP4WEWZNzk1HHlEgn
         DzHxbuTim6i1mC5SZ8VcDazuY2bm8ydgpQm51d0cTFjmW3O7B06wL5cI/FDRKDiLBhWs
         bdIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pZUn+CabKddPK7NEf/S7R2Utterh/ASXmWz24mderPg=;
        fh=L1aA7HS4FM813RMBsBXlqb/BC8h53/xTSqBxrczqbPI=;
        b=ltRdQuRsWBzOBGLmfjt+hy+NHTPA1zuvSv+/41jR9HdAAX6KJMo4WCXiZAHf4AsoRU
         wlXH4ljTTxpYJXJungxby7s6IRR6tF84wYhGQmUEpedqHq9wHZcGKQK9P8HEKqSWOTww
         h7xek6xSmBqLAs+O9r6L3u20YRTNW+O9jSMBMNrMFJg/3KqTUJxaMOhu2snxz1LuLRPj
         Exab7q+dhLkU26mBvENP9t7s96cI8fsuDhGDCjaJholm+3jmw6xGXNmthdI+DItns1ec
         04h6U+jReOE/6enBRn0h3XS2YVoQBp4iajhiROCdDHt0gFsfjkwdmG8Vh5AOcr0nMb1x
         +z0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w8rRI56b;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id gl3-20020a056a0084c300b006ea7b30555bsi44247pfb.5.2024.03.21.15.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 15:47:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-60a3c48e70fso15899027b3.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 15:47:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFpjxRO0eT1d7S9KSU+7KKRvyO3a77+F8iJO5BHpetMPTFX4DkOtO/uS/LRqZ1ogBeMjNlG/aJU07jgDr5pa8cq72FY+vARiIPBA==
X-Received: by 2002:a25:8047:0:b0:dda:aace:9665 with SMTP id
 a7-20020a258047000000b00ddaaace9665mr551844ybn.60.1711061278005; Thu, 21 Mar
 2024 15:47:58 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-6-surenb@google.com>
 <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
 <gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao@dpstjnacdubq>
 <20240321150908.48283ba55a6c786dee273ec3@linux-foundation.org> <bliyhrwtskv5xhg3rxxszouxntrhnm3nxhcmrmdwwk4iyx5wdo@vodd22dbtn75>
In-Reply-To: <bliyhrwtskv5xhg3rxxszouxntrhnm3nxhcmrmdwwk4iyx5wdo@vodd22dbtn75>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Mar 2024 15:47:44 -0700
Message-ID: <CAJuCfpEO4NjYysJ7X8ME_GjHc41u-_dK4AhrhmaSMh_9mxaHSA@mail.gmail.com>
Subject: Re: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>, mhocko@suse.com, vbabka@suse.cz, 
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
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=w8rRI56b;       spf=pass
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

On Thu, Mar 21, 2024 at 3:17=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Thu, Mar 21, 2024 at 03:09:08PM -0700, Andrew Morton wrote:
> > On Thu, 21 Mar 2024 17:15:39 -0400 Kent Overstreet <kent.overstreet@lin=
ux.dev> wrote:
> >
> > > On Thu, Mar 21, 2024 at 01:31:47PM -0700, Andrew Morton wrote:
> > > > On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@googl=
e.com> wrote:
> > > >
> > > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > >
> > > > > We're introducing alloc tagging, which tracks memory allocations =
by
> > > > > callsite. Converting alloc_inode_sb() to a macro means allocation=
s will
> > > > > be tracked by its caller, which is a bit more useful.
> > > >
> > > > I'd have thought that there would be many similar
> > > > inlines-which-allocate-memory.  Such as, I dunno, jbd2_alloc_inode(=
).
> > > > Do we have to go converting things to macros as people report
> > > > misleading or less useful results, or is there some more general
> > > > solution to this?
> > >
> > > No, this is just what we have to do.
> >
> > Well, this is something we strike in other contexts - kallsyms gives us
> > an inlined function and it's rarely what we wanted.
> >
> > I think kallsyms has all the data which is needed to fix this - how
> > hard can it be to figure out that a particular function address lies
> > within an outer function?  I haven't looked...
>
> This is different, though - even if a function is inlined in multiple
> places there's only going to be one instance of a static var defined
> within that function.

I guess one simple way to detect the majority of these helpers would
be to filter all entries from /proc/allocinfo which originate from
header files.

~# grep ".*\.h:." /proc/allocinfo
      933888      228 include/linux/mm.h:2863 func:pagetable_alloc
         848       53 include/linux/mm_types.h:1175 func:mm_alloc_cid
           0        0 include/linux/bpfptr.h:70 func:kvmemdup_bpfptr
           0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
           0        0 include/linux/bpf.h:2256 func:bpf_map_alloc_percpu
           0        0 include/linux/bpf.h:2256 func:bpf_map_alloc_percpu
           0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
           0        0 include/linux/bpf.h:2249 func:bpf_map_kvcalloc
           0        0 include/linux/bpf.h:2243 func:bpf_map_kzalloc
           0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
           0        0 include/linux/ptr_ring.h:471
func:__ptr_ring_init_queue_alloc
           0        0 include/linux/bpf.h:2256 func:bpf_map_alloc_percpu
           0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
           0        0 include/net/tcx.h:80 func:tcx_entry_create
           0        0 arch/x86/include/asm/pgalloc.h:156 func:p4d_alloc_one
      487424      119 include/linux/mm.h:2863 func:pagetable_alloc
           0        0 include/linux/mm.h:2863 func:pagetable_alloc
         832       13 include/linux/jbd2.h:1607 func:jbd2_alloc_inode
           0        0 include/linux/jbd2.h:1591 func:jbd2_alloc_handle
           0        0 fs/nfs/iostat.h:51 func:nfs_alloc_iostats
           0        0 include/net/netlabel.h:281 func:netlbl_secattr_cache_=
alloc
           0        0 include/net/netlabel.h:381 func:netlbl_secattr_alloc
           0        0 include/crypto/internal/acompress.h:76
func:__acomp_request_alloc
        8064       84 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
        1016       74 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
         384        4 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
         704        3 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
          32        1 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
          64        1 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
          40        2 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
          32        1 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
       30000      625 include/acpi/platform/aclinuxex.h:67
func:acpi_os_acquire_object
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:67
func:acpi_os_acquire_object
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
         512        1 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
         192        6 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
         192        3 include/acpi/platform/aclinuxex.h:52 func:acpi_os_all=
ocate
       61992      861 include/acpi/platform/aclinuxex.h:67
func:acpi_os_acquire_object
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 include/acpi/platform/aclinuxex.h:67
func:acpi_os_acquire_object
           0        0 include/acpi/platform/aclinuxex.h:57
func:acpi_os_allocate_zeroed
           0        0 drivers/iommu/amd/amd_iommu.h:141 func:alloc_pgtable_=
page
           0        0 drivers/iommu/amd/amd_iommu.h:141 func:alloc_pgtable_=
page
           0        0 drivers/iommu/amd/amd_iommu.h:141 func:alloc_pgtable_=
page
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/hid_bpf.h:154 func:call_hid_bpf_rdesc_f=
ixup
           0        0 include/linux/skbuff.h:3392 func:__dev_alloc_pages
      114688       56 include/linux/ptr_ring.h:471
func:__ptr_ring_init_queue_alloc
           0        0 include/linux/skmsg.h:415 func:sk_psock_init_link
           0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
           0        0 include/linux/ptr_ring.h:628 func:ptr_ring_resize_mul=
tiple
       24576        3 include/linux/ptr_ring.h:471
func:__ptr_ring_init_queue_alloc
           0        0 include/net/netlink.h:1896 func:nla_memdup
           0        0 include/linux/sockptr.h:97 func:memdup_sockptr
           0        0 include/net/request_sock.h:131 func:reqsk_alloc
           0        0 include/net/tcp.h:2456 func:tcp_v4_save_options
           0        0 include/net/tcp.h:2456 func:tcp_v4_save_options
           0        0 include/crypto/hash.h:586 func:ahash_request_alloc
           0        0 include/linux/sockptr.h:97 func:memdup_sockptr
           0        0 include/linux/sockptr.h:97 func:memdup_sockptr
           0        0 net/sunrpc/auth_gss/auth_gss_internal.h:38
func:simple_get_netobj
           0        0 include/crypto/hash.h:586 func:ahash_request_alloc
           0        0 include/net/netlink.h:1896 func:nla_memdup
           0        0 include/crypto/skcipher.h:869 func:skcipher_request_a=
lloc
           0        0 include/net/fq_impl.h:361 func:fq_init
           0        0 include/net/netlabel.h:316 func:netlbl_catmap_alloc

and it finds our example:

         832       13 include/linux/jbd2.h:1607 func:jbd2_alloc_inode

Interestingly the inlined functions which are called from multiple
places will have multiple entries with the same file+line:

           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc
           0        0 include/linux/dma-fence-chain.h:91
func:dma_fence_chain_alloc

So, duplicate entries can be also used as an indication of an inlined alloc=
ator.
I'll go chase these down and will post a separate patch converting them.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEO4NjYysJ7X8ME_GjHc41u-_dK4AhrhmaSMh_9mxaHSA%40mail.gmail.=
com.
