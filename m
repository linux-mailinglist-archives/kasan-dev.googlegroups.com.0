Return-Path: <kasan-dev+bncBC7OD3FKWUERBLOTYWXAMGQES7BD3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 63A8D859402
	for <lists+kasan-dev@lfdr.de>; Sun, 18 Feb 2024 03:21:35 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68c4e69e121sf42504086d6.2
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Feb 2024 18:21:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708222894; cv=pass;
        d=google.com; s=arc-20160816;
        b=gqDwRHm7gYldlJ2k31J8z4w10C46y2wJ5kbgfXMTI4uzQ3G8pD5ekym5nSoYw7vZb1
         BvWeF11tkNB3B2DrCgm3kIQ1D/kFENION8iQX7XE9+e/7rDiKfRL5JeJfnW/4851zbE7
         OZeEIbnNVNQAP/iO0wGUMjNJn+FoQQmU3cMwyy9S/OuS6HqnPZ7oXsx7iiqzaCG8dR+f
         aS1d/XAalVw9bUh3cj8I0XHeKkZpqmzx9wap9DHKHra+dpALc38i9EngP3m+5Gf/Oucw
         Ke8m/tzmnQX+gti+otnLg52nYmEewwPADl8CRhQk2Yr7dGiJQ/dAi0AszZxxzU8WNRNk
         TlGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YnutHMD2skd60nnyDAGHBJYaRERvdPWnarcKt6I+zmo=;
        fh=C+RJm4zhVPiiJO04zLxEuD04nHzWvLnljrt50pkLKrE=;
        b=inyODI2dDEg+0rVtiSwYKGL1xLJj77C8FwuE+i6484nIF+m0FCD+r6IfmYWHddO8VS
         FtxEdumculKAx2IPpUJ4Erd4nPAsoJvsWzM0GCUXom+fUQhMsg3EJO7QiEoQnP73tlXR
         dMZehv5f7PqYxg5VBGyx9l/9H6ackLqpqGUyK4lptdRS1jfiHICVgKugMM2STkSigvSG
         cKzNZlkakPJQ/MQ9AnRUyaKLWTpnlMc1NVvhecYiCW3wu+IeX8Bvo+1QTpWgu7iKL8no
         hjSAW7QmdAWtK3exfGc5AGLZSYFWGtr2bzRwkbgs8KTTSbkvrCqUH8QMRqol7vwpnn12
         /GEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wSyYWYER;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708222894; x=1708827694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YnutHMD2skd60nnyDAGHBJYaRERvdPWnarcKt6I+zmo=;
        b=GxssHUhDXHUZ3Z/L97qCZI3y4g+7FOmX4O/vN5eelvoegRobSisFzJKAAtyJAsGhox
         kEQflPzDThTr/Iz+9tvF0HSskAGIEKxoyhIJUkCZkqtLzTVvMIbSATpSKPC+n1g67bF+
         GBJ/LS/IrnLHU2gwfgaTjKhVMIfaQcE3w8Jfk7zDM/zUI+rguhV+VXXg+WYTAzXuMHVh
         /dcLbXiKzL/i9GwCrqo12r5/FNmairkqMppYgJl8lHO42ho7R8AXwSCc047a6ztsW84g
         zPQulE9endlB5kTMmbY7vsz8KJq624C/KxyE5UnGrqpbM3gfDNMK/XlHb09sX2toh+gW
         x4tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708222894; x=1708827694;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YnutHMD2skd60nnyDAGHBJYaRERvdPWnarcKt6I+zmo=;
        b=lD8r8DzWnTd4Me9usWK+EdEfHV8WG/H7mmIDgqM0jinJLiLCpA/nMfmGO/weAidniD
         z+O8QTnHg2FwI1n7fJVptkwy7QnmQTfUUKMk9rJE1Dx4O64YkXDS4YRIAjlITZZilv50
         Fg7EzRZbqH3iYOWfVt+1anWKlUsjqBizlJRVFx8v+1dub4xP+uSKtk/GCdK0Bwg3kdGf
         LZbqkmBdrH92yX6oADwWo82+7W1gGbGB4sEQmfwfy8IEKrts528NFo+jGoHfnczbJ8iT
         lIeE3S+/tVniF7QdWvIkQkHxinbWxAG+AVHIsKuiokCFLdaFfkW/y9t5so/DgA2loxn6
         KO0w==
X-Forwarded-Encrypted: i=2; AJvYcCVxOQOgpsj4dEqoqy47rt8tCVcJJB3vj7kac7XBMlaPmdYZ8XIuSgzH05gYZwY1tfE6NB2Ay0p9E/kSHl8Mh5nqzp4pXCIUaw==
X-Gm-Message-State: AOJu0YwU7fYhIxU1SpKIWEI3JYSqYM/wu2FaZMaAWq7yNpvhuSOCw1Z7
	6pE3BvbQU0oqr5zuo+3pD27L4abg5lJVM6lJrz8+9WG8ZAtbbK6p
X-Google-Smtp-Source: AGHT+IGkMujq8izjZjI6ZAyGDCm6bzWtCfPkF2K3h8LKp69yEWyvwAgqdLXdoiPnO6eTjmkqoZ3/7Q==
X-Received: by 2002:ac8:58d3:0:b0:42d:f2a1:4e14 with SMTP id u19-20020ac858d3000000b0042df2a14e14mr4625895qta.55.1708222893875;
        Sat, 17 Feb 2024 18:21:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d06:0:b0:42e:382:7cd9 with SMTP id g6-20020ac87d06000000b0042e03827cd9ls291225qtb.2.-pod-prod-02-us;
 Sat, 17 Feb 2024 18:21:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUiGiAEiraEQnHOhYBeX5uz/funCOf6IN/Ge/8wCA2KR4XCdkU2//nLG2IrUaejyKmVNH/cXUr9clyPiFG0Li0EfUbArORojOdzQQ==
X-Received: by 2002:ac8:5a15:0:b0:42d:adce:fcea with SMTP id n21-20020ac85a15000000b0042dadcefceamr11187671qta.36.1708222892962;
        Sat, 17 Feb 2024 18:21:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708222892; cv=none;
        d=google.com; s=arc-20160816;
        b=CdH0mfUCOjV4/qg7lcoqD3qYOS8HbvtwNoLf8aBR65bRi3oGKjwuChQU0TzqyYFPWX
         svPkmOxY0nJQj42Y209M/WLScIdgl7JZgif2nbSuUYQEGIea4J9mBFhWAG+oi8CGv6TC
         GD0EX/8oRgDIPAuSJeY5fyhjeZzv8o3qa0zduGEMMIa2dMqnzVGqWKR3vcvrpwmjkWVD
         whTitbF3tD3V2LdfliIky3mkf+yt97PNmEOgPh6c6RVCUKJPXIpMUxXqzr3v4ccDzNh6
         wmBb4YrDxmJ3rd++unUrkM1QDCkTDt+2e81Bkm2wOhUaqDwInVMGQg7SQzOQcvdP7ZOq
         zwow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aGwMPlFmMn7i+PsCRsmYPKBrgHwqE0wRHG6PNy5zjw0=;
        fh=sSHrb2PrcTqE2C4kR2S4DjnzCxz3TYxwcBtcY20J0Ac=;
        b=JsS9kwUusRvIlG1/1z9npdJn4cEFBVf1dETzp+QPxBVYlVoQ/1URptFDGZFsqP7V3I
         zy4ewJp4iNHk6ff3Lz3BiUtLMqI97H95l8NJfsNNiwQtOe7KssMSI2UAznIyWh/d30AP
         Afz/0+pleU3RECssO43hrCjL2Xg8TFubVr5SI9YT7dC3f1TTLWnt3UpO3Go+EmfGmdz9
         2vU4VyJOq0EdsQMq06PSYCsGtfFOEpv5sig+5ZmOZqxO2fpQBkAwzMf+MoGcV5BkO4cd
         L4nB8TR/Xrt0iDghdSwE9jkhH97ANoAHyOs7BqB9HF/MR2oO6z70TUWLIO0cHPLBLKHH
         X1Tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wSyYWYER;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id g1-20020ac85d41000000b0042e082ee1f5si5929qtx.0.2024.02.17.18.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Feb 2024 18:21:32 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-dc236729a2bso3041740276.0
        for <kasan-dev@googlegroups.com>; Sat, 17 Feb 2024 18:21:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUPR8AJdCuMv4AovUBSb9z6d8yk880Rpd5wROr8sYOGSMUHEubbxpPZjFZ+dojexANThVQkMsSFx0hZcysOH3REnE7hvBD2VMJw2w==
X-Received: by 2002:a05:6902:268a:b0:dcd:4e54:9420 with SMTP id
 dx10-20020a056902268a00b00dcd4e549420mr9768527ybb.5.1708222891980; Sat, 17
 Feb 2024 18:21:31 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <f92ad1e3-2dde-4db2-9b76-96c6bbc6a208@suse.cz>
In-Reply-To: <f92ad1e3-2dde-4db2-9b76-96c6bbc6a208@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 18 Feb 2024 02:21:18 +0000
Message-ID: <CAJuCfpGemg-aXyiK1fHavdKuW+-9+DM5_4krLAdg+DQh=24Dvg@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
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
 header.i=@google.com header.s=20230601 header.b=wSyYWYER;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as
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

On Fri, Feb 16, 2024 at 8:57=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:38, Suren Baghdasaryan wrote:
> > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easi=
ly
> > instrument memory allocators. It registers an "alloc_tags" codetag type
> > with /proc/allocinfo interface to output allocation tag information whe=
n
> > the feature is enabled.
> > CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
> > allocation profiling instrumentation.
> > Memory allocation profiling can be enabled or disabled at runtime using
> > /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=
=3Dn.
> > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
> > profiling by default.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > ---
> >  Documentation/admin-guide/sysctl/vm.rst |  16 +++
> >  Documentation/filesystems/proc.rst      |  28 +++++
> >  include/asm-generic/codetag.lds.h       |  14 +++
> >  include/asm-generic/vmlinux.lds.h       |   3 +
> >  include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
> >  include/linux/sched.h                   |  24 ++++
> >  lib/Kconfig.debug                       |  25 ++++
> >  lib/Makefile                            |   2 +
> >  lib/alloc_tag.c                         | 158 ++++++++++++++++++++++++
> >  scripts/module.lds.S                    |   7 ++
> >  10 files changed, 410 insertions(+)
> >  create mode 100644 include/asm-generic/codetag.lds.h
> >  create mode 100644 include/linux/alloc_tag.h
> >  create mode 100644 lib/alloc_tag.c
> >
> > diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/ad=
min-guide/sysctl/vm.rst
> > index c59889de122b..a214719492ea 100644
> > --- a/Documentation/admin-guide/sysctl/vm.rst
> > +++ b/Documentation/admin-guide/sysctl/vm.rst
> > @@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
> >  - legacy_va_layout
> >  - lowmem_reserve_ratio
> >  - max_map_count
> > +- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=3Dy)
> >  - memory_failure_early_kill
> >  - memory_failure_recovery
> >  - min_free_kbytes
> > @@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
> >  The default value is 65530.
> >
> >
> > +mem_profiling
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > +
> > +Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=3Dy)
> > +
> > +1: Enable memory profiling.
> > +
> > +0: Disabld memory profiling.
>
>       Disable

Ack.

>
> ...
>
> > +allocinfo
> > +~~~~~~~
> > +
> > +Provides information about memory allocations at all locations in the =
code
> > +base. Each allocation in the code is identified by its source file, li=
ne
> > +number, module and the function calling the allocation. The number of =
bytes
> > +allocated at each location is reported.
>
> See, it even says "number of bytes" :)

Yes, we are changing the output to bytes.

>
> > +
> > +Example output.
> > +
> > +::
> > +
> > +    > cat /proc/allocinfo
> > +
> > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
>
> Is "module" meant in the usual kernel module sense? In that case IIRC is
> more common to annotate things e.g. [xfs] in case it's really a module, a=
nd
> nothing if it's built it, such as slub. Is that "slub" simply derived fro=
m
> "mm/slub.c"? Then it's just redundant?

Sounds good. The new example would look like this:

    > sort -rn /proc/allocinfo
   127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
    56373248     4737 mm/slub.c:2259 func:alloc_slab_page
    14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
    14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
    13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
    11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
     9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
     4206592        4 net/netfilter/nf_conntrack_core.c:2567
func:nf_ct_alloc_hashtable
     4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod]
func:ctagmod_start
     3940352      962 mm/memory.c:4214 func:alloc_anon_folio
     2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
     ...

Note that [ctagmod] is the only allocation from a module in this example.

>
> > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc=
_order
> > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_sla=
b_obj_exts
> > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pag=
es_exact
> > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:=
__pte_alloc_one
> > +     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvmall=
oc
> > +     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cgro=
up_prepare
> > +      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
> > +      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page_cac=
he_func
> > +      640KiB     drivers/char/virtio_console.c:452 module:virtio_conso=
le func:alloc_buf
> > +      ...
> > +
> > +
> >  meminfo
>
> ...
>
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 0be2d00c3696..78d258ca508f 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -972,6 +972,31 @@ config CODE_TAGGING
> >       bool
> >       select KALLSYMS
> >
> > +config MEM_ALLOC_PROFILING
> > +     bool "Enable memory allocation profiling"
> > +     default n
> > +     depends on PROC_FS
> > +     depends on !DEBUG_FORCE_WEAK_PER_CPU
> > +     select CODE_TAGGING
> > +     help
> > +       Track allocation source code and record total allocation size
> > +       initiated at that code location. The mechanism can be used to t=
rack
> > +       memory leaks with a low performance and memory impact.
> > +
> > +config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > +     bool "Enable memory allocation profiling by default"
> > +     default y
>
> I'd go with default n as that I'd select for a general distro.

Well, we have MEM_ALLOC_PROFILING=3Dn by default, so if it was switched
on manually, that is a strong sign that the user wants it enabled IMO.
So, enabling this switch by default seems logical to me. If a distro
wants to have the feature compiled in but disabled by default then
this is perfectly doable, just need to set both options appropriately.
Does my logic make sense?

>
> > +     depends on MEM_ALLOC_PROFILING
> > +
> > +config MEM_ALLOC_PROFILING_DEBUG
> > +     bool "Memory allocation profiler debugging"
> > +     default n
> > +     depends on MEM_ALLOC_PROFILING
> > +     select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > +     help
> > +       Adds warnings with helpful error messages for memory allocation
> > +       profiling.
> > +
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGemg-aXyiK1fHavdKuW%2B-9%2BDM5_4krLAdg%2BDQh%3D24Dvg%40mai=
l.gmail.com.
