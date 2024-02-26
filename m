Return-Path: <kasan-dev+bncBC7OD3FKWUERBY4R6OXAMGQE3JNBX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA67867E28
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 18:22:44 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-558aafe9bf2sf3235173a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 09:22:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708968164; cv=pass;
        d=google.com; s=arc-20160816;
        b=IO9zU+bRggr9ujqPQX9JHL0WJ1rou0gLbJY4R3KfgFMnuFbA64lEC6UEr2bVsAjgKv
         BHDOPxPvsrz8Fj8iGcKjK8uTS5gU2ySGofiFgkE6nYke/t65h1C7y8GTFoOhp1FOmSsA
         TDhuwYYuXS8BDf91MJtSjqpRJVnBUENFU2wXZmjAwkkbQAG8Wdn5WrP0Z9IzguTjykEI
         LkAHaT8ocXChnGLwKa2UpnNBXNVjR2vekIs6guiS6lfm9J/3FezIZM7QK0VehfPmOMU1
         stQwy+pj9PTsiLYordX9a5ax4k88slphTS6d84NEupPgY/eVuNkQ4liJlJBQaj1UC+at
         Fhig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9ofAvyyQEvy+kBNHitIo1RthWDCtuYpruLMCg1hZnZw=;
        fh=cUzuTbuFQ60aOZFIf/wOUs2JWUxCrj1sjpbgvZ1DFco=;
        b=VcaMxVOcE6YAlxmWEcbBOQHn41K37OFNfSLVm9Qv+O68ismzDxfTT7zJDhhWYzjKmq
         pAQ2s/pL6w4KWYpNYWIg+v4o0LoZuLWlV6WPQAe7Z1B+x3V1mUtceBXpKkZVEzKhMyi3
         VKBUbnxHzPpRi88rNQfdQnxmkWekZo+Ix2RwuUK4pjODtue6CgcfXoU1calqkrAmsWN2
         80Omjtfhh+hWYyVeEufWytl8UgdYsKoihXag6STkpJFvXiQpwwElKQzJNb8dLlxc2Pdu
         ouqnyBFAvOb+74V9BHZCxWNxTCQ85urVxf9XMix+LKK4PHw8hsEkdzkFesrbJdHIyaX4
         oN8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0MTJr4Zs;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708968164; x=1709572964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9ofAvyyQEvy+kBNHitIo1RthWDCtuYpruLMCg1hZnZw=;
        b=R0u0euEZFddERp0D/Vsztzjj6tOhyS3UFG8aQzeLgL9aGveExauOy7IQiWuIWWP7+Y
         v9/EykOaed6lELuo7r3ac87SjRxTEBTI+PDGCszBmzMyJKUgk7eE8D/MUCTRUzdoMa4w
         bjCd+LIDIc2wg9Wg3/Fn7UYs6vrG0c/oC9R8l+stTNt6udvAp5F81RFpXezAweBmkqA6
         L1SiUa/yWvYX7RIp8h/39UzVe4UXCm1vssbE58p6iRZUAKXBfcBQZdKyP8q7XCiwqLY8
         TEB07K3oOBjaQTY+F9nlOjxu54CNNph4KTXXE8BpR7dnLt1v9LTzx5qpG+NZ24WPM9PY
         zLAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708968164; x=1709572964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9ofAvyyQEvy+kBNHitIo1RthWDCtuYpruLMCg1hZnZw=;
        b=Ho7M2N04DqOYQ+IG8FA6dLfOiOBlc55vqSETV9Oys95jZ/a1t2NaEYkgKI81SRBkyX
         9DtMA9Xdl4Hg9te0rhwxAyILOT066WF+mh5zLcNG4mVZSOxHQZRU4EEdYyvl7QQyvdi7
         rx7jB4iNDHV+pEJqEP6kK2WpHDQe4cli0pCfgbZZuDogXZ7LdLsvXf+5q2YnJJrxlXNs
         miltLgVgFdtMVadzguCuYR2bXSSvnHHVs9ovY04nl3dCRByXk+7RiFh/5HFSa4ViTXti
         hKaS29zzlQ4pm37SkX6Wzlg87AEuu2pogIZwghG0ioy/c2iY8xzQniKZyAQdAU1fKnnQ
         e5EA==
X-Forwarded-Encrypted: i=2; AJvYcCV2Z5s9xH/DeHFd69xUlDvH18ec0leC99V+zgXFYddE2e/m59CYN+vvwSY28TvSoaOjoLZT+hkHlYH1keDCkU5gTFCqk3VRig==
X-Gm-Message-State: AOJu0YzQynPJSIiiBNmwM0bHiRIB7wTArCIhixib1xCyNj42AWUtBVAg
	gDvvAHmdA+okYMofOoQWt7esJSu7hv6Xox0LdhU0882faMDEwSMb
X-Google-Smtp-Source: AGHT+IFXteZ1HDMmIb73kcSqWk5B47p9mKMVDUMsKPkvDUbwTBNiG0j9yUhCXsSGgUyqKC+1fPq0ZA==
X-Received: by 2002:aa7:de15:0:b0:565:c814:d891 with SMTP id h21-20020aa7de15000000b00565c814d891mr3443435edv.0.1708968163701;
        Mon, 26 Feb 2024 09:22:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4012:b0:563:7f55:3eb2 with SMTP id
 d18-20020a056402401200b005637f553eb2ls51249eda.1.-pod-prod-03-eu; Mon, 26 Feb
 2024 09:22:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUwkbLWSAOenjowYkAfhrV/Wh5OVCt3gpTRbNUUdeaX21xdr5UvGFGGFq7pByN8Brv6/3L1Ea7kHL6yLLXRJGjSx9wN8SKr5P/UfQ==
X-Received: by 2002:a17:906:3c05:b0:a3f:db30:8999 with SMTP id h5-20020a1709063c0500b00a3fdb308999mr5696334ejg.4.1708968161948;
        Mon, 26 Feb 2024 09:22:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708968161; cv=none;
        d=google.com; s=arc-20160816;
        b=KT8txaFtTNkUBQSrm/HYRVfxcx54QawMtxXboHmDutkAShzip1zYu7C89sYKc+a7Yi
         uP5fJUlnoDcnPiHwToXHtiMkpf2UwoUC8P7iSiYLKjJ00h6VmH/rK9ZZsnSo8G0UNgna
         zdP/+bqco3os05F6c4vFAquqa73fer2pjP7t7ieyueLyETg6Pt2dMVmgaJUZUXPtw33Z
         SFkdlgcx0wtYDgAY7ZiIDnGYEJzuhEdRnpozjMddUwZp3jUA6cV9o3FCDlEx04wOqq4y
         XG1ZGYU2PbV2y30w5lpCMi3j9eFC0UcQuCqjnFCrWnr3AGsWJOZi2n24whRyjc1v4vmj
         y73w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dv1MR8FFyIVeo2kD5/jRtw1zZdBqiDH8uTYdJ7duKRA=;
        fh=szvVUr276qS01xeH/BIuEudoXJONyCRcOMCofjhy/Ns=;
        b=a5n0rUUslaWtOIR9MVGdBv4bd5JtmXPqjv+o4mPb2dNoyjAK55sKCEZNsOBM0OpVHm
         qFZN5/kLxeOa17Q6yEQEO10hhLR3MpPoQaJIh8ByJRYofjNUsX5+JxyE+OFYwfPXqjhA
         U0CqJLhLJj16bCVezUNjlrFC6GJEsRQ4iXi7wgqIfjekxeswTJYIPYVfknC0QBFpFKNA
         h4v+kDhLqbNKEHVTJdBL/90PTrAem4eT+KNMmjl1n16zmrN2rOqaTjDmS8+P5Rvvjzeh
         tmnJcJVxNKc13O/kew+6ykjR3svi7+ubx6dL77RpN1TChrACfJ282YuADmhLqVrcWMjN
         Qa/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0MTJr4Zs;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id ga34-20020a1709070c2200b00a3e5ad28aeasi381985ejc.2.2024.02.26.09.22.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 09:22:41 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id 38308e7fff4ca-2d288bac3caso17158021fa.2
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 09:22:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV8o2Llhtshvx57JLcAKrUh5c2T2WuAORu7Kte2sXpiSNTBKDB+zw3F4v6jYnDgZulbV3cC+odhSDJyTuNfq6d4j5UlGhxnm4FnvQ==
X-Received: by 2002:a2e:990b:0:b0:2d2:7164:c6ba with SMTP id
 v11-20020a2e990b000000b002d27164c6bamr4367139lji.43.1708968160893; Mon, 26
 Feb 2024 09:22:40 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-8-surenb@google.com>
 <6851f8a0-e5d2-4b79-9cee-cff0fdec2970@suse.cz>
In-Reply-To: <6851f8a0-e5d2-4b79-9cee-cff0fdec2970@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Feb 2024 17:22:21 +0000
Message-ID: <CAJuCfpHA-0PsQcNMcJVniVyUo4+nUYaioQSS7ZnXO_TGxgumqA@mail.gmail.com>
Subject: Re: [PATCH v4 07/36] mm: introduce slabobj_ext to support slab object extensions
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
 header.i=@google.com header.s=20230601 header.b=0MTJr4Zs;       spf=pass
 (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::22d as
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

On Mon, Feb 26, 2024 at 8:26=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Currently slab pages can store only vectors of obj_cgroup pointers in
> > page->memcg_data. Introduce slabobj_ext structure to allow more data
> > to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> > to support current functionality while allowing to extend slabobj_ext
> > in the future.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> Hi, mostly good from slab perspective, just some fixups:
>
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > -int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
> > -                              gfp_t gfp, bool new_slab);
> > -void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgd=
at,
> > -                  enum node_stat_item idx, int nr);
> > -#else /* CONFIG_MEMCG_KMEM */
> > -static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
> > +int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> > +                     gfp_t gfp, bool new_slab);
> >
>
> We could remove this declaration and make the function static in mm/slub.=
c.

Ack.

>
> > +#else /* CONFIG_SLAB_OBJ_EXT */
> > +
> > +static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
> >  {
> >       return NULL;
> >  }
> >
> > -static inline int memcg_alloc_slab_cgroups(struct slab *slab,
> > -                                            struct kmem_cache *s, gfp_=
t gfp,
> > -                                            bool new_slab)
> > +static inline int alloc_slab_obj_exts(struct slab *slab,
> > +                                   struct kmem_cache *s, gfp_t gfp,
> > +                                   bool new_slab)
> >  {
> >       return 0;
> >  }
>
> Ditto

Ack.

>
> > -#endif /* CONFIG_MEMCG_KMEM */
> > +
> > +static inline struct slabobj_ext *
> > +prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
> > +{
> > +     return NULL;
> > +}
>
> Same here (and the definition and usage even happens in later patch).

Ack.

>
> > +#endif /* CONFIG_SLAB_OBJ_EXT */
> > +
> > +#ifdef CONFIG_MEMCG_KMEM
> > +void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgd=
at,
> > +                  enum node_stat_item idx, int nr);
> > +#endif
> >
> >  size_t __ksize(const void *objp);
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index d31b03a8d9d5..76fb600fbc80 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -683,10 +683,10 @@ static inline bool __slab_update_freelist(struct =
kmem_cache *s, struct slab *sla
> >
> >       if (s->flags & __CMPXCHG_DOUBLE) {
> >               ret =3D __update_freelist_fast(slab, freelist_old, counte=
rs_old,
> > -                                         freelist_new, counters_new);
> > +                                         freelist_new, counters_new);
> >       } else {
> >               ret =3D __update_freelist_slow(slab, freelist_old, counte=
rs_old,
> > -                                         freelist_new, counters_new);
> > +                                         freelist_new, counters_new);
> >       }
> >       if (likely(ret))
> >               return true;
> > @@ -710,13 +710,13 @@ static inline bool slab_update_freelist(struct km=
em_cache *s, struct slab *slab,
> >
> >       if (s->flags & __CMPXCHG_DOUBLE) {
> >               ret =3D __update_freelist_fast(slab, freelist_old, counte=
rs_old,
> > -                                         freelist_new, counters_new);
> > +                                         freelist_new, counters_new);
> >       } else {
> >               unsigned long flags;
> >
> >               local_irq_save(flags);
> >               ret =3D __update_freelist_slow(slab, freelist_old, counte=
rs_old,
> > -                                         freelist_new, counters_new);
> > +                                          freelist_new, counters_new);
>
> Please no drive-by fixups of whitespace in code you're not actually
> changing. I thought you agreed in v3?

Sorry, I must have misunderstood your previous comment. I thought you
were saying that the alignment I changed to was incorrect. I'll keep
them untouched.


>
> >  static inline bool memcg_slab_pre_alloc_hook(struct kmem_cache *s,
> >                                            struct list_lru *lru,
> >                                            struct obj_cgroup **objcgp,
> > @@ -2314,7 +2364,7 @@ static __always_inline void account_slab(struct s=
lab *slab, int order,
> >                                        struct kmem_cache *s, gfp_t gfp)
> >  {
> >       if (memcg_kmem_online() && (s->flags & SLAB_ACCOUNT))
> > -             memcg_alloc_slab_cgroups(slab, s, gfp, true);
> > +             alloc_slab_obj_exts(slab, s, gfp, true);
>
> This is still guarded by the memcg_kmem_online() static key, which is goo=
d.
>
> >
> >       mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
> >                           PAGE_SIZE << order);
> > @@ -2323,8 +2373,7 @@ static __always_inline void account_slab(struct s=
lab *slab, int order,
> >  static __always_inline void unaccount_slab(struct slab *slab, int orde=
r,
> >                                          struct kmem_cache *s)
> >  {
> > -     if (memcg_kmem_online())
> > -             memcg_free_slab_cgroups(slab);
> > +     free_slab_obj_exts(slab);
>
> But this no longer is, yet it still could be?

Yes, I missed that, it seems. free_slab_obj_exts() would bail out but
still checking the static key is more efficient. I'll revive this
check.

Thanks for the review!
Suren.

>
> >
> >       mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
> >                           -(PAGE_SIZE << order));
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHA-0PsQcNMcJVniVyUo4%2BnUYaioQSS7ZnXO_TGxgumqA%40mail.gmai=
l.com.
