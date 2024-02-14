Return-Path: <kasan-dev+bncBC7OD3FKWUERBY5EWSXAMGQEWXMMBZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C96685531C
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 20:20:05 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-363d18bdbd6sf24675ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 11:20:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707938404; cv=pass;
        d=google.com; s=arc-20160816;
        b=PekTvzVbjA2WYlXnzRHvJEaqQHNpbYHKbg04ZXMp7ijG6SePxWFN1kCHydwqHn7lBq
         EU6tNGLjXxogozgT5ZaKAVBNY6no1JR5KdTCibQhG/9woGwEXeJOYZbcMCxDjgs01ZxR
         TIQuGoKNSiye4mmMVU5AcZVxqYv5G5F9910u7B+X4FTozENYvIA+n48xp1QN3N1rkHmj
         EwKiUZXlvEH6pcBVySHQ+fFXsU/lcUTpdxtrw62GNsfMw+OZGT9wvbeQmArNBdGmCZj/
         uoKwbBSp7ifeX9kU3Pmw7B79vJY/t45wEeXOXoXlKZWozS5s1gCMvXWy2WCqVEFXZVSe
         r7fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1bPwbSqGSNrjlAcI59sFBDU9dO88KrypQ/+5g2YKq3I=;
        fh=cCHagZxp6eITG/7e7sKJU9bnSVepdI70Nj9v8GIe5IU=;
        b=XzUrk2fznnXk70P+hfy3EEwBry568BcszHz/OSyeyc3R6r14QwuW54TVHRHAnIHSAD
         3LoevdpclRuiRuTDlpOc0TA4ly5zOiONlo6dzTUsU8xsZQkzkRkk1mMBeeoNiOefFJaq
         hVAHCZI3PfnqlOmLWmrpen8iCr4xK0HCYdLJjGaoJibRcyyb5Aufwg5OFNFGaP1pkfU9
         jt4JcjrdV/CrGRn2QX1Ijphzl3C+PeRQXkjx1C+YorwpWjJeORPEY4/r7PN9kXCMe6Ps
         EKEhNrdScxshsxxiXP5d8db5BbAOy25ZSar8Yf1dhRmO3CVXOj1+48Wb03YCjkMWyLUr
         gq1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dB+DNQsZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707938404; x=1708543204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1bPwbSqGSNrjlAcI59sFBDU9dO88KrypQ/+5g2YKq3I=;
        b=c5rUrVMMS62NI2SdGlFTlB2EOjGFoItr8XIelbOP4n+PaGd1PKNrkl6xWoWdFiSnkd
         aNBA0tHJxYPaJlFb9iu+Hyw2mimBvEsseVP/Ug/odEOEvWBeG5PjHiBFeeRm/NNJl3LK
         zMzlyQk2a/G34O1ciwvP0vl4NlU/pEvM34b8ysMVgpXUbY65aqyWimokUhh7kIGdsFDx
         nvsIhEogRqRMp/3AZoK509nhUYX8NXiMh5djbMCVuEiWYICb4aTZGchQNSK41O2NqvbT
         s2NEuuoKb7jV7rdEPMulS4SkGC+4+ufXOiKiDQzcy0Q2G49XALfAoFeOBuVwLmknqciF
         9OzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707938404; x=1708543204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1bPwbSqGSNrjlAcI59sFBDU9dO88KrypQ/+5g2YKq3I=;
        b=WN+qUPerIz9s15qS5GEpetdB+E2pxYgjNNN0Y8uPddYRMFJKJUyW42+aWVnBiExPHV
         eZn3FLCTchqb6Xg4UmH1jgUtRuzsaaaaDt2io7wEYmS6prEM00LyKIjFR0zUVnhi92dG
         PxK7utGMYY0fuNXHWWGDC2NrtsSfrgCNwRKCcqncNQAubYLZkUiovUxRG9rKlxwFvEuM
         g77Xmm16YGl7Q5f+0MKkn0h3g9raDAgnxGmFH1PDN+A1ACshDOw8jiHOkd299EvZ952E
         wDcwyfMT+dTN12cstqkns/+ApWRmWB/y3Yy/um7ExF+cjTspmD61TknvmvJt6yM/3Ui5
         VBSw==
X-Forwarded-Encrypted: i=2; AJvYcCU+O/WYMtZ8T4Jja0OMNV3eBJn2blbhCscAqrumfpSFwad+0qvhHJhHBKP823SHXepLERFwd9fk5g6MSktYZ0y5vumOU07ytw==
X-Gm-Message-State: AOJu0YwDmQvAFU8monnjNmul8/ecxtRGYVGGDJ/02bNkd+ZaGB+j6me6
	YL5XAwquVTBijgz3y8J+VRsfESdjemFmnJUlC7cfNRoz652p1UaB
X-Google-Smtp-Source: AGHT+IFvTFU69TIpIN6YgbuB7sYJvrxe/g4CMamZVg51rfT1V5jJRLtjQUv0drrSgZGrR6gX12eVsg==
X-Received: by 2002:a92:dac5:0:b0:363:bd95:83d3 with SMTP id o5-20020a92dac5000000b00363bd9583d3mr205914ilq.15.1707938403885;
        Wed, 14 Feb 2024 11:20:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3109:b0:364:f2cd:ef88 with SMTP id
 bg9-20020a056e02310900b00364f2cdef88ls4742ilb.1.-pod-prod-07-us; Wed, 14 Feb
 2024 11:20:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUSkmQls1E4V9BxV6QUga2n3n6WiqFf2H/FyFGR1JFUf5Mqyu2yKiXIM0xiBLP64+wwWg9YdGCRboE3uZBhUCdz83BbeBOzjBiywA==
X-Received: by 2002:a05:6e02:339b:b0:363:812d:d6a6 with SMTP id bn27-20020a056e02339b00b00363812dd6a6mr5151347ilb.3.1707938403135;
        Wed, 14 Feb 2024 11:20:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707938403; cv=none;
        d=google.com; s=arc-20160816;
        b=XcC5VQ/XAgb6AJf2kTCMObFzxRHkv5FITRRW6BvkcYBdBPYvYtmzPRi/IsVx8UFsuf
         0ZABYOuzk0p3D7sU7fXZKnykp0EfEmcb9oI5RgcusRCUv3E1qWPTR/9sUDAT/nWL9+Jv
         C7EuamHeBSB3awtcw40Ry/jWzhsFbNn604gKqLxqCjbsJ5f7rF+DsZDgZF2cEgkzxZDP
         D0MLS1wDd6JU2PJCj376tnTmhlpp6nwoe3f/UKCaYa6HH6eDpVvn7V8bRV7iWu0UWuaQ
         cyDqxscVWpf+I225Vvqm6cBYMV8ANRxtFESE1zQMIFpmbZ2EzHyl8HWVJPnkv5Qmz1hj
         xG6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BeLyV2BNkjBFN275c/stAXS4Zt5cMLEm0RT7xxWo7xU=;
        fh=bFcHqrIJ+kiPICYiv0J5c42NvmpKMg7y2WflSWo4CoU=;
        b=xx8tNh3cI8q4/Ac2PBKBfQXmPtyJdG48wX9HHghevFVQsP/1nPGOsWUkZ6NNgbIh62
         ePTG7CHppjh9ZUWfgjpCzV2YREqnsA9yv8OTEktEIsEFInt3EI2CXFnI8GPz0cwcWPgV
         dZ+mxUl/GfAq09HVS8/F4jg2Ec3E64xaK2fH9PeC9R40ubUQEkMp3rtPoSJvWPLSz/nq
         Va2GAzSG9L1xnRu0rUNcLl0eUZIwI/JgB+pedEX+Vez9vzZxRcORxg1X9qF11l/X+eI6
         BhN/3RyndMOt9Bl5KtzwMFcHkSkrFiQWPmxSrGWKPBprCKoxBrBzQcNkYCDlhvfLMPxu
         xbjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dB+DNQsZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVEBTcwlwMh7t4pGLZcylNm0QmaoxcXUaJs+3U5vPfwcJ+dYdePqC9qO7dRP9DWGgMmvhzKXkJjGmhmeVz5vu4YVb8dXE7pAD6rcA==
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id p17-20020a056e0206d100b003642c039243si158028ils.4.2024.02.14.11.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 11:20:03 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id 3f1490d57ef6-dcc4de7d901so24687276.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 11:20:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVNgf6z51bN6CFvuV+Fxrnk1WGJqKskrI3yjqIKXutcjBEf6d3N0WV1GjXOxUsaR3cIpMJkstH6U/05A4iPV2JnbpxqSS6uSXrwrA==
X-Received: by 2002:a25:8708:0:b0:dc6:c617:7ca with SMTP id
 a8-20020a258708000000b00dc6c61707camr3594670ybl.29.1707938402225; Wed, 14 Feb
 2024 11:20:02 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-6-surenb@google.com>
 <3cf2acae-cb8d-455a-b09d-a1fdc52f5774@suse.cz>
In-Reply-To: <3cf2acae-cb8d-455a-b09d-a1fdc52f5774@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 11:19:51 -0800
Message-ID: <CAJuCfpH6O4tKP5=aD=PHnM8TpDLi_s6cRLHy-1i-7Eie0wqnFA@mail.gmail.com>
Subject: Re: [PATCH v3 05/35] mm: introduce slabobj_ext to support slab object extensions
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
 header.i=@google.com header.s=20230601 header.b=dB+DNQsZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as
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

On Wed, Feb 14, 2024 at 9:59=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:38, Suren Baghdasaryan wrote:
> > Currently slab pages can store only vectors of obj_cgroup pointers in
> > page->memcg_data. Introduce slabobj_ext structure to allow more data
> > to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> > to support current functionality while allowing to extend slabobj_ext
> > in the future.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> ...
>
> > +static inline bool need_slab_obj_ext(void)
> > +{
> > +     /*
> > +      * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditi=
onally
> > +      * inside memcg_slab_post_alloc_hook. No other users for now.
> > +      */
> > +     return false;
> > +}
> > +
> > +static inline struct slabobj_ext *
> > +prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
> > +{
> > +     struct slab *slab;
> > +
> > +     if (!p)
> > +             return NULL;
> > +
> > +     if (!need_slab_obj_ext())
> > +             return NULL;
> > +
> > +     slab =3D virt_to_slab(p);
> > +     if (!slab_obj_exts(slab) &&
> > +         WARN(alloc_slab_obj_exts(slab, s, flags, false),
> > +              "%s, %s: Failed to create slab extension vector!\n",
> > +              __func__, s->name))
> > +             return NULL;
> > +
> > +     return slab_obj_exts(slab) + obj_to_index(s, slab, p);
>
> This is called in slab_post_alloc_hook() and the result stored to obj_ext=
s
> but unused. Maybe introduce this only in a later patch where it becomes
> relevant?

Ack. I'll move it into the patch where we start using obj_exts.

>
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -201,6 +201,54 @@ struct kmem_cache *find_mergeable(unsigned int siz=
e, unsigned int align,
> >       return NULL;
> >  }
> >
> > +#ifdef CONFIG_SLAB_OBJ_EXT
> > +/*
> > + * The allocated objcg pointers array is not accounted directly.
> > + * Moreover, it should not come from DMA buffer and is not readily
> > + * reclaimable. So those GFP bits should be masked off.
> > + */
> > +#define OBJCGS_CLEAR_MASK    (__GFP_DMA | __GFP_RECLAIMABLE | \
> > +                             __GFP_ACCOUNT | __GFP_NOFAIL)
> > +
> > +int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> > +                     gfp_t gfp, bool new_slab)
>
> Since you're moving this function between files anyway, could you please
> instead move it to mm/slub.c. I expect we'll eventually (maybe even soon)
> move the rest of performance sensitive kmemcg hooks there as well to make
> inlining possible.

Will do.

>
> > +{
> > +     unsigned int objects =3D objs_per_slab(s, slab);
> > +     unsigned long obj_exts;
> > +     void *vec;
> > +
> > +     gfp &=3D ~OBJCGS_CLEAR_MASK;
> > +     vec =3D kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
> > +                        slab_nid(slab));
> > +     if (!vec)
> > +             return -ENOMEM;
> > +
> > +     obj_exts =3D (unsigned long)vec;
> > +#ifdef CONFIG_MEMCG
> > +     obj_exts |=3D MEMCG_DATA_OBJEXTS;
> > +#endif
> > +     if (new_slab) {
> > +             /*
> > +              * If the slab is brand new and nobody can yet access its
> > +              * obj_exts, no synchronization is required and obj_exts =
can
> > +              * be simply assigned.
> > +              */
> > +             slab->obj_exts =3D obj_exts;
> > +     } else if (cmpxchg(&slab->obj_exts, 0, obj_exts)) {
> > +             /*
> > +              * If the slab is already in use, somebody can allocate a=
nd
> > +              * assign slabobj_exts in parallel. In this case the exis=
ting
> > +              * objcg vector should be reused.
> > +              */
> > +             kfree(vec);
> > +             return 0;
> > +     }
> > +
> > +     kmemleak_not_leak(vec);
> > +     return 0;
> > +}
> > +#endif /* CONFIG_SLAB_OBJ_EXT */
> > +
> >  static struct kmem_cache *create_cache(const char *name,
> >               unsigned int object_size, unsigned int align,
> >               slab_flags_t flags, unsigned int useroffset,
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 2ef88bbf56a3..1eb1050814aa 100644
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
> > +                                         freelist_new, counters_new);
>
> I can see the mixing of tabs and spaces is wrong but perhaps not fix it a=
s
> part of the series?

I'll fix them in the next version.

>
> >               local_irq_restore(flags);
> >       }
> >       if (likely(ret))
> > @@ -1881,13 +1881,25 @@ static inline enum node_stat_item cache_vmstat_=
idx(struct kmem_cache *s)
> >               NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
> >  }
> >
> > -#ifdef CONFIG_MEMCG_KMEM
> > -static inline void memcg_free_slab_cgroups(struct slab *slab)
> > +#ifdef CONFIG_SLAB_OBJ_EXT
> > +static inline void free_slab_obj_exts(struct slab *slab)
>
> Right, freeing is already here, so makes sense put the allocation here as=
 well.
>
> > @@ -3817,6 +3820,7 @@ void slab_post_alloc_hook(struct kmem_cache *s, s=
truct obj_cgroup *objcg,
> >               kmemleak_alloc_recursive(p[i], s->object_size, 1,
> >                                        s->flags, init_flags);
> >               kmsan_slab_alloc(s, p[i], init_flags);
> > +             obj_exts =3D prepare_slab_obj_exts_hook(s, flags, p[i]);
>
> Yeah here's the hook used. Doesn't it generate a compiler warning? Maybe =
at
> least postpone the call until the result is further used.

Yes, I'll move that into the patch where we start using it.

Thanks for the review, Vlastimil!

>
> >       }
> >
> >       memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
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
kasan-dev/CAJuCfpH6O4tKP5%3DaD%3DPHnM8TpDLi_s6cRLHy-1i-7Eie0wqnFA%40mail.gm=
ail.com.
