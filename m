Return-Path: <kasan-dev+bncBC7OD3FKWUERBJUV7CXAMGQEMHFUXLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C4F5869BC8
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 17:15:35 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-dccc49ef73esf6682908276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 08:15:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709050534; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bo6YrUBZ64kNSwKoVxRAxpOPFONuX3GeVoJbUdRpC/RO3vO0S5GAAaHFcpxvaLwTP4
         O7vTXzcEjDQ2CwYbGBiEXZgLXsDHkdqjyZhGUiTU8UfXzewEAztwijJqpIqVRt7EMiue
         5jNzSlpQ3qncvPxm9No+vnbt1BFrsuaHk9+ILbSZQ7yVqkH4kZ0O3uZsKi3efl5+At7x
         6AvJ2dlfY1EEqoe1V0ZY4q4khWTeWVZhJndaTH5b9XNdqn4rz6ZTFEm2Ebu1STkfnBYH
         Iti4756bq5ZX6fhXb9G04LA5I8KiZkUzSYOCPoUOLjESXCER6PBIvH+w2SMYvisKlJ0g
         r2kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jSVrXt+6tWJsRVI+dvgLxdm7c1Qk4EVhVsG2ZfxfhWk=;
        fh=kVBkOe1VpfOcJIYuCNQeVpIs89T+Uy6nVEpLyEAb7VE=;
        b=XjCGfWy4AiFbK3JbMGg+oLgPvuB7Xdy9lqyhhNG4ovtz47BoVRcyVyFK4NEWdFZyZS
         MxS8JY2NjTDHgo2u8+6KB/ypsTQyWyzz7fVoJbT31YGg3rmq5aLTWCv/6MsMr8MAnxF7
         Y7AhFawBMTKeP078HroG1zkAJOMgBtY2hyOeYC5UKVuwz6hNTje++FbmAy9xcXRokjka
         rVdGpCHprH40ffbzbOH2DgctzhM2oRkmAJThb+aAKwkN7D21+LHgds2E1s/hiCgdoxlG
         ZTemD9paL/grw3S3SdVU9/pfAtyMz02p/4kvBDEKf61r+/G+m+KDNJbWTfqxGroc/U5a
         KRnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SNAcSwlZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709050534; x=1709655334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jSVrXt+6tWJsRVI+dvgLxdm7c1Qk4EVhVsG2ZfxfhWk=;
        b=EzYmBN2Rr2clEBuyq/a7s2nxtXBPYdvQyM4w2vbKVbJjhPo3BLUjtFld3tKDjT66GT
         GrZb+yB5kr7THum7athVIVTfzei7R4uSnkfhqDqklgCfk9OAyFtJ8SB8YxIayjLqs/kS
         96UTLMGgDVbEIRa4rGyJyX17/YDSm5IvPDrtFzdpBFk6foJyqcYGWhx0c8BLqGo0MPOB
         MbJruCsTZl1DPthetR+z1vlyXxn0nDbNmOeOtSr3KDErOZUKK9/+yH0S+ElytPzK+DDS
         S0QITAOTrH97E9G+1XgdpuR3SLfQrLKZyALm2fgm6mu0CFXNg8cN8Wn5SplK5EZZCZcs
         L0HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709050534; x=1709655334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jSVrXt+6tWJsRVI+dvgLxdm7c1Qk4EVhVsG2ZfxfhWk=;
        b=PLYCSurYpqqOXDeyAhX1t0egMKcrqXAy231wsv3uaGXOZ54gaIbzIF2UczRyS/8g7z
         D5gEqpFO+V8mAFG3SheWOHmBI/5Ys/iBGbFT0FWTB+AYjvdleMHiamR5GEj6zK/dbNed
         P9qC86AOmS3pZerU22tWXZ4dOsIWwmeWP12IxvGeHNz+mhfawz1TD8mFq2JEI6Uk9Leq
         XBTH6c+YSyVHaiDrxrpWDSYYzWs4ki57aTKVMMRBwLykVuFmeqerUZh9pG18zFfw4Wkn
         MFKL23J4LBxfDI4YxThIsEazbNsvr74iZZYZm8p7PJoGHmsUoX8p6qtZZZ2FvoSz0qlp
         /zyg==
X-Forwarded-Encrypted: i=2; AJvYcCXOqfQPMtjnorkZF5XbcMb2Kx1Khqy/yBs6YTe+RwIgND5H5OwUk3r1jB2ynTQ02LZTpN34ZkTurAL6W1j52Xko3JabFGNQ4w==
X-Gm-Message-State: AOJu0YyLqwxCDrjUdgWb8+kDxTdnAQd3N5MfldT9I22AKxrPW9NMkDeV
	AmmeVsZeWlU8LXvhL59AI/NmnMjGH05t3vFFukyOaufIiSth9dPGUmk=
X-Google-Smtp-Source: AGHT+IHQgLLhLcGm4nyZkREi9EJEB4h/G008FKrEiPqCf4nzxc0AFddGMjdb1+g/4KiI4x3BwwZ00w==
X-Received: by 2002:a5b:8c7:0:b0:dcf:66d4:1766 with SMTP id w7-20020a5b08c7000000b00dcf66d41766mr2635405ybq.52.1709050534568;
        Tue, 27 Feb 2024 08:15:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dfc4:0:b0:dcd:a08f:c832 with SMTP id w187-20020a25dfc4000000b00dcda08fc832ls510906ybg.0.-pod-prod-04-us;
 Tue, 27 Feb 2024 08:15:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXK1wMdKiTZzZeOG7rKDYkXFRzFjfv1QftC1Cm3lPTzk438mCL6dyjrYCLXdshjj2k9YElr8ZNPPAD1p2TfMt7CKwut6SdhJZ9lzg==
X-Received: by 2002:a0d:e8d1:0:b0:608:922:4001 with SMTP id r200-20020a0de8d1000000b0060809224001mr2361706ywe.5.1709050533679;
        Tue, 27 Feb 2024 08:15:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709050533; cv=none;
        d=google.com; s=arc-20160816;
        b=k6zRE6MR1GqGAQgRhO4Q47QWj25nwD1KiDHfqKYBWdFwH0+OmvCL7d5L+/j/HwA1/P
         UVFhzH/HiVcM0g0iprhpds8kOG2+45arB3PX0myRvgVHs7Pr4u8nKR+xfSmj7IPY5FW3
         2JXHUP+OZFmKCZCrmRbZeOzHmleVrWhcXPrEMVDgTa4ro2JTR7ush9lCZiNJV90RxPCz
         WcBJhmfyjpk9gllu16yc1yqC6SoG4/95Liw7xXcvFdjL0FFlt3OrFRVWBwgrDNjSnaDz
         QGdIg1QnEul9in1h0848R9Y3JpETzDbWvRIOXeE40Xk1cYNCSp790n1ftMkuQ3cfs+tt
         pY8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZscKwOxqDJIaAnxf3DOisSB4kKJVJaPdUBtyCsbS8zY=;
        fh=tSlHExWh2yjUttSdMt7FYZG0Em2sFAPbLx7lzsXYZac=;
        b=jBylMPQf2VpkVnPQN7EVYl/fGz5OSR/VwX+iALupl1GIfSN3SnYuXPuPdfDa1TzMPQ
         H3rK663cnoQYrf4EPk5slsQfKx6eSKxchEYRtWRN8Um5XXa0RVIEthYi2U7rDUfZSvE5
         C0JdKRb/wCvj5YOiGv7+ee19t4tskIT/BZGBuM9EbEBfOAEov57PuDWT5F5s6pAM9wxu
         Dr/gyP+yQykR4cVbJuiR00VifEx7QR0/LdjxgkVZ+69XZNAt8VfxsK6XRpLh0TryXjji
         XPxNugsvfb5Z/3e4aXh3kKhrcSSm1iv7sDhJPXv1rGShcYAoHmBMJU9StXpB+K/N749n
         VkLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=SNAcSwlZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id r198-20020a0de8cf000000b00608dc4f5a2csi666832ywe.2.2024.02.27.08.15.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Feb 2024 08:15:33 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-dcbc00f6c04so4584642276.3
        for <kasan-dev@googlegroups.com>; Tue, 27 Feb 2024 08:15:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXb22z8HhDiihfQzIKGcOBK1cZk/H55ziun/jeobnCJBS/CFXsMvVxsXIP0ORDI83A45Aaansj9RsNwj2+g5bmEjzCTUdwEBL1CLw==
X-Received: by 2002:a25:aac5:0:b0:dcc:4b84:67cd with SMTP id
 t63-20020a25aac5000000b00dcc4b8467cdmr2309188ybi.9.1709050532850; Tue, 27 Feb
 2024 08:15:32 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-23-surenb@google.com>
 <4a0e40e5-3542-4d47-bb2b-c0666f6a904d@suse.cz>
In-Reply-To: <4a0e40e5-3542-4d47-bb2b-c0666f6a904d@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Feb 2024 08:15:21 -0800
Message-ID: <CAJuCfpGvSfu5dtxFVxmQ4cMfQti2vGVtkNmm2kqQVPfrpFM1tw@mail.gmail.com>
Subject: Re: [PATCH v4 22/36] mm/slab: add allocation accounting into slab
 allocation and free paths
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
 header.i=@google.com header.s=20230601 header.b=SNAcSwlZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as
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

On Tue, Feb 27, 2024 at 5:07=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
>
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Account slab allocations using codetag reference embedded into slabobj_=
ext.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > ---
> >  mm/slab.h | 66 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
> >  mm/slub.c |  9 ++++++++
> >  2 files changed, 75 insertions(+)
> >
> > diff --git a/mm/slab.h b/mm/slab.h
> > index 13b6ba2abd74..c4bd0d5348cb 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -567,6 +567,46 @@ static inline struct slabobj_ext *slab_obj_exts(st=
ruct slab *slab)
> >  int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> >                       gfp_t gfp, bool new_slab);
> >
> > +static inline bool need_slab_obj_ext(void)
> > +{
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +     if (mem_alloc_profiling_enabled())
> > +             return true;
> > +#endif
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
> > +     if (s->flags & SLAB_NO_OBJ_EXT)
> > +             return NULL;
> > +
> > +     if (flags & __GFP_NO_OBJ_EXT)
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
> > +}
> > +
> >  #else /* CONFIG_SLAB_OBJ_EXT */
> >
> >  static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
> > @@ -589,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, g=
fp_t flags, void *p)
> >
> >  #endif /* CONFIG_SLAB_OBJ_EXT */
> >
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +
> > +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, =
struct slab *slab,
> > +                                     void **p, int objects)
>
> Only used from mm/slub.c so could move?

Ack.

>
> > +{
> > +     struct slabobj_ext *obj_exts;
> > +     int i;
> > +
> > +     obj_exts =3D slab_obj_exts(slab);
> > +     if (!obj_exts)
> > +             return;
> > +
> > +     for (i =3D 0; i < objects; i++) {
> > +             unsigned int off =3D obj_to_index(s, slab, p[i]);
> > +
> > +             alloc_tag_sub(&obj_exts[off].ref, s->size);
> > +     }
> > +}
> > +
> > +#else
> > +
> > +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, =
struct slab *slab,
> > +                                     void **p, int objects) {}
> > +
> > +#endif /* CONFIG_MEM_ALLOC_PROFILING */
> > +
> >  #ifdef CONFIG_MEMCG_KMEM
> >  void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgd=
at,
> >                    enum node_stat_item idx, int nr);
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 5dc7beda6c0d..a69b6b4c8df6 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -3826,6 +3826,7 @@ void slab_post_alloc_hook(struct kmem_cache *s, s=
truct obj_cgroup *objcg,
> >                         unsigned int orig_size)
> >  {
> >       unsigned int zero_size =3D s->object_size;
> > +     struct slabobj_ext *obj_exts;
> >       bool kasan_init =3D init;
> >       size_t i;
> >       gfp_t init_flags =3D flags & gfp_allowed_mask;
> > @@ -3868,6 +3869,12 @@ void slab_post_alloc_hook(struct kmem_cache *s, =
       struct obj_cgroup *objcg,
> >               kmemleak_alloc_recursive(p[i], s->object_size, 1,
> >                                        s->flags, init_flags);
> >               kmsan_slab_alloc(s, p[i], init_flags);
> > +             obj_exts =3D prepare_slab_obj_exts_hook(s, flags, p[i]);
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +             /* obj_exts can be allocated for other reasons */
> > +             if (likely(obj_exts) && mem_alloc_profiling_enabled())
> > +                     alloc_tag_add(&obj_exts->ref, current->alloc_tag,=
 s->size);
> > +#endif
>
> I think that like in the page allocator, this could be better guarded by
> mem_alloc_profiling_enabled() as the outermost thing.

Oops, missed it. Will fix.

>
> >       }
> >
> >       memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> > @@ -4346,6 +4353,7 @@ void slab_free(struct kmem_cache *s, struct slab =
*slab, void *object,
> >              unsigned long addr)
> >  {
> >       memcg_slab_free_hook(s, slab, &object, 1);
> > +     alloc_tagging_slab_free_hook(s, slab, &object, 1);
>
> Same here, the static key is not even inside of this?

Ack.

>
> >
> >       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> >               do_slab_free(s, slab, object, object, 1, addr);
> > @@ -4356,6 +4364,7 @@ void slab_free_bulk(struct kmem_cache *s, struct =
slab *slab, void *head,
> >                   void *tail, void **p, int cnt, unsigned long addr)
> >  {
> >       memcg_slab_free_hook(s, slab, p, cnt);
> > +     alloc_tagging_slab_free_hook(s, slab, p, cnt);
>
> Ditto.

Ack.

>
> >       /*
> >        * With KASAN enabled slab_free_freelist_hook modifies the freeli=
st
> >        * to remove objects, whose reuse must be delayed.
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
kasan-dev/CAJuCfpGvSfu5dtxFVxmQ4cMfQti2vGVtkNmm2kqQVPfrpFM1tw%40mail.gmail.=
com.
