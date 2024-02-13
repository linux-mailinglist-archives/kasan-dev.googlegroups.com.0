Return-Path: <kasan-dev+bncBC7OD3FKWUERBQPGVKXAMGQEHWGUV6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B0B08522E6
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:09:39 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1d932efabe2sf248615ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:09:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707782978; cv=pass;
        d=google.com; s=arc-20160816;
        b=hGokuVZMeZXo/kDxivclq20E8fvvBFX6iuJAZYT+TyIkt81Dqfh0CaqCHCwPAAdhuu
         RFRVceQJ4dNaSsTHkHNKvkDGifRrPwMUtAb0+kzre213qAlbTMtWORecUSh57pFptI8m
         U7I3aOOZmbwT75nxm+fnU0uTSYZJ2OjqqJElR92PoE7LYFp3MWXitPRdvEims6KqXlNZ
         Qmk0g3FOVjlILRDtOxwQk0ZzmNpg/8CPcp9TJSEv6qOurXOJ352HYwijSWdjB1pOQWD4
         afPFRwLle+dnWDrs75m1O7JNycHfZp/Xi3ScT3p95LE1hIQ55vIf85f7Hvo+xDdIOr7S
         1I2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ODPMtcEMXFpqdST+stiPE4oGWFtbQP2LAXLeJxyfwRQ=;
        fh=EkpGrozM9bPVGibCkpRRNoVst5MUgYXK4uOe5JUguog=;
        b=NRpydm/IPMTbNZSYmBZIvipGjyfNsaftxpfgIzCbj3xmFcMjPGT2gUWINeG7e4ZdTW
         h3kgcGP2ved0AIrJ3ydg0mhU2IkmNSX24iwNlTdWik6ebsmn7ibXtzgw+P7McPGzBI7c
         ocDZNx109i4u/rHUamv+JBReytstao0v18c5fOXPNWmDeLx6SnPS8SMU65qFdf7WEinI
         IBsIEfKHiXM3uQAE/yDM4GsemWyIfOwYriJDxs9+R3NiG6z656MH1y99G0d+5ca7wpfq
         IIqzaL58MBE/KicuaItXmKS1ebaGqa+gCfBRsRqPUKizxGWXlOQS9p+VOofr7D5cWQLO
         3bkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ukDHvMoD;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707782978; x=1708387778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ODPMtcEMXFpqdST+stiPE4oGWFtbQP2LAXLeJxyfwRQ=;
        b=bXG1Q6FBrOP21ONCRIpVkJCDeOhlXTiphYjs4k///+smVo9mHxngeTBLIgaUu5so1I
         eL1HI2T9nSbazz+Zw4l5pXX5kU/adpCTQDGPONqILgbKa3c31kiOHoE08SqWfI/CiTIH
         VgzDxxrIXkjDxcn0FtC5NzcmsQp9EMGKNeXPVvh/iSac/BMhRiM4ZiK9SfdtaURhzFKP
         OJByuLwmKnQRJOCn1gPXobAPl6qxK9MMj2vS5vlqS73XsZXrjm5r+fQxZ3qAZhLZO0LM
         EbLUoYeOaFbB8Vg1Spxio9xpjWAPD9rCxC+Ug4WzsfrotMVVGHGdr7d3MZMywJz8FyTR
         pGuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707782978; x=1708387778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ODPMtcEMXFpqdST+stiPE4oGWFtbQP2LAXLeJxyfwRQ=;
        b=O/VTtLWDb0aRmtF4Doc+rX8UAhnTiMaPLFoixguvk5S4CpObMLVTN1WLEncR/N9GyU
         3gWrNJxstwnvurNMEJUH+DAOc9PQUrql8JulrwNV7iS2xtGqGob2DH70h6qZUX7l5SoJ
         GW0DZr2QdRaVoW1g/rRzZOvf6AAFx4juHRxAavUtB+YyO/sXAuWixD2aSwb3mtu+pRmQ
         +09t4jLUXXoHSytGvrkL+qu2Oyp1xobBy6AffMe8MM08p9T/Elt03ei2uMgsTgHEnfbW
         BsUtJbP5cYrEN+FRquBrDviOSKpM3MoTqxwn1vylgzL0zeSvBn24zuEy55WW/jiUoVvX
         3wLA==
X-Forwarded-Encrypted: i=2; AJvYcCXmPEtpYjzEDWTYzJoetSRQIOgIbjqUSsdQuDm1Ayud0s7trngegFu4aJZQxF0xgmwZ1slIAQE88OgHCb7yp7lM+CyhhPbMhg==
X-Gm-Message-State: AOJu0Yy55lkTGW+2UhyGLxBYB4HJtXc9XYj3p/saArrD0uw40hZQCGUF
	zsDG9/w8SX8tNq3RJjjocjGBg7+YskbxcEXCQSBaD55gNN6EliIi
X-Google-Smtp-Source: AGHT+IFaPwDoSmg8dIkAz7r/IyyQKVNSUmDTEoSf13Kw6bJER5Upm64wYt8loUZvFuB/Kdu7tW9J+A==
X-Received: by 2002:a17:902:eb86:b0:1d9:ce46:6eaa with SMTP id q6-20020a170902eb8600b001d9ce466eaamr10610plg.27.1707782978187;
        Mon, 12 Feb 2024 16:09:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c10e:b0:297:312c:7477 with SMTP id
 q14-20020a17090ac10e00b00297312c7477ls745315pjt.0.-pod-prod-01-us; Mon, 12
 Feb 2024 16:09:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW0ppHERJiMkgsvbauLjqMcRgDuIM9WKpUt+cFQoyFJvXs5Rp0VCZe1E4Lr3AJCMSWAFwl24wQah7d+37aXM1iEiSD06cypj+7Mxw==
X-Received: by 2002:a17:903:41c3:b0:1db:306c:5ab8 with SMTP id u3-20020a17090341c300b001db306c5ab8mr619675ple.2.1707782977126;
        Mon, 12 Feb 2024 16:09:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707782977; cv=none;
        d=google.com; s=arc-20160816;
        b=nYP/R9fHaXCZsw2lz7suPHOw0YX9boSmd+ZSUKPWthSeCZkQsHaXBbzGxixk6aBNjZ
         9q+fl1oCQunpuOfwqT4jX4puaLRH0VoT6TrIkipMBLdfhNwmR0oCK7IS2MxPlT6oK+bx
         +Af9lrgMfDllyy/ficX8kyptblJp6lYAsL7Uizs4+ICKPggKKjG0o/qr+4h5p9zdtlkX
         qGXdKXOVqgBoukyt0YzA3AWHN02fy/S/mhCnJS6fUMDYpOHxGhr82aO/buAWC44eA4Jb
         Z3vJoRv90h4+6BZCu7v1Se11w1Ce8UkFuumytp/IAGMr+Js4B6pwun2MrEGbI1mLA+i5
         GuGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gLK7xEb3jxgpuysPUzwq60xsYYfX0bEwBasjsp6nC7A=;
        fh=8IjZsbnlu867+bWfcEEz/CtztwP0q6Nphxhpd+x8bjw=;
        b=zIG6g045pwuFPdNbp3YJW/gsd4Lh5fENg0t66gRRdrp4a4knctOEX0Xum6Y9e+wuV9
         8822lzXus+hEzAuDG9mDWpFeHFj34nHCNyTNAFIqfA6ea/T8gpUZOgmrVLumd0V6BtG/
         +vxp32B0rw1YcpNRSMBnjCrL1SRtvtbZTLKfgUifs8JD6iFxWM8ki1gCQWRMLskaVtbD
         uBHu2rU8dDkAMIcBGjCZR+IjQEBbzlr7CJ5SKAsMUbRElpRVSSOMK3F47bhpNIEYEndG
         TB3NmyBqcI5JPebh2779/khSEzmmK/Gex1qdKgx4HGHWWcDokWkPW5KaoYWy8gvm6r37
         SsNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ukDHvMoD;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUGiM1DC6x0eeo99nzt/ivgpS7cFABovODducGQw3x5YG6JwKDdnGl4X6aMm5IOt7AV1BInlwUKta6zVb0XGiQ4qSgjLXaTBVjH9A==
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id o23-20020a170902779700b001d4b701bb69si93988pll.1.2024.02.12.16.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:09:37 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-dcc84ae94c1so93825276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:09:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV9cV6untsq1bcuuNNo5wIsLneXFYUoNbTmuFtjcmwcybLml95J2nTWjVwE3r2JXTdlt2jDLhGELZA6BmtIID6rywHRQcnaWoMKtg==
X-Received: by 2002:a25:8241:0:b0:dcc:623d:e475 with SMTP id
 d1-20020a258241000000b00dcc623de475mr508725ybn.30.1707782975978; Mon, 12 Feb
 2024 16:09:35 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-35-surenb@google.com>
 <202402121448.AF0AA8E@keescook>
In-Reply-To: <202402121448.AF0AA8E@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 16:09:21 -0800
Message-ID: <CAJuCfpEUQ+KctApss1upC4pWLvnU2bWVopbL5EsBzhsF0JzrPA@mail.gmail.com>
Subject: Re: [PATCH v3 34/35] codetag: debug: introduce OBJEXTS_ALLOC_FAIL to
 mark failed slab_ext allocations
To: Kees Cook <keescook@chromium.org>
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
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
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
 header.i=@google.com header.s=20230601 header.b=ukDHvMoD;       spf=pass
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

On Mon, Feb 12, 2024 at 2:49=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:39:20PM -0800, Suren Baghdasaryan wrote:
> > If slabobj_ext vector allocation for a slab object fails and later on i=
t
> > succeeds for another object in the same slab, the slabobj_ext for the
> > original object will be NULL and will be flagged in case when
> > CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled.
> > Mark failed slabobj_ext vector allocations using a new objext_flags fla=
g
> > stored in the lower bits of slab->obj_exts. When new allocation succeed=
s
> > it marks all tag references in the same slabobj_ext vector as empty to
> > avoid warnings implemented by CONFIG_MEM_ALLOC_PROFILING_DEBUG checks.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/memcontrol.h |  4 +++-
> >  mm/slab.h                  | 25 +++++++++++++++++++++++++
> >  mm/slab_common.c           | 22 +++++++++++++++-------
> >  3 files changed, 43 insertions(+), 8 deletions(-)
> >
> > diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
> > index 2b010316016c..f95241ca9052 100644
> > --- a/include/linux/memcontrol.h
> > +++ b/include/linux/memcontrol.h
> > @@ -365,8 +365,10 @@ enum page_memcg_data_flags {
> >  #endif /* CONFIG_MEMCG */
> >
> >  enum objext_flags {
> > +     /* slabobj_ext vector failed to allocate */
> > +     OBJEXTS_ALLOC_FAIL =3D __FIRST_OBJEXT_FLAG,
> >       /* the next bit after the last actual flag */
> > -     __NR_OBJEXTS_FLAGS  =3D __FIRST_OBJEXT_FLAG,
> > +     __NR_OBJEXTS_FLAGS  =3D (__FIRST_OBJEXT_FLAG << 1),
> >  };
> >
> >  #define OBJEXTS_FLAGS_MASK (__NR_OBJEXTS_FLAGS - 1)
> > diff --git a/mm/slab.h b/mm/slab.h
> > index cf332a839bf4..7bb3900f83ef 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -586,9 +586,34 @@ static inline void mark_objexts_empty(struct slabo=
bj_ext *obj_exts)
> >       }
> >  }
> >
> > +static inline void mark_failed_objexts_alloc(struct slab *slab)
> > +{
> > +     slab->obj_exts =3D OBJEXTS_ALLOC_FAIL;
>
> Uh, does this mean slab->obj_exts is suddenly non-NULL? Is everything
> that accesses obj_exts expecting this?

Hi Kees,
Thank you for the reviews!
Yes, I believe everything that accesses slab->obj_exts directly
(currently alloc_slab_obj_exts() and free_slab_obj_exts()) handle this
special non-NULL case. kfence_init_pool() initialized slab->obj_exts
directly, but since it's setting it and not accessing it, it does not
need to handle OBJEXTS_ALLOC_FAIL. All other slab->obj_exts users use
slab_obj_exts() which applies OBJEXTS_FLAGS_MASK and masks out any
special bits.
Thanks,
Suren.

>
> -Kees
>
> > +}
> > +
> > +static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
> > +                     struct slabobj_ext *vec, unsigned int objects)
> > +{
> > +     /*
> > +      * If vector previously failed to allocate then we have live
> > +      * objects with no tag reference. Mark all references in this
> > +      * vector as empty to avoid warnings later on.
> > +      */
> > +     if (obj_exts & OBJEXTS_ALLOC_FAIL) {
> > +             unsigned int i;
> > +
> > +             for (i =3D 0; i < objects; i++)
> > +                     set_codetag_empty(&vec[i].ref);
> > +     }
> > +}
> > +
> > +
> >  #else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> >
> >  static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
> > +static inline void mark_failed_objexts_alloc(struct slab *slab) {}
> > +static inline void handle_failed_objexts_alloc(unsigned long obj_exts,
> > +                     struct slabobj_ext *vec, unsigned int objects) {}
> >
> >  #endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> >
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index d5f75d04ced2..489c7a8ba8f1 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -214,29 +214,37 @@ int alloc_slab_obj_exts(struct slab *slab, struct=
 kmem_cache *s,
> >                       gfp_t gfp, bool new_slab)
> >  {
> >       unsigned int objects =3D objs_per_slab(s, slab);
> > -     unsigned long obj_exts;
> > -     void *vec;
> > +     unsigned long new_exts;
> > +     unsigned long old_exts;
> > +     struct slabobj_ext *vec;
> >
> >       gfp &=3D ~OBJCGS_CLEAR_MASK;
> >       /* Prevent recursive extension vector allocation */
> >       gfp |=3D __GFP_NO_OBJ_EXT;
> >       vec =3D kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
> >                          slab_nid(slab));
> > -     if (!vec)
> > +     if (!vec) {
> > +             /* Mark vectors which failed to allocate */
> > +             if (new_slab)
> > +                     mark_failed_objexts_alloc(slab);
> > +
> >               return -ENOMEM;
> > +     }
> >
> > -     obj_exts =3D (unsigned long)vec;
> > +     new_exts =3D (unsigned long)vec;
> >  #ifdef CONFIG_MEMCG
> > -     obj_exts |=3D MEMCG_DATA_OBJEXTS;
> > +     new_exts |=3D MEMCG_DATA_OBJEXTS;
> >  #endif
> > +     old_exts =3D slab->obj_exts;
> > +     handle_failed_objexts_alloc(old_exts, vec, objects);
> >       if (new_slab) {
> >               /*
> >                * If the slab is brand new and nobody can yet access its
> >                * obj_exts, no synchronization is required and obj_exts =
can
> >                * be simply assigned.
> >                */
> > -             slab->obj_exts =3D obj_exts;
> > -     } else if (cmpxchg(&slab->obj_exts, 0, obj_exts)) {
> > +             slab->obj_exts =3D new_exts;
> > +     } else if (cmpxchg(&slab->obj_exts, old_exts, new_exts) !=3D old_=
exts) {
> >               /*
> >                * If the slab is already in use, somebody can allocate a=
nd
> >                * assign slabobj_exts in parallel. In this case the exis=
ting
> > --
> > 2.43.0.687.g38aa6559b0-goog
> >
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEUQ%2BKctApss1upC4pWLvnU2bWVopbL5EsBzhsF0JzrPA%40mail.gmai=
l.com.
