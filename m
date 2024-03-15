Return-Path: <kasan-dev+bncBC7OD3FKWUERBS6Z2GXQMGQECTSFXBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B15987D084
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 16:44:13 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1ddb7335c40sf2188355ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 08:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710517452; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eb1T2xErAPiGMpEJ6L0zCGLVSg0hiJtxDs3viBa/dDX/NzCttozVjJhtolHkE2GK2q
         7CsWXH8ViTpM1KvU04ADlsRCk2oDjuChxaf8DQOfndTCkFPWhK79ThCw10e39YifmuUa
         Ka/xv7p/sThigOq9cRLkKMLE3/oVh8jnRq05qrr/m0IdWEfKZcvbdzNf2brKShThje+w
         +3quotmsjLHRvpzXsAreWnFkTZLO1pUh/exJKWw5+PEZfplsKQi2HQ4rM/GANqadbBK/
         uD3sNvpVhGWnorLoqgr6BJBs+n8O1L8PXeBUCD6lsCb8EzmP9UY2pMk8ifeqmkdc57Sc
         uV4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YU8hmKsDMxTRmXciXCRY2vommklBizXg2QI84KWEfis=;
        fh=9iKDpIkVUDiaymAoTwM/3rN4XlQB1WSL6fxEdtudxkQ=;
        b=rdLZZ8Z+R0Jt7wSrk4AaI7/XFkpHnWYWov6IR2ZEBbyZ6pqIYVjXlj3NMmS/T21NUt
         RPVtlRNKyFuxvKbo4KCSdgV8brujupCy11iK7IQcElVbV4hu3wTcoI6TbA87iVwAYmaR
         s/v6aufCGNSVe6UhP0llXilZ4JJsBBHzPTov2mnZ6amK6eRNxltZUylHYo5LB/7fMSja
         UlYy7pM5/FTOJaVHAQE+uReZbdDpi6wQYs14E0RVTyacpbqGOY7260hR/qgmKgJZuSCg
         0xXd4z7fQ7eLdhnEMuU3P2Xg0u+WLSv2sP4PEqhoKfHEDBeJFySA4a+2Qtf1vbEQuSfp
         LneA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="H/d0ZI2J";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710517451; x=1711122251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YU8hmKsDMxTRmXciXCRY2vommklBizXg2QI84KWEfis=;
        b=xPVMKyPUXrOovP8ivutNtGp4EhC9Y5EyMmpU3F2cjOb2s8GqMP2OpzqU8h0UdqCOCx
         1V5F6OL/gU5Cd5SHIPoDdtzgH0stfpOf8sWWLEMGohiw5B3Uyn9gGJMcmkd94A5+2tCX
         FoOwuCYlezWJLFjdC5tU8p8YsnbAGxqctH8mk5RNxWAGJYa/yQZr5HmEFi65efxvQ9mI
         S+VmjMK2Y9JI8dlmvtwXVluQwgPLPWWQ6C8X79gVs+8QKqcZMD4wc+JiPFfSTxjxkKFR
         B1tq5EW3tP1SBTMAhES1abndQm+tDt4pSmpBixIH3wRYwrHeEryUzSY5l2523miXE/hV
         WFzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710517451; x=1711122251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YU8hmKsDMxTRmXciXCRY2vommklBizXg2QI84KWEfis=;
        b=P5moKuomIY65hjXcLsyyzeMXEDIujnpAum4N71ortIhoYHaOtnJlJxoXd8yA1wNXDp
         2cmt6zATQy6qx2jVGaAYOlhM8cOEzyGeDxa/40tibj8LyqEtiW0bu8IrG+XN0ngR/Zn+
         mLok9sHYlbwpLRN7klsctMUCzr648sH1HPfHnIQ67L5qnnfMnAvIcDvcUKWXTKh7hPUq
         4CABOFPk7dLEJfgEIluevfNMgTST3oA6XEaFX4p7a26VleUNjvHnudtQ27gnty00jw8P
         Q1/sBiii9cZPqj3tHaTWN0/JiTFaBYMt4BWXdtTaLr+ibsbnHRkepPuDEvIM8uwquZb4
         wi7g==
X-Forwarded-Encrypted: i=2; AJvYcCWF4bc1Gpf0jEWIFSLIBkvvWZF2qV4gCdqM3lwnDt7Hx7MevlFcq740+9y7TIvsn/8wnranTt1I5md16CE2EQIdu6MyclXdSw==
X-Gm-Message-State: AOJu0YwlQpqhkdYMH3t5OCR7kCb7vHODF28CGK6LsK+9vO0/1E6A2KgC
	2shpPn+ZhLFqaljFQGh3/xfo3C95sxdLjPHiu+7FhgWulpYFraA5
X-Google-Smtp-Source: AGHT+IHX12VijQwJMswUgdNkc1y9+HedxdfiaqkAh1Jcmh7kiLO755odWs63J0biTXcHPxomybDyyQ==
X-Received: by 2002:a17:902:dacf:b0:1dd:b315:905e with SMTP id q15-20020a170902dacf00b001ddb315905emr508388plx.5.1710517451255;
        Fri, 15 Mar 2024 08:44:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4d0:b0:1dd:b739:82e9 with SMTP id
 o16-20020a170902d4d000b001ddb73982e9ls197232plg.0.-pod-prod-01-us; Fri, 15
 Mar 2024 08:44:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9pVRbSCbtHj7gjYGcBJSPcDB6zqZxGklYn0R7vZCQKc71RDl3bapXARXDVJNbRjsv7ORLr9i+xwF0Hznll36LcIx2Jmm/o0GG0Q==
X-Received: by 2002:a17:903:41d0:b0:1d8:f129:a0bc with SMTP id u16-20020a17090341d000b001d8f129a0bcmr6545577ple.13.1710517448871;
        Fri, 15 Mar 2024 08:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710517448; cv=none;
        d=google.com; s=arc-20160816;
        b=T3G9Sy+h6OcPWtEQxd0j8RtDyg8e0DPwqgMV7ALUX/WEgfIOrtj2rsfiW+0m1OWDeI
         DF66yzWlTY16jiHHalKF7mYZ2bNKq3sdc5yoemtQ8/85hPPaK6e3VLUtzrbpaV6ZkPdg
         J1JzlkLR7mlWW+KKyNaWlS0Sx7gRFvgm8xKXPKa/lfogjvwGi4DtxMHrbnmIrrslYru0
         UJ9bpRlEFELM2LhMJYYz1DhXvhcgJUcRRYNV18KNqSna3Zg4YcXmvwDPrJqi/YDrel0D
         0nUWJV0Z/sARZ1ZP3t3q9Kz/K0ilQN6ap+tnSAKvenPir0hI7iu603l1QKfd6hqModIO
         ZbMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=clGRLHEdZJU1hIbUHWzW6z0FfJkCL+OJ6aU0ekE5bnA=;
        fh=q7OS7Gg96Qx4BB2+N6Y3J9QDU8UojfgP9jsy8Z2SeK4=;
        b=tNvh7lapfbg0qIk5Lvo6Z3flbol4oJXxP873c0zFXfe+Pl/NACUqUjrl3SysXeWM3v
         oYvjhkdj0S4N78X4JegmxnI/HBIhr5wy6L68JYMgqEvNygz1zzsK0mIiFTy4Y01Aa97i
         EEyADZqZHVLgga6wCubJrx9sTH223wn7MluBtlOvXgJs4MgRI6Dk6tI0BLdT9BRHZ3Ar
         vtkyYpbGPqZ9FRA/QJnXWymuefUKGAl/EAtQuTkcs8yWfK5xaXB9Xd0BlDCFfckIZaQV
         /4fxFLa9lKDaPaIjUVF2REPvqeJQin6bn3er6Zyv/hQIWTb7wxSCas275U/q1Y/R8Y2n
         ycsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="H/d0ZI2J";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id b5-20020a170902d40500b001ddddaf7343si312977ple.6.2024.03.15.08.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Mar 2024 08:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-60cc4124a39so22747397b3.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Mar 2024 08:44:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVC7FqF+Yq5F4WnD3riNlEqm40LBwqMqVlG6jEmSkKieC2ReGmhuBupFbq0xMpfJZz4xH4kHBDtVl9I4Nx7vi7NBloHYLTnU3MscA==
X-Received: by 2002:a25:2fc2:0:b0:dd0:e439:cec6 with SMTP id
 v185-20020a252fc2000000b00dd0e439cec6mr4700323ybv.18.1710517447501; Fri, 15
 Mar 2024 08:44:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-24-surenb@google.com>
 <1f51ffe8-e5b9-460f-815e-50e3a81c57bf@suse.cz>
In-Reply-To: <1f51ffe8-e5b9-460f-815e-50e3a81c57bf@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Mar 2024 08:43:53 -0700
Message-ID: <CAJuCfpE5mCXiGLHTm1a8PwLXrokexx9=QrrRF4fWVosTh5Q7BA@mail.gmail.com>
Subject: Re: [PATCH v5 23/37] mm/slab: add allocation accounting into slab
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
 header.i=@google.com header.s=20230601 header.b="H/d0ZI2J";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1133
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

On Fri, Mar 15, 2024 at 3:58=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 3/6/24 19:24, Suren Baghdasaryan wrote:
> > Account slab allocations using codetag reference embedded into slabobj_=
ext.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Reviewed-by: Kees Cook <keescook@chromium.org>
>
> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>
> Nit below:
>
> > @@ -3833,6 +3913,7 @@ void slab_post_alloc_hook(struct kmem_cache *s, s=
truct obj_cgroup *objcg,
> >                         unsigned int orig_size)
> >  {
> >       unsigned int zero_size =3D s->object_size;
> > +     struct slabobj_ext *obj_exts;
> >       bool kasan_init =3D init;
> >       size_t i;
> >       gfp_t init_flags =3D flags & gfp_allowed_mask;
> > @@ -3875,6 +3956,12 @@ void slab_post_alloc_hook(struct kmem_cache *s, =
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
> I think you could still do this a bit better:
>
> Check mem_alloc_profiling_enabled() once before the whole block calling
> prepare_slab_obj_exts_hook() and alloc_tag_add()
> Remove need_slab_obj_ext() check from prepare_slab_obj_exts_hook()

Agree about checking mem_alloc_profiling_enabled() early and one time,
except I would like to use need_slab_obj_ext() instead of
mem_alloc_profiling_enabled() for that check. Currently they are
equivalent but if there are more slab_obj_ext users in the future then
there will be cases when we need to prepare_slab_obj_exts_hook() even
when mem_alloc_profiling_enabled()=3D=3Dfalse. need_slab_obj_ext() will be
easy to extend for such cases.
Thanks,
Suren.

>
> >       }
> >
> >       memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> > @@ -4353,6 +4440,7 @@ void slab_free(struct kmem_cache *s, struct slab =
*slab, void *object,
> >              unsigned long addr)
> >  {
> >       memcg_slab_free_hook(s, slab, &object, 1);
> > +     alloc_tagging_slab_free_hook(s, slab, &object, 1);
> >
> >       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> >               do_slab_free(s, slab, object, object, 1, addr);
> > @@ -4363,6 +4451,7 @@ void slab_free_bulk(struct kmem_cache *s, struct =
slab *slab, void *head,
> >                   void *tail, void **p, int cnt, unsigned long addr)
> >  {
> >       memcg_slab_free_hook(s, slab, p, cnt);
> > +     alloc_tagging_slab_free_hook(s, slab, p, cnt);
> >       /*
> >        * With KASAN enabled slab_free_freelist_hook modifies the freeli=
st
> >        * to remove objects, whose reuse must be delayed.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE5mCXiGLHTm1a8PwLXrokexx9%3DQrrRF4fWVosTh5Q7BA%40mail.gmai=
l.com.
