Return-Path: <kasan-dev+bncBC7OD3FKWUERBCMQZ2XAMGQEC7HXTQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 127C185A967
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 17:55:40 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-60824500fb9sf25314607b3.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 08:55:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708361738; cv=pass;
        d=google.com; s=arc-20160816;
        b=noPM9sUVix1sKuMvICo9lgfd4hBdmSxvKF5mkscB/4FrdwPsl4oI2SGOMeQL0X9YIT
         R2woME08uomtnPCT9uiVmuf/NNBGpKTxf4bEyBKlLNov0DJfZ8e0UDLE4K8adHNOvDCs
         sCc4onxe0Lg5YiyW8ZLk0yC18BV9LPLdSuUH8tx0GQvb5XMEdB6CW9PGB36tC94eDML5
         XJwUxkdeSTG8SNqi/MbUtg4sik8CVZPEN4KzK7G5nmVPnhNNMpdf9BKKZtCPxahFvIIU
         6d5Lz2n6KSmIsE5oxYFeA/5csygWtD5htmhXKfeHfTpbAlphnxLnsIaqekMYr19XLvl/
         yX7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rnAbuemwCwFz5n/l448aHUhzFMepw8Pinx0CGWKCQis=;
        fh=lVlVeEDwlWRMTEr0QAvLAE91tyE3opwD6H+w2X1Q4Vw=;
        b=A4f70LEMUYEZFTjZc1boBPAJV9qb87MSK/OI2Tdjdmm2fPUsBIVH2CVr8oAHxKmUcX
         bVA3khFi136OXeuVFizPmyqbHloeOvSNMBp5Z6HTI4ltzQMR35HWbyFQIxv+TaJIWkdm
         UT9itbS7UmtTcvc+JIjmIk+7Y6EpYplRng3Pa7Zu+wfF9IFN45NrYjFVS4unF1um8AjL
         NUe+lktNQiQiMioeCZx0GA62eDHi8P17luf3u3FtHa8t4L3+KBdQMU1DLDcmi8MbKheJ
         6fyR25DMvIbuQFWx3vSj0KCqTDuZxlqXjJihmtgGDF1BiytAJsgEmKD8QC+JX+CLHDa2
         FwdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="G37RTg8/";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708361738; x=1708966538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rnAbuemwCwFz5n/l448aHUhzFMepw8Pinx0CGWKCQis=;
        b=jd8SN+QwecHmqfKIAEsyXcsqu2CMARYVi9o1Fi0OTx/hKwBYl/s09LukVLxiYop3GP
         s8EYg4CBBOYPZL1TatpmtJ/cBRSHpX2f9PjeVKAU1+6c5kmM2GxoDJPn59mc6csEJTv7
         FajDchlsT63vMewbTuoZiLBuJClE8FWqbiYWQvhrAAvhD9AoOY3vpwQTH4cHbjiXtjoO
         jK7kk2bK0kGlvtNt70EUeXh9aJk8A8YcNzF1KH500d5DFtRTMr5gnT1oz+QOXLLPaZ5r
         179otDs8zbtROd4XWwTxduD5TxtGr/kG/v5hsf0uctG2nX2KRuTUyexHLkv/woh6ZttS
         +8wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708361738; x=1708966538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rnAbuemwCwFz5n/l448aHUhzFMepw8Pinx0CGWKCQis=;
        b=OGD2VKNzGoffvGkU3ZNNXQZ114zDkaEVelds8x+gMhmfxPG3FfKz1a+dIgVRxdvy/+
         OSNzpMPzjPByymzs6XLQIEt084GT+Gk4A61cXuP6YJDFE9OlgFx/TVNPdgx5iBkQlczv
         M7h6VYpwojsAXirjt0bDx9rYM+WlkHpL4T/OFOKjzO8mte8AlJ9uKPfly5mDuYNUmgHy
         ORw9lv/rPkVQZ6ZnVTThBMS7PEdgJAf6ygeFx1E8b5Hp+tA+pOJcBSve3gBs1qqG0VIN
         Ce64CjSBMHXLx9FT3pQPan0z4kIzD8XeOF3wWnUySKll/lzPQE6mpP2+s5rKmOmOeGlB
         InGQ==
X-Forwarded-Encrypted: i=2; AJvYcCUwdppOBaGFKeBmKm/T17RxBbVUrCu8UHrM39d3CDzKJr9YcjMSeQD0Q5LzQXwL6pOJLnSYNHcUDUpScoGDoMHPAWxzd60L9Q==
X-Gm-Message-State: AOJu0Yyo1pAR0u9rjuBTFfL8EWVOvLzoe6HD9SgAepZV9/FopaA78E4Z
	9CCH7LGyg79qs3qEZ7Swy31Vd77+Jy/Pr4SWe2Gq25rrq8wAKUfY
X-Google-Smtp-Source: AGHT+IFKqGHw72VdF2cDpCtjGu5J7SAPsakppNhdxojQ1lxi8ioEo7bf72gfsHbn9tvh6p8HHXZJIw==
X-Received: by 2002:a0d:dfd4:0:b0:608:5917:63c4 with SMTP id i203-20020a0ddfd4000000b00608591763c4mr559785ywe.12.1708361737376;
        Mon, 19 Feb 2024 08:55:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5889:0:b0:42d:e5cb:e3d5 with SMTP id t9-20020ac85889000000b0042de5cbe3d5ls3173197qta.0.-pod-prod-08-us;
 Mon, 19 Feb 2024 08:55:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVPRYE+8IREfoB5/Lec5HBMPbe+k0rmUt8ndQhJ0AjhNkGuqWrvA76uNKVHg+75tIqpAW7A0sI27Fh1P4bauOmSywEk1DVeMKa6w==
X-Received: by 2002:a05:6102:a4f:b0:46e:dc93:10 with SMTP id i15-20020a0561020a4f00b0046edc930010mr9226473vss.23.1708361736259;
        Mon, 19 Feb 2024 08:55:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708361736; cv=none;
        d=google.com; s=arc-20160816;
        b=Tt2iMkxjRjZ70fajPoVOLkJ66v9yPnD92klsFNWK45jW1ESaq4i4Tg/nTf4JHh9zLn
         qXFLuDzHwVGKx+HCflfv61JUZbxJL1My15SpVANNwaUeR3Fm3orOj+NLum3IbSX+PktG
         d2sxfq+VSUyhPZ1j0PfEQ+haXq9hw2fnuH38QBZrM7DtXGkq02UqhMc6bzl1kevVDYSF
         nNk1qAPiY7V2aOq5g4EmX7eMZb0nQXcFR+bqIBsBTQl4ZPZmKI8fO+WtlDi/OkIe2l4R
         L6DxRlswViB55qZ0hLmZys+u/9gtWIhZsddKoOPV/QZYXZmplOtjnWLBmW2lq5aGEH/S
         fEwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MC1JxayV7V5FEwBjiEEHat04AtMi8UdAlknxmmQHPbY=;
        fh=UwNkaOSkok7j2rEdmYKF04lBWfXXsS2mBH4DfGhW4y8=;
        b=stvQLnhlHvexx1nPZOuGKmjqKNhs4pA+eFoReq4glpwqg0Jsr9b3CaJX2HZZc/o4tC
         a0tL/mEnHyaqLi3DSRYkysOxJr+U3uZQt9rCi5ryy32lE0RMVRTvQ5aMAVDn5QEW64zn
         l+qgDrfRi1wKY8nk+vu7mRv3AtxHIJPJGj0C5Xe5AiZCdLGVZjST0ihmynw1AX1968qC
         7/1yjgwfKHO/5oRkAtD5jmbUkjpmYS5oZJUo5KJ2IdH35+GcVLg2Ogq9iKCDA6gxJPod
         3/ARNW+CJEQBnX21iHg0XyfnQypK/MHU81vU7GvnJ0R3wKzAKofU/EUQz+RUkLnWoPqk
         SJ5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="G37RTg8/";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id z20-20020a67ec54000000b0046d3d08309esi476365vso.1.2024.02.19.08.55.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Feb 2024 08:55:36 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-db3a09e96daso3724357276.3
        for <kasan-dev@googlegroups.com>; Mon, 19 Feb 2024 08:55:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVitLC9ShFSU4H7OoCazdhuzjCv7ieJ2HF5+vDoMIX+oVyj6ueZGBYWRMaJ/qhbNiGz3F3A4+PeBLfddAIYYBdOn+O/fu+8Dh5u0g==
X-Received: by 2002:a25:d68b:0:b0:dc6:aed5:718a with SMTP id
 n133-20020a25d68b000000b00dc6aed5718amr10952783ybg.26.1708361735183; Mon, 19
 Feb 2024 08:55:35 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-33-surenb@google.com>
 <f0a56027-472d-44a6-aba5-912bd50ee3ae@suse.cz> <CAJuCfpGUTu7uhcR-23=0d3Wnn8ZbDtNwTaFnukd9qYYVHS9aSA@mail.gmail.com>
 <5bd3761f-217d-45bb-bcd2-797f82c8a44f@suse.cz>
In-Reply-To: <5bd3761f-217d-45bb-bcd2-797f82c8a44f@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Feb 2024 08:55:22 -0800
Message-ID: <CAJuCfpHRqiV2LZEnCB0hwwoexw+8U_XzqH1f+LwLjsQxmXR3Tw@mail.gmail.com>
Subject: Re: [PATCH v3 32/35] codetag: debug: skip objext checking when it's
 for objext itself
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
 header.i=@google.com header.s=20230601 header.b="G37RTg8/";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
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

On Mon, Feb 19, 2024 at 1:17=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/19/24 02:04, Suren Baghdasaryan wrote:
> > On Fri, Feb 16, 2024 at 6:39=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> >> > objext objects are created with __GFP_NO_OBJ_EXT flag and therefore =
have
> >> > no corresponding objext themselves (otherwise we would get an infini=
te
> >> > recursion). When freeing these objects their codetag will be empty a=
nd
> >> > when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled this will lead to f=
alse
> >> > warnings. Introduce CODETAG_EMPTY special codetag value to mark
> >> > allocations which intentionally lack codetag to avoid these warnings=
.
> >> > Set objext codetags to CODETAG_EMPTY before freeing to indicate that
> >> > the codetag is expected to be empty.
> >> >
> >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >> > ---
> >> >  include/linux/alloc_tag.h | 26 ++++++++++++++++++++++++++
> >> >  mm/slab.h                 | 25 +++++++++++++++++++++++++
> >> >  mm/slab_common.c          |  1 +
> >> >  mm/slub.c                 |  8 ++++++++
> >> >  4 files changed, 60 insertions(+)
> >> >
> >> > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> >> > index 0a5973c4ad77..1f3207097b03 100644
> >>
> >> ...
> >>
> >> > index c4bd0d5348cb..cf332a839bf4 100644
> >> > --- a/mm/slab.h
> >> > +++ b/mm/slab.h
> >> > @@ -567,6 +567,31 @@ static inline struct slabobj_ext *slab_obj_exts=
(struct slab *slab)
> >> >  int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> >> >                       gfp_t gfp, bool new_slab);
> >> >
> >> > +
> >> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> >> > +
> >> > +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
> >> > +{
> >> > +     struct slabobj_ext *slab_exts;
> >> > +     struct slab *obj_exts_slab;
> >> > +
> >> > +     obj_exts_slab =3D virt_to_slab(obj_exts);
> >> > +     slab_exts =3D slab_obj_exts(obj_exts_slab);
> >> > +     if (slab_exts) {
> >> > +             unsigned int offs =3D obj_to_index(obj_exts_slab->slab=
_cache,
> >> > +                                              obj_exts_slab, obj_ex=
ts);
> >> > +             /* codetag should be NULL */
> >> > +             WARN_ON(slab_exts[offs].ref.ct);
> >> > +             set_codetag_empty(&slab_exts[offs].ref);
> >> > +     }
> >> > +}
> >> > +
> >> > +#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> >> > +
> >> > +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)=
 {}
> >> > +
> >> > +#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> >> > +
> >>
> >> I assume with alloc_slab_obj_exts() moved to slub.c, mark_objexts_empt=
y()
> >> could move there too.
> >
> > No, I think mark_objexts_empty() belongs here. This patch introduced
> > the function and uses it. Makes sense to me to keep it all together.
>
> Hi,
>
> here I didn't mean moving between patches, but files. alloc_slab_obj_exts=
()
> in slub.c means all callers of mark_objexts_empty() are in slub.c so it
> doesn't need to be in slab.h

Ah, I see. I misunderstood your comment. Yes, after slab/slob cleanup
this makes sense.

>
> Also same thing with mark_failed_objexts_alloc() and
> handle_failed_objexts_alloc() in patch 34/35.

Ack. Thanks!

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHRqiV2LZEnCB0hwwoexw%2B8U_XzqH1f%2BLwLjsQxmXR3Tw%40mail.gm=
ail.com.
