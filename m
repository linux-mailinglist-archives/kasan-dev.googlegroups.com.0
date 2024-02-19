Return-Path: <kasan-dev+bncBC7OD3FKWUERBROSZKXAMGQESIG6QKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B79F8859A4D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 02:05:10 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-42db934c1f8sf43888771cf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Feb 2024 17:05:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708304709; cv=pass;
        d=google.com; s=arc-20160816;
        b=x8idG51aXVnjvczt6mgc4rdZFoVkfi2QpnSui6Diw3c5wu5M/9g7BbxxxHAvkatejj
         tBpsnMjRUuIE3pYDjKyOEQ418oPSHH1sIKv+PIugJNUuoR047x/Jr72X+bq7hUstyVeU
         kK4xdmRWm1GnosBEQPKqfYJdAVbW9ge9IduTkknm8cw4pu7BP35Qn+PfrgiNW9u3j2ED
         lV/CZNo9siUZnvgdn4F3/wgeW0N2NTf+tC8RAONRme/wCBhDT+2os2ZwV4gzyf8vWTgC
         ypHO30NtQF+KguX26lLchSNQnY1E4eMQPmX+31k/npqUmpNan9/IYfRW5zw9XUUh2xtx
         hj4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wjajXtag0TFnk846wTxT1zcVfYQMaQESsAWUEFgrNgE=;
        fh=Zhq/tvEGUlA2p0WbLFxAvs+FhA6JjqFqM/Ad6rkS3GI=;
        b=dzz9Xgej/wpTMeEIyu4gNuhQs+0QJQiJsadNOt7mzbnxy9dQxy5dRxClhXdy6Z07AD
         cAiuNYS0cFi8cv12AFTbuR+Sq3HvTc7XgfEF+er36EXzgv/5KaG0TVZ0JWZ4+CHYq0fb
         z2ljnS6/N/Qz3WAXgOUuSjCVnMWeKlEOrTPQRX1xihK7Wxi/KC9TnzJW/pEQ6HGqo0tV
         cx9IdzsSZjdghFg+eDYy1JpD4ea1lSnnxDxLTOzBT/leHxfGxQgtPKMdhjTS9ataKna7
         qHGP+BsZP/TkMyYYhqZdwErwD9K3CyXaDUXwnOjhqKO6qBbENjW1JX8fgiQukQx9V1Yr
         F4fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XRpxe4nZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708304709; x=1708909509; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wjajXtag0TFnk846wTxT1zcVfYQMaQESsAWUEFgrNgE=;
        b=HqrjGy3G2185MYyh5xgi4RMctv39+VQQ7xsPZnN9knJsMy0jWmnBfjZnLDgdLEOzWb
         brCm6aQGn6SysHb02fbZc7SgovBYQh20LWXSUY78eo/hsay8UwqrbfLMl9Jb3kwdIcD7
         WMySkgfFNaPoPRM545Bd8cW/o/78BoBzkyulYqo91+EeDM17LGVdRowpUsG7NEzW0bgu
         IBZRIRgkT1PoLNJa0Eb6N2hdZJE/QeMYRT16x98hpgz6P//srbdGISApIiFYLvVdCsy0
         WSGAHnwt7rTQdl0Kl/zaEqrF0G6k/HQIKroNx+XdhQn+4F29CD5Ggp7By5M8N0u5f971
         cUJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708304709; x=1708909509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wjajXtag0TFnk846wTxT1zcVfYQMaQESsAWUEFgrNgE=;
        b=jxDi7/GTUmuKhYuTZesa86FNjg+N/qM7/+qUvIHj2ySj2kdGcrmbKRWmegwJG6Ga2s
         TqSFXiNgM5Z++vWyADWw6pKEk4oaXK3Ike0kb4JP4aNQIWWIyAQ9CwBO28LdDSbtsrUE
         ifEbv8f0+eKGzawIItO1lR1HtIJGVRPUWb784TiZD8aoDYB8VBHZzf83bSh+AhISwXht
         694qutbrZTBv3L7oRkYFhdZ/AOS9vuXjmE7BRiux1IZCoLXKfLbtpCcwbs143zmuPAzM
         Z6APNzwtSlGqtVEGI2eLguKP7b02DdS5L1J1d6vW4bPw8uJyXtqSM8B5Zg80SwG0eifd
         geTw==
X-Forwarded-Encrypted: i=2; AJvYcCWyr2H5ctRvwmeJsfqUzXRk+0W7T+4aTSt9ivC6iAT2jo+RgBB/5n1F1OThFPNzhaxVD/O3TtfnLEQqC+UQR/weMJgYjT/kTA==
X-Gm-Message-State: AOJu0Yz8OLbkFHZ32uOA2go5v56S3L2xo0COhsOnunTO+KgxRwvMDubF
	DBg4KNddBPyCnjDfe6NZXO2lOPYisxv1yxy90Z5933s0na1TU7BK
X-Google-Smtp-Source: AGHT+IEpKj+dKINQLeLXcF/nhB9zJY3tSmowdLkU6W8KiKsyzIurMNSelcLoy+TbvWiM7fLSPGqJRg==
X-Received: by 2002:a05:622a:4cc:b0:42c:66c9:ed76 with SMTP id q12-20020a05622a04cc00b0042c66c9ed76mr12765824qtx.59.1708304709336;
        Sun, 18 Feb 2024 17:05:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:193:b0:42d:dd40:847d with SMTP id
 s19-20020a05622a019300b0042ddd40847dls3294372qtw.0.-pod-prod-05-us; Sun, 18
 Feb 2024 17:05:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWzDcLjReiQL9xqE+llI4yv52bRxSaR/MrFzdXYJHmkwYxOJ1M9nlWUQ9V64wLicZyVfHIqqhFBb76zX0ZnJav5pTIrD/zZJkRgkA==
X-Received: by 2002:a05:6102:240b:b0:470:510d:742f with SMTP id j11-20020a056102240b00b00470510d742fmr1963886vsi.35.1708304708461;
        Sun, 18 Feb 2024 17:05:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708304708; cv=none;
        d=google.com; s=arc-20160816;
        b=eVrXjeCvfS+1wRiRCX/86tVI8KQDG8lp2/qKLyaB2ez72Varg0K9zFT2ykAJen4894
         DS/0Gvq8C0i9fAx8DLS21znHf6+jbCQhcJxapycY8+J4BjbBAS4BvQFqlXwsT5QVIikS
         qU5NoALL2e38XafkjDxM3RdPw63PCD+/4Th/M0/Q9u2W1zsj9q/BVK8x4KuCvLcaRjA7
         7/bteUQ3W+zUDRjTytYcHdx0bq8yqVyK8Sxek1sSMfsgIkgIRHtLbpLQJvTx+Q/f+grz
         a9XPdu6kLUC3TzyHkxnkPmOXncoAg6OMjRiAYLgLPvtF0mQRJTjCuUk8K2VYP9piEyDa
         sViw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mIDaOHUmOnFQVc3Wwg+6+LPaeJ2ta81+Eqz5TMzPBys=;
        fh=lziVcT86+68XbviwWcNW7YOX9AiQpeQaJBGqJcRDheA=;
        b=XkJ86/wUIG4RH4t+uQ28i28n42dKjAjb7iIOG1qsMmdaaUdwasMDhf9dzqwCO/Dhwh
         rBhY0wpCgH5NgbUS55/5P0IfZ0D7OF/4C9VhAxTff6WSEnAyZlY5wOavJZqQhjESOTKn
         rFV7e08I+rOKJ08czH+9U96jqw1mO9+FR3u4rbosc0TgU/wvx6wrEfUDIVgsMCIyFqhZ
         WtsWPnDoDKufOuwgfxL6/Df2gc/AHfNDpvXDZspI4+K9STXQ5KpDZtMKKoJ7K3qDB205
         gFM8dC/uT4g2uEF0Z6kqCTSJK1DxUCDJxngwFGpCgyipG0lwSxHevOh61aAeES/a7+bE
         o5Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XRpxe4nZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id z20-20020a67ec54000000b0046d3d08309esi357724vso.1.2024.02.18.17.05.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Feb 2024 17:05:08 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id 3f1490d57ef6-dc238cb1b17so3543795276.0
        for <kasan-dev@googlegroups.com>; Sun, 18 Feb 2024 17:05:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVmHDXOfpQwOudyr/6cMt7xBc335N+Saj+zX+QEsGn4w745TgMWRnJMjvMdsvSpvQgRpx8yEoPqfSllDRPHGiQyFROoGhLweJqwtw==
X-Received: by 2002:a5b:b43:0:b0:dcc:eb38:199c with SMTP id
 b3-20020a5b0b43000000b00dcceb38199cmr10258615ybr.56.1708304707680; Sun, 18
 Feb 2024 17:05:07 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-33-surenb@google.com>
 <f0a56027-472d-44a6-aba5-912bd50ee3ae@suse.cz>
In-Reply-To: <f0a56027-472d-44a6-aba5-912bd50ee3ae@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Feb 2024 01:04:54 +0000
Message-ID: <CAJuCfpGUTu7uhcR-23=0d3Wnn8ZbDtNwTaFnukd9qYYVHS9aSA@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=XRpxe4nZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as
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

On Fri, Feb 16, 2024 at 6:39=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > objext objects are created with __GFP_NO_OBJ_EXT flag and therefore hav=
e
> > no corresponding objext themselves (otherwise we would get an infinite
> > recursion). When freeing these objects their codetag will be empty and
> > when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled this will lead to fals=
e
> > warnings. Introduce CODETAG_EMPTY special codetag value to mark
> > allocations which intentionally lack codetag to avoid these warnings.
> > Set objext codetags to CODETAG_EMPTY before freeing to indicate that
> > the codetag is expected to be empty.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/alloc_tag.h | 26 ++++++++++++++++++++++++++
> >  mm/slab.h                 | 25 +++++++++++++++++++++++++
> >  mm/slab_common.c          |  1 +
> >  mm/slub.c                 |  8 ++++++++
> >  4 files changed, 60 insertions(+)
> >
> > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> > index 0a5973c4ad77..1f3207097b03 100644
>
> ...
>
> > index c4bd0d5348cb..cf332a839bf4 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -567,6 +567,31 @@ static inline struct slabobj_ext *slab_obj_exts(st=
ruct slab *slab)
> >  int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> >                       gfp_t gfp, bool new_slab);
> >
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +
> > +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
> > +{
> > +     struct slabobj_ext *slab_exts;
> > +     struct slab *obj_exts_slab;
> > +
> > +     obj_exts_slab =3D virt_to_slab(obj_exts);
> > +     slab_exts =3D slab_obj_exts(obj_exts_slab);
> > +     if (slab_exts) {
> > +             unsigned int offs =3D obj_to_index(obj_exts_slab->slab_ca=
che,
> > +                                              obj_exts_slab, obj_exts)=
;
> > +             /* codetag should be NULL */
> > +             WARN_ON(slab_exts[offs].ref.ct);
> > +             set_codetag_empty(&slab_exts[offs].ref);
> > +     }
> > +}
> > +
> > +#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> > +
> > +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
> > +
> > +#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> > +
>
> I assume with alloc_slab_obj_exts() moved to slub.c, mark_objexts_empty()
> could move there too.

No, I think mark_objexts_empty() belongs here. This patch introduced
the function and uses it. Makes sense to me to keep it all together.

>
> >  static inline bool need_slab_obj_ext(void)
> >  {
> >  #ifdef CONFIG_MEM_ALLOC_PROFILING
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 21b0b9e9cd9e..d5f75d04ced2 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -242,6 +242,7 @@ int alloc_slab_obj_exts(struct slab *slab, struct k=
mem_cache *s,
> >                * assign slabobj_exts in parallel. In this case the exis=
ting
> >                * objcg vector should be reused.
> >                */
> > +             mark_objexts_empty(vec);
> >               kfree(vec);
> >               return 0;
> >       }
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 4d480784942e..1136ff18b4fe 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -1890,6 +1890,14 @@ static inline void free_slab_obj_exts(struct sla=
b *slab)
> >       if (!obj_exts)
> >               return;
> >
> > +     /*
> > +      * obj_exts was created with __GFP_NO_OBJ_EXT flag, therefore its
> > +      * corresponding extension will be NULL. alloc_tag_sub() will thr=
ow a
> > +      * warning if slab has extensions but the extension of an object =
is
> > +      * NULL, therefore replace NULL with CODETAG_EMPTY to indicate th=
at
> > +      * the extension for obj_exts is expected to be NULL.
> > +      */
> > +     mark_objexts_empty(obj_exts);
> >       kfree(obj_exts);
> >       slab->obj_exts =3D 0;
> >  }
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGUTu7uhcR-23%3D0d3Wnn8ZbDtNwTaFnukd9qYYVHS9aSA%40mail.gmai=
l.com.
