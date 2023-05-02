Return-Path: <kasan-dev+bncBC7OD3FKWUERBRNRYWRAMGQEF4PZY2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C71F06F49CA
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 20:39:02 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-b9a25f6aa0esf7720475276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 11:39:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683052741; cv=pass;
        d=google.com; s=arc-20160816;
        b=WYYmarKHnMwdwdYeCqEYflfDTQwtMAinaBdUDdQml9NnBDI1/YJkgSegxwc0ZGSW3v
         wIlldBB8B0++Zwmt4e2aSeUDicGlv3FQ/I+ITk8pZcDVKLrNDzcAXVXmoFYpVEl2FUAd
         ufZ35tC/99cNc4G2VctbJZD3dbcH1NRKW3E8fykWXhU4l4dgVaV+3EY7PBZu4HfgzWcx
         rnTg1zetZEQXbUbR7LmXYzuZS5LXhG16+Vi05YINQ9vtLwHR9tteqKZ5VUss4z15SH65
         Mei2GSOwqDRb0sLAx711JMvag2WfKi2u2MlHhzTyS9//zUk+rm/CiKtwnXtsfYJa9knP
         kr1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kTaW91dXLZA1dXbyqSSYqnrAaUoVMc01YDd8AGfXUM4=;
        b=hqqlwKaHZ/8OCVeGsMU3RJzoKKHylFEc9XLq7Gt8/iW1rFVt3pwvSnNb+zCJMAEZrn
         Lv2w5/i0hKoGiU/GDoSUyEwvSynobUt0331dyMV8JbgLrVFnc5GsRhhPOxiLhqRlAuMt
         NStSQCbRINyxdocnE3u0JwRwI74Iy8d5IUA9TNJj2WxXs+notp7Zd7yfcpjZ7RH/rnEk
         gBEVPOE5QamdnPxS7YvFgfs7NZOBS0f7Fn5eATZIy40QHT0XUoGXhxzXtASKvLntlQiD
         2N2PmrGPxdkti7VHJRhHavuNElnnOk6n4Gfil5seHmmQn1XdR5Q3nFS9XpGd7zBizvCZ
         AZBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3ehzpeir;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683052741; x=1685644741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kTaW91dXLZA1dXbyqSSYqnrAaUoVMc01YDd8AGfXUM4=;
        b=sZfVMW5kEwJ2VJ6RU2uGdYLBNMhWhhAgPhUd0la+P4yzeljS/h45+k8dnza7Dk4ZBV
         tW9iMjp8g9N4qp2uVNd9TosCa6w2MRP3W6utZofXsxznJi3hloyKXCN54JB8wVjZbsUk
         c3VUdmAJPKrPEHiACJQ/BILJmleAda7X4glAI7qlgKcHynKP7W3SDLh1bjp8yAhfwvht
         Ov5flzEoRCv5Eq04m/94qkZlEMRB7tA8Y5MbZxlyvyCAVr2PHlmfCxPfOXIwSH1FpwuN
         M9ASFmlkeSUPpY7Bm+GYtEBYUCqJeuSFhwJZtsUOl8ULpVDcTjhTrVuyb3N0itnsTuPe
         pTQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683052741; x=1685644741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kTaW91dXLZA1dXbyqSSYqnrAaUoVMc01YDd8AGfXUM4=;
        b=gH91c4lQIVbW6IA2sRbo9lYD4fWt2Ev1RmRvgkc9Z9Y2RghvE34GummNF7DIEKVyCC
         YpqQUpB33EbxceBEAIcbqQHgXzg+wIFFXGgRlvky2+qnSSnswXRTAidOQU7WafqGou+2
         hTWdRHzSfdGyiYfR85H1M92vMBsmrqJIPAow8Ef4vNya/ouUvMKQpGPUUr19vC0uRA0V
         hRUXeRiUsw87CysIiCkvcSJHMFzvw7q4tbj+SWsbeLD9v95UamkquWB0tGxOIO74XIdO
         SnS5BybSykNtzGja8xkTn9T27ByPZeSfQAnLo5uvT3+ZaWem8mcWi3MxgKCTYcxWOT4m
         0BvQ==
X-Gm-Message-State: AC+VfDyzz4rXpieA1HuSe7j/g7ioNqG2Ldj1Fb203vEXs1j5/eHj4wRO
	zMcBN8QTL/XawnYs1+vZMEw=
X-Google-Smtp-Source: ACHHUZ587rFCE4is7msgtZOjZ88t2K9q9xcp4Pf1qIV6He+UK8vqoTljK2DHSRIwQGGITSmqRqwNAA==
X-Received: by 2002:a25:d345:0:b0:b9d:c27c:3442 with SMTP id e66-20020a25d345000000b00b9dc27c3442mr4051526ybf.9.1683052741368;
        Tue, 02 May 2023 11:39:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:ac43:0:b0:55a:a1b8:6532 with SMTP id z3-20020a81ac43000000b0055aa1b86532ls1462874ywj.8.-pod-prod-gmail;
 Tue, 02 May 2023 11:39:00 -0700 (PDT)
X-Received: by 2002:a0d:f207:0:b0:544:9180:3104 with SMTP id b7-20020a0df207000000b0054491803104mr14877155ywf.34.1683052740598;
        Tue, 02 May 2023 11:39:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683052740; cv=none;
        d=google.com; s=arc-20160816;
        b=RUwm/aKuVaDm2dBpDuL9Gs+Ok8QOhWP8q4P2jzN456pXbdDXQgDAAlIqlJ3kiZxE2n
         8g0Acs/bgqzF+jlGmFLFjAFMEyhtWFGJLEWzNJhr9KJWZgu/XygSFNC4CeKgm24WBIlG
         hn6y8ysiIMTLeu0ibRukD20ixD9yz0fYl1h5MU2aMVEqgj5MjJgBpmFXlZPjL3AnkrwD
         OnpMLQUHVvoNeCX9FUMiLLAvPEeQfbHAr+KUjMYtDH0RcGXgSR9+oE+P/VvhsE9DBH4L
         b+nAjMkBRoQKV1YrrfaQ645GK6lKMIMw5zMVO6AADCR4Vier1Hhwg/pmn+e95nvi6HQb
         t9sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7OMnp8U2QsJWbp6tha1jAHM6ardwied5yoCJwV56xmU=;
        b=Djl9qp1MLG3Sc6BG4Brt9YxrMy54+iN4F5xKGV92Cv2NmGsJTvBRD03v2wM4SEgW1r
         xWx8I5T2HI7ZiEuJc/he3KwlB+A62z18AsrYczTbcFmkHjOewvSyjzbycXWncX5EY7j8
         BPyR+53mHNfmtCqOauU1Yll1E7mNOmPP8ZynpYTn6w3XJhDWz7O6wqeQOUje056IyDwZ
         jVXNI/MnGXY0ZHp6z/H7Qr5zYqvpQqsV6PXm+Wv5dsE0Tg1rXVvSS4pnQUglcoA0DuLG
         I2x0iq2qrtK4kEDMIwRTjoLVdA7CPaKO09I0DwnSU1E0bRWBE9MiNXXa86mzKGh5pZiV
         qdWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=3ehzpeir;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id bg12-20020a05690c030c00b0055a905c06bbsi161695ywb.2.2023.05.02.11.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 11:39:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-559eae63801so53019097b3.2
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 11:39:00 -0700 (PDT)
X-Received: by 2002:a25:420f:0:b0:b9e:4fbc:8a7f with SMTP id
 p15-20020a25420f000000b00b9e4fbc8a7fmr5707930yba.1.1683052740029; Tue, 02 May
 2023 11:39:00 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-20-surenb@google.com>
 <20230502175052.43814202@meshulam.tesarici.cz>
In-Reply-To: <20230502175052.43814202@meshulam.tesarici.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 May 2023 11:38:49 -0700
Message-ID: <CAJuCfpGSLK50eKQ2-CE41qz1oDPM6kC8RmqF=usZKwFXgTBe8g@mail.gmail.com>
Subject: Re: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid
 name conflicts
To: =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
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
 header.i=@google.com header.s=20221208 header.b=3ehzpeir;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b
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

On Tue, May 2, 2023 at 8:50=E2=80=AFAM Petr Tesa=C5=99=C3=ADk <petr@tesaric=
i.cz> wrote:
>
> On Mon,  1 May 2023 09:54:29 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > After redefining alloc_pages, all uses of that name are being replaced.
> > Change the conflicting names to prevent preprocessor from replacing the=
m
> > when it's not intended.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  arch/x86/kernel/amd_gart_64.c | 2 +-
> >  drivers/iommu/dma-iommu.c     | 2 +-
> >  drivers/xen/grant-dma-ops.c   | 2 +-
> >  drivers/xen/swiotlb-xen.c     | 2 +-
> >  include/linux/dma-map-ops.h   | 2 +-
> >  kernel/dma/mapping.c          | 4 ++--
> >  6 files changed, 7 insertions(+), 7 deletions(-)
> >
> > diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/amd_gart_6=
4.c
> > index 56a917df410d..842a0ec5eaa9 100644
> > --- a/arch/x86/kernel/amd_gart_64.c
> > +++ b/arch/x86/kernel/amd_gart_64.c
> > @@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_ops =3D {
> >       .get_sgtable                    =3D dma_common_get_sgtable,
> >       .dma_supported                  =3D dma_direct_supported,
> >       .get_required_mask              =3D dma_direct_get_required_mask,
> > -     .alloc_pages                    =3D dma_direct_alloc_pages,
> > +     .alloc_pages_op                 =3D dma_direct_alloc_pages,
> >       .free_pages                     =3D dma_direct_free_pages,
> >  };
> >
> > diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
> > index 7a9f0b0bddbd..76a9d5ca4eee 100644
> > --- a/drivers/iommu/dma-iommu.c
> > +++ b/drivers/iommu/dma-iommu.c
> > @@ -1556,7 +1556,7 @@ static const struct dma_map_ops iommu_dma_ops =3D=
 {
> >       .flags                  =3D DMA_F_PCI_P2PDMA_SUPPORTED,
> >       .alloc                  =3D iommu_dma_alloc,
> >       .free                   =3D iommu_dma_free,
> > -     .alloc_pages            =3D dma_common_alloc_pages,
> > +     .alloc_pages_op         =3D dma_common_alloc_pages,
> >       .free_pages             =3D dma_common_free_pages,
> >       .alloc_noncontiguous    =3D iommu_dma_alloc_noncontiguous,
> >       .free_noncontiguous     =3D iommu_dma_free_noncontiguous,
> > diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dma-ops.c
> > index 9784a77fa3c9..6c7d984f164d 100644
> > --- a/drivers/xen/grant-dma-ops.c
> > +++ b/drivers/xen/grant-dma-ops.c
> > @@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct device *d=
ev, u64 mask)
> >  static const struct dma_map_ops xen_grant_dma_ops =3D {
> >       .alloc =3D xen_grant_dma_alloc,
> >       .free =3D xen_grant_dma_free,
> > -     .alloc_pages =3D xen_grant_dma_alloc_pages,
> > +     .alloc_pages_op =3D xen_grant_dma_alloc_pages,
> >       .free_pages =3D xen_grant_dma_free_pages,
> >       .mmap =3D dma_common_mmap,
> >       .get_sgtable =3D dma_common_get_sgtable,
> > diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
> > index 67aa74d20162..5ab2616153f0 100644
> > --- a/drivers/xen/swiotlb-xen.c
> > +++ b/drivers/xen/swiotlb-xen.c
> > @@ -403,6 +403,6 @@ const struct dma_map_ops xen_swiotlb_dma_ops =3D {
> >       .dma_supported =3D xen_swiotlb_dma_supported,
> >       .mmap =3D dma_common_mmap,
> >       .get_sgtable =3D dma_common_get_sgtable,
> > -     .alloc_pages =3D dma_common_alloc_pages,
> > +     .alloc_pages_op =3D dma_common_alloc_pages,
> >       .free_pages =3D dma_common_free_pages,
> >  };
> > diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
> > index 31f114f486c4..d741940dcb3b 100644
> > --- a/include/linux/dma-map-ops.h
> > +++ b/include/linux/dma-map-ops.h
> > @@ -27,7 +27,7 @@ struct dma_map_ops {
> >                       unsigned long attrs);
> >       void (*free)(struct device *dev, size_t size, void *vaddr,
> >                       dma_addr_t dma_handle, unsigned long attrs);
> > -     struct page *(*alloc_pages)(struct device *dev, size_t size,
> > +     struct page *(*alloc_pages_op)(struct device *dev, size_t size,
> >                       dma_addr_t *dma_handle, enum dma_data_direction d=
ir,
> >                       gfp_t gfp);
> >       void (*free_pages)(struct device *dev, size_t size, struct page *=
vaddr,
> > diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> > index 9a4db5cce600..fc42930af14b 100644
> > --- a/kernel/dma/mapping.c
> > +++ b/kernel/dma/mapping.c
> > @@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struct device=
 *dev, size_t size,
> >       size =3D PAGE_ALIGN(size);
> >       if (dma_alloc_direct(dev, ops))
> >               return dma_direct_alloc_pages(dev, size, dma_handle, dir,=
 gfp);
> > -     if (!ops->alloc_pages)
> > +     if (!ops->alloc_pages_op)
> >               return NULL;
> > -     return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
> > +     return ops->alloc_pages_op(dev, size, dma_handle, dir, gfp);
> >  }
> >
> >  struct page *dma_alloc_pages(struct device *dev, size_t size,
>
> I'm not impressed. This patch increases churn for code which does not
> (directly) benefit from the change, and that for limitations in your
> tooling?
>
> Why not just rename the conflicting uses in your local tree, but then
> remove the rename from the final patch series?

With alloc_pages function becoming a macro, the preprocessor ends up
replacing all instances of that name, even when it's not used as a
function. That what necessitates this change. If there is a way to
work around this issue without changing all alloc_pages() calls in the
source base I would love to learn it but I'm not quite clear about
your suggestion and if it solves the issue. Could you please provide
more details?

>
> Just my two cents,
> Petr T
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
kasan-dev/CAJuCfpGSLK50eKQ2-CE41qz1oDPM6kC8RmqF%3DusZKwFXgTBe8g%40mail.gmai=
l.com.
