Return-Path: <kasan-dev+bncBC7OD3FKWUERBGPLYWRAMGQE3L3YZHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DBFF6F4B81
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 22:42:03 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-6a638a6e4e7sf1557642a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 13:42:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683060122; cv=pass;
        d=google.com; s=arc-20160816;
        b=1DmXUDSnTf3Nbx+V/CcB2wvu315LZjSjfC7d2U4ysOnrf6AI/inSXICmZoXD59QnNv
         hxCIc/CZv1Pro/pycpmwWfswiG/I5WBs001426wv0raCyigD3vWZUM8ir948Fx3tF5Wp
         wwBacpT4du7Z7KFczW5cqCHSPcn3fNIpFbx1foC012NlP7lvao34a9GwByfRm1XWfDDD
         7T3Sz8zWdjxNeHzU2dZVxBZfs9L1KPuJC0AFVwvE+qQW5O+jNiHRL2HLoT8Zo/YBHd/T
         A0WrXH3fJn2ZUwzPPjavKi4BFeuGbdxLkA25MSYCn0eLvkbl//T4VYbATY6B+Xn7qWFG
         Lq2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J4OnwEwqapjmkiyV7mekgUxV3HTPU/x2ruxn0Y1PGdA=;
        b=wnxxXGZQ+TmxfpkZW5WSLxrnjwZGZ4xWfsnWYE9s5cERHYLvoueK0VnvAdw9v1t6gs
         57wWLqDujttC8JwfWTSIVGPVpv44jv2LUDSbKY3CrL+tta8vp9EqHxjDPFLZuP+C8xpn
         pepzzCUsyFzgW0QUK5wy4H/YcUSRGTHg8lQZjMhJ2FmwrGr1/PD37aQhlsKf9LC+njog
         Uxzub/du8g64Cqx5c3gZgkJVDN3Rxnh6yUMyMo2DsstwLz80mt78Vd2WbQF8SD+AuzoW
         9cFukB3oAVV3O06wV4f8Jb6Umm15V3V0sIASncP8S19M+MPCZoVdosJrNTa/XnR0Rr8r
         vI5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=USgXLop6;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683060122; x=1685652122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J4OnwEwqapjmkiyV7mekgUxV3HTPU/x2ruxn0Y1PGdA=;
        b=VGgAXKxhCQX2C/JR5jXxcIOnQo/Na1UyzoHXIbCrrGdgEzUIeQFjvmRhnAEhd25LEs
         Mjb6MZJaWiv0SDqT6kG1E2JfO0aVCYB3/d4MhYEWo6HKX5ePo/5544x5H6mGXtqVHr7x
         g3EHDdKnovPXpNrStxn0B3jzC8zZMcVWXLup7tFgww22AFHFCOIymjts/ur6aJxvWxqx
         4BHTJqhR1mEochNSX89YCdGbviTgD4cKqCuCbI1UBRreDMRXt+lPwN+zuOzUKzAx8NnT
         T2omE/KQwgLcXTskcTbpzZS3nIGmEVCTClr/z7Txy8fotRh8QArDqeR8hqBr7l5dgctq
         t7Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683060122; x=1685652122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=J4OnwEwqapjmkiyV7mekgUxV3HTPU/x2ruxn0Y1PGdA=;
        b=IQLBEr+9ZRWbYZsFlnmLATL/xz0+pN4kGLiiezG0cC6wwW+W4uFJIVyLGb/qz57zWn
         j0ASPjFnY7QyCzVd5lspuXCV/3TaWh/XRstZDKc7hICaYGmNqK93V/SElPbqomD6VQkk
         0xloJs29RV+FTonpmOet2iMUChyM7CLLIDi5jhs8esuxoqvGYBfoSKZMcVz4x8qz3kqB
         QEoYBqBqDdaoxeNHPIrWUVL1J/7tKWH2dl7Fn1PJ3Fu4cAe0Fdf4NeKxr+oiGuKNuy5s
         Eb2ovx8b+XOTbkZbWGIIzYg6CIru3VjG4dlofSh/uQA1uUXPTalW80neV/yUDWbvTPQX
         VXGA==
X-Gm-Message-State: AC+VfDyoaoAupcTIWsryVUNQP/kJ+AHaDtck6NrMAbyq/aKtTUahi5q2
	CIw2Adihw5Yxmr1vavGySkQ=
X-Google-Smtp-Source: ACHHUZ6yS7fwDucaiVX9Fuz3Cdeyesj9xCKBDIUOhkGWPbkY5XSpXOFp157XG2x2844TsGXIQobndg==
X-Received: by 2002:a9d:5f1a:0:b0:6a6:633:9168 with SMTP id f26-20020a9d5f1a000000b006a606339168mr4372784oti.4.1683060122027;
        Tue, 02 May 2023 13:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:de17:b0:18f:9d2:8d6b with SMTP id
 qg23-20020a056870de1700b0018f09d28d6bls4378345oab.7.-pod-prod-gmail; Tue, 02
 May 2023 13:42:01 -0700 (PDT)
X-Received: by 2002:a05:6870:c6a7:b0:192:6deb:f704 with SMTP id cv39-20020a056870c6a700b001926debf704mr3188505oab.18.1683060121526;
        Tue, 02 May 2023 13:42:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683060121; cv=none;
        d=google.com; s=arc-20160816;
        b=YQbUVJ1Cx2WYEhythBgqMtrvF6pqTSNPP94gAiZ8XlFiIonLd7BnXBHcsL0urGQfOq
         iY15YOlGkoAVoWxuq+BeO+9drdHJ+632icUtXselk3B/PBBjBmuMB1bVbSdzrpdWApuD
         5Kv6znuS+3m3c6mKsCg8gKa/IexIs3Dg153vuNzjxtuNcVsGK/YWA8BbpzBkywbhB55Q
         HKLCYZohr+jYOCkWOrdUuPYovuWTjJTx3rsEa0KWxuSaIeZLaARvqQWslhhV+D4DmxEP
         y1LnOuYlts14wosFmmRV8uZktaMYZjdvaV1yDRjmwyQ9YV+L2TcdF9VfmWO5vy5NNxcl
         jYlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Jeq6+nx3g2wrW78uPfEerLbf18qIDqHe8kQ7v5/JI60=;
        b=rbwkkkai1f8icq5B/VAHiqyNbiNyPxf5V5PMteOucIyYe4Fzih8myumFyiLbtoJqFX
         sikwUCKNzg77AIOnDUi31sBzAhfQxRkG9mZFsUBFSSA+ErGn8JwKrpbjlj5LsHaYpNuL
         mm8L8H//WDtfBBiHQ1N6DNXC4kslxciqSoKdi1/6j5ktaBxwugaf8E8HtPZfYTOj1adS
         izUmGMd/MlO5XWwK02ZfqQ6T9KzexnMuqBkVO3Yu92akyopW8KkLKcYXb0c703qUulOv
         WdFC1ciXwBIAbAHYEMbcbIu3f3Q28SFIhNAw6nXYYX6agPFO2QhY3iHnv2+1KFkSgrkM
         Fj8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=USgXLop6;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id gy16-20020a056870289000b0018b18eedb62si2040539oab.1.2023.05.02.13.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 13:42:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-b9a6eec8611so107484276.0
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 13:42:01 -0700 (PDT)
X-Received: by 2002:a25:e78d:0:b0:b9a:6a19:8153 with SMTP id
 e135-20020a25e78d000000b00b9a6a198153mr17807199ybh.5.1683060120872; Tue, 02
 May 2023 13:42:00 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-20-surenb@google.com>
 <20230502175052.43814202@meshulam.tesarici.cz> <CAJuCfpGSLK50eKQ2-CE41qz1oDPM6kC8RmqF=usZKwFXgTBe8g@mail.gmail.com>
 <20230502220909.3f55ae41@meshulam.tesarici.cz> <CAJuCfpGGB204PKuqjjkPBn_XHL-xLPkn0bF6xc12Bfj8=Qzcrw@mail.gmail.com>
 <20230502223915.6b38f8c4@meshulam.tesarici.cz>
In-Reply-To: <20230502223915.6b38f8c4@meshulam.tesarici.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 May 2023 13:41:49 -0700
Message-ID: <CAJuCfpE2wBnekxOTNpCaHRwnMznPgBkSUJNHk5y1-togkAtkHw@mail.gmail.com>
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
 header.i=@google.com header.s=20221208 header.b=USgXLop6;       spf=pass
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

On Tue, May 2, 2023 at 1:39=E2=80=AFPM Petr Tesa=C5=99=C3=ADk <petr@tesaric=
i.cz> wrote:
>
> On Tue, 2 May 2023 13:24:37 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > On Tue, May 2, 2023 at 1:09=E2=80=AFPM Petr Tesa=C5=99=C3=ADk <petr@tes=
arici.cz> wrote:
> > >
> > > On Tue, 2 May 2023 11:38:49 -0700
> > > Suren Baghdasaryan <surenb@google.com> wrote:
> > >
> > > > On Tue, May 2, 2023 at 8:50=E2=80=AFAM Petr Tesa=C5=99=C3=ADk <petr=
@tesarici.cz> wrote:
> > > > >
> > > > > On Mon,  1 May 2023 09:54:29 -0700
> > > > > Suren Baghdasaryan <surenb@google.com> wrote:
> > > > >
> > > > > > After redefining alloc_pages, all uses of that name are being r=
eplaced.
> > > > > > Change the conflicting names to prevent preprocessor from repla=
cing them
> > > > > > when it's not intended.
> > > > > >
> > > > > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > > > > ---
> > > > > >  arch/x86/kernel/amd_gart_64.c | 2 +-
> > > > > >  drivers/iommu/dma-iommu.c     | 2 +-
> > > > > >  drivers/xen/grant-dma-ops.c   | 2 +-
> > > > > >  drivers/xen/swiotlb-xen.c     | 2 +-
> > > > > >  include/linux/dma-map-ops.h   | 2 +-
> > > > > >  kernel/dma/mapping.c          | 4 ++--
> > > > > >  6 files changed, 7 insertions(+), 7 deletions(-)
> > > > > >
> > > > > > diff --git a/arch/x86/kernel/amd_gart_64.c b/arch/x86/kernel/am=
d_gart_64.c
> > > > > > index 56a917df410d..842a0ec5eaa9 100644
> > > > > > --- a/arch/x86/kernel/amd_gart_64.c
> > > > > > +++ b/arch/x86/kernel/amd_gart_64.c
> > > > > > @@ -676,7 +676,7 @@ static const struct dma_map_ops gart_dma_op=
s =3D {
> > > > > >       .get_sgtable                    =3D dma_common_get_sgtabl=
e,
> > > > > >       .dma_supported                  =3D dma_direct_supported,
> > > > > >       .get_required_mask              =3D dma_direct_get_requir=
ed_mask,
> > > > > > -     .alloc_pages                    =3D dma_direct_alloc_page=
s,
> > > > > > +     .alloc_pages_op                 =3D dma_direct_alloc_page=
s,
> > > > > >       .free_pages                     =3D dma_direct_free_pages=
,
> > > > > >  };
> > > > > >
> > > > > > diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iomm=
u.c
> > > > > > index 7a9f0b0bddbd..76a9d5ca4eee 100644
> > > > > > --- a/drivers/iommu/dma-iommu.c
> > > > > > +++ b/drivers/iommu/dma-iommu.c
> > > > > > @@ -1556,7 +1556,7 @@ static const struct dma_map_ops iommu_dma=
_ops =3D {
> > > > > >       .flags                  =3D DMA_F_PCI_P2PDMA_SUPPORTED,
> > > > > >       .alloc                  =3D iommu_dma_alloc,
> > > > > >       .free                   =3D iommu_dma_free,
> > > > > > -     .alloc_pages            =3D dma_common_alloc_pages,
> > > > > > +     .alloc_pages_op         =3D dma_common_alloc_pages,
> > > > > >       .free_pages             =3D dma_common_free_pages,
> > > > > >       .alloc_noncontiguous    =3D iommu_dma_alloc_noncontiguous=
,
> > > > > >       .free_noncontiguous     =3D iommu_dma_free_noncontiguous,
> > > > > > diff --git a/drivers/xen/grant-dma-ops.c b/drivers/xen/grant-dm=
a-ops.c
> > > > > > index 9784a77fa3c9..6c7d984f164d 100644
> > > > > > --- a/drivers/xen/grant-dma-ops.c
> > > > > > +++ b/drivers/xen/grant-dma-ops.c
> > > > > > @@ -282,7 +282,7 @@ static int xen_grant_dma_supported(struct d=
evice *dev, u64 mask)
> > > > > >  static const struct dma_map_ops xen_grant_dma_ops =3D {
> > > > > >       .alloc =3D xen_grant_dma_alloc,
> > > > > >       .free =3D xen_grant_dma_free,
> > > > > > -     .alloc_pages =3D xen_grant_dma_alloc_pages,
> > > > > > +     .alloc_pages_op =3D xen_grant_dma_alloc_pages,
> > > > > >       .free_pages =3D xen_grant_dma_free_pages,
> > > > > >       .mmap =3D dma_common_mmap,
> > > > > >       .get_sgtable =3D dma_common_get_sgtable,
> > > > > > diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xe=
n.c
> > > > > > index 67aa74d20162..5ab2616153f0 100644
> > > > > > --- a/drivers/xen/swiotlb-xen.c
> > > > > > +++ b/drivers/xen/swiotlb-xen.c
> > > > > > @@ -403,6 +403,6 @@ const struct dma_map_ops xen_swiotlb_dma_op=
s =3D {
> > > > > >       .dma_supported =3D xen_swiotlb_dma_supported,
> > > > > >       .mmap =3D dma_common_mmap,
> > > > > >       .get_sgtable =3D dma_common_get_sgtable,
> > > > > > -     .alloc_pages =3D dma_common_alloc_pages,
> > > > > > +     .alloc_pages_op =3D dma_common_alloc_pages,
> > > > > >       .free_pages =3D dma_common_free_pages,
> > > > > >  };
> > > > > > diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-ma=
p-ops.h
> > > > > > index 31f114f486c4..d741940dcb3b 100644
> > > > > > --- a/include/linux/dma-map-ops.h
> > > > > > +++ b/include/linux/dma-map-ops.h
> > > > > > @@ -27,7 +27,7 @@ struct dma_map_ops {
> > > > > >                       unsigned long attrs);
> > > > > >       void (*free)(struct device *dev, size_t size, void *vaddr=
,
> > > > > >                       dma_addr_t dma_handle, unsigned long attr=
s);
> > > > > > -     struct page *(*alloc_pages)(struct device *dev, size_t si=
ze,
> > > > > > +     struct page *(*alloc_pages_op)(struct device *dev, size_t=
 size,
> > > > > >                       dma_addr_t *dma_handle, enum dma_data_dir=
ection dir,
> > > > > >                       gfp_t gfp);
> > > > > >       void (*free_pages)(struct device *dev, size_t size, struc=
t page *vaddr,
> > > > > > diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> > > > > > index 9a4db5cce600..fc42930af14b 100644
> > > > > > --- a/kernel/dma/mapping.c
> > > > > > +++ b/kernel/dma/mapping.c
> > > > > > @@ -570,9 +570,9 @@ static struct page *__dma_alloc_pages(struc=
t device *dev, size_t size,
> > > > > >       size =3D PAGE_ALIGN(size);
> > > > > >       if (dma_alloc_direct(dev, ops))
> > > > > >               return dma_direct_alloc_pages(dev, size, dma_hand=
le, dir, gfp);
> > > > > > -     if (!ops->alloc_pages)
> > > > > > +     if (!ops->alloc_pages_op)
> > > > > >               return NULL;
> > > > > > -     return ops->alloc_pages(dev, size, dma_handle, dir, gfp);
> > > > > > +     return ops->alloc_pages_op(dev, size, dma_handle, dir, gf=
p);
> > > > > >  }
> > > > > >
> > > > > >  struct page *dma_alloc_pages(struct device *dev, size_t size,
> > > > >
> > > > > I'm not impressed. This patch increases churn for code which does=
 not
> > > > > (directly) benefit from the change, and that for limitations in y=
our
> > > > > tooling?
> > > > >
> > > > > Why not just rename the conflicting uses in your local tree, but =
then
> > > > > remove the rename from the final patch series?
> > > >
> > > > With alloc_pages function becoming a macro, the preprocessor ends u=
p
> > > > replacing all instances of that name, even when it's not used as a
> > > > function. That what necessitates this change. If there is a way to
> > > > work around this issue without changing all alloc_pages() calls in =
the
> > > > source base I would love to learn it but I'm not quite clear about
> > > > your suggestion and if it solves the issue. Could you please provid=
e
> > > > more details?
> > >
> > > Ah, right, I admit I did not quite understand why this change is
> > > needed. However, this is exactly what I don't like about preprocessor
> > > macros. Each macro effectively adds a new keyword to the language.
> > >
> > > I believe everything can be solved with inline functions. What exactl=
y
> > > does not work if you rename alloc_pages() to e.g. alloc_pages_caller(=
)
> > > and then add an alloc_pages() inline function which calls
> > > alloc_pages_caller() with _RET_IP_ as a parameter?
> >
> > I don't think that would work because we need to inject the codetag at
> > the file/line of the actual allocation call. If we pass _REP_IT_ then
> > we would have to lookup the codetag associated with that _RET_IP_
> > which results in additional runtime overhead.
>
> OK. If the reference to source code itself must be recorded in the
> kernel, and not resolved later (either by the debugfs read fops, or by
> a tool which reads the file), then this information can only be
> obtained with a preprocessor macro.
>
> I was hoping that a debugging feature could be less intrusive. OTOH
> it's not my call to balance the tradeoffs.
>
> Thank you for your patient explanations.

Thanks for reviewing and the suggestions! I'll address the actionable
ones in the next version.
Suren.

>
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
kasan-dev/CAJuCfpE2wBnekxOTNpCaHRwnMznPgBkSUJNHk5y1-togkAtkHw%40mail.gmail.=
com.
