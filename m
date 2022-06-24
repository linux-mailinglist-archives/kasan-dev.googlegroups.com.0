Return-Path: <kasan-dev+bncBD4L7DEGYINBBTPH2WKQMGQEOELE5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 17DB3559537
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 10:20:31 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id q11-20020a9d578b000000b0060bfe0e8c40sf872006oth.11
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 01:20:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656058829; cv=pass;
        d=google.com; s=arc-20160816;
        b=XUN8bHTOgi+q9ryeVuu6BAi3GK1qoaHFO9+RKXDMZH1NnG0OXfua4GgKeO+agsQ92G
         L4EB14wiC5Ked/UqrjKh8vVn1DjKbRa4C7iueY5CCUPjAazaAGaz/bfvwj/RroxZ+6gp
         9Hg496bzIpq87h+NWg+gH6PAS7AJ0lnitAhOJIFOCVoRcAoCMUTGu8KPauLGkAgrHT69
         gzYP8BFXLg2MApZxZQjDUWFNi7UdZEaXBhFd+B1pLeVPkX46Mh2m1hKs8N67YzJUUtSj
         0HWVxpdHn9IAjsfJmrkQpKyRth9UvQVVjJk1zxvVtEdOpqk26vXS9owuakRtbL769OxT
         lCEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=OtiWF6uJn3OYXp2a+PLbuoip2HcW0xWDuICmgqMz4QU=;
        b=P9hNLYsiWr4H3oVIUCxzeT7Ml6oHcx9YsIrFGctUyrAFE1WlDgRAC5YWJQApmyyXHn
         Z0x2kIcFYGfx0Ga0WQw1joQU+qpEcr1AtAwMVz876ohU3cH2oyP4ZOaTTOx1mcEVXq6O
         mIvB5bUs8BMNvmNZcB/AV/hPAnXAIc1Vbz/QnReoido2oVNvWEDDWkZ/UxsAGFHfvYUd
         mkHmuXwnkO3M5GRJpu5zajJvnHCx+uMSVqTLJ/wFsetKietiZMCZ3CBqLXOHEC0BI+LB
         ao3lwXDGwqgPB8yi59d3Vlxb7Sfloi23U/RQ99LST97W7mN28hfgqUZyQjMo9XJ8v3H7
         mdrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OtiWF6uJn3OYXp2a+PLbuoip2HcW0xWDuICmgqMz4QU=;
        b=TY6V5qfmBbUX/NYkHIPd9y089zhRsg9C6nm+uyAOgpVfBL7f1zgb4FAOQE7tKATbGD
         tkKsoVWs2ucM9cTPUq5sOPOZOvHZDytdOZ0Mw3Jo0AlMlxw7AxEGr0oeh92Wi6G+TI7X
         7wet2+pi5eOrw0JU3pQ04wn9cGBPQERqY7lk5DMk17lqrNooWkP/EVJ/+ga7c5UOqFAo
         unRnswWz9Rh7IzP+FKjydcAL/IELgki9A86T1jrjvMtrmeDdiMmszzEhkq8r95bTr7iY
         LH2t/G5Sf+PGthYyaQWynAzkSF1gN7zm5+6mA7yF+o97JEhWr7lTOzM+KDYz/6Ndyn1a
         JuEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:subject:from:to:cc:date:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OtiWF6uJn3OYXp2a+PLbuoip2HcW0xWDuICmgqMz4QU=;
        b=LvSW2hJvRgBlY8YnR7vkHJ0A4ezLT0FQsXK0UUyl2qxKYLzMvT+SJJVBymRSAthjGX
         V38ulZVyYttXzb1fZlhn+XmCyHDXn1j88hxeoFO0nBv71uYtLYqRFmXLj+38kzWThV/G
         hcudUR1kKTpTTZGBIH1hoNkX8apHOndj0+Lhk/tjXYTAuWJf0WYAWVv9tMuX2miIvNsY
         3+fwpI3o23ypEnO3QUZAPChCK7Mj/IJUHDuuRzont2WEmKZdRaUKtA2DFF/Thgd3oVnK
         BH7ELGwxnI/GGtywVYv9Gsb2dI0axrY7Xfh73Qz/qSqSkXP8fZCv2jRB9LQxxRKAsDa1
         Zhgg==
X-Gm-Message-State: AJIora9d2iLL+9h8CBc35wyPG3zhT9aCa61fOX0u83bLmJ9QgpUnyAhW
	XJ12sqKdBW/nsI75A1Attro=
X-Google-Smtp-Source: AGRyM1tEF8JvAzomt3O+LNFXBOCTqbiwDyt9/u1U3MDAgls8pDHjr7L2aCsPN147Zjh3z9H0SaFpug==
X-Received: by 2002:a05:6870:1710:b0:101:d286:f491 with SMTP id h16-20020a056870171000b00101d286f491mr1298332oae.207.1656058829692;
        Fri, 24 Jun 2022 01:20:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:618c:b0:101:b0dd:89d3 with SMTP id
 a12-20020a056870618c00b00101b0dd89d3ls7018856oah.7.gmail; Fri, 24 Jun 2022
 01:20:29 -0700 (PDT)
X-Received: by 2002:a05:6870:5896:b0:e6:6c21:3584 with SMTP id be22-20020a056870589600b000e66c213584mr1319359oab.220.1656058829245;
        Fri, 24 Jun 2022 01:20:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656058829; cv=none;
        d=google.com; s=arc-20160816;
        b=Do69BXEXzit3GhMp0PV0MlbCJJoZzXUVx//sj7ZjePDpzt85nGOE401TvRJbEBbTTc
         bwaEFgTEf63QydAQ3ernjQLrq7b2dAi/Kf7xL0nM4HIsiLf6xsxW7PmNxDcdMuoSPhD6
         xLRqFPGpbyQOO3bLtbHgYbeTZNfXM4crRcEoYsdyQzlM4nJOtSm1wfy2/WEm1qhIjNhG
         sBUR2RLWi7D3ekAEEG80o0PrAToZ8edRookUE2T5jUkW4A6wGLT//CamTv9B9w1hJ7SQ
         fWiKMD1Gmi0QBzvfk/brGo+u5dqpsxU8QBcMdrinLNmCAJvhgkNXyTLS5uNeqIkujX/n
         8gfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=j6K6WxpqWr5yM3SzDPZ6o5KXpJQczgte2Sli127Axro=;
        b=baJXtxwTPp7A4VRmHhWTlGp9DNIADqD4KPsqxdohsSJ5emnBBw6EskenxLrZvACQ8W
         EHtXqC/XgcsmHisfzAcFqgxsceGRRXW6Q+8edWDXjAds8atVLfeG5yD/Gsc+dzGz/+Su
         xjhhfHDbWfUhXzuKn5UsGxhZSuz/KrN04YdUKcMo8IJMM1G4aFFPRBi7xp+8Y8Ke1b8u
         SWCXIZDzGr30DkgrLHsqBkZFNUn1MMUcuKDuJWxtwqIBt+z3bzqp0dHneEqXomPTNiap
         g2jGNtM8wL1rALB4oMmMMowMKlJG1pQhwKnfGEmLyJMmt0Pq0Uo70YSxbUHSB59wKnOD
         9EsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id g5-20020a056870c14500b00101c9597c72si295627oad.1.2022.06.24.01.20.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Jun 2022 01:20:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 753c42cefd3c4672b525df6e5332f283-20220624
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.6,REQID:bc71351e-462f-4ee6-be3e-29355e27aa92,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:51,FILE:0,RULE:Release_Ham,ACT
	ION:release,TS:51
X-CID-INFO: VERSION:1.1.6,REQID:bc71351e-462f-4ee6-be3e-29355e27aa92,OB:0,LOB:
	0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:51,FILE:0,RULE:Release_Ham,ACTIO
	N:release,TS:51
X-CID-META: VersionHash:b14ad71,CLOUDID:562678d8-850a-491d-a127-60d9309b2b3e,C
	OID:810ffcbf3856,Recheck:0,SF:28|17|19|48,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:0,File:nil,QS:nil,BEC:nil,COL:0
X-UUID: 753c42cefd3c4672b525df6e5332f283-20220624
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 709302985; Fri, 24 Jun 2022 16:20:21 +0800
Received: from mtkmbs07n1.mediatek.inc (172.21.101.16) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Fri, 24 Jun 2022 16:20:20 +0800
Received: from mtkmbs11n1.mediatek.inc (172.21.101.186) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 24 Jun 2022 16:20:20 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkmbs11n1.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.2.792.3 via Frontend
 Transport; Fri, 24 Jun 2022 16:20:20 +0800
Message-ID: <bdfd039fbde06113071f773ae6d5635ff4664e2c.camel@mediatek.com>
Subject: Re: [PATCH 1/1] mm: kfence: skip kmemleak alloc in kfence_pool
From: "'Yee Lee' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KFENCE" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Date: Fri, 24 Jun 2022 16:20:20 +0800
In-Reply-To: <CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-+OYXpik1LbLvg@mail.gmail.com>
References: <20220623111937.6491-1-yee.lee@mediatek.com>
	 <20220623111937.6491-2-yee.lee@mediatek.com>
	 <CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-+OYXpik1LbLvg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Yee Lee <yee.lee@mediatek.com>
Reply-To: Yee Lee <yee.lee@mediatek.com>
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

On Thu, 2022-06-23 at 13:59 +0200, Marco Elver wrote:
> On Thu, 23 Jun 2022 at 13:20, yee.lee via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > 
> > From: Yee Lee <yee.lee@mediatek.com>
> > 
> > Use MEMBLOCK_ALLOC_NOLEAKTRACE to skip kmemleak registration when
> > the kfence pool is allocated from memblock. And the kmemleak_free
> > later can be removed too.
> 
> Is this purely meant to be a cleanup and non-functional change?
> 
> > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > 
> > ---
> >  mm/kfence/core.c | 18 ++++++++----------
> >  1 file changed, 8 insertions(+), 10 deletions(-)
> > 
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 4e7cd4c8e687..0d33d83f5244 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)
> >                 addr += 2 * PAGE_SIZE;
> >         }
> > 
> > -       /*
> > -        * The pool is live and will never be deallocated from this
> > point on.
> > -        * Remove the pool object from the kmemleak object tree, as
> > it would
> > -        * otherwise overlap with allocations returned by
> > kfence_alloc(), which
> > -        * are registered with kmemleak through the slab post-alloc 
> > hook.
> > -        */
> > -       kmemleak_free(__kfence_pool);
> 
> This appears to only be a non-functional change if the pool is
> allocated early. If the pool is allocated late using page-alloc, then
> there'll not be a kmemleak_free() on that memory and we'll have the
> same problem.

Do you mean the kzalloc(slab_is_available) in memblock_allc()? That
implies that MEMBLOCK_ALLOC_NOLEAKTRACE has no guarantee skipping
kmemleak_alloc from this. (Maybe add it?)

If so, we cannot identify later the block is stored in the phys
tree(memblock) or the virt tree(page_alloc).


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bdfd039fbde06113071f773ae6d5635ff4664e2c.camel%40mediatek.com.
