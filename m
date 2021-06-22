Return-Path: <kasan-dev+bncBD4L7DEGYINBB5P7Y2DAMGQE6JUKP5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id E83ED3B01BB
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 12:48:22 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id x11-20020a9f2f0b0000b029020331a0ba74sf6232804uaj.15
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 03:48:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624358902; cv=pass;
        d=google.com; s=arc-20160816;
        b=jjMqryvgsvmd1i7Y6OKoyMqMaVmW9ChbdbXg3qq6Ej3H7I+aIoz+eA10EHUK919gHY
         FiMIrEtBzGsEvuUwaUi2Msz9jsoq2FXhrLi8RZonnrTRy/rbos4XwgVl6rm7j5+9h0n/
         iZILpJBGncbsrlRzxR16dSy4xp0Ldn+PGozPY36+AhK8oZexBB4R6OrR8XTIUl5hz4ab
         5NPqQpGweuiDUt3qYhDoyZEGNz0YIv+Ctxn00x0daa8n75EP7mlpkxrD4AMi4vBTZFPX
         GUENy2i5CKVwoc19H6VM63d+vFf5023Pi+ubXKenPs9br1lBLUcwMJPh8YR2JG4TaEZu
         VzQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=W53Ih/5TVRvoIIHf3uKY3+eOgccs2B1YdK83SdzoMnQ=;
        b=JjtXJZ6FVP62Wl6trTDKYcEYAzovSLRt2ck0zFg5PjUwB5kSCXDoyrJt/Fo3lBBPvo
         4EfmUNGI2DG8baQL0BE24dLnwDDwkol5ouGXPpyZVsGdeGDOOz/tW76LRLT/Yrh6yPyf
         Tt46xDnS/pcMrLlsMlLDTSDriWszppT6EHq5VD8f9E90rIYBzxz7cG/BWss/FxKmSepi
         agwpz3uqe/f0BGeLEKjCxND1tVmtGNl22Cj9ma+8iOS7FrxemKCs96EdgEWYw2Nx7xDO
         Am7zXI56QkYQlzSAjunevCSRM0DRUX/JgSWmsKeRgLp3lZ3t/nIiCm70YmKveX2QsiEx
         UC4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=gzfNptSp;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W53Ih/5TVRvoIIHf3uKY3+eOgccs2B1YdK83SdzoMnQ=;
        b=MUJrkCMurULSfmvKNesYv89t5ZXELpgyHcngUloTAAXRj0KStmGu6bGUjUB0JV4/Og
         LOE8Fzj7WnM/BHIdNH/bnleQCMaskFhFWjhShiBLN0z1dQN5bVQNPZbwqtgeynoF6Ajn
         TUP3+sVeW0X24Yg7nNS3OoQaCwe42ShP027JsIdMp+xvNnOQieoUgHhRjuuw/+goT4JC
         /sEQwL2+zXGDcGul22uMmedMAKFGQVqJ5ov/DKiV8ECTTBjsMXAM+7yE8STkaIF3KuLL
         BgTB0P3cuhb8yJHMYvC5EjDmSPIYo9gmrf2ZAvoTbCpPDfVDZgoeKHI0jOh1TRF+L32q
         h0hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W53Ih/5TVRvoIIHf3uKY3+eOgccs2B1YdK83SdzoMnQ=;
        b=olvpJ+6ysg3NoLpKEg5LdGJ/dwAomJod/4i/xIp9EQjeR/ap6sbiftnhqkxXIrgvO7
         GsbGoq3iTy3pBjNKC1S8MNyNbSRl+fwonvKNaa1Ln8MxFDblm2EYeRl7sP+fZrq/SHgg
         99s+rU98rhLpHUv4tyzVwVXhOPqP8FboDck3WbjRQpQyiAb56n+i1/FeqKfY+HjJEnVC
         Axo+W0CMlRIvGniLTaEVJzVAT4i/C/nYZ8MP8B1LSkHLpzzJR2FA+pQRKKlGV+zMOW0n
         aX+JQ8VqKOAXJn+O0Bc0uLVxCSYcpB/tc896EgJbWZOxHFGszq1dl+oXCSVSB3WP3Xqk
         3u8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533C/QtAk8G+zef9H2p0oQOfOesHTmZfOZmk10LZ6vcvRHOFY9E2
	U6qA8tEnw28RnoPKiVEYENU=
X-Google-Smtp-Source: ABdhPJxNi7ymZPTwoB9LPYkLIqY5b4QLytSQQ/Ml3b4TomNUft2WigFR9eWW3s7qARmcDb//OZGUlg==
X-Received: by 2002:a67:ec48:: with SMTP id z8mr21884831vso.43.1624358902068;
        Tue, 22 Jun 2021 03:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:32ce:: with SMTP id y197ls1909308vky.7.gmail; Tue, 22
 Jun 2021 03:48:21 -0700 (PDT)
X-Received: by 2002:a1f:add0:: with SMTP id w199mr18482529vke.0.1624358901536;
        Tue, 22 Jun 2021 03:48:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624358901; cv=none;
        d=google.com; s=arc-20160816;
        b=MIA3xZjhjKGIE6Euq54MRooFVMouCsW2iuBvkZkEX2MvszdzvJtqx2wqzi+N38oTAH
         yhZWswK1TP/zA9XUY9xytAn18k9IXSmGZCf8ErnsDsFKDlTfR0b7P97h81Wp1xMBBcQt
         gXRhPHrcg/shD18GDyTGK4Yfck6bZ+BLd9AGY9zIV4THG9eRp929zI5tRD/D3A7MaCN1
         tGg46XP/bUaA9dSzZP55sy1FxTM1cOLsmfdZynOzTf0im9YY1zvPguuQ8sYmnZ1EBs2M
         /pOQhc3jEUVcsl/c5JPL+8wu1WRjrSqXXrFBdyBFcQtcTdS9xjCPmAAaGo/a/0qVt/Dq
         iQTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=2Xe8s5S2Pr4ZdWw9QKHGiKnjYf3PUAlezQXXPGZ6XEY=;
        b=VciEaMB8LjfRNC4oNhN5Ry30bEzeJU4y34PdTjx7DWTtiEwI4CVLTapDUD2ymFypN2
         dDo+wx2zG71rxITiGNAEqn2/5Cl+qd4l6bMEMYA68zkftTKldAIw+gCUUtVHgJEDGI/7
         cNanSuLPs+LuV2c/ZnP+QHYTvwapQF1R/LxqytBu5XXUOFPOL6587oO0ei16qrGWvEPB
         tss3iBsxBdayvIxUDh8ZmB3XxseOabyQsMbTQgwL14FKqG9GdDrb9pSC1zxGBv5RzL/d
         KCt6TBDCIHVfH8+LHOslGdGmNsraPvjRjQyqsymD69oHMv0eKaiEv+42w8tlNEKmi3Q4
         jgLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=gzfNptSp;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id z26si118863vkp.3.2021.06.22.03.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Jun 2021 03:48:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 32333258e4374f999c43cf6b44d74857-20210622
X-UUID: 32333258e4374f999c43cf6b44d74857-20210622
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 793337003; Tue, 22 Jun 2021 18:48:15 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 22 Jun 2021 18:48:13 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 22 Jun 2021 18:48:13 +0800
Message-ID: <46b1468146206e6cef0c33ecbfd86e02ea819db4.camel@mediatek.com>
Subject: Re: [PATCH] kasan: [v2]unpoison use memzero to init unaligned object
From: Yee Lee <yee.lee@mediatek.com>
To: Marco Elver <elver@google.com>
CC: <andreyknvl@gmail.com>, <wsd_upstream@mediatek.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN"
	<kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Date: Tue, 22 Jun 2021 18:48:13 +0800
In-Reply-To: <CANpmjNPyP2-oULXuO9ZdC=yj_XSiC2TWKNBp0RL_h3k-XvpFsA@mail.gmail.com>
References: <20210622084723.27637-1-yee.lee@mediatek.com>
	 <CANpmjNPyP2-oULXuO9ZdC=yj_XSiC2TWKNBp0RL_h3k-XvpFsA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=gzfNptSp;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2021-06-22 at 11:01 +0200, Marco Elver wrote:
> On Tue, 22 Jun 2021 at 10:48, <yee.lee@mediatek.com> wrote:
> > 
> > From: Yee Lee <yee.lee@mediatek.com>
> > 
> > Follows the discussion: 
> > https://patchwork.kernel.org/project/linux-mediatek/list/?series=504439
> 
> The info about the percentage of how frequent this is could have been
> provided as a simple reply to the discussion.
> 
> > This patch Add memzero_explict to initialize unaligned object.
> 
> This patch does not apply to anything (I see it depends on the
> previous patch).
> 
> What you need to do is modify the original patch, and then send a
> [PATCH v2] (git helps with that by passing --reroll-count or -v) that
> applies cleanly to your base kernel tree.
> 
> The commit message will usually end with '---' and then briefly
> denote
> what changed since the last version.
> 
Got it.

> 
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#the-canonical-patch-format
> 
> > Based on the integrateion of initialization in kasan_unpoison().
> > The hwtag instructions, constrained with its granularity, has to
> > overwrite the data btyes in unaligned objects. This would cause
> > issue when it works with SLUB debug redzoning.
> > 
> > In this patch, an additional initalizaing path is added for the
> > unaligned objects. It contains memzero_explict() to clear out the
> > data and disables its init flag for the following hwtag actions.
> > 
> > In lab test, this path is executed about 1.1%(941/80854) within the
> > overall kasan_unpoison during a non-debug booting process.
> 
> Nice, thanks for the data. If it is somehow doable, however, I'd
> still
> recommend to additionally guard the new code path by a check if
> debug-support was requested. Ideally with an IS_ENABLED() config
> check
> so that if it's a production kernel the branch is simply optimized
> out
> by the compiler.

Does it mean the memzero code path would be applied only at
CONFIG_DEBUG_SLUB enabled? It expects no other potential overwriting
in non-debug kernel.
 
By the way, based on de-coupling principle, adding a specific
conditional statement(is_enable slub_debug) in a primitive
funciton(kasan_unpoison) is not neat. It may be more proper that the
conditional statement be added in other procedures of slub alloc.
 
Thanks,

BR,
Yee

> 
> > Lab test: QEMU5.2 (+mte) / linux kernel 5.13-rc7
> > 
> > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > ---
> >  mm/kasan/kasan.h | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> > 
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index d8faa64614b7..edc11bcc3ff3 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -389,7 +389,7 @@ static inline void kasan_unpoison(const void
> > *addr, size_t size, bool init)
> >                 return;
> >         if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> >                 init = false;
> > -               memset((void *)addr, 0, size);
> > +               memzero_explicit((void *)addr, size);
> >         }
> >         size = round_up(size, KASAN_GRANULE_SIZE);
> >         hw_set_mem_tag_range((void *)addr, size, tag, init);
> > 2.18.0
> > 
> > --
> > You received this message because you are subscribed to the Google
> > Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it,
> > send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit 
> > https://groups.google.com/d/msgid/kasan-dev/20210622084723.27637-1-yee.lee%40mediatek.com
> > .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46b1468146206e6cef0c33ecbfd86e02ea819db4.camel%40mediatek.com.
