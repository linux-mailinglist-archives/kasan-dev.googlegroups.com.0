Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ547ODAMGQETUJTSIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 343123B9E51
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Jul 2021 11:37:44 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id e21-20020a2e81950000b029017ac3a6b044sf3780232ljg.13
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Jul 2021 02:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625218663; cv=pass;
        d=google.com; s=arc-20160816;
        b=bawN1sAQv/jYOx1eZFMyAEBpe/D1q7fhtqvys0ibnCH4hDq/XArKu57UhqmdQCX1On
         2f6QHqO61cinVi1wg/bJNC4SJWXx5tQGrrUJbG6FyaoScYEMgsjx2zWV9xNg8nnRAoyH
         hSuL+pI6f0tRNd0ecc/LYm+wHoq1gK6k5+y/Qoq+rsb6CaeTmyDPLHufMBhaka363Kdk
         PccZfuq0h5bBO/gRnEs+pKM27BlPCeSg5/u4ocpqV7KR8+CcYNl+CVPSuK+/Cg8qeCHf
         KP9WTAtN1Bz/ggDgYNlNimdAJfkUlE+0jMKfrmSvanUwjuG60eakSzFN4z323EM2jZjI
         DSfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oFFZtlKSvMgMV4rFaM5q8hPjBhGiCeNrcx50MOQolZ4=;
        b=RbK1lxbWDTDHF6mAhCYdEXhegYcwacC9tlU6HO01nEgtnlHLIqPJcq6l4AYgA+vO4w
         YWgF/k4J9hLDO7iLxgXepnVsk5uCtBaVTQNXFCd+Z+DTfCnyWDsHwZaF8kTHnyDVM21C
         z1rafBioniZRxviLrW7K7Or3imWsGcVUlGlIw8tzfz5Ij+9Pgi4KdlfCEndiodDBDAWm
         zWke3FVAxkJtuSUNkgThC/40t+ues8h4OzHS4irKgPA8gJD0HOcGEHmbnTpuvBPPo7+K
         hL5U3zHipqsAm2QtO0iemD4X2nF8jplSfQd3xf9zQOdz4Ek5wYVNfaWFPvdPk/ufHQp3
         7VMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=seJWsMXt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=oFFZtlKSvMgMV4rFaM5q8hPjBhGiCeNrcx50MOQolZ4=;
        b=T9Z+udoGj2AcxTVmvwrcfe9acwa3C0POYm+slfy+jdp51nGtKCnt8Te0CbQywACrwI
         AejlI1N1H3OYWuOw2k0cqEGhLaIu1agt9JrKW/lmP4EBHRisHB6mK9PZnarQV+srmFe9
         7ImYDW+jpHxOInypidfebC6qqKBgFeyfFkZULe+qnhkr4rTUbdEZSWfQvU9n5384Bl0M
         cy2CTOYKbrh/6BehpE0l7iTsmzZZas6eaSnyT8zm4fnb9BvQ/6B8/nnJeCsKZmLgbRbb
         YbCtgZSmEndwZQfpy7od6wMLcoFODrpdtFx71fvyvJwFiPaVQ6qq5bkkqPYdBbq/BuTW
         ZPNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oFFZtlKSvMgMV4rFaM5q8hPjBhGiCeNrcx50MOQolZ4=;
        b=gB8upqxkZnEvPFrmHb2PSIpAxJovq96qOCLnGdYrMFhOMAVUpcP8u95XMtSJ5fw9Vd
         VaHCoN+PW1zL9mLAmwsvkjs9dhWKt9MJqBSHpSwwI251FkEMNd8TK7EnMiu8H8tdb8tk
         pu++qn0olWLgj4tqJR+4jFAGE2xu8QpAcNVgkuHJgOD/z0Z5F8cerTrPqzdlbS7YbIH/
         tyLEPrsPjPciBK0VMrOMWcAjtuNeKIhFT/C4n328lGLikdw0Qj0yBeypQvKgcvJtkrZ1
         +GO6rCpoHC9T0VBix+ZcGuaoAnb/hb3HFnplsm6FpPGVqoyo4zAS9V0kANiARe9IExod
         hzjw==
X-Gm-Message-State: AOAM530oCc0QzFZN/zuEmYpo4lncvfaDxwzo3O2ByTRi7xbh/Em0e90A
	XNMko3WK8jZ8xraguV2KXTA=
X-Google-Smtp-Source: ABdhPJxMi/Qucs+Tsgdhwc5WAcT7u5BvWQh/3apCKiqS84Ake4POQ2o/UUa/ZQF5GwjvroVqPEAJ9w==
X-Received: by 2002:a05:651c:504:: with SMTP id o4mr3075594ljp.357.1625218663704;
        Fri, 02 Jul 2021 02:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f94:: with SMTP id x20ls548457lfa.0.gmail; Fri, 02
 Jul 2021 02:37:42 -0700 (PDT)
X-Received: by 2002:a19:f11d:: with SMTP id p29mr3196382lfh.165.1625218662488;
        Fri, 02 Jul 2021 02:37:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625218662; cv=none;
        d=google.com; s=arc-20160816;
        b=K8pV/odJCarYnffldRnGBEcy/oJANK8DRc9uEkbex1/lICkzcuFNRu1Lm8YwEMRyFF
         /R3mkB/dmwRwsH4IgHGOnDGvHbHLLAUCHLFzKRMO5axVe1EPIi3AI+YJXJ7A24B9Gikr
         mEvpr+cUUI7CDrNh3C9okByFUcydnmUbbWM2pP2xHlYUs0TCzhjaAKuoOh6yi2cp5DHQ
         1ye7J91EpLVuXR0DurJqqCU7nmBC0qcsERzHOlbHHdFzDhFi1IvTXgyL9cYAkLg2Bleh
         1NcWHmTZEtGldAZ7HCpLg8NLd4ewY399VySSD6GZAYwz9D76wjNEq7fVvH5snhYDU9eb
         1yDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zmw3iGewZOSDs+c1/yw4f6lr9XV4A3V9IcDrAGu7EUY=;
        b=PbJZYXzEL2rIc0qKz8zTe5dgUtdGYHqzv6+ZgFAFiQ/6BbTaLQYXEAy5pFqoTZrEH1
         eAj24KpF9kwaVzAZwaUXrq9eZabFDStSo+g8mGOUnpUiUB/zH7RtQF9y3Atg4j9vxYkN
         ILOYCRE4buw4n19HOETDpdHFVOTCoZ9qfKy9XISAC+M/OESCR+Iq1wASQSCSrsABNqwH
         TjslSLA3KtzhCLM8qVRjH775HLZIGp5OjYy9678yYMlbEeyhqe7tmqmWphFJLhf2UKQO
         f1Gf4+N4vGwKD2dgdIeylAlsd2ZP0Z3N3CYWCDjSw2SBP86q7sKN/Dy2Nd8pE0PPBiKu
         AGHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=seJWsMXt;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id m18si114881lfl.1.2021.07.02.02.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Jul 2021 02:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id i94so11685947wri.4
        for <kasan-dev@googlegroups.com>; Fri, 02 Jul 2021 02:37:42 -0700 (PDT)
X-Received: by 2002:a05:6000:18af:: with SMTP id b15mr4769198wri.252.1625218662074;
        Fri, 02 Jul 2021 02:37:42 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:212e:6681:cd1c:caef])
        by smtp.gmail.com with ESMTPSA id n18sm6583605wms.3.2021.07.02.02.37.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Jul 2021 02:37:41 -0700 (PDT)
Date: Fri, 2 Jul 2021 11:37:34 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: yee.lee@mediatek.com
Cc: andreyknvl@gmail.com, wsd_upstream@mediatek.com,
	nicholas.Tang@mediatek.com, Kuan-Ying.lee@mediatek.com,
	chinwen.chang@mediatek.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	"open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
	open list <linux-kernel@vger.kernel.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v4 2/2] kasan: Add memzero int for unaligned size at DEBUG
Message-ID: <YN7eXr30zVH7nLhQ@elver.google.com>
References: <20210702085422.10092-1-yee.lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210702085422.10092-1-yee.lee@mediatek.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=seJWsMXt;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Jul 02, 2021 at 04:54PM +0800, yee.lee@mediatek.com wrote:
> From: Yee Lee <yee.lee@mediatek.com>
> 
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone of object with unaligned size.
> 
> An additional memzero_explicit() path is added to replacing init by
> hwtag instruction for those unaligned size at SLUB debug mode.
> 
> The penalty is acceptable since they are only enabled in debug mode,
> not production builds. A block of comment is added for explanation.
> 
> ---
>  v4:
>  - Add "slab.h" header
>  - Use slub_debug_enabled_unlikely() to replace IS_ENABLED
>  - Refine the comment block

^^ this changelog ...
 
> ---

^^  this '---' is wrong unfortunately.

> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>


... should come after the tags.


git am removes anything between the first '---' and the actual patch
from the commit message.

The typical convention is to place the changelog after a '---' _after_
the tags, so that it is removed from the final commit message.

I think the code looks fine now, so please go ahead and send v5.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YN7eXr30zVH7nLhQ%40elver.google.com.
