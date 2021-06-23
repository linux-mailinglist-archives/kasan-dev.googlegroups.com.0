Return-Path: <kasan-dev+bncBDY7XDHKR4OBB4OPZKDAMGQEG2K7AZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BA0B3B1218
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 05:18:10 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id b4-20020ab008440000b029028070c7b794sf205011uaf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 20:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624418289; cv=pass;
        d=google.com; s=arc-20160816;
        b=N7UgTEhD4bzngT9UG5zYCprzTETnErsI632nukAIDYPDvdRTnMHPRyoIj8tO8jja5y
         yF+AtCWNY9/zO1GPcpNqqjDltsNecBmi0nHidYjVXHCFfNZ5ANIrJB2EWNWvLmbECzdQ
         QIgk72vdSuEsfgkRoBYQKoIyUXlKoDywiFK09dnPG1rAP46RgK65K2/5Mp43LU8ABi+N
         VTQ42+TE04FiRk9awm2ZjlmVyZX9tPggfDv9eF0GeRJqtu4YwT9+2wmeetv8IJPBd2jc
         lSPgnk2r0RN/Nie27aZKbVRbQbsbMpc1BQxGtI8/cr7p/13pfQYQiBh51ESnRAQi12mH
         0xIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=xPckH7EnVa+BoB5X3Y9rFLE+T1BxTe1R12SOaN4CHFo=;
        b=XnQa+MTcrlswd3oos7o2qp0hreWrll1XjPdWVZ05I2kVkyyEYLrMye5g1EFArvRKLw
         IQWWixD2s2E5LMC/wRo8TtcXM6+OPYYMjJ6GwhF/Gtx+IbWsp/N6cNkXG12QFmetOY48
         RUGG+ebfZJx01kQVNzkdiIvkS72vdV4aLZ4UadvlLmyPORuNV7E66+5y9RR1maoGJ4Vx
         6+IV7EUf+8k0E0ojUA6pNATTnNYYMkrhljmO+jqB6qbF+U/esv78qCwesgILOwTuJmN6
         86UjpcOrx18RWLiVA4hHFGgeUKSI8nKC3KUNy9VXavYhn30b9emsPJScZyjlIYc5ERBR
         l92g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=tHHRkDmV;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPckH7EnVa+BoB5X3Y9rFLE+T1BxTe1R12SOaN4CHFo=;
        b=N46FtLZgKEnPwlg5GdaAQcpFZHnmM6seMNHW/8PM2E0DWeBXO67gkz3sMRFSe1JqSB
         AjeijY1qDrZAh78tVTnaLZMtyAd9W/V6zKgE4XMjNkjWqd6lroNl4DDXyvGAIeN9pY7G
         IonMWy8RTVOB2WaRfvsO2A6Cpplu/rYLk4wwT52wjVhd9qt8VfBI7VgLgCgzYAFqNw+f
         kUVbR9MJM+P+YJWiA2qrD0JW9El/M/E9OwZkIuQNBVFtgxrpgkRfzq3ul/Vy99yKJb62
         orZWUTE3A62TQV+b41DuBoyAwebbJyBIWQVyN7ZwdHqpzsY873RDPIIcpOaWzK9jZbD6
         LtGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPckH7EnVa+BoB5X3Y9rFLE+T1BxTe1R12SOaN4CHFo=;
        b=syfKW1JfVLEhnpMF6zMh0bhKD9tbLNgCyMIXJ46d9jLyMpzgXSusCY0Dv9HpldR0/u
         1m0boeJGVvsNrAPMpq9x75YJDnkKGnAF0SBd05OMWwXc/OJTAkKJZVefQOFWVRVDEeMb
         eFlsXuGz8VIQRGGxTUfu9vnoNinVCyXocln/4ZJagSum5ylsD2pnWpqiGYlyD4EvlyHl
         ZHJdnsxcQCqloIMbt23FCvIOR3gdpC2YlZPzlIO5IUiH0fw6dgwUrrh4bwtrSdCNCivv
         2ore8vmELX/HXfBXV82nN+DNmuPObi3Wm13rDfHTxwLklmSsSFqWf+8YOo86oPZ93xef
         cs3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DAUw8W4dnark277iH1knybm6+RLtjS/3X/FeWI3QR/dcOkRy2
	9WRP0KQB7aJg7V+dPPLejsw=
X-Google-Smtp-Source: ABdhPJzS/HyCqDLd3cr/TPQPsPd4+8bsR82IU+6G70rXoKZrWwUMtawaOPMiJ4U7GwmDAgjhVmvbAA==
X-Received: by 2002:a67:f954:: with SMTP id u20mr21552514vsq.58.1624418289236;
        Tue, 22 Jun 2021 20:18:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:32ce:: with SMTP id y197ls107564vky.7.gmail; Tue, 22 Jun
 2021 20:18:08 -0700 (PDT)
X-Received: by 2002:a1f:280e:: with SMTP id o14mr22698802vko.19.1624418288744;
        Tue, 22 Jun 2021 20:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624418288; cv=none;
        d=google.com; s=arc-20160816;
        b=CLrOKjKGs3qwZP9lvgxyt9obKLGqN0kWkL2esbHlLYcJ176EK1db5ZE4RoJ6+tTj/Y
         jBZTzi7GMuzjgwBV8JEpkPyRGILOGn1/VVjFchgI/TJK9zWgODYWWk9kDbs+EKRJYLxZ
         pSNsRIRduvGBaNb73pze/X083g0lagP2wmQRweBFJt9OE6i4Nm9vuCYbtDGtVwBtw0+Q
         J5Hvk+ZJsG/nTkfUcY0223sAwE5lIHdvYC0wz0PN4qox3/n5/TBgqtEKyOKytI2Kql5x
         zEAuta2bOFttzbaBENAGE7AyxpJiYj+BZ8jyeCcj7HIc4WhwarhCnjmAxJDQvvhl63Wr
         t8lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=bgnuDS/Z+nPqmzTT4TvjlnF+A9DJYxftjxThaCbTG3Q=;
        b=CbPzwbj1IqOJPWXmg8Yz6bzta8ugN6WF/imh0XC8EoXiitQkrmgQj1QwTHa9uNvg43
         fAL9Nht3JfIHyAfD7gOYHCJ69qWGzl073BhJoIJB+YcRy8Viq+gBaYP775eEiX4sdr+S
         JZy7lEnLgv3fbzTqv2ZtinpNFYqGxX7hvnhzimNCGrWfgG7WWb/8Cbe1V+mkkmy9BlNr
         /R9f6loBmlPK/WkDYWOBeenwXTMw4WsEA2ccC9QhkeRwfQIHBRat7cUJEp6PojPFUHxi
         yLl3DtHfdYoLOZirHl6AYDlwCp3uNmQIpHnTIRuunE4Z8nb1SdSXPse60+G6QBVapd9H
         /9Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=tHHRkDmV;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id y2si535633uaa.1.2021.06.22.20.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Jun 2021 20:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 4f2304a7abac43d6aefc5e044998270f-20210623
X-UUID: 4f2304a7abac43d6aefc5e044998270f-20210623
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 835981017; Wed, 23 Jun 2021 11:18:03 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs02n1.mediatek.inc (172.21.101.77) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 23 Jun 2021 11:17:55 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 23 Jun 2021 11:17:55 +0800
Message-ID: <cd9c48696809ac92f9c201f4a08effe657da53ee.camel@mediatek.com>
Subject: Re: [PATCH v3 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Linux Memory Management List
	<linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>
Date: Wed, 23 Jun 2021 11:17:55 +0800
In-Reply-To: <CA+fCnZdGQ-_USQ_dCkmp+=MGS01yRtn1eLpGRLvbq=j-SQDrog@mail.gmail.com>
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
	 <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com>
	 <CA+fCnZdGQ-_USQ_dCkmp+=MGS01yRtn1eLpGRLvbq=j-SQDrog@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=tHHRkDmV;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2021-06-22 at 16:54 +0300, Andrey Konovalov wrote:
> On Sun, Jun 20, 2021 at 2:48 PM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > 1. Move kasan_get_free_track() and kasan_set_free_info()
> >    into tags.c
> 
> Please mention that the patch doesn't only move but also combines
> these functions for SW_TAGS and HW_TAGS modes.
> 

Got it.

> > --- /dev/null
> > +++ b/mm/kasan/report_tags.h
> > @@ -0,0 +1,55 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> > + * Copyright (c) 2020 Google, Inc.
> > + */
> > +#ifndef __MM_KASAN_REPORT_TAGS_H
> > +#define __MM_KASAN_REPORT_TAGS_H
> > +
> > +#include "kasan.h"
> > +#include "../slab.h"
> > +
> > +const char *kasan_get_bug_type(struct kasan_access_info *info)
> 
> As mentioned by Alex, don't put this implementation into a header.
> Put
> it into report_tags.c. The declaration is already in kasan.h.
> 

Ok. I will refactor in v4.
Thanks for suggestions.

> > +{
> > +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       struct kmem_cache *cache;
> > +       struct page *page;
> > +       const void *addr;
> > +       void *object;
> > +       u8 tag;
> > +       int i;
> > +
> > +       tag = get_tag(info->access_addr);
> > +       addr = kasan_reset_tag(info->access_addr);
> > +       page = kasan_addr_to_page(addr);
> > +       if (page && PageSlab(page)) {
> > +               cache = page->slab_cache;
> > +               object = nearest_obj(cache, page, (void *)addr);
> > +               alloc_meta = kasan_get_alloc_meta(cache, object);
> > +
> > +               if (alloc_meta) {
> > +                       for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
> > {
> > +                               if (alloc_meta->free_pointer_tag[i] 
> > == tag)
> > +                                       return "use-after-free";
> > +                       }
> > +               }
> > +               return "out-of-bounds";
> > +       }
> > +#endif
> > +
> > +       /*
> > +        * If access_size is a negative number, then it has reason
> > to be
> > +        * defined as out-of-bounds bug type.
> > +        *
> > +        * Casting negative numbers to size_t would indeed turn up
> > as
> > +        * a large size_t and its value will be larger than
> > ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        */
> > +       if (info->access_addr + info->access_size < info-
> > >access_addr)
> > +               return "out-of-bounds";
> > +
> > +       return "invalid-access";
> > +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd9c48696809ac92f9c201f4a08effe657da53ee.camel%40mediatek.com.
