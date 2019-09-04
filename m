Return-Path: <kasan-dev+bncBAABBWHEXTVQKGQE5JA4W6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD85CA7966
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 05:41:13 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id g9sf11018581plo.21
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 20:41:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567568472; cv=pass;
        d=google.com; s=arc-20160816;
        b=LBd7hfivepfz41xvEUYjn+tyIkQmcbS/BZTY93/4vn1ag97ykItSusdlS7osYiVhtn
         2oOO5SuMruyudqKTp4utZHqYUZqu1rKyaDdpwSGF4XiiOgWgWS8ytdVlfhdaTEHwsJCq
         CnMbjY/gzDm5gf128fziRO1oJabfu+I5vVR00aMzDAEdaGdhE/uLViWjkgKKL0CBKsY8
         5ufsd1u9SRqa9mX294czsU6W8BiKfGQrSVHTuQuw9zrB87MZSiNmqtHlccSbRtc2ANwH
         YepXalBkVvDpWLm54vk5clqTstiY6hhBzt+KkQXaQM2Y+WoYinILlwBdDuQe6toU0jdK
         Fw1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=kANP/bkzRGAynSkuKViYNPqEZK69AX5iKlukGp+IlR4=;
        b=dctJuMN+tFeODxUY359qx8LmpStmAFS6k9Cq+czA3T0QmfPKVkPiVo95HtGWeRjd33
         28PMaZbs8jgq4sWv4nEnhy77q+BJpkjkD+Lt51coTq4lKRnnmt5HLnbxJLeNi4IIHFx/
         FgKtDGj6+GrTpLNteate/r2b7lsTFc6TsGwMrhe3plOIa40YfXL+VTXTt9OlFLSpacGd
         92yASrEIKhfnJrxaNWZxBoSmO5Ydq+JUHJATVFhQsQdxbD1GOdH8uK/43aKRg9Qwpkz7
         /XQSRKOqI8Xs1eAnVIc2VX/6vVjGwGYS7On9943EI6pPTO/sc3jkgnBl5T2I0dgRAjoz
         Xx6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kANP/bkzRGAynSkuKViYNPqEZK69AX5iKlukGp+IlR4=;
        b=rFB2JP5aQIB0fbcQ3rNG4iTS8Z+y950Yrwl21o75att20bIdMW5LSRWTifQRdp1smi
         uqQ2MVUEpTW3SZC2nJKMvkEJkQb9xz0zVRkyFgPl0igzGOS5S81e/aEHMici+3K8CKzC
         Frgd+BRCw+RBJPEeOb2FxcE/w0CX00RrFMLgLnoZYqzRu1+PYvNHzO5mpvAHv1fJCmgg
         iV7TWmP3YP3MrqIK34Yo+g6LtQpdWqsj2jjCcmutOADmI2TA+Sk9AjA+I1Enhj2V/SmO
         EXCpjJQgttxuPml7imAkaw6m/R3+XE4jmfXGfSNr/NN5eMGBX1h2pipKQ2KqPWYor8Nt
         48tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kANP/bkzRGAynSkuKViYNPqEZK69AX5iKlukGp+IlR4=;
        b=j6MTtx9qmhKuHL7fbj3BAui2uAOe6z9SgvpLFYxsWjgk8poilemZybaXmXzsXYO7K8
         pV1l67L81OOKwnsQ422uD7YEFg5auqNL1y3hMKLSDFD9gvIt7L6FqG5CFMpuoWCSlFoT
         qy/26qOKBhAlkStaV+RG57VgMxO71NqTXc04i3+daFdTi1gBeGYt322UU6fnm+AX6Zq1
         t2PFPncOLHFFN8TvFHrzpT4hA/4cGWJNwuYUcM0+JZyLmlAdSid8cTzr7QM7DRZnKK7s
         5ClyL3/T8afWLJjXs6fsF+FfpOD/oQWZk39kFBabFehHIbPC+VgVsVJoYYdbvj9SV8iR
         g65g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVNV9q4PiEO9cOAltCiUcsSTlyxlVYVGZTY0wTfUDwd63nfQIgs
	VpQG0crqIP8sL+7xiPMEQMo=
X-Google-Smtp-Source: APXvYqxLcn9ukFS+3wVa699uW51WX8oKxfICyoHqiS+J5hGgiS/nksVMIIW/rSstSvte45R0P108Eg==
X-Received: by 2002:a17:902:9686:: with SMTP id n6mr37612367plp.113.1567568472202;
        Tue, 03 Sep 2019 20:41:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:580d:: with SMTP id g13ls4427170pgr.5.gmail; Tue, 03 Sep
 2019 20:41:12 -0700 (PDT)
X-Received: by 2002:aa7:8edd:: with SMTP id b29mr11058785pfr.138.1567568472000;
        Tue, 03 Sep 2019 20:41:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567568471; cv=none;
        d=google.com; s=arc-20160816;
        b=TccrtXupnOQX8d9Saa0Gf53ZXiJcaNDYIA6MUUBfCUKff4fQh8q2ojOEsirfX6qyt2
         iFzPWNvoXCehBI82vNKnBRi9w5AibjOGdK3ijlk0fQunFSzKT4KBJZA8vdyy7dbIupK9
         ZrgOtQzUW513PkBJzBuQm1zKUryryy8FLWWA6jM2yrXJzyrTzi+7Rcq6kICy2iCSBdt4
         nWwXBezNhHGNykTIIQPPq10OPBKmdPDpobTn/tqfLIyam5gDfz/r7wVzFQr1vBvLTzAY
         bGSCBTlsCvez1jFOS60TY71VpCbYba/JfTp5+TvYeiiC0+0far8edySqLUJBAelxcT3Y
         sZLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=dqxakFlc9/alj64lMc1Aa3qAzgA2Ue+Np9eIjjCYt1A=;
        b=qGqpNfnboDTurLuwq4DSh+OKGymmKRl/qHYUTKYci+KohRsyep9pxjfB/viYhmP2Ej
         /L64JN9g9lsqVByNW4hZnWM9EoC5DCStSY5439YuuaGIrfqEM2T+ktMoXAGBvFtTVVdI
         sOaAg2EmfjW6eNBV9mXmPsUp1nwvEi9238Bygs0pVkt6IRD2C5KqBzkZFXtmcKcG+C+s
         BbLbNFnlaAHA7SedtxJpk07uIM6A1rkeXmJ95bI16LBq1WXUCLzIxAg8Mk1ZBNveEuzT
         NlWHyKNjfJk24ok/NCQhv+Q4xM8dt8fFPvlt6EcuHr8C7LSIu0AA5AtO96UJkUAZo/a9
         Pv6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g12si473974plm.2.2019.09.03.20.41.11
        for <kasan-dev@googlegroups.com>;
        Tue, 03 Sep 2019 20:41:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 307026c154a34123ae996d4f0cac5f5a-20190904
X-UUID: 307026c154a34123ae996d4f0cac5f5a-20190904
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1655979396; Wed, 04 Sep 2019 11:41:07 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 4 Sep 2019 11:41:06 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 4 Sep 2019 11:41:06 +0800
Message-ID: <1567568466.9011.34.camel@mtksdccf07>
Subject: Re: [PATCH v5] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton
	<akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, "Alexander
 Potapenko" <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>
Date: Wed, 4 Sep 2019 11:41:06 +0800
In-Reply-To: <CAAeHK+xO-gcep1DbuJKqZy4j=aQKukvvJZ=OQYivqCmwXB5dqA@mail.gmail.com>
References: <20190821180332.11450-1-aryabinin@virtuozzo.com>
	 <CAAeHK+xO-gcep1DbuJKqZy4j=aQKukvvJZ=OQYivqCmwXB5dqA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       struct kmem_cache *cache;
> > +       struct page *page;
> > +       const void *addr;
> > +       void *object;
> > +       u8 tag;
> > +       int i;
> > +
> > +       tag = get_tag(info->access_addr);
> > +       addr = reset_tag(info->access_addr);
> > +       page = kasan_addr_to_page(addr);
> > +       if (page && PageSlab(page)) {
> > +               cache = page->slab_cache;
> > +               object = nearest_obj(cache, page, (void *)addr);
> > +               alloc_meta = get_alloc_info(cache, object);
> > +
> > +               for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
> > +                       if (alloc_meta->free_pointer_tag[i] == tag)
> > +                               return "use-after-free";
> > +               return "out-of-bounds";
> 
> I think we should keep the "invalid-access" bug type here if we failed
> to identify the bug as a "use-after-free" (and change the patch
> description accordingly).
> 
> Other than that:
> 
> Acked-by: Andrey Konovalov <andreyknvl@google.com>
> 
Thanks your suggestion.
If slab records is not found, it may be use-after-free or out-of-bounds.
Maybe We can think how to avoid the situation(check object range or
other?), if possible, I will send patch or adopt your suggestion
modification.

regards,
Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1567568466.9011.34.camel%40mtksdccf07.
