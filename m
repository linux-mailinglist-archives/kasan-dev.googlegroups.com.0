Return-Path: <kasan-dev+bncBCP7DNHBSQPBB36TRWBQMGQEDJWGPEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6001634F098
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 20:12:01 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id m21sf9835761ooj.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 11:12:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617127920; cv=pass;
        d=google.com; s=arc-20160816;
        b=djsoVhtw1NPm5QCYZT/QKnb0pNgYn+nrL8tnFzCVq1FYkYgZGoUN9oS2kVZ9hXPxhc
         uqtGu+TYpyPjMrPvkNricExYTVWXX3odNm2DFOjHzwttxndDhoSAHzZaDtwpCsAslL7Y
         44MxyYHItUI63nnW9hGHJWJRI+/2rOdMqMgJi8hQxTRNSBJ/LycDsrOEkfG6g2Lmtatd
         jOYYbDATRvP6X949+0IVrU6Vq+ubkAOEoDsoMNHAKdaOOhomUNnTAn0crQzJhQgYo9Hr
         4rfuNkIhZuQBm8kqVgNDBbFQmofKeBYz0V0OC+O0EgXfcrrshen+pA81qG6dMg2prrYM
         x6hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=u//okMtTPhrRVFc0uIGf8fiyFo8oAvPwKNFKJReJu5U=;
        b=di/tPUjhpFnAnpUpY2HgLEdzzmMQwUwb9uaC+N6SYg3O1hbPWdaQ1ZaKrxQvrwmLAt
         fVrjvK2oftgmPVIYg5IA+hFp44O8G7S2y3NlSicaT9AjZoxV1LIHssEsBxXUU5TER+Hl
         VanLvasQuYnF0C1HI34cu9vt8JJyQbYinVM4VqbeCZKn8m1d0YuZPiF1bculPfTOKcQi
         tR6JhTxgWBpsEEHS2xDBWL+OwQXm8UB1FOnF3W36f2GjhG270MGX6Z5qo9mNBLkewIvV
         72HbEtC9kWSw+6WmoNEYJ75cyZT7SgqNaiAmAuKyojx+2u2H1z1XgidIaKIAH8VSZwk8
         E7uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of slyfox@gentoo.org designates 2001:470:ea4a:1:5054:ff:fec7:86e4 as permitted sender) smtp.mailfrom=slyfox@gentoo.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gentoo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u//okMtTPhrRVFc0uIGf8fiyFo8oAvPwKNFKJReJu5U=;
        b=jGAi4Nt5bO2OJNHq5LNWOYCz8K9COIAFG3h57gEa9hbuiz8qq4WN6MfbbQe+rxh/75
         GzmmKqjMOQPD8plqwKU4apDRuTkZ33YWomCdOmDQV70IlnXwyd4kQ3YVpvZh8VNydtti
         J2HYABTf8KZTLR92KK4Itydj2Svj7RI053W4M+S+PNtB3nYFKmY6zUzfDLoXRJ0fGbig
         hxEbZY86IXKygC6jb4MaPJ4bBq4XoMyqSZOCzHv4uPe+0F1nmU233ufkgfgB5DJNh8vg
         9lqW6z0wWA1OzD4mySINY164GKjLLBf8xCSOSDan1kYSmmW0sFLeBLrFdibNbkKzzjNM
         KBXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u//okMtTPhrRVFc0uIGf8fiyFo8oAvPwKNFKJReJu5U=;
        b=euBQpq7yPCSdmkFQ6spe2AGvZ4SvI13WGZdSqb/UYRyiDsz1f1MWYci6JHFuPo6ff3
         1spj1LGt4ohomYC79rv753uZdcWIPkLJ4USJpMess2unZjwmrUXV4m9laeXmW/kMkx2S
         NPVuLSGdAh7B1Q7LyJEuKpo6Kmce51Awlxw3QcD7e+D0LyVQ1u4ojp/mu5IjxPrC2eBI
         N7h3OOJ9YVxl4routJdBEXuOjaNjmO/fMtX4sIH57IgRSXjPc0WC8GLOAmRJ0medQukk
         cKBkwID4OU3OcNQZghHI7pZIgEIs+aeAhIqgcfM5pZSu66EzFYvE36OhGe22zN+0l5dn
         S/pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530wF7ZRnr9VI21ikepgKCeoeZ/Nfn91aRu2ssYe5vKeCeTdtPvG
	F0/iel5L4PRBK4diNfhMeFw=
X-Google-Smtp-Source: ABdhPJyE+XBt6T8SjXumxcOQrw0jJ5dxfADIvpQlhdepWWgZvaJQv6a4d0zt/cpZvYNTpQo2I74PAw==
X-Received: by 2002:a05:6808:2d6:: with SMTP id a22mr4261395oid.18.1617127919838;
        Tue, 30 Mar 2021 11:11:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:eb92:: with SMTP id d18ls118427ooj.7.gmail; Tue, 30 Mar
 2021 11:11:59 -0700 (PDT)
X-Received: by 2002:a4a:e6c2:: with SMTP id v2mr26787920oot.74.1617127919466;
        Tue, 30 Mar 2021 11:11:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617127919; cv=none;
        d=google.com; s=arc-20160816;
        b=UpR8CWYNrfIdig2bBu9l6xJYLIlbq8C+v2S+aDUnHtZSYdzGeD7fvD2Bg6Flpvx5Cv
         EtENFOIHEy/VWxlixOAkt5QuRCR79RB6ESPKw1RIhzMkSnAWkOBGgcnRDEHutN2rW8Qp
         ND4td/n3/NC1LfKw4aKyXShicsOs5h5HmdGdz5ECDp9GloTAcKfyNAdvUHCW0HXDNWIO
         X50L8yODOSnAMMLrmKYGfP5LAOGsdskmCjmiaODWPNDBlVS/yob39Q50iZ797l28zuQh
         TCIO5yjCajs/qE2ta1IYS1++7o2ReOO7F97AHBlM42vCHu8y5pf5EhVIT9BAzghzENh+
         ZEiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=nhMICHq1VMPKBxjQ7mzsmDGDCR3aEsvS5oUnO0P8anY=;
        b=0XLBWmMPRFgOatc+6hqzZ5qcEQKgvUEmIKYDUMhk8oA1VJbhLJUhN1MQcEyUM1Igi2
         roX14h4FgPDnFVhcI8iD33tyv57ldYhibvq4XbMr2x8YmbECOFYw6c9ONunSvIS2//CC
         nm6Lut840cx/xlJUHExiRJrkN4hjmD+qcdrv76kc+HzrhiPaWGSzmTYCUBj2cO50HW3P
         8zt3nTDiSEkb4Rt5BTEKiQNPzIGN4V4TTpa7biqC2TQhHDVmOVcAf7ezKBrt3WANAdFl
         94SnQA4f1TqDldWRKWI3FPR9KtZq582hI46USiJ/yO7MF2MeiZCwNFGkUdbIzrveFTOO
         ZoKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of slyfox@gentoo.org designates 2001:470:ea4a:1:5054:ff:fec7:86e4 as permitted sender) smtp.mailfrom=slyfox@gentoo.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gentoo.org
Received: from smtp.gentoo.org (dev.gentoo.org. [2001:470:ea4a:1:5054:ff:fec7:86e4])
        by gmr-mx.google.com with ESMTPS id x143si1225846oif.2.2021.03.30.11.11.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Mar 2021 11:11:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of slyfox@gentoo.org designates 2001:470:ea4a:1:5054:ff:fec7:86e4 as permitted sender) client-ip=2001:470:ea4a:1:5054:ff:fec7:86e4;
Date: Tue, 30 Mar 2021 19:11:49 +0100
From: Sergei Trofimovich <slyfox@gentoo.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, Marco
 Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey
 Ryabinin <aryabinin@virtuozzo.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v2] mm, kasan: fix for "integrate page_alloc init
 with HW_TAGS"
Message-ID: <20210330191149.68d93145@sf>
In-Reply-To: <404ad944-ab46-cffb-5fbb-3dd7ae25caaa@suse.cz>
References: <65b6028dea2e9a6e8e2cb779b5115c09457363fc.1617122211.git.andreyknvl@google.com>
	<404ad944-ab46-cffb-5fbb-3dd7ae25caaa@suse.cz>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: slyfox@gentoo.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of slyfox@gentoo.org designates 2001:470:ea4a:1:5054:ff:fec7:86e4
 as permitted sender) smtp.mailfrom=slyfox@gentoo.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=gentoo.org
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

On Tue, 30 Mar 2021 18:44:09 +0200
Vlastimil Babka <vbabka@suse.cz> wrote:

> On 3/30/21 6:37 PM, Andrey Konovalov wrote:
> > My commit "integrate page_alloc init with HW_TAGS" changed the order of
> > kernel_unpoison_pages() and kernel_init_free_pages() calls. This leads
> > to complaints from the page unpoisoning code, as the poison pattern gets
> > overwritten for __GFP_ZERO allocations.
> > 
> > Fix by restoring the initial order. Also add a warning comment.
> > 
> > Reported-by: Vlastimil Babka <vbabka@suse.cz>
> > Reported-by: Sergei Trofimovich <slyfox@gentoo.org>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>  
> 
> Tested that the bug indeed occurs in -next and is fixed by this. Thanks.

Reviewed-by: Sergei Trofimovich <slyfox@gentoo.org>

> > ---
> >  mm/page_alloc.c | 8 +++++++-
> >  1 file changed, 7 insertions(+), 1 deletion(-)
> > 
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 033bd92e8398..d2c020563c0b 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -2328,6 +2328,13 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
> >  	arch_alloc_page(page, order);
> >  	debug_pagealloc_map_pages(page, 1 << order);
> >  
> > +	/*
> > +	 * Page unpoisoning must happen before memory initialization.
> > +	 * Otherwise, the poison pattern will be overwritten for __GFP_ZERO
> > +	 * allocations and the page unpoisoning code will complain.
> > +	 */
> > +	kernel_unpoison_pages(page, 1 << order);
> > +
> >  	/*
> >  	 * As memory initialization might be integrated into KASAN,
> >  	 * kasan_alloc_pages and kernel_init_free_pages must be
> > @@ -2338,7 +2345,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
> >  	if (init && !kasan_has_integrated_init())
> >  		kernel_init_free_pages(page, 1 << order);
> >  
> > -	kernel_unpoison_pages(page, 1 << order);
> >  	set_page_owner(page, order, gfp_flags);
> >  }
> >  
> >   
> 


-- 

  Sergei

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330191149.68d93145%40sf.
