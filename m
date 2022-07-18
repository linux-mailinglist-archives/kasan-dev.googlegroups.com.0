Return-Path: <kasan-dev+bncBDW2JDUY5AORBJGD26LAMGQEAPH25UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AFD1578DA7
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 00:41:42 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id e123-20020a636981000000b0041a3e675844sf912072pgc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 15:41:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658184100; cv=pass;
        d=google.com; s=arc-20160816;
        b=zqnsSTzUa2WIOS0CUySVkNtNYt4uEsqxYFOTBWnG0U9PhquAJ6u0xkZHetzb6eV1kK
         Rqtf0LuUscv27DHxSFj691PK47SBbBHmSK+qX8r6R8qtl5zOUOIaQ0KhsXF/OorA+NMd
         IVeTKP57rsyfPVPPhc5Xb1+M7dzLdvOpoSauUmsFeP5jLl3qRhDxGM0X7IsuhVIy3+ys
         2jfoM8Wz00DXH9NREzpi4vymKr7QwUCxc0vfeUXT9Cob7fj1HlLsp+KTN/4rK8dULsbW
         R4Rltlk/gx7NB4nTkyYpMvgk7d0kpF7NKdOC/drFoEXo+A33tMNyxafahbzdECO9//QU
         UydA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=XdLCNF3YLuuzekwCBv4Pxedca6weV2U76IjDf/uEZE0=;
        b=B8rLJNqwTXK+6hjaJsdzlo+OlOCAStSUAcvgg9rX5fb+ozLsXsGIm/r/aAwctXK40l
         sevQOyHCKty7v3ma5DlYuJB/e6ju3QUkR9kkYYhIsCXwcPNhF777d7w25Fvnb82gEOa3
         LpIRo/hTVETUKeFSDQj9MtNKBsE6jBBLf4G6+BeFbUKRpxUMjWDIFVF3QIckZARwQvPL
         z9AkQ+a5ihqPPkVze/X10+/r3QJQm7NOD7nbippgEkIQ03FwgOEniy0aSvfG9yFQ8aXg
         Rb80gSekLn8RFXnSOgepGA4m5oV/Qe5CLFHAPGrDz+A+Xb6fq2PgvGUwsmP6/vcAD3wU
         JRhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aZjpVE4E;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XdLCNF3YLuuzekwCBv4Pxedca6weV2U76IjDf/uEZE0=;
        b=BVe9d8ySLoPwrwqwrP/qpDX0rDOvbxOHdoRV9ku5RJHM4Bsa+YvO2mapAW9bKILsrp
         emK/FPDKCSfdf35BQtk16fSvN3IFBdfvt44ZA1RbeW/I5Q56ypqu517/MeXVz5f+5tUo
         MZId0z2j8U8u5VXT9DMvwl2VqIiAcnSvWmxLQbyWBv/yV58CSJzE08lyA2+FNUaO9BVW
         EqRo8IgHge2vFkiEPeksXSPsFKTjH7PC0sotrfV8ERWHA3omj3Mh1xtR/8f4P/3XJiTc
         jF4FitP8l1Ai1W1HvKiiDDUp9FK66UJX4KgjOT2RYuXCBMcLaTeHmBYbe6BdQrRHtx7d
         dwFA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XdLCNF3YLuuzekwCBv4Pxedca6weV2U76IjDf/uEZE0=;
        b=qFIn4Q7dl/kZhfrA9E66dQ+oHrEbarCIQ6HtvmdkZhJuPlBOfm2uaKG5RheQAcXOnx
         dzO0+b85XIrQlBj2mxjOz9COzz4CniG6gVm1NdjqGjwL4igrvNaqGfrN1bPC8Eiu/VCG
         IO4sJWf4ad3DU8P8cU04X4pqTWfnyUGp5Yu1Wdy+hefE+Q29HL7AzQkyZT8b1OyD6T/4
         /1DR+7XkCAzFZ67i8ZIkTmRhxHvzNuPdfDOzWPYKc0Pk1tE4W8b5fsintsF7RFeZiFxH
         r5KqquLiVsljg+fyrkL+eUnPnxBGGgyuJRSCMbC64egjlWLfOgCPd0ASBQfmGhqYqImx
         pPcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XdLCNF3YLuuzekwCBv4Pxedca6weV2U76IjDf/uEZE0=;
        b=eFqRlpJix1y6xB9iHZT+7H0PxLqmbhq/aEVAEqqoWwKCKsbuJlaACocqcAD0dRkLLu
         oytYW9Z/WjxT0k8Mx29qZTy+jXjMpDIW9rfJMdODXy4056LLs82VvUQyp2b/eWGsyYLo
         agoEWlqKe3kDnwaSzPD46dD8MVFec3Jr7lxZ/B1EjV9yTvUrL/sbgcQq84IHNaEP0C+q
         W9XuZ2/qKHg/qDa0GGYaiWIRPfxiNJlMDNWZBcuwj8e2prgrCcW5aJnYjF7UMRzDQZEL
         WE2epIs+735n7zINySSNHKvtDzSSc068Pi6ziEtMbfnd+e5uIoEq6I8nbfj3lPGXSgDg
         sEhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9GADsMJsogOcLEtoV3UzYsve1gFtXhMq0+wUchXcYXjhn3hnfq
	L7DNqEKvw73XC6m2gPfEeZY=
X-Google-Smtp-Source: AGRyM1sRHccsJwRBPiovGeMJlAg/iklqsqH0N19vsTKWvIbN9tJsemuJBKghF1CCe90ZK49FjESWDQ==
X-Received: by 2002:aa7:9afa:0:b0:528:bbf7:e444 with SMTP id y26-20020aa79afa000000b00528bbf7e444mr31056513pfp.71.1658184100584;
        Mon, 18 Jul 2022 15:41:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f604:b0:168:9a69:49b1 with SMTP id
 n4-20020a170902f60400b001689a6949b1ls12004203plg.6.gmail; Mon, 18 Jul 2022
 15:41:40 -0700 (PDT)
X-Received: by 2002:a17:902:cecf:b0:16c:4a62:62ab with SMTP id d15-20020a170902cecf00b0016c4a6262abmr30997183plg.129.1658184099930;
        Mon, 18 Jul 2022 15:41:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658184099; cv=none;
        d=google.com; s=arc-20160816;
        b=igY0oCUnOhdXQxC65ECrFJ7T48p5KtKYM2KYPOEpaJvcTGVaXEcW8LXQaKiOaXrQEE
         wkD96DALyCC4c8ezCnhZFO7HfCEAx7CNoKOLjfOcsq78zJPKtGA9CO8g29EgKqtjHenw
         OzfnzQw8joYbZiTNhKpFIpJyu2Dl9l2OMhJYif/0gNGpVgDsnfHpRFCQU19eKsgXfnSK
         n/KjWw3yRcD2r1uTwLrNF6uxPbqY18rRLrSy/Vfz0ZWguDffWrRqagmvKwVAwl2epMXV
         tadqmFhqy0WtMBnQZvmfQB8u7yu/Py0h4LcagFLL4XGB5yD/DykRWZzrxccUQy51LxQ9
         bnQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dhwistRYtSEw+FOLxYsmvUgg2SfWUhko3Y0iHqBJPu4=;
        b=XRblsW5IDizub6E6t4nCohQeTZvBay+VWMg34HHZDrXaSRDuqugTvfOcaY68dbrc2V
         /9sL6YsP/Wa2AzEAZKWys3fHZCjgOT3d5wGeeotICTAkJxznYHKcIxqdSVt6i36ME459
         MKNzIL55Eu6C1OaoBi+ipJGhqJ5DS07Tr3JS0vIZ9+zJuzyUqZ8Y10iqqQRxsNiNDigp
         9AU2RsUAzXIlzYCIN86fqx26S0GWQHSk9jXtpzE+tunm9I2MJ4AAlYMLTmyqGO61FSIl
         D5jZQ0y56owMvik2iB4+1NARwm1DS9eOpWqA8lIh1brxmWoq9k8O3BdceOZ+q3GLmQCE
         rB0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aZjpVE4E;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id c11-20020a170902d48b00b0016c509aac57si532438plg.8.2022.07.18.15.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jul 2022 15:41:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id m16so5702426qka.12
        for <kasan-dev@googlegroups.com>; Mon, 18 Jul 2022 15:41:39 -0700 (PDT)
X-Received: by 2002:a05:620a:2556:b0:6a7:9f07:602 with SMTP id
 s22-20020a05620a255600b006a79f070602mr18213055qko.207.1658184099146; Mon, 18
 Jul 2022 15:41:39 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <9363b16202fb04a3223de714e70b7a6b72c4367e.1655150842.git.andreyknvl@google.com>
 <YrBDzKTZMnWztGIQ@elver.google.com>
In-Reply-To: <YrBDzKTZMnWztGIQ@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Jul 2022 00:41:28 +0200
Message-ID: <CA+fCnZe7b0iNPePpYXswDsjZykphK8vgaYDeeOJCuKbePPDVVw@mail.gmail.com>
Subject: Re: [PATCH 19/32] kasan: pass tagged pointers to kasan_save_alloc/free_info
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=aZjpVE4E;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::731
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jun 20, 2022 at 11:54 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, Jun 13, 2022 at 10:14PM +0200, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Pass tagged pointers to kasan_save_alloc/free_info().
> >
> > This is a preparatory patch to simplify other changes in the series.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  mm/kasan/common.c  | 4 ++--
> >  mm/kasan/generic.c | 3 +--
> >  mm/kasan/kasan.h   | 2 +-
> >  mm/kasan/tags.c    | 3 +--
> >  4 files changed, 5 insertions(+), 7 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index f937b6c9e86a..519fd0b3040b 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -227,7 +227,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> >               return false;
> >
> >       if (kasan_stack_collection_enabled())
> > -             kasan_save_free_info(cache, object, tag);
> > +             kasan_save_free_info(cache, tagged_object);
> >
>
> Variable 'tag' becomes unused in this function after this patch.

Will fix in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe7b0iNPePpYXswDsjZykphK8vgaYDeeOJCuKbePPDVVw%40mail.gmail.com.
