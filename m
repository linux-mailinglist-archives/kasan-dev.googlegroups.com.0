Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOVC3H5QKGQEIHKXA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E48242809CB
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 23:59:23 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id 124sf10462vss.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 14:59:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601589563; cv=pass;
        d=google.com; s=arc-20160816;
        b=AFk3WS8DpBGNumLmLymaeqbZiswMr5BSNxvRLQDWuYUHhDQ3zhadkqVXq22FAPSYi0
         bx1fx0SC1J0LFbjmUvMSiIMMVjfhZ8cuN2a+VIiJHEQjpGZ+ShnxAPJ7ZafuYd5pdGuf
         AAWsRpPbV1lClsgyriLrCWltiCLgfWttKV6dapLiG4PT9hyHV2puMoY/daFm/b8zQUyF
         31l1Hd8Dpaw84qXLbk2vKkbOFGQqP73uW1mZODn93cRxRwesWs7IaQrtUkNcov0S/VQV
         58SgOg44KX8ILvvgPsvkhvtJYEAUj0rsahgmkODyRfIOyqw4jCg3Kmbt20iQo7FrD7jC
         iksg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4TXDu+hMXm+5SPYlKnreopsm7CMg7mNllMFHfqVPKq8=;
        b=TxIvbdzVLOHnMN+rt3k7hl13x8wWUmSP8SyYT2QnvQVx+Aty+uQ2bHwkPI+J6OQ1ab
         24E/LUWCmLt8GEZ29Pzf5jC91JLkdbvWI6nGyNCBQgn9ccUCchDRcn7si90SMysaEo0a
         uqH2d5225uIUupGtmPqpdJLJorLLStmU1qCRdzM2M6cwhrwe8/JY9ZRWjSvoAC7M0p1y
         IF5zR2LBVJWWAfDQF4axTUCmQfuREN5hX9C1NxzpDDM7TyD5+UHxj99VbN3q+06CYXyx
         Cv9WDXdW2EdrJEVr3FvmymiQXnfhGTCiOQgxeJi3LPjEPR4KFqySFpVSfKfAaAXSMBlW
         gzIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TBqS7OT7;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4TXDu+hMXm+5SPYlKnreopsm7CMg7mNllMFHfqVPKq8=;
        b=QXK565Um7PcCJ9nxjnGi99OBBs1CsgTCfs7Y01/K26rwTDy8cNu0ot1igPe/6xsjcT
         QGVlhTlLru0pULQXxbzN4p/e1CGdOqRmhf5zdeSnXgYggBvKV4Y5PIAyva0yXa9H0UL4
         dnPxNsurybjZ50ObOnRCIlDbElPgRtA79MU1h+Mh4YwjhSEvMxN6Z+qqP85aTDJxRyko
         KNWpvc1JzUhBLPrS3Uovkil//rzWv8czwB/FHJ0LgOUSsItvcnflbLR4vb5zjvQcjDbV
         eUOnC+h4M9RtP0tdfRFCMjUAztxpaw4ebyuZov+oZxj7wysjHNe1Vm0G8RP453rsIiWG
         FGHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4TXDu+hMXm+5SPYlKnreopsm7CMg7mNllMFHfqVPKq8=;
        b=Xg0fIdC10nrhumPHLXNhvakQmz492L/1+k+MSb47IsxZd3xnipqam++pAAxgU/bDUh
         fYzTSsR+uOTvNHL0iZVT4RN09zSX7gLjuJ+yiynrhE9ap88dW1TF71u7wu9A49JmPQYU
         yIG2qEVKe2UZ1rJvflcnWXFIfWakc4vM5gdePXRiDotH0EyL3fVmitJsdHasyRb/oosj
         JiXYOszwIFE8Vmvr/BJJDI1kOtc/eV+BMNAIPVWE0wlTcKQ+OhYRgzI1ywRoS1iOvLb1
         R5R9hz7t/oRNsTcgIwT4Yr/5oFQQ8dK49xoUU/kKTneL9X4cDiUPDPTj9Swq5K8aiaL8
         bElg==
X-Gm-Message-State: AOAM533Uh2VXcSmm1q73xovcPXczvrlusOkkwbzp0HwkxFvQYOlhc1Rc
	hkSghMrGvSg9h1yydIXeBos=
X-Google-Smtp-Source: ABdhPJzSI046waJDS6SZ5XhbPIuIs0xbir0fFDlUTp9KBBwyS8YUcglun03KwxYovGeoz++i/429VQ==
X-Received: by 2002:a67:1986:: with SMTP id 128mr7228220vsz.20.1601589563003;
        Thu, 01 Oct 2020 14:59:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:874b:: with SMTP id j72ls913241vsd.9.gmail; Thu, 01 Oct
 2020 14:59:22 -0700 (PDT)
X-Received: by 2002:a67:79d4:: with SMTP id u203mr7070756vsc.35.1601589562575;
        Thu, 01 Oct 2020 14:59:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601589562; cv=none;
        d=google.com; s=arc-20160816;
        b=aVqnGTNssYl6p7yno/1+u65+AbyOLjofQdItPGkXixvk8WsQfJC4abmWp6g66nk89l
         FL4Pt5rAJolkLEumYfkZZydoHaSVFMfRnQ7ujpzldDrc2VGDrjVzds/3Bc4dSmb/4ExV
         bcwErzI3vjWT2IzqiLDCXX8pGeaaHsMp8wQ84aaKX+dqByp1YhM7B9K7E7HqKJuwNg74
         ih4Z50XgKn4wCcFGAfMF2SRR+RfdK20nWfGKHYiymkzdvr7j3elZPo2jwLlsHyg5UM7T
         39Ij9G+IIQqxlOEFN3gHBIIAoyGfVXfw+U3j9SlquKcLjKCjo2GumHw6f53t6u+xKafq
         gk3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FeLdvrmRrEjRDvLDp8IMeU8yTFWoBJ46ycNhebnMFYM=;
        b=zsVyQNisa+QfN/IIpyGz/N3ClpadUOG0aBNzmSypepUdcpoH+xkFdjRfuUug7mnHt8
         VxMlff4Ronac/7EdEnId6T0kc2n21DBgEughEpRS2p44hn5n8rOjYeAi3ZwVFVrPY4WJ
         aDWJ4BouJrZGJ4QBCnpbsRqIxvQZGdk1ox73TRVShDDGDjCbSqmoAQ3ksKHSubxPz9Ds
         a2/Zc6gqbx0n75IQaOofYbKXhpINw17f2oqv0FZErYXXEnWxyz3P8sBaVdlJ3ucnvL5V
         DO4t41q/WhFp7XwUXkb+EKC3nQCSww0zcpqA/G247VE+xFhHXBpoIWTHVrg/kprkIWPn
         nMpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TBqS7OT7;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id s11si541486vsn.1.2020.10.01.14.59.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 14:59:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id e15so824696pjg.0
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 14:59:22 -0700 (PDT)
X-Received: by 2002:a17:90b:140c:: with SMTP id jo12mr1907027pjb.41.1601589561599;
 Thu, 01 Oct 2020 14:59:21 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <08b7f7fe6b20f6477fa2a447a931b3bbb1ad3121.1600987622.git.andreyknvl@google.com>
 <20201001175841.GS4162920@elver.google.com>
In-Reply-To: <20201001175841.GS4162920@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Oct 2020 23:59:10 +0200
Message-ID: <CAAeHK+y4cn5sZeoeL1SkwA70kFcgneZiFgs6EwVR=7SaHgi5LQ@mail.gmail.com>
Subject: Re: [PATCH v3 32/39] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TBqS7OT7;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Oct 1, 2020 at 7:58 PM <elver@google.com> wrote:
>
> On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> > Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
> > KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> > ---
> > Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
> > ---
> >  mm/kasan/kasan.h | 6 ++++++
> >  1 file changed, 6 insertions(+)
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 9c73f324e3ce..bd51ab72c002 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -5,7 +5,13 @@
> >  #include <linux/kasan.h>
> >  #include <linux/stackdepot.h>
> >
> > +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> >  #define KASAN_GRANULE_SIZE   (1UL << KASAN_SHADOW_SCALE_SHIFT)
> > +#else
> > +#include <asm/mte-kasan.h>
> > +#define KASAN_GRANULE_SIZE   (MTE_GRANULE_SIZE)
>
> Why braces? Shouldn't MTE_GRANULE_SIZE already have braces?

Will fix in v4, thanks!

>
> > +#endif
> > +
> >  #define KASAN_GRANULE_MASK   (KASAN_GRANULE_SIZE - 1)
> >  #define KASAN_GRANULE_PAGE   (KASAN_GRANULE_SIZE << PAGE_SHIFT)
> >
> > --
> > 2.28.0.681.g6f77f65b4e-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By4cn5sZeoeL1SkwA70kFcgneZiFgs6EwVR%3D7SaHgi5LQ%40mail.gmail.com.
