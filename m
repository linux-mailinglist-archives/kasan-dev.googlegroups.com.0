Return-Path: <kasan-dev+bncBDW2JDUY5AORBP5XW6LAMGQELF4255Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D7057276A
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 22:38:25 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id c19-20020a5ea813000000b0067b9a1a91f1sf2852636ioa.21
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 13:38:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657658304; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnianOFUlNs3e/zJHoyUwFBBfTvEJo4n4VPKSM4vdI/uQQOdxa/7Iwvoti6tpME3MY
         BFnmQ9xU1VCscBRNLe4mOK83zc6rnL7ZJghLeDywfYbpOSpV46aC1/1mCovGmxPJJrKw
         l9WSgzKed1TfHv/teifT1zdYZ3DpWwCu/HHia6CzO6kQlJKFzOyd0yGo/Wp5pvTThUQL
         nMZPR3PCK6I11OTDY0N+F4gnI5zKylsMzWUkdAhWJB1315YmH71hv+u18fFqB9exhIJk
         NLfAXElA5zc5Xr4sa1fwGehiL4hpdYdsg9mBtyZ2vMGbCBQDMgI9Y9ZpUMJVkTIasWbm
         5MiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=R0J3UEPxnrNiSrZ1RhbzAOvmGRoEwz5/PXJeLHoUu8Q=;
        b=DkkSu6NJB/1OxS4q/7JIVW0y4nPiEhE+ln7vr1+yTIfygdyYpBB64Vyd8IBa5S9gAG
         nn+04QsrwvxROuouQ0oC6J6JfIffVPvlscg6rgMjj/sE6oVrL5gpjZMWsPoDNUnyRzu0
         x5LhZB2mu6mXJ9PXOiEJ1Z/ZUuKar0AcPlDllsAlCG2CG2FrxdCtft7+ijGZh0+iGJrK
         4Ns7L6tVTYeLCLel2hc5HIEJXXY9kh2vXB+WxdowQFtPYtX2lpcagkmL3h30xFP2cgZ2
         ZFeFDtFp94Tbncn3XhGCYnc/uJZBVreUU2fq0SqhQftBm6oCgP3uMiwuzuQ6BW3/Ed7F
         FajA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=n9RIa554;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0J3UEPxnrNiSrZ1RhbzAOvmGRoEwz5/PXJeLHoUu8Q=;
        b=KQUWqs2SnlJx7V5WGhLLsrugdh4njxMLOQjtNCyTopvHSRJKsGwzEnicr7HEX0p7fF
         qJMsUYOId2N5T1+yhRHtwsR0pqesQX1zLho06rgkUC8J3i5T1Y0WCVptEo6ZlupCxQT9
         +Cnh8dRZ+hSG/4xu6Sa5825MK4sZ30P+X+iGoy6rYefPAIipPsJxDEi8KdU9DtbGrLkb
         s6MVYpmnGfjO+DlnqychiJin6Im+3lTvoG71tjh7RaUk6NRyyank2N/EsDGaqkR7ifx3
         32qhq7O/iRi5kPk7rniWBV7nKMUxdJEhyTvJ3HnJJP5X7zi7os+974Eo7OF8gumP6Edi
         20oA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0J3UEPxnrNiSrZ1RhbzAOvmGRoEwz5/PXJeLHoUu8Q=;
        b=GhZj1SQ+P2fukZMufibnA4A+2KMUCn3uLDFO5ZgUrsZIeA8DcU3oDQlIq6eNURfxuc
         DNDlO0e1/hFWxMbh3rnXB09taUjrD2lu8ZZ8i7yT4ZZGHvWy8Wlk1DOmZcFIB2vYpOmc
         qQi3SRc2XdHJl5Trm7cUEwEHRgQiNwVFf3p3k/iYXwcWEWgope7M3b4wpC1nVcTVQVw1
         wtxA6CdRBoUB7fh5G6NQBbGHRLzLCidPjoODTJcmofdl6xBevKGyBcX56lnekEmEITY8
         FGzKRLjwk7Ebj61omghs3u7Ajc0eGGQ98hVDOBgfBK7miOyUEGF/rsB526v6zvru8BJW
         /+Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0J3UEPxnrNiSrZ1RhbzAOvmGRoEwz5/PXJeLHoUu8Q=;
        b=IIctBRTOru0tQyXR7rKPxHzmgJ3B3mm/u6ZAEcuctJ9sD3KxVxUUjMxCyOlJhHh+fb
         pPSN94PWQmSQ4D9jGObFdca90qMtFriCZKFtIR9a012kbO8LrTGzGlGGSV1SUIIf3AjK
         fYVg25v55QjKF6Sv5jCWIjIxgYpcpY18f/nu+Lju3nmxuwLZiNZsbALtHfXicBdfLMMc
         0ibN3CXmsBAvplGKqVrlQlHyNwe71DgaOEjROVMiGA446Abjnw+ewGtodvSa76ds4IFE
         LE66y9waoZBno35JspbbfXDGOi8VWzELhOQcXTJySB7BY+FBrPMQ3kPsj2Zv+yC7lLDX
         5Iyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8MPlObIo6kuX0K/YsaiHN/8cJh+vzNfge43bE9BzxqE/hLiQNd
	a9DUlEWEiV9KVQU1oJZPge0=
X-Google-Smtp-Source: AGRyM1t3jg21gqYKcMCFEtjZjtBKZLNyVJQGnVTXiWJPPiWWSVnswBj7tlhqXUkHmahY2tSl08WpIw==
X-Received: by 2002:a05:6638:1509:b0:33c:aeab:54be with SMTP id b9-20020a056638150900b0033caeab54bemr14331086jat.111.1657658303837;
        Tue, 12 Jul 2022 13:38:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1a4b:0:b0:2dc:60eb:c369 with SMTP id z11-20020a921a4b000000b002dc60ebc369ls545892ill.8.gmail;
 Tue, 12 Jul 2022 13:38:23 -0700 (PDT)
X-Received: by 2002:a92:8748:0:b0:2d9:3f81:d0b7 with SMTP id d8-20020a928748000000b002d93f81d0b7mr13173477ilm.310.1657658303363;
        Tue, 12 Jul 2022 13:38:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657658303; cv=none;
        d=google.com; s=arc-20160816;
        b=AuzzAw9oLvgGYnPRvbmDhxq2OtaZxPb5HahUOS6ZLC8eqIOIcBiaZWsOJ6flRoA8DG
         ws8fuERWxfrl/dw4Zj72hvYAdjecKoal8+Xfykc8gK+6zkdLGrR4qGlwdm+pCmlw3bC2
         /ohha/ZEfoE8tDEAUqumkeYP0SY3if276XEWsuYdRYtXWfBr8ol3WRF9SvEHFo/EwLYO
         k8D/RhxjpkPjxMrVFexwQCa8s0DJ+GqUneY8qZrUMcDVjTDzvzJmYoqMg7HxLGn8nha0
         GOni0O3XHQvKIxkSBxT0DLzlF8QdNLsTiNfRdLvHYrDWEy1GLI2IkiXeiA9xPVInjgY9
         fs0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gtA9X+fkjEw/LyXx7cshYRPvYgSQ7aQHvwyjYuYISkY=;
        b=u45/Bn0vcbDvZEYxDo2EohGQfvBFk4pRCalve8Q+7ehF/Zz6OzqFqhL9Hb4cqMfHNh
         c259KjzAwkWm60oercToH8ag1aJFd6a7oWTsGll6LQE+QVo+CwlFqCO2zhgVahbTXFDm
         46NGO1JTc6U7/7Lk5E4NfYItfrjNd1+UfQ7/6phagC9TSTTnaQWQE0YQG7DN0NtP/ja3
         DOmFRJhspAZ/psABMOjOqX24C1AAFDpoiVLCyx2541ET+vxcz/GdTklwS2oCx9Tx2/mk
         nGkJygvpi0ZKM4o8SHAHM1kQDW2CGunA18+a2SkOABQzLAYl/thdwBl/u7PMCcsBKRJC
         6a0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=n9RIa554;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id b13-20020a056e020c8d00b002da79182b3fsi300097ile.2.2022.07.12.13.38.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 13:38:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id z3so5565253ilz.5
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 13:38:23 -0700 (PDT)
X-Received: by 2002:a92:c562:0:b0:2dc:7ca1:a54c with SMTP id
 b2-20020a92c562000000b002dc7ca1a54cmr15605ilj.28.1657658303138; Tue, 12 Jul
 2022 13:38:23 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <f7f5cfc5eb8f1a1f849665641b9dd2cfb4a62c3c.1655150842.git.andreyknvl@google.com>
 <5949bc710889be1324d5dada995a263fd3c29cb5.camel@mediatek.com>
In-Reply-To: <5949bc710889be1324d5dada995a263fd3c29cb5.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Jul 2022 22:38:12 +0200
Message-ID: <CA+fCnZd2tND0CN1kVXt2ZpqtypDuQba8gXVMyL-XnLd+61X1cQ@mail.gmail.com>
Subject: Re: [PATCH 21/32] kasan: simplify invalid-free reporting
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=n9RIa554;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12a
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

On Tue, Jun 21, 2022 at 9:17 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Tue, 2022-06-14 at 04:14 +0800, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Right now, KASAN uses the kasan_report_type enum to describe report
> > types.
> >
> > As this enum only has two options, replace it with a bool variable.
> >
> > Also, unify printing report header for invalid-free and other bug
> > types
> > in print_error_description().
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  mm/kasan/kasan.h  |  7 +------
> >  mm/kasan/report.c | 16 +++++++---------
> >  2 files changed, 8 insertions(+), 15 deletions(-)
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index e8329935fbfb..f696d50b09fb 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -146,16 +146,11 @@ static inline bool kasan_requires_meta(void)
> >  #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW *
> > KASAN_GRANULE_SIZE)
> >  #define META_ROWS_AROUND_ADDR 2
> >
> > -enum kasan_report_type {
> > -       KASAN_REPORT_ACCESS,
> > -       KASAN_REPORT_INVALID_FREE,
> > -};
> > -
> >  struct kasan_report_info {
> > -       enum kasan_report_type type;
> >         void *access_addr;
> >         void *first_bad_addr;
> >         size_t access_size;
> > +       bool is_free;
> >         bool is_write;
> >         unsigned long ip;
> >  };
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index f951fd39db74..7269b6249488 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -175,14 +175,12 @@ static void end_report(unsigned long *flags,
> > void *addr)
> >
>
> Hi Andrey,
>
> Do we need to distinguish "double free" case from "invalid free" or
> we just print "double-free or invalid-free"?
>
> I sent a patch[1] to separate double free case from invalid
> free last week and I saw it has been merged into akpm tree.
>
> [1]
> https://lore.kernel.org/linux-mm/20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com/

Hi Kuan-Ying,

Yes, thank you for the patch! I will rebase my series onto it.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd2tND0CN1kVXt2ZpqtypDuQba8gXVMyL-XnLd%2B61X1cQ%40mail.gmail.com.
