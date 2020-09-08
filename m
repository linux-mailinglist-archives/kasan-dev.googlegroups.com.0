Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVEL335AKGQEO6RS6DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BF0132611F9
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 15:23:33 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id g6sf10629770pfi.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 06:23:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599571412; cv=pass;
        d=google.com; s=arc-20160816;
        b=dOIvXkhRvheA/Js7pQ0J8sLIMUl3oNW13brPintOd+wh9+vI1cdJz6+f0wvJShEKTC
         YueNzLBkVJn7pedBhaXvGehNASoNMrXbPx9DnHfypPrayNhNZ1ijIsLa3QQ9VIZqbLi8
         FzCsQK/hdEG+F8cEFLqSwD4Wgqzjfw0+YUN+oKW1DnoLhWFFqXyf0oXVUErORxyNuC0+
         la2iWQRsjeXkVbE0WhqJBmR68TAKW/ah5DgiYZxVkNIMMh32W/x3CWVJpBL1XPgML2i7
         MD9YU0DqzCzotxQ6d1UqbP1aiRGjdRUhXF+ReXWZ3Mh5enOLTMPtolkhup5KlOuaMHl2
         YP6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hWJUgxh8ivsaZHnbt0IHoWHftIfIKGKpWIxVcNfVnNs=;
        b=Avlpcx9a+zWYguGkZG2qI3yoX3D5uQJjs0B7OGw+qlI6EQKYiLGYfTp3r/d/pNdiXE
         u1P3Bi3x8C9bE8muT9iHLWSnykTqmBk3TDgXJ7cKaX1srkn3ZGkiL8fMyKkkCYMkqGkL
         cbKfI9HqNEvO9i9wsQh9B684QCE5XiIxnBv4ug8N4w1TtYZkcH0ElG1j0SWMEAX4AjO1
         UnJKVdRoAFh1eRIF+6qH8UOuCQObQjzv4y+2jfkDz7JbulzctuUfWFAvXRUvnBpPoZFS
         lo6DZ9JOcwgOhQKZwvMPpwS+lOqvUJ+H6TLR8h97L456RXrPs0WR81peAx1Qf48U8aWN
         MwFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BNRMmLHz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hWJUgxh8ivsaZHnbt0IHoWHftIfIKGKpWIxVcNfVnNs=;
        b=nz3NcsnZXvcwdaItMFiitYIIB1GVNcXN9lNR/TZMhfm9LxlcyZoLd0lSWwEVuNAG16
         GTcCKmnldDTdXTbpmcKwhEOWD8LgQ+D6uBPgec4CcfquMW4TqVk0q/m6iXAD5f2FkVL1
         Eqa/DHtprH3kt+17rZLjxF7n9ljFGFv3KEzrZtsTHXVCOVr7fEpeSbVdOtSTRECa9IuP
         jZL/KSb66WXqIkZGGrUrx9VIdzD2EU3QyRKIod8WOcZNF4YVsZAsFHae3OqOWHFaDGlj
         CO4SQN0kB9s9Y1NXHsN7+P3QTEE7FimUxbcT07f3bn6/Risx9KWMCMpTQD6PH6rzzY4s
         +Zbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hWJUgxh8ivsaZHnbt0IHoWHftIfIKGKpWIxVcNfVnNs=;
        b=gcXD7WRCZg5TlLyMPR3kvnBVwAhGFxSRTtgiP7wYFT0wolP7K7Ps6KUC4PlfN98Ex7
         y4Ft9b96WiBzhF2puzNenuFNfpW5ejdtmDdy9aAp0kEbJLYLm2qpT9TJRNVrKTa44yFL
         n5Rh4BJkQMTdDD97n2CUZVlIcIS1TSbcfVD/2AqSLo+H1DH6fnIG1YjtwmbF1I9G8Tyn
         zZK7R/Y+6PNX4OLy3xPPVd+nspBby+oL34LDw7hyT6fK4ZakeCITTVrDt1KF2DlUYfmC
         sKMiQna/S/TEAp083gNR+DN8HU1sY4Ns5VM1qzGocDvAeM8GssLJdTx3pkEP+PQvJOW8
         +pcw==
X-Gm-Message-State: AOAM530AevJ+R+tmmct+4JM5OmNQNOys8vQF6SvrWUYXsOthnhUNYGFA
	y5HhdIayQ/XpMzZAqJH60Zs=
X-Google-Smtp-Source: ABdhPJxBXRCD5WkW94tMkNO4NiyB3PaBpLmCnubfxMWp6o1qo9Vx5rQo/ANxwWJWFD5gpqZgga80mg==
X-Received: by 2002:a17:902:b18e:: with SMTP id s14mr17028996plr.72.1599571412372;
        Tue, 08 Sep 2020 06:23:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96cd:: with SMTP id h13ls6653711pfq.0.gmail; Tue, 08 Sep
 2020 06:23:32 -0700 (PDT)
X-Received: by 2002:a62:5fc4:: with SMTP id t187mr24435367pfb.34.1599571411926;
        Tue, 08 Sep 2020 06:23:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599571411; cv=none;
        d=google.com; s=arc-20160816;
        b=SYe7cILyy+ImN1atqKXfvg7VUvnnbF/aZUMBN1ShlsMUwomBHFH0fs0HIsjx5zHOyt
         t1XjUM+o/+ypQiUMvxsFk/2JOhHAy8FKPnntSfJO2YR9ncPoK6rMZlvN6B4KYSReP2GF
         LMUca1dWARXsag93opUQtakazCQgm+BJh9FePYaPREteoR3kvvOpkJQx9VKK5mx0PRyd
         RJ5FSC+WREMWmngf73yficOMDceqhAWfMHQsM6BYvGBkNMUUFqWhmKQUZCiytEhAjRVN
         cTjeBwDA+FAeUshE61FteB7SzkVELQPWQb9ykh5ScbodMFU/qA7kNe5aVP2CxYVErcP/
         k4kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7QJMDMbNmolR6AioGkNQtnG3AJr/WPDscGoTEPtadkI=;
        b=TLYhzqvXygOlDDZbLZBmqmSiuZWu5C8AH2bfMQ7P/w2aXdl/NmmU7rZj/ReSHkRZvf
         2/zKELxvoqj4qJk/7kkoPaJHf729OCblq5j4NLVNK7pK/9Cz60Aui0SilLmwDgHDGmSH
         HWFhHsCX1lcMKMkUG1AdgAN8TAwiftjURcTC5QUatdr0vS+b3IFyDBjphX5dXKBRiwCQ
         Rdp7pjMUWtBovtWrrwz6BXz4znggBxiakjI8FIuyjZCf0Ph+ouGmh3MlDnykh7bAbIJN
         V0SSd5ILVs3jtrQBOT/ZEC0UofuAxctx5FvP2cQaB0EQszbwoywUmDd6t3CjoB5Nu/O4
         P9Lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BNRMmLHz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id s60si319269pjd.2.2020.09.08.06.23.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 06:23:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id o68so10953997pfg.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 06:23:31 -0700 (PDT)
X-Received: by 2002:a17:902:b94c:b029:d0:cbe1:e737 with SMTP id
 h12-20020a170902b94cb02900d0cbe1e737mr790548pls.18.1599571411337; Tue, 08 Sep
 2020 06:23:31 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
 <20200827093808.GB29264@gaia>
In-Reply-To: <20200827093808.GB29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 15:23:20 +0200
Message-ID: <CAAeHK+w-NLfCXFxJNEQ2pLpS6P3KCtAWJrxAFog9=BNiZ58wAQ@mail.gmail.com>
Subject: Re: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BNRMmLHz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
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

On Thu, Aug 27, 2020 at 11:38 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:02PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> > index 1c99fcadb58c..733be1cb5c95 100644
> > --- a/arch/arm64/include/asm/mte.h
> > +++ b/arch/arm64/include/asm/mte.h
> > @@ -5,14 +5,19 @@
> >  #ifndef __ASM_MTE_H
> >  #define __ASM_MTE_H
> >
> > -#define MTE_GRANULE_SIZE     UL(16)
> > +#include <asm/mte_asm.h>
>
> So the reason for this move is to include it in asm/cache.h. Fine by
> me but...
>
> >  #define MTE_GRANULE_MASK     (~(MTE_GRANULE_SIZE - 1))
> >  #define MTE_TAG_SHIFT                56
> >  #define MTE_TAG_SIZE         4
> > +#define MTE_TAG_MASK         GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> > +#define MTE_TAG_MAX          (MTE_TAG_MASK >> MTE_TAG_SHIFT)
>
> ... I'd rather move all these definitions in a file with a more
> meaningful name like mte-def.h. The _asm implies being meant for .S
> files inclusion which isn't the case.
>
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index eb39504e390a..e2d708b4583d 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -72,6 +74,47 @@ int memcmp_pages(struct page *page1, struct page *page2)
> >       return ret;
> >  }
> >
> > +u8 mte_get_mem_tag(void *addr)
> > +{
> > +     if (system_supports_mte())
> > +             addr = mte_assign_valid_ptr_tag(addr);
>
> The mte_assign_valid_ptr_tag() is slightly misleading. All it does is
> read the allocation tag from memory.
>
> I also think this should be inline asm, possibly using alternatives.
> It's just an LDG instruction (and it saves us from having to invent a
> better function name).

Could you point me to an example of inline asm with alternatives if
there's any? I see alternative_if and other similar macros used in
arch/arm64/ code, is that what you mean? Those seem to always use
static conditions, like config values, but here we have a dynamic
system_supports_mte(). Could you elaborate on how I should implement
this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw-NLfCXFxJNEQ2pLpS6P3KCtAWJrxAFog9%3DBNiZ58wAQ%40mail.gmail.com.
