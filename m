Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBPHWD6QKGQETTAKX4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C1E8E2AF89A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:55:02 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id s201sf1967391pfs.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:55:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120901; cv=pass;
        d=google.com; s=arc-20160816;
        b=xdI//tBODAkz4oDby1lqaY3Y4rGihRQELJScyCDhvPPnMsvLmC3PqzpX/Xm5vjw6nN
         JtRDC91bh+DAYdnDtXipTHB3dSrjnNrtCnE/uSw0CC9sukI8ce3kxW1sjPGetvtcEBRA
         XbtjIdM47RkLhSFdTZuxUi8ISti8pW6nySINu5Lub2N+PK6mItuGlRbtmgZNXkPNas5s
         DxbUw2HixFYVteJnMFAJvhiB094t4fbj9tMmW+hWz7Pu8HLGewK7Yjh1pP5JrpipQkGY
         9y9GR697k6t0jdYMWhJjkjQEOrAD8pPoGep+gphLQwqilrg2Jzt1d5TtN2BTb6EVLpoZ
         I9nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZHs1dBtZSUaXmpWi76sCjO/DcrYOy9lviBMU0RTrBhc=;
        b=bf8yChEUpRIBW1/OewdeaYVDckezQv53YyFRahegzdMxrTkMmxhmP8IO3USgX1DTqF
         R1dOrWcvTurtqUip6BKj98uYRvs7L6vt5RQJIR4sS5Yf2ohFeU3cwY67wQMVbfSV6y9l
         TaJ5Bu3lbSn2vHF6/4wryKTVpqeB3xA1q68d3VXgvgE/Ks97wXyBTJKB//XBx2nlEwZo
         Msoy4pBk1QkY/ETVZyQnJ3kD6LVxsAgda2ppA3UuoEPt4L9mJn/nJcx4ZhH3S0LVadYH
         p9A9JyglxlmwI0OuCwA6OEM2TrmeSNljZ7ebaqUGd3iIVTgKU4HZO3tgFiVdkcoFnly6
         7JHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OOpFfVi/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZHs1dBtZSUaXmpWi76sCjO/DcrYOy9lviBMU0RTrBhc=;
        b=NVwkxltMIEz8rRfOC+8tlO4K7d4Fbc1HoVi+XBhE1lB3ZquSVzKDbpT5PhdsbnhLBu
         BjWHX3OHZtQQxWijw2mUvsO1WNmsXsSPLmZU4huEuqf4hDM004ZkFGm7sPVBgfXipwUi
         xphFYM4illHMTTYnrFf2lWdl7ujkaLvJZkOfOm0/dU3kGoKusSogjCqUm+jN533NDJJe
         TrnDinONqlvweG+g0KwZozKKpamSo9ei7Py4icw0m0fIrOSOQV8g5dmsG4wh5FxglIIc
         53jDIlVUnMgA3jLpDx+S0MF2YUZ8M+/OWVcIojkEu5GfmZdyttDP8gB2KFzRuKZm3ass
         qODw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZHs1dBtZSUaXmpWi76sCjO/DcrYOy9lviBMU0RTrBhc=;
        b=Bc8N31Y6w6ltEO5NH/ibniC+qAgLmENtcyL0jgLbQqIM+0DKmbv9GDasNf/uRuuT14
         Thjhgi+/UpMdB4NO4r8HB7R4s28Z5DmR5BM/XizU9q6+azjqmCS4mHkVwklfnJiymrRu
         G/VkkfN2tdNv3nU0XvoBHtA8EHes0ZTGerx8I+ShCLAAbixwVw3HweqL5FmDSUutsFdw
         Z+TbTJtCF4aB5n526xGQegxwTzL/p6EcB8uAgrPY83r3fvc9n2lkNNJR8Q3s/UXvxfR1
         4MI2Mm2HCobzxJxWi/pUG/Wnr/w1WQuI+kQ2Rbbu6Rqx6BttZ77QVeDMfCIgbXUg8Y51
         NcNA==
X-Gm-Message-State: AOAM533Upw4Bi7NOcMi/iCz9luyVdbYHNteE0aRm72gvLGG14cTauwvJ
	yao4jbngT49X0+z+RXZivsM=
X-Google-Smtp-Source: ABdhPJyKoaVH7aK3tyrNElearNkZvg8GDcKwNj7k+Swodb3Yr8V4Rytshw0ArrahSltsKkn1r9bDWw==
X-Received: by 2002:a62:d114:0:b029:18a:e114:1eb4 with SMTP id z20-20020a62d1140000b029018ae1141eb4mr25014124pfg.41.1605120901485;
        Wed, 11 Nov 2020 10:55:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd82:: with SMTP id z2ls91887pjr.3.canary-gmail;
 Wed, 11 Nov 2020 10:55:01 -0800 (PST)
X-Received: by 2002:a17:90a:c693:: with SMTP id n19mr5323293pjt.69.1605120900909;
        Wed, 11 Nov 2020 10:55:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120900; cv=none;
        d=google.com; s=arc-20160816;
        b=paTNXdonJXwNFHtEOXBtk85wnGo+ppCtV40o3jFnP7DxVBphJ6WO4rChNgCmjLhWCd
         E3qBty7OOynKg2SoVFO3/nr+Uz18S+sjBD+t394VqTREAUANeM5jx+s1GAiUMhLjuiei
         4fFpXHyApGbH9jv25Ym5qQe0+dNaUaZPEdKKLtCyHSrOgI7O1RK3ik7LG92Zvp/kZSzh
         i624pNfAmVI7pjmnixbr6iglnZUqBMMZD5yxlb2TCNG64hsdMqaTUeEhi4lTbayjwP3n
         YTbN051UGiGFrRZPSX+4yFYrnKeoKwRVPCfZ2uxbIBGdV4xzqZuig0muIZJdcO9REsRb
         ZagQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6WeV7hUrwro5zFQ6cbjkRFYCH8+pe7+r1CSRKZroL8E=;
        b=JsVYAstQxepbQirFY6A1LSuPDv758XwuLO23BajBC3eMqFYubNCvRqL6bi5IQxhe0I
         ecbp6gwkMPy14OEhF2Z8D9DDs2h+n3RXQA//kfAe+95PreT1lkEIaE4NMUt7mN4owAKv
         gA/I1c8b1+EqsL5iSsYYMfeJAVgAhA1aql7LHugOGrPGjSePdkShNYjhFO99sOKHb/pr
         tEzJxhSLHCBkAQ/GtkO1c2JYigNv88OYvBCAkGy37KrLNWj5zrt6h1Nbmhfai2wMi453
         UIf9oQdhInQ/jG/ipS4QT42I5CiIsMrIiEpG96x6mSMZUpetztnUBU0lnYZV+q5Krh4X
         VXDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OOpFfVi/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id v24si164844plo.1.2020.11.11.10.55.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:55:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id z1so1432161plo.12
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:55:00 -0800 (PST)
X-Received: by 2002:a17:902:8d95:b029:d8:c2ee:7dc with SMTP id
 v21-20020a1709028d95b02900d8c2ee07dcmr2128379plo.57.1605120900544; Wed, 11
 Nov 2020 10:55:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <e9077072bcdd4ccaecb1c84105f54bac5dc6f182.1605046192.git.andreyknvl@google.com>
 <CAG_fn=XvXDe=+wuBNBq=fmidZkghNx_g6RbHRjgMMa658_1LXA@mail.gmail.com>
In-Reply-To: <CAG_fn=XvXDe=+wuBNBq=fmidZkghNx_g6RbHRjgMMa658_1LXA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 19:54:49 +0100
Message-ID: <CAAeHK+xoPQ5sVFVf2aRqcLJX8d9e7t1sNAF5F=gwTArDVN99Aw@mail.gmail.com>
Subject: Re: [PATCH v9 43/44] kasan: add documentation for hardware tag-based mode
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="OOpFfVi/";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
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

On Wed, Nov 11, 2020 at 5:57 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Add documentation for hardware tag-based KASAN mode and also add some
> > clarifications for software tag-based mode.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Reviewed-by: Marco Elver <elver@google.com>
> > ---
> > Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
>
> > +
> > +Software tag-based KASAN currently only supports tagging of slab memory.
>
> I think the reader may confuse "slab memory" here with "memory
> returned by SLAB" (as opposed to SLUB).
> Maybe "heap memory" is less ambiguous?

I think heap memory isn't widely used in the kernel context. But I'll
clarify this part in v10, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxoPQ5sVFVf2aRqcLJX8d9e7t1sNAF5F%3DgwTArDVN99Aw%40mail.gmail.com.
