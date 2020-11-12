Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVXYWH6QKGQEZY7EQMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 407542AFBBE
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:05:44 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id r6sf2455202pfg.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:05:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605139542; cv=pass;
        d=google.com; s=arc-20160816;
        b=DyFyL2G95g69ULksiiaXsStQ1ALbcfcGlU5ZWjUnA/rJoq5jYlDJqVjY2oo4eRvCMo
         8Tc/cUtCK3ZFKFdOO5ZFq+pxlraMWpAqhsfje0sg4BgLSvUlUWKwt6DuenxfKFMzklSN
         0itCBIJDEc+DaGbqCRIeViJdS1hk+X47dSxzB0aHyEdT6rRToSA8PEOPGtuUVatZttwQ
         68Mv2e+RN20YrHOOTalqpPdLgFq00BwuiQuYHERSr335h881UD2miGm+ZZC2m8EpPpb6
         hxGYt3dfYCi8fLu5EoglXOOCz2YIqVtz70gO0NhHXuGXXmbHF3vNMZPvrJ/JGSm4mtDB
         Bc1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XyoJ1jn/oIC/LDglkKgDlQsvsArR9EO8N111eXXnm1o=;
        b=rdlpcoR/p/OVzqyfOod4KGcMltYu+EV+stam/h/iCkaPC8bB2VKsYAC5awvyCcmxC8
         hAeKBuB2RXqVHA2tE/81yA7qrr+1qP587WWgf2VR/LX/muoY2j1tIVTX9+Pfx/7Rwhw7
         BQIOVrR4zlvyNt3Q+5DxhZx5td7ocq8BgD4x3tpnyf+IdAv3fAPpp5NwEdA2uVWv7cZu
         hKGGGPunBkw4yWhOKsTqeXDpAxYZ1kWZKS9cpWGcUK+4CqQX6n6P8K0rLYHRcMoZNgcS
         WI5JltejWVZhDtjZ6eyHH5o2J/1EgoeHxcwjAKsxC/CWNBNO3ywQGT9J9o2i5QA9+56H
         DB+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a9rslGNN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XyoJ1jn/oIC/LDglkKgDlQsvsArR9EO8N111eXXnm1o=;
        b=D7ldit9PKnCSVU+ySbRJrwvJL1o25yy04OudgrEG1dQkHrdsA4IW0UBRpZR/hBctFT
         2CKaxMDOT+0GddUP2/gAziRaqmXsRG+Q4DKMGHTfzluNwd+98At0rfHXO7TZT17oIp4x
         SOiqzyXxo1vkvY5WCiH2V5eyBTaTJs7OgZaZUv4yi3ZQEMezIkXDFNLVL9umcZxFvZNB
         w5C3IkzZFk8PYvegZNsaIztHbAQ+OqvcGp1Dc89Ecv6CzIsKDfpfGYEbc+w3pqBmzXJ7
         UJxKk1PMIM8nP46YEE2BM3judunUnqLQqI8hCYP0FzlZDVideMwpo3a7n5P8ww73tpLc
         CfGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XyoJ1jn/oIC/LDglkKgDlQsvsArR9EO8N111eXXnm1o=;
        b=EOz7GadDD/RhfSA5v3SpknmXOrh4reZ+fG5cCUHuAeeYrg4F/Rd/PNDu/Ja3Txrqjr
         eGhrzzWDIWe+zBIkSF2Z0WdlBXoByBEuT1Bkrgvjqh9FNp1x4ZKG2ekVPcqP6qGEdyKG
         YBPF3BcYTelf6tdflVDsQlqSgRUSuc3Ibgedam6JFw6YUZtbsfItkMPPU7fmSRIvN/ow
         YT6eOps1ay7I/cxq78ruwDGL/PU0U3yTuQK/1kxyiizFoHBjngB3IL6W86g1bF/FCjnL
         xVbWpIGJE7c1DTojRwmh4Zne5WXD0M0+KHTIj0T8v5JykIg76rheNvfMpoj9Cm4RnkL0
         Nwyg==
X-Gm-Message-State: AOAM532RcY7hlcGN47qCCs7/HhCsLXiBH9EZoi7fkgIxWjMl9N1N8FBR
	HTzrTfiwp//ozEmOSraOWF0=
X-Google-Smtp-Source: ABdhPJw3QvdPCGr3cDNZlEIS97f4UHzTEr0+rIwo21CuLgGup49PJnn7U7X/VzGi3J5JpXOhTsiZCA==
X-Received: by 2002:a63:751e:: with SMTP id q30mr13837664pgc.294.1605139542511;
        Wed, 11 Nov 2020 16:05:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b4a:: with SMTP id g10ls546134plt.6.gmail; Wed, 11
 Nov 2020 16:05:42 -0800 (PST)
X-Received: by 2002:a17:90a:2e81:: with SMTP id r1mr6424204pjd.92.1605139541959;
        Wed, 11 Nov 2020 16:05:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605139541; cv=none;
        d=google.com; s=arc-20160816;
        b=zDJ1Ih5sNcljiD68U//KYc7yv7/kt9YAvpWyCa+fQ9ll7LgxtZYTd5iLbIJUf3cqFn
         QpeV3503G9k74N4QeaM3JUSgrgBkhF5uiBlzee3qkc/5ssQCWYSbc0/sWfh4pogZsNDg
         MsfQykCbJpA7xMtDEl/ncJgXLTJ+I3UHEHYy47mtrtNk9va8AQtYTLPqsoOJ5J8Dhr0S
         KCF4nxUL+6iIi+Ba82ocisM70oAOBmvJI5dqedNkUrAGqUNIm4rY0ii+tc8UoGT+PWET
         n6xaK9Xxs+UA9P6g0jcposfyMP0Pus6G6DzH9Y85hdnwyHOsySB6zT3YFAcuw5Efpfco
         piqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eIXncWLvf3BJhcwIlL7/HzTlh6QP9c7KA+O5cQg6G3M=;
        b=ejpvtsE0qdPu+yBcmKe8Y6YomPEygPULi+o9vexUQdRMOvpf6gJkFq+l/WZjrOeNYa
         kCnoYFdAq9+rAKMfgyw3TEsTzGBBGzmjmyjdNKmU0UjN9afUMcVAIV2vTTITYsvgC09B
         wFMZFYTGQJ6cU4B5tm5xWlfaNhGBM1gJrXJgVqq9sZk3tIheY8Kzm3AD3IhGChixIKxL
         nLWiHSB7JSINsPDTkPZk2A1Mpk/zeOVe6owb20RIxRBwf3CdwMNuaDIjsS9on6itMoIN
         pEQUmC8GjBZH7W1yx01w7cTQgbNzwFNOJtr+0jthx+0ObpkQYTeA+vothhiOht7z5uO3
         T07g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a9rslGNN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id e2si116667pjm.2.2020.11.11.16.05.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 16:05:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r10so2585653pgb.10
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 16:05:41 -0800 (PST)
X-Received: by 2002:a63:1f53:: with SMTP id q19mr24237607pgm.286.1605139541442;
 Wed, 11 Nov 2020 16:05:41 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl@google.com>
 <CAG_fn=VuM=4axS6ex7_MgCeZ47o+Scon1WuFGStF78T36sHayw@mail.gmail.com>
 <CAAeHK+xq2tuVYGOPx=_uj08Xwa_1o9Wv-ODrgN3yWXxAgEGV3w@mail.gmail.com> <CANpmjNPkUJreN0YRSWB743L-nrJvMObdKXdL_b9pBAK7AaLGVQ@mail.gmail.com>
In-Reply-To: <CANpmjNPkUJreN0YRSWB743L-nrJvMObdKXdL_b9pBAK7AaLGVQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 01:05:30 +0100
Message-ID: <CAAeHK+yf11KvZWkL1HCrxFT0R4VWH+Bz8YtnOYW7k6vm5c_h=A@mail.gmail.com>
Subject: Re: [PATCH v9 10/44] kasan: define KASAN_GRANULE_PAGE
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a9rslGNN;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Wed, Nov 11, 2020 at 8:05 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 11 Nov 2020 at 19:48, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Wed, Nov 11, 2020 at 3:13 PM Alexander Potapenko <glider@google.com> wrote:
> > >
> > > On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > > >
> > > > Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
> > > > the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
> > > > to simplify it.
> > >
> > > What's the physical sense behind KASAN_GRANULE_PAGE? Is it something
> > > more than just a product of two constants?
> >
> > No, just a product.
> >
> > > The name suggests it might be something page-sized, but in reality it is not.
> >
> > What name would you prefer?
>
> Is it actually KASAN_GRANULES_PER_SHADOW_PAGE ?   AFAIK we're trying
> to calculate the granules that we can fit into a page of shadow
> memory.

Not exactly, it's the amount of memory, not the number of granules.

Will name it KASAN_MEMORY_PER_SHADOW_PAGE in v10.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byf11KvZWkL1HCrxFT0R4VWH%2BBz8YtnOYW7k6vm5c_h%3DA%40mail.gmail.com.
