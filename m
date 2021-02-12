Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTG5TOAQMGQE2PU62II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BC3131A690
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 22:10:37 +0100 (CET)
Received: by mail-vs1-xe3e.google.com with SMTP id g10sf432703vsb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:10:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613164236; cv=pass;
        d=google.com; s=arc-20160816;
        b=gn4evpI7bGmTi1+aXWfL5C+7vRpyK4DDscSu9qUytWWX0trES8oV7TgCPR2q7+yHKa
         SoiA01VWbI9mzmkAv8NjMlFFJ8VnU8Wy26jMb1Aj4uKFClbONnpcSc/4cPt4yVaY9P/d
         1roYdZR6F84IV9wlOzjcsDeUfuhhPKSFbsNsVGsa9NDtwGBBrXDBsw6TTv4ePGb3RbG/
         qKlo+qq+vdCh23zuk+bt+/ah2/Iye2pqC+nSyomS3efpjPAyuk9326JLh6zWy5wv8vfE
         n3FK408ocZWIOa3zZsA2B1XC4pL58169/b9XWdaY3N7ozI/5rRUWTz3DnaeiSuuPM/Tg
         pB6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U18DRGgoTyFIJYZlUg+o2GeYXyFw2Gf9aGXbpUNsEJw=;
        b=OUBlQvZ8BCt5Um9mFXDbULbvYbDpzd3S/YwqpIuQJl7TIVCROefL5aKE39NceG5wbx
         TEJscR0g5WTXfHBF3QMN+3O6P7AafNeXpKSEzbfYi+VBJnURiWEY9ewW//3TbM0PoKAV
         eyWaRm3UcW8Fg/WNEMeFdV+74XJgq0RVvr3+rFSr7fIMq86hI98AaA/MiWRSiuZqC9Fb
         rVP+aMarI0DCzZVuyviqk23mvLVSYu07La6uIddHD3TptJpguzDDescoASfWeiXfhBW5
         k1H8xbKPFCnGYwMLdsHJOPmQ8V/xWOkh3quRK45iM9acaio/8ckL1lBuEUona4gVfA/C
         TuxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XXg0m272;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U18DRGgoTyFIJYZlUg+o2GeYXyFw2Gf9aGXbpUNsEJw=;
        b=jzQkFAObbBeuX83fu0pd/TDbEIlYcKK9MdvG/CxYfAxRardL2EYQrTljHmNBXEg+/5
         5LxY9GwCN/Y7W/dIgk2RJSGQR6PZwmpMoy3fYOWDMlpB7g8KaVh01tzswFunHz6dh4Jw
         rWUj3IiDdVJdQScsGVhIr8vC/6jDaCTrdOXl98o2DFkGqZsdjB3Ej+TmngNt7R2Ykg60
         Alj+UEOquNFV9Wa8NXLla6Heaw4fpLSLAiHrGq8olHJX2RnqbyM92PQTyMwrao/bxnGg
         axps5/0jKX+3TxYsNuVCXywcmGo1FevTz0mWMHUpW8ThjuoOPyMVRTF8J2xThbxATldq
         j65g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U18DRGgoTyFIJYZlUg+o2GeYXyFw2Gf9aGXbpUNsEJw=;
        b=f7KSwYcFeBwLqAAOGCNgqUu9N4s/erDrSYs1iz3B0BmteZi97VLiM6z9GJQv0FH8ev
         F6A6sgzTpIjhvi7LU9YfWESj5s2PByiMBCYZPvu6FRUcD+ThqCxFig89EDk513XC6SS6
         X8KERYnrbi8uhDMODB4wOaMSv6vHsgQhpj8i6sQzUsdLct9WO4ur53FPadJHQMF9+v74
         njp21Z7+PUY0OVTboE7jzRTr26vRT/aST67DjUokXbuQrSjg4LTpEM18En4qzeXPY1Mb
         ty1xQyHIVcuttViusZfkK718PeyURACkIXe1GGw4HT3vVj7ePPsiAbdu9R2v0VjuW0A/
         nFlQ==
X-Gm-Message-State: AOAM530142yrNsztD/DAhWs2DyW2gBFDDwztraBptuTXnbWlhp3xhJbd
	6w/OL0EsOBL4zDs+CSV9IN4=
X-Google-Smtp-Source: ABdhPJxTwDcZmcLQ91CMnkv/khurEJQMC8Kc3z7l4ONbrQ4ytDU+4+YjvguXrLvgSqMugGh14G67Aw==
X-Received: by 2002:a67:df17:: with SMTP id s23mr3205133vsk.41.1613164236753;
        Fri, 12 Feb 2021 13:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fa1a:: with SMTP id i26ls1250322vsq.10.gmail; Fri, 12
 Feb 2021 13:10:36 -0800 (PST)
X-Received: by 2002:a67:eacd:: with SMTP id s13mr3146802vso.12.1613164236414;
        Fri, 12 Feb 2021 13:10:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613164236; cv=none;
        d=google.com; s=arc-20160816;
        b=abArJoMB5dfVRaGvOY+7nHnZG/8s4PPKlGqN53J/dcDEARZzScJuW72qrzoJhIsTwh
         3GBxRiG5L3i0iECIZlXF1VviCW9qvzC3hyuNa5BfnNfJ8ksv5bdoh2ggB1UG0iVr1u0I
         SUtswSZ4H2gKNtPZEmOlCPA2pwo4RTLqzDhXcL0hxZ8kvB5iNEmN2Sjy8cbAQdL8Wa2n
         16cCGd7EBdmtoSa1ai0lNfeK+cluc9e9jd3Z8rxr8HbQdEksZQK0AA+yXnY1/KlN0PH2
         qlgeFmo5t+aTBR2cWkziazMwWB9O3kvkwgkByJxviR4O7U1OJHbq5/YmAKXkQrnQxyNz
         piwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bmK+2FrtXJ1N8kjX/gksPRqXGNz83KFxwR+0lffrQZo=;
        b=xN+EbwAj5T09qL+N9/ULy2E0i69Fx/lAbmdAjuPHCgkcnCJ9khxlsrOWAVNjr7CW5M
         L9RoaQcJK9HjSMDlTuftuwrxmJyltlhmLm5vyq8Xre3W5gRV1Iw3fkv4Ov2zOz4R/Lq/
         Y5QBuxPthP4qCvBnRGsRcsT0gVX2qwZuRe0OKszEHMC5M2m2cAo30+r3Vg59KmKgCNMS
         guo/F8uCneVN+C3HE46N/YzFfGOlGiCMkbNt8MG8VQ1RiFF3kLQ3W6w40P85/tcVaNf4
         qwBkFRNNUYRAa8EaF7h0t4fUac/Ex9FhG0KEyN17weOqMuBoLCAiJ80mJL7FRwhRm6pG
         dNGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XXg0m272;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id j25si591764vsq.2.2021.02.12.13.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 13:10:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id j5so443609pgb.11
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 13:10:36 -0800 (PST)
X-Received: by 2002:a62:8cd7:0:b029:1d9:447c:e21a with SMTP id
 m206-20020a628cd70000b02901d9447ce21amr4821819pfd.2.1613164235762; Fri, 12
 Feb 2021 13:10:35 -0800 (PST)
MIME-Version: 1.0
References: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
 <20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
 <CAAeHK+z5pkZkuNbqbAOSN_j34UhohRPhnu=EW-_PtZ88hdNjpA@mail.gmail.com>
 <20210212125454.b660a3bf3e9945515f530066@linux-foundation.org>
 <CAAeHK+w6znh95iHY496B15Smtoaun73yLYLCBr+FBu3J57knzQ@mail.gmail.com> <20210212130816.cde26643a6b9b24007be4e54@linux-foundation.org>
In-Reply-To: <20210212130816.cde26643a6b9b24007be4e54@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 22:10:24 +0100
Message-ID: <CAAeHK+y20nuSLs1bQO2wyND5S1xFRDHNvvL07Jk8y72tF11O_w@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XXg0m272;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::531
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

On Fri, Feb 12, 2021 at 10:08 PM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Fri, 12 Feb 2021 22:01:38 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > On Fri, Feb 12, 2021 at 9:54 PM Andrew Morton <akpm@linux-foundation.org> wrote:
> > >
> > > On Fri, 12 Feb 2021 21:21:39 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > > > > The wrappers aren't defined when tests aren't enabled to avoid misuse.
> > > > > > The mte_() functions aren't exported directly to avoid having low-level
> > > > > > KASAN ifdefs in the arch code.
> > > > > >
> > > > >
> > > > > Please confirm that this is applicable to current Linus mainline?
> > > >
> > > > It's not applicable. KUnit tests for HW_TAGS aren't supported there,
> > > > the patches for that are in mm only. So no need to put it into 5.11.
> > >
> > > So... which -mm patch does this patch fix?
> >
> > "kasan, arm64: allow using KUnit tests with HW_TAGS mode".
> >
> > There will be some minor adjacent-line-changed conflicts if you decide
> > to squash it.
> >
> > Alternatively, this can go as a separate patch after the tests series
> > (after "kasan: don't run tests when KASAN is not enabled").
>
> Thanks - it wasn't obvious.
>
> I staged it as a fix against "kasan, arm64: allow using KUnit tests
> with HW_TAGS mode".  To make the series as nice as we can, and to avoid
> bisection holes.

Sounds good, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By20nuSLs1bQO2wyND5S1xFRDHNvvL07Jk8y72tF11O_w%40mail.gmail.com.
