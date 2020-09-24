Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS5CWT5QKGQERG4WZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id B9C59277B1D
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 23:36:12 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id fs5sf267130pjb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 14:36:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600983371; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ie8vHG1E0JGhPr+n2WU1gPgx4fuXqD1OsnnoNbLJ6etvLBppeb7P/Tbn5c4khSw+g+
         ct00t4+sOiA0Gvd/6gayuO9kRBVHMf82D6RUtcSydvhbivhLHWaek0kjYSSOZmzpuhkC
         HUFO52nx51Y9dNuznFxpB2WgqfOe5rsMR1cuRLZLWaH6k2/OFuJR0tW4dZJtfqYBmYQl
         Mt3sRkKeaAxmyFfSJRUu+Fd1+m84g7XVUyC2CdF+ZqiDofp1uv0UG4LB8RwRbnqBXdSY
         RxNAB6ddX9Wl4k4Xu2n2m+MOjrIBBJXbMuHcm77qyeYJg82fpZGeCKDNqwf+B/sfg0Yu
         2Syw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=V70mwh/FgGU0FvWa3MMErHgYyqb2D9dwqcUMvH0ST3U=;
        b=jTqWZ4fyAod6rCXnGroU4336/DEfEe6smkJIOnxCr8CYMJdMeAcS/0BNYxy1PxVsnh
         v2A5Yr4zCZ28muwuoQL0SLLy70sF5lE4vJQJKmI5wLxMrnyKBxBoAfJ6ulQWJtaq71ag
         cmlWu/fUstiSB6RQ2vDoPsXKd6Gx9jgl3rMRM88IhjXSSXJ/WMszPow/N0+kt2V3kP1c
         9u1zEtG7IsAaXENat7ZCqLIvpXGqCADt6s/ZUNXKm5bDdJVNhlt/98VpBa9cmxTDIIFB
         hmGMY0B8j9YfTh4A0eOWJRHl0tHtIXHqEkU1dM3i+Ya+JQ33aFV+X06wmbeqs+ZcsKNV
         ToMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WKIXJIcJ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V70mwh/FgGU0FvWa3MMErHgYyqb2D9dwqcUMvH0ST3U=;
        b=rdOWZxbgsdQzxFqjy4UliecoeBzLl6/GCglpwxpyLRjNJd6jAb3GfFtvAvQp2IMx+O
         MwRq6Bw8iEtC7WW58uMUkS3TFgwsz5RPfm5YteSLoZBTu6hkYmBOCNZLGWZvfMaeLlva
         0B4MPKH0134mZ1bOke0iXe8dsw0J1cVlDvfUGgtEDoVG+BUmnuAnq7z27epeBc5bPla0
         FOuMbnwdcnFocsRPhy3PnFfW2KZrqHKXinjmtciKebeh5Qn7xy3jwK9D1YpHGPM7RIIA
         W5degAjnEWINk1zpUW590LW/Yz3/aFI3ETryzSFcHYADsh+f/8K6u2U21sKOSz3g81mo
         Crlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V70mwh/FgGU0FvWa3MMErHgYyqb2D9dwqcUMvH0ST3U=;
        b=mEYlkXk+q0/FvLCrRodteQZJOpClACEpCrAIz81E0sRY1qIjOL9uko90wkEgy17q/4
         RFGTUmshsoUEasFgAJG/oWytaSljQduqn3nk5YdaaBo5VoBktFz2FcFpqXvpcgnK0UeU
         0BvHZDigCc3FkSgLHQphfh+dfxksYnISugMci39JpRXUtMjZUbheBbI1k1L0hXpLBaWz
         F87UxXi3ISl1TSI1EIvL+22xkXeSwAilz7228Avyd7ySJqS6GGxynvLj5LeIkprhv+6/
         8uxQoX72p54MsswmSo5b/f6dbX/ps5pVEdhK9zRbjNBJ9hUHuFTzpcwSYuHMyydzq/4G
         eqHw==
X-Gm-Message-State: AOAM532Kd/h2t/wDcKQ515j37N6wOaVe/UYuF1EMY5Bk+1VvUPMdmxW5
	cUs2KPFcu3ToKwS7NQXUi8k=
X-Google-Smtp-Source: ABdhPJzX8bWO906pcbdecjFJQVCP3rDxemsNgMc2e5H8BRXPe1jYKwFjphj6CPbijs++hCk5Djk+/A==
X-Received: by 2002:a17:902:760f:b029:d1:f8be:b0be with SMTP id k15-20020a170902760fb02900d1f8beb0bemr1145068pll.9.1600983371473;
        Thu, 24 Sep 2020 14:36:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c050:: with SMTP id z16ls232709pgi.9.gmail; Thu, 24 Sep
 2020 14:36:11 -0700 (PDT)
X-Received: by 2002:a63:1a21:: with SMTP id a33mr870590pga.305.1600983370903;
        Thu, 24 Sep 2020 14:36:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600983370; cv=none;
        d=google.com; s=arc-20160816;
        b=JJAXGed1LlYIBeKXQ3KHhiwHf4lC3+zz1Kt6rNLIOUwTlRpo0qRFwcMuSrlg9D7WbE
         +sh8+HMLUadMR6/vFuJbQPltOBriwzaU6GERTAWg5l1v3GwdpKrfYbDlgz82P9gRKMtr
         TVxdWWRhH3rn+P6Cq9IMyHLlOZrqOWb4qIUFP20j/WUZ2+wQORLDYfv53DIGod5MxAcZ
         Vrd/9kxjk/C5/IHFw1M1znmZPzAgEmSAqwma2zthWdB0yq3H/mXfDpgzVpl4to1J4/DG
         nF+5o/+ou9eMRM/t79IikrBVEDpeost+zCudOwbw0kqLoy4oQbImX1khfF/u6CB+d2rh
         ieVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BvSPAHOajbMQLOM6/h2D7KmM/xxmcFLZr4eiztRedpU=;
        b=yYcmMLGGM0OjN8yGK51VAdz4TjTBfonlCm0DUuRYBSs0a+UlNZ0/co0hVBw/3QYHbT
         sSF6V0Ov9BX8Pnk84JNzWqveWNNfVximmOXMwU2nOBqTm3JsnVI+sLF8KGB9kdIxzDgP
         UqyUg/WycHrHJEpTDcbBlRX7pmgokYqmPu2X+1/yQHegcePIK4AyenHoL7G2Kd/1at7s
         fvvYYIFKdYdjQvhktf6dQMdw9gXbbujTcqLz3QTUBpdh39iQM8+cs6QJ3hmc/2oob317
         nvSBWSkKa5f/9MKVf5SzJTjgFbvRb4v9CIWqk8TELvX/55aHij8V5rQcmq3qbi6SlEHh
         dpcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WKIXJIcJ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id mj1si60154pjb.3.2020.09.24.14.36.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 14:36:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id k8so818759pfk.2
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 14:36:10 -0700 (PDT)
X-Received: by 2002:a63:5d07:: with SMTP id r7mr871225pgb.440.1600983370451;
 Thu, 24 Sep 2020 14:36:10 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <0a35b29d161bf2559d6e16fbd903e49351c7f6b8.1600204505.git.andreyknvl@google.com>
 <20200918105206.GB2384246@elver.google.com> <CAAeHK+wqzZJWWh+u3HaLvSAt=4SxaFT4JUgTqzMYcPNGhBFFBg@mail.gmail.com>
In-Reply-To: <CAAeHK+wqzZJWWh+u3HaLvSAt=4SxaFT4JUgTqzMYcPNGhBFFBg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Sep 2020 23:35:59 +0200
Message-ID: <CAAeHK+yce9oUVG6J6oofjGLqU5gLLx8b22cqF6AgVWXT778g2g@mail.gmail.com>
Subject: Re: [PATCH v2 31/37] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=WKIXJIcJ;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
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

On Fri, Sep 18, 2020 at 5:07 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Fri, Sep 18, 2020 at 12:52 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> > [...]
> > >  arch/s390/boot/string.c         | 1 +
> > >  arch/x86/boot/compressed/misc.h | 1 +
> > >  2 files changed, 2 insertions(+)
> > >
> > > diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
> > > index b11e8108773a..faccb33b462c 100644
> > > --- a/arch/s390/boot/string.c
> > > +++ b/arch/s390/boot/string.c
> > > @@ -3,6 +3,7 @@
> > >  #include <linux/kernel.h>
> > >  #include <linux/errno.h>
> > >  #undef CONFIG_KASAN
> > > +#undef CONFIG_KASAN_GENERIC
> >
> > Is CONFIG_KASAN still used to guard instrumented versions of functions?
> >
> > It looks like #undef CONFIG_KASAN is no longer needed -- at least
> > <linux/string.h> no longer mentions it.
>
> I'm pretty sure this is still necessary (something didn't work when I
> forgot to make this change), but I'll check again.

Yes, it still fails, as compressed code provides its own memmove.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byce9oUVG6J6oofjGLqU5gLLx8b22cqF6AgVWXT778g2g%40mail.gmail.com.
