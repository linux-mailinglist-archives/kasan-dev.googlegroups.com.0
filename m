Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJMVSP5QKGQEIHHGH4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 87565270049
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 16:56:38 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id h8sf1799767vsh.19
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 07:56:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600440997; cv=pass;
        d=google.com; s=arc-20160816;
        b=ePimTrIDkweArnHEnDvTl3LLtn1a5ho1o8v8Q802oOyyMo7RHqfudTw+LEgDODfFpg
         0DWT6KTnJqpDvpdq/xgCPtEGCYkmd90+2RfK0lLP6evUi/vbglJTuoMDo4kRZx/fpdSu
         5ldcJHFa0gNMkRX85m4LL8ZlbVEMsH08RraQwYCK814Z/i8fqSWnSMw+GsApemMp9wwR
         bHuekq6emUWa4wUVsI6q/I2vRPDChCIzWckpkAB31UowlqDjaFjUE99Jwapl9U6LOEzI
         9BUKtHpBa0FGM2Ht7dUvCY+70JuwNqA0I229D+PIFRQSgBi2gzQ9zpotC+Uuibt1fMkw
         8WJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+Y8k5tKHuW21WC/ELkBknBRscLakFLr0kOW50Spkn8s=;
        b=Ar4WYZPz7AWSG67JiZ2lHBiArO1GP3apT0UoIS3pEfjpO7Kxp+Oe9SAZCa1YoqKMwR
         YHThchTqBXX68mThQn6AKQO9ohNDacHsy+CBbb6tWDlXOIvpT+0/YCrXKDQQzKGsJyls
         GD6t4P3qddTNliHP5tM1Xu7UZbyVWt4SYZ6zi3sisJ5TElvHAepwBmlALJ5+xGOT3wAD
         2sh4oo5YS+TuFpqqR7OiwKIuAQUnZ4jvSYwFX/sKPyOklhVjVF6yq5PURZRTksrDD/hH
         Z6qc/FIl4fOfvQlQzkLHQamIUSAnY/7QmCyepg75Uv0SdaqGImTlsRBRA1CvBxme9TIR
         YPiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W3Tpv9wP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Y8k5tKHuW21WC/ELkBknBRscLakFLr0kOW50Spkn8s=;
        b=h85b+8/tEPnNrLN0kuoGoRXt2Qe2fIK1GgAWwCx7ZAmpAgO3DLSB5u3pIx/m1Acfoy
         0EfJ5of31FFFEoDG4fEtoh8Va2lwAPqSiqKkjx9Vr1o7yMUsvuJ/11ktjUV6qPK3WeD+
         3O/xSRsxgdILjFMff1i1ghWSxyCKfccsUQ/l+FMbtdcNUUOLQRdR9NGolXju469uk1K4
         MVIX6AHO+3y2BPqQDlrGb0y6q15QLnJBmreKM2prQ124zbmKZKfXPlcKzyqVoKVT5tJv
         DE6QmPErOlNdiFPS0Fdz1KKrRYzz9DjaWz5ALz1IZ7tZxMquWoBasqbUYjyRN4NTraUG
         EI6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Y8k5tKHuW21WC/ELkBknBRscLakFLr0kOW50Spkn8s=;
        b=Vlm9g+Kppc412nK5EzjQQgw/H6URtGdwJP1x8CkYA/wF2SBAnR0oU6LqebulRVK4p8
         EtDWvDZDl5QHioHPQXhSDWlFT/CNWIpNIqF+wonlA/mqBk9FrnPy1hkxsZUxfuvuCGBo
         bS7F9/KvfWIyV+EqcEpQQyV57ykKDu4ZYs4U4vzNr/1Cow9BzYL6u+mjo2eUQGccOf+w
         DSjKpwFMUBG5FXk6b7qONe28qsz092GpjJX2RKO1kAfWtswmkmpu/3NJinexb90yb+ZY
         XO5ys4NFuYC2dlMHfCHNVlQm22gihn1KYPxB5X9x0Q2O0U9A0F3sW+/H6xN/fzF+G+7v
         y+vA==
X-Gm-Message-State: AOAM532cZbOfleQ/kGaIEbxTg2Dsd+CIkcUtRV4X4JI5DxvJ8Vvx94is
	GXjecm9BMv1bY+M/o3p6FS8=
X-Google-Smtp-Source: ABdhPJxAHL70tgB3632drJ2kLx55k8LIDKXj8ZWhpwRsjgXW105D64p94YNgdTaGA36woJgFTlW7tw==
X-Received: by 2002:a1f:17d2:: with SMTP id 201mr11686807vkx.22.1600440997452;
        Fri, 18 Sep 2020 07:56:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1057:: with SMTP id g23ls396742uab.3.gmail; Fri, 18 Sep
 2020 07:56:37 -0700 (PDT)
X-Received: by 2002:ab0:6542:: with SMTP id x2mr16332184uap.127.1600440996940;
        Fri, 18 Sep 2020 07:56:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600440996; cv=none;
        d=google.com; s=arc-20160816;
        b=PwBTjbKTeweRDwJx9M57mjiDj0Yu3tInpCNJXrYZaWAIL9ne25C4VyYyHnhoEgTYtc
         r1IJdrq1e/ENjzSKlVxBe3ivZ7x2c3W8xLZWFySd5U5BU81KgdtvXefFeq4IQx2R/XvV
         odDbr+XkFIo+Eb95TA/q7UsoU1Y/l2meLxFxT4/+9dQePdtKIsxVHvQojDHcgNqsCXXT
         M3r1IJy4PLWNtQyWYn8GxGvbksTKKEaHA/MYaNZ/D33RlYXF/K0hwzzB9/5uEnLGo6T4
         o1TWzkZon6OkUYbTMF6upYZTSsF62L9dliLd6cv1w9F7McSV6e2gEsDM0hoOPanvoB7U
         NPvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=84mJPr8Gpr4/Tq1Lxh29BXusyQ2UCdZanSBlBtKi1cQ=;
        b=A07gI4SrLAn2WXVBTiPdRwIqA94jY6SDhSHtWcCYaQwlCV03RPLemPM463AfwHDOa5
         aomssfk415OU21QNLGEKP2Y7zqsa0HIXZ2R4TuAbcM9/qhzYtucY994tavUtfDu/iRct
         Fxchmj7sBRMYqMEefv5eyqISJCBkpHrRgS6KoxLvOSqKSiv80gZd8zng/k3VUtIBLjmz
         p0EOE8eTi1DhhSJq+BRczT/Rr9031h0XKz3vw0UM5J/bEEELAupyXo1ZocxjeXwb2q7A
         suo/DWJ/NFjIq9/ZxweuGIAuwzVBabFo9zIjGWaO67nTNPY1eH/imQfy3tvcMzX3wrw/
         85iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W3Tpv9wP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id m5si168500vkh.4.2020.09.18.07.56.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 07:56:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id e4so3107065pln.10
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 07:56:36 -0700 (PDT)
X-Received: by 2002:a17:90a:81:: with SMTP id a1mr13066299pja.136.1600440996199;
 Fri, 18 Sep 2020 07:56:36 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <272b331db9919432cd6467a0bd5ce73ffc46fc97.1597425745.git.andreyknvl@google.com>
 <20200918145541.GA2458536@elver.google.com>
In-Reply-To: <20200918145541.GA2458536@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 16:56:25 +0200
Message-ID: <CAAeHK+w-RyACkoeKXSXaLsZWDRQ-cy3oGFSTJ2J=Hb3CUQnWHw@mail.gmail.com>
Subject: Re: [PATCH 03/35] kasan: shadow declarations only for software modes
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
 header.i=@google.com header.s=20161025 header.b=W3Tpv9wP;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643
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

On Fri, Sep 18, 2020 at 4:55 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:26PM +0200, Andrey Konovalov wrote:
> > This is a preparatory commit for the upcoming addition of a new hardware
> > tag-based (MTE-based) KASAN mode.
> >
> > Group shadow-related KASAN function declarations and only define them
> > for the two existing software modes.
> >
> > No functional changes for software modes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  include/linux/kasan.h | 44 ++++++++++++++++++++++++++-----------------
> >  1 file changed, 27 insertions(+), 17 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index bd5b4965a269..44a9aae44138 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> [...]
> > +static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> > +{
> > +     return 0;
> > +}
> > +static inline void kasan_remove_zero_shadow(void *start,
> > +                                     unsigned long size)
> > +{}
>
> Readability suggestion (latest checkpatch.pl allows up to 100 cols):
>
> -static inline void kasan_remove_zero_shadow(void *start,
> -                                       unsigned long size)
> -{}
> +static inline void kasan_remove_zero_shadow(void *start, unsigned long size) {}

Will do in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw-RyACkoeKXSXaLsZWDRQ-cy3oGFSTJ2J%3DHb3CUQnWHw%40mail.gmail.com.
