Return-Path: <kasan-dev+bncBDX4HWEMTEBRB544SL5QKGQEBGA4ALY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20FEF26FAC1
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 12:39:53 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id e83sf4180284ioa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 03:39:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600425592; cv=pass;
        d=google.com; s=arc-20160816;
        b=y41VC3WSB0byKSzPP3RqDDynmiFLjQIHE3vCBVQAkWdZZYi9l5l+7OfDhVei+PHoxY
         qu/l6rjrIB1dCddsIJJ51u2sRjqnkMTV8EUMc54aIoHaazVFIoGUacIxc2IQMs1uECW5
         mZDhLg9Rq27ku0uxRQetf+LNQHl6XvAjwTuHq9XeNazzQRNH+bx2QZfUXFpFU6kRTUM+
         Wl8SG4+fVqdFbrpAt8ejfYbM2+aCIXTV/An/TZWpBBmIw9V5EUpY4e7hTrQ2nQTUDG51
         eNSY9I5fNiZEZmcilV3Hr0yvU6aijCERFbk3su/0IINfUvvBUd2Qs6x6HESuv6fiqY4b
         eFhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DoB+jzpjmGXTidwsV24cjNrMupLiWrESlGU9YLMy0i4=;
        b=inGXL7LqcyFIJ6EXYDjtuqNYuuknq6rMtnR6wg9OWLL3VoTQDsQij5Vi2qXBKJfElH
         pLSR+1K/SxwCIbNoQHNoHwiAnDmf7vzcCEFeET3Nj6kwgBusVkDmWHCV6wMJvC/lIU0m
         tSR9itBdzy0Z2Cf/smLA+gd+wJkL5OWG0CfbbSAEOGWq21q1Yr7y05spuUFf+3vcy+MS
         3IXWrwPwUIO0RsqJzUumHUB4SD3hv73HcvLFeqOOpACLR5snVjJS/TfpPp1cfdm5r+io
         gLaKw+oDLRu0qkrMpWnL3gxiOdJuw10R01IFfDyusbnvWjz9RbRWX92G3QfFls20xVlS
         sF/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bZzEE8ST;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DoB+jzpjmGXTidwsV24cjNrMupLiWrESlGU9YLMy0i4=;
        b=Ag4HsYruxgSUZkzDkN/V2YRP944PAEIliMx+gytKnSOv+A6TMyRL9p8wnJVwOvz92W
         m7zAaGHEIEJhx6fQGuyx82vh3p9ZHfGOx8MXVcdiQtQGTgK0Kp1rJ18LyY+lA2500kvk
         BdZx/xSR0AUIc5xycZRFhz3Ca8kfSXahv60VrHESTCEdVRWjDjcFiajLaGvsnMLPpJkh
         bMpOYjVVUqxE8dB4+uwy3WQIQvjYmUAieSV2AJGwApN5RZzSLWRnbup2Js1/qKDlraHj
         s/UUak5uVgDjdlBK4n7oMt4CluhG3WrKbqSFUQ91HjxBduvzjC72jUoZOC4ax2jvs1Qe
         nEyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DoB+jzpjmGXTidwsV24cjNrMupLiWrESlGU9YLMy0i4=;
        b=PmhrungTEjhuixGNsmDy1rqS5Jcpxiqb1SbKyH8TmjTXJG8ir2q8G8Y0FHs6v1w7pj
         jxW7xavMXXXnY43rAHWup8G3GxHX3UL42R1i5l0PX0eULAV+dV3RDJGyF2S5OHa7u+gq
         Us78Dj7E29zOMfPPc8/u4Ghj5Z/d97DREzdVdkSRRnpVqr/PkdFktNTMFVtUyQDpf8zD
         xfuVzR/VCxIhkB7Z0Ov0ppprxt0s46uhW+MoJVQIPUkr8y9PvDAKchyTe4bERy75vK3D
         4wZDfuXII00kUrFFh4++OdPfjao6BMtFgvXZETWZbS/zKTG/DfoP5QTpvIIN3O+h4EeM
         2KUw==
X-Gm-Message-State: AOAM531jI3XtO9rFd17SLsTPg/stF5r/X9PW/iVBbrLTe11CVUz4O91q
	LGJx0i4XE8OMrwcVJeJasuc=
X-Google-Smtp-Source: ABdhPJzLiKir+AsgvqvXId7xopdT83hI/ih3qWHM0TJwuJWCPK59b4QA/4u6pN2Od3TGaHzXCdOcVQ==
X-Received: by 2002:a02:9f0d:: with SMTP id z13mr29927103jal.60.1600425591935;
        Fri, 18 Sep 2020 03:39:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9d52:: with SMTP id k18ls877072iok.3.gmail; Fri, 18 Sep
 2020 03:39:51 -0700 (PDT)
X-Received: by 2002:a5e:a909:: with SMTP id c9mr26104507iod.56.1600425591537;
        Fri, 18 Sep 2020 03:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600425591; cv=none;
        d=google.com; s=arc-20160816;
        b=SjrDxbtsrXBw483erVVTgSZ5difgSE3cwidGtETDnFuO6JlbssOA8oXyi2DiumrRRd
         tlktIcHh8wp7Z2YemGpJ1GUxpTX+6CG8wrF4QSU2tW0DBkt5vj37n/uOUSn8nLPo9EWN
         6SCmL/8AQQZkNKNplUsgviE//jmarByiL9/kzefEKK0403qUGheGED+p/uTFrsTAhpCA
         jtyo2okRJyznF48RudigeRrC4TFTdo7o5i30M+zY+zJTRvaxL6zKP249Tq0rffxszk/j
         xMX564u6n3EdLPQtW86Oq4iEtVhdxCipDjJzHaOV8CHA04i0gZYomoEmh+QMZ37Fhx8e
         WvOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0BA74pq9Zk+EY0B+5KtILBM++vfiF9LClb1TtG0VGMg=;
        b=ct+ZhuFH7q2VMj+PU7mPtoogYIZnEVecArBeItvXkdA7KGj6MGknPPGickOaqWhnVo
         sLPx5IxN2NnmTouLsjgpMSYWD0BHVrlr/ypOFPbEOmo4jL6dmXlHlbOP3O0setToNr/T
         IGRCT4X3PcQoBln74MJcOzpg96ykSTpEokId7htRFTN3RWD73rL0o9bhI643C+mwuC4m
         YB95FhggB7kVL44pBTIIkvpoW2l38tntgh4Q15lzVaEZOfYi+MB2Ptv/tB6DHXzP7UoF
         7m32IHz0733r10XBefq2T8Yu2LuIUDfDhBKsqeC6AZafzokRNHMRoxfmu/xTyeUpHAIW
         kpVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bZzEE8ST;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id z85si186223ilk.1.2020.09.18.03.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 03:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id l71so3242240pge.4
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 03:39:51 -0700 (PDT)
X-Received: by 2002:a62:ee10:0:b029:142:2501:3972 with SMTP id
 e16-20020a62ee100000b029014225013972mr14985432pfi.55.1600425590587; Fri, 18
 Sep 2020 03:39:50 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <88c275dc4eef13c8bcbe74ecec661733dcbc67b8.1600204505.git.andreyknvl@google.com>
 <CAG_fn=Vuu-hiaACaoyvpo7RCzvk4faz=AANX=oyAKEJdHDSxEg@mail.gmail.com>
In-Reply-To: <CAG_fn=Vuu-hiaACaoyvpo7RCzvk4faz=AANX=oyAKEJdHDSxEg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 12:39:39 +0200
Message-ID: <CAAeHK+x1rPq_UCU8rCFhpqQvcT-cX3=-ccE77bwbwZViDfhvpQ@mail.gmail.com>
Subject: Re: [PATCH v2 07/37] kasan: split out shadow.c from common.c
To: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bZzEE8ST;       spf=pass
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

On Fri, Sep 18, 2020 at 10:17 AM Alexander Potapenko <glider@google.com> wrote:
>
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > new file mode 100644
> > index 000000000000..4888084ecdfc
> > --- /dev/null
> > +++ b/mm/kasan/shadow.c
> > @@ -0,0 +1,509 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +/*
> > + * This file contains KASAN shadow runtime code.
>
> I think it will be nice to mention here which KASAN modes are going to
> use this file.

Will do in v3.

> > +#undef memset
> > +void *memset(void *addr, int c, size_t len)
> > +{
> > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +               return NULL;
> > +
> > +       return __memset(addr, c, len);
> > +}
> > +
>
> OOC, don't we need memset and memmove implementations in the
> hardware-based mode as well?

Hardware mode uses native memset implementation as all memory access
instructions are checked by the hardware anyway.

> > +       region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> > +       region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
>
> "PAGE_SIZE * KASAN_GRANULE_SIZE" seems to be a common thing, can we
> give it a name?

This patch just moves the already existing code, but I can fix this in
a separate patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx1rPq_UCU8rCFhpqQvcT-cX3%3D-ccE77bwbwZViDfhvpQ%40mail.gmail.com.
