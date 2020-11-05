Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEHMSD6QKGQEV6MYNUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 874162A84D9
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:27:45 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id z31sf1645105pgk.8
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:27:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597264; cv=pass;
        d=google.com; s=arc-20160816;
        b=OcNJxXcRHgZNx8PIVUz5Sk/mVZPrzYpN3nXH4XDBLm6am5QmOfMc/0hV9uKMedl55a
         SJ6tGNXlFE1+7oDhU9hBVN81Fq+WRxPk3J6tJTXjdxkUp+CAv72emEygeRi+p0z2HqsV
         i6JPKC7+DPOdxG3Ta6s7ProaG7d/6yn5PHL/s+eQ/QyBZ57W0VeUQEEO2olWl9068Iwp
         AgEULl7RtbPxeaxiPDRejMxHpqCh7YJE3X2SsouS4zafsnzxRa16PqrBsyrCs42WDF3F
         BoUrCgMgwy6bdldyd2PGJAAbVEKsNLOENqsdK3wcsh2/QVftVi7Arkc6m5kXbTigGW2Q
         1djg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VnwiICJwkKrUBtft555aNTTN64Ctgjlip+BqnjufO3E=;
        b=F/V8BXTo0TVYgjYwDEe9Uozh/uTLuDgseRVLb4TtmigNaIpuhLnLpS5NhLFT9lsmU7
         SHHNgLLeU09ZVwE36ybRsmWTYFYPnXhF67lKqSTzBllrJ5HqjRQK2AIdZuN6MyBA+c89
         DYYcxLJ48QzmE5F6mQFqoaNySHdweDZct6yybWuO7oFlQZcZOfNi+3tAcqK3Upz3I/b0
         EM0VULXXAiKtrBpB4c06pCkwHYM77wGXEreCC19uj7ZQq6fgb06MmCzIx/VysiOur741
         YhaC/9acOgnLkxKRu+ggViKPVNqw9V8cDpQUAlDXSGKLVXT7H5Jo67PJMRXukyIBWwmI
         wKFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jTkbl9gK;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VnwiICJwkKrUBtft555aNTTN64Ctgjlip+BqnjufO3E=;
        b=bAJU/mplTY0Ntly9noU/xcrSf8YF+olVghbQQiz0/XlSyKk/nHVu6xtuZ5G/dMD1nI
         1E9nQwJeR63N/nc3LOzHYHV7+SCPb+fjOjnj4sc34817Mvb8UvHwMpR4qvEIYoeCjeur
         UG7IlqipDZmAemEhWoLCm7fbV1K9jKjUqOj5FTndIBy6E90Kh+kSSJo0xVQ9yB5qywZg
         ZTIHoHrjdqui6WDqvIWwXUBz0LRHoGBFEGktPNNQH5Ay/I6GPUyCkTFV/SVWq2ynx0oL
         G/TcJ8qOBEY2h6uhqXybtP5rUo1bvvj/98EuDSCgWyLvg3J9TOwzqIBIpzjCbz8e2F+a
         54mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VnwiICJwkKrUBtft555aNTTN64Ctgjlip+BqnjufO3E=;
        b=jRrd7fHWLAERzlo5yfnSO6GaSGd1nMKe4W2z6TChYp4FbNXuQjhgVzaGOu5j/7kAE5
         TQ/UNOGwsuprElOi3/Onr6SYPxhECtE6v21Gbg8PMiJ9Go5UdlsjeBEuMScktM2tbQN2
         OKt77EybVYnAu9ru68rKmnMT+OZY+a5x/YQKHcvAM7o07o6goLdFDW4HLMdhVIROMBN8
         aGfPCOzACx2H0WPR/R0DqhIsZqFJGIj3bHrZRA8V7EN2QxO3MeGeQ3AU40DIrtp1B5WQ
         oeq1NSMcXnR15WtOKFx+DqAkkGNBIAUarzvEFM0P65yJ3vd8SZwph5dw00BBqGPxPe9F
         yjbw==
X-Gm-Message-State: AOAM5319kvC2FBd5JGFC/0OuLa5EsGTyi/xYwvYk9GF8fPWDGoASDMuM
	y1C7P1dh0dpBOCbyq8PmLAo=
X-Google-Smtp-Source: ABdhPJxaiUO9wsP+JBauJFcZSpVDT7pvgXhztl1lSNVswlB+t88DtvfN5A1YF61MKIaBTS3WUfa+pg==
X-Received: by 2002:a63:4661:: with SMTP id v33mr3464601pgk.163.1604597264206;
        Thu, 05 Nov 2020 09:27:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:64cf:: with SMTP id t15ls851115pgv.2.gmail; Thu, 05 Nov
 2020 09:27:43 -0800 (PST)
X-Received: by 2002:a63:1f11:: with SMTP id f17mr3425977pgf.282.1604597263633;
        Thu, 05 Nov 2020 09:27:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597263; cv=none;
        d=google.com; s=arc-20160816;
        b=xWy5oaFNB/jTu5Ap7Uwzgyn4UKUIccsQYLNT1hJ1GQ6e28Hjm3AlUfXHvi0LOcaHBB
         7E3IpUR1Hii2nCOPh4ptKn+ioyyA5/2oroEEW3MGpCHP2ENUAzaFLVsXoqOamcUAWW37
         nLuAIrBOstolIX6FRGAmvqG0qr42IH8CkE8fc5mr8eFtc/6kIZhOpl0q4kGgvo1SJcpa
         bRsNA2eSeHpzZ8m6q+f5d9uTu8kwhNw1Xf+S6c6h512odo1xJxWj6zFORtjph9Agdm6c
         Ecb/AC7/FnuFYRMdmcO/PYMkvYTibHDZHV5DHxko98qN8amEbPDacX0PsVqAKZJWjc7P
         RhTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yuHzlMA7AoHCHwuNKz7UkjzBoF493bgOUUuEIK52/Ng=;
        b=IaRJChI3AeZmovKw9Iv9/i9ISujnucMsDuTYAcq83fnsNCIVtFev3+nf84/4QNwklA
         vSZ61Lb60rl1xqXcKB1O2AuvwaCaIqEDXyYlNI8D+8xXXcz3rncy3U+n+TGSq7PaWcfZ
         iZTAspPu+JXa00FM3H71AgwQeKFw1bHOTcEDaPekR9XTA1vyFqmxOoDleaJsAqTQNF7Q
         4keRFPruedMBYMf5YXGF+E1tbhzCPTsxnro6/OUkjwt232ymew+sdDv8NOfD9eYUv0uS
         qFHfoebSuJZTe9PMjf9aDbYxy0+wpqESoOBJvACapr69n+8V9qlggIR9m7T9fByx7AJ1
         8EuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jTkbl9gK;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id g4si132698pju.0.2020.11.05.09.27.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:27:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r10so1811599pgb.10
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 09:27:43 -0800 (PST)
X-Received: by 2002:a62:cec6:0:b029:18a:d620:6b86 with SMTP id
 y189-20020a62cec60000b029018ad6206b86mr3384207pfg.2.1604597263116; Thu, 05
 Nov 2020 09:27:43 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <58aae616-f1be-d626-de16-af48cc2512b0@arm.com> <CAAeHK+yfQJbHLP0ja=_qnEugyrtQFMgRyw3Z1ZOeu=NVPNCFgg@mail.gmail.com>
 <1ef3f645-8b91-cfcf-811e-85123fea90fa@arm.com> <CAAeHK+zuJtMbUK75TEFSmLjpu8h-wTfkra1ZGV533shYKEYi6g@mail.gmail.com>
 <090ab218-8566-772b-648f-00001413fef2@arm.com>
In-Reply-To: <090ab218-8566-772b-648f-00001413fef2@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 18:27:32 +0100
Message-ID: <CAAeHK+y+F+A8-5_ouc8E8UEPGf8L0fFUVXGo3jAiNFpx_GorrA@mail.gmail.com>
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jTkbl9gK;       spf=pass
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

On Thu, Nov 5, 2020 at 3:14 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
>
>
> On 11/5/20 12:14 PM, Andrey Konovalov wrote:
> > On Thu, Nov 5, 2020 at 12:39 PM Vincenzo Frascino
> > <vincenzo.frascino@arm.com> wrote:
> >>
> >> On 11/5/20 11:35 AM, Andrey Konovalov wrote:
> >>> This will work. Any preference on the name of this function?
> >>>
> >>
> >> I called it in my current iteration mte_enable(), and calling it from
> >> cpu_enable_mte().
> >>
> >>> Alternatively we can rename mte_init_tags() to something else and let
> >>> it handle both RRND and sync/async.
> >>
> >> This is an option but then you need to change the name of kasan_init_tags and
> >> the init_tags indirection name as well. I would go for the simpler and just
> >> splitting the function as per above.
> >>
> >> What do you think?
> >
> > OK, let's split. mte_enable() as a name sounds good to me. Both
> > functions will still be called one right after another from
> > kasan_init_hw_tags (as it's now called) though. I think the name
> > works, as it means initializing the hw_tags mode, not just the tags.
> >
>
> I agree. When you finish with v9, could you please provide a tree with both the
> sets on top similar to [1]? I would like to repeat the tests (ltp + kselftests)
> and even to rebase my async code on top of it since we are aligning with the
> development.
>
> [1] https://github.com/xairy/linux/tree/up-boot-mte-v1

Sure, will share the trees, probably later today.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By%2BF%2BA8-5_ouc8E8UEPGf8L0fFUVXGo3jAiNFpx_GorrA%40mail.gmail.com.
