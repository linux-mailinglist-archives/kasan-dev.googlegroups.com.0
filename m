Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRFJQ2AAMGQE5NMNZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C09A2F7C31
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:12:37 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id k26sf6866722ios.9
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:12:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610716356; cv=pass;
        d=google.com; s=arc-20160816;
        b=yB0fIpaE85HNBsPkhpkJ4sbu/ZDvuQtUmJbqkntHd4Y4Iwih1YS0aoETIQVRENj15G
         SZA0ZsXm7XvtnD3PHtB309ZpekjRquFHxrsDo9yt0nqNZxbalKZGaQArY2UyDbKiW7o5
         9dZfBXAjvVur0wLaCFLloSzkP5SR3wXKXgxu8TuJBDQF/db7P2DehlzOYY6XA2r6wP9O
         gYtPgeC0mV0RnFmM2VSUapjCc64MsmgcKUraax41M7fdEXNiJmPWNAKghXKsIMmXbOG9
         1Iv/ukjOH8P5/QIMnptVVvJNXOwuDIjYDMwF+56+rqQn6lDYQfaUpuT5UjtRw8Wf8EDq
         nnFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SgSa1KJ2alKMEkqcBEMMx7PDAW99GMkW9XhAUOPQs0Q=;
        b=0aH1okX5aVOm29x8Y1jmN11tUxUHnKbkidtl3DMsggjqeo6CCVee+VXWvjbN7yjzwK
         6BOi6jTs6o5ls45hKhWHoBfJxGrNISDp9PP0id7arWAcRe5cFtCFrs3VE0oTB+nZ6Wxd
         2Rn7Cjh7F+/BU8oT8WcWjbeOjfSoXubnODkHOLroPhwL45LhfAf1+BJYLe1YvbpbrUhu
         0QUJI5MNAO6c3kTQAbicU6B0V2b6TYy/kmJW2zRCRjtMHxqkOdhFdt1d4Q5L3nIGEi86
         VFClQFdxv0oQ5ByIAIxjP0dqXOLpkyqCQyNnnpTZ5ebTklQQxbH7Q3LEBAoJXq7s+/PD
         3Tyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TgoQzblg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SgSa1KJ2alKMEkqcBEMMx7PDAW99GMkW9XhAUOPQs0Q=;
        b=UrdI1TSEmkkvoD4njPqbd8+bcb+4uxT4dRV+Ivpm8yPrFYMUE3k4GCrovPiB0ajLdt
         M8t7Nbv9mFrM63HN8EKn9JdyU8cDKQa0eMl34K4XlWtq9SwWH8YWiWoZqu+/FLdmvL76
         ioiUV8HtRBUB1eOYwvJKWn6+OP/S78w+OUvtpJqd+erhJVnqFQAl8EnMRQxyBZ21ccIx
         cMxirDa5QQGqW6pwDaxCORh4YEJqyvCGTgDEodqSE9Y3afh1r4Mk0heRHpLS8D6WVCT1
         RrwdWOqVd4b8pui0DgP23qTH7wtMUL05PByRmpX2XcmcNtNJ8BIxS7VXLzbvp2gJIE1r
         1E8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SgSa1KJ2alKMEkqcBEMMx7PDAW99GMkW9XhAUOPQs0Q=;
        b=bCpbXwgit+uqDiy+Lm4tu7+WNWFJXQKpC4K0nWiCr/JHCruWdnG8iuzIftTUbzdfOI
         6BlkH3x40HzDNHbj5K+cOBAqW9HwoD/f2GvzAwo5bAhlx+lbn/QQBPJDiitJN4gK5lqZ
         ox8AieXmdudIz/QTirIB8xYGNWLpCubPt5jWoQfIHpRu2ORKzkbRFMfZpyqiUxeBaI0T
         pN7TEYHcv1FU5AI9jFUIF0AQLvbFp5zvFdH3M4oNtWa0IJS3T7kKEwLdYBeHLi1hQDB+
         EQ4mf4uYY/TpRELD1grYYhvtOZrro1gJZaD46yb7zjdLq87wLnQZPmq6T3z9YWKOrSPo
         ujKg==
X-Gm-Message-State: AOAM5317PHSEA+iBqvU4FWz02qT4oFsP/34kTPb3suVv3CiIjnwcT1lw
	lH0FGoU1i9epRT5QE2ktyAg=
X-Google-Smtp-Source: ABdhPJwE7gX0Cwmza4poLN7redy5/JVRxmlbTuz5fS9yyZDOU6pAiiBHHKacxfmcloahHtjAIp9tbA==
X-Received: by 2002:a92:d210:: with SMTP id y16mr10665999ily.97.1610716356600;
        Fri, 15 Jan 2021 05:12:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:991a:: with SMTP id p26ls1220339ili.7.gmail; Fri, 15 Jan
 2021 05:12:36 -0800 (PST)
X-Received: by 2002:a92:dd89:: with SMTP id g9mr3614266iln.132.1610716356268;
        Fri, 15 Jan 2021 05:12:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610716356; cv=none;
        d=google.com; s=arc-20160816;
        b=PGIg/nnucznaOaKFdrbA3sx0R6kwWTYrfLXWtpns2aXnixZtHxGB05TtyjWFJT2B+l
         uz6urnfmOkR4dceYYEZLVpnr59q4lgu4ee5ZcuWTfT8Iv4gYLMdaRE7bCcjniPHg0DFH
         hkH7T0sHdPKHBap0kbK3EeVsTeNo8nLRgxKX3dFTGhOurj9UpbGfJm3BOlEqKUcBNvqZ
         ZltD1Av0YdKtEmPf0KsKbPS7qtpfdfVSxC2aPoLOn2RwUm43Q1FtVUzFJr7LVyTEL/+2
         m0orfJHMaE1WnsA7q1Y0wB/4e3TNLHsZhv6q8JvfeuNGPePosD6sFd6gfNf3N22KvFtr
         Cc1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y3t7IOxf9Vkdfiy1MFmpsGSvvf/wDyt1mm0FiJiJHkU=;
        b=Yf13zP/6JRRZtO8hbjPi7MqbxkuPv+YPZp8Io1mCgYxx5TF23rCQCV+5qmEh3yEfwq
         ZLleYmccfOJWYGOU0gZsH6JophD8oaz5fsxlou2JE12sCvcjmspxOo9Qp5ky4IBEAplx
         67Yk5PamkqUAGXq5unItddcKJS+kR4rgeQ2VRWqhNevqnBtCkasTKM7gd3fiaKygikif
         j5HqscEXvgL5H5xJLLxL54OEkuYEeWTKkEnDMv4oo5nsZXEA9OwYlBN2Qaps0AvX/MRd
         adztLRWUsZtqGnxS/1K1VO7iO6LYXkttnFkYiRj+aB4xHcaCvBbALaHFK4KKPGS0JWVy
         iPtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TgoQzblg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id b8si1082187ile.1.2021.01.15.05.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:12:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id h186so5474751pfe.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:12:36 -0800 (PST)
X-Received: by 2002:a62:115:0:b029:1b4:c593:acd4 with SMTP id
 21-20020a6201150000b02901b4c593acd4mr289508pfb.2.1610716355514; Fri, 15 Jan
 2021 05:12:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com> <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
 <20210113165441.GC27045@gaia>
In-Reply-To: <20210113165441.GC27045@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 14:12:24 +0100
Message-ID: <CAAeHK+zThyq7ApsRTu-En7pL9yAAOrEpV45KOuJV3PCpdjVuiw@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TgoQzblg;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::435
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

On Wed, Jan 13, 2021 at 5:54 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> > As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> > that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> > while KASAN uses 0xFX format (note the difference in the top 4 bits).
> >
> > Fix up the pointer tag before calling kasan_report.
> >
> > Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> > Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> > Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  arch/arm64/mm/fault.c | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index 3c40da479899..a218f6f2fdc8 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
> >  {
> >       bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> >
> > +     /* The format of KASAN tags is 0xF<x>. */
> > +     addr |= (0xF0UL << MTE_TAG_SHIFT);
>
> Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
> was added, the only tag faults were generated for user addresses.
>
> Anyway, I'd rather fix it in there based on bit 55, something like (only
> compile-tested):
>
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 3c40da479899..2b71079d2d32 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
>                               struct pt_regs *regs)
>  {
>         /*
> -        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> -        * check faults. Mask them out now so that userspace doesn't see them.
> +        * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> +        * for tag check faults. Set them to the corresponding bits in the
> +        * untagged address.
>          */
> -       far &= (1UL << 60) - 1;
> +       far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
>         do_bad_area(far, esr, regs);
>         return 0;
>  }

Sounds good, will do in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzThyq7ApsRTu-En7pL9yAAOrEpV45KOuJV3PCpdjVuiw%40mail.gmail.com.
