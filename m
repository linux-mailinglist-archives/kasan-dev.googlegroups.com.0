Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX7NTOAQMGQEK32XZUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B3DE431A70A
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 22:45:04 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id v10sf556304qvn.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:45:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613166303; cv=pass;
        d=google.com; s=arc-20160816;
        b=mMIyKdRksnIw4S62A6r5noZgXPwe8JPjEWvbzzavPvKGF8vJlhVvg2Nc3KIHRmxbjG
         juDof4VdrWCQA+EeTLqm/flDcfG4tvNzntsYsMtre9VvcxKhNEVZtNpu53m+jMCnu5u0
         HIEyjMAd/qchih045Cknxd0G6wuOs/Ir9Ues8P5TDtD/cMMS78ZsywqOE/g/BHp6dRS8
         0dF71PZGBkeTZwjVyuXSgzfSDO8mfMM+c1BR0xHtxoDNn7y+926rj+1bk347IsL8zV6d
         Ph0za9Hyx+IXf7ujJZbSn7dWMGJQLa6eeW1xpt6EVcRO0vDeE0ampuQKVcv0PTdjBckg
         4NHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=S3H8WPnf8cSiAEaU7Ai2QPTSQ7kSONz/b0Obsfi8Lpw=;
        b=oW6pVEtG6gg9cLB94lGHgT4WGawvos54qW6/xFdNzEMIrM5Sq+nROtuocYfqOqCOy2
         vqqryQhAyR5vn6/pD82cmpBjk5XHvWrx5xZFlqgmErCKn4tVYL4+QiqPH5pywk2+hO6g
         Po9nYYr4DxNp4rklSHEzP0b9PHmJ763pbKiX8FFDwhHJ7haPLF1amB91ZH98L0abZ0hi
         6r0ViHyvbJ5QhG3TH9H5dMxo7HXEritxGyJH0EdcfAU/aWAiC1HUgOMlhL2+KB3dPXcJ
         KxFWc/Pinij1Yk5Cve6DKNJZA0YaNV6gRVtgRC/wOq4ds12R4rIu2jQoJLjAdCc8nI+m
         I60w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fqnpY2LT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S3H8WPnf8cSiAEaU7Ai2QPTSQ7kSONz/b0Obsfi8Lpw=;
        b=Y4I1Wyks7tSV3KsG+TG/a8eLGBDmUQFKuVTivRAJlYCMti9wQBAZQ/aTnUQ9n0YbKD
         GQ6e8+QFm4lo//u3DJWW3PQq7RJosk1Z8uy0Il2izGgLwYOSI3w4ph5+ItX7S8SN2PvQ
         vaJ0u7QfhtVSQkUe0b1UDAu11DRrbDKNPGw5FVafIIzHMflqqbFObWYqyCtI1Uq0rccW
         keStr2wU/+DmjvP4WjkftSpk9T3RxCiFEHWebt4IgWRXEwdU91QOWHCsOMhtqWTsaOVF
         9Xb60nJoHrPl2OOXa44NnGktp+/rnJ/SB0h/NdJt0rwLThKIMDb7ux1XOg13ogDwXEVl
         imUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S3H8WPnf8cSiAEaU7Ai2QPTSQ7kSONz/b0Obsfi8Lpw=;
        b=HpzRHtmNHgtJctNwULfWEo79kApaaaD5Y+odwGa5ACvu2n7yCDf6Gz1i9VFo2/Fy4L
         miSZkiXLlCz2NrQJXj1iZZvhAOz2BDJ+C8aI5jpgmwCMlffyVKQUvgFNZ4Pw7SDaQ7nJ
         Aba/A213mFSd806wgRpou5bzYEuLpSmzkuJnMvZWV9c430xXQ40JSl+nKYyyA/cqnu9l
         nKy/RlTIc04WiL41tCEa9mUVezv11UiQbC9+0jlQ2whr3+yMNwf+SvDceRo6Dq6Qrhm8
         ahbJM6A4I/xNjNByn35UBvRR3VHJAgbF7QzPCmQmZYc+6i/hSGarfDDS6m9GxWLDSPur
         2gWA==
X-Gm-Message-State: AOAM532jIVSFqmg3oGxtQR8KcmmT+Q9UeAj9wZMRnE0TihUCYkrfjgx1
	L153+7561+oFFjVTQZDH6X4=
X-Google-Smtp-Source: ABdhPJwW8SJMOMFh8b+CJuXkDMc/PNtAgDoyOwn3pIRhFYV7htX5nbgwDuVuFiE5HvhFvDoNRNn+Hw==
X-Received: by 2002:ac8:6716:: with SMTP id e22mr4432576qtp.117.1613166303847;
        Fri, 12 Feb 2021 13:45:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:47cb:: with SMTP id d11ls552657qtr.1.gmail; Fri, 12 Feb
 2021 13:45:03 -0800 (PST)
X-Received: by 2002:aed:2e42:: with SMTP id j60mr4488678qtd.189.1613166303535;
        Fri, 12 Feb 2021 13:45:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613166303; cv=none;
        d=google.com; s=arc-20160816;
        b=N0bpV9UwS3XkuIioMzdBWScxrPNbL4RoSqccIQtDRygP8SyQ/yFW7YNSukGoAgdh9W
         uDaqXnQwIOkc+mwzpMzXd5mrsSQh6rnJrZqNrCdiG+KE+aGec+YBm4txRLiqDbb8LQiU
         daymcbNrZw5IEUq3eYDElQ9WMmg79JOfAoTYJkqBU0BGakKEsNda0pHAp86xYpdIjFjR
         veNT/OmxFlWPnaeUHIuR40PqFYJjKACDYEV+gLXKuRfPiS51FSNt7Rhq2cVMHSZYKmDo
         wmZCjFS6PmepXV3Qw1flg5weJbDrUOu9uj50zi0iiVZpV03O7aR8E/eNN4lM0ujWgtDo
         0RDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9lL2r/Ey+YYeyZvvoc/iJkTezo+Dg1gXvxnIcJaEP3o=;
        b=VN74/Bv9J4hC6kBrEznON+jD90XUUE01JIzyWEtcsMTKAHhYG8dyt49oWRpokKDlKp
         rQ6NmM+hSFh7ooPG24n967H1lyXny1xSG3qeGwfYEHNWqP5SM3rhNHyAIX+0yOsnedM2
         ZRfpZ1L4ZtnXQz6Ysm3J8A0uGQNZE4sdLrmo62T5+AylRZSLJ4uHB9U7zt6zVOOizjeL
         JxfiBhGHwWjAiTCdWQula5sVulIqmGrzHMIQT+Vp2b7nCJQfO7MSaxaPRBDBlV1xoA0u
         QtGP75MRUEIQulS/dONgydaklExJywWNI+KYRAeqvSxO3v+qNQnq2AldixQBYLXsKbhU
         ESyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fqnpY2LT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id p6si402766qti.1.2021.02.12.13.45.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 13:45:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id t2so385046pjq.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 13:45:03 -0800 (PST)
X-Received: by 2002:a17:90a:9ac:: with SMTP id 41mr4510715pjo.136.1613166302591;
 Fri, 12 Feb 2021 13:45:02 -0800 (PST)
MIME-Version: 1.0
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-8-vincenzo.frascino@arm.com> <20210212172224.GF7718@arm.com>
In-Reply-To: <20210212172224.GF7718@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 22:44:51 +0100
Message-ID: <CAAeHK+zg5aoFfi1Q36NyoaJqorES+1cvn+mRRcZ64uW8s7kAmQ@mail.gmail.com>
Subject: Re: [PATCH v13 7/7] kasan: don't run tests in async mode
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fqnpY2LT;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102e
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

On Fri, Feb 12, 2021 at 6:22 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Feb 11, 2021 at 03:33:53PM +0000, Vincenzo Frascino wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Asynchronous KASAN mode doesn't guarantee that a tag fault will be
> > detected immediately and causes tests to fail. Forbid running them
> > in asynchronous mode.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  lib/test_kasan.c | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index f8c72d3aed64..77a60592d350 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
> >               kunit_err(test, "can't run KASAN tests with KASAN disabled");
> >               return -1;
> >       }
> > +     if (kasan_flag_async) {
> > +             kunit_err(test, "can't run KASAN tests in async mode");
> > +             return -1;
> > +     }
>
> I think we have time to fix this properly ;), so I'd rather not add this
> patch at all.

Yeah, this patch can be dropped.

I have a prototype of async support for tests working. I'll apply it
on top of the next version Vincenzo posts and share the patch.

Vincenzo, when you post the next version, please make sure you rebase
on top of the mm tree version that includes "kasan: export HW_TAGS
symbols for KUnit tests" (linux-next/akpm doesn't yet have it).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzg5aoFfi1Q36NyoaJqorES%2B1cvn%2BmRRcZ64uW8s7kAmQ%40mail.gmail.com.
