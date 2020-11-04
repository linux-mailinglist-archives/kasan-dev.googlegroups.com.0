Return-Path: <kasan-dev+bncBDX4HWEMTEBRB276RP6QKGQENTLGVFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DE2F2A6DC1
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:22:21 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id s9sf9143800oom.15
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:22:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604517740; cv=pass;
        d=google.com; s=arc-20160816;
        b=uLWRkOb5h5fWx7DjBp4BXxK2ZNQ2f9BtOSUE3owP/0uKtQ9gBk31zYQJySOkCkJMfS
         cRchO1GzgzaAq4QO8951+fC/nuqOOhp7JKgE0VRJrU/AoWPh/X17+bO6ZTiNN772/Ejk
         eWcc7GcsGuKPKRiBy2WIngNWsukQMP+8hLUH7RR4NXxPndRACvD4vkFGZuXXCmh1T9bv
         hEDMCzTdEVHl3G3VGbYltcg4TYe32MimUJ/NBB34v/VC3fLqbaQ9kAODKWEQx13k3cfQ
         Cc/3kFIEfx9HxeOSwFzmik81QTnxSH7ef322M8lbon+oBrHQPT+r1JVSlTEIRS2d04Io
         KLhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kKfNfIdPF8rBa8k9nFcSIFLejiOive8tn2Z35I1y+xE=;
        b=fhgK77Na642lr9+cLvSca49sXtV6PAv6IYUXEC1nFasOxd9+HkGoLzgRC+QIrHUOrL
         jRy1HNLqsDvHL/1zDejKHhi4f0m1BAaOHggeTDdrWw55VZbV0MFMoDZ1hQAFiqu+bENT
         psniRpArhiSvQHZx8uY3KKtUGr+p03kFeaYYTCHmk8hznwnSjUCVy+No4S3yuFRXVMoy
         Jg2Zl/eqsyewmm3LN+vHrk3Al3j8WSb6lrnvDgc/26IboLYowJ8nMFPnadzvlfKVLSvN
         jh+Dcakd6bLnCy2w0AX4HW5A0+OzWlhA/MHG+EYHvaF4l+qfDEXchrkLbFyzBO9spCwH
         5CqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c+mg+DzL;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kKfNfIdPF8rBa8k9nFcSIFLejiOive8tn2Z35I1y+xE=;
        b=XS3R2BVOR0Re21h4IYung5pDiOmMqiNaB+QZmjgeCIGALSr8pa8q9cgUJzUVurReZa
         XUyeaGAwCLSk1pru64Mxe0WGwT1Wt0NlUpJJe52Inca/+5F64zyv2wEyoSivxuEW5dWF
         zwF74NituLi5HuW1Od4OKlEa37lTVs9NXGXorTmpkjEigw7Yu418yY1fEhHG+3uYZlK0
         /QK88VX2ovJE7sP7uKgtUDtdMDNncBXhRJEYjiMxeTYy4kqnqZUmt4S6oHbYD81FoPTp
         qU+Er9qvfRMSA2IwTVRm76q4e4RqyFNIpBsNu2bPB7W0g0uj2SxtcIIHoFel+YOWhPm1
         TfAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kKfNfIdPF8rBa8k9nFcSIFLejiOive8tn2Z35I1y+xE=;
        b=AAU0JaHZjBOJOipbwVhOUPYaPWjr02XHXerEFz9Q2KOkBrbaMrnI12lpgqzymUO6Wt
         SgcoXA4GwaRVuspCaxRYumetZF+/uBaRzBLCuvq9lxmPY9cuJZtBLtOGKX/1nqJLoSDm
         wzOMz1+9RGnr+juAqfH++e5Qi7s9r2DF2T6FoaCXidEroXxY7wcs6XskjT4GF4DIa5Pr
         DTqNFlEwOV9t/jpj3XDkN4rnJ2ct0f3/DxvST4xIDX4E9PNFnCjQoMj9BTdKEEnrIVh1
         vUO8SuUueeC7PHqjjYqKgf90KAOy0O/c0W6iYFp2V6NBOTWu1pr6lJSZU7lnEet/J7Wb
         trfQ==
X-Gm-Message-State: AOAM530VunrCTdWcU52x7YFycgaBJDbUdafCrWtL6ivRTSaa9s7OoEp5
	HjQv3R2c254Ce2Ib4wsOq04=
X-Google-Smtp-Source: ABdhPJxZ3HFyj9SrLAJxg6Jum38tlStq739OX56k7O7601VYbmUyu4ebw30nEd5t4c+9rv39dVwSdg==
X-Received: by 2002:aca:b606:: with SMTP id g6mr3322601oif.22.1604517740032;
        Wed, 04 Nov 2020 11:22:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf15:: with SMTP id f21ls838333oig.8.gmail; Wed, 04 Nov
 2020 11:22:19 -0800 (PST)
X-Received: by 2002:aca:440a:: with SMTP id r10mr3680561oia.110.1604517739662;
        Wed, 04 Nov 2020 11:22:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604517739; cv=none;
        d=google.com; s=arc-20160816;
        b=m6246Rcn2dHnIERV/ZLmcFgfyu7jk9Pi1j6tSVq31sosf6AJ9tMVNgunKRFaGyYOuB
         oozSl5OI1jOeQ3PmV5F6qVcZE+4UwoS8ppSzPd55Mljj+YhP+e12vrzJG0h6zFs43mIL
         0KWlr5yZezeJPo1zFFtp/iKcZq4f3hFkz7/0KlOcDlsp25g7ZL+sxnhVwolVPJkxyF+M
         Vk5OGydrEbPEGlySYkaDJQdDAfV9vNxCQYkct6OPNEY9ew6/I9v5e9KQ1qhKeBeNG/la
         jAvK+IROayPi4pW932+AVEXCe0PGIDOnR4GWm3cg+4CbasnqZ2PxWLOdlxv2N5zbuObC
         yuig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1AS6LJKOijonuhwsBoB44CLu/ocg1LiPjNjpXhH5Y8E=;
        b=xJ1jTpWtCxtFE25lkDEvDRmREXq8Y5oe6f7fI1Am2mlY/n5yrCjvOwqbb2kV5VrtrU
         Yb+c+1/zUom/dSyle4YIFSVyue71UACPDeBHhUzSavpf9UgMcL+FbXgxk6Glbr9d34bM
         Iqz9hyXu5Em58jfnNxtvnHIgxlL/Dfbra1rBRS0283RU3AcYGaVaWKH54MwQEr8RK0QB
         IiLecEWwnMHsZyMjvV6rkeSybenSCdd+haFMTOBKwRYCbXuUm8RcimN/fwtzgalta3oU
         NfGkLMZ1mcCP+er6FVLP/AAU6Wul+gVNokLmjWVaoirVVlmvmVj08ltrDTnrMeetFWYU
         EoaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c+mg+DzL;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id p17si302451oot.0.2020.11.04.11.22.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:22:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id u2so4808616pls.10
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 11:22:19 -0800 (PST)
X-Received: by 2002:a17:902:d90d:b029:d6:ecf9:c1dd with SMTP id
 c13-20020a170902d90db02900d6ecf9c1ddmr3847240plz.13.1604517738891; Wed, 04
 Nov 2020 11:22:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com> <4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl@google.com>
 <your-ad-here.call-01604517065-ext-2603@work.hours>
In-Reply-To: <your-ad-here.call-01604517065-ext-2603@work.hours>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 20:22:07 +0100
Message-ID: <CAAeHK+wuJ5HuGgyor903VcBJSx8sUewJqmhA_nsbVbw0h2UFXg@mail.gmail.com>
Subject: Re: [PATCH v7 16/41] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
To: Vasily Gorbik <gor@linux.ibm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c+mg+DzL;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
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

On Wed, Nov 4, 2020 at 8:11 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
>
> On Mon, Nov 02, 2020 at 05:03:56PM +0100, Andrey Konovalov wrote:
> > This is a preparatory commit for the upcoming addition of a new hardware
> > tag-based (MTE-based) KASAN mode.
> >
> > The new mode won't be using shadow memory, but will still use the concept
> > of memory granules. Each memory granule maps to a single metadata entry:
> > 8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byte
> > for software tag-based mode, and 16 bytes per one allocation tag for
> > hardware tag-based mode.
> >
> > Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MASK
> > to KASAN_GRANULE_MASK.
> >
> > Also use MASK when used as a mask, otherwise use SIZE.
> >
> > No functional changes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Reviewed-by: Marco Elver <elver@google.com>
> > ---
> > Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> > ---
> >  Documentation/dev-tools/kasan.rst |  2 +-
> >  lib/test_kasan.c                  |  2 +-
> >  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
> >  mm/kasan/generic.c                | 14 +++++------
> >  mm/kasan/generic_report.c         |  8 +++----
> >  mm/kasan/init.c                   |  8 +++----
> >  mm/kasan/kasan.h                  |  4 ++--
> >  mm/kasan/report.c                 | 10 ++++----
> >  mm/kasan/tags_report.c            |  2 +-
> >  9 files changed, 45 insertions(+), 44 deletions(-)
>
> hm, this one got escaped somehow
>
> lib/test_kasan_module.c:
> 18 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)

You mean it's not on the patch? It is, almost at the very top.

Or do you mean something else?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwuJ5HuGgyor903VcBJSx8sUewJqmhA_nsbVbw0h2UFXg%40mail.gmail.com.
