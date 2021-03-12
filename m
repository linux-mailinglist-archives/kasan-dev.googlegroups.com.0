Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLPLVWBAMGQEJJPEPHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AA63338F6C
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:07:43 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id x7sf13370891plg.18
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:07:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558062; cv=pass;
        d=google.com; s=arc-20160816;
        b=PxWdHpn477t3nJsBvaqBzmVRhfXIxImoTGyMKa3cU48YjvX6u4aa6cjeWPEmxbcmON
         MpLNOLEpmamsSUIGItdG2a/mY+zlvkq/ltfRIsXbNrqznYJfNpjHvH/Xe96RX/6exGCQ
         0zfWN59rzTlKx71nggXbFxEqr5UUOpV7/hbSIrQLOUD6Te/KH+h1+lx4DWxz2DmDWmp4
         U6P2NpmwvooxJM1zmhozDTc0llmQnJ37YrsFBDougB5cmDQ99kXVTp5MWwxkaINejQ6F
         tKT4FA6DJFTAWCfuLeOExBhY5hraq/iGcUKUH6PYqeMK6IV4L0WT041OpsZqH+CYqJLD
         N3qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=joCzXWjbHc2RjxJKUnwfXAB79pAUujFRQvbM5wMXVMo=;
        b=BP5bMXfWBH0ohThTp8JOo8cpTbX8/EsVP8+gluxsx/RAkF9LUjx0sGm+VIoVF1LAQB
         QE+hGoi+5ciyKelWAYXus1wvr8Cl4OILpmKFRoUYm8Ig4gnPOx2qnBUxgOlEfNfpZEe7
         Z6cO4hvK6A5pgkpF0QbHgt9ZR/M/1RNmptaCx5CJfgpOQk9PsESEGWt86JiUPaJc6stg
         2QmTAHj2CPE5dl1Zxva1uoBPTkF7R9gQVyYpOaegofjvboK9INjtQZl5IlHsXJ1cRhgG
         uVbhYQMA0b2T7o9fIAoH09HJjd8kdrMx5jjOMrzjvF4YrvjpR23SIzA3GBJqMaZUcWsM
         X8pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="C/1wEkaq";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=joCzXWjbHc2RjxJKUnwfXAB79pAUujFRQvbM5wMXVMo=;
        b=sk4u+qbxek6eEHSqJMXr/gLnjginguOEII8tF9NjLe6m/TJDtco80qg6y+jgHl6VUe
         QhbUGQdRNZZBUo1VIyIzqnKPAyCo7KDf9B6QoUnLU8jIR0CyvkoKY8FgWlcQJjP1RYQT
         +pv3soeK3Qe65bBasP3yyrgQ4BpODDQro91mfcbFwh9F+ytqWfQ1v70zbpeM4KFa2vmu
         ORcH4ULi5C62Th/UA1fb8glVrXG9W8eSR8Q+GeV/6fl5iqHTDk50cllY6fuUO8Ab+KmP
         mZK3gQL4Vzfa526MF8lyUgYlB5pMEpahuNzvSy005K+rz+bm6s/e+X6RsYfhp3/Lp1cR
         jydg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=joCzXWjbHc2RjxJKUnwfXAB79pAUujFRQvbM5wMXVMo=;
        b=f/y5ARBI+DNqLAVo/ar5br7LbFTy255A7zamW6qc9d4hYmL5db37BwzeCXFLT7RcWt
         tOIxPpmqE5APZInRYQjJFdSYWHYLOaxdTCt938L/1p4FnYYP0rgbeTFsZRbdixM1A6xU
         F84oYJeYlnIiQLJAXDoatzncQPpt+87Ex2YEyCtp3MsTehP6Qvb72VH4JjfoP0OLg0Hb
         AvXl0yPyUOofYtvTQP1nnnZc25kQaPq+f+0VpPndJ7QW67ugh2/dlnJgodjI/Wlrreor
         CpALWFCbnB9RNXz5MJrAmvq8GW8kC+9bD5BEamdzUXL8mbnyYh5BSwNn9zdMV5d+rXa/
         VdPA==
X-Gm-Message-State: AOAM531/B5cmu4Wwhow7LkHaVONv11DvOSKpLgJJoNZImWPYCnL3kdod
	/hAdBdFn15mxRDB5s2NAWp0=
X-Google-Smtp-Source: ABdhPJwQR5tSfLGBAKCM+7AZ9UsRlWTKy+9WnseV6htaLYDAfk0hTG+fsh2egsRL3Hx+tl0iz3agkA==
X-Received: by 2002:a17:902:a404:b029:e6:23d:44ac with SMTP id p4-20020a170902a404b02900e6023d44acmr13452392plq.50.1615558061907;
        Fri, 12 Mar 2021 06:07:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1914:: with SMTP id z20ls3632460pgl.0.gmail; Fri, 12 Mar
 2021 06:07:41 -0800 (PST)
X-Received: by 2002:aa7:9984:0:b029:1f8:b0ed:e423 with SMTP id k4-20020aa799840000b02901f8b0ede423mr12385130pfh.81.1615558061431;
        Fri, 12 Mar 2021 06:07:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558061; cv=none;
        d=google.com; s=arc-20160816;
        b=mUTaI7KpByij6ax6wgtm7q4E/vyRKwCZtTUs0XlzA82OZ8kpLaRmCSegirvH1+AbmV
         U7tnXKwPHtTeUrnhHrix3/3qbK6cfTmEYV/5soq7be4qWitqNRQdDllPmmM0Ly0Dj37T
         tvIMBYr4mLeVdqAKqiur4iTxVpBI8yBfFJY0Ea62FZDE8I9wetDOJY3SzmMMuPF3Ku0q
         yHsBdr891IuwAM6DTPrMfBk/xHfFPe/gxcIKvszH0AeELiUtnh2IKGyHCKeI1Rq/CAKH
         8vQW4+Ne80xDu17orlfjNr5XBLLDgVNJ21PPiSUkLxctI6laGWRPsnrCNn5w2Xcbv2lW
         m7bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v/GgEAlBKF2uwsyk9hjE5RIXHym45HMkX/lhiSnnj6Y=;
        b=rF7SAPWdmf5RrrG0gmWgkYnMs417vC783ZL7PtZJK0TBpML5hfhsjmP6yrNuNF+HyH
         X9CwNjkZMOPpgDfwwmp8v5Zhf6yk3R/HZejws+Yj5lqyKWG9xsEKkgkkfOhc0bBRu3nB
         TmHUD3WHEJzHBgN1hXi39Q7veHx+YBjvpRz5JrE6802Mn/Lop/Xl+uD3jf8A32Oh09bJ
         cm/9Rs4Nr5R7QlA6xL4CyU33VNCyDMAM++I/Vomm01E7L7LMa+jK/G8FoEYr/Hd7uP5g
         s59rghLnTAnqsyr4RbQqxbOdpFKuO29gV4mCyd6GXFSXJjB85peLrO0CNbDoVIMcyydA
         FgqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="C/1wEkaq";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id z16si434457pju.0.2021.03.12.06.07.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:07:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id s21so1957447pfm.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:07:41 -0800 (PST)
X-Received: by 2002:a63:f14b:: with SMTP id o11mr11989658pgk.440.1615558061031;
 Fri, 12 Mar 2021 06:07:41 -0800 (PST)
MIME-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <c0f6a95b0fa59ce0ef502f4ea11522141e3c8faf.1615498565.git.andreyknvl@google.com>
 <YEtKVYVeUycUKySP@elver.google.com>
In-Reply-To: <YEtKVYVeUycUKySP@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 15:07:30 +0100
Message-ID: <CAAeHK+w3C+Umd9j__P=97KHQ-AEqS10gi-5DA5tc0Yav5zzWEA@mail.gmail.com>
Subject: Re: [PATCH 10/11] kasan: docs: update ignoring accesses section
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="C/1wEkaq";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b
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

On Fri, Mar 12, 2021 at 12:02 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, Mar 11, 2021 at 10:37PM +0100, Andrey Konovalov wrote:
> [...]
> > +Other parts of the kernel might access metadata for allocated objects. Normally,
> > +KASAN detects and reports such accesses, but in certain cases (e.g., in memory
> > +allocators) these accesses are valid. Disabling instrumentation for memory
> > +allocators files helps with accesses that happen directly in that code for
> > +software KASAN modes. But it does not help when the accesses happen indirectly
> > +(through generic function calls) or with the hardware tag-based mode that does
> > +not use compiler instrumentation.
> > +
> > +To disable KASAN reports in a certain part of the kernel code:
> > +
> > +- For software modes, add a
> > +  ``kasan_disable_current()``/``kasan_enable_current()`` critical section.
>
> Should we mention function attribute __no_sanitize_address (and noinstr,
> which just applies to any kind of instrumentation) here? Perhaps with
> the note that called functions may still be instrumented, and in such
> cases would require combining with kasan_{disable,enable}_current().

Indeed, forgot about the attributes.. Will add, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw3C%2BUmd9j__P%3D97KHQ-AEqS10gi-5DA5tc0Yav5zzWEA%40mail.gmail.com.
