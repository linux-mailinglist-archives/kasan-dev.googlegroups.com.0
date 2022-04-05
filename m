Return-Path: <kasan-dev+bncBDW2JDUY5AORBNV5WGJAMGQEEOIFLXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B56A94F3BDD
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 17:22:31 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-de47057030sf7435050fac.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 08:22:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649172150; cv=pass;
        d=google.com; s=arc-20160816;
        b=ofAdrInVYcPgfm70A0Nexf8iEQpj15ajvklJp1HCjZtjXXYnYFwmhv+My61QbhrA1K
         E7rc32GF9ves7NLn25vDJs4/aV0k92fY+PZYpd1PWD6buRW0331tqqZq7F81ahFkEFBh
         k6hyCslDaYGa1sazzIisGPprKbmdC+jt/HXYTLDqKQFi1t6gYVqr1cXWlGvl5F8vAAH3
         ehURqyKgH2ydktT8mqjHie6YpS0bSUna81W508xBmG8eGBPZzooTNdGCeiBtHr2nymZM
         MuOh6lezUyBrnl9TBBgvnIpTmgGTS7SEWptpXmPT/XMwp1/2fvRZ7T2cdSrri3Mn/k6M
         scTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=jML66punqidgM984nEcGuXal7Iqsut1YueFaTT0hs+4=;
        b=kwlwIZY1xNBYPP93oKovcp0awJMkoOcS5Kl5s8bAJnHF72aIiC2emUl1cpyxmc80aG
         VmVyTYbs0Fl29ntqTKO9nCIoGv6dILIpbnJoLZ06KuoeKqEuOiHPvnL7Tk0So5Vvs3U0
         NPqZ/clWd0JGfJib3vG/XihYE77g07Uki2T4jQrCBmjkVPns9Ha02O13PfFsnVOePBD7
         XpdDYTHHO/GtGM6QGfI92xULBnUs6yr1ucHyJWbD4MGi0u1OT1spEg/hBHNMEmQ0wEln
         nmv6HeUepvJ3Owmhj6ZMNQagxnpU45/Rmx+njkIERfiE6hxzzulb+O0i8PvmrKqqmfdW
         L1sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="X/ggfC92";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jML66punqidgM984nEcGuXal7Iqsut1YueFaTT0hs+4=;
        b=N23WPZS4v/snPHsDet+8P61D4phf4Cv5pSuR13prc/lYh2N/OgqlZuQFORU7nedjAa
         1v1cwTD/Cjp7cXv7Z3UNx84/vwqFFy0OsNh9/uqM77l31SMTfcL2tiuW5jZwui+fqwlk
         fokDRQUvYmnbhBV2lNs+HZHjC2LB8BRfEKSlGF+NQPCSZLaJbIfth5yvXbUskmhRaHpk
         zXIlmTaxPD6MP5BYI0jFW/tJJr29Pp9J9GEcgvDttHZRNwGTl9S94HYFOEb8I7UlQ4cL
         hA6tkRnFZIUH6PO4yhTUFQdtnBKjtp38tjPp0UmqNWsd4nayg2exynhUHum9CmnagBy6
         9KdQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jML66punqidgM984nEcGuXal7Iqsut1YueFaTT0hs+4=;
        b=jpL4u0jXuyMAReckSr8IBquxH6C38mxysZ8o7z3wX/q1dK6IU8/LRkRRBU7lIRtpcn
         bi/FJo7iFfoIpVWH7bNp1kdL8nrCOsNs5pa3D4yY2lpjSKKMAF8i0/4T5uof4havbZ/H
         26ngBJ6PMIVrSFdxDFaRp+/QkQ4Y4cQwq3lnz7sMGWpnO2YLqII7K4rIXp6z3uAd4x/s
         NMxHGAhYXVTByfrMlCCTyukqJ4mdKDXoSjOY+4uzHFPQPKdfv8P9++8eQW7YlfJ+8v8f
         fF3xJu/EoYDJPCZ+QZqTct/UdfCIJTh3Evw3Y6Keu8vNHw/hgFsdDtmu4x855Obf1sQn
         sgXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jML66punqidgM984nEcGuXal7Iqsut1YueFaTT0hs+4=;
        b=C7JVTFowbCsMsh0iO1lMhf7S26CyFOIGKVKhedobT7cPU0AjFjhiJ/DM0Mdr2iPceS
         ICJ7AVYRiY5ycphMSRvu6QFY0CDty1Evj4T7T5sACjaereBEFC42wJbD50PnZdf66YHv
         PhH8ki4ZifKjFmVZlljT7ihbuo9TEANkk2tKiO8/TB7t7Lsfv1lG/b3EhxD73SRDKPju
         KzYXZAtepumof/LB79YW5SkrBb6DcZdLoj7Ojh/7oDl9z5PkCsE3aMEIytqLO7OnZBPa
         5qFzhH9Mu4/uMu20w2iPlOL7edzt+Jy5jDHi9eKUTfRp8P+SlVEipKAtcj/O1hetMuch
         bWoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gPpGFqG+6NhdTPg8dchVTzyLDZe65HajgaTGBgeubS4O9QTeQ
	cuhd5twOLLPZXREeOLTiapg=
X-Google-Smtp-Source: ABdhPJxt0D7vTUbVgH6BjXPcExbwsfs6LvNh3GFJwxjPC/ttsqxjClIGvzXQPCZiEWnycmnLBF8CYw==
X-Received: by 2002:a05:6870:5686:b0:dd:c3eb:e98d with SMTP id p6-20020a056870568600b000ddc3ebe98dmr1737081oao.0.1649172150447;
        Tue, 05 Apr 2022 08:22:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a1a0:b0:d7:1d2b:ec1a with SMTP id
 a32-20020a056870a1a000b000d71d2bec1als7127552oaf.3.gmail; Tue, 05 Apr 2022
 08:22:30 -0700 (PDT)
X-Received: by 2002:a05:6870:610d:b0:e1:f70a:9e8a with SMTP id s13-20020a056870610d00b000e1f70a9e8amr1863479oae.120.1649172150182;
        Tue, 05 Apr 2022 08:22:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649172150; cv=none;
        d=google.com; s=arc-20160816;
        b=KLWFCxlLq43Bt30j45KCwvcBaFiAD0rKDZ9OEtRXFsSPmL3ewxN25U/M9W9u/asZ/z
         P5YFC/KV0TGfTZie2QJg8jbbF92ZXaK93Em0McDyaBOH3fplrqdlXijGYVBWDxq3vxH8
         Z6G2cWriKyJ/IoX+YYsJbTj/DLLWrddc7wmiDOLvr1FrkXi3/1Gyf4OTHBXo6BNdb0la
         I2ryv9KiUe7AJSqzLcNQKaMRaV4fOxat6yyEmIqo+8T1Om0vdbz8PsPv1Rra9wyZtbqW
         dU9eonPsaw9O4bMd9kxHW0tb9GGjOOSthL4+t9ODsYrb4Cmzuar90EtzsOo5qcRx80T7
         bSjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VUTUxfwx0BMlegLzejTeqPrh28XK1GfyeFHo2+PzHSA=;
        b=gNg1YI9udwVUApFtxEE0BjRvxafYxaG4fICMy9gz+KiOo/Vw8OgotpMaKqDgrOxi4l
         psMxE3/s2J5vAzVFz8Emp9UVmm8nQk76vcXjdoGS367+UBFfjUnaU94zZ0LMnoTjTAeZ
         yncU4k+s1mFDnd72sHwTn8/BfC/DOaBbIQcFAJnlnF2mleLEDln/pCMg8quLUH3bpFuX
         UvzGZVv88xM/d4b+hhAzSt7fxBwesEdt+mf2q1U6IXTm4S5jF9IT1+DPnPXm1zbHN6K2
         HRe+VKIumdQBMgJVlUyDDK/cp8vIZyLLIAnJgf4+ZKol6dq1YYLcFd0AbM8exdsnosNx
         C/cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="X/ggfC92";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id o39-20020a05687107a700b000e217d47668si370372oap.5.2022.04.05.08.22.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Apr 2022 08:22:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id e22so15514731ioe.11
        for <kasan-dev@googlegroups.com>; Tue, 05 Apr 2022 08:22:30 -0700 (PDT)
X-Received: by 2002:a6b:116:0:b0:648:bd29:2f44 with SMTP id
 22-20020a6b0116000000b00648bd292f44mr1993367iob.56.1649172150007; Tue, 05 Apr
 2022 08:22:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
 <YkVzTbafttTHWETU@FVFF77S0Q05N>
In-Reply-To: <YkVzTbafttTHWETU@FVFF77S0Q05N>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 5 Apr 2022 17:22:19 +0200
Message-ID: <CA+fCnZekoAMEcS+0905JzP=Gu81R_F_em5Un8JL+FOF2Jj3rqg@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] arm64, scs: save scs_sp values per-cpu when
 switching stacks
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="X/ggfC92";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Mar 31, 2022 at 11:24 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Wed, Mar 23, 2022 at 04:32:53PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Instead of trying to retrieve the SCS pointers from the stack, change
> > interrupt handlers (for hard IRQ, Normal and Critical SDEI) to save the
> > previous SCS pointer in a per-CPU variable.
>
> I'm *really* not keen on *always* poking this in the entry code for the
> uncommon case of unwind. It complicates the entry code and means we're always
> paying a cost for potentially no benefit. At a high-level, I don't think this
> is the right approach.

This also gives a 5% slowdown, which is not acceptable.

What we can do instead, is to not collect frames from the higher
exception levels at all. This would leave SCS-based stack collection
method impaired, but this is probably fine for KASAN's use case:
currently, stack depot filters out higher-level frames anyway, so
KASAN never saves them. And the lower-level part of the stack trace is
enough to identify the allocation.

Thanks!


> For the regular unwinder, I want to rework things such that we can identify
> exception boundaries and look into the regs (e.g. so that we can recover the
> PC+LR+FP and avoid duplicating part of this in a frame record), and I'd much
> prefer that we did the same here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZekoAMEcS%2B0905JzP%3DGu81R_F_em5Un8JL%2BFOF2Jj3rqg%40mail.gmail.com.
