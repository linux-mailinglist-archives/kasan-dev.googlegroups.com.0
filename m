Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHODUX4QKGQEYLJ3RBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B6723BB1A
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 15:24:47 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id v125sf7852279vkg.9
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 06:24:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596547486; cv=pass;
        d=google.com; s=arc-20160816;
        b=FY3uxon2N7SciUdi0R3N46ZLhxlcejXIdsYW7fdF8rDb1zuHYTBwjoL3KhMYtzIoWU
         wkcbUJzUYeq4GNJKy3QU4DRrPPXASerT5vU7Lhoh6AE7Fz3r/iQVfn8Q/n7aeeGj4Et+
         g44nhUIW4CJNp7DnEx8/CN4nbLVf5kJBS+tUMVhyv9w+45d9O9lcCPZ8Tx7vsZs7lPcs
         h55nEUKPJmGhH2YMGEnlwF2ihvDhzNrNuzwHjI0BcC6EGpnSA2j9wCCC1m5B7oTsSBtz
         nXqZvUQPj5BAW0BqiJnJhTxl28ptznhmPGntycmbkvQfFdb/E2RC+2Sk52qZgK09qsJf
         kK0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ML9d8xLUekYEG/14FmP0xne6BCrEwGAP/JXGx3H8zrc=;
        b=Gr7KjuKAFq9wWr3QX1eTG1ofLgsAKM3i7vGjui32Hw1v/DW3xlVeqRS56gxM1MkQi1
         XdlJKgOHcPqiQXiUbWXUK69z9xlIfLo5EFC9DjcqbxR2MOa1ZwE5KIl7cBmKJ2sezeQw
         sgRl7jWl+n2noT8p4chdYkfH+Z7l01N7ulXk9kc3RoWC4QrC+mx5dxEwK1IHy5ID6x8C
         /xQ14ojy1in3S0pYjIAQh9UwdAkN+0I40xJonz9v/OFwkGs639rZU8tDr3WDcdw9U6qh
         Jn4+Ge//bEqwwAEPCQ+vZ47oK2h3CZMC7C30KzA7JN/5/XDA2Fh4eFSbK2eD5rOiIa3l
         /UgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HNLlroBU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ML9d8xLUekYEG/14FmP0xne6BCrEwGAP/JXGx3H8zrc=;
        b=ow9049EaqrXW6drqBJXM4fVi2G0VsXU3MilXynFV7227ucAyYLKhV8NL+GV8GM+V8Z
         bnWsNXt21tK8FO7XNCT1txxswrzzlyoQxyCtUB1h9KWsnelUynGSPD82+jV0MRDCFtuO
         rp+iNvC9R3OA1foPGNnnHRy3vOuVfJ1bIknjMymOlgR14BGA1fybpoos27QPrr0Z9a/g
         rcddRaqs0YMu+J0VtbEEebQbEx5JuJXEXDuCgNrchJgtTOGb/kA3fiISFUC0cmsWbsGF
         pEqB/PNXDGhl7BabV6FK43mZ+BSR4jk+ohwgdWtSquXSGRhPSbJfgwaIl4FSAWeX+szT
         xrqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ML9d8xLUekYEG/14FmP0xne6BCrEwGAP/JXGx3H8zrc=;
        b=EfnJSfOFyCey4z7LDNxtmce323CoEgacT6S585KSORoe6CPDsKFMDfCuIy5PoO9K56
         OQAnGQd0bN+32odAyNlMaM0S5gAUtRf5sgPEJg4vA8ypFRsLY/bXPRkNeoB+mNP0CiYa
         C3Z6zR95VoLd/tY1zn/HC93InxiBe76OAY0+Up9XQAQJUtgfZBYnm0cFM5ObbcqZlOHk
         AdFBh2Au1zho6HLls8ivPQQU0FzTZFKfI12PE8hITBaO9VWCEbiCW0dRocGFTN9yAMAW
         lqptUxY+8Z/krCyXeFzBM1Z1uvMtWcYUuCbM1U+fDH4GDikLpSAm9mdjHalPyGYS7IHb
         +vYA==
X-Gm-Message-State: AOAM5334X6dyVHJzIMnI0tGtG3v+LyXmrcNFZipltiXoZ1V2EfZsfoFc
	2xJWHRF10H6Lk1PtOFLKuGQ=
X-Google-Smtp-Source: ABdhPJxFpkLMHaKGf4lCqkJwrGIt50bkGL4tVzpjNaL8gXPcfrPsfL3CFHZKVV4h1jPIPUiin/yksw==
X-Received: by 2002:a1f:b6d4:: with SMTP id g203mr6324542vkf.2.1596547486002;
        Tue, 04 Aug 2020 06:24:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:d1c5:: with SMTP id i188ls960478vkg.3.gmail; Tue, 04 Aug
 2020 06:24:45 -0700 (PDT)
X-Received: by 2002:a1f:230f:: with SMTP id j15mr7223170vkj.83.1596547485713;
        Tue, 04 Aug 2020 06:24:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596547485; cv=none;
        d=google.com; s=arc-20160816;
        b=fk7uUctCJWWjQS038tKpJp6MqO63B6kSuHrpGbdtk4uJD4Jx4EGMyhEpB0Uu5cSsrX
         BHaswzE2yMCekgCrxLj3ieLZdSuKd0DCUOuC6NB958SgBTYA7IlJs4UA8fjPzuBx/RT3
         qNO+lnRmOKVcO5mlRV85YNk4qUDkt4utdUCHC9SlnWN3nl98r0vAGp+A1BgLVQT1g27J
         URtbn2TC6fjjSf+jN8wzQmYbbMrNpSENruY8C/tcm66SBZZ3ck16P27BVtz3AYgtHPZk
         vp/yUvK7c5YbYklSOdHb5r+Q8o37aGjBfKpadiQm6wa36aBw8lk9a8o6yR2MmfIwHqSB
         Ochg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LL7CVx3M+GnKSSe8eUQMx8d9kBXew/bFtxjaZTrFB4I=;
        b=rO0VftUR0xSzG+44ps/Zk3rw7CAyVkn7BKHLSQ1RrPv0Yh32/zzq96VWvlv0te/x91
         TTtrLCUAKMEciClyg4Z2EKxmH2TfMFa4YyDSz/gwAajkbxcxyRCAPLBNjUsDMKoJ664n
         zD6jMMeSiI3khp3dNaS6FH1sYlSKk0i5cuZrYqFzmDGNrQc4K7/CSCJd1reNBlgDVheW
         dT9fq9KtWKlsbYK8FesioemEmbD2jI9babGm4zvWrlT5fg0QEtgI01yLWpmtqaAKRVwt
         KkI3PZeKc6SmAuaKb9l7sIvC2eDB3CdDmwI2LnPOaNLiVQm9SkmrsIFbJWP5Ij7ASNP/
         ePuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HNLlroBU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id p19si379371vsn.2.2020.08.04.06.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 06:24:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id f5so4832636pgg.10
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 06:24:45 -0700 (PDT)
X-Received: by 2002:a65:4bc7:: with SMTP id p7mr3313300pgr.440.1596547484618;
 Tue, 04 Aug 2020 06:24:44 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com> <26fb6165a17abcf61222eda5184c030fb6b133d1.1596544734.git.andreyknvl@google.com>
 <20200804131939.GC31076@gaia>
In-Reply-To: <20200804131939.GC31076@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Aug 2020 15:24:33 +0200
Message-ID: <CAAeHK+wVpLvjcwGzD=0FyXiC0+tf6CU0uwh_vfzBXfaCpDyKPg@mail.gmail.com>
Subject: Re: [PATCH v2 3/5] kasan, arm64: don't instrument functions that
 enable kasan
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Arvind Sankar <nivedita@alum.mit.edu>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, linux-efi <linux-efi@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Elena Petrova <lenaptr@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HNLlroBU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
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

On Tue, Aug 4, 2020 at 3:19 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Aug 04, 2020 at 02:41:26PM +0200, Andrey Konovalov wrote:
> > This patch prepares Software Tag-Based KASAN for stack tagging support.
> >
> > With stack tagging enabled, KASAN tags stack variable in each function
> > in its prologue. In start_kernel() stack variables get tagged before KASAN
> > is enabled via setup_arch()->kasan_init(). As the result the tags for
> > start_kernel()'s stack variables end up in the temporary shadow memory.
> > Later when KASAN gets enabled, switched to normal shadow, and starts
> > checking tags, this leads to false-positive reports, as proper tags are
> > missing in normal shadow.
> >
> > Disable KASAN instrumentation for start_kernel(). Also disable it for
> > arm64's setup_arch() as a precaution (it doesn't have any stack variables
> > right now).
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> I thought I acked this already. Either way:
>
> Acked-by: Catalin Marinas <catalin.marinas@arm.com>

Sorry, I forgot to include that into v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwVpLvjcwGzD%3D0FyXiC0%2Btf6CU0uwh_vfzBXfaCpDyKPg%40mail.gmail.com.
