Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ7GWD6QKGQEVEPLQDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 21DF62AF893
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:53:28 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id h67sf829056vke.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:53:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120807; cv=pass;
        d=google.com; s=arc-20160816;
        b=uNiIaQbm10Q3J/Xn406SHM/Eg5lnyrhmeYIMblC49mvzOQXhpvbeFlZ9hbKwqk71hj
         25jmjVjSMPko1A4S1A7WAL1wtOuktjdNRqObASUtRxFVQvvNfUGyvAprKLMjWvDY+0yc
         PoaQb/IA7QL0dwfbuxdv3AbmHHIFpXdSla46RfoH3IrhSx4zfmFvLb9mYfLNf7ugCIJE
         p+4MPid4hm0SwrUHoKb6qhqYnIcysr5U+PEdUWdKloolpSh0Mcd3YysvWS3XnEW8VEBJ
         XaLx0VuLWtXv3jrC3TqksgbcUKdgPmt9G2G2DoNqYvcUNF+ZBomX9py5ohx9bKTd71+/
         lZrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IJapdLQbMW+r2l5Rl7bC0pEoi5WDmLuSa3vERUcE2eM=;
        b=wxNZ18Bd1Ki99zJ3bC+ugMSDXqLRmZdSf9G/gGXhtJdpAtrhcvekqF8Yd+vPuJBxjl
         xlmfA93DJk8Dh8MCtMdg+oBMMzlQCfGD3RCBitrzFLHSV4mtPr95gHf4IooOpHU0O8gz
         vPpzjIPwDlMpaMzljZUVXzpmiN1ULOhJ1lMqjR4G8cTYkklXorsrEQpP4U8Lh7AVdOMi
         H/O4S15dKtMMiINej3XYLkA38ZuivhN5b9Mz2Rxl1+BtOYMPxckPK7XfsdtPtkdWfPAG
         TYPCFIPQCnrsaenJzolHqihnfef076hUvpb5xjIrPMMsbtCu9RnecaU1kBGVMgzS4HWJ
         lfkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BCG7CNt1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IJapdLQbMW+r2l5Rl7bC0pEoi5WDmLuSa3vERUcE2eM=;
        b=ABt8ntBhainpSY7jR9jcOrR3zWCcgDGPidc3JH/VHg/6qoGsBU7/0GzLsreEoRSFdY
         TLO1eNR7O0Rz2tKDKSlsLgZ6DNOEz3hzNItKKsaFIqq9hBn339LcJ8psS3OSZyV2hWmG
         L3apO317auxviqFJj6HFlSN7OO/BbFgofJYESsUXcLsc6iviTPm7/SRt/tNCEBM4PeVI
         3bH+Srefa8bc4s17XuAPipOq9pap+mVkRSgy82eV3KMrKXIXbp9bxSP5dMUqWDLqTvGB
         91uqWIUKZARptR4nAbuGyeQYrzWTWqAJ5Gao8bCucse8D24ZScSo5cfuPsQc+wOsR9Ak
         iwcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IJapdLQbMW+r2l5Rl7bC0pEoi5WDmLuSa3vERUcE2eM=;
        b=oL4wCFDAlrGsBsnKeBkm6HmZOxua4t9ykU4afLiQT2Jtouv9UtJFevDWGMlxN4ZaK4
         PTkH0rU/r+NHMA/4QZSpDqdLu3a0g2r6EbpiSwTE14WocgwalNrG/Y1FIoxCeAwW6Nre
         ppnNdj0BTVxjY3cXXO7fWLZl5dra2ghsdivaFx5fA74KO+HntAYxqT7TXeH+1suI8OM+
         Uf6mhcj3P0M3DdFIZOIAuXFjv/wRjcvFmIxGxV7di4gTImAPiY/1lWhEjsliUwOecia3
         RaAWyC/O454hdl1BLm9K5QVzDPFIiNf79v5o/Q6tMReZRbr1kbICHlyiVAck7JhpSqxH
         fVmA==
X-Gm-Message-State: AOAM530RZ6mJ7jNlgOnCl+qrj7ntHocSlpuQjhGJUzi/NUEtN8Ep5XIh
	7hWyrFanjrAUWkX81Qv0z+8=
X-Google-Smtp-Source: ABdhPJyP7ZQmXk8DwQp6+gE0ucnB6WMox2jWt0U2/N3K2X/jzvcucHO0abD0JMh+b7TZePYfPPLgtw==
X-Received: by 2002:a67:ea02:: with SMTP id g2mr4022422vso.3.1605120807221;
        Wed, 11 Nov 2020 10:53:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ee96:: with SMTP id n22ls125416vsp.2.gmail; Wed, 11 Nov
 2020 10:53:26 -0800 (PST)
X-Received: by 2002:a67:cc2:: with SMTP id 185mr17148483vsm.42.1605120806753;
        Wed, 11 Nov 2020 10:53:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120806; cv=none;
        d=google.com; s=arc-20160816;
        b=wy5DlmrjtnJmhMjmQzJ4czQG6NXzl8NszowO7970g++iNkOilh4ndDZbIg7ONDf0sl
         ddHtdU4Adh9NlppO+RH5bQSFwYFXDg+yUqXYVjn1qJ9cxdIrLVZFxkEUHeihphiJpWTb
         icB7Ol9mM5bGTDe60vnC8aRkHNdt9dCBcox5rVnYiMHVrUeMGNKlTHPBfOAiQa3V3I+f
         bXU5y23Si99Kt6zukup4z0xt8MGHEPd4hCeTMwfcqILs4RwCD+mSxeKclsyXUPTBHIJl
         NcApeIcoo0YPIDZ566jOARpIEoXKWtiROVbBIhRgJu18jRq42bCAKE0Mc67IIdQ1qkBr
         neAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HzAJlsJ6yvoLH7Y3l/4EC1l7M1jcLwaE/y+qJVhny6w=;
        b=WCQculO55hAuWKpqFNMnGUYr38t6wFYxy15+qc8o0LCxCQSxuXatgO8tInHF2JRqj7
         GQ0RkTCsHx8+cxUchqeIANwEnEzWNyLyq/L9AsmpBShPcGd8hAQrDLB6YzM/SpB2+ppP
         mXJZJoVK++JTy2mcv2qIJKCJOGRdrWpjgpnl71/Qz0oH8sAe0j9yxWNuc+4O9Uo0N4vN
         SxfQ2dBuf2S5UDWU+K5mY4LgVkQdOmcjKGg+VlwI2oY6HjiwwC9PQllnkBTU1TOh5P+B
         nhgmfulATsgbg34rFEswsSg0/F47RCnMpzHoTCax5A6RPfEOhpjftusZqM0Fx2eTrJuX
         KORQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BCG7CNt1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id c124si193285vkb.4.2020.11.11.10.53.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:53:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id y22so1439103plr.6
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:53:26 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr5058987pjz.136.1605120805834;
 Wed, 11 Nov 2020 10:53:25 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <55d90be0a5815917f0e1bd468ea0a257f72e7e46.1605046192.git.andreyknvl@google.com>
 <CAG_fn=V1Pu1NED5K6rJJZ5ufeQwrjN_JShO4m_V=gbLwry7cyg@mail.gmail.com>
In-Reply-To: <CAG_fn=V1Pu1NED5K6rJJZ5ufeQwrjN_JShO4m_V=gbLwry7cyg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 19:53:14 +0100
Message-ID: <CAAeHK+xT6oL_FqJVvgCFA55bLQF72318CaS8F_aSthJmMbMuMA@mail.gmail.com>
Subject: Re: [PATCH v9 25/44] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BCG7CNt1;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Wed, Nov 11, 2020 at 4:58 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > This patch adds a configuration option for a new KASAN mode called
> > hardware tag-based KASAN. This mode uses the memory tagging approach
> > like the software tag-based mode, but relies on arm64 Memory Tagging
> > Extension feature for tag management and access checking.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > Reviewed-by: Marco Elver <elver@google.com>
> > ---
> > Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> > ---
> >  lib/Kconfig.kasan | 58 +++++++++++++++++++++++++++++++++--------------
> >  1 file changed, 41 insertions(+), 17 deletions(-)
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index ec59a0e26d09..e5f27ec8b254 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
> >  config HAVE_ARCH_KASAN_SW_TAGS
> >         bool
> >
> > -config HAVE_ARCH_KASAN_VMALLOC
> > +config HAVE_ARCH_KASAN_HW_TAGS
> > +       bool
> > +
> > +config HAVE_ARCH_KASAN_VMALLOC
> >         bool
> >
> >  config CC_HAS_KASAN_GENERIC
> > @@ -20,11 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
> It might make sense to add a comment to
> CC_HAS_WORKING_NOSANITIZE_ADDRESS describing which modes need it (and
> why).

OK, will do in v10, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxT6oL_FqJVvgCFA55bLQF72318CaS8F_aSthJmMbMuMA%40mail.gmail.com.
