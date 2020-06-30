Return-Path: <kasan-dev+bncBDE6RCFOWIARBF7Z5T3QKGQEA75HX3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CDE320F583
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 15:22:32 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id t7sf11824963lfl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 06:22:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593523351; cv=pass;
        d=google.com; s=arc-20160816;
        b=genXMzRKIA5az0j5JWtqTQssX2RGjBoiXOw5WxG2zyFbKf/lKM1dTV0f1KtekISVAW
         F0FJcygEif08MGAsytP06YXOBgYXWa2XWJJkHBNnnakRH3cSOD4dU99v83gsRzVInB36
         ulm68Dkh782ZuZfcTbbXBC1c8MeWFoKjW1ixTUvF0ICvXgiKce7FlMmccLdPdi8ZXw8V
         BH+sx/SDf2UxuU3wJYS5PEtD7HiKtVgHnAU1v4fesDzCZTQHXYsQ/Kc8rJAT6Scss11q
         angIcBXFcs8VHhP1eCD3ULDe5AUQ7Xn1kO9KYDPOFKDEgLJAPYsr3VmhiLbhMKNnSVG4
         H4wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=hazYfhIFh2OsOQPgYCJMpM8uMoXL/ivAfzSkJ3JLm/c=;
        b=yo5qntoifSDxhmMLSotrAYNh0aIZlJF42kbxw3T+YQDCRc+/5cUnK07MfCeXwDT9hN
         gffnEnxWFV4YGuPTLwuazxRayslSXJv93c2s2Jyf4J75mwrnye/nkNaA2SMKKL+e3s9i
         H11Y0h14b1KHkMi3TyFzT2j+KigTvxEdcACcPxwmB27kW4K7FDE6rtGe9BHCQ3aeF1B2
         fuMMBkyYeaQIIQaPieHAgwWjG9aMq9teGIBh5zOSb+SRN+70D1w1HFQ1jVd7kbeu9cM4
         AYDqhNvR00A6NRzzaF7W05jRHL881zj5G8KoMUbIWEdf48LPTDuzE6Dhn/dypGW4gy/8
         yBNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=sicns1Ex;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hazYfhIFh2OsOQPgYCJMpM8uMoXL/ivAfzSkJ3JLm/c=;
        b=TLmlykBvPAJXlSLy16JObFXTq4FDC+Xwkx0oQFBTfGS32Vjjh67OI+zVZirCdi8rx0
         PK0Br5WMJRPoeOmG1/M/yt2aogfSwE3BnO1TktPOhqA5wuKIx823fC/4jxzOuhQWuBIX
         00w2fHVIU2nsKITADSvTYm90waN9N78KoGwcRM4uk7NpMlYLQmQQ65GidcvTYkeiECxm
         X/eD7i+fEOUuP8uVlnwx7yUzn0FJ/M7UbVv5t86ljjFyfEn8915DpxKX1XodWR0yGMVB
         y8OEyRJ7pJbtCz/HNbgxZNP+XmZ2R671kBnb2wmaHp2P1iszTxMhKUOsqKwfuPlED9/j
         bU7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hazYfhIFh2OsOQPgYCJMpM8uMoXL/ivAfzSkJ3JLm/c=;
        b=su8xGV+8VkUScNQGh7Toam35Sfceb4ADVPuFxrQnMfxL6pL/F2IJ+gg1llRKCTRmil
         aO+KVEsD2pcCmTGXjkuy/yAcNeRGKUKBEBbUXvDhmlp0RLsEIBrT7cXa4cle3kvmnIPX
         LM9o9OgBe/7Eme/DPIYz02urAyaMhtJyk1MD/047/mRlDa3M4Pwjlz/4x/b2t6dkpBTb
         3LeBMXJUtPBqD9dJ7WPFSeqMi7e7ToYxCTFgYnkgv38muCXQym3oD1eTt4gtru50q80c
         2PRrHA3wOcxVtC3N/HH2WuE27Xtt82qmAp06LjFnoelElMNsZGStZT8Jy4Xgbcyrd9XW
         epcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530HnQ6KNi/WmyYdzpTJGVXXtbQh5ThQIz5sscT0mocTTBdjyQyH
	0fVI02AprwnNBaboCEuOf8g=
X-Google-Smtp-Source: ABdhPJxPR5Uq72ROig4jRoN3BC+YEESBCC2kQB7KHAEEEQ1AeTV/uBwsyGZo/oXnzcO2L6fnSb84TQ==
X-Received: by 2002:a2e:9a05:: with SMTP id o5mr11029759lji.63.1593523351537;
        Tue, 30 Jun 2020 06:22:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c188:: with SMTP id r130ls144867lff.2.gmail; Tue, 30 Jun
 2020 06:22:31 -0700 (PDT)
X-Received: by 2002:a19:4bd1:: with SMTP id y200mr12065663lfa.60.1593523350997;
        Tue, 30 Jun 2020 06:22:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593523350; cv=none;
        d=google.com; s=arc-20160816;
        b=zIessBtdXVNhTMfL4EREWiIlBr8CulltsU4OwZipkvWROJro3ev5UB/9ATWl8Rlv3U
         NQoIXU2nawvdIOg7CLA0UjrXT2Hv/3yYfzS8+2qQEHBrsE9mxf/6Mz2Qupb45jdrVstv
         O8jQf5GKNJO0F5epj9qDE8XD2xQVoKZM+LIv9+68Di+8L7DEv0MJWC6EkddKkiI4flT8
         q3VJZd6cwjmv5Z0/kC2ZypDrGycgtHU0QBfgnwABIyZSN+pDQx1EKgaKV70dSQVtC4aj
         aJACTTZf6ciAyTOeEKcASjfJVlgYRJNMJd6Irc6SK9GdvRqzrcjMBWBHBw4oZvhrIfsI
         FZVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FEj0Ifm2HKHczEFizR20K5HvSlnwJVp+gdjz0L7flE0=;
        b=zTqirSgy9mjvbIqtta9ViOpaSJKUIo6E831gaUOIcn5hFnNNucEkH35yJmK9gWdbpI
         baHGFvQvNV966hs+LZ5iZKcGubdk61PsegtniRPLO56hlMT1wktO6zF9OLNiwKoz5Zxk
         +y5Cv+j6TVpbw3e51WgFTXcwnYmGedH5g8CUHJd4xOFcA6y5jODOJTCAbgRaHUMN2aqx
         TimsPdy1PlyH/2S0p6P7ZCgNyfDN+hSF31mVeErsWArBwT5WRaM4OMHrEwlduOQb0IvM
         H8ajuRj15FRIyos1iJJa2/VXw9jkps9r+3SdUE/I+SwugtWfPWQ4WrEtuzeau0f+PphB
         kTMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=sicns1Ex;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id o10si186846ljp.3.2020.06.30.06.22.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jun 2020 06:22:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id y18so11356297lfh.11
        for <kasan-dev@googlegroups.com>; Tue, 30 Jun 2020 06:22:30 -0700 (PDT)
X-Received: by 2002:a19:745:: with SMTP id 66mr12006454lfh.77.1593523350421;
 Tue, 30 Jun 2020 06:22:30 -0700 (PDT)
MIME-Version: 1.0
References: <20200615090247.5218-1-linus.walleij@linaro.org>
 <20200615090247.5218-5-linus.walleij@linaro.org> <20200615143316.GA28849@linux.ibm.com>
In-Reply-To: <20200615143316.GA28849@linux.ibm.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 30 Jun 2020 15:22:19 +0200
Message-ID: <CACRpkdZvQgPXBsdUO1JwBW0gE-Jhse0s8U0-Y5BGCcxkq_Ue2g@mail.gmail.com>
Subject: Re: [PATCH 4/5 v10] ARM: Initialize the mapping of KASan shadow memory
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=sicns1Ex;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hi Mike!

First a BIG THANKS for your help! With the aid of your review comments
and the further comments from Russell I have really progressed with this
patch set the last few days.

On Mon, Jun 15, 2020 at 4:33 PM Mike Rapoport <rppt@linux.ibm.com> wrote:

> > -#define pud_populate(mm,pmd,pte)     BUG()
> > -
> > +#ifndef CONFIG_KASAN
> > +#define pud_populate(mm, pmd, pte)   BUG()
> > +#else
> > +#define pud_populate(mm, pmd, pte)   do { } while (0)
>
> Hmm, is this really necessary? Regardless of CONFIG_KASAN pud_populate()
> should never be called for non-LPAE case...

It is necessary because the generic KASan code in
mm/kasan/init.c unconditionally calls pud_populate() and act as
if pud's always exist and need to be populated.

Possibly this means that pud_populate() should just be turned
into do { } while (0) as well (like other functions called unconditionally
from the VMM) but I'll leave this in for now.

>         cpu_switch_mm(tmp_pgd_table, &init_mm);
>
> And, why do we need a context switch here at all?

This is really just a way of reusing that function call to replace
the master page table pointer TTBR0 (Translation Table Base Register)
while setting up the shadow memory.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZvQgPXBsdUO1JwBW0gE-Jhse0s8U0-Y5BGCcxkq_Ue2g%40mail.gmail.com.
