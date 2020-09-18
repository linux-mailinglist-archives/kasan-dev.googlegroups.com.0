Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZMDSL5QKGQEJ2YFMVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D03D826F986
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 11:46:13 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 26sf1860669ljp.19
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 02:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600422373; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vo+EKYnTezv1bX/7DoJidcK8YTYIn1hvsuVsQKb61QdtpMHnPGH4WjZ/FcKYPH3wRX
         evPcCcvQ5bAo+SPTE46n2whPJ/9NqBdN8Cj/Mq/J7skL73M64K3TD8H0Iq3SR7L4OQIx
         T22YKHMc9uuvu320AQrVT+VuiCh2Hhb/jqDwbzofm2qOpMWIkzabJg//tcmhGa9QYYGE
         v1XOPVcUb/RL+8v3qNYHwCwr7+qtqzjJS0bF4I9mbdY3iBdshA/wHzxo/FzbglNqBXAN
         Xa+zfMejwjbhORXffu0UmKCo3Uz8bl0Zh4sTpqbQRUWsmJE+A3J+k7/9R3mzVuWhmXRC
         KXPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f9srKKKuBZkRpdi3ZG+fCMcSMTUQ/wcpINoGyr2X0Ao=;
        b=QmLOQ1R3h01Y8IO6DYahFBbro+zqeE/gGKuKiagtLH1PZUHMO+Htbi/cEjowuZJr1/
         W2QkCzWop+yDv5HycoxBCEPW0dEEZxmSsGz9VDwbvZfhR7RIKcQdIT9FmoKq9I3fYTKE
         gLZTrg4yodhNpLr5P0HmlyUbAUzydMVp0/lTZPrENH5s5SDI0PM9vf3Gr0Uo49R/miKO
         6COfSEFOJe4r1SeudZHUN5HXgNHfW6nJYASVI5fxw+UlpGVQaflPPS8AedufIi77RX7k
         SBi60qS4T/aRh7jkOc4JPboOql8CqeEJD30ufOSuw4xFsbIiEj25OjL+pfDS939X+IPv
         7cOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qqhCH+vk;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f9srKKKuBZkRpdi3ZG+fCMcSMTUQ/wcpINoGyr2X0Ao=;
        b=YhvElkbTpes7zNbX64vET8qarIuUyHNs3zjEi/MHqDxYt44JfaQhkVGVnor3YagNzl
         GltKNcaf59qYCaEUuTva85uakcntQh3R+J3LFoapW7/t4ZrYXn+Mu+5ScHVoI+0f6oLT
         Np3GevadGU73us7DDDcgsHf/+WCAoLpWQNXT2KF/zQuICFbxafOIDLYLpAqqvV1kcCew
         V3QMTpVHdJf86FgtRZaH40gmB3VYPj1fX0neOAwr5S7lurXD1l7vS2XM1h8A0F1kEWGr
         IbtQnz65WMH7gi/nu8gXc+JmIgJv7oMq2ibatZGBTPrS7nFqAJudWM1xnBNTor7UVM75
         wYeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f9srKKKuBZkRpdi3ZG+fCMcSMTUQ/wcpINoGyr2X0Ao=;
        b=JvbKHwStjkeAx+Fx9Tyxg0X5N8N/04Vvoqp4CXFpVVG6yX1QppuuGLQeZkCJeoz4Uw
         jCt5BvsFzPfQujfAmrL839+sOlJBnYVN8ESWUeFSSsQaZAKRh9ux47haWnYTYo17W6LD
         d+dXsOc3Igp6MaQCgNPi/wFHuRtmAYHSf3DfhrPmY8SAcKKwrNBj5zhs/6nZHaxGRbVR
         7WGOS3xC23SAb5/ckuJH5RlF7WOz1MHBXczwzX5oRo4DnLsbiJ6UcKa/sksGSTZDJtlu
         8MnpTn8rgzmPOTrvgTWc5uUjCAjj8Ma19ePbzNPQ4CTL8pXwJ20lUwtt0JEhzxnSm7xo
         cHxQ==
X-Gm-Message-State: AOAM532szbFuR1wezJJeC1f8S2KP/RF5HWA7B0qNZ2cCo40tg5I8AR6S
	NTBn3dTEf+pqzu29XjkTcLo=
X-Google-Smtp-Source: ABdhPJxq2pcF+02eUbv0IFWMGXbbmiW+FGloX5+/LFddZli6QroyKFBX+1OPyAqNr610v1Ir/JMBng==
X-Received: by 2002:a2e:6d01:: with SMTP id i1mr12044552ljc.181.1600422373408;
        Fri, 18 Sep 2020 02:46:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls739927ljc.6.gmail; Fri, 18 Sep
 2020 02:46:12 -0700 (PDT)
X-Received: by 2002:a2e:9b02:: with SMTP id u2mr12995207lji.303.1600422372389;
        Fri, 18 Sep 2020 02:46:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600422372; cv=none;
        d=google.com; s=arc-20160816;
        b=obmlju211QDYV90E0UpsQNf+HW/Tap++tr7G5pOYuiBBJ/s54uwhqAIGlzbJuYHz04
         fkYAjw7OXsv44Hw4TD/R1lvZKcuAbtJTIMmv97WXtLlg2IUpKl+RM/fYYRSJ9ZEEZIbd
         K14+akcAUZQn/ezp4fo/8tc2Hp5OTmkDYbDK/wpUPlCGLa7yhwfut3UZhlnpRD7cwPSz
         SYRYNWHIbKrYA24S3o4WSdWPfXvC2I6uVPyvvrK73ibw5x3o0zgHkxBgK9WJPIO9DcAc
         VKH/UKXKuMnPb5ok1/IUeyVpwwp00ACdl46xTqr0IZzUEPbdUl08bFRH+tglhUUbq1TM
         KzDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XgPTd8GJDPNaoiWfgXmr6X5TAsaC/3AQihdlF5dTIOI=;
        b=h/h2V9PwvqVU8oPDSMRVs1FdZ2mthQSU7LviXA4LoHpWHVWeagMNj7WnwIWbfeHEMX
         3S+2qX5MwYrbjVsKMc7GW0yse3NH8THTSXDCTKtqifnnOahg0boaChBBjrIvt/4VJQYd
         Haey1dVjkJWJa2nrcgUs4h9397LZ2n/NMmB57B7ZkbNJO985QKqCKCg+qItVXmix8BzQ
         hcMdj1oeFs5cVip+NpwTNHEETkibzmhiAoz7OlDSkXhuX0LzzedP5J2Hg5FLIRRy8n+l
         Mr26Fz8WkLoRaPykeHoXws4dPPboz9NPGhI95eSQvDDV1zXSw/89TSV9/o8JiXpK6mUa
         oa5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qqhCH+vk;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id f12si89518lfs.1.2020.09.18.02.46.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 02:46:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id z1so4961887wrt.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 02:46:12 -0700 (PDT)
X-Received: by 2002:a5d:60d0:: with SMTP id x16mr36360211wrt.196.1600422371731;
 Fri, 18 Sep 2020 02:46:11 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl@google.com>
 <CAG_fn=UACdKuiKq7qkTNM=QHcZ=u4nwfn7ESSPMeWmFXidAVag@mail.gmail.com> <CAG_fn=V2MT9EfS1j-qkRX-TdH4oQxRbRcBYr8G+PV11KJBO26g@mail.gmail.com>
In-Reply-To: <CAG_fn=V2MT9EfS1j-qkRX-TdH4oQxRbRcBYr8G+PV11KJBO26g@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 11:46:00 +0200
Message-ID: <CAG_fn=WpOoAf4t1iKrWcD+LBaCvL6tf_QYeqoX65UWPi92h=6Q@mail.gmail.com>
Subject: Re: [PATCH v2 20/37] kasan: rename tags.c to tags_sw.c
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qqhCH+vk;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> Also, as we are going to have CONFIG_KASAN_{SW,HW}_TAGS, won't it be
> better to call the files {report_,}tags_{sw,hw}.c ?

Sorry for the typo, I meant "{report_,}{sw,hw}_tags.c, mirroring the
config names.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWpOoAf4t1iKrWcD%2BLBaCvL6tf_QYeqoX65UWPi92h%3D6Q%40mail.gmail.com.
