Return-Path: <kasan-dev+bncBDX4HWEMTEBRBE6FRP6QKGQEYGWTJBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C98DF2A6B81
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 18:19:16 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id n5sf8994827oov.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 09:19:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604510355; cv=pass;
        d=google.com; s=arc-20160816;
        b=DbkQ8r7AgR0K0hfny4yBXjA7vwTZ2Iz3Ph87je2IouHSQgT/0en0Lwnm7Tvsl7uGId
         /idCY4x1PrTciLDbyTVBA428HYt6A4dLjQ4pspGZ8pPbAr3Ro+IpvpHHLrUhATdsvTdM
         2j1hmbNh7qc+onhuGfCfxjyp4G+cT2NPlbkBT3FNWABWl4k26Nkth30LuHVkWJBTBvTk
         ZSkvDlRHSITMpfwQvO/wwhH+o/ZTsIS2tyvypIlizjx8eY2BY+GxXjU9qJNQ2dRVByJi
         Us0iOtLIS6MEsUKaFWtlXikVFWZLzcocsiXuecCmCTgOAz1a+DzlBYLY30vvgtpFdV/x
         cQGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0rchDYZsRDCqL7IxlLFzhJlc9II/EFglvqVzU/EZlcc=;
        b=W8cZSB30kptylbTMTGNTwW8PGuewWlKTL55oXI48jsWxeVSq9IEcFh28uJ/0O0VFQP
         VSowJwRJgcTw9rnuvi30ZRyBalR5vCfBSrZg6arWvFxMD0LTTyFQliNVBL7Oos1J6421
         OwVmxk34wIoWSHjmPuqHo/Fi7BCYIvoGjjZO269Z4blgqltPQl8+9tS3RC61emYYQYvr
         /0myNXdyqZGsBcpCmVBAYMM5geowgLrmEovXV2tl7MMNFz8DPLU00P3T07P+f6CRp35U
         Mt4FWVGcOqBU9cNovcGGErNwDZ1qtSm16Jp+re6mcfbRg7HktqjynsgSKud5b1ZsiUGe
         if5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BhZZuTp0;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0rchDYZsRDCqL7IxlLFzhJlc9II/EFglvqVzU/EZlcc=;
        b=YlkS/se+2GvVPZOlzt4seGsbOmmFWN9JLAkuBfH2HxMoUsRQFDVqonhlaya5Zk01pJ
         nKYWqT2ouwfE1F9C/LqxVQJjGMjE14e3xm7h2VDQrUnhvA2VWp7pCLp964MUJu92jLuj
         Puv5y8GzZtmOFDh3EJT9vocAkSF8mq1IXuhCmsIZuhHBt87NV+4WvIOzBBdLI0/iLPW9
         IcHjV0cVzPR57ZmFyRqL3bdjE/kjYo7XhPhUhw6MI7tSlgsptd9kJspZcEwP9Sb3l9ci
         GultU+mRGK6m+M8Io+TtT5UyA9/yapgzxvf9FRSjYYTsOe8btjGK4FQ1mBs3NV1hNT3S
         2zYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0rchDYZsRDCqL7IxlLFzhJlc9II/EFglvqVzU/EZlcc=;
        b=dAO3/tYVZriVZ0oZdah91W7pgg8gAwpwX6ZicvMogla1HQCJRFR9+XeA68vZfZjyLs
         nEvjYxxVpevZzm9TFbWaevYtNqixW++DjtgiUYWN/WtjV9eMucI+L5ANxQjRT1qUVXq/
         pHCFvIsu3Hx6HctOdP66BNZADgSpKgb2Qv/5q0Qx9KYr98ypPi5eaCcyKU8jkfMotIU7
         7QIvC5K0kBpw2SWTZfeNbaAe7zZk8Zu7XSDaPZ5SP+wV96I2bZFdrXrN4pGgShZ1hqmG
         YDdMZIySXgocUKHfU7ZIa78FjClOKvAGaKzOGZIiGTCXnROtkOIbpmOITzaNtxS2nBWq
         HjUw==
X-Gm-Message-State: AOAM532utjZBZbaT/MWKj0tSq2dIg7W2lxxkKtKFRAFX8wUXWhyDYlD+
	3X2Kj33KTXIy2UrKW/f9Pks=
X-Google-Smtp-Source: ABdhPJwd5MPTyCm1Rqv9vzki0OJmlYvdCfzOzB+312eT58VC49kIywmFAocIiOG5jPxmOqDEgfiYKQ==
X-Received: by 2002:a05:6830:1556:: with SMTP id l22mr10660508otp.102.1604510355785;
        Wed, 04 Nov 2020 09:19:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls679000oth.1.gmail; Wed, 04
 Nov 2020 09:19:15 -0800 (PST)
X-Received: by 2002:a05:6830:22da:: with SMTP id q26mr2213307otc.127.1604510355406;
        Wed, 04 Nov 2020 09:19:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604510355; cv=none;
        d=google.com; s=arc-20160816;
        b=Aw35Y+xKbKatJP+YHckxijWR1Bj3Dk8SEcaA5ELNrx+zCTO1eyYujsmfEgKgTyLSSW
         P23DY/GvmAjSKh6MzuppF8lC06q0Bctl7EvJ236OT7mwqiYAzB0KxhX3XG9SBfwyPUeJ
         oe5eVQEnjABfY7aQBaaDX0HEmtLUQUFcp5mL2BqobPxNp/hJ5Y24B9IUuEbtD0XbNx4i
         3x7aGIrx6p3wXkMrxyl+tLZgKf5iEEV4ct85BY4Wdscuuf908JloimPKjILgom+QRkKC
         Uo50BHJaJ/FEWlml671usjSpcGkQiSi+1IeZri3CGttJY0OHhen1C2KxTPIILL0eaZQl
         9sOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BRsEpVNsm2U1NymzNtz6XZIq+7ItUy82ketxZkuXZwY=;
        b=APka0/fuPDPCCRoM9Gi3zmydLHEWDOQQo2MEZwN7NBJZEMaulx8uNzro+C31T//lJ/
         iDRQJ+BBYT+zCaR7m6Mg0FJalJWDapY6Fob0F13XtmYqdn2uM/+OIZM4Z+VM+n/cmVTf
         hWtUPVWddabxsokmEcyEhailn3qljDqD80N7MMQfzQViuCTkwpTD1sV13mWR9vNoA4L0
         CJq4fXy6QGPP6m1ejqKvc4jgLBjtqdxbSf2Z3f5y3SX4JyK5YsD0TmvTyNxlttAs4yrT
         dp64tX9gsqHfKJLzaFZAy0MMGDx6J+r14185HASzePuccajOHouIPAjaZ3MMjOCHpPSV
         MYWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BhZZuTp0;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id m127si268690oig.2.2020.11.04.09.19.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 09:19:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id x13so17824184pfa.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 09:19:15 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr5124452pjz.136.1604510354459;
 Wed, 04 Nov 2020 09:19:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com> <5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl@google.com>
In-Reply-To: <5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 18:19:03 +0100
Message-ID: <CAAeHK+z3WWTcvpaokXwnAML8hYpP==Ghw-QTNVgHUMytK=kmVw@mail.gmail.com>
Subject: Re: [PATCH v7 13/41] s390/kasan: include asm/page.h from asm/kasan.h
To: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Will Deacon <will.deacon@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BhZZuTp0;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Mon, Nov 2, 2020 at 5:04 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> asm/kasan.h relies on pgd_t type that is defined in asm/page.h. Include
> asm/page.h from asm/kasan.h.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
> Change-Id: I369a8f9beb442b9d05733892232345c3f4120e0a
> ---
>  arch/s390/include/asm/kasan.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/s390/include/asm/kasan.h b/arch/s390/include/asm/kasan.h
> index e9bf486de136..a0ea4158858b 100644
> --- a/arch/s390/include/asm/kasan.h
> +++ b/arch/s390/include/asm/kasan.h
> @@ -2,6 +2,8 @@
>  #ifndef __ASM_KASAN_H
>  #define __ASM_KASAN_H
>
> +#include <asm/page.h>
> +
>  #ifdef CONFIG_KASAN
>
>  #define KASAN_SHADOW_SCALE_SHIFT 3
> --
> 2.29.1.341.ge80a0c044ae-goog
>

Hi Vasily,

Could you give your ack on this patch?

The full series is here:

https://lore.kernel.org/linux-arm-kernel/cover.1604333009.git.andreyknvl@google.com/

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz3WWTcvpaokXwnAML8hYpP%3D%3DGhw-QTNVgHUMytK%3DkmVw%40mail.gmail.com.
