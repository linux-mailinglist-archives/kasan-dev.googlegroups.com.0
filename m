Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMW2SH5QKGQEVGQD4SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5386626F7D4
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 10:17:55 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id w10sf1876758ejq.11
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 01:17:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600417075; cv=pass;
        d=google.com; s=arc-20160816;
        b=MjkHRM7HKC3FgTdcj6h4EpQS5/YNSkJcu0OWo7uHei3boLs6LUEHZeNKuKA2GfElGx
         zUmjiSTa2jhg6MjHAJAQMaM1jaUGTU7q4xx1EREl+vRNi2r99CaYhIGM9aQsjFzuLFJc
         hgShr/jrWmjbTBlw3CPIE0QoYYl+UyGWcC4OOyWHCQYS+YmCdaCIfUum/tRoIZk5jdKA
         19dIHVrlvaiJsq87TgWBA+eRiy5NiNNSCa6WuF7vjic8yyibGbGHqdJMB1RpjsgL2vbm
         qFaY/SekhyeC3IWACPJfJyymNR7ZS0CrzPQRBojPY9H2Gl/nGiiKArQGxUEYAYi8n325
         1nNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KxladdyVnyIeKXO1Rq/iz82cxx+Z8E0NtUsk1RDVXqg=;
        b=GofZ7uBklypxQK+XAJxgNLkA0/PRPIbZcIxhzOWQS85xYpVHBwew8ngTLq655cdgkJ
         pDvUAiDKfSqMvKgkJw+Sa2t1TyJnnmx7YPB0g0R0lXWAz9HCXUc16GV3Li2gKJDz+Wff
         ngC1HqUFHXXfFSuuKTFkBPq5WK91sMjDaMoguAXa4b+7/97gKyEimSLbXpvBLz8UFcwk
         2bbY79gfjB8JIFAq1yqRD3C82mXaoqHLm0iUha9rthwaoZU2tqT+P2TDze+Pc34jdrII
         sJI7ll1bRxA1RfKm6RU0sneVsF7caNJ3s5uTCiSexsZrFvgoSDoh0vhiO5s14VOERLF0
         2MuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P6hxU2ON;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KxladdyVnyIeKXO1Rq/iz82cxx+Z8E0NtUsk1RDVXqg=;
        b=D19QdPDPJ54Xnvb6L64xs+s6gFEfPqTqwx+zEV1ZJEkiLhYir14bu6fJ2ynL9Vm8Nf
         RDnxajWY3nNGXHIFGn54lXlYzUElEYh/HmHXaZyT3LZ/pTIJEyW5/4sgnda844pamXgu
         uRd4wTuCfUShBmnmSGsuoQZWBinyL+aIpgJ7049+iAD89Z+RGFB0/YxSndnzLjebmei6
         IuzsX+o+BaollAVE4IgVaRz+7yMtNWNtCRaZVDBh8Ihq0tpEd32EI0M6jAofLuwmyAE9
         /lXUi5YeAU7urxhR6c2dxXAQ/oM437igC/UMyTTn2ykj9U+LdnJuJZhwbnZ4OZvClHM5
         bzTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KxladdyVnyIeKXO1Rq/iz82cxx+Z8E0NtUsk1RDVXqg=;
        b=X+kCvwcukWhVzL4TmJ2G0gd5gL2CvScWvpGGESzBZ85/1AUXBMMZMPDKBaQ4868jN6
         v3iFMWhXSh7aonFT62cgMno0co66jK3hl2KdspZgk0t3Qa4KnMdaqM6gwSw24QtTf/BY
         KiarXoqyFRmKhMqW1+uETABMKtcWsfhPuacL3JP+3lrMFCcm2Z0aZJBiaufu2VgrLuFt
         2zMeImtKX/y8gNHwQ0xznRGkTx3EOY7oGcndWlz6CRodSfIB8kDIoFQm6cAiiq7IaHqi
         aHgWc2BtcEozVhQHlspNPs5vEmflkh7USEnOHA0jnIkQ5luFGVBc4Tpdhk6sB9f1mvuC
         fKmg==
X-Gm-Message-State: AOAM530q3rzXGLVTxaevq0RyIQsyYNGvpQ3QBeMnu6pk8ijSKS5NyXAg
	/CjsCFVTowmHjiRAXGPKbOM=
X-Google-Smtp-Source: ABdhPJxQMRp5M0TS1twNp1t4lMFIRwfI3txxcD5Ja2ih13GMpAhDbLcQXaxKphn0Mjy3J7rb3AktDg==
X-Received: by 2002:a50:fd87:: with SMTP id o7mr36615429edt.180.1600417075023;
        Fri, 18 Sep 2020 01:17:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f996:: with SMTP id li22ls1258334ejb.10.gmail; Fri,
 18 Sep 2020 01:17:54 -0700 (PDT)
X-Received: by 2002:a17:906:1c03:: with SMTP id k3mr31680212ejg.259.1600417074085;
        Fri, 18 Sep 2020 01:17:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600417074; cv=none;
        d=google.com; s=arc-20160816;
        b=hrmy2nIrZUK+C5qpGxxGTJVBkwrQotwpRiXt6rLE7HGR6uf8XzmQ2+8zkUCojr43qy
         V9F1BXs/UDUsuqWfZ83EsUzVEaoju7yz83BMdpbucMKqIRlYrdWVN0z0YtdNm5dqI7Gn
         bq4zZHj+wRP61hz8ORZtecWFYWtL5M0VqPEhK9asusUZI7njyYOj2rxszm2mdn41DswE
         wQrh+P/kyFKRMkxn08pMjyfdsZLIcvMebTqNKGYpezNzwEjT1upABg9b2rxt84BGrPob
         zSXD/KBMhNRoiGFC9BRAMci6tzbS/o9lR91RO7wvhblC4iV2Nnl2VJo/RLMK9hzKltqd
         R4kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=336DK+gr8bWeArYbXXeTUATGYeu4M+ZLn03audwBSjI=;
        b=kix7x/20mgM+fBpUE1b8j3b5BV4ZCORYqgFDo6I+JXQqpOGYkTIGnPDbpYaUBwUPjj
         bMXBgy2+Assy3LwLPfkll7Ra6OrDIU3k+ZcAmK69V6d59MMTyhZaBTMansllgKA4Vnmg
         onG8+sCD5BvZfceMEM+1TE0sGuRmL3W/pg4n5h25d/qJM9qqUUIsw1DOKdHX3g/UTTEQ
         5Xn4FwvhsJpdeusrd/tvaExgUt/PCEQaeH4wFyyrhN/+R7sxtn4ebil73k3AWNYLmxcH
         LdqONh5BWWdQ2RiqN1Y/yANvh+xY7pJN2HolPm73h2SBzQo2Kv2Y+nyuloko6qQoUDcd
         8HqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P6hxU2ON;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id w16si50189edq.4.2020.09.18.01.17.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 01:17:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id x14so4659416wrl.12
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 01:17:54 -0700 (PDT)
X-Received: by 2002:a5d:60d0:: with SMTP id x16mr35980678wrt.196.1600417073613;
 Fri, 18 Sep 2020 01:17:53 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <88c275dc4eef13c8bcbe74ecec661733dcbc67b8.1600204505.git.andreyknvl@google.com>
In-Reply-To: <88c275dc4eef13c8bcbe74ecec661733dcbc67b8.1600204505.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 10:17:42 +0200
Message-ID: <CAG_fn=Vuu-hiaACaoyvpo7RCzvk4faz=AANX=oyAKEJdHDSxEg@mail.gmail.com>
Subject: Re: [PATCH v2 07/37] kasan: split out shadow.c from common.c
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
 header.i=@google.com header.s=20161025 header.b=P6hxU2ON;       spf=pass
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

> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> new file mode 100644
> index 000000000000..4888084ecdfc
> --- /dev/null
> +++ b/mm/kasan/shadow.c
> @@ -0,0 +1,509 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains KASAN shadow runtime code.

I think it will be nice to mention here which KASAN modes are going to
use this file.



> +#undef memset
> +void *memset(void *addr, int c, size_t len)
> +{
> +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +               return NULL;
> +
> +       return __memset(addr, c, len);
> +}
> +

OOC, don't we need memset and memmove implementations in the
hardware-based mode as well?


> +       region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);

"PAGE_SIZE * KASAN_GRANULE_SIZE" seems to be a common thing, can we
give it a name?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVuu-hiaACaoyvpo7RCzvk4faz%3DAANX%3DoyAKEJdHDSxEg%40mail.gmail.com.
