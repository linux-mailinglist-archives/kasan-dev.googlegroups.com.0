Return-Path: <kasan-dev+bncBC32535MUICBB3VPUW3QMGQE4JWCZJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 952A597AE9F
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 12:20:31 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2780069c7c9sf4415532fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 03:20:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726568430; cv=pass;
        d=google.com; s=arc-20240605;
        b=cGeocued6Hc8CYwOrbIcinEgduP7PjEjw2iU6p7FB0t82rh0r0t9JJRptWC7DnW5US
         LCNJYadOIbb+9jljA0IAvZPsXbkgzLqQSUR1mVO1SI450pVa12YoQpOQ1On0RfGtOVvj
         CQzq3/OP6chomWf4YHOrBaacxEOoEITDUj0+pDBUN9Dzgz52765YKl5SbeMJtjAYwXlE
         gEyn369UbiyNk3NYqVIKv7I8jva+qFtAwHjGDKyrQTEBDCWYMep0GJL4RdyK1WrMcPHF
         nj670cpD2U0wQxs2h6mrtyAiYDrfeobb/sjbymzg/paTTcZpoLh1IgoSdk2JTAmxxU1O
         mCwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=uHFBenbrDaHvjfszW0epvzjBvMDttAgV1oFZD+fGq3k=;
        fh=aABKRncnnCUgL1kqK3+GPsX0wLW7XO738yPGS4xvmTk=;
        b=PmjYpvTqr9/av8EB1llPkFb2fTQIud1H6IpwV8yrWFOX48aPm5nc5SoOzxRq83pQ2C
         Bb/wQKiGvg9rgpzQy7aHVUC1hGWQ0ocwETIVNDw4/ogToU5QTd+ppusRALm2A29n4pzl
         xC9cIxhZxF6SmeMfTuQV2mYxRVbCPyt1W3/a4nCNZA+iXhh4jaLDhJ5yF9OW1sz4jsT7
         XHlILDQacJf4Ujc0DOZ/J1LjNGPul9C91cAE3/HiU9A6ArzEa32/14UWUahCILl5ChvJ
         kWKUykgNCVikNgcf3aNki+tIB80V0wN/h/bdfbcUlZ2PSRpv1Jiajfw449li3AaEsOLo
         MOTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BLqmIprJ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726568430; x=1727173230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uHFBenbrDaHvjfszW0epvzjBvMDttAgV1oFZD+fGq3k=;
        b=mTP4eVm1vjz8D4+KQ2NXBQVYA79LeEYz0XZRPaNajI/7oy7mPzcYc5sY6hfYDwOChK
         apKKNHgSgvjIzhylnFZ4alU156h678raWjanFzYC5U3OxoZjR3Nor3SQQb0IaUOgVNoI
         5pb+82azUDzFq/vHY1/knvrwXOKJfVUqRoHZ8CLd7dZ3oA3GKtvI3AdgCP2QsdmQqewn
         ab3J64opYFij9y5jTauSpIFBoo922fQgdyZ93RXq+7bQzsVwHG5/LdKft0nPcMyywXWk
         AxyRJr0tsOBtTIoIFkdjr8Wx7eGm19J58dl3pk5CH5pOxnrZJP4+ifjS7AncPwMyFGcY
         fO0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726568430; x=1727173230;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uHFBenbrDaHvjfszW0epvzjBvMDttAgV1oFZD+fGq3k=;
        b=fFy9MpI1vEqgIwC0hcIpoiaZi0NT3BewLJRIunf3Qe/d16Cra/TUuOeGjN6Bqpze75
         cP5lCmcPZc8EWh9z8gaT2+Xq6/auj4ErFyFF+Vfubini5j1OlQHbg4cwg7geXrf6pm+J
         V7kcxhKEODtwIWJhYXZvIPfP68cn4KqNmDJJ9wa0OKnsFickultvw3YGPNum4HIoM1pM
         AI4k2VI8dSMfuZoqP9x3+2x5k7YMoy95IXjY0B5bRt4wvUre9Bzl9KgjSHmhxciOY39N
         I6e29tWM3wJETAqV296CI1eU+5hu0H8XEYiMIjcBuCq6aMiZNZKDSzjQfhSKdXNG6wWa
         Crug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXN17vRD9+HKfsrxJ1ZH091auFBja5YY5jxIMzr0aOJZhHhSrEF9OxZaCvaMbaTSDUJdJvwDA==@lfdr.de
X-Gm-Message-State: AOJu0Yz2p+nYIOqdxRJca0FSQywWVq9i9ickk/qzAwtjy4W8Sbubo+bA
	sNTyyvAkdwQJcxiKH+59wOlG1CcDNr+6YBossi7SLXYrOLBWY1y9
X-Google-Smtp-Source: AGHT+IGy9AskG4D7sjDcDbcRUIQfkDZAiAAP3c1CncZtfIx01tav3mvWZ+Z0jCKuAjDzyNr2LrJGJg==
X-Received: by 2002:a05:6871:580a:b0:270:3a68:cc08 with SMTP id 586e51a60fabf-27c3f67f013mr10753165fac.40.1726568430286;
        Tue, 17 Sep 2024 03:20:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ab8a:b0:278:233:d36c with SMTP id
 586e51a60fabf-27c3ae8db8cls1367268fac.1.-pod-prod-03-us; Tue, 17 Sep 2024
 03:20:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViuxX9IdtoeSaj3p9h5vadUBFby+ZwReSiQXlRrXwYWtoxdJrOLx6ZEfhQmeE9Lvd+y891G7D7xk4=@googlegroups.com
X-Received: by 2002:a05:6870:f702:b0:277:e35a:d2d5 with SMTP id 586e51a60fabf-27c3f6a6e8dmr9271312fac.47.1726568429353;
        Tue, 17 Sep 2024 03:20:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726568429; cv=none;
        d=google.com; s=arc-20240605;
        b=aoAZyOcqkTRU+gdMAKpTbRMgV623zKQSxdwLhpsGDhAGDQtVgpT+nGBjpNSUmnzfXq
         YAJ0gq777hHVx82q9gnT8RQymwFXnGuaYN8bG4NfCuC8NtqJkwQvH807dhLQcu6OO9kh
         fOPKCerakFDi6KCGWLcdMXzf2hvvb6Lr4YyCd6Rn89e4DfoC9H58rwgbTtXzLiNz08ky
         jwb+7OHzBQvRaMlRkVc9ZX2Ptxu4F3GLCJocnCphsB1P7PpapAB4j+Rx1o4EDJnuCUM0
         51xZLNWJ2TejK+Q756/pi9hnz8eI0eWkYoSa9sOkxhJdkCkxbX3LczFoyJq3tS7QSxRq
         qO2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=6ZCJTmJx2xNT3osb0wa+deaEyFcFSSWyiY3NZGLuGe4=;
        fh=Qt4ggpVWkD3/PcHaJA5srCQRs8CEYAfFxOJdPp8mo+I=;
        b=cQ1I1s3ItZHbgBXQZtszpHVQHy3TjFsUDfjJjmRu4MfEjlNcrBTS2yB5e+zD/RUiVv
         KKd+o40jofXnYfOc8jfeNMkBPpRI4nbdb6b0l537TPaT0n4XYoHhkual3Mc9VT3ptSLZ
         bB/vVOnVtStRT1KrMagOH4nb2+Q8RO9J0FFN5jLiME4Kuo+xkuw5dBRDDj59i9BFhgVn
         60kIIrzKbZSIBnr85wJFxGudy+w6jkOte5Dnn09eGCEvbBpmXbTIaOsdijuq16SxI7TO
         QEQbv175/ic9FZun7a5BoZ5a4oCZ7bbJvzmwHMiHC0eZ5+3ZeMW6lVUuGdE5eT2Bl7dv
         BBGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BLqmIprJ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71239daea73si255111a34.0.2024.09.17.03.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Sep 2024 03:20:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com
 [209.85.208.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-387-5hmoTl_wNKif5CNhUNtwcQ-1; Tue, 17 Sep 2024 06:20:27 -0400
X-MC-Unique: 5hmoTl_wNKif5CNhUNtwcQ-1
Received: by mail-ed1-f72.google.com with SMTP id 4fb4d7f45d1cf-5c268497042so3178947a12.0
        for <kasan-dev@googlegroups.com>; Tue, 17 Sep 2024 03:20:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqfBqT230t+rzU/lfo+ZLIBMSrW7Y2IQBAqEodyYbvD1VyCDCB64md82WY85E+M4NanvlMmt57drM=@googlegroups.com
X-Received: by 2002:a05:6402:280a:b0:5c2:8249:b2d3 with SMTP id 4fb4d7f45d1cf-5c413e4c51fmr15560394a12.26.1726568426140;
        Tue, 17 Sep 2024 03:20:26 -0700 (PDT)
X-Received: by 2002:a05:6402:280a:b0:5c2:8249:b2d3 with SMTP id 4fb4d7f45d1cf-5c413e4c51fmr15560373a12.26.1726568425483;
        Tue, 17 Sep 2024 03:20:25 -0700 (PDT)
Received: from [192.168.55.136] (tmo-067-108.customers.d1-online.com. [80.187.67.108])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5c42bc8a51dsm3510875a12.97.2024.09.17.03.20.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Sep 2024 03:20:25 -0700 (PDT)
Message-ID: <4ced9211-2bd7-4257-a9fc-32c775ceffef@redhat.com>
Date: Tue, 17 Sep 2024 12:20:22 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 1/7] m68k/mm: Change pmd_val()
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Ryan Roberts <ryan.roberts@arm.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Geert Uytterhoeven <geert@linux-m68k.org>,
 Guo Ren <guoren@kernel.org>, Peter Zijlstra <peterz@infradead.org>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
 <20240917073117.1531207-2-anshuman.khandual@arm.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <20240917073117.1531207-2-anshuman.khandual@arm.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BLqmIprJ;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 17.09.24 09:31, Anshuman Khandual wrote:
> This changes platform's pmd_val() to access the pmd_t element directly like
> other architectures rather than current pointer address based dereferencing
> that prevents transition into pmdp_get().
> 
> Cc: Geert Uytterhoeven <geert@linux-m68k.org>
> Cc: Guo Ren <guoren@kernel.org>
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: linux-m68k@lists.linux-m68k.org
> Cc: linux-kernel@vger.kernel.org
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> ---
>   arch/m68k/include/asm/page.h | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/m68k/include/asm/page.h b/arch/m68k/include/asm/page.h
> index 8cfb84b49975..be3f2c2a656c 100644
> --- a/arch/m68k/include/asm/page.h
> +++ b/arch/m68k/include/asm/page.h
> @@ -19,7 +19,7 @@
>    */
>   #if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS == 3
>   typedef struct { unsigned long pmd; } pmd_t;
> -#define pmd_val(x)	((&x)->pmd)
> +#define pmd_val(x)	((x).pmd)
>   #define __pmd(x)	((pmd_t) { (x) } )
>   #endif
>   

Trying to understand what's happening here, I stumbled over

commit ef22d8abd876e805b604e8f655127de2beee2869
Author: Peter Zijlstra <peterz@infradead.org>
Date:   Fri Jan 31 13:45:36 2020 +0100

     m68k: mm: Restructure Motorola MMU page-table layout
     
     The Motorola 68xxx MMUs, 040 (and later) have a fixed 7,7,{5,6}
     page-table setup, where the last depends on the page-size selected (8k
     vs 4k resp.), and head.S selects 4K pages. For 030 (and earlier) we
     explicitly program 7,7,6 and 4K pages in %tc.
     
     However, the current code implements this mightily weird. What it does
     is group 16 of those (6 bit) pte tables into one 4k page to not waste
     space. The down-side is that that forces pmd_t to be a 16-tuple
     pointing to consecutive pte tables.
     
     This breaks the generic code which assumes READ_ONCE(*pmd) will be
     word sized.

Where we did

  #if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS == 3
-typedef struct { unsigned long pmd[16]; } pmd_t;
-#define pmd_val(x)     ((&x)->pmd[0])
-#define __pmd(x)       ((pmd_t) { { (x) }, })
+typedef struct { unsigned long pmd; } pmd_t;
+#define pmd_val(x)     ((&x)->pmd)
+#define __pmd(x)       ((pmd_t) { (x) } )
  #endif

So I assume this should be fine

Acked-by: David Hildenbrand <david@redhat.com>

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4ced9211-2bd7-4257-a9fc-32c775ceffef%40redhat.com.
