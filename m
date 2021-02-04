Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBAGU56AAMGQEDVVVKVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E6C9230F33B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 13:35:13 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id u1sf1652820ooi.12
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 04:35:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612442112; cv=pass;
        d=google.com; s=arc-20160816;
        b=sa+t8de5oPBzpcyfaHuJJFQ53wJBJZnl7vzObe598KfzOnAPLvFqFs6Pol8+6HtVif
         dG4TkWoAXy6ms9eKAv31kdc23UhwDZJmSce+CG4ojWS8CI+wUWXtHEZSdy5ikHRb74Hz
         duEProgo7XyBDfCBhBTLmsEkgrwyW8ujGjCJqC8ew/GBvyDJmAdhsu4884oVxEqdmOUC
         lyD0jFcoK1+qc48cLnDvPyvZnTAVTYgULBDy+KFQijN1oubzF60IROW8UZigZjWxwZQy
         93vboVomNyQdbOOimg5TcQz/GiWLZa4rstRaRRdXJ2e5aqXLyGSpHWFDMdKYFqu7r4M1
         fViw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=oXHmD4xrgv1HySgQUFktYWYlE/1knl2jruZ+oKqGCkM=;
        b=lVJwziCAIvE4T3mNatUOCy4nLYuoJXBhuHYSavBDB+g53HuvAAF1BSxEgAlgrWfHeh
         hpHpbLtOX5hu03aV2a0y/XDAFoRjgP5DB93UwCy/ChHr3Sx9j2G7o7qbQ8OZLDMrswJN
         7UoLQ/zDbaqvbED3QPMGFDmiA3jOlpC8IvZUKm/oJltvstfXesYuIeRFaMwxl79RxDwS
         XhOTKYlXITNAikl7BSQ03AtMfkDR4/b+QguBUP5JOFJye5FRaGqTP39K49OUsoPq6sQC
         kV5p2Fg26L5Mpwd3AewkJn1s0tPvC/HUJVwwAA8Q/wAsSqu3tDMTBwsuUoZYH/CgJUjH
         sTpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oXHmD4xrgv1HySgQUFktYWYlE/1knl2jruZ+oKqGCkM=;
        b=N/2BHyh/WYEkKco3Hr+uC+QIYbR4JMqGJ1LY08XSvFNbw4ZkBpClTimozxeCw4AdSc
         RYhXbnWtt3P0LX4Mev6k0SY9CM4INN4w8mpd4G9VOo4U3b/oLJqKd50x7YNvtQI6b0b8
         6+xQA9LH7WSrsiqcPUYPjQioHLu/mcMNlsvMoIfCCfbjDMfPPFCyblxQvkrl53I+K7nn
         0w9Q6lSSdTT0FnwkfMcDaDiW4epZi7rSICmSiPrqmz+Aqf8GerUv04gMtEcOu5edgx9E
         86iuLrOzFee0EHU3jYLg7dfX4jrSNmZI+EmbfOVwtWVAmDvQlaJbjwXN6kwaz9QhVwPE
         tafw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oXHmD4xrgv1HySgQUFktYWYlE/1knl2jruZ+oKqGCkM=;
        b=hE+cfkvN5bp/ZQls2me4xY81JfdM9tHNS0SBfG0D9OXapuMizIF4cEiKUNzjRp5BZC
         v1s3W6anVLu9KT4PHo7LVsJNko9dD4m2R2xxWujwbFqyycNRibUs66RL9TT+KqyR49Ri
         VG0gl6JkfGJOZ/Zzs0hIa+gmFooZLYDvn8xEV7J1yt5rVoVPlX1d6BLdwYvjNYY6e71S
         vXPT2H90hZJX9XhiXkaNLZin8csnoT3zAREVos3gzjyrnWOWh9NG8E+ceg4DmsGVpFil
         XLmjc1ANBlmz2zX/uDoJF5weD1xA/xlGAvJTK1+cngT4B3yybyWCR2+jtIonW2m0/6mS
         bMtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tWEbsUlIJNcHwJtWCBaTsPRUSdpu+jS9YBsgjpmCaG2VFWOtb
	OWwRCI+DEA7DmnaBh7/qi6o=
X-Google-Smtp-Source: ABdhPJwEVCygOFs2PCYNncle1R+4p6DBARsPtnBO9FbrDj7LNwH1X2rh7JDog3+YFHLfC6ZOgaeCSA==
X-Received: by 2002:a9d:22a4:: with SMTP id y33mr5848047ota.98.1612442112364;
        Thu, 04 Feb 2021 04:35:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:495:: with SMTP id 143ls949814oie.8.gmail; Thu, 04 Feb
 2021 04:35:12 -0800 (PST)
X-Received: by 2002:aca:4dd8:: with SMTP id a207mr4877373oib.116.1612442111977;
        Thu, 04 Feb 2021 04:35:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612442111; cv=none;
        d=google.com; s=arc-20160816;
        b=06j+cEa6KfvJSWpIQx4+anYTvrreRzAr56Juq8wBLm1OQvpfaHdyQa3ebCLktroDOc
         v5Hf4RmhiVZtt6sA6Xweare1GK6F/pvI+8ywgIpn1Cyo0BpOW66IjzVR4Q07paSTOtoe
         j1kr+tIayq0F7fEcUzyz7w5FIIKXBEgrK0ukrWKUgxwU2o8mFoxbMv1eW/UPYKExuXdP
         hkuMt1UDiZ1dklDU1tKKgWkk+Z+TwVyKFsbfhgb639Ql5DSBac95Z0wLtm8b043MtR+F
         7VhvhWF+0+s+kY6ZzJZvatuTJwWwQmveqgoXXddcIIFtqrlGR4pqAUV2iY8oz9tXiJJ4
         MqDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=bSsaF5Zy8N1tbGmfhSRJDcwnxPzcCVno6Drrtdse9DU=;
        b=Fi9Smxs8kNzQdQTKM1b2RxnxkkwKo40Z0xMbdyX/upngqSfALH88pOJZ5WFABXutJw
         VaxUbuYVD8uuffedcELSB7N9LSTap4fTzb3th7s9mZI2XVpw82gK3SIoYg6hRON1mqaA
         xPynsUVfpizHTa8MKZUFyP5Q/pkbGwf2RQuzCatBrOI7ghYMXdj7D/gyTHiEWW2j3lVE
         vT8BxETczXo8jGmNI6axgKEMy8tR5k6Utr5kePfMUlNt94JlCGgsDGLgoH1A6qmiMpGI
         gqa69EvU03YYdMY39zxTT/QruOIu97DGDTSUhfAKSIxaoWSGwgPC0Zgzd/7f3reVgDPn
         odSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x35si352186otr.4.2021.02.04.04.35.11
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Feb 2021 04:35:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B58ABD6E;
	Thu,  4 Feb 2021 04:35:11 -0800 (PST)
Received: from [10.37.8.15] (unknown [10.37.8.15])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B65A63F73B;
	Thu,  4 Feb 2021 04:35:08 -0800 (PST)
Subject: Re: [PATCH 10/12] arm64: kasan: simplify and inline MTE functions
To: Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1612208222.git.andreyknvl@google.com>
 <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
 <20210201144407.dd603ec4edcd589643654057@linux-foundation.org>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <f87043c9-6126-c87b-a5c6-b48f28556b92@arm.com>
Date: Thu, 4 Feb 2021 12:39:08 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210201144407.dd603ec4edcd589643654057@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrew,

On 2/1/21 10:44 PM, Andrew Morton wrote:
> On Mon,  1 Feb 2021 20:43:34 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
> 
>> This change provides a simpler implementation of mte_get_mem_tag(),
>> mte_get_random_tag(), and mte_set_mem_tag_range().
>>
>> Simplifications include removing system_supports_mte() checks as these
>> functions are onlye called from KASAN runtime that had already checked
>> system_supports_mte(). Besides that, size and address alignment checks
>> are removed from mte_set_mem_tag_range(), as KASAN now does those.
>>
>> This change also moves these functions into the asm/mte-kasan.h header
>> and implements mte_set_mem_tag_range() via inline assembly to avoid
>> unnecessary functions calls.
>>
>> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> Co-developed-by requires a Signed-off-by: as well.  Vincenzo, please
> send us one?
> 
> 

I added my Signed-off-by to the patch.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f87043c9-6126-c87b-a5c6-b48f28556b92%40arm.com.
