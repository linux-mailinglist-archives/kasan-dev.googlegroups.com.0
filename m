Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB66UVOKQMGQENFLYWZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49E0854DCF0
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 10:31:56 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id c185-20020a1c35c2000000b0039db3e56c39sf789551wma.5
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 01:31:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655368316; cv=pass;
        d=google.com; s=arc-20160816;
        b=RZQpXODos0Hej4JBcZcoRqI4uyxwljt+sQVXmSUZLKtp+x9aGFjk2pPfVDWBhORVO7
         Ss9Q/EA+4sHW9cqfOzG+haALhxwNbGFMxhOCeGSjsna32anL+13MDfwaBkqtM2BBH48N
         NliOTsI8SWEqAVjyDvtnvmWJBmLuZw23/2+aKsGzrRsOo1bNvpQBTT4a53MQfpWDoN6z
         qu4BZlpsHCA45mWTyLeUyzfVZZ47Tf21UEvDx9xLU060RroHLTSDy3xfn6XtYsJY+WDL
         14Z+90XztlUlAg/q5tG0ZMBAlqJq4k4fVFOUf5nlsWI7PxoQw/o/c+cHXs6iH3bKFzD9
         BrNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=GKorDJH832lImNNiONJWB022YR0wUcdhrUbI3egwmp0=;
        b=t+w61AIYmrPvMMe1rSeReI9KTTyqG7uswvczfxVFXO7iMFrTwBK57zAmRu0tE3Dabl
         Q/r9obvMSqyoLaQK5qwLHUqCJ0LHfIiDz4VT3hdXCdVAWn6nxbzxnVzwn1NNl1IVqdrq
         zXN7TerJF0/IM+fBvud1+VjizMNSKcyPFRToHIYGxhEJtilDCbIrXWXgWfZw7FBOnklA
         t0u+lFT/RZWWAfhVRT7hwbeDwc5r9gwwRek4sAWIuVaNYdEMaVgnVMkIb01POqJqTF8w
         j6cx3y3o+B8ny4KjuasCiG87q/2O/D6V6aqTNo0f+ijnML4Qx6+IEY7vQWPW4wwWlvTb
         d01Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKorDJH832lImNNiONJWB022YR0wUcdhrUbI3egwmp0=;
        b=IIJfOBcetxEcvo0bDUROf3kkJ3yWilFlnYD9nQ50yBYxl/40hMIp/YE9krgpqEOmt5
         tcxRDp2GGrP34akxXn1/9AfaTNT1oVPVy8EK3PV+1ZdHMMOhazApakQQfGujivObCPyz
         pM3YHGJ2jbey7BXxtn0Tnw+JeRqtTIEocVEgzZojPxKl3uMowqijqnpGNY1JcBDNjgFV
         zzf/gPm+pylhsP+7gESDkHf2t2ImyoW8v+mvnViNXJiZtxqULH4Y2UsLVWL6ZkNp7Xvy
         ON9dKMm88T11uMXpH2ZCELumAfxBHrNK4v8LxrTWuRaP+6RkRy8KVQ92phYnpwBY50BR
         rD4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GKorDJH832lImNNiONJWB022YR0wUcdhrUbI3egwmp0=;
        b=4SQtveSWepO8+01A1YtkcchKjnx/F37z1Ok04izpMOvGa20z8/rsDytO2v9tHGDcCO
         0Hszj6XcNWuYTSu15hZz20VioRKtDPvitRwDCBjvcjodYecvMDv0ZEPhcfbJEQuA1sRX
         EOfg/dGoVMDLxJ9Lpl74/Oa0zZWqcpxDx59Oj2NLMOHoEErbQq39ho3juO/IhzJUHvAc
         /UPNYk///PFxK2MZIeTGoC/wObTVbc64ftk8I1cDGl+FP3oAkJy8dpsTcsiolH4tSwUu
         CNNpNKWmPysxrFyPZVBXqjuLb5o5NJ6IvPnjDcClBEKI9ZXVrazq2jfhf/L/bqR4O8g9
         CcLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8KXw+3OjLdB4j5sS3UOprvVRjwcSCaTzq8rCZ3LNdWEXR09WSj
	0fhrNOLwuIGJ/jt7Xl8plqM=
X-Google-Smtp-Source: AGRyM1sq71ibozYUxUKG5zf0LNVj0xRz3kjI6i/5axmk8VNtU6Rs22HEiJwPIcV/rExeIZ2m6dzxzQ==
X-Received: by 2002:a5d:55ca:0:b0:211:4092:1c27 with SMTP id i10-20020a5d55ca000000b0021140921c27mr3612390wrw.108.1655368315689;
        Thu, 16 Jun 2022 01:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5848:0:b0:219:b7ea:18e1 with SMTP id i8-20020a5d5848000000b00219b7ea18e1ls1651241wrf.2.gmail;
 Thu, 16 Jun 2022 01:31:54 -0700 (PDT)
X-Received: by 2002:a05:6000:1789:b0:219:2aa8:7159 with SMTP id e9-20020a056000178900b002192aa87159mr3480428wrg.474.1655368314668;
        Thu, 16 Jun 2022 01:31:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655368314; cv=none;
        d=google.com; s=arc-20160816;
        b=lpqxXFWZOlE6O4Uzo8Mktc2oES7P8u54kYSTKwF84YXsw9HCI/2TXdIsFSO5HJf+D9
         SompKBAYYsoXvXt1u1pnYRrRaNlmwaocFp6dcCXQijJa9Cmvd31sOPI/sS7mxwDhlbtj
         RPFmFvwBEBlVkh59AziG0lrKuHATcm4wR1Org0QIonyjRwr7NxsmM8a7v+PLPgu68j30
         r0KluTCVNrlQteNSLqStFIRhiTe30eKQ21LMCixc1LFcIw0VHatmzkDtVKtYima1SM9Z
         Dm1T1VVCWzDb2fD8ieOsXabSDMxQwXpc4WyV5j9iRPhYEmJb2q2+/iprrKbv+tX0fs7v
         EbqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=IqZ+hZyAEiz+E8OGzxpfXdnI7felGnGoOrHidH9d8qQ=;
        b=terMPeytxH9GND0DKJIujeJhUA18txcG+fEaLxtW8/pPlrf/e2b51Lacw0kFuK8iYg
         qf26lUQ+9soWVVYHIS7p3Sy5HyvjdkoD5O0uIYkPzkCkjLI1iR4iV7xpietmHFWWEO/w
         j3+YAGKUt2bKnqHWhiOuAyNCkux7pbvZiJNIfV4A360udMt/Fq2iOYFWX75y83NoDXzL
         LoKWHmXjBMc7ibPilMVTMC96du2iCJdbc4n0HIxCd5VaUYG88iSkRVHAPefRjiV7O7T8
         /lKE4cWPySOvFiu1WZc3945ryHVvXpnXQcwH/BgHPmkcbgyB9vQUutwDAmGpOUEy7trV
         Tlzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m18-20020adfe952000000b002132c766fd7si61852wrn.4.2022.06.16.01.31.54
        for <kasan-dev@googlegroups.com>;
        Thu, 16 Jun 2022 01:31:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2402112FC;
	Thu, 16 Jun 2022 01:31:54 -0700 (PDT)
Received: from [10.57.69.164] (unknown [10.57.69.164])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 312093F7F5;
	Thu, 16 Jun 2022 01:31:51 -0700 (PDT)
Message-ID: <8982344a-c726-934c-70fc-011b8b83bdd2@arm.com>
Date: Thu, 16 Jun 2022 09:31:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
Subject: Re: [PATCH v2 1/4] mm: kasan: Ensure the tags are visible before the
 tag in page->flags
Content-Language: en-US
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>, Peter Collingbourne <pcc@google.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arm-kernel@lists.infradead.org
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-2-catalin.marinas@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <20220610152141.2148929-2-catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
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



On 6/10/22 16:21, Catalin Marinas wrote:
> __kasan_unpoison_pages() colours the memory with a random tag and stores
> it in page->flags in order to re-create the tagged pointer via
> page_to_virt() later. When the tag from the page->flags is read, ensure
> that the in-memory tags are already visible by re-ordering the
> page_kasan_tag_set() after kasan_unpoison(). The former already has
> barriers in place through try_cmpxchg(). On the reader side, the order
> is ensured by the address dependency between page->flags and the memory
> access.
> 
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  mm/kasan/common.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..78be2beb7453 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
>  		return;
>  
>  	tag = kasan_random_tag();
> +	kasan_unpoison(set_tag(page_address(page), tag),
> +		       PAGE_SIZE << order, init);
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> -	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
>  }
>  
>  void __kasan_poison_pages(struct page *page, unsigned int order, bool init)

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8982344a-c726-934c-70fc-011b8b83bdd2%40arm.com.
