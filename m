Return-Path: <kasan-dev+bncBAABBN5AYK2AMGQE5ZBOP3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5227E92F3EF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jul 2024 04:08:59 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-dfa7a8147c3sf2817268276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jul 2024 19:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720750136; cv=pass;
        d=google.com; s=arc-20160816;
        b=qPw8xZ1jWs74UPJ+EGMDB8V9XCz6apP63Jy7O7Xbc4uG5a2OdBWgVOLAbDrxgmwne4
         0tqzIbwcYE5AKqiNVn8+QmFuMdhggbwRnTccYmJ1muS9rjPnw+tEvi9STrhrrsPezGTx
         hNQSYOni3F7/wZjNtG2UJ7jmNhNH60Pe9lK2wnNtrbltGKrwDI7UlUfengDxzM4Ykcoh
         aYbbeupI59eLxRKkiI1e3J7dEI8gaz5o133psYaDXxWC6pYM4NtMeFJYSz+sXV2WWmXO
         xqmNAI2i+ArTgwQQtvcjOItDa91iUYWynIr8eN7Cbp/aRNf5P/gqHr4ed7ikXQYpyKdH
         VvqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=tmcNmH4nA39g/VQY7DpjtZNCWqzF2fGKwj8eqNM1A04=;
        fh=cVXLQsJpdwbbWJhxthNT+SM2XN7Y1+1U7grAxD80aiM=;
        b=xHjGRar5fv1yOENBtW9HL1TeNZZwcNUHBKPkJJOrVFBZ6rVevswJGoU+X1CXLl8llW
         lOKZYnkfBWT8y9+uS7EWJPGZWmAUoLaH54gzitsmN0IeO8Sp3SlA6za1J77AoFmPYgTU
         LPV9Z8X9Pjqs2Z8oHPULhEa8jckJkkyaNNHbvR+5XLDwlYIUiXyPLrYur2nPIyhv10mp
         sm57FeOjjUPKnEh0C/tYh2ne5E/6P9k4XRL7rdk9DjA2/0baFEIuQzgh39SHRhItCIJK
         uibaNHUio62k5Q181wudnqyKu10bYOmxudpqjiJ30tqlF2XOYnqjIcgT9yx8zLtZys0O
         cN6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720750136; x=1721354936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tmcNmH4nA39g/VQY7DpjtZNCWqzF2fGKwj8eqNM1A04=;
        b=gTlcNV7AOpDbL8gnjv3bDSfH5Wt7G7PmZXN7TxuT/4W4Id6JHKGGDuS5S9FDL5+81F
         DZN8Q91wPeaAOTMhlCm7nZZ647RPHrPiI4Bo3R8wSfR7zyS/Sh0IAEqtsgmO9F5w/sLp
         bsojJrLG5CMd9rm5CEHXyLZMEiql6vOkstXHA1Lu5VzG0SBRfbnRbNXUWba+qGVmVETI
         vKSL3vu2Egz81xkm43T5qvDBvPV2g8G/k/87JHbOfLFEuUkXXtI1bEUCiBYWqFiwY/E3
         mwqwXpHvXbLVypdjnyLrMGpOdKPt6w0exMlAJjU4EG/OSg/IJtoeYdNQ3s4rmEUwFLaR
         qEyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720750136; x=1721354936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tmcNmH4nA39g/VQY7DpjtZNCWqzF2fGKwj8eqNM1A04=;
        b=W1ohvekb21ge3f+wobqvZnd/54oupF0+asO+/PhUJ6mOR8CC/QrMwOEx3WOcz4sYM0
         bJ5mEUVwm/8RV1NjrMkBOQfJKplg6tZsp1DvWws16DmU0Ps8rUBu8fEi/ruVFO2i3p0W
         T5gsx9Gs9HbpZ/RPWe5+9brDhuFsrK2yDQrSi9VbR2BLGtOSW15Rp5ws/EiweEgvRE3V
         dGU9b4YZLLfaPogycLq3iXZg4g8TyNz19yED1o81stPLs3Tj0ho0GeEt2keAxHla/Ok0
         hJQmusDesvJENiIQWFz5Kaz+p1wUH2aE7OTQUfh5BdvxgIETvNdhxXsbVfVCNoEwu7iA
         TfVw==
X-Forwarded-Encrypted: i=2; AJvYcCU0wcQOo2fwgQPMxSkpU0rMYEX/h6nJstSsrPvZtM6rzhcKQnxaZwfPcnMdrXTt/cbWEHpE7O/Um/ckolA17QSd4kmaVMe5mw==
X-Gm-Message-State: AOJu0YyQPHuMYcCVKo5vj8Blo7H5Rc+WmNZI/oHUM50J5VWfuM+0LNHj
	R1TGlz1lJw/ZUcKuDpTOYwBntiU1LPDuA8sPHz4OexYy6p8UCwIo
X-Google-Smtp-Source: AGHT+IFVPkJQtvdltzQ7fKJtyMHsBoVMowrPunaaMhDsSUymI1xu/chptdJA08URySaov6XW+WU6Kg==
X-Received: by 2002:a25:a524:0:b0:e03:3f55:b1ac with SMTP id 3f1490d57ef6-e041b120f30mr11304943276.48.1720750135609;
        Thu, 11 Jul 2024 19:08:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1247:b0:dff:34c9:92f8 with SMTP id
 3f1490d57ef6-e0578ea82c2ls2242283276.0.-pod-prod-05-us; Thu, 11 Jul 2024
 19:08:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpEd8TiU9Yhm9lsIdA92XMXHu3lTnTNfG2M9zsMwT+jcb055WeuG/DAnrlXJGQwYntndHGXm+nugd8EQQu6JTGegPtVre0mkjI6A==
X-Received: by 2002:a05:690c:b8d:b0:64a:373b:cd85 with SMTP id 00721157ae682-658f08cc3dcmr136282647b3.46.1720750134945;
        Thu, 11 Jul 2024 19:08:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720750134; cv=none;
        d=google.com; s=arc-20160816;
        b=lKx2AJgCjM4PvrQOzDI7c9wvaKPNrtSQGzmyRS8efZ+wbUkYC+tP0bOQ7krZHyVPdg
         yMt5f/HZM2ji9IMmFNw3maoCOmeqUMC1htoybWtZDGGbOYT5XHuCW2ERXVDWXmIQV3J8
         jxsZku/gHcDJvgnV7AO/W1Eb63wVSyylyqFWAPKs2tlOLTGm9svAW45eRJ+eKkfXDAuJ
         lehbfB+dWrX+HNBvpRTtBJOZMpq82X4gyCzU47PCuiz3Prz8kpspk2+znLhNoefWWiTP
         /WUANn1P9biaYCJ74iJCjaa7m4mCKhBC1i2TMQpnHE9nBLpcpDWUrXB9sgvLMczNXs7N
         EFBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id;
        bh=3TUC2TvXpgK6JLKjFKWIhf/CL7q8Rvz4X6zOLvojveo=;
        fh=WWH5nxB8NmGM+xgKqaD/vz2drHXNHfWPRpP+uRF1MWo=;
        b=aGzZmx8XJOZ1vT9DIFT8x19Hre/JKwrRhscpJlIcrl8MvZb1A+mKh3y13qAxn/WX3c
         0L9szR/8Wx7Gtq+X7LBPryAauk8iDW2xtrbKZdNrqcjSTL0PlQMznB+eeRbbgnR2HiZL
         zKlHmBNnXe/5fQBxJBmv0n2FNcBbTlVsAhqC5KfAgONDBBJXqIBVJCfyjN2aTJpRBEkj
         DEfYfzqcOaof7rrE5Z9cY45EhLu7O+/gNXGPFES+xrgFzjxVene5hlD2SMt6ia/5PFrB
         fV5urvrCPjOrS7sBmc6I/+gFT6V8qSvLfOID31+g93eYdLtaOniawXTr/mG6dBh67BE2
         GYDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-658e796bd13si4008027b3.3.2024.07.11.19.08.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Jul 2024 19:08:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4WKvyn0Zd3zxWDM;
	Fri, 12 Jul 2024 10:03:45 +0800 (CST)
Received: from dggpemd200001.china.huawei.com (unknown [7.185.36.224])
	by mail.maildlp.com (Postfix) with ESMTPS id 15A37140413;
	Fri, 12 Jul 2024 10:08:22 +0800 (CST)
Received: from [10.174.178.120] (10.174.178.120) by
 dggpemd200001.china.huawei.com (7.185.36.224) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.34; Fri, 12 Jul 2024 10:08:21 +0800
Message-ID: <e66bb4c1-f1bc-4aeb-a413-fcdbb327e73f@huawei.com>
Date: Fri, 12 Jul 2024 10:08:21 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
CC: <mawupeng1@huawei.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [Question] race during kasan_populate_vmalloc_pte
To: <akpm@linux-foundation.org>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>
References: <20240618064022.1990814-1-mawupeng1@huawei.com>
Content-Language: en-US
From: "'mawupeng' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240618064022.1990814-1-mawupeng1@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.178.120]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemd200001.china.huawei.com (7.185.36.224)
X-Original-Sender: mawupeng1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=mawupeng1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: mawupeng <mawupeng1@huawei.com>
Reply-To: mawupeng <mawupeng1@huawei.com>
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

Hi maintainers,

kingly ping.

On 2024/6/18 14:40, Wupeng Ma wrote:
> Hi maintainers,
> 
> During our testing, we discovered that kasan vmalloc may trigger a false
> vmalloc-out-of-bounds warning due to a race between kasan_populate_vmalloc_pte
> and kasan_depopulate_vmalloc_pte.
> 
> cpu0				cpu1				cpu2
>   kasan_populate_vmalloc_pte	kasan_populate_vmalloc_pte	kasan_depopulate_vmalloc_pte
> 								spin_unlock(&init_mm.page_table_lock);
>   pte_none(ptep_get(ptep))
>   // pte is valid here, return here
> 								pte_clear(&init_mm, addr, ptep);
> 				pte_none(ptep_get(ptep))
> 				// pte is none here try alloc new pages
> 								spin_lock(&init_mm.page_table_lock);
> kasan_poison
> // memset kasan shadow region to 0
> 				page = __get_free_page(GFP_KERNEL);
> 				__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> 				pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> 				spin_lock(&init_mm.page_table_lock);
> 				set_pte_at(&init_mm, addr, ptep, pte);
> 				spin_unlock(&init_mm.page_table_lock);
> 
> 
> Since kasan shadow memory in cpu0 is set to 0xf0 which means it is not
> initialized after the race in cpu1. Consequently, a false vmalloc-out-of-bounds
> warning is triggered when a user attempts to access this memory region.
> 
> The root cause of this problem is the pte valid check at the start of
> kasan_populate_vmalloc_pte should be removed since it is not protected by
> page_table_lock. However, this may result in severe performance degradation
> since pages will be frequently allocated and freed.
> 
> Is there have any thoughts on how to solve this issue?
> 
> Thank you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e66bb4c1-f1bc-4aeb-a413-fcdbb327e73f%40huawei.com.
