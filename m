Return-Path: <kasan-dev+bncBC5L5P75YUERBZOZ5LVAKGQEST2HYSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 1782C92617
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 16:06:30 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id b1sf5316399wru.4
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 07:06:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566223589; cv=pass;
        d=google.com; s=arc-20160816;
        b=xhA14Tbd5oHTpnsQzfciyWEuOEX0Nai1z+vc7id50T4oHZnmiw26wQfh81czAxqcLx
         gyRMt8xyTJOy95XftMF8FOkeXB1DhRpfYXvylw30VrKmuCM5iP2glzWMolR3VVldMKhn
         sobvqoh0R1iqYIfoeDazgpjqxvz4ZaOtUP1V1Xx+3AovmwzebM2NEGrdaLNn/Ft48HY+
         xRa0Pf0jAZMiwuZ+sDFqFDWL84C/AneWVPw12dO0ox8auxAehJ86zB/SoQZFLbBx34iL
         KfeZlGqDTBsEtvOTEAIgPzojEe0NUkahVntyCMgmwrDpY0QjKYaDSY7vTj/rdTM9Zp56
         eeaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=+OO1S6X5+4quLEwgAwEJP5/tcDcJMImW8nXlEbi/Ldo=;
        b=htW/vpq5w+88jz+UwrabDxEzi24exAHrlco8Ni2pAVKdiUoMJNywmWuYpue/+lpp/l
         g40AnrbxxBYoSuw9Bh1IkmgoOikQf82m0J4gtONXUA2UJw1qBhhpocHCNt1j50Mid0n6
         dRg4tj2KNZ2qEwJt0BrYSCAYnwtNXMQbc8ZLLmk0FtFFS+GWQn0+z/SnJdJ+vugDh/Ic
         /aeQNNyegoHwtz6L9FYV0s9aWzndPhosP37SB1fdwo986TaoIs68T3wZTxhwO2oMLLFP
         GAWrYbghiqeUcV8mxkJ5YGXr5s38ImPtqx1wDPNCCFJciuFuzsTsY0fR0gW02pj8n++1
         ngtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+OO1S6X5+4quLEwgAwEJP5/tcDcJMImW8nXlEbi/Ldo=;
        b=sdAE9N3OrqdZU0F8MNwLgZIm1JUpRHQyIUFY5pQ0g7AGKrcadSAJV43QEeWRGtZmHa
         6lwlGqlcAMDY73AddyBSqrfBqo/o5/jhkUhRjZy6WDiyTCQWeHTotY2Fa/QB+wTnkfZO
         sU1/rllbpdiVqgYN3EtnlnVZFRKcAwwSTXr4lyAKyDX9Prir59B2xr54q0dx75RAyQ7u
         rAzjEa3G8VuP1f8+UQR43lfv2zuw2YJhARCD70tnR9puE1WQE9sKITmxvtG1pTkvy7bY
         ez4YgOlRFL2ZU+SsaKPHgHuMUiyst8x3+bYf1382Pe5DD9vWehYjyQwZl/QTHywj/Xmd
         gI6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+OO1S6X5+4quLEwgAwEJP5/tcDcJMImW8nXlEbi/Ldo=;
        b=oT2ibawbWaRlZPrASVDZSLjh92VoNYDvUgQSL3RnDBxi5ELCa21k5+KB054oGUoOj3
         RPAwkK9HmU2zZOeIYoLM+SQM2hNJS54x1T5FluFFl2mxr2+gWcTysDeiaAzJDNcA9/33
         uKEMAH0T36I0U8qB9QytRNykKq5mBEN6WD7WS1PNxMCMoPZ1TJ8DMOBv11JmdrgeJjlW
         Q4B2UeGN4jbFup7deXDjcyi+2eMGwfgIxIgtYj0K3aU/iSNpfNDRhyHyKoyGYJPBeglD
         TMW0PGqDi598fu/yZuAAdfVBxl0mYGTJAqGWzFOFkERwVoCC/r4C2DpV0+jNergnNv6O
         XbAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUU2VI5/U9s5uFwoQnPoFjrocq9DZE3pzwzpfFRDq5zrfsWBM6A
	YoOeC5KV0qhqttRmrmoDirw=
X-Google-Smtp-Source: APXvYqzW6hYe9yTiiKE4R45POI1ElV4JHVKlBGhmwd2oV4emwH/HhYtSLGHs6mDvRrYOHL1sRY1vFQ==
X-Received: by 2002:adf:f2c1:: with SMTP id d1mr28537751wrp.157.1566223589798;
        Mon, 19 Aug 2019 07:06:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5506:: with SMTP id b6ls4590615wrv.4.gmail; Mon, 19 Aug
 2019 07:06:29 -0700 (PDT)
X-Received: by 2002:adf:ea89:: with SMTP id s9mr29001650wrm.76.1566223589426;
        Mon, 19 Aug 2019 07:06:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566223589; cv=none;
        d=google.com; s=arc-20160816;
        b=k/z7uFHM+DJK+mGVuKj/GVUx+j7WxniXXbXHuvScXPMwydFio00QyM2eX0bFtKv2Mq
         Po9vHhKHm+PGKQ2InEnUAByA9Clg+2/oGJTx31NSuCzavgLLd2TSZxA0Bmu7TpBsmqdk
         Uep+SDI4oHpGY5G4g+Rco7d2CQ53Q6PRF2KGUaYsFADdYvRjt9Pug0MBnzzXVLhBB90X
         znrsQm16cm+l4PVO+DgYX/7Pv4qk+slx8xYbpgZjIETIAKqJe16n2tIzCucCXXLdqtvr
         wxozX8iDQ4dqgL1BGSPZPtlP2HAZEz9hnwi/PH7FGXS+ypgP4HXjMTf4uvO5hNtvzL4J
         TGjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=MqRZppYTRbLh5KhLJ3SwBGItLRn3iwBBy4hz7jq9+rY=;
        b=Exjy7e0IPHyTHAuDIkemZ7ql32gGOyWx63rDJ2kL/eEaUlptJ9+0U6V5olDRGMYIhh
         b+Ho1gYWPHV4tvyRbAjH9CZSx8xLUxQaswOjzz//ggaqTze7m7VMF6EEZVzoE4gR1iKP
         A64A1UmNM7LVMH+UlrrrX924F4gEUyvOdT+8o/Dn8sT751Z4J0UEWHfrBmx7meapAZLg
         w+sFOjnP1DhzMsivHrHRp1wxjgHd/9HDSSKh3VTxU6vRJA38HaaUbqrBCHNFFmcl7f4Z
         2xyTTcv9h4i+MC4owXhT5j9aOvultWYMyBpV9A1pj4+SAagy6rPQn4EOc4zJ2RDURaqr
         vCeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id p4si491020wme.2.2019.08.19.07.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 07:06:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hziIi-0001H7-Gd; Mon, 19 Aug 2019 17:06:24 +0300
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
To: Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>, wsd_upstream@mediatek.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mediatek@lists.infradead.org, linux-arm-kernel@lists.infradead.org
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <8df7ec20-2fd2-8076-9a34-ac4c9785e91a@virtuozzo.com>
Date: Mon, 19 Aug 2019 17:06:33 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 8/19/19 4:34 PM, Will Deacon wrote:
> On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
>> On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
>>> On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
>>>> __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
>>>> but it will modify pointer tag into 0xff, so there is a false positive.
>>>>
>>>> When enable tag-based kasan, phys_to_virt() function need to rewrite
>>>> its original pointer tag in order to avoid kasan report an incorrect
>>>> memory corruption.
>>>
>>> Hmm. Which tree did you see this on? We've recently queued a load of fixes
>>> in this area, but I /thought/ they were only needed after the support for
>>> 52-bit virtual addressing in the kernel.
>>
>> I'm seeing similar issues in the virtio blk code (splat below), atop of
>> the arm64 for-next/core branch. I think this is a latent issue, and
>> people are only just starting to test with KASAN_SW_TAGS.
>>
>> It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
>> virt->page->virt, losing the per-object tag in the process.
>>
>> Our page_to_virt() seems to get a per-page tag, but this only makes
>> sense if you're dealing with the page allocator, rather than something
>> like SLUB which carves a page into smaller objects giving each object a
>> distinct tag.
>>
>> Any round-trip of a pointer from SLUB is going to lose the per-object
>> tag.
> 
> Urgh, I wonder how this is supposed to work?
> 

We supposed to ignore pointers with 0xff tags. We do ignore them when memory access checked,
but not in kfree() path.
This untested patch should fix the issue:



---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 895dc5e2b3d5..0a81cc328049 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -407,7 +407,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
 		return shadow_byte < 0 ||
 			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
 	else
-		return tag != (u8)shadow_byte;
+		return (tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte);
 }
 
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8df7ec20-2fd2-8076-9a34-ac4c9785e91a%40virtuozzo.com.
