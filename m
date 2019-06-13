Return-Path: <kasan-dev+bncBC5L5P75YUERBQXBRHUAKGQEQ4PQBFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EE6C43E75
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 17:50:27 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id g2sf2505311wrq.19
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 08:50:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560441026; cv=pass;
        d=google.com; s=arc-20160816;
        b=GcGonZBuZ3vnQmjpzgqBFjF3hppW/eYoQs6HUApIDvnw5Ecv7TzRENgs3zPx12ihEI
         OvjcmaPpulQOzXU98KyRExWlHN4DROsjET2Zku5IkDdIKV625LCZhd1Dgwg/gyxVT6BY
         RLASC9BDPfhswbJJoiC81rfHPk28sXMA2pMmjVSGY7Cf+GT7YSXyyrXbg+1oFSxds+bo
         RJ8gfAQLtE/8qYqUDZPGFmYVq/CeHvU5lqd8BDXZImjgKRmT/d8pzL3Hz3M1paLYI5wR
         HDLjmBEnuX78QC5rNMSj4IUfQ4LOBf24gZ/pxvuEp/dB5s9bY9waGYwFzmt3kSGIL+IX
         JjYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dnS8liPxlwu4QnmZpWQLJoKU3Bp/t/rb/+3IyI7Os5w=;
        b=EaxXgzHFmZmONHxLNmG6jJuTlo07ezE4m6KPXCqbpdekAac4oYBFhmoNuhruOKWqxh
         l9MPiC8zH5tFR1IboHrlrpl4g76oS7D1Lo1FFQBg9uQdzrPJk+z/2aP+DB8igXKiYrYX
         ee/jnMkkUmGzRd4azM+5piNu5WY6JzZk5dU2UxLzDTgPAFGTZX/uCDMFIedAPEAoPQjj
         hQYjgsV2iZkRKdCP0CZFsreMx/EdbYYev4SFGbukLZQtijD8yq9kxRhDZx5E3/3JFbEi
         tzcz+uQVfXJ1VYtxloNGe2El3co7dum+nGczvaEIA4BG6Vr5LzSKwa/Qer1SivRqG0Wq
         Gouw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dnS8liPxlwu4QnmZpWQLJoKU3Bp/t/rb/+3IyI7Os5w=;
        b=tP/clEufrS4r9WuE29ptlqgShJTKRxwElhTbmCDTD1Bm6aDxuT30m63l1eKGqfLZEe
         JF/gEbYh5p3hH8sa+PD0rdiTQV+v+7kUKwMWuhKbuXvyjLZgfMKcWkuvBxbYdbN/pqYK
         +VZL5MeV1jY5o+RPa3su7ygjRAimnquFMWdbVfe4lKLBlekWWoxD5DZWML7j3Btz/04Q
         HOvv8XzF0zESItAVKFGl4stJ1eBmpQBsmld6a55UV2t+5BS1Vo7JqLm0Xaapjv623Gg+
         OPUU0/SqqY1CEckLOpYhQa0MWodx33cRmjtsuhNzuJYMvHTJBuMSlTRvUkQgXunzaPFF
         4x4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dnS8liPxlwu4QnmZpWQLJoKU3Bp/t/rb/+3IyI7Os5w=;
        b=GSsNIka9eQYWZloh8GIueOYxrwkTqZRX1uLEuJTV8f20srUb7D4PNo5fKNx4S7Aa0e
         Qhz1krA6SzeFnLX8o/rWXP6pzsbh0i8YQo3stb7FKOXJNqhwbsIs3HWVCVkgMHT4dbZO
         HqoQ3roAG7tqeQS+NjHpO/qZ67vxFE0m/EyQVIpGim2eGd2TKLKgz+ToUJvt+6MAWubr
         S9xELYF8igzEOUkTQCFVK/Qcv82/1qMVK5X5bN6QBxDob9VsbjpJ/lJG+SJIoaHWAPC/
         t6d//mV4ULAG6pQJPPrXDFG2M6hyR4I7ZHhpxrtY3nBYeV7Kjccxe99REU+f9LW7Vj4e
         s5RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWFYjSntxSmukioNh5eluiThiF/cQyndZJ9frsc5hYWuybmbXKT
	admMRjFmEEDbVEnx08SQr8k=
X-Google-Smtp-Source: APXvYqwtvIy2hU/h9Im4EPvtZ9SeC6TpN2m7fUdK38prKBBQOz6hv14ukPeLyvX0W1H9MguFT7203w==
X-Received: by 2002:a1c:480a:: with SMTP id v10mr4323610wma.120.1560441026858;
        Thu, 13 Jun 2019 08:50:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ab4d:: with SMTP id r13ls297446wrc.5.gmail; Thu, 13 Jun
 2019 08:50:26 -0700 (PDT)
X-Received: by 2002:a5d:628d:: with SMTP id k13mr9394362wru.317.1560441026411;
        Thu, 13 Jun 2019 08:50:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560441026; cv=none;
        d=google.com; s=arc-20160816;
        b=od6MZvIOV2ZyTcRDCQAxMc7hj7ZQTLoNfLhHrX9ittIYXyOjaGmT+uFrZqvSRHEvd0
         d+bPCMUKRCHbSHSVjC5eIQdg9MzvexNL2oWK4a+B7em8QZeiQXaBTYkGepLKboPNvxl+
         AFCJEVkXfF/59s7KnjUK9J537eAjWu3J3YGovWsadfRNiuAcR7zgCcZwNmZ2nwftcOIz
         RXmPgq6lB6oQoFwFLKINkO0SvVoiqrO3xx813TMzTQNunTjTAnxAn7Tp9OSAqJAsDBJF
         TtgKz1WPHUSfer2CLom+L0kF/9fAQNaiOUeUO+VYv4S8xgB4h/ndf0nFQF5mHsDp0szx
         HwCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BAQ3ZZbpFyn74ZZBbyfrvLcJL6fj+10PKW2YlRVqguw=;
        b=cymlmO4FA9XOac+75IihZfLMya02O/Ig9vNsJ/xJA7vTZkLJ+zDYLEz3FvHD72KdPM
         VnQ6qk6SBYa7CS2WNnzxDwwiA3RveEk0jxb2BsR5n3jeZ4ChD4+5SoSXDYERkFqgKI2z
         9iShRuzTdhGF35s0V9etFZyXTazd+ZWo3Ckl5FDTiCUP7nFwSri67LUE+iiqlYj5uRiP
         TEvjMPMoeTyoFwNQhjEuvuQJqiywBZzx7r7D4iVVYhht/6wkP8ngrSNktAfD6ihxz+h6
         kHPA9aQT7ppLm7NO0eGicANxVj49XVFFI6W1N7KtDJyTWtxOC0P2RGVt/TSZuBJQ6A3q
         wI2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id v11si22192wmc.0.2019.06.13.08.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 08:50:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hbRzR-0002en-B5; Thu, 13 Jun 2019 18:50:13 +0300
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
 <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
 <CACT4Y+ZGEmGE2LFmRfPGgtUGwBqyL+s_CSp5DCpWGanTJCRcXw@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <278bd641-7d74-b9ac-1549-1e630ef3d38c@virtuozzo.com>
Date: Thu, 13 Jun 2019 18:50:25 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+ZGEmGE2LFmRfPGgtUGwBqyL+s_CSp5DCpWGanTJCRcXw@mail.gmail.com>
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



On 6/13/19 4:05 PM, Dmitry Vyukov wrote:
> On Thu, Jun 13, 2019 at 2:27 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>> On 6/13/19 11:13 AM, Walter Wu wrote:
>>> This patch adds memory corruption identification at bug report for
>>> software tag-based mode, the report show whether it is "use-after-free"
>>> or "out-of-bound" error instead of "invalid-access" error.This will make
>>> it easier for programmers to see the memory corruption problem.
>>>
>>> Now we extend the quarantine to support both generic and tag-based kasan.
>>> For tag-based kasan, the quarantine stores only freed object information
>>> to check if an object is freed recently. When tag-based kasan reports an
>>> error, we can check if the tagged addr is in the quarantine and make a
>>> good guess if the object is more like "use-after-free" or "out-of-bound".
>>>
>>
>>
>> We already have all the information and don't need the quarantine to make such guess.
>> Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
>> otherwise it's use-after-free.
>>
>> In pseudo-code it's something like this:
>>
>> u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
>>
>> if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
>>         // out-of-bounds
>> else
>>         // use-after-free
> 
> But we don't have redzones in tag mode (intentionally), so unless I am
> missing something we don't have the necessary info. Both cases look
> the same -- we hit a different tag.

We always have some redzone. We need a place to store 'struct kasan_alloc_meta',
and sometimes also kasan_free_meta plus alignment to the next object.


> There may only be a small trailer for kmalloc-allocated objects that
> is painted with a different tag. I don't remember if we actually use a
> different tag for the trailer. Since tag mode granularity is 16 bytes,
> for smaller objects the trailer is impossible at all.
> 

Smaller that 16-bytes objects have 16 bytes of kasan_alloc_meta.
Redzones and freed objects always painted with KASAN_TAG_INVALID.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/278bd641-7d74-b9ac-1549-1e630ef3d38c%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
