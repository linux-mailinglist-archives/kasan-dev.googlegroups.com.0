Return-Path: <kasan-dev+bncBCRKFI7J2AJRBENBTGEQMGQESOO4ABI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 366413F76F5
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 16:15:47 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id x20-20020a9d6294000000b00519008d828esf14775925otk.19
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 07:15:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629900946; cv=pass;
        d=google.com; s=arc-20160816;
        b=LFS6fKBL52RLmMzs3jOoTbELOx47agyzSuKirDKUYdAu6mfjLTsOtLJi4aaTSqwyQe
         hqiFZIF+QoZxRWS3ZxI7JSUzvghS0U8g09fhL4poh0B9bAizP53ftq0yDgcDwKZZyD8D
         BZcTgQFSmaZEmqiu+FcYKtK2gm1wEv94vvLZ03gd9wdZ7ouW8/i7+EuVmnK5AWFbJZww
         ND8dduspNRr6qph7QkflrrPOTvvQpjRPpw1fdI8VGey46icj8B6ObhyPDilQz1KRdg+W
         RjgaXNkENkUsJ0Rlh8Pllh5oBQMOZmWWJz2gC7QI4nVoHkIcaZxDnSo3Nbv1wZgqPHul
         ii2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=j+MtfEkYLS+16zItTyEJ92BGUadtro+7/+oA+hKY6QQ=;
        b=NvjHO/RbhB8dmSAUQ0nK3SmlvgbUpB4By2UIJWpvRZbd6o2zQw4VcAoIPODDQ4mQSU
         6RKhXFoK7vN/aVse7JG9SmqaUzQZ1dKqErv/QrceqtSpO0bJ9u6DeNJTLbK8si5d2HIE
         BHo/k+c+2ie/cnMkyOkvOHlXTC3UNuU+balUCbwuSavGOepQIlBLaB34dgL5J6hArJmi
         FLj7cvKxYDcTa4VHQL6OvFhLsFkAGo7z2vDMYyW/sM4k/c1jtEnq4lALNCsmFOrBJyVy
         6QxIGHIHFuhn/1LBa5QFVUXzJugh4QBbP6vvTGMv4n0pwAI4qXIIT4O+Yq1ZOa0t/WMi
         Ndrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j+MtfEkYLS+16zItTyEJ92BGUadtro+7/+oA+hKY6QQ=;
        b=LITjQT3uerGXHe80p6XONzgoahoiQr2CHaJFzvQ8OfOxTkFQJdwl5UWPo18of32quk
         0DWNwaG6IYu4VHZVGLE2SMLh7jSD0eyMSuc9XW58C4FsU5aYXurIlhtGdN3rbBBXzIo5
         rFJI/Rwkee6vFr8tDYql8BtWKjSStfNqAbtS3jpK+M6DSOBVO2j0w+1VwBQXD7vP8vMa
         OXoqplM6ACDkfYz5EOVTUnefWP4t9hMXCF+G8ma0LJ4ZFog5PjGSRZ+Pw95ZtpCYKrCJ
         aexLxrv2IxmYXnxRnGM/igvzSeCFe/UptjddELyzED6pR6cK8F+7/bwQhnrvpCk09QfL
         kZmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j+MtfEkYLS+16zItTyEJ92BGUadtro+7/+oA+hKY6QQ=;
        b=ccD9kSoSkT2I9On5cWMoJ+RqCazfaRQt8SYLHFxxIWOoVCQKOD/hPrvXMXaPBqbi57
         6HCV9D/Fm1vZaTeRy1O62g9mE7ehz3Z9zLpUzFEa6jM1wDGBoUudE5aJslaTgNN6mKqX
         KUDGK8W0gqkmYwUdJPeOtL6zAy8QCXohLtUiOdfyHyDDmj9UQg00eVTWICr/3x57T+mL
         rDSMZb80oRVIHyeU2YHjEi7IRRJ61zVKdX7RrwoRxzSHl3G9SXIaLUBhkhRdoSI895lR
         5+Ty033AFO6YYneKcB3kR1ABa1yHSg5+wHkSsSJTLhTASHw3+Oqr618roMI6HoeY27qF
         ++0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MDWRYYYnaNPiR49jH7W6240PR3RUiK7sNzlcbtQQCIARFz/gD
	JUHIKTYw17C+6kbYbNu6g9Y=
X-Google-Smtp-Source: ABdhPJwbd3cVf+E7KXRJqkUfIeJg/cmaxk4VfHDbomyY9YZhe3MOda9u820hzFF8//IBhklnm0ediA==
X-Received: by 2002:aca:add3:: with SMTP id w202mr4372586oie.112.1629900945896;
        Wed, 25 Aug 2021 07:15:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2186:: with SMTP id be6ls598680oib.8.gmail; Wed, 25
 Aug 2021 07:15:45 -0700 (PDT)
X-Received: by 2002:a05:6808:aa8:: with SMTP id r8mr6906645oij.171.1629900945461;
        Wed, 25 Aug 2021 07:15:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629900945; cv=none;
        d=google.com; s=arc-20160816;
        b=SUofOoT/Zhis+CO7IlBu+lfw8P+FEEDBIeGN6dkfugvo1WGRT+ZAfCg30k/gMHHwEp
         2VZi4Oi9KH0+ZfqEZo6a49tYB1BNQn7tD9/rexp/+QQH67YNclk+vnioG7l4cj/7U0mS
         1kCHcGU2ND9jqOcBNBeE6ZSXV0YgsgzcRKD9hYVIJHijqSRiEw5iz4hT6elUxb91SfEO
         s39mVpajC2OqeVbG3hpUBlJBOih8kq0JdbMMAHAJVJ69ffMqN3KASrbStlYzzU0qnIyN
         xN0wNzGkkfDdBKnjUuR7VaGe2W2gx3zc29EQf0kiMeDm2ycfoDt4NIg1xMgON65JnHhk
         tCYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=DRw1VDZlYuKD+iBRCzIahu9NEZEhULML2xweqPYW1Ec=;
        b=fVq0+cQaTTiy6DNFhkV5+hnN1QrlI+EzODvIgq5O/yjOceyVUkfFkyBiyN2wxUd3pL
         eq2PRLKA95ERlJuqmYufnERLhd8XjtgtZdT9eHxD+lREUuTXhJvu0lbbuFvqw2iPT9JI
         JUB6LjkEM1IZ9ABYYr5hbxzfwvHklCSg6ew2l9MOswf7krMoYXLO5M4JSUki3GyHzg5I
         Nq13/kQIiCLHKIL3b91/hddmG0lBZnigbU7ub55kHxyUBZHF7M9DZ/vGPvEWzgwXP+Ck
         8FHgYZiijC0eSL3dJt6h00r93fYQMVg+joXgs8noGXN2y8EHUYBztmmyc/8G0kjStg1F
         69Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id a9si7917oiw.5.2021.08.25.07.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 07:15:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4Gvp0Y4cY3z7tFX;
	Wed, 25 Aug 2021 22:15:25 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 22:15:40 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 22:15:40 +0800
Subject: Re: [PATCH 0/4] ARM: Support KFENCE feature
To: Marco Elver <elver@google.com>
CC: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <CANpmjNMnU5P9xsDhgeBKQR7Tg-3cHPkMNx7906yYwEAj85sNWg@mail.gmail.com>
 <YSYiEgEcW1Ln3+9P@elver.google.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <f0cb0ebd-2b4e-7a65-8107-f7e1f23d310f@huawei.com>
Date: Wed, 25 Aug 2021 22:15:39 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YSYiEgEcW1Ln3+9P@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/8/25 18:57, Marco Elver wrote:
> On Wed, Aug 25, 2021 at 12:14PM +0200, Marco Elver wrote:
>> On Wed, 25 Aug 2021 at 11:17, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>>> The patch 1~3 is to support KFENCE feature on ARM.
>>>
>>> NOTE:
>>> The context of patch2/3 changes in arch/arm/mm/fault.c is based on link[1],
>>> which make some refactor and cleanup about page fault.
>>>
>>> kfence_test is not useful when kfence is not enabled, skip kfence test
>>> when kfence not enabled in patch4.
>>>
>>> I tested the kfence_test on ARM QEMU with or without ARM_LPAE and all passed.
>> Thank you for enabling KFENCE on ARM -- I'll leave arch-code review to
>> an ARM maintainer.
>>
>> However, as said on the patch, please drop the change to the
>> kfence_test and associated changes. This is working as intended; while
>> you claim that it takes a long time to run when disabled, when running
>> manually you just should not run it when disabled. There are CI
>> systems that rely on the KUnit test output and the fact that the
>> various test cases say "not ok" etc. Changing that would mean such CI
>> systems would no longer fail if KFENCE was accidentally disabled (once
>> KFENCE is enabled on various CI, which we'd like to do at some point).
>> There are ways to fail the test faster, but they all complicate the
>> test for no good reason. (And the addition of a new exported function
>> that is essentially useless.)
> I spoke too soon -- we export __kfence_pool, and that's good enough to
> fail the test fast if KFENCE was disabled at boot:
>
> 	https://lkml.kernel.org/r/20210825105533.1247922-1-elver@google.com
>
> will do the trick. So please drop your patch 4/4 here.
Sure , please ignore it.
>
> Thanks,
> -- Marco
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f0cb0ebd-2b4e-7a65-8107-f7e1f23d310f%40huawei.com.
