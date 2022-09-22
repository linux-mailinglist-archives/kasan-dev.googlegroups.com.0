Return-Path: <kasan-dev+bncBCKYTRUVTMKBB7VGWGMQMGQEYNOUMFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CCDC5E6238
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 14:22:24 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id y10-20020a5d914a000000b00688fa7b2252sf4551406ioq.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 05:22:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663849343; cv=pass;
        d=google.com; s=arc-20160816;
        b=e0dvKaQnwb2ho6dkBt9dgBc1uOtdyrpLJka2hNwbrBPDTwr+ZVdjPRB5a6C/cV887k
         m88ObCdsZ8zVv1VqZbWAtfCyXwv+595Cc+CZPNO+9P84uPl8js3MVCrWI1EycSOzRRMn
         oUcrvmBdhQUY0Rm14xTUCLHi23Dr6XFhHv7HVxIvwOCnG1aBeZQGWe1Y0xwKcmMapCyR
         loPFTwv+i66JZQzuHcxa6DLJG7h5HOHXCyzBbPiuSUHDJMji03fbI6+A9f3jwy1TR6Ep
         ENCKo6D7SWU83bBOdfaQrmk0ypkT21wUUYFRnbDCyRMw7TvD6KOUACsnd7Jm2pX7S1n7
         u/XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=EBvpxZL++gTfa7iJjmCHlgFqB+FnVVvAMhirgEo3oU0=;
        b=bhxrHoYtqsNDv6xfpplMRROrpPPxIcKGmkK5RBWmc+mnIlIODHbPU6Dh+fbxJKvZGv
         MoV29Um4rQQ1C5C15BOfw0CCpJKIeFe0EgneNm+76v2HksPa6KBek1veSp/UrsVVQl4V
         4eDBziXVhuK3Py5q2PxZQ4geJIgB7rOoAg9/XyKQEwtnOSTlXZe9QEP4n5gyQqxFPKQJ
         x3Cuv7FZ45PZ/cGvRkhtlvykdr9cyrBLUIeYTj7gd2/vt0BmO0deJUO3zcPhfSgCyD8d
         v0CygbU6nXzsGPfYrL7CO/ZK749xMx6BPxiJoUATVaQCj+LX8KBSo5XrYCS64KvLP/YT
         3CaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date;
        bh=EBvpxZL++gTfa7iJjmCHlgFqB+FnVVvAMhirgEo3oU0=;
        b=kTK2uJUOKzngUp3lFWqQRUq29HfM5p05kFWskHQDBE85FglUn3PoMU0DQS3y1NE4fE
         dxPKPr1FsxvwgKB7j5enhadCxj2T1vx3jOvGvF1KBjCwp+FPjueHI4d0wPnpRC0iAQy1
         KcefQgfaJWCLfyK5BFqL/uzWL/nG61iWQld7ZsI7Cb/EgAHKYsUPvn/rM9fCNsnavr1+
         lY5BgSKJyu/If7gE5tZn8nBaVwDmvx2xsLz03aIU23PQSqg71K+2AlaikSJWnUSuGlp/
         +YMMGEtjVqFA0zuF+E5gj3Vk4FkB+9GXQZotswDZi/7nlQB2lRWRmyEwEwwVjBGQnbrT
         /umg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date;
        bh=EBvpxZL++gTfa7iJjmCHlgFqB+FnVVvAMhirgEo3oU0=;
        b=kD7yTrxXWltxnjkxxFX4Ux5uxEycxQ2CHFt5Ux6qLnVYB/RtMQAKNOw2hIHMvk1P2W
         6AIDrKc3nAD5Ejuu8+bn9z7gMXcV8ohFO+4LWS7T6peB6QVrEBgUylB9rpI+UeiyWlFv
         5mr/ZjFYxt0O1F6rg105/JZBlri6ySLgiPhPut+dLXn3OZCfxG2VWyeUAS1RKKPKHafa
         HT+HvGd2OgW3U/bpmiQ198i4e/+eGLWKAdRC5oAuFXNj4JlphsFLsvbwAT7ocU9S3vCf
         7zbHxnyeSOGWkrEI/e/VMCPjW2jbbzuD41kxB3OdorED0L/NPQtbUgymJeo+a74rtzMq
         dQiQ==
X-Gm-Message-State: ACrzQf3pRdgn5fKPmfWm7jsxipyWfUtbE8a/Agm6osjJcVRkH0G0cWYx
	wDHMwXsUV7sYWptkcb8Zcmo=
X-Google-Smtp-Source: AMsMyM5jfCd5eNDdvfAPeYL57UDRvBzgFasizp3wi3cg/nsFev9wta2Z59Z0oGFvDWKOxyhNEN9xbQ==
X-Received: by 2002:a92:d843:0:b0:2f3:5f18:bbe7 with SMTP id h3-20020a92d843000000b002f35f18bbe7mr1509047ilq.108.1663849343082;
        Thu, 22 Sep 2022 05:22:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a1dc:0:b0:343:44a5:a2d1 with SMTP id o28-20020a02a1dc000000b0034344a5a2d1ls2836148jah.0.-pod-prod-gmail;
 Thu, 22 Sep 2022 05:22:22 -0700 (PDT)
X-Received: by 2002:a02:b681:0:b0:349:b7d5:7c25 with SMTP id i1-20020a02b681000000b00349b7d57c25mr1695770jam.228.1663849342665;
        Thu, 22 Sep 2022 05:22:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663849342; cv=none;
        d=google.com; s=arc-20160816;
        b=RT1h/a2LD1eUYTO0FxZIc7fZJ3uGdPzwlJ+JWu9sSNK1GowRlqiAD9DaeI1LhH84CE
         qDF1pKlxBOS9HY5UDLzHPkJGKD1AL7eOmkAQz9YxGAHEiPNdJoMmzef60RfW83fJHYJk
         BXviJTCVElO2PXN5NtilMvSMvRkhsTjHu0lRqmzFtL7R4YIcfnDGthC3YuWJN4zllyxF
         sONWHeByCWTIVBOJnQKOjHyf+C1zrq80agciCQf8u/DVwJPxUb9HyI5PuxguJ82kCiWS
         4y7gzmpbPmlVi4QEHnxqY+gsUDbxm4hdM9G211cx66+M9C3I4GHVYyCixaMmd0GFZTsM
         zKbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=lnZDqnMlR6GRtE3I1jhWp4fn8qATyPOSn2/+z4IMIFY=;
        b=FpmDzJ3XozRnLuWOgyZbj7JjVGbBnB5Dz6qscnAOi2d2Vm0OReNJ89YUDCVICLjZph
         x51wqzexjsi3uRrXJPkhF9r1wl3WzlZGvNtkLF1FIo/PLKg4iIBF2pa+C617dA5nqHbM
         W51ELRddsRZ64CMnaDItpEz9zoVzIVJrQ6EOvhALGADoRQO7F121Z52h1dcZgZXe3U/c
         v6LdwOw2/MzkRi22epXfTM69KZ9revvf0g6RXk96tbpIfzotIoyW1OON3jlpevNcuavx
         HuBEWzaKHaHMjWk8OgMXNBBnb1DkyGH7HM6NLhlBw91bbcuy1UUANT7XHEtruEghYDys
         jVCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id k1-20020a92c241000000b002f605782c7dsi361599ilo.2.2022.09.22.05.22.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Sep 2022 05:22:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500023.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4MYDnF47P4zMn1v;
	Thu, 22 Sep 2022 20:17:37 +0800 (CST)
Received: from dggpemm500013.china.huawei.com (7.185.36.172) by
 dggpemm500023.china.huawei.com (7.185.36.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 22 Sep 2022 20:22:20 +0800
Received: from [10.67.108.67] (10.67.108.67) by dggpemm500013.china.huawei.com
 (7.185.36.172) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2375.31; Thu, 22 Sep
 2022 20:22:19 +0800
Message-ID: <316fc8ae-b96b-1fb6-4a24-b8bcc6f8b948@huawei.com>
Date: Thu, 22 Sep 2022 20:22:19 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.0
Subject: Re: [PATCH -next] kcov: Switch to use list_for_each_entry() helper
Content-Language: en-US
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<liu3101@purdue.edu>, <nogikh@google.com>, <elver@google.com>,
	<akpm@linux-foundation.org>, <andreyknvl@gmail.com>, <dvyukov@google.com>
References: <20220922105025.119941-1-chenzhongjin@huawei.com>
 <YyxR2ErlHj6wrR6m@linutronix.de>
From: "'Chen Zhongjin' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <YyxR2ErlHj6wrR6m@linutronix.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.67.108.67]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500013.china.huawei.com (7.185.36.172)
X-CFilter-Loop: Reflected
X-Original-Sender: chenzhongjin@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenzhongjin@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=chenzhongjin@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Chen Zhongjin <chenzhongjin@huawei.com>
Reply-To: Chen Zhongjin <chenzhongjin@huawei.com>
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


On 2022/9/22 20:15, Sebastian Andrzej Siewior wrote:
> On 2022-09-22 18:50:25 [+0800], Chen Zhongjin wrote:
>> --- a/kernel/kcov.c
>> +++ b/kernel/kcov.c
>> @@ -133,10 +133,8 @@ static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle)
>>   static struct kcov_remote_area *kcov_remote_area_get(unsigned int size)
>>   {
>>   	struct kcov_remote_area *area;
>> -	struct list_head *pos;
>>   
>> -	list_for_each(pos, &kcov_remote_areas) {
>> -		area = list_entry(pos, struct kcov_remote_area, list);
>> +	list_for_each_entry(pos, &kcov_remote_areas, list) {
> so how does this work if you remove pos?

Oops... will fix that.


Thanks so much!

>>   		if (area->size == size) {
>>   			list_del(&area->list);
>>   			return area;
> Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/316fc8ae-b96b-1fb6-4a24-b8bcc6f8b948%40huawei.com.
