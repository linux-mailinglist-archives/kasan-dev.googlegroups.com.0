Return-Path: <kasan-dev+bncBCRKFI7J2AJRBR5PRKFAMGQEPC3YYFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id C9A4F40D10C
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 03:03:04 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id e17-20020a056820061100b002910b1828a0sf12325520oow.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 18:03:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631754183; cv=pass;
        d=google.com; s=arc-20160816;
        b=sP7Y+cHuPpn0oB+WQzG/xLo0v9D/AS1exWrkn3KjQ7mbkuzT9qB3meBoHy0PTj6fcD
         u+w3YvlDvDFHVssS67qzF0hZii9xRN17t+UmEaxS2l+pKwevS0dZQ22w5LzdSNlN3Q6n
         ldSkrQSKuWfBezogQ8Be3dDnXSwi6p6wHzZCy2Dt5UA2FybMfJcLDWIi+fB84OIk68G2
         oKyaZBOjqMH4OAmUj81+O2hkALsLVNvDSOSyZ1OTmG7SKrmpsBNQ14e9gcDq2E2zm6jB
         MwwRGip4/6nI2RsQNLfTUA21sczNQuHM97c4FadcSrIz2q8Du+jVBRPVBPNH6eaZzWxz
         Jm6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=3YFvZqGwWIfqrshf+AKssBvejlsZzC69ItDTX6CzW7s=;
        b=Br/mtPsdJ+DVEKzN64c39+LVRiGs6bEL+UR2xZgn/W/Fd+roj6RzcsA88CorTVXqVI
         sdCWaxcPcH9ieYc0joNhXGf9u7813MVeyGql9KhmfTy9lEkezeZtZz0YNVTrxQ8W8dEt
         IyYVzXnJbISSzr9/ko7wJ6nWfN0wrwXuXcL6M2rtpleoWOKvvR9DTln0ypR5CHt3+y8g
         s97zciIXaeYrWmqFnjEvWize4lSDhZEAahGWKdmkFi+dcQksXv95z9YnUNgy/MUwEmFq
         s3TWEKU4Q3MzJg0E5gbl8rOy/VgXyzzdTl1YdP7qIGSvGTh3Yi2/D97drtYTGYLAhzF2
         ALZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3YFvZqGwWIfqrshf+AKssBvejlsZzC69ItDTX6CzW7s=;
        b=hP3fBGsBYvxFDqeCptpVBgN+QYldUv51HzuCvVCS+AUmX+SqQbKyE8FgjIqrbx6tme
         TrvXQcy/3kSkOMNPwWqOHTZG9wzKNVXhIlOisdW/jYECI/WOaVI09ZaNqCmxdk02zBNl
         sYMzOvCR4Q9jk/1lvSUcF2/fTKSkRT4l25WikjeFAkPqhYqvBtmosv3JioAUxSq2I+2Y
         LDlQboXwxt+977uiCLI2AbIRrN/fN1G5bhLhj43uJNr7QrTyYwDAmz+T36XU3ZYPnxg7
         1aWFW7rcVdyDXrdHyWHeeMG+kNGppzupNxDOC4QcvIbnWDMjFZfhfJI/l2rW02gdhcAH
         04kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3YFvZqGwWIfqrshf+AKssBvejlsZzC69ItDTX6CzW7s=;
        b=McduzW3OVWU1lu3cR/zefJ74dgRqlSi5FT+iYHdtX9J5vM817Qhf0/2nUeuW2QS+Nb
         /Sa8hzmNe84JToeySsOXRt36f1on0tNXHNo03DEdeGPSbwy98JukP0OjuHDNRRsudt4k
         AvLFJTSIIzuCn2RBIAc7heQhTj/XE+mr+78q7CdIgP+EeSbJ/cV9kDQI9Z2fdU5WhiRq
         zrn8BxvITLyRwyMCaQYdL2nTIrJrBqlh6Lcv/bxbeFmpIfc6yBIADVgvbbcDd4rKpTk5
         FO0xxUQKS49bT/8PfBhFZG1SoVPpmiHgzgCO38pc2UWsz9pUjQarZsNvH3thTruWcvZs
         l9/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XaXgpOi9xqQ3hcAQj/f02YUdj7ZVHn45qGQe10ttSy11EobjC
	BoOwodNlXc1X2WN7FdiY7wA=
X-Google-Smtp-Source: ABdhPJxG8bpXmwN/Gr22t+IStLqoy77NTH+K3UMWT9KfeLwNKq+chO4gVMBDakBX9XHRv4TWaTI+zQ==
X-Received: by 2002:a9d:468d:: with SMTP id z13mr2610025ote.31.1631754183789;
        Wed, 15 Sep 2021 18:03:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7b4d:: with SMTP id f13ls1206098oto.11.gmail; Wed, 15
 Sep 2021 18:03:03 -0700 (PDT)
X-Received: by 2002:a9d:5548:: with SMTP id h8mr2547519oti.370.1631754183409;
        Wed, 15 Sep 2021 18:03:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631754183; cv=none;
        d=google.com; s=arc-20160816;
        b=X6MQnBVU75xsa8+vTxTB9iO6uTHFC2ZTVuQd02ilQonCHWkHhqOxw5AkqmWfn8sM+P
         hjgUbum9jTq8IAgz1n1zqqAjCiyYKMa6yODksZjKt0L2bOPCtP5r3ekNupigNumsTf+/
         Ba4YZA+5uyCDau3Su+R0gOSv9BGyKvf9sB83thzPY/y9hDvml9mtM9dan2+98oC/eNh/
         vgbcklrFZDV0yQtvQuyIUGMj19kmUzOjX/sPXKTPcZ+6t6N0LiG5un0zElDO4hwjkdS8
         WX8/1RUzRGMuuo05OMvd7iqNbQJ0/DwJlKiv7XB4AvUG0c8kLjc9/8rF3QgVioSpjOur
         KLjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PiN3wS5uwcKdZgKoV6iO6EUvp7tAUNAP2m2oJ5AcUK4=;
        b=uGEF8JdWNJIwoDOG5ZISTztNK0ly6BEBIJX6PS+zFWn3/Yi77lVUXM/X4yPxetbbPY
         vr/mC4L83o5qpHqOUqSdOnof6+ehXalkBSig+nUTsbwhcGWIactlCaks9R7hvtrSQCrn
         3+X1Gr/gcoVoRK3539Dsd5CmZlGsycrrvO7TRZJD4ilEk7MFQJNvqSOAi27gtWl+KJ/r
         znAeMzpZL7Ne3GOeBUhOkzfsHda6yR1kpzwtCT1cqplrejO8u7yp7JfRX48mSyDDe9h3
         UEh+sCzikNibv85ehTVAuSamKKzTm7vsmyKxOSK4Dz/XFoLNKK6ZYu05fkm2MWg4paCE
         ikBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id v21si361977oto.0.2021.09.15.18.03.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 18:03:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4H8zGM50MFz8yZ6;
	Thu, 16 Sep 2021 08:58:03 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Thu, 16 Sep 2021 09:02:29 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Thu, 16 Sep 2021 09:02:28 +0800
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
To: Marco Elver <elver@google.com>, <akpm@linux-foundation.org>
CC: <glider@google.com>, <dvyukov@google.com>, <jannh@google.com>,
	<mark.rutland@arm.com>, <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <hdanton@sina.com>
References: <20210421105132.3965998-1-elver@google.com>
 <20210421105132.3965998-3-elver@google.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com>
Date: Thu, 16 Sep 2021 09:02:27 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210421105132.3965998-3-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
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


On 2021/4/21 18:51, Marco Elver wrote:
> The allocation wait timeout was initially added because of warnings due
> to CONFIG_DETECT_HUNG_TASK=y [1]. While the 1 sec timeout is sufficient
> to resolve the warnings (given the hung task timeout must be 1 sec or
> larger) it may cause unnecessary wake-ups if the system is idle.
> [1] https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com
>
> Fix it by computing the timeout duration in terms of the current
> sysctl_hung_task_timeout_secs value.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>   mm/kfence/core.c | 12 +++++++++++-
>   1 file changed, 11 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 235d726f88bc..9742649f3f88 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -20,6 +20,7 @@
>   #include <linux/moduleparam.h>
>   #include <linux/random.h>
>   #include <linux/rcupdate.h>
> +#include <linux/sched/sysctl.h>
>   #include <linux/seq_file.h>
>   #include <linux/slab.h>
>   #include <linux/spinlock.h>
> @@ -621,7 +622,16 @@ static void toggle_allocation_gate(struct work_struct *work)
>   	/* Enable static key, and await allocation to happen. */
>   	static_branch_enable(&kfence_allocation_key);
>   
> -	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
> +	if (sysctl_hung_task_timeout_secs) {
> +		/*
> +		 * During low activity with no allocations we might wait a
> +		 * while; let's avoid the hung task warning.
> +		 */
> +		wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
> +				   sysctl_hung_task_timeout_secs * HZ / 2);
> +	} else {
> +		wait_event(allocation_wait, atomic_read(&kfence_allocation_gate));
> +	}
>   
>   	/* Disable static key and reset timer. */
>   	static_branch_disable(&kfence_allocation_key);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6c0d5f40-5067-3a59-65fa-6977b6f70219%40huawei.com.
