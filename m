Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTFNTSEQMGQEOHNC2XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 67A703F818E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Aug 2021 06:21:33 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id x10-20020a05622a000ab02902982df43057sf1033199qtw.9
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 21:21:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629951692; cv=pass;
        d=google.com; s=arc-20160816;
        b=O2m9iUqXxH/rSyVvJ86JsCQeAMNbag/bGUb4i3BNoCuyvq2Uu4lJU7N4kLmGXV/+/m
         11H1lyt3MePgboR4hWPfF/E1t2GSMZ4EyO9kmLD3joQ7oWJnyqxu+GTp5/8xOwEw5xYM
         RB5FRKXLqjBrHVotvFeLEnEWcCEyh52NVEtXgCejYy7IaUg4TbTwk/eG+jH1TlVZ/sh+
         hGyf2EC+eQMDuGNCXCMnHSToAzCOijIywGxRuiKIOl13tJVNoVgQi4iX8BfSFErVdOvi
         T9edYJTVrGhZ+ACWyt8gz5jxS/UvkaQLwcZ+tR2Clo8w9THEQ9GCDeRbdyRrlk96CeQx
         r+BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dCuR0ICca/sU5OGfvYmnr00Es/vD5jEYoZ48Bh6VS8o=;
        b=ao1EKMjQwV+6E+1EfEZJ7LdyqMcPqULJ54Y45oBf4IE1boce+A5q9LTeL48bMP12xi
         0B6NIceLIr5tQ+Mjz+LgzUA7LszKgFLfJBUqovhmw1ZNdNJG/gWh+gefPWGqEP260LBH
         BKNvGphXDhYKZ6CUZKeicjDamjZnRX28/WOAH0SWy9r4acD3DxQNUFqwxEwwSv59VGi/
         73YQS6CrSuyCp9nxTAwsxeP+6kXh7wVqep8co0hJFJQvGah9wImNE0xJoqsbHZecC91c
         gv02QDj7qKFDxbYUS/WqPpbDDhtjFSPreCc3Db2m0pNU1SVykkOeGoeL0BGqdKWNEUib
         +XqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dCuR0ICca/sU5OGfvYmnr00Es/vD5jEYoZ48Bh6VS8o=;
        b=b49McfSdkjV9fONpBXQ4f5RFWIzydIUlojnNvoG1j5ZWX2RA+dGu0Eb6e6kOAwboJN
         BKaD9qdmh7qiWYxEJORvTUlf/Aa43HfXC0LFqQyfDQEmTm4f41z63n+poXgKdsy3+7/G
         RBkx+ZzneQBGea+NKWRLB7NRBkNLLKJy8kLB1aLO/velMhWxmP6cxkWS/962Z2gHt1tf
         P/27VTsdCv1JgcDxjVZbTsPGbsxPnxmLn04cZQ3lEz3VMcbKNbqW65DXJR+8g3Q9miEQ
         l2zSTrcmgBgNy52fB4QCUZTMf4kHDyfx51ClPOdkhd0D6N7jYNx0blLwRYV5SZyBjfDl
         fxUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dCuR0ICca/sU5OGfvYmnr00Es/vD5jEYoZ48Bh6VS8o=;
        b=FqU1tx9gkxR85CZ8rs8JZxl6SxDD5GKBLYm6qWbH8HOr8YFoEQxyoodLalj3Z/4VVK
         oeFSgvzWDieWLcjc9FFhm85hE8pUXoIB2sSkHQoK0O3heMF/3hbpaaYbEfNFQl+g7oTf
         RfU4+9vpXt4Mkuso6NXbrFAoGh+et4xqu7lTphI3a+gRi0W7ifqNl9xaGn2eK6VZjdxl
         g5Zex1JL1XfXn4ao3X2zDlbR6HA7Txh3looVG013CZ6ABSIwLlIBg8+dFgWc+p6Nz0/g
         p9jAaIInA59ClVSZ4tqkGETOiJqjd1HXw2rGbi+LSn+aPF4UO73oQC3KrQQM6gn52Hic
         sb0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323lr+EcT/5K7VkKy2QgWkYFzLpRXlpXJbnij6kW4KkiVlG1vPq
	q52eDqk0KBhpUfWlc6bFJB4=
X-Google-Smtp-Source: ABdhPJwSpit+1AiIxVNF28ty+B5OvmDpcC+BUv4FOEU7lRSUuIldAgfER0xpHFh1fyb/QoxaDKFJeQ==
X-Received: by 2002:a37:4452:: with SMTP id r79mr1933352qka.70.1629951692399;
        Wed, 25 Aug 2021 21:21:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:710:: with SMTP id 16ls2482064qkc.1.gmail; Wed, 25
 Aug 2021 21:21:32 -0700 (PDT)
X-Received: by 2002:a37:b703:: with SMTP id h3mr1960159qkf.240.1629951692030;
        Wed, 25 Aug 2021 21:21:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629951692; cv=none;
        d=google.com; s=arc-20160816;
        b=Ppf0Ep89MFfkkgI8YQySEJ7NBl4KlgXvIHoiLzO7tTEhqzNRC0vXfQmCLeLd3qDE0t
         DHpkHhlxriimrf/J9Wp4lmyYv30ZRg98iXtQEKl0EpumBJlYkjS5G82DcaGBDdCVxLqh
         QA76o7y4mZvUsQg5ecSWQ52ROMZd/2L23URnxLpQPQdYWUfDWPg7WbN3wo7kVEh2j8XW
         YmknngOrLBwC1lVM7zDnDy28SKhxsdn1TAyaAj8u/E9Sbl6OlURRH0BYR38M3Kv/c2w/
         iDPnkaBtEBtIKFjdIN4uTZIrvV7MIOX5iF2wUIF6RWCf/XEq7tTaOnt9dCOzzV7mJwaQ
         duHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=65FfpoP2NFrOsAjCUT4IuBGQGTcqbtWjDy+9arbK+1U=;
        b=04G53SV+D/RWYB8PR0C94s4bBsVpm/cvK6SCjMNKDRQ5InEA7MjP1joa4cX70F9fAp
         fdPORvaULu9OfAESMXPq+/YtUWPvpOVjOeCSds9sKZA7OB1qhGskDHlQaZXHnc0uQ0J3
         bye97ogufQR8JxAnHgEEHJ7L0WdqQNY5FZz5x16L4t8bvgHy/OsDF7vmzmBkGANLibHZ
         /ZrphOq922HKhBzs7hbLzo4Uv5Ei/tZrRIK0kltYjfqmkfUmaBfYlrxX1XJl36oN+uhv
         zsDPfftKCGnr8x6M79cdFnL01iJEy22VZw7TTUmWBmjepJ/EedqWlko/WjR/9xs3B4AZ
         qq1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id d201si118704qkg.4.2021.08.25.21.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 21:21:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4Gw8gz44FJz8v71;
	Thu, 26 Aug 2021 12:17:19 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 26 Aug 2021 12:21:29 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Thu, 26 Aug 2021 12:21:28 +0800
Subject: Re: [PATCH] kfence: test: fail fast if disabled at boot
To: Marco Elver <elver@google.com>, <akpm@linux-foundation.org>
CC: <glider@google.com>, <dvyukov@google.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <kasan-dev@googlegroups.com>
References: <20210825105533.1247922-1-elver@google.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <9f1ba12f-1126-46a1-a1ed-4f47ed5a5ffa@huawei.com>
Date: Thu, 26 Aug 2021 12:21:27 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20210825105533.1247922-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
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


On 2021/8/25 18:55, Marco Elver wrote:
> Fail kfence_test fast if KFENCE was disabled at boot, instead of each
> test case trying several seconds to allocate from KFENCE and failing.
> KUnit will fail all test cases if kunit_suite::init returns an error.
>
> Even if KFENCE was disabled, we still want the test to fail, so that CI
> systems that parse KUnit output will alert on KFENCE being disabled
> (accidentally or otherwise).
>
> Reported-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> Signed-off-by: Marco Elver <elver@google.com>

Finally find this, it's better, and tested, thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9f1ba12f-1126-46a1-a1ed-4f47ed5a5ffa%40huawei.com.
