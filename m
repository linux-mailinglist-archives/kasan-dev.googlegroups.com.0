Return-Path: <kasan-dev+bncBCRKFI7J2AJRBH6VVSKAMGQERLQ6PDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D8B530994
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 08:33:04 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-f26c00595fsf1497439fac.6
        for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 23:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653287583; cv=pass;
        d=google.com; s=arc-20160816;
        b=ER8O5f3iRczihlLhj57tBjXcQ8kIte80u30aAtCRpeUOk9OHSktOrtfoBnyjQfvsnZ
         PCtAfM073k74YFGY5P2FmPduVVDk1VQDvj8RJOmYKXaotydpYuElknukqGqTqsEZzIy8
         GlABZhjUp0eSjd4ZeP7AUTC1eqRZ2vUteEIH+mN04fqxXDZEDa3LJ1EcClw9elqeibzV
         +71bfGowK3p2DxYndlmGlJxRE0BznwJvN3BtynXTQpla/cYryEp3v0k2Oyxd6Kfo8Kix
         cYD3uHiJt6b9cCzhlm3vmQ/BPhdNNVBcwffldysLIilfj2utJUvKhwoz9gx+ws1p6ddk
         gZUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=oF7JrTqj5EcMpRdbZSB2dA8xVByt5m+qJwQ3yQX+aN4=;
        b=k63VrI3R7BvNJuxX14a/5ED7TKV1Xqd2BHmkXzlHOZRYArItV1x6R0P062Snch1/p3
         EBSWy8ZKzejT596sLcfLhoKtw6c9yZ2Jqfng0uAfzX8pZ85aUSlt5jGRnGYilMFa++9n
         USrvu8u/cPZWyOoxsslHJtHIQLmx6dO8UN2cIQ2vIu4EDK9Zrh79FqNFRLCzXPahmASa
         1dZI5u3mQzMgpRJjSw1V/KE22j67WWt6JKpAHfoeEhFyRr9f/HFtf8ID+TkQo2NmabXB
         TCK8nGOoGMk3UEtOJBXeFXA7U+4u5cGn6m+drVsP34dAhdACtjkMB315sCRydukYTwUT
         uubg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=oF7JrTqj5EcMpRdbZSB2dA8xVByt5m+qJwQ3yQX+aN4=;
        b=qeTH5lKOoYHbhCR8J8SS7ksSlA5X5XLy9JMRMRZ4rbdBApj9ZhdlzEYJsb7JYtx2Cz
         aCjsyiwyUhV6ZJ65AYIyCfGA0K4PjcDT5ms17CuK+FttVtMIv4psb6UPPy8C/maSWBKw
         Euy6wndO0q39kv2gJsIvi6zId/OPF/ad8qzuEponTfnMTprPcCc0f2PqKDZdCgqaG1T8
         9BrS/X98liLutwzcagyeoFg3uGyMFw7Nyp6sxJgQUZKYmrDQJdA9KTzACN5Ie2gMaFN+
         dce8ABbEsT6h+V8iL0QjfQHSG+tZ3UODM/78u5Xv62y0MBlq/Wx00eLoi1Q5IE4aDAus
         O4xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oF7JrTqj5EcMpRdbZSB2dA8xVByt5m+qJwQ3yQX+aN4=;
        b=bl0h62XhdS8SVqX0fDynikdAmDo9JPvZ3E+keFFAKEExUso6HGRMmZr9PRH4mKqI4g
         ztBcaz5tT5YMoB6bFsc5Hj80D/w062hkZnptHmL0fLtz+iYKtAtulDu0eA68DtfnMVrk
         qRYBmk/SM1LnzsaYXwcUGvjsMm63E35qQp4eZzQrLwZKl203giWDgHS7Hzjq2V24MjSz
         ymWBy2txiB4E5QpOjpsd0SGIMF0dczEKMUW8eDdPj60WyAyXIeKV6cs2ITko7MDeQaIG
         1Qfu+u1SE/CgWxy7Sw6rPUA6HkRedn1gL6lurzLCJRmrS906Emf8ioEqLWc5vm6yP1AE
         6RFg==
X-Gm-Message-State: AOAM533HmrUY+eWu3jM7nxOPxjZbs9dDniAieO8xF0mRBlRoqESX/Z7Z
	pBqCf20mjexcl0oKfjuiFPk=
X-Google-Smtp-Source: ABdhPJwGQwKsAxNUOr9gJxWe3w4Ye7k8ybG0zE8sevTdAwwLdNtSDCjetvevgpCdEEdnIIZIJ+Apiw==
X-Received: by 2002:a05:6870:311d:b0:de:9b6c:362b with SMTP id v29-20020a056870311d00b000de9b6c362bmr11103456oaa.200.1653287583321;
        Sun, 22 May 2022 23:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9a03:b0:e2:adb7:ef12 with SMTP id
 fo3-20020a0568709a0300b000e2adb7ef12ls4731958oab.10.gmail; Sun, 22 May 2022
 23:33:03 -0700 (PDT)
X-Received: by 2002:a05:6870:3306:b0:f1:8b45:bb31 with SMTP id x6-20020a056870330600b000f18b45bb31mr10927076oae.210.1653287582994;
        Sun, 22 May 2022 23:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653287582; cv=none;
        d=google.com; s=arc-20160816;
        b=TS3tqGt4oVs1lxHzf215x0F2UsjwqUCdvDS4hpwOyOo6uSvo1zhoCM2uy1lDESHUhU
         /cnSAGPhPNTwfbu8zcnEvp+D/82SRYHovB23GG1vQ8ZwYr0lMYC5lSmiCZGWvPwpsndo
         5HyWWTuzvFe+gsY9DSUe1ju9nzkYnVantmND39XsR8Tqjeq7F6xoSGUD9prXrRf8dcyq
         yqPt+7SdBzmho1K4nfuUtLQKySeBaaQVofkFY+x2woJgBzvwl+cIIOzcF+vKCaPmAqpu
         ihaf+/T+7qAqWSgSSAEHhy2k+eoC189kFvICKIfAt0QEF6SuRQKutyTvd9xC4SXlUJ9n
         3Njw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=UySkrngpyxlqFXuXvAuuyWJoHZM4/VJBqsuofm9PV2o=;
        b=ssyuNgT5kw5XtcIzEuWMd8WXUvJ0sQMYdSmDwFwhVuknbQED7tswNjGUcyufSsh/gs
         Bbvnc3u6vgmvhhBPIKDsnoJJGR2t6ucMtNbwrC9kgjOG7gYUjSEfRLDcYcZYUrMOUQIR
         eEwZYjMvK8xNRqAEjlvR16upFFRoD5WgF71Fsq2koEot9+ioeCgO0TuPZY1aVFuLtXyo
         /Otum6tkfioVXVJqb6CEtAtBklqMKt9RmXNVl8LtT3Ix2fnQrn+5sT3N8cuOlG4IauxO
         m2gjwNwjy1hrZRfRuAHuCIbms8/B2wSypoWVJBrjk/DvCRUxpCiqGCJ1R679W1vOCF0l
         U5Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id fq38-20020a0568710b2600b000e217d47668si1360980oab.5.2022.05.22.23.33.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 May 2022 23:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500023.china.huawei.com (unknown [172.30.72.54])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4L66p848wkzDqL6;
	Mon, 23 May 2022 14:28:00 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500023.china.huawei.com (7.185.36.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 23 May 2022 14:33:00 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 23 May 2022 14:33:00 +0800
Message-ID: <20d731fd-f7f9-4c93-d851-01972dc04cb9@huawei.com>
Date: Mon, 23 May 2022 14:32:59 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.5.1
Subject: Re: [PATCH] mm: kfence: Use PAGE_ALIGNED helper
Content-Language: en-US
To: Muchun Song <songmuchun@bytedance.com>
CC: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>
References: <20220520021833.121405-1-wangkefeng.wang@huawei.com>
 <Yods867HAh5NH2kN@FVFYT0MHHV2J.usts.net>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <Yods867HAh5NH2kN@FVFYT0MHHV2J.usts.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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


On 2022/5/20 18:26, Muchun Song wrote:
> On Fri, May 20, 2022 at 10:18:33AM +0800, Kefeng Wang wrote:
>> Use PAGE_ALIGNED macro instead of IS_ALIGNED and passing PAGE_SIZE.
>>
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> Acked-by: Muchun Song <songmuchun@bytedance.com>
Thanks,
>
> BTW, there is a similar case in page_fixed_fake_head(), woule you like to
> improve that as well?

IS_ALIGNED is defined in include/linux/align.h, but PAGE_ALIGNED is in include/linux/mm.h,
so better to keep unchanged in include/linux/page-flags.h.

>
> Thanks.
>
> .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20d731fd-f7f9-4c93-d851-01972dc04cb9%40huawei.com.
