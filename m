Return-Path: <kasan-dev+bncBCRKFI7J2AJRBHXIVSKAMGQEN2AAPYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 714AB5309DC
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 09:13:35 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-f19e94411bsf7286601fac.13
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 00:13:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653290014; cv=pass;
        d=google.com; s=arc-20160816;
        b=RRW4ROcypT9ZurpevVxjP5ZoQjNSh9vZl38ZP+1lY2A/8twXaa/TC31z/6bEpuyCyV
         0zMKeu32v/ZMFHsDw5XArD6gJl1w4Nltcde4zr2r5DxqBBthqs9eY/bS3n15Gpcii80h
         n0OztENeD/uBPbAtQ+qaJEiWk81RJTjZJuBI8PspAQuSqtHPioMqG5VqhMH3/Ih425op
         iGqKO61q6tPjSjsXKF+SZc0agWmxlQqGE04GJj8trjYjNqNDjSnH+jwOHUrgMuxyjS8C
         ubSokjQQPn68Pxk48tSD3UP6Ke9jZrwPuYRwjc1TRTeKoTC8LIR2ykzBOOMeQDda0jKB
         1VoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=PpoXe39CfoJm4itkNgdknUW4kI4xqGKSZtHrJmjTdyU=;
        b=W7E4gNBddDVlH6cScHVMpmRdjyxlAOlWcO+sNlELWTMJ3iwVHMMJY2kZdrGA0r4P6V
         xP9mwuYD8+chBFNZQlFZlXtp1WvTzAjyDysGj5nJMHcYm7albSCLswv2hZXVHPiQ/X1g
         h5uiG4zad8JcMprfzAtwnV3JAjL6lwK8qlKBSgmekCvbTe/7jR6U7yYsNj12Y19S0BWw
         +trmns2hm7D0PUSdg12ICygtRRF4rPK1AF9ok9lMIjS1Sz/5bdA/Rv60YZYjK+nlxfP6
         6AN5d0ogUDZ/KGAAFTJFB1yZbGJfPUrT4lP86FGIaQc4cnwwRUEy2dxIUo1bjADGYhbO
         dRMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PpoXe39CfoJm4itkNgdknUW4kI4xqGKSZtHrJmjTdyU=;
        b=aGXtEi6G3ShV9WITqFbWDxqpSYWGeCdmiFmC62de2/AVgnk/btSan/uj7/6gYroE1d
         8Kjq2LeSKoeZSGNPKxYhu4qmC5lkmDEwYR38wYA4N0/f1+lGk8ZA3biAWK0G4lMXDVMi
         O5PD6fYESGuBJLWX4JzRMotAKQBZkDOfvH/sDvLMfaD1FWdpyii2lHCeydEgYa6+r43J
         dIJxEXB/rNXSEaNTW81o0rHSTtpGM7ql9YaXRu/Jwdb035zN61fr+rTAREU/DftW4CG7
         fkThG1xK7s5U2ZvRAV8s5Szzt92roFS8a76QdPh7xri6j4UjXCbVi8yD5ToVFrivf24R
         sVfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PpoXe39CfoJm4itkNgdknUW4kI4xqGKSZtHrJmjTdyU=;
        b=lCGNJY6bW3BGaIFp8thznvCcgy0YUaWLqo56tgKSlQ0qWT/t8zB6WT/HiK4px4zcd6
         A8p97/dCPVlNy5iTbbkLxGTELeK0rCs9CSDI+RJEnuEocdrebGrlBrXmicLLgPswgSnJ
         PmsZWUex4tuhrCNLGUjppxpGeAi2Qgp0oJwM9P8lpp5H97c/pAu99nEESEQAKsnXYMQu
         ushavpIIa3RnLbogjxTQJdQJ5XPy2DaQE/3uWo4tHUvWX7kOi1mXB6MAAyvPUblvmxmg
         zIpSJb7zy5RjotwLh4J+27jJvZnI/oUBvsQTj4VNn87J7DIV4ymzdI3porPB9nQCprnJ
         dQwg==
X-Gm-Message-State: AOAM532wyCrIkhlKxs4A7MTYHwA0H7/7p79+RuFLdBDd4WaXGszRnoHa
	KyX3N6nYMF9WTIxR0/M/Cu0=
X-Google-Smtp-Source: ABdhPJyWAYGVC+WobA6xVv2XFWs/oSseJIEJi9UHa8uMBf/z2aV3hnB95Z0PzuPlXznsdEVUqDVDgg==
X-Received: by 2002:a9d:5782:0:b0:60a:f42b:45f8 with SMTP id q2-20020a9d5782000000b0060af42b45f8mr4842233oth.31.1653290014136;
        Mon, 23 May 2022 00:13:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a11c:b0:f1:8768:4744 with SMTP id
 m28-20020a056870a11c00b000f187684744ls4765016oae.9.gmail; Mon, 23 May 2022
 00:13:33 -0700 (PDT)
X-Received: by 2002:a05:6870:b427:b0:f2:2dfd:e895 with SMTP id x39-20020a056870b42700b000f22dfde895mr5007924oap.225.1653290013725;
        Mon, 23 May 2022 00:13:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653290013; cv=none;
        d=google.com; s=arc-20160816;
        b=Hzi5+u7gu2MMoxEVlI8JslCP/ORYHw8kCLJ1Ftvzxsq+Ynkv5S66Hz4Uskfr7SvRco
         NJnPsMaKOa4/D1LdiIGAV6Rg2QaKdFw5KsTFXUIzihscL9ZuWanZ+zBFr8gb/S3a1eZ6
         Lvk53BbmYhD1qAj9JteN+OcfOsSeR0FvAcVgyhJiEgoRH2nAHJdubT0ndiTj5cTDusEv
         yzf+vIIzf62wnQBDQv9bu3BIf8m4ay2ZWmwhHZjR4YKIBil9yUbptn/fFEpUzVsQ91jx
         QYkS6N1G3KkmxifZ9qYJU68me7SwuO6/50edARb3j14B6GkHO9NZOANV4TFBhDsmxt+b
         CHtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=FAbB332r+wqh+IPDkQl5C4hkZV3ZdgS/dimXTen2IGo=;
        b=TolIGPzBJTXG5PivbfVeDV/G41okpOtwWDJC63bFmUwqDcLAqjnBtXQJV3GiACYHmB
         D33NQD0H3jzUJOWZp3F2vBjQetzXjbq8B/nxLvZih1SZ3jOdpc30c9R3ORusXxRobLkt
         gz8oBNnD0zGzGfeKELvgBBQrpZned+Xmf7Z7ehQi2o7MYoBWZ1Icg9az+eulBswUZLwq
         h3tnp4rN/RceANjj17yk6zp5al/qEYKwrTekVJLq62SmrwyZC70w2e07MtVlA6RAPaLL
         AkRh9wfbK/mZLJsgSBtsG26h93Rw/go2Ldui/hBHo4rUk3Ba0g9VqKxlO0+HuAc8jByu
         9gCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id r1-20020a056870e8c100b000e2b65e71efsi1318218oan.4.2022.05.23.00.13.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 May 2022 00:13:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500024.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4L67pd2fl3zDqNS;
	Mon, 23 May 2022 15:13:29 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500024.china.huawei.com (7.185.36.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 23 May 2022 15:13:30 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Mon, 23 May 2022 15:13:30 +0800
Message-ID: <d857524f-1040-ec81-eac0-6e3a31f072c5@huawei.com>
Date: Mon, 23 May 2022 15:13:29 +0800
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
 <20d731fd-f7f9-4c93-d851-01972dc04cb9@huawei.com>
 <YostzHXNIE3qcgQt@FVFYT0MHHV2J.usts.net>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <YostzHXNIE3qcgQt@FVFYT0MHHV2J.usts.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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


On 2022/5/23 14:46, Muchun Song wrote:
> On Mon, May 23, 2022 at 02:32:59PM +0800, Kefeng Wang wrote:
>> On 2022/5/20 18:26, Muchun Song wrote:
>>> On Fri, May 20, 2022 at 10:18:33AM +0800, Kefeng Wang wrote:
>>>> Use PAGE_ALIGNED macro instead of IS_ALIGNED and passing PAGE_SIZE.
>>>>
>>>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>>> Acked-by: Muchun Song <songmuchun@bytedance.com>
>> Thanks,
>>> BTW, there is a similar case in page_fixed_fake_head(), woule you like =
to
>>> improve that as well?
>> IS_ALIGNED is defined in include/linux/align.h, but PAGE_ALIGNED is in i=
nclude/linux/mm.h,
>> so better to keep unchanged in include/linux/page-flags.h.
>>
> Maybe we could move this macro to page-flags.h or align.h so that we coul=
d
> reuse it?

align.h is inappropriate, could be page-flags.h,=C2=A0 but this could affec=
t=20
the include of 'mm.h'=EF=BC=8Cso I think it is unnecessary to move the=20
PAGE_ALIGNED(and there is a PAGE_ALIGN too, no need to move both of them).

> Thanks.
> .

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d857524f-1040-ec81-eac0-6e3a31f072c5%40huawei.com.
