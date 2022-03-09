Return-Path: <kasan-dev+bncBAABBG4XUGIQMGQEJL2Q4EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 166A04D290E
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 07:39:25 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id e14-20020a17090a684e00b001bf09ac2385sf1021520pjm.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 22:39:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646807963; cv=pass;
        d=google.com; s=arc-20160816;
        b=JHmM5Pn9CbqCWllqSZ50zl4EO3SnkFsg5+qgoennm4hkR397Wq1Ru6eEJdrp/UJS0n
         3snDkwDbuYIhyM4hxiQgDzhld54QbirVdQbTS8UetCa9funKhwmZj1NZ+SMHduUssjCh
         ClM6RiTi5Gs0t2nHJo8TITaa1VwOW17MbbFF4HKAM3Xdm9hBbajrYGTOC7WUQTEMTnrc
         Xc32Y7o/EbC4DYD2aZRpq+2Xf1LY45ebIR61J8lfyiEA6mxN/sEEqlWYuc9dEFXNAMdq
         TTcuDK16StTrQVgYGDTvKRUl1buW1Q+9fXz+rJMXsHJFGGaK2KCgpOwH1KYWNCplEWLu
         fxSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=S+NBhzzUyhPZdwYXGFBmK+pVA12wLAG5GNYUQg2mUpU=;
        b=LCXBBXjQ6rwnMUJlTqi82DYVCQI2Jrk30qbmg4t2epbblkX9+ZdUCS6nueBuctfgY6
         lhj0KQJm3zqinn7uaK1So7Ke0Zvty4uCuQZoNRGF6Sx75OzsjJs8RuNaZ1EH89A3sVtF
         K+uLtu2Kmg9YOtkbcOmhOt/YXj+b6fWgc/xxsTgz1aKJ/OwiCbK4NzdGylpV89Iedmp3
         YTlEExxGOslBb9awRRmzTobyAgY4ra42CdUiybK9+ykUd37bH2WqjucSoDHpzLreskpe
         UCEfrQV5eahM/ahYrmcNBEcJhZuMuSwbblUnasZXzKpw69e/hcYE8aG0i0iLacmcJ6Xe
         X1tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=S+NBhzzUyhPZdwYXGFBmK+pVA12wLAG5GNYUQg2mUpU=;
        b=bpaA9TKxwYozjz3xcrggwztTpgN1SKIhVx/JsiDHY6AwKtoYqUgoRr6qo1zzlfpDQM
         eieABBM64qj/Frgxpv8QGBljxZz+DydmRi+ezJ4rKO43z3Ye+/ZOV8LYZyWfhTi98T7X
         SmLut39t5ozJr6v971h1orscKStrpOsgfUg6Rzv6iCIWqfgivHlwEDd3mgVDkcZGt4+v
         D+DZSwfZCnXo3DB0aqlURwLrqDJXuACyDUt74IbiWZ//pTSb0dMYJoBlPTQq0rM/z9Pr
         9puk3pg0DN4rdpzr9/tDJ2yf7w9oGTDT5e4HxUD1nNouR3zmk+DurDDuh0IxEGZO5Xui
         uaaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S+NBhzzUyhPZdwYXGFBmK+pVA12wLAG5GNYUQg2mUpU=;
        b=AsMtNP5BQKL1J8cyLJX2e8zgypZ0XEBGlenKm+9S5FvlPLTpeKr4Pe5ZxuaRnVDJD5
         FLEufEw/8VBaRUEUGZA0Wz/xlYzhDvkj+8eVnaGZlTNTGzvkCU5weuMOiJiV65TAWQzJ
         dyFYcgUd+npCbtJs2lYnBLvFTIZKrxyDmgVdpYzIRParzPI+939fpLPKtznKmGSrKGSK
         7FSHFZJpE9X9dytaAtCZYHxlvLOGChRudKnhctX/WM8PwHoVIsvj/KvT9lTZjW2tgZTG
         zN6tRRrn2c0M8aqczQewknEsIW44/a04SbXytUzLMLfV3ZejX5n6/MsPqrarYBDXXhRo
         ufQw==
X-Gm-Message-State: AOAM532tz3HAq4BJtbsNKEu5cXQtL9E+MUrT0V6O9o+RLVufbHVaJzTI
	1wmUVcPs5Y3yhHtQdCw0g/g=
X-Google-Smtp-Source: ABdhPJz9SOALgBa/l0PgH00YvaDGClYQUfGhXZCprFtdo/29mN8OEeQ9DJ6nBKnhGTh4PwAnwPYRAw==
X-Received: by 2002:a17:903:4054:b0:151:be03:2994 with SMTP id n20-20020a170903405400b00151be032994mr21430986pla.77.1646807963650;
        Tue, 08 Mar 2022 22:39:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c202:b0:151:f2a1:8a5c with SMTP id
 2-20020a170902c20200b00151f2a18a5cls931112pll.10.gmail; Tue, 08 Mar 2022
 22:39:23 -0800 (PST)
X-Received: by 2002:a17:902:a9cb:b0:151:f21c:2432 with SMTP id b11-20020a170902a9cb00b00151f21c2432mr12008416plr.158.1646807963117;
        Tue, 08 Mar 2022 22:39:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646807963; cv=none;
        d=google.com; s=arc-20160816;
        b=k4dTpwzytAvaw9FKSoamvTPnrdYHStkItKOSpS7Fk9q3lZq/LVsoVqoOA+0JlFgZ2K
         HM99y9DT1/QdH5iUs2N3p0mu6AX7t6Y/jIm5OzCfgU4Frfr8rhqDpjw8PwSYTOzj5LeT
         KsT2ch33oOWcOAkMLRZrPvQQAPP3Bycu7vom7RiUN7CNa+XdTY8DD8l5sInM30Mx0WfN
         6YsXDsqJHQoUe96gi0hNDaWi/+WUZB6kWj2HRMXBgA+53mj1ZuJ0C/Ul03Xs6KIjnycz
         lTNbaKCdJBUQvudJPXAOCZumxgwJEQMFWqSJMZKioeeVN6YBTLdresozFbzy7p/3esEz
         ECKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=5S+JA/dcgJz85Vyr+LREtD15K40ppg0rvXXvEMcrZJs=;
        b=w4t67YUM8hQAUxpICT4oqWIv3rvZMTRADLR34r71BLTa8HCNS+YjBt1hLw+gMdUgrD
         j0igh/+/J9tGmkjj3IlDIhxbvriCsU0twDas6NWqYZHNXPbEWpAvll95mhs+4Wg9GOiO
         m828sUs4R+YdpgQtUoWSq7L1YdrZJXuGBgZfGK3nCNom3fQ/W5kZsHb1VMiRCE6IaamO
         M03SKCIwdCQ1rvu63z56QALYtEofaAM16GUtPIi027b+4px8PmWm8PRfvxbNOS3Sur77
         sNfuWXlzXpFtm853cMs1TbdpAIhVpejuWMmTez7tB2ivaO5OYRFgMf/K/+AtPcWjnJ7c
         KADQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id n4-20020a17090aab8400b001bf23a472c5si53924pjq.0.2022.03.08.22.39.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 22:39:23 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from kwepemi100017.china.huawei.com (unknown [172.30.72.57])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4KD2VJ33G2z1GCG9;
	Wed,  9 Mar 2022 14:34:32 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100017.china.huawei.com (7.221.188.163) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 14:39:21 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 14:39:20 +0800
Message-ID: <832e7424-280c-d5e7-ae61-832f4f0a03b9@huawei.com>
Date: Wed, 9 Mar 2022 14:39:19 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH 0/3] kunit: fix a UAF bug and do some optimization
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <brendanhiggins@google.com>, <glider@google.com>, <dvyukov@google.com>,
	<akpm@linux-foundation.org>, <linux-kselftest@vger.kernel.org>,
	<kunit-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<wangkefeng.wang@huawei.com>
References: <20220309014705.1265861-1-liupeng256@huawei.com>
 <CANpmjNMfkUSUEihTc2u_v6fOhHiyNOAOs2QROjCMEROMTbaxLQ@mail.gmail.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNMfkUSUEihTc2u_v6fOhHiyNOAOs2QROjCMEROMTbaxLQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "liupeng (DM)" <liupeng256@huawei.com>
Reply-To: "liupeng (DM)" <liupeng256@huawei.com>
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

Good, I will send a revised series latter.

On 2022/3/9 14:12, Marco Elver wrote:
> On Wed, 9 Mar 2022 at 02:29, 'Peng Liu' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>> This series is to fix UAF when running kfence test case test_gfpzero,
>> which is time costly. This UAF bug can be easily triggered by setting
>> CONFIG_KFENCE_DYNAMIC_OBJECTS = 65535. Furthermore, some optimization
>> for kunit tests has been done.
> Yeah, I've observed this problem before, so thanks for fixing.
>
> It's CONFIG_KFENCE_NUM_OBJECTS (not "DYNAMIC") - please fix in all patches.
>
Sorry for this mistake, I will check it in all patches.
>> Peng Liu (3):
>>    kunit: fix UAF when run kfence test case test_gfpzero
>>    kunit: make kunit_test_timeout compatible with comment
>>    kfence: test: try to avoid test_gfpzero trigger rcu_stall
>>
>>   lib/kunit/try-catch.c   | 3 ++-
>>   mm/kfence/kfence_test.c | 3 ++-
>>   2 files changed, 4 insertions(+), 2 deletions(-)
>>
>> --
>> 2.18.0.huawei.25
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-1-liupeng256%40huawei.com.
> .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/832e7424-280c-d5e7-ae61-832f4f0a03b9%40huawei.com.
