Return-Path: <kasan-dev+bncBAABBBMS262AMGQEUMS4V4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id E6DEB931E53
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jul 2024 03:12:39 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-6716094a865sf2847236a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 18:12:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721092358; cv=pass;
        d=google.com; s=arc-20160816;
        b=L0EHAJght/NFW+wffYXP0eBOQe8sdnwywRxPRSC2HxVWWYK1mccpdEpv2QZsTNdCxe
         Uy6X4nEJiYqaXlw7jaTwh60vJmQpmAyCeFp4wTMj9azyxvSHVTLVHj6v8HlcIhVV9YAq
         ttehmCGoAfpG2/XnWFdSGT9UugX66D7tCSSswwgMNCd+bJNPzZ4aXRwuXh4NVfBmsAw/
         Zty7v3yYid2M2X+JQsVUrboXgkbu3XYjSB4NDDCrIRwIM5aTi1eAK+8gu9+DDINuhTqW
         ppAZz8YFisTshVNwMuWqLjJVQm4zr5IJSE0Vvgv7XYAnkdKhSRs6qY+zquEQsb33tdxG
         sv+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:to:subject:cc
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=pw96MjMP75mS7C3So4g8Dlor4Q7i+e+yRpIh7zm8rl4=;
        fh=OWIhb26JmwUDSFu9lSp9vxB3n5d9QgNW5avQ3OWNGvI=;
        b=WkplhWEdYOR0tQZuh30704y2Dx4F5VFjMy7mYAmoFbz0FZpjfd+MhkXUlMMYHrdkVh
         2yfJod4eDweip9Ck4/T6nixUHg0hyVdk00OeFlhFHCFmV+hxWhCUzlubF5lSng6j5u4I
         u7ERnTTvQUI4rPSlRYe/YliCWwYaIvH6ifNo7yQCFYFO+blZNrPLv21zffRp97qP3nDU
         KT1AsjoNZjkQrJIpICqpgdTTNR0uovVcYMZIk0W0kSU0dnzWSE5BScwM4PHiSNgOlOuV
         ywkfjSxPej2l5cTPeg4Lj0gFAVR8lekzg2ZVHv89bSN3HBsRTHiHblMvH+M/ghPZCD0I
         og5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721092358; x=1721697158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pw96MjMP75mS7C3So4g8Dlor4Q7i+e+yRpIh7zm8rl4=;
        b=xKd/exGcFrmiQhD/PUD8dJbfuwSdhdkTnBm9T64tLPTgcMCMQkFWu0mANFUe4noPEy
         zvs5OAiijaCjsmhD0tI7pIyQXR/6itr+Hafhh46zaFMR1C6WOuvRxn9+TiGarbB2Ci2N
         iES6M+PP6F01YDGUqz4DfE3/63kXbqIndXrrVPsO02Sp3z2FPpQ7J0NW38TVNS5Pqe1/
         rCaGrk6GBKK6AEMaUsSQrGqSZZpVfWKybT8Z8G8jW18gPGjxJar6tguJOM+LUkx0RMrs
         7KWN905BCeSPgVdgvWOF7tfdEywK4RzglqBNNKzcGnuWEKcfnG6Y+bFgju43iQs3Eean
         SOQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721092358; x=1721697158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pw96MjMP75mS7C3So4g8Dlor4Q7i+e+yRpIh7zm8rl4=;
        b=EgTp5WyPNa+fJkDtK1UL+RvhpP5uKCRRrkzKI572WRGF/jbWX9WQIyDjh9iBN6hqpk
         AnynLfDcc+4yL3F46VrFyi/Iirc/Bx6opKciaBMasobZheR5GKCcXGqH9zEPlhLJ7UeN
         sxCYGNvRkJ9Cz8AcnCk2n/4th+cG5tQ626do8FntNYuCY7+SScyYAnK+BYrP5IM83Pt2
         FrZju/tAqrNJdCCrslf1mFYm3beBPde3vwaR5seDLdZoksu9WScls8vwDwMAwbakYUw4
         9vrHePmeTeZayKywY9hWVG95IM1F50cMdzW6e2HeDC2hOfmaHdToYSY16Y6MlC8SeYBJ
         vHkw==
X-Forwarded-Encrypted: i=2; AJvYcCVGzNENcHwyfOVbFX2LgGOJ8nXnOz4Aw3zksJ/KWE2qiTrpblV/tBx2YFwO9B4tQokT9sX5IDhO/2HVtUwzToBBT5OOBAlf4Q==
X-Gm-Message-State: AOJu0YwaqVdM7S9xxDExXb5nxAIhwJDh3YfUBI2qD3trUwsDhTjLncBx
	vwluztmIVXKuxfUJ94qCjgoFN91JpWhESODjifhtPgv/uOD54nre
X-Google-Smtp-Source: AGHT+IHb8Za3DfvK4ppUOXuh9YT5gNjG4864JkYrZnrhDz9E2ShaYehuK7QjFTCy0jEp2cxVJu0NvQ==
X-Received: by 2002:a05:6a21:8cca:b0:1c3:a63a:cef2 with SMTP id adf61e73a8af0-1c3f1242fbemr778566637.28.1721092358000;
        Mon, 15 Jul 2024 18:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2a84:b0:1f7:2780:7276 with SMTP id
 d9443c01a7336-1fbdd415472ls27334035ad.1.-pod-prod-02-us; Mon, 15 Jul 2024
 18:12:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXt1GUf13yiqeKw61KrvkWfBYZ+FfFLgQkdoKiKSVpi7Y0B8tmcrX3HHU3o2DHwKeTU7FZWLiVBlkOyShdG2wT+tr1zGOaXhLW8A==
X-Received: by 2002:a17:902:d486:b0:1fb:da49:6d53 with SMTP id d9443c01a7336-1fc3d946496mr4684895ad.21.1721092356991;
        Mon, 15 Jul 2024 18:12:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721092356; cv=none;
        d=google.com; s=arc-20160816;
        b=iDmmMG8puMNB1VxWkfJBapyM1QvbIb2hRhX64Jx0fqHdP0ArjN+Oa3op3ZkunWp0OU
         eysaDLMUns3gFo4xPAdJ7V1bvYtV1cGRjohY2QIaqPHUZ39CU87ltfKhnFQpeUHILDkA
         Jh0ghXPpcWTgFZbC0cl+jQfKXmolbRmTCuxPyd+GtXKTNzivCmutQS36NHXQiay2tqoF
         C8ovi6jyWozlqoRP4bDdtn4oMp686RBFtXF3SZuMnzcDgviCjC25dgNP8di1aIIZKm0V
         3gY2I1Z6uyTb4PhbztZuzOlC2ZzYxbGeqMf6hzddVoMom9yXPDCfwRj7Z1oyXXIcFn1I
         IY3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id;
        bh=k5Fs9EJaG2ycw6HyMlnqOSxi/81mTzAWC8Qpq3EoJv4=;
        fh=Riq3vsZxRwWWw38YOW7xkSxaNPFQRqKEtsssXrDwomc=;
        b=T/Aufti5tOCC9lQxPf/tuGRXHUv+85VDueqazrivAOVGdeUDH2iBwA2ny7cIKeM/zz
         aPgSiFycIw6HerSa4h2Z7WcGUVUbe1jWEIzyYETProjqNo03rW5vnEhTiyPtHdQosuDz
         3Rmza3aBvByUEHrDDiSa7JHqJPde5NmuaNJkBeV+9DEFDcicEZTg6CMxQt61pqQwYlEu
         SYvqOl8sFmpdiEsVZ5eGZzodsLdS070ZEOuQLGaKxzQaAWZ/HNNi8zGbQ1phsT4gpzwN
         HU2bymtLCeekv+Bj/AA2G7xFlj5vCspzwf9Zcu33Se+oX7k1j9VK87UjnKaBKQDT7AJY
         Kcvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fc0bc18c3csi2280235ad.5.2024.07.15.18.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jul 2024 18:12:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4WNLXK095bzxSmp;
	Tue, 16 Jul 2024 09:07:45 +0800 (CST)
Received: from dggpemd200001.china.huawei.com (unknown [7.185.36.224])
	by mail.maildlp.com (Postfix) with ESMTPS id 1EAA8140795;
	Tue, 16 Jul 2024 09:12:35 +0800 (CST)
Received: from [10.174.178.120] (10.174.178.120) by
 dggpemd200001.china.huawei.com (7.185.36.224) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.34; Tue, 16 Jul 2024 09:12:34 +0800
Message-ID: <50385bd0-f47a-46b3-a196-a93ec8f040f6@huawei.com>
Date: Tue, 16 Jul 2024 09:12:34 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
CC: <mawupeng1@huawei.com>, <akpm@linux-foundation.org>,
	<ryabinin.a.a@gmail.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [Question] race during kasan_populate_vmalloc_pte
To: <glider@google.com>
References: <20240618064022.1990814-1-mawupeng1@huawei.com>
 <e66bb4c1-f1bc-4aeb-a413-fcdbb327e73f@huawei.com>
 <CAG_fn=VTKFDAx2JQAEur5cxkSwNze-SOqQRbqBGwDx96Xq-6nQ@mail.gmail.com>
Content-Language: en-US
From: "'mawupeng' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAG_fn=VTKFDAx2JQAEur5cxkSwNze-SOqQRbqBGwDx96Xq-6nQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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



On 2024/7/16 1:19, Alexander Potapenko wrote:
> On Fri, Jul 12, 2024 at 4:08=E2=80=AFAM mawupeng <mawupeng1@huawei.com> w=
rote:
>>
>> Hi maintainers,
>>
>> kingly ping.
>>
>> On 2024/6/18 14:40, Wupeng Ma wrote:
>>> Hi maintainers,
>>>
>>> During our testing, we discovered that kasan vmalloc may trigger a fals=
e
>>> vmalloc-out-of-bounds warning due to a race between kasan_populate_vmal=
loc_pte
>>> and kasan_depopulate_vmalloc_pte.
>>>
>>> cpu0                          cpu1                            cpu2
>>>   kasan_populate_vmalloc_pte  kasan_populate_vmalloc_pte      kasan_dep=
opulate_vmalloc_pte
>>>                                                               spin_unlo=
ck(&init_mm.page_table_lock);
>>>   pte_none(ptep_get(ptep))
>>>   // pte is valid here, return here
>>>                                                               pte_clear=
(&init_mm, addr, ptep);
>>>                               pte_none(ptep_get(ptep))
>>>                               // pte is none here try alloc new pages
>>>                                                               spin_lock=
(&init_mm.page_table_lock);
>>> kasan_poison
>>> // memset kasan shadow region to 0
>>>                               page =3D __get_free_page(GFP_KERNEL);
>>>                               __memset((void *)page, KASAN_VMALLOC_INVA=
LID, PAGE_SIZE);
>>>                               pte =3D pfn_pte(PFN_DOWN(__pa(page)), PAG=
E_KERNEL);
>>>                               spin_lock(&init_mm.page_table_lock);
>>>                               set_pte_at(&init_mm, addr, ptep, pte);
>>>                               spin_unlock(&init_mm.page_table_lock);
>>>
>>>
>>> Since kasan shadow memory in cpu0 is set to 0xf0 which means it is not
>>> initialized after the race in cpu1. Consequently, a false vmalloc-out-o=
f-bounds
>>> warning is triggered when a user attempts to access this memory region.
>>>
>>> The root cause of this problem is the pte valid check at the start of
>>> kasan_populate_vmalloc_pte should be removed since it is not protected =
by
>>> page_table_lock. However, this may result in severe performance degrada=
tion
>>> since pages will be frequently allocated and freed.
>>>
>>> Is there have any thoughts on how to solve this issue?
>>>
>>> Thank you.
>=20
> I am going to take a closer look at this issue. Any chance you have a
> reproducer for it?

So far not good. I am trying to get a reproducer, but there is little progr=
ess in it.

>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/50385bd0-f47a-46b3-a196-a93ec8f040f6%40huawei.com.
