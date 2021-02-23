Return-Path: <kasan-dev+bncBCX7RK77SEDBBLHG2WAQMGQEISSRU5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A29D32333B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 22:27:09 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id k10sf7985850uag.12
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 13:27:09 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614115628; cv=pass;
        d=google.com; s=arc-20160816;
        b=MLFF0chewFOq4WYekYkS0ooEuxLhQZuGCFlsxU5kIPv6YTSRkn1HHmQ1hJHaH+D6n+
         Up9MmfiqcGFZA492LrrxkCqekQe8VDMnHbXoqVYERgD25eVlUfrSJWK+EDtUVjDEGy+E
         8jqE9oTocAqaME1MeYnejjncMHz47/PK+VAViXBHEiuxSwafdMjgHMYsfpWzJKmRq7Fm
         15sPbCO4r9SO/TzXhFZ1j+uOAUqwjIk/lXvDcVeT8gTjQSv9sc09f75O6/pUkcwViKtj
         iG41Fu52Q7KGkwuMV1d0D17cudkv41hmRQUQ6wbm9FhzquBLlHlUJlzo1uCF8L0yccIF
         6Zbg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=6v5/ft+qQcQh+HdMshHbUJdiKaCmSpi4pnQudWmSrcc=;
        b=e5BhQq7LCV7UKkmlSQUzgCNnJAIDW+TvM8YTjMmqOgI3iuVDRknzlIBCA6tAIfMWim
         NiE1bAoZgM2STomW1EnYbhg7Suu8V1subFWxPXGdJGN/DQYLLPtZ/gHL18Z/uwhvvFAn
         ZcUxJy7I9LCgV4/DAQqe+Z1lR4fApCyeUxW/YoFHFRUlwNFRiq2svxC3/6HKara39lkn
         Bc4oPvstTYK8ywXnWTcLwJUWvTILlCDeeA9eyj9kIEZXb33dX2CxnlCqikSxQxOi6azn
         Xirz2EPhAy/7VDP4pJQ2AFjWHmMAZC0XykzLnQkk8aLqdCFLAoXM44HCE6JLldWDt2o3
         5rXg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=bESHsz9F;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JIrpjWku;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6v5/ft+qQcQh+HdMshHbUJdiKaCmSpi4pnQudWmSrcc=;
        b=dFCvsl5n7CZrLRvugV/M1QsfZ8NrvvNlA/7TE2u40Mdy3Bf89VzE7YpesdVPJNkzw7
         iqeKhB4dOoMJVm/Z5OSWrUsfCQ5d8PVG7NDm3xK5dy0E5gr+xFlyYqAW1ZcbiVGcw3IS
         NLkoi1+ZW1SkX3dglBZj3+evMP2slZSp+sc44AYtVUr/ckV6ogpaolXWUAE9690GP3ma
         UjIuwnbLzdD6QXtx9ntX0KS3J3OP6hK9Iwsn3jwxmRUSU+FIOlieYmERd06MzvQggvRa
         Fd/0wP3Nhq9yT7UNPt6EGV0tmJXTP7fR07KSFLHGR/aGh19cWBRXkQYKu+ZZwB/SXm84
         QO1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6v5/ft+qQcQh+HdMshHbUJdiKaCmSpi4pnQudWmSrcc=;
        b=AiK33338n7TsNcWJ39a+K3FJsxEIDpH9VYGek65OoZ98mm3Vfs7uUDJ+oPmvlLRvC9
         dp54bv3Xg9Gwmk/IEtqqY6fWFVLNWR0uOu2L+eWcqkCFQr8wOKs9S1h9HAa0bu21gZNC
         ClMyu7if8DmGTnHAcuEVG7VfwvGuYNmSPxHDU8LdF5gCU03e7oVeSz0zJ8bgoYCTldOn
         LYyNLXCQGSoyjQbh3IwJM8IY8wnG9q6NEo5K19PC+I1CxAnxl2t52QsYxMURFukKJm3k
         j1fR2ER+kI8P5RzttPwfHWcKJJ4xj45YrzN1yVJypzKmn3BTmLktRucHKEaokBNK1h2A
         WmZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53198KSRMhd5x4SDOh2PeRcvyvaSQha3kUVSsJuo4CmNw9XO/3xk
	kSVVhL5+LThMO6a/ciSmcf4=
X-Google-Smtp-Source: ABdhPJyXTOxyeXgF0XK7zg3y4CuQD6M9tVZfiVwagrOQcKLna1yNOnJNghHcwOMH0SkoFe5KTADszw==
X-Received: by 2002:a67:14c1:: with SMTP id 184mr2783114vsu.41.1614115628331;
        Tue, 23 Feb 2021 13:27:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ebd2:: with SMTP id y18ls1536562vso.11.gmail; Tue, 23
 Feb 2021 13:27:07 -0800 (PST)
X-Received: by 2002:a67:69c7:: with SMTP id e190mr17739904vsc.20.1614115627794;
        Tue, 23 Feb 2021 13:27:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614115627; cv=pass;
        d=google.com; s=arc-20160816;
        b=0BIVVG+pYSFFNOo6SKPAvskEm81c99+sxkP0zJXlSENUW4a6HBPcmqG+t7AYCtOYii
         DHJl7ahO9ihwBZPTjuASW8GZINv2TDleL1KX7weI7COZk0Vjn+KZpxUanjdIwtKKboTb
         UpITtLn8RihW9LzgCEMNiPwwr+hwfe5NJ1jZOcYIFh5WGStt8N2NfaKvF8pv3Citnfau
         bzRIa+QsNaUJwvpQqUQrTvSGEDgiSxTZEEBnX1s2ssbJlLK4BuUmomFftdTaJGojj5lG
         KWefZ4oiTM8+vcJAuTM9lOe/HnfnLHdbcNoER8tBLcNM4wr1MaxJKAl9jFgQVuPmhjYt
         C5wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=3IFCYmp2MdeYaWolaKlzWLWK9zGRCfUrgBd8VdIPItY=;
        b=BSeYzYXzp2bWKgvofHNeNSXMDmSpJXpjtlh08/YEscELgq36jbIgINNXwVAe73bFmK
         q/r79HV1t0w2H8KWKoVBnAh/iKLBKmY/3yBa+jiB6DaljMRiv7rgYnpexR3P+nW7WM5n
         a2wU9+cL9UuEF5gNYm27FIbAZyVIJC6/b111AlffvrVDYkZSywIUakouOGWT/9sapN61
         f9ekqrSBvflPralL/CLUYT2fKJ0Ny6pLHYas/O0li3fH9LnpRGbzG0A/eQoC/ecIpr+f
         1yGE/ivWblFpqKJvLuRI8XdYZwWgWsq/lVLoz/GxFg2nquxcMvJ7Mw3Fz2o05tCeYfZs
         MD3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=bESHsz9F;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JIrpjWku;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id h7si139vkk.1.2021.02.23.13.27.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 13:27:07 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11NLOF2K017441;
	Tue, 23 Feb 2021 21:26:50 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by aserp2120.oracle.com with ESMTP id 36ttcm8w3n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 21:26:49 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11NLOkG2026543;
	Tue, 23 Feb 2021 21:26:48 GMT
Received: from nam04-bn8-obe.outbound.protection.outlook.com (mail-bn8nam08lp2044.outbound.protection.outlook.com [104.47.74.44])
	by userp3030.oracle.com with ESMTP id 36ucby1q2n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 21:26:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=P1y3XX20HQMDTtfQtOGqYT7UcHsRW5AujJ1z+XnwQ1R7VQW3sCv3CQbL9ZTtLi1SuD2gE/IAUwma5lvYeOcMz9bP8/v+ctNSf9jegE3Yx7OWN4C+kVcOFxDQ9STI4YpzMrk8utX5b+c34IUVv/AurghNcvxRpEN5cytFm0GR/iEEsj98x5ue5S840ygBXXGf/3ccCEwvVPwOBeWLmM8BsYLgDoeOy+q561z3eclPDkQZ39+MFJS5CEAbAo7LuAkucZiiav/IQ65p3nE7dwjOOB2TEflc11c5F88eNAyg2NZh3py8eWcyEN/S5ImpXTogqigGQTDE2efTSBx19m7fZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=3IFCYmp2MdeYaWolaKlzWLWK9zGRCfUrgBd8VdIPItY=;
 b=Q/AqwXym7zNdiL4yAdxSzwur+f1DNc7lCQ92t7ZjRHdZg/UTG6D2UOiYiL5aUbuY5l4F6e+up9EOwWQB/KQAqnI6fnvnVX+zLtSNON5R6OwWJI2fkObkEdgI9cRklI40Tmv39suHBN+TkoIijCH276Ef5LRe2/K0cSsleiwg1TGOQcp1ldxY35A/gVWtaNwuzLCTGMU4cf17MLwW1ROyC8ZxfNgFqx/qA1/CiP7d7Qu2mWsKzSb+R8aTHthy+smi7WcXLD5vbzsukBqvm7A0CRw2lTo88Mg6BccV4w0VECHt1kHKLZK5c8FoJiaCBj2ALFdaq0AmDTJkm9pmntj6wg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB3116.namprd10.prod.outlook.com (2603:10b6:5:1ab::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.32; Tue, 23 Feb
 2021 21:26:46 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.033; Tue, 23 Feb 2021
 21:26:45 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Konrad Rzeszutek Wilk
 <konrad@darnok.org>,
        Will Deacon <will.deacon@arm.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Christoph Hellwig
 <hch@infradead.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        LKML <linux-kernel@vger.kernel.org>,
        Dhaval Giani <dhaval.giani@oracle.com>
References: <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
 <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
 <20210223200914.GH1741768@linux.ibm.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <e2cc19f0-5b09-d661-e7a5-ab94d0ec819b@oracle.com>
Date: Tue, 23 Feb 2021 16:26:38 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <20210223200914.GH1741768@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: SJ0PR03CA0052.namprd03.prod.outlook.com
 (2603:10b6:a03:33e::27) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by SJ0PR03CA0052.namprd03.prod.outlook.com (2603:10b6:a03:33e::27) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19 via Frontend Transport; Tue, 23 Feb 2021 21:26:42 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: ecee3d71-6514-4392-4a98-08d8d841b8b4
X-MS-TrafficTypeDiagnostic: DM6PR10MB3116:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB3116A0CC900DBF8F7A5266EFE6809@DM6PR10MB3116.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:8273;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: wo3Knajp9W8+UfG+L+HUpW3OLhcQK/pKc3MDnzDlEksDECUsXjCsLc3CZk8EtevFbgq10v6mPYwlt2yKp1hWff9v48tvzNNz6FeCMHVsol7eUpV/p67u8+5a5SHXv74CszdLEUFW3YTeT81zpGlW/Gwa3YaxJ41wbGAsY9ESFZ/Mx1jLODwAXFhJov8bpfbAL+MGf2Y4dKOnGXkuYgzmqPScw1069DZy+UkJeoMb0wZIV87V0+aIMaQYD7CwnsNNaMMk5dP/agNdPQoRWlM6i97CX8JGrrxxgbjTHkIXQcqyP85oYCen0rYSzN6k9JuZ4xoVvOo4pwhyT9ND+k2s24x3ndeddjB0f3wYNRkq65GC4fT6LxiLUyeKYAV7VUDFm7xYGMdNuiDAp4jgkOut/k2NU4Kfk39WZNu7SK1GdSlIIO0QMOlN/kEQJZLGdtuf/y7I2T2/eU0zWYbXv210aI0R+1jLT6mDgGUAmTKx805Mcxo+vhuN3ptXnAjfDrVIRGDF3HpYePaipnZIRkSUbMAqWpOxayKJM+sDQ0na8PY2o49Qy1Nezqlmqv/1nvKaTgSNFoaQSNwT48CNQjVcFCKlBFpt6wD0I+fcdcimGcAhjYDb83ML+a8bWBsKRwRS
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(136003)(396003)(366004)(376002)(39860400002)(31686004)(16576012)(83380400001)(2906002)(36756003)(44832011)(6486002)(53546011)(478600001)(31696002)(6916009)(316002)(86362001)(107886003)(7416002)(66556008)(8676002)(2616005)(5660300002)(956004)(36916002)(4326008)(8936002)(186003)(6666004)(66476007)(54906003)(16526019)(66946007)(26005)(21314003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?UytJY3FLSmRkQW9jdzlKOEJXbzlibEwwY0ZLTFNnUXJxK1d6TnVHRnZwcytH?=
 =?utf-8?B?Sk5iSVIzN3RaVEt0QUFoaXVqdVRmMWxHbEFZUHBueFMwYkdQRjdlOFdpVWF1?=
 =?utf-8?B?cU1IL0YxWkdhcm01bVA1eGhYMEpicnpOc3lGdSs3SEJoemllV2NpcGFBeTla?=
 =?utf-8?B?OFlBN0RkRlBPUEpOeHU1NHIzM0lYRW8razNPU3R6eW1senkwS3pCbVYxTmc3?=
 =?utf-8?B?anpGQjF5cVFReTlIc2laVTRtd2pKYUVDbVJVNnRQcTQyRm03YXZNV1o1a3Bq?=
 =?utf-8?B?Qk9qbkc2RGUzR0twVWtJZ1dIMjNyejNRVXRpczV6YWJ4MEZZQ1haMDhVcU9a?=
 =?utf-8?B?aHRXZHpiVk9QZ2hYdWR3RTFFMDRESHYxYTFCOEY2Qmw3Y0dhbEpsMzJJdmdn?=
 =?utf-8?B?ZzhJNDhFWlRUdGNzUHF2VGY2bnBiNUNlazUxbFRDTmNQZHJvTmR4cHdXYk5R?=
 =?utf-8?B?S1RGcEFTd0lYQUkxVExUVzRwdlY1ZGVTdXpiTkNCbTBndVNyRGU1dDJXRVl2?=
 =?utf-8?B?NkpqRlBLclFxaUtTdFYrRVpDNDRCNDhtUHZiK0o2dzVYUlY2TE0vVVpTZnpm?=
 =?utf-8?B?Mk5qY21aNkVmbmRXT3pqZFBzaHJENVVNaE1YaUJ1RVBaYUl1VWJEZHJqc0lC?=
 =?utf-8?B?TGE1VktwMXNTK0JGVU00cWszSHpJYzdRbFlOMmM1dCsrUzhxZUlrK0ZTM0hZ?=
 =?utf-8?B?RVF6NnBrQUNHUytlaDExbTgxVnlUM3ozRlRWTmtkZnZzdmRjOUJyU1h4TVRS?=
 =?utf-8?B?MUZNT1IySEt1TnA5RFVTNmRGaksvcWIwTHZIbHlsTHBIaG1zTzdQQkRYTlZO?=
 =?utf-8?B?TWxEZGZaZ3ltYnI3N25LZmlrTHJqdFR1cGorR2FWMWVObW1zRld4N1J1OEs1?=
 =?utf-8?B?Q2lqbGZCOG4vNUp5aG1yaVo0dWNpUFMvWWVtZFgrREhKR3FGY25leTZZci9r?=
 =?utf-8?B?akM2RkFEQysrcXUwR0V1S1hlU2luRUp5REY1eFY0Ujl2S2tBaGtBcWhtNmdi?=
 =?utf-8?B?clJVVDBOdSt4ZnBPYmhrby80cUdXb3E0YlIxb1FWSzZQOUNydktteVhSME93?=
 =?utf-8?B?VXJiNHFVR29lK3JjdlNUNEVwall0YktibFVuU2VlQlkxQ3BjUXYySnhmc2I2?=
 =?utf-8?B?VzNVTkloUXhNMGVSczBVMng2bmcvQlpmWnJqV016eWxBMGorMGpDQ1BzWHJB?=
 =?utf-8?B?bXo4S0NzWUtLQ3pTNk9yUzRwVDhkcDVFNXBPZ3h5dmI5cmswQUpEcGdYN21w?=
 =?utf-8?B?cm8zUUthci95YkJ6enlPSFVuc2pVRSt4WVJvbWlBa201YjNacVhTVUNTVVVN?=
 =?utf-8?B?UnMrWlFHdFhOMXRzWkM0WFI5WU5VSmZKNjNTMUhkSjNtNjdnaUVyTjJ2V3hK?=
 =?utf-8?B?ZFl1RVJjZFRHM0N1TUIvcGo1bllCNEltdUNuNVZOQzBiZm5Hd3dFayt5V0xk?=
 =?utf-8?B?czdEL0VtUk15VFZDYzdKQkduUzcrM0FFcGcxNm52WkZWeUNxYjFPS3QxeUtZ?=
 =?utf-8?B?TjNUMEdjLzBjTFJlWm1LbURmbXJCSU9pQlFmUUpOWFFNV05qbWZFMG1nTHlu?=
 =?utf-8?B?M2RodytpZVdsTCtYZlp6aVE3QnRpaCtKTkF5OWhtbHR0YXBzUVpBc0RsWTRw?=
 =?utf-8?B?alE3NWN2SzZzSGwrQ3hucXVuam9NVnltRk5PWUwvZnZFdm0yOVgrZFVVN3g1?=
 =?utf-8?B?cTRZZVRRWHRiVkdLU3hGekNtWGhNTnhRcC84Vy9YOHAyZ0Nxa1JmaW5WQ29Q?=
 =?utf-8?Q?TQo373LbAQMcv0MP6RypGrPkk1DuWGt+0dm6o7C?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ecee3d71-6514-4392-4a98-08d8d841b8b4
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Feb 2021 21:26:45.8331
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: m+WmcjjZttr967lCiAK1WZrBG0YamZujjLcKBkMXGjKIvcITprfJ/wUWXF20BQ5i8BR0h9p5dIUI4mNsR+6LgRmC+tUgs+e9Nkm6wc1vPE4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB3116
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9904 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 phishscore=0 spamscore=0 suspectscore=0 bulkscore=0 malwarescore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230181
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9904 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 lowpriorityscore=0 spamscore=0 mlxscore=0 bulkscore=0 clxscore=1015
 priorityscore=1501 malwarescore=0 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230181
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=bESHsz9F;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=JIrpjWku;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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



On 2/23/2021 3:09 PM, Mike Rapoport wrote:
> On Tue, Feb 23, 2021 at 01:05:05PM -0500, George Kennedy wrote:
>> On 2/23/2021 10:47 AM, Mike Rapoport wrote:
>>
>> It now crashes here:
>>
>> [=C2=A0=C2=A0=C2=A0 0.051019] ACPI: Early table checksum verification di=
sabled
>> [=C2=A0=C2=A0=C2=A0 0.056721] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 =
BOCHS )
>> [=C2=A0=C2=A0=C2=A0 0.057874] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 =
BOCHS BXPCFACP
>> 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
>> [=C2=A0=C2=A0=C2=A0 0.059590] ACPI: FACP 0x00000000BFBF5000 000074 (v01 =
BOCHS BXPCFACP
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.061306] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 =
BOCHS BXPCDSDT
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.063006] ACPI: FACS 0x00000000BFBFD000 000040
>> [=C2=A0=C2=A0=C2=A0 0.063938] ACPI: APIC 0x00000000BFBF4000 000090 (v01 =
BOCHS BXPCAPIC
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.065638] ACPI: HPET 0x00000000BFBF3000 000038 (v01 =
BOCHS BXPCHPET
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.067335] ACPI: BGRT 0x00000000BE49B000 000038 (v01 =
INTEL EDK2
>> 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
>> [=C2=A0=C2=A0=C2=A0 0.069030] ACPI: iBFT 0x00000000BE453000 000800 (v01 =
BOCHS BXPCFACP
>> 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
>> [=C2=A0=C2=A0=C2=A0 0.070734] XXX acpi_find_ibft_region:
>> [=C2=A0=C2=A0=C2=A0 0.071468] XXX iBFT, status=3D0
>> [=C2=A0=C2=A0=C2=A0 0.072073] XXX about to call acpi_put_table()...
>> ibft_addr=3Dffffffffff240000
>> [=C2=A0=C2=A0=C2=A0 0.073449] XXX acpi_find_ibft_region(EXIT):
>> PANIC: early exception 0x0e IP 10:ffffffff9259f439 error 0 cr2
>> 0xffffffffff240004
> Right, I've missed the dereference of the ibft_addr after
> acpi_find_ibft_region().
>
> With this change to iscsi_ibft_find.c instead of the previous one it shou=
ld
> be better:
>
> diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscsi_=
ibft_find.c
> index 64bb94523281..1be7481d5c69 100644
> --- a/drivers/firmware/iscsi_ibft_find.c
> +++ b/drivers/firmware/iscsi_ibft_find.c
> @@ -80,6 +80,27 @@ static int __init find_ibft_in_mem(void)
>   done:
>   	return len;
>   }
> +
> +static void __init acpi_find_ibft_region(unsigned long *sizep)
> +{
> +	int i;
> +	struct acpi_table_header *table =3D NULL;
> +	acpi_status status;
> +
> +	if (acpi_disabled)
> +		return;
> +
> +	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> +		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
> +		if (ACPI_SUCCESS(status)) {
> +			ibft_addr =3D (struct acpi_table_ibft *)table;
> +			*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> +			acpi_put_table(table);
> +			break;
> +		}
> +	}
> +}
> +
>   /*
>    * Routine used to find the iSCSI Boot Format Table. The logical
>    * kernel address is set in the ibft_addr global variable.
> @@ -91,14 +112,16 @@ unsigned long __init find_ibft_region(unsigned long =
*sizep)
>   	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
>   	 * only use ACPI for this */
>  =20
> -	if (!efi_enabled(EFI_BOOT))
> +	if (!efi_enabled(EFI_BOOT)) {
>   		find_ibft_in_mem();
> -
> -	if (ibft_addr) {
>   		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> -		return (u64)virt_to_phys(ibft_addr);
> +	} else {
> +		acpi_find_ibft_region(sizep);
>   	}
>  =20
> +	if (ibft_addr)
> +		return (u64)virt_to_phys(ibft_addr);
> +
>   	*sizep =3D 0;
>   	return 0;
>   }
Mike,

No luck. Back to the original KASAN ibft_init crash.

I ran with only the above patch from you. Was that what you wanted? Your=20
previous patch had a section defined out by #if 0. Was that supposed to=20
be in there as well?

If you need the console output let me know. Got bounced because it was=20
too large.

[=C2=A0=C2=A0 30.124650] iBFT detected.
[=C2=A0=C2=A0 30.125228]=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[=C2=A0=C2=A0 30.126201] BUG: KASAN: use-after-free in ibft_init+0x134/0xc3=
3
[=C2=A0=C2=A0 30.126201] Read of size 4 at addr ffff8880be453004 by task sw=
apper/0/1
[=C2=A0=C2=A0 30.126201]
[=C2=A0=C2=A0 30.126201] CPU: 2 PID: 1 Comm: swapper/0 Not tainted 5.11.0-f=
9593a0 #9
[=C2=A0=C2=A0 30.126201] Hardware name: QEMU Standard PC (i440FX + PIIX, 19=
96),=20
BIOS 0.0.0 02/06/2015
[=C2=A0=C2=A0 30.126201] Call Trace:
[=C2=A0=C2=A0 30.126201]=C2=A0 dump_stack+0xdb/0x120
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.126201]=C2=A0 print_address_description.constprop.7+0x41/0=
x60
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.126201]=C2=A0 kasan_report.cold.10+0x78/0xd1
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.126201]=C2=A0 __asan_report_load_n_noabort+0xf/0x20
[=C2=A0=C2=A0 30.126201]=C2=A0 ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.126201]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
[=C2=A0=C2=A0 30.126201]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
[=C2=A0=C2=A0 30.126201]=C2=A0 do_one_initcall+0xc4/0x3e0
[=C2=A0=C2=A0 30.126201]=C2=A0 ? perf_trace_initcall_level+0x3e0/0x3e0
[=C2=A0=C2=A0 30.126201]=C2=A0 ? unpoison_range+0x14/0x40
[=C2=A0=C2=A0 30.126201]=C2=A0 ? ____kasan_kmalloc.constprop.5+0x8f/0xc0
[=C2=A0=C2=A0 30.126201]=C2=A0 ? kernel_init_freeable+0x420/0x652
[=C2=A0=C2=A0 30.126201]=C2=A0 ? __kasan_kmalloc+0x9/0x10
[=C2=A0=C2=A0 30.126201]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
[=C2=A0=C2=A0 30.126201]=C2=A0 kernel_init_freeable+0x596/0x652
[=C2=A0=C2=A0 30.126201]=C2=A0 ? console_on_rootfs+0x7d/0x7d
[=C2=A0=C2=A0 30.126201]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
[=C2=A0=C2=A0 30.126201]=C2=A0 ? rest_init+0xf0/0xf0
[=C2=A0=C2=A0 30.126201]=C2=A0 kernel_init+0x16/0x1d0
[=C2=A0=C2=A0 30.126201]=C2=A0 ? rest_init+0xf0/0xf0
[=C2=A0=C2=A0 30.126201]=C2=A0 ret_from_fork+0x22/0x30
[=C2=A0=C2=A0 30.126201]
[=C2=A0=C2=A0 30.126201] The buggy address belongs to the page:
[=C2=A0=C2=A0 30.126201] page:0000000091b8f2b4 refcount:0 mapcount:0=20
mapping:0000000000000000 index:0x1 pfn:0xbe453
[=C2=A0=C2=A0 30.126201] flags: 0xfffffc0000000()
[=C2=A0=C2=A0 30.126201] raw: 000fffffc0000000 ffffea0002fac708 ffffea0002f=
ac748=20
0000000000000000
[=C2=A0=C2=A0 30.126201] raw: 0000000000000001 0000000000000000 00000000fff=
fffff=20
0000000000000000
[=C2=A0=C2=A0 30.126201] page dumped because: kasan: bad access detected
[=C2=A0=C2=A0 30.126201] page_owner tracks the page as freed
[=C2=A0=C2=A0 30.126201] page last allocated via order 0, migratetype Movab=
le,=20
gfp_mask 0x100dca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO), pid 204, ts 27975563827
[=C2=A0=C2=A0 30.126201]=C2=A0 prep_new_page+0xfb/0x140
[=C2=A0=C2=A0 30.126201]=C2=A0 get_page_from_freelist+0x3503/0x5730
[=C2=A0=C2=A0 30.126201]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
[=C2=A0=C2=A0 30.126201]=C2=A0 alloc_pages_vma+0xe2/0x560
[=C2=A0=C2=A0 30.126201]=C2=A0 __handle_mm_fault+0x930/0x26c0
[=C2=A0=C2=A0 30.126201]=C2=A0 handle_mm_fault+0x1f9/0x810
[=C2=A0=C2=A0 30.126201]=C2=A0 do_user_addr_fault+0x6f7/0xca0
[=C2=A0=C2=A0 30.126201]=C2=A0 exc_page_fault+0xaf/0x1a0
[=C2=A0=C2=A0 30.126201]=C2=A0 asm_exc_page_fault+0x1e/0x30
[=C2=A0=C2=A0 30.126201] page last free stack trace:
[=C2=A0=C2=A0 30.126201]=C2=A0 free_pcp_prepare+0x122/0x290
[=C2=A0=C2=A0 30.126201]=C2=A0 free_unref_page_list+0xe6/0x490
[=C2=A0=C2=A0 30.126201]=C2=A0 release_pages+0x2ed/0x1270
[=C2=A0=C2=A0 30.126201]=C2=A0 free_pages_and_swap_cache+0x245/0x2e0
[=C2=A0=C2=A0 30.126201]=C2=A0 tlb_flush_mmu+0x11e/0x680
[=C2=A0=C2=A0 30.126201]=C2=A0 tlb_finish_mmu+0xa6/0x3e0
[=C2=A0=C2=A0 30.126201]=C2=A0 exit_mmap+0x2b3/0x540
[=C2=A0=C2=A0 30.126201]=C2=A0 mmput+0x11d/0x450
[=C2=A0=C2=A0 30.126201]=C2=A0 do_exit+0xaa6/0x2d40
[=C2=A0=C2=A0 30.126201]=C2=A0 do_group_exit+0x128/0x340
[=C2=A0=C2=A0 30.126201]=C2=A0 __x64_sys_exit_group+0x43/0x50
[=C2=A0=C2=A0 30.126201]=C2=A0 do_syscall_64+0x37/0x50
[=C2=A0=C2=A0 30.126201]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9
[=C2=A0=C2=A0 30.126201]
[=C2=A0=C2=A0 30.126201] Memory state around the buggy address:
[=C2=A0=C2=A0 30.126201]=C2=A0 ffff8880be452f00: ff ff ff ff ff ff ff ff ff=
 ff ff ff ff=20
ff ff ff
[=C2=A0=C2=A0 30.126201]=C2=A0 ffff8880be452f80: ff ff ff ff ff ff ff ff ff=
 ff ff ff ff=20
ff ff ff
[=C2=A0=C2=A0 30.126201] >ffff8880be453000: ff ff ff ff ff ff ff ff ff ff f=
f ff ff=20
ff ff ff
[=C2=A0=C2=A0 30.126201]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
[=C2=A0=C2=A0 30.126201]=C2=A0 ffff8880be453080: ff ff ff ff ff ff ff ff ff=
 ff ff ff ff=20
ff ff ff
[=C2=A0=C2=A0 30.126201]=C2=A0 ffff8880be453100: ff ff ff ff ff ff ff ff ff=
 ff ff ff ff=20
ff ff ff
[=C2=A0=C2=A0 30.126201]=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D


This is all I ran with:

# git diff
diff --git a/drivers/firmware/iscsi_ibft_find.c=20
b/drivers/firmware/iscsi_ibft_find.c
index 64bb945..1be7481 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -80,6 +80,27 @@ static int __init find_ibft_in_mem(void)
 =C2=A0done:
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return len;
 =C2=A0}
+
+static void __init acpi_find_ibft_region(unsigned long *sizep)
+{
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int i;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_header *table =3D N=
ULL;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_status status;
+
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return;
+
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRAY_SIZE(ibft_sig=
ns) && !ibft_addr; i++) {
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 if (ACPI_SUCCESS(status)) {
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ibft_addr =3D =
(struct acpi_table_ibft *)table;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *sizep =3D PAG=
E_ALIGN(ibft_addr->header.length);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_put_table=
(table);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 }
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
+}
+
 =C2=A0/*
 =C2=A0 * Routine used to find the iSCSI Boot Format Table. The logical
 =C2=A0 * kernel address is set in the ibft_addr global variable.
@@ -91,14 +112,16 @@ unsigned long __init find_ibft_region(unsigned long=20
*sizep)
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* iBFT 1.03 section 1.4.3.1 ma=
ndates that UEFI machines will
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * only use ACPI for this =
*/

-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!efi_enabled(EFI_BOOT))
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!efi_enabled(EFI_BOOT)) {
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 find_ibft_in_mem();
-
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (ibft_addr) {
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 *sizep =3D PAGE_ALIGN(ibft_addr->header.length);
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return (u64)virt_to_phys(ibft_addr);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } else {
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 acpi_find_ibft_region(sizep);
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }

+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (ibft_addr)
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return (u64)virt_to_phys(ibft_addr);
+
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *sizep =3D 0;
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
 =C2=A0}


Thank you,
George
>> [=C2=A0=C2=A0=C2=A0 0.075711] CPU: 0 PID: 0 Comm: swapper Not tainted 5.=
11.0-34a2105 #8
>> [=C2=A0=C2=A0=C2=A0 0.076983] Hardware name: QEMU Standard PC (i440FX + =
PIIX, 1996), BIOS
>> 0.0.0 02/06/2015
>> [=C2=A0=C2=A0=C2=A0 0.078579] RIP: 0010:find_ibft_region+0x470/0x577

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e2cc19f0-5b09-d661-e7a5-ab94d0ec819b%40oracle.com.
