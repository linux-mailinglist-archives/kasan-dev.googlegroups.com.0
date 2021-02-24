Return-Path: <kasan-dev+bncBCX7RK77SEDBBYGC3GAQMGQESE3FGAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3768D323F21
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 15:23:29 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id o73sf1271175ooo.10
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 06:23:29 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614176608; cv=pass;
        d=google.com; s=arc-20160816;
        b=gsgY9eg7EyQH8ZLppagTWWHVOERpeHj3PTGYnxbLRd2ReecLjGjleJAdmj2Ks/Qr6n
         hseSiMlVmmfQ71YScP6WVhQKM2YdyGeiF9b+2qj/r3TLzsNwOoQoK/GHE2fGHeh7y9Z0
         FgE9Z0MaJet5glZEEscm1tEgyqPT4fSFLIgtmyOGl34WBD9aZi9jKZkRHIbv0Le7orTQ
         bS+/EoIN6eqUthtdENRDW0dzKRZES2al7LEtFVfhVcg6WluaS0Qzq1S/GFJYT26LxuwQ
         UBxV5QI0pfXL7IhuZKmz9eM76OjwNY+tTiUFObOpuqu7JjOQT7UVprW0V5R2ofyRtcT2
         MTJg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=JkJcyPfdOMXvXkK5szqcBed5Br/066uBMBhRSnLDpfY=;
        b=0DDhS36Us3Ukq5D1/HMLQ6bxByt0r/E0G35ja5TjAgiFAybMj5to0EJmHoHjMMF2Xj
         OCLa4ZiEDSUOpkRcmaA1KytIBXL8MeyzvOyyl1Le1WGsUS2oId/XKE0YuGHv7bCu2lED
         JysV2SK/7Ionb2u3K9+OWLyWALN8BJHicP4MHjDalxqfaynvwCh3+TW4hgramF4GTbtr
         gGFC2ncR0WiQ24xwRluTLsExPFa5YwsG0MdtVMnCJV4UCX27+Lh5FTO2G0Lgg92x7++W
         CPI9VdKf09SOcIt8nq5KDkQPVEJcYcCtcF4PCm/a4+VgxoUc7Ask/s2ubIMuEiWwWnjC
         5BCA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=XLk1lBMX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=oT2k9obo;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JkJcyPfdOMXvXkK5szqcBed5Br/066uBMBhRSnLDpfY=;
        b=o3JLEGQZO8OZwz21M9WZ7O5ojsoswvIHu4yBxyifMj06an8nSXmgYhJ9rkTSzXdUO7
         khV5XZli9OLy99JNMTlo+hWYsL9yLlzaTl+MN/JqfYobcWlvmQXjducFzG3IImaaTQjr
         0JicDOR4e5F2LxrTCAKg0aGoT5qgpFYaAxcKE+PALruX66fftqeTEchsuSl8wh7b7606
         AkAGm4UTI5LEIbyKXC1x+LSiYeSME1tv6SgiSOXtrN6DTakVO1fGc2DsIrwv3eAm2+5C
         9ceOz5t1qZCqVcGFYtHLXtcaaelkqvGMxloAUJUt3BmuVmOG6+trpvWxxJolUEoMeXTr
         jY4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JkJcyPfdOMXvXkK5szqcBed5Br/066uBMBhRSnLDpfY=;
        b=ksA4r9WBfhZ9U5qJb3VOvT+yzFl2pPrK5Qk7f/jcjKLyFnyJpHT5e+hFYBIO4CeeKG
         k7zteGNcggzvy05L8sHCzodDEhQ/1jb7jgfiFz2IbAIM9qIZUFWJMD9UTuLEys+2kTX0
         yLmBqF7LE+KeteVgTdJd/A80QMxRvDJLDRlNMKEUgRyZI7hdQmPshRf5Fn+9mplNXqEm
         GqfJU3rSeHAunnIsRLCFTFkxD0Wwr6NW+/Yhzli+JU/8rB1MuSTg3fUpDSSwPb/Ccbzp
         kPruU9+ZMfuZVPy3l/wsB3PrqzWdIBlZhWQfRo4xTvCQNoS26psU49vyQjQiu0g9b9GP
         tkJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322AieGJJFE6yfIi+8nZEuTk5HpCyaOeZ+zUuj8gAY4dt9AqTX9
	X11lTjLkvKBGKdqEaBEEME8=
X-Google-Smtp-Source: ABdhPJx+TP4NGIhPdWMsZbEVU4oJdITwKSmuIVKzx8ozS2tuCnp62jnU8HrNCBl8lE62+i44a94shw==
X-Received: by 2002:a9d:66c9:: with SMTP id t9mr4125824otm.111.1614176608174;
        Wed, 24 Feb 2021 06:23:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a0e:: with SMTP id g14ls682108otn.3.gmail; Wed, 24 Feb
 2021 06:23:27 -0800 (PST)
X-Received: by 2002:a9d:328:: with SMTP id 37mr2236674otv.250.1614176607787;
        Wed, 24 Feb 2021 06:23:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614176607; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2iHTl2mB7+geeBZlF+GIve9karxbrx+98eUjdHMJ7iCoNwElz7Tx4sHOGbFEmOeki
         oZmPk8hqBqnN5l4In9A334QkcEoLM+KEpMJo9i4fuOgpNRb0gEs0AUFeaoMk8gBgy1Yb
         j5pkSleS65HHJAoWa1DmZuKBFF6NZds/bs7rZ/0KTbg3zuTqqNd1o4wq9krFC8jc7tU/
         c92mFKvAAz9aufHYK7fqGiZ29/NQfl5Y1D1ILfO+nx/J4VawsmMizGQVdoYldJsbXYvl
         eeBAZdCFLJ/G0/C10wzzdi54X4OLS04Jd9B0QcnKfarGln53mxKqfJxFGUuf/Q7U3joe
         HUpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=Drt9g51HOHLYGCY6HhvE95GF1jthc3F2ZzA51HizCSQ=;
        b=UjKAIgQSxKys3/v9B0B6SMnphUP0vO7qvUvjcpeTJX5YFEumpS7zSUoy/Jxk8b3zy9
         VRehQHgDzkNVDGi336hoxuEOptxL7PCmLflFCo2Zi7ySnJt+OhRgzCkYZl2NpN6kZfhr
         qJBheuaF4nqAwcIu0ZKhKcjSttAVcL1WQmxEbw+oWAObuYwJdg8pu3a2mTKxP2j6Ww32
         7KCpU4IT6kLKej8+CyzqL2weIMjORjv8fFrFHLxkJnmn8nx/v/vwz9FhYnUoPVSauPlC
         qj4bJws5lAVtRA8DpfpA9kq5u65mdrWMWCN5QF1MzTmpsQXfSQ+/gQUir7rrztPvVzVz
         BQVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=XLk1lBMX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=oT2k9obo;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2130.oracle.com (aserp2130.oracle.com. [141.146.126.79])
        by gmr-mx.google.com with ESMTPS id x196si106224oix.3.2021.02.24.06.23.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Feb 2021 06:23:27 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.79 as permitted sender) client-ip=141.146.126.79;
Received: from pps.filterd (aserp2130.oracle.com [127.0.0.1])
	by aserp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11OEIhcc040965;
	Wed, 24 Feb 2021 14:23:10 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by aserp2130.oracle.com with ESMTP id 36vr625dpy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 24 Feb 2021 14:23:10 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11OEKWqv036135;
	Wed, 24 Feb 2021 14:23:10 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12lp2048.outbound.protection.outlook.com [104.47.66.48])
	by aserp3030.oracle.com with ESMTP id 36v9m60tf4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 24 Feb 2021 14:23:09 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ZJiZLs8X8lyeLpRoGbgEAyfkWAuTQJSZElhZkdxzzRw5xqZQBDXaTDHwXSQ7O26XHeOYurWiLRsQ9Adv5cTG4O+ITJi746YJUIZ4CK4ewNZAwXy1hnpEs08mm1aFId/ap4IkM8kqWFlAxi1QoGdHSB6qOv4SKFX32VuiQMf07uIpk01t6iaKiGh+XTV1RWZEPZT/SauwFBsftgVdEn/N5855pS2+AepaRGkWP6F1OS8qwQ2ztwSWE928va2rpWRAavUwQ7Ze389TDEcX3hj4TncdMo1MwKqCwZZkmgn6uth31vZsXa4Fft9D4G88GVJUK8GMbDoELJVNbPvnJ1vsfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=Drt9g51HOHLYGCY6HhvE95GF1jthc3F2ZzA51HizCSQ=;
 b=h0UcHO2aM186v8eG0i+ENmDKSsSgLfkyIIfPfrv+PrppSKEZysImQl5bWZiSex5ZpBzNU1dVf0y4fA12+a8UEyZBdt4H/BNVP6dB90IEdncGdKE/tPbKoG7KRNlaUQvwBUwUYNjAG0Ye+RYHXglsDTFMIFW+/MIe6lWItV50GdyGYA+H7VR/9iu0P8Oril35OiWI424AWE9cYLPFX3w5Yo8GiLnZe9+5ElidXIlSQT6iCi7rFnV4mouLDrsPGIQc9ndd2lyCzXalY/qQJcGPsCq1cFBlZ6aCwG0hlH2N/SSfBrfXn0/Gn3dZcbRf56X7VV1oHWPCZ68HXb7AgDMIdQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DS7PR10MB4895.namprd10.prod.outlook.com (2603:10b6:5:3a7::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19; Wed, 24 Feb
 2021 14:23:07 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.033; Wed, 24 Feb 2021
 14:23:07 +0000
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
References: <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
 <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
 <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
Date: Wed, 24 Feb 2021 09:22:59 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.1
In-Reply-To: <20210224103754.GA1854360@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: SA0PR11CA0085.namprd11.prod.outlook.com
 (2603:10b6:806:d2::30) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.222] (108.20.187.119) by SA0PR11CA0085.namprd11.prod.outlook.com (2603:10b6:806:d2::30) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19 via Frontend Transport; Wed, 24 Feb 2021 14:23:05 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: ecdd1f09-e064-4ecf-8143-08d8d8cfb485
X-MS-TrafficTypeDiagnostic: DS7PR10MB4895:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DS7PR10MB48958A7EA804190CA10DE670E69F9@DS7PR10MB4895.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:6430;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: oA7cV6RejmhpRYwMxkEvIS6qZNhsuWRZNVupzE8ArDvkLYO935GnGWcSs0N/LdXj9LIP+gFLw3YY3bW7XJc43/QS/GFUvtos1CixrBE57QascuX9OLFDnMqmlhGCgjKqxWHaJHqtvWhbZMVpGEUIuwUTViZN2SYj9dKBzjmZSZE1i3ICICgFDuOmD31nikdXDkVee9RgJFouQYKud+hcsf0gppBxXSnr+jJYrRyRNi+synicCYYaHHy1glCz6cspm2I8S+0ubuLjDXj2dYoEIdxBGmhdvEJ6QFarAvz+5kPBG5RY4eK6mp1aad78i3NeokHeZNOf71e8b8nNCBOnmQmMzr0IvPNjbRrufyoJPcWdUxe4vnhEUwsc0mu6veO4i2WOAJz40c0llaZOMi4ct58CZ/6T+lSpHwN4BPJn5QdOt8h6EM5wIfdkkgnZPtQddugaYHkBaDpvsMvzDjq5Cqh43Yf41AK2t85eTiJlJnFNjA7rgyo7EqBuE10TGOnYXeJ4mRZvM3j55n3dn8RrrY9ZDDZOwYB9i2kPJt+M53dhi7B0Flw0UaWWror7xHBVBO2R7LryhXnYJ2cUj1MA2mkhA0HvtWnFfItpWKbpq3Q=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(376002)(39860400002)(346002)(366004)(136003)(396003)(83380400001)(478600001)(54906003)(6916009)(36916002)(31686004)(5660300002)(44832011)(6666004)(956004)(2616005)(36756003)(2906002)(316002)(16576012)(31696002)(26005)(8676002)(186003)(107886003)(86362001)(6486002)(66476007)(66556008)(66946007)(16526019)(53546011)(7416002)(4326008)(8936002)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?KzdWTVZ4c3lpdjhGUUoyNkxzeERCNW1keHArMEMxUVNqYVl3REt5KzEyRVZi?=
 =?utf-8?B?aUg5Y2JDTmVibVUzVXgwdnpjTWZtUndMUWNiNndIc1l1ZDF5MzRsNGRnVEF6?=
 =?utf-8?B?SzlmNXc0MlNOWDNoUm9kZXRtWUs5eTNUYlA2Y3NmU3RLYUZDWjAyWEtqM0Ey?=
 =?utf-8?B?dUpJMmpWQmFHQTJ1L0Q0QzByM1VlYjNQWXJ1RVdoTUpQd1pqQ25aS2xma1kr?=
 =?utf-8?B?dFMyTzJlV0tDTWpNaWVTcDhZL3pLYmV5Nk51ZEttUmVOeGRSMWJGcmRwazR3?=
 =?utf-8?B?emNXVjFRaXZwaUp6RUgxeithbjM2U3dEbllGQVY1THl5UWdGaTk3SzBYcXAy?=
 =?utf-8?B?bkxwRjZlSHVkeUNBTTI1NWZQWFp4M1N3UXB0TkRCeUFXd2ViNTQ3SjBHNGhp?=
 =?utf-8?B?MU5Gdmg4bUExc3UyeU45RGhTdTM2RlRPQ1ZSZGl5VVNkSFgwemcxWEsrN3ZB?=
 =?utf-8?B?N2ZXUTA0Z04wcis1VUh1ZkRYYks5N0kvV0FHeittQUNDbzdPVHNpUURTTUdY?=
 =?utf-8?B?WHhKZWtPZ0VZQitEeCswQ084K3gvM0FzaEdnOFpwVC9WKzZabUc2cWw5cW9Z?=
 =?utf-8?B?TzB6TWZjV3VCVmdRT1g1VXJoeE5IZ1JWN25OYmpTdmZUdkkxbDRZZTRXdWZP?=
 =?utf-8?B?bE9vV2dnK0VaWmtaZjJKWGJqQjV1S0w2YlBQT2VGcUxrT0lMOU1MUjFzNm1t?=
 =?utf-8?B?bU1EdFpkRjc0WGNLTEtzdnp3clZpVTAwdW1PQStXSnZWVEx3aU52OENFbXdV?=
 =?utf-8?B?NUxBeHJYZndERkZwRVo0R0ZUbzFwbDF4eThhTnVITDFiUXd1SHkyNnp4aHhh?=
 =?utf-8?B?cU5XRXN4Vi80VWtuQ1lENjlkcEREU0kzRlcrUjZzc1VQajNsVXdxZTNmNmZs?=
 =?utf-8?B?c2pLODg2bTdyWVRVcDFBcFVkd1ZUc1R1Tms5b3p3TGNVbzUraWdSNHVWSnFz?=
 =?utf-8?B?V2dXRWJ4bWk0YWI4VENGcDJtK2hnWHFhSjZNemFSSWZFNXNDYlNzQ21NdmFT?=
 =?utf-8?B?N0ZyODdQS25SaDhFT3ZhTGtpMi9YcnVCaURMdVJ1SnYzWlpBVyszeDI0bjRt?=
 =?utf-8?B?M2dXOTRHVEQ3UzdJYTBDOFpTcldzUFRZUE9mcDNJbC9NbnVsMVJINTdlMEx5?=
 =?utf-8?B?R1pObkx2NkYvYXZwMUdxR050L2owbW1kWVRCZ0oxSWQvSUhranlHTmQrQXRU?=
 =?utf-8?B?WVZHUE8xc2N5VEhIMFk4MkxsR1hSWmV2RDAvK3A1cUxBbzNoZzBCcjFnTUQr?=
 =?utf-8?B?WUNlZVRZSUtVZlFXK0xBWnZzdGRZbC9UTTBLUEpBREFKVUtXMVE1ak51TEN4?=
 =?utf-8?B?TzJxNWNNTDRvTTBRczl4dzJxeWQ2K1h0UHYxeitkRGZkQ2NXdnNXQXFDTmc0?=
 =?utf-8?B?WGF4VTdzc2kvYWViZjJHYVoybzVaQmlldVlkUzVyNWJrOEJ1L0I0THkwdGZk?=
 =?utf-8?B?SDUyakNxYnYyQjN5RnJHUXJlbk85eElvSFc3REVuTmo5TGc3MzNtZmdOa0dF?=
 =?utf-8?B?YmRJcjd3RXRXaEl1RFdmSThRRkJPdDNWeTg0K1lsNWZEMWNWZ2NWZ3ZzaElx?=
 =?utf-8?B?eGVBWDN0eGFlaXM2bXpFdFltYVhLU0RvbWVqVHBrcmt6K3lUdkgvOEdDR3Vi?=
 =?utf-8?B?dHlTWXlvMS9WWUUxdHd0ejZYOERKVUVSaHVwaTYwVHBISTIyeSt4NTNDUWZ5?=
 =?utf-8?B?QmZudUFzNEJseXRza2ZleVBwcWZnZjdzQlVFdFI5ZFRDaGQrQWphL21kejVO?=
 =?utf-8?Q?zX6N0S8DKA/53M49003dq+gl8QrO7FDLF3J/SdH?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ecdd1f09-e064-4ecf-8143-08d8d8cfb485
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Feb 2021 14:23:07.4591
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: VdwO/gG1FYVxxYJivCUicjTM54cRNCZ3fCYmxFN7yyCs24f0Lo8qX9W0zrgGWpkLWaLtGFxdde8NjfiB1vFlXWo+Ot7g036EuOALjWHTL2E=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB4895
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9904 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 adultscore=0
 suspectscore=0 mlxlogscore=999 mlxscore=0 spamscore=0 bulkscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102240112
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9904 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 bulkscore=0
 clxscore=1015 mlxlogscore=999 lowpriorityscore=0 phishscore=0
 impostorscore=0 adultscore=0 mlxscore=0 priorityscore=1501 malwarescore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102240112
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=XLk1lBMX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=oT2k9obo;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 141.146.126.79 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
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



On 2/24/2021 5:37 AM, Mike Rapoport wrote:
> On Tue, Feb 23, 2021 at 04:46:28PM -0500, George Kennedy wrote:
>> Mike,
>>
>> Still no luck.
>>
>> [=C2=A0=C2=A0 30.193723] iscsi: registered transport (iser)
>> [=C2=A0=C2=A0 30.195970] iBFT detected.
>> [=C2=A0=C2=A0 30.196571] BUG: unable to handle page fault for address: f=
fffffffff240004
> Hmm, we cannot set ibft_addr to early pointer to the ACPI table.
> Let's try something more disruptive and move the reservation back to
> iscsi_ibft_find.c.
>
> diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boot.c
> index 7bdc0239a943..c118dd54a747 100644
> --- a/arch/x86/kernel/acpi/boot.c
> +++ b/arch/x86/kernel/acpi/boot.c
> @@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
>   	if (acpi_disabled)
>   		return;
>  =20
> +#if 0
>   	/*
>   	 * Initialize the ACPI boot-time table parser.
>   	 */
> @@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
>   		disable_acpi();
>   		return;
>   	}
> +#endif
>  =20
>   	acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);
>  =20
> diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> index d883176ef2ce..c615ce96c9a2 100644
> --- a/arch/x86/kernel/setup.c
> +++ b/arch/x86/kernel/setup.c
> @@ -570,16 +570,6 @@ void __init reserve_standard_io_resources(void)
>  =20
>   }
>  =20
> -static __init void reserve_ibft_region(void)
> -{
> -	unsigned long addr, size =3D 0;
> -
> -	addr =3D find_ibft_region(&size);
> -
> -	if (size)
> -		memblock_reserve(addr, size);
> -}
> -
>   static bool __init snb_gfx_workaround_needed(void)
>   {
>   #ifdef CONFIG_PCI
> @@ -1032,6 +1022,12 @@ void __init setup_arch(char **cmdline_p)
>   	 */
>   	find_smp_config();
>  =20
> +	/*
> +	 * Initialize the ACPI boot-time table parser.
> +	 */
> +	if (acpi_table_init())
> +		disable_acpi();
> +
>   	reserve_ibft_region();
>  =20
>   	early_alloc_pgt_buf();
> diff --git a/drivers/firmware/iscsi_ibft_find.c b/drivers/firmware/iscsi_=
ibft_find.c
> index 64bb94523281..01be513843d6 100644
> --- a/drivers/firmware/iscsi_ibft_find.c
> +++ b/drivers/firmware/iscsi_ibft_find.c
> @@ -47,7 +47,25 @@ static const struct {
>   #define VGA_MEM 0xA0000 /* VGA buffer */
>   #define VGA_SIZE 0x20000 /* 128kB */
>  =20
> -static int __init find_ibft_in_mem(void)
> +static void __init *acpi_find_ibft_region(void)
> +{
> +	int i;
> +	struct acpi_table_header *table =3D NULL;
> +	acpi_status status;
> +
> +	if (acpi_disabled)
> +		return NULL;
> +
> +	for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> +		status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
> +		if (ACPI_SUCCESS(status))
> +			return table;
> +	}
> +
> +	return NULL;
> +}
> +
> +static void __init *find_ibft_in_mem(void)
>   {
>   	unsigned long pos;
>   	unsigned int len =3D 0;
> @@ -70,35 +88,44 @@ static int __init find_ibft_in_mem(void)
>   				/* if the length of the table extends past 1M,
>   				 * the table cannot be valid. */
>   				if (pos + len <=3D (IBFT_END-1)) {
> -					ibft_addr =3D (struct acpi_table_ibft *)virt;
>   					pr_info("iBFT found at 0x%lx.\n", pos);
> -					goto done;
> +					return virt;
>   				}
>   			}
>   		}
>   	}
> -done:
> -	return len;
> +
> +	return NULL;
>   }
> +
> +static void __init *find_ibft(void)
> +{
> +	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> +	 * only use ACPI for this */
> +	if (!efi_enabled(EFI_BOOT))
> +		return find_ibft_in_mem();
> +	else
> +		return acpi_find_ibft_region();
> +}
> +
>   /*
>    * Routine used to find the iSCSI Boot Format Table. The logical
>    * kernel address is set in the ibft_addr global variable.
>    */
> -unsigned long __init find_ibft_region(unsigned long *sizep)
> +void __init reserve_ibft_region(void)
>   {
> -	ibft_addr =3D NULL;
> +	struct acpi_table_ibft *table;
> +	unsigned long size;
>  =20
> -	/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
> -	 * only use ACPI for this */
> +	table =3D find_ibft();
> +	if (!table)
> +		return;
>  =20
> -	if (!efi_enabled(EFI_BOOT))
> -		find_ibft_in_mem();
> -
> -	if (ibft_addr) {
> -		*sizep =3D PAGE_ALIGN(ibft_addr->header.length);
> -		return (u64)virt_to_phys(ibft_addr);
> -	}
> +	size =3D PAGE_ALIGN(table->header.length);
> +	memblock_reserve(virt_to_phys(table), size);
>  =20
> -	*sizep =3D 0;
> -	return 0;
> +	if (efi_enabled(EFI_BOOT))
> +		acpi_put_table(&table->header);
> +	else
> +		ibft_addr =3D table;
>   }
> diff --git a/include/linux/iscsi_ibft.h b/include/linux/iscsi_ibft.h
> index b7b45ca82bea..da813c891990 100644
> --- a/include/linux/iscsi_ibft.h
> +++ b/include/linux/iscsi_ibft.h
> @@ -26,13 +26,9 @@ extern struct acpi_table_ibft *ibft_addr;
>    * mapped address is set in the ibft_addr variable.
>    */
>   #ifdef CONFIG_ISCSI_IBFT_FIND
> -unsigned long find_ibft_region(unsigned long *sizep);
> +void reserve_ibft_region(void);
>   #else
> -static inline unsigned long find_ibft_region(unsigned long *sizep)
> -{
> -	*sizep =3D 0;
> -	return 0;
> -}
> +static inline void reserve_ibft_region(void) {}
>   #endif
>  =20
>   #endif /* ISCSI_IBFT_H */

Still no luck Mike,

We're back to the original problem where the only thing that worked was=20
to run "SetPageReserved(page)" before calling "kmap(page)". The page is=20
being "freed" before ibft_init() is called as a result of the recent=20
buddy page freeing changes.

[=C2=A0=C2=A0 30.385207] iscsi: registered transport (iser)
[=C2=A0=C2=A0 30.387462] iBFT detected.
[=C2=A0=C2=A0 30.388042]=20
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[=C2=A0=C2=A0 30.388119] BUG: KASAN: use-after-free in ibft_init+0x134/0xc3=
3
[=C2=A0=C2=A0 30.388119] Read of size 4 at addr ffff8880be453004 by task sw=
apper/0/1
[=C2=A0=C2=A0 30.388119]
[=C2=A0=C2=A0 30.388119] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.11.0-f=
9593a0 #11
[=C2=A0=C2=A0 30.388119] Hardware name: QEMU Standard PC (i440FX + PIIX, 19=
96),=20
BIOS 0.0.0 02/06/2015
[=C2=A0=C2=A0 30.388119] Call Trace:
[=C2=A0=C2=A0 30.388119]=C2=A0 dump_stack+0xdb/0x120
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.388119]=C2=A0 print_address_description.constprop.7+0x41/0=
x60
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.388119]=C2=A0 kasan_report.cold.10+0x78/0xd1
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.388119]=C2=A0 __asan_report_load_n_noabort+0xf/0x20
[=C2=A0=C2=A0 30.388119]=C2=A0 ibft_init+0x134/0xc33
[=C2=A0=C2=A0 30.388119]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
[=C2=A0=C2=A0 30.388119]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
[=C2=A0=C2=A0 30.388119]=C2=A0 do_one_initcall+0xc4/0x3e0
[=C2=A0=C2=A0 30.388119]=C2=A0 ? perf_trace_initcall_level+0x3e0/0x3e0
[=C2=A0=C2=A0 30.388119]=C2=A0 ? unpoison_range+0x14/0x40
[=C2=A0=C2=A0 30.388119]=C2=A0 ? ____kasan_kmalloc.constprop.5+0x8f/0xc0
[=C2=A0=C2=A0 30.388119]=C2=A0 ? kernel_init_freeable+0x420/0x652

George

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9b7251d1-7b90-db4f-fa5e-80165e1cbb4b%40oracle.com.
