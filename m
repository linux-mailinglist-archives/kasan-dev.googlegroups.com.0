Return-Path: <kasan-dev+bncBCX7RK77SEDBBC5736AQMGQENIIXQSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id B763232548F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 18:34:04 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id u15sf3797592qvo.13
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:34:04 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614274443; cv=pass;
        d=google.com; s=arc-20160816;
        b=NtLxvlrlSiz/rqHK6MIDvzJFs2vnfELl3RQrIzePwLC+g8/FDMXA8LP1UioFqyxCN6
         YJAtVfoK+cF6+Bd4py9TGgPOXYEHsWY9JJAlmXFRCa/NbEfYEbkF1yt3Z/xwaOg718eA
         QaUal+YBtLXvVo+DTp4qgFTufpXoZrXA6X8O/ZfTEkxIWj2htFziK/lcLLDBWEucG9bn
         yqED6UshE49n+VUcVVMwmyObrBwkmYXLVaVyHn2kl2v96ijwm99foBSi4qvLYd2K3/CO
         tGNSpqou9mdNVJ2osNeixfsm+YSVsqkUdEiyJeQJnHgdxIdnePfjfFCRKs+9ZWEj+5ba
         /XEw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=NFUSm5D/cf/RZIUSNZa98sl2LTci3CpCxngdOf+fnbE=;
        b=YjLCctho9mj0rjwn2ST0yMFnWNcq54pPXvYsbKUzl/BCXbPEBAs4nI9NJgqW4V/F2A
         2eDJvkvYxPXBTC9WuRYIzLWztT4dIj4TX9bmF+u5J0y/xDfkjWfTpri9ZGXbTEV9D+pK
         JXMFzDMPdg1G6UVvslWoycwHiNgjw+ni5fiUBDVNgAIjMhqG0OdN/k6fntBlPq/tp/aB
         8cgZWVF5Y6qqYeEIYcYm10D6kINfuQu6zFfA4B+h8s1d86jkE1m/r1Iz4+pr1rVjQng8
         ryANh3VTlQfHnMGyRB6RVNSRM0gKbksuOe8K6GseJfhrDdJ8sLRgH9Ru9GvFvXxhBpkG
         GgHw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=WiKzgCI8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=yaZ0wlKC;
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
        bh=NFUSm5D/cf/RZIUSNZa98sl2LTci3CpCxngdOf+fnbE=;
        b=UfdiRrD3uBvNfnk5bDfvcX1AsLn9Y5MjBKu07RlBRLTVJfNC8wpag7HKxwY4wpfZSk
         EOyDnqsDlwoek3s2r+zW2lscH7RTWgeZZchB6kE5GbUbQ3ZKrDB1Ss0eRGKWE4FcHMs1
         hPmUmQ/msgm9vc1QdNyelWNHksKkAIEdSrpb/eBbZpvePx9bv34gd8pgFqFN5/ySQemF
         vpQWnktzfv0IFS1hByvkb/1NnhB2ZkixeZpX8sb+i+kVgrK7kYnFpjGJhFddNYiZdbzk
         l2rMHNjuOwmbLLysSX048M6jDB6BKCpaIktK1iOhCO4Sqa/o/6ruJnQoKJhoLD9lE75M
         dhjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NFUSm5D/cf/RZIUSNZa98sl2LTci3CpCxngdOf+fnbE=;
        b=FHAMdJ6FhlVBRkF8Ypvfzuw9naqD0RxsW2/ln4RN4t6Y5gJLX2IQ60v/LFq2CYA+O9
         4bMbo/RKcmT7o2vQCS593LAfegVx/gR8zhuiZ/vWCNyYw632vx93vUUBGaBh8ezA/sz1
         rQi5uN6LSt5WFmsX+SUTkwIjRJULAd3SLShHpS840l5sNmAb6gx4UUcLlrs22fYy/EI/
         +EKR3myTrlMI6seayI3L88Arvl7iDHe5ACA6ujCSIZ4BW970MBI0Eto4lhM0mOGLTHvR
         HHVTPPGkdTSSH+JFWJSpSemNwoHqcI3WAcVTcWS/ODEr7+oIABPzJ8jvcBtGBNGHjuTJ
         nEZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532isB+yP8JFinmjv8aCakteS0xDYd8qGOFlYTQ9LDlJWvLhZh3J
	JS4vNIk0lRB3jPMc0Zhg6zM=
X-Google-Smtp-Source: ABdhPJyb95cgWW6N95/5Mt/9kPtbLczvjIYjefTlDfkKSRtpdTKadMHB8dFtG76MiAAd943eT+aNUg==
X-Received: by 2002:a0c:b584:: with SMTP id g4mr3778197qve.0.1614274443715;
        Thu, 25 Feb 2021 09:34:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aac:: with SMTP id u12ls1670561qvg.5.gmail; Thu, 25 Feb
 2021 09:34:03 -0800 (PST)
X-Received: by 2002:a0c:c488:: with SMTP id u8mr3678584qvi.9.1614274443239;
        Thu, 25 Feb 2021 09:34:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614274443; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbEI1EDzGTX+wyPtDefbsbbkp9jt4sNU85iN6BqVNAHB56X8i4X1cB0fUqOIHeKF4K
         bm6cxqw8ihiUwUGbs6VtgjhQuRzSp5IRiMz0AfWBlubVUZqWgUJoXz/SzVq2rmcurmIC
         fooBRQrgcuDLYquQrfMjoI8xYJWIcehOQMgHNWJNcsqC6WVMsAQkPAKVY5XY+mLOEm+Q
         viy/foZNVuhJpLWJFVkljAzWvdiOt0DA0k2K4TZF1oI3oLsJQDQDX2pMQF2D0RZjfsOs
         /dkbP0TgnOJRg25VDKAnFu4k32Oi+2HSTUmn9hFA2J1h40p/KXgTMlVaGsNvQAWeBmrJ
         bwXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=NUsO3bKMxcKeT2aKEXs1iORskqoHff330Fz9OOoniIE=;
        b=z8vKK8pwWutQm01x8yQfsw35a8DAGFxLmVCsesRVGiJVgIlXnC+NYZNdSaOGAZu5vr
         +hcPi4jJkNrXpMb60sXbVkXOiHOGpIVQvwLpDB+HK/CKnlvBv6EQJiwDx8pjHy3Fw7Bg
         Xxjoixigw0ThffcUTRmJSv5OdrcSvv7Sxhw3qeu4xQRoXXxAyx+dbzCaB/t/4O1f4Ap0
         YKgNNT4zHIb4DGEcHG3nch0eLYsRgN/larJFgt7NRdRBxKwH0hAO3aGy/Pc/szG9Kw+R
         V1CO1htYTzK6YQdL/3dsKF5P6RQNy6ICMw4ZJDfS7buNozqkA9JBPf+l7U/DqK7dbpJX
         P4uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=WiKzgCI8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=yaZ0wlKC;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2130.oracle.com (aserp2130.oracle.com. [141.146.126.79])
        by gmr-mx.google.com with ESMTPS id s20si46962qtb.2.2021.02.25.09.34.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 09:34:03 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.79 as permitted sender) client-ip=141.146.126.79;
Received: from pps.filterd (aserp2130.oracle.com [127.0.0.1])
	by aserp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11PHTlBV133752;
	Thu, 25 Feb 2021 17:33:46 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2130.oracle.com with ESMTP id 36vr629n4c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 17:33:45 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11PHUhfH175232;
	Thu, 25 Feb 2021 17:33:45 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12lp2176.outbound.protection.outlook.com [104.47.55.176])
	by aserp3020.oracle.com with ESMTP id 36ucb2b6p7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 25 Feb 2021 17:33:45 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=a2O8Q5GvfetAEdZdbs7uOeIjCS3HX7I021L/CpDAzDDpHlYX9FHkUnrOhZNsl1m2yyJ0HUMKhtQsQ077RuBESuhs4YGXP4OOktXR2qs4gSUbF7GKCEZN/JnTvXXLUXbWAwg5NbT1Jgq+03j9xgoWz8TDjK/kWPKLJ1bwAX8tPHZjpZYQzLwbThmcJdHJq8t/A/GPCllw0Nc9hVDydltQCR/Dgxb/9/iX0ZhR7LbKBEA86DMvYm9o+BOKiAo+m5DimiSdJY0bUvApovc3apwhsrSMiZwlFtmnuRm4Fzl3i/pWALcO4VhX3hkFZPqzGYPxK0aJYjJrrIeQcdk8c23TXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=NUsO3bKMxcKeT2aKEXs1iORskqoHff330Fz9OOoniIE=;
 b=i+YznFemBOHsPR7h2aQeaB8nn8ISq1Zp6j7/xeUL5FzknWLKJPuxca1gbqgeiZtweMOWuKkQoMcee1fw3g48gkCqRjGpR4SEyMQSHBj67cdZ4Y0BWMy47NwN53IgphYh//DQRMYSQp87FHz4eTNta5Zw8Zsz9pn6NNN1wCj6oufh8Z/W8IpGU5z5270SQnC/7832AO0Fc8To1VPCAz2vqXazUaiu4kktDtpwsMfoRLLRJAepW8zqJ5DJegfk63Of4DnTRHquLL4Tz/Kx6dksOy8DoVYucm0nMl8IRImpAKuC+iczS9Rc2GaFd253Taz8opPmLor38rvXxFPQx9jkPQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB4330.namprd10.prod.outlook.com (2603:10b6:5:21f::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.31; Thu, 25 Feb
 2021 17:33:43 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.034; Thu, 25 Feb 2021
 17:33:43 +0000
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
References: <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
Date: Thu, 25 Feb 2021 12:33:34 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.1
In-Reply-To: <20210225160706.GD1854360@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: BYAPR01CA0042.prod.exchangelabs.com (2603:10b6:a03:94::19)
 To DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.222] (108.20.187.119) by BYAPR01CA0042.prod.exchangelabs.com (2603:10b6:a03:94::19) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19 via Frontend Transport; Thu, 25 Feb 2021 17:33:39 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 215014bc-e5cd-4bc3-c3a0-08d8d9b37f37
X-MS-TrafficTypeDiagnostic: DM6PR10MB4330:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB433090C2927626158D145983E69E9@DM6PR10MB4330.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:8273;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: Dzt6DySAhzvMmLQo+KieS7LD+H3gMa2vrbRz7U8e3xOX2w+A4g1wGLjT+gy+zRHSdkffqxs5S+HW/uATnjixNcmEB59eOPAvDPL0JHKitOMNb0WUpOCHTia3Wh5tNLKix+T122R4WZqR/ufHbFwzrxw/oEkpN1w88JA1E6RA5GCSiDOi30Ti/nP9WPzdq9ltoI3XjHUqJFOXpf8lQ9GUF2ocGJEot71XNf20UuFrXVjgJrqbH91pv2r8tluEdYrT9GhEeozwzUFPiujJR2faSmWk2kPRYEWcPgCxkK0haX3eRQbX2GEsaATTWNsypTMYwYbieJd+WrV27EPvzuhgGUds+48KfIBtTiOPIV0vtzRHdEyEuA8unsgPAB0VAcMVL2zLEBwNtD8lfLcQnPEbVfaSaurn/T2y+cXbhH114AYDF7L2YId4IpCPVZ5qVGlYSuTLKtcuwWxnzb9ab4S9dFttpt1xa6yC1YXhWYGOxn1g7IfdZ/VODKXLleVFAclqQf55+mtOYDU3CbzlMz5ImFpKU+ptvDEjen9vBMx2et6uNNPDBHezbN1luamhkyxsPDJHl1+/0IjMqBUv9vxZagkS1PoCLHFIJ7t6QGzXbLo=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(39860400002)(136003)(376002)(396003)(366004)(107886003)(31696002)(66556008)(2616005)(83380400001)(2906002)(6916009)(26005)(478600001)(186003)(86362001)(66476007)(16526019)(53546011)(8936002)(36756003)(6486002)(31686004)(30864003)(54906003)(44832011)(16576012)(316002)(7416002)(5660300002)(956004)(36916002)(4326008)(66946007)(6666004)(8676002)(21314003)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?SlVFQVV2SDI3M2JpdVlCK3J1VituazkrUzVadDBhYkxrRjRyRldoTVEyWWx2?=
 =?utf-8?B?dWFndFBmT0RzTFNRRlN6VFdEMmNnbVF6RDBLRW5FQnh5STJOcVJ1aG04NGlr?=
 =?utf-8?B?YmdIaHdLMnlBRHRTUEcyaTJ1T1NLVjBzYSt4cHBLckhQekl4dnBwRnVRU3Bp?=
 =?utf-8?B?SjZXSW5SWXNvZng5YkFsM25qYnd2K29HNUxkWUo4NDdTMWNQcW5SL0U0dEM3?=
 =?utf-8?B?SWRPUHM4MUdaWS9QKzNNeldEWVk0TGdoZjMwalJOUiszVVdQUFhpdGY5K0ZX?=
 =?utf-8?B?QjlJYjJkUjNxSVZDWFdmRlh1WHBxaUpBMllhS1o3Y25EN09keVgwWForVW53?=
 =?utf-8?B?OXo2SG9qN0hqM1d2Q0JnelhYZXVqdHVOcGdSemNPdmtDQ3h3eUlUZmJEK1R6?=
 =?utf-8?B?WGFoRGc0RWNiWEdTaWc2d2Mzc2JDbWgxM2hzMFhmc1dIanhoYXlMN0ZuazZm?=
 =?utf-8?B?cHgra1Y5cTl5KzBNRlVkTnpLNStNNG8zOWJKQ2p3TGtkcHlHM2p4cFh2enpK?=
 =?utf-8?B?WHNBMng1bzBwSnNCblE3NGgwYXdDUkUzUkI1S1N1V2kzYVduNWMvRHBrSWc3?=
 =?utf-8?B?Q2N5dGRpbmk1MXpzYTlTYlJGbnkzanNvV2M2WmdsbGFTS2QvRTM4S2d0OEJz?=
 =?utf-8?B?WWtJY0granpYRVFIb3VPS3o2Um43RlVaMUEra2pRZ0J1MDBBYk9kZm85bUlo?=
 =?utf-8?B?RjdEdU1FSUZuMjZrNExtQ0ZQT0Yxd25hc2hkbDFBZEhnbkZ6OU4xQnJwa1dj?=
 =?utf-8?B?OEMyY0UvU0wvbzkwYXA2eEVRd3JTVkVnUEg3MWVLRngzeTJQMkpqVERFVzRK?=
 =?utf-8?B?bzBYVmlBMnFuRDkwNnRab3lkZ0hJRnU4YldrUDBQUC9VVFdiaVBqNEVvY3pF?=
 =?utf-8?B?cko2UFhuMzNwOGZlNmpld1phZlpjbndocmFMYTlNU1VRanIvdDZGaFNENjNw?=
 =?utf-8?B?b2VLY2tDK2I5QjlnVndYK2pkejNxZFEvMWJBM0VxUjVzMmhFMUpqRGExMVRM?=
 =?utf-8?B?NkN6bk1DeTFSWUQ0WklRbGd3S1E1ZW5OTElKMGtBbmNUNFpLYUdvSHRoTDcv?=
 =?utf-8?B?RzVSU1dFK1g4eE9aV3dWemcxY2E4dGhSMnowUE9HQkg0Z0VGRUpuZGhhV3dF?=
 =?utf-8?B?a1NDL2NuZlhtQ2VRbzE3a1o4amM3aUJwdEVYWEdrdjI4V0JmMnV2NW1KWW1D?=
 =?utf-8?B?VHlmV1pvMTZnVVB4d2syNEN6ZGs3NVBTNFhOTjJJRS9MK0dEVVpjeFBtWDBj?=
 =?utf-8?B?YjZJdlFrZWFwTnRIQjNEa2swZ1I2TEFEcUQxOWpyenlKYUxlejdpd0RXRDJT?=
 =?utf-8?B?WFRLZGRENUk5cHZYQy9NaUtsUm5RT1hvY3pSU0dMQkNpWE1kSjJ6dlhLM3Ex?=
 =?utf-8?B?aXpGWWU0N3FDeWRhMkRWRGQ1WFQzYjdnZkJLMll3Zk9VT0hRbG5Hemt4di9o?=
 =?utf-8?B?UU5uSFRldm94bGxvV2RvTTYrNm4xRndLRG5GRUVWamtBaFNMTTRPaTIvSzc0?=
 =?utf-8?B?SHUwWk04SGxiYi9Ua1Uzd0N6SDEybVBab0Znd3RMeHJUUmJBaEdzMnM4WU5P?=
 =?utf-8?B?dFFLK3pMQlpBb292cDE4VGR2NjlhSlBvZTRPMEtla2dJbk5nSTE4K3h5Q2NG?=
 =?utf-8?B?SWZPNFV4WDdzVjlXSEdlRTExVVgzclp4RVo0YnpmRy9zUnFQdTNzWGQ1K1JV?=
 =?utf-8?B?ZXJrWlB4RHFjS1UyNHB4SkFmRkwxODlNcFpleGkyMC84Y2UyYkI4QUNRN05D?=
 =?utf-8?Q?BkZSw9lJ11+69TpKJ8mElguYAHysz1MnTaMr9XD?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 215014bc-e5cd-4bc3-c3a0-08d8d9b37f37
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Feb 2021 17:33:43.1638
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: jRa/IpqRAk46xQl50mwVQzap9ld6cEjBunKRJl1xMSBeCZe+MidgnYyBaxUBd0bOmhQLobqMhyLup6n45J5sNjpLZiyPUJQ/+E9Opz+5Aic=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB4330
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9906 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 malwarescore=0 mlxlogscore=999 adultscore=0 bulkscore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102250133
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9906 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 bulkscore=0
 clxscore=1015 mlxlogscore=999 lowpriorityscore=0 phishscore=0
 impostorscore=0 adultscore=0 mlxscore=0 priorityscore=1501 malwarescore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102250132
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=WiKzgCI8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=yaZ0wlKC;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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



On 2/25/2021 11:07 AM, Mike Rapoport wrote:
> On Thu, Feb 25, 2021 at 10:22:44AM -0500, George Kennedy wrote:
>>>>>> On 2/24/2021 5:37 AM, Mike Rapoport wrote:
>> Applied just your latest patch, but same failure.
>>
>> I thought there was an earlier comment (which I can't find now) that sta=
ted
>> that memblock_reserve() wouldn't reserve the page, which is what's neede=
d
>> here.
> Actually, I think that memblock_reserve() should be just fine, but it see=
ms
> I'm missing something in address calculation each time.
>
> What would happen if you stuck
>
> 	memblock_reserve(0xbe453000, PAGE_SIZE);
>
> say, at the beginning of find_ibft_region()?

Good news Mike!

The above hack in yesterday's last patch works - 10 successful reboots.=20
See: "BE453" below for the hack.

I'll modify the patch to use "table_desc->address" instead, which is the=20
physical address of the table.

diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boot.c
index 7bdc023..c118dd5 100644
--- a/arch/x86/kernel/acpi/boot.c
+++ b/arch/x86/kernel/acpi/boot.c
@@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
 =C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;

+#if 0
 =C2=A0=C2=A0=C2=A0=C2=A0 /*
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0* Initialize the ACPI boot-time table parse=
r.
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0*/
@@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 disable_acpi();
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
 =C2=A0=C2=A0=C2=A0=C2=A0 }
+#endif

 =C2=A0=C2=A0=C2=A0=C2=A0 acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);

diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index 740f3bdb..b045ab2 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -571,16 +571,6 @@ void __init reserve_standard_io_resources(void)

 =C2=A0}

-static __init void reserve_ibft_region(void)
-{
-=C2=A0=C2=A0=C2=A0 unsigned long addr, size =3D 0;
-
-=C2=A0=C2=A0=C2=A0 addr =3D find_ibft_region(&size);
-
-=C2=A0=C2=A0=C2=A0 if (size)
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 memblock_reserve(addr, size);
-}
-
 =C2=A0static bool __init snb_gfx_workaround_needed(void)
 =C2=A0{
 =C2=A0#ifdef CONFIG_PCI
@@ -1033,6 +1023,12 @@ void __init setup_arch(char **cmdline_p)
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0*/
 =C2=A0=C2=A0=C2=A0=C2=A0 find_smp_config();

+=C2=A0=C2=A0=C2=A0 /*
+=C2=A0=C2=A0=C2=A0 =C2=A0* Initialize the ACPI boot-time table parser.
+=C2=A0=C2=A0=C2=A0 =C2=A0*/
+=C2=A0=C2=A0=C2=A0 if (acpi_table_init())
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 disable_acpi();
+
 =C2=A0=C2=A0=C2=A0=C2=A0 reserve_ibft_region();

 =C2=A0=C2=A0=C2=A0=C2=A0 early_alloc_pgt_buf();
diff --git a/drivers/firmware/iscsi_ibft_find.c=20
b/drivers/firmware/iscsi_ibft_find.c
index 64bb945..95fc1a6 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -47,7 +47,25 @@
 =C2=A0#define VGA_MEM 0xA0000 /* VGA buffer */
 =C2=A0#define VGA_SIZE 0x20000 /* 128kB */

-static int __init find_ibft_in_mem(void)
+static void __init *acpi_find_ibft_region(void)
+{
+=C2=A0=C2=A0=C2=A0 int i;
+=C2=A0=C2=A0=C2=A0 struct acpi_table_header *table =3D NULL;
+=C2=A0=C2=A0=C2=A0 acpi_status status;
+
+=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return NULL;
+
+=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr;=
 i++) {
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 status =3D acpi_get_table(ibft_signs=
[i].sign, 0, &table);
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (ACPI_SUCCESS(status))
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return table;
+=C2=A0=C2=A0=C2=A0 }
+
+=C2=A0=C2=A0=C2=A0 return NULL;
+}
+
+static void __init *find_ibft_in_mem(void)
 =C2=A0{
 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pos;
 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned int len =3D 0;
@@ -70,35 +88,52 @@ static int __init find_ibft_in_mem(void)
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 /* if the length of the table extends past 1M,
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0* the table cannot be valid. */
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 if (pos + len <=3D (IBFT_END-1)) {
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D (struct acpi_table_ibft *)virt;
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0 pr_info("iBFT found at 0x%lx.\n", pos);
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 goto done;
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 return virt;
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0=C2=A0 }
-done:
-=C2=A0=C2=A0=C2=A0 return len;
+
+=C2=A0=C2=A0=C2=A0 return NULL;
 =C2=A0}
+
+static void __init *find_ibft(void)
+{
+=C2=A0=C2=A0=C2=A0 /* iBFT 1.03 section 1.4.3.1 mandates that UEFI machine=
s will
+=C2=A0=C2=A0=C2=A0 =C2=A0* only use ACPI for this */
+=C2=A0=C2=A0=C2=A0 if (!efi_enabled(EFI_BOOT))
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return find_ibft_in_mem();
+=C2=A0=C2=A0=C2=A0 else
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_find_ibft_region();
+}
+
 =C2=A0/*
 =C2=A0 * Routine used to find the iSCSI Boot Format Table. The logical
 =C2=A0 * kernel address is set in the ibft_addr global variable.
 =C2=A0 */
-unsigned long __init find_ibft_region(unsigned long *sizep)
+void __init reserve_ibft_region(void)
 =C2=A0{
-=C2=A0=C2=A0=C2=A0 ibft_addr =3D NULL;
+=C2=A0=C2=A0=C2=A0 struct acpi_table_ibft *table;
+=C2=A0=C2=A0=C2=A0 unsigned long size;

-=C2=A0=C2=A0=C2=A0 /* iBFT 1.03 section 1.4.3.1 mandates that UEFI machine=
s will
-=C2=A0=C2=A0=C2=A0 =C2=A0* only use ACPI for this */
+=C2=A0=C2=A0=C2=A0 table =3D find_ibft();
+=C2=A0=C2=A0=C2=A0 if (!table)
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;

-=C2=A0=C2=A0=C2=A0 if (!efi_enabled(EFI_BOOT))
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 find_ibft_in_mem();
-
-=C2=A0=C2=A0=C2=A0 if (ibft_addr) {
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 *sizep =3D PAGE_ALIGN(ibft_addr->hea=
der.length);
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (u64)virt_to_phys(ibft_addr);
-=C2=A0=C2=A0=C2=A0 }
+=C2=A0=C2=A0=C2=A0 size =3D PAGE_ALIGN(table->header.length);
+#if 0
+printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,=20
virt_to_phys(table)=3D%llx, size=3D%lx\n",
+=C2=A0=C2=A0=C2=A0 (u64)table, virt_to_phys(table), size);
+=C2=A0=C2=A0=C2=A0 memblock_reserve(virt_to_phys(table), size);
+#else
+printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,=20
0x00000000BE453000, size=3D%lx\n",
+=C2=A0=C2=A0=C2=A0 (u64)table, size);
+=C2=A0=C2=A0=C2=A0 memblock_reserve(0x00000000BE453000, size);
+#endif

-=C2=A0=C2=A0=C2=A0 *sizep =3D 0;
-=C2=A0=C2=A0=C2=A0 return 0;
+=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT))
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 acpi_put_table(&table->header);
+=C2=A0=C2=A0=C2=A0 else
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D table;
 =C2=A0}
diff --git a/include/linux/iscsi_ibft.h b/include/linux/iscsi_ibft.h
index b7b45ca..da813c8 100644
--- a/include/linux/iscsi_ibft.h
+++ b/include/linux/iscsi_ibft.h
@@ -26,13 +26,9 @@
 =C2=A0 * mapped address is set in the ibft_addr variable.
 =C2=A0 */
 =C2=A0#ifdef CONFIG_ISCSI_IBFT_FIND
-unsigned long find_ibft_region(unsigned long *sizep);
+void reserve_ibft_region(void);
 =C2=A0#else
-static inline unsigned long find_ibft_region(unsigned long *sizep)
-{
-=C2=A0=C2=A0=C2=A0 *sizep =3D 0;
-=C2=A0=C2=A0=C2=A0 return 0;
-}
+static inline void reserve_ibft_region(void) {}
 =C2=A0#endif

 =C2=A0#endif /* ISCSI_IBFT_H */


Debug from the above:

[=C2=A0=C2=A0=C2=A0 0.020293] last_pfn =3D 0xbfedc max_arch_pfn =3D 0x40000=
0000
[=C2=A0=C2=A0=C2=A0 0.050778] ACPI: Early table checksum verification disab=
led
[=C2=A0=C2=A0=C2=A0 0.056475] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 BOC=
HS )
[=C2=A0=C2=A0=C2=A0 0.057628] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 BOC=
HS BXPCFACP=20
00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
[=C2=A0=C2=A0=C2=A0 0.059341] ACPI: FACP 0x00000000BFBF5000 000074 (v01 BOC=
HS BXPCFACP=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.061043] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 BOC=
HS BXPCDSDT=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.062740] ACPI: FACS 0x00000000BFBFD000 000040
[=C2=A0=C2=A0=C2=A0 0.063673] ACPI: APIC 0x00000000BFBF4000 000090 (v01 BOC=
HS BXPCAPIC=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.065369] ACPI: HPET 0x00000000BFBF3000 000038 (v01 BOC=
HS BXPCHPET=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.067061] ACPI: BGRT 0x00000000BE49B000 000038 (v01 INT=
EL EDK2=C2=A0=C2=A0=C2=A0=C2=A0=20
00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
[=C2=A0=C2=A0=C2=A0 0.068761] ACPI: iBFT 0x00000000BE453000 000800 (v01 BOC=
HS BXPCFACP=20
00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
[=C2=A0=C2=A0=C2=A0 0.070461] XXX reserve_ibft_region: table=3Dffffffffff24=
0000,=20
0x00000000BE453000, size=3D1000
[=C2=A0=C2=A0=C2=A0 0.072231] check: Scanning 1 areas for low memory corrup=
tion

George
>  =20
>> [=C2=A0=C2=A0 30.308229] iBFT detected..
>> [=C2=A0=C2=A0 30.308796]
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> [=C2=A0=C2=A0 30.308890] BUG: KASAN: use-after-free in ibft_init+0x134/0=
xc33
>> [=C2=A0=C2=A0 30.308890] Read of size 4 at addr ffff8880be453004 by task=
 swapper/0/1
>> [=C2=A0=C2=A0 30.308890]
>> [=C2=A0=C2=A0 30.308890] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.11.=
0-f9593a0 #12
>> [=C2=A0=C2=A0 30.308890] Hardware name: QEMU Standard PC (i440FX + PIIX,=
 1996), BIOS
>> 0.0.0 02/06/2015
>> [=C2=A0=C2=A0 30.308890] Call Trace:
>> [=C2=A0=C2=A0 30.308890]=C2=A0 dump_stack+0xdb/0x120
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>> [=C2=A0=C2=A0 30.308890]=C2=A0 print_address_description.constprop.7+0x4=
1/0x60
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>> [=C2=A0=C2=A0 30.308890]=C2=A0 kasan_report.cold.10+0x78/0xd1
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>> [=C2=A0=C2=A0 30.308890]=C2=A0 __asan_report_load_n_noabort+0xf/0x20
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ibft_init+0x134/0xc33
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_one_initcall+0xc4/0x3e0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? perf_trace_initcall_level+0x3e0/0x3e0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? unpoison_range+0x14/0x40
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ____kasan_kmalloc.constprop.5+0x8f/0xc0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? kernel_init_freeable+0x420/0x652
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __kasan_kmalloc+0x9/0x10
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
>> [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init_freeable+0x596/0x652
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? console_on_rootfs+0x7d/0x7d
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init+0x16/0x1d0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ret_from_fork+0x22/0x30
>> [=C2=A0=C2=A0 30.308890]
>> [=C2=A0=C2=A0 30.308890] The buggy address belongs to the page:
>> [=C2=A0=C2=A0 30.308890] page:0000000001b7b17c refcount:0 mapcount:0
>> mapping:0000000000000000 index:0x1 pfn:0xbe453
>> [=C2=A0=C2=A0 30.308890] flags: 0xfffffc0000000()
>> [=C2=A0=C2=A0 30.308890] raw: 000fffffc0000000 ffffea0002ef9788 ffffea00=
02f91488
>> 0000000000000000
>> [=C2=A0=C2=A0 30.308890] raw: 0000000000000001 0000000000000000 00000000=
ffffffff
>> 0000000000000000
>> [=C2=A0=C2=A0 30.308890] page dumped because: kasan: bad access detected
>> [=C2=A0=C2=A0 30.308890] page_owner tracks the page as freed
>> [=C2=A0=C2=A0 30.308890] page last allocated via order 0, migratetype Mo=
vable,
>> gfp_mask 0x100dca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO), pid 204, ts 28121288=
605
>> [=C2=A0=C2=A0 30.308890]=C2=A0 prep_new_page+0xfb/0x140
>> [=C2=A0=C2=A0 30.308890]=C2=A0 get_page_from_freelist+0x3503/0x5730
>> [=C2=A0=C2=A0 30.308890]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
>> [=C2=A0=C2=A0 30.308890]=C2=A0 alloc_pages_vma+0xe2/0x560
>> [=C2=A0=C2=A0 30.308890]=C2=A0 __handle_mm_fault+0x930/0x26c0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 handle_mm_fault+0x1f9/0x810
>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_user_addr_fault+0x6f7/0xca0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 exc_page_fault+0xaf/0x1a0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 asm_exc_page_fault+0x1e/0x30
>> [=C2=A0=C2=A0 30.308890] page last free stack trace:
>> [=C2=A0=C2=A0 30.308890]=C2=A0 free_pcp_prepare+0x122/0x290
>> [=C2=A0=C2=A0 30.308890]=C2=A0 free_unref_page_list+0xe6/0x490
>> [=C2=A0=C2=A0 30.308890]=C2=A0 release_pages+0x2ed/0x1270
>> [=C2=A0=C2=A0 30.308890]=C2=A0 free_pages_and_swap_cache+0x245/0x2e0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_flush_mmu+0x11e/0x680
>> [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_finish_mmu+0xa6/0x3e0
>> [=C2=A0=C2=A0 30.308890]=C2=A0 exit_mmap+0x2b3/0x540
>> [=C2=A0=C2=A0 30.308890]=C2=A0 mmput+0x11d/0x450
>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_exit+0xaa6/0x2d40
>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_group_exit+0x128/0x340
>> [=C2=A0=C2=A0 30.308890]=C2=A0 __x64_sys_exit_group+0x43/0x50
>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_syscall_64+0x37/0x50
>> [=C2=A0=C2=A0 30.308890]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> [=C2=A0=C2=A0 30.308890]
>> [=C2=A0=C2=A0 30.308890] Memory state around the buggy address:
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f00: ff ff ff ff ff ff ff ff=
 ff ff ff ff ff ff
>> ff ff
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f80: ff ff ff ff ff ff ff ff=
 ff ff ff ff ff ff
>> ff ff
>> [=C2=A0=C2=A0 30.308890] >ffff8880be453000: ff ff ff ff ff ff ff ff ff f=
f ff ff ff ff
>> ff ff
>> [=C2=A0=C2=A0 30.308890]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453080: ff ff ff ff ff ff ff ff=
 ff ff ff ff ff ff
>> ff ff
>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453100: ff ff ff ff ff ff ff ff=
 ff ff ff ff ff ff
>> ff ff
>> [=C2=A0=C2=A0 30.308890]
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> George
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6000e7fd-bf8b-b9b0-066d-23661da8a51d%40oracle.com.
