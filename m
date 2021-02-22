Return-Path: <kasan-dev+bncBCX7RK77SEDBBTXWZ6AQMGQE6QAT4UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C51C3321F49
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 19:43:27 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id j4sf574191pgs.18
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 10:43:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614019406; cv=pass;
        d=google.com; s=arc-20160816;
        b=QHBbRUKIMgs0L3xBs3Q0RWFPYUIfm7aorUZZkLxWkYh7bTfklGbBHwumHD4fi6M7EA
         ntB8PJlYwWZICfc83D0rkokQvSqrWC+pYZa/YTiaHc2/64LQsNn3mnLAeBvcxqMu2QfJ
         7EFuRoUxImuqWe7xy157ljAD2hdofZM21/xreeKTzMVrNBK8zOTp3ZyKP+g4wbREsCpD
         RLkGTHgPsPeH/8UBsSkOdzOiUyEbh5HprUBP1EpNNECnMVR6zfWdTYEnFph8/Ne4sO1A
         AJKCK2BE4JJHRTQg+VbSFgPMk5wLYNFxia1JXL3GYxHfdhLh5JlW1By350iIWQo0CP5h
         w90A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=UxnBNR/obfBf6iA0iZHV3cRYDxJD2pQebJgvvyKLExk=;
        b=vo9h3gx4iCfaSRoxtjst4DSpGK7ZjP+BH+NiNLAlxErlhICcr6fudueBNTqNZXfFtX
         7gFkmSbr4EnNz+5WMDcvATdZ0ZM8y3U5AtiQEFac6SeMDL3kWn4YYnkXSR+nDK1S5MAM
         0EjhO7N0TkBWrl9WX4diqmK+Gr30nt/WdxSbnHbDz24TCIdQZdLnHf9gWjdfkjVI/WvY
         2CWMr6WxUZ/gUbyG8+bAXgzUXds/tZMTkNU4/mvGEcQgo4pP+pEm4xYENqdSf1GyJdzM
         zwtk8+o4HOLe0Eb2vK7Nm3VL5xxf4pFvsDQcbfrJJ7tWhLVn3nCbZwip5T+arN+e7BDz
         YkBg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=get+Zf53;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=cPpvm2vj;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UxnBNR/obfBf6iA0iZHV3cRYDxJD2pQebJgvvyKLExk=;
        b=nOESq6I9GyGQtb7Fkra9DI3oXcwWP8JZPCUrfBcWKwL6kTUeegLp22O5Hjmy43A4d7
         oCaqaN3vpcEwcXbE9CD6NQWtj1oVTwE6RvSgC0mOGIFueoV08GgzN8AW6lofKSvFWCCZ
         aKDTdEIo3eGz5XVzjz9hgPaa3WXtJvYnJCmsI4CrWRJuTvWim3ogZeKXvGtYPyF9laIT
         F4BNvl89PQxqSOdnlkuYq4mQS7hCNg0EddbrmG/iBHSNWrN07So5EHCiBFz0DHTmQ8bM
         b5TjNKcHoHO6rgd+ev5KaIPygmNd3j42l4GgOzWeJ38oZIH//FLozaUMOFS5OMLxL1s6
         x7Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UxnBNR/obfBf6iA0iZHV3cRYDxJD2pQebJgvvyKLExk=;
        b=Jt2loFFrFKmw0GY40g4OGcKw/sgbfmsqeo/F4MpTP/Sw8hLgOSCFVHsfHJfWEmjVrp
         5E29bml68AegTfhZlqbgJl4ylnTB1nZvD0n2zi/S0e7taA77NkXQGGia0dwYD7SIOyLg
         y3N6rDete1G8HkrKB7FkYCSUK7yE7dQg3I5c/Ef5sHp5wk7Aw8HMHtr1Qg6ivCsf3AxS
         +P9h87RnX/pUsWIj0fd4ZTAYmn44jzYYZNXRw8j1rXr7kinqnvBCWCq1YfBO9miblBGp
         7AUJEFyVdu3Li6IGBgsFOk+LY4WS64igMtS70ITCi5tsVMMtLlG/EpMbgArslu1AfIIm
         cdLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PCXEHgtvflWreQTEF/qGpJ8TehaVxyhRbG2t+CIzB8LN4vmNh
	GkWAGp/sBss6EIyVSvB9LEI=
X-Google-Smtp-Source: ABdhPJx2bkqs8HZGmQa06IQ2tLx1LD/19gSt2qJHMWiwrlgCXVhSj0qvd2CjQ1O4KpEiOpSEDtbkdQ==
X-Received: by 2002:a17:90a:d998:: with SMTP id d24mr24766182pjv.169.1614019406539;
        Mon, 22 Feb 2021 10:43:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1490:: with SMTP id 138ls7149120pfu.7.gmail; Mon, 22 Feb
 2021 10:43:25 -0800 (PST)
X-Received: by 2002:a62:1412:0:b029:1ec:bc11:31fd with SMTP id 18-20020a6214120000b02901ecbc1131fdmr22532562pfu.76.1614019405825;
        Mon, 22 Feb 2021 10:43:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614019405; cv=pass;
        d=google.com; s=arc-20160816;
        b=0PyIfznSjMvqvf53y8GjqM+DZMiiQBZ1jG1Gm1sByY9ZPgc1K1eWCvsJThZ2D9Azke
         K00cSDQQdMThU+UdDCmeahAJx+yzU9SNVECCIr6uOI0K6vYcVoSkiKqVqIqXA3EkYS+e
         HSXEEnlS5UtFQu2ZTmeMtWWm3398yQVRHd19D0AgmNo+Z0Kl5AHc8cS90bPmP7v6tKns
         DTjrrpinMZPChWlZaHTJ0xmG1GpxuovgNYy4QVwhxwzLF8yiRzWHvyPamogvxFXY7z//
         4pjzBhHedZrnQ8ni4y/kUMR8BIjEMgkYrJVAIzRw1E/7HlT7J8gC5UmXV3XN/vrGWjdJ
         skPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=CVdGajCLMI2+3gzgx3h0ZAYJOFhSDO7t9stTQZiF0Gk=;
        b=pR0t5In5+CZ4kfVHq+v8E2Vx3SATMWtjgfIqgT2Y2nKvjxgTue4QBkvuwq08i8a7s0
         8Ae+o0Ra8vqFxyPhVUGFeAtrU2OISV1e8BD7Du5QcUHl9zIM/JrBaVYTN6/EJeEgdNTr
         syLyjqM/YczAakn3+xygQ+Thje24ZgiZHFnoLAnC9IxvcUBE6rMYoEF+oC+JVL+K32cF
         FWUIzjCkqjG/Q4S1DH0EEo2eERgkWq09qIu+uVNr6MLENkSpnahAqIN9hXLUsYU9QMr1
         DzKJM8tubaPY3VqMh1ajzRF2ormbQDTus8Qej43CgZDlsy5MVktvB6ASeDh+mcSTAU0V
         qn/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=get+Zf53;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=cPpvm2vj;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id n9si11183pjp.2.2021.02.22.10.43.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 10:43:25 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11MIQA1O160898;
	Mon, 22 Feb 2021 18:43:07 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by userp2130.oracle.com with ESMTP id 36tsuqvr1g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 22 Feb 2021 18:43:07 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11MIeKxO186844;
	Mon, 22 Feb 2021 18:43:06 GMT
Received: from nam02-bl2-obe.outbound.protection.outlook.com (mail-bl2nam02lp2056.outbound.protection.outlook.com [104.47.38.56])
	by aserp3030.oracle.com with ESMTP id 36v9m3me0x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 22 Feb 2021 18:43:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=O5+5ngeAlg0dix41mo+nBBTCCSVd+gOut8aEe/N42B/h0e0cLddimiyGUxxUo9gYkqHCA98drRJkUUMZIAJVWj1YxjvQvslAZzW7awWWaWnaqcAo0ReTXtU5SWnxNBFrc2q5QXP64wqOsZOQau7X/ENTmOWWaH9I+bykv9UD56nXC6vUs7LNtjcb9H6+gIUvcfj2R4nAO5GFO8R0A1c855xd/Nzw6YPxVQr6WbJmibc22kxXk1fgItbr40Jqx2Vpjjyj6cVGY1/ojxVJbT++TIyRSnAT8K7OhyzJbONYyLhUoPcBUYK9l5Vjb5+o1mDPYiR58I01/KV3vbCS1EppvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=CVdGajCLMI2+3gzgx3h0ZAYJOFhSDO7t9stTQZiF0Gk=;
 b=EXX6j25YB+gZGxpj9udKswbxnVDbhNXgpsOEyIbE1TQN/vM9qgNBy52Mi+8PILd3L4ft8MFSCVUmi+YMW8JT5/vddBemphBULOHDbHmyGix4eNkUJWP0XeglySLBsgP7hUY7QHjC8K+qnNCyswPxrQMZwn0oAR2frT7AHCl560L7+SUrA9VsoV7vVO+Bc7/w++tHkmeDl+YJ7hNmNgNDxMW+j4WVp0BqzU2yP/gmCCiuCejvm/5vmvAbug4jOj9PrGpW28ifoJNFYeJ63bvTxYNzogD6SGSNi5f7znFKBUariRrYTgF9Zbl4HeeAfdw1Yju4xObJT7ddYzPT4lLtWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DS7PR10MB5343.namprd10.prod.outlook.com (2603:10b6:5:3b0::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.32; Mon, 22 Feb
 2021 18:43:03 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.032; Mon, 22 Feb 2021
 18:43:03 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
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
        Dhaval Giani <dhaval.giani@oracle.com>,
        Mike Rapoport <rppt@linux.ibm.com>
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
Date: Mon, 22 Feb 2021 13:42:56 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: SJ0PR03CA0182.namprd03.prod.outlook.com
 (2603:10b6:a03:2ef::7) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by SJ0PR03CA0182.namprd03.prod.outlook.com (2603:10b6:a03:2ef::7) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.27 via Frontend Transport; Mon, 22 Feb 2021 18:43:00 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 93b99620-8681-44fb-9060-08d8d761afde
X-MS-TrafficTypeDiagnostic: DS7PR10MB5343:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DS7PR10MB534373C63E01D79B00D2AF47E6819@DS7PR10MB5343.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 9ZzdN2NPj2jy8gd1pNRN/dDrFaQx9S613Lhp8gZfqcCQuI/3p3KqStnq3hoK+MaTBBhBTEATNwPRrFgcp9mOgrnbioqpoRqn9dfuo/y9y7R7MiVKEh4eituyW2swBC7IKO8VRhY1Dov1VLB6gqwkQafFx4Tk+b4pTrz6lftcIIghFu9qAvBvHdwZCaZfYzl2CSDtXx71NBxqcuwDOqnM+SmQFsqmEcq+2Uw1uKLyETCPCQbZ/3Z5FHda9hmK7eskfbZeO1Rm5B+gImy4o7o7H3AqFQa4CppDfmwMqlOek+CNIavkO8bmjwnXn4XTghGeqcL/TEj87/2nRcZGlgJHt9U0Kn/bQkMatSDN+OCTSsNHO6Uqn3ktVLJ8bRnaAkOX/9YzFQ7Id/dAwnB5zsYUbYaoZ6lTc33LlVi+BhiElC0QQsc7DL7F+J2fx5mqyCKnXA3Njp39g/QqK3g6DdlmVYckdZW0ZpPMCJgmRt2nzOs6TGNE8hck7qu6eXSa4WYUIOCJSHWIYeDLMhuaaA5XUud88Vv4uuc8u/iJaR2oxhW0JT4fyOqkbxc81Cy00ZzGSZVTqHqrIJP8PfVSfFL5l9+s7A7xnBnDCUKq2DDR5je2M/ctDLufz2GVfllTzfo4AUI8TVZ2M+H9aBkyoCes4uUxYMw2Pn63uuF0ouMTBjaV7usJ/wEK/GfzWkaDokWbm1BZGYjd0G6UnHHyHmBYhA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(366004)(346002)(396003)(136003)(39860400002)(376002)(30864003)(4326008)(2906002)(7416002)(36756003)(86362001)(83380400001)(66556008)(8936002)(45080400002)(8676002)(6666004)(31686004)(2616005)(44832011)(956004)(966005)(6486002)(110136005)(316002)(54906003)(31696002)(16576012)(478600001)(16526019)(26005)(5660300002)(186003)(36916002)(66946007)(53546011)(66476007)(21314003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?RHBCME1SR2RYeWVvQXg4VHRWajZqYTFvOWw3RDF1eGVrT2ZJYTNQbFMwZnkx?=
 =?utf-8?B?NzN6QzVmbUJJTGpPcnJwdllQc3JWdzhnRHh3TkZxQnJuVUJVNHVQdVBiS2pX?=
 =?utf-8?B?WmJjbys3L0VqZlJqVWZVSUFSOE1SYk53akhMK0pNSjA4R3VHaUN0bmhPQnhn?=
 =?utf-8?B?Qk5ZYkFHZkFxdTV6bTJaQWQyTDhzKzRpdTVSNERkSFozc29TSVNpTVJHS0ND?=
 =?utf-8?B?Y2FTaDNkSk1vMVVGTVRCd0QwZDhCcnEzUS9tTm1xWEJTVzJ6Ry91MXN0K0px?=
 =?utf-8?B?R3lXVi93R3psd2dtNEtTTHNQK3JKRnZFNmdEeGRycWZTWkQrc0xEZEhFVUxo?=
 =?utf-8?B?SFNXMlVRT3Y4S1JoclNSWE0zR2I4U3JFTXV2R1hFUlhoSi8zM3hiQTRzUmty?=
 =?utf-8?B?YkVZNXBxdFlldzJERW9JTmVqeGVETlFQdWRxay9WQjNjUGpQVmFqZm5aM1Vh?=
 =?utf-8?B?ODhvTXdTUFhXcFIvYlVKVnNkTFJNL0NlTllLVUJRTTNLT0NnaU5HOXZXc245?=
 =?utf-8?B?UWZJcVVBcTJFS0cxc0dndnpFVk1ERURPSXdBeVI3QjZianAxeHl5UlhmSzVZ?=
 =?utf-8?B?QWJoeWREV0xOdnFHYkRLOVV3bkpKeFhoMEtwS05xNVNCMkxrdnNKbUpJblpX?=
 =?utf-8?B?Rk5adWl0WTlXK29sQXZhNDJaU3A0OEhMVTlWRGxORFp5dzBabVFRK3Q1b0tF?=
 =?utf-8?B?Znc2RytmeFNYbVVQNjlXbEJCUk1hUHpRK0JFblJBZWV6RkVNS1gvQkp2NGpL?=
 =?utf-8?B?a2JxZW9HaHBNd3VVU1hqcGx5eFF0K0JtNEFWSzJIMlp2Tm4ySXI0aTVEUjN1?=
 =?utf-8?B?WGdKOThMTkZCU2dnREtyR1Z3endiNUxjNTlRU3MrU1hvRTBYelpxclp4cHdY?=
 =?utf-8?B?RkNDd0dGamlZOG1NM0cyZ2IxeG1hMk5JRTlpdkdOTkVHV0lmSXBPZ0RxZElk?=
 =?utf-8?B?UFgwM2Nxc0ZPcjB6a1U3bk5yQmVnTVdvR3VuUHdaZG1Vb1F1bjVTbmRnRnQ0?=
 =?utf-8?B?N2lxSnZUaWJGYzFUNUFLdUt0YlAwQ3BtNUM1Uk5lRTNTOTdoZnZjK3JxVndO?=
 =?utf-8?B?ZlpjMUNWakw4bFU0RVc1OVNuUUhIWURPelg5S3RNTXcwdU9QZVVPcXpoSnVD?=
 =?utf-8?B?TGpPdXRTVTNLMlJkdDBEVDVhMW4rV2RkSFI5T2UwNEhPcFUyRnovTHk5QzhE?=
 =?utf-8?B?R3B4dXFCRi8xQkgwUDlhMjRXSFUwdTFnNTFqSG16cG5DNWl4STR6V1VyT1dQ?=
 =?utf-8?B?MnQ4OG5kY282VVhXL2pPTFRlRTRiZ2FneUFLUFJjd0Vmc3A2QjNyUTdWQ0Fj?=
 =?utf-8?B?aytQeHl2aG9HQUZlbkNXVnpqN0tDRHFYUGhUOE8xWnhtYjJ4VS9OaWtJeDUz?=
 =?utf-8?B?cDJPUFZkTUNickN4ZGFHZm13T1AyQ25kTXpXczJKcCtLMTBtK3BaVWRZNHNz?=
 =?utf-8?B?RHAxWHlIaEpyT0tVZFQ5WWx1MjdIQUNJanVlVlhvVWhkMlh2MVVkNVZZVTNt?=
 =?utf-8?B?alVrd1pyR2IwYncvSitkVzluTWRMWkxUYXAzQy9HeGdKc2Y3aVdFVXNHL3VE?=
 =?utf-8?B?VkdIZ29ZOXRGdStkeFNsdm9PQm0xSmFCOENPbWZhU1liTG1KcU9BbksyNmYx?=
 =?utf-8?B?T0VkZ1VOaEU4UzVJNHRkYTU1NGkzYlNqSGhYYjVOUFRWR2hwR0cyTTl6eVcx?=
 =?utf-8?B?Y1VHeG50VXlLbVJ2aWlrT2NPdnVodnEzZXVWQzRNUXowQlllbkZEUkJxMDZ5?=
 =?utf-8?Q?0snblp1Vc/hmaYRfjtlzMih+6sgE2H/s6vcAPW7?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 93b99620-8681-44fb-9060-08d8d761afde
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Feb 2021 18:43:03.7742
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 4kiz8YGUgSwVJHH33Q6ocaHHdgfRgg8blRiRneDrwooas/CPMQ6NcGg1g+85R9//ImESBoTcfASWXEcA39vE+Ahr36c2k5qI43M6GNF0rmc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB5343
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9903 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 adultscore=0
 suspectscore=0 mlxlogscore=999 mlxscore=0 spamscore=0 bulkscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102220164
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9903 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 spamscore=0
 priorityscore=1501 impostorscore=0 bulkscore=0 mlxscore=0 malwarescore=0
 clxscore=1011 phishscore=0 mlxlogscore=999 lowpriorityscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102220163
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=get+Zf53;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=cPpvm2vj;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
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



On 2/22/2021 11:13 AM, David Hildenbrand wrote:
> On 22.02.21 16:13, George Kennedy wrote:
>>
>>
>> On 2/22/2021 4:52 AM, David Hildenbrand wrote:
>>> On 20.02.21 00:04, George Kennedy wrote:
>>>>
>>>>
>>>> On 2/19/2021 11:45 AM, George Kennedy wrote:
>>>>>
>>>>>
>>>>> On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
>>>>>> On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
>>>>>> <george.kennedy@oracle.com> wrote:
>>>>>>>
>>>>>>>
>>>>>>> On 2/18/2021 3:55 AM, David Hildenbrand wrote:
>>>>>>>> On 17.02.21 21:56, Andrey Konovalov wrote:
>>>>>>>>> During boot, all non-reserved memblock memory is exposed to the
>>>>>>>>> buddy
>>>>>>>>> allocator. Poisoning all that memory with KASAN lengthens boot
>>>>>>>>> time,
>>>>>>>>> especially on systems with large amount of RAM. This patch makes
>>>>>>>>> page_alloc to not call kasan_free_pages() on all new memory.
>>>>>>>>>
>>>>>>>>> __free_pages_core() is used when exposing fresh memory during
>>>>>>>>> system
>>>>>>>>> boot and when onlining memory during hotplug. This patch adds=20
>>>>>>>>> a new
>>>>>>>>> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok()
>>>>>>>>> through
>>>>>>>>> free_pages_prepare() from __free_pages_core().
>>>>>>>>>
>>>>>>>>> This has little impact on KASAN memory tracking.
>>>>>>>>>
>>>>>>>>> Assuming that there are no references to newly exposed pages
>>>>>>>>> before they
>>>>>>>>> are ever allocated, there won't be any intended (but buggy)
>>>>>>>>> accesses to
>>>>>>>>> that memory that KASAN would normally detect.
>>>>>>>>>
>>>>>>>>> However, with this patch, KASAN stops detecting wild and large
>>>>>>>>> out-of-bounds accesses that happen to land on a fresh memory page
>>>>>>>>> that
>>>>>>>>> was never allocated. This is taken as an acceptable trade-off.
>>>>>>>>>
>>>>>>>>> All memory allocated normally when the boot is over keeps getting
>>>>>>>>> poisoned as usual.
>>>>>>>>>
>>>>>>>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>>>>>>>> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>>>>>>>> Not sure this is the right thing to do, see
>>>>>>>>
>>>>>>>> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@ora=
cle.com=20
>>>>>>>>
>>>>>>>>
>>>>>>>>
>>>>>>>>
>>>>>>>> Reversing the order in which memory gets allocated + used during
>>>>>>>> boot
>>>>>>>> (in a patch by me) might have revealed an invalid memory access
>>>>>>>> during
>>>>>>>> boot.
>>>>>>>>
>>>>>>>> I suspect that that issue would no longer get detected with your
>>>>>>>> patch, as the invalid memory access would simply not get detected.
>>>>>>>> Now, I cannot prove that :)
>>>>>>> Since David's patch we're having trouble with the iBFT ACPI table,
>>>>>>> which
>>>>>>> is mapped in via kmap() - see acpi_map() in "drivers/acpi/osl.c".
>>>>>>> KASAN
>>>>>>> detects that it is being used after free when ibft_init() accesses
>>>>>>> the
>>>>>>> iBFT table, but as of yet we can't find where it get's freed (we've
>>>>>>> instrumented calls to kunmap()).
>>>>>> Maybe it doesn't get freed, but what you see is a wild or a large
>>>>>> out-of-bounds access. Since KASAN marks all memory as freed=20
>>>>>> during the
>>>>>> memblock->page_alloc transition, such bugs can manifest as
>>>>>> use-after-frees.
>>>>>
>>>>> It gets freed and re-used. By the time the iBFT table is accessed by
>>>>> ibft_init() the page has been over-written.
>>>>>
>>>>> Setting page flags like the following before the call to kmap()
>>>>> prevents the iBFT table page from being freed:
>>>>
>>>> Cleaned up version:
>>>>
>>>> diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
>>>> index 0418feb..8f0a8e7 100644
>>>> --- a/drivers/acpi/osl.c
>>>> +++ b/drivers/acpi/osl.c
>>>> @@ -287,9 +287,12 @@ static void __iomem=20
>>>> *acpi_map(acpi_physical_address
>>>> pg_off, unsigned long pg_sz)
>>>>
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
>>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_pa=
ge(pfn);
>>>> +
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz > P=
AGE_SIZE)
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=
=C2=A0 return NULL;
>>>> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)=
kmap(pfn_to_page(pfn));
>>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
>>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)=
kmap(page);
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 } else
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_o=
s_ioremap(pg_off, pg_sz);
>>>> =C2=A0=C2=A0 =C2=A0}
>>>> @@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_address
>>>> pg_off, void __iomem *vaddr)
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>>>
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>>>> -=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
>>>> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn));
>>>> -=C2=A0=C2=A0=C2=A0 else
>>>> +=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
>>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_pa=
ge(pfn);
>>>> +
>>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
>>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
>>>> +=C2=A0=C2=A0=C2=A0 } else
>>>> =C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(vaddr=
);
>>>> =C2=A0=C2=A0 =C2=A0}
>>>>
>>>> David, the above works, but wondering why it is now necessary.=20
>>>> kunmap()
>>>> is not hit. What other ways could a page mapped via kmap() be=20
>>>> unmapped?
>>>>
>>>
>>> Let me look into the code ... I have little experience with ACPI
>>> details, so bear with me.
>>>
>>> I assume that acpi_map()/acpi_unmap() map some firmware blob that is
>>> provided via firmware/bios/... to us.
>>>
>>> should_use_kmap() tells us whether
>>> a) we have a "struct page" and should kmap() that one
>>> b) we don't have a "struct page" and should ioremap.
>>>
>>> As it is a blob, the firmware should always reserve that memory region
>>> via memblock (e.g., memblock_reserve()), such that we either
>>> 1) don't create a memmap ("struct page") at all (-> case b) )
>>> 2) if we have to create e memmap, we mark the page PG_reserved and
>>> =C2=A0=C2=A0=C2=A0 *never* expose it to the buddy (-> case a) )
>>>
>>>
>>> Are you telling me that in this case we might have a memmap for the HW
>>> blob that is *not* PG_reserved? In that case it most probably got
>>> exposed to the buddy where it can happily get allocated/freed.
>>>
>>> The latent BUG would be that that blob gets exposed to the system like
>>> ordinary RAM, and not reserved via memblock early during boot.
>>> Assuming that blob has a low physical address, with my patch it will
>>> get allocated/used a lot earlier - which would mean we trigger this
>>> latent BUG now more easily.
>>>
>>> There have been similar latent BUGs on ARM boards that my patch
>>> discovered where special RAM regions did not get marked as reserved
>>> via the device tree properly.
>>>
>>> Now, this is just a wild guess :) Can you dump the page when mapping
>>> (before PageReserved()) and when unmapping, to see what the state of
>>> that memmap is?
>>
>> Thank you David for the explanation and your help on this,
>>
>> dump_page() before PageReserved and before kmap() in the above patch:
>>
>> [=C2=A0=C2=A0=C2=A0 1.116480] ACPI: Core revision 20201113
>> [=C2=A0=C2=A0=C2=A0 1.117628] XXX acpi_map: about to call kmap()...
>> [=C2=A0=C2=A0=C2=A0 1.118561] page:ffffea0002f914c0 refcount:0 mapcount:=
0
>> mapping:0000000000000000 index:0x0 pfn:0xbe453
>> [=C2=A0=C2=A0=C2=A0 1.120381] flags: 0xfffffc0000000()
>> [=C2=A0=C2=A0=C2=A0 1.121116] raw: 000fffffc0000000 ffffea0002f914c8 fff=
fea0002f914c8
>> 0000000000000000
>> [=C2=A0=C2=A0=C2=A0 1.122638] raw: 0000000000000000 0000000000000000 000=
00000ffffffff
>> 0000000000000000
>> [=C2=A0=C2=A0=C2=A0 1.124146] page dumped because: acpi_map pre SetPageR=
eserved
>>
>> I also added dump_page() before unmapping, but it is not hit. The
>> following for the same pfn now shows up I believe as a result of setting
>> PageReserved:
>>
>> [=C2=A0=C2=A0 28.098208] BUG:Bad page state in process mo dprobe pfn:be4=
53
>> [=C2=A0=C2=A0 28.098394] page:ffffea0002f914c0 refcount:0 mapcount:0
>> mapping:0000000000000000 index:0x1 pfn:0xbe453
>> [=C2=A0=C2=A0 28.098394] flags: 0xfffffc0001000(reserved)
>> [=C2=A0=C2=A0 28.098394] raw: 000fffffc0001000 dead000000000100 dead0000=
00000122
>> 0000000000000000
>> [=C2=A0=C2=A0 28.098394] raw: 0000000000000001 0000000000000000 00000000=
ffffffff
>> 0000000000000000
>> [=C2=A0=C2=A0 28.098394] page dumped because: PAGE_FLAGS_CHECK_AT_PREP f=
lag(s) set
>> [=C2=A0=C2=A0 28.098394] page_owner info is not present (never set?)
>> [=C2=A0=C2=A0 28.098394] Modules linked in:
>> [=C2=A0=C2=A0 28.098394] CPU: 2 PID: 204 Comm: modprobe Not tainted=20
>> 5.11.0-3dbd5e3 #66
>> [=C2=A0=C2=A0 28.098394] Hardware name: QEMU Standard PC (i440FX + PIIX,=
 1996),
>> BIOS 0.0.0 02/06/2015
>> [=C2=A0=C2=A0 28.098394] Call Trace:
>> [=C2=A0=C2=A0 28.098394]=C2=A0 dump_stack+0xdb/0x120
>> [=C2=A0=C2=A0 28.098394]=C2=A0 bad_page.cold.108+0xc6/0xcb
>> [=C2=A0=C2=A0 28.098394]=C2=A0 check_new_page_bad+0x47/0xa0
>> [=C2=A0=C2=A0 28.098394]=C2=A0 get_page_from_freelist+0x30cd/0x5730
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? __isolate_free_page+0x4f0/0x4f0
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? init_object+0x7e/0x90
>> [=C2=A0=C2=A0 28.098394]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? __alloc_pages_slowpath.constprop.103+0x=
2110/0x2110
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
>> [=C2=A0=C2=A0 28.098394]=C2=A0 alloc_pages_vma+0xe2/0x560
>> [=C2=A0=C2=A0 28.098394]=C2=A0 do_fault+0x194/0x12c0
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 28.098394]=C2=A0 __handle_mm_fault+0x1650/0x26c0
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? copy_page_range+0x1350/0x1350
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 28.098394]=C2=A0 handle_mm_fault+0x1f9/0x810
>> [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
>> [=C2=A0=C2=A0 28.098394]=C2=A0 do_user_addr_fault+0x6f7/0xca0
>> [=C2=A0=C2=A0 28.098394]=C2=A0 exc_page_fault+0xaf/0x1a0
>> [=C2=A0=C2=A0 28.098394]=C2=A0 asm_exc_page_fault+0x1e/0x30
>> [=C2=A0=C2=A0 28.098394] RIP: 0010:__clear_user+0x30/0x60
>
> I think the PAGE_FLAGS_CHECK_AT_PREP check in this instance means that=20
> someone is trying to allocate that page with the PG_reserved bit set.=20
> This means that the page actually was exposed to the buddy.
>
> However, when you SetPageReserved(), I don't think that PG_buddy is=20
> set and the refcount is 0. That could indicate that the page is on the=20
> buddy PCP list. Could be that it is getting reused a couple of times.
>
> The PFN 0xbe453 looks a little strange, though. Do we expect ACPI=20
> tables close to 3 GiB ? No idea. Could it be that you are trying to=20
> map a wrong table? Just a guess.
>
>>
>> What would be=C2=A0 the correct way to reserve the page so that the abov=
e
>> would not be hit?
>
> I would have assumed that if this is a binary blob, that someone=20
> (which I think would be acpi code) reserved via memblock_reserve()=20
> early during boot.
>
> E.g., see drivers/acpi/tables.c:acpi_table_upgrade()->memblock_reserve().

acpi_table_upgrade() gets called, but bails out before=20
memblock_reserve() is called. Thus, it appears no pages are getting=20
reserved.

 =C2=A0=C2=A0=C2=A0 503 void __init acpi_table_upgrade(void)
 =C2=A0=C2=A0=C2=A0 504 {
 =C2=A0=C2=A0=C2=A0 505=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 voi=
d *data;
 =C2=A0=C2=A0=C2=A0 506=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 siz=
e_t size;
 =C2=A0=C2=A0=C2=A0 507=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int=
 sig, no, table_nr =3D 0, total_offset =3D 0;
 =C2=A0=C2=A0=C2=A0 508=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 lon=
g offset =3D 0;
 =C2=A0=C2=A0=C2=A0 509=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 str=
uct acpi_table_header *table;
 =C2=A0=C2=A0=C2=A0 510=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 cha=
r cpio_path[32] =3D "kernel/firmware/acpi/";
 =C2=A0=C2=A0=C2=A0 511=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 str=
uct cpio_data file;
 =C2=A0=C2=A0=C2=A0 512
 =C2=A0=C2=A0=C2=A0 513=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if=
=20
(IS_ENABLED(CONFIG_ACPI_TABLE_OVERRIDE_VIA_BUILTIN_INITRD)) {
 =C2=A0=C2=A0=C2=A0 514=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 data =3D __initramfs_start;
 =C2=A0=C2=A0=C2=A0 515=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 size =3D __initramfs_size;
 =C2=A0=C2=A0=C2=A0 516=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } e=
lse {
 =C2=A0=C2=A0=C2=A0 517=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 data =3D (void *)initrd_start=
;
 =C2=A0=C2=A0=C2=A0 518=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 size =3D initrd_end - initrd_=
start;
 =C2=A0=C2=A0=C2=A0 519=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0 520
 =C2=A0=C2=A0=C2=A0 521=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if =
(data =3D=3D NULL || size =3D=3D 0)
 =C2=A0=C2=A0=C2=A0 522=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
 =C2=A0=C2=A0=C2=A0 523
 =C2=A0=C2=A0=C2=A0 524=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for=
 (no =3D 0; no < NR_ACPI_INITRD_TABLES; no++) {
 =C2=A0=C2=A0=C2=A0 525=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 file =3D find_cpio_data(cpio_=
path, data, size,=20
&offset);
 =C2=A0=C2=A0=C2=A0 526=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!file.data)
 =C2=A0=C2=A0=C2=A0 527=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 break;
...
 =C2=A0=C2=A0=C2=A0 563=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 all_tables_size +=3D table->l=
ength;
 =C2=A0=C2=A0=C2=A0 564=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_initrd_files[table_nr].d=
ata =3D file.data;
 =C2=A0=C2=A0=C2=A0 565=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_initrd_files[table_nr].s=
ize =3D file.size;
 =C2=A0=C2=A0=C2=A0 566=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 table_nr++;
 =C2=A0=C2=A0=C2=A0 567=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0 568=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if =
(table_nr =3D=3D 0)
 =C2=A0=C2=A0=C2=A0 569=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return; =C2=A0=C2=A0=C2=A0 =
=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=
 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 <--=20
bails out here
"drivers/acpi/tables.c"

George

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/cb8564e8-3535-826b-2d42-b273a0d793fb%40oracle.com.
