Return-Path: <kasan-dev+bncBCX7RK77SEDBBOEGTKAQMGQEU2USNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 36B73319FE6
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 14:31:38 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id p19sf6670336plr.22
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 05:31:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1613136696; cv=pass;
        d=google.com; s=arc-20160816;
        b=clyqpse/7zQZCM0OKCLYwY9uXWwtITTGXqpwdWL1DSf6xFbDdi3QluR2IcNnF6zWC+
         GmVol/RYb2+mTao1G25ENYL5EucI69V3SLyE1oGLV711lVVfaoGNgewzemRwGsmTpBZH
         8dDnaQwUQ4Y9K3b+kZiW11p0fe8jiPaT4MlyewJsLOLwEuL0T/ptkeWsiAigAgJVJcPb
         88F7un1gSRsuMkGms6PCEUuvFaMG1HNdQly/56Xdkfx8zy2FUNgqZn0XxdPfEs7fPvTr
         JgGf4gvZoaUBch8dqARLYClumrPwnjNLe3dl0CYDYXtOpXX65mIbQV7fVJAmzKomaDWf
         6DKw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:references:cc:to:from:subject:sender:dkim-signature;
        bh=Y4IQiVx9gAyga4pTP9cCuJscktkqlP9WOZTBRe90qvA=;
        b=xBqqIkf2j7ftnv0l7s19tEe4DTnGrS9r1SYOuJpcCeDkjjsmdIQ3x9neImqMyrNtSg
         zjY7LJdU4ZCp1kyj+fka2krpeREY7wB7dsMwUVSkue46AqOckpMP6W7o+UbvKGqWnUmc
         zW9rGR22sFkKAbfr2VmZaj+5awAiA417cHTQVX+xIFQwBFLzSliuTiBpsklVMxrRbgPS
         xkH+tUAjz58emmbWnECQwgDCBqgfSaGDKxg8VWdYXAq85FpOCmnTj3ioVNujrhZDL+9g
         g71CxarzzhTLHXa2oMxuuIa5xTc9o6ZoWFXeCnGj1UyIpz6iQxUOBdIi+JksW+2qWBH6
         TwJw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=GpoCiNZN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hfoY1s4S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y4IQiVx9gAyga4pTP9cCuJscktkqlP9WOZTBRe90qvA=;
        b=EYWlmtE+DnGsyytRAK/OXlg0ZNsH/SffpOW+Wi0PeOb5y9f9rs49qdwpdl0f3GVeT6
         vOU4M2mWtWyiME0/2WbSIgRD0ow4I1byLvdi8R/sPQINABOVU4dCDTkhZ6XR4NkeXZvh
         HF+1esURqW61BwYPLtFZUVkG0UfEHoiPk3/eIBivSoN6Vj64rCBZXy0iOpKRHv5bUe+i
         etLuBTNaav4hLd2OFwQnadXZhN1LtVF+zfKtlN0ekBKVZ/+OB6BY3rAco4RtX9IQwGyS
         rDOBpNVtS4gGwUdqLBNHpwDDVHBbWXLMmqDUKXav9jl8YafmAciKKS6hRaGErvMqic4I
         I90w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y4IQiVx9gAyga4pTP9cCuJscktkqlP9WOZTBRe90qvA=;
        b=SsNUxg2MXSfn0J+R+Nq0Vs7bFl02wB5dKj+O8wgQ4vx2Eprm14SmKJq6tCTi0ucTPl
         LoTNWuJ5nvJAiD0QHqtEb05D+OW+waHL9CKpvzVCZU7qKorcLgsdMKsdwNn3j1laWBhg
         4z1HHNGfz56vs0DyzpsD5c8CoRhrP0rpqvcU3UJFBWRHECoXW2KeeWr6ruEmHlFeaove
         ZBTTaUl1zZq9APOGwyxnpQZiKOi16+P9pT8EnPnJFT6uNRwgaEWf06aB8yJ+Tt402wMK
         lyO2SYd3KvUpF1YPeEae7OubDZoXlKcTB1vakVq8k1XBARBOB4MOhgaoYZrMbceAoqVk
         58vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Kkyy3CVGseaKG2XUMkTHHwF1xxvx8WEGqTAqrjLHIDNghfZKm
	5ZH77vOrDvlUH2qo+5PkKHI=
X-Google-Smtp-Source: ABdhPJzQbYDzVvzK8CY41NeqMAO/+hQ2zWBAGBHEaY/WEPxPilcDX5Qc8uqDyt0JvO/hh7TpAPQvfw==
X-Received: by 2002:a63:574b:: with SMTP id h11mr3137981pgm.25.1613136696770;
        Fri, 12 Feb 2021 05:31:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8d53:: with SMTP id s19ls3498533pfe.7.gmail; Fri, 12 Feb
 2021 05:31:36 -0800 (PST)
X-Received: by 2002:aa7:8598:0:b029:1dd:9cb4:37ee with SMTP id w24-20020aa785980000b02901dd9cb437eemr2920586pfn.54.1613136696137;
        Fri, 12 Feb 2021 05:31:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613136696; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vp0VbCtnhFfvSNY7qygyYVmjcQyg8sosFyKdMFG80v4uwgc9po3SgoagiuqRYfC+fo
         mKFI4uWuwXdCn/nUp5jeSY/rvNM5X3fCk9uOQEChp4rmmwkFRDoBXMIwcMA3G6YTLluj
         QwraZ0b7BpVJnIuxQWyArqZPqWt8Bnciy1Y7twd6JqGiMt2Hh/jufQNj7J/venQkV9S+
         x4p+YgfNepMUPnqxQFy+Ey2NE3pemrdgXBiBtQD05WzDHFDWkRoqrI8QxVurlP6jCl4O
         sK9vn8T52JTxE+eo0Ei9I3cDZyWTrwLyGyWcrbXMIzSLEfT/PpTJ6uoIV3P1zOoA+/fW
         biHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:references:cc:to:from
         :subject:dkim-signature:dkim-signature;
        bh=VAiL+WbAaswHZESk33R9Yy1FkBuLaLCxpl7+HeAkh6A=;
        b=Z+o9LtxU1TSI8svlCVlcnRVcSJLJaL+kp3XH6KtUg4iDnhmdTkwggnYbH2m6RLSfeY
         vE9aI2PRYC4/lpdP6Q+hLvxNdrX0vSgTTOKKmOqM0JPeRtXetS1WywopHeJVnjNW9sic
         cUIrVPkzZoml5j9xbEXUsPaPymTPD344t20ZEzY7AE9jQlIWAmbKuBDwTYSOOco74MxR
         evlm7cqSMHpgnOgrbEJWLX9vUftOBg9Fn2mGhNw+8TJEgM/VASowKpVH3SJ5GchBD2oc
         DHxIxc2GGXbLgornVO9Sh55EfewGHRHWcV+rto1Z8UIs5fhR9yECp+UnDf/xEfXwFcQX
         ksmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=GpoCiNZN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hfoY1s4S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id v7si456219pgs.2.2021.02.12.05.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 05:31:36 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11CDTO6w169070;
	Fri, 12 Feb 2021 13:31:21 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by aserp2120.oracle.com with ESMTP id 36m4uq1qv2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Feb 2021 13:31:21 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11CDVFBG086888;
	Fri, 12 Feb 2021 13:31:20 GMT
Received: from nam02-sn1-obe.outbound.protection.outlook.com (mail-sn1nam02lp2054.outbound.protection.outlook.com [104.47.36.54])
	by userp3030.oracle.com with ESMTP id 36j521gasu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Feb 2021 13:31:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=kkX6jJEwVckMFBYEbHcqyQiUHTB6SgyKZ+X7/ThpwQD1cB7ARqcbapPuBzHF5Rq+CSCRJCkLTiv6Dg/bTeFzOgrxanTdZoiASLh0xZ01DJ7oSUIekLEgu6tCKZ9D+DzONBZDr25IHoCTwNIqby6blaYZJQs0SXGT7cqRfS49BYLfGVP1ac3S40vH+NRuq5Syi+h5uy0kA5x8/LW1yLx9aT8yc4LuFFzVzN0TnBRYz8B8Xdo1p/sfFXiUTM8GdjRIhSPs9Sm2LKEW56QNP4ns0pO4D6im9OK1Moodkspdn8Mwb3L6vOFCbjeREMY2bCcIuPHA65GE28sTgBMmwzaBPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=VAiL+WbAaswHZESk33R9Yy1FkBuLaLCxpl7+HeAkh6A=;
 b=e2gulh0MAnaEPHi3uIkJ8Ez8qKMhbVG/L8kxbq4eG0I5inD7nFBtbzxuE5c/oQEcG5JLNQC3B3cY6vrwp48seJ0bnHvMzhXkfzqJXrzYcAUxYCPfk1qno83u7GyQuP7NfViiuxmhUm2PZ8gGTpv8Dt4TWuGmnVkag1VX4o2Nzes2nbaVy6Fwz3Zm6BUfF+NCmn6CqDJd6OtHmAd8U0h04cc+NL08YXUASW0K08rVDlSrQu238aYYU51zewbiSYj3pkd3/5nAIu+5dUXh8bzTh30XhEEU2Og0N6SpWMmsWq02MlkJMd7T3Q/nPW81/o/J7tpB6d9BS44/QhrMhCmI7g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB3113.namprd10.prod.outlook.com (2603:10b6:5:1a7::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3846.25; Fri, 12 Feb
 2021 13:31:00 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3846.027; Fri, 12 Feb 2021
 13:31:00 +0000
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in
 ibft_init()
From: George Kennedy <george.kennedy@oracle.com>
To: Dmitry Vyukov <dvyukov@google.com>,
        Konrad Rzeszutek Wilk <konrad@darnok.org>
Cc: "Rafael J. Wysocki" <rjw@rjwysocki.net>,
        Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com,
        konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>,
        Dan Carpenter <dan.carpenter@oracle.com>,
        Dhaval Giani <dhaval.giani@oracle.com>, david@redhat.com
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
 <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
 <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com>
 <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
 <20210203192856.GA324708@fedora>
 <CACT4Y+bscZGpMK-UXXzeFDeJtGYt-royR_=iTzTmBrwe3wOmTw@mail.gmail.com>
 <14124734-326e-87b3-a04a-b7190f1e1282@oracle.com>
Organization: Oracle Corporation
Message-ID: <bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com>
Date: Fri, 12 Feb 2021 08:30:53 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.1
In-Reply-To: <14124734-326e-87b3-a04a-b7190f1e1282@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: BYAPR05CA0061.namprd05.prod.outlook.com
 (2603:10b6:a03:74::38) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.222] (108.20.187.119) by BYAPR05CA0061.namprd05.prod.outlook.com (2603:10b6:a03:74::38) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.12 via Frontend Transport; Fri, 12 Feb 2021 13:30:58 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 04c4e0b3-e9bc-4a1d-bb7f-08d8cf5a6fb1
X-MS-TrafficTypeDiagnostic: DM6PR10MB3113:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB3113D5344F7B1F870383977EE68B9@DM6PR10MB3113.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:9508;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: DIB4lY2wo2c1bNfDzRELtG7TNYFpkLYnEgiW6B/blt8ZFAnBcUY8+gppcO7KOAiPDzFulnaLajLkEtdTEqIQUS6wSKoE2pRozB6WfD7SCLnAwulTlIYTGlppjbeZpiBuP1yiwUIGuU8V/OTXV0Smn5xxi4sBtXh+aEM6HYs5Fmo34hLUZbk4WLFq/xHYqk21bR+qAd/NGB8EOOaSfU9Ihd4RSrVWSzmRCWko1DxEZg1JhMXBbyMjDChdqRVoQGA0Ya6OViAYnvuVVOw2qxShcEDL1iZOWTUrW4LpfLa4W9RV6RwwKrCRY/fiOrd8C6o9t7c0ASlvs+wzV/JI0NYXMVjWPuWnILM8lcNuWMDuhBYRQK4rnAhQjSoCurGfcN2UEVGhZX1sVlMIe6pbDpotU+2NG7yPZfS835mpKf2h3y/rVOEVpZUhP9KorYUqbuKyK9tK5KT0mCSMomLS2MCNEFwE2KJzjwgjBDvT3VLNSkS8DGGe4ilm1kfdi4iX0/hOpjgJ/Z204Qii52hThYo1TS/ymAWBQhsros6WDWRtrhhvqUCJwfVQHEgttWN1ec1RkfERRX0YiYtGOBINdojfRxTtWiFPKu4WT/y57g0EpeS+mM6p9JRHd7t82pRihlEjg4fKxXr+UPindRNifazCJ8HPDfLAR1sRZhCRXqGC72faQHptmF84+iq9ZarFb5Mq
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(376002)(346002)(39860400002)(366004)(136003)(396003)(44832011)(26005)(316002)(66556008)(66476007)(66946007)(83380400001)(30864003)(2616005)(5660300002)(16526019)(186003)(956004)(31696002)(53546011)(54906003)(45080400002)(110136005)(478600001)(2906002)(6666004)(36916002)(4001150100001)(36756003)(966005)(16576012)(8936002)(8676002)(7416002)(86362001)(6486002)(31686004)(4326008)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?TWprbzd0NGZsaUx2WnNzdzZWM083aGVMck50NmwwZEF3ajcrb1AwMHZLeDlL?=
 =?utf-8?B?UXVseXljVlJQWUxWdC9lYXFjWmFPbkR6RVAranpvR2c2bVR6RGo5bE9vejEx?=
 =?utf-8?B?Z3NSZFhpNmtiNXhjN0tWNllPYkR3SlVjK3NZeEpjb2ZRbm1qdHA1OVZpUk1H?=
 =?utf-8?B?TzFndW1WcENUMmQrTmtPOWlGeGM4YWRsZ2M3NUw4eWZ2M3dpTUFsUjlnY3cw?=
 =?utf-8?B?Umx5cHd5bFlUZTVYa09MUDcrRGlBa1hJb0daUWZyamUrWi9RSStpTUUyTWVR?=
 =?utf-8?B?MXB3UlNycnRzOVBSOHhHZUcxOU0rUFhtZllGVUswRTVtRUJnRjBkRjE0dTVj?=
 =?utf-8?B?N0pDTnFiRS92ZFlvUnpCS3Q2OWhTdk40YklHOUQ5YVJtdndxOWtIL0tSUWV6?=
 =?utf-8?B?OTc3UnZzVm1uWnFzYU1vdSswQ2k1aGZRdWxHZ2dtVk5tcVhEU3BEcTV2L2h0?=
 =?utf-8?B?NnRaWnBSN1ZPbysyRzU0MURDUVR4SGJ0aWNXS1hjWWxZUVFtZUlIcGN1c2hT?=
 =?utf-8?B?dndXTVVIQWc0N2phMXJBaFZvY0dlMW1iR3hEUGdOWjBzUUc5aW42ZkRJSDJF?=
 =?utf-8?B?RXJ2VVAxSEJnbEF6OWtha29zQ2RnR2tDc2MwS1B3VjB3cVB1bVJXbitDTmRP?=
 =?utf-8?B?dzhudUhTRlEzbndnS1d4KytZS2UrcWJyN2ViL3FadGVBUlhTSUtwQjZFMjVi?=
 =?utf-8?B?eWMrS2tNZ1FROGo2V3VzdkowL2Q5WHIrWS9IYXRlN0U5dXZKTmdBZ1ZreTRZ?=
 =?utf-8?B?b2EyOTBJeFM5SnpoN0szSERlVE9yRkxqS1NYRWp6dXpwUFB2SVRVVk0vaGpO?=
 =?utf-8?B?eGxobmlqSm5heFZNdjVqRVV0Zkl1OXpGK2Y3N0NwRGt0UkRFdHpRNWVEbDIz?=
 =?utf-8?B?eENPYWFXZGZxcnZYKytDVzhiT0JweGFtaG9IRnE1MituYkM0UElFWHZlb29B?=
 =?utf-8?B?RXBIQ3Z5c1R0UllWRU9YOC8vWWJGZ2RodThvdUkxSCtEWlVBeHVmL1NvRGlD?=
 =?utf-8?B?L3hWTkxQUnlBTVhZcE5IQys0Yyt0NDV4RWZUalAzTk1YM2RsNm1DTlFkUitR?=
 =?utf-8?B?c0lpYjBFaUd6c3dsNDJmdzgxcUUzeEJZUlhrdDFRZERYRWN6bHR2N2w1Uy9Y?=
 =?utf-8?B?b3FKSSs2TU4yK2FUa1ZUZUZrWEtLYVhzeWxEYlpBVWxUakdQSk1yWTRaOWhX?=
 =?utf-8?B?b2F5WUQvbThMaEN1U0tZeEl0UFgwZUllYVc0K01nQU1KVFJBY2JDdnFxMy9K?=
 =?utf-8?B?MVRIbHNDWWx1WEp0Rm5Wb2owNTNvcmNITHJrZSsvRlF6QzQxRGIzdldzb09X?=
 =?utf-8?B?WmhZNFdjN2VnbGt3SFVVWVZ0Qlloc1FFNTRHVUxBMzhKcndZdVdrd2xCdVoy?=
 =?utf-8?B?ZDlmV3hJbzY0NTMwMmtULzd5V0dHM2M4RHBOZmk0VGJESnZsbytIYmdMWVVh?=
 =?utf-8?B?VWhwR1RHQk5TYmpKSGJoS2JhVWNEWjZqZWtqdWxRdEYxZWpUbWRmemtUa1pC?=
 =?utf-8?B?a1JyZzR6TUtjTExJMzRTcEhQN0VzL1VUQlJmY2NKMWhZOXFkMGMwS2FGa3Qx?=
 =?utf-8?B?VWc2dkRsdVcyZFlwWHBJSzUzQ1FZeUdFOHg3UXRYRFp4U3ZUU2JRN3ZRVkR5?=
 =?utf-8?B?T1hZVGljYm93T2RuRlEyUWdRSzNPWGxJekVUeVY5TUFMaDJaUFRwS3NyNEdQ?=
 =?utf-8?B?MFMyMU5MaVNrVjRGNmR2QXYwa1lDVm15dklnYjhvems0VUxDUVFWQy9Bc1p3?=
 =?utf-8?Q?E2MmIHwCY+n3F/l28LqK5knPBCpjDq6gCj6BL5D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 04c4e0b3-e9bc-4a1d-bb7f-08d8cf5a6fb1
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Feb 2021 13:31:00.3298
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DH9SkalP/4Osz2OPD1T8OsPm9qHbWVDH44Ro1l9/8TBgVc7DNc0XwLLC2YB/RfPwPFn79YDsYzon13E6+9V+rcZ3rTFcfwp8DhUz5Y+KBIs=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB3113
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9892 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 spamscore=0 phishscore=0
 mlxscore=0 malwarescore=0 mlxlogscore=999 bulkscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102120105
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9892 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 priorityscore=1501 mlxscore=0
 mlxlogscore=999 spamscore=0 impostorscore=0 malwarescore=0 clxscore=1011
 suspectscore=0 adultscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102120105
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=GpoCiNZN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=hfoY1s4S;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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



On 2/10/2021 4:51 PM, George Kennedy wrote:
>
>
> On 2/3/2021 2:35 PM, Dmitry Vyukov wrote:
>> On Wed, Feb 3, 2021 at 8:29 PM Konrad Rzeszutek Wilk=20
>> <konrad@darnok.org> wrote:
>>> Hey Dmitry, Rafael, George, please see below..
>>>
>>> On Wed, Jan 27, 2021 at 10:10:07PM +0100, Dmitry Vyukov wrote:
>>>> On Wed, Jan 27, 2021 at 9:01 PM George Kennedy
>>>> <george.kennedy@oracle.com> wrote:
>>>>> Hi Dmitry,
>>>>>
>>>>> On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
>>>>>
>>>>> On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
>>>>> <konrad.wilk@oracle.com> wrote:
>>>>>
>>>>> On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
>>>>>
>>>>> During boot of kernel with CONFIG_KASAN the following KASAN false
>>>>> positive failure will occur when ibft_init() reads the
>>>>> ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
>>>>>
>>>>> The ACPI iBFT table is not allocated, and the iscsi driver uses
>>>>> a pointer to it to calculate checksum, etc. KASAN complains
>>>>> about this pointer with use-after-free, which this is not.
>>>>>
>>>>> Andrey, Alexander, Dmitry,
>>>>>
>>>>> I think this is the right way for this, but was wondering if you have
>>>>> other suggestions?
>>>>>
>>>>> Thanks!
>>>>>
>>>>> Hi George, Konrad,
>>>>>
>>>>> Please provide a sample KASAN report and kernel version to match=20
>>>>> line numbers.
>>>>>
>>>>> 5.4.17-2102.200.0.0.20210106_0000
>>>>>
>>>>> [=C2=A0=C2=A0 24.413536] iBFT detected.
>>>>> [=C2=A0=C2=A0 24.414074]
>>>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>> [=C2=A0=C2=A0 24.407342] BUG: KASAN: use-after-free in ibft_init+0x13=
4/0xb8b
>>>>> [=C2=A0=C2=A0 24.407342] Read of size 4 at addr ffff8880be452004 by t=
ask=20
>>>>> swapper/0/1
>>>>> [=C2=A0=C2=A0 24.407342]
>>>>> [=C2=A0=C2=A0 24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted=20
>>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
>>>>> [=C2=A0=C2=A0 24.407342] Hardware name: QEMU Standard PC (i440FX + PI=
IX,=20
>>>>> 1996), BIOS 0.0.0 02/06/2015
>>>>> [=C2=A0=C2=A0 24.407342] Call Trace:
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 dump_stack+0xd4/0x119
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.407342] print_address_description.constprop.6+0x20/0=
x220
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 __kasan_report.cold.9+0x37/0x77
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 kasan_report+0x14/0x1b
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 __asan_report_load_n_noabort+0xf/0x11
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? dmi_sysfs_init+0x1a5/0x1a5
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? dmi_walk+0x72/0x89
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? rvt_init_port+0x110/0x101
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 do_one_initcall+0xc3/0x44d
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? perf_trace_initcall_level+0x410/0x40=
5
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 kernel_init_freeable+0x551/0x673
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? start_kernel+0x94b/0x94b
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? __sanitizer_cov_trace_const_cmp1+0x1=
a/0x1c
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? __kasan_check_write+0x14/0x16
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? rest_init+0xe6/0xe6
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 kernel_init+0x16/0x1bd
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ? rest_init+0xe6/0xe6
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ret_from_fork+0x2b/0x36
>>>>> [=C2=A0=C2=A0 24.407342]
>>>>> [=C2=A0=C2=A0 24.407342] The buggy address belongs to the page:
>>>>> [=C2=A0=C2=A0 24.407342] page:ffffea0002f91480 refcount:0 mapcount:0=
=20
>>>>> mapping:0000000000000000 index:0x1
>>>>> [=C2=A0=C2=A0 24.407342] flags: 0xfffffc0000000()
>>>>> [=C2=A0=C2=A0 24.407342] raw: 000fffffc0000000 ffffea0002fca588=20
>>>>> ffffea0002fb1a88 0000000000000000
>>>>> [=C2=A0=C2=A0 24.407342] raw: 0000000000000001 0000000000000000=20
>>>>> 00000000ffffffff 0000000000000000
>>>>> [=C2=A0=C2=A0 24.407342] page dumped because: kasan: bad access detec=
ted
>>>>> [=C2=A0=C2=A0 24.407342]
>>>>> [=C2=A0=C2=A0 24.407342] Memory state around the buggy address:
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be451f00: ff ff ff ff ff ff ff=
 ff ff ff ff=20
>>>>> ff ff ff ff ff
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be451f80: ff ff ff ff ff ff ff=
 ff ff ff ff=20
>>>>> ff ff ff ff ff
>>>>> [=C2=A0=C2=A0 24.407342] >ffff8880be452000: ff ff ff ff ff ff ff ff f=
f ff ff=20
>>>>> ff ff ff ff ff
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be452080: ff ff ff ff ff ff ff=
 ff ff ff ff=20
>>>>> ff ff ff ff ff
>>>>> [=C2=A0=C2=A0 24.407342]=C2=A0 ffff8880be452100: ff ff ff ff ff ff ff=
 ff ff ff ff=20
>>>>> ff ff ff ff ff
>>>>> [=C2=A0=C2=A0 24.407342]
>>>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>> [=C2=A0=C2=A0 24.407342] Disabling lock debugging due to kernel taint
>>>>> [=C2=A0=C2=A0 24.451021] Kernel panic - not syncing: panic_on_warn se=
t ...
>>>>> [=C2=A0=C2=A0 24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G B=
=20
>>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
>>>>> [=C2=A0=C2=A0 24.452002] Hardware name: QEMU Standard PC (i440FX + PI=
IX,=20
>>>>> 1996), BIOS 0.0.0 02/06/2015
>>>>> [=C2=A0=C2=A0 24.452002] Call Trace:
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 dump_stack+0xd4/0x119
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x102/0xb8b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 panic+0x28f/0x6e0
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? __warn_printk+0xe0/0xe0
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? add_taint+0x68/0xb3
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? add_taint+0x68/0xb3
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 end_report+0x4c/0x54
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 __kasan_report.cold.9+0x55/0x77
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 kasan_report+0x14/0x1b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 __asan_report_load_n_noabort+0xf/0x11
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ibft_init+0x134/0xb8b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? dmi_sysfs_init+0x1a5/0x1a5
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? dmi_walk+0x72/0x89
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? rvt_init_port+0x110/0x101
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 do_one_initcall+0xc3/0x44d
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? perf_trace_initcall_level+0x410/0x40=
5
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 kernel_init_freeable+0x551/0x673
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? start_kernel+0x94b/0x94b
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? __sanitizer_cov_trace_const_cmp1+0x1=
a/0x1c
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? __kasan_check_write+0x14/0x16
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? rest_init+0xe6/0xe6
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 kernel_init+0x16/0x1bd
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ? rest_init+0xe6/0xe6
>>>>> [=C2=A0=C2=A0 24.452002]=C2=A0 ret_from_fork+0x2b/0x36
>>>>> [=C2=A0=C2=A0 24.452002] Dumping ftrace buffer:
>>>>> [=C2=A0=C2=A0 24.452002] ---------------------------------
>>>>> [=C2=A0=C2=A0 24.452002] swapper/-1=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 1.... 24564337us : rdmaip_init:=20
>>>>> 2924: rdmaip_init: Active Bonding is DISABLED
>>>>> [=C2=A0=C2=A0 24.452002] ---------------------------------
>>>>> [=C2=A0=C2=A0 24.452002] Kernel Offset: disabled
>>>>> [=C2=A0=C2=A0 24.452002] Rebooting in 1 seconds..
>>>>>
>>>>> Why does KASAN think the address is freed? For that to happen that
>>>>> memory should have been freed. I don't remember any similar false
>>>>> positives from KASAN, so this looks a bit suspicious.
>>>>>
>>>>> I'm not sure why KASAN thinks the address is freed. There are=20
>>>>> other modules where KASAN/KCOV is disabled on boot.
>>>>> Could this be for a similar reason?
>>>> Most of these files are disabled because they cause recursion in
>>>> instrumentation, or execute too early in bootstrap process (before
>>>> kasan_init).
>>>>
>>>> Somehow the table pointer in ibft_init points to a freed page. I
>>>> tracked it down to here:
>>>> https://elixir.bootlin.com/linux/v5.4.17/source/drivers/acpi/acpica/tb=
utils.c#L399=20
>>>>
>>>> but I can't find where this table_desc->pointer comes from. Perhaps it
>>> It is what the BIOS generated. It usually points to some memory
>>> location in right under 4GB and the BIOS stashes the DSDT, iBFT, and
>>> other tables in there.
>>>
>>>> uses some allocation method that's not supported by KASAN? However,
>>>> it's the only such case that I've seen, so it's a bit weird. Could it
>>>> use something like memblock_alloc? Or maybe that page was in fact
>>>> freed?... Too bad KASAN does not print free stack for pages, maybe
>>>> it's not too hard to do if CONFIG_PAGE_OWNER is enabled...
>>> Hm, there is a comment in the acpi_get_table speaking about the
>>> requirement of having a acpi_put_table and:
>>>
>>>
>>> =C2=A0 * DESCRIPTION: Finds and verifies an ACPI table. Table must be i=
n the
>>> =C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 RSDT/XSDT.
>>> =C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 Note that an early stage acpi_get_table() call must=20
>>> be paired
>>> =C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 with an early stage acpi_put_table() call.=20
>>> otherwise the table
>>> =C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 pointer mapped by the early stage mapping=20
>>> implementation may be
>>> =C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 erroneously unmapped by the late stage unmapping=20
>>> implementation
>>> =C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 in an acpi_put_table() invoked during the late stage.
>>> =C2=A0 *
>>>
>>> Which would imply that I should use acpi_put_table in the error path
>>> (see below a patch), but also copy the structure instead of depending
>>> on ACPI keeping it mapped for me. I think.
>> Hi Konrad,
>>
>> Thanks for looking into this.
>> If ACPI unmaps this page, that would perfectly explain the KASAN report.
>>
>> George, does this patch eliminate the KASAN report for you?
>
> Hi Dmitry,
>
> No luck with the patch. Tried high level bisect instead. Here are the=20
> results:
>
> BUG: KASAN: use-after-free in ibft_init+0x134/0xc49
>
> Bisect status:
> v5.11-rc6 Sun Jan 31 13:50:09 2021 -0800=C2=A0=C2=A0=C2=A0=C2=A0 Failed
> v5.11-rc1 Sun Dec 27 15:30:22 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
> v5.10 Sun Dec 13 14:41:30 2020 -0800=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 Failed
> v5.10-rc6 Sun Nov 29 15:50:50 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
> v5.10-rc5 Sun Nov 22 15:36:08 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
> v5.10-rc4 Sun Nov 15 16:44:31 2020 -0800=C2=A0=C2=A0=C2=A0 Failed
> v5.10-rc3 Sun Nov 8 16:10:16 2020 -0800=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Fai=
led
> v5.10-rc2 Sun Nov 1 14:43:52 2020 -0800=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Fai=
led
> v5.10-rc1 Sun Oct 25 15:14:11 2020 -0700=C2=A0=C2=A0=C2=A0=C2=A0 Failed
> v5.9 Sun Oct 11 14:15:50 2020 -0700=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 OK - 10 reboots so=20
> far w/o kasan failure
>
> So, will look at what changed between v5.9 and v5.10-rc1

git bisect has identified the following as the offending commit:

2020-10-16 torvalds@linux-foundation.org - 7fef431 2020-10-15 David=20
Hildenbrand mm/page_alloc: place pages to tail in __free_pages_core()

Here's the commit that follows the above:

2020-10-16 torvalds@linux-foundation.org - 293ffa5 2020-10-15 David=20
Hildenbrand mm/page_alloc: move pages to tail in move_to_free_list()

With HEAD=3D7fef431 the KASAN crash occurs.
With HEAD=3D293ffa5 no crash.

With latest upstream (HEAD=3Ddcc0b49) now getting this:

[=C2=A0=C2=A0=C2=A0 1.759763] BUG: unable to handle page fault for address:=
=20
ffff8880be453000
[=C2=A0=C2=A0=C2=A0 1.761100] #PF: supervisor read access in kernel mode
[=C2=A0=C2=A0=C2=A0 1.762106] #PF: error_code(0x0000) - not-present page
[=C2=A0=C2=A0=C2=A0 1.763114] PGD 28c01067 P4D 28c01067 PUD 13fb01067 PMD 1=
3f90e067 PTE=20
800fffff41bac060
[=C2=A0=C2=A0=C2=A0 1.764672] Oops: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN PTI
[=C2=A0=C2=A0=C2=A0 1.765731] CPU: 0 PID: 0 Comm: swapper/0 Not tainted=20
5.11.0-rc7-dcc0b49 #39
[=C2=A0=C2=A0=C2=A0 1.767103] Hardware name: QEMU Standard PC (i440FX + PII=
X, 1996),=20
BIOS 0.0.0 02/06/2015
[=C2=A0=C2=A0=C2=A0 1.768665] RIP: 0010:acpi_tb_verify_checksum=20
(drivers/acpi/acpica/tbprint.c:161)
[=C2=A0=C2=A0=C2=A0 1.773301] RSP: 0000:ffffffff8fe07c78 EFLAGS: 00010246
[=C2=A0=C2=A0=C2=A0 1.774330] RAX: 0000000000000003 RBX: ffff8880be453000 R=
CX:=20
ffffffff839ab92c
[=C2=A0=C2=A0=C2=A0 1.775718] RDX: 1ffff11017c8a600 RSI: ffffffff8fe3dec0 R=
DI:=20
0000000000000002
[=C2=A0=C2=A0=C2=A0 1.777099] RBP: ffffffff8fe07c90 R08: 0000000000000000 R=
09:=20
fffffbfff212ebfd
[=C2=A0=C2=A0=C2=A0 1.778479] R10: ffffffff90975fe7 R11: fffffbfff212ebfc R=
12:=20
0000000000000800
[=C2=A0=C2=A0=C2=A0 1.779864] R13: 0000000000000800 R14: dffffc0000000000 R=
15:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 1.781245] FS:=C2=A0 0000000000000000(0000) GS:ffff88810=
a400000(0000)=20
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A0 1.782819] CS:=C2=A0 0010 DS: 0000 ES: 0000 CR0: 0000000=
080050033
[=C2=A0=C2=A0=C2=A0 1.783941] CR2: ffff8880be453000 CR3: 0000000024e30000 C=
R4:=20
00000000000006b0
[=C2=A0=C2=A0=C2=A0 1.785325] DR0: 0000000000000000 DR1: 0000000000000000 D=
R2:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 1.786709] DR3: 0000000000000000 DR6: 00000000fffe0ff0 D=
R7:=20
0000000000000400
[=C2=A0=C2=A0=C2=A0 1.788094] Call Trace:
[=C2=A0=C2=A0=C2=A0 1.788595] acpi_tb_verify_temp_table (drivers/acpi/acpic=
a/tbdata.c:499)
[=C2=A0=C2=A0=C2=A0 1.789546] ? acpi_tb_validate_temp_table=20
(drivers/acpi/acpica/tbdata.c:469)
[=C2=A0=C2=A0=C2=A0 1.790536] ? __sanitizer_cov_trace_pc (kernel/kcov.c:197=
)
[=C2=A0=C2=A0=C2=A0 1.791474] ? write_comp_data (kernel/kcov.c:218)
[=C2=A0=C2=A0=C2=A0 1.792263] ? write_comp_data (kernel/kcov.c:218)
[=C2=A0=C2=A0=C2=A0 1.793049] ? __sanitizer_cov_trace_pc (kernel/kcov.c:197=
)
[=C2=A0=C2=A0=C2=A0 1.793983] ? write_comp_data (kernel/kcov.c:218)
[=C2=A0=C2=A0=C2=A0 1.794766] acpi_reallocate_root_table=20
(drivers/acpi/acpica/tbxface.c:182)
[=C2=A0=C2=A0=C2=A0 1.795736] ? acpi_tb_parse_root_table=20
(drivers/acpi/acpica/tbxface.c:134)
[=C2=A0=C2=A0=C2=A0 1.796706] ? write_comp_data (kernel/kcov.c:218)
[=C2=A0=C2=A0=C2=A0 1.797488] ? __sanitizer_cov_trace_pc (kernel/kcov.c:197=
)
[=C2=A0=C2=A0=C2=A0 1.798422] acpi_early_init (drivers/acpi/bus.c:1050)
[=C2=A0=C2=A0=C2=A0 1.799211] start_kernel (init/main.c:1023)
[=C2=A0=C2=A0=C2=A0 1.799955] x86_64_start_reservations (arch/x86/kernel/he=
ad64.c:526)
[=C2=A0=C2=A0=C2=A0 1.800875] x86_64_start_kernel (arch/x86/kernel/head64.c=
:507)
[=C2=A0=C2=A0=C2=A0 1.801699] secondary_startup_64_no_verify=20
(arch/x86/kernel/head_64.S:283)
[=C2=A0=C2=A0=C2=A0 1.802709] Modules linked in:
[=C2=A0=C2=A0=C2=A0 1.803324] Dumping ftrace buffer:
[=C2=A0=C2=A0=C2=A0 1.804003]=C2=A0=C2=A0=C2=A0 (ftrace buffer empty)
[=C2=A0=C2=A0=C2=A0 1.804707] CR2: ffff8880be453000
[=C2=A0=C2=A0=C2=A0 1.805369] ---[ end trace fab88542288c30b6 ]---
[=C2=A0=C2=A0=C2=A0 1.806272] RIP: 0010:acpi_tb_verify_checksum=20
(drivers/acpi/acpica/tbprint.c:161)
[ 1.807325] Code: da b8 ff ff 37 00 48 c1 e0 2a 48 c1 ea 03 8a 14 02 48=20
89 d8 83 e0 07 83 c0 03 38 d0 7c 0c 84 d2 74 08 48 89 df e8 c6 f8 1e fe=20
<44> 8b 23 bf 53 33 50 54 44 89 e6 e8 f6 84 db fd 41 81 fc 53 33 50
[=C2=A0=C2=A0=C2=A0 1.810904] RSP: 0000:ffffffff8fe07c78 EFLAGS: 00010246
[=C2=A0=C2=A0=C2=A0 1.811930] RAX: 0000000000000003 RBX: ffff8880be453000 R=
CX:=20
ffffffff839ab92c
[=C2=A0=C2=A0=C2=A0 1.813312] RDX: 1ffff11017c8a600 RSI: ffffffff8fe3dec0 R=
DI:=20
0000000000000002
[=C2=A0=C2=A0=C2=A0 1.814701] RBP: ffffffff8fe07c90 R08: 0000000000000000 R=
09:=20
fffffbfff212ebfd
[=C2=A0=C2=A0=C2=A0 1.816078] R10: ffffffff90975fe7 R11: fffffbfff212ebfc R=
12:=20
0000000000000800
[=C2=A0=C2=A0=C2=A0 1.817458] R13: 0000000000000800 R14: dffffc0000000000 R=
15:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 1.818841] FS:=C2=A0 0000000000000000(0000) GS:ffff88810=
a400000(0000)=20
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A0 1.820406] CS:=C2=A0 0010 DS: 0000 ES: 0000 CR0: 0000000=
080050033
[=C2=A0=C2=A0=C2=A0 1.821529] CR2: ffff8880be453000 CR3: 0000000024e30000 C=
R4:=20
00000000000006b0
[=C2=A0=C2=A0=C2=A0 1.822918] DR0: 0000000000000000 DR1: 0000000000000000 D=
R2:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 1.824299] DR3: 0000000000000000 DR6: 00000000fffe0ff0 D=
R7:=20
0000000000000400
[=C2=A0=C2=A0=C2=A0 1.825680] Kernel panic - not syncing: Fatal exception
[=C2=A0=C2=A0=C2=A0 1.827454] Dumping ftrace buffer:
[=C2=A0=C2=A0=C2=A0 1.828122]=C2=A0=C2=A0=C2=A0 (ftrace buffer empty)
[=C2=A0=C2=A0=C2=A0 1.828821] Rebooting in 1 seconds..

Thank you,
George

>
> Failure is intermittent, so takes a lot of retries.
>
> Thank you,
> George
>
>>
>>
>>> CC-ing Rafeal.
>>>
>>>
>>> =C2=A0From c37da50fdfc62cd4f7b23562b55661478c90a17d Mon Sep 17 00:00:00=
 2001
>>> From: Konrad Rzeszutek Wilk <konrad@darnok.org>
>>> Date: Tue, 2 Feb 2021 17:28:28 +0000
>>> Subject: [PATCH] ibft: Put ibft_addr back
>>>
>>> Signed-off-by: Konrad Rzeszutek Wilk <konrad@darnok.org>
>>> ---
>>> =C2=A0 drivers/firmware/iscsi_ibft.c | 19 +++++++++++++------
>>> =C2=A0 1 file changed, 13 insertions(+), 6 deletions(-)
>>>
>>> diff --git a/drivers/firmware/iscsi_ibft.c=20
>>> b/drivers/firmware/iscsi_ibft.c
>>> index 7127a04..2a1a033 100644
>>> --- a/drivers/firmware/iscsi_ibft.c
>>> +++ b/drivers/firmware/iscsi_ibft.c
>>> @@ -811,6 +811,10 @@ static void ibft_cleanup(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 ibft_unregister();
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 iscsi_boot_destroy_kset(boot_kset);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (ibft_addr) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 acpi_put_table((struct acpi_table_header *)ibft_addr);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 ibft_addr =3D NULL;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0 }
>>>
>>> =C2=A0 static void __exit ibft_exit(void)
>>> @@ -835,13 +839,15 @@ static void __init acpi_find_ibft_region(void)
>>> =C2=A0 {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int i;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_head=
er *table =3D NULL;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_status status;
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 return;
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRA=
Y_SIZE(ibft_signs) && !ibft_addr; i++) {
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 acpi_get_table(ibft_signs[i].sign, 0, &table);
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 ibft_addr =3D (struct acpi_table_ibft *)table;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (ACPI_SUCCESS(status))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ibft_addr =
=3D (struct acpi_table_ibft *)table;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0 }
>>> =C2=A0 #else
>>> @@ -870,12 +876,13 @@ static int __init ibft_init(void)
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 rc =3D ibft_check_device();
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (rc)
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return rc;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 goto out_fr=
ee;
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 boot_kset =3D iscsi_boot_create_kset("ibft");
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (!boot_kset)
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -ENO=
MEM;
>>> -
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (!boot_kset) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 rc =3D -ENO=
MEM;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 goto out_fr=
ee;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 }
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Scan the IBFT for data and register the=20
>>> kobjects. */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 rc =3D ibft_register_kobjects(ibft_addr);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (rc)
>>> --=20
>>> 1.8.3.1
>>>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bcf8925d-0949-3fe1-baa8-cc536c529860%40oracle.com.
