Return-Path: <kasan-dev+bncBCX7RK77SEDBBCFG62AQMGQE4QB3RFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ADF1329581
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 02:21:14 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id c30sf10792209pgl.15
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Mar 2021 17:21:14 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614648072; cv=pass;
        d=google.com; s=arc-20160816;
        b=yKb6WIfNi0bUjL9gSQZvx42bxDWU6WslQaoPQ+4X7jj9/dyDNkSzeOGDPi3B9Gaquh
         2iY4Z4jAKqhXIE6CkZDlogwAMSf/AVqCMHD7EQCp8BWLCGWEdZwDTS69JD7qZFUDgAgU
         42BBV2EZgU1SgUgxucemXlW1C2sf9/PVUXJ3xIW4JA3aqCqM9wFSSFdBbI7zkfrAzhYc
         yzFJNRop3FOFYjpUM9+FG0zvQp80sVZC2Ers2vXatmH3SIB6Xs8ZVpAwI9m2YrX++Yu1
         Axdfhy69MytR9qSGy5BGdU86GPyXL5mr1vMXe+n6TsxptBVfFB7YplqjsJL2AHEl9CP6
         6RqA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:references:cc:to:from:subject:sender:dkim-signature;
        bh=FWdoqezC+tlDblLq3jmEghn2vkfxI6PcGBneBhYS6Qw=;
        b=UZ47Ty83lOnxXC0UxoiVM1zNIJAOgfXmgGk1aoL82FPhMIxg6/qGnMUTLF4GYmI+mM
         MOKCvFJo9b5UG3vRu5A/kpbZ/zts3wi4flEzRwR9HpzcKn6MS8SF7tqsQwK9UPVOQKHU
         hXMH+Hu1PUVFMxqRPXFam3FLp5ZHazg39FGQkNq/vCfRJpvnRvmBRU5nLd1xpqO9Oc2m
         43OATl5/CDuozfM5WxzZpJJuc3KPKpgfFJKziV60v4i9Na3QiqS27285k8Ytjy6QFVA2
         aQqhCbi6hHACLC3fOp2XBPcdDXjX6p8f7DPvtcRDYR0MBOQoTJg4LTLvCushfXmhywov
         dWFw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=Ldg3L9tJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=mMGgItmZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FWdoqezC+tlDblLq3jmEghn2vkfxI6PcGBneBhYS6Qw=;
        b=fCfLALdF91JuUMJW6/vHPFFMmW41FHOHKfGJ/xKiRyhA3SeJ6WECFAiid3ZY2DwxvK
         q5ejqrAyMF55Ystnw/cuVlcPM2KWpEbxioIBM2h/0NySlY8S/VaDqhLRcDPoD8OHVscD
         jJ3xDG8EkuQfdhyN8e6PRvujzGtafbD4ZRs8qb+6LAJTAXVz8wYjQtVfdPd2lEo4xUo/
         Kn6D49uHuPBflUFm4z5p4NQzn8wt9CFCwTA10z9K7V1txQq+NDfUxIzE7fbMuPaHgNQq
         QW0Kg3sEx3XOTfPebZ33D3euJxoaw8rt4Mr/RXq9tu52+1o8cUYMRGQqZo4mwO5H/WfZ
         vwLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FWdoqezC+tlDblLq3jmEghn2vkfxI6PcGBneBhYS6Qw=;
        b=eauuZU6a6kleLopXnNGSzq53tO4ZIaDWSqfZJNBS2KhOgcwKuVb8iIsGEOUJ21+SaR
         gUgkrjqqtYxJQ/nMBE87okb8Zx0tq0j7JQ4/iFTu7JFN/aV/eC5fhxRvRZPnerHsUjF9
         /kNu98W+cJ24kzaeKtxN99L0sMDyYqs7Ja+E2cWgaIIqEshKFQrbbSRrHpS5UB/j5guc
         ZU7i04rp1g/lSgsa+xOV1oHG9NHaRjJt7IWk2m8c2o1YDiMzPL2WsJWAqEzMRBALTZzF
         9Hq0xmteWNyCmd8BwGVtlKssWT1qPAC7/wgZnjRyh9Ho9hha0Gz4x4xmhdBJMSTq9aHN
         zuew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MDnMYXDdDm5lZerBv7WHh66mDfV8gsOmplQkHlg/AcgRF+4PJ
	iuxxgf8eq98x1RtnEonG3iU=
X-Google-Smtp-Source: ABdhPJxLCv8s8nGXGMOnK9umnuk3/eO0DtF3B0FkzPaHdYEUxaejARwYqYd+qF3TnHfzQPHrEojhMA==
X-Received: by 2002:a17:902:aa49:b029:e4:3825:dcd2 with SMTP id c9-20020a170902aa49b02900e43825dcd2mr1367625plr.39.1614648072772;
        Mon, 01 Mar 2021 17:21:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6902:: with SMTP id j2ls2728184plk.10.gmail; Mon, 01
 Mar 2021 17:21:12 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr1696629pjb.166.1614648072180;
        Mon, 01 Mar 2021 17:21:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614648072; cv=pass;
        d=google.com; s=arc-20160816;
        b=b1zhuDgeT0SdFYB3PuZFYCCGAsuT+PiEphsXCjGS/me/tMUgxJzGz4BIjD9JB58H+o
         DOtm4TyKL270mRxcbrCe2xktq9cgHOh52PY+v+R2y72JCFXPXPZ9cgbYUAYUQgGJG57S
         vsL4LABptrsYga1twtI34neuJDziSI8jiyX/Ff4O1Gs6lcuxhicLdvYmsUCIn+q611LK
         I/bz0mjks4eu7tGI4DwWOb8+B885CEwqhIkay9GMSIsZ8T8mlRVZgClBV46Uax3/dIaH
         QL+Qd6yKo1xQypDJ9ig6msd/Pyd3bejS07NaCvcwCcBbIruFLmVt2EDcIo/CX2zh1HnF
         4dOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:references:cc:to:from
         :subject:dkim-signature:dkim-signature;
        bh=4WToiToDYmFCBhzKiH2QynmKkoQW4ghWpFW0pHAY0ec=;
        b=NcM05ZJfNUNgsHpyvEG708Jh6Q6UMwgrNhRuyCB7Wm9RppgrsBTXmj277te9ymlXpZ
         iNbI2eKG0oFQbzOE/CH6feJO3FLsx9/cxtyLM50e8pzNtfJWITCD4RT9fM0yRIwPHfkz
         rwdZdeoNnJUCHBnZQT3kemgpzrLrVTttv6qZKST2zPKakqZXAqn/7qLjQNT2ahOGX0NS
         hXAr/hYjpCTozJuA3SRwngl13RNrNFERgUYAPTHf0jBFtkqH4IsDYMY+QQZ1osZJnMUN
         /b7k7gbeJwStY0FZBG5q1YfHlDIESiJmTm8lgyr2v9Lq2rzAqAxM625ggMa9kaXBVd33
         v7Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=Ldg3L9tJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=mMGgItmZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id e4si497444pge.1.2021.03.01.17.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Mar 2021 17:21:12 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 1221Krhl043880;
	Tue, 2 Mar 2021 01:20:53 GMT
Received: from userp3020.oracle.com (userp3020.oracle.com [156.151.31.79])
	by userp2130.oracle.com with ESMTP id 36ydgr5vac-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 02 Mar 2021 01:20:53 +0000
Received: from pps.filterd (userp3020.oracle.com [127.0.0.1])
	by userp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 1221KUkM160140;
	Tue, 2 Mar 2021 01:20:53 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11lp2172.outbound.protection.outlook.com [104.47.57.172])
	by userp3020.oracle.com with ESMTP id 36yyurayef-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 02 Mar 2021 01:20:53 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=SV9MuYO9sj8bzk0KbcmYDyxvvJwtlArPDGU6gk0BSZ3rxkyRb23E+Ezrit5XkkSvwrCASaAA8b88NDB9xSqa4cDUoVnY8RUjQurtuKyyL3m1tJkj8IihKKZfWX4F8wLoPDfc24deHbKAbOoXrJYTLCoXEAm6BrFx+iqLiLd3ZIiWfz/vT2V+V6qyjT5INT8/ok0EOmLGspKzF5eesdjU0fQ0Ep3uyDwKn89ukYJx6LB+qLnyJnfNj3hnXz/Y6u4Fs6faIt1iKqFsUCyG8cqDg7o5ATjF7a8NE3R/TywIJ+hwaQkOoCDoWSfNyYqWk8gk41Ne7oNveICLaSU/hXLHMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=4WToiToDYmFCBhzKiH2QynmKkoQW4ghWpFW0pHAY0ec=;
 b=XSNvWKMEqKIHbJ7cKuafKlpUwdbieC/nnAK2kWy3cIL9poNcAxGxJYstw0WolcqUEaVlTAgeZucDlsXRPwJXWqPJVYtqSIprjOIVUyzUqB5FBHFUnnpm/bX9uj+oxqLL2/yYD2mKoU+EjCbwMhnHsp7ngYCFmAA4eiKxWNPZRV4XELm0TD3/l39EyN6P9zl0+Zwqsxr0YpcIqoabXabLJJwyMgljm8AjYXwZQwkn0Eyk1L+aCratmQvCkZsamwzdoyg4AKCWOPfMnkaqHUkGtek+lZx75qCnY72cl/AORKrhH2vvANwifE0Ux5/slRfuuba/lhzpSeClCbkYVGVLIg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB2985.namprd10.prod.outlook.com (2603:10b6:5:71::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19; Tue, 2 Mar
 2021 01:20:50 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3890.029; Tue, 2 Mar 2021
 01:20:50 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
From: George Kennedy <george.kennedy@oracle.com>
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
        Dhaval Giani <dhaval.giani@oracle.com>, robert.moore@intel.com,
        erik.kaneda@intel.com, rafael.j.wysocki@intel.com, lenb@kernel.org,
        linux-acpi@vger.kernel.org
References: <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
 <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
 <20210226111730.GL1854360@linux.ibm.com>
 <e9e2f1a3-80f2-1b3e-6ffd-8004fe41c485@oracle.com>
 <YDvcH7IY8hV4u2Zh@linux.ibm.com>
 <083c2bfd-12dd-f3c3-5004-fb1e3fb6493c@oracle.com>
Organization: Oracle Corporation
Message-ID: <a8864397-83e8-61f7-4b9a-33716eca6cf8@oracle.com>
Date: Mon, 1 Mar 2021 20:20:45 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
In-Reply-To: <083c2bfd-12dd-f3c3-5004-fb1e3fb6493c@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.26.147.230]
X-ClientProxiedBy: CY4PR06CA0071.namprd06.prod.outlook.com
 (2603:10b6:903:13d::33) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.26.147.230) by CY4PR06CA0071.namprd06.prod.outlook.com (2603:10b6:903:13d::33) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19 via Frontend Transport; Tue, 2 Mar 2021 01:20:47 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 67987aa4-181a-4449-816d-08d8dd196a1e
X-MS-TrafficTypeDiagnostic: DM6PR10MB2985:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB29856374DFB988BD2CF42F8FE6999@DM6PR10MB2985.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:9508;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: IXTz5xiEwlEGkETTANgnCC8WMXEPI59gzjrfzji82Tx//SF4Y7cvjyR+4Y0fMUwrDijgBdniQaU+/SKU+jN5esQlvlyNDRYdIKhPJLzwGxNVwzntwqTqE2a9Xofb2cLd1mTlHEIYBmKa2fluZYYlAjXb9DHzh6H3G30nGtJestj6btTvwyhbiO+S0Oy72bIUoN2FzaOzYDkR0S50KsPrGelw+xNo9P2cBIM1eMubGU2nenGLtF3vy3+yRVf8K3VSSpbAB/2I9Odi6Sxng4IWq9yH1xrEWZLXu11BXYwVSBhdrgMNTOKPJjER8i4EF5fgswkCWht/qERluD2/GwpY/H7wJfsgHyFK7gWklJBHdN5oM4BzNiXOHjTfM8cqpnjBQbC0PSHq4J1bRGAAs7xkr1kFYB1FJrZGr1LFUEysuNkVdDAiKyLmH+rPJgXuV7BQk+tDC8ym5CseR+zkdgDxEjGApNnwKweVnAvRLM+qUfjVjpeH7JVGQvTA59KTvCNhssctJErmVwgfviDSr00pLHKVPDbSF+ABAvywrdBA1gvxhuJpJqm2STqX32pUHRlIgb17mBOJyv0aQ2crmIXbKVIPVNTmzN89mx7yCelrUzY=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(136003)(396003)(346002)(39860400002)(366004)(376002)(31686004)(8936002)(66476007)(36756003)(66946007)(86362001)(4326008)(66556008)(7416002)(5660300002)(186003)(16526019)(26005)(2906002)(16576012)(8676002)(2616005)(316002)(36916002)(31696002)(6916009)(956004)(44832011)(6486002)(54906003)(478600001)(53546011)(83380400001)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?aUQvN0kzU2xpMkF1azN6TlZQc3FzTGptU3VmY1U3NFZSZnBpMVFXcVp5S21M?=
 =?utf-8?B?ZUVIZlhMcGpXS1lFaGRIL25KcUtLT05Td0hhdk44cVJGUVErYTR1bUNsL2kv?=
 =?utf-8?B?VzN4cDluOU1EYlRUanBLQ29LMjM0UjArS2hoaE96TWE4dXZodm15Sit1WlFF?=
 =?utf-8?B?TERUcTJGRmlCSkYxbytNL0ZNY0UzMnkwdVNybGtCWHFXY29iUFAyMFBRTk8y?=
 =?utf-8?B?N2c1VUpQazJHMFhMcGdOUk93dFBqSVJwTWdFTTMwQkhqMnRrMndQYnp4SWs1?=
 =?utf-8?B?bmlaY3BWRUtNNWplTVRPd20xL0k3MmoxdXBEN1RUWHZQRTVRRUpuUDNaQk14?=
 =?utf-8?B?eERsdmJHd0p5S2ZJaGV3MDBkS1RrQytZZFE2dUlIVml0aG50Zzg4Tm84Slh0?=
 =?utf-8?B?RC9YWTFRWFg0dVQ2ekVkMjVrWXdqQ2JhTlhKWVozZTlpSGxmVnMvYitkSU5Q?=
 =?utf-8?B?NUlnZEtacEg0TzhWSWR3SVNzdUsvUUJNK2oxZjBtazBOaW1sQkpGdWtOOGIv?=
 =?utf-8?B?cEhLZWxGTlU4SmZZdWZZVWt1K0srWlpXRWhhSk1LdmtTQjEwb0NwcU9JZitE?=
 =?utf-8?B?VFdjc2EzbVRDVlRoYlo1dlhlWW4zcisyQTBXaUlyZHNTNkU3K1ZoY21xOXQ1?=
 =?utf-8?B?Qm1wY09jTGkvMEhDeENiclhaUjM2dzlhS2ZvRGM2OENlcFpNYnpub05UQ3ZY?=
 =?utf-8?B?TTlabEZFTURQZXJWQnN6N21BbWxVS1VOdHRGU21IMVVsV3hZemVqRi85SHlK?=
 =?utf-8?B?bGJpRkQvam1SK2VkbVNnWENVMGMxWVBjVjJlRDRwUURYWEpXblUyeVdXMktz?=
 =?utf-8?B?MWZrRjlXaHIzc2xUSlNTblJzeDRSTUtyaW5oV0tFVWt0L1QrQ2N2NG5uNGY4?=
 =?utf-8?B?S05PN0l2NDdhR21rblErbzNvQjVKem52R1hMRDlxdnBGQ2NyS2F0OFZZQVNs?=
 =?utf-8?B?NXhKYlgxSGtFRW1IQ0FWRko0YkJNeXdEb3RqdlY0V3RMMEF5eGU1bTQ1VVQv?=
 =?utf-8?B?dHpZKzNYMGF6TmlyeUwxNytjdmhBV2plVEpOM1V4akpWRlRHQU02ZEJlRnU3?=
 =?utf-8?B?aXVJNkduZXVMd0lGdkVWaDd0L1IxVjNoaTBQeW94a1Z3TVFIeStTbXhacCtH?=
 =?utf-8?B?Sys0YmZCS1h2V2R1Q1cvcUZTUFBSUUVpSkxGb0Urb2RLTlJBT1VXOWNCNzJO?=
 =?utf-8?B?NFppWWhYRmliOW9DdEU4TGNtUXF6UEdsWGRSNGFQUUNhMTJCWGp6U1J4S3hv?=
 =?utf-8?B?bHBrR1lhZFptNi9aRmdGeGozTEk1cWVVbFdQRU4zWnppZm8yN3hqbC9hV1g0?=
 =?utf-8?B?eUFMcnFxS0tXTUdpc3NwRmJzTitpSVdxc2h3cisrclpvOXlabUdYbnIwTU4v?=
 =?utf-8?B?bUJIVkNkbW8zL01DVmxNcFl5alpFRUYzTjFBNlRzd1RuZVlTTm8vSWdiR01F?=
 =?utf-8?B?Wjg0UmVwZGUrRHBFOTdTbzgvS0F1c2ZsOUlmNEZtcDJGby9KQUhIUjFZUFJE?=
 =?utf-8?B?VUhEY2o4b0VkNlNZSVZCa09jVFFNTExiaXNwOVprWGhwaVVMdzZRdFFRSUJU?=
 =?utf-8?B?cVI1QkFJUzZmVDYwUTROaGdZSldxMFhCMmFVWGFNcWZzcXZWUmRxS1loVDc3?=
 =?utf-8?B?QXMvYkZsYmtpMWtDR3Y5YWlWUlc5K0dXK212SlNDT05Sc2kxM3lmbE5ldmJC?=
 =?utf-8?B?OTZwai8yamlzc1RPWDVYaUV5aW1KNW1udTExTTM5UjBOa3hHdmZPVzZzdExj?=
 =?utf-8?Q?SHi75xSRYrJZiuRB+G/0HEPa1wY86rIOvmP/NFj?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 67987aa4-181a-4449-816d-08d8dd196a1e
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Mar 2021 01:20:50.5455
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: z5dTcPUDXf2niMlPBQHO+jIQoqrtpbDNwXElML40oebn/6EIZJ8/LDVxUQWAVfwf3i21HMUjQ5nCuCm1eOvR+em1Rfvsk9eFQIdIbMKM8ls=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB2985
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9910 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 spamscore=0 suspectscore=0
 mlxlogscore=999 bulkscore=0 adultscore=0 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2103020006
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9910 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0
 impostorscore=0 clxscore=1015 suspectscore=0 malwarescore=0
 priorityscore=1501 mlxscore=0 phishscore=0 bulkscore=0 mlxlogscore=999
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2103020006
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=Ldg3L9tJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=mMGgItmZ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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



On 3/1/2021 9:29 AM, George Kennedy wrote:
>
>
> On 2/28/2021 1:08 PM, Mike Rapoport wrote:
>> On Fri, Feb 26, 2021 at 11:16:06AM -0500, George Kennedy wrote:
>>> On 2/26/2021 6:17 AM, Mike Rapoport wrote:
>>>> Hi George,
>>>>
>>>> On Thu, Feb 25, 2021 at 08:19:18PM -0500, George Kennedy wrote:
>>>>> Not sure if it's the right thing to do, but added
>>>>> "acpi_tb_find_table_address()" to return the physical address of a=20
>>>>> table to
>>>>> use with memblock_reserve().
>>>>>
>>>>> virt_to_phys(table) does not seem to return the physical address=20
>>>>> for the
>>>>> iBFT table (it would be nice if struct acpi_table_header also had a
>>>>> "address" element for the physical address of the table).
>>>> virt_to_phys() does not work that early because then it is mapped with
>>>> early_memremap()=C2=A0 which uses different virtual to physical scheme=
.
>>>>
>>>> I'd say that acpi_tb_find_table_address() makes sense if we'd like to
>>>> reserve ACPI tables outside of drivers/acpi.
>>>>
>>>> But probably we should simply reserve all the tables during
>>>> acpi_table_init() so that any table that firmware put in the normal=20
>>>> memory
>>>> will be surely reserved.
>>>>> Ran 10 successful boots with the above without failure.
>>>> That's good news indeed :)
>>> Wondering if we could do something like this instead (trying to keep=20
>>> changes
>>> minimal). Just do the memblock_reserve() for all the standard tables.
>> I think something like this should work, but I'm not an ACPI expert=20
>> to say
>> if this the best way to reserve the tables.
> Adding ACPI maintainers to the CC list.
>>> diff --git a/drivers/acpi/acpica/tbinstal.c=20
>>> b/drivers/acpi/acpica/tbinstal.c
>>> index 0bb15ad..830f82c 100644
>>> --- a/drivers/acpi/acpica/tbinstal.c
>>> +++ b/drivers/acpi/acpica/tbinstal.c
>>> @@ -7,6 +7,7 @@
>>> =C2=A0=C2=A0 *
>>> ***********************************************************************=
******/=20
>>>
>>>
>>> +#include <linux/memblock.h>
>>> =C2=A0=C2=A0#include <acpi/acpi.h>
>>> =C2=A0=C2=A0#include "accommon.h"
>>> =C2=A0=C2=A0#include "actables.h"
>>> @@ -14,6 +15,23 @@
>>> =C2=A0=C2=A0#define _COMPONENT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 ACPI_TABLES
>>> =C2=A0=C2=A0ACPI_MODULE_NAME("tbinstal")
>>>
>>> +void
>>> +acpi_tb_reserve_standard_table(acpi_physical_address address,
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 =
struct acpi_table_header *header)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 struct acpi_table_header local_header;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if ((ACPI_COMPARE_NAMESEG(header->signature, ACPI_S=
IG_FACS)) ||
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 (ACPI_VALIDATE_RSDP_SIG(header->=
signature))) {
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
>>> +=C2=A0=C2=A0=C2=A0 }
>>> +=C2=A0=C2=A0=C2=A0 /* Standard ACPI table with full common header */
>>> +
>>> +=C2=A0=C2=A0=C2=A0 memcpy(&local_header, header, sizeof(struct acpi_ta=
ble_header));
>>> +
>>> +=C2=A0=C2=A0=C2=A0 memblock_reserve(address, PAGE_ALIGN(local_header.l=
ength));
>>> +}
>>> +
>>> =C2=A0=C2=A0/**********************************************************=
*********************=20
>>>
>>> =C2=A0=C2=A0 *
>>> =C2=A0=C2=A0 * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_install_table_with_o=
verride
>>> @@ -58,6 +76,9 @@
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =
=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->flags,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =
=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->pointer);
>>>
>>> + acpi_tb_reserve_standard_table(new_table_desc->address,
>>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=
=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);
>>> +
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_tb_print_table_header(new_table_des=
c->address,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =
=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);
>>>
>>> There should be no harm in doing the memblock_reserve() for all the=20
>>> standard
>>> tables, right?
>> It should be ok to memblock_reserve() all the tables very early as=20
>> long as
>> we don't run out of static entries in memblock.reserved.
>>
>> We just need to make sure the tables are reserved before memblock
>> allocations are possible, so we'd still need to move=20
>> acpi_table_init() in
>> x86::setup_arch() before e820__memblock_setup().
>> Not sure how early ACPI is initialized on arm64.
>
> Thanks Mike. Will try to move the memblock_reserves() before=20
> e820__memblock_setup().

Hi Mike,

Moved acpi_table_init() in x86::setup_arch() before=20
e820__memblock_setup() as you suggested.

Ran 10 boots with the following without error.

diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index 740f3bdb..3b1dd24 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1047,6 +1047,7 @@ void __init setup_arch(char **cmdline_p)
 =C2=A0=C2=A0=C2=A0=C2=A0 cleanup_highmap();

 =C2=A0=C2=A0=C2=A0=C2=A0 memblock_set_current_limit(ISA_END_ADDRESS);
+=C2=A0=C2=A0=C2=A0 acpi_boot_table_init();
 =C2=A0=C2=A0=C2=A0=C2=A0 e820__memblock_setup();

 =C2=A0=C2=A0=C2=A0=C2=A0 /*
@@ -1140,8 +1141,6 @@ void __init setup_arch(char **cmdline_p)
 =C2=A0=C2=A0=C2=A0=C2=A0 /*
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0* Parse the ACPI tables for possible boot-t=
ime SMP configuration.
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0*/
-=C2=A0=C2=A0=C2=A0 acpi_boot_table_init();
-
 =C2=A0=C2=A0=C2=A0=C2=A0 early_acpi_boot_init();

 =C2=A0=C2=A0=C2=A0=C2=A0 initmem_init();
diff --git a/drivers/acpi/acpica/tbinstal.c b/drivers/acpi/acpica/tbinstal.=
c
index 0bb15ad..7830109 100644
--- a/drivers/acpi/acpica/tbinstal.c
+++ b/drivers/acpi/acpica/tbinstal.c
@@ -7,6 +7,7 @@
 =C2=A0 *
***************************************************************************=
**/

+#include <linux/memblock.h>
 =C2=A0#include <acpi/acpi.h>
 =C2=A0#include "accommon.h"
 =C2=A0#include "actables.h"
@@ -16,6 +17,33 @@

 =C2=A0/*******************************************************************=
************
 =C2=A0 *
+ * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_reserve_standard_table
+ *
+ * PARAMETERS:=C2=A0 address=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 - Table physical address
+ *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 header=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 - Table header
+ *
+ * RETURN:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 None
+ *
+ * DESCRIPTION: To avoid an acpi table page from being "stolen" by the=20
buddy
+ *=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 allocator run memblock_reserve() on all the standard=20
acpi tables.
+ *
+=20
***************************************************************************=
***/
+void
+acpi_tb_reserve_standard_table(acpi_physical_address address,
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 stru=
ct acpi_table_header *header)
+{
+=C2=A0=C2=A0=C2=A0 if ((ACPI_COMPARE_NAMESEG(header->signature, ACPI_SIG_F=
ACS)) ||
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 (ACPI_VALIDATE_RSDP_SIG(header->sign=
ature)))
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
+
+=C2=A0=C2=A0=C2=A0 if (header->length > PAGE_SIZE) /* same check as in acp=
i_map() */
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
+
+=C2=A0=C2=A0=C2=A0 memblock_reserve(address, PAGE_ALIGN(header->length));
+}
+
+/*************************************************************************=
******
+ *
 =C2=A0 * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_install_table_with_override
 =C2=A0 *
 =C2=A0 * PARAMETERS:=C2=A0 new_table_desc=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 - New table descriptor to install
@@ -58,6 +86,9 @@
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->flags,
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->pointer);

+=C2=A0=C2=A0=C2=A0 acpi_tb_reserve_standard_table(new_table_desc->address,
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0 new_table_desc->pointer);
+
 =C2=A0=C2=A0=C2=A0=C2=A0 acpi_tb_print_table_header(new_table_desc->addres=
s,
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);

George

>
> George
>>> Ran 10 boots with the above without failure.
>>>
>>> George
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a8864397-83e8-61f7-4b9a-33716eca6cf8%40oracle.com.
