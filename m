Return-Path: <kasan-dev+bncBCY3HBU5WEJBB3FU4GSAMGQERGKU3IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EA9573D1A3
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Jun 2023 17:17:02 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-39cdf9f9d10sf1702840b6e.3
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jun 2023 08:17:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1687706221; cv=pass;
        d=google.com; s=arc-20160816;
        b=S56DlIHFaeZmQm2ByN+cHQp8ynt1ypfqhHveGf7389kdhnyumJKv861P7YqgTGY8mz
         drof6VjtNvWrldqck1eOqjsL5aIrVTc1BLCBs+z5OkKXWBGRkAmdajO+WuV8ky5Vt2Q+
         r+h87rUSOMl0HakHj7ZiA8HWrWiW/T2+lZr8Y+ku6Egiuft8LkxtVCPHXsFHFalxGTBw
         9W+s6sLh+iL1gAj90mWCqyD0bFCcTh3Cn7xQmS6kYEBMjAPTsGcWp6NsY0H5zJsdMrA0
         fXVsfXgOlNau46p7gFE4LJvSVxRNMTdDRp84T0/s+9pStienAUUI3jiUzKeteeru8Bsv
         4bPg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=j7ELT+FMJ1hpK7jdKt6OzJlDHoAHTDnC5haHPgyAtE4=;
        b=IcScmPvO4GLniPmNgL9rT4BKURrWX4ZKCoSX7o0EJqsnk/NQ6wK42MZ2V9nsi1R0cM
         IVS/20kWhkOKeojtDRZ1nRcBo2KBDruvGwCwYqUjANfCMn0FStVGR9nyB3E7mrnooEov
         aDACproboZ4jc/Yknz+riv7ImIzjuUNl+WaKwe6fvnCKMD8BUeau9rA8sF3p3Dr/hVF0
         T+IfMBwUbIPjhEMjoJ6AP7swMlVApXrbAydfnYowqWz5TE145Zoj6EiDLH/khAQWI2Yz
         MsZm9q7EX4rGJCjmkpixBf18uuki+M/3OcM6KxYSEamJnhjwMapfWu/jkcXh8guVPF/1
         NJvg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=ng4qyj33;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ccsG0ylE;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687706221; x=1690298221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j7ELT+FMJ1hpK7jdKt6OzJlDHoAHTDnC5haHPgyAtE4=;
        b=tlT/7byXlhCAp+JIk2fH93Y6P8zGo/kfEfHLZd95Ei1OJQazeNflsNMs1lpxmJ8FCr
         hGNUV2BtsHHqJhqpQ4WYeddwb8LoQrAB6Yd38vk+wfHzrPm0+ESy4AZPAOuPNRRh5n3q
         qxg/W5xQqWV8JfS30nq3VlWXs4AkdkiKq37VdvaXB4YL8jiVetxVoijKG0pXhpwL2aLf
         QcwbpQOmjzthHoxFuISHq+sUdrvN3sIUB293kh1/VJJB433igk29qYseyvX8pxx7SdFp
         ap8HDBDzww7MrWrAm1LokseZK9XCmC3W0KK6IGKS9f7yLpU/OJBiPap/9uSi68G7G32u
         JzcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687706221; x=1690298221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=j7ELT+FMJ1hpK7jdKt6OzJlDHoAHTDnC5haHPgyAtE4=;
        b=WJsSLl5eQoFFZ+wz24DekPyFwRX1h9g+0TMW6bF9yAAgWrb4rPi7FtJa70MvOb7XIW
         Chnam8y6vOGG8oQmr0FlUSKCFJyqvrw6qXAPKWgwjtJKe5pnMNGJfvYNofuEK0vmAUrg
         8aVaApS66xGBYV7ansEWQVw7SCoisjJXPDZzmeEB1x4Ai+m/GbBUs0ZCs1SBDMOkJrra
         Nzkfa+WYpz1sxIta7DwqIN6B1ZJ82zXQy7TrIeRICWUL2zLic3irnOO8PBlBlBRiL//K
         AtywbGU6sTuAmTMrGDmalQ9sRs/SYTZO6esLmZbZvScz4sGJFwkuYT5v/JjQJbP0kSCQ
         fOQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx9sWXqnPI/yKssVlG1uQxRTacqKD3qsFU2R2kvLSH4+2GDhmvE
	ndZlde+Lv17IC9HagHdSNTk=
X-Google-Smtp-Source: ACHHUZ5S3bTFooeSm/W/XDKJuftfqYhh5KVQ9pxHLZD1d3zUgbEYJVQMG6GMbcJUJTgOreWsSh4Iag==
X-Received: by 2002:a05:6808:2788:b0:39e:acab:1558 with SMTP id es8-20020a056808278800b0039eacab1558mr21519491oib.45.1687706220754;
        Sun, 25 Jun 2023 08:17:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f70e:b0:1ac:f73a:23cc with SMTP id
 ej14-20020a056870f70e00b001acf73a23ccls2265721oab.0.-pod-prod-06-us; Sun, 25
 Jun 2023 08:17:00 -0700 (PDT)
X-Received: by 2002:a05:6830:33fc:b0:6b6:f292:43e6 with SMTP id i28-20020a05683033fc00b006b6f29243e6mr7697450otu.25.1687706220229;
        Sun, 25 Jun 2023 08:17:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687706220; cv=pass;
        d=google.com; s=arc-20160816;
        b=zCNBRRiG+9WUOguD37Fvp5b0p/jeA0UN8g6cNXhV+MiHPkaCWcs8xOe1OrPbYBHoi+
         m8YnKWmqTxpIoiudXNnEbaA/wh904IpWLuHCLfSDm2wa1PFjRXUb5bNI5jOEsz+P2VhS
         8ERStUv0m5yecjqWWKz9tlXMSWYubSmvFlepAESGvkIojeoh2fszXp0iAvVlnJBXlwe8
         JAcV3+b7xoiczL8qbnAE5bwYIuNdL+fCyeOG3HaG/FJF3h1ff9FGZ7fc2cprybAC83pp
         tXMq79pEGV6cmS0QBA3ME4IInlCzspfSfSEkSA6riiKggrLKymRoS+/Uq2TZxuX4isZG
         nj1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=xK6pYzX5d3Ab2rdRRatu0WwiYLGoMqt2lVXcS8QwgzI=;
        fh=nGX+oQteWnFCxGKtNK3UU91mr8par89s9aPJ+D7b12c=;
        b=wmspfLOzJiLylPcR/AglsQtgnAEvM4OSlgwlNPLdC6gSXFABQo8Ttw9aSQeq830JEo
         3PnLrrEpu6sOP7y2YlAf6FO/nWgA/zPZISg9VVRa0q0GwfJv8/BsImDgYjmhep+vswvy
         SKXdjSFWLRD2hTQygOlXF/Qihvj2Z6ovjsUJfhRvycBdt7Vacs1SUOR0jpbyHGGGQ5BZ
         e1+7E0K6kz+jEFSbkKw/L2wKmU7IQiZLSSOkKvavyszy9eZtuV06ulA+5uB68nVRgF4J
         psUX85c3ftAahfD0HnCilbeKGvVtYC49cUwot7cyYbgpCnFmxgkh4CkR9bo0kEYkzlz5
         MW0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=ng4qyj33;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ccsG0ylE;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id y19-20020a0568302a1300b006a5f12c714bsi275639otu.0.2023.06.25.08.17.00
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 25 Jun 2023 08:17:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of chuck.lever@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 35PEkqBv005299;
	Sun, 25 Jun 2023 15:16:58 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3rdr3thajn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 25 Jun 2023 15:16:57 +0000
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.17.1.19/8.17.1.19) with ESMTP id 35PC0Y1f028377;
	Sun, 25 Jun 2023 15:16:57 GMT
Received: from nam02-bn1-obe.outbound.protection.outlook.com (mail-bn1nam02lp2047.outbound.protection.outlook.com [104.47.51.47])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 3rdpx26jwh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 25 Jun 2023 15:16:56 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VKEmVrMLUu3VWqMDnRPCzJeqeVTvuKNbs6ED2bADGW91GTZaJFbI/Yc4Me6wpc7AucABZRXeRH8RxCzNZZDasnBbR4YxFjhJKVQciWqm7dxEH8dWz7CdCmMzzU0bpOLuCR0BN/U0TszXE2yttGH2Mcq0At+6suyckilGU9S4CDrBNVA9ETQ7d1FNaKObsoLu8dy1LK8IubvuzYONE9vc88SCWnwzzrp+4eVlHarO1KOUBA0bkL/+IRu4H8hQMSI4+AiF93sFs0X87tQXw/ExHAw0bP6vo4u4NBybIo8vv3onbQLH/vyOG6DN61ivtUVmc3MpHc/tr/3add+UHYFLPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xK6pYzX5d3Ab2rdRRatu0WwiYLGoMqt2lVXcS8QwgzI=;
 b=TrBNcwhjA2kuHbkxGiGCRNPZuDco+Y/BIh91SdYoSNMwvRrJ1v7NvwIJMk951qGkvbxiOJkXPxbOkIhzYhN2rewXxliesRdk5kjsFKXMgByovlHpKBDeIEHzsXbWRlRK43VwnXNcMGIakWlq6XLgpJyCTng2IkGmOZSta7e5AGL44dslWyhwErF1D1FvxmRleEknoPuROD6g7/KBTkwiGBwFRuW6rPAm2QbULWgGLjBS3QyvY7Wsv6AXoh02p4rV4CSDvducUL1sDZCgu6YPNHTdwJpix/xOK6a+efqjknj2ARiNc1GNZrxj7h09U5wX0ywPo1gjAwzR2g35PWzwFQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BN0PR10MB5128.namprd10.prod.outlook.com (2603:10b6:408:117::24)
 by MW4PR10MB6440.namprd10.prod.outlook.com (2603:10b6:303:218::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6521.24; Sun, 25 Jun
 2023 15:16:54 +0000
Received: from BN0PR10MB5128.namprd10.prod.outlook.com
 ([fe80::ae00:3b69:f703:7be3]) by BN0PR10MB5128.namprd10.prod.outlook.com
 ([fe80::ae00:3b69:f703:7be3%4]) with mapi id 15.20.6521.024; Sun, 25 Jun 2023
 15:16:54 +0000
From: Chuck Lever III <chuck.lever@oracle.com>
To: Geert Uytterhoeven <geert@linux-m68k.org>
CC: Dan Carpenter <dan.carpenter@linaro.org>,
        Naresh Kamboju
	<naresh.kamboju@linaro.org>,
        open list <linux-kernel@vger.kernel.org>,
        linux-mm <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>,
        "kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>,
        "lkft-triage@lists.linaro.org" <lkft-triage@lists.linaro.org>,
        Marco Elver
	<elver@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Mel Gorman
	<mgorman@techsingularity.net>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
 __alloc_pages+0x2e8/0x3a0
Thread-Topic: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
 __alloc_pages+0x2e8/0x3a0
Thread-Index: AQHZhNY3bXnUQYyknE2sxxtPxlRzIq9WqWIAgAABc4CARM6IgIAAbQ+A
Date: Sun, 25 Jun 2023 15:16:54 +0000
Message-ID: <206F3FDB-59BE-4386-82D2-6FF3CD16D053@oracle.com>
References: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
 <6c7a89ba-1253-41e0-82d0-74a67a2e414e@kili.mountain>
 <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
 <1059342c-f45a-4065-b088-f7a61833096e@kili.mountain>
 <CAMuHMdW3NO9tafYsCJGStA7YeWye8gwKm2HYb72f1PRXGfXNWg@mail.gmail.com>
In-Reply-To: <CAMuHMdW3NO9tafYsCJGStA7YeWye8gwKm2HYb72f1PRXGfXNWg@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Apple Mail (2.3731.600.7)
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: BN0PR10MB5128:EE_|MW4PR10MB6440:EE_
x-ms-office365-filtering-correlation-id: 866e38d1-fc31-40db-bb1f-08db758f3575
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 8hihAP703DpkssW3fuvbeA8v/9cIErQz+x223TP9+fuBh8u/2OiQuFl6O3JKoy9mms6K0JChgY0OO2WumLqqQ3yL3VnoDMaz5EkVU+3IBUV96g7BH6rFkDlqSODdr4bm2Cj5QWwAvt2k8hy/WLgKgkHObfhGqJwanmFd3T9RIpGAvJn0WqEbfmQUSgws2qFmf+Q5wJ5trZqPzxiS4xymewv5wd6c24Pi4SN6Pj4crpBqFXRjTNX0r0120lLx7Eg3rLdYNTUuAjdVNtq0+2Y9Z4LUXd/qQqZLjk3OV0sSN2UGAKMC9U7Gmv7Fmg3/iyrAdBEBHlvf4lYAwS+RDFUl/ktYy9LKhwGGQHHDSel+c4+oIEG8z80ikrGDo8xoVrZ2xXBp4LrpnI4E2MIzuqkEXflx1kH6KKKB8V6sMuJTbta9N4d5iJItTe3wXwt2XFyP55a8fik93MkT6/3pbnT5GoP/LHDydHkKQn2XULakICi1xDs+f1K6d+OdmdpT6+gkFdjS8GKH2VyPhIvFjiZn1lEsigmfoXNoC5/r12TAqWT9q38VcRHoJc4MApMmkF2WYlfV4ljiYYPCbAyXwGQGOxh1M9gzqCrN/5Oh0foDwm8Ps1SilIVgl+n/oHDqg/OGo71UOU15O5ealld7hPe9zQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN0PR10MB5128.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(136003)(346002)(376002)(366004)(396003)(39860400002)(451199021)(2906002)(6486002)(71200400001)(38100700002)(2616005)(83380400001)(122000001)(6512007)(6506007)(26005)(53546011)(186003)(966005)(41300700001)(54906003)(86362001)(38070700005)(478600001)(316002)(36756003)(91956017)(66556008)(4326008)(76116006)(66446008)(64756008)(66946007)(6916009)(66476007)(33656002)(7416002)(5660300002)(8676002)(8936002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?QlBFU1gwMG1BaUFqNEM3dCt0MUZvQWJLRnhad2pWTmt1djFyRkk3cnJYb0Zh?=
 =?utf-8?B?bGQwU015allxcXErclhtWGQ1U1lkOHNXQmRMUHllNnpKcENweG9RN2RVNmlU?=
 =?utf-8?B?emEvK1lhbGZtVnR1YU14Mk1UcE13OVpnK2pvb2twcE9GSmhucHF6WUoxWXYy?=
 =?utf-8?B?VTdQRjZpL0pCTlordEFCRzl5OEk4c202RS9ZSnRDZnViNk50bG0xKzMrK1FY?=
 =?utf-8?B?eEJRNUZqODJEK0FhSWx3ZmRDeHNWUUZCZUVyNEc5d0p6YUx3YUUzeC9qeUxh?=
 =?utf-8?B?NjRmTlJaYTBMemhMUUorbGgwc1YwcUoyUWJVZG1mZUIzdjkrRnBYamlGeEQr?=
 =?utf-8?B?NERqTmZ1Sm1qUEtnMC9qb3hzY09CcXlTTGQxc2FZUWpidllNUmt5alVFVDg2?=
 =?utf-8?B?ZnZQRHRrS1hkWmtFVzRoREhlT0xZUkpQNC9Qa0Rxa2JCWEFhMlJxOXA1T2JH?=
 =?utf-8?B?UXgzVTQ3T2dxWGprcHVPcnVIZWNiT2Naa0hZTEZhK0U3RkZEQithREUrM3or?=
 =?utf-8?B?MWVLMGFRNUgwZzdWaFc2Z1VmQmY5MzR4ZnNvakZBTlFQMzJiWnJEMnFLMmVI?=
 =?utf-8?B?dnF0NWtuRXpxNGFvMkVHZWJPcnExOUtZWFRWQ1ArQmgzb3dUN2g1Z3hJVUow?=
 =?utf-8?B?VmxiY2MrUnBzNk1YdlljRTJOMTRtSUYrdEgzdnFHeENHcUpZL0Z4L2xpMlJu?=
 =?utf-8?B?RjdBaHlMS2V6K3dLdGpaMktDbitubmJlNENEaVdpWXhYZ1NiTXBKb2xMUVF4?=
 =?utf-8?B?UVZaNElZeitaRENmZjduVTFLcnQ3ank5ZEJMYlJtT0h6Z0t6SzJvd0ZuUDB6?=
 =?utf-8?B?RFZ6cEkyUG4rcnhreDVudXljOVJhd1NoaXdMZVM1RVZiSkNMRGhFQ3JDZjlJ?=
 =?utf-8?B?bnJNZ3M4ajVqUWowM1VUQUFwbTQxSHhGYlM5MldMUEd1dXVONHJ4M3c0Q3gz?=
 =?utf-8?B?aVB0bGJuR2xWbm1vZlcwUmxqYmhJM0FMQ2xCMDl1VGlQWk1DWHIxNWROdERK?=
 =?utf-8?B?Znk0aisrS2NkMW1CQjRMY1RsOCt0UDRjTnFmdlVNS0VRd3AzMDYrTlhRVFpy?=
 =?utf-8?B?K01FaDFOUnRHSFVLZXRRRVBRYTlSZEk1RTV0bEsrb3NvZDlvTTFXVWM3aC9P?=
 =?utf-8?B?VitBTXlVWUZMd3puemo5ZFVBOVFBSG44cTF2amtqMnJ3N1FYT2tteTNESFZX?=
 =?utf-8?B?UGEwTW5XaFdWMklhR1hwUGI0ZEh1b21FcDNWemFxN2dpV2RpclJ4WlZLSi9x?=
 =?utf-8?B?cHo2M2JxRTdPeWRrNG4yT0VBdjViUG44ejZQQjVBY0c4RW16UGRQL0tlTmdF?=
 =?utf-8?B?bFpvcEd1c0VlbHNnK0dBTjBJeUZBcklWRkk3NVVNcWV1NFZKdGRlZFRHNDRM?=
 =?utf-8?B?Y2lhYlhsSHdiQjNlWUFDS2M4U1FNWjNLcFdIRC93cmROOU9oeHc5dFd1enhn?=
 =?utf-8?B?ZXNwbUhkL21HbUhDV29vbFlHWGZmaGV4UGRqTzRYb1EwY2ZqMEM5SmpZdklw?=
 =?utf-8?B?VFVRQ0k0VUZFM3IySEZOYzFVbFRVQ1JGQ1VRaFV5bjJodUgxUXh1Y2hqVzNT?=
 =?utf-8?B?SDB0cnM1QS9GN292UHlSMTY4Rm5oalhYT3ppaHBOWHQxMzB0cjNNS1g5S3Ru?=
 =?utf-8?B?RVYrbFF1VUhURXQ0dllMbDZkdXF6R0NSVEIzZ1U3a1FQcEZWR0taWk1GR1p0?=
 =?utf-8?B?NnVtWDZ4VXU1UklVaDdzNzZaZFRMZFREQ0NJVXZZOUVxa0JYalVsMElFN3ZZ?=
 =?utf-8?B?OGhwa0diZXJOQnRQQUtHckU3Q0w1L1I4djFqcW90UXYwamZyYk5VZGFlQWwr?=
 =?utf-8?B?K0VOUDg0OGhFZ1pzVWVnaFNTQldBbjVuYkFNLzdPSi9LaGU0Q3luNEoya1V4?=
 =?utf-8?B?dldvTmRBVE9maTEvbmova25KVkxlQ1g3NlBFUFdhaGVhSVQxVnhnQzcwdTQ5?=
 =?utf-8?B?cDR1VTQ5S1JITzVIZ1V2aFhPeGJtQURsZlB2VzBKZVFQVUVJTTQ1TXVVdzV6?=
 =?utf-8?B?L2YwV2ZtTGg2cGxGK09qb3hTcCsydXh5M0N6U0p2SWl1TXdjNnZ2cEkwcDBH?=
 =?utf-8?B?N1ZiOHRITFZ3ZjIxM1BpWVFVSkJ5c1hxbGorZ2U4dWtmejZtZ3l4QTcySlRS?=
 =?utf-8?B?OHRqT09JN2pYekc5ZGl6MVlKaldGOGZrWFQ1WEZSNnNwL1lmZUhZdGVxdnZC?=
 =?utf-8?B?NVE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <80BD6B682E89E049851618F44A465CD6@namprd10.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?utf-8?B?YzdJRDF6MWRSQmdMNUlkaldHMGNaMDVTS3dLbFlMSjFpd21DMFdWZEhEc0Z5?=
 =?utf-8?B?N0lVYmt2NjkzQjVYMWtRREJZTXVCbnNnSDVjYmVvUXJYd3NYUDNrcXI0UWE0?=
 =?utf-8?B?WXBOT29CQ0dvVGplVHI0b2V4cGJrdVVwK0pUU0lMbndZbm01K1crUHZEL3FW?=
 =?utf-8?B?dTUrL0pYb01sTktRSm5kci9CeXIrbDRjbzFkUjEwQ1NUa3AwVVRYK1A0cGFl?=
 =?utf-8?B?eXQ3bUdFbnZiR3lxRzA4T1Fjc1JlRE04NFFyREs5L3N2WkxJVHlFcEd5eDJM?=
 =?utf-8?B?WlN1ZXp0TE5SV2RaRGZjSHdqbHB6VXBkM3Fxa24veVFJZ1hKZy93UExkc0da?=
 =?utf-8?B?d2dNQlY4VWtYNTRJbTJBTmREZThscmhFTWdySzNIODFzMlhxNE1vK2NQemtR?=
 =?utf-8?B?ekVuc3FONTV4b3YrdEMwRmlVOERORktnMysyek1Da0xpNEFnTUVpLzJxbkVo?=
 =?utf-8?B?bUNITTBxb2d6cEFlNVU1UjFGV09IdHNWNWxVSnRxUGZOZTYxbGhneCtPWU1X?=
 =?utf-8?B?L0F5aW5DL1lrTWZUbVhNUXc4Q3NXSCtaN1pmVlE1aWd5WEFuRVExYVBBb2ty?=
 =?utf-8?B?VURpbk1DM2JlaTYvTnRJT2RGaE5ydmdXMTlMWTV2N1pvUlNmUXc4SXh3cUhK?=
 =?utf-8?B?cGdXTXpyTGxod2tUS0JWa25nQXJKR1NCdWdYQmptcVpaQmd4T3JRb0VJMXFU?=
 =?utf-8?B?U1dmWG10ZlFmV2lQOGhNcytjUE0rNnk5UHRTb1RDcHZjaHJwK1h0UEs5dEJ2?=
 =?utf-8?B?ZEFtd21IWVU3a3ZWeGVrS1V4d1VWVmFLbzVTdVc2ZE1zUEJEZndjUEFRR296?=
 =?utf-8?B?bnNFVXh6L3A2ZUkxRlVGbUtmeDJkMW50YU0rdFFuMzlFSDl3ZWNWdmtSN0E4?=
 =?utf-8?B?TENCdmRJNFl2d29mbHVadlBGa3l2MEJ4R3NhZjV0RUMwdWxXL3ZQbG9zSEps?=
 =?utf-8?B?Z1o4Y3ZmcldpZGhzMHFlS0EwQkJzbTZxYTJTN0JIQXVRYUdxYy9NbUcyYWZx?=
 =?utf-8?B?eEx4dUtGbTM4cjArZStmQTlmQVBseTdKWGhyOFRUbHFTUVdYMTVSUmw2bmtQ?=
 =?utf-8?B?TS9rSCtWK082VzR5NFNlWXVYR3hmYkdqczZSNkFla1A2SUxDaFE2cVlHRnJV?=
 =?utf-8?B?bGZLN2RLQWF2bWR5YjhNY2RMV25idDJEK3NUcjhPbkJQRGRaRkkyQkEwRjNm?=
 =?utf-8?B?aS9IbGNPbDlPdXRwd2R2clcrKzVLR3J0T0R3UDdEUlh0RTlqRmVUd0RRUWJj?=
 =?utf-8?B?NlhvYnRhYTdCUTFlUkUwc2VyWVZXYlJnT1QvaFJzK1lXWTJpUkFncWwrTmNW?=
 =?utf-8?B?a0MvQm1pSWlENndvTHp1Y2pCbzZMdTB6eEZQbG1nbU9KZDc1TGZmaVhkZXkv?=
 =?utf-8?B?SFFzUU1nbnd5NUkzVDBPRGdETlNxZjFQOGVhdGhRZDZKUFI4WGpzeEFhejd6?=
 =?utf-8?B?Z20wUTlsSnpZZWErWXBwQXBOZ1QyT0crRjNNS2IwdU0yM2YycHJmRHYwd3Fo?=
 =?utf-8?Q?upWZirz084cu8RhB6xKSjGDJSB3?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BN0PR10MB5128.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 866e38d1-fc31-40db-bb1f-08db758f3575
X-MS-Exchange-CrossTenant-originalarrivaltime: 25 Jun 2023 15:16:54.0414
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: iOfjMvhxIvZ8+glBKARu5d0sFJS5GBwM2ppwsXdE3IafAk9Opf/sZja1bYJ5QIyVdE5hEPmD7ze5WN4cwgtWXQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR10MB6440
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-06-25_08,2023-06-22_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 malwarescore=0 adultscore=0 mlxlogscore=999 phishscore=0 bulkscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2305260000 definitions=main-2306250145
X-Proofpoint-GUID: 1XY9u4qN7pZunCOYDTge_y1qFJ-Qyr9K
X-Proofpoint-ORIG-GUID: 1XY9u4qN7pZunCOYDTge_y1qFJ-Qyr9K
X-Original-Sender: chuck.lever@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-03-30 header.b=ng4qyj33;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ccsG0ylE;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
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



> On Jun 25, 2023, at 4:46 AM, Geert Uytterhoeven <geert@linux-m68k.org> wr=
ote:
>=20
> On Sat, May 13, 2023 at 10:54=E2=80=AFAM Dan Carpenter <dan.carpenter@lin=
aro.org> wrote:
>> On Fri, May 12, 2023 at 01:56:30PM +0000, Chuck Lever III wrote:
>>>> On May 12, 2023, at 6:32 AM, Dan Carpenter <dan.carpenter@linaro.org> =
wrote:
>>>> I'm pretty sure Chuck Lever did this intentionally, but he's not on th=
e
>>>> CC list.  Let's add him.
>>>>=20
>>>> regards,
>>>> dan carpenter
>>>>=20
>>>> On Fri, May 12, 2023 at 06:15:04PM +0530, Naresh Kamboju wrote:
>>>>> Following kernel warning has been noticed on qemu-arm64 while running=
 kunit
>>>>> tests while booting Linux 6.4.0-rc1-next-20230512 and It was started =
from
>>>>> 6.3.0-rc7-next-20230420.
>>>>>=20
>>>>> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>>>>>=20
>>>>> This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and qem=
u-i386.
>>>>> Is this expected warning as a part of kunit tests ?
>>>=20
>>> Dan's correct, this Kunit test is supposed to check the
>>> behavior of the API when a too-large privsize is specified.
>>>=20
>>> I'm not sure how to make this work without the superfluous
>>> warning. Would adding GFP_NOWARN to the allocation help?
>>=20
>> That would silence the splat, yes.
>=20
> But introduce a build failure, as GFP_NOWARN does not exist.

This is the fix that went in:

commit b21c7ba6d9a5532add3827a3b49f49cbc0cb9779
Author:     Chuck Lever <chuck.lever@oracle.com>
AuthorDate: Fri May 19 13:12:50 2023 -0400
Commit:     Jakub Kicinski <kuba@kernel.org>
CommitDate: Mon May 22 19:24:52 2023 -0700

    net/handshake: Squelch allocation warning during Kunit test

    The "handshake_req_alloc excessive privsize" kunit test is intended
    to check what happens when the maximum privsize is exceeded. The
    WARN_ON_ONCE_GFP at mm/page_alloc.c:4744 can be disabled safely for
    this test.

    Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
    Fixes: 88232ec1ec5e ("net/handshake: Add Kunit tests for the handshake =
consumer API")
    Signed-off-by: Chuck Lever <chuck.lever@oracle.com>
    Link: https://lore.kernel.org/r/168451636052.47152.9600443326570457947.=
stgit@oracle-102.nfsv4bat.org
    Signed-off-by: Jakub Kicinski <kuba@kernel.org>

diff --git a/net/handshake/handshake-test.c b/net/handshake/handshake-test.=
c
index e6adc5dec11a..6193e46ee6d9 100644
--- a/net/handshake/handshake-test.c
+++ b/net/handshake/handshake-test.c
@@ -102,7 +102,7 @@ struct handshake_req_alloc_test_param handshake_req_all=
oc_params[] =3D {
        {
                .desc                   =3D "handshake_req_alloc excessive =
privsize",
                .proto                  =3D &handshake_req_alloc_proto_6,
-               .gfp                    =3D GFP_KERNEL,
+               .gfp                    =3D GFP_KERNEL | __GFP_NOWARN,
                .expect_success         =3D false,
        },
        {

Is there a platform where __GPF_NOWARN is not defined?


--
Chuck Lever


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/206F3FDB-59BE-4386-82D2-6FF3CD16D053%40oracle.com.
