Return-Path: <kasan-dev+bncBDUO37VG7MIBBYPE2KMAMGQECHJQOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 957DD5AC4B5
	for <lists+kasan-dev@lfdr.de>; Sun,  4 Sep 2022 16:12:51 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id k16-20020a635a50000000b0042986056df6sf3406940pgm.2
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Sep 2022 07:12:51 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1662300770; cv=pass;
        d=google.com; s=arc-20160816;
        b=vMokERay7swf++GhXaieu2dcUWoekBcPMeZAvrY7mgHWLKwcZ2ZUiXTmXgTMqEJOMd
         h+W+ckqqdL7IL1ya0BOzxOL9asdhnh/51zqMHVBeBn8wQ7CrhetsngXUuy/RcnUCvvym
         KTy6yjn8pp2u7x/xt9ZMshJUP32do1t1GvtFO+cBuiTrXyHUqGB33Ps12YIy4UqDblnq
         pPB97CENavExUnSJS5CQ5PIULhnDiRCS9TRokyNAZ+YEjntbvroEStnjfC4YSRLOD1Ob
         vMgg6hC/+41IfD7CvW9ROG4SVYhMt9IoHCiO34SoTIL+QCCXxEGVGE9es8K17Nl9HySX
         /J3w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=BT1fAMq4C2drBx6AMnWbMwFOxOJrorDn12b/872voRM=;
        b=Lu+UZs6n/wc57s+iXdRtccVHgH5vf46pJWaggJEHqV8pKBGIIJDvLY1wRgEgovKfD3
         XygIs/2vkCQA+LbPNEm0BjZM9YFf6k6pFrGkf0WJ3aHAsYiiFufWhxnCz5RsSC49XLGh
         ALfhRPIOryVOkVMcV+jcGK8zDmE8sYMNPexUCSltQ/kC+FOGrZ9exY2YT9tty3QIbEzM
         APg0KEbuRy6j0bX2JtuX0kimDzg6atvzrdD7BacXoMhtkVDs7ULgYLLT6Pp3VF3sz4w8
         AwjQjxD3VHukan+qS00QrNzQhngoq/1tyP0faNNPNHnEu6DlJfJHTH3boegLwNZAPaAU
         u7MA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@qualcomm.com header.s=qcppdkim1 header.b=P4Rqm6CX;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of ericsun@qti.qualcomm.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=ericsun@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=BT1fAMq4C2drBx6AMnWbMwFOxOJrorDn12b/872voRM=;
        b=ACJtGt8MLJgWPVr2U4hg+f5fG2MtYOJ5Qc9VJnUTntXc7P/qPX+LNd0NNzXJQupZhc
         UU9lrpfbj2oLJjWqCTAKhsV507DgEUCGBzDUdKC3RAH4T4jxDb4uG37aENEvN6B//4J7
         /SA8udhP9QDwSyg3pNePntC+dN1dPqRWCeyBDzKHRRQziqOH8kpl4iVyLOLtVGZPP4QG
         A546jV9ttwUvO8IBYMUYysS9NDaSdujMmJes19N7ZG4ik5EnkX6hnrul2yoBkNc+0KZG
         mFUlS+6HgksHZqkGMhklEta5wPsxyF9aChr8xopASNac1KY89R4kBPn0SolqCqNE7Ekc
         nTXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=BT1fAMq4C2drBx6AMnWbMwFOxOJrorDn12b/872voRM=;
        b=p7ze8YiuJXnNhs9zPzvbkFrXIpOrgltv1mHNPxGtrI2JBfTdskSkE58h8zwaz3aoVK
         3ceWpCw9ZkCbPYLPl4k7pzlKszFeE9IQFvFA+eu5cFZ1xPxRwktiVATQvB7GawbHPaGB
         30A4vqbPLEHBHS8mwqRyxguqAwZzUpk7pxGaUetRY9BvWxue/feXmddlPBSDW70XRaB/
         QT1d59hukrdakHUhzVA5RrU23n0AJ3I0BL3XaY6JbR8Xc8/spjFGQlDVrEbMKhlDln53
         rCgfE6XNZO/sw61edvQ0vK8i9GyBopockITnAev6cBXBp90IiIQ9zsRa56kSH6xRtLfB
         IP4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo26SZaX5SyqXeQgz4hHfJi6LlvcZ3m25yIthgiqOVubTmeWM72E
	1mMz75WD20kom1yDh+WQJ4c=
X-Google-Smtp-Source: AA6agR760LCeakT31MhZS6lhYUomzqLuxvlNOlDQDjSL/gck/9TYnY0v46ydVUl7+tWQz3AAPB5BcA==
X-Received: by 2002:a05:6a00:21c2:b0:52b:ff44:6680 with SMTP id t2-20020a056a0021c200b0052bff446680mr46000997pfj.57.1662300769931;
        Sun, 04 Sep 2022 07:12:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:28c4:b0:1fb:a751:8707 with SMTP id
 f62-20020a17090a28c400b001fba7518707ls8265933pjd.2.-pod-canary-gmail; Sun, 04
 Sep 2022 07:12:48 -0700 (PDT)
X-Received: by 2002:a17:903:2343:b0:176:830a:c2ae with SMTP id c3-20020a170903234300b00176830ac2aemr7280575plh.107.1662300768756;
        Sun, 04 Sep 2022 07:12:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662300768; cv=pass;
        d=google.com; s=arc-20160816;
        b=YQDxtywigdjY0YVI5Irr+Gq8habdqvXIZTwlw+G8qPLfMyZn5qj0HMRVZC/F4p4byn
         tyvJwLSkdFHWTfJZdBSQ78yjqh703Z/3kOMcIjAfBHnGE6Uj9zqhdAEf6QZhiUk9wnCh
         CfbZGnrYYmfwJpPU1KU1j95Nu2Z2ozN0x9iTNSkoJ9q3CobHonrkhpbwnOE3oE2RLRli
         U04ChtdrznS9GyB4Ac/+65vfmMm10B6NFr6ePwbx7zFwbCf6ktzSzeq9xConjk2STtuR
         eOVVDIImMoT+zJoyEJrgqfu2bUktodkxGx/Z7PcVZ06/IKUFzw8idRy0xgskQ/s42ahs
         zNQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=LF6wUGCYDVWcP7+7e0WWHejeTZu1t/RLq5u/t+pPJ8I=;
        b=M1Qx6u9q311wXr6vwRjMKRtovU0lzmiYfc4rjKhIxoLSHHANd/JI/kz2Z1b9NYlYoB
         q71VaGcrTikrAykYlpENE9PydectWgtfj4j1u70aoLYWZAIFQbHl+bmFt8cw3LnvTP9Q
         hnvSykQih/0H5Uk6E9K4vpkA7XXzJ0NRing6qdAXFVGaWUAwY+FngaL8aGc+OcCZzMk9
         B0qKIAeTw+j56qS3TwSL7ZRuug/q0CXR2IvFinu1+JwjV6b3BkBkdXbU1Oq3/2PHcwRc
         wYxJdDaXjLghlEmznnOCbbA1mcp6fka/d3n/nYloTaP1Hb5rGJXq8yyqKxgrfLDK9ryk
         pdqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@qualcomm.com header.s=qcppdkim1 header.b=P4Rqm6CX;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of ericsun@qti.qualcomm.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=ericsun@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id e8-20020a63ae48000000b0043238c0bd99si246184pgp.4.2022.09.04.07.12.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 04 Sep 2022 07:12:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ericsun@qti.qualcomm.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279862.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 284Dpjws007034;
	Sun, 4 Sep 2022 14:12:46 GMT
Received: from nam11-co1-obe.outbound.protection.outlook.com (mail-co1nam11lp2169.outbound.protection.outlook.com [104.47.56.169])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3jbypmj5xe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Sun, 04 Sep 2022 14:12:46 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=O1qt+DQsoFO+ILTnXi1HJ6/o4sdRDOXE0U7gfgZTHpwvVO4WbJk59y0lZmFHcf3y+ozAszZLWlFdKdFw7ToDTPkfF1zWBiYkBc8uaOYK0n9P99GZ9FIPfM0xTgAMSDpBO2Bw/qMQ/KEf5D7Zc9D7mvLH3L/U6d7yAPxGCXCk5XgZ9XD20LDWi+h8PVy4aDvz2lGGOy0yh3nZxUQgkJpMtD2KovMgfM2U7zOiUZti7w6o/AuPxoJlN2py34tNU8avzriE1q17pZ6MuCRfaSsJsXelE69Q0qgsOcbj/8Z96Jt3cW79QY4ZR+OyLKCE7ieP6ZNVkTtRrYqikFw+2OC7XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LF6wUGCYDVWcP7+7e0WWHejeTZu1t/RLq5u/t+pPJ8I=;
 b=nmv6KcesSde1q+dXcUrHKprKdOqDBRP0tPTBfvHBvN6W4rn324NRwiNizt/pbZCyChswvxkXs4jCNjWLSjmPIcKdXyhM25ScSyjU2yCzTWArhNaHwn6R3jmKLEXcLdd1zbUkpVuxtjU7z8JpQ7MIOzKp8QmnBm1KXE0hXlB3TiARw8ohPVQXnqvEplGYpOyuqyc/u1e2HjJty6qdjhZK0v6bl9zpvlNqYDKAQlak+VKmmbRvQSyhyAT3U6ty8MaaiJ0b7IJoJUyZqpm9UYiN9HbJAMIn8qN+uZkAgUs8MDyBNilzyOmu5j6k6WxliIqQe5R4mg9UPWF/ZxpYFmInWA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=qti.qualcomm.com; dmarc=pass action=none
 header.from=qti.qualcomm.com; dkim=pass header.d=qti.qualcomm.com; arc=none
Received: from DM6PR02MB6922.namprd02.prod.outlook.com (2603:10b6:5:252::8) by
 BL0PR02MB4756.namprd02.prod.outlook.com (2603:10b6:208:29::23) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5588.10; Sun, 4 Sep 2022 14:12:43 +0000
Received: from DM6PR02MB6922.namprd02.prod.outlook.com
 ([fe80::4ef:c106:8b55:1cd1]) by DM6PR02MB6922.namprd02.prod.outlook.com
 ([fe80::4ef:c106:8b55:1cd1%6]) with mapi id 15.20.5588.018; Sun, 4 Sep 2022
 14:12:43 +0000
From: Eric Sun <ericsun@qti.qualcomm.com>
To: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
CC: Andrey Ryabinin <ryabinin@virtuozzo.com>,
        Alexander Potapenko
	<glider@google.com>,
        Andrey Konovalov <andreyknvl@google.com>
Subject: RE: Enable KASan for ARM32
Thread-Topic: Enable KASan for ARM32
Thread-Index: Adi9Bm2bjyW7hDzUTfKSo6s6uHHQEQAATbqAANe3iwA=
Date: Sun, 4 Sep 2022 14:12:43 +0000
Message-ID: <DM6PR02MB692214E8514F99A46B0643BA877C9@DM6PR02MB6922.namprd02.prod.outlook.com>
References: <DM6PR02MB6922BEFFD6AF46E62B57342987789@DM6PR02MB6922.namprd02.prod.outlook.com>
 <CACT4Y+ZrpjxwVN52NJBeLaLPgTZC4_6wspwNJSe=s2NCdGTq3w@mail.gmail.com>
In-Reply-To: <CACT4Y+ZrpjxwVN52NJBeLaLPgTZC4_6wspwNJSe=s2NCdGTq3w@mail.gmail.com>
Accept-Language: zh-CN, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 116ac754-6c43-481c-3983-08da8e7f88e5
x-ms-traffictypediagnostic: BL0PR02MB4756:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: lKvD7YqhOnMIXmV9+lbm1mc+AWiPZAKM00wt/1xoqQjjnwG+OHckzvs4ptRFKrvoi/TYjBJciWeCjGfhWKf3c73O/HHd6lbwbReN3YwyD9SegV20wqH2+qiM6Z23o3AtIJGNlLQr5bBtTJEOlU5E/+FqxqnteEIpRsghk8ulO6IejlqcLqM5iQLTjkiLgCyMiyngofnVxJwv8xNdSlUfWHPyy6vi9QTxqumSe4PpN+sdb12EwZt+te1HMwaJXVs2A5EHaYgND0WVlEERsKym99jfO8XoElvDJjYn7VHPusgTBieyD9N6V6+sDIDEIo/EfGmiRE28hRaszI2RD8zk3xlYKW9spDpySO4ct3cGe/G3LjpMGtGY9gMOSvdQ6JslhztV7D8G8/L3JCtsoiuY40tse+2ocbx7CduFPeKW06CcHoFaZ0gtDYrveLyFHasWrcaFvuKssNSXZQz38MpLJsWxuKo+Zg2EZzieH7ZBrSi5rTUGPp55F5RRUuEVu5N/QIExcgvcvKF9P9oN238+h68JTSO4gj0xguDH4ERmmjJUhVzowPNZEkqzyS1CpBn1XeSfwNbH2cbFKOHRwwKxGTMkrxLD0t8FdFcWf0YJkGp3d9RlBWjpLNIGFnZFe5Y8d8t39XEXnW5FbcT1uuM7WIID+3U0pI3wIemHpc/K189pnMpPmLeW+X/tKVCmLiatNX2GVNgb3Zsax5vO51U2sL6ZMVbrYgj6tWuV5gr6d4RvIyNvz1l4izsCE6fr/iiXY8+c1hcq+M+ydDdmTahzUL83VAJ51L6YbC5WQ6Q2hyA=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR02MB6922.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(4636009)(346002)(396003)(136003)(366004)(376002)(39860400002)(9686003)(7696005)(316002)(4326008)(122000001)(26005)(6506007)(5660300002)(53546011)(38070700005)(52536014)(8936002)(966005)(2906002)(33656002)(71200400001)(41300700001)(478600001)(86362001)(186003)(83380400001)(38100700002)(55016003)(66556008)(64756008)(110136005)(66476007)(76116006)(66446008)(54906003)(8676002)(66946007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?QzZpbnREMHhNa283blpPbTdjNk1tOFNPcExGWCtwdTdwT2RUZE0yMktzcXBM?=
 =?utf-8?B?ZmhhUzBzRm1tWnoyNHBRSUNhYnhKTnhzYk9pcTJCUXdFTFp4Y3VMejdCMkhZ?=
 =?utf-8?B?Tk5HUUcxRnkzQ2MxcHN3SUpFSFphRTBGak55VXIrVEsrbWQwb24xSWE5ZHhD?=
 =?utf-8?B?dVVuV24wdmwzRGdxWUsyMEhHREo1a0hDVk9kcW5GQks4M2ZDbS9Falk5Umo5?=
 =?utf-8?B?KzRiczdQOWw3cEZaN1h4WmhmWmJhbGpBcy81OFFlQ0oxMjVuQU1xTm9UN0hF?=
 =?utf-8?B?S29UK29icFV5cXJsN3hnUHFla2Q4d2M4ZEVZR1lMVWxyaHJrTVlIMW5LanlZ?=
 =?utf-8?B?NEd0T3o5YTg1UHB6YjVHcTZrMzMrNERGYm9wT05uZWRsWnVKRVZFMlRzbnZU?=
 =?utf-8?B?d09LWXNwbTNyV3hUcHpZajRoUmhFU0RhN2syM3pQSllwU3pxWXZ1c0NlYklh?=
 =?utf-8?B?VzBrWER4dURvMXNoemJhd3NZeFM1eHB6NjJ5c0FKZ2Z6VURONVFJRGZSeFgx?=
 =?utf-8?B?emFVSHZIaXhmYkwybGVUbUw4cWNsajB3OXN0cDdaUE01YWhwb0pyQ0VQNURo?=
 =?utf-8?B?ZmV2eWcxeTY3eXVqZG12bTl5L1RaUDg0ZTdkdFFxWkRkUDZIOG1sYXRialdZ?=
 =?utf-8?B?bzlzdU5IK3ZXbXpYMFlRSmpXc0VSTTQ3dmNHaWdaaTFKK2JXWWM4TjljSG56?=
 =?utf-8?B?aXF1aWdhYzg0QlIyN3FVS1BCNjl0Vm1qL3RhYTBhcU5oMXN1NDRYN0JydWR2?=
 =?utf-8?B?d0pMRW1oS2FOYUc5bHVFMGJHYTJXbU4vcG54eGFPaXlKN3RtSnBJSFNtL2Ex?=
 =?utf-8?B?M2dQWXVwN0hNdi9OL0IvalArSC9pVXZJbDQxMVA4bjFYUzhGb1F2OWw0UWk4?=
 =?utf-8?B?eGFRMHVNZy94bmlhSHp3VzFOSW0rWFZXeFJkL0wrV3YvT0pxdGxnaVh6Y3ky?=
 =?utf-8?B?aTJuOWcxdTNSSS9wa1B5SUlQZ1A5TzRLcEJPL01pRGZuQ2h2TXNoNnFLSTBm?=
 =?utf-8?B?UGFZbHZLRWFEeS8rQ3V1THAyUDJQV0RBTGI3QzVHMElaUHJKY1RJVlBhWVIx?=
 =?utf-8?B?ZmZSTDVWT0EyaGdOeG10SzRYQXdManJQd2tENVd3NnlCWVI0TVFiM3FZSDRE?=
 =?utf-8?B?TG9jZVpUb25XaEwvdWNXOFBGNzdPbjB3cHE4bVMvQWRqTjBFay82WkY5QWtQ?=
 =?utf-8?B?OHJJTERwWmovNjEvbVh4VVF0dDVScC9vYnhZcE5KZE4yeitBcmRxNWZ6amMr?=
 =?utf-8?B?dVVVMFdKV3RiZDYwRWxQaVc4VWV0R1RlUFlDeDRrMGxadGM4VzNxWi9HU0Yy?=
 =?utf-8?B?U1N0UkV4RWN6YTZRU2xQb0ZScEliWThtTjVsYXVxY2N4QndoTmNOYVo5c3NX?=
 =?utf-8?B?c3phUVhkUmYxK1JQeEFGeVN6dGYyLzhTblo4Nk1OdFdHamtSc3V6UEJYVXBZ?=
 =?utf-8?B?aXJ3bnhDNGd5bzFKc2V3TDVSblE0TU85NEVrQmdhK0s1V1oyS0w3R055d2xz?=
 =?utf-8?B?YUx1U0hUaHhndlkxYWZGaGZOVDZvNDg1TStFdlBrSHJtTTdQM0dRMlp3Uzcz?=
 =?utf-8?B?R1VDMmxIVG1pdVRkSVhMMnZIOEh1NklLYkR5UlFMMzNzc3grRzFrT0R6d21u?=
 =?utf-8?B?TGhqd0xCV056K1pueWlIVXlsa2xWRG83bnREWWYwN2dwdWI3bTFocXVQSUJn?=
 =?utf-8?B?M0xPTTRoWGxzSE1vUEhDWktWVlhPbWtaMFZQUDBndlJXYVIxNTh3TkNiL3RC?=
 =?utf-8?B?UW85R3JsVXVVWklqS1hFa2pjOWpkRmdKUTJSWU84YTBqa1didkFMSEpMMVhY?=
 =?utf-8?B?Rm1OYnpLZzBnSHNYYmFvNnhIR2dNa2EvTEMxUm1zaGVLM1ZNVDQ2eGp5MTAv?=
 =?utf-8?B?MEwvajRwVTQxc0dWQjUyMk9vVnVCYSs2UjUwc3dtbUhmdzFKdXVuOUw0WHBO?=
 =?utf-8?B?cUlGWnZxRURZNWF5K3dyZnFTRUxnWjdQQXVLZTNmTnpGU1ZiM0VLTC9GK2Zw?=
 =?utf-8?B?TGw5NVdlNmxucXhhNzJLOWRna2o3QW9LQTgxSHhra05iRS9qdjJQRnJicitB?=
 =?utf-8?B?ckVKdVEwOWpCVUVHOUFsVjFpaW9LS0s4bXJ2TGk2eEZvcXpWeC9DaWhzK3Fw?=
 =?utf-8?Q?p9jSb6xJOwsj5m75VuhwIKs0O?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: qti.qualcomm.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM6PR02MB6922.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 116ac754-6c43-481c-3983-08da8e7f88e5
X-MS-Exchange-CrossTenant-originalarrivaltime: 04 Sep 2022 14:12:43.4436
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: HK9x/nn3iXwWgrnkfdPl/by2uDcuYxQGH/qS4Ke3PxN7V4Nju4lx/GVusPTzeOsUJwMFULLcMsDWpLVheqGG3KkKKrH+aSMxUwVs5nDG9Ks=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL0PR02MB4756
X-Proofpoint-ORIG-GUID: unjjHHOWzcDric7JcRusWa3Ddu-UL5As
X-Proofpoint-GUID: unjjHHOWzcDric7JcRusWa3Ddu-UL5As
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.517,FMLib:17.11.122.1
 definitions=2022-09-04_02,2022-08-31_03,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1011
 phishscore=0 spamscore=0 mlxscore=0 bulkscore=0 adultscore=0
 suspectscore=0 lowpriorityscore=0 malwarescore=0 mlxlogscore=381
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2207270000 definitions=main-2209040071
X-Original-Sender: ericsun@qti.qualcomm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@qualcomm.com header.s=qcppdkim1 header.b=P4Rqm6CX;       arc=pass
 (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com
 dmarc=pass fromdomain=qti.qualcomm.com);       spf=pass (google.com: domain
 of ericsun@qti.qualcomm.com designates 205.220.168.131 as permitted sender)
 smtp.mailfrom=ericsun@qti.qualcomm.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=qti.qualcomm.com
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

Hi Dmitry

Thanks for your reply.

We are debugging memory overwritten issue on 32 bit- ARM  based Devices, hope to get more details on it.

As said in link below 
https://static.lwn.net/kerneldoc/dev-tools/kasan.html
==================
Support
Architectures
Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, and xtensa, and the tag-based KASAN modes are supported only on arm64.
===================================

Generic KASAN support on ARM is available now , right? If yes, it can be supported since which   version of kernel?
Or, it's only enabled on ARM64 not ARM32 by default, we need apply patches to enable it on ARM32?


Thanks
Eric Sun

-----Original Message-----
From: Dmitry Vyukov <dvyukov@google.com> 
Sent: Wednesday, August 31, 2022 3:03 PM
To: Eric Sun <ericsun@qti.qualcomm.com>
Cc: Andrey Ryabinin <ryabinin@virtuozzo.com>; Alexander Potapenko <glider@google.com>; Andrey Konovalov <andreyknvl@google.com>; kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Enable KASan for ARM32

WARNING: This email originated from outside of Qualcomm. Please be wary of any links or attachments, and do not enable macros.

On Wed, 31 Aug 2022 at 08:58, Eric Sun <ericsun@qti.qualcomm.com> wrote:
>
> Dear Sir
>
>
>
> I am a qualcomm BSP engineer , debugging kernel memory bug on ARM32 
> based DUTs
>
> And I noticed that there are patches submitted, is KASAN for arm32 ready now?
>
> Can you please share the patches to enable this feature?
>
>
>
> https://lwn.net/ml/linux-arm-kernel/search
>
>
>
>
>
> Thanks
>
> Eric Sun

+kasan-dev mailing list

Hi Eric,

I would start with these (+any patches that were sent in the series with these patches):

$ git log --oneline --no-merges --grep kasan arch/arm
8fa7ea40bf569 ARM: 9203/1: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC
565cbaad83d83 ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC
9be4c88bb7924 ARM: 9191/1: arm/stacktrace, kasan: Silence KASAN warnings in unwind_frame()
8b59b0a53c840 ARM: 9170/1: fix panic when kasan and kprobe are enabled
c6975d7cab5b9 arm64: Track no early_pgtable_alloc() for kmemleak
c2e6df3eaaf12 ARM: 9142/1: kasan: work around LPAE build warning eaf6cc7165c9c ARM: 9134/1: remove duplicate memcpy() definition
df909df077077 ARM: 9132/1: Fix __get_user_check failure with ARM KASAN images
421015713b306 ARM: 9017/2: Enable KASan for ARM
5615f69bc2097 ARM: 9016/2: Initialize the mapping of KASan shadow memory c12366ba441da ARM: 9015/2: Define the virtual space of KASan's shadow region
d6d51a96c7d63 ARM: 9014/2: Replace string mem* functions for KASan d5d44e7e3507b ARM: 9013/2: Disable KASan instrumentation for some code

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/DM6PR02MB692214E8514F99A46B0643BA877C9%40DM6PR02MB6922.namprd02.prod.outlook.com.
