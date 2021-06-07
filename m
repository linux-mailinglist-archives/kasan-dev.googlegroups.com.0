Return-Path: <kasan-dev+bncBCSPFHXUVMKBBOPH7CCQMGQEPH4AWHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id EFFF139DFC5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 16:56:58 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id t10-20020a6564ca0000b02902205085fa58sf10350376pgv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 07:56:58 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=subject:to:references:from:message-id:date:user-agent:in-reply-to
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+YqRRtximRUwvklY5/UviEbUXA5nLjOJU35AocZ3XWk=;
        b=Gjujc/80d1ENj5lZhJyIAut45DkEX7r9xBYRe0rqM01Zuc371YsXtaGMGZ/olBj7Dq
         x6iVQMDxMnm1ojn6FO9dI26GjMnsJpfeSA2tgpLXz/tbE5D5wSJUbkhcE4VuJereqYYo
         b3XLmu/C/502BMq8iwo/QQsEPi744pM0Dh8zhSOsgv3aKejUAnpuLGhFX79aJTh030zo
         SRPEHaV+d8+kM+/6dZCHTiSSBfJPzpzB/qePwbiK6CAFN3Cr/MwUlrE1p7LPNBFedS7t
         2oAwweJYmeXj8j6xfBfotT6nX0duR6EGnHx+blHek8e1+rmiESZghbB4qnz+EhTyaK/0
         Yu4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:subject:to:references:from:message-id:date
         :user-agent:in-reply-to:content-language:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+YqRRtximRUwvklY5/UviEbUXA5nLjOJU35AocZ3XWk=;
        b=SEveWAnnte5OL3jt/SFetLFOXaiXuHppVHDcB18l/gVP6tsfEM/3ztgOaj6gN3ZXRZ
         MaaNd4X7+zYLkbWozgGvADNAqStj+Dt7ufxQBs3L2H5IFKs0RkvuILzf3HwV9GoVI2/+
         gQWYyIMZeWqiJqiaqTtL9/GSvpIlBdUXgeaueVQ65dXC1mWjEMhOff+ZbqcHwvNFCiHJ
         2Vz16aJGchJSuJO7hqJaAZANCFki+MSvarMdR5K1YJuEClAH9ao/dSGLhjhLol40Mnz/
         /9/OeEAMmwqoNxPvE+Z4kn2Y7k5UACGnC2XtRC1JVcehfEafieOpgR7zSqA1hEpXknLL
         ZzVg==
X-Gm-Message-State: AOAM531M+SVfEZ66LpE2XfujRWVcvbDExY/++YKMyTdwUHzxEVOVOvmf
	Enat8ljdWL540gfPR6yGnts=
X-Google-Smtp-Source: ABdhPJzOSh1eTdUvFPRRrr+kPyXSIvF/23f0vbFk8KwtvCGsK31dKmWDR+Y5HflspSZZfIuCjqyXCQ==
X-Received: by 2002:a17:90a:9103:: with SMTP id k3mr32373731pjo.117.1623077817707;
        Mon, 07 Jun 2021 07:56:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls7592389pgv.7.gmail; Mon, 07 Jun
 2021 07:56:57 -0700 (PDT)
X-Received: by 2002:a63:f644:: with SMTP id u4mr18053785pgj.225.1623077817182;
        Mon, 07 Jun 2021 07:56:57 -0700 (PDT)
Received: from mx0b-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id u24si1137767plq.4.2021.06.07.07.56.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Jun 2021 07:56:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=5792e56dba=yhs@fb.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0109332.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 157EiqDd018308;
	Mon, 7 Jun 2021 07:56:28 -0700
Received: from mail.thefacebook.com ([163.114.132.120])
	by mx0a-00082601.pphosted.com with ESMTP id 390s14p23t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Mon, 07 Jun 2021 07:56:28 -0700
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (100.104.98.9) by
 o365-in.thefacebook.com (100.104.94.199) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 07:56:26 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=GUp5P5NsYc3PAK3rG/yp9aCZ+mV+LL8dg3jcT/5C5lGGMGltlrPNMVwdrANRgHk7EL6lbnrj3Zs55wX9Nk9txdWeutoYzlcQ2ycV++NMubE/dgNTh6OROaJCCBkHLs0sSHjRxMCQEBboWammZxRvyTbWHIciXBIP6AO4uivCGe8UVnEiCsZoMaxZVX5Kg0MBJVkG2vQx++pkZdUTCF/mi6INqd88RAXWjMK9BIYnqJbBik7OnhWQj7i8pSB9oJ30cEJ8Zwx//lh+kyhxSoCoiawBxvBz5S5G0bMthy7hEhiwh4xkxwHvjmjBh8CqpwM+9srNZJMv4hFUVAqdu9QvhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=OKiUFXMeeiL7WyBWC/C3vCAaK2MBFww+mQeAzYWHIXs=;
 b=DTaLflDlFKk6nuGBieH1WRXzYq+3vQrKnvjaFoULOJNt3RttGi0Cmik2YsmNiAsz1mMkcIQYoRCQjy9pwu1C7XDqKa8GDMn9Y53kUX1WjhxrKKCmHHX7bwgOa2jhckMnSCQOujUbD/QoTclRxN4XUFNh3in7pySGM27gD/rsD0cko8canD+bgchvBtMJIgSYUycGeI1UzKUF7OjF52vyC1aOk/hGqWxRhDaNvrKDcFh0uMb+fsEsxLC2AoO1SE1WyTwD9sWtabiwNzfY65JO4hoJMMBku4BL3b6pjYpBEUSQVwNSbRe1Y30+3d42+og6X7i/28fFSJ8guU+YuPRxXw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from SN6PR1501MB2064.namprd15.prod.outlook.com (2603:10b6:805:d::27)
 by SA0PR15MB4014.namprd15.prod.outlook.com (2603:10b6:806:8e::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4195.23; Mon, 7 Jun
 2021 14:56:25 +0000
Received: from SN6PR1501MB2064.namprd15.prod.outlook.com
 ([fe80::d886:b658:e2eb:a906]) by SN6PR1501MB2064.namprd15.prod.outlook.com
 ([fe80::d886:b658:e2eb:a906%5]) with mapi id 15.20.4195.030; Mon, 7 Jun 2021
 14:56:25 +0000
Subject: Re: [PATCH v2 1/1] lib/test: Fix spelling mistakes
To: Zhen Lei <thunder.leizhen@huawei.com>,
        Alexei Starovoitov
	<ast@kernel.org>,
        Daniel Borkmann <daniel@iogearbox.net>,
        Andrii Nakryiko
	<andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>,
        Song Liu
	<songliubraving@fb.com>,
        John Fastabend <john.fastabend@gmail.com>,
        KP Singh
	<kpsingh@kernel.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander
 Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Luis Chamberlain <mcgrof@kernel.org>, Petr Mladek <pmladek@suse.com>,
        Steven Rostedt <rostedt@goodmis.org>,
        Sergey
 Senozhatsky <senozhatsky@chromium.org>,
        Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>,
        Rasmus Villemoes
	<linux@rasmusvillemoes.dk>,
        Andrew Morton <akpm@linux-foundation.org>,
        netdev
	<netdev@vger.kernel.org>, bpf <bpf@vger.kernel.org>,
        kasan-dev
	<kasan-dev@googlegroups.com>,
        linux-kernel <linux-kernel@vger.kernel.org>
References: <20210607133036.12525-1-thunder.leizhen@huawei.com>
 <20210607133036.12525-2-thunder.leizhen@huawei.com>
From: "'Yonghong Song' via kasan-dev" <kasan-dev@googlegroups.com>
Message-ID: <e788d0c5-51a3-4cb1-52e1-f57d0d17d7be@fb.com>
Date: Mon, 7 Jun 2021 07:56:22 -0700
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0)
 Gecko/20100101 Thunderbird/78.11.0
In-Reply-To: <20210607133036.12525-2-thunder.leizhen@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Originating-IP: [2620:10d:c090:400::5:db22]
X-ClientProxiedBy: SJ0PR03CA0311.namprd03.prod.outlook.com
 (2603:10b6:a03:39d::16) To SN6PR1501MB2064.namprd15.prod.outlook.com
 (2603:10b6:805:d::27)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [IPv6:2620:10d:c085:21cf::1097] (2620:10d:c090:400::5:db22) by SJ0PR03CA0311.namprd03.prod.outlook.com (2603:10b6:a03:39d::16) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4195.23 via Frontend Transport; Mon, 7 Jun 2021 14:56:24 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 218db573-26ca-4b45-e717-08d929c46c08
X-MS-TrafficTypeDiagnostic: SA0PR15MB4014:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <SA0PR15MB4014655B1ABC3A96402A6E06D3389@SA0PR15MB4014.namprd15.prod.outlook.com>
X-FB-Source: Internal
X-MS-Oob-TLC-OOBClassifiers: OLM:538;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 0WP17DvnpvuVgDdlhg9500iYvZ+KHF+gxnYK0veqKXo1oC576cJdPyGi+CMHIPTDycffpN9K6Bda+N/s6xwoDuJfQ4G32oada6HpIQPKlLew3sW4FbqG4kuhWPpeYYXt2zbD6Vcaw4e220c7AZuXnMuRzNqtHzzt5aJWroia5XSPR8FqqzpB97TBMKUyPN6BI/w1X3fnBnhljXo/+F3ININV7e3wbeBc1/xUXiN2w0yTZJ1bYBeld90eBKRaomgSo3+pBYnFkq2kzyeo9hfR291HlP03eYKZWueuzxP7sKQ42BTUopOSn23iCFijskNiRuLGUlBTxCX/LNPo/Zuxxu8umeQSOgAKRjybI+p8/8+kFcyzgCSBW9iErIdAkrV6AicAbRAswDYnxN2OUPBRz0gjUY6nWgyUxGlEzXEYEr7WZM3NOBSTc8tVID3HB1XFBkEHpfLgw5ctQQcw/Za2HOh3VQgw0Zf4i8FhjIF5Gp5y7XfdeP3+2pZqBGVX6yaBkuuN6Z1xxt/u1WSN4LwpkAhvtMFR2+nRHxdclGfGBp1+co8019ebFYOqXnomZVPmNtnE0eGI3x1ahMH2bG0HyPOzgHks2rRub6XMN+IurRDnr/bBU0c0JxTevagd3FtL2EPxa4bgFmLJedb/qjWlwhwKa1x1cZZ/VnJbBNq94l2JKwdbLL0jYfYXGh9nKQCr4SSvaQUp3UW4Sc6HtJfnDQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SN6PR1501MB2064.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(39860400002)(366004)(136003)(396003)(346002)(376002)(921005)(7416002)(478600001)(52116002)(2616005)(53546011)(2906002)(31696002)(38100700002)(316002)(4744005)(16526019)(186003)(66946007)(36756003)(66476007)(66556008)(86362001)(5660300002)(8936002)(31686004)(110136005)(6486002)(8676002)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?MkdrTnRlOUdwLzhkRHR3a0ppRTRkblhNU21CT0orNlVYZ0NQaEFqYXMweHRN?=
 =?utf-8?B?bVIybjRFMWcwYU9EeDBaeXZvZ1VDYlBQSWxiS2hzd3djTkNkbnRRSGIyWCsr?=
 =?utf-8?B?UTNVTXhOd2U4UWRxS3NLdXZGSVFtKzJvMlVBN3RvRkllblUxVTNQNFVLc3NT?=
 =?utf-8?B?Uko0T2hISzRSM1I4cFhHMjcrYVZFbkVnRnpHSEtMbWFudmZVWkFpbDhkSE5n?=
 =?utf-8?B?TTRXVTBVZTdPWktMMGFZdm9iWG1ab2hVdm1VVHE0TldyemIxTmNvQ1EzQVlr?=
 =?utf-8?B?dDhhbUcvZUlzeTA4U3NlaHRCblgyNXpYejh5bWo1VTVxUXBOeTZBSWpjaC9F?=
 =?utf-8?B?b2lhSW1ScW5HUGNGU1M2cVFOMVlzd0NvVWJ1MFdVcG4zdTBXZE1RZml5ZGoz?=
 =?utf-8?B?R3labk1LcVNiYmc4NHBqSlVMUlJkbzAxb3dkY1ZUalNYYmsyci9nQjV4Zmll?=
 =?utf-8?B?Y0JwT1hDTGNZdnRNb0lsMmxzQ1ltWjdQRmZZalBQdXlYMHV1NTFNdnF4MVpE?=
 =?utf-8?B?MWZVcUducm5PMS9rZ3hwYmU0Ukx6SzYvOTJnbFhaejNNZFdoRlRIY3BDa0FH?=
 =?utf-8?B?ZW9LOUJodlJxRHg3L2pTZGt0L2dubUkzWmpBbHpVYWlwbE83K3Y1VnZ0K1Zh?=
 =?utf-8?B?cXhRTFRpcnNhQjAzM3IxWVVvZEtxYW10c2xobnVEcDY0TFYwTDFJUUVvZFEy?=
 =?utf-8?B?djJveTI4WHdsM1VHSExsVTlIYmgrRVN2TjVJYmk3aS9OSlRMQ1RDTXYreDVJ?=
 =?utf-8?B?SFNxbEJrSXBXQmh3em1QZUZHcDFGVHp6MnkzMWtkWkNCZXhaVmNFSFVJVHlq?=
 =?utf-8?B?SXV3MGxMVE1sQlFrR1k2MWZWRk5tSCtWTmdhSUFPSit3TXpXUWFLWkVTOWRG?=
 =?utf-8?B?UzhnaWlCbW96QnhhYlF2UmFnNE9kRnpWdm13UEliR2FpMlpYZXprSkxETmJi?=
 =?utf-8?B?cFJWRi8yTlVZcmdHZEh1RFMybThUT2p0UVl5VjI5YVZzaU01NWxySlZiZnk0?=
 =?utf-8?B?YzAzQm5xRWZmK2x5WCtMRHZ4NnNNb3pzM29lcnl0RnN1S0pSUVhxSDhiUVFZ?=
 =?utf-8?B?eVVWcXRzbXNKVS9EcW1yWmdBRE95RXpUOXFTeExJNUdSWmVEOVkrWjBhOWxk?=
 =?utf-8?B?VFZrV05zeitOeENRV0dKdFUrQnRDS25ZMEpCaGRRRG90Q2lIZWRTQnRYQWE0?=
 =?utf-8?B?SGFmNjJ5UjdrY2ZnL08xRmM0QXpvbFdtZittUWJUWGhtOGlHUG0yR2E0VnNw?=
 =?utf-8?B?TWFYaGQzOHovaG80S3FTc0YyZGVjVHJqSGRwTCtCa0Y4bGtLQWFqSE9pQ0Y2?=
 =?utf-8?B?T2VVbE90TXFNS1pmNW9NMVprQkFkZG45RWpLNG5YclZDZWZlR2Y4bmxUQ3Bv?=
 =?utf-8?B?WW1UR1d4K0VCaTFkeDVSZVJHTlBLUHVRTG41TCtaT3VwSVVGZnVQc2tEayt0?=
 =?utf-8?B?OGxtUThpWHpwN1R6U1gzdDRiWVowdDB6OVYwUVh1Z1BHYkFpK0twSnVYRnEy?=
 =?utf-8?B?L0k0Umd5ZUV0WER2eldwRExYYjRjKzJxN2lxbG9pcjFab0dncXFJN0Zjblk2?=
 =?utf-8?B?MHhzZzRod0FVMTFINEdxUG9nMWRENGNOY3hwTTF5ZFZFTGtZTllxcDBSRytm?=
 =?utf-8?B?UE9GUFE4Tllna0w2aHBRdEs1UlNPa0RtYzB1T0RaY3AzanlkUGovSnozNDJH?=
 =?utf-8?B?ZlY2U2dKSjVlM0owemtEditCQmNvSnFWWDlwaUpZWXg2Uk8vT1JiYmZBY3oz?=
 =?utf-8?B?YVlTOFBNZFBBZ1ZNdFB1azlkSlNvRE9ualNSNlgxcGdzS1V1Y0J3V0ZOSzNh?=
 =?utf-8?B?WHpWcmpkdGFVZTlaMS9UZz09?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 218db573-26ca-4b45-e717-08d929c46c08
X-MS-Exchange-CrossTenant-AuthSource: SN6PR1501MB2064.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Jun 2021 14:56:25.6625
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: E6VcF4x56nhCPhr3ajtgZZlUIs0di0gJoGnbBjpFBou3gn+BMj/mXy+GcbaExW+K
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR15MB4014
X-OriginatorOrg: fb.com
X-Proofpoint-ORIG-GUID: i2WKBEe7YhsiBiYAZBvRC80Sx5X_6OvN
X-Proofpoint-GUID: i2WKBEe7YhsiBiYAZBvRC80Sx5X_6OvN
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.761
 definitions=2021-06-07_11:2021-06-04,2021-06-07 signatures=0
X-Proofpoint-Spam-Details: rule=fb_default_notspam policy=fb_default score=0 lowpriorityscore=0
 clxscore=1011 impostorscore=0 mlxscore=0 malwarescore=0 spamscore=0
 priorityscore=1501 adultscore=0 suspectscore=0 phishscore=0
 mlxlogscore=968 bulkscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2104190000 definitions=main-2106070108
X-FB-Internal: deliver
X-Original-Sender: yhs@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=VOzOPy9m;       arc=fail
 (signature failed);       spf=pass (google.com: domain of prvs=5792e56dba=yhs@fb.com
 designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=5792e56dba=yhs@fb.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=fb.com
X-Original-From: Yonghong Song <yhs@fb.com>
Reply-To: Yonghong Song <yhs@fb.com>
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



On 6/7/21 6:30 AM, Zhen Lei wrote:
> Fix some spelling mistakes in comments found by "codespell":
> thats ==> that's
> unitialized ==> uninitialized
> panicing ==> panicking
> sucess ==> success
> possitive ==> positive
> intepreted ==> interpreted
> 
> Signed-off-by: Zhen Lei <thunder.leizhen@huawei.com>

Ack for lib/test_bpf.c change:
Acked-by: Yonghong Song <yhs@fb.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e788d0c5-51a3-4cb1-52e1-f57d0d17d7be%40fb.com.
