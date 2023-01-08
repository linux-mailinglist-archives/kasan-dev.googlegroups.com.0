Return-Path: <kasan-dev+bncBAABBYVK5KOQMGQE2RQFGEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CCFC5661475
	for <lists+kasan-dev@lfdr.de>; Sun,  8 Jan 2023 11:05:22 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id m8-20020a05600c3b0800b003d96bdce12fsf3393492wms.9
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Jan 2023 02:05:22 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1673172322; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vw8FCSASqJNNxs1H5q/WM+D/G9S5Rq62We1PpHjWlq/rAxl8XkHz8jdyWlsAt3lM0G
         wGLhCvVB2u97+hmx1t0GJKMEf7wfb2ztJ+xW6GrTXDDCml7mLmlgkOXz6WdQMEadx/Qz
         G+gKVxoupI0/pT4lFN4HqONsEukibjtZXQi2N4k+leV8XXyTUBAxG9ylpKd0AgyO0PQj
         wOAHCordLt9TO1gwiqKpEAAVA3d3ONp4CL0X7DLMT095/gtRCh1QZ2BbmhWdVFGzRAc3
         //86cTWFIwsItSQ3oudgD6EAbwEhCAYLFW3Yw8+zGNBZhSUAa3sSxfYE9utNiw+IGQjv
         wHWQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:to:from:dkim-signature;
        bh=7b6UpFRMW2Sc034vbLQFAgtCFP22eQ5wih1XTSFZBiM=;
        b=wYSD5e+8rGJQ0/fqbRCxvAl2vN+NXssRWbiIWTE7lczNtLvIw4/KFwmGF14hfvHGjO
         WiBl3/MR9WyMskLAcDpUFqKh9RLA6MxcCdqIAPR0EIpxdw6Bv0xjwOuZFX1XwMvBzYJR
         4oatvQsOmeLG8YcW83IH/36ubXE2tHhtMXx6sTt1mLcbxBHJXh1RMFf7uJ79PitnBiv7
         M23lwKqnuYgH74niLnLNEedDUqoUS2r/XMiUIKiAh14qd6PCiCCd83ovmVYNcmgJXx4V
         wlb4KNwL/BR24smM2rFljPNFQAz9fBNslOQ20SVbBQG3WP47o7H14WSFwUbmYCHxtQNw
         crvg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@estudusfqedu.onmicrosoft.com header.s=selector2-estudusfqedu-onmicrosoft-com header.b=JmgIsswk;
       arc=pass (i=1 spf=pass spfdomain=estud.usfq.edu.ec dkim=pass dkdomain=estud.usfq.edu.ec dmarc=pass fromdomain=estud.usfq.edu.ec);
       spf=pass (google.com: domain of nparedes@estud.usfq.edu.ec designates 104.47.56.171 as permitted sender) smtp.mailfrom=nparedes@estud.usfq.edu.ec;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=usfq.edu.ec
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=7b6UpFRMW2Sc034vbLQFAgtCFP22eQ5wih1XTSFZBiM=;
        b=fzV+aNQlstGCB2yLUK12qk2qDVKy3RMtWzTBTe5McWFUFoioNQiVD6q9md/IsrFfmN
         kDFhtslunXBTT6xjGY6F4ZcKHyc+IqygbXq5LAjbuOnTOvBOY9C5rqYX1FP8OYO6/KFw
         +V9qyX5kqXqZLEQ92uE85rKMXZtZ7NbsbcAPT7xNHSmqkWHDjg9eVp545eJ+w+O8ohEV
         58pwULKNiiA7d30elvMiHxi2xiVVC3mPXOqBBa+em+T73BK/GF3ljNkmi06RNKeia9HD
         aJzw78yQ9QRnZnixAARwPH+Yvxc3Bl0B75JUm/jWQ02HCyCEvZct/xlh2/S46jHlDVby
         41rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:to:from:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7b6UpFRMW2Sc034vbLQFAgtCFP22eQ5wih1XTSFZBiM=;
        b=ccLnscXrTQd9OX4YQwb9wUARKNpNfrWc08y+tphWonqXi9VfaXtpSLpK/xAPBqhhhg
         2kxQJJEZ9p7oiKAi10iWS7TRBJUbkpNCE1YLjQFtB2oFfVCTY78wkFUf/b0CcZGtEQz2
         Xz2DJ+XqjUkEAfs9YZ5OUtKPzvNaz9oWU9vMlKQClN86HZrVUvEUFYiFNjVNTJpxPOv7
         Vjc/NdNLoWQSo/2EA/70iWuWHC8rH5CDQz+eLGSA80TSWBrgVOsdMv9PUsfcpprPgHvG
         pSgvDLzx2CdKkVv+sjfaCBEz/naUV8DZhI9mT/wH3JmxCVjX6vN2paqLH/Jlvk2hd7xY
         6ICw==
X-Gm-Message-State: AFqh2krbRoPr1ktztUFlL/mVA2TKFtB3QUZhIhKpDkjQJmRnLilGU1FG
	8o1KFs6KHmWY6xg+Vam+7C0=
X-Google-Smtp-Source: AMrXdXurfM+Q1/mcOm3CLtw6CaUJqrP/rJHj4ujonYOj9ZIgpy66x9mcrIiky5a8U6lTdzqYV3wxMA==
X-Received: by 2002:a5d:60c2:0:b0:273:9de:c11 with SMTP id x2-20020a5d60c2000000b0027309de0c11mr2365502wrt.598.1673172322251;
        Sun, 08 Jan 2023 02:05:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f706:0:b0:3d9:bb72:6814 with SMTP id v6-20020a1cf706000000b003d9bb726814ls1727002wmh.3.-pod-control-gmail;
 Sun, 08 Jan 2023 02:05:21 -0800 (PST)
X-Received: by 2002:a05:600c:4fcf:b0:3cf:68f8:790b with SMTP id o15-20020a05600c4fcf00b003cf68f8790bmr44777942wmq.11.1673172321463;
        Sun, 08 Jan 2023 02:05:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673172321; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gr0LBAncOGKYLvXoUeM9YMakD87vPaHCKnZXEnJeDPFWUoCaFBjrzSLf40BEtyeRdf
         NXJ+8WhHGeLRxVfZIACPCYajKAXqQtHqeyzGbOWVqWFKur25MBkdMHNUWyzCLxXnfcdi
         npIMPe6AsDZO++VW9o64GK+pjkVOkZrhpeBuZhJtI/k6Ej9zXWbUV6fkr+5CqChqSgdb
         r0NX8wjo6dT7AikSuZHybr9dL0EajAAdWb12oNUIUkEJ5mBgLQIrH6djgDyA9dwXKHq/
         PmvldPsMxBX+SoYnJkNmDB2S4nDwfdhZdYshJMQRUomSh23PS7G4KMKwCFEYKnb3ZasV
         mthQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:to
         :from:dkim-signature;
        bh=Nc8v27t8Od+qRQ0zN6EZXbjE2rBAexXw5vhxAnAq2YE=;
        b=eEhpH9Xsk9eNtHD6y5AoZt2H5mY6kkxREj73x8Di9Mxbh+f+4oi6Tx0qJPlZgvIqy9
         tNXRXKN9GHUKpzNutyINEjwlcIxhQ2Ft/ttGk/U06GAyBA3jrQjwbuDI+VZWepaTqXRg
         r48OyDapDpt//beTHsTv7GbYIUAFzMcXYgcxrejxYGspypZfFhkkNzY+OynesM3Gxlzu
         4nHVQd8/VEDbByUeBuz5FXVpmO1CHHnf/HYqcqwADFkf7iP/PracC2Gs3mJX4Uaqcblb
         HE762fcoSNP3S/FaevVz/ypTliFMdJlnUVfuVdULzmTEfja2YeH3rKbGf1OY1zSKRkmh
         uOxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@estudusfqedu.onmicrosoft.com header.s=selector2-estudusfqedu-onmicrosoft-com header.b=JmgIsswk;
       arc=pass (i=1 spf=pass spfdomain=estud.usfq.edu.ec dkim=pass dkdomain=estud.usfq.edu.ec dmarc=pass fromdomain=estud.usfq.edu.ec);
       spf=pass (google.com: domain of nparedes@estud.usfq.edu.ec designates 104.47.56.171 as permitted sender) smtp.mailfrom=nparedes@estud.usfq.edu.ec;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=usfq.edu.ec
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (mail-co1nam11lp2171.outbound.protection.outlook.com. [104.47.56.171])
        by gmr-mx.google.com with ESMTPS id bt2-20020a056000080200b0025dd2434f36si234001wrb.2.2023.01.08.02.05.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Jan 2023 02:05:21 -0800 (PST)
Received-SPF: pass (google.com: domain of nparedes@estud.usfq.edu.ec designates 104.47.56.171 as permitted sender) client-ip=104.47.56.171;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=C8ORHmPpG8A625V10DuYwasLUosB6AW7juThu+DwN6Ks+3Rtlm3VTV+UE5trvVRIwaDXURFjyTO5rSOGATTLL8uNGjplVI4sCaWpJxlmGR3GBbEhDtL7GhXMiuCRgEf5yLtr47GKMpx9WhstJGwlHojDuCSXOZf6YYCpriXS6uPDMAiGKOpYnRvEBK5vDeXxJdI8Z84P8LwNCAqd0gctx6B732zIZPwxgV9xCRzc6ONnb8l0kSP9R9t8sM3jaKeqeKpPNvvspnrJU3Nn5GF/jStHx8elYunuxRPfhKcp1NQVXVGSPA7RtWWm6wCRLtbfs4YsEibBcIVSeGvNPEMCCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Nc8v27t8Od+qRQ0zN6EZXbjE2rBAexXw5vhxAnAq2YE=;
 b=CHcPgUz12979ODd3CacNUuMhVda70Nw+/zbAcvGN33ebf6WWHiyhSqUtSSCmCgdpgDIdpp5xsg2TQF7PrZr/GZtMVW9xXiRAumzxVyQp26b0LNP6zmPDL8POMPIsIjnhPHdBmmMvmy+/2BwRu77q2jmQApAl/hOFVzUymuanp7aH3y7OZtq/ej+4Nb/E7eM5NUZSgsWd1+V/W+Wc5DIA6ZFBVlVhzMh5eUx49/ZtHy66Sw4pHWEiIZigUpa4gc05qW3S125Jc9QyTWItvdzv8yXuWQk76Z3GNeIdBXd94cwlOO4MnFZ+2NEhW5dXuHu3Y2zLceuVk1NMjUkxbPWwfw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=estud.usfq.edu.ec; dmarc=pass action=none
 header.from=estud.usfq.edu.ec; dkim=pass header.d=estud.usfq.edu.ec; arc=none
Received: from BN7PR15MB2210.namprd15.prod.outlook.com (2603:10b6:406:8f::26)
 by SA1PR15MB5236.namprd15.prod.outlook.com (2603:10b6:806:238::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5944.19; Sun, 8 Jan
 2023 10:05:18 +0000
Received: from BN7PR15MB2210.namprd15.prod.outlook.com
 ([fe80::4e92:4e24:d984:d43]) by BN7PR15MB2210.namprd15.prod.outlook.com
 ([fe80::4e92:4e24:d984:d43%4]) with mapi id 15.20.5986.018; Sun, 8 Jan 2023
 10:05:18 +0000
From: =?UTF-8?Q?=27Ronald_Nicol=C3=A1s_Paredes_Cobos=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
To: =?utf-8?B?Um9uYWxkIE5pY29sw6FzIFBhcmVkZXMgQ29ib3M=?=
	<nparedes@estud.usfq.edu.ec>
Subject: Re: Taller 2
Thread-Topic: Taller 2
Thread-Index: AQHZBSgGjXWKn3LQMkKe4uWb6TgaJa6UjeKAgAACYQCAAAeXAA==
Date: Sun, 8 Jan 2023 10:05:17 +0000
Message-ID: <1C330F90-BEC4-42C7-95EF-0436564C1336@estud.usfq.edu.ec>
References: <SN6PR1501MB212893DEF97EAD7D13476381D1149@SN6PR1501MB2128.namprd15.prod.outlook.com>
 <MW5PR15MB5241AF009656D314D9C3A0C9E6149@MW5PR15MB5241.namprd15.prod.outlook.com>
 <010EC50A-8D1C-4F1B-8A3F-93342CBB74F8@estud.usfq.edu.ec>
 <5783872F-55AF-4339-B078-1B3B513EA0E4@estud.usfq.edu.ec>
In-Reply-To: <5783872F-55AF-4339-B078-1B3B513EA0E4@estud.usfq.edu.ec>
Accept-Language: es-EC, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: BN7PR15MB2210:EE_|SA1PR15MB5236:EE_
x-ms-office365-filtering-correlation-id: 746743c7-147a-4a53-dcb1-08daf15fd845
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 2pvhZxeDjRMhRWs+bYZx8RFp6zjrL3grH988Y0855eZAiTCPGCKvS0m6O0c6/5cv4DIJWrSuHohuJRMauuW6zf9g0QhqYDmTvLIYX+s/hKquB0tvRQvZcvm/uye+ZQCV73JUGXLMRprCCPzxawK1ABkHkj/V+Ez7PW59oE0UkM3qhjKOUbNv0miAbc1xw53VsXDe2N7pE014H600tt6ZJc5Ob0W8xaHLC0JOVXeXgkti7Uw6Qc62AsHc874V86FRe1JPodmcVWTgxZz8hTXe3TUb1iXXP5Ct7JBRcbxB0j5fmcpRpxT4LLY72mQ8yGsnyQvDZfFBEw4xcAJVMK+LE/Yc5fWBkGqEKQ2Yca2rNxxgDSDHGHTCy4bmA01e3og6cNUYtDymF0Q2Rb//wyoKsfICzEgKnL/gteFMbYYo0DNRrHOZz946xzSg5JOjKwPvKYGvh/qFRV8ErHOKPA5jhlKRrQQh9svB4y5BAZwsg1OlAPLbio1q5sXtOnWlb+rLrwwGlZ3ebtGeY34Zs/tACeoz5Iy+IUKawXbIH20onPVK7p7Mqh3mudZJWOMDLk3ehHYGHkhobThRc3/PO5xZjDs2HzrF2qwVQSsjICNxIp6N4zbQzbaLWrKlIcJmlbISnZQnc4GsVFOnKIycqHGHf4iMEsvqVmJsB6P/I2meDDAZmcOSeA6ShvZe22O37TK8qWKwjhNv2G2frQsGpu7WYw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:es;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN7PR15MB2210.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(346002)(136003)(376002)(396003)(39850400004)(366004)(451199015)(1690799008)(66574015)(55236004)(85202003)(186003)(41320700001)(6506007)(6512007)(33656002)(38070700005)(86362001)(85182001)(166002)(122000001)(53546011)(38100700002)(2616005)(8936002)(7116003)(8676002)(41300700001)(7416002)(6200100001)(966005)(7406005)(5660300002)(6862004)(2906002)(7336002)(7366002)(6486002)(76116006)(478600001)(786003)(26005)(71200400001)(37006003)(66446008)(316002)(64756008)(66476007)(91956017)(66946007)(66556008)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?d0hVNzk4azJneERsN05wcCtFd0U1SFFTczF3Ym4vUi9oOFNEN2liU2o1SERj?=
 =?utf-8?B?S250aDAycTdWRms0aTB0ODl2SXRQU3p0WHpLYk5jNzRQcnhxcVJFaGgvQ25y?=
 =?utf-8?B?Zmdra3R6VzJsWm5JVmQwa0lLUkN4QzNUbkM5ZFNQV2dGMXZuR25GTzBmR3Q0?=
 =?utf-8?B?K3c3ZmFFK1BHazNTZUJ2dnMvTkNQamhZSzV3Y3lqU2hadGNmOVFwL2Z2Vy9R?=
 =?utf-8?B?ZzRaei9hb2Y2bkRoMllxdnAwUWJFSDA0WlE1SGV1d2ZkbkQ4ZDFlS2hVSGps?=
 =?utf-8?B?eGduMnpySGV3SVlVakZnLzBZQTRKeXRYUzFQRlRMQk4rM2EvZ3oydlVoS0dP?=
 =?utf-8?B?K3VyMXF2WUZVZmtDZnRrQ091V1B3ekQ3Tlh0TFlLaHNMaFhCa0VDbEsxRVM1?=
 =?utf-8?B?azJwUjRubG5JQm9MOU5lU2Y0MVlFeldwMC9qNVQwMHNtNXovUUxUemZpNVJv?=
 =?utf-8?B?WWdjYThZVDEzaHN0QlpZcjVZVWFEdzc1WWQrMmN0UElhdy9LTTZUM21TOUJJ?=
 =?utf-8?B?NTJ4SFg3SGQ3cEgxbEV1L2VpYis5Mk1RbHBiNk5ORzJ6SnBLUkhaKy9Xb2Jy?=
 =?utf-8?B?U3Bya3VQTWppZ1dvY2RFRW12L3Q0RjU1WmVMK3MrSERQRTkyM0V2YTB2b1E3?=
 =?utf-8?B?NTJFdUNvUE9MK1U5WmR3WHd3dnlLd0ZvVVVucUV0UGdyb1U3aEVFTkhaaHVJ?=
 =?utf-8?B?bWFGcjgySVFWN3hmZXlWMVZFSURCWldaWHowMkFKeVNGMzhxQTdxWGdKVnlr?=
 =?utf-8?B?dUFQZU9zQzVIYnZsTzFZTnE3dGxCUkN5Q1dIdGRsdTN5WnRRTmVwdDhVUk8r?=
 =?utf-8?B?bk85eml2VGk2TFpiT2lMQlpFbmZQcStKVlVubGZDZVF5WUxndkxyaWJvY0lp?=
 =?utf-8?B?VHNzWW4ramVXN3NnZnRkSE11MlJJdWlLNkZzY1ZYeWFpWG5YckFodXdOeDZm?=
 =?utf-8?B?VzcxRlJVR2VjczlQWDZ2d29GOVFia08yUVF5VWZFWGx3SzY4UWpPYnFwV0lq?=
 =?utf-8?B?bThZempMeVZ4QmgzR3hBbXVUemMyK2tpRlh4SjVjeTA2eGhiR05mNXoyYjBM?=
 =?utf-8?B?bWY4RHpJNk5uNnNPMkszdVk3a0RnUE1XeG93VFBvN0V3aS9xbGxqd0ZsdThS?=
 =?utf-8?B?VkQ2RnV1WGoydzAvTTJZdWZocC94SmRPemszRmIrTlJmVFJORWJmNTJKZG9Q?=
 =?utf-8?B?cnB0cFVESC9XVWo5K2xJYlhPV1NqNlA1dFpHUGtjbnM2ZUVwTG4yRW1rZ25n?=
 =?utf-8?B?MzIrQ3p0dXZETkJ1K0Zpd1BVb1NPeTdFbHFNemcxOUI1eWowOUtmNDJ0U214?=
 =?utf-8?B?RUFzcDZnNENiUUJ5V2JGWmxCUlczdGoyYmQwcEl1QzhLUnFEanNFdm15b3dC?=
 =?utf-8?B?elpNUzR1Y2dIb1FweER3anVkakNXWnY2TTJtRHR0aCtjUlIzUURPOFZLa0oz?=
 =?utf-8?B?VHJhTXNicDhPZy90M3l1ZE41UCtMSVJORXZiRnJhS2lTc3UxL28xeHJ1VkJm?=
 =?utf-8?B?Wk1IamxpTlNVTHR6czJEQXIvd1VmLzdtQ1QvQk5pbW82ZVhpU0FsU1pnaldW?=
 =?utf-8?B?WEhEWHpHdlR6MWhnaE5HMUtCV2F5UkxpZGRlNlQ3WWxrMHM0K1l0VDJ4YWk1?=
 =?utf-8?B?MTJ5QmJEVFBVeW55TUczMmZUWW1aV2Y4RjZwMDMweFU2OXVwQldZS3ZKZTZZ?=
 =?utf-8?B?SndlUWY5R2RXV2cwQXBTMHhaYW54MEF3L0hWdTZSZlVaRitqMGphOXJEZ1Rh?=
 =?utf-8?B?WU1zMWJ6ek5UQjBvMXZXdFhRSTM5M0o5VnZ2ZFZ5YlladHFZaENocHlobHJF?=
 =?utf-8?B?aXlYTm00V0VkbjhYZDkxR0wxWUxuOTAvQ3VIV09NK01HN0h0amFqM3FLRXo4?=
 =?utf-8?B?Yy95ZzZiZTNHVVlUTG80YWRYbTl4a3N3YVJGL3RmNWFlR2lmSCt4ckZqZS9D?=
 =?utf-8?B?cU5ydmNIcnY3ZzJWaSsyZGk3ZTJzTEdVSExpcDZFdlRhRGlpc0xybXhTUTVB?=
 =?utf-8?B?NkIveUYvYUhXVjhHS0x2b2pYdmZsRUtEcVliMVg1dGJNWFZVdjMvb1NONnlw?=
 =?utf-8?B?STFmTDdhVU1LeS9OVXQ1QkRSbmJiNFBJeUpuZ1l3M1B6NkF2dEVSSE54ZHpm?=
 =?utf-8?B?QlAwTlg5TDlySXY0d3ExeG1aMnFuOVpxYXNYUnh1N1N3b3YxalAzY0ZzVk1Y?=
 =?utf-8?B?MUE9PQ==?=
Content-Type: multipart/alternative;
	boundary="_000_1C330F90BEC442C795EF0436564C1336estudusfqeduec_"
MIME-Version: 1.0
X-OriginatorOrg: estud.usfq.edu.ec
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BN7PR15MB2210.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 746743c7-147a-4a53-dcb1-08daf15fd845
X-MS-Exchange-CrossTenant-originalarrivaltime: 08 Jan 2023 10:05:17.8365
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9f119962-8c62-431c-a8ef-e7e0a42d11fc
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: m9PSUPbxdGGmU0KtNUk04khsOkQYVQx1VQaNfSMSz3U5XeSvgrc4pLGXFzaMExRF55sz4EayLHsj5IynwpDmJoXzlbxI4Gr8LFPwxPz2WcI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR15MB5236
X-Original-Sender: nparedes@estud.usfq.edu.ec
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@estudusfqedu.onmicrosoft.com header.s=selector2-estudusfqedu-onmicrosoft-com
 header.b=JmgIsswk;       arc=pass (i=1 spf=pass spfdomain=estud.usfq.edu.ec
 dkim=pass dkdomain=estud.usfq.edu.ec dmarc=pass fromdomain=estud.usfq.edu.ec);
       spf=pass (google.com: domain of nparedes@estud.usfq.edu.ec designates
 104.47.56.171 as permitted sender) smtp.mailfrom=nparedes@estud.usfq.edu.ec;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=usfq.edu.ec
X-Original-From: =?utf-8?B?Um9uYWxkIE5pY29sw6FzIFBhcmVkZXMgQ29ib3M=?=
	<nparedes@estud.usfq.edu.ec>
Reply-To: =?utf-8?B?Um9uYWxkIE5pY29sw6FzIFBhcmVkZXMgQ29ib3M=?=
	<nparedes@estud.usfq.edu.ec>
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

--_000_1C330F90BEC442C795EF0436564C1336estudusfqeduec_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable



From: Ronald Nicol=C3=A1s Paredes Cobos <nparedes@estud.usfq.edu.ec>
Date: Sunday, January 8, 2023 at 10:38 AM
To: Ronald Nicol=C3=A1s Paredes Cobos <nparedes@estud.usfq.edu.ec>
Subject: Re: Taller 2

i h=C3=A1v=C3=A9 a pr=C3=B3p=C3=B3sal f=C3=B3r y=C3=B3u




























[http://www4.usfq.edu.ec/owa/logo_usfq.png]             Ronald Nicol=C3=A1s=
 Paredes Cobos
Estudiante
Universidad San Francisco de Quito
Correo: nparedes@estud.usfq.edu.ec
Diego de Robles y V=C3=ADa Interoce=C3=A1nica, Quito, Ecuador
http://www.usfq.edu.ec
Nota de descargo: La informaci=C3=B3n contenida en =C3=A9ste e-mail es conf=
idencial y s=C3=B3lo puede ser utilizada por el individuo o la instituci=C3=
=B3n a la cual est=C3=A1 dirigido. Esta informaci=C3=B3n no debe ser distri=
buida ni copiada total o parcialmente por ning=C3=BAn medio sin la autoriza=
ci=C3=B3n de la USFQ. La instituci=C3=B3n no asume responsabilidad sobre in=
formaci=C3=B3n, opiniones o criterios contenidos en este mail que no est=C3=
=A9n relacionados con asuntos oficiales de nuestra instituci=C3=B3n. Discla=
imer: The information in this e-mail is confidential and intended only for =
the use of the person or institution to which it is addressed. This informa=
tion is considered provisional and referential; it can not be totally or pa=
rtially distributed nor copied by any media without the authorization from =
USFQ. The institution does not assume responsibility about the information,=
 opinions or criteria in this e-mail.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1C330F90-BEC4-42C7-95EF-0436564C1336%40estud.usfq.edu.ec.

--_000_1C330F90BEC442C795EF0436564C1336estudusfqeduec_
Content-Type: text/html; charset="UTF-8"
Content-ID: <D10675BC19DDE84393FE7700B8705DBB@namprd15.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable

<html xmlns:v=3D"urn:schemas-microsoft-com:vml" xmlns:o=3D"urn:schemas-micr=
osoft-com:office:office" xmlns:w=3D"urn:schemas-microsoft-com:office:word" =
xmlns:m=3D"http://schemas.microsoft.com/office/2004/12/omml" xmlns=3D"http:=
//www.w3.org/TR/REC-html40">
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dutf-8">
<meta name=3D"Generator" content=3D"Microsoft Word 15 (filtered medium)">
<style><!--
/* Font Definitions */
@font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0in;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;}
span.EmailStyle19
	{mso-style-type:personal-reply;
	font-family:"Calibri",sans-serif;
	color:windowtext;}
.MsoChpDefault
	{mso-style-type:export-only;
	font-size:10.0pt;}
@page WordSection1
	{size:8.5in 11.0in;
	margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
	{page:WordSection1;}
--></style>
</head>
<body lang=3D"EN-US" link=3D"#0563C1" vlink=3D"#954F72" style=3D"word-wrap:=
break-word">
<div class=3D"WordSection1">
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<div style=3D"border:none;border-top:solid #B5C4DF 1.0pt;padding:3.0pt 0in =
0in 0in">
<p class=3D"MsoNormal"><b><span style=3D"font-size:12.0pt;color:black">From=
: </span></b><span style=3D"font-size:12.0pt;color:black">Ronald Nicol=C3=
=A1s Paredes Cobos &lt;nparedes@estud.usfq.edu.ec&gt;<br>
<b>Date: </b>Sunday, January 8, 2023 at 10:38 AM<br>
<b>To: </b>Ronald Nicol=C3=A1s Paredes Cobos &lt;nparedes@estud.usfq.edu.ec=
&gt;<br>
<b>Subject: </b>Re: Taller 2<o:p></o:p></span></p>
</div>
<div>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
</div>
<p class=3D"MsoNormal">i h=C3=A1v=C3=A9 a pr=C3=B3p=C3=B3sal f=C3=B3r y=C3=
=B3u<o:p></o:p></p>
<p class=3D"MsoNormal"><b><span style=3D"font-size:12.0pt"><o:p>&nbsp;</o:p=
></span></b></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
</div>
<br>
<table style=3D"MARGIN-TOP: 10px; FONT-SIZE: 10px; LINE-HEIGHT: 120%; FONT-=
FAMILY: Tahoma; BORDER-COLLAPSE: collapse" cellspacing=3D"0" cellpadding=3D=
"0" border=3D"0">
<tbody>
<tr>
<td valign=3D"top"><img src=3D"http://www4.usfq.edu.ec/owa/logo_usfq.png" b=
order=3D"0"></td>
<td width=3D"10">&nbsp;</td>
<td valign=3D"top" width=3D"100%"><span style=3D"FONT-SIZE: 10px; COLOR: #2=
44061">Ronald Nicol=C3=A1s Paredes Cobos</span><br>
<span style=3D"FONT-SIZE: 10px">Estudiante</span><br>
<span style=3D"FONT-SIZE: 10px"><b>Universidad San Francisco de Quito</b><b=
r>
Correo: nparedes@estud.usfq.edu.ec<br>
<span style=3D"COLOR: #808080">Diego de Robles y V=C3=ADa Interoce=C3=A1nic=
a, Quito, Ecuador </span>
<br>
<a href=3D"http://www.usfq.edu.ec">http://www.usfq.edu.ec</a> </span></td>
</tr>
</tbody>
</table>
<span style=3D"COLOR: #666666">Nota de descargo:</span> <span style=3D"COLO=
R: #999999">
La informaci=C3=B3n contenida en =C3=A9ste e-mail es confidencial y s=C3=B3=
lo puede ser utilizada por el individuo o la instituci=C3=B3n a la cual est=
=C3=A1 dirigido. Esta informaci=C3=B3n no debe ser distribuida ni copiada t=
otal o parcialmente por ning=C3=BAn medio sin la autorizaci=C3=B3n de la
 USFQ. </span><span style=3D"COLOR: #999999">La instituci=C3=B3n no asume r=
esponsabilidad sobre informaci=C3=B3n, opiniones o criterios contenidos en =
este mail que no est=C3=A9n relacionados con asuntos oficiales de nuestra i=
nstituci=C3=B3n.</span><span style=3D"COLOR: #666666"> Disclaimer:
</span><span style=3D"COLOR: #999999">The information in this e-mail is con=
fidential and intended only for the use of the person or institution to whi=
ch it is addressed. This information is considered provisional and referent=
ial; it can not be totally or partially
 distributed nor copied by any media without the authorization from USFQ. T=
he institution does not assume responsibility about the information, opinio=
ns or criteria in this e-mail.
</span>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1C330F90-BEC4-42C7-95EF-0436564C1336%40estud.usfq.edu.=
ec?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/1C330F90-BEC4-42C7-95EF-0436564C1336%40estud.usfq.edu.ec</a>.<b=
r />

--_000_1C330F90BEC442C795EF0436564C1336estudusfqeduec_--
