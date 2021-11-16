Return-Path: <kasan-dev+bncBDBLXJ5LQYCBB2WE2CGAMGQE3BQBVXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id CA093453BA4
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 22:28:11 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id w131-20020acac689000000b002a813c6e600sf450028oif.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:28:11 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VpD6uGTCc8203EXgkc7Npm4Ut4J4pji4Y7c0uu0ENZE=;
        b=nkcrp7Q0kK2WFlLuY1JZgbVpvK/rZFxNXArRaqjOkIeuuesRWybKho/3sOkNOyboap
         qgWQwU9errmVb50n1gG0ksu2rHJKw0o4YWYA5rlE+Zx1stry7rI1VGvJbElqWHl72sR9
         GQFN1iBcfQ/6dgzRGDm9PZA3dh7+OIREYKdm6++E1pA4AAKFkLdzaMnk/wtmaTQLIvCP
         6/XM/fW3HHFNUot4VVrcisdeMI4PkUAYIC5vdXlHzzfxIQMzb8ky1iHann/WPhmP03SC
         Yh/Nq89qIKdMXRUtL+z8g4kgNiI4jj4lmclKToalmF3zIBESOBGupAtSvdV6+S5Rmx2W
         CuVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VpD6uGTCc8203EXgkc7Npm4Ut4J4pji4Y7c0uu0ENZE=;
        b=PMrTmo2B96rZzeZBrKxhVQbe9Vo+HPewTl7SvR6iZEW1oqmxBPRFDQn9eFfH6aeRwR
         BI4vYkpJ6O8aDgo1I1FdAQMS4PYesSloH+LPs+oZoYJLw3NxwKX1eceFpkpnyDO37GV6
         zwUzF6cEYSa4m8G6PZyzMctKkvd7eN45C+lgETEBej34DkKyJaDBVmnjWqc+urCqXevw
         wWBSP+6jWyUDc3k9UDfkHq5gqFIgYfB0VcY8IFwGR+bRyC0C3S11OYknbzbi12o1Ue+u
         JdW7g4GP+H6MA8bxOgfulb0R4AbAwSOc41IW2SMxYlD2+01Liji3AL11WnLfkZLuOcrr
         sIQw==
X-Gm-Message-State: AOAM532UfteknhUpKq9F6R2Wxh1ydNz8aWI2coEBeW5AA43TpUvkFdAL
	7TG7k792NcN26yvtZHDYXmc=
X-Google-Smtp-Source: ABdhPJxQuzM5Afk+FU0XiYXvBNMgA+p/Yi30Hln3a5WvR1veZXoVCcDPN/R6J8ICeweGlR8TIQCi6A==
X-Received: by 2002:a9d:758e:: with SMTP id s14mr797537otk.218.1637098090372;
        Tue, 16 Nov 2021 13:28:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:440e:: with SMTP id q14ls6553008otv.0.gmail; Tue,
 16 Nov 2021 13:28:10 -0800 (PST)
X-Received: by 2002:a05:6830:22d8:: with SMTP id q24mr8572828otc.170.1637098089946;
        Tue, 16 Nov 2021 13:28:09 -0800 (PST)
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id w29si1407576oth.3.2021.11.16.13.28.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 13:28:09 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=095491a111=terrelln@fb.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0148461.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 1AGIBms5010366;
	Tue, 16 Nov 2021 13:27:46 -0800
Received: from maileast.thefacebook.com ([163.114.130.16])
	by mx0a-00082601.pphosted.com with ESMTP id 3cccpe42xe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Tue, 16 Nov 2021 13:27:45 -0800
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (100.104.31.183)
 by o365-in.thefacebook.com (100.104.36.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.14; Tue, 16 Nov 2021 13:27:44 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=nV9cnQsywkl/ttVkyaRMZ9Ly5j8/LgyGPtuZTTh/mf6UdXqH25FG2j8EZfJYuj95S0A9NanCcZhh+2DtkI0yAdL/ph1wl5QBbpnNGOibkXIg6ssn/ui4QEWAEDiIgP+il3SCkN4zsrgIv0TfpK0BPePK+432usV+ZckHYIdcRuoUrX5iL1ENqz9/HxpyZglSZGqqsbv5KRPo8DB08i14PTn507jAN47bTuhAJZ8XG/xJ3P6Tkb765A6jYvasdhGGy7lRaLoNhmMvc1n2qDTNny8REzdGLA+4YD6Gc/Ae3CqjKLFXYUSi7DgLG2ZA9lzls7yL9F5hg8t4m7Cr4BBNxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=whqaTExxjIQerMSt552CDfkqtaU9xePgzpp0mIZPdWQ=;
 b=AaPQ7d4uB1jCR7XSt5FAtBC+L5DWL7baS2hOWf/y9A3Fk/YzCh0p6xHgG4R3+wgYP3m5wiaQ501bjFJSyez6z3c1vOOVluGqWGAusputBJMWD1nPVE4wyiRI5h7wjbVxxDuzmex48PHT++AKx+YyZs0K14uNZN8YmW8NrE9QQLoPJmLPeSNLIIAfw2HcW3O2GMppPFJiq+wqi4T7nGnONRib+QexRWVnUEkcMOh3+N9Euie4VvjGQ7ccsPcjmmUhcQefY3ZnWjtqkYOv01U1t9YE/OpMYdvRSr2HWuxSs5DDt5L3ZNI8kZ3jJuW0PhXq2gvdMWHGAGvzbtDPJ3ZhZQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BY5PR15MB3667.namprd15.prod.outlook.com (2603:10b6:a03:1f9::18)
 by BY5PR15MB3619.namprd15.prod.outlook.com (2603:10b6:a03:1f9::28) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4690.20; Tue, 16 Nov
 2021 21:27:43 +0000
Received: from BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4]) by BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4%6]) with mapi id 15.20.4690.027; Tue, 16 Nov 2021
 21:27:43 +0000
From: "'Nick Terrell' via kasan-dev" <kasan-dev@googlegroups.com>
To: Helge Deller <deller@gmx.de>
CC: Geert Uytterhoeven <geert@linux-m68k.org>,
        Linux Kernel Mailing List
	<linux-kernel@vger.kernel.org>,
        Rob Clark <robdclark@gmail.com>,
        "James E.J.
 Bottomley" <James.Bottomley@hansenpartnership.com>,
        Anton Altaparmakov
	<anton@tuxera.com>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        "Sergio
 Paracuellos" <sergio.paracuellos@gmail.com>,
        Herbert Xu
	<herbert@gondor.apana.org.au>,
        Joey Gouly <joey.gouly@arm.com>,
        "Stan
 Skowronek" <stan@corellium.com>,
        Hector Martin <marcan@marcan.st>,
        "Andrey
 Ryabinin" <ryabinin.a.a@gmail.com>,
        =?utf-8?B?QW5kcsOpIEFsbWVpZGE=?=
	<andrealmeid@collabora.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Linux ARM
	<linux-arm-kernel@lists.infradead.org>,
        "open list:GPIO SUBSYSTEM"
	<linux-gpio@vger.kernel.org>,
        Parisc List <linux-parisc@vger.kernel.org>,
        linux-arm-msm <linux-arm-msm@vger.kernel.org>,
        DRI Development
	<dri-devel@lists.freedesktop.org>,
        "linux-ntfs-dev@lists.sourceforge.net"
	<linux-ntfs-dev@lists.sourceforge.net>,
        linuxppc-dev
	<linuxppc-dev@lists.ozlabs.org>,
        "open list:BROADCOM NVRAM DRIVER"
	<linux-mips@vger.kernel.org>,
        linux-pci <linux-pci@vger.kernel.org>,
        "Linux
 Crypto Mailing List" <linux-crypto@vger.kernel.org>,
        kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
Thread-Topic: Build regressions/improvements in v5.16-rc1
Thread-Index: AQHX2jynD2CHATmgwEukyh+iAPvEB6wEy7gAgAHcBwCAAAVbAA==
Date: Tue, 16 Nov 2021 21:27:43 +0000
Message-ID: <241006B3-699F-44FD-AF85-0133971BCD85@fb.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
 <587BB1D2-A46B-4E93-A3EA-91325288CD6A@fb.com>
In-Reply-To: <587BB1D2-A46B-4E93-A3EA-91325288CD6A@fb.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 20d65738-7b52-47b2-016e-08d9a947ecf3
x-ms-traffictypediagnostic: BY5PR15MB3619:
x-microsoft-antispam-prvs: <BY5PR15MB36193A72BBFDAC812773F9ADAB999@BY5PR15MB3619.namprd15.prod.outlook.com>
x-fb-source: Internal
x-ms-oob-tlc-oobclassifiers: OLM:10000;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: XLGHwfRYT/a4ixZPkjRXp2Qks7kcA3qfNK4kH9pdaY5aSVEvxUu80vz0gfl8AZOX6gdaXU/xxw0DwEfyzYj7zzs1YZ4g4jwOzhAtfp3AAiYd43QyIgMhOtV1Ig4g02Op7giNzpnxOBKLQtrMKxIQXJTv/IHVfaBci+qojhKp3FkRBQrgdXT+LTgj0wKNf8ALjqXgYbYuTg5NxfaOiVCioHnUxhTKGkegGJWLLbk3Gd4QJUlEYR1sU4Zorn+3EeUSL3lGzbo0/gymWeTwIj30kOh5vfKyS8JK1lnV3NQ46Z/27i4crhaQpYa+K4SFghRgFzeGWHXGp/f/UKKYCyaDKSiQIo5Qez0b6A4l2fPo6UOwjfXlvyXyqY90Zz8Y8vc2D+2BrQzB5nKaFB6IcjIFfaFSPI8JW6AV5Jh9+CYj/yfvvMG9TGRA80YQ9W//k9e2s7kXK5kPXWnoNhWpf5ljMaNagvb26ZWeoDi5uqvqUM7RKyLVUHRQX76oa1bXupxjcCAZ8cqLB3anLy8LvzkTqDbUc+l+VTcyquG17z7YDPjZ4Nw4Q7/Mbt5P/zzpllVS9YIMVzVEZi84OLPBSvNLa8+oWiszWb/Da8YluZKAT1c/M4e4gr9Rm/zmu3iP0L3n17zL8ZykOJ5e/Up3pY3sh12xTbI0wkyDbNUM60DuOTbYhuwhm0Vn/4tAGMqF6GXf8a3hXlqCicZ6qAwhV2iGuYSujzkj2KS+m3DxdCJjm2mJES1Yh/Al4NJyWvWcv4ZGGeA2MUUjD2RHyeKtW2lbSaJuM6DF4paAOj8J85NAYaAqlqnErso5AlVjqMvg15FThj+fr+xs6ByCuR+UD6628w==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR15MB3667.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(6512007)(6506007)(36756003)(38100700002)(4326008)(66446008)(122000001)(54906003)(33656002)(53546011)(91956017)(186003)(38070700005)(66476007)(316002)(66946007)(7416002)(76116006)(6916009)(66556008)(6486002)(5660300002)(8676002)(966005)(2906002)(83380400001)(86362001)(2616005)(71200400001)(8936002)(508600001)(64756008)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?Ukx1VUpDVHFJeDh2VDhVYUtFSDh3Q2VXUTBRc0ZHazBieWdOMGJlaW8zNnBw?=
 =?utf-8?B?Yld1UXBTMFEwaWJYMHNGeERmejA1aFlCWWxWOFB0MTVEZkF1YkhKWHgvcXRl?=
 =?utf-8?B?bWgxZFBuZVJubTh1OGNxSnMrbktsazhySnRKbkZYMEtjMWVteHBveWxNUVd4?=
 =?utf-8?B?K09IN21NMzQrQ1pXSWsxa0RFblFMeXBFMHlzcDB4RFZGTStQY0NQYkRTN1lN?=
 =?utf-8?B?MFlwZ3RMSzU4dlRSYVRhNUpEbjRIalR4MGxVZDNIQkEyeGUxVDlYSTBucnBW?=
 =?utf-8?B?elN1S2tib0d1ZENWSnRiTngzV2dIUTUvQUswK3VTVmt3OHMrK1VyZk1kOWxr?=
 =?utf-8?B?cGltN2pSL1Rlc3hLQUU0QzQ1Ryt1QjRpbTQxZk9jWnJsMTRkN3BrRE5ab2hZ?=
 =?utf-8?B?NUtzb3dSaEExQmRFRVdvaVFDejlRMHRkNW9uUzRWUnhlNi9zZUdDbS9hc1l0?=
 =?utf-8?B?RUxtUGZlbk5ZVWN6TEJPRStJQnJLK1NvM1E1T3B1bjAvbXQ2a0VWalRjaDVy?=
 =?utf-8?B?STY1a0RjOWpGZFhRZVlEQ3VXMWFmRmRiNHN2SVF3eW13Y0p0aTE4Y0JMSWpD?=
 =?utf-8?B?Y3BaaFlTL1NqT2FON2VkUitBcFk4U1R6enoxOTRpc1V0dDhJZmVHT2hKK253?=
 =?utf-8?B?UmY2dkdCK2RrUWpnWFB2RTJRQncyYXF2WFh1T00xUGhGa1pKd2pmTXhhTWY1?=
 =?utf-8?B?dGpCNmtETFVUcnQ2TjhXSE04eWpmbDJYV2tobGJzdEdnSkM0REZQRVN0YVpt?=
 =?utf-8?B?Y2NpeWpkWXArTHhwM1RUNmZ5dFMybVQzTVl0eXo0VVQ1UTF5bnRxdEs3cnN1?=
 =?utf-8?B?QXdTdExWTmZxM0IxbmdHNFhXbVlwVDN1eDluNzQ0TVU0RWlGc1ZZU3lyQmlC?=
 =?utf-8?B?eWVIWmtnbmN4dEJRbnQ0R1ZQL1V2UnZmN0w0Zlc1VGhZRGZpSFB6M1BGRUVE?=
 =?utf-8?B?STRCTGtndGVTQk5TKzlUQlFxVW94cCtaZWR3NFdZRWpNYkhaK2lJWDYwaFlv?=
 =?utf-8?B?bzN3bU8xTEk0YnRWaG51U01kZjROMXV0QWVXbjV6aW9MZGFMS056cDRXeTBJ?=
 =?utf-8?B?MjNsKzM3OWR5bWFIR29WQXh1RlZMakp4VnpEbGdSR0oyMklqMkd5RmJhbjBv?=
 =?utf-8?B?UjRKRTAzWThwcW5TZVFhN0pHSHU1eTZkcHpmV1k5YnUwOWRxb1E3Wk5FNmkw?=
 =?utf-8?B?V3MvdUdVS0JHd0JIa3JldEVSZUR1enozNWdiOUtRL0dqSVlVbE1MWUZHTW5s?=
 =?utf-8?B?R3hTYnVZdlg2UkRYTDBEWGhZMC9EMFkvT0RKVWJMRkFGNDZpOGJVMG9LOUZX?=
 =?utf-8?B?RGIrTnh6eTF4c0svbFRYNHpoTVRBa1VWNlFHeVVQaXRWeXh1RTMyQmZuUmI5?=
 =?utf-8?B?ek1aY0tTazRmSGJZemhiUU5LSklrTXVIclZyNHBOSG5JekYrbGdPeGxXeVBq?=
 =?utf-8?B?QzBXb3l6dm5UYUcwUStQa1lTcTdVQ0dDaTF1NTlUUlhJZnVFMnpZRzRMSW9L?=
 =?utf-8?B?Y2ltY0JPVnRkclNqUkdnWENzL2luQ2txSnJXNmhSQjNqQ21aT1RKZjBTL012?=
 =?utf-8?B?aWtSRVlsT2JMNnVRTTh3bi9BRW0wclBtSFFaOXBvUHIzLzUyVGdoKzZuK25G?=
 =?utf-8?B?RS91d3ZIdFZLVmdoSm4zczNtSW9tb2VNRitCQ3NVaWc0QTgrVG1ONVFMeDJ2?=
 =?utf-8?B?RVlDWXhBSGl0bjBTVzc3c2N6MlA4MmpFYVAwNjI0Zy9TdG5HNHVXeWVZa29p?=
 =?utf-8?B?Vmh4dVEwUzEvOUdEbk1hbHE2d09PMTBiVllFWm52RXlwN2luMzVIaTBZS3N6?=
 =?utf-8?B?NkhleEQrT0ZCZzNwRzRYSUh0a3pVTW9xMytwa3hteVhySktTbkJUZzhHWnAy?=
 =?utf-8?B?L05mMjNWRWg2eE9uZWVvOHBKYisrVVo1eGRBNlcrelh4VWVHQU80alE3Z0Fv?=
 =?utf-8?B?NHMvUWV6eC84QWdXY0RhZHJHWXFhcjJISG1DeStWWi8rb2NKMDJuSFZsc3Ro?=
 =?utf-8?B?aFlRNWczRWpyMHJlWFNTb2YxMDE4OGtWZGlZeHEvR2ZUczV3S0NROEdDUWw1?=
 =?utf-8?B?R0liV0l6LzUvSnIxTkJobmhUUktNb1AyakpoQnRTWVpOT0RudW5URjFwR0xV?=
 =?utf-8?B?ZnA1amF4eWE4c0I1Y2YyV3dnMU9KR1dQK0hSZWRCMjBocEg4bm9KdFJVeFh2?=
 =?utf-8?B?WVE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <EF3DB8C37A97F14C9D18B0F145826D8B@namprd15.prod.outlook.com>
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BY5PR15MB3667.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 20d65738-7b52-47b2-016e-08d9a947ecf3
X-MS-Exchange-CrossTenant-originalarrivaltime: 16 Nov 2021 21:27:43.0517
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: /Ce3Au4XMCqIlNTH9RRXP2dbeDSw9Y8os8g2R5IQym3LD7PH13tPxaET1+2SdeLC
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY5PR15MB3619
X-OriginatorOrg: fb.com
X-Proofpoint-ORIG-GUID: 753AWNPJIZPaKa-4UNjFBcHeVrLfjgtv
X-Proofpoint-GUID: 753AWNPJIZPaKa-4UNjFBcHeVrLfjgtv
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 2 URL's were un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.0.607.475
 definitions=2021-11-16_06,2021-11-16_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=fb_default_notspam policy=fb_default score=0 mlxscore=0 suspectscore=0
 phishscore=0 lowpriorityscore=0 malwarescore=0 priorityscore=1501
 impostorscore=0 spamscore=0 adultscore=0 bulkscore=0 mlxlogscore=999
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2110150000 definitions=main-2111160097
X-FB-Internal: deliver
X-Original-Sender: terrelln@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=f9q3+2ZQ;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of prvs=095491a111=terrelln@fb.com
 designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=095491a111=terrelln@fb.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=fb.com
X-Original-From: Nick Terrell <terrelln@fb.com>
Reply-To: Nick Terrell <terrelln@fb.com>
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



> On Nov 16, 2021, at 1:08 PM, Nick Terrell <terrelln@fb.com> wrote:
>=20
>=20
>=20
>> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>>=20
>> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.or=
g> wrote:
>>>> Below is the list of build error/warning regressions/improvements in
>>>> v5.16-rc1[1] compared to v5.15[2].
>>>>=20
>>>> Summarized:
>>>> - build errors: +20/-13
>>>> - build warnings: +3/-28
>>>>=20
>>>> Happy fixing! ;-)
>>>>=20
>>>> Thanks to the linux-next team for providing the build service.
>>>>=20
>>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc43=
c1aa1ba12bca9d2dd4318c2a0dbf/  (all 90 configs)
>>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972ad=
531c9b149c0a51ab43a417385813/  (all 90 configs)
>>>>=20
>>>>=20
>>>> *** ERRORS ***
>>>>=20
>>>> 20 error regressions:
>>>> + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected ':=
' before '__stringify':  =3D> 33:4, 18:4
>>>> + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_ye=
s' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>>=20
>>>   due to static_branch_likely() in crypto/api.c
>>>=20
>>> parisc-allmodconfig
>>=20
>> fixed now in the parisc for-next git tree.
>>=20
>>=20
>>>> + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined [=
-Werror]:  =3D> 531
>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 47:1
>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 499:1
>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 334:1
>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 354:1
>>>> + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 372:1
>>>> + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 204:1
>>>> + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 476:1
>>>=20
>>> parisc-allmodconfig
>>=20
>> parisc needs much bigger frame sizes, so I'm not astonished here.
>> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simply =
tempted to
>> increase it this time to 4096, unless someone has a better idea....
>=20
> I am working on a patch set to reduce the frame allocations some, but it =
doesn=E2=80=99t
> get every function below 1536 on parisc with UBSAN. But, in addition to p=
arisc
> needing bigger frame sizes, it seems the gcc-8-hppa-linux-gnu compiler is=
 doing a
> horrendously bad job, especially with -fsanitize=3Dshift enabled.
>=20
> As an example, one of the functions warned ZSTD_fillDoubleHashTable() [0]=
 takes
> 3252 bytes of stack with -fsanitize=3Dshift enabled (as shown in the firs=
t warning on line
> 47 above). It is a trivial function, and there is no reason it should tak=
e any more than
> a few bytes of stack allocation. On x86-64 it takes 48 bytes with -fsanit=
ize=3Dshift. On
> gcc-10-hppa-linux-gnu this function only takes 380 bytes of stack space w=
ith
> -fsanitize=3Dshift. So it seems like whatever issue is present in gcc-8 t=
hey fixed in gcc-10.
>=20
> On gcc-10-hppa-linux-gnu, after my patch set, I don=E2=80=99t see any -Wf=
rame-larger-than=3D1536
> errors. So, you could either increase it to 4096 bytes, or switch to gcc-=
10 for the parisc
> test.
>=20
> I=E2=80=99ll reply in more detail later today when I put up my patch set =
to reduce the stack usage.

Zstd has been compiled with -O3 since before this update, and I=E2=80=99ve =
left it in. However, if
I remove -O3 (which reverts to the default of -O2), the stack space reducti=
ons disappear
on parisc. So it seems like gcc-hppa-linux-gnu doesn=E2=80=99t handle -O3 w=
ell.

I=E2=80=99ve done some preliminary performance measurements, and -O3 doesn=
=E2=80=99t seem to be
necessary good performance anymore. So I should be able to remove it. I=E2=
=80=99ll measure a
bit more carefully, then put a patch up.

> Best,
> Nick Terrell
>=20
> [0] https://github.com/torvalds/linux/blob/8ab774587903771821b59471cc723b=
ba6d893942/lib/zstd/compress/zstd_double_fast.c#L15-L47
>=20
>>>> + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2240 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>> + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2304 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>> + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2320 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>=20
>>> powerpc-allmodconfig
>>>=20
>>>> + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_366' declared with attribute error: FIELD_PREP: value too larg=
e for the field:  =3D> 335:38
>>>=20
>>>   in drivers/pinctrl/pinctrl-apple-gpio.c
>>>=20
>>> arm64-allmodconfig (gcc8)
>>>=20
>>>> + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_o=
verflow' declared with attribute error: detected read beyond size of object=
 (1st parameter):  =3D> 263:25, 277:17
>>>=20
>>>   in lib/test_kasan.c
>>>=20
>>> s390-all{mod,yes}config
>>> arm64-allmodconfig (gcc11)
>>>=20
>>>> + error: modpost: "mips_cm_is64" [drivers/pci/controller/pcie-mt7621.k=
o] undefined!:  =3D> N/A
>>>> + error: modpost: "mips_cm_lock_other" [drivers/pci/controller/pcie-mt=
7621.ko] undefined!:  =3D> N/A
>>>> + error: modpost: "mips_cm_unlock_other" [drivers/pci/controller/pcie-=
mt7621.ko] undefined!:  =3D> N/A
>>>> + error: modpost: "mips_cpc_base" [drivers/pci/controller/pcie-mt7621.=
ko] undefined!:  =3D> N/A
>>>> + error: modpost: "mips_gcr_base" [drivers/pci/controller/pcie-mt7621.=
ko] undefined!:  =3D> N/A
>>>=20
>>> mips-allmodconfig
>>>=20
>>>> 3 warning regressions:
>>>> + <stdin>: warning: #warning syscall futex_waitv not implemented [-Wcp=
p]:  =3D> 1559:2
>>>=20
>>> powerpc, m68k, mips, s390, parisc (and probably more)
>>=20
>> Will someone update all of them at once?
>>=20
>>=20
>>=20
>>=20
>> Helge
>>=20
>>=20
>>>> + arch/m68k/configs/multi_defconfig: warning: symbol value 'm' invalid=
 for MCTP:  =3D> 322
>>>> + arch/m68k/configs/sun3_defconfig: warning: symbol value 'm' invalid =
for MCTP:  =3D> 295
>>>=20
>>> Yeah, that happens when symbols are changed from tristate to bool...
>>> Will be fixed in 5.17-rc1, with the next defconfig refresh.
>>>=20
>>> Gr{oetje,eeting}s,
>>>=20
>>>                       Geert
>>>=20
>>> --
>>> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-=
m68k.org
>>>=20
>>> In personal conversations with technical people, I call myself a hacker=
. But
>>> when I'm talking to journalists I just say "programmer" or something li=
ke that.
>>>                               -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/241006B3-699F-44FD-AF85-0133971BCD85%40fb.com.
