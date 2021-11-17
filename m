Return-Path: <kasan-dev+bncBDBLXJ5LQYCBBPOE2GGAMGQEKJKDTDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DD24453E25
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 03:00:30 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id ib13-20020a0562141c8d00b003958b43bcf2sf1234601qvb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 18:00:30 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VI0rpcUwHBK/N1QueCEq5a5HeEd/G5NwwiDzjK6H5uE=;
        b=EGk+e9hLOb3Jfrzq8nkfnqBG4ShiveScH8OULufpLRuR70Tub91Rd/ua3G3Z+nRiuc
         agKN3XylP+JxbXky1a284ekS60gYBVGXo/enJFZGQ1gDV9Hjo9nohGGlszlTB0+zdsrt
         HImiMRihl0S/WrtcfWUkh1IXRH4J/QWHnq21ibn1BpCRTonNsSlRw9CUH4RSaMWju6yF
         rpouFISF/5halXjQOWEeAGumTFG7HaB96XuQUg6ebYw7w0b4wyLlHuNAkn65YJzPrXl+
         9v0AoUWPuMdIN4Gi/mGOnFLg64DhCMCK2NY6GhQK71YePcaBK4N1ugGCiZfdHj0Ts1wL
         a19g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VI0rpcUwHBK/N1QueCEq5a5HeEd/G5NwwiDzjK6H5uE=;
        b=nQ8QK3+Gv4x5xd6NfTfApb9XEDmFbKLdrhKBT6Mf+uK5B6O7JB9UyKgXFZOtTAj7eS
         gePIXpsKB5/wI85YyM4BCn6s/1pTh1iXVB4yB7VecaQUoaViyf1B5xC0FDinfzXFx2WY
         bbP5QCCOVKjBWtP6iuw9nFD5DJKslUj/hQVMRsStQkLtIsGO2ZaM47gGNGtaxgkTNBeJ
         3FAq/5xyKM9OoiYhtnTozpAFZ6R5tUMFMR9O+3yHCiusFJYVEV5LxOvlNKGfPaDe7O5q
         QBGuKtkaFuG7KTOz/G6g7vgz0phISU+7RFK9jbk02TQmWoBXpk52/YA6YIIQh3njftbL
         PApA==
X-Gm-Message-State: AOAM532ZXFAP0QCEu080llFGQV3aDtloJ20BDgpVgQW4gUKkD2IWaz0y
	w6N3cEZE7do/K87MvzyR2gY=
X-Google-Smtp-Source: ABdhPJzRMcpmojDLCMoq5cRHv0dofznJtz1XumI9EFDOJGUFRExQsd1k5AcDjY+hoZQ3I+/zjIiClQ==
X-Received: by 2002:a05:6214:f2d:: with SMTP id iw13mr51725737qvb.13.1637114429381;
        Tue, 16 Nov 2021 18:00:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5fd4:: with SMTP id k20ls10847160qta.8.gmail; Tue, 16
 Nov 2021 18:00:28 -0800 (PST)
X-Received: by 2002:ac8:5906:: with SMTP id 6mr12987557qty.230.1637114428879;
        Tue, 16 Nov 2021 18:00:28 -0800 (PST)
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id u2si1114064qkp.6.2021.11.16.18.00.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 18:00:28 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=0955d447e6=terrelln@fb.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0109334.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 1AH1cMiB001281;
	Tue, 16 Nov 2021 18:00:02 -0800
Received: from maileast.thefacebook.com ([163.114.130.16])
	by mx0a-00082601.pphosted.com with ESMTP id 3ccgr7bush-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Tue, 16 Nov 2021 18:00:02 -0800
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (100.104.31.183)
 by o365-in.thefacebook.com (100.104.35.172) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.14; Tue, 16 Nov 2021 18:00:01 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Z9tsjDeUgj4IwHJWUwqWqV9ytOPFXWXVo6zu3epZf/5N1QOCU2eBOz0YZQqMAlmw5qxCnv31+NnocoiLVqdgCznukz8hfN5y7lj5A3MZeVjjttp3fn+0/aOLyTc4CGD91KGZPeKqpgYVsMtyGIW+w1O5pPl0GY5x0lS7k1Y8cGNDM5A2MnnokUWDxO7mYQ/fBDoZmE17bwovaCoa8dpmn3ls5ajrCyR1qVZ5SFreVCzOjdn/dg96NKN5riLg6I7Aoqt5Onacmgi+fpO9EU+3gGOzNHF7OV1NNzhU9QV3QdQjhrHR/rmNlsd9CnofyXztYo/LxO1Jfhn3mRWsBSTuRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=a6lWXSIg+X2cXkfbXTfDBNBBE0zXyL4zHo7XMePdLjU=;
 b=hXSxNYoyAOOxnYJ8gT073WvVtMzYhqUwIyiU03WCnxaZ/bZidB1XtoldZNNIYAPDRYUiSOBPQbPS0OkNb+pZMw7HRdSeTIUUIPp5KtUmy067h1q1lzHvNG7ldWPVTGmW6TMH621ghADs625GPGoYr9nzxo1ajT3gAr2IrFKIrvdnJrfRWaxlRA3xJ6qL91jPkg49b8s8xrKO+v9Zn74JlJO/rarVyZa2CwCiBGQ5qVGOloX5FPflvYfZhg6rmD1MRmkbHQ7PY1xUquIA21MqIrAMenTamd78I7GsZe2X/jER5lVnkylCwxV2ilbGPaVXFI5+KrTElsCvo8jULGX3hw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BY5PR15MB3667.namprd15.prod.outlook.com (2603:10b6:a03:1f9::18)
 by BY3PR15MB4995.namprd15.prod.outlook.com (2603:10b6:a03:3ca::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4669.11; Wed, 17 Nov
 2021 01:59:54 +0000
Received: from BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4]) by BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4%6]) with mapi id 15.20.4690.027; Wed, 17 Nov 2021
 01:59:54 +0000
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
Thread-Index: AQHX2jynD2CHATmgwEukyh+iAPvEB6wEy7gAgAItboA=
Date: Wed, 17 Nov 2021 01:59:54 +0000
Message-ID: <480CE37B-FE60-44EE-B9D2-59A88FDFE809@fb.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
In-Reply-To: <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: a9eb4ef5-0756-42dc-80ce-08d9a96df341
x-ms-traffictypediagnostic: BY3PR15MB4995:
x-microsoft-antispam-prvs: <BY3PR15MB4995CD83649C35790F6E173FAB9A9@BY3PR15MB4995.namprd15.prod.outlook.com>
x-fb-source: Internal
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: X5VGjqcbJvIvPaZF4Fr7MLSphffu3Er8/67htxugzFa0zhWV0SdUAlOa3H//NZiH+uI4WryG5YJK/iwIk2pQ8t7t4CdzJlbuC/sAoGCCpbXNiaEKcCEwr/CnzFNjhv0r747eoukC2eQDzuah4JiqIc3DP8Jf/dn5Yyp6hdwdKpmYN0QL46PJxBj9PLRzTMm3AaK9j47FIVT2ir/nttr0YT2zqvVNTaDOISz05UZBr62fa0noaYSVBmh2aJSV29/SyfKeu5wdmypUXoPOMgn6vj3dC/fxBmRKM2UZ3udrv+isepr5SH0AcC1KY9sxmef0rGSCj4NyIRilVWXFV9kvQOhz91wmFVpw0Asus/tV6/IMKqQuLTOFGfAOFxfNCzVcfxTzqC4igB4GXDDb2O3UwVR42GaHxouA/RR0Rdu74cLN7w+BeRfTADtiQUScgWnTui+ykjoML0ns3ifOhpjyZyDUAOs4TA24aGy/yhrYt5a9XDQs1hZn1zH+nVgdzl21b+pv200dBsRZ9a4+ygJvPmbhLzhQluQMRrlPyBaQcFDcY8bJuMKuT79yNimRh2RnMTAOORwh5g55y6smHaKNOmrXbuTBey1riXWO2d+pbDH5Oqif3ebA/Dhx+EeqnslPGnNXcxhEW65zjosGYN1MeLWU032iTMRI7yuMsV1/tCphI2OVjTN/Xfq/CcWvkMKjLRhxeeceUjMTiEt1ugbyqxoeNrpALIXe1vzEzClzTbWe00udzdorhYcKScM3ydcnmo38teYVzRwC8Y0Epdh3YyV2KbdVeBmy/Uh2wUC2+/uYnYlIx1TTBMDypFW5/82HEeM6mJkEjAns3yIWhjPRrA==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR15MB3667.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(91956017)(316002)(508600001)(83380400001)(76116006)(6506007)(64756008)(6916009)(122000001)(71200400001)(66476007)(66446008)(33656002)(66556008)(36756003)(2616005)(38070700005)(2906002)(966005)(66946007)(8936002)(53546011)(186003)(8676002)(5660300002)(7416002)(6512007)(38100700002)(4326008)(6486002)(86362001)(54906003)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?YktWQVlYd3lEVWgzNTJNeTI1NGtHODk0NUkzcE9DM3diQjdWK1B1dlhwaTJZ?=
 =?utf-8?B?ekJmZFB3TzNHeTREZkhYcXNkcG11b21uUUJTRDcxUUl5RXNhdnZaUzNaZWtE?=
 =?utf-8?B?R2FzWnROTUhZM1VOZWF5RlI2bzYrQ0plN25hcEZGT2FVZko0d2VlbldkYkJl?=
 =?utf-8?B?OG9scUI2MGx3cWxYWTVnVVdLSTlqdTJlY01qZmZKN1ZPYTk3aGZ2TmoyOXBQ?=
 =?utf-8?B?MTJMUis0VXpyY0tNRXUzeEdvRWxZSzBIYlp2bWo5NHFCV0J0bHBQd1ovMmI2?=
 =?utf-8?B?cGgwekhrUHI5dUI1djlFWWxIQjhZZG12UFpKSTdQWTNOSVdhdStVVFZSNkdu?=
 =?utf-8?B?Wk5mR0VoREt2Y0lIU09BZ0pOaGtCcm5LQTNRSnp2YkZqWTRrYmJoem0yZjI3?=
 =?utf-8?B?c0FVMjFTbFJQNmNwVmpEMHZlY3hkY1NYaEVPaGc0VWorVlRMOE1rR2x3RTZI?=
 =?utf-8?B?M0hZb3lTWmczd3FuM3pUazNMclJSV3Bxei9UU3FJS09XVzd3NFowbG5XTC9E?=
 =?utf-8?B?cjN0ekxwNEhVTzFxSStkYWZhcVlQQVYyZVk0aDVTdDEwVXZyZ1lGbWo3S2tP?=
 =?utf-8?B?aG4xaElidHhoMGJ4VGtFbkRRdGdSaTRHeTVuOCtmT1pYR2d2VmExWkZtRy9u?=
 =?utf-8?B?VWdJempnbXFPcG5Hc3QxUVhFT2UvNTZwYm1wRTR0dmdob2N6Q1VuTm5kZ0s0?=
 =?utf-8?B?aFJYSTgrWlBIdkZKUWZiN0RwY1B1eGR0VlVUaWtWa0czdjdONTY2czJjQkNZ?=
 =?utf-8?B?Uy9rUngwc3pZQ1ROM0gwWUdESXNaUEdnRXpNck5rdk14NVhxQ2E5aU5EMG4z?=
 =?utf-8?B?aVVBREpkK1Vxam1yejdCMHEvandTSGFWOEUzWFBTVmkwVHZGM0R4eVFhcW9J?=
 =?utf-8?B?aUpuY0k2ejhQVkFURmxOUmpDb09iSjQ2WXdneFlvOWxNdjRzK2hJUWJ2eWIr?=
 =?utf-8?B?eHltSmlLZnJ3bGJ5S0I3QjhTZTY5bXN0cjBWUExmQnZwQUx4VDZqelh6a2Ro?=
 =?utf-8?B?NEpnWnZnZjdqZ0JOQlAvTWlWRXNEc09FVlNHUTVxUXlGYXM0UjErRmV5NHB2?=
 =?utf-8?B?dm42RURWamp6bjFYQzlkTmFmekI2Smhvd1VydWZvMmZHOGNsSWxkdkVLZ2po?=
 =?utf-8?B?TklaUGlDNVNsc0d1OU41VytGT3hrQ3JxM2JGUm83ZnEvTUdBVjlDWjEwenlY?=
 =?utf-8?B?UjAvVHZ4VXd5VGhiOXdPNWFYSjdHOTYxMmFpQ0N4STJWNE1QcFRFUmJkeU15?=
 =?utf-8?B?eW9uUW5NRWFZZ1Zsay9uKzc5aVA5aTl0OWtHS1RrdnBhenZhSHhMdUxZdzNo?=
 =?utf-8?B?MVBjQXFRZCswRUgrODZkVjE5Q1ZtWWwray9qK3ZOeEZnOVo0ZDh0WE5rK0dw?=
 =?utf-8?B?TEJUSVFiUXowTkhKSnVjdGh5cGliM3lCelcyTFRhdG9iOTEwSWRDS0RwK1p1?=
 =?utf-8?B?ODc3bklWN3R6L2hUWDlHcGJSRFZBT2ZoT1lQZWNmS2hRK1U4TyswVStaWUJx?=
 =?utf-8?B?dCttYUhnUHIzQWxKV0NHZFNCN1ZjRFYvK3k2UmFCUzFENTZyK2UwSVJ2cWxV?=
 =?utf-8?B?RmxnSXp5YmRWYWhmMTNVWURMY0swdnBSeVZjdkdsUE9XVHdPN1JjZXpuZEl5?=
 =?utf-8?B?ZDlidkFkWWJCV1FsUlJETDNmTUExTUlaeFRZT2s1a1ZQWUZXemxZNXh4TzIr?=
 =?utf-8?B?SmFrY2VneEg5WUlhZVVQYVlNSzRDL3lCdk82Z1dLODJjbGdDTklDK003bUdG?=
 =?utf-8?B?b0VmWThzSjhJZmw1NDJ6SmgwWHhCcXUxc211SEpPZ2dRcCsyaTdKVll3UVlM?=
 =?utf-8?B?VWluampwVEVDa3F2eVRkd0lBNGRSRjFJOW9aZDdpYW5EcXRQVk1wbmVnZEhr?=
 =?utf-8?B?Q1ZoZUpzV1NtekVlbWhvMlRVVTNFSXNVWTNnSFJ1cnlDWEc0bGNUSk4rTm9z?=
 =?utf-8?B?VU5LWXY2SjJnVVEzUjFPdWZXeXZBc2ZxSVhkNnJGdmU5QWwwR2Vwa09tL0hy?=
 =?utf-8?B?b01YK0h1UDFsTzZndEcvWC9LVTRGNm9ZT0lUWXRRcWQyTlNRWXFkampBdXhY?=
 =?utf-8?B?UkN2WHljVDVEelJmTjJBQllEMjBXcFIyRURHcitwamV1bHcwSkhBR2t4TGRa?=
 =?utf-8?B?UXFUWXJuU1RkUzVTTVdyTWtKYzFDcDJMUExMY0VqTnV2VDZGSHlQMDQvbDVG?=
 =?utf-8?B?ZkE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <9E602ED3A1C78A4D8F9DEAFA8A6CBBFB@namprd15.prod.outlook.com>
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BY5PR15MB3667.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a9eb4ef5-0756-42dc-80ce-08d9a96df341
X-MS-Exchange-CrossTenant-originalarrivaltime: 17 Nov 2021 01:59:54.5832
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: trODfFguX9Tz1CVPSDlB4blnHx4S/lrzJLfU0Ib9rOLloyVrj82zKJdEMcInNW2p
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY3PR15MB4995
X-OriginatorOrg: fb.com
X-Proofpoint-GUID: KPMP0YXMvmoEisLTn4S9VhDiOaCdBctz
X-Proofpoint-ORIG-GUID: KPMP0YXMvmoEisLTn4S9VhDiOaCdBctz
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 2 URL's were un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.0.607.475
 definitions=2021-11-16_07,2021-11-16_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=fb_default_notspam policy=fb_default score=0 impostorscore=0
 bulkscore=0 spamscore=0 clxscore=1015 malwarescore=0 mlxscore=0
 priorityscore=1501 phishscore=0 suspectscore=0 adultscore=0
 lowpriorityscore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2110150000 definitions=main-2111170007
X-FB-Internal: deliver
X-Original-Sender: terrelln@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=E+QcX5u9;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of prvs=0955d447e6=terrelln@fb.com
 designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=0955d447e6=terrelln@fb.com";
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



> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>=20
> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.org=
> wrote:
>>> Below is the list of build error/warning regressions/improvements in
>>> v5.16-rc1[1] compared to v5.15[2].
>>>=20
>>> Summarized:
>>>  - build errors: +20/-13
>>>  - build warnings: +3/-28
>>>=20
>>> Happy fixing! ;-)
>>>=20
>>> Thanks to the linux-next team for providing the build service.
>>>=20
>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc43c=
1aa1ba12bca9d2dd4318c2a0dbf/  (all 90 configs)
>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972ad5=
31c9b149c0a51ab43a417385813/  (all 90 configs)
>>>=20
>>>=20
>>> *** ERRORS ***
>>>=20
>>> 20 error regressions:
>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected ':=
' before '__stringify':  =3D> 33:4, 18:4
>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_ye=
s' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>=20
>>    due to static_branch_likely() in crypto/api.c
>>=20
>> parisc-allmodconfig
>=20
> fixed now in the parisc for-next git tree.
>=20
>=20
>>>  + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined [=
-Werror]:  =3D> 531
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 47:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 499:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 334:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 354:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 372:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 204:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 476:1
>>=20
>> parisc-allmodconfig
>=20
> parisc needs much bigger frame sizes, so I'm not astonished here.
> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simply t=
empted to
> increase it this time to 4096, unless someone has a better idea....

This patch set should fix the zstd stack size warnings [0]. I=E2=80=99ve
verified the fix using the same tooling: gcc-8-hppa-linux-gnu.

I=E2=80=99ll send the PR to Linus tomorrow. I=E2=80=99ve been informed that=
 it
isn't strictly necessary to send the patches to the mailing list
for bug fixes, but its already done, so I=E2=80=99ll wait and see if there
is any feedback.

Best,
Nick Terrell

[0] https://lkml.org/lkml/2021/11/16/1217

>>>  + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2240 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>  + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2304 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>  + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2320 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>=20
>> powerpc-allmodconfig
>>=20
>>>  + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_366' declared with attribute error: FIELD_PREP: value too larg=
e for the field:  =3D> 335:38
>>=20
>>    in drivers/pinctrl/pinctrl-apple-gpio.c
>>=20
>> arm64-allmodconfig (gcc8)
>>=20
>>>  + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_o=
verflow' declared with attribute error: detected read beyond size of object=
 (1st parameter):  =3D> 263:25, 277:17
>>=20
>>    in lib/test_kasan.c
>>=20
>> s390-all{mod,yes}config
>> arm64-allmodconfig (gcc11)
>>=20
>>>  + error: modpost: "mips_cm_is64" [drivers/pci/controller/pcie-mt7621.k=
o] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_cm_lock_other" [drivers/pci/controller/pcie-mt=
7621.ko] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_cm_unlock_other" [drivers/pci/controller/pcie-=
mt7621.ko] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_cpc_base" [drivers/pci/controller/pcie-mt7621.=
ko] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_gcr_base" [drivers/pci/controller/pcie-mt7621.=
ko] undefined!:  =3D> N/A
>>=20
>> mips-allmodconfig
>>=20
>>> 3 warning regressions:
>>>  + <stdin>: warning: #warning syscall futex_waitv not implemented [-Wcp=
p]:  =3D> 1559:2
>>=20
>> powerpc, m68k, mips, s390, parisc (and probably more)
>=20
> Will someone update all of them at once?
>=20
>=20
>=20
>=20
> Helge
>=20
>=20
>>>  + arch/m68k/configs/multi_defconfig: warning: symbol value 'm' invalid=
 for MCTP:  =3D> 322
>>>  + arch/m68k/configs/sun3_defconfig: warning: symbol value 'm' invalid =
for MCTP:  =3D> 295
>>=20
>> Yeah, that happens when symbols are changed from tristate to bool...
>> Will be fixed in 5.17-rc1, with the next defconfig refresh.
>>=20
>> Gr{oetje,eeting}s,
>>=20
>>                        Geert
>>=20
>> --
>> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m=
68k.org
>>=20
>> In personal conversations with technical people, I call myself a hacker.=
 But
>> when I'm talking to journalists I just say "programmer" or something lik=
e that.
>>                                -- Linus Torvalds
>>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/480CE37B-FE60-44EE-B9D2-59A88FDFE809%40fb.com.
