Return-Path: <kasan-dev+bncBDAL5AMDVMDBBV4L32GAMGQEYGS6KRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B222456DFB
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 12:09:12 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id o4-20020adfca04000000b0018f07ad171asf1702728wrh.20
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 03:09:12 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1637320152; cv=pass;
        d=google.com; s=arc-20160816;
        b=TWoSB67tRCPm6/k/3/sq0YE9ZcrVAPGi8RDtKDLFHMJJVV9Wg+rAs1k1YqXNNtSLvx
         dLrTk6lhTycY4eIfHxO96+wUxeijnz59JObqWGQpdg4EddUZDZFtBvsnWNAwnS5LvIKW
         3uCQxYf5RC9cQOt52Ck0InRHiOLp468stps8G+hB8y95BUWt6VOzREI2lJGmnZaDsgdR
         aYl2BuvMoz9EoXOPoHGFPNYiw+F+d9X8Zz8iOUxpztwx78qdx4Cl5lW1QxJTSLNGVNkx
         /Wwak6voIbZftk2GhQU+128394PBg/rDD3EiqO4wEZcmBeAjwjsueH5JK3MI/9ODa4V3
         yB3A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=nDQ+BNrw+L67MWfAe1MBJjMCgWQ11vpBiQLFWmIoAvw=;
        b=r5l4GVjB6mnd4maH+NDq2Eri97ZV94d7z2pDwPpNpYSn7LXXB7rUd31BduBYbigH/W
         C2JBKLuW/SPgJfKgA0GA5FYyzQwOBffe8Sqv9+yRnW92juaFHoE4yWC11bznlBcMQJgp
         +q58I8f7rgrWFJsaFXTv9+SKmJ5E6rLYtDDMeF6AsZFykVhoN35d4cWp0T8eLB+gbf+w
         2bo+8YJ5R2rKXHy3JeZlvoP9V8udy8ZTvXN9glEY+CBtvSValYpuiGp2n/+CNPQzKPAT
         +QQpchlNZf2rGUX3CJGoFF5NGDoHHrIz1NpKfbQVcAQWnfj/UuloOdotOGMJ0p93hkpa
         D5ag==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@qti.qualcomm.com header.s=qccesdkim1 header.b=uK0S82+R;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of jiangenj@qti.qualcomm.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=jiangenj@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nDQ+BNrw+L67MWfAe1MBJjMCgWQ11vpBiQLFWmIoAvw=;
        b=dd5RQt/bGjGWnNMvJSQiidcjZoQAsokiaStesdA7rxUvag5irEb1rhLw0ij7Og9bWr
         HIlcVlQEBg8432MRwCyc8p+TJlunENNmTw0fLDeEoTz7lym/kyUzQZchP/ve4LLYRNB6
         KXTA5IinglTazx5DLaTJ/PHXlUJdIvYS2EsFVMeMpiJYFhSg8aiqvvhqQXCRLBrYPvAV
         dL4K/I5JuxPbnkwMLAJBHk0CdlMBmaamf9cIQV97DWLC3neO9X+S+m5EE2nAhHXmHyCa
         twPZfkGH0HTl0PqEtkpe9fG2DTFqrUWfil5YXfKsayZNaJDogqXTRb4k5bbSVusb5zo/
         iaMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nDQ+BNrw+L67MWfAe1MBJjMCgWQ11vpBiQLFWmIoAvw=;
        b=kg5CaPzjuCTv60jowJe4B66dqexx3bQAJzHdx3XRpqEdHimFVCCbjSiVUw0+ysxv5f
         njgoOdTzAmYHi+YnrMfF3yiL/o5HeBEBSwl7hDNSDYb4nSgrr5CSd+0eL9n1h92SjmkT
         K8YHdmCRlqmrUmO9SM+3gjDEPlUgT0YQi2LgVBEydqeBEWuudbZAgcgvt1iV5isFTpmp
         qJTbNX233VnmPcCF8Fr8hFryUgJ8w5+RFvIzEH9uFVSp9wtVbbIkaA33iztn0/eIsvPy
         vomnwOxDzLZzUtVVesJJbTAu7R2wKzAyuq48Gksa3DcruLA0Lz+iRByErYPCq7rhA7+w
         tDkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532i05jEb72G2xq574ByofuZhGcvIhwrzzfubeSnBQ3wX80WozcF
	Zwa/U7iXe3bRDQqAl0qECXk=
X-Google-Smtp-Source: ABdhPJw1TugTbvIM4JU4TGoObGL1KYj5VlGYG/SoFmLB8bn7RIIj5Ve/y8rMhslJk6ZntI3Jy90rbA==
X-Received: by 2002:a5d:48cf:: with SMTP id p15mr6233392wrs.277.1637320151859;
        Fri, 19 Nov 2021 03:09:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls6891771wme.0.canary-gmail; Fri,
 19 Nov 2021 03:09:10 -0800 (PST)
X-Received: by 2002:a1c:2397:: with SMTP id j145mr5796415wmj.113.1637320150877;
        Fri, 19 Nov 2021 03:09:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637320150; cv=pass;
        d=google.com; s=arc-20160816;
        b=nnzxOpBJXxsEBvfBqnrwPFnkGoPlj9pWd5cKtidrOCFZzN7VDUGi3+bA09haKvCuJh
         bqUNWNFEYZLqmstopGhpZNPoWM8e+YqhA42bm/z6a0EG7Ar1wIITkh8laCQAlzfSlbYs
         QaIfzfuWIVMgDmDjnc3jFHtsv0LxPAcu5yCADqfv6U6FBwIZb377R7plI+EPJ2yaJ2kC
         p3EHCY8H+2FmCMscvoZVmC7WAJKr7wxrGZeVGIpVdJN1rynpK3i8Sv66oK2JDLn8ZRUD
         4ROtxkMcFnBvRGLdDb0I8DJF6j9ve24d300LjiCORw3u1sxyeddNHfak/YDT36gutav4
         eatQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=V7yUWx3Zq1hx2NvHD6/fjK+fsZoksjsOUo83UTkD3hE=;
        b=ItX75T1AIdF63nBuSr4FoHykINI6ysC4dxRwiUSCOf4lnN7Z4vCf2qQQY8a/xQN25N
         8U6/DjRW0VGOwrNOxvw+i9/7VYZp5fPxS/WaRowQ9BpEIY6WXibHuQpAl1jyKM+u5hJC
         19qUFsWmXO/Gcw1z1jvesXd77acZZFd5qilDoDNs8qh9b0jrEEHlrDfR3NB6jvka8vHV
         bq/bgK+QuuAYhJdysIkIVqMUxz1ei47W281zgwbz59IpTkBQ2JToHFzQbsNFbZLSzm1B
         HOZWLWWg75MllDZdWJ5IVucQUxrzc9N8BEwom4UaDDdD3dpJ6URd48SWD8PI/16R+Xh3
         3aGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@qti.qualcomm.com header.s=qccesdkim1 header.b=uK0S82+R;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of jiangenj@qti.qualcomm.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=jiangenj@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
Received: from esa.hc3962-90.iphmx.com (esa.hc3962-90.iphmx.com. [216.71.140.77])
        by gmr-mx.google.com with ESMTPS id j14si186457wrq.5.2021.11.19.03.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 03:09:10 -0800 (PST)
Received-SPF: pass (google.com: domain of jiangenj@qti.qualcomm.com designates 216.71.140.77 as permitted sender) client-ip=216.71.140.77;
Received: from mail-mw2nam12lp2049.outbound.protection.outlook.com (HELO NAM12-MW2-obe.outbound.protection.outlook.com) ([104.47.66.49])
  by ob1.hc3962-90.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Nov 2021 11:09:08 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=FUzqTPxGstHdljVsNZzlFtcnJj4F/mppcuKoDtW+adIH7ojUu1rFkHFJcuzzAqjNhGy0mqB0gOrDmR1nwfNnZ4OpLKVtsLSHEenlcqjDe6hIo4vJV65a3mAVDnHK+E6wKKsjrWZSVz13o9vgxqbWDs226aYKPjbxEjzxWV07wk6OsN78O2t7HJcDz6GmzFvAccrwpIC4+x5VGEluA4NdGz8GuDqMeVXi9RZ/QnQk2DKNJAP4BXsZY3TNaT9xND5DMAygwO6eauA6qGpOGXALrLAQjc4tuiqhGo0BkcRFdN6DqBLADjxuKUnZUAXozffzwtv/QVykpgJW4vUnFnwmTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=V7yUWx3Zq1hx2NvHD6/fjK+fsZoksjsOUo83UTkD3hE=;
 b=Rt31aos8HidwXcrZuCmof9RPixMGnbX2cgRY8g2LnkP0P9OAQ01c9hEPiMpPXL4ji8HFocZMDR3Qk2gz+u69LdwjIVNl+s/DCWm0NyBDIOKO3CPRDG1sqOLfdA7U2WwEkK3PPypYonK3d1SNTVTvip/2CTxXbXVmBQ+QNfN1LnRVU1XBb+BHsKBBdDMLaKArTwmMziOQw5SWK6Pr725NBrR3wDdtj91Av+1aoewGhzbynMN52Kwx7IwChke0ycQqS6jl+h6m6Q54ebunczCNPGDNIYt7BvxWHdcHNFgsaLKuxyLPMIkT5SSfyCstv4U3rOKwuAMQANaS2GzhF9vCeQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=qti.qualcomm.com; dmarc=pass action=none
 header.from=qti.qualcomm.com; dkim=pass header.d=qti.qualcomm.com; arc=none
Received: from DM8PR02MB8247.namprd02.prod.outlook.com (2603:10b6:8:d::19) by
 DM6PR02MB4332.namprd02.prod.outlook.com (2603:10b6:5:23::32) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4713.22; Fri, 19 Nov 2021 11:09:00 +0000
Received: from DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3]) by DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3%9]) with mapi id 15.20.4713.022; Fri, 19 Nov 2021
 11:09:00 +0000
From: "JianGen Jiao (Joey)" <jiangenj@qti.qualcomm.com>
To: Dmitry Vyukov <dvyukov@google.com>, "JianGen Jiao (QUIC)"
	<quic_jiangenj@quicinc.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Alexander Lochmann
	<info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX23vD2nRqghWy5Eq5zUX4/l1PcKwJUjYAgAC3OuCAAKLFAIAAB9gQ
Date: Fri, 19 Nov 2021 11:09:00 +0000
Message-ID: <DM8PR02MB824798E699AC9F4B2510E293F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
In-Reply-To: <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 479617f3-17d7-4a75-14ae-08d9ab4cfd8d
x-ms-traffictypediagnostic: DM6PR02MB4332:
x-ld-processed: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d,ExtAddr
x-microsoft-antispam-prvs: <DM6PR02MB43326607CA1E44462B969236F89C9@DM6PR02MB4332.namprd02.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:10000;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 9faBHq+Ir414ksTxtBD1ykW0yK2b/I6vwGVuufeM6hq89VDFPnRJjN5+g/fAxRy/jWZTZ1Sw8JbTgz/G+PSK7u7ZrI/+kkJfk14245VCGCIWk3XDO1TtxUVcxZcRF8aMef2+csxWISiBoA4i3woSaxzcHMlPYGMi11LuCWZKI1cW0LQ80euCDcukHKvQJMKbVoFG5MfdC8MlQJzqgpdeEPG7unl9MkxfLjB17DJai8G6qLVjBFSYx6VtvuLCVrPzg2eqKtxnY0u89nzhkjhY61D4SjXs8BAXc7DCwXgK5ls0YINMldv9yhOLumJtVuCZzOF5/3qe55xUPgGY3fnRTm2AbN9Jy54poXxN43aDhUfqLkDHzcWWbq2nyGVxu8+Re+R+pdXBiDllGK84bDcmboC4TK2Sn0q2mxixxf9+HuDQmZYy3Xqn7KK4EKlSrcW3NjXzxQgxcs/M1+PwNy24pC4fyKJB0gP+aZG8Cw77mnDfySlZzOnUpOfsK2XlmA8TcjoQC2VGOcj+e+Qp/bQezG/0IbZBArvaZbjwyqD6e1HKvVP5ZC/ky3/RhSyvf8KSLACspL/haefZUpG9TNi0viCQ1/dJlOqgJYHdT6WGa5Zvci67dqvwnXj3kM7FPNTm8ABJFnA7ontPQ5XBaHxXGZTzZYN8e/YzV0uCCHkwFZIXBhxUmwlp61vRIZ5xqKztXAIPOA8O1ViXolq6epn4tFquOcLKUtNdrwNvqmhEx5RU4tGM6f0+6L2cDiFL/s8P0gKtNGcsBRpi8802AOzSkF0WXZA9f08jYQHsrYm0/F7Ek+mS1Ran+IKrXXlXrw/E9bQT8/1G7W2XQUiiQ99SXg==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR02MB8247.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(54906003)(966005)(508600001)(71200400001)(7696005)(8936002)(316002)(110136005)(33656002)(4326008)(38070700005)(66476007)(64756008)(53546011)(6506007)(83380400001)(66556008)(66446008)(52536014)(107886003)(38100700002)(2906002)(86362001)(66946007)(76116006)(122000001)(8676002)(9686003)(55016002)(5660300002)(26005)(186003);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?SkNXamFSWHY1VHkyUGdZQ3g3R1l1dlJ1TzhjR3Y4Q1ptMFRyTEVJdXBJQnFH?=
 =?utf-8?B?RW83RGZTd1Q3Z01iUitabGpZK25Nbm00eW9PdlRSSUQ4dGZxc0V2TWVteGxH?=
 =?utf-8?B?b0dGdFltR2pjeWhjVXdvbTB2c1J4eHdRVDVCUnpCNXpUaTQ5Q1BqQytnRWZm?=
 =?utf-8?B?VUxkeGZIYzFNMVlSTUN2a0c4aHJpWHBOV2wrU0VycUZwU0M5MzEvNm53amtH?=
 =?utf-8?B?aW5rNjU3aEVCQUFWcjRRZnBVWmRVK2VYUFI1aE5uWkxYblJFd0trVG9idXI0?=
 =?utf-8?B?dEd3L2ZndVRCMVcvY1dydzc0d0ZtKy84czVPQjdiVXgzZ1lEWWlUMkVIQjI1?=
 =?utf-8?B?WjI3dHZWNTRzaVhGZ2dPK0REN29zNC9JbDNRMldHM0t3ZzVpYVBLc1FIendY?=
 =?utf-8?B?TW1TREU1VlV5WnB0N3dLa3Zza1F1dkh5RVBocHFTZytIUzZteEU4N0xUZFJq?=
 =?utf-8?B?TGlGZjdxdjZnbTg4cTVWZTdwYlpDUHNYS0lYTkh3Q0JoSEF0Y3AyTkJRenRQ?=
 =?utf-8?B?NXVnMms0dm9pY29XS203QzZoa2FMcnhla3dwL0NQa1dFUy9SanRjczdyc3N2?=
 =?utf-8?B?aDlTMlFnRGhpTkZLWmpQdVJvckszZkhkVDVHWjloYkp0WXJOVDc1MU1ab2NZ?=
 =?utf-8?B?a2JpY0U4VzlZSk11UnczeFNLaHRLZ0p5dnNQMlhWNGZwcW94Zm5Nb2duczFp?=
 =?utf-8?B?Tnl4dlJ3UmIzY3Z0M3NlWlM1a3d4VzRpL1hibU5HQWVtVjZzaEUwY0syRFA1?=
 =?utf-8?B?dTluU01GanpaVjJOUldCRmZKR1NDZEpsNUQ4Y2M1TFkwQmsyK3N2VEZHZkt2?=
 =?utf-8?B?cjNkTm41cFNrNG5TTWpJTWVHM2ZSS2ZVYUVGOXZDRmZHWmUxQ2lHRHZkRW03?=
 =?utf-8?B?bWVoL0lvZXR3bW1WZG5CeUVPZzBlNFg1TlJTSlpnWlNTUExEaHNONk9ZT3BL?=
 =?utf-8?B?eDl5RUJYMFdWY0p3Y1RIVjFvZDlHWi9oNDlJRUIwRTh4REZKSFhqNmZqcDU1?=
 =?utf-8?B?SzlPWU1yK1lYUEM4WlR2SXVxdU1UaE8vUEZvSnRRU01QUDlsT3VBQ0VibjBa?=
 =?utf-8?B?WmVheVQ3UlkzWjFlVDZVNnBESDFmaHlEWUJDYzhMTmVUR3B0OUdoeGdHUnRi?=
 =?utf-8?B?am9pL3B0ejEzSGl0Si9qVXkzVUVaNTVGOXF3d3dVdTdsVi9DaFlhWHFVMmJT?=
 =?utf-8?B?TFN5aVZFcE5QQTRJSWRzNk1ad2U5Q252a0hPZEpBUW4yWnF0cWNYTjhVaUg2?=
 =?utf-8?B?eFQyNi85d1JHL0NKYkxiL0d3ZWoxWEI0Rzg1TFhVUTg1T3d3NlY3ZldBU1pq?=
 =?utf-8?B?WUwyOEJYNlNDRCtya1huaDE3OTJTeWRNMTlaTk9lUHArbG9haXVRUytkSHcv?=
 =?utf-8?B?TDBGWTBUSittUU5rSlRUZ3c5VlFSNTk0TUlYekF2SFZrM1ZMZExUaWEyM21M?=
 =?utf-8?B?Qm1mQ3lIU1Z0VWh3LzN6cERKQzVBdnlNdVVab0dvc3Arb0E0SGNCR2l4MXQw?=
 =?utf-8?B?U2hEdVl3Z0FrbUNWdTkvWThOZ3NqeEF2NW9PamxDeUdMNnEzbGRwaTdtc0t5?=
 =?utf-8?B?UnU3VGw4MGNRSHNtLzFMSThuZStFRHdTZWQrcDBqODFORkNQTXZvemhGVFVl?=
 =?utf-8?B?aWdpNHRuUk0xRFFUeE50SFgwRHJVUHBrbWhFQVc2VmdwZWhMVGJCUS9pWC9j?=
 =?utf-8?B?TFd5QzE1M3FRQWdhTDQxQ2RQdUpyOHFzSnZiV0hMM3pSYWhRUG5PejNzTjFt?=
 =?utf-8?B?MllMVkh4S2tYSlJzalNON2w4ZFBMWEF3cVBpZUR6Vjk5aUlFS0ZIeHZSZDRW?=
 =?utf-8?B?RTBCTFcxQ1liejI0eXhueElFU3R5a0VnUWczR3pvNEZiWTdkUkhFc1ArSUxm?=
 =?utf-8?B?bWtwenhDRG10clNIRlB4cVBmZkNMVlk2aDRBMzVZWFlEKzhqQ1llV0JVUGEz?=
 =?utf-8?B?ejVkWnFURElwZ0NZV3IzZFBPSWh4aERqZVdkcTZJWjdJOGgwdVhlbkR2R0lO?=
 =?utf-8?B?SERsR0g5bTEyK3VhUjJwZm5sRURGNW92alVJeHZxMU1GVXNja3JMYmY5TFV6?=
 =?utf-8?B?eitDVXBvTHEyT09RWmMxVEduZUJHVHByanJkSGFqVXdNb05IZE96K2hackVE?=
 =?utf-8?B?cFJBVjYvaG9yYXZjWU0za3BWZWFzUUcrSVZZaWNsbm9VczV1UzJvZGZJMFIv?=
 =?utf-8?B?bXhhSm9OM1hhNDIwaHRjWkxOVDNiQ05EeVVCWlpxQW9uZUNlT1g3bEpVbmJZ?=
 =?utf-8?B?S1dIWXZ0MVBVT1hSMDh5RG9NdUNRPT0=?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: qti.qualcomm.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR02MB8247.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 479617f3-17d7-4a75-14ae-08d9ab4cfd8d
X-MS-Exchange-CrossTenant-originalarrivaltime: 19 Nov 2021 11:09:00.8156
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: hbfiGW1OqRUNxjoydSVIVMwmUkHXM9UmlHntU2K5BaiI4IoUBCU/8FBgi4wVtBaehLLJGqs++FRMLMb4TAsgEEcZR672Lx9fkGdylumEiSM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR02MB4332
X-Original-Sender: jiangenj@qti.qualcomm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@qti.qualcomm.com header.s=qccesdkim1 header.b=uK0S82+R;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass
 dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of jiangenj@qti.qualcomm.com designates
 216.71.140.77 as permitted sender) smtp.mailfrom=jiangenj@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
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

Yes, on x86_64, module address space is after kernel. But like below on arm=
64, it's different.

# grep stext /proc/kallsyms
ffffffc010010000 T _stext
# cat /proc/modules |sort -k 6 | tail -2
Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O)
# cat /proc/modules |sort -k 6 | head -2
Some_module_3 16384 1 - Live 0xffffffc009430000

-----Original Message-----
From: Dmitry Vyukov <dvyukov@google.com>=20
Sent: Friday, November 19, 2021 6:38 PM
To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <linux-kernel@vg=
er.kernel.org>; Alexander Lochmann <info@alexander-lochmann.de>; Likai Ding=
 (QUIC) <quic_likaid@quicinc.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

WARNING: This email originated from outside of Qualcomm. Please be wary of =
any links or attachments, and do not enable macros.

On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangenj@quicinc.co=
m> wrote:
>
> Hi Dmitry,
> I'm using the start, end pc from cover filter, which currently is the fas=
t way compared to the big bitmap passing from syzkaller solution, as I only=
 set the cover filter to dirs/files I care about.

I see.
But if we are unlucky and our functions of interest are at the very low and=
 high addresses, start/end will cover almost all kernel code...

> I checked=20
> https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ,
> The bitmap seems not the same as syzkaller one, which one will be used fi=
nally?

I don't know yet. We need to decide.
In syzkaller we are more flexible and can change code faster, while kernel =
interfaces are stable and need to be kept forever. So I think we need to co=
ncentrate more on the good kernel interface and then support it in syzkalle=
r.

> ``` Alexander's one
> + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; idx =3D pos=
=20
> + % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(pos <=20
> + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L <<=20
> + idx);
> ```
> Pc offset is divided by 4 and start is _stext. But for some arch, pc is l=
ess than _stext.

You mean that modules can have PC < _stext?

> ``` https://github.com/google/syzkaller/blob/master/syz-manager/covfilter=
.go#L139-L154
>         data :=3D make([]byte, 8+((size>>4)/8+1))
>         order :=3D binary.ByteOrder(binary.BigEndian)
>         if target.LittleEndian {
>                 order =3D binary.LittleEndian
>         }
>         order.PutUint32(data, start)
>         order.PutUint32(data[4:], size)
>
>         bitmap :=3D data[8:]
>         for pc :=3D range pcs {
>                 // The lowest 4-bit is dropped.
>                 pc =3D uint32(backend.NextInstructionPC(target, uint64(pc=
)))
>                 pc =3D (pc - start) >> 4
>                 bitmap[pc/8] |=3D (1 << (pc % 8))
>         }
>         return data
> ```
> Pc offset is divided by 16 and start is cover filter start pc.
>
> I think divided by 8 is more reasonable? Because there is at least one in=
struction before each __sanitizer_cov_trace_pc call.
> 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
>
> I think we still need my patch because we still need a way to keep the tr=
ace_pc call and post-filter in syzkaller doesn't solve trace_pc dropping, r=
ight?

Yes, the in-kernel filter solves the problem of trace capacity/overflows.


> But for sure I can use the bitmap from syzkaller.
>
> THX
> Joey
> -----Original Message-----
> From: Dmitry Vyukov <dvyukov@google.com>
> Sent: Thursday, November 18, 2021 10:00 PM
> To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> <info@alexander-lochmann.de>
> Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
>
> WARNING: This email originated from outside of Qualcomm. Please be wary o=
f any links or attachments, and do not enable macros.
>
> ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com> wrot=
e:
> >
> > Sometimes we only interested in the pcs within some range, while=20
> > there are cases these pcs are dropped by kernel due to `pos >=3D
> > t->kcov_size`, and by increasing the map area size doesn't help.
> >
> > To avoid disabling KCOV for these not intereseted pcs during build=20
> > time, adding this new KCOV_PC_RANGE cmd.
>
> Hi Joey,
>
> How do you use this? I am concerned that a single range of PCs is too res=
trictive. I can only see how this can work for single module (continuous in=
 memory) or a single function. But for anything else (something in the main=
 kernel, or several modules), it won't work as PCs are not continuous.
>
> Maybe we should use a compressed bitmap of interesting PCs? It allows to =
support all cases and we already have it in syz-executor, then syz-executor=
 could simply pass the bitmap to the kernel rather than post-filter.
> It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander propose=
d here:
> https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ
> It would be reasonable if kernel uses the same bitmap format for these
> 2 features.
>
>
>
> > An example usage is to use together syzkaller's cov filter.
> >
> > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > ---
> >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> >  include/uapi/linux/kcov.h        |  7 +++++++
> >  kernel/kcov.c                    | 18 ++++++++++++++++++
> >  3 files changed, 35 insertions(+)
> >
> > diff --git a/Documentation/dev-tools/kcov.rst
> > b/Documentation/dev-tools/kcov.rst
> > index d83c9ab..fbcd422 100644
> > --- a/Documentation/dev-tools/kcov.rst
> > +++ b/Documentation/dev-tools/kcov.rst
> > @@ -52,9 +52,15 @@ program using kcov:
> >      #include <fcntl.h>
> >      #include <linux/types.h>
> >
> > +    struct kcov_pc_range {
> > +      uint32 start;
> > +      uint32 end;
> > +    };
> > +
> >      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned l=
ong)
> >      #define KCOV_ENABLE                        _IO('c', 100)
> >      #define KCOV_DISABLE                       _IO('c', 101)
> > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, struct k=
cov_pc_range)
> >      #define COVER_SIZE                 (64<<10)
> >
> >      #define KCOV_TRACE_PC  0
> > @@ -64,6 +70,8 @@ program using kcov:
> >      {
> >         int fd;
> >         unsigned long *cover, n, i;
> > +        /* Change start and/or end to your interested pc range. */
> > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =3D=20
> > + (uint32)(~((uint32)0))};
> >
> >         /* A single fd descriptor allows coverage collection on a singl=
e
> >          * thread.
> > @@ -79,6 +87,8 @@ program using kcov:
> >                                      PROT_READ | PROT_WRITE, MAP_SHARED=
, fd, 0);
> >         if ((void*)cover =3D=3D MAP_FAILED)
> >                 perror("mmap"), exit(1);
> > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> >         /* Enable coverage collection on the current thread. */
> >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> >                 perror("ioctl"), exit(1); diff --git=20
> > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index=20
> > 1d0350e..353ff0a 100644
> > --- a/include/uapi/linux/kcov.h
> > +++ b/include/uapi/linux/kcov.h
> > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> >         __aligned_u64   handles[0];
> >  };
> >
> > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_range {
> > +       __u32           start;          /* start pc & 0xFFFFFFFF */
> > +       __u32           end;            /* end pc & 0xFFFFFFFF */
> > +};
> > +
> >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> >
> >  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsigned l=
ong)
> >  #define KCOV_ENABLE                    _IO('c', 100)
> >  #define KCOV_DISABLE                   _IO('c', 101)
> >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remo=
te_arg)
> > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kcov_pc_r=
ange)
> >
> >  enum {
> >         /*
> > diff --git a/kernel/kcov.c b/kernel/kcov.c index 36ca640..59550450
> > 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -36,6 +36,7 @@
> >   *  - initial state after open()
> >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> >   *  - then, mmap() call (several calls are allowed but not useful)
> > + *  - then, optional to set trace pc range
> >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> >   *     KCOV_TRACE_PC - to trace only the PCs
> >   *     or
> > @@ -69,6 +70,8 @@ struct kcov {
> >          * kcov_remote_stop(), see the comment there.
> >          */
> >         int                     sequence;
> > +       /* u32 Trace PC range from start to end. */
> > +       struct kcov_pc_range    pc_range;
> >  };
> >
> >  struct kcov_remote_area {
> > @@ -192,6 +195,7 @@ static notrace unsigned long=20
> > canonicalize_ip(unsigned long ip)  void notrace
> > __sanitizer_cov_trace_pc(void)  {
> >         struct task_struct *t;
> > +       struct kcov_pc_range pc_range;
> >         unsigned long *area;
> >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> >         unsigned long pos;
> > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
> >         t =3D current;
> >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> >                 return;
> > +       pc_range =3D t->kcov->pc_range;
> > +       if (pc_range.start < pc_range.end &&
> > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > +               return;
> >
> >         area =3D t->kcov_area;
> >         /* The first 64-bit word is the number of subsequent PCs. */=20
> > @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, uns=
igned int cmd,
> >         int mode, i;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> > +       struct kcov_pc_range *pc_range;
> >         unsigned long flags;
> >
> >         switch (cmd) {
> > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, un=
signed int cmd,
> >                 kcov->size =3D size;
> >                 kcov->mode =3D KCOV_MODE_INIT;
> >                 return 0;
> > +       case KCOV_PC_RANGE:
> > +               /* Limit trace pc range. */
> > +               pc_range =3D (struct kcov_pc_range *)arg;
> > +               if (copy_from_user(&kcov->pc_range, pc_range, sizeof(kc=
ov->pc_range)))
> > +                       return -EINVAL;
> > +               if (kcov->pc_range.start >=3D kcov->pc_range.end)
> > +                       return -EINVAL;
> > +               return 0;
> >         case KCOV_ENABLE:
> >                 /*
> >                  * Enable coverage for the current task.
> > --
> > 2.7.4
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM8PR02MB824798E699AC9F4B2510E293F89C9%40DM8PR02MB8247.namprd02.p=
rod.outlook.com.
