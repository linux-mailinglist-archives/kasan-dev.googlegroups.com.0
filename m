Return-Path: <kasan-dev+bncBDLKPY4HVQKBB56D7GMQMGQEVFPZRTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A654C5F6063
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 07:04:56 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id g20-20020a0565123b9400b004a20db020c5sf242226lfv.13
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 22:04:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665032696; cv=pass;
        d=google.com; s=arc-20160816;
        b=zUTN34yUq8kfRHLVez9epYgG4Wdks0SXHS0+jNN4AJvazD+6UdGQnQUG1B0xiL04Kg
         B77EB8h423frB9vglRcj4kYXdDVgs6EosQHzDgcbk8PvajjMSHCwEQiWTDDNtjPSPCXq
         OnT7ZobeFKt0BVOWDvbMoHqGXXIoFsQGFxbKCgxTzslIJTvRqrS9gW+xmj7kgMvmVH5v
         Fi+T34uhHlr9J0o9vwqXfvpW1+xkkq0viSo+F5RZ6ytCcOT1CP9nPZUrmjmmxpupYSiB
         6w391UOu19CqjYYjjHk1bDellMDmlSyTzuD0INq6WnT6rgu8fTAhA8VPqrgpqkhBpodU
         uQrw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:to:from:sender:dkim-signature;
        bh=xWTUqwcocPX6XLK7wpSELxIpzEB6kL8L6alp7+7LZZ0=;
        b=DHM7IOeSw+T+tm+bh+lAFKUjudBHHtkDFP5T7xFFP2XsxeSjKEHr96zrEpzyWLz428
         CvMbTYQzxls3cTZP9JXXql28kf4cufRwTcmEF5zpRuK02+vZMJ6HBg9fVIdeH37KVP9x
         pkVJYG3CGvEY6w8aGjOtKia0Kil2uSUasD+cPwzQqOE9lW97msvfshJzJu3cIzBlqc4j
         EWq12qA0w0eG5adU5TOyGSsfrdcjnXOrrO7pZBTHwjJhq5qWPSApgJ9y1vLBtx4RxXvE
         WwLhuWXCU+y7B5SO87bt2j+kwBSeDr5up7AYJpC3bH5t4Zb9YGLx6RmQDe74ndb+MfDL
         JANQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=3Pvnl+fc;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:to:from:sender
         :from:to:cc:subject:date;
        bh=xWTUqwcocPX6XLK7wpSELxIpzEB6kL8L6alp7+7LZZ0=;
        b=FdglOaleaiGn9AIi8rN8iklCoAhiDzk1H+dTAIEyu60teRIy9wURZ0mhNigMd8uD2Z
         QUSvPRSpnJepKbaMONM+UrWuNu8XyE0XBbD5qcQqHJ74LXRRDZ3ZNdwfT2Uqx2xLzH/q
         BF/KcrMAtaI0bS8uMSfaFigMDc2G1RniaMHFLVeVRuPOmG5tEK1ooBe1dZyFQNL3W1r4
         dG6FUVRO7Bqx+GW6vnmgR66oUAHjFTDEKE5mrcYIB1TgudmJJ/vyXcOLjicTKuT3/fdb
         5cxCnXLdK+gNz2dF4Z3oMNhwijF9PIQBSqWqkwucC3DAJ2rjttI50TkZoSZJDmqeB/uZ
         DbDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=xWTUqwcocPX6XLK7wpSELxIpzEB6kL8L6alp7+7LZZ0=;
        b=V9JU8o3xE407BbvOx/9Wk4OdpoWze33joGXI9+/ELyR7dnN9D4W4JZgY8+QzANCUyP
         1B6Dk0Y3Fr+gzAZCNGd3VysvyvPP83u3U+Kk/+XMdzV4DuxUGu5LiNPqCOlLRwVSdqE2
         dwgHAJFGprrwnpz9BDZJQjlSNdCrMOPu9VmOxpBRSflOor0GNz9ADXc3PVYx06tDDfk7
         3GAZvG/h+/nqAoTwjN1mr3hIhGaTv9/RcOE/E+CknCTf5rxMACwltqGYrN3gT95KVJic
         srI7Zn9GnVTFHW6/gK+IagUVRM+WXZvxfOiEddRJSWzszL+QpL82PkGgQDgrIgVkgeC5
         sbsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Al8Kt4ZDKpXXQNl8NwnoVgREvbUTk67h4lm5m3+kOZMKECLzH
	yW162HQgPM6A9vBavMQnuNQ=
X-Google-Smtp-Source: AMsMyM5eOCS3a3flIptI0wpruw8hIdme5xTtDMztAzzwfpjaNVNMS+ENEUendGH+rh1ij7xQvmXJ7g==
X-Received: by 2002:ac2:5609:0:b0:4a2:734d:6cb0 with SMTP id v9-20020ac25609000000b004a2734d6cb0mr469098lfd.611.1665032695920;
        Wed, 05 Oct 2022 22:04:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91d5:0:b0:261:d944:1ee6 with SMTP id u21-20020a2e91d5000000b00261d9441ee6ls153039ljg.0.-pod-prod-gmail;
 Wed, 05 Oct 2022 22:04:54 -0700 (PDT)
X-Received: by 2002:a2e:9f09:0:b0:26d:e740:ecd with SMTP id u9-20020a2e9f09000000b0026de7400ecdmr1058175ljk.324.1665032694648;
        Wed, 05 Oct 2022 22:04:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665032694; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xpdc9EWkp98w3yPaZLHhggHlltvp/62++WYoo50cAJ/lIITO+O3pWYEFiahUjq2fji
         4xmxu4SIFi1DH4+Dp3qVq0eLoN6uXQyddpnnxcmNJQHPce4p83x+u/Kec4J4J1bqgIzH
         nFwp6Uo48Dm0pHz38Lkm+UWiwUAMsfGC7drsJ2WAyuBUfIWkzxDf4FP72SmN134HwVe3
         n78bqY/0EdCSJvyzgDOoGgydwKai7dOR7aK3NiV/cyIpMR7sSLUQtFAzAQMgS1D0vLJJ
         Dgmtj8BasyjVAuLLLjROhc87c22ySElis5psuH7YtjIGYEy0PSIOymrr25nekhM0ewcL
         ZfNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:to:from:dkim-signature;
        bh=Hvbm9xjuNQoUJTs7XTOQE8rt2DtGJNppwrxUEVs8KHY=;
        b=BuwhkMvAEfw2lvX9BAOsUZIuULvtCDo0c3H0JaUeHqcakVhx8n8YI/aaa1sG4E5RAq
         apDjN0un7hnpBDtnAY5I/ATEaG+sLOXYh71mOxFuAniqTpZjIliHR1qA5l+ulArW5kPS
         yqnwFNGSb5/8uLwUaCtC1oBKMtfTf4mumEpEA+KnDI6yMyQ1iZOTe43kSj4bVgl4IzEa
         0tfsEZz7vGgB4bj9uBqgPIj+Cc6JUbiRBq+by73sn//OverdlLGBnHICnF9okqvq4Vx4
         uORx6qTCrv96AuWkbmmNVCrZXWwyLHGiWVwbLnSLTJ/d1YYQop2C3r7cpLCcuoju7Lra
         ZUTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=3Pvnl+fc;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90052.outbound.protection.outlook.com. [40.107.9.52])
        by gmr-mx.google.com with ESMTPS id i12-20020a056512340c00b00497f1948428si674630lfr.8.2022.10.05.22.04.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Oct 2022 22:04:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) client-ip=40.107.9.52;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=DyQ02pcX3nDfPdKRHjrYU5yGT7Xhy9hU4Cqavrw3gZ7YwxmrsoAuRTd+kD0kKD+ugi3Lc49ea7AZ+twAgGwzP5qsOCjmBFa1O3mVPV43bnj49LdK3fwXa2jHUIDhlI7xNc72ciNHpxpcBdD6WUA6exMzkWRwzLKwrKKf7DX3TL3+meDH8ViKi6hY3xrbfAv4nEODO23g2Jpr4Vb6dtUVX0SH5y1fs1PcrPVTmiZ44Wgp45VQ/rJzkt/F14dmz1faOXt51zhZ/b7ft3mN0MQGwbeH8eCkSjuN4nVbdVuTxKw7cHZdw1qHLLhorwPjNnltG89NJGyvIvRlANX0xLQE4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Hvbm9xjuNQoUJTs7XTOQE8rt2DtGJNppwrxUEVs8KHY=;
 b=i57omGY84Fk1RHrBfdQlnIBLxLUphbxEHJUQ/wMSBuM3RfUkVMGZ/+oB/HpYYmkMyst1ToBGXiGJIIfL32SBFV/5bsOdy7Bay9q3Wk8uRkjkimTduUx+sTG4wFh2CUMUXgt4043HFLeHO0udYCcF8pyBvXdxBp22VeVUbjkHZAEIe2e5IepFBkePvw7gEGUiz8RH1n2UCjQdF2LRWlwwMchiS3CxpdpFLZJSkX0Sldz0FuX/HWn/ANtMgYJdzvDWtvlmJArGEegClwem7JsymAyXxRpJlMV3aF3ow+biVBaEAUO0jsedHpekYxltFi/VcpxuQQ8nWX7rNZgNwgftBg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB1937.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:2::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5676.34; Thu, 6 Oct
 2022 05:04:52 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%5]) with mapi id 15.20.5676.036; Thu, 6 Oct 2022
 05:04:52 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Michael Ellerman <mpe@ellerman.id.au>, Nathan Lynch
	<nathanl@linux.ibm.com>, "linuxppc-dev@lists.ozlabs.org"
	<linuxppc-dev@lists.ozlabs.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Thread-Topic: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Thread-Index: AQHY2EIBh+iraNEA6UKZa+r/wPzLXq4AwrWAgAAPGgA=
Date: Thu, 6 Oct 2022 05:04:52 +0000
Message-ID: <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
In-Reply-To: <874jwhpp6g.fsf@mpe.ellerman.id.au>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB1937:EE_
x-ms-office365-filtering-correlation-id: d462bb16-06f4-4332-1140-08daa7584d6c
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: ChsFjvafE6B55OGqar0FvIH9vgthmQJNTEi6X9tmHRwpcooILQGj6jiiJnHUCKwGL+L272/N9+a5vh+o752Sc5qqS8YWQF3xNJVvPu2nkyt2zSNB7gIYK16e4X9FbFwwj90hBMH46G6r6/TaKBY7mjPk3YkiJCRY+ltKih1PiVr7IdixObwJHE/0N/95/U9cEi5SD7c3uVkR4yd216sQbORMz/jB6QffeNAaPg6JcACWsNgzrFnEeD8n3b39j9CAYObsLQ4bByWc9T3k3WG1qDjZTIZqIsJI2BNPCrGS11KhGS5DUeAi7wl9SEPB0MHzsUUaLRG4BpBTJM+CKLkNRXan8s75z4MVgBJEbUKe6Q6J/LSeM3DY/HeoXYwlN2RpGUV1NstEQYSB6dg/yScTtSbFUAGYjvPLh6FMeN2/E9T/BEW4AelOevURC0lMGIkLB++GoL8ydzBkxd7FkRV4i00mAisP/GlJAiALlR0I9Fu3GZ+CkYoo5kCQuVJFecxXq83ZVw/IYIfn4QTxmm0Hj1QpHGPwiVzoKqeSfZaNN4tbgmkcaBju3wOw80l8bHmxbBnTqJMAnS2QDLcRTypj8v5TZrnIgNzidEcSZ31xtoT+436Za8Zlso7u0qXCYZ1dETPv7cyxPirnFMRYPAjNPb3/duc7X+csssvHrSYJq3x9L86uFI9bqb2XLxnL8U6lZrshLgbqraGL/xWubSlkV/lc/SXU9BKhb0+tVofpn5gLIHk7CTN7v5L4j45hVAGUz+vS8LJfQ8Q9f+Ib7Ny02ZEJFY48aNtaafBCeSs39+CFKF57fFVZeGLc4oPN4wm6d8Qvf7+ZMgMmEEvFd0Tn/w==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(396003)(366004)(39860400002)(376002)(136003)(346002)(451199015)(31696002)(86362001)(38070700005)(122000001)(66946007)(8676002)(76116006)(91956017)(38100700002)(66556008)(66446008)(64756008)(66476007)(316002)(110136005)(44832011)(2906002)(41300700001)(5660300002)(8936002)(186003)(83380400001)(2616005)(66574015)(71200400001)(478600001)(6486002)(6512007)(6506007)(31686004)(26005)(36756003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?bk1KWWM3c2orNnN3MXdlUmF0cENkWkhNa2l2Z1QzU3lEazZhQSsxSWJ1cVMw?=
 =?utf-8?B?UHorUzFTUDZyN3BtVkNmUFV5REhBUVZpL2VWdkFZclBTUlZmYm52OXE2WERC?=
 =?utf-8?B?QytoTVZhdGtXQjZKV016VkZGNHJrUGpHRnNlWVQyaDVlS3BCamNUN3NBanJo?=
 =?utf-8?B?SEtpcEZVVVo5Q3hFU0lyNzdybnl0R1pRTDFVcVRRc0dDMnFuRWFnRHZhaFh5?=
 =?utf-8?B?VzFEZklyaTVJQzNCcFFmVTlYUXNSNlJaNk5xQ2NBYnkwc3NvOTdNV3FvaTRT?=
 =?utf-8?B?cFdSTDlkeEZYcUxVNlJUbUxkL21IbGY4L3RFb2xPZmF3VjRNdTljbUdkZkhR?=
 =?utf-8?B?U3Q5WFN4c3dzYUxoRlFTbzFpejJYd25zd2dOTldvVmh5ay9TdXhjOElQYitI?=
 =?utf-8?B?YWFuYmZGNm13Y0VwVlVqOTJlY2x5RlU1MGIwUGtBMDEyVWpzV2poOG9GNWJj?=
 =?utf-8?B?ajlIWU5TcmFJS01DTGp2citOV2xSdkdRSTg1d2I0SS8xY0xUYXN0bHRLQkc4?=
 =?utf-8?B?Z21nbHFRYWQ1YVU4dDJqa0pwcmhXdStET3Y3VU1qT1loTWtCOGFObHZIOURa?=
 =?utf-8?B?TUNiaEtNNXU1Nld6ZUo5VXpYV3kvV0VGem5jVmhYc0JDRG9SNHN1RWNMM3VK?=
 =?utf-8?B?V0tsc2pTYUlYaktZOE9XbWZSK3ZJTDhVUWQ1bE80SlU0dUZNWkUvUWpBb3Mv?=
 =?utf-8?B?bWJWeTNtSkNRL3h1dXhzcVdrSjVCWEdJcWdMUHB2YWJacXNjWkpRaklpRGpv?=
 =?utf-8?B?SzlwQjBvTGdCd2pYUkdkOEF5ckxEMGV0QmtkdXJlUkZWMTZIL3RoTEZBalJP?=
 =?utf-8?B?eEM3aE1hd1RxVnpxMUNMMXA0N21SanNlSFFuRWhqUVJHcGR1SEp6Z1dKelFE?=
 =?utf-8?B?aXB1d3BwQXV5cnBRNlBwV1hHNkYvK09PRUJBNjM5cVZNcmRpdXpvUjhVa0VF?=
 =?utf-8?B?UnUwdzlxeDlnNkRnTVczRDR6bk92eDV5cENteHhJQzVZV2twTWxJSE1OUXQ0?=
 =?utf-8?B?c1Vzc1pEb3IydHdTZS9IdzdqQ3QydFhzZkpZWXEwS1dvYjFyaS9CdXUzVjN0?=
 =?utf-8?B?ZTM2Ri9KWkhPQWsvWmt2N3pqTC8wck5acGc0YmdCRC9Xem52Y2NnbWIyWlVO?=
 =?utf-8?B?SSs3eVlTanhtTHF5elU0cXJWWTFVcXBDbGVVdS9telEwQWM1M1I1QUZhK3Jk?=
 =?utf-8?B?SU5oODIybHA2eE1vNXhvRjlQd2dXZjZwOWRkTTFtUktoaW1MclF0MjA5TlZB?=
 =?utf-8?B?ZzFyRWpucndqc1RFdEVrQ2dRb2dmalJmRkNiUEpHbGNXZGRIckhBdnhRSDBh?=
 =?utf-8?B?cUVHTzRxVU93dTdIZ0ZTL29Tb0dhbHZGWm9YLzczYnZKVjZ0Qm5VdHBPaFpP?=
 =?utf-8?B?eS9PVC9LWE9mVnEzRjB6QnFaOGdHWUdBeGZVbW9CQnBJQ3hlVUNtU1c1SnlC?=
 =?utf-8?B?UVJkYWYyTSt2RDVTWFVVeHcyUW1tMk5ENndKUUpzYTRQTWJWTTFBRVdPbS9H?=
 =?utf-8?B?dFllaDZ5UHV6MXFxYytabjREVUJOcERidVNucDVneU1objFxM3pkempjcVRx?=
 =?utf-8?B?QUtRam5ScXNPTUFnNHhQRTN3dkFXMTNVc2dhQTJJMEw1NUV1b1RYMnc3N3VP?=
 =?utf-8?B?YkdZYXg5eEUvMk56bDMyRE9ySTlyd2pzMEJ4eDhtZEhtbFNFcXI5REQvcHR4?=
 =?utf-8?B?eU1yR0dtVitsdE1TeFNRZGRsZ3pZRDdSZUJYckJJMmdZUVZNR1lKaUxUL2gz?=
 =?utf-8?B?T2d0b1IzWXJqeXZQUmNxdjdsN3lpVkVTQ015d2Q0c3ZvaVUxU0FLNXh0UGxD?=
 =?utf-8?B?cXZ4d0c5dHJpaE5CZ0g0SWkzeS9jaDhGTmVqeGhkUVNCMDhkcHJuOXc2WUtt?=
 =?utf-8?B?K0xNVzE2ZUg2RXNoSG9yd3VaelRmZDhYYTZMUEc1RHphR0dWK3NhY24zT1hj?=
 =?utf-8?B?T0hnTDNJcWdndjQ3c0dJNEhpQ3gvdnBmN1FTdFUwWk9JM0hPZm5RTTdpakJV?=
 =?utf-8?B?U1RUTEVxNHZUSnBOb1I1Y3NiNGgySFVJcWQvWnRzR1YvNmN3a0c4UHZBSHN5?=
 =?utf-8?B?UkJOUXREakMzay9YbjNiM05rQzdWRzhlK0hvWkFjNUJjV1A5MzFGcFZrMHpP?=
 =?utf-8?B?a0Y2K3J1WEUrd2dyaEh4R0FzSzhpeDRCQlFSREFrS0NmdjBMSTFvVEl5R3E4?=
 =?utf-8?Q?P0Ptnv+pvfMmK3HamhQGXAU=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <224C9307AE1F21498A72301446E21372@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: d462bb16-06f4-4332-1140-08daa7584d6c
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Oct 2022 05:04:52.4078
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: e6HbwViBTY1FHg1i/5FU4LYmZZZ0TJZK8UFtjj72Use9IUHmHSuR4t1AJ/tRKlQ/md7l3XpTC5YUP83YtL9IXhWDO0Sz8nStgvmw23lwfOQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB1937
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=3Pvnl+fc;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

+ KASAN list

Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
> Nathan Lynch <nathanl@linux.ibm.com> writes:
>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>> KASAN support"):
>>
>>    A kernel with CONFIG_KASAN=3Dy will crash during boot on a machine
>>    using HPT translation because not all the entry points to the
>>    generic KASAN code are protected with a call to kasan_arch_is_ready()=
.
>=20
> I guess I thought there was some plan to fix that.

I was thinking the same.

Do we have a list of the said entry points to the generic code that are=20
lacking a call to kasan_arch_is_ready() ?

Typically, the BUG dump below shows that kasan_byte_accessible() is=20
lacking the check. It should be straight forward to add=20
kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it ?

>=20
> But maybe I'm misremembering. Looking now it's not entirely straight
> forward with the way the headers are structured. So I guess I'm wrong
> about that.
>=20
>> Such crashes look like this:
>>
>>    BUG: Unable to handle kernel data access at 0xc00e00000308b100
>>    Faulting instruction address: 0xc0000000006d0fcc
>>    Oops: Kernel access of bad area, sig: 11 [#1]
>>    LE PAGE_SIZE=3D64K MMU=3DHash SMP NR_CPUS=3D2048 NUMA pSeries
>>    CPU: 0 PID: 1 Comm: swapper/0 Not tainted 6.0.0-rc5-02183-g3ab165dea2=
a2 #13
>>    [...regs...]
>>    NIP [c0000000006d0fcc] kasan_byte_accessible+0xc/0x20
>>    LR [c0000000006cd9cc] __kasan_check_byte+0x2c/0xa0
>>    Call Trace:
...
>>
>> Change init_book3s_64.c::kasan_init() to emit a warning backtrace and
>> taint the kernel when not running on radix. When the kernel likely
>> oopses later, the 'W' taint flag in the report should help minimize
>> developer time spent trying to understand what's gone wrong.
>=20
> Should we just panic() directly?

But then you loose any sight that the problem is in=20
kasan_byte_accessible() and have to be fixed there.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38%40csgroup.eu.
