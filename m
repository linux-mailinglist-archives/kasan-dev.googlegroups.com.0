Return-Path: <kasan-dev+bncBCX7RK77SEDBBT7U6OAQMGQEA34NDDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AAA33280CD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Mar 2021 15:29:36 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id w34sf9620600pjj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Mar 2021 06:29:36 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614608975; cv=pass;
        d=google.com; s=arc-20160816;
        b=rABRSUUnuHby362H5sRzx3Fz2y8tp2FgA7t9yws08pAmMpBAq69Cufb1hhhb92yR8u
         MOts4nitj6smfbtK2FyfbVc3fJHpmhjD1Dr3/UHEhm5t4ofF6dg9B8XMrmnh2/+jE42h
         rbs8zq8yRPeMv+e5YGnyHFLIczmXlR9YpktW8RN5KUyDBjnZDRjNyO+OQdMDlnEifqAu
         tMW2nI/Q+lcp7RnMITvowE8QMLxUOSZ5TIngsVAeWW6EuTwEUQsG8fye0Kwr8VUqDTEJ
         gX+lfl8NYg1jspRpNLBG0tvmWBCgKoH2G9VcpJP7Qz/2x7TI+8pD8k9Da4sbH79gO8hG
         d+qQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=Hm9m85ZROyCg9XdexcIEDAR8RfoyL2dFa9IKwUSsr9w=;
        b=eNz6W0H50AxYfLffS/TGnDhMLhG0Fcsls+3Yltn8TeYvDYbph7DrvuvCoach7KUbQv
         xco0151SNEbggOrPn8u/5FRwbz1Erf9JcN14ElkKOwvGLhZeIQ8tmucXbpsszOdQP4FQ
         j2dJxpGJkGmGhag5DBv6lIhc9isN3mIKTVTAzGSJ99aWjHOfbmK2AMYcZE0/r9nGKfTN
         IBjLrQH9mOvSdec3uWClgoL4S8UHr4F2msx9p4Z4FSfFy6/MzXHss6TR4WZavdC9wiBL
         suWRfd2tcdghYphmNYiaTXHr20eLu6ACaGSwS+Og0FZoB58jKDwdYdXVTzQd/0Mp7Vl4
         2JHQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="uUFZW/W6";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HTkCRjd1;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hm9m85ZROyCg9XdexcIEDAR8RfoyL2dFa9IKwUSsr9w=;
        b=bzqSr6T7+4WPtxOtqOLi/ksXbpuY/hIQKJz8IS6TKmKLkHzMtjJW1p98+9XtUzqa4G
         yEvZU94p4HyE9oOnHNwGCmDKXjrrUPgH7wmXywTPWO2XhOldyMaKAss3DAwxUTYxGmhW
         KqT020RnddunpoPHh7tm/H0CNbsAdtZ6gqx/t7jmGRZts8A5oEiK1SlTi7TxTJGRZW9c
         x59x85oAzUVIVIkHskq+/T0M6jWq9T1ZvnYUh+jAStNObhM0jNmgwQj3g8W1aTncae1U
         H+9IkixsCvUHr45e0P68rPhffMwmJeqyWsCws9oDsAs9rZzEzza+KMU/kxHWh6d3gf28
         wMog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Hm9m85ZROyCg9XdexcIEDAR8RfoyL2dFa9IKwUSsr9w=;
        b=aMHr7vSA6ycpPfREiCO5HC2jcANWsXgy/o9PEBw3juHBEockLoX70s9e7bvjiPUwXg
         lv8pJoR1LeKoMsiiIJI1nTaWYGlH6SVSB/TPSl+w8wxBFLHbIxwek0t+H000ZvIFIjKz
         53Q/rESkbp98Y69R7FvsIfFrMWuWK5R/hoM/WD1KfTV2KjiD1nDbraISpf/J6H6d20e0
         nanfBrs11JgXep+yUN1vIJNOJ+1mRM8DPIYzCbfMHaWnLHI3M7SDqpCjTZv/u4frJq82
         kAXVOBbD+qes7yMiZ76lM+M/LrAnBO3F6qfBGpi12Tp/EH50kmWmxxrhbKy9QENKIbHr
         e6Wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533b2uuLX6mOcmF8jPlc1fdLrpGXM83nja4aJWyjLx9pgvI/KKmF
	lrpkGcsMpjvQTWD+2381pEE=
X-Google-Smtp-Source: ABdhPJzz9aYgrBwn+kiGOYmaSPCAtoziAMuPo9yI0zd9pJIoTb5PoyX7UUc4ooj/lm2PNS1FR0fYOw==
X-Received: by 2002:a17:902:7897:b029:e2:c149:cbe6 with SMTP id q23-20020a1709027897b02900e2c149cbe6mr15322528pll.68.1614608975070;
        Mon, 01 Mar 2021 06:29:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb43:: with SMTP id i3ls2063835pli.7.gmail; Mon, 01
 Mar 2021 06:29:34 -0800 (PST)
X-Received: by 2002:a17:902:9694:b029:e3:3855:303b with SMTP id n20-20020a1709029694b02900e33855303bmr16004829plp.46.1614608974587;
        Mon, 01 Mar 2021 06:29:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614608974; cv=pass;
        d=google.com; s=arc-20160816;
        b=ualW1Ak7V3vWBJLwSfX4LIjXxCfGTbr4UadnQDuVqYsXiuCTfGaN19spQxK/+lfED1
         B59+XavzAFRMdsDFu9Krwmbdkf27F3fSOPIcjGCnojz2AkpTpUeSo0eOHPNvS4cnwd/+
         0mnz487jvcIea4K14ou/u9Umbz70XlF6SVDvIDE7VfrAqWzmawqOYxcueCktb6EEOfir
         ITs/DFisHUsFGzZJ2OPN9/8oyAiub+t2BjCvYQJtXMdLh84xO3zyvklNy/1nif1YyMQQ
         cUH6Xo00LQNkWGcRgiK34Gud9mvzT4OLoVfox3oSLRtHyKUQzXzXPB3k6RXUDB5aCwVh
         SeCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=EDaZMCLt1qQG/K111ETL0PPT/qpJAJSMvHnsV3zyse4=;
        b=ko1Egy75klaNrmr1IUbseq7eQ4foIl/Nv6yPk3g0KbExd427OSepRZG24FOcFAHTNk
         D8WRWNZYcQn4hCD+6bKTVbVTEK1pFdxy3hcyTaB07DxMomnZGchih35RMpvvHn2yXxhd
         ugyfm4b5HKEOPEbCuasYBnMpIEsSucKdmZ4eNVR39F1+h0SZJElZ3Q6r7VgS7W2P4Nkz
         FlWHZK25fZmFkriXp1hhZXJ4LqoBu9EzLVYioSrkLFcjlPkrCdNTMZyMEwDbn6hw3pk6
         a+gzjMRRTFc+U+pIqov8xtyaupAou5BHKcEBvtLEc72twJGbMhwY2QDKHWi61DoFnRcR
         2p+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="uUFZW/W6";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HTkCRjd1;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id w2si784065pjc.1.2021.03.01.06.29.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Mar 2021 06:29:34 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 121ETFEM129394;
	Mon, 1 Mar 2021 14:29:15 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by userp2120.oracle.com with ESMTP id 36yeqmv073-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 01 Mar 2021 14:29:14 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 121EOrGo118017;
	Mon, 1 Mar 2021 14:29:14 GMT
Received: from nam10-dm6-obe.outbound.protection.outlook.com (mail-dm6nam10lp2100.outbound.protection.outlook.com [104.47.58.100])
	by userp3030.oracle.com with ESMTP id 37000vkft4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 01 Mar 2021 14:29:14 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=n4cibdcCYEO3qmCS/pO56x9mifvRZ4ljtLtThezoyeVnv0BGWPlll+r1voOP8pUYE0LmfnPWB3F0ggAkRHBlIx5boXkznpjbdMgJeZrDpumAV5ILZLOk3VPE9mLRFXLiMakkmDGTEku7wt/RWaub1kmKmG9Svp69N/OV0QmiezY+QPpqYjzol0A2DOvJst/mcSAqbLB348TW/RcbMyuiHbMON7ZdUc/gduexjWAUSVnVCNq2LjDevNJSvFKq+T+OmlvCjebJEeJnJ3H8C1T82Y9NPCZOjaKDdjcPxNtVpdFgIHdxpcmDh+bQje1PMGZQhKrISgIOFqyvL4ib0OeAKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=EDaZMCLt1qQG/K111ETL0PPT/qpJAJSMvHnsV3zyse4=;
 b=BdYs++D4yB69txwxsFGf41QJKcRbEg8trBMtDTwH8V2xEVY3kawfycjgw/khhgsFU19d4W9KxfCny4209wwyTwGLnn19IIQLjO7sl6x9GKNs9nOeL7yEWbzy00IZQz0GVUGCGT0admm8JxPzI1ggS03gJjadCH84bW0Xkt+7gUE1Ny/njj8nUwZxviDaEllewplgvNNpkOePC63o2lt+0TMTaNarG8gCCDvSxJUkzTffeTiwAGWB1/03F88Ennpsx2/6JbAO5WTtK7zpcBx6sF10o3FkXi7o/ZUiI3IyMLnqD0cSBHesSadX8b/me0Do5HST5jtWkuOQRdQr10UzNQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from MN2PR10MB3856.namprd10.prod.outlook.com (2603:10b6:208:1b7::12)
 by BL0PR10MB2964.namprd10.prod.outlook.com (2603:10b6:208:79::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.26; Mon, 1 Mar
 2021 14:29:11 +0000
Received: from MN2PR10MB3856.namprd10.prod.outlook.com
 ([fe80::4871:6b79:c2d8:d7bd]) by MN2PR10MB3856.namprd10.prod.outlook.com
 ([fe80::4871:6b79:c2d8:d7bd%7]) with mapi id 15.20.3890.029; Mon, 1 Mar 2021
 14:29:11 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
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
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <083c2bfd-12dd-f3c3-5004-fb1e3fb6493c@oracle.com>
Date: Mon, 1 Mar 2021 09:29:03 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <YDvcH7IY8hV4u2Zh@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.26.147.230]
X-ClientProxiedBy: BYAPR11CA0087.namprd11.prod.outlook.com
 (2603:10b6:a03:f4::28) To MN2PR10MB3856.namprd10.prod.outlook.com
 (2603:10b6:208:1b7::12)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.222] (108.26.147.230) by BYAPR11CA0087.namprd11.prod.outlook.com (2603:10b6:a03:f4::28) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19 via Frontend Transport; Mon, 1 Mar 2021 14:29:07 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: c3379632-949a-4e80-1a1a-08d8dcbe61ba
X-MS-TrafficTypeDiagnostic: BL0PR10MB2964:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <BL0PR10MB296428D43066C7AAE5A5EA73E69A9@BL0PR10MB2964.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:9508;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: EduLRtTbNy5XJEsFrhEej6zS6X9Q5C97VxB55VeyqTxmeGIGmJgJqTfFzj+UuIP9saRnCWq+Z5lRYEXD4YSWKYZLt6zgoV/70kDUU9O0sQaKXJNQs8o+hVwRuSk8Z6U37F2QyGwR26cZ1s+rWJIHdjJkf2v0ubbYu3mZTLgbSnJKG/xW+wRFLYdpX65aMOSyVB4CumPKcZZrzsqdiTCKuDCTHCaiT2pYCkaWuNPyct39NCmaF1yi1sGG4HRJNjU085L1M3E8d3+Gejddtap3InVxR7meeYYXSuidYHqG/PVtpdMbYvHgYY0Z87R0RrPSf5uOixU89oQIDcPhdbfT+2FBDHGzio/ay+qlt4xwppmmHCtnEyUIwnZaldcCHu5N/zawM54yAACmlSPLGT3QVoeN13ua13iz3nDqxLfQj9xVq8rm700rzNhDvlQCRIUpv1/zg9ZOJrO9Wcl6GoffcDHxDq78skL/BHfz8LfwNBSOlCxVnYJmgCfe1f5sbZNyM4B3nFqeamz/RhyAZQF6UITIFBhj0fMgKyAHyYrOZabkBOucuEKHuMIPxcsXrkDMC0ccHtZh9b+ZnLzXnMlXHYFgJwcN1+StL33VyaYWyyE=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR10MB3856.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(39860400002)(396003)(366004)(136003)(346002)(376002)(16526019)(26005)(2616005)(956004)(186003)(44832011)(86362001)(31686004)(6916009)(31696002)(4326008)(7416002)(36756003)(478600001)(54906003)(8676002)(6666004)(16576012)(5660300002)(8936002)(83380400001)(6486002)(66476007)(66556008)(66946007)(316002)(2906002)(36916002)(53546011)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?Y3QrTWsrcDVxV1prYkJtZlp3VU44My9EU1pYTmo0VHRxTnZ4ZGZPcjBzMjFy?=
 =?utf-8?B?QkU0YytmLzhiTHNCMkpTemFtWVdLRlRORE1ZNS94ZEIzMkJEZ3hKdW1pM0Vq?=
 =?utf-8?B?aVhIT2VDWk5OV285TEJxbytvcnZudVlLR28yNjFXa1N4VEhyR09tTy8wWjVN?=
 =?utf-8?B?WjlTOE1DcHRRQ2VldGpNU2RzT3dVbGlldDVCZDQveDhEY3RUS3pHb0tGSnJN?=
 =?utf-8?B?NmtVZlo5bEpraEk0N0hndG5MSkV5a08wTzdLNjV4eEFiOHBxclBBSG1idHRu?=
 =?utf-8?B?Wnp2TitsQkptWDZmUENoclBBSVhtdFBpb3AzaitMREJnYnB2OWszL2RxSXZz?=
 =?utf-8?B?Q1llcmVLa2V6SkpHUjluQ0k3ZFNuV0YrOVRVamV1S1RHS2pNU0VNSzZWUWJ6?=
 =?utf-8?B?WDI0QXh1NjVLL1RuTXdtM0p6aHI3bUxNSjQ3d3pqcEx5WUtWTjZMUzZodDVP?=
 =?utf-8?B?b2R5a2hPaFJzcXpjeEFvVnZhV1k1cHBZYnFVbVhDdkNLeDg1dFk0azN4aUZ3?=
 =?utf-8?B?YzVIWk14cU1kRzNYMEF3Q2ZUajA0ZFZMQldOWFJZbHVXb3VXSGRSbjRXZE9n?=
 =?utf-8?B?dnI3dTljNmNqeXRDU0dPZ1hzWGhNVTJBYzM4SmZUOUhvN2tGTzJMck83bklO?=
 =?utf-8?B?V2hOUUNZUEFkUWFRMkpSdnprZkFzQ1RGOEJoVHhheG9SRk12a0pSSTBwbitQ?=
 =?utf-8?B?VndzZTlvc1htbnVNSTF6T3pONEVQdnk5bUtzN1Q3NVQ3anNrZ3BIT3k2Ymxr?=
 =?utf-8?B?WVZ6YWNpUVIxT24xS2dkVUQ0eUg1QUtpRGJMRkdzNm1sUmdQT1F5d3Jmb3dX?=
 =?utf-8?B?TmovNXRreTJJUG1VT21ydDdYWERRK3RUaTc5cnl6WkttQ0lUOW5oS0FhWHIx?=
 =?utf-8?B?Qk1FZHBRaDE3RFhRZzZPN09XK3VOVUd2MjJTUnNzbGowQ3ZQdVJwTTY4SGNo?=
 =?utf-8?B?eFRRQVhvS09ES21wWEM3NU4vaXovdUYxWTdTU0hzTmV4UHNDQXdxNVZLZmto?=
 =?utf-8?B?QTZRQVJ3Y1B5cDVnRkU1RTdlZHh3TDRJeHk4dWF6ZnFmeTJISWZ0b0pWWWtK?=
 =?utf-8?B?cWtHeGVyblhVMnBlUXRRSnlxUm9wM2kzdE9WNm51bmY3WDZuTHU4R1o3aHlG?=
 =?utf-8?B?SnlDRDRaUVMwU2l4WnpBUzIyaHpjUVFoT1VNeGtyWTVaRDVTdzAyWktVYW1W?=
 =?utf-8?B?N3VIRG8yK1N0UitBYkdqMktteXZHUmJTRlowcElLVGdjZ3JDcWJZZ2FGZFRP?=
 =?utf-8?B?ZVBVTkJKRUdPQ0VHRVc2ZVF6b2FWSWRxRDBad1d2S3ZnZzk1eG0xcHI0S1RY?=
 =?utf-8?B?RGxTSkQ2YmNYdm1pVHlXd0FHLzlHTy85UlV1Vy9KeFhSWlNacXc4MFY3R05H?=
 =?utf-8?B?WHBSQjdGdGR1amhjOVdpQnA4RUdrc0lTSDE2QXVWTkNtZWZlRFh5VWlTMDFV?=
 =?utf-8?B?UjZLaE1GR29EQjdoUVFHRDNpNHlGOHF3QzNDY0Y3ZFpDb0NweFJNWmZrbkl5?=
 =?utf-8?B?R0NuM0xlV095YURrWjQrVkFnTnovUzUzUVhYWHdWMUlPN25ucXZ0RkwvSjdo?=
 =?utf-8?B?KzVubm9WZmsvMXJyOXUwajR6OU5KRUd3eFhpTUxzSFF5VWVvTCt3cmczWko3?=
 =?utf-8?B?NWRVb2V4V1diVTYzZmczTS9paEJwY1BGdU43Z20rSjF1Q2NUOXluT2pFMExh?=
 =?utf-8?B?L0pPUDUyQS9KQitxUDkvU25ia3RCcHBYVk53V0w5azdRdXNtN2RXenZiWVB1?=
 =?utf-8?Q?gKPomAsh4eDnsKsvvyXMCJlqzUc/IiINrDTIE2Z?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c3379632-949a-4e80-1a1a-08d8dcbe61ba
X-MS-Exchange-CrossTenant-AuthSource: MN2PR10MB3856.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Mar 2021 14:29:11.7976
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: iRwRSG7YEH1/cZzsaTmqOGojDwvQ+2bUhSjwa3FwEcmgCboviQi7FFPZn8Bf1bBMBlXMQRUHbE8B6qmbe/Sb1l1r1Y/+noLQdQSiqZpXMBY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL0PR10MB2964
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9909 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 mlxscore=0 phishscore=0
 malwarescore=0 spamscore=0 mlxlogscore=999 suspectscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2103010122
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9909 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 clxscore=1011
 priorityscore=1501 mlxlogscore=999 suspectscore=0 malwarescore=0
 impostorscore=0 bulkscore=0 adultscore=0 mlxscore=0 phishscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2103010122
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b="uUFZW/W6";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=HTkCRjd1;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
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



On 2/28/2021 1:08 PM, Mike Rapoport wrote:
> On Fri, Feb 26, 2021 at 11:16:06AM -0500, George Kennedy wrote:
>> On 2/26/2021 6:17 AM, Mike Rapoport wrote:
>>> Hi George,
>>>
>>> On Thu, Feb 25, 2021 at 08:19:18PM -0500, George Kennedy wrote:
>>>> Not sure if it's the right thing to do, but added
>>>> "acpi_tb_find_table_address()" to return the physical address of a tab=
le to
>>>> use with memblock_reserve().
>>>>
>>>> virt_to_phys(table) does not seem to return the physical address for t=
he
>>>> iBFT table (it would be nice if struct acpi_table_header also had a
>>>> "address" element for the physical address of the table).
>>> virt_to_phys() does not work that early because then it is mapped with
>>> early_memremap()  which uses different virtual to physical scheme.
>>>
>>> I'd say that acpi_tb_find_table_address() makes sense if we'd like to
>>> reserve ACPI tables outside of drivers/acpi.
>>>
>>> But probably we should simply reserve all the tables during
>>> acpi_table_init() so that any table that firmware put in the normal mem=
ory
>>> will be surely reserved.
>>>> Ran 10 successful boots with the above without failure.
>>> That's good news indeed :)
>> Wondering if we could do something like this instead (trying to keep cha=
nges
>> minimal). Just do the memblock_reserve() for all the standard tables.
> I think something like this should work, but I'm not an ACPI expert to sa=
y
> if this the best way to reserve the tables.
Adding ACPI maintainers to the CC list.
>  =20
>> diff --git a/drivers/acpi/acpica/tbinstal.c b/drivers/acpi/acpica/tbinst=
al.c
>> index 0bb15ad..830f82c 100644
>> --- a/drivers/acpi/acpica/tbinstal.c
>> +++ b/drivers/acpi/acpica/tbinstal.c
>> @@ -7,6 +7,7 @@
>>  =C2=A0 *
>> ************************************************************************=
*****/
>>
>> +#include <linux/memblock.h>
>>  =C2=A0#include <acpi/acpi.h>
>>  =C2=A0#include "accommon.h"
>>  =C2=A0#include "actables.h"
>> @@ -14,6 +15,23 @@
>>  =C2=A0#define _COMPONENT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 ACPI_TABLES
>>  =C2=A0ACPI_MODULE_NAME("tbinstal")
>>
>> +void
>> +acpi_tb_reserve_standard_table(acpi_physical_address address,
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 s=
truct acpi_table_header *header)
>> +{
>> +=C2=A0=C2=A0=C2=A0 struct acpi_table_header local_header;
>> +
>> +=C2=A0=C2=A0=C2=A0 if ((ACPI_COMPARE_NAMESEG(header->signature, ACPI_SI=
G_FACS)) ||
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 (ACPI_VALIDATE_RSDP_SIG(header->s=
ignature))) {
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
>> +=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0 /* Standard ACPI table with full common header */
>> +
>> +=C2=A0=C2=A0=C2=A0 memcpy(&local_header, header, sizeof(struct acpi_tab=
le_header));
>> +
>> +=C2=A0=C2=A0=C2=A0 memblock_reserve(address, PAGE_ALIGN(local_header.le=
ngth));
>> +}
>> +
>>  =C2=A0/****************************************************************=
***************
>>  =C2=A0 *
>>  =C2=A0 * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_install_table_with_overrid=
e
>> @@ -58,6 +76,9 @@
>>  =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=
=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->flags,
>>  =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=
=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->pointer);
>>
>> +=C2=A0=C2=A0=C2=A0 acpi_tb_reserve_standard_table(new_table_desc->addre=
ss,
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=
=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);
>> +
>>  =C2=A0=C2=A0=C2=A0=C2=A0 acpi_tb_print_table_header(new_table_desc->add=
ress,
>>  =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=
=C2=A0=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);
>>
>> There should be no harm in doing the memblock_reserve() for all the stan=
dard
>> tables, right?
> It should be ok to memblock_reserve() all the tables very early as long a=
s
> we don't run out of static entries in memblock.reserved.
>
> We just need to make sure the tables are reserved before memblock
> allocations are possible, so we'd still need to move acpi_table_init() in
> x86::setup_arch() before e820__memblock_setup().
> Not sure how early ACPI is initialized on arm64.

Thanks Mike. Will try to move the memblock_reserves() before=20
e820__memblock_setup().

George
>  =20
>> Ran 10 boots with the above without failure.
>>
>> George

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/083c2bfd-12dd-f3c3-5004-fb1e3fb6493c%40oracle.com.
