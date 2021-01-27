Return-Path: <kasan-dev+bncBC3JDKVA4QNRBEHJY2AAMGQEAXJF3KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 19AB330637C
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 19:44:34 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id z9sf1675542plg.19
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 10:44:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1611773073; cv=pass;
        d=google.com; s=arc-20160816;
        b=PWyo+MkD7X53JlKm6Vkg9G7ZwkKpuCJ54vbOtj19dGOkFbimwCty5K+SJkWdQ+Knud
         dJbbvEr/HcuBo6/iX3zvks7+jY7spM/qIyjKfZxOSZ/MElXRyI5fYLAbbluZFPRuFey7
         20gmSI19ZaQ9gDqLVJEC8BJPskjG3f4cJbqgLSC30lzayMvmATfA0SCmqrgKPR3zvIT2
         eXtejaCRCjGN9+xG+NFXJWdj600Uepl/P3W1AcMMHYx2H8dFWVlC2gCmsKaCBCHWcDWG
         V2vmiDUgM79XxFCR9BV8WHTzRGOoO90Y99tydFH/dkoMnpnuoxSH1++7ZlXt43yVOA+i
         tUfA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=Y35DTmBIRV51WExpwtcawpK9VohRgMA4lA07pFft4Og=;
        b=auZDbmDhS/SZDa2quTvEqIEd1WtSGkBsd0Q0tl0h5j4/bSQOrc0+edze/r0w3dWMj6
         AgSKmLu7LBI8zBkAOx6Pp2T9oSS7f0js8zaYj+YSgGsqzNnWrtlH5+kyrHJeKtohsorQ
         ZlYKnZi31kQEw3xULUuE91nBBRb19Xg+/ZL7jncRkc0NhvQyAaJTP694c8Fuh1atM7eB
         wMdDq60GcU97jxsxMRTUFvWrKJGBTJ/z7Igasyxxk6BjqBR+IVg7iVMUTMMSgU+xoXDC
         unzepmzPfZku66CxLVZb7bZwj4Yw5QTknBnHlM4XNQOsnnNCnzCQ1n6SPSNAG4z/kLP9
         BwYQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=iBKVESIx;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KQjt6LRD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of konrad.wilk@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=konrad.wilk@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y35DTmBIRV51WExpwtcawpK9VohRgMA4lA07pFft4Og=;
        b=IMsjh4cyCOwYd+snxj5rOp6E9ABpN0jT9Ch/oheQRYeyIcz6eZhdpp25pSRD0JeE6Y
         Q20j3eoQjR6i9mUQn8hQbRnQHyJo+zd9fNrEA+Crrs+4Vf9/BpfhT3nyQIilmTf9cxT4
         bPAItuXWG6LzmcpA0G6f3u+Q0riD4+aXz3wZKLfi0kIWVJnViAIUE19yYcbCNv0Qq5m8
         DTF+zy4CrF7a0yPVUusMW+lVma9JCBvfL/SguhjKPWSKn7KPHdLauqdE+nRsosnwuyxz
         ETHh7c+RG6+dEjMk/uge11fqIoCRqjD++WibGkYcd5sS6XLzdW3IROqXZNdz6PuosBOW
         XMCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y35DTmBIRV51WExpwtcawpK9VohRgMA4lA07pFft4Og=;
        b=Wus1MMVg154sNQUH6W5yLQ3IrAj0j6hA7IZ4BfbP6bu3xF92pgj0nQ2ZVWULs7NmXQ
         TusB/9LGF5MrMEjehGWrbZTrOiKp/cHwEtOF70/KMo+LIf8eUQaPa3nlDyJ46CS+m0fQ
         hT+JQi7pLSa8tWAJk3cUpJZG/V9BjjyyC/yCMYkA+wlXFyp46JOs+/61CLa/n1aofgmw
         XXdW0VoubB6u8BgCBhmzLn1rZ+gNyx/cb+SUd8foB03zXOzqxvTGoToRr1LtSIzF/QUB
         i5+fgdD8WCXyIAMi/Uhxc7WZv/3vUJi8h3hYthlWZAIcAvu/DRn7kHBJgv5xvBO0hV0o
         5yow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Yy7iajmVwr+vbGoNdy4HNpKdu9paVY3n9O90YXu2NMi9FnTgn
	Gs4kLBJkjhIKSAqW4GWkd0k=
X-Google-Smtp-Source: ABdhPJw9IExtiil6VI1G4Z38+MIAOoQoW53JYaDZv5LDUzLJjS4aGGkQXYe0xI88tzJYnBem57fyeQ==
X-Received: by 2002:a63:643:: with SMTP id 64mr12459985pgg.422.1611773072681;
        Wed, 27 Jan 2021 10:44:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ef57:: with SMTP id c23ls1150315pgk.1.gmail; Wed, 27 Jan
 2021 10:44:31 -0800 (PST)
X-Received: by 2002:a62:ce89:0:b029:1bf:3a2f:1ada with SMTP id y131-20020a62ce890000b02901bf3a2f1adamr11969406pfg.16.1611773071878;
        Wed, 27 Jan 2021 10:44:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611773071; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ci1UX58/IBnS5BaMHnnjs8F4qlOCW4G0jnMZk1YjN5+Lu1yYnOmK5x7sirLL6UrKR0
         5y8/oK2cWDZfRYpCZ/VgrYLK8FgRIABeIMiuTCMnfpCn6bZduQ2Zd6RDDrvk3jczIWnL
         nSfGBgkyAD6gA+WdrXam8Uhtv9W/bOVU88u2Rd5EbFzK4M+RXiC/gby6qRa7Masw5WIV
         3BgmPxjScH+J9zV8nV9cbiV+vsw5E1rQRYZvsOYMZpjW4HSppXnwtIir+p3xPnSwU7ky
         7eEdbAuG6O4dpe1IRv8T0crun1Qf8U5QddKWWEaWirnZ8koVlM3nKziYTbsYnfxrFLMC
         I45A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=V1napH+qFCyPVYTFyuECdULClaq92A9Ccs5yEfD7R3w=;
        b=qJCv0a+aR1dBUjxJv4wvovRONxP3CmY+anZF4EpgQSPxO3y09SUzHJne7lL2wItLo+
         v4n+qTj2QxZPjll+stRIfrmiNinlUW3YpwVLTfl94UKnIqhcnRn9Cfv4RXyJB1VQDALV
         htmczqwOR8cif2SnfFCc0/TIucEEgnPyqkDNlnKGsZ6wLHwWLioEuR6TpH6sTRB/IWY0
         Qr1eGc32WMOnpvxRZm1z5uXlwlLz3IJNINqoixErJDhCqIGBfr7UZxUiW1+b7LPH1LVS
         qFJT0g/hT4kgq+jPTZmVzUnwX2Zuo78QX2XjhN9PSmo3yrIVI9KsR0xPayDrQGfmPDQk
         5eog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=iBKVESIx;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KQjt6LRD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of konrad.wilk@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=konrad.wilk@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2130.oracle.com (aserp2130.oracle.com. [141.146.126.79])
        by gmr-mx.google.com with ESMTPS id m63si149386pfb.3.2021.01.27.10.44.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jan 2021 10:44:31 -0800 (PST)
Received-SPF: pass (google.com: domain of konrad.wilk@oracle.com designates 141.146.126.79 as permitted sender) client-ip=141.146.126.79;
Received: from pps.filterd (aserp2130.oracle.com [127.0.0.1])
	by aserp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 10RIZGXf077862;
	Wed, 27 Jan 2021 18:44:29 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by aserp2130.oracle.com with ESMTP id 3689aarvn2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 27 Jan 2021 18:44:29 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 10RIaAOO051828;
	Wed, 27 Jan 2021 18:44:28 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10lp2107.outbound.protection.outlook.com [104.47.70.107])
	by userp3030.oracle.com with ESMTP id 368wqy7cy7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 27 Jan 2021 18:44:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=D9zTuBIfXlh95vraqLxR8FHNWsG9tSgzm6Tc35+2JF3+72qCwODGgAU0Fjp3E3Bo7+MtN4DCxZB/VRHwplmGHgY5wf6zgileQGFcpXzBcvcwrX1g1c5x5NZ8UJFg7hI65qA+9XaLsK5TKhy2mzrZy1gDJn06kxMM6NY+C4Yv+6f4JL/bXynp+p4ihcXfeDUFFKt5xK0xxPtqPScMvjRhQAxiptidgdV0/QwBRmR/F4xW0IwKWly7R2wKvci5Hwly44F3VjbfcZXW9K2SqeCuOnRqSp+eufn3yCt87Sl5XgLkgzZpHHSCyqllhzSWaNnDWTg0KRO9XQjlRJW29xhutQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=V1napH+qFCyPVYTFyuECdULClaq92A9Ccs5yEfD7R3w=;
 b=GnNVkghiBcleMQek3bHL9IWmaF/pXIKseCvf4U6ahKKtlhvQmAIi/ZP1teWDqVeoHiJvy8NUdkDJscFipkI794Sw0BtaPa69c7AauOhfozlXEJpNaw5txqE91jY4RrbB/H7tC4fPufwEcwZSPMh8YKecrucCjK6N1B4AQd5Ej5vqMBotqvF70DYf3SKnsLaQE1Ezs756LHa5bWW4G2smZcZZ9ehlgagxlUOdw52pwqEYRqeFK2vqwN+eh7vWq02KGYh0EOMyTDvOstBVrgUV0TisEdilcrzzyr7fGcL4deJOJKX0XNEQIkAeuF5wXcibgPTHe4/dIS+1F/2qinmy6A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BYAPR10MB2999.namprd10.prod.outlook.com (2603:10b6:a03:85::27)
 by BY5PR10MB3906.namprd10.prod.outlook.com (2603:10b6:a03:1f7::30) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3784.15; Wed, 27 Jan
 2021 18:44:26 +0000
Received: from BYAPR10MB2999.namprd10.prod.outlook.com
 ([fe80::e180:1ba2:d87:456]) by BYAPR10MB2999.namprd10.prod.outlook.com
 ([fe80::e180:1ba2:d87:456%4]) with mapi id 15.20.3784.019; Wed, 27 Jan 2021
 18:44:26 +0000
Date: Wed, 27 Jan 2021 13:44:18 -0500
From: Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>
To: George Kennedy <george.kennedy@oracle.com>, kasan-dev@googlegroups.com,
        glider@google.com, dvyukov@google.com, aryabinin@virtuozzo.com
Cc: pjones@redhat.com, konrad@kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in
 ibft_init()
Message-ID: <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
X-Originating-IP: [138.3.200.30]
X-ClientProxiedBy: CH0PR04CA0084.namprd04.prod.outlook.com
 (2603:10b6:610:74::29) To BYAPR10MB2999.namprd10.prod.outlook.com
 (2603:10b6:a03:85::27)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from Konrads-MacBook-Pro.local (138.3.200.30) by CH0PR04CA0084.namprd04.prod.outlook.com (2603:10b6:610:74::29) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3805.16 via Frontend Transport; Wed, 27 Jan 2021 18:44:23 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 5db7d6f0-49a0-4892-320b-08d8c2f39215
X-MS-TrafficTypeDiagnostic: BY5PR10MB3906:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <BY5PR10MB3906F728FCBFA20D31D90E7589BB9@BY5PR10MB3906.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:9508;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: jbeqTd14ixevsjLwOYHUcDSP3ZTxI55FmN/YhPpF50qloQWXpg5cf2L/X00Uih40A4pKM9HGHhjgp1/Ck5Dn3nnt6fSar8RF0Pa4vUKAu3yit/ogqcy+WgPlmvYgFsT+wL3QNXu5IWEFpHdbwlO3tmtT5diFEsg+KWeOhWS1e7kWgA7UQlwHBUyD64kGmAhiIujFjN9PP2G2eoKEFB9vNRJB6rpIp8R4hUK+TlF3JczGV6nEIwQUjdqHWe1s8BA188rIA46iaMt6chGjT1o3LgFyXJLCPAz3CWA5TkA2F5XswstVKCKVWSu1PQBuUHigifQLZKsSdY77yRQWjvsNtA6U7FeBVVOpxMjVsIvq6ocFjzmaxW8I8yanVrdNFyYBs/5123lzOsmKEjuf5fIRH4VkJX4SQDzlel+NhCNPkJooVWODGno2YrabDCZ37Vz9DnCb/yOEzHS3Rl0Hg3YU7Hj4887rprxhrfJgA8Sv5CVgg0Ier60jS4vEmAio6XEWgdn11ib5/NRwzEmOPMxtpA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BYAPR10MB2999.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(39860400002)(136003)(366004)(376002)(346002)(396003)(8936002)(9686003)(5660300002)(7696005)(52116002)(4326008)(83380400001)(16526019)(186003)(316002)(26005)(8676002)(956004)(2906002)(66556008)(478600001)(86362001)(6666004)(6506007)(55016002)(66946007)(66476007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?YOft0t3hEaWEP2Mc9WeKeMqZYhI4heIcfljeoZ49qB1ipTXLScmWEUzw6q3z?=
 =?us-ascii?Q?qt+/Z027749lftMYHWcaFG2eCyqKjLOHa7VRlyCKKZ6pTwhbxrxjlCHCHMFq?=
 =?us-ascii?Q?yvmWhixtqyPDrRm8XCnTe+olXinMXybpry5/l1W4pSV5zcltoAGDHdSpjcS8?=
 =?us-ascii?Q?g89q7U7RG36VpQl/3E8tHYeMSTFM3+qAO3AurDgrvHpN7yMN34noLJSbSYi3?=
 =?us-ascii?Q?FYr+hlIP14IYoWKIGcVmWRuCtsw1ExErVZESU07SBn0wsKESQJVX11m0DEDE?=
 =?us-ascii?Q?Auy9olIiOZ+b0VLqtiuz82GVB+yEPLDVZqclKUdecnk85uqnvxEbSSoMc7X5?=
 =?us-ascii?Q?cExZXcGFaxnhlx8gG/3Y+sRUlfXvBZ0B43ihmFSxCAFH3qUElItG8KFxgchB?=
 =?us-ascii?Q?sNFbcuGWNS71gpAewA5QjxZ+bprC40pTtXvwoVjJQlB8tEOPDQ5fzuyYz44r?=
 =?us-ascii?Q?iqxAe9SRUef601CydmonOFdvByEjC9RfZjGdo2mcknCd1qTgALLOBOj/Jdq2?=
 =?us-ascii?Q?FVw7qAQwStPmzdNy2UGaWJFZOOedhnNMc5VhY+7OgdCbRiiZZXm/8+t91z3a?=
 =?us-ascii?Q?uMODjmpZaXZ28eoFOHhdd7zmiOOYOoKtGEfaNkEuGzgNGEfBatzdehEkfp0i?=
 =?us-ascii?Q?xq9jxpBT6qeKzvnhUvOApqZ8Rhmj2yBrzt7sbibPQVUhYCLx+axXRyW6kH1I?=
 =?us-ascii?Q?CiGi/DzSKzxR8avrRHBZi9t9T5NjkICnE77s1iMtNEdaqGKIRh/abuYosRfK?=
 =?us-ascii?Q?cSDHLT+BBjPwDf+UMEDQbTojr4SJCE4DuszYY32yRSaIB033Q0WrtaDwuVlX?=
 =?us-ascii?Q?S3tar9oC1OPOsN7ElDGIJnS9U2CO2QibToybEjwHOtymaF71M4K6IgfAtGc5?=
 =?us-ascii?Q?g4Bjd9e5GJR0KpTAuSNEIrLou6Tn0peuLA1VV84yDTUo+GUoviNjUlqtX71x?=
 =?us-ascii?Q?Zv58j+b6LazOiLy58T3ilwnEmLGXRGwmlNV0yA4E+ehC9ajmR+E8Mna5hGiF?=
 =?us-ascii?Q?B2yK4VsP3/dpvXYL2ao484QQ2EnXEDRbPfB0TjiLLUQBt9SI1PGybOiTu+2r?=
 =?us-ascii?Q?TbWFIYYA?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5db7d6f0-49a0-4892-320b-08d8c2f39215
X-MS-Exchange-CrossTenant-AuthSource: BYAPR10MB2999.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2021 18:44:26.0487
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: u4wBBJFJwlcH7aALipQ08l5NOUyXf8i03wJEWwXhc926/G2YeyUF8/hCEfLCayTaakFV7800A8NJH+8jAOH1DQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY5PR10MB3906
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9877 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 spamscore=0 phishscore=0
 adultscore=0 mlxlogscore=999 malwarescore=0 suspectscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2101270092
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9877 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 adultscore=0
 lowpriorityscore=0 mlxlogscore=999 clxscore=1011 phishscore=0 bulkscore=0
 spamscore=0 priorityscore=1501 mlxscore=0 suspectscore=0 impostorscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2101270092
X-Original-Sender: konrad.wilk@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=iBKVESIx;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=KQjt6LRD;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of konrad.wilk@oracle.com designates
 141.146.126.79 as permitted sender) smtp.mailfrom=konrad.wilk@oracle.com;
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

On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
> During boot of kernel with CONFIG_KASAN the following KASAN false
> positive failure will occur when ibft_init() reads the
> ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
> 
> The ACPI iBFT table is not allocated, and the iscsi driver uses
> a pointer to it to calculate checksum, etc. KASAN complains
> about this pointer with use-after-free, which this is not.
> 

Andrey, Alexander, Dmitry,

I think this is the right way for this, but was wondering if you have
other suggestions?

Thanks!
> Signed-off-by: George Kennedy <george.kennedy@oracle.com>
> ---
>  drivers/firmware/Makefile | 3 +++
>  1 file changed, 3 insertions(+)
> 
> diff --git a/drivers/firmware/Makefile b/drivers/firmware/Makefile
> index 5e013b6..30ddab5 100644
> --- a/drivers/firmware/Makefile
> +++ b/drivers/firmware/Makefile
> @@ -14,6 +14,9 @@ obj-$(CONFIG_INTEL_STRATIX10_SERVICE) += stratix10-svc.o
>  obj-$(CONFIG_INTEL_STRATIX10_RSU)     += stratix10-rsu.o
>  obj-$(CONFIG_ISCSI_IBFT_FIND)	+= iscsi_ibft_find.o
>  obj-$(CONFIG_ISCSI_IBFT)	+= iscsi_ibft.o
> +KASAN_SANITIZE_iscsi_ibft.o := n
> +KCOV_INSTRUMENT_iscsi_ibft.o := n
> +
>  obj-$(CONFIG_FIRMWARE_MEMMAP)	+= memmap.o
>  obj-$(CONFIG_RASPBERRYPI_FIRMWARE) += raspberrypi.o
>  obj-$(CONFIG_FW_CFG_SYSFS)	+= qemu_fw_cfg.o
> -- 
> 1.8.3.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YBG0glwiK1wyJTeN%40Konrads-MacBook-Pro.local.
