Return-Path: <kasan-dev+bncBAABBLXBUHAQMGQEKTACSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id AFA23ABA9AA
	for <lists+kasan-dev@lfdr.de>; Sat, 17 May 2025 13:19:12 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-742aa6581casf1403181b3a.3
        for <lists+kasan-dev@lfdr.de>; Sat, 17 May 2025 04:19:12 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1747480751; cv=pass;
        d=google.com; s=arc-20240605;
        b=aR43Ngf8G9pNVcs9iVlVIt1h6RXdOMEIRnGfGhFStDll/uxKPxItjzTLa7xrsx6Cmz
         cFLxbkdL4R60eiBs6BuXnRcboQ1PKLNdGok0FasGmbqR0SCRTtliKHVriZ6nVfA3v0sO
         tzvdRlBp+gP9ohpXELtas2QK4O+Ktw2nG48T0Xo48BgdcH/IVZeCRlsqK0OC2wbh72N2
         lpuu0ZOINgqiuetTbgqBuWx5M2BKIeweUzlTn0hkLx1+7vt25JboxWSyHluyXeu0Wnsa
         yvNQ3IjP7wA5c0qF5BgThcgpr2YIS2GVlshmVs3z3ywv50Vmwy2It9ruCrgXFsYZhGwH
         mhUA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=PhGjcbMg+C/UO2zvey1ccg4Zhp53HPe+DOg2GRR7Mv4=;
        fh=1E9orkFrwSmoGnk7Kpj1FGTfJu6ZM4aulnINqJxucfs=;
        b=HYWxmj6mVa+NwoLrdAuqpSGpolcE73YU3zwJeb8d6PRvcBjQ1X/bd86GSNJt4CU22/
         /Y1ZHdqJe4ziRMd7LPRYC+izZ/4CYoFR+o39hcJeBzyjxqzxft4v+YL/TpC3YYOqrcKU
         3MFri0irPgPv/dJ0+7v7JF4X5gW4BuUEyzIRmO/i0qHmz4yvuNVaO1aw4j3Z57ZJJh4j
         C02iYdRYC6U2Jjk8yFqeWRTuYj4bEfnxlVPI4lZ1lKp0unDz7+jhVsnBZQFG+vsS5wdE
         bQ01PKmO6NfOYgoCeBR9uWeJFrYQ5kybBLrYqMX9jH92PJgl9QHnJc/qL09dlu9xD6Il
         EV/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AIMcQmSJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VOOTpamL;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747480751; x=1748085551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=PhGjcbMg+C/UO2zvey1ccg4Zhp53HPe+DOg2GRR7Mv4=;
        b=FAPocieuIFTrMLh+HLHis1ETo/hMEs0GfwHDYrDa9yKJZeggk0Ztoq3AyEi/JEWA8F
         jftG1Zl/qCAUK1Lu9a3lH0KW45xTyTPeX/ApGzLMTiRRa3NEWKH8yUJ9ZzrwXJekXXxB
         UHFavSnox3WaWzIdFHR3Vn4j8k/iX6HZ8ik9kx0az0GaJlZcIyVelOe/y20DceX5Kx/u
         9FpkPRCVEO30lYUuAn+j8ASSW/8AnLzXuvso4nq+EZARTbmWolVg85thSusvJIvEQBZh
         DJb0TcALvLS5oOkvNdJfdgh0WM8hcmt3fYrSYTeYWts06oyoI2XhO4oDTHM9R9znxKiD
         MACg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747480751; x=1748085551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PhGjcbMg+C/UO2zvey1ccg4Zhp53HPe+DOg2GRR7Mv4=;
        b=g46J4qbNmIFkUwJp/ObtGyjVRegwGimIPkl2D+xDPAW2BF6iHZFv0sDk6gtjr0ZISC
         e1SPUyFirouVg6q+h+Pq9s9QGhvzW10NzEWfA3V6s2tkv3uOa6PItwbYy+1VNA7l9yiH
         SDJxKl2W3Mb1qhmoJdtyJojFL3tES6Sf25NwzXnbTtNjSIsa+qBdtm4k40LmCsEuDDAC
         p8a54pxqx9gvhDyzXhxUoU4S4zHl2EJ3pcG6YSDimUBVewV4tVCB1MftBnHJlV/wUQ1j
         IamewmnBu3AtAdo/eFM9TtzRIeAQf2gzSII4j+Yo71r2xb+MFQBobegTbOr10umtct57
         wwxg==
X-Forwarded-Encrypted: i=3; AJvYcCVPDtHFcaa09Ow5rVLPKcKSmaECRVh+l1+V2Z9lX09VPqY9JmER32o6UJi4SIVXxDrwtW9BMg==@lfdr.de
X-Gm-Message-State: AOJu0Ywg7VvXBYxuUCWDrV1CKQv+cieoCRicnfvfPZ3LmqlNcTV7yfP9
	7CU7UcrDioe4oRDwTD7waLkwvDogDLwYO94W4Yp8VRwiUNqUq4KLKgz2
X-Google-Smtp-Source: AGHT+IHVF5ZXhrspguF4A4FUdJJTd6DUrTAlPoGtD/kQXrBYfbPyIjyS2ABRSE6sE+iJVBWYTPTQNQ==
X-Received: by 2002:a05:6a00:9144:b0:736:4d05:2e2e with SMTP id d2e1a72fcca58-742accc2342mr7387688b3a.6.1747480750521;
        Sat, 17 May 2025 04:19:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGBW6JUHTMWpqyO1prC0HGvxlRkmSnvRYAQnXHH8LARxg==
Received: by 2002:a05:6a00:2188:b0:728:e1d1:39dd with SMTP id
 d2e1a72fcca58-742968c9930ls2755428b3a.1.-pod-prod-05-us; Sat, 17 May 2025
 04:19:09 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUoUvvbgu/rczTXGmKlJNLd6FU89v31piZfVdiMG7SWdSFErOP9K83GRyL6ERcJOHH9dp/rsK+JgO8=@googlegroups.com
X-Received: by 2002:a05:6a21:9185:b0:1f5:7ba7:69d8 with SMTP id adf61e73a8af0-2170cc65d73mr9187543637.15.1747480749233;
        Sat, 17 May 2025 04:19:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747480749; cv=pass;
        d=google.com; s=arc-20240605;
        b=EGoDauunmRf1sJMtasns617Pz0Uv3h4U/zn5+0/djdI0mhlnCjmNRXfRu2+3CRG+Lm
         TnSShhd2Sj9zEQutIa212dGdjmL71lk/43zMqpOEeIQCeL3evb+0M6CQKFuu7Kenvio3
         fESU8nCbKx2In8xqgDQrclMxijqOKIUkRxFyUzZvC49D/AaF6i/b7vD7CwU2ajqLzp7j
         qiTFpZ5iKNgfE19UIEy6Z6s7fkWLvZC68mR2UEFC0ZHVySWa5Dv+RKx8tDuDWqVNyOSf
         4PkvHSMhH5lSIf/7ppOm7Uk+8s8cfbkjhtEmbOzaYpHRelYWa3LAoKERiZBttZ6FwwQf
         nGBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=r0PSi5Gwlp0D4w0sW/GwMJz9j/BDsY7sNO00AcnsQ+c=;
        fh=vZDVMGuAHVstcoxpR37bje4wUcDtpbOa5BfyS9r5Fok=;
        b=czeMd9MOx78bVhGEkkBi32OXQMQajtyhY3xj0oK5yorRlYnbB5x5cGR7P8C9+yjDH/
         tLKBhKuz1EITsXQ+aNi9XealQ2n9mms7pxrnkmJv7He3yIELsc4rQhlx3w32XTqqGxcL
         OhdmUdycHeGycwYGRrK94RKFMI2TzT54aruOCGyGrvFsYv/psBc4YctUp/GQsJnckRPC
         0hMkzSojdZhF0gp8ZkPrXeGV5gHJ9Q9AdF4muZoUQU9wvNKzRKSm2HaVJ9MqWRIhaSsC
         z6E3uT+S9A4zkS0g7V+sZLDDgJKc8CVpnpjUB90nz0SvZH9aiAwKtp5cSy9HBiXzRhZg
         FHMw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AIMcQmSJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VOOTpamL;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30e10039b44si486363a91.0.2025.05.17.04.19.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 17 May 2025 04:19:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54H3Oug0000833;
	Sat, 17 May 2025 11:19:07 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 46pjge0978-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sat, 17 May 2025 11:19:07 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 54H6UMch022372;
	Sat, 17 May 2025 11:19:06 GMT
Received: from nam10-dm6-obe.outbound.protection.outlook.com (mail-dm6nam10lp2043.outbound.protection.outlook.com [104.47.58.43])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 46pgw4yu7v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sat, 17 May 2025 11:19:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=EYWq+Pa87zroF9CYY2Cn6LPpN5Z/c81BiC8vDGBZTjfQwGJsjR3whLHw4cBqBiut2OcEWCjU7KJsdy9z4A3ja3QPMkzY1PqznJ8Wpdoh3wLw//uNPXWPw3hPFDtAJxJNF1kjUyOfougxSlle6SzaylCU84+cC5tV/DTpwaIoYxLMu8BYEge8S+PZPWk2D0VwsmoOIKQLsscWIIh7rHWD9YXUrxS+OAiC8Y+QNtRLyMh7SR/k6ANUbxuP6r/+incvWNNYXL9IpkfGa7wpUJm7KIlLAaTyBdTPRbalxkYJtkyGWTs3uFTvbkkLXkLs0ojCwDnXo8MVjDvifn+dd4znxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=r0PSi5Gwlp0D4w0sW/GwMJz9j/BDsY7sNO00AcnsQ+c=;
 b=NmjVgsUkDG4IZ8Wf5s+HAlmeY7cevKO37ZJgI2CuECPbHrSnQGCgPn7gZBDwATILl6GsArFgHZf7+iQXiz9cwEwYc3BsnNLhdv7V5VkC4DCVNarxZqBLdQLSVh7XXViBDkP2YlFvnYXCfnhjw4ymB+rWqEF19cbbC4H0gqWyO1mpYuGeOli+G5MTkc98qP27ZniOlc646KcwOFdtZqwEBrDuF2a6ykbD+KAs2mv+7AEP+PZtlDIkpl7pOtSIDD3cu81fPt/b7abhfB06UNKQTL4LB15DlYDkS1rokdyYIwzaPhB38k0axpCqNPtGFLZ0vt4Lw5s+KK+/jpgN8sfZ2Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by PH0PR10MB4472.namprd10.prod.outlook.com (2603:10b6:510:30::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8722.32; Sat, 17 May
 2025 11:19:03 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%4]) with mapi id 15.20.8722.027; Sat, 17 May 2025
 11:19:02 +0000
Date: Sat, 17 May 2025 20:18:55 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v9 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aChwn4mmYMdMSuEt@harry>
References: <cover.1747316918.git.agordeev@linux.ibm.com>
 <c61d3560297c93ed044f0b1af085610353a06a58.1747316918.git.agordeev@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c61d3560297c93ed044f0b1af085610353a06a58.1747316918.git.agordeev@linux.ibm.com>
X-ClientProxiedBy: SEWP216CA0093.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2bf::8) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|PH0PR10MB4472:EE_
X-MS-Office365-Filtering-Correlation-Id: db286bfb-46c8-490c-262e-08dd9534a09c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?/M6Eun3p5aW4a5JkVYEq0iuA0Wvhcm7trumFLZnGAxkOrkVx2wlGJEXGvuV8?=
 =?us-ascii?Q?jUJ2BZ1c5ZPmMXLRDF5EqZPgYSK8bVEVvj8j1hhXRg4d0Z0Erl/hyJORdTAe?=
 =?us-ascii?Q?nzTACYXDfqCZb/Mel/DtmmxD9b3SfWU533DIVQ022iC1nVChImrAzm3tXWp/?=
 =?us-ascii?Q?2D5txRHE0UHgbzxDE0KSpskrsOGEpMZDIR4kHKm5h5VXt4et+iZizEBgfsGX?=
 =?us-ascii?Q?P9dGc2fKKyhg4MrFDx60O/1N4VX5kQHShYrXOA80uNjNmtkbgCCfnvoR7zXK?=
 =?us-ascii?Q?rJ3DBW58stOzKz70ZCLhYOUKiY9ymxanr3C/S55+NKfqK8y50zUqtUXgMPPK?=
 =?us-ascii?Q?bGAPDk5pCXwFA+Z1J1H7Hoz6OnbMOFrCNdloEPt6oZcpG8FwdMpr4GF+zuzS?=
 =?us-ascii?Q?P/1Kt6eQE9EU4952I6nBYxZihm9RRcYbfMxckVsuxl9wS15SLPGdVUf7fuHr?=
 =?us-ascii?Q?/SfkubEZlE/hSYdP8NykuvBtnY+W69NwT8mw32p0Y004hhbkVJmA19MEl0bG?=
 =?us-ascii?Q?T3e8VkGQRtMNcQFqWOdDi9UCqWSDOeAx/mfE0Ldv/9NNiIPRz8Y0+Y4m3C4n?=
 =?us-ascii?Q?xspEsWor/pUqNemWCMefxCt8bHM3ioR3Aom5kS5hZbZnQgrh7MglFdEPRMms?=
 =?us-ascii?Q?8eqt8Evia6RIDw7LnOXU/pgdfAf7SYKdF2Tk0nSctLlq52zUJp6hpJa0vrQv?=
 =?us-ascii?Q?TxLxfhiE+6S2h/fWCHOWrz0nRsJwK31UWxj+bo8BNrWAkK74e/n0LBTFZxBS?=
 =?us-ascii?Q?xUl7RmgYq3RtTOKYV58R00b+q0lirTsyJnbSY2R5Vdww66twNh9s/2QzIWjh?=
 =?us-ascii?Q?sV/NodVfP6qEK6L8gVZGjinY0h0YxEm2QbSQLdT4eQc1CahPKd8GyRPHP/Np?=
 =?us-ascii?Q?P2qhRV9xOw5n+X/2n8dOtzr7TE8CQICU2Z2/ylWZ0aK23bBecOMzfJmTuWXh?=
 =?us-ascii?Q?JI1XWgskdDJrSBCL4lOuelOOoxdNmoXSbAJCkFVYBBO8dnJHcnsxm0YAplTB?=
 =?us-ascii?Q?HRYxK1sgIf4iPO9VZxQv5EstJTQlxBMLZJd2jM8u/Vpb7cbrPC3W+gxlzFXO?=
 =?us-ascii?Q?rJi7b9QEduEdAj0YVGHISx6qM0v+y/z8BrOc1S84mF49V5Cnf1iHi/rMIuEl?=
 =?us-ascii?Q?Y0IAi+BlugEqOK35wBLeypxjmJiGhUnduXWzpWAVNiyOL078sobM9RJJt0jk?=
 =?us-ascii?Q?g+BNtMJyBi8T0j6ykmGUdf2REj7tTDrTlH+RTP0FMrYoGwekw/+mIwbmctZg?=
 =?us-ascii?Q?39CzAyl7nH6PISs10Eok757lVLae7MVJV/jNhPyUcpUWG+SA5uhnJQCXhUli?=
 =?us-ascii?Q?qfZYJ0xRiygMdxV44lGS5fRolc/72RHOKzO2/90TXuO2iEgqxLlm+gijTu3J?=
 =?us-ascii?Q?xKi2UZGE7jsGFsf5Rh6dIFSUW93mLvetqt+nnmIF6cqV3+0taut9N6fsvTJO?=
 =?us-ascii?Q?2EDpFgmn+9s=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?TKwXsBWzI7A+Z/oAyjvzp4GI6/RFVmgFRhqPCy/0fm3ywTAabT2uO/aBjUXI?=
 =?us-ascii?Q?E540IBwh32plaOjp9nywC7LWa2LSMfxj5lsgDSeVlVaYs1/iuGMHVukPsSYZ?=
 =?us-ascii?Q?mfeIaLonA/q7ELOkSjJu/cQUIrqLWWsd2nbIpJjT0sRwhXcvUPhufFHaX5Mt?=
 =?us-ascii?Q?1qfqXAA9aV+iBWlmcBNQ4XBtVw07u7GlZ262zXzhMORP0sDkWTTogcTdABEi?=
 =?us-ascii?Q?L27B7XLdIxJrovXwDWcQ0JQGtqOLEOjOyfsbfo6E4L5wLBh+7O8/plfPxJvq?=
 =?us-ascii?Q?L83wkI1O3pt9mcSxWSTuuzZP18hNsAfNTtdGJEeo2vvR/GjnRW4OVf3FtVUs?=
 =?us-ascii?Q?5fjbljlXb2VkaOEG8pHqZha6cUHYGA8eyWpoOdnWMojz6E42cUYrKrcQvGTf?=
 =?us-ascii?Q?EhCwUO6xIxjg9REkdxqgdUCr7w4l3iz+vBYNTuQUuXVvZuXWTjTT+1V0lrhx?=
 =?us-ascii?Q?i3/T6j6lTnRi7guZKADjFL9RxXjt71Ly7fKs2EMi/53LZXatGpYm0MsKrnQ8?=
 =?us-ascii?Q?ntObtNOi1wCMesndcwZR5kbxQVQhJfxjWTmdyK9UpED4IaeSk36cw7vdnZf5?=
 =?us-ascii?Q?qCmUvf/9TO6XOhVraS4GlsOjZa3scXBVxtRLmTw8oIC/YbqlTXb5x7y5MRzN?=
 =?us-ascii?Q?zoQEz8ZTRvQd26ubVxdhvR6L1k1G3JwkX4ffsL9rtc6pbJO3NRSV7RIZVnlV?=
 =?us-ascii?Q?CdASYCg8qdUsLISvlJNVvBX0EVzvql3AIGF6/apJ4sjhuCRZZJt9uMwUX3/8?=
 =?us-ascii?Q?ABROcnDrftun9GgQ4LXHYSNKBCS4LIH4Ftgb/TKJ3vClbOlL7I65iFJ+f6yd?=
 =?us-ascii?Q?rG2PtAofYcZ5vAXH69kb0oBdeL1lcp3TbXgYDCqyvfZNZ8fBZYXTZtPTVbBt?=
 =?us-ascii?Q?G4v/DP7PCgzxYSEBlPan4ZB91oJGuYmwX05Dm4h1/0Fc8HMzgNlxFhSvuM7I?=
 =?us-ascii?Q?HBvziol+mtQ5nPa4gJagMg7eZg8dyD6uwAj2L4khuSpG2YCSLFPEzM3tOax4?=
 =?us-ascii?Q?RINZ8nisYOK4m0u2TPL7gpAa4a/cXBnClvqH9hzdf2A6qZjnl+DlpXHDLL+5?=
 =?us-ascii?Q?40XTZyootB7aJ9VukWnCPb4YH7XxXl7eAMceYTTFGneFQAjNPkVewIaGGyqH?=
 =?us-ascii?Q?3huNN0MVGg2SK1To1dfK7TtPSaHA/3DNahQ2EwcW2mbgkFmkxOeYvnU/YdG/?=
 =?us-ascii?Q?IWdMyu4cdSB2yJRQPDVh4T6QflBI7mvCnukEgPjkk/ckmHW6Pje+r7/iW4be?=
 =?us-ascii?Q?lMD5Ruu63aY20LBJ+Q1u8S0bNGuIwRzJMGhVTuFqshB7u91eK/pqZdcgX9jS?=
 =?us-ascii?Q?36V4Ff0zXvDyI5IMFO+sQAn0GogS82HhwhkVgd35UKOhT1PPk8J7r27e2WND?=
 =?us-ascii?Q?g3CcdyTem7OtBxAYg4XE4zDMHmoKkM/rOjXKup2URVT7v/2pphHKh442/ZCR?=
 =?us-ascii?Q?OZ0F7EEdhSoX/OGt0K0XGLOF7IsSKy/qrurYAy/ANMGz0vZoYzgXSjzn9Igk?=
 =?us-ascii?Q?pUk0LNuKV6ZEZP+vkezlazHB46eomCc2BDiQp51CrGaXQLNtkWJBXzkEX6ic?=
 =?us-ascii?Q?3AVGYqrCIARbAHeJCLyiT65nehVuETx8ed4m0kZZ?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: iQWQ0GASvJaM5P9ZKhzWkoBc5+PpJwnGRd4OIgkT8LgSO7OG8CBvHzQBKRNboBnx70odqPBSR+yLe/QQWLp+aLub1gTxDa2O4GMDtU2p5LYnOpSw8h9BPVnFEvgcD+fMy4zZcF2v6xWDegPA/3hl2xYVoXFQwCJHak+OSnxEvX+i+KVd49ObWr2a3+bk4r6Wfk1sPdGbNVdGUwQdWWA4qZx7kphOYnzPZYYHg+BJ4DIyWRqQwtBOSEEKNDQV/GkqEDFCNXfo+s0x/5XC6FSxQgr2Ia2/oYClXXSOqwqXXXb98VUCTz6KthTT8PlzcR1Ui+qQGGqHi5dJiWebIGLBZ2ZhbNLHAvdI1O0WN6CsbjVzcsZJnSkxcUosHBZ7Nx0xZajWmeoFYXJLQvXmVf8aVDOYPm4xlt/uQ3F8ScC/AKv1YKqkOy3mtDog/mce28EfKOES4OhkRVrXqdWHuXAh9N2+S4cS0jxwjReiWAXLAYHUkkG17zYaJSJ1gWi6xNUzxW1qICVnfQfN4i+IUAQIgyI+DqE5hWwIwouM/ZpoJY5+l8xZ0MXCYutpF/V2MwLmkMUmvkGm3+MAVBrkOa9YVQDLebwNGCzSEcAxlrCZZbM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: db286bfb-46c8-490c-262e-08dd9534a09c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 May 2025 11:19:02.5911
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /63EVe79Zw/pjlVqZ8WqXznzKyyc68OHcMqFuEBMsLASCQPOF7d3tOe+cDx346Jp4n+BW0k+pzYSDKhtqwGegw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB4472
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-17_05,2025-05-16_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 bulkscore=0
 mlxlogscore=918 phishscore=0 adultscore=0 suspectscore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2505070000 definitions=main-2505170110
X-Authority-Analysis: v=2.4 cv=RamQC0tv c=1 sm=1 tr=0 ts=682870ab cx=c_pps a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10
 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=GoEa3M9JfhUA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=yPCof4ZbAAAA:8 a=bQecwb_pF5ZqkJzrMiEA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTE3MDExMCBTYWx0ZWRfX4rZwOWSn7DSI 7BGRRwJvw4U+ag+v8bWBKYWfOVvQYFBvW6MCZYRGmKVPdNiCk4mJMTVcVW59gWaND5yexiYqiUc 4M9j9HIUabvGhG1d43aeWBXOUSxrKPM/nUmzrUxNycrlQznV865yNXGa36DzcVYwSDHFhovM0tX
 1S8d2I6QUUxOgf7xoy7YZv0DMZwEqGYyygY5xw/9TGT4olaOLKzP3CGXuEgekWG2or7MgfgyKeg 6Hcn7nTvmRJ917+NsVIMXeiDnegc3U95ekVkADbVJhwGo9O6nD0rNGw/Lo97Yc75eOAGaAeqrTn a0sajhmvPq10cw0XwK1YpTE50AsluhQkvaeJGZlvhxa0b96G1TmWmJaoGFUXdI77d7VZ2tlLfh+
 CcYLaZvDZRxWuaRais5oG4gCMG2414ujnulpHDwYAMePg1dSuTGlKRpxf/+jel6uJvrjGXXD
X-Proofpoint-ORIG-GUID: T9mdo23jKGuHP5zEkbjNVPc4nICvOc8p
X-Proofpoint-GUID: T9mdo23jKGuHP5zEkbjNVPc4nICvOc8p
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=AIMcQmSJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=VOOTpamL;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

On Thu, May 15, 2025 at 03:55:38PM +0200, Alexander Gordeev wrote:
> apply_to_pte_range() enters the lazy MMU mode and then invokes
> kasan_populate_vmalloc_pte() callback on each page table walk
> iteration. However, the callback can go into sleep when trying
> to allocate a single page, e.g. if an architecutre disables
> preemption on lazy MMU mode enter.
> 
> On s390 if make arch_enter_lazy_mmu_mode() -> preempt_enable()
> and arch_leave_lazy_mmu_mode() -> preempt_disable(), such crash
> occurs:
> 
> [    0.663336] BUG: sleeping function called from invalid context at ./include/linux/sched/mm.h:321
> [    0.663348] in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2, name: kthreadd
> [    0.663358] preempt_count: 1, expected: 0
> [    0.663366] RCU nest depth: 0, expected: 0
> [    0.663375] no locks held by kthreadd/2.
> [    0.663383] Preemption disabled at:
> [    0.663386] [<0002f3284cbb4eda>] apply_to_pte_range+0xfa/0x4a0
> [    0.663405] CPU: 0 UID: 0 PID: 2 Comm: kthreadd Not tainted 6.15.0-rc5-gcc-kasan-00043-gd76bb1ebb558-dirty #162 PREEMPT
> [    0.663408] Hardware name: IBM 3931 A01 701 (KVM/Linux)
> [    0.663409] Call Trace:
> [    0.663410]  [<0002f3284c385f58>] dump_stack_lvl+0xe8/0x140
> [    0.663413]  [<0002f3284c507b9e>] __might_resched+0x66e/0x700
> [    0.663415]  [<0002f3284cc4f6c0>] __alloc_frozen_pages_noprof+0x370/0x4b0
> [    0.663419]  [<0002f3284ccc73c0>] alloc_pages_mpol+0x1a0/0x4a0
> [    0.663421]  [<0002f3284ccc8518>] alloc_frozen_pages_noprof+0x88/0xc0
> [    0.663424]  [<0002f3284ccc8572>] alloc_pages_noprof+0x22/0x120
> [    0.663427]  [<0002f3284cc341ac>] get_free_pages_noprof+0x2c/0xc0
> [    0.663429]  [<0002f3284cceba70>] kasan_populate_vmalloc_pte+0x50/0x120
> [    0.663433]  [<0002f3284cbb4ef8>] apply_to_pte_range+0x118/0x4a0
> [    0.663435]  [<0002f3284cbc7c14>] apply_to_pmd_range+0x194/0x3e0
> [    0.663437]  [<0002f3284cbc99be>] __apply_to_page_range+0x2fe/0x7a0
> [    0.663440]  [<0002f3284cbc9e88>] apply_to_page_range+0x28/0x40
> [    0.663442]  [<0002f3284ccebf12>] kasan_populate_vmalloc+0x82/0xa0
> [    0.663445]  [<0002f3284cc1578c>] alloc_vmap_area+0x34c/0xc10
> [    0.663448]  [<0002f3284cc1c2a6>] __get_vm_area_node+0x186/0x2a0
> [    0.663451]  [<0002f3284cc1e696>] __vmalloc_node_range_noprof+0x116/0x310
> [    0.663454]  [<0002f3284cc1d950>] __vmalloc_node_noprof+0xd0/0x110
> [    0.663457]  [<0002f3284c454b88>] alloc_thread_stack_node+0xf8/0x330
> [    0.663460]  [<0002f3284c458d56>] dup_task_struct+0x66/0x4d0
> [    0.663463]  [<0002f3284c45be90>] copy_process+0x280/0x4b90
> [    0.663465]  [<0002f3284c460940>] kernel_clone+0xd0/0x4b0
> [    0.663467]  [<0002f3284c46115e>] kernel_thread+0xbe/0xe0
> [    0.663469]  [<0002f3284c4e440e>] kthreadd+0x50e/0x7f0
> [    0.663472]  [<0002f3284c38c04a>] __ret_from_fork+0x8a/0xf0
> [    0.663475]  [<0002f3284ed57ff2>] ret_from_fork+0xa/0x38
> 
> Instead of allocating single pages per-PTE, bulk-allocate the
> shadow memory prior to applying kasan_populate_vmalloc_pte()
> callback on a page range.
> 
> Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: stable@vger.kernel.org
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---

V9 of this patch looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aChwn4mmYMdMSuEt%40harry.
