Return-Path: <kasan-dev+bncBC37BC7E2QERB5N57XDQMGQE64FQ3PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (mail-yx1-xb13f.google.com [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 67A1BC0D5B1
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 13:01:05 +0100 (CET)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-63e3421b8f3sf5566982d50.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 05:01:05 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761566454; cv=pass;
        d=google.com; s=arc-20240605;
        b=MHrUaX+X4GzEDBjnQ1B7IMHNwFsErxYobj9JVrOnQQYgFn0ux/OJa/2EtLebitVFCN
         RhGEvoez1ALYcbkCGuKXUkTgL9Fk92Vrz6q8JVYLLDY7T9UzwMaN6M4ffdLVaYC1awNI
         y8Q22Q7LF+TAu+Fx5f5Wpyt94xlYokUPXOa2DKX5o3jbye87GdrX8RPpcpf4Y/tfVQjo
         tyCGG0DG7kErf8yR2gnbcNEtBggodPAWpSWcP1UE0ccpUGKyvF3itPIVWYxwQgA+4Gsi
         cBdW6XD0lSWJonLp+wkNTt+ssr+ji/kcOuKlqTZgGPxNxaMcKOkjE4svkqdFHnZQ4Kcy
         CF7A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=kkL8BkvEX1+eu+WTdKXiueFLNNskuv/uhXlgiIyBxaI=;
        fh=PcCeae2q/07W/6hBALIsUI5KpgJuQ1lm/2rCoNEm5wY=;
        b=WLG9YcJZSlpiCiNE2nCFClpAU6NVxwJ11vvGLwKUsSjAHiPNGcIdxwaK0XXv342y+A
         gJX+GSIeJHBR9aJZGS2ynAkMwJo0dK86eNg2vhoCtdFjKbpQmoakoRN0f1oq09YzrpFZ
         i1fy44DcDZTeoDf+x/3Y6aKd6mspVHko7xxYLtGnWhWDcsYoWXF2h8VJWd3W1Jm0y03P
         zzBFKkdYWSdSd9Wv+MnOT7QoTpa325oEyG2+qGGji9zxsHgEOI2wFXPZl1ns4TcNrRDC
         DXaU5uJzu3rB1tcCEnwri1tvIQCO+jFzXrtX7QbPUJdKWsgNFKJqyrPIeUfks2yI2xvP
         /DyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=A49eSCi8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AAcG5okQ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761566454; x=1762171254; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kkL8BkvEX1+eu+WTdKXiueFLNNskuv/uhXlgiIyBxaI=;
        b=nnckIlo7RjcFfRpOz6RomopetxiKz+61GKrWsT9OviK80h4xmuZcoyyEZEXnPVG+1A
         qejS/lHMlyY/bb5S8yKM7h/OaeUQ0r5lX4K1Y3ukJ68yYcwV8IlYeH825R8XihyGDSRl
         TK0rYX0rmWrPc2DYrkOXnh3JfeEcX7F/769SyQZw+mrkYnKdDQcSmDfkZq1RcAjw/EWo
         y9t7km7Bv10fU4ADLtk+BvpQ9e4b6+45dFtM2IHhhFTaH4rXTZiiMG1PywUNd5rRqrxS
         H5is90g5ttJeWZLbws8/ZISbtazwS3IByMGzwqKyuSNewjrecv0OupwJdshLuGvtIAfE
         tRdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761566454; x=1762171254;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kkL8BkvEX1+eu+WTdKXiueFLNNskuv/uhXlgiIyBxaI=;
        b=puHjGsPL5Tx78Veig8OhEMF2uRFGwvmnod8PioqdCl5jNL7IC95VfW/HPneepW2Yhj
         Uum7e/L0Y+3rxZMKiQenGmc1uYwMZcWFAqn+FBbEFxqQ2oKB2CJMzynNkIUzJ9oOrErr
         yBmqEjEeDQexwO/2iohLq+QEbUu0QtWUvBGSATc3qpbJb+Js7kAp0pUbx7r5DoFKAYwA
         El8Y2PZ9U5gOceWr5GycLQbSWrU4tQKYA/3xdt0R01O5UUwg+AE8grGjNZsxZZn8Vclc
         8NdBlFDLLqLVjtrlVaFiVGHFFyJP7bRiTvFfTbPcKHDPyxafHRvcG65Po9kaj2HoQvu5
         kl/w==
X-Forwarded-Encrypted: i=3; AJvYcCV/RQ/X7qY+f03DNQlGXpG0DiUhG1O0Trb8MwLcZNj4sf9IEafIqJGZGIHkmclFbwkMm2RQMQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzu54a7oJDhUFF6dTttY3OBUmm2pWQna12v7vLIyFhwo1AiZmEx
	wumpga3fi/ifN4eRViR9rVPCLnTebdQdFcyb+FauA15qZqJUncdmaEbf
X-Google-Smtp-Source: AGHT+IFQjOtp2EeVJv56tx6z+DjM0Vc9BaUM80GBW2SRXyMqKNdN9OpZndhAv/4tWmQLOVk/mXk1Jg==
X-Received: by 2002:a05:690e:4081:b0:63e:d1f:d6a0 with SMTP id 956f58d0204a3-63f377f6ac8mr12643338d50.18.1761566453597;
        Mon, 27 Oct 2025 05:00:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bUgm3e13KICk/CZXChO4YpsBZYMt/Y+x1+DygkLQcOIg=="
Received: by 2002:a05:690e:2019:b0:63e:1ef8:c7d with SMTP id
 956f58d0204a3-63f37a8ada2ls3863096d50.0.-pod-prod-01-us; Mon, 27 Oct 2025
 05:00:51 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW4f7Z9My7GP2rxDzD9F5JMXgNTIKCIZoWCCuynlkNFVhMmn/hQHc6QfxlUXmF5lSEjLQOlhWeobcc=@googlegroups.com
X-Received: by 2002:a05:690e:d89:b0:63e:a2b:6862 with SMTP id 956f58d0204a3-63f377d2542mr12170330d50.12.1761566450793;
        Mon, 27 Oct 2025 05:00:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761566450; cv=pass;
        d=google.com; s=arc-20240605;
        b=RaFRZPwC+sN192kI9LZWIXsUa/8SGezi23iFiTe4E75cOhj0s5QznG5Kg1kdr7KbGE
         TrZ5neYgHC3E36rzD6imgE8SZ2hPVPk+HcZRZCcIpmy3GPTQGVcBMI4/pKFEOVZG0qK0
         sXdd0kGkmmi+aI1D+OjEU+HbPYE4cDTxVZoiS+YM6A6aMByVVf8GV5gu/LywHO56SBqN
         B4p6co5SbLQAK1c2U+cZJOjHjeU/FFnLRGuJ2HRZfQ5rT89GqGYqeVrxyjfZfl3xg52f
         aN8qpzgdzY7/3Bk/ZdOlWakQflPIN9rXr6PZwAP9l/qZObdvGP9CDKuAEzdhHLZUOdGt
         9/bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=y4pj9AHLwkFMEr9c9kBvOVzrpFujuuv7Gqfc/uc1z9E=;
        fh=NPg6FNx29/bRSPNsmQnFrkIVKU4M8FEC9m3ZRLv+8JE=;
        b=dmHlqkViONpYFLFvVG2qNnUGBJ5wKuqe9hagG42/6vIUK0bnTtGJSWa7SZjCY/2v5o
         5NT6ri9stmQn4TUZ+UA/7MS81/R7HQHU5BPwkz2Kp2IVaIlm+ZuC509ce8D8lbVMMPjV
         6NuuHPzcKR2k2Dv+pP7MrliKnq9a9YCcpK4Pt201mjD+/M9+S0H6jTkCf/JrLZNkql+s
         yWs+v5RCl+RO1PQBIXXMQj3qsZq6xcWSGFwXKHRCtuGxRcV8QAQHJ4FdMgEznxlQSpVa
         Il5u2m3axbZIqOX3xFqkV3zBcCqWCRdd5uWCxA/b6oWS8dvctH3g7Lp0WJX9g8h3dmny
         OVDg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=A49eSCi8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AAcG5okQ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-63f4cf295b9si282395d50.3.2025.10.27.05.00.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Oct 2025 05:00:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59R9CW8B005061;
	Mon, 27 Oct 2025 12:00:41 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a2357gpec-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 12:00:41 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59RBrqWf013433;
	Mon, 27 Oct 2025 12:00:40 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010063.outbound.protection.outlook.com [40.93.198.63])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4a0n06q1gv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 12:00:39 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SNg1TCW9sB7hzn/2vut9GZIBo/CEsjSIaP0N7DjWYLcI6GF4FcB2s1amLlLJ30AWFqjB4iqL3bpqrpedHGOXyuuTPp3+G5Bzqfo1XVp5TzHrxC9pSa8gFH3Iec5Hs+N+MpoVgDvIY9+gsrVnaDbnLbDV3kXDlYvZCGNKGx0onulNyum5oMy7UGeDaBmnGj9TGLQUnTsCIgZd1VfvY1HMFgjA6O3xNQhXS7xpbGitYznUwbQ6cCxSPZz7oxTgKo3HxZ653W5qsjtQ9YDiGiiL3mm1k56CKW/cOMb62NgYK4PD7Em+UJgQfr+UYC0oICI66gN+9voUkUJADP1deGNcrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=y4pj9AHLwkFMEr9c9kBvOVzrpFujuuv7Gqfc/uc1z9E=;
 b=dmDNwkpQL8SjgD782LjZ54Kq5Dx/VMaIwZhVp8iu+BmI1rDNr+/DK3+UXvtmIAbHYw4pFj0NOIi/L+1rQBWpIkiLLZBkKFG0D2dToo9b/xU3pHviFKz7vYH2KfBUdBSGJ6TdbuLS8RDyc29C+5w+AAeLhtnozunvxYHXRihAh//TK35qkgQZJEpSWeRRwH2HBxb7qmdhyZm6fhDqkPNTa+eu7c8YxikaVj4+bPUYIz+EjrfAK4zKJgqnKM2NZBY6CTUT4B0MziQ/gwTLef6/C7HSG9mhe0r2bk0tRlBSzdS3qaLk5nNYY+22ozme3YtHeQlygIjRxB4+dKki7vt9Nw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by MW5PR10MB5737.namprd10.prod.outlook.com (2603:10b6:303:190::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.18; Mon, 27 Oct
 2025 12:00:35 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9253.017; Mon, 27 Oct 2025
 12:00:35 +0000
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>,
        Alexander Potapenko <glider@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Harry Yoo <harry.yoo@oracle.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Feng Tang <feng.79.tang@gmail.com>, Christoph Lameter <cl@gentwo.org>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
        Pedro Falcato <pfalcato@suse.de>, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, stable@vger.kernel.org
Subject: [PATCH V2] mm/slab: ensure all metadata in slab object are word-aligned
Date: Mon, 27 Oct 2025 21:00:28 +0900
Message-ID: <20251027120028.228375-1-harry.yoo@oracle.com>
X-Mailer: git-send-email 2.43.0
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SEWP216CA0133.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c0::10) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|MW5PR10MB5737:EE_
X-MS-Office365-Filtering-Correlation-Id: d8801c7e-7e44-41db-718e-08de15506fd1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?X0P2lt4dMmSucrlh41INcrwppknLkn4lfebrcKYGduTjnz+ivQkuwhBPSsXr?=
 =?us-ascii?Q?gpaVp2CS+YjjhN1BH4lFqdSgPtPC584fN7KKipSLvQeAtA7dgv6dnWXXEnmX?=
 =?us-ascii?Q?OfNzfqAEmAeNQxspvZZgwtMwqzgG3sBmKWzq7ml6u+USbMBij7I2zbiUd1t7?=
 =?us-ascii?Q?UUEew0nWwY1BUo+uCeVq4oS6SzaLTspBi/vMFQCCc+7Zwel660NdGRqNzeF2?=
 =?us-ascii?Q?F9iGl5VdDgzxK8K/uXSz1dsE9vAA3/+qTAeZOdbgBZdv53GjMKm9cd9107KZ?=
 =?us-ascii?Q?2xVj+3mRBHGYi4vJjmRZiZcNqu76lrxaQdj4nw0ldKdknysrwvyY/4rMDJqJ?=
 =?us-ascii?Q?zWYcN8xpk1ZP3Ei3sHFV09RNYdT5ZxovwVLIewlv9dX3ppJ1599fKkyMmq8E?=
 =?us-ascii?Q?dpSdHTx7dbccVuH8XZtc0u9pD3nxaSJnHtPYHPoDH7cf2BRZm1cWZdclGPSw?=
 =?us-ascii?Q?IusNoCFOokxknLVpuDytvdQk9IJFfOTghxagKzcYwzcxgO1l99Z+EdMZHyCj?=
 =?us-ascii?Q?H7q7vRHOR9rN6yCdQvReCZsqJoUB/RCdqFH9vBn3U7EyioIUO+Ymfo2dWF0l?=
 =?us-ascii?Q?43Z7XDcDVCR/SSaUXS+8oBV5LkjDgCj83Cb0FO0ZzoTa27ay0FPGGbFbiOds?=
 =?us-ascii?Q?6OZ604XhBF3X6JISB4+5p92NdtOW66g+blfXC1WlpGt5xjzB4GAO6hiwi7gs?=
 =?us-ascii?Q?uQ6aX1d7Fz9UovfqXQsGzLSD2FSc+4dEfrrCIjvXHsUCiZhr9cC4gD2AFe20?=
 =?us-ascii?Q?b1bvxtg8J8axqAcN70kNcEIql3LnI7P07jW61nLMWYy3j4MqFA4yfoj7CbHu?=
 =?us-ascii?Q?heGRrFPoYQyNYUYqliufXQP9tnIF2x6Gd6H3j+jUK+xONj34vd70G3Eao9D9?=
 =?us-ascii?Q?Jle1d2b+TrleUByTQcsStvnPfdIB05B5euG9yxTWAMnndCYpiATm06D1bheP?=
 =?us-ascii?Q?mDyulkFJxSt6LXxPkfuCjsCGkSePY/2Vo/sBuu+5f3xkcRlNIEjSLUYbsK6I?=
 =?us-ascii?Q?c3mwVSFGXHTYADjSqknsciWQt5Njt86RaPGcMfTr8zVIyP5i6FhYq1iEINZq?=
 =?us-ascii?Q?AdfsaqAKoKlF1aCRWTypcodPHW0VooQXPx+mf8xuqDbhCO6HWIQ5nbvOU4Yk?=
 =?us-ascii?Q?BWVP8B2o94oxFnb70caiJOWiAYWlW1ShqJu5YV+vtX5I+kYsW3WEUEOA4aJq?=
 =?us-ascii?Q?AiFfDtf0mSzBEcqGZ7/bM4J6NtV03yLUxKdOXQy1qHuaIkRb89K9ZTdSTP6J?=
 =?us-ascii?Q?Pwq+FuwtjdY/Aw7WT5Ki2agyqeT3YBkEgC2ZAgkcpjQqUTi3nT3vbjLeQcNs?=
 =?us-ascii?Q?1V7t9w8FoLZMZsFgbhOxxTXqMoqsKj7EfBhDNVmzQMZLxk/RMxzSp27ouyQZ?=
 =?us-ascii?Q?q6gRXx99yj7hRfFNk3KvlYJSlElY3T7IbXt69iC6VlyIsDUsixJq/wckWvQ/?=
 =?us-ascii?Q?rfGRuz8gRBIsqE53R7BaiIWtUU0tXzw2?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uFD64CGq1Ohjy3awKpe/F0NV8gE3/F9EdM5/10gQUHZLPMw+qToTtO+QEO35?=
 =?us-ascii?Q?J/SXTrq46ZrTE3kSLC/9mgpKHAZviY7MwfPhbwMs4amNlCRAa984jDpc3fXb?=
 =?us-ascii?Q?r7hQGkJslnHYIlakB31M+YSyqH0+odEzKzH0P+88U03x239G0qbTS1SjtGjg?=
 =?us-ascii?Q?AVt5PAuzC9BePL3Go4W5GImdHhd67tN3KxxLk2mZ7H4a4E1LUCmCSxikdAw+?=
 =?us-ascii?Q?10f6wFdzzVasC24dZbwvYq0PjMtbUUXCe/f3bBuX1GZ6tUmWcwu+Douw41zK?=
 =?us-ascii?Q?k8bwR8Iv2v80L4QR4PVfg/mtxRqx4FJUstq5RLOs41RweGYwGrXudpbaDj4t?=
 =?us-ascii?Q?xgO5AvjKIeSk3q8UYowXo8x39rxOmNKl9Y7bl+d/9u8VwyRF7Tx7bCMIRwLl?=
 =?us-ascii?Q?rsBvZYMJ0hQHkvc3POO8zCKohy4b/l29RLzYvQuJh+KdyG91BzdgMmundTWH?=
 =?us-ascii?Q?jHXZ9o3LH7wJnBPYiwoY7/rbGWuBuRyVxVjduotI0q9cO7nlpg0W9nJq07Iq?=
 =?us-ascii?Q?0Qqd2xkjO2cSGe+OzKkh9gCVi0jRT2zoUttJfMhPGkn6APSi2wmOcJTlcUkx?=
 =?us-ascii?Q?psYVoJuZsgu1gxH5f6tRdLZQZ1nqOlW9m2z7eW15deZl91A3NCJ9Oc3fL+q/?=
 =?us-ascii?Q?Gkl1OhfmxgY5MaqtlTVCWdxBCWy1QJlVJm7HTnsq/RgVnM163ZMryD+a/WPE?=
 =?us-ascii?Q?SbbCHfp6d31JtRG6/YQq9D8ygSOSjYFrP0ICeBAVLmPyCfgUylz/ghGk3mf5?=
 =?us-ascii?Q?MjGeM/VgBst9atOIlwMqwA5i0TmJWl8+0fo8iJaAgEvA0mvlzGqjtB2jz44+?=
 =?us-ascii?Q?CgC6SHIRt6+Vf8iFy1G6C309r8h8Uvz1BhEGZv9HsoHm242I4jfhie6i9Y3A?=
 =?us-ascii?Q?HZi9KCuc++IwQJ0JWi7S+6s0cOGDUnu5LtUOPGtAu1QvPD7pflIIlX6NcCBC?=
 =?us-ascii?Q?3mnHGLHqHk7ygLQ5t0DZ78X87HA7MfOk7EE65UMQnGS5Ovg4LdO3q6zNzGM3?=
 =?us-ascii?Q?JfM0nE7bXMGf+hpY4xmL2XlR6pX2Cqo9XTRQVUkU7QuT+E8swAbexVxmczRC?=
 =?us-ascii?Q?29IIIa2NIfEt1trOvxKWIZjsZLNr18kiR9is5AefYwJj2Kmb57XEuAzA+OPF?=
 =?us-ascii?Q?psjb1Cs+b6SnYQHgstv79Zq2oMPFkolf4v+6/zEe8Ri/XyRMEGj6sIqAuEvV?=
 =?us-ascii?Q?5ejE9kPE2ONYH0VeJiUbP9DIYqiVT1uHNrEhlJ3owz5HQv1S5l7cICPxoQPl?=
 =?us-ascii?Q?JYKvo08ARuJ2iNFh6IBXa8XH7w5RP1WKunmG/HU722gFzmlwZ5KP1RTcpWSK?=
 =?us-ascii?Q?9buL25JpnS9aVIrCPGRp/R6pLUlHqrXRW6ojXIEhaGYBl15edcLG43zc0688?=
 =?us-ascii?Q?N7Cl7bZ1ycIJDql2cos1Tsu4uQBUOsLq8HRax/aN+Kt9HE+7f+32pwMzJHUG?=
 =?us-ascii?Q?bAc2fAe0YubAZJ+dlBTMKkrluGXvPyqtVAKgABR68TDnTQCRUgKVWAVID2Fh?=
 =?us-ascii?Q?BbVLPXcfBAFHDD2oE+4wVcTlBXsCD5eBuFScQ3ZhcVjvryHhiQbdzJWLBHpA?=
 =?us-ascii?Q?22kg4jFchHH/UXKA3iCUG752W84H7XB96JtUV4t9?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Qkn+SrykPh09H1q2XT6ghyvfT3HIDKDqs+Y8GkXJoolOCv9kn+hGYWzUVPOZZNR4qLOh/Cj0UtSL4Da/eccApfixiUkGUwnQHIkOVqKmX041kbFlvsyWuMLhE6jIt/z/bcsusNjiC3uZnGFnqBDnZ3EBhcmvLndmRhuMe3IQIRMgk1jBt5Zv4l9Vg6DroM3dIVaGsl25RhYS9rVGOiWsxckjgZup+nAnRws79kxn8j6xlEqWaspspaE1VuvEOjX2nPeMRzXsq+tQ5cJ5YxvUC0Knu9HtFd8D2d2DOul6lrbb/b323O5Wq9oC1fcCHOTzI6JdrDuagXb6nEOYEY/GeuELP2d7PpYpTUiKt1EuemfW6gjM5yrDN1HX8W8cbAyZQIYPO5FTEFzsYXR1OZwZLpFLDvIS0+NV/byVVW6iJ7D/Gw3LFBbtWH1EcPGgiFcI8v3IO9Xv1KxcXLOknATwKQ2h/ZIk2XFhNuzR/yAH0Q4QL6geCiOpqD+dbqAys/BRVECT/t9T2iJzHqeOQCYSUcwJhOEJ3Rx8b13S8VW5QlHQxkTHiXm1km8+9ROf5Nv5y5nuni6eLMuaD8dFbG3JoWmndvpoyDKuQYlmtwQptz4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d8801c7e-7e44-41db-718e-08de15506fd1
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Oct 2025 12:00:35.3015
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lpfJLC3GRbrWJSi5go2UhD2N1xZNm6/2SAHITxfoVpAfl5g8TLSXEp2PuR8Gt0jCTVXeqvGhxF8B66uuEr3JIA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW5PR10MB5737
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-27_05,2025-10-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 spamscore=0 adultscore=0
 phishscore=0 bulkscore=0 mlxscore=0 mlxlogscore=999 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510020000
 definitions=main-2510270111
X-Authority-Analysis: v=2.4 cv=Bt2QAIX5 c=1 sm=1 tr=0 ts=68ff5ee9 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VwQbUJbxAAAA:8 a=pGLkceISAAAA:8
 a=yPCof4ZbAAAA:8 a=60bAUpEqyJ0hnt3RZ0MA:9 cc=ntf awl=host:13624
X-Proofpoint-GUID: YOXAiuxnodo4cZmxgGIDBMe7HzYiy_Os
X-Proofpoint-ORIG-GUID: YOXAiuxnodo4cZmxgGIDBMe7HzYiy_Os
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI3MDA1NCBTYWx0ZWRfX2gaPL8uCKjWD
 +t//X9Cdr4KWUwQxozYWEKg663nZLaS48Y4XQB31XMo8cerJP04eJJs8UAZOEQEg1IOdCLXsvTG
 xaZeVx2FKHSLj78p7jRGSyWPGUTY+zXZC4QKjV3bkUaCKvrnlHCinmQfyfMhiXcKIJE/P1rkzeb
 jfyXldKR3bj8V/06PiBPFIGc7kGzsPd+nk5qZNX5ATZDWIfXM0ep+Kj07V3pEGS8HcMyQLJ9L56
 4WVqp6QsBEEKyfqe4cT5nhDfaD/zkCR2xCxNRjiBoTicT26nEFTW1ww6RFgIYMu4+XQAWh8BUjr
 jIJWzy8ZzvJ89RXF8OgFRF8HuUVDIYf8Y7t/80EDzKrzlA0Vz2/VW+bqyPYkzQ51gEorBqWnsKA
 LCIjIZHWs+oftyswW8YGY7l14gwjgA5VDuYetJtpq13eaeVlJUs=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=A49eSCi8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=AAcG5okQ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
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

When the SLAB_STORE_USER debug flag is used, any metadata placed after
the original kmalloc request size (orig_size) is not properly aligned
on 64-bit architectures because its type is unsigned int. When both KASAN
and SLAB_STORE_USER are enabled, kasan_alloc_meta is misaligned.

Note that 64-bit architectures without HAVE_EFFICIENT_UNALIGNED_ACCESS
are assumed to require 64-bit accesses to be 64-bit aligned.
See HAVE_64BIT_ALIGNED_ACCESS and commit adab66b71abf ("Revert:
"ring-buffer: Remove HAVE_64BIT_ALIGNED_ACCESS"") for more details.

Because not all architectures support unaligned memory accesses,
ensure that all metadata (track, orig_size, kasan_{alloc,free}_meta)
in a slab object are word-aligned. struct track, kasan_{alloc,free}_meta
are aligned by adding __aligned(__alignof__(unsigned long)).

For orig_size, use ALIGN(sizeof(unsigned int), sizeof(unsigned long)) to
make clear that its size remains unsigned int but it must be aligned to
a word boundary. On 64-bit architectures, this reserves 8 bytes for
orig_size, which is acceptable since kmalloc's original request size
tracking is intended for debugging rather than production use.

Cc: stable@vger.kernel.org
Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
---

v1 -> v2:
- Added Andrey's Acked-by.
- Added references to HAVE_64BIT_ALIGNED_ACCESS and the commit that
  resurrected it.
- Used __alignof__() instead of sizeof(), as suggested by Pedro (off-list).
  Note: either __alignof__ or sizeof() produces the exactly same mm/slub.o
  files, so there's no functional difference.

Thanks!

 mm/kasan/kasan.h |  4 ++--
 mm/slub.c        | 16 +++++++++++-----
 2 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..b86b6e9f456a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -265,7 +265,7 @@ struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
 	/* Free track is stored in kasan_free_meta. */
 	depot_stack_handle_t aux_stack[2];
-};
+} __aligned(__alignof__(unsigned long));
 
 struct qlist_node {
 	struct qlist_node *next;
@@ -289,7 +289,7 @@ struct qlist_node {
 struct kasan_free_meta {
 	struct qlist_node quarantine_link;
 	struct kasan_track free_track;
-};
+} __aligned(__alignof__(unsigned long));
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/mm/slub.c b/mm/slub.c
index a585d0ac45d4..462a39d57b3a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -344,7 +344,7 @@ struct track {
 	int cpu;		/* Was running on cpu */
 	int pid;		/* Pid context */
 	unsigned long when;	/* When did the operation occur */
-};
+} __aligned(__alignof__(unsigned long));
 
 enum track_item { TRACK_ALLOC, TRACK_FREE };
 
@@ -1196,7 +1196,7 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
 		off += 2 * sizeof(struct track);
 
 	if (slub_debug_orig_size(s))
-		off += sizeof(unsigned int);
+		off += ALIGN(sizeof(unsigned int), __alignof__(unsigned long));
 
 	off += kasan_metadata_size(s, false);
 
@@ -1392,7 +1392,8 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 		off += 2 * sizeof(struct track);
 
 		if (s->flags & SLAB_KMALLOC)
-			off += sizeof(unsigned int);
+			off += ALIGN(sizeof(unsigned int),
+				     __alignof__(unsigned long));
 	}
 
 	off += kasan_metadata_size(s, false);
@@ -7820,9 +7821,14 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
 		 */
 		size += 2 * sizeof(struct track);
 
-		/* Save the original kmalloc request size */
+		/*
+		 * Save the original kmalloc request size.
+		 * Although the request size is an unsigned int,
+		 * make sure that is aligned to word boundary.
+		 */
 		if (flags & SLAB_KMALLOC)
-			size += sizeof(unsigned int);
+			size += ALIGN(sizeof(unsigned int),
+				      __alignof__(unsigned long));
 	}
 #endif
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251027120028.228375-1-harry.yoo%40oracle.com.
