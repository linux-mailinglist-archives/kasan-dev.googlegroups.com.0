Return-Path: <kasan-dev+bncBC37BC7E2QERBQX33XEQMGQEK6G526I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id B8ABFCAEA31
	for <lists+kasan-dev@lfdr.de>; Tue, 09 Dec 2025 02:39:16 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-8b245c49d0csf642832285a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 17:39:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1765244355; cv=pass;
        d=google.com; s=arc-20240605;
        b=hpbJSg3YDT9tVWykISg1hzq2hrRloF7yE56vYloDxEsWyV8QXUILm1IN1Q6wW1wHvv
         mekmWmw9z0B86rURrcZ2DNKOoy2ncOFT9RSCZRbxrsUN9sxv+hB3nb45rgUElMVi9hBR
         dbquV4C9zL5S3osVTYd9uOJhIlSWQ0f/ER1qhDmDb/2l5Albqt3YIZRRkSjnNO6WzGtD
         GEXFAu63yIU8kqYI+CZt/iQqOiHTd0CT98itnFRrvb298hlLPgvH36+9R90dHrfwgFuI
         JFPFMbjWu5LWXw4AEiu4k1/8kR7j2K7NmhDGJiS+eEp2p7l3xl+pB/3gRypbf+xohHj8
         13Ow==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=H8NFg3YSel6BH76QTxAsOcJKo76mw8zLmsJu4+eHIMI=;
        fh=QyrHjr0uRdcyBGw/2faWMKgXS/a6adquwMUlzjEttfU=;
        b=dtKNYHJ5gJ73Cmarf8x/el2DxvLQNarNg8YGKxLDm4AGQBtUlbe9K5mN/seGP2cFkC
         WSheFFec5q4sUg9ylz5paZGdKJiwwp+G7jNms0tRqRISk4BSqmhUBxxJ6K3BPh5deiW4
         RujHAtLt9GQzZrYtwAhL/bHFWZDvdh5sO4+PPDyINaeKXfYEs/FKwPQ5nAJAek6848qu
         XIKGRKbQxfeggVSVciYZsT69PjpG+dSIlOVec/ySMegcUAufpg3iHwrgxrq8Ftocuf9E
         vbGA8k9WxwEslPbC030JreBItbBfuwYOOktN4seJluaRrMy5wztsX1/i2ZxBhHbZuLvo
         L8kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=mDosgxYG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Ng1vsc/a";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765244355; x=1765849155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=H8NFg3YSel6BH76QTxAsOcJKo76mw8zLmsJu4+eHIMI=;
        b=mGqxCAjL9joA4vsExC6WXV0jcmyjZrg48CMz3Iuu9IYL4V0SvX493Wv3kQE2DUMAjB
         Y23V8CsKCJSJk+9tmLE9JjPGib4XEAeIbw5hXe/0v6ggZ0Eo6z5KA+ukmX31JNHLbAPk
         N1rgnSdvh9jg7NNGzZIfMR7OwMftAFNOmzpvukIN/iOYnUaLUMYfQEAA3cSXXBSQY4yV
         HPmxTk41DOeVyK0tATBFsGVhuQJ+hOaAjratoqsy912dLA0XfCskI9phP1/0IW35NmEt
         m/phAa7m+FFxiYIvbwZqI9SaGKtNwovbtvwPhnZH8CATduq//2veS40bu03AIQWdEZ88
         ccww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765244355; x=1765849155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H8NFg3YSel6BH76QTxAsOcJKo76mw8zLmsJu4+eHIMI=;
        b=NlIIZeKLZzFoWrDIEmiskHsGl8Q670umtL4Xu2Q1cDTgGcSbvTmSV2Qk9A3vRGzIru
         oFd4d8oWdbMvdqktEoXDdY5CLyZ3eklT3oEe+hhRC9T4I3Je50qlOGCwthgNH6SNhJXY
         qKrr0p8WhmtGgClEdRBKPBaToSH4CuC1Xycy0nrWgha2xyZ4dCOlmmmDUkhgLezkrp3g
         PgLRAs5O4LnULfz6dOt0ftoKGCDv59RZmq+S1uIzg3Ux/Ak+7wYWM45aWETSr6NCT/lH
         pqnEZ/tWk7MUgJ2mf3jUrMIZQFNKJst+S0VZ7HUG6oJ7Ow0YYD5Ayk/e5gwdhlnLlvv5
         oXSQ==
X-Forwarded-Encrypted: i=3; AJvYcCXBo5gJkF5IUyVwgmoSDxy7zkeJdcJvLqyPqRd5juAtXreuluDx1iTyWjv7r/M3K/zPT8hoYA==@lfdr.de
X-Gm-Message-State: AOJu0YzWbjfRUev1ijVD0pV9q2YyBhYdJb99BYmfIhfSLfFrVMAZQYSS
	UvkNYb4fANBpD/NzX/Thq6FW7Bo0ew/8W2zdOaAXr25/VGqpwH8fGHJN
X-Google-Smtp-Source: AGHT+IFHbCatPpnYU0eOGR4OQ1nMhrriR3IJsqa6oWjWRS2DODY/nS48BSn8IN+RnpKB7cxJnYDK8Q==
X-Received: by 2002:a05:620a:444f:b0:8b2:63ed:dd10 with SMTP id af79cd13be357-8b6a2401d67mr1358514985a.78.1765244355188;
        Mon, 08 Dec 2025 17:39:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY3O4ugv/AMlEZA66tiNitBPBaqFlK1Oh65Q/s1+Du/0A=="
Received: by 2002:ad4:4042:0:b0:882:3d7d:3964 with SMTP id 6a1803df08f44-88825e5e39dls100286616d6.2.-pod-prod-02-us;
 Mon, 08 Dec 2025 17:39:14 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXN7pa9YmFwQOA2glJ+b4veuFSBqwfayDSqhy0kcEiSQYkYVrZq8LyZvwrJc460OTG2rgbhbOwTFJE=@googlegroups.com
X-Received: by 2002:a05:6122:1d48:b0:54b:bea5:87ee with SMTP id 71dfb90a1353d-55e8459ad95mr3148873e0c.7.1765244353896;
        Mon, 08 Dec 2025 17:39:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765244353; cv=pass;
        d=google.com; s=arc-20240605;
        b=FmvFwHO6kwa0Me3x+osZNZ8knLthAeVYygUe2pm0owdByhc7hZP7kTRqo0lLE4efV3
         Yj11URP1cy4Swq/dBqckRTh3Nru64oWykStF5l7i4+gvfx3nFRNbl9w9xDfn/QD6v9/D
         7hFgK7ur/DVfs4NJS6aynl3fE9B0zDpBG9N0EMXmleXrPBVOAVI9uGRwhlp3ilEi3bq2
         vFKFzHcqqqvCFswB+b6W0XzZlUhAyB7s8r8LTcewAjGjlAC9TgTeAHjZ0dHCq5mmnnFM
         fyFNl2eVE/CXt+FRcc9dgYEuZJR3iX6y7G760lSTEuQyCbyEmFpMlKtGIWvaQEAeN9a6
         WMrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=zRiUKkZ35ZTxtoltmD2BUyy09Aq9pK68u0oaCReTIgA=;
        fh=Edhnzvq7s6JiYRBIUIbL0giqNA/fXo0Z7t3q2+e7vQY=;
        b=PS4nLOHXJrE8iRRQeXt7SnmIXwFoTilnod9RhI9idmjDb+vOMcNI9JUVpU7wdWADRd
         gjl4z/67vbe7bEKim9rqwd4Kp84lC0Sv4P0Z712R7cj7RGL8t1W/S73kFnaxudC4jrJn
         GKtWAdazKx95DFhMjWclGpZPjA7+ecY3K896tWu37dS00Km1eUvSPbUDz8VqcLwjOPux
         c4sx604wC06LzX/tQglfa2peUnnq1HJldJxApCEzJ9hS7xQGuqIfkU7PiMM8X7e0KYkP
         QKI9ZLpRjZaR0RWe2GT7XK/GdwulM0IFf87yC5xesZDbhdl1JZ2n+k8fUsJlMojwFsJX
         rA5g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=mDosgxYG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Ng1vsc/a";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-93eeda12df8si327835241.2.2025.12.08.17.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Dec 2025 17:39:13 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 5B91at5R3880162;
	Tue, 9 Dec 2025 01:39:09 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4axa8kr02b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Dec 2025 01:39:08 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5B91QIxt021113;
	Tue, 9 Dec 2025 01:39:08 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010000.outbound.protection.outlook.com [52.101.85.0])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4avax8fxur-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Dec 2025 01:39:07 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=fm2E/knogtEv9CVyt41rOPZRkDkXMFdydIzaIdhhm5n7XaKUVyN5mZS9Jtsv5NHdn5WiohUOTLor/kinTHsD6QDQdS1nj1CHqw+EaagTmSpiAU1ind2s8zBGOSWo6roF7H0ZDtVGzn+EEdGOkugWPQu2VknIEHt+aJDsSYJ+RsxIrLWnYsCvwrh30n+BmAlfi9SDkjvVwHjMB+BfK65p4tRV2+crlAXxCYiU1/CUJJyzBUEKepBJXJ1DK5EMTInxnvit3L6pqMCeGhQDk9VfS7JfoT9KZxaUWrD30cz3hT94V7RWFpbZJnzxpYOJE7TSjHgwxoyd7E+yR8ciStDttg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zRiUKkZ35ZTxtoltmD2BUyy09Aq9pK68u0oaCReTIgA=;
 b=VQ4gMSkTfvTJvuotvgZbtluMJ8RsIxzVahoDuXAjwX4xUYB37iLgYViunXLR4aGlDn0M7uVX08idWKXaUjKwWReP7UaS8aIUeMZ7U4e9UQjDedKFpVSbkmvGwNsu9M/bpwe35EJib54Ty6MvhjmtEcCD4GUUkF5kP2sGGKlLG22KLO0IefnZWl/gBtgL7+qa1SoFb7XTb0q1RmdJmhvbt9R/fe8qI/yhOki7M10qD+r1lHwBTa+YYI++gymIwA6ypp3tSr9Yr3FF+d8BnbfS1BWvqNrzyO2k7rViByF+EDTeEfpXDnzws/gk+wW2K867zq7GZAWY5aPeJ6T3nDwCqA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA3PR10MB8442.namprd10.prod.outlook.com (2603:10b6:208:57d::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9388.12; Tue, 9 Dec
 2025 01:39:03 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9388.013; Tue, 9 Dec 2025
 01:39:02 +0000
Date: Tue, 9 Dec 2025 10:38:52 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>,
        Alexander Potapenko <glider@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Feng Tang <feng.79.tang@gmail.com>, Christoph Lameter <cl@gentwo.org>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
        Pedro Falcato <pfalcato@suse.de>, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, stable@vger.kernel.org
Subject: Re: [PATCH V2] mm/slab: ensure all metadata in slab object are
 word-aligned
Message-ID: <aTd9rNgjahFZRbEi@hyeyoo>
References: <20251027120028.228375-1-harry.yoo@oracle.com>
 <1bc9a01a-24b3-40a0-838c-9337151e55c5@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1bc9a01a-24b3-40a0-838c-9337151e55c5@gmail.com>
X-ClientProxiedBy: SL2P216CA0118.KORP216.PROD.OUTLOOK.COM (2603:1096:101::15)
 To CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA3PR10MB8442:EE_
X-MS-Office365-Filtering-Correlation-Id: 154c0bd3-052f-4a31-a13d-08de36c3bb6c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?zkjP5uVNIkA6gve64Ryi8xNiRp9jyzTOBxMvnfltmgbM2Gdqq0cxjDMpAJj4?=
 =?us-ascii?Q?BSioiEUjvpM0+VJpkf9hfW5n573hDSsGPypS0GybuDeaXgLB5cvvMohY3q+5?=
 =?us-ascii?Q?zLeL55E+q+Mm8cutXgdTaGwW7bxw+UHt5fepUruiSIu2wn6bJ9hO8hxSgakL?=
 =?us-ascii?Q?+EQTxNDNiliwVrgFR94SVKDc0OEMNs7QgCm3T7k4r9FrKMjTL0urRsu8fZKB?=
 =?us-ascii?Q?218xdOxYV1DXAIiLaFo2EzRVNZM0n3myKys0EaQ+JIdw+MAn0Sze+Kjr/5UC?=
 =?us-ascii?Q?b0RII7T2Ln2AX3M6RZG1xb+jej4PuRJMP+TutkiwE47yAx8+RiiQjU78Od2B?=
 =?us-ascii?Q?3iBUg9AXBYiT2zCe8gV5mVM4PeI6gBVYPgCDf7Qx2zrvU12mh89sIQEk6WCK?=
 =?us-ascii?Q?fnrlo7BBDuVCQtRk7bd2vAFe51prQmT35MtetwnABfiggcoWKAs67VDac3tm?=
 =?us-ascii?Q?o88sxKg3NvSH/ksUgRYKsRzDsI0mwNqHZuV1Iemrw7FNUi9DsXIL2xdk8oc7?=
 =?us-ascii?Q?fyVD3J45mKdX7nIStohgAsgkmCNtxrVRVJgU8k8609MIDdnzqTkFlQK39t8z?=
 =?us-ascii?Q?OTLgX4xkNhRP7/dBWfuMkbk5RVxqTfBHbPlN2eFw2Eh4bst+GEa0RNPo0hfs?=
 =?us-ascii?Q?203av0OU030aOPoKNqHnJpsoQI5up9j6whY878BDxjMnUnQ9CHy0rHDmaTlC?=
 =?us-ascii?Q?XDGwDUiJ/M5VHVj2lr/41l39mAVVvYHgSrqjN72SVLSoq6WahI4BNZC/+ioe?=
 =?us-ascii?Q?/sP0IjR/9JCz60dn82pJBd7MGKkCzTTH6t9rfDh3PyQHBwPfLgDlaTWo5Fua?=
 =?us-ascii?Q?1vDtczCzKeSu4NYHYRSTxPBQhwAgTErOZuW3EJqex8SV5wB6eGm9SY3k3i6N?=
 =?us-ascii?Q?txkfC4Di0e9nmJum7R/Ux4f2MheaP8MRCO8r3FG0taJNKI5pgICTX72GAKRn?=
 =?us-ascii?Q?6HtgqPog1l9NcO/oAW8P2vXF2n/+vj9rnfhDkSyHDh7tsc0p9gNZzWC3Xgo1?=
 =?us-ascii?Q?+nhZNLxVnjkadpCr42K/BJXkFFOFNViR7PCGEmS9yabwFTakDp9s9i9KE/KY?=
 =?us-ascii?Q?s0u4Vk7F/o+uGcLCP21cGLlUr7h8WtFWKp0G66hH8Sxrzio8o+rtnHPKQ9RF?=
 =?us-ascii?Q?SYBCJT8FVnV8YpFpb4v4DIp3odr9K1WSAyR4hB+YXfwzVlp9k6x2zh9AhGQk?=
 =?us-ascii?Q?raO9+p8jM0jGDSA7X743DKW3wHQ/rlFURJXq4H8WTUs4OWTcUvdBSthV+3Fs?=
 =?us-ascii?Q?QK3kGHCGPqfRCmX4uaE/5CHjHBzL3hXetH/jUC2qpj9zPmusN7y20bmFk3N6?=
 =?us-ascii?Q?Wd8Ix87WHHvbKD+BK6A8FPqur95RNaiQHfNiTNacINhHBK3V4HqWbq0vDrqi?=
 =?us-ascii?Q?OxqZlubSOufG/esQ/vkjzvBbKKpm9Y+78C7IzdvB/BP2/HsCCzxOPSUti9Pt?=
 =?us-ascii?Q?m3RMLShMwz2BFWMtkX9TIsLaBhaT+QnH?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?tvovmrcMutCJlFgP5mJDJ63SLXc2tlXSFPFxR5TQrewAT25DnRB/dIHM5+i3?=
 =?us-ascii?Q?w7ziEwCLzjEP4VHyBKpzo7dTSCrvuPsslSf3VstsnUmAVZscfqBLj0X8UqeU?=
 =?us-ascii?Q?zpjMY8vMxNuG1qlfClHhGX8z3yAyuDFAMwEVQbXEskg5UA13BTTJkF96lWc0?=
 =?us-ascii?Q?HKTsn5YLt9fjA6fHwC1uwlMrx4tHfp/fXfmNTErFG1BwvkBCxt2o4tY39Alm?=
 =?us-ascii?Q?q3RUdmy1z5Ed0x11RkXi7QU14SwV2T8EUGjzB90FNak22mTZW6rJK4s++0yo?=
 =?us-ascii?Q?akPUv1LAS+6oC4MDLiXNtC0x1fCXh3ZCUj+MZ0H5n3Xu7bWm32HxxMFD4dkA?=
 =?us-ascii?Q?eFo7cklT4dFMJAj7itG+71SdaxLOO2+gIhbj8JsYdZLZ3w0eLw9yVPwaSbgc?=
 =?us-ascii?Q?HvmVEXjkSlPtJdiuf9Cd+Ti1U3A3/Ph/Z70Cc9Mrza6xLnibmG08xBePyYcp?=
 =?us-ascii?Q?uDbjTZ5WK5GSxB9szJIp5WzRcz6xB2PotJnBDUwPQ1rQKMWqamh4mY/tUtaw?=
 =?us-ascii?Q?voWq5mv+MDRvF0NNWPYFw9X2c0Eu0xnSsLc9eLl5ImbJQJlzts8IWHb4aCJv?=
 =?us-ascii?Q?s2v56qL/yVEL0Z9jcx8yMlJgluQYa9PHFFEWeigO0/Bs6Yh/rjs+iH2J3UWg?=
 =?us-ascii?Q?DgznCrmOfFpaY4gfLfVqdXv+0rTvHpgMeRT0uV21Fm8vMkUg8JZyNvFmOH8u?=
 =?us-ascii?Q?3a+UH0r6c74Be8leEEcdDSYsWhvuYyipUJBNL3LISOu74bxXdg+ch4mnpRWa?=
 =?us-ascii?Q?BYk2kHxKMNP0oTMKbQYc3pxkLBhMfwnE6SYgBF8e9XuZI2PmDteRh7DE5pEL?=
 =?us-ascii?Q?9az37nkmhrG9f69aJwEYsR6nZ1LHPZsndAQswpqThWzLOmGHAImveCI5v9Tf?=
 =?us-ascii?Q?IAgodLF3kZF1jyKO4X0FCLIoP1zbnwiAFWoLVpc9Jh6STzGNxuHK9Z79sjl5?=
 =?us-ascii?Q?OuNpYdfIvAUcoMMdiafMjvt08x2pZ1b58nMtV4RNzXe+rea6U07QqQmLj8mw?=
 =?us-ascii?Q?F8eicPXokChVHSQccNsOnCLMDZbwS314R66OLCW89ynLfJdk0VgdDlO9ymiV?=
 =?us-ascii?Q?blkTe5i5qhFYqOVl0H2omxZLfJ4B6O7wsTuIlL/5MHc/m80qV9FSuHSQvPQb?=
 =?us-ascii?Q?rLY9gjRZNCK6bCKfvJhAOzkFEKlrS9YO4fR8IwxhuvXctpWoaB39z7Wbati4?=
 =?us-ascii?Q?2ttpgi/0MgJIktOFsiy9flhuyjw1QWRHe38sXB/cRh8dPdigIHyILXpoYCcE?=
 =?us-ascii?Q?cIxkkVpTtPWMr6m+e+b90WX0JC1RA78KowsWCMfuk76HQN6iHnfr3eSpj6hL?=
 =?us-ascii?Q?GsMgDoOD+MKvvLoepkYID8S0PSUU0EZNY5A9BvNetdtbspaFfSvYBuga9jdK?=
 =?us-ascii?Q?CudSou/4XEyW3AyZ7kWacgOBQXsm9l6T0DosnWGkKE9nttF2RmkiIuSPmq7p?=
 =?us-ascii?Q?HIi2eNvF0eJ4VPpdXf4Wcj02lZXSPxscdhGIxboJDWaP4VjoCh8KL1cOh40H?=
 =?us-ascii?Q?rebrumMy1hYu4WmdDZxYm2OOXE4kU/eTYhYhRlpvCTd4w2zm49iSS7mIY9q7?=
 =?us-ascii?Q?QS8/W/8f/IHHnNsktMktTtVArdOHg1QMNpQ0hiVC?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: gDu6QwfAdJsH8SrmzAJQ36Iifl2jAt75bND64RBU1B+qUJ/+jFwu4wrfnnmvhPNDEKsOIrvfQ/xEGXWx8tjEA6O6YqGmRi7UlyQYWx1dk/yFCNmsZExg0bghiDHrFAtdmw2DwIxR4SmLmrHekN7jkG1hPQ+UffP8K7Tt1XGQ+BIdLZLK0qA5ag6+nnu5deNpbW+qYbA3lX/ggRAS8m6JYsMkSzEZt1GI4HIh2WgwEpQtpziRR56fGAk8hje0UXJnRu7gQcWgrU/y4misfZbXOF84lYiVo38mBribW1Dua5G9yx+YCcHa1ZEBUyCPUurfvly3LmlomZOUyR+ID6QbftvXGF/K5xHrYbnnVmyI2YbqWbDQvsNbuSQAA8vTKZoVKeC3qaGm99qYOLJStOPczfKqiTrvJn/RIw4Pj2OXp458TWKfo8qvTTr3vguC0RystzfFV2xxQMJu7rtwjMyS0FFQJdbMdhXyCQGBo7G55gKHEmoe7g+JOaFJqD71RsyKxLEw73JLPxREsN/6XIVRWT4zR65THGXjMFjtnAI+OMoZrRrSG2mNKmjnf5BIu/gQmHrMjfM3UMLqf/CylnDJzq7Ofls1Bv/9xQpCPLrMmJI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 154c0bd3-052f-4a31-a13d-08de36c3bb6c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Dec 2025 01:39:02.8259
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZGyTECmhRq+SvKExONk9btkVMdwigVOHvP9TwFeDqHIYqkzlKzVw6wJPuIBtU3NqQS9JLiglStriVzBjRB7gqg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR10MB8442
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-12-08_07,2025-12-04_04,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 mlxlogscore=996
 bulkscore=0 spamscore=0 phishscore=0 suspectscore=0 malwarescore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510240000 definitions=main-2512090010
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMjA5MDAwOSBTYWx0ZWRfX5yWW5iBP3O2a
 Q55cQJx3bdVZiXUYmglckTlKVjPKy6WijmZPKIePRbnXX//yvO9L7/esWYHQy0pfxGnhyztujZl
 44wiELX+5lJPp6eTaWK5vHRXQfB79P2UMytHiyyeXTiBlGXSy8Bdb/FMuoAmRoFS4oKP1t7jszp
 YXaCucBnHqCPIW+9atY0i1jaOfAawXAJyO9K657ii0gfkpPHIu9ZTGisPx8ATieVimMukTWUR6I
 fRE75HaZJ7IXES5wVNJOh9PKHV0YuzoRI7Gu4Sfzs8kJnBFPoN+jgN/fKlTU/vkKvemVkI8KOkJ
 W6z/ZA2a8aNClptNv3SqQvncO/V+FlUvOkqz447YwfA6gHAWNJo7R2GuNGnN48ty5TggOYO9xhp
 3wnWoTlXLjnLLct7iL/p05o9IUidJQ==
X-Authority-Analysis: v=2.4 cv=ebswvrEH c=1 sm=1 tr=0 ts=69377dbc cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=wP3pNCr1ah4A:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=ddmaWls4HE4ikYURDQgA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: 1J-tujrjYMZ6Dtr4MIM8OzvYSQ39k7T9
X-Proofpoint-GUID: 1J-tujrjYMZ6Dtr4MIM8OzvYSQ39k7T9
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=mDosgxYG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="Ng1vsc/a";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Oct 29, 2025 at 03:36:28PM +0100, Andrey Ryabinin wrote:
> 
> 
> On 10/27/25 1:00 PM, Harry Yoo wrote:
> > When the SLAB_STORE_USER debug flag is used, any metadata placed after
> > the original kmalloc request size (orig_size) is not properly aligned
> > on 64-bit architectures because its type is unsigned int. When both KASAN
> > and SLAB_STORE_USER are enabled, kasan_alloc_meta is misaligned.
> > 
> 
> kasan_alloc_meta is properly aligned. It consists of 4 32-bit words,
> so the proper alignment is 32bit regardless of architecture bitness.

Right.

> kasan_free_meta however requires 'unsigned long' alignment
> and could be misaligned if placed at 32-bit boundary on 64-bit arch

Right.

> > Note that 64-bit architectures without HAVE_EFFICIENT_UNALIGNED_ACCESS
> > are assumed to require 64-bit accesses to be 64-bit aligned.
> > See HAVE_64BIT_ALIGNED_ACCESS and commit adab66b71abf ("Revert:
> > "ring-buffer: Remove HAVE_64BIT_ALIGNED_ACCESS"") for more details.
> > 
> > Because not all architectures support unaligned memory accesses,
> > ensure that all metadata (track, orig_size, kasan_{alloc,free}_meta)
> > in a slab object are word-aligned. struct track, kasan_{alloc,free}_meta
> > are aligned by adding __aligned(__alignof__(unsigned long)).
> > 
> 
> __aligned() attribute ensures nothing. It tells compiler what alignment to expect
> and affects compiler controlled placement of struct in memory (e.g. stack/.bss/.data)
> But it can't enforce placement in dynamic memory.

Right.

> Also for struct kasan_free_meta, struct track alignof(unsigned long) already dictated
> by C standard, so adding this __aligned() have zero effect.

Right.

> And there is no reason to increase alignment requirement for kasan_alloc_meta struct.

Right.

> > For orig_size, use ALIGN(sizeof(unsigned int), sizeof(unsigned long)) to
> > make clear that its size remains unsigned int but it must be aligned to
> > a word boundary. On 64-bit architectures, this reserves 8 bytes for
> > orig_size, which is acceptable since kmalloc's original request size
> > tracking is intended for debugging rather than production use.
>
> I would suggest to use 'unsigned long' for orig_size. It changes nothing for 32-bit,
> and it shouldn't increase memory usage for 64-bit since we currently wasting it anyway
> to align next object to ARCH_KMALLOC_MINALIGN.

Sounds fair! Patch soon. Thanks.

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aTd9rNgjahFZRbEi%40hyeyoo.
