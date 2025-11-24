Return-Path: <kasan-dev+bncBC37BC7E2QERBJMGSDEQMGQE4Z2U3YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id CA25FC7F242
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Nov 2025 08:03:03 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-343e262230esf4830927a91.2
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Nov 2025 23:03:03 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1763967782; cv=pass;
        d=google.com; s=arc-20240605;
        b=ULHPoWvUOCZFlOiFWg62CI4Rk661ARsdyop/jUudwyVHJ4Xo0muJC6sNMlJtb9DYT4
         29+MEoALnEmp3Ncr1uqsQKlWAxWr2ekS85oGtS12svqSomE9XRsplaC+zY67yOZJNbhB
         9/FSz9+Jgt+FUleiJXhBwUDfdNzSFq6ijf+NBDZRIXExEETf/g8bPbcGH2bwd9xuarI0
         WDXmrfR8rsD/0o/4x17PshRb70ScKjTqVl3zMvqOeZyMVkUFGINOPDf2NjFXtQzrlIIo
         iuvSvO9VY0mRdpyIESeDrz+nIEuk8INkugYOdgv6rK9Ahm4gdL1dB1hCGwMDVbxPTIn1
         t1uw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=10vxwN81NajMNeurBqAgE/TiVLLN711yVntuzvq8L44=;
        fh=hNeKZDZrHOu2c7bigtGn4NWCAEhzBmo3Ga2E4gOFmEg=;
        b=eVAPe3f+Z1qNWPXj5VDHaALqX/2cTSOpart+Z/71I2JUGBAAeg33TGLlfG9BqpyfKE
         XL50NJYFNkPZ/jp3FpugeS3IAG0sEaD19F17+aiC6R0Kk0SjsyZ1H3YubQtrG5OGVXg2
         cFdecMGmT5dSasK4QggtW5rWbEsP7Au5AudIdjibd05HgExVQXKIFSbUkYpJuM9yzeP7
         IvSqlAhkFMFTcG2kJJuq7GOkmzOIYTE5vfFa8uTcINuKOhVp2uH21sRjrWRhIELU1VWX
         qK520VZv5jGc/E284DTo+yrxO/+7tFNhzQ+xEMsMisprwpjzb0K1/69CPEINUlSWgCry
         silA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=VRBssGFM;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=U8GPSwqs;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763967782; x=1764572582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=10vxwN81NajMNeurBqAgE/TiVLLN711yVntuzvq8L44=;
        b=cgSfAZqsg26HVLJE/AuWXI0mzHpia5dncOeyqvUc7Ft+Ftx+4/IIborY7zgHKvL8t4
         6bq+dMU1e5UCK2AF17Jyw//BwykbJBWkE8cm4LJehDAg7rpNx/Nb49YKQCl6HAzhY/99
         6gHby6HkHpHriz1oug/puaVgd7xqiztzPhD0UEOje/RINLV2XEugj+4t1CcLGqHuDOl0
         If/7y+Yob8AMX8oK47gsxMN39hPD7z6FZT8Slfbpn/5y7FVklpE4Kv8eqatghueqRX5f
         GegZi0UWn9RfKQE8Aove7y4cz/4Mpc7ytRx74V8at8o2PyQTc/dp13cP3BwVYETHvxeg
         Fa8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763967782; x=1764572582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=10vxwN81NajMNeurBqAgE/TiVLLN711yVntuzvq8L44=;
        b=H1TxcbiWzza03ATcwJtry7LU+H9xedy/2W2/g8inOM24bGpeb2VNu8WwO1qEJ1Rfkm
         McN2ON0DDH8/SuIka2zZ3QcK2CB6o22Qa0N0tOsSsFL3dwEKq9KRnqYBzLkQdKMR/qY/
         LkYbPC2BKCvXfgnrypUyyfx3xPxoRk5Kr2yNOEKdswo/eIVSt0rnempa9FHaJzGygKy9
         FFRgYrzgjNvvVGmxaZRD+Yh4/cN1Pf2GEhd9Qp8xQ7QFViuTBy5PABa5sjI/Ca6OeRB8
         DjQdriuTeSVk2yBl2uNuYRWLMKNmzr93//doqkVIWsQg5Y1hODz8qfSVytZyrG1gVFX7
         J0vA==
X-Forwarded-Encrypted: i=3; AJvYcCUcYNUdGZX2yarmLI3eXXNxkZESZRdpNbmct0yWcwgAJ35fVOUUK5cYPRWFSNY57O7s4biIcg==@lfdr.de
X-Gm-Message-State: AOJu0YyW7y7PO3sXENMkATeaF07MbxIoISeeb4EBEvBZFIjJYct6iPf6
	eGNPKxEnjOe2znp56LpT8tPQH8Y2VrHucn19coUe5JAGswi0s4PhDJQH
X-Google-Smtp-Source: AGHT+IHoR/gUwmktudgfbrHQJQ6zi9V3YNqRae5q/Al2ApTiX9czrbl9k2PK+09/Ud2/melBANsNHQ==
X-Received: by 2002:a17:90b:5626:b0:32e:e18a:3691 with SMTP id 98e67ed59e1d1-34733f44083mr12018701a91.35.1763967781854;
        Sun, 23 Nov 2025 23:03:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Ylnz/bSM1T3hwAwaL3BluA+X14kN7HqnmFLLz5usu1RA=="
Received: by 2002:a17:90a:e996:b0:345:b4ef:5c82 with SMTP id
 98e67ed59e1d1-347317a2ee3ls1998643a91.1.-pod-prod-09-us; Sun, 23 Nov 2025
 23:03:00 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXHhekKt1mHSXOg17fOqCMuo1y82FskCkPTOqoGbfn9Esdb9Bl49AZXc8MLzMVcC4JN/Yrk2UuXRRw=@googlegroups.com
X-Received: by 2002:a17:90b:2587:b0:343:87b1:285 with SMTP id 98e67ed59e1d1-34733effe64mr10544086a91.18.1763967780130;
        Sun, 23 Nov 2025 23:03:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763967780; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZskrscQMCQTTMxSF+1vACkSxP1NwjvyQvz5kuPfdAD+o3ipWee5fIDVfXzXyiFgnO6
         xabGBAfk/cNZCx645x9c/OvKiXSiGYeQJ0RpSV4ls6T+EcNFl49MgDVoR99xs0mCXmNn
         7wLw0kMHs+W+Ml+Q15dNjeKHrTygcOcCucdNziAE/GlxkSDyNE2dPubEj5lJBnZpJqbF
         m6OefnWcakLDx1UQBvP3iMH2TJnoUrNPuxGJmm2dI2d6xCrS4YsyQKVaKdUVTcETMgM5
         NRjVQePQt1bDFjtZQJYqnBsTyhch8SuBDUw0jbg6PIYxCvs3i5UxkKy3Xhb1lNZJZlY3
         tn7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=xMiEGeO4An1Im7RW5RLPOIv7zOYiow52okc8V3wmBxo=;
        fh=X25taNQKfUaEkHDjLkq/trSEmoZVDzg5hy+TlYkManI=;
        b=FTCY5pFicxBwEhm6KZ8exeFa/rGwho1YDAkwCSwp9V5AjW70cabI/rITCgSncv9gEL
         o3H2SgEvGsCpNpeBy+7ipIPIEiuEqI4sBOShIaXI5tJBtIbjlLroXuaRWNyWBQVpjPh0
         Ufwi+grsdDCawrLR0Vapk3Ux1OQBsuN2UsnzJf0q3awCGdfTEp5k0Wx8+H08XOBzS+lN
         CcNpTABBqYdHdoQq/YrsY7IudTGm2zzdfUvamI92T39pX3ApTuzzGI6kqXx2oPOabaWA
         bmuAAvWhw25DJMCb8h0mOgObyMyFQxdhM/FoSdBPtRwbH5CDx4CVzCs3dGoqIgvPi80y
         LesQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=VRBssGFM;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=U8GPSwqs;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7c3ef567556si296625b3a.3.2025.11.23.23.03.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 23 Nov 2025 23:03:00 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 5ANMcUJ33943954;
	Mon, 24 Nov 2025 07:02:48 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4ak7yc9ge0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 24 Nov 2025 07:02:48 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5AO5j7Fk022448;
	Mon, 24 Nov 2025 07:02:47 GMT
Received: from ch5pr02cu005.outbound.protection.outlook.com (mail-northcentralusazon11012061.outbound.protection.outlook.com [40.107.200.61])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4ak3mhsevt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 24 Nov 2025 07:02:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SrCCfbnHR2DRUl+uq8UFogtdP2bEt2kdMmBcBTgGQe1IIfj3p6kpYbN1Y/DvUpBbzkrJeuCMczoRU61sbKrRO/EJOInCbVDjZatS021k1l96V8gPeyuLqwXVDXdrsLYRcKGjLf7zAjv5LUAqDNL7FNqp/mCSDr72He6V3Zmc7Frrf27PlHZwq4dxWMXndlGTUC4OtdKeJ9NeHyJtxu8Ir+xmAFi+yllA0aN9ekzqpGL7uzedC2Ao/AmJI8A73tR2NBejos7LK5b4n7SXIiHkQ0mvbKyStVGursV2g7kqDo3RYEwW60o9eo8S2K6gW6TY3FVcnUY1UGvB6yKnzRlmcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xMiEGeO4An1Im7RW5RLPOIv7zOYiow52okc8V3wmBxo=;
 b=czz00HB3lJuWRMweWmCGb7c28u/n4/5e0ElR6aOyVMJSg1c9UrGM1PD6ytLuF2CZ9jVgavGMvdGClXh90kdEmiwEUdZIsBsps1EvV7wcaCZEtxpAayzJNeEGtkDVmuYdc9bNre32MTLZfyk/J9BPfzrdSFsJQCgRPHCTmSbP0vybOoQqnE8Z4K8SWY9uox0PM62asEO6mHxRwPkCGbpJ8yAouRXh7T0GP6BsyoHcBh3iysaG4oOW+Ie39zogHWwe3Yesxrd0NyQfAs0fKUiww9kWAzUcw2MJ1QoiyoVJqai267f7pndE1iW5c9a8n1Dhr/sQJXm4RAR0WEAdk3LhHg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by PH0PR10MB4629.namprd10.prod.outlook.com (2603:10b6:510:31::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9343.15; Mon, 24 Nov
 2025 07:02:42 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%6]) with mapi id 15.20.9343.011; Mon, 24 Nov 2025
 07:02:42 +0000
Date: Mon, 24 Nov 2025 16:02:32 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
        David Hildenbrand <david@redhat.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v4 15/16] kasan: Remove references to folio in
 __kasan_mempool_poison_object()
Message-ID: <aSQDCCmqHAYtKkK8@hyeyoo>
References: <20251113000932.1589073-1-willy@infradead.org>
 <20251113000932.1589073-16-willy@infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251113000932.1589073-16-willy@infradead.org>
X-ClientProxiedBy: SE2P216CA0010.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:117::19) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|PH0PR10MB4629:EE_
X-MS-Office365-Filtering-Correlation-Id: b551589d-3bcc-48ae-516b-08de2b27762c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?/c+B7PXoQq9hKFmxpAPqEPjnRG3MgfGgys8vGza1eooQzDGbKCxgTT+sOoOG?=
 =?us-ascii?Q?W5G46f8Qqdq0RyZ/FStVOIm4zFauGC4OGmre4kzWvR3YFl+0C6+ksCxb90aQ?=
 =?us-ascii?Q?+7v1GLaRGr6w/vckmUsq7dGUCN+55luH8uwj+tYW4sE6bVAO/aG1BiBZm1QQ?=
 =?us-ascii?Q?2HbGoozKbRUqU7oFNkw0Ux+Y/AYxNdOBcaX8cWKq9QpSusBLmWMdShIY7B5w?=
 =?us-ascii?Q?d5IK+5efiFZSNF/KBE6KUHlRlti1WGOM+1g2KBYBy8omlqBZ3QyrJfiUcOEx?=
 =?us-ascii?Q?84r2oEy3GUp7udOilH/r2Of0wzgBQZvsBVfpWLVQQpjTruaOduknGmzS8mWX?=
 =?us-ascii?Q?IkWvfttUiqO99UPeazKXm8O/4Pf0Zupvw4ZCgzWnh+CvZdu0TW/KaDL609vE?=
 =?us-ascii?Q?xuUu8pm/lBWB4WwJ3gT/ZFbK5T9HN8uQqbS4Ppfcpd6k+zvvDLuh+dRCeWfJ?=
 =?us-ascii?Q?n8l2YvPpUTjMqpPi8XgUVS1KWhWiEmDDTSsU+FXtcP1rYr7HgNmj49o2dULf?=
 =?us-ascii?Q?A0ivqhj9G2TJQTEbodAMG3bws4G9EGOgbFD8TbvC3NIdnKKKbWSbi5IvUpvx?=
 =?us-ascii?Q?xmR6szwiavBLxm7sFwykFOIXpm9KaytYP4itMZtGlclDznC8QY4RB5CGHfAn?=
 =?us-ascii?Q?aIr0zicU4FJh1diHsWWGL5OQjnH2b8myQvLddk5dAJ5L4jHJ8hMFu3jxHuck?=
 =?us-ascii?Q?JBla1wVKNRqCixlPrHw5ipjCGLlisdgwYZ8cBadKdjMyZlP3AExkA6LL0NhX?=
 =?us-ascii?Q?ztLnmrg30bwuXXuNJMEkt3NoQBP1qILwQxFZ74xBcrCNF0qe2erCxy7ODAiC?=
 =?us-ascii?Q?VbP7mjlqcC4mcA/rB3OfjlMVFDKuVjyYvGkfxOxbIIZhjAO0u8UPiYV+AAYO?=
 =?us-ascii?Q?ibmjm3+hu3yCGEYNRq1/e7lBiHUHhzG3n4sb0Oo8t6kOqi/aObv49PQr+NCM?=
 =?us-ascii?Q?p+BDgJuM6NeLrHhn+9X21lrfzgptvd5NCzDayxRpyRiIZIUkdS7xixEfM6/u?=
 =?us-ascii?Q?G0EJVEorjW4kWMhYRakqcQzrUFp28rDk1EKoySxGK81oZmia4EhUEhrmQcdC?=
 =?us-ascii?Q?iaEG5TFOkJAw3tniRjCnWufX/JYWissVxf9nwBflai3JoHra1IVIPNQNLPdA?=
 =?us-ascii?Q?PfgMV0eEV7v+1pDoy4B4Qusl9juazko80hoKCGh/dBo3v8Avhdc8onmIqMb2?=
 =?us-ascii?Q?esg5MB9YltOvOYkBvi1tJdL07uyFkwMkJ720Tai0OHqVXaU7E1Aq7ey2Cj6V?=
 =?us-ascii?Q?vDDGxCU1I5s/N+0MHc/v30wIQG4F/q3LE2F+iA98/ZxW+pSY7H51Qe5ndNCV?=
 =?us-ascii?Q?huJBXg/9SRzk9hSIFgCljbLHGpZ7QnxgVaePmyygCN1pEibwNO4Ua/+1AAMQ?=
 =?us-ascii?Q?HylDTIhDD6vjgDd/wTolPF9pXb+/3UrPwUYDGnqWZ4lgrt0O026NYHl6wM1R?=
 =?us-ascii?Q?Bct9yCU55x1soE73yO9GBijmfrV23qh8?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ZooFiwDSGBFNP4ZpJSluK2l2ar44kL+E8idKf06k9A5kFqSzGqggenLSI00n?=
 =?us-ascii?Q?H3RtQpkh3M+RdzpkonbcdsSaJJN41ziSNUIGQdKmDUQpMbvZp71xBInePeng?=
 =?us-ascii?Q?sstQH6YoCiBxSX27nmSK/3S8ONmJVpNXPcgXHRgJlEDuAq9zCmxhPkFmWwNj?=
 =?us-ascii?Q?QH+ECDvD/WxXdkuL1UzDxpsdTtJTVaBJYRNQb8yf75M+mHFEMyJhktQSxheN?=
 =?us-ascii?Q?/1PTjSvabfcEdOZm/A1ehETltOO9x3aA2BhKaOm93ngySTZBZD8+mfcHS5XG?=
 =?us-ascii?Q?utVMjnHD9yV1MWqgOD0bRHpXM2aFZCO0h7qITulxTG7LmXdfPpD5qnKl2s7A?=
 =?us-ascii?Q?pA7u0yyJcNTn+3K9qj0YP+4RrsprZdgroqKQLREhTtArhaJ2b5g6Ws4oHgMw?=
 =?us-ascii?Q?mOcVGfCgVf8uMKZiekjitObsLNx2v5DYYzG3tz19zj2RwcE48QDD7xRX4179?=
 =?us-ascii?Q?IRtOFdgug8mX9xmHv0UBVSF96mj2KTVth/4a9zp8kLUcI9XWQjJMhwE6CbKE?=
 =?us-ascii?Q?Ec+i8njaGpUfrZeICKZ0WO4CggIeOjjBMuov6d2PCjtMHNiSYP8efrHfgGYh?=
 =?us-ascii?Q?m3B+fiuKZxGS8felV89aqlcUW0I53EBq2F7MNl1JVcFDlhJ2hkT09+VMMDnN?=
 =?us-ascii?Q?oTQHLYwdDxKem2SY9WRuDpGr6TdXpdsSpozQn8yuLXWkhqmykx1Sa2f7xfaT?=
 =?us-ascii?Q?DkKlQCVQsdOvADOsWahacRA3AY9eRKkAtf7firQ0cf+XHijht4jVeFspcfIY?=
 =?us-ascii?Q?DhRtXjmOC011BdWS3eXXrAHBf6y7QXkm/IClrN4/Lc5gpi4B+yZNOJpRbkqF?=
 =?us-ascii?Q?RFDClX0ntHQus0SvfMQ0KL4RseSaSoQJ9nvwuij4L1o7cbeb+QGNk87vb1Bs?=
 =?us-ascii?Q?+doHhHinqFfLhKv2w1OGq88rjYQioiXkFGgNMq1fyiurV/2Do2hk5nUxw7qH?=
 =?us-ascii?Q?1IXkIFScZsvLOVSI7zmrSaXLJIQMgjV/AXqXstZ92wpKyirAqfb5y/ICvTyA?=
 =?us-ascii?Q?1UzpkFxqsUn1pzOK1oiYbn0ITcPYfWO2IWsemjQgKuGzHiK4PmbsIV4AuB1q?=
 =?us-ascii?Q?tOUZ7A+SWd8HxbegzXRvELvhgO9zgOZnCT4kG5+ODKEA8SMEdkAFCHeF/dzA?=
 =?us-ascii?Q?eIPgudVdMfHmbt5zf53+Vr6Qfi6tWCtdkkqMMMl2gDQie3ticn5sDfsK9wSg?=
 =?us-ascii?Q?oUMdHzkGMdsgWw3JEd6HDzvudhLX6ZPqbGluoa9c5zoYE2egHkJeiwa+bybc?=
 =?us-ascii?Q?wbMB/ImBH/e516cF0BHAT7AA2+0zPMK1Oye/amPBv1L/rdt9GR2bDYXLJqsh?=
 =?us-ascii?Q?PUxBUF9coWNIiHIGgrrO+DlRuxyLHJrtxVS0gqY0bqvDHYxzGxKLpZ82U3i4?=
 =?us-ascii?Q?I9Sactb7ILEBLasDpxHiO2iu+N34nxbAY7M9PxOlrXzmgD/OjgO+1jaqZhKD?=
 =?us-ascii?Q?VZtkAAs0xQI5JIp2kPLYbE2b7odCglG/+Kwclzp11ggkb6Zw/+HnpHtpJiMN?=
 =?us-ascii?Q?25QZRI9Rli9wbxscIAw8vm4shFDAmoNgX8Z8tt/pXOs4sPAj0koi1r+Y8IvI?=
 =?us-ascii?Q?lH8X518y3VQ2jomdgGRMLXrMhimLMEO68/LXxJM5?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: EMV//hQ/o2ongXKyZrvN/4YInAEfI3+JkfR10mcGNxe/aBmQl4Q6TEU2qo0/te8+7+eOnSaddGrRLw30O9vyY8z7nDdoFNj5MeXV1cV++iZi9gALJFulrFc8h7q9x6hqUR5dISfrNjScs+/HE9FRaq+VYqXS1yeTmxDZOVHIfv4eBaAAI1DOoRQRrVm30myApjLB8Q23kjXdA83Fr1SxzVoBv7K12gt/iQqpvx8FG89lbXaWW40WYeXs4lu3NS2Z9pNHjDh/ITot19P+M1h1j22lnCMNGHE+bbsnIWUljfCEQyvRYdFoNx5EEeuOHfgyOL90XXtVYKaT+cB60J9+B2h6yMpkMBoxrX5U2qfXZFUOVJvQOTjuLj9eEbfVXCRq6VKb8kLmwYyWnHrGPqnWp+ua8YMDFysNMGXTPS92C7ST3TQ6lpLX6xDxFt/T7Nzn1Z+PeaW5kS7zXsvQbdBQoz/LtVmF8srUFMYWY6UYg04asDmOGwRfNOHtwF2U5YhXy0RZD3RLPlTNYeAO91MfGgoioQYw/0quQY6KjfkTyyT78jXP9/IwIeLH0SHW3buBze3mYnE/fGBc/KGBOEoSA3USdPHHaxr3tyWDnSgtSqI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b551589d-3bcc-48ae-516b-08de2b27762c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Nov 2025 07:02:42.2618
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: N8leEjPw3Qwblu3p5OKuUT9dlIWf/FWGJdLB+QpDmfL61+daem9t0om/Labyl7zidKl5Q6Q/V9f3APpHfL+MJg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB4629
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-24_03,2025-11-21_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0
 mlxlogscore=999 suspectscore=0 malwarescore=0 phishscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510240000 definitions=main-2511240061
X-Proofpoint-GUID: kSv3HqwYgNnlhnXbHk952z3ai2zAuAsz
X-Proofpoint-ORIG-GUID: kSv3HqwYgNnlhnXbHk952z3ai2zAuAsz
X-Authority-Analysis: v=2.4 cv=RofI7SmK c=1 sm=1 tr=0 ts=69240318 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=6UeiqGixMTsA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=JfrnYn6hAAAA:8 a=20KFwNOVAAAA:8 a=1XWaLZrsAAAA:8 a=pGLkceISAAAA:8
 a=7CQSdrXTAAAA:8 a=4RBUngkUAAAA:8 a=yPCof4ZbAAAA:8 a=kgNNjo2PNP_B8mUuU0UA:9
 a=CjuIK1q_8ugA:10 a=1CNFftbPRP8L7MoqJWF3:22 a=a-qgeE7W1pNrGK8U0ZQC:22
 a=_sbA2Q-Kp09kWB8D3iXc:22 cc=ntf awl=host:13642
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTI0MDA2MSBTYWx0ZWRfX+lhVMTW9NXKL
 Ps7ySgA7j/vcilKlFy/hc1BeEqFJI0eklOM8XBItJX6IC6BsZakltQbc0aomvH6nqZgqsIq9EA/
 TXNfMpZeROUc4XpEnVmcbIJIqOcgGEbqeSJYZCxKjpuPRtUpmubk7E4XQGSnrDZlCTsfwUEeMRH
 lKxLGV1EBAFzLbL2zP4keCzc8eUwqu/3XymFQUL3oFtGcA1XBmSRXLtzigXr/Y2ld2rPKe/rnrO
 ZzG1dTFyF3cYauweBf3oAQSO+HW/uhF1QlXX8k7QOgzzTdcHewL6uErlc6S73v2E52CRPrgj0vS
 M6uGkvNYFxVuO7Iw2iJu4ZlcJxs7H3Ha5RNRtprGjO0R9GYWoI1fA/UWTkw9GCQ54Bn/I+3kR5O
 hr30pxWuEt9d4IQ7+fpESgbHxUghovu37dPJe4mU000RUrVffYk=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=VRBssGFM;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=U8GPSwqs;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Nov 13, 2025 at 12:09:29AM +0000, Matthew Wilcox (Oracle) wrote:
> In preparation for splitting struct slab from struct page and struct
> folio, remove mentions of struct folio from this function.  There is a
> mild improvement for large kmalloc objects as we will avoid calling
> compound_head() for them.  We can discard the comment as using
> PageLargeKmalloc() rather than !folio_test_slab() makes it obvious.
> 
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Acked-by: David Hildenbrand <david@redhat.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev <kasan-dev@googlegroups.com>
> ---

Acked-by: Harry Yoo <harry.yoo@oracle.com>

>  mm/kasan/common.c | 12 ++++--------
>  1 file changed, 4 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 22e5d67ff064..1d27f1bd260b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -517,24 +517,20 @@ void __kasan_mempool_unpoison_pages(struct page *page, unsigned int order,
>  
>  bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>  {
> -	struct folio *folio = virt_to_folio(ptr);
> +	struct page *page = virt_to_page(ptr);
>  	struct slab *slab;
>  
> -	/*
> -	 * This function can be called for large kmalloc allocation that get
> -	 * their memory from page_alloc. Thus, the folio might not be a slab.
> -	 */
> -	if (unlikely(!folio_test_slab(folio))) {
> +	if (unlikely(PageLargeKmalloc(page))) {

nit: no strong opinion from me, but maybe KASAN folks still want to catch
!PageLargeKmalloc() && !slab case gracefully, as they care more about
detecting invalid frees than performance.


>  		if (check_page_allocation(ptr, ip))
>  			return false;
> -		kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE, false);
> +		kasan_poison(ptr, page_size(page), KASAN_PAGE_FREE, false);
>  		return true;
>  	}
>  
>  	if (is_kfence_address(ptr))
>  		return true;
>  
> -	slab = folio_slab(folio);
> +	slab = page_slab(page);
>  
>  	if (check_slab_allocation(slab->slab_cache, ptr, ip))
>  		return false;
> -- 
> 2.47.2

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aSQDCCmqHAYtKkK8%40hyeyoo.
