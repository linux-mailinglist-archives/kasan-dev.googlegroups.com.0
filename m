Return-Path: <kasan-dev+bncBDNMJTNWWEEBBBPZ5GGQMGQE42RHHLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6984A47669E
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 00:38:46 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id a12-20020a056602148c00b005e7052734adsf21906246iow.20
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Dec 2021 15:38:46 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:content-disposition
         :in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rv2EhI08W+LI6lmhZFqeMPvA+r3igmqV3z00Ul+4OnM=;
        b=UNb2EmKXoGsLPlexKZaMr4uD1RWf+FI/geb7oSKjOKnuht6xCNF6SESMz7OYhEh/yn
         ZlxEJDzCsqtNMJlwPTyGdI0BTVneUKNlqJV509SnEFBeJsJTINCtFN4aUvJQV95s9cGc
         E46QIB5JjpIoAP4W8gVXknAsSp/l69ZY+Zc/w+4qJOQG/KtYD4jci+FJfHBXCjOZ4D23
         YmXm/ztCwmCLJ7LO0Q6qMDKIPc1g0brmHxGZswhDv8lgRI4bKFnNiHsBI4r8zKsBAUUE
         VG9ArejefIkDYjo2cP0lpmEDnnPzxIhpY86guNY2ZAe1JfTfT44ZRUw+a1hIOOFmx85z
         nqGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rv2EhI08W+LI6lmhZFqeMPvA+r3igmqV3z00Ul+4OnM=;
        b=NxgPZqwBrX/773vqGBTFN4us7sCzMtTVk1leYLq6Zj3o3xVWsE2Kak3CN8upB7a8YL
         +aAY52nPeBkNEkizmW+1EdjtypZEunG8bJwRIgWaSM//Hux/0eXndiXhEelPpn4urpIR
         r/oEeIYeDYR3aH2Luvu2+DzfPBDGfJc8v6MCSZrowfrTtR0zlYI12wgvR177YquLRqs5
         BVyoHrArH1yAZgjz6ai1OjaOwda+1KUPs8jyjnGG//pziI0xa9tqXaEvgcVkF69hV8JB
         8XRV9sLUvDKzKZM+hjTfi/3wfByMv60S+lJHh+WmhpMs92zU3Ze7reUvbOsV/upJEM20
         pnWg==
X-Gm-Message-State: AOAM5334KA316p1ZWdw4A4Mthmp0QndSwdqDf4Irpr3SH+Q5w5MpUKau
	iNZ47Aj2IBdgzeHvMv9RpuE=
X-Google-Smtp-Source: ABdhPJzTNlwXNjuUhVyf5lgPtuxmoN7QOZy9PEg69ITc8r9TB6U0IWSGER6pe0G14KqbzXWTVn2Ycw==
X-Received: by 2002:a05:6e02:1748:: with SMTP id y8mr8266747ill.107.1639611525274;
        Wed, 15 Dec 2021 15:38:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e4f:: with SMTP id l15ls552451ilk.1.gmail; Wed, 15
 Dec 2021 15:38:44 -0800 (PST)
X-Received: by 2002:a92:c563:: with SMTP id b3mr7581937ilj.94.1639611524820;
        Wed, 15 Dec 2021 15:38:44 -0800 (PST)
Received: from mx0b-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-2faa6b53fc1si557038173.0.2021.12.15.15.38.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Dec 2021 15:38:44 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=19835c127b=guro@fb.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0109332.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.1.2/8.16.1.2) with ESMTP id 1BFLifJB008483;
	Wed, 15 Dec 2021 15:38:28 -0800
Received: from maileast.thefacebook.com ([163.114.130.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 3cy7crga64-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Wed, 15 Dec 2021 15:38:28 -0800
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (100.104.31.183)
 by o365-in.thefacebook.com (100.104.36.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 15 Dec 2021 15:38:27 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LrRrjqAEWM7+2qrlUBRv4olSmlElAM+8bI33aCqsY/sl9zFpUUSPR2dAjqvJkmhOY1Dh+x+CcVv9Uptd9/rvjfl8lEcvRW+keddAGwqGRQrDciTOqHpqGZMZ3FiP8xywxysS6NPNaKhTE0n5WJFlZf6g9uVTLev477VY5bnu6Ey0petwr7wHJsxZ8MaEP6DRxGmhshrvj9QWbPMq+bPQ24KRLE66TsooKEL5bXdCTMW2qm7hE8jyzMUM6UcMntAUumcG/RWhC7DGmzMysfKG+i49S1l4dpAxmfXKF9Dkf6hiIoIHPsQkCwhx+KPgY3tHA5c1tLnOJ+9qamFuYltJew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=FISMclEalm7kRVdN9oOm4Xk4Dtn0W9Br+NPCqWkjADQ=;
 b=QTxhY5jDzBj8SKjFeRJTwbrNUdt3lOr/5ZwNfO/aVc2dwyMoohuRVBARmmVWa1VFb/9SUlpevy2c3jTj7OMImzPM9rwmUUEwViEhgO72fyOWiSA+f1zmgGq1sFpm3QlIaFXZ23r/aGGB5pA0rZbChSVXI++dEYg4zShWqcxUeo8lE/lihNS7Ld7ibbTrZwBvjBvJpDZ0n1AxUZYIkVK/Qg7hd+Muz2T5om3goyIUE9QCfjrtxuQYCIWl6Ma7xcOLacuy5d7XxB27F87GnORUfGSLZO0HhZY0RwLygUgo2SUoVSNQ+bpiZUQRW4FFZnBffxdHcC7TY8SyuQKCcYBScA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BYAPR15MB4136.namprd15.prod.outlook.com (2603:10b6:a03:96::24)
 by BYAPR15MB2279.namprd15.prod.outlook.com (2603:10b6:a02:85::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4778.18; Wed, 15 Dec
 2021 23:38:25 +0000
Received: from BYAPR15MB4136.namprd15.prod.outlook.com
 ([fe80::8584:55d7:8eae:9463]) by BYAPR15MB4136.namprd15.prod.outlook.com
 ([fe80::8584:55d7:8eae:9463%7]) with mapi id 15.20.4778.018; Wed, 15 Dec 2021
 23:38:25 +0000
Date: Wed, 15 Dec 2021 15:38:19 -0800
From: "'Roman Gushchin' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
        David Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Pekka Enberg <penberg@kernel.org>, <linux-mm@kvack.org>,
        Andrew Morton
	<akpm@linux-foundation.org>, <patches@lists.linux.dev>,
        Alexander Potapenko
	<glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Andrey Ryabinin
	<ryabinin.a.a@gmail.com>,
        Andy Lutomirski <luto@kernel.org>, Borislav Petkov
	<bp@alien8.de>,
        <cgroups@vger.kernel.org>, Dave Hansen
	<dave.hansen@linux.intel.com>,
        David Woodhouse <dwmw2@infradead.org>,
        Dmitry
 Vyukov <dvyukov@google.com>, "H. Peter Anvin" <hpa@zytor.com>,
        Ingo Molnar
	<mingo@redhat.com>, <iommu@lists.linux-foundation.org>,
        Joerg Roedel
	<joro@8bytes.org>, Johannes Weiner <hannes@cmpxchg.org>,
        Julia Lawall
	<julia.lawall@inria.fr>, <kasan-dev@googlegroups.com>,
        Lu Baolu
	<baolu.lu@linux.intel.com>,
        Luis Chamberlain <mcgrof@kernel.org>, Marco Elver
	<elver@google.com>,
        Michal Hocko <mhocko@kernel.org>, Minchan Kim
	<minchan@kernel.org>,
        Nitin Gupta <ngupta@vflare.org>,
        Peter Zijlstra
	<peterz@infradead.org>,
        Sergey Senozhatsky <senozhatsky@chromium.org>,
        Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
        Thomas Gleixner
	<tglx@linutronix.de>,
        Vladimir Davydov <vdavydov.dev@gmail.com>,
        Will Deacon
	<will@kernel.org>, <x86@kernel.org>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <Ybp8a5JNndgCLy2w@carbon.dhcp.thefacebook.com>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <Ybk+0LKrsAJatILE@carbon.dhcp.thefacebook.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ybk+0LKrsAJatILE@carbon.dhcp.thefacebook.com>
X-ClientProxiedBy: MW4PR04CA0380.namprd04.prod.outlook.com
 (2603:10b6:303:81::25) To BYAPR15MB4136.namprd15.prod.outlook.com
 (2603:10b6:a03:96::24)
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 13123b19-8e1c-4acf-988e-08d9c023fd34
X-MS-TrafficTypeDiagnostic: BYAPR15MB2279:EE_
X-Microsoft-Antispam-PRVS: <BYAPR15MB2279D37CB605445C8E14AF07BE769@BYAPR15MB2279.namprd15.prod.outlook.com>
X-FB-Source: Internal
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: m4ZpujmxJue4PB3Ip6Xbd//u7zrtULBvySXMnFhCy/bxY2V44Oi+1MLfShwg/rTgRotXD95dJ+yH+5Wb4W+QO/N+Tb8hiMWr2kqTC4vsA8VlEeVNhi1TybLx7n37rWRwTzKiJ5StFZSIZ+vDyzULSzM4Z3h8cOlbi44CS1hIDfayMak77VM2fefl0OSGO2yQLIgmJvlu0hW7lrIukBDd3TMmaQ9gVdrw3CilgMrkeqx6AHitFnmzc5yxIFlQG5wz3Dnd8BgAURKlOofcGlYq4sudGJ9MEqJE05D2/Sq6skSYNNCd6nfOqIfPz2lUEPiCM6kOwLP40hRNDCSwTi0eqQ461CyQXFS36ER1ensxRLmbAh9hs5qc3Km0zgWdAhSNvjMJHEeWULnZrqYT1gf0+pZBvx9jD6eshjHV8WAp41yxkJrJoh/uonIv5g/Qce9Jb8yQXERdgNTTbkTH1+7gOhsTLbzAF4g+SbBw+N9nyDnsJzhtQeQvRE74L2KSd7up39HeqYHSA0d86nwgxGEbDe7QySjbOHkr+s6zp5PGPnDuevnEtH6N6htLhPxyLBioalHhCfFyYPk1fK+m/GJV+0xD00kkFiMRkHnAkRGsWW+ayjPKE+8hm1fl3YYFfrl3FRU1+Edi23nrdeU3EEJDSKrVdfpigCnbDzzlpnlzg1mOx6PHQ45elzx2+4V2lbY2sa2qzsUal4w8Os4Q0EABINnRiybdoKAfS4FgLXtZed0=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BYAPR15MB4136.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(66946007)(66476007)(7406005)(7416002)(966005)(6506007)(83380400001)(186003)(9686003)(53546011)(86362001)(66556008)(6512007)(4326008)(6486002)(5660300002)(54906003)(508600001)(8936002)(52116002)(38100700002)(316002)(8676002)(6666004)(6916009)(2906002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?qHZbvZW3xZfg2H639D4oHo8GWNrKe7RzpHXjjcEw0j+ElSCeIy3fl1MCxgNp?=
 =?us-ascii?Q?fk5sRY28xqZojCGoVA2OwXBbUpXZP8UbvKxmV0wnjy9m81tGH5j193BXmdYn?=
 =?us-ascii?Q?htfxioVC8w6BGbOIEjLCh4f7zlmbPzwFXQ1gg2WRpopVJmfVhd1ULUuvCHYK?=
 =?us-ascii?Q?c0rNVL2i2bsSvsl/VznafJW/kmnHmUeQZ8ocQt9S/i1jCeE+qe+B9J1vzslq?=
 =?us-ascii?Q?co/UOLjOnSpoIirnO4XBxq6M4UZ660T+via+aO+4Uj7xigugP1tYcGsz0X9g?=
 =?us-ascii?Q?oIul2cP8V1zVRw5j5PMBB6TWxLcWUIHRDCiJET+UGqPVOmPbBcO/6NvoXl/a?=
 =?us-ascii?Q?jC7QLhLU4+uSl7Ma1NWuUS1YzWewM50jFpuYDVEnl4txL3rPYWp9zu8ITmbK?=
 =?us-ascii?Q?toc0ld9lwmjQqoTn2H7N8B9PWoy7owLZkS5QxLqOMzEWqsTzC/rvckH03pdZ?=
 =?us-ascii?Q?DnNswTpQ9SilQvEaas8K4qg7vppWK+80F40EZo8Gwoc75BLzYPTxbfq+V5GA?=
 =?us-ascii?Q?vCpXCDzulZDcQE2GeesTtV3EXgX2RLK1+YAJBX90nd37hEq7z4RMRjwiCXPP?=
 =?us-ascii?Q?M7uG8bGk39s5VNovmRnMg4EFZCguRRE0Ei4rDO84vU6xKbUl/35ACn9/K8qB?=
 =?us-ascii?Q?mMWPhzJeFs98/HF8RWup2z2FVt3YVv5KL/+Rj+WcB7xRy1SUh6G4UkVaG+YM?=
 =?us-ascii?Q?WQV4lE3NYTKSPlonZU2F2VCAZ6g5/n1xOK8ayGlpmm/gmzVRtKqPHFXnq0VR?=
 =?us-ascii?Q?JFAXEiNi03aMSZxXec1UiroKXieQYscQu9L9nxhO0LKkl0aN7rnC9o5s83S8?=
 =?us-ascii?Q?wL4u3mNJq7Pqh/A1eHNKulZcMyApzAB4V6ox6Hx8EKHjIsNq3Co7fxzHGLqf?=
 =?us-ascii?Q?TglOQj8mjz9RYHTaiN+E/lLglITwE4IOSm/cuVysIpRonDnzpBMTCk78fApt?=
 =?us-ascii?Q?6NytAINVY12obb60gkgGYqePBUJwIUPalzHvlSkqJdMbbREtqoN3pJOiCXzf?=
 =?us-ascii?Q?tLrZVXswMU64aHlu8wLVlhNKfHKfqN3OOTz4M93unzcMU7uKzn1MCRmnl9kf?=
 =?us-ascii?Q?VErEtN504qBgUwWVZ/tcjbZGv6+Y84nnRWenH1qryPK9FwCBTgWvNz1fk6yl?=
 =?us-ascii?Q?cbsSQXqDM6tFn7fVGKHRRPJ0iA4YrPTrKytavaMHZkcD/F+jVUuv8jkI/DNY?=
 =?us-ascii?Q?lZjv+ELSTt8Q7gBV8EZZQSPiOf7wwFiCmX7HHnR5zaZioH7MOSkG4eoaZi8J?=
 =?us-ascii?Q?9oTlTkahsfabDeHkC7dt4qFCmA18SdugdpRNTKoXg2vAgZrvbpO57Mo/8I2n?=
 =?us-ascii?Q?53VQ7Tm2AN7TGu5n6P5x6fk5SYYcUnRc+95Bvxk0I1/wVbI5YDQ+Mn7Agzz7?=
 =?us-ascii?Q?ncFMz8IHDDgYgO9cKTniF8MJ3ElWxjD273WRb7FYy/mKKqydE2zVF4ZXV5WA?=
 =?us-ascii?Q?rKjrSdTgx7AqPPq27Iy/FJsp56tw1xSbaQ5ozzmlQGjrRMg75tJ1LVIKmrMy?=
 =?us-ascii?Q?FaIT9l270YllC7GC+y+9Hf2WHu4p3Q8qOCn6kOaaoyBjXwXNp1syZ43momAk?=
 =?us-ascii?Q?VNW+U9q95MACyjogLny6yKqQNdIKEpw0/lJeAJ5k?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 13123b19-8e1c-4acf-988e-08d9c023fd34
X-MS-Exchange-CrossTenant-AuthSource: BYAPR15MB4136.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Dec 2021 23:38:25.5981
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 502OFXuYOCyoUZa0d1BI9xnQ4zLRydmx+XGfQHxIUkvtXXeTvKbVwlVWzBPZJ4BV
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR15MB2279
X-OriginatorOrg: fb.com
X-Proofpoint-GUID: ejU5ABcSgpWPvL7_kP-E2zM79ngJWtJL
X-Proofpoint-ORIG-GUID: ejU5ABcSgpWPvL7_kP-E2zM79ngJWtJL
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.11.62.513
 definitions=2021-12-15_13,2021-12-14_01,2021-12-02_01
X-Proofpoint-Spam-Details: rule=fb_outbound_notspam policy=fb_outbound score=0 priorityscore=1501
 phishscore=0 mlxlogscore=999 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 impostorscore=0 suspectscore=0 lowpriorityscore=0
 clxscore=1015 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2110150000 definitions=main-2112150129
X-FB-Internal: deliver
X-Original-Sender: guro@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b="Wy7dJd/h";       arc=fail
 (signature failed);       spf=pass (google.com: domain of prvs=19835c127b=guro@fb.com
 designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=19835c127b=guro@fb.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=fb.com
X-Original-From: Roman Gushchin <guro@fb.com>
Reply-To: Roman Gushchin <guro@fb.com>
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

On Tue, Dec 14, 2021 at 05:03:12PM -0800, Roman Gushchin wrote:
> On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
> > On 12/1/21 19:14, Vlastimil Babka wrote:
> > > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> > > this cover letter.
> > > 
> > > Series also available in git, based on 5.16-rc3:
> > > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> > 
> > Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> > and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> 
> Hi Vlastimil!
> 
> I've started to review this patchset (btw, a really nice work, I like
> the resulting code way more). Because I'm looking at v3 and I don't have
> the whole v2 in my mailbox, here is what I've now:
> 
> * mm: add virt_to_folio() and folio_address()
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slab: Dissolve slab_map_pages() in its caller
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Make object_err() static
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Split slab into its own type
> 1) Shouldn't SLAB_MATCH() macro use struct folio instead of struct page for the
> comparison?
> 2) page_slab() is used only in kasan and only in one place, so maybe it's better
> to not introduce it as a generic helper?
> Other than that
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Add account_slab() and unaccount_slab()
> 1) maybe change the title to convert/replace instead of add?
> 2) maybe move later changes to memcg_alloc_page_obj_cgroups() to this patch?
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Convert virt_to_cache() to use struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Convert __ksize() to struct slab
> It looks like certain parts of __ksize() can be merged between slab, slub and slob?
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Use struct slab in kmem_obj_info()
> Reviewed-by: Roman Gushchin <guro@fb.com>

Part 2:

* mm: Convert check_heap_object() to use struct slab
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert detached_freelist to use a struct slab
How about to convert free_nonslab_page() to free_nonslab_folio()?
And maybe rename it to something like free_large_kmalloc()?
If I'm not missing something, large kmallocs is the only way how we can end up
there with a !slab folio/page.

* mm/slub: Convert kfree() to use a struct slab
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert __slab_lock() and __slab_unlock() to struct slab
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert print_page_info() to print_slab_info()
Do we really need to explicitly convert slab_folio()'s result to (struct folio *)?
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert alloc_slab_page() to return a struct slab
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert __free_slab() to use struct slab
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert pfmemalloc_match() to take a struct slab
Cool! Removing pfmemalloc_unsafe() is really nice.
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Convert most struct page to struct slab by spatch
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slub: Finish struct page to struct slab conversion
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
Reviewed-by: Roman Gushchin <guro@fb.com>

* mm/slab: Convert most struct page to struct slab by spatch

Another patch with the same title? Rebase error?

* mm/slab: Finish struct page to struct slab conversion

And this one too?


Thanks!

Roman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ybp8a5JNndgCLy2w%40carbon.dhcp.thefacebook.com.
