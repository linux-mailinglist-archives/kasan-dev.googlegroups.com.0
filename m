Return-Path: <kasan-dev+bncBDNMJTNWWEEBBPOV3GHAMGQEXXFVAAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 48D17485F82
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Jan 2022 05:06:23 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id z17-20020a926511000000b002b43c84f5d3sf1000773ilb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jan 2022 20:06:23 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:content-disposition
         :in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=oqJd+nb/Ax3t9uIetp6jIQEH+PABHMro3cpPPz95vEw=;
        b=DVux7sjg2cyWEr60NUKdJcSiZL7KROVPJj+GN0Uvfw6oeJQKS0vkapuQMMIC9SkrTx
         HXyT/1TpHLcfPYegEvfVfqCX8BVkVbrvMjutDrDKj46EtYN+O9EumKW4UCYjlYcX2i7/
         TcJZDTOoKpWrPmxDwp7Rm94CW4YbjO/z6OJiixiWsJq3PoCZIiZjVQWglVod3sXni121
         a7XQlJmZLUjBj2iVzCg6aFdiX7+wl3XyDOAjZ5r+vpGpPfvCcQgF4j4TW+M40B82Gvc2
         fqN8+fa4QqWsSzW18sfM6nPSopoyVCiABBWQwpOIRzpxN/selnCWMK9sylgi93y71/hl
         CEcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oqJd+nb/Ax3t9uIetp6jIQEH+PABHMro3cpPPz95vEw=;
        b=2qHj8SXAMBoPe+5MptqyohsAc5rX5R6h/Jr3glvmszcciZmE+LESJ/g91SeDTST3Ki
         iiJ6w5sojMdnxIPN/YPLCR2dpTcsXyRd8ivRa1IB8Y+H+EZDJDB56tb/ytVH2tRZusLY
         Ulw4rfGLz00YlcpmGfjedACgNZqbwKCtxwtI9f/lvP+31EXKwgthG3/tXutJ/hL0jNT0
         f/9EIS34ic33QdtThLzaXjxBi6kIGV6ImtDOhrc+P5XlsgDjS8dBiSZFCw8X1fLgumsS
         amegGOgXgbvUNFvwsZcyMWnuuIt+t5jCmVP3TCWdx4SN7EHkOTC/nxoJBw3XkxOrEQHg
         XZAw==
X-Gm-Message-State: AOAM5329i62xwrpWS+JsNC4onNnUzFBAn9HIl51xsOriMF4qKVTHvIFj
	chphO/V2CfJHjbdgCnU9nfE=
X-Google-Smtp-Source: ABdhPJxWQW7GsIervVNHav1MQQhQO1yKXDxhYhRsB5f1NZ/ZLJ9xA7/KUgkGdCttkuNT3t0yluSmXA==
X-Received: by 2002:a05:6e02:52c:: with SMTP id h12mr27108935ils.69.1641441982017;
        Wed, 05 Jan 2022 20:06:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:da:: with SMTP id z26ls90827ioe.3.gmail; Wed, 05
 Jan 2022 20:06:21 -0800 (PST)
X-Received: by 2002:a6b:f715:: with SMTP id k21mr26844051iog.96.1641441981587;
        Wed, 05 Jan 2022 20:06:21 -0800 (PST)
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id c11si54664ilm.5.2022.01.05.20.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Jan 2022 20:06:21 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=2005fbe8c5=guro@fb.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0148461.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.1.2/8.16.1.2) with ESMTP id 205N50Gs028549;
	Wed, 5 Jan 2022 20:06:16 -0800
Received: from maileast.thefacebook.com ([163.114.130.16])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 3ddmpe173b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Wed, 05 Jan 2022 20:06:16 -0800
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (100.104.31.183)
 by o365-in.thefacebook.com (100.104.36.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 5 Jan 2022 20:06:15 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=OtZhXWkajYeT2axeG+XZiLPzlqGm92OzNQ8mTZdrCsv05BOf0J+uao8olruVJuQGowTacWJRVbYRSJ9/SPkYhROaD5AZnLJ1Ni49NmofGb8UIMXISCOJkz+U4ip7IzZGv8mh5FW4HHjGQowB+gVOLLrPNl8S+ORf++Wsn7WtEabEI/6+sLNe1b6iY55rl02gkSFpxI287IzHJElCOmlz39MbCuEAxoy7UXa4yLFw7aDrGgCjV8/Bw8OPWlXtBHyyOkt2SLhRGaz9SoHTA+BV+3wBRIaSV7j2em1i/XLfnPvwI2lMgriZB6H3Y/aJNAIC20uDIGhXvoBJlDvjBNrPKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TeRRTWiV8maF4665C0fsNVtMYSAL0tIBa0PzofGRGkI=;
 b=bCC0bZGiOb0xXCs5xAVIQ5n4HxT78ftuCuwbRsUlINEdrOCc8u4cdy6D0pDweExVxS6roXzQ2rGgMEN8wSMLtRWPwWufvS3wluegAasl0juiyDWmcZZ397soCvCrIPQqJwpcDnG6+MxYwNmp+DzLIlOU3OVrvFWDwWusxJlbM83CEll5+7aXI2KuwhfXY0YNz+GVAGZSzHcpO2I9btPl9QzWSzcsh+GmcxLrHRsat/GROCM6dgr9O+e7vaEmv5QymZYsjhfaBXpiWw+MF/viqIiNsWVFfzYp/lZyCX/EgTa62BifUukbFpXDYK/jJcyKEGjVVaFGYIgZ/lwz7vCEVw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BYAPR15MB4136.namprd15.prod.outlook.com (2603:10b6:a03:96::24)
 by BY5PR15MB3554.namprd15.prod.outlook.com (2603:10b6:a03:1b5::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4844.14; Thu, 6 Jan
 2022 04:06:14 +0000
Received: from BYAPR15MB4136.namprd15.prod.outlook.com
 ([fe80::c4e9:672d:1e51:7913]) by BYAPR15MB4136.namprd15.prod.outlook.com
 ([fe80::c4e9:672d:1e51:7913%3]) with mapi id 15.20.4844.016; Thu, 6 Jan 2022
 04:06:14 +0000
Date: Wed, 5 Jan 2022 20:06:08 -0800
From: "'Roman Gushchin' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
        David Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Pekka Enberg <penberg@kernel.org>, <linux-mm@kvack.org>,
        Andrew Morton
	<akpm@linux-foundation.org>,
        Johannes Weiner <hannes@cmpxchg.org>,
        Hyeonggon
 Yoo <42.hyeyoo@gmail.com>, <patches@lists.linux.dev>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander
 Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v4 25/32] mm/kasan: Convert to struct folio and struct
 slab
Message-ID: <YdZqsLd4Ee1P2ITQ@carbon.dhcp.thefacebook.com>
References: <20220104001046.12263-1-vbabka@suse.cz>
 <20220104001046.12263-26-vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220104001046.12263-26-vbabka@suse.cz>
X-ClientProxiedBy: MWHPR04CA0045.namprd04.prod.outlook.com
 (2603:10b6:300:ee::31) To BYAPR15MB4136.namprd15.prod.outlook.com
 (2603:10b6:a03:96::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 0d72d084-6f55-4d0e-5861-08d9d0c9e19a
X-MS-TrafficTypeDiagnostic: BY5PR15MB3554:EE_
X-Microsoft-Antispam-PRVS: <BY5PR15MB355448418F546B4EE0FEF773BE4C9@BY5PR15MB3554.namprd15.prod.outlook.com>
X-FB-Source: Internal
X-MS-Oob-TLC-OOBClassifiers: OLM:2657;
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: /GY3WWn/PaYQsVZZTmQBe2VIwhHzs7MNr0JUbhDiaGxSU8LVvV/fuPQMxpwxowRL+Vf6eDTEedObyYgIxvrko/MCq3X2tRcdJfr1EFjfzehevOOY1AUo0z614UMUoI1sayvk4bcj0WvrmUX9KbcCCpPIVR/KgKjCdeDD+4utjPhvo82cRbugH16KZDVnUbPKnxxc5v7V2I0MfG9HYg/o8IMZxHN6cRVxpkeIqvLlUxXYPoOnt7W+guGlLgAZUYci/ReL7EMty5F7w9LRXLI88mS4rGmvRQI8nxxxL2Hbunqde6Ka1yUO4ocJVnvayBf92ODZ9c5dPcj1JSI7yq1yliCUSwmaaInQLR39DX8tuYbpxmPTpgmPMvoR0S3AMRBdjHuIAN3GO/sL2T/FBrD6AHMRRSQpo7WwEbsxr1VJ/ocTJWhkZcOkemuK1DmPYUA7MCbKLbaae4zZ/z4J5PznILL0xwJFMRV7qRF47Vp/LXQKJ/izC2t5NpJp0dN0mULT9caZzG28EYEwLE00IoIG2FLCwK1oKxnuXuMtAUdlSiatlw9Dl44enCdFpGPj5KCVSEXRGeDzKhNw7DqIfe4dEZfG54XbivSw362phcScHRLP8fe4MytdyCBa+FPpin1fLgjnS7r63dOr7rnVvn0XFw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BYAPR15MB4136.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(316002)(6666004)(66556008)(8936002)(6916009)(4326008)(9686003)(66946007)(8676002)(6512007)(7416002)(38100700002)(86362001)(54906003)(83380400001)(52116002)(6486002)(186003)(5660300002)(6506007)(66476007)(2906002)(508600001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?6GgkgfCCKqKmv4tPGOBgrrlczG4hSFYXU5d2IAXXFJhvCWYSvU8uaKDZ19FQ?=
 =?us-ascii?Q?9WJnOc8slQEqVl0nKvFB5C8g/tr5TD54G3BhEuXKVUS60c/SJ+nmUpjleK9S?=
 =?us-ascii?Q?fBSUk9L7V72sBW+pFpyZcVD310yoAql0QvGcql9k+zBynS4YZWj87xVpJB15?=
 =?us-ascii?Q?KoNCu5wL5obuGbCPWx2F/32hVJ6z7NPa2H4Px+V5g+qNqSm/yJHXlMkpGQ+G?=
 =?us-ascii?Q?JQwpt2I72DT/5UVP9u5IYH9CAPyfCr41a6dxNhHJn2KkxpwI+wKm6YYXN6Nt?=
 =?us-ascii?Q?XQt/Ci+njba0osyfye/YmMSrB5DJoyGzBiKXmka+G8ifey41+S7GEahVV5sP?=
 =?us-ascii?Q?hGF8OYIWAcinooluQyKobln/Pc3BGIDczr14jBbCaTX2PLrJ6/EO0/CQdrYJ?=
 =?us-ascii?Q?MWi7Nw061IkL+J5yS6KZr2l5pqPDTlaMY1caTZOovalRaWsVTUmuAKBAUK/H?=
 =?us-ascii?Q?zb2v2JPHqUPOZUYrP7c/osuKlNX/q3LNYJQmdXRyjNv31SepKRLoU8/ghhdh?=
 =?us-ascii?Q?Ns4vCDbJThM+sunFYHYKQ9u69WeogK6eE0QYbNvxSFNh7oMoc9BIdmLqTb8A?=
 =?us-ascii?Q?3fo88OCgMYJVTnKschwM30wSDLBDrkYTeSWit3caBexHB5D456mULWWyO0c/?=
 =?us-ascii?Q?v3BYRCFja91VhM8gHBr99jbvAohn8/HYUMOUGafMBm2k1VzZ8k8X8Wi3YLjt?=
 =?us-ascii?Q?loCYvGnOcmS0SkIJBh0SfsR9UQwCwq8rx03Qi9MUY8bVV9q/8HlJi6JXIAik?=
 =?us-ascii?Q?JuTqr3H+0pTcNfD1GwEtoRmWggBZ8zVS4B0idydnsYsrMbUd0ae8kZFPb55E?=
 =?us-ascii?Q?FTwNt2tw1WNBxDZXLqgAdfKzGiqyIMkwwDMINKdWf9B7lAZt1viI0xlh7gVz?=
 =?us-ascii?Q?QwWZ4mUxGJdYqmUZQX+kYjwiSztb0GX/+DWElIEH/hTRQPdbITH19x0IGnzN?=
 =?us-ascii?Q?67Vg/i5B3Brc09lnKgYuqa3YUGKH8/GS0c00oq7/FfokUpkfktMAWVBgV8sl?=
 =?us-ascii?Q?s6LxNJuUkzYRIzEeVbVrNgftpLvJxRQwf8prKJRhbKTlCCVMLN5EYJsO5Xaq?=
 =?us-ascii?Q?fhRhb23JoOzSKrMrqat3/8fdZ5sr++S10i4t/NNV4GcdkEzp8/MGg+49mrBn?=
 =?us-ascii?Q?7rM/C5Ft1jh0Talr/6e3Tt5UyBrU+qTIJwPOMKpmcEV7+CHUZ2AcEWBlPApF?=
 =?us-ascii?Q?HLU/lMyvAJWLzovgkaSoL/dyGmPp+D956+Au8U33SPxrjElPLpRLdGC8XOJ0?=
 =?us-ascii?Q?IWrV4h3NjjJnz8h5McJoE6LzKk5lwKhUaTQMsTk8lgbRGpQYEiQFem1DXP/q?=
 =?us-ascii?Q?yniA7bQLYGp+N0C+CnN+uKR/wFfIErWKBYZbckeTiBTMtY53kZeGO9BwNRLn?=
 =?us-ascii?Q?uSXG+RQaG6OrEgkUii/vb2r4m96t0vsnKGA/2x8jGDUj1lwmrzAvI+PXNh8P?=
 =?us-ascii?Q?2S8hb0vxIEeBWaff7Sdte3/XwKVvj9333cjG2ZY4LD2DUHaaUouLvDhNM4iG?=
 =?us-ascii?Q?Jrjtb7ELBmz7BJyf6A7mSdMO0AF5gj9o6MyP1vn6JZauOrCIVH9xsilI4h/D?=
 =?us-ascii?Q?K2keXaUBjLaA3U3i55CRHTbZwI/B5aSlWzni/LI/?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 0d72d084-6f55-4d0e-5861-08d9d0c9e19a
X-MS-Exchange-CrossTenant-AuthSource: BYAPR15MB4136.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Jan 2022 04:06:14.3190
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xBVtgyoZI8Rhdc/cxokYinoKht/WjRHC50OPW/1aDNpYaIMQRiQz+y68cGVhY6Pw
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY5PR15MB3554
X-OriginatorOrg: fb.com
X-Proofpoint-ORIG-GUID: Gr-aUUI8d1W4uhnPtpm599II27EPB7Sx
X-Proofpoint-GUID: Gr-aUUI8d1W4uhnPtpm599II27EPB7Sx
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.11.62.513
 definitions=2022-01-06_01,2022-01-04_01,2021-12-02_01
X-Proofpoint-Spam-Details: rule=fb_outbound_notspam policy=fb_outbound score=0 mlxscore=0
 priorityscore=1501 malwarescore=0 suspectscore=0 spamscore=0 bulkscore=0
 mlxlogscore=805 clxscore=1015 adultscore=0 impostorscore=0 phishscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2112160000 definitions=main-2201060023
X-FB-Internal: deliver
X-Original-Sender: guro@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=Rm3USUjb;       arc=fail
 (signature failed);       spf=pass (google.com: domain of prvs=2005fbe8c5=guro@fb.com
 designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=2005fbe8c5=guro@fb.com";
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

On Tue, Jan 04, 2022 at 01:10:39AM +0100, Vlastimil Babka wrote:
> From: "Matthew Wilcox (Oracle)" <willy@infradead.org>
> 
> KASAN accesses some slab related struct page fields so we need to
> convert it to struct slab. Some places are a bit simplified thanks to
> kasan_addr_to_slab() encapsulating the PageSlab flag check through
> virt_to_slab().  When resolving object address to either a real slab or
> a large kmalloc, use struct folio as the intermediate type for testing
> the slab flag to avoid unnecessary implicit compound_head().
> 
> [ vbabka@suse.cz: use struct folio, adjust to differences in previous
>   patches ]
> 
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Tested-by: Hyeongogn Yoo <42.hyeyoo@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: <kasan-dev@googlegroups.com>

Reviewed-by: Roman Gushchin <guro@fb.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YdZqsLd4Ee1P2ITQ%40carbon.dhcp.thefacebook.com.
