Return-Path: <kasan-dev+bncBD6LBUWO5UMBBL4EZ3CAMGQERIWTK3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C7C5B1C9C4
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 18:26:25 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-7075d489ff0sf2139316d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 09:26:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754497584; cv=pass;
        d=google.com; s=arc-20240605;
        b=fCmk5wdQc3FWlmHRr2gcHwhzHXZ+Etfm6AMQmfGsSD9iZC8BkRddzouPbdJh7C7C0s
         Hb7LInSd3eRX3BaoaP41HxFQ4LGiDWBzD73RF8FP8MH/fT1cYw2R6K+qCP7Ul4q+/fO7
         TzBIit0iAGLUWYp+/Ee/SL7Qa37eVnlyyOrAIuUAfmAbILjnlJGhSGz2LELq1R5UoAcx
         I6WUK5lgcc7LLjjkcC0Swk/gnAuXau1xRg3aCvstTjVB92M0AqxWtoyIouwyXWTmQo3t
         MRXvbl2IpWlSXKLp/u/Iq0VK1I9RWNbWqgbYEvbY0zSlGbI3i5IMmoiQKoGo+LH2h5Ot
         m8Sg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dWejt8J71lAEBLk8U0hjF2iPqx1hVSdwSXkZ+Hd0B48=;
        fh=9Lp1fw4XIO7WZyjKWA0+Yf5+sz5TeiZXCL9nOlJmdVQ=;
        b=AhJtaaLkhShTXSu8oOLynn4u7kwjbO8mgxJDL7m2kQ7e8jwf006Fwm0Q21ihc0+uFJ
         0xo7Vh4J1VcWG4VpQxhZ7Gp7ypMMKnxOdD7D4NESNft13vJ0uOTfsvp4dmBEHKxvOsE0
         xsHCF+1wLWxocxAR3EmFmBgE1V2STjKsalhgzQXlQhnB1M+T1aH6k0fbnf7MKzedkiCe
         ya7Mklv1xh9DISl9m7lMTMDUEAVAqdZ78ZKj/+if9cMdx+YOcEW3Tc3U+h4hp3UvUmSV
         tS+V5X+w0tMJbmQDJ/X86Yawh3hDqei/zL+2AnGZMvQRLk6WWnxvmVdRB7uKpgaIZjL2
         OHcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ursc7H1b;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=w8YyMCrK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754497584; x=1755102384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dWejt8J71lAEBLk8U0hjF2iPqx1hVSdwSXkZ+Hd0B48=;
        b=vn3iGDVgXQqjq8UmOUVFM4DFYEyAIILcbBuJhHM3VUf76BBPWKTouNVH36YlaN8PqX
         vLWYN0JGInabX2A0zdESUY7dD+sVVPZ/azo1H8I9IF0UrboyfzTQ2f0kYMbHOD8TyWex
         mPhHqUPbLxKKIXoZYgM5QfSpf4klzL+bgByG1UZr6sxRGfSNaUTE5ucfusZb77hyQCfr
         XOXMwwwKAy0hgn848hiRM038oQNRK76LMATKT2RSIldgEotHGo9TZKuaS0qgiHgGfyrg
         RfM9KconK7DrUqMb0B0/gqSW+NfPLj7e/H/GsbIt8rRCTtRLG1L08NgeeXBhT3LSTfSu
         jzBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754497584; x=1755102384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dWejt8J71lAEBLk8U0hjF2iPqx1hVSdwSXkZ+Hd0B48=;
        b=PoP1JI5swdxOv2mNEaetaTxMrloX0pwaGl0T2lsuQTm5EB+sas2ChndJCBxWmISsgz
         36D20SatZa/8Xi2OIbOtTlOBRoKbncWZ7ILNkammA4hE3mWgee4SXGzTtD/TvrK4lEEu
         n8uTbF/1ogVsj2My4YVSBVrqK0N/yk4SoiOIZQ6qELr9MbqzrM+al2ou06RAtH3hyJuT
         K2bHGOOZHfcX3Fys66+l1HJUrrfuvRMy3BnGK2XBGe2xw3ClxwBAKQTdd+CNR4xnv/HH
         tyMA1mTiMxA/2LN/UWe8EYRc1kn0uvPJuD1bGVPGCqZGPX9/FXWH19gUvlBR4iMZNkAU
         oF2w==
X-Forwarded-Encrypted: i=3; AJvYcCXtHi54CTCLFWjYjvEnf4cW+cKEuOfQFnx/bfDFXOtO4DiSfqX8/RPmHUtX4s01fr/YtW408w==@lfdr.de
X-Gm-Message-State: AOJu0YyxE8Od9BrgyUVAC4/Rrlq8Y34OnBxqjC4gRQYVKNzb4enqC5Lo
	v2aihplonF+n6ZGKMklC8i0XQMXgn2l02Xq7ssrpAHS6cbS8oamaQmoJ
X-Google-Smtp-Source: AGHT+IFFxOOe7yJ7mNGkbVLlvP9a8rrAyh3evZku0AAonv1kWEUHU9fllq7e2mwUhjbmT1FJYLZqyQ==
X-Received: by 2002:a05:6214:2a45:b0:707:43a1:5b0e with SMTP id 6a1803df08f44-70979529959mr51816426d6.10.1754497583683;
        Wed, 06 Aug 2025 09:26:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYKZsIPgdzn4f1Cw1CnRs64rcispa/yHAJY3PF1J5sFw==
Received: by 2002:a05:6214:2686:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-709883bd08bls3077906d6.1.-pod-prod-01-us; Wed, 06 Aug 2025
 09:26:22 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWAN+2tfjlrEOkl19cM6xGRf/3WunMMOOOcO1NqdMmF/mU/ooiUQo/rQ3H63Qury+YOulgI1/+iY3E=@googlegroups.com
X-Received: by 2002:a05:620a:25d0:b0:7e6:9a29:eb68 with SMTP id af79cd13be357-7e814d06947mr504818685a.11.1754497582286;
        Wed, 06 Aug 2025 09:26:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754497582; cv=pass;
        d=google.com; s=arc-20240605;
        b=WSwc73KUpoumTGed+oxI854S5gjzxtJyG7iygAu2Bhw2jtUZ3mpj64A0libUEEctHe
         XhSYPelW7gcRjUCC3KCs6zZW9JiVZE4u9ks5mP3+BlTidemPk3xY9TKwKPsU6ugxzxHj
         Hi8NNo6BGRnPZKdfdTR/9fu8UMuX/9LBtGuWLN/HUs3uMSkvse533gmvLRhnbYfCHV5g
         9jJ0AXt10GroHMszlxpzW9wdhOv4JQQyKCwx9etWkTqQNEsxcnG7HyZOA0VwLqjKl0kW
         h8ouv9F3hLb9aPnUqU4kWliOz+xbsnZSuiicSMC2Rq9hXP7evjoYtnriFjVXZFjZ0LDp
         8yLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=CB3DRRvq0WYZw6RJtnoaMTnJWrzV8Qu4Aq0zOTZ6kOQ=;
        fh=bujRNrMc04QrPd8Ow779kXzmhqG5dcLQ+FL8SWRIYvg=;
        b=RJBgnjRcQb1pQRY6EKwzmTflN/7votW1+hpazH3Gsf98ndOSRFRzX9Um6X3Mi4hgWR
         o0jPBpvaBN9eTUQfVf/WyRIzQ3ujO/hk2qWfkJbbaDzshwuLFNXukNGpB6mAngZJlDF3
         3NHvR3T9Dg04q/yWnKY8EiCXkNs+eQHEf+JBhw+Za+iIpiuPlf4Pua1wzmNluDY3nLmP
         Z13MYBfc6zqSRne85PImwaSecYat+RzXy5HWAv7e3cg+GNCJ2+YrILbTb4XP6C0Tkxg9
         +Gx4NZfsTaldhVSkOdj/2JsaD6WfWJGAK/EFhTOJTIZbP97HAmPVQSh9bB5jl9ZQy/lP
         O+kw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ursc7H1b;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=w8YyMCrK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e7fca5a83esi5420185a.0.2025.08.06.09.26.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Aug 2025 09:26:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 576CRSrZ011407;
	Wed, 6 Aug 2025 16:26:18 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48bpvd25ve-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 06 Aug 2025 16:26:17 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 576Fme2k032091;
	Wed, 6 Aug 2025 16:26:17 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2056.outbound.protection.outlook.com [40.107.243.56])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48bpwqrvv7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 06 Aug 2025 16:26:17 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Jm3yXXI8pRkW02GF1I1PHhSCkWtYit9iRPAKGNek8/25ETd5ECtvQlq2dWjLWTE6DJuWZkXMtSc6qTgEh//tv0ffs9vhRkjYYgJQDAZEk173Jhm9y544wekWc4SnfZ4aQ+D1MObOxid4biC423RfEiA9kKJceRnwpa0S5ffBWUlTE220WRZdAFwvKdTBhnwMJ+gb6d7VH5HYAaF6ORC2KVYw9ASh1jddNfoC3TvpGMIh7Y7HNuTG3qDZzDc+RD/BcQLlpusVF26MhziNqso9shB2LLBjcdHB0zsc+IsK3o41wELaDDcH9CLs8wKu26pfqrIrI4LEPhod2tOX0EHmWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=CB3DRRvq0WYZw6RJtnoaMTnJWrzV8Qu4Aq0zOTZ6kOQ=;
 b=DsZYocZEqTTj5Qmu8WV6+smRFmRAMIvJ5+hMDLKkv5vVPXMi4N7qFKWryVDEbEf1w/xdNluvVv1iAEz7G7vNV1guvG3t3ZiPi7pQtLXMuJqNMI4+bml2rD5cxSaGwJmxofDUUe/qSu4Amc3mK2cWanQErX97FmxbkeQ94I2S494h19WsHLEYMdzYxvVevPWNtzIf2LZav9toEvjeNKDZLiaVclb6IGrLqOpoVDQ26rkj7jMZhLlzs5wL8IyX5Y3Hp2z7hZpKVH2uLVXa3qPW3tsERotrFEXMYR9FRcv9whxVLAZQvAj1MBAAXjH2BGG4lSkL+Nv07taoaOS7KymErw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB4624.namprd10.prod.outlook.com (2603:10b6:a03:2de::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.13; Wed, 6 Aug
 2025 16:26:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9009.013; Wed, 6 Aug 2025
 16:26:14 +0000
Date: Wed, 6 Aug 2025 17:26:11 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: SeongJae Park <sj@kernel.org>
Cc: Baoquan He <bhe@redhat.com>, linux-mm@kvack.org, ryabinin.a.a@gmail.com,
        glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
        vincenzo.frascino@arm.com, akpm@linux-foundation.org,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <9ca2790c-1214-47a0-abdc-212ee3ea5e18@lucifer.local>
References: <20250805062333.121553-5-bhe@redhat.com>
 <20250806052231.619715-1-sj@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250806052231.619715-1-sj@kernel.org>
X-ClientProxiedBy: AM0PR06CA0141.eurprd06.prod.outlook.com
 (2603:10a6:208:ab::46) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB4624:EE_
X-MS-Office365-Filtering-Correlation-Id: 2f3a36c4-782c-4c91-a0f5-08ddd505f6a9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?tBge5PpSW92p11d25Yb4+Imhp4LA3PtVxoaFNpEuubKaHv0hY+zKC1HphCJs?=
 =?us-ascii?Q?4i1cN1oCoPpS2NTe5ie7dzVSB2zNia+IxjmM9xWAWFuefbpPYJmIhGnZrkO/?=
 =?us-ascii?Q?V78VzH3NmlkJhaGJtXHlnlKZiTKrXk2/SF4Qpf1cIIusSrfd4kle8n1BEnJa?=
 =?us-ascii?Q?+5j7nDp7EbLF0kMt84o3VkyuubCVAEZbcJLOoEimpRhCLPkz5im0A6+BhslR?=
 =?us-ascii?Q?tMLjUmfxo9P86KG5zBdW1roLe+DO8Xkg5f5YjGQo70pW0e7Sk57HNU4or54L?=
 =?us-ascii?Q?FHJGwCwI1SdabTtjsjpNAK7mZjQLOR+oAyrcutYsLJhwPL6YhBrvCIgRldIv?=
 =?us-ascii?Q?l4kv3eyJEuzGQOrmee/F3ZZn56mQNc9bwCUo3GCEqpUrCt69va+rFdVoaSDs?=
 =?us-ascii?Q?52MFFuBepyP83vTZNJvZbiu5CghbZ7JIMmlmju0Inct+CRw9QH/SOgU0DzyS?=
 =?us-ascii?Q?Fwg7GtfUV/i4UlN2iusftzp5ADIHLTpia1lb64hTgHk1tT10hbt486hW9+td?=
 =?us-ascii?Q?/VIiTbDof/2whAICjVcvY6JQg6yLl+fMYoPDKP3WkIfszeiOzc39/uqv2ZG4?=
 =?us-ascii?Q?5waqM9ertUxnTI1Q+MflsLQRokptWucpbicWNMLTZ6+PSZJdmfcqllndigQb?=
 =?us-ascii?Q?gSbTqlPQ8VK9hbNfqvYmltBgW5vavnotuQo57S/SVKk/y2aGUJmHrP6x84EW?=
 =?us-ascii?Q?gKP0Eh2Olvi6jMvybbGCSwzaYNCsDGiPsxc/FV7+PJZYMm30IZE+ReGmhaPl?=
 =?us-ascii?Q?32syR79oJwTrqJaDmNOQihs7ciWMJj+KhrxnEzBdg9hTvzC8IJPuaC9XdmPl?=
 =?us-ascii?Q?Xb+55cpYPdMVovnTiMDnLbBLYKFloBanFF8rEnBGfFcDvzWruMrDqI7XLW9P?=
 =?us-ascii?Q?mkGsMD65J8pSHjlw7WA75VtOrg0L2vZ1bDFrUbrbM/BwkZR4z73SKGL0wtY4?=
 =?us-ascii?Q?KBUfX0UaNtRyOsnr7IPdSlVvwBuaExH9Tm99lECMgB9mPoVc8biz+fn2Jy5W?=
 =?us-ascii?Q?/w2T2tsLupq26vFl+MIu5+0Wtmk023vANW3bCE0VDPZjqR/2aG0V63K0ybgp?=
 =?us-ascii?Q?D0A3fKyBREBLV47kaALlcTkNWIhWq3ZbgEf6veUZcysge4HMvo00/+pllokm?=
 =?us-ascii?Q?x0LOgDfB3+dJK3G6XhNgS+drcpgYdrap/lWkwSnv1xqMX2UbZcVtcS+HKV/+?=
 =?us-ascii?Q?HpzJYBkeURs4KJnYtkeKAOnyOxEtmBELry4oAs9FRUdLqsaw0gz8wd+YJPh1?=
 =?us-ascii?Q?ac35pByUXRDGTBt3HsyeXiyIBNznYQ9MsKIkSKlFzRUmvEubCUKq2bAxhujv?=
 =?us-ascii?Q?s20J3jC6HOKMcEu8FgGFyVVo3GNSgCUS6uWpDpwedKFyuqW9tyx69p5WxCiI?=
 =?us-ascii?Q?yI/+pwI0P2UwZ7femN8Hbmo6I+L/qVX4k2QLm5Dwg3bKXtKq/ruT4YDXPK8M?=
 =?us-ascii?Q?o0GTChYREWQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Id95/rEslsCdoAIYt3yuSGpnAV0MgVNzERhIJnorfUnfzfDztalU+nREsRr6?=
 =?us-ascii?Q?djibZl3+OhIK6qUuBpgoGN9yT0CHymjcwLeagdOjwbLpLWNkEKrmf1dXKhVX?=
 =?us-ascii?Q?WyiSXmrEtXXGgjkerEtCiZNdostzQAJdAbH2H18yE27YtdUflCM1yA1CmOSV?=
 =?us-ascii?Q?21xWtmnhW63hrL1FDmgsgBfnBJshYz1Jk8FdEcKw0jUqrhhecPUzbMkevqN3?=
 =?us-ascii?Q?lFVTyWa2HcX4RG3sRNWoIFPtwqrDwt5Vb5dUnsLM0BM61tklC6zvPpf6mA7l?=
 =?us-ascii?Q?8urHAiAoSIzssTDVIn2zdP8LVg0oszwXsYTLTg4XOqW7CTRWUgUSzBNWF35G?=
 =?us-ascii?Q?Lbz28KLYKCsqEvzZocZUl0ZP+bf5E7ICWuVMk2/XJYM8dsJAbZ+kfFqjgH8D?=
 =?us-ascii?Q?AsoGWKmTlJJjk/aEp4xJSFUu/cSbsacKvtTSpxGxM8nzvDcPMuDx3LAHRkP6?=
 =?us-ascii?Q?UGf0rW+tSKBKUzPIu6qVJIpM1GMAJQ8vDh/PQH2yZWKl6nuXh1zl/Z/Tbq4s?=
 =?us-ascii?Q?gXfD7/lqZE3oPXBY8fygcxj5LEMm67Ry8Hz9cjcPhguJiN/w++j0vMskyUZG?=
 =?us-ascii?Q?+0RcqmiOv0iAXBptweKZVx2zidUwzx8h/2w4uswpI5signiLTiQLSme1UtIx?=
 =?us-ascii?Q?jV9QlBwf+CuTwwEm+8IseK53OG0/ib5YFOGgi7BPIRyTRk8dL0SEY2Ou9Umd?=
 =?us-ascii?Q?T9G9l49q4VkaJtUWz42EnqqsOpRqtFEa0m9tsQj3p0dWL8og8A8SHEqpYuae?=
 =?us-ascii?Q?rmueXoliq0MRbLKx5282tJEUvprcPGyy77o3/Q49R1YLe5GcuRfa9Emk3TUo?=
 =?us-ascii?Q?nMqoBLv2sXfl7HkNRot1Gy7fWrpxxk5R7i5AbPx/yslql0MzLIl4fE0BsDMO?=
 =?us-ascii?Q?YEgWj4BMA71FcqtTSjBPOykbeMAvj9cm4jSOYO+N97Aar3aTjmXry/5rfq/6?=
 =?us-ascii?Q?HIRbExg3faW4IYWC+XDH8s4oTjlB7pxM9xdnZeZosTgysDYfQ7fMnqwXF9Ar?=
 =?us-ascii?Q?R0cWdRwAX9q2htfk91dL7AuhsjszqdX8waxvAdSz2Cnkyovf2IZwrmZ8V1cK?=
 =?us-ascii?Q?iXbkF1OFoHZRpzzKbLq9knrquwk+Mdc+XPqU1EBsncK7pFw+6KPQYKQsertA?=
 =?us-ascii?Q?xg0hONx5NhW7adJ1lXE0mq3wYAOSfEDppJdgO+eB6H+MK3rW5vhVQS3mkGtF?=
 =?us-ascii?Q?F5A0gqPH6x4e0aT8tX7A35N/XoURSa4E1z2gnMGeaM0ag2PSaYCoNoQEK8mN?=
 =?us-ascii?Q?JXUk7ZjpCcwm3tePDx6Bd7k2YIcN52VpeJjsvSiXBN4fwJpv7MFvwCHqdiN3?=
 =?us-ascii?Q?MUlljqCo+xJ7sKFiCQRL+fzqu5RT/8VogT8ZyNRsw1H+QIUTrWK5dVAR9BUr?=
 =?us-ascii?Q?/khcBTL+FEZZyTBLGIJTJrMnjg5zb7z5YfeHIrPNgAy9x3NGjXnUCtSqLNYK?=
 =?us-ascii?Q?XsoZGXDhSwl812zJSz5xO9gTSlD96sgrOHGTVjWk14fuMrz294LT5/UyJu+G?=
 =?us-ascii?Q?YlUgrs4B7YKlb7SVLL/D3UOJSFDtFjBYvD+8y0JPtkUzIjNq1zy3lMx4A/CS?=
 =?us-ascii?Q?CPqxaKqZ11um/FqJ9ngEfxeGco+oIJZSpmHOv9LWbNnTChZhJoayuB0erIHI?=
 =?us-ascii?Q?VA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: h76Pn4S9xXgO6n2P9YuCqLpeOizllFSCwtE5mZ4dvoMF+kPGyC72GyYg2yTW0VgaE4QTsdPdMh0WRBwoQQFz96BVCU2R/bWyJZEHH4XW50bNf8b2x5nf3kw4DgENfft70+FQkao8Fsp43HZOFZ1CCGCPchwhY3Aq/Ih9bfwZIvu4vGArMUvPtkY2yKie/vbx4ZMntKGVC9E94L8Mpkd+9reCvXD+18EjhxsVnqnDKFz+ECom3ctjcqS+oMsvQ52jbr8GqGSRKy+qCeMdOsv9IBjrMZuFYW+1lLxWyl6X3+5j/aO3FI7ZPDitELaVy3qQg0KiednJxAhARRcGE+xqRUD5wQx2HX1APvF5hpEOWrTm+UhYK9Fu6yJjnbgWZ8mzUgyaXaRd48ECfb0WkVtTr9ulO3PG4YAEaKyH1TexS4+fFLTBeV/1v1Kx2aDO945zkelr/2oWT6PilTvrVV0szVHGFp6hnVnXVIcJWH+gmsRuEpalA7akfb0W35sttUblbySDjZ399KcfWUCtx6NfGjb4cASWokgIhSE6g4eJuaQ9eZ4pYWIklp8YkWSEZA0yp01aPNYhHwb9N1yicknfNkYQ7i/Z+sG7KGKf1uJWsZc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2f3a36c4-782c-4c91-a0f5-08ddd505f6a9
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Aug 2025 16:26:14.8019
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: aovKUaDiyUfn8VXF6zFOG00PpNOsyPaANvTThDHxl6IaqUCyfE1z1KeyJlHpuxBYytJkVIXT296y4GMYOAezlBWwv5o/BptL0OAHFfuJqZg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4624
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-06_04,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 suspectscore=0
 phishscore=0 mlxscore=0 malwarescore=0 bulkscore=0 mlxlogscore=999
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508060104
X-Authority-Analysis: v=2.4 cv=fYaty1QF c=1 sm=1 tr=0 ts=68938229 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=drpxK5Sr0r6PeNfVfTEA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13600
X-Proofpoint-ORIG-GUID: K4i3LfeUPhF_YeTrkIEVoGyc6RjZNKGk
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODA2MDEwNCBTYWx0ZWRfX1AQWM+IHoKGb
 ramUCgExUGIELWydClJC+UNG06WmWAUFFHcwiPXGXKS7+8t1WQ4LutP6S6DW8PCrGaKhtJDFOlG
 9cb1T8pQ95hAb/ecLfk31rcgWtsmsgVebPBRslAGBdVdg4Hrq1XgAtluctnnuUvcWRYtZXG0hzU
 CHxC6CoWLGihu73S2UOqda9qfmoNSrXYrKZW0cAS+m28KkTUm4vyVci30xbohZ8sdr+4UBTsIK7
 FOJLU3MLqijZkKcapejsUfQoprFcdCEktnh4DgsTTj36YxlSjJsiUQpDyOeidHFVNT7M1oTOQyT
 IDBmP0TIGEC1X03xMVZY4F2PXQ2k0SANETZRLe+5+qx9JswVBfyT7TQA6kDVSaYf8GNoSx1KNH5
 XwewumQLjKu06Rdq7NyUhxVXY/z9Jxm6cj4tnafk0VeIBPRBjs/mCvaGShLgKHX70BHzZ4la
X-Proofpoint-GUID: K4i3LfeUPhF_YeTrkIEVoGyc6RjZNKGk
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ursc7H1b;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=w8YyMCrK;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Tue, Aug 05, 2025 at 10:22:31PM -0700, SeongJae Park wrote:
> Hello Baoqua,
>
> On Tue,  5 Aug 2025 14:23:33 +0800 Baoquan He <bhe@redhat.com> wrote:
>
> > Now everything is ready, set kasan=off can disable kasan for all
> > three modes.
> >
> > Signed-off-by: Baoquan He <bhe@redhat.com>
> > ---
> >  include/linux/kasan-enabled.h | 11 +----------
> >  1 file changed, 1 insertion(+), 10 deletions(-)
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> > index 32f2d19f599f..b5857e15ef14 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -8,30 +8,21 @@ extern bool kasan_arg_disabled;
> >
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > -
> >  static __always_inline bool kasan_enabled(void)
> >  {
> >  	return static_branch_likely(&kasan_flag_enabled);
> >  }
>
> I found mm-new build fails when CONFIG_KASAN is unset as below, and 'git
> bisect' points this patch.

Yup just hit this + bisected here.

>
>       LD      .tmp_vmlinux1
>     ld: lib/stackdepot.o:(__jump_table+0x8): undefined reference to `kasan_flag_enabled'
>
> Since kasna_flag_enabled is defined in mm/kasan/common.c, I confirmed diff like
> below fixes this.  I think it may not be a correct fix though, since I didn't
> read this patchset thoroughly.
>
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> index b5857e15ef14..a53d112b1020 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -8,11 +8,22 @@ extern bool kasan_arg_disabled;
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>
> +#ifdef CONFIG_KASAN
> +

Shouldn't we put this above the static key declaration?

Feels like the whole header should be included really.

>  static __always_inline bool kasan_enabled(void)
>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
>
> +#else /* CONFIG_KASAN */
> +
> +static inline bool kasan_enabled(void)
> +{
> +	return false;
> +}
> +
> +#endif
> +
>  #ifdef CONFIG_KASAN_HW_TAGS
>  static inline bool kasan_hw_tags_enabled(void)
>  {
>
>
> [...]
>
> Thanks,
> SJ
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9ca2790c-1214-47a0-abdc-212ee3ea5e18%40lucifer.local.
