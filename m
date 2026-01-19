Return-Path: <kasan-dev+bncBC37BC7E2QERBF6QW3FQMGQE5LXMBSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7125DD39D34
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 04:42:17 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-c5291b89733sf2134744a12.0
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 19:42:17 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768794136; cv=pass;
        d=google.com; s=arc-20240605;
        b=PfBBmxGJKIyhWz9f6BFUP8U4s3Rhe1X9Mad7rFDdVNzOam/qPavKmFPAvERlw/7sqr
         1/ex/3rfHK2ouLfYllb0gbSs03hwHWk9kMxnpfnphuTU2zT4ygWoWEn4lmxegC4dEIDb
         X9q2JLnEYt9qn9iHYX+YT/GewHIaW0RAgEPSGO5XoGTB7X+1XPKaXaAr3dtr87CxtZbj
         0o+CxyAZGZYuqqYymSiy61SJfaVa6aT+GHM294kFrnaC+RuxEl9nDTgF0hXDEq+Yp5ix
         T/3/S/iZEmoArEfYUi9BfyZhXF8CqqI06mUjNPlFOJDGhKJJhLOSbTxs3VDm7NCyyBbi
         WJaA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=UeSSCUEwaRXErOfJ6m4cMVgheuMtmH3yABdfA4t5Wps=;
        fh=S+iBHMa/L2g4bzGPoK+X8899RwEpJ0rNTJNPIt/1idc=;
        b=H7Ypeci5ZEUlIF9DRhz9VoCkZ7Ydpt4MBTyZt2+RUS21P065M33qAbJLUq5hIJyD3e
         R49cWvw2TkZDuM1EEi6SL+tbxPrKDA/PqJ97ZX+xPPx+d915gi/TxPK5a3IC42ibw8ut
         Vt9IoKBIs0ORj9te9QKzPcuNwZI8Ro7L1ouszJTSc+lp47q+8RQxq+nCwerc/rAeSV2U
         7J//x93hGhcRvWe3QciJJj2QSwBQA8PMwcg936YTuE+xkol9AtGe2vLYHLi+3O11lAne
         crJ6jhcTUfN5utzXkVsYnKAFXc+tXZOdwmDVL/VfOAspKfcScVVz9jM76GbHBAeR0kJx
         cACw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=MqyMU4lS;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bEmtkisW;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768794136; x=1769398936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=UeSSCUEwaRXErOfJ6m4cMVgheuMtmH3yABdfA4t5Wps=;
        b=FXgpo1SMiannQSkyJNHmO02uTrzzYvCLpAN2S1R7AkKZ0BfYTaPXQ5shPr/BlZeT9L
         q630TYicCSF0FicKMQAI4zZ3noR/5DLIfjGAQyvB7B/4RDqEjVq6ZXNxXZ+ikgXT04xS
         ob7fgXCP2mtSmrKKsn5oaMzJTX+2pAk3DxXPOUTPBC/sgGEiFPoblT9tquiCremAXDPA
         5C9Wrb9SsO0AevJ4L20A1s3G0OBPU9N/OkfSZqIz3/F2KaTPa2/euRMKdeS8D8uSNm9b
         Ta8v/heP5a4HnaBv0F9UUKZe3XMM3ictQz65xSeHN38RHjHCn6Q09JKq4uppyOFGSRmQ
         n9vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768794136; x=1769398936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UeSSCUEwaRXErOfJ6m4cMVgheuMtmH3yABdfA4t5Wps=;
        b=kmJ+bA0gd684ZSM5I/ZRyGL97L3V8xBH82k0iYhGNHHHIVR224zfzo8w6sjfRmcRCy
         n7SI91qx9jHye1v4XAxQiOaZ6TZwfjRTI2Y7beQjS0j8zNF6827o5i9dMQPT/RaER0LD
         G3DqKOpEq8q0v0y3QbQ1j2EiLSjY6IGTJO1diUBpZtjRi7aLq1lF0LlK3Zon/0n/q0wf
         oPP8+q5+FCfobluX/BsEo3fgERHv5YVZusGoHH41tmRAq0267qXz8eriB/W6gDW6ciiD
         jAq/Gto2tO//QNfr7z5glBDm7O8qQW5XeIL5kMNAFzK/0R4UDeiFyKhJ1ds+5cSh552P
         HTrw==
X-Forwarded-Encrypted: i=3; AJvYcCU8RrUxWupXMEIoyXxUA0i4a3JtlZ3Bc0VzaTkVlG7FXqjM/PhEy8DBHjorKPxKTj/r53zflA==@lfdr.de
X-Gm-Message-State: AOJu0YyiJQSGqKPwpMrL7IaLME4Van6Xg4V87MfdNC2yknBrHW8FK/rW
	uYXN5m99v8zIIY9hchuiPhBBs5+pQnttEoLMphLWmuhbDHMRNS5QUnFH
X-Received: by 2002:a05:6a20:a122:b0:38b:e944:3e90 with SMTP id adf61e73a8af0-38dfe76e215mr9050679637.46.1768794135512;
        Sun, 18 Jan 2026 19:42:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hr/lRvkJcrcoZCV5Yp3VF4wLfyFeHnlS0DjWk1uFzYaw=="
Received: by 2002:a17:90a:1656:b0:343:88ae:9518 with SMTP id
 98e67ed59e1d1-3526871882els3331013a91.2.-pod-prod-07-us; Sun, 18 Jan 2026
 19:42:14 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUyif4t2qFvTB3SW1GYwvTTlwVgl2RSIo/zF7gqhPGTkwXsGzLpdC+P6n8VcFIbG8kocrTYoXXPUaw=@googlegroups.com
X-Received: by 2002:a05:6a20:938a:b0:38d:e7a1:4fb2 with SMTP id adf61e73a8af0-38dfe64d9camr9526289637.32.1768794133976;
        Sun, 18 Jan 2026 19:42:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768794133; cv=pass;
        d=google.com; s=arc-20240605;
        b=S7BZc7SBeowlcpx9Hj72meP2mQSGVYg+Xh11OzGA4BASE4G54LAYNnCxerxjy5P5ge
         BBIhnc+gBtOCzXMpnIRGkFW8E3r5tsXiO+T+TECDM5wVpP2BIDyZHGGvXr1AU7A0HWqn
         vHNNtetxx4vSDATmZkAc4AQvUIzxgyfIIzECPtA3JcmebHHzqADKml7alZuoQT2tUAXQ
         hOc/c7OhGUIXfGEmiJl0HUX6/4Ast6+iFofZ9DMzHSjAXy1HLI6qf7hnR70ksldD4qqD
         Ixd7tARnkLEPYeN2tokeT5BM738qo+uY6SkY43yBDWxwvjgHw975/lTiOtfWf8oOv1ET
         lOOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=/Qj3Yk8fgFeedntqP/d9uo+z8NvlNFkBmhmvZ4ONtsU=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=bnEIEd644QnrNdVz3rc3VtWwfhrQAgY11qKW7oXkXGHcWSu8zCiJeF1l8uoKAY1fN/
         +UX6BXrSybbL5O7sSOqWNJIeCv2g2ygaY0EMuRKFmjsHzjMn/72rXxns1xt0kV3z6Neo
         LN0/UkWeLphJFzM7bu/bn+Oed3CPHxQkuY+UM9uZAKc2p4bvE99kv6emPe/MbNnU6sSs
         mmmJIAlvKgBLpVXVHrb91gKljf+PZ5S+5uRD0MtYwxukBGOl6vixyeTN8D6Htcd4osbs
         GsjoD06C+LE7h3qriATDzzl5Kyy4CEW/OSvCa+G8ptvDAWLw3VAzW7XkDzamwxttc40S
         cDEA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=MqyMU4lS;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=bEmtkisW;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c5edf2ff4besi230529a12.5.2026.01.18.19.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Jan 2026 19:42:13 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60J1r2gK1183545;
	Mon, 19 Jan 2026 03:42:10 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br2fa1p21-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 03:42:10 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60J1l53T008406;
	Mon, 19 Jan 2026 03:42:09 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010067.outbound.protection.outlook.com [40.93.198.67])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0v7uq0u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 03:42:09 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XsfGQwk17qz7bpBiQB30IIJ15xYt2fi0ietT9BNd/YIMcVYkJ8dGJ00oundSy5188SDy+3w8jlptSXLifNHgAn4vX3n9mlJnJlpzJop0pTOthc/0A++6GGZHqlmVAaOsQ7HTJV3ochVPm2ogPZOiyyujevWz/YzJoi6kXiidOdrPtpQlvHPs+tSV1TbL6MG2rK7Vrnez9IutiFdkCP9sTS/T3jjYDSdyWnPdXocKEDxwxDQJPbYc5Y76goGxy5rP7IhRQB4L7KgN3EjX8fYANokUc125bJs8lB5jz4GvaQZOXJzZDftiYIEQiAGVO1Xll41fN7snDVy6mKJb2FmHXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=/Qj3Yk8fgFeedntqP/d9uo+z8NvlNFkBmhmvZ4ONtsU=;
 b=tzgqmfsER/bsoLO2VvAFO32AyGjrH+e06OPRpnmg6rgltwuhCpL5Bix5vWK8QNdsnbWVh+xVLomaaCakw6j4v2wR59nAnydEWrq15So42CB9XdtDjcfSTY4KUkOUXgg7UxL1HLsirSPT6TpYkHU+zC26H7igEH39P1+ke6MGf+BKyhUa//9hBMi3jVS61G6h7cE0TGfhUBVTQsxIqkrRuPPF1ooH1l57OzeRMpegkwEQBPYVwB1j0nZuDWAShMJSChS9k4/3V/1QVkj1oj23ruKyNPiXZS3W00T7SNFg43FfCC9WeSLyG5Nf8M+q+mOWW079He7vLfJhYWXwRsxIow==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB6635.namprd10.prod.outlook.com (2603:10b6:930:55::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.10; Mon, 19 Jan
 2026 03:42:02 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.010; Mon, 19 Jan 2026
 03:42:02 +0000
Date: Mon, 19 Jan 2026 12:41:55 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 02/21] slab: add SLAB_CONSISTENCY_CHECKS to
 SLAB_NEVER_MERGE
Message-ID: <aW2oA98AZYY_gC5t@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-2-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-2-5595cb000772@suse.cz>
X-ClientProxiedBy: SE2P216CA0148.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c1::14) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB6635:EE_
X-MS-Office365-Filtering-Correlation-Id: 1061569f-3839-4331-abd9-08de570cb510
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?fYBvZPKQx2vHCQUGdXttLkrFvkarw1FdtjjwwKFStOsNnsjvFVPhjVAM0fYm?=
 =?us-ascii?Q?t9vSKSNckHsJVJIxfR1aDDoB0zkJFyD0q07bk+2bTJ6XslSbM6F622jL+z1y?=
 =?us-ascii?Q?IV+xDBl7ryLvStntBcP7/hsZg8g6LbgAbUXLOecNYHarzfAb4cRqkNqeLNhY?=
 =?us-ascii?Q?Ck+VHq39wiH8G75xlMshxZMINXHp7XDtHByNmd41UNCI0CYb767+xQES8Z5h?=
 =?us-ascii?Q?fdBJWL0X523ZG6tnfFTLM4Q/CSXBpKMUucIYNP/IlPyPE3ZCPMwx9cRqMh6k?=
 =?us-ascii?Q?xkFSyTCYDRboXD3rQ7UBrgxP46/La4XYlssV9a/qRc/zg9jeC2S+y7/gtDk2?=
 =?us-ascii?Q?xJyuM1QEs6X+oz9zgykSfTKJ8aSei2IZh3OepCbCWJxZoFy0sIcKISipNoYD?=
 =?us-ascii?Q?F76afZTmRIo+GmkcbFop24Rn/G3fotFeDLgEfaGUNiww4dwlAB4ZbUtTtIuH?=
 =?us-ascii?Q?DYd1whFAesKWOkF3KpPqAO13xIAbdtUdTYFwQHX/RQwbsWtFm2fkGsPr/ZYO?=
 =?us-ascii?Q?6PVxkbBVSRnicSvHZmj3AIe2Vewd3BeIdmOhMY95AMQA9gSKolB02sdoVWhK?=
 =?us-ascii?Q?FZdT5QhYxoXyf8LHZsNknMBKR1eHGRRZIQ7dg7zjWRafd2BXa55h0Jqo6fil?=
 =?us-ascii?Q?epUS3ST+/UjpP5J5tfOyXnfE+UemX665yUqhpsibeK769c4kNfGtrZ5lnwWj?=
 =?us-ascii?Q?RzAWoqZbW+mA7O2B38pCifdV74wiJ6aBDreb/KYZxWVSgH0cjisbcQK8L5zT?=
 =?us-ascii?Q?QBKhH7X0qoMJ+WdgRyP6vaqRNGBm1jfl4NKZsnjGpHvhbGnZKiTaxYk0Eg2g?=
 =?us-ascii?Q?9O2DWCyusKuyD/JNNrYK/8AIGIkrYk4CvOlC3E1WjkdVZ6VqsYOi/y7hJg09?=
 =?us-ascii?Q?ZouADQXzPzGL060hns/AJ8fcKzKFyftivZFiCUNv9XGVN/cXiSWF2FKM+inj?=
 =?us-ascii?Q?p+3NMMBPY/VnFc/GWzmIHhZSeUo5pg1HlpW9Fe4cuToqRr7xycnMF6i9jACR?=
 =?us-ascii?Q?UCar9nnJcqrTARPI63YZw1GmggDQEWhCr/1jR2l5sXGaaGQ+YgQISSybrUr0?=
 =?us-ascii?Q?st4vx5kYiIj+JwW2r+6H7Keo74p3SCB2SxhyvZxHXo5wwhNePxBSL4Hp4i/i?=
 =?us-ascii?Q?BNcUBl1RtWU7o0EggQ8ZkNKhSLym4nZxHC5UKFnK2IWtbf+/04SGajI6cMFU?=
 =?us-ascii?Q?V2Q6RNC3BeOZJ6b/fkkxdPfEJGQ2CA5G17slmyMTez7LK+KCOlcPjJ3xJX6g?=
 =?us-ascii?Q?NLFdmBdbjqKvSUt1+jcRwCjXsrS5o/vNIj7rR/0qQgyqgvxtgoQJQZfmJeGk?=
 =?us-ascii?Q?Ufvy7vnc5upZeOr7pIu3LHqIv8Ru2LV94j20GHHuQKwr2jKEoCnrwNk/Efbf?=
 =?us-ascii?Q?5nIjoA1MjoU0ukB/nbMqPaMIcMFn5+HzTfbvfD/8zl33V+Ra1Pg9VtE7/tK+?=
 =?us-ascii?Q?1hGUIujyV4U8941qM0+P4YB0lb/zx/hEIGQiiVLyLlwjNghGoSs4H9T3I+Ix?=
 =?us-ascii?Q?CsxAypCv0ejq+Zo95RgDhOhJkEzqcTUwmI2LPWmxScYsQlV1iLQxfLzkv9B0?=
 =?us-ascii?Q?DxLJng81QHj55eOEev0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?WYJ9VdfDw36x7yymmhtO2/eMVYJJKp2R6LUpTmOA2j2aZHpmRFrYATySkh9+?=
 =?us-ascii?Q?4mZ8QGR+6YM3rt43Gxrv10S6iVzl/kOB11DJeXryKQ+LZNlS1AyTZFCji4LO?=
 =?us-ascii?Q?S4eUiQmo/ZjGgV1T6CTujL1nJLwl6zTHZUPSaIvh+gP7En9gm4ehboLMPT6y?=
 =?us-ascii?Q?VfoCB6w4aYjZe1ye6Cc6wROQfUXlwSoTRD+0Q9Bjg9oJxe6cX6MykZFjTQKC?=
 =?us-ascii?Q?XVS6w49FnTIicPjZoZUgtXxcDVsAiubxRwq0HvISja5uuOknwTPzdgLHEfDK?=
 =?us-ascii?Q?RXZ0c4PO+rtNWa3qYmGSHFA8iJetllgbd0ky2QqTLYsbigTUZJyexkPOMIKI?=
 =?us-ascii?Q?R1TtoAwgacrWe1H5yFsEbBjh5EYDSUbiO40yQRqrBI8P/J57qxLB1U/FfjF5?=
 =?us-ascii?Q?EK3A3kRrH46yys+hLCCkx7q6ucXpBz7HQHk8jbMHsztjAIcsuWPNlYGk7vlI?=
 =?us-ascii?Q?msK7/Hy+6YR7vRTRHpfACKTqYughLIjr4X9O/1ghIARJL2nkExGamF7bQyik?=
 =?us-ascii?Q?011U+nWy+x/FDK79xskg91whr3T+GDwoaJuVYe4qqDiqKs2ywGbKc4q4KXzk?=
 =?us-ascii?Q?RVrGHlnL5S1Zr+32Xrd194HHCMrKxiFeCAtx8KJnW3A/HAbSTTWN96RDSyq4?=
 =?us-ascii?Q?lNN7KCJA//IuO76O0McCZU6PNR6BK0XliDyCH4gEgZVCdi1+6m/B4KOKvk4k?=
 =?us-ascii?Q?YFYFbSUckhMLU9L5wxHjb/k6UrObwXxtimFZx18UJf39mLVSly06tqy14SC5?=
 =?us-ascii?Q?asFamQbDBCdUIPOh9lxIyxF/VcIp4HrE6o+znSwh367ZGYA2AGT8hETvOUmu?=
 =?us-ascii?Q?p5z23idiS0WhpV1l7WvuP4bSWPoDGYcCkfys2rh97mT10TWRZ01nIuVBDwrX?=
 =?us-ascii?Q?6qtkrO3+J2V0Hk77j9tpAx+kAvOllPVMDjEYsDgCjsqMN9T4Lj8GdpILyY7K?=
 =?us-ascii?Q?rMXqRe81MCarKfP7S6M4DmqVTkZpbOGfPhcQELq0N/TSGpZ0VNeU3G17PdG/?=
 =?us-ascii?Q?gih8JUem/WAIdhdlSWezW6OO/BtaALLUEeQWfvQf5sv7+L2j8ZEIjWY2U8u/?=
 =?us-ascii?Q?EHifj1tBsq0VEpQKr/qqpigW9BgYeNdtpNHuj0pNXx4DW4c20gjTZhG84y60?=
 =?us-ascii?Q?5P9KuIcFg8CMKP1TlBmAYKs68nb22z8JquLZWC8bMQxhzd3Y0Jwcz/oWEq5N?=
 =?us-ascii?Q?UanW/O1M2Zm6xp+zLVo38ppfqr61ScUJFpO9W5aaM3jzhdgtdlawln5KE7Y2?=
 =?us-ascii?Q?E8gZTQDHeXGTX0KcosRcOzxxOJrPPBwP9t70nW92sqcr2MVyA5pxvjnmF7zZ?=
 =?us-ascii?Q?nXXGGQfwqEAPlWy2Md30joVw+kxG7rmYbhtFEHDLZBlv8sGwvImn8ctwSYGS?=
 =?us-ascii?Q?8XJTroz1dJZQdQGe7pq3oZ4mXw539gSkh+KZ3JuU0iivvRc3i5NAseJFBlOx?=
 =?us-ascii?Q?rvEX0cU47U6x3Neqc27OLHPSXSy2HSc19lQkZIxYInytWDftpK2DgbcMiXbF?=
 =?us-ascii?Q?WmR4Veu/pEfUxDrzXDrHqf50ll1MjeqbPujuL5lAdR7o43DeSaWXEpiLEHRF?=
 =?us-ascii?Q?gC6I6UKBdbvc8aX7QlwH8KLmA3NXnSDSk/zg3gLKg/WQEEGhFMXjKCTewPQJ?=
 =?us-ascii?Q?bvKQ9qinMFWS4ILfNZOEAKCL8seotu/lLWYjrigZGfm9U3nFjfbTNeNdLLuL?=
 =?us-ascii?Q?R86L9BaqTQ/ti7q0jE+yAZsRNz1mxWSfIyozRvZQtvDOUe7AO2Pzi/JzWJ9K?=
 =?us-ascii?Q?/sO9YLqGwg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: mOvGbcjULls64Asot4oIg/jirIPVzr2b964RvVZZ6XgyaL0i93XAKCm6fmhkcOCaSB2VGbPT9S25iBP6hAc5pfCG3r+Hfz2L0NvC6Gs1jJp61/oQEJGYUtz5hgUVeocBVfLdbl55P/vsN7SIw+FNGtAhbaQHES8o6mCBJP/R9qe18n+qvSbrlAxecDtH1X60QCU6bn790AHKMGALl0Bie+PI6WsjB8dh6B3KETn0py73Q+owt5AbtQLjHPxbRpkvOCR3ThO3Vum93B2BUN8FZAWu6ze6EbLwAcU+GGR3uF0Ox1cn7JPia27FACl92fHfin2WIVUs0Ly6VLZDy0FlnsmcJelh5fdFueTL+L7eZTDISdfBzIL+nU3tCM8KfWoZ+bq27gad56LNDGGJbjJ7eNZA+6vx7eRgF8IQC2u2HKyo4F3t+we9G8nif2PPUawpGeVJVgzMs/v5wv/BRS3QUC6UzHGWTsEZuZnTrM39nIpCPPBBHnTtK8esESSOv6usA24dnzyiZvEN1b4TwB0g+DRF4hloF9DdbTsJHmzj88zgHJ7cPIRJrd+iPE+WxCwdrInNuUC9y+FDUrWlRy9phIH6UTpok6wS3r0+ivpjYms=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1061569f-3839-4331-abd9-08de570cb510
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Jan 2026 03:42:02.3878
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: x+F9i9LvWb8GR9dpo3D3keCepg5x0n/e+uHevhrqe9JCitYIGOvcuxb4tVLzRXuDbgKc4fncgVaajUex5VAGBQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6635
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-17_03,2026-01-18_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 mlxscore=0 spamscore=0
 malwarescore=0 bulkscore=0 adultscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601190028
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE5MDAyOSBTYWx0ZWRfX3iyTB72kw4Qz
 P+OwNINAfw0VprI+RBrtmxtk9I8ld8ah6Lfwo6+KQMvx8YC7ZRI3Zlz1J+2T3BcwWzRb1MS83km
 v9gE7D0xp234WE0I1pmrIYTkIjkuxdj5ZIPY56K9Vmd1FInid9HDC0O4nGSjG0rglq2xDII+/VD
 36ccez6jFnA+7No8bfHQcOkc3HB63b/uT+8XnALye6i+5Tp6GFO1eW6LCmzDCgPYGVob25/B9M0
 m+7vR45Dczb/GfbpJ/jYoHuJRXpuwS9P5rymPzk390Z7BnjH7fu5ZyIKwDuSD/FqZS1rj4yJ/GH
 uY7MuqTaT63yOsOCbDfmTbMYcRKVq7M4trZ0SySbDDCY9PQx+z2LmmaN6tzDZUhBdP0UGWN8lox
 LeSGUXW5UZ9UPY9ooe5Jy0SD0fyxo5OTVNwuPkPzyxJlh5MTnVP6VjiqncQYSasuFiaTIKS6Fc1
 +yE9RHGxzbMdpEuvjuQ==
X-Authority-Analysis: v=2.4 cv=HvB72kTS c=1 sm=1 tr=0 ts=696da812 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=tsyjUIWJt81gzSTrp9sA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: aLLo0fiRRvIitoO7PrtvpRkolNi29Fkk
X-Proofpoint-GUID: aLLo0fiRRvIitoO7PrtvpRkolNi29Fkk
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=MqyMU4lS;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=bEmtkisW;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Jan 16, 2026 at 03:40:22PM +0100, Vlastimil Babka wrote:
> All the debug flags prevent merging, except SLAB_CONSISTENCY_CHECKS. This
> is suboptimal because this flag (like any debug flags) prevents the
> usage of any fastpaths, and thus affect performance of any aliased
> cache. Also the objects from an aliased cache than the one specified for
> debugging could also interfere with the debugging efforts.
> 
> Fix this by adding the whole SLAB_DEBUG_FLAGS collection to
> SLAB_NEVER_MERGE instead of individual debug flags, so it now also
> includes SLAB_CONSISTENCY_CHECKS.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW2oA98AZYY_gC5t%40hyeyoo.
