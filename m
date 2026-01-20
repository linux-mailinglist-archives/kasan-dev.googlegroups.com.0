Return-Path: <kasan-dev+bncBC37BC7E2QERBZ52XPFQMGQEZXFIPKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id B575ED3BD07
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 02:42:01 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-65f6588abf4sf10870557eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 17:42:01 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768873320; cv=pass;
        d=google.com; s=arc-20240605;
        b=L8M8GhsqtjyGmyDNIfSlLLmbiQdarnNXeMlg4S+oQmGRofu16+mkcHRx4Ncg/7WhPF
         bVTO7FsqqEQDvXXiTCsxXvqNKk9+L4CCi7eTw9KAvaT8xXpbcePsKrsT497Xwl8/gxRK
         qiq+mhQNwlLlkT28ulFksk+jU7Y9HVoXGRx4CgpvCifc3y9SSPGVTgWs9S5YVrUIXICt
         dnYHMcZdSHOaZ45nqoVgeoT32JzsJUyk3nLlTGqXHOJlvn5BkJj+SPgx9QezLNmkPtNX
         YqLuPHfQk4XhAzPuT89cNVgiVSXrrJ5R0Lcv8M/XdO2pqvUWrmg+IXct70/n+k5gwY51
         he9Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=52TzXAyatMedwuPLgbGipmrnIAVEur9JTHQWGDfbC+U=;
        fh=lt1IuIHGuT0ZYTzNziVvGwUHZGP5UYrDip9ZLeMIzZs=;
        b=eXJdoXee3R9h0QisCXAtSQEPscy5P8DEysD8Ihi+L9onaaQWrijouYB3ennHxOsO6a
         xCUyqtIlrztDttyHXmbS3gFCcqn2gndmCZG9Mr9Vdj1cOjIYS4OVsbkjkHBcVSDkZAfz
         X6K35RYBLGzFkJ89sEcZZV8YOtKkNvK6OCDcPTTvxeXdQ0EnBHkPfCm38zSxWrug+ej/
         DU2WDH6tFmEujMDjGUlcz9qWkmYwE6WFVe39BwUlv/2piSsp2yJxZdNX/VK+qEfbJWJV
         Fv+bC1AiX4kCCoK0MwWoetoQNU0WemuCSNLcWuc+M72Dja1FGhFwJp6NzIaGgiVxDWXP
         jCtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fTzGd0Ru;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GcOVh+ah;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768873320; x=1769478120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=52TzXAyatMedwuPLgbGipmrnIAVEur9JTHQWGDfbC+U=;
        b=FzF16nruYZeI+uj6EGhK2ibuJ6XWuV2Kp1urFpGCn/gtFUvlSZLrj+M8SnDVl/B4Mb
         HFMyY+SUJ5yjgQFudl7Fh+sMU3/xwb49iXwwr8xs+g9TODBmlCp02KEi7yGfJ5EuBgI+
         vHl9ynuxxC/SlfU4ngdXLw+e2n/7TwIB8WR0BiPOj0b/hcZN1WG7M5Xz4VIbj6IvkFcc
         QaybeQi8x0/r1kNkYLstNdP8mxkFaUy1Y7JaQO49+6QQlghdyOXyATvn5BPFGX4hKTc3
         6Il3s1cpRMob6U1qrnThkV8NUnvFY5s6FZa3a+Q50WFUWF3mXDlRkGOS7cLHj1Xtp9z7
         ro5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768873320; x=1769478120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=52TzXAyatMedwuPLgbGipmrnIAVEur9JTHQWGDfbC+U=;
        b=NMEh6zfgrE9hhB9+8vu9puHiz0i9Dq8bYGD7Ci0he+ikN8aDIxQIAYKIwpsxVPzccW
         kuaY0kOwYjWeuI6pk0boiRHQwW1z989MQXRidlm36Q3SKGH1Lzofuef/YfRU9Qx1GMZt
         xAjvcVHMGhrMMuHXfgdjkuOVrLkS1GdV7LYXyeZ86KUHxKwP+2l1KEZVvxCAEtYM/gcH
         ie7o0JsMSgEKQOlooRs9w1pQMTcNC+Tq8zE1cDWa4QLLs3IIPKlMNj24TqbIBip99U5o
         Dliu7NOMFfc3CDzwb/yYq5IiJSX/cy8SouWAHJAIIHwtYG49TOgHnEYk8eNH2rsRsD67
         7sLg==
X-Forwarded-Encrypted: i=3; AJvYcCVwQSZ1JmtDJ1u7DLt/CGGuC8PWwLvb+dF1o/QRjQVDk/58sTZHcIRGZup0Utfu9ZKVr89rtw==@lfdr.de
X-Gm-Message-State: AOJu0YwWe1N5BKXHuFuqsr6q9bIcuwDT34mwYoMbgTvyImmo4vxj7IT/
	kihsJ+ju5yERMGgETmaxvKmKueXwlt8iCg4CWWNfil+vSFjT/hd+ddtw
X-Received: by 2002:a05:6820:460f:b0:65d:33de:1c56 with SMTP id 006d021491bc7-662b00b255amr98837eaf.64.1768873320112;
        Mon, 19 Jan 2026 17:42:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GQCRV+wR0NgWK7tsfBwxlO93U8M+OUtwN5x7id8U8VOw=="
Received: by 2002:a4a:e1ba:0:b0:657:59d0:735e with SMTP id 006d021491bc7-6610e5e800bls2157529eaf.2.-pod-prod-08-us;
 Mon, 19 Jan 2026 17:41:59 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWGtyslIE+QfGjzTCq2bXhbMavQLssYFSXrcXljDSDg+9CSHCUv8sMOx3NAYsVhA49Wy3rP2euLLXc=@googlegroups.com
X-Received: by 2002:a05:6820:210c:b0:65f:1770:de44 with SMTP id 006d021491bc7-662b00b21efmr107778eaf.63.1768873319161;
        Mon, 19 Jan 2026 17:41:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768873319; cv=pass;
        d=google.com; s=arc-20240605;
        b=RDL7eHJDvYBoqRrVGMi9umg9wUG6ZvUX7ur6w9yXNFtFM/SdfdhEg0xSxWs6CeztR0
         9wwMnI4jQc5JT4y/ICIHBKvzKZQaOhMdS5+d1D4thjEfLdwkwYcvztb7pMPTCj3dL3WL
         /X67pnn29SL+Wl/3yunePqnVIowUSFND9rEcCgcSm7eQ4ajfHOJZZq9+1jIoiK9flJQa
         Kg/Tb6Ko7ADeRXGJFnwcOZvptC8lchqgNjXKKwm4HqsJ37kQo+6TF4HD1jxULrJeXkmN
         BD+Gp1SYUhyIaFsXj2gZaCU19q5dr1equH37D3AmKfhOzF/xDTuz7B5l4uwuJF6FfkEE
         TNQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=w/0DYR/KmPWl+XtrkDSxjB3uX4z+XMesfyQ/yBb1qT4=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=EJRrxZgG0jFMLnADXXo/a2M1cjZOdQFFpJAbsoamhGzYI9zFkS8u3ENbpU/vBfK7Z4
         5zbYV+k2MTmXFU12BQU8KaljJeSVU1Fgf5PfZ6/XeBOq3vC34EgjVg+MeBm7PzTgGiaT
         8TCdU7ZNLyRnoEQb1qwq4DRYNrnMPUCUDUxCdSuoICvLxDYOGarQ+duJiv990PFThp42
         BPk4ki57GWDP3EuEGA0iNwi6C5L7kdTR7k5/cvwqTq0k5ccvaGUxDWnKffF1RsEUMEX3
         0lv2bfw712CS7k+DjqV1s8aBCsR/ln6M3+LOGCjyolOcWOMn2iUzK+uUG6iEPzRPQc2N
         CIhQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fTzGd0Ru;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GcOVh+ah;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4044bd2c7cfsi321799fac.7.2026.01.19.17.41.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 17:41:59 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60JLuvUM2568797;
	Tue, 20 Jan 2026 01:41:56 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br21qayd9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 01:41:56 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60K0MgKU032213;
	Tue, 20 Jan 2026 01:41:55 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012031.outbound.protection.outlook.com [40.93.195.31])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vcq6dh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 01:41:55 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=KIFALoZPUIxXPXM+8Q3OCBiKmEtaz91U48IjawIpwxRgpcufkXRnILmxpfXrJxFEdQefDw36ZUaPIAtfaSBEchU7y+mmBx2rP71zqH2bJEZU0rRHY2jtyjLw+knu5iT1GMy/5E6F+vO6H1xbkN70nCIQSXYddF5e8Nocia097lmioXNIwoFSY3ogjjzURpaMw6Us37qIQrLbhgago9gokN24uV0woa1l5IgVrUlRXbQtuLojqKYTH4dkiKLnWL0P4ytDDjLCjxiSTk9keQLBvF+Ha7f7yLE6eyqAIfluY9h+fuX6Vu5VEgtMsfyHkkjA/IUSuuTjZydmlINEujUbqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=w/0DYR/KmPWl+XtrkDSxjB3uX4z+XMesfyQ/yBb1qT4=;
 b=lKQTvxZVOR3iEpYSYukfZfT+MI6tLYUWoUzKDoFF2t9XocNbdQ5N6aNQDfIfeisHgak4UimTxPMryW2mbWDMorDj3FlXOhpjYaE9YghVyt9W8GgmU+v4ykRrcHQq4Y50ZHtHmI6BD77cV3kIC9RJsT8hRMSmYWqTqlbK7eVBqjXf8o7Yujwn/mrwjxX0e6nB60G0XwpuYBw9Qm7lCDcFEajLKQh9xEQNlwdZWiVK58jBPE4L9LNXRmgWM70yf2xxxZ9gGuCDi3Tg3kvHXGjsqHeocx4z0IBcEA98sN6Sbq3iy5fodbbnwbs6/23ClV+peNPzdN3udBHB/g8shnTlTw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ5PPF7F0BE85A1.namprd10.prod.outlook.com (2603:10b6:a0f:fc02::7ad) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 01:41:48 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.011; Tue, 20 Jan 2026
 01:41:48 +0000
Date: Tue, 20 Jan 2026 10:41:37 +0900
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
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Message-ID: <aW7dUeoDALhJI0Ic@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <aW3SJBR1BcDor-ya@hyeyoo>
 <e106a4d5-32f7-4314-b8c1-19ebc6da6d7a@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e106a4d5-32f7-4314-b8c1-19ebc6da6d7a@suse.cz>
X-ClientProxiedBy: SE2P216CA0146.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c8::6) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ5PPF7F0BE85A1:EE_
X-MS-Office365-Filtering-Correlation-Id: 2cf14fe6-143e-4da8-b287-08de57c5137b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Wl5sSO2xRkx1mBnm6k/gWy9QYNAbx2lRZbr97Nx4+mSzmk8h1LjoGEPupcUX?=
 =?us-ascii?Q?n0L7mb2+LPqzIiiTjGJdfQVbR41c54XiaXgm3HWcrl11rlluBu8KpMW27+5Q?=
 =?us-ascii?Q?Mn/b7qN32+jsKpEsFIBoNVl927ek6QIg1VVOTGI4zlgt6KM8jELQAvcO2sJ0?=
 =?us-ascii?Q?3aIkDFJyryErbouNq5FM0TBWMCFhmWWS10haEm0u25dKJm77OzcwpG0KmNCn?=
 =?us-ascii?Q?aC/qmB/MZY+RlZOLhsI3gQDfC5caj2vhu3JDM1qJRJ+Rhjr3if6fKjZfXUcN?=
 =?us-ascii?Q?oslJNqpp8JE2IXlE0k03N0xwMMdSFY9JK5tUIVsIQgPhj18J4GKXY2DYNzs4?=
 =?us-ascii?Q?CLyRClNNpveaGa9d4GPRvwTPjGdkaCs9BR63rca/wKtLFfbw7a8s0cLXzaZE?=
 =?us-ascii?Q?boqZR7ZP8ScuLAhhZWn8t7LVQlgg9CQx0I2dx/p2gsdH1+z6t214IL7fkYQ7?=
 =?us-ascii?Q?aW1Lb1TDXl9FsCDFrFUjpKVoT7LgY9DDGetOAuv0nhocDbL9WnNBuliDEDVj?=
 =?us-ascii?Q?/ts6482EXdFsmh7EqXS6vQiH0nb3jDn8hS2mwpsb+e+3nB8dSEn4z0orTQDb?=
 =?us-ascii?Q?+xxBJe97Qu9tnhM5xl/lucunFDcEW25s6yetzM6QoQnceCs97IHEmgeW0KKi?=
 =?us-ascii?Q?syxZT9d1NhKe7j7uqAVgAIPzMBPIKM7J9ghUKj+++I5Q4o8GnUJ84i5B8dK9?=
 =?us-ascii?Q?ZkIbxuTf1IKyExAN/8W+UKOL41xuzzZ08Ntz/ozlDXjnMOwT+JKJkrRR1yui?=
 =?us-ascii?Q?7sg5FMFStq3V7KGMVh8xX2CZnxG0duGZUlFCqOHyMjK7Nf8NTEz0TUQrQpRW?=
 =?us-ascii?Q?MMyozX7gb4sHU1bxKNPXBC9Q3zE03mFOcFDkJRCL9eh5VTiwKt7cZ5uGaDs2?=
 =?us-ascii?Q?+Edh9ZZESDxZm+zNSWC3JQjjivqsVUqOgiz85MuLn1bURP4QMoq0Y1mSU7KJ?=
 =?us-ascii?Q?Wj8Ctsrx8DApRJGyUNgIz2tpjqaFvSDBSuB7uuRC1ewBaFFnS+Vuvuy01Y5k?=
 =?us-ascii?Q?Vg4bkO9TTt3NL7SjH4cncqgBO57MiHXNWFlZ7WbThnm7BG6wkjLyeKiA7Fof?=
 =?us-ascii?Q?fkFIXubOC2s+nrJOO2OqcJ59P617hOeJXJKp9Hx2wx3ivLH/DsVOjmU0/5m5?=
 =?us-ascii?Q?0loE7W/sjrJV5qazWRJiCVZrJV4H81FSSTB1lJ1CL6uQQHUfnURWCZl/QQtQ?=
 =?us-ascii?Q?BtALU1wWqarkT/0R626Hk+kscnp87xURGfFiKvSXLyGBYEuxVQ27NyKaS3Wk?=
 =?us-ascii?Q?n/T1hX5oE4WFabs7Lf3nBW7Rd+eSgLl/WRtW9GeYJPpqOW+tm36JVJf+5y8N?=
 =?us-ascii?Q?Eiaq/zCiKsEchFV/wfcGTlGxu8r8wfE1SAGeaRJA+l9FEES5/m1ZDyAO/8hh?=
 =?us-ascii?Q?uCC53xwkvlXlNnfZISpQ82iT+EkaRUcOkD1bXMx2AsBB93jIYnHPfjWgNq/B?=
 =?us-ascii?Q?aKtNj7OeLQ09nXkzspY7NW6iIGt9dBTIPhtyS9Pl2px7BK4snwSfoPeYGx/e?=
 =?us-ascii?Q?1NHBqxFltg65Tu1g+YCh11ejamnLApGbOsnRT/WZtAE8b9WzFX9ezwMpNZIZ?=
 =?us-ascii?Q?Eq1OtPUF6NUyTf9geBI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?0oYThucZk9CgmENk4ZpOmlNjW9SO1PTbYMONFRs5T+uqm5go0EUzyTLsYU8g?=
 =?us-ascii?Q?zNlwox5rDnQ4SVNXUl9SNovn8fa5O7JVeb0wwPiid4hmcMP9Kpygvi34sI3S?=
 =?us-ascii?Q?hd6Kb59DztOt1W2WW3rDLbFkxUBmzpMYmo+ZxA2+oLAoHFmDR/7tLE61QwWE?=
 =?us-ascii?Q?uBTVgCIWDz6rHZeV0jyf/V9SxVuNoxCTCK+2/vf7vkPHlL11G/LBrzzFliqQ?=
 =?us-ascii?Q?iJdb2awxDXaRtnCiNqfMya9HdM1pc9b6QzvQkAs4P0OkN04JiWWNl5bRYJCc?=
 =?us-ascii?Q?HJfVZAApRgXbUvmLf0NSilol6bRmjA4EpLOeQjs4dMsxnAmQn5BlpRf+A03U?=
 =?us-ascii?Q?Hr66k5NebgVwgad1TMpi5SzsVLk0uWA3mrb8iv+Cslw4VKyVyvkD/PLsXM9F?=
 =?us-ascii?Q?MvkDEbl3M0VFrs9PUMilm1MsYRjJ5u4Ujwg4K1izK23cd5sER0LrFPjMHwep?=
 =?us-ascii?Q?FgK5fsNeoWrDVZFIBAGJZ/Ws+5t7ixhTvVfXl9iG+uYXLHOPN1ClocSUoWTy?=
 =?us-ascii?Q?H7L8xPNDxtZ8cLtqDjMwfO8UYCcstNDkep6hsOHChRzPLPKbTIOrQdv1yZOs?=
 =?us-ascii?Q?T7LBNYOLI6WZc39HulyII1srN+DfkMFSWvZfH3rAvv3K4g0zyKx8USJ7mBK7?=
 =?us-ascii?Q?Zt5qQXqqDU39+FNswMjZBo5M/PMwBoEcu7JkVa1tdxTdWbv564X7vr3JoVxV?=
 =?us-ascii?Q?foWF5347r+HTWe8t965yXW7ktC+RkjQ5+S19HOf7qmqZZvJ7jVQ4AQ2pQwQl?=
 =?us-ascii?Q?JsjOnfJHtXH+Bnew4gAbVQIiziZVZon6TbYHzUBmEoYonoqgtVxULwAwy4h4?=
 =?us-ascii?Q?EEMy3RIfER6Rsd9EgzVUz4jEu9M/hr0AvLtG1dhYfFZ5XNzamXKf2eCrbCdP?=
 =?us-ascii?Q?f34FytT9xShxgyhzeDPSQgwcB15cIBKzhE2IXr1FXtgUsJKisu42BPB52lL5?=
 =?us-ascii?Q?8c/lEMLKYlmdMmMDoSa2WmanBJxbf/3xZALVgdcWxwABctdI82xrU8Qlc10H?=
 =?us-ascii?Q?TRmELk4/FbKd8AmAc9+cki3DQyo8pYCmGP0unc9u13va4kEuY8EbjZUkz7/q?=
 =?us-ascii?Q?sE9bOuI4Q5FMNuTr5StPjj3fj2vYOTuBPzbxmsxPilIEnMTy4ysbIw03f0QQ?=
 =?us-ascii?Q?NdLIvEGCFZlTPO05G3FmimxJfac9/dyq8/Jz+G7r8/pvKyQ/XtbGY8GoHdkW?=
 =?us-ascii?Q?TLgzWTnLUpAo/P1l22P4NhZ7jZiIKekeuwYC77K6kjEwEnFQ1GHxSoJqAzne?=
 =?us-ascii?Q?1q2cfExSNssDJ69qOKLfU0QqkrMRvUIZbL9MZ45xG3MMuCCFbKDJS+y1Le2f?=
 =?us-ascii?Q?rVYCGfsXsNu4HcBZsKmno/Gi+7fWBYWjwXSgiqnMscfNscye8J3OTVisNUYx?=
 =?us-ascii?Q?22830CbzA5e2od6v+IZ4TqTQLbEMxfr4q2ucfu9vO800139DwZ5+0SWP57p0?=
 =?us-ascii?Q?MoyBurdn1Mk4UaWjJ5g4pB7yDylgELH6w5PZL4dR9mIR8uRIQYPLrCvT6tmZ?=
 =?us-ascii?Q?xtOW+20SAdJQE7cY4kYBH7DKOAlMp7nNbhnOciRj0qddsPOR6rHJ3gujDOVa?=
 =?us-ascii?Q?6s4fV1WYYhLTWiAcsw/Jn7Kbvm1Ud1yzPsPBWKONKdgdpoz1V6ngShq5hadb?=
 =?us-ascii?Q?16+GJS/A8891+q0VW1OfR89wTCmYGQXxI0+IP/LWEUD8Tjsf0YsywnIoKiUl?=
 =?us-ascii?Q?Rxk6f2UflEt74IrH6/m+lmwdJdUZgLNYFd5kFnp5S8wyBGlGpWM35ZvDTUpU?=
 =?us-ascii?Q?0gpkaiMW4A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 9WeLb64QjJmbm9inXy8dCv1aQVK4wdFq4PCi5EPBnsmoNJZX3olccnF9X/utQGDWZmgEhP8agx6jtBziYj9SeM9ibe6dyHV3TtDQCWZ1Czl34gPN7Ik/DovyD4dEteAVywsv8Zuz8HMAhC//Tcu+6/WyMHMChttUH84U3e1old6kRDABlTUeu08+UdAH0MV5jXUmocXkKjugGj+HNKInvAFp62hiIn1nncrUOpuqRPu2Ib8UCVQVfT5XC2I2aE+G+IJnARle8qZzu7iST2Xxd7zst2naTWALlWhymSxNfvp49Ax8aLSTiHKuYNWI0ttvZlqD3Qwvltmzn8zBcFy02Rtb0V4C/vAcGFE+1JOQZ92vM1xqbh3BWoeOZtWkEfj2Abx3SiaN8KyZ9j+sbRJEFAcoEOTa6+jgsHM75Y8dnamX/eeTuRJnRtlyzT/08GePKROBUxOyhjiMnI0U9R0eLK0Y32JmoADpL68si564wGRJviphaStzEKFdnVhRy43e069RkqZAN11M4V9HisSdBAxMJejz4tcoEzumDNItJS5K7nJJVYA6Hykq/xbl/HDjgmorvJeUJEJv5syFOM5zSh1V6RVeqnh2XlrYSEN8RIM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2cf14fe6-143e-4da8-b287-08de57c5137b
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 01:41:48.2580
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RR7a5QsNZFOqlv6WDvwQDWNZTn7Q24j2RMgehdPJ35Ms6cQ9sPzlFqnrIyen8yc6AkpXZixqgHOwCkDm9Dh1+w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ5PPF7F0BE85A1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-19_06,2026-01-19_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 bulkscore=0 adultscore=0
 spamscore=0 phishscore=0 mlxscore=0 mlxlogscore=983 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601200012
X-Proofpoint-GUID: gsG4sUCPa8zsCpUQQhDqnq3LGqWAd1wz
X-Proofpoint-ORIG-GUID: gsG4sUCPa8zsCpUQQhDqnq3LGqWAd1wz
X-Authority-Analysis: v=2.4 cv=QdJrf8bv c=1 sm=1 tr=0 ts=696edd64 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=DBvTpO_pozPjgqcj1I0A:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13654
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIwMDAxMiBTYWx0ZWRfXzVbfY9jXUPMm
 RdTZzHy23lUi3qxEIuXtbifqbX3C4VwxwOZ4MZbUXcaMEjFiDbOUH/34QwUYE2BeCDU87hmGutr
 gTAocM2lhHNu7egQFk6YB3s91v9j8E9b52EO/vOziX1dWWfWz8XxE55ggEzq3ElKHsyJILU0nRu
 COW05r0QZPkQpQB3bN0zNitsYW6yzW/ys4nvsml6BOshGkctkPRtYj7Qtf1i1kZx8zyYL1TMCKj
 8E7QyH/1zFzAmYNRlVpIVbPtNxgeHc+mSQgRr48u0kgKt5LKEAv5PsmUjCmZcu/pIHBBh/oPRi+
 5/jRfGEGG2Ue9gR6AP4ANW53MBUoxMIsidkK++WX+XQ4YRddTo8RjLRjO1veaXtLosZUoR2xLCU
 aYS58++d9gFJ+3zfMHBHZP4g4NJ6J+OPIzAdzlVx6QaZZ26CU4v3x4kFnGseJAyrx/b5Xms5RXF
 RQziEcpI0IptwuTOTeH/oW+nlFewS+9LyB5F4yag=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=fTzGd0Ru;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=GcOVh+ah;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Jan 19, 2026 at 11:54:18AM +0100, Vlastimil Babka wrote:
> On 1/19/26 07:41, Harry Yoo wrote:
> > On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
> >> At this point we have sheaves enabled for all caches, but their refill
> >> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> >> slabs - now a redundant caching layer that we are about to remove.
> >> 
> >> The refill will thus be done from slabs on the node partial list.
> >> Introduce new functions that can do that in an optimized way as it's
> >> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> >> 
> >> Extend struct partial_context so it can return a list of slabs from the
> >> partial list with the sum of free objects in them within the requested
> >> min and max.
> >> 
> >> Introduce get_partial_node_bulk() that removes the slabs from freelist
> >> and returns them in the list.
> >> 
> >> Introduce get_freelist_nofreeze() which grabs the freelist without
> >> freezing the slab.
> >> 
> >> Introduce alloc_from_new_slab() which can allocate multiple objects from
> >> a newly allocated slab where we don't need to synchronize with freeing.
> >> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> >> the cache is a non-debug one so it can avoid some actions.
> >> 
> >> Introduce __refill_objects() that uses the functions above to fill an
> >> array of objects. It has to handle the possibility that the slabs will
> >> contain more objects that were requested, due to concurrent freeing of
> >> objects to those slabs. When no more slabs on partial lists are
> >> available, it will allocate new slabs. It is intended to be only used
> >> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> >> 
> >> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> >> only refilled from contexts that allow spinning, or even blocking.
> >> 
> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> ---
> >>  mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
> >>  1 file changed, 264 insertions(+), 20 deletions(-)
> >> 
> >> diff --git a/mm/slub.c b/mm/slub.c
> >> index 9bea8a65e510..dce80463f92c 100644
> >> --- a/mm/slub.c
> >> +++ b/mm/slub.c
> >> @@ -3522,6 +3525,63 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
> >>  #endif
> >>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
> >>  
> >> +static bool get_partial_node_bulk(struct kmem_cache *s,
> >> +				  struct kmem_cache_node *n,
> >> +				  struct partial_context *pc)
> >> +{
> >> +	struct slab *slab, *slab2;
> >> +	unsigned int total_free = 0;
> >> +	unsigned long flags;
> >> +
> >> +	/* Racy check to avoid taking the lock unnecessarily. */
> >> +	if (!n || data_race(!n->nr_partial))
> >> +		return false;
> >> +
> >> +	INIT_LIST_HEAD(&pc->slabs);
> >> +
> >> +	spin_lock_irqsave(&n->list_lock, flags);
> >> +
> >> +	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> >> +		struct freelist_counters flc;
> >> +		unsigned int slab_free;
> >> +
> >> +		if (!pfmemalloc_match(slab, pc->flags))
> >> +			continue;
> >> +		/*
> >> +		 * determine the number of free objects in the slab racily
> >> +		 *
> >> +		 * due to atomic updates done by a racing free we should not
> >> +		 * read an inconsistent value here, but do a sanity check anyway
> >> +		 *
> >> +		 * slab_free is a lower bound due to subsequent concurrent
> >> +		 * freeing, the caller might get more objects than requested and
> >> +		 * must deal with it
> >> +		 */
> >> +		flc.counters = data_race(READ_ONCE(slab->counters));
> >> +		slab_free = flc.objects - flc.inuse;
> >> +
> >> +		if (unlikely(slab_free > oo_objects(s->oo)))
> >> +			continue;
> > 
> > When is this condition supposed to be true?
> > 
> > I guess it's when __update_freelist_slow() doesn't update
> > slab->counters atomically?
> 
> Yeah. Probably could be solvable with WRITE_ONCE() there, as this is only
> about hypothetical read/write tearing, not seeing stale values.

Ok. That's less confusing than "we should not read an inconsistent value
here, but do a sanity check anyway".

> >> +
> >> +		/* we have already min and this would get us over the max */
> >> +		if (total_free >= pc->min_objects
> >> +		    && total_free + slab_free > pc->max_objects)
> >> +			break;
> >> +
> >> +		remove_partial(n, slab);
> >> +
> >> +		list_add(&slab->slab_list, &pc->slabs);
> >> +
> >> +		total_free += slab_free;
> >> +		if (total_free >= pc->max_objects)
> >> +			break;
> >> +	}
> >> +
> >> +	spin_unlock_irqrestore(&n->list_lock, flags);
> >> +	return total_free > 0;
> >> +}
> >> +
> >>  /*
> >>   * Try to allocate a partial slab from a specific node.
> >>   */
> >> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> >> +		void **p, unsigned int count, bool allow_spin)
> >> +{
> >> +	unsigned int allocated = 0;
> >> +	struct kmem_cache_node *n;
> >> +	unsigned long flags;
> >> +	void *object;
> >> +
> >> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> >> +
> >> +		n = get_node(s, slab_nid(slab));
> >> +
> >> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> >> +			/* Unlucky, discard newly allocated slab */
> >> +			defer_deactivate_slab(slab, NULL);
> >> +			return 0;
> >> +		}
> >> +	}
> >> +
> >> +	object = slab->freelist;
> >> +	while (object && allocated < count) {
> >> +		p[allocated] = object;
> >> +		object = get_freepointer(s, object);
> >> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> >> +
> >> +		slab->inuse++;
> >> +		allocated++;
> >> +	}
> >> +	slab->freelist = object;
> >> +
> >> +	if (slab->freelist) {
> >> +
> >> +		if (allow_spin) {
> >> +			n = get_node(s, slab_nid(slab));
> >> +			spin_lock_irqsave(&n->list_lock, flags);
> >> +		}
> >> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> >> +		spin_unlock_irqrestore(&n->list_lock, flags);
> >> +	}
> >> +
> >> +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> > 
> > Maybe add a comment explaining why inc_slabs_node() doesn't need to be
> > called under n->list_lock?
> 
> Hm, we might not even be holding it. The old code also did the inc with no
> comment. If anything could use one, it would be in
> alloc_single_from_new_slab()? But that's outside the scope here.

Ok. Perhaps worth adding something like this later, but yeah it's outside
the scope here.

diff --git a/mm/slub.c b/mm/slub.c
index 698c0d940f06..c5a1e47dfe16 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1633,6 +1633,9 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node, int objects)
 {
 	struct kmem_cache_node *n = get_node(s, node);
 
+	if (kmem_cache_debug(s))
+		/* slab validation may generate false errors without the lock */
+		lockdep_assert_held(&n->list_lock);
 	atomic_long_inc(&n->nr_slabs);
 	atomic_long_add(objects, &n->total_objects);
 }


-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW7dUeoDALhJI0Ic%40hyeyoo.
