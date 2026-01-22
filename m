Return-Path: <kasan-dev+bncBC37BC7E2QERBFUGY3FQMGQEJUW4HPY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id iOObERiDcWk1IAAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBFUGY3FQMGQEJUW4HPY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 02:53:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id C856560905
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 02:53:27 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-8823f4666absf12956356d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 17:53:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769046806; cv=pass;
        d=google.com; s=arc-20240605;
        b=bqymPo/5nDwBndh0SBGewKRNXglSbZEwvTamx7s614/FYij8M66sBder0HNBZDhYIP
         grNMgckA6TV7kNmNFXlxOzlirxp0eadnKfm84/LjndmCg2LjVDWQu+tfgXrE0fNateC4
         Gqbg2h/DaodW+KAwBYb0MyvStfdFhzANsSePs5n/NxGdZ/krzrn75mjOgiYoB7T7ESul
         o0Y+hx0FpK8BeRKsuU5UTrkcIPQ9b/p8G6YcqXXKkFAc9OYqcyvHWFW+Ut4IOTcFB82+
         ut5yIbiQ2rz8mS5kGI/CKibMchNMUkUNytTB5m1Uexabnk/wix77OKzwJzuaPgbjFGpg
         JvzQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tf3d6dHOLz3sSUAbQvguLThxVSDLxZ5VA9Ic1MDFepA=;
        fh=lo63xyRUlHEnUEAa7GnOi43mu6Jp3VkM4CYkd4cueRk=;
        b=SEwCtS5EyOwEs6VVRb0du9O1iKl2I/M0cmaw0YJwmMApDx1OR4fIdr6xhlgr3bKKZd
         dGeyhJ1EypaH8D/EdcLlzZYAZHx+4CADISPKc1qezKafL/OqYe8iSeM7gmNvundcRbDJ
         4zHLF9ONBWiPsZSF3alWcYcZtHUlfDJXKI+zX2rUY1Fyoj2y7sn08TUv7iU9SAwxzSbL
         3q1PnnC8PHSiwrM9bMmECtt6lBX73yxlNtC7uEwxsFgUgoaZDfeqyLj+4435gpPzB3MM
         aJXLK0gKSWuuuJdaO92/Fs78/ET8uZMQnpbeX+QnngsWxZ9cHXccX2DTFHWFO1cOiU1f
         eS4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=QZIjAm4n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=njhex5Jx;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769046806; x=1769651606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tf3d6dHOLz3sSUAbQvguLThxVSDLxZ5VA9Ic1MDFepA=;
        b=V1NLGepQ7naR+npOBQl5HxuafZeyC+4dB2b135OgzHUavKzOihJtWWxfSzK3J9zXsR
         InFQexmsYZ0/hUdaMUhEPTgNfM01s27nWwFRqnbzCm9gwWbD0ED/LW3BX0bAh+1Nktqm
         RFvlV1XIXV+rKDr7pJLDn0st2cVgfOkiYkr3uYLniALrAtEZckGoGdkQEeTTvQJHh1xh
         3BD/9W9XiqXuIEArKROzg8qAGy7Db52dOV7ABN5XwWsqHd9p+jnqjLnBQts4XbK+gdKP
         3WwW8x2yiC6R3OFM+2o9VS4kpo+CkSPHtcMzef9jy3tPT6PBRyxSJ6t8BHlyfbIoYWnm
         coKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769046806; x=1769651606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tf3d6dHOLz3sSUAbQvguLThxVSDLxZ5VA9Ic1MDFepA=;
        b=Em+HqsLYlOgA3xZn4V9LdC4TjAC3SeyPGP7euMmY6vlkuF6jI+Z8/TrvG6iTsxWhcA
         zDpx84hiqm6pS3bnF30V8uumB1q5K90Tf/8kJPhi2AVL4VxSNtjbJQR+nZtkUlGzyOkF
         9bU7L5WmqUYlFKMWNR73s8nctbFvejpHWqk5hZPNSEYRDXKcQ03r30uvoG/4gUP9JXyA
         VYrS1XvzuygcahwAOPR+S5Y56Cig3qeOjnpL+xoKJJQQX4v+x3u0eMWIU3PMNMqEgXZ+
         /CXQP+eaQDdx2LQ/Jo3gLK1jSXNdG4ndpNfWXDJoqM86BvsOX39HWOP+LenM+BgFA5vs
         y2XA==
X-Forwarded-Encrypted: i=3; AJvYcCUTX2+Ol+avnsdNNyP51Wf2kmzr9E5WswcVBC+xetyKI+TJZ2JsMhDp1D8vmaAYSje7HHygfg==@lfdr.de
X-Gm-Message-State: AOJu0YyV0yar8jy9rV/aEr9WxhbaruoKkeZPfDhWVSg/rt6ln1bCmk8n
	LtWbjSSpGB7JOJW28oUM5LXziR6XAo19waM+HyyhIHme9YPE8+T3EE9d
X-Received: by 2002:a05:6214:1c85:b0:886:3fd2:ea78 with SMTP id 6a1803df08f44-8942e2de814mr249883236d6.24.1769046806231;
        Wed, 21 Jan 2026 17:53:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gs0f8q17S4qQVqjx5+pUTn7yLZ2qW8VYtsXN0Zz6uPuw=="
Received: by 2002:a05:6214:268d:b0:88f:ca81:d5ee with SMTP id
 6a1803df08f44-8947defb938ls7429806d6.2.-pod-prod-05-us; Wed, 21 Jan 2026
 17:53:25 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCU0d8qa0lbO+zHEc2j+3vv26C1aG2NWeX59SKGiAIAfvYQ210k6xZFUwwQcQkcdTBoABdxG66TbhOE=@googlegroups.com
X-Received: by 2002:a05:6122:5017:b0:566:20ed:44cf with SMTP id 71dfb90a1353d-56620eda1f3mr984986e0c.3.1769046805036;
        Wed, 21 Jan 2026 17:53:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769046805; cv=pass;
        d=google.com; s=arc-20240605;
        b=cP33g4JqcXPWyn/nTdInBkft/YfnBmt69EAz81jGGiqF2uW2VtF5Lln6oz5OGwBqEa
         F9d+F9rT9NlTdjXoS5H0hYi8fVO/YvWb4cSdpusN1og/fmu/ZhN/sFHF0MmiMlByCP52
         5bDzKMehsNn6yYt4rNQznYrJW0z40j0aMW3J23iT+fWNn2ugQURfnTuCGIZ7kcyPE18D
         RD5fcdYic+XabWpxlsPha6YXlxJBqka6mKIva1q9nYQk3TnJYQf48whqrJokDlyH0EcM
         nV8wobT5EKm42o2AFSthnkLFT11yT1S6qILR36UBnWelC0moofFSidtobsDWd4gi8nBU
         LZ1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=fCPqhUzvu4ZclAoVNXjBfTkXycvCi825RXOoYzHTarU=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=csA8Nmr0NP01S49fQ3TwRXeMYdLqS92nXELlljhgO6hNTpJ1yY9tobMRon/cQDZlEA
         UuGOkEc9RpIp1dcGVbwX6CygvKztP8CsxjfypfXXPASh7lZ/EKK+G8Yy35gPDGMtKSmf
         Edh+IOp8d/Rn5LJjTDCkMtpd5kJoPtFgbDngohYrFoh8fOmkRDMQTuPNVkOBBlo6AeL4
         QGiFJWoW0tWVBHH/ywM8eaxM6khuFyEH5TaCRx4Vwx+rrqvkReqZgl/X0/X3HUDi7am6
         gurGLYcxCKG6obDBztEar0YoW8EdeQVRLb3OaoEwnD/Ov+6YfqlxWGYB6acv+kvtfmpv
         Ndlg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=QZIjAm4n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=njhex5Jx;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-563b70f23aesi525175e0c.3.2026.01.21.17.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 17:53:24 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60LGPOII720383;
	Thu, 22 Jan 2026 01:53:22 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4btagd3jbm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 01:53:21 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M1Nb2N008488;
	Thu, 22 Jan 2026 01:53:21 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011000.outbound.protection.outlook.com [52.101.62.0])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vc5naa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 01:53:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Abtcs7D/X+gvY4iEsJAsALgQtaexbYk5zzIJNDDHHwpDY6dDotKdMcFDTUdF48WjYFzM+GG4DNMCG4GhtAX6TYAaNJRa2M52JOBruEi6AffGlLg7PbN3DK6SHDQVpbXN9GgXinsLQak6EimYgTxX4l5K03icfKTqAAd49m01jOfPRciAJDaqVRCzXCBiqBgV6nr8jGMSllh/pdU0bYxW+QwCQBKVNPVbZPW4FgZL3N1hjmIEr4Krclqls/C25kSH5+cglejxXohsxsQm0BfS8pG7mwkMivZX6CiYbhX7ZCyn2wItK+xDLDifIIXlPeJCDJUt4sldwgkM0Wgg9R8Nbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=fCPqhUzvu4ZclAoVNXjBfTkXycvCi825RXOoYzHTarU=;
 b=F793qJnIg5nT7frfr/tUwfIDzszrLoLUwrvOv9n0/bHY1FPnxXxIw15+XArkWa8jeB2tbOTYgUxN6jp3cqA/ewDSDnQ1dbrRUFlpGQggldJPL91TrMOxau66h2InvdWGLzLCE9ZZOGbJLrakufeDY+bkuxV/82ftyhM7PrTMJ5HuL0o77zp02lwFeHLCpgPVjl7bl203XwLeeQi9dR4CAA0LwXBLr8c6462qizbzfzCXCzyxjneWbw1qP1pqGScwATMqOL0dy1bK3jqoR45lUiO+9B0aJKJW37k55dqZ6UlID06Lt9Ltz1nV3wTx/eCkRHnditLyrvm477+c35QpOw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ0PR10MB6430.namprd10.prod.outlook.com (2603:10b6:a03:486::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.10; Thu, 22 Jan
 2026 01:53:17 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9542.008; Thu, 22 Jan 2026
 01:53:17 +0000
Date: Thu, 22 Jan 2026 10:53:00 +0900
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
Subject: Re: [PATCH v3 14/21] slab: simplify kmalloc_nolock()
Message-ID: <aXGC_JRmz3ICjMHW@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
X-ClientProxiedBy: SL2P216CA0129.KORP216.PROD.OUTLOOK.COM (2603:1096:101:1::8)
 To CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ0PR10MB6430:EE_
X-MS-Office365-Filtering-Correlation-Id: 57ffd6b0-fae7-4645-16e8-08de5959031c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?/dYpkC8Ihx02UJ4wfN79lP4XCQer+6mchi6mezLtVCS9r9ySXTHptVC/ErVT?=
 =?us-ascii?Q?BJgBkp7/6vNbuQZkjAHAMfEZP688ZzFN/YgzaaVGkhXUWFrZ6SGCj+vxPvAv?=
 =?us-ascii?Q?1HUexIaUG+HD+nGMsba+CM8Tj4VhF7+Mg6m20OvbmrH9L1K9fKfB518URvtD?=
 =?us-ascii?Q?zOcgKNhoBYTjeAkix8Ut+LlqgVtp4hyXrDfJkrYC9JT6ns6Tp0bK7XR4Gjn4?=
 =?us-ascii?Q?+bXO8io8HBFg6XakXipmKXjS0c8sVYmsadv+B/iiJMln0y2cs6uPTZQVhdHF?=
 =?us-ascii?Q?tB280e0JZcAQAb9rsKpdYUQnsyRQB+zT0T/VzuGNKK0AWxzT0fYZ5ShJACo1?=
 =?us-ascii?Q?G8VLqmLYpX8/5f4TmUp9WAVur4tNfHUFQiUcWJGnSOZifxl3hTVyPZ3PrG5b?=
 =?us-ascii?Q?nh/aRG9/Ukew0NzJnPqiVA8f3QoEAtpAExhy8xFLZyTMzUzrdTotWoeh3Xk6?=
 =?us-ascii?Q?Zb/albFekNddkyb8H3cEpPpZNAwqkcsIYHechNa51w086TZOXK+OSO5DPDy0?=
 =?us-ascii?Q?PUrU8mud2Ytmf9qetWd/OVFAXqPhcJkfiAZU/9OEv4gE6ae+gcCjFPXaK5VP?=
 =?us-ascii?Q?PmfSc0q7K0XHEmi3opkGwRfOFeX9IfGyc3vt3sYwaYFhvO1u5xl487tUnhIQ?=
 =?us-ascii?Q?1kU9mFKP8X4AeOLDH9hgWSLrXSRwgvZ7/BGg8kcynlZjSxlFjd+fxuQ0+y1h?=
 =?us-ascii?Q?7TEtncPxGuI7dMxyqyk3DPTXDrj0wzZJgfo3PYEt8g+DE/min2bj9x9iVdej?=
 =?us-ascii?Q?5NHV2cDf/R4qx93Q9Ch9MZNCERf8GB7UNrxBUKLmvUVq7cYwqAyXtm8FawaN?=
 =?us-ascii?Q?W9LMa/kgZEkidkG70hOzBMEcw8iG2Zu08jpHzN2Gwz80S3Gh6OgYom76Hg9P?=
 =?us-ascii?Q?fm8DFyX5BXw7MoClN1TEdp42frNn+Y6AmscJsoLANurnntCDrhgRGkkfdlCg?=
 =?us-ascii?Q?ZODfe0NvauLYjkIBf6qXJW+fqWOAf0RyllwMalkKUQZL13PvonkNEN4y9m50?=
 =?us-ascii?Q?+zcwT1zhE6cSuSgD2ZKWbAq6oAwY3Zhb/ATIZffzZtf3rF3uG9lcFoK3bFfy?=
 =?us-ascii?Q?KKc8lE501ZS0NG3dT1Ka0XSg839Nwh2aFj0/U5roTaDgfhX0YciKA3XsVCFI?=
 =?us-ascii?Q?peGuZN3lwUPjV0tnFXfdHMZy0jxmw1GwUgBhSzyRQ6NbwwpyDwDlxFT5YpLE?=
 =?us-ascii?Q?/HFPWkYGToU1idlZB7rvIIWkbkCYC6u+ur+upVfPvkXTWFSkGCQTPlr2cThQ?=
 =?us-ascii?Q?QlSxakM2ERxB7Gx6jOntmFPJwxeg/blvQcngV8zAPBIrfvrORoFFmdTBacrw?=
 =?us-ascii?Q?itMqZa5heMYKOGCXY9vFBYjoIcO53OwBG0fSNvpKSOIrF09YjRg++z79mptk?=
 =?us-ascii?Q?ljeP7Y6pWEB6vx5WxpgYAos9rzqEkE8itP1fTh+7wDl7/WHXhTbkYOPVZ3Jb?=
 =?us-ascii?Q?cJ8sw3afiJahWW0AmpfoIx7fKqB5Exw7Vu6tYZ52jflxk/dUrICObwPSl1g7?=
 =?us-ascii?Q?26gD+auP8t6tX3qtdkxddMelfpmxg1hkEFRefcp3TSUezMXCUK/nB1GRYNCD?=
 =?us-ascii?Q?tLm2cAO87yyvvbodE1M=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?aKTJAEK3tBde8fCsZk3xKwlCN8pWUS38F3cd+JviRAbvgLVKamM67WJUo3v5?=
 =?us-ascii?Q?rKVKEVCENoZzAejyVLxR+MFPG/hqRA/fVQmDCFldhPOgM/3zpHrbfNeEI9Dc?=
 =?us-ascii?Q?Qio7y4sMw3PAliGWAC1YLdclJvoQt8Le+V9KfntK/rmaE3OPJV0fpypUlSxW?=
 =?us-ascii?Q?nJdRfc9d30eCTrjbXugiUWgeJr4ZZ1bqH5seSQZ4PEck8yQC5i8gOfeou+bz?=
 =?us-ascii?Q?PGSoFRxcynSbO8fUxjzv9y6bsdzfFualBg3czCDsw1Z5A0sV6TnQFuEeYK5r?=
 =?us-ascii?Q?cyl8lDKmDhYC1ohTEqhvnWHM21apFQu1M7s6nv8OIakfstcfBZHR7loTjEBM?=
 =?us-ascii?Q?uRg8ziMcNsp5Qlam01ZeRCHyt+s0FKZ+FZxZHh0LALETYzne8KNZti1FdP3S?=
 =?us-ascii?Q?7ml+g2czaf45D8PChQk84u4akWm/8XwnuMZWv1ul08ZTRDi3hnAuLLIpjexd?=
 =?us-ascii?Q?dIQz3v3nzDescFdggtRP6nXB8AfMUl+tTjnQBJO9u+vZVIJnjeOn6aDQRVHH?=
 =?us-ascii?Q?3XEsyUS1YRYgjrKuLWcqSKRNi2JlP4jI2op/blBL+PbB7UAtpgloMlx9VU93?=
 =?us-ascii?Q?PgjEGtAnZm6AkYsrNzv7lPT+T87CvLYW1gbwfnRr9SbV/sVOgvb72Rf+b7GL?=
 =?us-ascii?Q?1LAbrlUMaJkhY/AxvQcSnOqRH/0XyTb6wKzVjem6cplZhICrBXEW7sILdfe9?=
 =?us-ascii?Q?2YK53IuZ7Ik9g3zWltMJs5E/zsJqA4RWd8iBaQRO2CiOyakrZLy9qA+nznUJ?=
 =?us-ascii?Q?2jcq8muP7WQvKF86hCG7toK72Rp/wU2MCG9+twDsMTx97fB/79wXbVyHcYzA?=
 =?us-ascii?Q?PDMs4ukZz4TCtYGl7eqVZTXV4btSkT8CBEb70RYjEpUqCwqkGWVMhlDkaV1x?=
 =?us-ascii?Q?5dZvWaxYK32ZBVX4sIoQV+tzv4tpAzjhJIqwYHK+kPn2s0D36MoE15SH8vyM?=
 =?us-ascii?Q?flZTaNkSgJckHeUb1cyK39Iou2OR48DrmKJMKV1bj1iZjtEP9HjTHpYBphV0?=
 =?us-ascii?Q?7PjzsN/Qru0PVoznSaJmNvER/VzLNyH/i5hP6C/eIYM/WLi/AlzQfIe9aTv3?=
 =?us-ascii?Q?m3nhqfy41K6NFvOaDxbyrPwNPSfkozETtRp3pOZSXpn+RBLZOw4t3elz3uN5?=
 =?us-ascii?Q?rTJbGoH51hM3fcVO/YVCz438JrSvz+x+ayWnSU5/lpJNag6Yjp4nlRJ+SIHu?=
 =?us-ascii?Q?HFoucUslqkOL58t8YpONuWpIeSSG9NF5qv2ZzjR6K3NRrU/ifdjorDyWMaSD?=
 =?us-ascii?Q?Al/3gWrFsel/CIRMtgSB3Iu9/wWXfqM54UxYkN7v8PCVW0H97P1kk76U37nL?=
 =?us-ascii?Q?wdltVW3SiQRyoVJoMZhIiMds+g1i4m8pggLQcQRkMymwxsDWAa1W2AOpQvMx?=
 =?us-ascii?Q?B/2jxTb8gZ4TjbHvppuphN76R83MNjfkW8kgHrl+UoelVpEPff9t9lo5L5Hp?=
 =?us-ascii?Q?91iAYaHfL4XaSzs0kxHH/k0uKpe+amofFdjKWjXPMY1OYBaLziblh9sCrDva?=
 =?us-ascii?Q?uDqIrU9/SUVJIajyWJ8e7DaYBrkKDtTt/Y6SDHkDuq7Dw7QkK5IBnJo7taBv?=
 =?us-ascii?Q?OkmpImNurILQ1P8ny0+40bPcvhF0AtclJnQUWdhC5zmvlcpsacc667BbtpPz?=
 =?us-ascii?Q?+0BSIGEe7v4Qq5n+OWxsXOfI3eA+DcynORKdBcvFBtG0IGbvrxF3EENewXwi?=
 =?us-ascii?Q?T7kqA3Qf7/vuCsXL9LyvWuoJyD5eUaLEu6m9SnL2U1gkm4mSqcXdNpeQ1GRS?=
 =?us-ascii?Q?ysHiymNoOw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 4SJR6d7fJMAfydxFySJhM5gtsu0hI8xmWqqABstlR5tDvO/qpZPkeekBWwRPzf1iA4wTc/A/9e3are+RGhW24QHcU0V5w9rA7TiUAwyveo/IwSfSiW4y4siNs40kBgk+Kc8h6yGKi2XbgQ7VnBx8vnK8yhhMoGgtqXUnX7qBRVj1YdX5mtqy5H7MwZCZ3Fd2tGrvbYfzFCqde7nDHVw3s53cv+w7nZiQD07m58kn+Ba2bW195NZvBdY0IsaASszDvBFd9MDBEsoUdCUZFc0La1o/g6TrWK95etqxX5wmvvqKZwpfFDMYdaMAl94ObT6gnAUdJiA200xTGvo70fET3INLETgo/iPpQBlJedojiWztPgs7sKsrquSHYuykfZgO1BBVzmWp2OS19xoyCtSkoESfte/t8Jmz8YRpAbdeVO2XdS+pesv/N9wgGYvFko/AEw7Fn9bcf9UmAkUPKiaz04QFbRQnE/o11BJhbH2kEvLtg/S6Jc2Qu/EoPevYerwM8HfYA6sLj94dC39e6OYJiW2jOg7sFtUhK2GDf1Lj/35LMEq4dv8vbwX2HR3s1rOwo+YTiqUJC8DkjDa1TbAvxiMxJ4yB3L3UYyFvvuP7p/A=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 57ffd6b0-fae7-4645-16e8-08de5959031c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 01:53:17.6448
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ESJR87VIus9YMV3/jqsad0+VqYzv7olGdppEpqhB4EZuUtWGisyejANLH433j8jT+GnMtmu6MZxweDZ0tKKv6w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB6430
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 mlxscore=0 spamscore=0
 malwarescore=0 bulkscore=0 adultscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220013
X-Authority-Analysis: v=2.4 cv=PqqergM3 c=1 sm=1 tr=0 ts=69718312 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=Yeq8MSSKk5_Neusd4DgA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: 7Fc9IjIQ1s6JF5-sLzQmTXTBnwBdfz8k
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDAxMyBTYWx0ZWRfX/f4rI3Z4mwW4
 xZGYO25wzGcspjiI/oL5TWb3qxm9nKUQIoDWWqVQWCQalpZrOt0ML1Of6FBZuPbl163hkhIHLUD
 ySNMsYlYJOR/b1JtWGRlBfXPtOmcVIi0zZwsGsEfbEsL72iD3gJjZM6l4GPiqlxzVjRdgpTFEa2
 G9etgPOcbCerk5xkvUFMbJZ7jBTI1BwC6hn8ieaVrFYhUqd6cJ64TDDf6tS+BhCEHpXTt4DEXfF
 jdQh1s09ZDtkTdCQ7HaaFzNt8keeCSqH+z9VFaYpWk2tGRDrsrHx3b1NguHm3VpEEE5UsofOZte
 JJBs442dGzBmulAYOftl/L9SYcTv17trTulrrgyXMKluAYUMwJU6+1vEPM+0grlH885FkynSo/l
 Zdfsn9dfnMmheDCasOeM42AlOQXe+xdCT13NtRjC71e/YJxBZQzdGuk3sAJaFnmqNke8eLdLFQt
 iZLoC68ruI36uaQyI8w==
X-Proofpoint-GUID: 7Fc9IjIQ1s6JF5-sLzQmTXTBnwBdfz8k
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=QZIjAm4n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=njhex5Jx;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBFUGY3FQMGQEJUW4HPY];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,mail-qv1-xf37.google.com:helo,mail-qv1-xf37.google.com:rdns];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: C856560905
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:34PM +0100, Vlastimil Babka wrote:
> The kmalloc_nolock() implementation has several complications and
> restrictions due to SLUB's cpu slab locking, lockless fastpath and
> PREEMPT_RT differences. With cpu slab usage removed, we can simplify
> things:
> 
> - relax the PREEMPT_RT context checks as they were before commit
>   a4ae75d1b6a2 ("slab: fix kmalloc_nolock() context check for
>   PREEMPT_RT") and also reference the explanation comment in the page
>   allocator
> 
> - the local_lock_cpu_slab() macros became unused, remove them
> 
> - we no longer need to set up lockdep classes on PREEMPT_RT
> 
> - we no longer need to annotate ___slab_alloc as NOKPROBE_SYMBOL
>   since there's no lockless cpu freelist manipulation anymore
> 
> - __slab_alloc_node() can be called from kmalloc_nolock_noprof()
>   unconditionally. It can also no longer return EBUSY. But trylock
>   failures can still happen so retry with the larger bucket if the
>   allocation fails for any reason.
> 
> Note that we still need __CMPXCHG_DOUBLE, because while it was removed
> we don't use cmpxchg16b on cpu freelist anymore, we still use it on
> slab freelist, and the alternative is slab_lock() which can be
> interrupted by a nmi. Clarify the comment to mention it specifically.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

What a nice cleanup!

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

with a nit below.

>  mm/slab.h |   1 -
>  mm/slub.c | 144 +++++++++++++-------------------------------------------------
>  2 files changed, 29 insertions(+), 116 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 4efec41b6445..e9a0738133ed 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -5268,10 +5196,11 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  	if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
>  		/*
>  		 * kmalloc_nolock() is not supported on architectures that
> -		 * don't implement cmpxchg16b, but debug caches don't use
> -		 * per-cpu slab and per-cpu partial slabs. They rely on
> -		 * kmem_cache_node->list_lock, so kmalloc_nolock() can
> -		 * attempt to allocate from debug caches by
> +		 * don't implement cmpxchg16b and thus need slab_lock()
> +		 * which could be preempted by a nmi.

nit: I think now this limitation can be removed because the only slab
lock used in the allocation path is get_partial_node() ->
__slab_update_freelist(), but it is always used under n->list_lock.

Being preempted by a NMI while holding the slab lock is fine because
NMI context should fail to acquire n->list_lock and bail out.

But no hurry on this, it's probably not important enough to delay
this series :)

> +		 * But debug caches don't use that and only rely on
> +		 * kmem_cache_node->list_lock, so kmalloc_nolock() can attempt
> +		 * to allocate from debug caches by
>  		 * spin_trylock_irqsave(&n->list_lock, ...)
>  		 */
>  		return NULL;
>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXGC_JRmz3ICjMHW%40hyeyoo.
