Return-Path: <kasan-dev+bncBCJNVUGE34MBBP5ERHFQMGQECX6RAZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 57668D0D651
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Jan 2026 14:21:16 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2a08cbeb87esf59091445ad.3
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Jan 2026 05:21:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768051264; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y/Wa/bxngf6AN8QTTNRBfCurETPho1GtfN7i1lILmikizEMcvtb/vj+tD5WXuXmVvs
         Bbs/zGz10i1S6S+oyCcNOdF0KF5NmWQRKcDrV93dRzTGR8dygpopq8MALplEGGhZKz+k
         ieMFQmeMXT9mbKPzKarA1jDmoL4OZlW1GvlRe0an91BCqZo9TevKHXcPxWb5LQqo1GcL
         w7vyUrQ8M4R0j/7jX6nGMn4tYxUq96A+zi5bJA0Ofd1+D4Kd1PkZn7pEoNIRzHy/SNME
         HNsLju31kKA/W888dtPgXZwoZY6T+Oe4tTf+a1AZnV8bbcSBS3PkFJEbl/3N7uhQ/sec
         Z4IQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=uFH1/EXAYNz11b/yPffXpCWPHxUgVIg8ue2vNrSgUpo=;
        fh=zgwgliSJUqdInHJUZLVFnhdBM0c0v4ByVhIxNY8Er0Q=;
        b=YMf7Ow7NCdo6kD8rr75WLEasJU/jcbeCP5Am4UX4E+acUG21Gr0u90z0Id2TVWGdc4
         yBSFRYD1LiaCQzHl+prpE+84pXCwrDCaIA5btcga/g4OW3mwX1tWW7ncOE94oP1Ff9hu
         GXJevj7yBDIYySj4ZD0JSOOhF6+Vcf3LKYHbfIrxr0fuV0S6Wd0s9HYSh55E+AOTQHpa
         HWNYFfIreg4CClgMxHzE6LFsms1Ulat9nrNQaHGl0Yk3OS4N+91tGeXoAFCXIjiYAgXW
         3UHowUWfS0LL9wmhKgrEwCQHwXyZxKpB4iCw0zFQoucB7p84sts3OuB2ceVNQuqRB/GS
         EZ7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=K4rsntVp;
       arc=pass (i=1 spf=pass spfdomain=meta.com dkim=pass dkdomain=meta.com dmarc=pass fromdomain=meta.com);
       spf=pass (google.com: domain of prvs=94707e0023=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=94707e0023=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768051264; x=1768656064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uFH1/EXAYNz11b/yPffXpCWPHxUgVIg8ue2vNrSgUpo=;
        b=brTpjLMAkNeOn5XwIOiHGmWOuGOKfuyprhMHDW0aNpHgrp2EWtYwq3pPoaHc3iGymI
         nspHy4En68OeBZS2XoX+3IL1O0pjVd2+yYQDEj8uHtKTnQdhl3aQDhhN6mRTZdjz4npg
         YTmYcLKXbKY1DrvUudOYaqGWCpbalZ9Tj8H2QYLIahA96MHRLLSeg9fcARHQ7vJh2rgz
         W6s6sVCl2FpIZ89M3TwmEnEuZI/+iUJUy5a5gY3oIcto5BMcZ/HerY1pekNixJkrCqEK
         QUrd92qBL2lBpFEVSNSMMj8iZJ8NX5DMt1Z9pCOEwzMB4Wk16i54YJyLqXCUQ2yfS0SU
         7keQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768051264; x=1768656064;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uFH1/EXAYNz11b/yPffXpCWPHxUgVIg8ue2vNrSgUpo=;
        b=wtGyxU6E0HzwfgZu2DZYB59tV8LBlEQjECTS6YrbPOZ4xY3+WfUc8tJ07xhyStG79V
         HMT6wrJ/XKiuMA062CA90W9zJe+hKVtmMyJ6JLKJGNAczStxu6HGwcuUzr6TDXies23a
         0dI5/HXrwtkN5zcNYQVQuVKzfAWvtfeK8Rl/4noVBXVvOOQMDmSDmNuYg+Vt0XD00DBd
         zFK8AVCX0nDG737prxLTC1phX6CJ7R7gO3wDSiQIxkL32Y+AGQE1rfY+fcdg0xG4mV07
         Q9KZeqKGKQtvqwSHtyFOi8Wjm/A4/H67yawF1K5MDw+BlxE6zdbDJX9/vWKbJYg1NQBp
         HFvw==
X-Forwarded-Encrypted: i=3; AJvYcCWG9gIzNkRRtGrPZRVdfvCsQ/OGB5abLtacPa1oiIdDU45EeBYJ3MDrvu1WLewl8yeQ/vMayg==@lfdr.de
X-Gm-Message-State: AOJu0Yx81mrM/QNRWZJlZaoNorw8u4ZzhbhV+dP9SKqKQpqK42BstvKh
	/O0eKilYlZncSr6vPTF1Oz8qWzsM4HAo47qsehLK1XFR9ffOS9kqaeQc
X-Google-Smtp-Source: AGHT+IHNyc6PjoV1y1euMPGdMmnYCDiQk/v4YTMmVHBH8ia+Zeg4DN8nqVrgfhyfhSFrdIqTTwPYUQ==
X-Received: by 2002:a17:902:d491:b0:2a0:f83d:c321 with SMTP id d9443c01a7336-2a3ee4403ecmr110458255ad.23.1768051264249;
        Sat, 10 Jan 2026 05:21:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hh8PlW+maUzHsGjfM7j8yKiajdLJlwR7/7R2pXKMUkZQ=="
Received: by 2002:a17:903:32d2:b0:295:dc2:6444 with SMTP id
 d9443c01a7336-2a3e2a45b19ls59260595ad.0.-pod-prod-04-us; Sat, 10 Jan 2026
 05:21:03 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWTCCNSEHnUFk1sgb+fd/F5rxBVUfxTE/gdZhshxE/FVXqA+asQULtVz8MHLsrcxpKj8OliRAXFJBE=@googlegroups.com
X-Received: by 2002:a17:902:d4cb:b0:2a0:ccee:b350 with SMTP id d9443c01a7336-2a3ee4c0ea8mr124388815ad.58.1768051262736;
        Sat, 10 Jan 2026 05:21:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768051262; cv=pass;
        d=google.com; s=arc-20240605;
        b=XCtwknE/DPyPceZTpFS28etK6oG23RKj2XxaPe/URhN0qCB+FPiy4LYII+DDcBd+8I
         VGrVzo5dAeShPPljQE7O9C59bki0+hy9z3rgb5KT9tDlReaOnLw6CEiqXBzE6GkGgGXJ
         XAbbxGGMGjBmf015QocP3m/p8c00QiY3WgIwmU7Df/Ui13vm4PQnhyVdYrmipEipHxCp
         7XKqQyoTQ1Wed/CNGF1muY1WGcFf8A3OrjNJ+/QKXwSsLoYA7U0o3jaMau9qw4hQJKII
         k9+vdd389Xs67mBZ6ZnpfUTXRS5FVouMMkGFUtbwMaC9PfafmF+ZCcLPiUQz2v6bEe6L
         7Nog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:content-language
         :from:references:cc:to:subject:user-agent:date:message-id
         :dkim-signature;
        bh=z8e1kCE6/mqj9bpn9gFAYjmhLo7kFY6txpTOvyk3cKQ=;
        fh=EXVbe9fsxJGDvjeHVErSCMk79xG8pxMuwoghtJ5lpoA=;
        b=QoMX7hPMVXVFa3DU7da4xz6PINU9QYCEW9b7tVA41F2pdGyet7/3zFBH+USE0Bvtfh
         tsSvF5zgpNKg/UB9ahmc1iqdKMlEkh1N11Gbkzp92IXdkF2bPUj3uQeKVfSL6CIbsMKB
         GB4xK0l/ZmFDII3xd0+grCCYFNch5SNJUe4RAqAfCjmvIqq0y8kOyNLJJVh3IyEs31Xf
         9BqepeZjrpS7IrOpCawD9TNhVy8mqOJLvkRrIcUH6C8H4Yzgrdarx9014PUJVoGwz8ys
         L98sNCC4G0xeS+51OEn4GxEA+Xs19Y26KBcAYC1gLeZ2td8bjMRP5uySmyeveuDa5MGw
         X9Uw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@meta.com header.s=s2048-2025-q2 header.b=K4rsntVp;
       arc=pass (i=1 spf=pass spfdomain=meta.com dkim=pass dkdomain=meta.com dmarc=pass fromdomain=meta.com);
       spf=pass (google.com: domain of prvs=94707e0023=clm@meta.com designates 67.231.145.42 as permitted sender) smtp.mailfrom="prvs=94707e0023=clm@meta.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=meta.com
Received: from mx0a-00082601.pphosted.com (mx0a-00082601.pphosted.com. [67.231.145.42])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a3e469c7cbsi3898375ad.2.2026.01.10.05.21.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 10 Jan 2026 05:21:02 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=94707e0023=clm@meta.com designates 67.231.145.42 as permitted sender) client-ip=67.231.145.42;
Received: from pps.filterd (m0044012.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60AAnpGb2152493;
	Sat, 10 Jan 2026 05:20:58 -0800
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010000.outbound.protection.outlook.com [52.101.56.0])
	by mx0a-00082601.pphosted.com (PPS) with ESMTPS id 4bknb0rg6b-1
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Sat, 10 Jan 2026 05:20:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yoSyJrmFKtRUT8a2/svSCx6pPEkNMMFG2dqiBaDAybKw9v0sgo8iUvAw6y5yPxJ8vRWNDGApmptzyhyEVC+OI5wJhWvQeGJJgLpO63H+ipDFGVf+gPQ4wIshexA9BmeHr53eS7nmj7P4OA+RfbMlwEaUi6xJVS6Vaq/A7C8SB7Mcqx4Y9Ab973qP91tTTg5PwWsPZpUFBv4GFEs9mQ7BmzESVbPKwgKyjy823AD9xMZ11ONIPcFFPyuUhaWdFXmxJJXakvLFtlt0eotOkFgZUjU58KT7OJz5qmfaOHcAi5Dd2U3zbd/T1J9v2Zsg+E0Xmr2hqh9nAng7NpVz8eskJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=z8e1kCE6/mqj9bpn9gFAYjmhLo7kFY6txpTOvyk3cKQ=;
 b=xoz8Y2SRZYh7q1LtUId1WWJwyMaBBe3QMJudSVmDhriH1eD6wFXkcRpiI4XlVVBBpSl9/F9w0dtuljX4gP8QpKN0IZSVu5Pzlw9ap8Y3TATUkttKNmrmM9CMLeWg/x4Ahbo1hdvrx1m5DqP3ZtM+37jr4MPW9LRqa/vjw2W5PjyvedmLYZXzb27BlnHbvzThAGnCbLBRlhsi38IGbSXJQsqjj3bS1F4JQ/CkrJymkIqe2rx/eyUndDGh5sTtNZtW3BwSVJj1AGmobPGax/LMYUpULRXcSpnuOWeLZtIzYS+ZVCjw6HVdkSQ3QqwVl5vwBXDKJN90Jf0cn9/NBwAWeg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=meta.com; dmarc=pass action=none header.from=meta.com;
 dkim=pass header.d=meta.com; arc=none
Received: from PH7PR15MB6463.namprd15.prod.outlook.com (2603:10b6:510:304::9)
 by SA1PR15MB6397.namprd15.prod.outlook.com (2603:10b6:806:3a6::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.6; Sat, 10 Jan
 2026 13:20:55 +0000
Received: from PH7PR15MB6463.namprd15.prod.outlook.com
 ([fe80::46c0:7653:5dde:4b66]) by PH7PR15MB6463.namprd15.prod.outlook.com
 ([fe80::46c0:7653:5dde:4b66%7]) with mapi id 15.20.9499.005; Sat, 10 Jan 2026
 13:20:55 +0000
Message-ID: <9a00f5c2-7c9b-44c3-a2ac-357f46f25095@meta.com>
Date: Sat, 10 Jan 2026 08:20:40 -0500
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
To: Vlastimil Babka <vbabka@suse.cz>,
        Roman Gushchin <roman.gushchin@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>, Harry Yoo <harry.yoo@oracle.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com,
        Petr Tesarik <ptesarik@suse.com>,
        "Paul E . McKenney" <paulmck@kernel.org>
References: <20251024142927.780367-1-clm@meta.com>
 <28e6827e-f689-45d9-b2b5-804a8aafad2e@suse.cz>
From: "'Chris Mason' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <28e6827e-f689-45d9-b2b5-804a8aafad2e@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: BN1PR10CA0009.namprd10.prod.outlook.com
 (2603:10b6:408:e0::14) To PH7PR15MB6463.namprd15.prod.outlook.com
 (2603:10b6:510:304::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR15MB6463:EE_|SA1PR15MB6397:EE_
X-MS-Office365-Filtering-Correlation-Id: bd000a1f-dab8-4d0b-376d-08de504b15c1
X-FB-Source: Internal
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?WEtxZzJxMTJ5UFVEREtybGV6Ump6NVo2UHZxTGhIaWovd1h3bFZ4SHJwNWln?=
 =?utf-8?B?MVV4QzRMQlFBeG5hd2FMVXZiVk1mcEZNNWVhcnNXTmNRZHJmRmdmczJPa3FZ?=
 =?utf-8?B?Ym9KRXBCcTlUZWlHZER1L2RBcnFNSHdjdzY0SzNzNWZzU09nazYwVXRhSHNR?=
 =?utf-8?B?QVhscUxtbFdDdHVCRFAxVlQzdWFsZGJzaG80K1MxeTBVd1o5NHVSbkxiZVRY?=
 =?utf-8?B?WUFKeXZJMkxYQW16R2ZpVHN5UXVOTEFBRVlFVWNETlhlVzBNL3ZrUWRVeEtr?=
 =?utf-8?B?TVRCbHRqMzBWREFFdTcybXpjOUtiZlFCVzkzZnQybjh0N3BjbkowRHlaYTB2?=
 =?utf-8?B?REFHa09ZcjRDZW1GZWx1NXp4UWZ0ZXdvMHVFTWRqclkrZlpFM2U5UHVHTkxF?=
 =?utf-8?B?TWxpUmVpblM2TEpFNlU3ZXdtNDFpTkxIcVhIR0dXV3NiYlRLUGZUQytXSFVn?=
 =?utf-8?B?RXh1Q1luNjVXaWlhR3BlL3hoM09xakNVSkdxNlBtRVBReUk2UnlRRXVvNlpv?=
 =?utf-8?B?SlV2b3FLZG1vY013Z3ovMi9KRlI3Z0N1dWFwOVRORUVrTHBCaDg2TmRhRER4?=
 =?utf-8?B?TW5qY2w0cGF0RG0rdWxvdTIxLzdINnFjUElwUTEzWmZVOGt1clFpSDNLOENi?=
 =?utf-8?B?Y0M1K2VmaitVRW90b211S0ZGOGdKV29Sd1RyUkxycHg2cm9NQTZ3WmJNbE4y?=
 =?utf-8?B?RDU0T2dFczN0ZjA3dGNISkJONnhxd25NNnJyMXNrRXNvWFQ3VTZSRXFUb21V?=
 =?utf-8?B?TnJGM3Z0N1E2VEdiVm4xMFdING03cE1YT1IvRktOamRYeWhoaE5US0tCcE95?=
 =?utf-8?B?T2dMR2NJWXdpai9pOGJZZkxJMmJWcjFxajlsZzl1MkZETFFWNU1CVStOcURR?=
 =?utf-8?B?cFYyRlRJc2VxR0RJemNPSVdPTGtFRTA0M29HcCs4YUp4Y240R0pmeGg2MTNY?=
 =?utf-8?B?TnNia3BmbWppd21nc1dpN2FvOG9zU1ZCbEYyeDhNaXk5VkdIZ0ZOMVAzYUxq?=
 =?utf-8?B?TDZBbU9FZGZlWmVVODNvcXFKa1duUlljRWVVbFZXNENmZUxDN1JFRlEyN1pu?=
 =?utf-8?B?MG1mUVZNUjVsemxlZDB3amErSy9qYVBSR0luTmh6akU4YTNkV2hNNUpRNCtP?=
 =?utf-8?B?Rk9ZS1M0OFd5MHh2TUk1WXhrdFpwYkttaTZMQUlPYi9LQmRxVE0xdnRNOXhn?=
 =?utf-8?B?Wjd6cDhvN3ZUdFpGeWpOV21xaHlTa2pnKys1QkVyMmFtaG56YUFvMlE5ejRS?=
 =?utf-8?B?NndwTmtpbkhwT1VpYXczalJHYkVZejNnTklYZkpvMndWVmxyamljM21mOUg2?=
 =?utf-8?B?eWNoZ1pHa2c3WjBRVisvQnEzVElYbThSbmJ6bm1lTmR1WDNLQmEzQThFMWRy?=
 =?utf-8?B?R3F1enpEaEs0ZTNFWEppSmJVVmlNRVIvaHNWZGRQbUE2VGpibld2MG9ER3Yw?=
 =?utf-8?B?bzFLSlV0RlU3TlBkTU9zaTg5MzUxOFNIQ2FURDdGWDRaQUhrbmVIUjFiV1Ur?=
 =?utf-8?B?S29XR1I0TUJXQW5aMFgxREhqNXhpZTBlK1FucWlXeWlYT2RtclltbVdVQkZl?=
 =?utf-8?B?SzRNSnlIYWFHQ3ovYlVCeDBWL0E5SkxVL015Rnd2RS92K2xBWVIvRHpraU1V?=
 =?utf-8?B?RGVZYnFjMzI3QkNtLzcveEl0cHR1cWpIUEpGZDhLTHdWSEVuS05QT28yVTlG?=
 =?utf-8?B?U0VNamZpNFVBL3FYRkZodDRmZUFXbE5YVllRUWRTUUJweXJxYjFEeXNGS1A5?=
 =?utf-8?B?b0g1Smh5NG9ieVdNV3paeEhUMk5rRUFpODVCZmpiTktubUo4MC91ZUZxS25i?=
 =?utf-8?B?UUpmZzBGOXFmVUhwNUYwdlU0QWxOSzlYZDBaL1VJYVI2VjcyMWVwZTZJWElL?=
 =?utf-8?B?V3lwZFNCZkUxSENIQTdjdmhNTmhEcFBOVFdQNkprUG84bDhoWWhNdkdUQWtW?=
 =?utf-8?Q?3dMvhgkqKH4mDQKxGxU+gNQrmMBzwVQI?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR15MB6463.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?R01FMjBpK2MvbTNkQXlXdXd1eG5LV2p6LzQ2dG5sTEhITWZKV2kxUW9ObUFL?=
 =?utf-8?B?bFhnNW9IdmY2OE5ubEVkelJ4RGFKTDJnMDR4N2hBRHFIRHF1amRrZXVyOHhJ?=
 =?utf-8?B?RkZPeHIwSTVLdkgyeFY0d1pUSDlQYmZuekRvUCtqVFVSVTl6UlBIQ3VCbUZC?=
 =?utf-8?B?VW5RcTB5MzR3b1AxWnNJMkI2THVOc2VvN0ZMdHhiSXRlWDEvRlYyUnFuWE1T?=
 =?utf-8?B?QXFQYkthTWpJRFozRlA0ZFhDYnVRdmt5RFdyZ2tiekNJalFxVGFYVjV3ZzZh?=
 =?utf-8?B?WFJ5RDc0N2pjaThEUzNYWC9uOUN2SzB5ZDNJd3RvbDNIYVdRRDBUN1BVY2xX?=
 =?utf-8?B?ZkMzQWVPWlNtSmVweU1BQVdYSFp4alBtVVZlWmRQTmpqMWNZRzJTYVVkUEZs?=
 =?utf-8?B?NEJkOHZTVXp4SU9Gd0pwb1B3WlF4RkdoNlcwSXFhZGx1ODJXK05zZ1VQd083?=
 =?utf-8?B?ZEs5Tk9NL2pxWjJFQzYvR3NTektIUldRZE9LZVFtTnRMWC9YTjJRUE4wc0hq?=
 =?utf-8?B?b1RLRE5Fcy9mUWFEcjJOdTJTcUFMbGxCNFhTdFhBVFdZYzROa3lGVzhtRmNh?=
 =?utf-8?B?VnpzM3J6WlJEYTdSK0ZxSUxpMHIyR2FtVWhZZkxqcmNBek5tdHBrcjh4dHdr?=
 =?utf-8?B?Rk93TWlseTB1RHpEWkFCYkliRnYzVHdTR2t6RitUWWFQVjRtNWg3eXVhc0tR?=
 =?utf-8?B?c1htQk9hNjhVeUpwSVhnTFJZZW1JaWJiT2ROZUcwM2s4YWVJOVZOd3phbUp4?=
 =?utf-8?B?bTZzZWU5S0xYTmxmN3Z0SktFQ1Q2aXpJNEl4ZnhqOTRsK3ZxR0NsRno0R25n?=
 =?utf-8?B?V2QxdGUveERBbFhPdHFlVDkvSzF6WHNPMlQ2dkxaRnMyOC95YjIzWTJmNjNW?=
 =?utf-8?B?NGlaU2hzWmE5dUd6eXliWmhUa25UbUhmMUl6T1I2SmV5QWdhK09RMERuTHhS?=
 =?utf-8?B?UGQ1ak9aS2tiMzVsekowWjB2czBsUXQrN3ZUdjRsTGlRdjkwV1A5R0ZVa0h0?=
 =?utf-8?B?eE5peTl6VHVDMEN3aDlFdU5IaDI2VEM3dDhSeVAyQ29IbzQ3K2NUUExyT1lx?=
 =?utf-8?B?ZmlMVHo4SjVVeU9XVDJwcU5SQnRwNW5OVElXWm5YUHRldENoeTRxeUQ1TWJZ?=
 =?utf-8?B?SUNZT2ZmTHJFUEN0a2V6Nk1LM0JHQzRzZURDcTRaTFE2WjZvOHRudGFSL0JN?=
 =?utf-8?B?U1U2bTEzeGRCaHh0VGpXZFIxMmowY1dvL3VlcFhEVzRxdlU1Q0pZODE4TTBN?=
 =?utf-8?B?N2VjeDB3TEhtdjd5UGM2QW9Pd2M2akswRTI3c0tMcG9IcDFFbTJhNmcxZ3Zj?=
 =?utf-8?B?U2RQYWJPUUh5VTh1UFdwZThXOTQ4UlF4RHNTdHFEdWpGcHhaUlBST01idjhh?=
 =?utf-8?B?akxzRTVsakV5YVJmNEVWRE5FOG1ES0JEMDUrejdlRGxrUkQxdjRmZVpYWk5k?=
 =?utf-8?B?ZmNybmZXenhFK2tCUXZPSnNEdXdDekdwbXZFR0pyRDc4R2EzcmpweGdYd1hV?=
 =?utf-8?B?WjFDYjBjc2hTWkk5c1FWTS8xZ2NOeHBkSFVYUnZ2WTVGM0tFVTFXd2FEcGNi?=
 =?utf-8?B?VHM3UkVxQTBDVFRqaG14bTFYZXQwdy9heTVrVEVLL2pkS3ViaHBNQzFUallk?=
 =?utf-8?B?aGlXcFlGaEg5dlM0SXdLU1JLRVJjd2owSDdBOFl5eERZV2VLMVU0akpxd0Rq?=
 =?utf-8?B?d2dYZWVxeUJjc2hXM0U1VythVUg5ZmRQYzVJTlJxb2YvNkcxdDY1SW5UbFNI?=
 =?utf-8?B?a2M0eG1hQ2xnV3FVQ2N0QWZYY3YxaWdMNVFoWS90T01QTjd3OHRyQzVIVC9n?=
 =?utf-8?B?UWNQejNKU3dZMXpmTUk4VFFCaTRkSWttTlFybmlyU29mVlJEQmxQQVJDQ1Vz?=
 =?utf-8?B?UkxSbzhqTERwUks1TloyOWpWcHNRNFBOaXkzQjZXUW0xeE5aUC9odXdDcytv?=
 =?utf-8?B?dk9QZjRoNC9CdktKaU1VTktlS3hQM1lQUGRWUGtIQnJTNVJJdlMvQm9PMGhj?=
 =?utf-8?B?dVFmN0g3bmhHbjFJbmh2a3E3WXA5aS8vS24xR1Y0Z29HVEtqWC9qcEp3aXpU?=
 =?utf-8?B?K1dSem9QMDZUN1hLSFRVWlVNS24vQnI0cmlHOWoxMnZmSDN5SExnRDFnbEl2?=
 =?utf-8?B?TXpvTU05aEZqOWRoNDJXelMrTVY3M2IvWEdpUGVlVVRib0UzSVptOEpSajgy?=
 =?utf-8?B?L3d0OExzcm9obVVyYzFXNlNwQXJFZWpNSnBHdEhaOVdXUUdWKzNvUjNxWnFC?=
 =?utf-8?B?cVlsb1pIczFhTWlhTHdiaXY0aGhna0t3QW9kUzhhZDl2NHFnM09sUEpiZzdk?=
 =?utf-8?Q?4EhDbEoRDTEUzairhp?=
X-OriginatorOrg: meta.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bd000a1f-dab8-4d0b-376d-08de504b15c1
X-MS-Exchange-CrossTenant-AuthSource: PH7PR15MB6463.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Jan 2026 13:20:55.3316
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 0BLxQHLd96Z2xYuHu43CjGHrEGk8KXe1S38Mg0dKKkYJw/tD4pFHIvDv71gaqgsD
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR15MB6397
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTEwMDExNSBTYWx0ZWRfX3DLlQR0zpr2C
 WkTmJjsDMr1si/LhvBL1Hc0RUYQ/m+Wa6WXt+ZPrjTKOFTuhhFImbA1DeKGYMyaa7GWMgFD5vei
 IDi9OnKmHCLKiWL9mtWODOJzcjEt8TpqwrcndE/ipOdz4P8LzErMdCqmuEC90MNObSlYbJjEiQb
 Qa0d11N2S1Xa1peUdQHbgi0Lbd5on9LFLODk3YIjeraxmv7XrwQKPiUhB51mfvEtpeq8V0czqgv
 4EMYHjczm3e+m/ButnxhfWhzPy7HxNP+GYDVidn0WLj87+m1RXrNBRr/fghK7j1mS+15w35SKBZ
 JOlR1Z0qYtmbYNaWeX6d/uTeKX0rDj7TOp9LaL9lb4vDuyKSdKgMYHI6jJlTh38gtP3XBOigltd
 dgYyUgOYd08mx7NHlrtUFI8KTU9wiw2NZFIxB8LCNi95Eu30DyvzQm7otpPRwVB5pH7aVZdqEg7
 L3a+V7KB7Da3bVg8Yfg==
X-Proofpoint-GUID: AQuIC213qOHcAVfrUIIso3-_pBqcCyas
X-Authority-Analysis: v=2.4 cv=f4VFxeyM c=1 sm=1 tr=0 ts=6962523a cx=c_pps
 a=EtrKi/+kAVY73poqiPL3VQ==:117 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19
 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19
 a=xqWC_Br6kY4A:10 a=IkcTkHD0fZMA:10 a=vUbySO9Y5rIA:10
 a=VkNPw1HP01LnGYTKEx00:22 a=vv0Oz4QAI_S6nznekUsA:9 a=QEXdDO2ut3YA:10
X-Proofpoint-ORIG-GUID: AQuIC213qOHcAVfrUIIso3-_pBqcCyas
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-10_04,2026-01-09_02,2025-10-01_01
X-Original-Sender: clm@meta.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@meta.com header.s=s2048-2025-q2 header.b=K4rsntVp;       arc=pass
 (i=1 spf=pass spfdomain=meta.com dkim=pass dkdomain=meta.com dmarc=pass
 fromdomain=meta.com);       spf=pass (google.com: domain of
 prvs=94707e0023=clm@meta.com designates 67.231.145.42 as permitted sender)
 smtp.mailfrom="prvs=94707e0023=clm@meta.com";       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=meta.com
X-Original-From: Chris Mason <clm@meta.com>
Reply-To: Chris Mason <clm@meta.com>
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

On 1/9/26 3:16 AM, Vlastimil Babka wrote:
> On 10/24/25 16:29, Chris Mason wrote:
>> On Thu, 23 Oct 2025 15:52:32 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

[ ... ]

> By the way, there was another bug in this patch, causing a severe memory
> leak, which the AI unfortunately didn't flag. Petr reported it during
> performance testing and it took me more than a day to find it. Oh well :)
> 
> Wonder if things got better since then perhaps, and your or Roman's tools
> would find it today? :)

Yes and no.  It didn't find the leak until I changed the prompt to say:
"there is a leak, find it".  I'll see if I can improve things...

> diff --git a/mm/slub.c b/mm/slub.c
> --- a/mm/slub.c
> +++ b/mm/slub.c

[ ... ]

> @@ -3592,54 +3549,53 @@ static void *get_partial_node(struct kmem_cache *s,
>  	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>  		return NULL;
>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +
> +		struct freelist_counters old, new;
> +
>  		if (!pfmemalloc_match(slab, pc->flags))
>  			continue;
>
>  		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> -			void *object = alloc_single_from_partial(s, n, slab,
> +			object = alloc_single_from_partial(s, n, slab,
>  							pc->orig_size);
> -			if (object) {
> -				partial = slab;
> -				pc->object = object;
> +			if (object)
>  				break;
> -			}
>  			continue;
>  		}
>
> +		/*
> +		 * get a single object from the slab. This might race against
> +		 * __slab_free(), which however has to take the list_lock if
> +		 * it's about to make the slab fully free.
> +		 */
> +		do {
> +			old.freelist = slab->freelist;
> +			old.counters = slab->counters;
> +
> +			new.freelist = get_freepointer(s, old.freelist);
> +			new.counters = old.counters;
> +			new.inuse++;
> +
> +		} while (!__slab_update_freelist(s, slab, &old, &new, "get_partial_node"));
> +
> +		object = old.freelist;
> +		if (!new.freelist)
> +			remove_partial(n, slab);

Is there a missing break statement here? The debug path above breaks out
of the loop after successfully allocating an object, but this non-debug
path continues iterating through the partial list. Each iteration overwrites
the object variable, so previously allocated objects would be leaked.

The commit message says "Now we only want to return a single object" which
matches the debug path behavior, but the non-debug path appears to allocate
from every matching slab in the list.

> 	}
>  	spin_unlock_irqrestore(&n->list_lock, flags);
> -	return partial;
> +	return object;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9a00f5c2-7c9b-44c3-a2ac-357f46f25095%40meta.com.
