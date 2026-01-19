Return-Path: <kasan-dev+bncBC37BC7E2QERB7H7W3FQMGQEDMZBQXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C7CFD39DB5
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 06:24:13 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88a37ca7ffdsf50033036d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 21:24:13 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768800252; cv=pass;
        d=google.com; s=arc-20240605;
        b=QN6C3SCuEj4moHR4MfD9cNzRhnQVWA/zyT3I+QrHgOfAkBVEMNVkhHHnHFpH9viT7i
         vHpBw3VziJp22bOPlaIk2+4FEH30bRmAEujLcKBP8UIKqoiywP35B/3Lu4Bemhnle8B/
         CgQQ30cUzGC/zuDvUzbHnUIfjVoEGA+HZSjeItbU/IktX2Kg+5BAUJBlKzgTWo7dV9Ur
         pf2LCSFZyXqUtMaD9RDQxBIdUk25tl8mTF3gzL0yPQ3GL8smu5su9aPZx3CxSdmKMCt6
         LCKV3YggYmKwKr198G9a5F111qpuov9vFz4SdhzUE6Cvtv/iPj0zJybz+vUlHU9Ap1KJ
         JBow==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=GagOJcT/sGKmdckjLSe+yQSJoyRY9GGrgOdJIfuU7aY=;
        fh=j+I/G9AAZgWCZEXikr31W51qpJHIdLVuax4QEmFLj0w=;
        b=ZW8PeOEUBM7Te6jfkojARpma8IAbX8xXHKVKJ77Dt2Ro/SaGpWqbE7vRO1uD/ebaNI
         BhX5VlBUyRdjZpOSnU89uRnOZmLCOOQdUdalSRRXSH6t6/FPSnkhUjn2hN6Cct3JRWje
         3nr9NWFRdxwtDcZyjdiytn7AbsKfyQjMyUQ5XmDA2hVToaXpc8oZBpRcBYHNDixv1jyw
         wXqinrRlSKRn9nMISv+OqIcLZTbJjA50cBPHYEj1I/4GQe8ZuhxlDKr7/YpJkaROz4Dt
         +r4k8TGAj/cZG73qtQbOJvZiElhVDZ27+Eb+wHfUZ5KOdhAcFUsdJ4nffRK2UXt5SDPD
         gtjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="UdT/oLKJ";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hPOYcsjK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768800252; x=1769405052; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GagOJcT/sGKmdckjLSe+yQSJoyRY9GGrgOdJIfuU7aY=;
        b=o/jxpUrl9eadZz3PJVdXMXlfeSYKHJCzBY1Pq+KvLlrbUYx4wtbDqndYTCuxi9Vpou
         eb4mfui3eHzKH/9rIa1SYt11oOp/tffRZteTAI01GboCsOK7Fx0X2sDmPtCKRzmbbXVS
         RUEukULxv5SwsHUForpGCM9pNPFB5T9mZQiumjHAJ411jrSLv0qUxMMFmCQ6ZbUJlBYE
         FMal3gbCOnE1mOfdPaFcOofsrPUJ+yvHL00JCjHR7YicRoPFrbNavGqtz/JMIaTE4JFr
         AklRbRKe8U8j6LxmA42qHLnJ22lmzIOR5Le7GhxkEfD7jxCHInzNu8ec6Gm0iy68hWFJ
         KiTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768800252; x=1769405052;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GagOJcT/sGKmdckjLSe+yQSJoyRY9GGrgOdJIfuU7aY=;
        b=sUThJSsjggNrs3be3qqUXxcgyUuSYVUjt3h3qn/3Q7WuYXMrsyPRoRw/rB96/1jQ2L
         rli0NeKCEQaHnJpOGUXKqHd2VwgkY2y2CjZUWDFeeP1Jkwux0XKBhvYifXmWDS9RXoUy
         aLa25sHVCcQu+roT24UJMmcwreJ2kViYmLWuATcs3p1A6EWD05TBC0Yk2yzqQFjKCGvD
         SVvUKD2nXxQsc1ovD5BIE1Dp3bhT4Ysan4pL9mv92LxseYNbEpjTHBs3qanfg+50LWOo
         kl9IdXsKG+y5fTTKLlHNQyDw+q7y0Pgou91pyfcXEpTLAxAlJKfqGezqDQJnZbcWqzn9
         G+MQ==
X-Forwarded-Encrypted: i=3; AJvYcCUlN8rvDzp54w9H5gK1zYPiB+yNH73Ot0mhkSVCBkyqtnSD4TrySyDvnF4nXuWsXr7uSwcxrw==@lfdr.de
X-Gm-Message-State: AOJu0YxG+/RE3E9jxJSWYt7CJ6J2goKSMqTG9yuSgfSUSGhIlPGmQ5gE
	m1f6BKWHg0svH7pvJ5V+dykG7fNFTNDG8sK1HVmRcRz7w5CDRaRBWT7q
X-Received: by 2002:ad4:5f8c:0:b0:88a:52a1:2576 with SMTP id 6a1803df08f44-8942daf148bmr135924906d6.1.1768800252229;
        Sun, 18 Jan 2026 21:24:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ESDuXG8W04jSB5ahuCYT+co65svsrYTfrvjJAOLuGaog=="
Received: by 2002:a05:6214:1c09:b0:890:7f83:6625 with SMTP id
 6a1803df08f44-894222e2ab0ls58361206d6.1.-pod-prod-08-us; Sun, 18 Jan 2026
 21:24:11 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXbHO1J3sNCchU/HFzE+QNMdVkZwxmkLGcolk6tE1f+E3ebS9csAwqRI6X+iXkqfj0HomBRil/myEk=@googlegroups.com
X-Received: by 2002:a05:6122:a22:b0:55b:d85:507a with SMTP id 71dfb90a1353d-563b5b8a7a8mr2986498e0c.7.1768800251050;
        Sun, 18 Jan 2026 21:24:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768800251; cv=pass;
        d=google.com; s=arc-20240605;
        b=UQTxpH7t1jkcnmQ61zCn7cOahn7RggFv5hwHuoe9v2QEFBw9BPfyVocsZXW0ZFblZR
         hCFf1UZ0MR1tTjFPtNbx+mbYNxlJg8yz36IMFtlxbVzAgB5etSuIwMKiFP7+MNDsdYwI
         giQ53dM2vQTiAYgES+E+yKV7t5+3+Uc10Dwjd9EMP1Ig76kfYYu6+7pZBDgba/1YMX6a
         cK931F0RTIbl/WJDIoSCMUHeKDiksbT/Ad0QCXydCUHFu5UEa0kp5RJ66pXLEpUz7uJ9
         6yEeciPsTO51Ch4Tqyhx4DtAjwm7hZ66zYvWZhi6p7OI1FPsvlez+3m0ZiA0HJEp9jmQ
         HDhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=yQd8tGNhMEoO1zYbFnr2kU6aQZgjET0iEv5wGZojYvg=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=XNeIyhb6D0Q1J/6f1tsnNU7tYWuTUXzhsmychBhinlVz39biXYvMTvKm1eyHSI35D+
         6GPeMljrWhyAOqPiYaoMj5YbyhnMDoQ1sHiw3mxJBLzqW4QLOUqijfIz2V7f0v/9COC8
         UC0rTDFDK2PBMvp7O4OT3Usic5dTQ6j+WvjU/A+hcrSDL+5az6jb5qjQUl6xdUNNBo4o
         bSAX7gg4GIJOor6cUBumRPwrQM7j5PZEIkdg6jxLCtxjWC7P0PdslNlI9xiMfZJjGA8s
         yFQtXQgLrVDbzekKkZDFyf8cjQM2cyvKJjltpEftNANZcONcbiEZSFm7voOSQlzG0Yhl
         p0eQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="UdT/oLKJ";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hPOYcsjK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-563b716bcaasi280312e0c.8.2026.01.18.21.24.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Jan 2026 21:24:11 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60INj2UK4130755;
	Mon, 19 Jan 2026 05:24:06 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br2ypsmwx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 05:24:06 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60J2tw5H008423;
	Mon, 19 Jan 2026 05:24:05 GMT
Received: from sj2pr03cu001.outbound.protection.outlook.com (mail-westusazon11012047.outbound.protection.outlook.com [52.101.43.47])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0v7wufu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 05:24:05 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=UaMWx86tDkg6auWrZntrbirSzlYvAlotFagbCocIQ7zEnt2MNK0FuFAjwSTLe9mOwdAK15mFmxuzwlTrX7nJYLvHIk34t6MilL6wTB9NosktRYDao+/QMKoBDgX2R3w4FbpcMN1JIXYW6efc9/mkg6DO6Q3tHyddaoH506aCpZnMi95b5diAtECs6DMp+yXGoo7IwI7U9KrWNeqCYr6tl7rw0gh/5366lpLzpBPsnzYvCF0qjCaJ3N/+X6829vhsyVpU0tu3PNjnDIRmtOX5nxmAZ7dj67TtYC74e/t6qahSrFLRwG78P3wdnJXNb6t/UbevpzDj9HlfSRKugIdeRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=yQd8tGNhMEoO1zYbFnr2kU6aQZgjET0iEv5wGZojYvg=;
 b=YtuTn8ixqjfeeH8WnXErJooV8CuGdGiU8SvTPkk9xhk6Jk9/rD1jJ6D50LWwPaEFTXucMFSmcTuLj6cJSlSU7LCJ9ERbYEqz/9bGy6eqcTAdDNCzDKF+dEmCQkP+Or0HL13ckN1qdflivxrywWHWEZEG0zNXR0LMqCfbfYPX20/KmMRI2lOeGuschB0qobvPKKcMXjCfFZTDRNlMkRw0N8z10mSjENi52u0kCO2WpgfM2g/gn0aAradhlERSf/83HNVhfw7Q9xPMYDnVVHmx8crSKxPMnCDklRXiEKSCL4D+remuvrxPdpWMa7c2y6W5g0sFSMY98I1TNj4t/aAgOw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ0PR10MB4702.namprd10.prod.outlook.com (2603:10b6:a03:2af::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.10; Mon, 19 Jan
 2026 05:23:57 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.010; Mon, 19 Jan 2026
 05:23:57 +0000
Date: Mon, 19 Jan 2026 14:23:48 +0900
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
Subject: Re: [PATCH v3 08/21] slab: handle kmalloc sheaves bootstrap
Message-ID: <aW2_5LW5HgqdU4rr@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-8-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-8-5595cb000772@suse.cz>
X-ClientProxiedBy: SE2P216CA0095.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c2::10) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ0PR10MB4702:EE_
X-MS-Office365-Filtering-Correlation-Id: 13b7ad3b-04b3-4636-9e33-08de571af1ef
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?06J+KCReRB58nWPc4ZvSOwUNhHfElKeDbE8pfNEXPwd2qtB4Mo5szOdO0dyH?=
 =?us-ascii?Q?9LoQeGLcCWxLNmRVyPPMut527YWVdpRHvxGTwwmhEyim3+aoOl9zSSANyS0h?=
 =?us-ascii?Q?9QoVPxPcq+ilCSRVg3MN/ULDxRhpdx7FeOf0xjrTdsm5eyyYjBLe+GNk9qKF?=
 =?us-ascii?Q?KrJHoktiUreHKn5xd+2JWTxovPFRDl9nofh4Fs1T78wakxGkXR1IA/YEHlg0?=
 =?us-ascii?Q?RqWTTQHa+9qBKnPlUukFSTx1q6+5gPuFOCRPurKfoDWCEag0ITv15cFCwjG2?=
 =?us-ascii?Q?L/OdADAfT9arXvyq5NalZMF6LupHSVriRAPcGbzttpGNlwIQ782TO3FLae4q?=
 =?us-ascii?Q?YjK7HcKtN9Clc9vQIHeT+WIJS7oMJAUAuLOJWtgkcibNXVavyyrpjcvHPZB1?=
 =?us-ascii?Q?GtRRQ3Ct8vCAMyprLIpiL/asAUmCDvhiQt4iIMIeo/8wksnKDnpfatxq+vY8?=
 =?us-ascii?Q?JECs/c/DqUA/KMXxGlOSHcvX4v6WGafL56gJUSfbtkInY4T0rqDC3lnroSMa?=
 =?us-ascii?Q?XPhUybxSAgRvpV4Ry919B0GJmqo99u25HtU1f1p8WollaNi0Zh1diDgyuMc0?=
 =?us-ascii?Q?YXBEufM0EBwn/JxwRyvMyQVOln5nLS79iX0W9IX4OKhClDslBaa1YOKUiJTn?=
 =?us-ascii?Q?jyn5cNL/MN7AtIIhiZ32F1iypj+zLQlQ0R/qjcuUf5zCIEehLTQmVnxM1IdH?=
 =?us-ascii?Q?2wEoqe0MpQSaHuxjOqjzkIRBvAJzkorTD1DAMe4GjFm+jLE5Bu5sQwvL8WeQ?=
 =?us-ascii?Q?bypPNT0h2TVDkk6i8+r+q6zYdGIKltQW0l8Ir64dkiFraFsRLiSXC2aBt2R7?=
 =?us-ascii?Q?hswD3rCI6+Ka5GLk3iZ1Ikm0km4Exh4ErxlRGQWC+8tHMfCxsZ04Z1Sjx52Y?=
 =?us-ascii?Q?tq5VycT7PIGn/UE2hK+Bf52ZFC8k1YxNiVyKk66qtUPZe199OU6wmp5F4EzL?=
 =?us-ascii?Q?bxR9mufkY+Q0dupxj7jSnMtfY8e9VUq77+qNy0kHgIpoElnaGnnJuRFA4BfY?=
 =?us-ascii?Q?eCHTD/jKoUs43UoN84AqMgNc6xMVfOOCmp+mHMQu+1ePEgst3e34VutpE7Px?=
 =?us-ascii?Q?i812ZxUiDlvLXcrIUwt4GJjRF4Uh34Wliwrg/nACE5smZihbU74sg2CnEH1T?=
 =?us-ascii?Q?jyFozlMQxoXy0gVu79WQ9U6IPHOPOGmmGC8QT+Ql8koa+E+gqnRqeOYHxEAt?=
 =?us-ascii?Q?8Sveov0VtRBbIb7/Sddkd5e+jAMMBTsJtazdBmk5NoanT9QQuvk1Q6Ag9Dbj?=
 =?us-ascii?Q?/x3QNfqRWWkis5yvp04xrPY9hXHuvAPDewKQgpbrYIFQHJsI9+U3MIaxjDzx?=
 =?us-ascii?Q?NjoOcjqTA9zFrqfZJhsYvoSbi+FSuVyYS1fV5my2Mqi8Tyj10fvKzAJCvMEn?=
 =?us-ascii?Q?+5jkbw+3XQxlYolRX5nzXpfWs9Wj5lqZO6bYlgSK0FJc6nYbrn3J38aZ1iAi?=
 =?us-ascii?Q?fs6rzhYNE75GStOOUn+zmCWVoeoVVqdf3Sphax45XEIiKUroawHKfIaFmN1c?=
 =?us-ascii?Q?2HtVE2t5O+PQ7kqEq8Y7BHpcIYzlrVH+0Q3es501hE0S7qQuPBFlJt15X5+a?=
 =?us-ascii?Q?uybUjCoNl77r2CcE/bc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zSnmQxD5iymFZ+nfboKMuqjarAyMBE227dC/ynacVOHSlWhe2ie/zd+V2N6X?=
 =?us-ascii?Q?OKF0sYWbUlrWnEV8DRIz2qS9iGtWCoEZkeKuJ4z0MvL7pBppQ5Hu1wmquBYm?=
 =?us-ascii?Q?d7opkKEm6U31eRg+NUVq3jtkItsqplqLgSKv9ANHe4mhv7ou2VaYv6q8XVuD?=
 =?us-ascii?Q?+vgJ9vdawUZKqyUDf1kUHeyWGFkh9DLUBKvZfqn5B4bFu4peNDZ7xncAXBkB?=
 =?us-ascii?Q?WRpmQBr74QoZCKKnYYtmjduCkCu92x6+A8vG4dH1KfAlrwVNRYPZ/8ZzVp6+?=
 =?us-ascii?Q?GTGkUJ03hrvKcInGbEq0kJ+jDIqts6VzeqgsNbua380sFs35YrhczdbLUoIA?=
 =?us-ascii?Q?zw/wmPmTBMJoCQfvpag8cHgzfiUAC6cZkn1Lq5EvvwuWKM2yRJWfQnsreV2u?=
 =?us-ascii?Q?1uHK9TGptRFWtvbadeQsYshV+9qLWkRXMAIwtmpHiCLVlfh7P0tpvTiqDdta?=
 =?us-ascii?Q?c3Bm7+eo5O2E/2E7ENyzjc/VNMJFBduflfRH//xSrdS37KKz4Kh2a1wVNCOP?=
 =?us-ascii?Q?m3zshzW2i8TDI/aLBRRgIHkdN1nA6vp8RwRKlt3m9M63F8/Tq3JEB3cMuXsX?=
 =?us-ascii?Q?I+on5fqzWs12RjwhSXno9R2FPF2FDkcUVSksMeh2nS3F7rrGOFBsD/qHtrhL?=
 =?us-ascii?Q?8Y4iOm9baFzntsNuMPjlGj9oYO8Cfs52KOQ27Cbn/0XLr5L3gMAyfF+tsDkA?=
 =?us-ascii?Q?ipXxMfQYHAv2+E3GH9vg6TmAGS4SWLFBVAZYdGDcTNvH50wz4PfRWrHUoNW3?=
 =?us-ascii?Q?rZ25y0tK1BBUyMDAT8bSeF1FkudYGbocgzIJPyZlNFUH+LKJBHquwKoXfasC?=
 =?us-ascii?Q?CasvpCVkWv6qYczffhhyV7Cwmo/RCC18Cgu4POy6TlYrYDVyDO7gC65KXkX+?=
 =?us-ascii?Q?SAMWUSCsRzIdAnVcvYXxdMqReeaG3DBdxoo76FjWVu3EGjAzbMdJZPM7RB4j?=
 =?us-ascii?Q?g3tyOx1WAdXrz9a8uH6lmBKXY3A1haRlXLYfv2lyHgwggRavISfUX+E68Tvj?=
 =?us-ascii?Q?igmp0bJp+MJ+KdGDpRgjTn+UqjTiYUDBwmUy+pngCzZNfBf/YWSNt5LqRgXl?=
 =?us-ascii?Q?3WJeAlXW9QSCYFiXnKPJxsZxjTt6g2FSka9ZIpeyaiqnzDXngkGMvSGjCo3Y?=
 =?us-ascii?Q?Sv8CEPDPq+VYf6YaCJmIdYdveECi/Pa/bPImuaghdPoYdyRF10sx0Jq8seJU?=
 =?us-ascii?Q?HA+EY6q47kra2RFBm5ieSykwUvFDJUkombz4BcY+uf6cCYmqEFkuhB5pZDbU?=
 =?us-ascii?Q?x39WVjlo7ltLsmeEt3LENlGWDnj9dQ4guatZN7eAdcp1XiUWwF48LgyvEtq8?=
 =?us-ascii?Q?AgS4fzKj7ZvCPGYyoenLsLMZFJDIm6rQF46VbjRx+2OIrDZXjmxxqNIYtbUU?=
 =?us-ascii?Q?lhB8QKOvRaxxJOpKg9JVl3v4Sz/NVzvAQJVVIFq906ci1SEEnB9cidVsB/3W?=
 =?us-ascii?Q?2h5ngGhF8xZXoGALOXawx/tvi2IcQDgzwtRf7YwUt3iyfZh3347fQVkwjQTc?=
 =?us-ascii?Q?YLRCuEVqQTle9c0qLgaiXjG/7DtO1zMk8kU6X2GTUMsbTWZ08ucTaz1844W/?=
 =?us-ascii?Q?e8wJuWvzEg9CME2kxbpE4OkJ9fgf+aZBJEsdC/OxEeWLdquxBCtfz8Py8GGe?=
 =?us-ascii?Q?i9F8HtGs8PSAn8f6BHUtYCRr4xrx0G4203VnFjZCtRZkUOJTeVOTWy94MJN3?=
 =?us-ascii?Q?i3i2OOvl17DXkvRvfuFroIza/86sLyl7Biyr3UXMXbueZHkhPlEmYdXtEQBp?=
 =?us-ascii?Q?N7w2Kuu0BA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: pTxv2f6atCw6Ux0f+ZBxN+FKAC4dFNTsFCHzwlGtkirw7oB998pgUaGy6FUaiPmvIDrsksLXW7Lsg1lMppUTP7M7D/abXtRjsZUgMy/yECE6sZGTXa6RZKsOBCKbRy/quERflbe3m+0nG7lJ0fqLcG/kSwCKtKfy2MJo6OsI0c7MoXNlnJG3MUfA9WVY36TMnkj4iWUMxcCvOZDWOR8PUXRgXZuzIqlrSoPs8soXiC4qf3CIA916y9WsmIqb8mG8Ez3YGwA8jv3XBeYRSgtEU1+KRwUiSh4H02JADIalqKBsxVmA7koec/EsR5q70np9lmOXEZjoEzcvBV52osHUO/IX/rVbfuEweEMI9dtLv+xJabNBk3j/gK8G6yz7AUqCZ1NehEZZkw/dE+eVNI3HqBqxUiexQ+Y9khAKoX4RkpeN3mpfP6sCYLgawh7LPWAv7w8c+K6EZd0iEi9ZzQ08MXqdnotyUNe3CgIhFDDkDd4lscrtkFGyGDg+r8XlDwbqi6dBSHMy1HtZ4LblXlwPAg0YyX57Me0K9Q4/7E/M2lO7KRYaRmiUADQMPt90FyDUpY2glOANkBoYDywua5ND2pSksjYtLVxNYi/YdEyv21k=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 13b7ad3b-04b3-4636-9e33-08de571af1ef
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Jan 2026 05:23:57.4806
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kyb8wDXH9Z7o8VgtW4Qcd20QUfBDPqhGohKt13Ba6+VzMpGowr97hSt1Qo1r5hbNLXZak+FdoDrd6HBIXtVJ7w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4702
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-17_03,2026-01-18_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 mlxscore=0 spamscore=0
 malwarescore=0 bulkscore=0 adultscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601190042
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE5MDA0MiBTYWx0ZWRfX8lFaO9ykdjHS
 VIGwN7pyNMCmJ6NfA/2k77KVFKM2rzXQ7JKMkBGQXorQz0qzZdnBxsIiu+K2STiClpGxdSiUJ2v
 dAxr0L5lSBhV3hILst5rhAToi8Y7pr0l9aOykxoTdmZJAGGnm2PdOdT6PHijPLS2p6/9YXDJriQ
 CNNZiUcFFUA8AHlax0SJ+c97ljxdy+66+Gowu0LpTJ1i17bbtZkKvmsd9p8+U1KTd2TIFIA0coz
 cvfZxNmgoAo3rlnxYf3sS/c2/TV430pIe7m124+C6pEWPftSsl0sFRgMYbzdusSWDbrddBYbm18
 yDYhu4VBIdcZAbziIoRf4m8ovy3xs8fUfUvMa2pNRM3yIHp3F15hf9ZyNj3iZdnntI/ncJr78I1
 Jqg03AvjUJ6+Td9Q+0kUAD400W0N8v7IfOPIsWXECQopWvP15dvFDypgc49HhsQIlWHwVsXnLEM
 EpVQhbrKIKffpQylT8A==
X-Authority-Analysis: v=2.4 cv=de6NHHXe c=1 sm=1 tr=0 ts=696dbff6 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=CtFNG391Hm7LJwxQceIA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: 1x8UId_OGlfQDmFveKIk3aiugLk9C6w7
X-Proofpoint-GUID: 1x8UId_OGlfQDmFveKIk3aiugLk9C6w7
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="UdT/oLKJ";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=hPOYcsjK;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Jan 16, 2026 at 03:40:28PM +0100, Vlastimil Babka wrote:
> Enable sheaves for kmalloc caches. For other types than KMALLOC_NORMAL,
> we can simply allow them in calculate_sizes() as they are created later
> than KMALLOC_NORMAL caches and can allocate sheaves and barns from
> those.
> 
> For KMALLOC_NORMAL caches we perform additional step after first
> creating them without sheaves. Then bootstrap_cache_sheaves() simply
> allocates and initializes barns and sheaves and finally sets
> s->sheaf_capacity to make them actually used.
> 
> Afterwards the only caches left without sheaves (unless SLUB_TINY or
> debugging is enabled) are kmem_cache and kmem_cache_node. These are only
> used when creating or destroying other kmem_caches. Thus they are not
> performance critical and we can simply leave it that way.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW2_5LW5HgqdU4rr%40hyeyoo.
