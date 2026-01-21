Return-Path: <kasan-dev+bncBC37BC7E2QERBLGNYDFQMGQELV2P3HY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YG28NK4mcGmyWwAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBLGNYDFQMGQELV2P3HY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 02:06:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5898A4EDFC
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 02:06:54 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-8c6a291e7fasf979808285a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:06:54 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768957613; cv=pass;
        d=google.com; s=arc-20240605;
        b=DVduG4Dq9Jzk3W+Qq1DId1qZXRJzbAkWV+KX/JU6lJq0D0JsL4UuaJ2YoleAr3+Kc4
         fBHvC62+biE11s+xB7IaA4sCvrol3PjgNa8/ZjRQsJuw5fykIAFDFxkP2bV/Km+CbLLO
         uTNJDAiH2Y2q60ZepITEKK1/OED4ecu6v4pRsDNb4YNHns6KvcsNUjvdRJUvNeeBQNGh
         zK00RAFBi9r+azdz9g2IRWNOyem2vzypFQ1mwZSPgd5H7fHZlnn7QdV9/iKd76UVAwa+
         vQJe8OkfCNEsLf6OKiSGHvd0IVcjPzdYYoGKOK0ZKwgj4fKVUdP+hPt0dt29cowqPAiK
         MGXQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WFf1eyOB9VCP3VRgMuRsei1xOCRJVzW04lGPW08B7G4=;
        fh=hjQXdWGCGKes5RFMcXxfTMBZ3UdubHOZnbMo7daDeY4=;
        b=ftnQiljM/X299QVi0ZN6E/POkT1q2BrlT24q6nzj2bUsYkaLOsIP2srutEsTFsnIhB
         esOCau39Rxk4zDI4JUVxkA+kYzwilxpp5hA7+V6xnxD4gaV1wzrT1FmKWKz82Y/4wyEG
         b/0P8ZQxeuOjf0m1f45WCDiZtEbZpGtN+DoUQEl4U4I/VQJa3ZGfjDHi5XGMY7I7QQEN
         OmQ+XKm32JD0X1e5QrpgiY/Q5KgdR51fPSnCWHTS2db8IoIJNNrprEWCTNcib2bfQTTQ
         3mhIaB56vhzYNQhufACCx3iLt/jnm5B5pFnBQZfCAHWESS+2STABByFRh+lKcgE1J+pR
         V0UA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dX5sHHWX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TMEp5MSr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768957613; x=1769562413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=WFf1eyOB9VCP3VRgMuRsei1xOCRJVzW04lGPW08B7G4=;
        b=dfJ3+lZbCDZX3Z7wE5uuV+vKJ/ra8+tpUVp7A4LPwFM9jhcR5X0WiXNXjMUjg35QTk
         phyDskjKBchFtzYqqe8Cg/pLF3qneyXBpF/KSx6hvbv3JM2Q6ewoXjLK8fwISUiOOQaY
         wb7ZSDweuZI7JXKG9DEgouGTaOv28evWdbNz6SN10VQQBQVf2Hi0x4NHHHBreMEqbEiB
         TO1g1KrMwlnEcZhTla/u3tWwtDTPIEfJmSkOXPjMjfDPWtWmX+MDMSsb1d2ZGhADK1gk
         rERABTiue1h34BHfpfgQKq4EOO4FWWbhIkJZUhEdueL1eTUduZHYWpk8+orpzYjE+eBV
         Besw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768957613; x=1769562413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WFf1eyOB9VCP3VRgMuRsei1xOCRJVzW04lGPW08B7G4=;
        b=aFtEfKQj8HqyeqB5vfKVtEBNMT5v4QJBkQcuDHM5qlnx1/lebRBNSA3RSwPUPRsGht
         9FeNmsmKwrMrr4hSLR7pZ5md4/Xsns2t9/9kLAOqKzEWfMx+gepkw7R1ZpfVKZujh1F8
         kg/mzCMNr5FxqgLgTNV5XzJ5ekzRY2XaxfH6utWfIR0jarIQzL1E3x7Qk6+R8Rrd0Rda
         nn6PhXaSmJ/FrnFFKNGkfLqmDGXWI+UlJCEhJ/QxLF3y6+hDF5CW9OPWyPLClk9zvcUe
         +gzCWGDk9ls6yX5Hy/PlFZEQ0pDEKG5JFb/cY25FlbsjuzZPwWFXEX0nszrkreYMptzg
         pQJw==
X-Forwarded-Encrypted: i=3; AJvYcCW6VEVYyqmjWeJ6BsJWDh1eTNuAsoyw8HmcvXWyAKmZkLgxiKNK9NpznyH6IqFQp8OQhLYcCQ==@lfdr.de
X-Gm-Message-State: AOJu0YxUacrL/p//mZNGHXjTwqxFC/wppeNLAiRJzkqAenjInmHM9Aow
	5W1B8he43v8zf9JN2l8b5zyBjmDkz9Fe81jDeyMvSF4r5L29XmlF+rg2
X-Received: by 2002:a05:620a:2913:b0:8c0:cd96:9bd9 with SMTP id af79cd13be357-8c6a6979feamr2258567785a.90.1768957612794;
        Tue, 20 Jan 2026 17:06:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eiltk8rz5EWYTXT/JuyCMARj1qGet84iP2+/yupWOZNg=="
Received: by 2002:ad4:5d62:0:b0:888:57c0:3d18 with SMTP id 6a1803df08f44-894222d67c7ls129182326d6.1.-pod-prod-04-us;
 Tue, 20 Jan 2026 17:06:51 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUF/DRCbxLPpzF5W//TrJGJ+QNciYtTYgp5kosV5qiV6s0GDhU39M/BH/s78KbH/4mN0iRqMso96xE=@googlegroups.com
X-Received: by 2002:a05:6102:304e:b0:5e4:95f6:3dca with SMTP id ada2fe7eead31-5f1a716f8e5mr6130315137.30.1768957611688;
        Tue, 20 Jan 2026 17:06:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768957611; cv=pass;
        d=google.com; s=arc-20240605;
        b=OHaPGaOOnuSCMgaxbPEhKOHqqjsHGWfIPfUgY+o1CsUdAP2SgnfdFRSkoBHAnMGt2F
         cPNbFB4QsuZsgQ2Cd6ro6CpRoPMLowUP5r3Y4MtpZGoKJKcjX9Pj3pKW8uz1kiG7tvgf
         1FC/iL9riUtDsVLORHJEQBus/69r6InwKR951WGx7u1weXHeLlBxZGNglmLSF24X6TYk
         FirubdG0HiJtEJV7HO9lRybvXgrO+cKlqHP+IyGHkPvLSFKtSU7p9zRlzZCu2JURAzce
         pH9Bts3M8cs2nB0jSz1D4Byg0bdkjHl2sa+ib5q2cm5ptg1aBQudJtUtXuoZWmB6RqD8
         VfGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=YoBTUVKkWSkcGCbsM3MIegGb6O/4W7SjN80DteeFGrg=;
        fh=TNvnfp43dsY3aVEuJzrpi2qwrvkTwBLK5sCpt64Tj/k=;
        b=gZOSuhWiWCpt1hoc0vsCs6MVGOb7HCmGhtpopWsj/yCpv0NrZAWP+Ui+xSFbLCmrER
         y7wjN80XG8qPj/bWLBTUXAK7NrEDDRGk99sBHDh/F0oWSIoQmHem1KgXGXzLvEcps76z
         cGMExnoQdqs7My73q16q+V3iGwB2YCy562bCow7nQw4JZzi0ii1bsWpDDGNHXDXUYkqy
         Yj0cHC/44/OCUuwOzRggXsVE+knO+YRsY+ZVVApTf9QlC9hZC3WcVwA0kotQ34HrAeCY
         U4n/U+hdcgvsEOq7jhX2vhPMMz89EpNpNYJ86B1hwqwMEHCgNS6WM54P8QzbJGFEBVkm
         oKBg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dX5sHHWX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TMEp5MSr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-947d04920b6si503274241.3.2026.01.20.17.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 17:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60KIRdZw3523865;
	Wed, 21 Jan 2026 01:06:49 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br21qcvgr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 21 Jan 2026 01:06:48 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60L0MwTg021921;
	Wed, 21 Jan 2026 01:06:48 GMT
Received: from sa9pr02cu001.outbound.protection.outlook.com (mail-southcentralusazon11013051.outbound.protection.outlook.com [40.93.196.51])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0ve95n7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 21 Jan 2026 01:06:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sqVOI5nOkbzT+gpKuCaPLOOaWUuXD6oAsra3kcx0MJkGdBc4nXWf4itOur08ZGRXOtW3JYYxmeIV38nUK2w56jlsCFvnl7OVNb82tYo6zCbt+WQ4yU+eXUYwwp2vf5rCbJNP6bg/b/plCylUFNNHU6yEy+2uWk0y9me/TvRzZjq8OgR7u9BoYGIub2ztSC+/lRMAs5/AfzxMhCpiNg2waWtx1Zf+0Z9M26V33NsXlMl2Bg3I4aBo5dcbo1IkIj4/9NS0vKgW4YvcQGG6oVezzYYZj3njmDVIHY5r53czJ14hOLrHHMnhZnm3gmD3gGYrt5a0MUIsn2VjzJ3qCVtDHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YoBTUVKkWSkcGCbsM3MIegGb6O/4W7SjN80DteeFGrg=;
 b=vPLobErUddArjcFMVRphD2BeentV0dWZgUv+hAJGFUmWvUmLfL0Ney6PqBiAGAODVIzrlMx1B+o6cQXDpkF5Hed+WMO2Tk61Zylf42ZGSmXbTIORNa3kqHXaFmtRc6DDjnraqRuIOHl7/sdWtPraoJ1yevdjSZQua7ljV3Zr90uMO0OXGl64x619JFOHuMTRyiLZF4O71TMJFY9tYaHZP0RbiQa6eRWeIWtMP01PGOyRzIRNKG6bgHmUK3ZFCiZqqYtHSwQ+VNgqsQGV+feHWVq+UbKk0QKleXC4MiNhxExU3x+9cng4ygiIsQAogxvrUoUpt6Q90OAhqJLDc6CYog==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DS0PR10MB7341.namprd10.prod.outlook.com (2603:10b6:8:f8::22) by
 LV8PR10MB7822.namprd10.prod.outlook.com (2603:10b6:408:1e8::6) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9542.9; Wed, 21 Jan 2026 01:06:45 +0000
Received: from DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d]) by DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d%5]) with mapi id 15.20.9542.008; Wed, 21 Jan 2026
 01:06:45 +0000
Date: Wed, 21 Jan 2026 10:06:37 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
Message-ID: <aXAmnbhynV3xUKPW@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
 <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
 <aXAkwLsGP9rqamKL@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aXAkwLsGP9rqamKL@hyeyoo>
X-ClientProxiedBy: SEWP216CA0150.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2be::15) To DS0PR10MB7341.namprd10.prod.outlook.com
 (2603:10b6:8:f8::22)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS0PR10MB7341:EE_|LV8PR10MB7822:EE_
X-MS-Office365-Filtering-Correlation-Id: 67cdaf47-38bd-43a6-0b56-08de5889584e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?aVJpS3NVK1RuYk9WbDhLZjFhcGhacFh0ZDVucjBieXl2WUE1U0hzSHhnMFdC?=
 =?utf-8?B?clBESGVUQjJYcUtmeXZnNW8yYVNaaGtabUFRcjgxbEF1WHFJd0YrYTZ2Z1Nk?=
 =?utf-8?B?QmdRbkVuY1Z1bjRiMFRCR2kyYmc2aGx4TU9uRzZXQStvODZxQmtMTkQ1cVRr?=
 =?utf-8?B?S2xycEpZdkNPT2RPam5CZ1ZLbzlETEQ4Nys1dnArazJEWWkvd252ZHV5TzNH?=
 =?utf-8?B?YmVjb3RJWnB5Q1l3R2ZCR3I4TVlZR0haeUs2UjQvTTVXOU5qWkYyUCtjUG9p?=
 =?utf-8?B?S0VJZ3YrTWpOK2hTSXQrUFhKT1ZPT08rQk8zK0lEZjV5MkV2U1lLSU10VTE3?=
 =?utf-8?B?T2VUeFNNQ0VZUHNnQVFCTXk3QjBkMDJIcFVpRCtsWjVYYmVLMXdTN0VNNFBi?=
 =?utf-8?B?TFBSMytBNStvUmN4a0xkZW1vNWp4WDlzUEI2b05GSVJyVDVVNnJtVlVzcjBF?=
 =?utf-8?B?SFpIdVNkL3R4YlBZbW1JU2ZvRVhJUGdoTlJ5TGxmcmgvWHRaaGNOVXpRang3?=
 =?utf-8?B?U2JYeEU2ZWJqSzA1OTNHYnAwc0hhVllYV3lxNEpXQWZ2T1NyNUVZY1QvNk5l?=
 =?utf-8?B?d1JuYWk1eU5LZ2ozbTdNVUtvd1ZDVG56S1BtSldSbE4yMU9oZDZJTXF3UW1x?=
 =?utf-8?B?QXorcm1tR0VaUHZNVEk1QklkYW1nOXk4aVMvSjhLWFd1RzB3ZCtWVXIzMytM?=
 =?utf-8?B?YWFOcy9UNHV0WlIxM0UvN0F1OEtFY1pyUERxbHVxRzR1ZnpYZ0VGdlZrSWMz?=
 =?utf-8?B?MlZ4OFJ2QVIrTm50bWVGK0ZIVjMrZVJmWlV5dUJOUWNyZ1l3aGh2Zy9aRUNt?=
 =?utf-8?B?V3RmQXFvMStqQjhtbDFFK3dFQVpkZytjbjBoYk1oK01uSms3TDV2UDAxZHNm?=
 =?utf-8?B?azBrRmdMdm5STTB3QVBML1cyL1FYNUtuMFdqSFNBZXlJcExNaC9iVlU0R3hu?=
 =?utf-8?B?aGVLS2pjU3FjZ1BSUC9QdjJYbVdKcVFUa3hERHc1bVpLUUZEY1QyMjIxbDdl?=
 =?utf-8?B?QTN3a1ZLWjJaN2lCWVRWWXo0ZmVqRk95V0xYVlU1OXFqcXRQWEtMa3EyU056?=
 =?utf-8?B?aFY5eWloY2MzbHhZRkRqYkFObXJFakZRWTRlWXJ0Q2hzaXprRm4wdDZlZDFY?=
 =?utf-8?B?Qno0M2NSMnlIVDdya1VWdzFrV3pLMjdTSTlXR0FFRlVpMnJ1czdBRXJPc3ZG?=
 =?utf-8?B?RFQ4cllmWEZWL2dqdzJGNm42dFJYaUdrOVhuVDdpZWpudkxQSXZGZUdCZndH?=
 =?utf-8?B?dFdKd01pTFc0VUNrWkJFRER6TDFtMGtvUGdlVktlWnZGU3hML0JmSVpqanQx?=
 =?utf-8?B?dWpiTWtEZlhFbWN6czBGenJ1VlBEbk84emZnU3ZPTERMd2VONGs4QnRBcHJ2?=
 =?utf-8?B?c3JMeDRHMXltRkMwa2RsdWJDR3d0ZEVJa3VsbjFabDFQRzBWdnFPSFVnOW9p?=
 =?utf-8?B?elFwWHBRMGQzWDkrN01wYzY5ZGlOcXBvYk1mSDZnOURaNTl4RENMS24wdmpa?=
 =?utf-8?B?dm9sTFdFQ09ZaG5BUFdzY0JrTnRsa1ovYmJ2Z1lYQ3N3NDE4KzQ2ekM1cG5t?=
 =?utf-8?B?UHNMSHovbFY0TXZEQkdiaDZ5a0NNUnd5TW4rRW5EL09KMDdhOU9sNVM3OUJL?=
 =?utf-8?B?L00rMEZzWDBCYUZxazJsQ3NKS2RiajFPZVVNVlhBV080SmNtYlhNZFpFRVhV?=
 =?utf-8?B?UWpsSjNtUkVOdmRwYTJjTk1PNXZaRFV3V1FQckNKMUZaQ084Vm9QZGxSZUxl?=
 =?utf-8?B?UUJIRWdUcG9WYkRTVUtPazVGY1cyNHNEdjhqR2tBYTFieGoya0JZcWVJejVr?=
 =?utf-8?B?c3l2NTRVTnNXQ3lGcFhPNVdCVEVqWGtnZXEwY1MyOEhRT29NbDU0bzJQclk5?=
 =?utf-8?B?dVdpYlR3YTNOOEZEdmYzNGNBZ1BzUFdwRTNRcWRBbEVGbHlRN0pVK0JzTTJn?=
 =?utf-8?B?aTNPcXhhZGYyMFpDcXZJMHM5Z3Y4dVg2aFhOcGhHVlQvT1RXbjlST1hxb21t?=
 =?utf-8?B?ajZvelhqSlFOdG1jc21HVTQ3Mmc0L3BLdWpGakRWelVrSUxKeVNCYVduMDQ4?=
 =?utf-8?B?cU9PMng4eW5pQXJpVGlueFdQMnRDMHZocVNIWUlMSU44QmxwVkJOblRnU1pj?=
 =?utf-8?Q?Lt7I=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS0PR10MB7341.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Tkk1bzBtbnVXVDRqMm12Q2NiMHVJOWNLY1RKQ2Rrajc0enVkSEllaUhFRitx?=
 =?utf-8?B?S2ZhOGxFVHBXM1JPRVROQVhOQ2V4K0IrMGR1OFpUWFlKaFRrUTR4NndMbEpi?=
 =?utf-8?B?MDIvVHlyY3M0bGQ3VWZSSDJCVCtQZlBSNFErYWFGcWVBdGErVGpydGRDdmhm?=
 =?utf-8?B?aTBIM2krNGY0bnZtQSs1TmpkYTNGVmcySGNCTkhQUzI1Mmlad1BOQ2tWMndX?=
 =?utf-8?B?TGtjbjhhbGRHbVIyRDdlR2hGZGtvWEl4eEFkamtxdVZVNU52QzdUVEx4U0U1?=
 =?utf-8?B?ZGxZTWNOc3dUcmtLNXdvVWNLRVUzNU1hQndBZFBtUjlpclovUnVzY1JIejVu?=
 =?utf-8?B?WkdDb1R1L0srbm9LNjBEaGNzWTlRdEpOZnZTdEdjYVdIVnJUNDkwSmxQbXM4?=
 =?utf-8?B?N1Y0ZTYwcm1maXdnUDdxdnJZTHU0Y1pRQXA2SW90L2F1VGU2OGZtMEhOdmI1?=
 =?utf-8?B?UEJ3bStRWlJkUlRVTE0zMkJQYUxMN3RWNTc0VEFEZ3dQWnZ3TnhpUjVIUEdD?=
 =?utf-8?B?S2ZUQklHeXRJNnM0NSttMnZBb0ptVnFqdk9HVUlCeDhJNys1b2E0WHBHejg3?=
 =?utf-8?B?N1lwSnB6WnZmcHFkS0RxZ3NkK1htMlpndTBCUmlrbWRmVS9WUWFBNU1tNUV6?=
 =?utf-8?B?SmUyQmhIWmRVKzl3bTlTZW9ZYlpVYmRuRkhlSUJxZzZZYmhtcjRIYmEzTGxr?=
 =?utf-8?B?Z2NjYlhFL3JRbEdXZ3NraFViVGhuaURDQy9XK2ZSWWNDUHpnaGt5aWNYZFJ0?=
 =?utf-8?B?bG4vZkhWaDBrbGtHckFXMmxiZDRUbmJiaVB4aHFSQ0tjeEVLck9LZlRqbFMx?=
 =?utf-8?B?bTJDTytpbXNnTGl4OGZFNWsyd0VHVXJOdVhDUkp6TXZYTDFGcEpzd2tDRy9w?=
 =?utf-8?B?eFg3eVA3aTk5SlNhMlg1N3hMUmwxdC94WWpiYVRwTXY1dHFJajcyOXlyMFg4?=
 =?utf-8?B?YXVlYlFtUjJQeSs4SWh2dXptOHZJZ1RkblkyUVpDa0R2UXB5M3VNWFFER1o0?=
 =?utf-8?B?dXJXZ2FPL0phV0R0Z1hPWlVXaWNCM1pESk93N04vU21tbXJJSXk5d3Qwb3Iw?=
 =?utf-8?B?dUFxdFJ4a3hkYjlub2laYU5CNnRiQ3NncDltUU9UQURoWmFDcTgzb1ZUelQ5?=
 =?utf-8?B?S3ZGMFoxRjh2TXRnNmlRM2VVQnBHc1B0QUdlT2duNmRsanIyTEF4TzExdzBh?=
 =?utf-8?B?bjBFangvK1B3RFpTTWRxRnd4ektpYzRBdHdHRnhPZC80azBQUGdMbDdOckJS?=
 =?utf-8?B?WGRQYUtMTURxbE1STklYeDNiTUUxeklzVXJBMzhTYUJNdkw4K0ZUaklMTTNZ?=
 =?utf-8?B?bkxycFpJUERPSUpZMTdnaWgvbnlkNmJJeDZ2VExIVWNpclp6NFlCQldtVCtx?=
 =?utf-8?B?RVlDeVNuSnF2YUo0elFoRWlkdGJtSEFUbTVkNEtrc2xqanJmR3ZQMXdkWk5a?=
 =?utf-8?B?dEZ0TjlkT1drUHNyM3d4MHFlVlhjbmVBeERSd0FrMEpQUVUzUXFCN3RmUzRj?=
 =?utf-8?B?VGphdDNDbXlucjNPc0ZzczE4d1QxUTlla3NIZjhxTGtBL0swWFVsVDFJa3ZY?=
 =?utf-8?B?YStBckRRWWQ4aE1KMEcrNkVnT2NEUDVGM3dLTGF5d0E2cXNNZWFmS0dJT282?=
 =?utf-8?B?QTdERTIyQ29iSGRmYi9PZkVMUEsvdTl4T0tJR3hNRHRLRUp0QjJ5N2djL01v?=
 =?utf-8?B?VVlhQ2N6QytKK2ZpY1BxSnZORSthVHZ6Mis3M1BsZ3AwZm93aVJHam5hRVhP?=
 =?utf-8?B?elpSeGhXZldHUFg3UE1BZnRXRTNFNDg5cURmVnZ6WFJodzl1MGM0R2lnOW9V?=
 =?utf-8?B?NFllRzNGQ0VNTkxDc09LUmhWdGVVMzFvR3FNZFJ2U3p0dFpzVkNvWmxnZklX?=
 =?utf-8?B?dEJobTlXOWVwRzFSYm5MSnRjb0dWbHA4VEdhcjR6NllCYzVnZ0Jrcmh1RDVN?=
 =?utf-8?B?YUJ3eE85V0J6dWZwWDRLYUQwa0EwRURlS0JLWDJoRGZPVWltZ2VOR2FJTWQx?=
 =?utf-8?B?T1gwYjV4dTBYZkwrY0F6S2pwRjNndjFlNEdqY05qRWxURGhEZmt0TWM0dnFl?=
 =?utf-8?B?QTV2QVRvbHBtV21RNERIeFNob1ZSREJVUHNucklCd2NnbXdTN01qK2diSkZm?=
 =?utf-8?B?TzcxN0VDdTRDZ0xnVjZLb0RIYUFhNDZkUHI1R3ZvVW1uM0hpWnhoKzFkWExI?=
 =?utf-8?B?VFJSZHB2RUNiNEtxTFQyWDdGekp0VjlJR2ZXQWxGUHhTc0Z3WDJ5NTNOR3RG?=
 =?utf-8?B?TFFLc0hLQzRhdUNRZEdkT3ZjQXpwTldEY1k2czRERy8xWjJZbkVMY013a0xy?=
 =?utf-8?B?OHZNNXI0UTRybmovT3ZENjFqWHhmdTZ3dlo0SHNwQ0dSalJKS2c2Zz09?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: QG6imd5a7QUckIdCrhzT+9CKrNWBFhm685b7xtJ0d0rTFesAjV3L94auHNTRuZ8Vz1xAvaVi0DuSJtEPLTD6Q83UBnmERAqO18hOXGco5Ts1QEch8mMoT00Vi2fQjG//0Xyi6uodJtd3LMYpTBE9SfIVU/T7AipshCtPRqu2muqxRYkR/bTRyo+2+vb1L87s5gjehyB/9MVW7Okeq1/cRxa7n/xfwNhgk2nq7w+urhjYSiXchAeNr/8oN7Dq43IJiBE90UVHo/JRHlroOZFpgeNhpmRrlmOEzfpnEiqwanMTbUMXOcn3X/dFGhfuQtyGj2vURiiNjU8hlXwH8NkgCLaICIuGKpwbrKuea06wIwci1u9+hp8OUs5wwRvDvP+Q9Nmb1yE79CM29XgmbgDGRYybazeGQbqCGFumJT1cMM4a4h8NifINjrw5+deVKO1/nLGYGAx9w0CYV3Sz5f1kSbKVOkljkz+s0mQOOHSidJ7XZtl14afbRPwgoxZ8GeDc+zAGATDxuwZ5rPm6jq1zQXwgR/WC3WYxrUnUDnupF/8qlzq9QjJW5rB90m3QuvUePzWuf32mbZ7pwpK7T2MWqjz6jFOJgrIv8QdxSeyGZKE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 67cdaf47-38bd-43a6-0b56-08de5889584e
X-MS-Exchange-CrossTenant-AuthSource: DS0PR10MB7341.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Jan 2026 01:06:44.9921
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CyrhhbB2dOTaG4Y2e/fvMfWIqLF7WsXc+tUxCDKIhbp/CfInXSnncreTRWjLn4Gn1YTrs3fnk6iMqAiZ30loCw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV8PR10MB7822
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-20_06,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 phishscore=0 mlxlogscore=965 mlxscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601210007
X-Proofpoint-GUID: 0Rrxh7mdonmBjsLj5GBju7_uPUH0ynGM
X-Proofpoint-ORIG-GUID: 0Rrxh7mdonmBjsLj5GBju7_uPUH0ynGM
X-Authority-Analysis: v=2.4 cv=QdJrf8bv c=1 sm=1 tr=0 ts=697026a9 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=IkcTkHD0fZMA:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=88JjD3xRybQXUDNOIxwA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10 cc=ntf
 awl=host:12103
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIxMDAwNyBTYWx0ZWRfX/qHyMH+AzNuF
 uRMk49DJhmQyoI2R+QdXlld3LdD47Oe3JZtn82YE8XnieG9K4/V06AN162ndWIO/f3jGO+uu/a1
 +kzvtva+OX1GU89HZ6tUwihwfxmWcxWrz2t4YecBTsBfFptkgUUq9LHU0z6VTY2uJtdlvkmByJx
 wcEiHcyLvbOmmPb8R2YZVv5ZSJYLOq+sG4r9NGRNGzf4lFtvaVolqcN91iENlH6jtUy5zDPQDX7
 oCRIIeufejNj6qeQCPiXlzD44TTIV4/VOiS7cpWLSw+Ci3HNybZ/9qJKN8laiaQRS4MsZxZKXdE
 CSaOw3Shfk4iz3ZElrHStRy8fL7bdvG4h/1cw8viqguF6Sr0xtR0b3XAdDhQf1qvQnP0Ko/36iv
 0VxQggR7nQdDq/z8Du6VhygUPwP0Yu5nXEOTDqDbnNDZKOL9t2lL8bhE/8+2CQhNrEEOEOe/w73
 3luGpPgtUY3iIVGfHtt6oaq1vCwUv2kWgaeAg6nk=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=dX5sHHWX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=TMEp5MSr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[suse.cz,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBLGNYDFQMGQELV2P3HY];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,oracle.com:replyto,googlegroups.com:email,googlegroups.com:dkim];
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
X-Rspamd-Queue-Id: 5898A4EDFC
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 09:58:40AM +0900, Harry Yoo wrote:
> On Tue, Jan 20, 2026 at 10:25:27PM +0000, Suren Baghdasaryan wrote:
> > On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> > > @@ -5744,10 +5553,9 @@ static void __slab_free(struct kmem_cache *s, =
struct slab *slab,
> > >
> > >         /*
> > >          * Objects left in the slab. If it was not on the partial lis=
t before
> > > -        * then add it. This can only happen when cache has no per cp=
u partial
> > > -        * list otherwise we would have put it there.
> > > +        * then add it.
> > >          */
> > > -       if (!IS_ENABLED(CONFIG_SLUB_CPU_PARTIAL) && unlikely(was_full=
)) {
> > > +       if (unlikely(was_full)) {
> >=20
> > This is not really related to your change but I wonder why we check
> > for was_full to detect that the slab was not on partial list instead
> > of checking !on_node_partial... They might be equivalent at this point
> > but it's still a bit confusing.
>=20
> If we only know that a slab is not on the partial list, we cannot
> manipulate its list because it may be on a linked list that cannot
> handle list manipulation outside function
> (e.g., pc.slabs in __refill_objects()).
>=20
> If it's not on the partial list, we can safely manipulate the list
> only when we know it was full. It's safe because full slabs are not
> supposed to be on any list (except for debug caches, where frees are
> done via free_to_partial_list()).

Of course, when a slab was frozen, this doesn't apply and __slab_free()
explicitly handles that case.

--=20
Cheers,
Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
XAmnbhynV3xUKPW%40hyeyoo.
