Return-Path: <kasan-dev+bncBAABBU6N4XCAMGQE25ZDNLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FF5FB1FE38
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 05:43:17 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30bd2b8a948sf1793197fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 20:43:16 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754883795; cv=pass;
        d=google.com; s=arc-20240605;
        b=IdI+3Mra8JHzcXKc7vHVAWWs61uvBF9ovP6zTKWAIRNNDtBLGM0Oz7vk2r3TdjJo/r
         mZI+LqLNsit96OpGmc5W6TQ4pnHaZol1Zf/jIMjRSSo2dHcfkucUHdPbgG5MZBa6T4ZY
         1/7qsNDjbd2yJek7/1ZApV7OYRz8N9ig3aMzA7dYM5r0U7BuZ0AAj6H0YiY5Nu/rGtjE
         Ajkg6q7iVnSIV65p0IV1o8yLa0DI5h6CX9O8aeUTdTG2jCJp5E5cIK+CjodtU+ggDXV5
         TpFa0t3k1nZZAHVjJTyfAWWYQ7Gd8hPgjH8MxLEL9BhvPYbaUo2ZMBgFnNQk2I8ytLEN
         uYjQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=Dg9/GDwN9tO9zRjhN2hehdDlotEyBNEMlT5deBFlLUE=;
        fh=7p7/76U5ACbO0I9Dy0Bu0eKismcqHmPCjVcoxmxZWQA=;
        b=Xa7ig11qn00f8n90Gl4ZwVBBzE6VLb/FZalSbdB972743sYsLpIANMV5odQMPmJ80r
         2Hu6j3R0WM8qnapKlukfIigNXelkeO+z/z3ovXTl1opj9ru11GFDTmrczsQK3I84dKw1
         Um77WHMAErZt0EKs4f8DnxxRewjBGqujRryZioSPplXsXK4Zw9r+i0uw49Ttip7zfYZh
         pL810y6y+AHpa5jPh/ESiCBMf6s1ttMYNStgEfMe1LpJF81seVBsT/G7zF96XXpIJM6e
         5CHFNqHkEfh9i9hnlYV2Oi1iw/LYd5nqCxtiUjipyMkpaRK7gTTmgglJmxI5pkJ8qMaa
         4IrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@vivo.com header.s=selector2 header.b="M2VjGCe/";
       arc=pass (i=1 spf=pass spfdomain=vivo.com dkim=pass dkdomain=vivo.com dmarc=pass fromdomain=vivo.com);
       spf=pass (google.com: domain of zhao.xichao@vivo.com designates 2a01:111:f403:c405::7 as permitted sender) smtp.mailfrom=zhao.xichao@vivo.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=vivo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754883795; x=1755488595; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Dg9/GDwN9tO9zRjhN2hehdDlotEyBNEMlT5deBFlLUE=;
        b=pnSlrb2bexoyNF6p4+rPFr6VmSC3/XaOuGML4pTer02QA2/haTMiDLiHZCgygKuqc3
         wl4wZF+bL16g5QBY+SiQJyxpkVYNyvZ9ScY6L8hXY2t6oHLTVB99Tzk4v0VGFM3nf91M
         mmerytBvoR1XaHCiz3rPJfIJfyztpwIF/BV7lfLTey7nQCMz+K1JrkToeaLMfH4mX5UV
         fD1B3v4DQErQogELyRNh5QBf0DdCl8Xb6V8td4srxuyDmFSOWpEqQxq77pi56dhC08GA
         7xYiIT42QxOr5weemAvq69BfwTNiJNFOn4BUYVmGaHvh2DUiq4rho1RLOyzufiKmfrm+
         rnDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754883795; x=1755488595;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Dg9/GDwN9tO9zRjhN2hehdDlotEyBNEMlT5deBFlLUE=;
        b=mEGJCmqFk04zDNBmJRlLSEnhNJcnAFZcBjMlLCim9vgUh2/nbfDcDP8yKRNmiWJGck
         VJq7LsYf+S+tdmMJ6rWNTWtIP6e6ZldQVE8In/YGrW0Hu7duSOEO8ZIS5HxrJNJRKROw
         S5ZPuFo9ST3OWR78CXbSzIhYTPtyPtGNH7Yz6tDqYAynbJg1zTUKqwnJJmDcR/9HqcJE
         HEuaU97FTyRahzYfR1bL9OSYBPJwW3NBGkWLyMNmY86eSvx0qRQpzme7jrI/1iv70UtK
         6cErgIMNaO0CzuFhddFwm9V0RgaXJzrr7wIODHe50vOFxtDh8OMzOXWyCXcQY9uh0vAy
         Yk4Q==
X-Forwarded-Encrypted: i=3; AJvYcCWBJgEMBhxak0RTHC5dDO1T1YxuHB8n2+8k7qi8scDSranmyCzSPs6nJf51zE4JJGJfXuk0MA==@lfdr.de
X-Gm-Message-State: AOJu0YyT8sMArg1t4H41yPWh14RVu6xm3yO88J2CrSHxMUrcsQAiVIjw
	PK6yhSk2V+qlB0PnmIqHzGzv6+pLowjinxACMhF2mFhSzGE3JpW2Rhyw
X-Google-Smtp-Source: AGHT+IGlV2sUgIjdt6+h/SnSaYMepbbY3vI6EvOwNn7vqU2a0E/QKi9zO5jQ3LJ1EvAl54hv7sP57g==
X-Received: by 2002:a05:6870:8992:b0:30b:cb15:28b1 with SMTP id 586e51a60fabf-30c20f2d908mr6341894fac.7.1754883795505;
        Sun, 10 Aug 2025 20:43:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCg0+apOxHP9eGLZTtmULudJFnr560wmFRuBO8DRS9Nw==
Received: by 2002:a05:6870:1707:b0:30b:76e3:703 with SMTP id
 586e51a60fabf-30bfe7323d3ls1745479fac.2.-pod-prod-06-us; Sun, 10 Aug 2025
 20:43:14 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUNzNh+sYoD1C996I9OCbqTi81nx4vEtjOmXVvzFeosBZXMAYoOXlCLHAwwiV9UcTqKO1A8ZZhe84s=@googlegroups.com
X-Received: by 2002:a05:6871:810:b0:30b:cff2:7be with SMTP id 586e51a60fabf-30c20f90ecamr7954048fac.9.1754883794667;
        Sun, 10 Aug 2025 20:43:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754883794; cv=pass;
        d=google.com; s=arc-20240605;
        b=crCjeWLUgSbf/STMs+8xMe9jRRAdMKNwxS1+zRVMC1uwM8xT+LkLnZ8XI6c0CXD0RO
         j/kAw/DbbGPY5KWcRXrEo4ngqdpbdsK3dkDYklyNB48J19A/Mqv2j2RfyX9YcR8uNbfA
         6TJcZUrML8S+u36/dctkO3Wh1lpeVckg8ouNwRz4gdAiSaTTPG7VgGOJTYs9GTqmVAHF
         1u0vfsC7uDJFmu0O5m+IGH9Lppi9rUA4SO1Ze9c48LpL0X63SAhdEGM+yNbaSoUp1Sg5
         QbKOzezT5BDsp5l0G64JcGPhjOip4rTuVGcuPpq/sS186iayiSSqna5KrjJaiKfSO6At
         IfuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=bZNhe5BaW2iApbq4BISISCgpd4cNpGKbdxT255hz7Wg=;
        fh=4TFMe8xDyX3HNwBTGoaRvp3bt2qfc7KA131+Hn5ml6U=;
        b=Zp+C+ZHy4MoSsURdWTk0zvzcJoBUhOUiVSVCBX6ZREUIjp9frqa4NM1atkhfC3nTtW
         e3svfISTJ1FLhMnOd4vIXVArHHL8eHwqoL/b4GdMv7CVFivvq0nMBjGivvz2mpinPv2o
         Sy278qH2aLCdRDVhxRq/0yUvVJXXTBALYV2u5ZsyAvErE9NLriRJ4DRcMgw3fPy7GUz0
         CmNrmBrp1eq4fbwlC6y3VdiQsaGXp6Pzfw6z/ugbMhAWwguB0/yc9uzhMjKeOCupcBh1
         hTUZZB5tZU8zRtdOLbjpm4wl2VQ2dJvCYn8/AlubqjIUJMQK1P4PFrrkAi/7nhWdAbiA
         ngeQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@vivo.com header.s=selector2 header.b="M2VjGCe/";
       arc=pass (i=1 spf=pass spfdomain=vivo.com dkim=pass dkdomain=vivo.com dmarc=pass fromdomain=vivo.com);
       spf=pass (google.com: domain of zhao.xichao@vivo.com designates 2a01:111:f403:c405::7 as permitted sender) smtp.mailfrom=zhao.xichao@vivo.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=vivo.com
Received: from TYDPR03CU002.outbound.protection.outlook.com (mail-japaneastazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c405::7])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bd07efb28si316110fac.1.2025.08.10.20.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 20:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhao.xichao@vivo.com designates 2a01:111:f403:c405::7 as permitted sender) client-ip=2a01:111:f403:c405::7;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=qbZRApYT/LGA78jbg0WUkczHMKP4BfeDD3ripegcsCc747HzYBTaMJVaHCS/MJGXD4dek1UXXJ9Tj/XhhEFYKDOkr2g8m+Rig+U6Fsa33gD0snihGzRGtZ1stXfephlpdjwc9uqNUm9TDKuxfY10IeeQ/tJNR/TqdaU0LOFxva6IWNZE5ZuT/tAmhu7q+NLvMrnNLkQwNbBlS5KNd2PeEREomEt0941rRdsuRQmwACFMggkQK3yUkkzR+mxlBpollqLR6p2A0Ic/ytDU1pgEnbDNNmFrQ9nIEcm+A/wLBNxjr6w5/DDT3lYc2F4xx8PoB1xAFXcHmARJfrON4lLMeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bZNhe5BaW2iApbq4BISISCgpd4cNpGKbdxT255hz7Wg=;
 b=TYna/2s+40InNjKaDIPO8U9K8xqtvZ2Be26Xj0eEZ9YnRYVnF5QQpFBjkxEpnk9gsRIPSpkYuEzQkyrr8AKbNlVwjRmu/MOdTpRmb5ZEGk7eDinWUqr7EddEzm1GTvmdJW60lR2LZvftIsu4anJvXKqpd92Jwg83yCwTAwnNRSsvRcQD2p7zNYKWMQs/W3Lziz2c4Hy+bDKCAfMz+uO2NXACpWuen5OSuLjk3zzSFwtjKaL6n816zQz1VcA6y9w/OqxqiwxLFcGLi0qveUCA9u9k7c/GF3zpiDVNLnnIil0H+0uy8KKsbpvXYlbPDvYq5YIp35WL03AU2I8dzhsAuA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=vivo.com; dmarc=pass action=none header.from=vivo.com;
 dkim=pass header.d=vivo.com; arc=none
Received: from KL1PR06MB6020.apcprd06.prod.outlook.com (2603:1096:820:d8::5)
 by KL1PR06MB6905.apcprd06.prod.outlook.com (2603:1096:820:12a::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 03:43:10 +0000
Received: from KL1PR06MB6020.apcprd06.prod.outlook.com
 ([fe80::4ec9:a94d:c986:2ceb]) by KL1PR06MB6020.apcprd06.prod.outlook.com
 ([fe80::4ec9:a94d:c986:2ceb%5]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 03:43:09 +0000
From: "'Xichao Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
To: ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org
Cc: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Xichao Zhao <zhao.xichao@vivo.com>
Subject: [PATCH] mm: remove unnecessary pointer variables
Date: Mon, 11 Aug 2025 11:42:57 +0800
Message-Id: <20250811034257.154862-1-zhao.xichao@vivo.com>
X-Mailer: git-send-email 2.34.1
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SI2PR06CA0010.apcprd06.prod.outlook.com
 (2603:1096:4:186::6) To KL1PR06MB6020.apcprd06.prod.outlook.com
 (2603:1096:820:d8::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: KL1PR06MB6020:EE_|KL1PR06MB6905:EE_
X-MS-Office365-Filtering-Correlation-Id: b6d5bf0e-e28c-4ecb-d7ca-08ddd889300a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|52116014|366016|1800799024|38350700014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?gJEwACizBY95GLMfpwdcFxphKcIprvpNrtNMmb7X9aVDsFEd4wQzEi3V37QU?=
 =?us-ascii?Q?DKlmRlPh99mqsw4qdHMRPtvQP0Wk283OW7VyCnhw7RnRXdtxSiKGxxr1Vb7m?=
 =?us-ascii?Q?tePkwEcgjyxcA5S4Aa7AcwcvwkzFvjHbDkT9MiHCRb8Iv1Vw9QJNR2/Z5sMN?=
 =?us-ascii?Q?VIcmzDwYaNY2VpvMUqVDBvJ6y2agLMwPWg6ifx+yV+fpcBK1WH0QVD0y3aO0?=
 =?us-ascii?Q?G/lZIrEGEVu+m1Xfh7i3t1xpov2zhTkvc4w0CKU/w1ou3Ck1IwkYwPdE9END?=
 =?us-ascii?Q?JTSMd0Cvdlbhoacb2IxmQFSyEm/2YC3pjQTnuh4S4uKhAvNT7EuPq6BC+cQp?=
 =?us-ascii?Q?I0HaPBclICJwyVLppzQO1wcglZLnP5pjZKLlp9y6gvm502ahbAEJvherPbKI?=
 =?us-ascii?Q?ovipOYXna3JsGol3K7BgTmCBD3lZXcpZCs8iymZh2vz2yDxyd23vgfLDagAi?=
 =?us-ascii?Q?rgA8BiT0NEfahi6OojPhpGks56IrN6CnPLF8U2KA7v9QwtMGPpD9mvV/2qg9?=
 =?us-ascii?Q?ZAmiaY94Li/aZxT4IqCDEAdFLv6K/atPQKoquKUOWPQ45+BE0JDgHW/KO7dU?=
 =?us-ascii?Q?TpQ6VsuPkTQoXrFlZt1J4Sn9EFFFcMTksbb8iBDcVmMSu53x1xJQ0qBjeUVG?=
 =?us-ascii?Q?k+9C7rv1RvDP8Kklonv82CFCYbE5YqwjiKmSI6GT6QV9rhjAHhOVr6emXwad?=
 =?us-ascii?Q?KsQ0VlhB8qpWYDb3eqIxfk4eGk5aO2NaHlqjVijhn24RkPF3Xd/vIC+/hfXp?=
 =?us-ascii?Q?hB2p7V0VPnzavjr8OknhLzX1vod9j3o4fLSnqumBhrc+4G8dqxMKPWdmAAHO?=
 =?us-ascii?Q?UCgxdDPfMLQpK9ep5iIP/84N7xwCn6CqBud1pWZW6HRfB4jomxW7bt0i+uZb?=
 =?us-ascii?Q?C+DVaitLZVi+QFQItmWPfYuUZ4YlF+EUdb/rKRocb7ok0akg7frWP/dEL+LG?=
 =?us-ascii?Q?Gy2wu7gtU9E2dEJqiIhz9/3tyjxd3JqEjuquFFcgg/kRzqPJLR1dufjGThM8?=
 =?us-ascii?Q?j42SaWxhnbqx5+IVvBnxzPvJC1t/nw5tDM3EkkZ0G04ykt1F8z7/a1N0/7Yp?=
 =?us-ascii?Q?unvedN+IX3U6bQvE8FSchLUVugQBlYmKf0e9Js++TuZveusXo+tdxfZY9T3U?=
 =?us-ascii?Q?IiAYEKOI4YezRB5C/b9QTvhSCAM+akR/8f/CIixQWLS7QbFo7sbdeGtlIHBo?=
 =?us-ascii?Q?LyYyGN53QYHHfcAx1oekrWpIf5ZS5zcBV6p+rdCVEaX9j56y2MMBYXRZb4e2?=
 =?us-ascii?Q?xD3njz476QE4HD81ZP6MEG3nZ6X/dPfEdKSAj7hfBbIDtjePkgrJ994SEAU9?=
 =?us-ascii?Q?72ZegQVrKz016MXy3XmzYpjr7RXwGGPa1Juj9KlpK8txOn+nhj+2jXbletlI?=
 =?us-ascii?Q?HDaELCCaC+Fy2bhnBx7on8ZCt+QqSRt4YzxwnnFSD2yLJvcnIijYf6CX+EKI?=
 =?us-ascii?Q?kp8gszew2vAbvccVmLrHWAXgmiLoVLOOYAdWJQaIuUVXGwPbkdztBQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:KL1PR06MB6020.apcprd06.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(52116014)(366016)(1800799024)(38350700014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?DYgUskcmN8t8YZCtpnCUK2+q0dnww4b/ZB2OSTeA9qtZ/DYn50n5MdNILY4q?=
 =?us-ascii?Q?rKxRnzTFF9U3r/j8M+65o9EvYNryjd7CqLlBPGc5Ty8ciptHrlOT/A2dU8HC?=
 =?us-ascii?Q?LbP9g/ovwDlwfy+e5a1e7/HWpojzAqjjlxaPZbONisKBKDg5H4hz/34SkBtO?=
 =?us-ascii?Q?jCmOY0I4YUFiNlfkaIwSEzoVi8jAODqfK/givtxpCLhz7dvJHbV7oP0Dg25I?=
 =?us-ascii?Q?+YU7OpX4I/EoHAjHPKQXUCMU3NMOzin1CsZWKpeRS0CCIiJLGxXCWMOOBjuF?=
 =?us-ascii?Q?gaqWw8IvfblWkClsVEVqmUSZorz71vFunmqY30iA06pmAvReZ9jlHdi2XfnC?=
 =?us-ascii?Q?gYL9VDZ1kduiHyy/TFMdDjNBlOW0tww9kR2DI25G2vB8dCcBDNAv/pEzFCNb?=
 =?us-ascii?Q?ApHDiRN+vemfufZp9gQATkHBgvzqPjVllxcdPS/3nsLqopOzCtTnoOSf6Ef1?=
 =?us-ascii?Q?jK/zGY2ooOxNpBMQKgURjihhB5BQjw6Eo0PlZxwwy8Gwy4lmZSEx8bsOIAK9?=
 =?us-ascii?Q?Olj5qj67CkG62Wa46BvuoIZTe0MlM1ijOKjw+NBYblnqrJIXR84RCExg3xgC?=
 =?us-ascii?Q?qnX1lbROzlJtnmZ2wFeVzfFdoB7patfxhi1OdrQzo6CRxPiitJLQX4Ap7Ij9?=
 =?us-ascii?Q?7O31n9kekZ3l2vdJ5/HayHH28DLddR5+YkngdhqTRtLzVO4FXc0gRQDMuIKv?=
 =?us-ascii?Q?6QZl1SK1g/YQlYukQigXSCI9TBjDR/aISKEk7sm4eZ54tdOGKBXXuujCna+i?=
 =?us-ascii?Q?z96cII6RKt4CCtH+FMUXLF7aeCSKmm2IYQPk2rowWVx43YYAYmKnZDqu8bqa?=
 =?us-ascii?Q?1sK5UWPvrcynYVnNBwaaNfobg8Werul6eQCI3dzRa4irtZJsiH33pKwzESyN?=
 =?us-ascii?Q?hLi5ZRx2kqBiXLIiSHsOjlu084D75NR9g669CPc2uwafRFj3uLoVBrgVTIkf?=
 =?us-ascii?Q?4cQajrSRhwK60B4vc/oV9EBtnHL1rdVDasXvkyUvoPCAK7GBN5ALv0aksAZj?=
 =?us-ascii?Q?BnvCa7xIHQRBozRu12FEWLgjSmVPvsm57qEQNEr3Yvl3PQFnsgJgS/4z1SIt?=
 =?us-ascii?Q?WV7Jbgq6ndNh3QOuScWBeV1jw0O/7X9q6f1tL2HMEeWdWxsiw+T316hNZ727?=
 =?us-ascii?Q?ESeaol74C2CAHo7s32GSozMhPFRWX49I5MpJNPJYvzCohoMweMxpdjnXjK6k?=
 =?us-ascii?Q?yx/LEBns7jI21uWgfnvDDBcdMzd8mvdV0gLFpE/9d57OAqaBngLxe3blXnPA?=
 =?us-ascii?Q?hUEQzT22hAQwzDbpad9L1gp3iQFsdN/XkDjE82zX/1E/Rf+DfvhRhXkO0qI6?=
 =?us-ascii?Q?ZaiuVCNhXPZmvVLQ0XnM6rYeTKtYNR6uNIiUGnJ3rNHM4mM8Gd16MOpZ6dgy?=
 =?us-ascii?Q?6D2p7bbn94OsndkGLiX08wkkLHnvkQUvGcWAO3e56q4CunAr/O2LmOX0IcbI?=
 =?us-ascii?Q?s5N39JKhYn0GXYkD8Wy5kPLy+qKZKdBUe8iY9OePWsJ3AdLXkq6983lLg02w?=
 =?us-ascii?Q?74yfGIHRggPgOI8/4bAGqfSIp+ATDvLEhmUWT28/Q8gwHH+GIgTNTikiB6HO?=
 =?us-ascii?Q?nvOvPDRh3AvWYuhUUSFM7WPnUU+4dU2rW/T5H+qy?=
X-OriginatorOrg: vivo.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b6d5bf0e-e28c-4ecb-d7ca-08ddd889300a
X-MS-Exchange-CrossTenant-AuthSource: KL1PR06MB6020.apcprd06.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 03:43:08.9219
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 923e42dc-48d5-4cbe-b582-1a797a6412ed
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: aXO4m8Y5Rb4rZJad121IBGX3PBedG2sX8QGGdY54OZFHWkIZKtmTaOnf+yLkvbDung0en05Yj0OcPD7OFhwMYg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: KL1PR06MB6905
X-Original-Sender: zhao.xichao@vivo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@vivo.com header.s=selector2 header.b="M2VjGCe/";       arc=pass
 (i=1 spf=pass spfdomain=vivo.com dkim=pass dkdomain=vivo.com dmarc=pass
 fromdomain=vivo.com);       spf=pass (google.com: domain of
 zhao.xichao@vivo.com designates 2a01:111:f403:c405::7 as permitted sender)
 smtp.mailfrom=zhao.xichao@vivo.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=vivo.com
X-Original-From: Xichao Zhao <zhao.xichao@vivo.com>
Reply-To: Xichao Zhao <zhao.xichao@vivo.com>
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

Simplify the code to enhance readability and maintain a consistent
coding style.

Signed-off-by: Xichao Zhao <zhao.xichao@vivo.com>
---
 mm/kasan/init.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ced6b29fcf76..e5810134813c 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -266,11 +266,9 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 		}
 
 		if (pgd_none(*pgd)) {
-			p4d_t *p;
 
 			if (slab_is_available()) {
-				p = p4d_alloc(&init_mm, pgd, addr);
-				if (!p)
+				if (!p4d_alloc(&init_mm, pgd, addr))
 					return -ENOMEM;
 			} else {
 				pgd_populate(&init_mm, pgd,
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811034257.154862-1-zhao.xichao%40vivo.com.
