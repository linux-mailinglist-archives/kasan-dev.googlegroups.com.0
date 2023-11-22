Return-Path: <kasan-dev+bncBAABBD547GVAMGQE4XOWCNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C9037F5101
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 21:01:21 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-41cdffe4d1csf1317151cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 12:01:21 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700683280; cv=pass;
        d=google.com; s=arc-20160816;
        b=vlqLfOT4YJ5XAc5w8Xwp/uxgI2VrjyAbpiRoEJbSvDFsu1zCmbDOoTzgk74CJ/trdf
         Fu5XtfuRaPNeEPrGhMcqRdbuGhJ07SJffukOqAgPZcCOAUVjcMA+ONCH6ury8LiSj85a
         OUu6Uxu0bLj2P9Qwli9figM4dV6FGpZ7SC0FNXOi3Y0Wi57xia6o0a1EW0Wz3vVoOk3w
         rUedOCX4vQzlg3rwuAy84kpbhrGceT4h+jywgSl8apYnaRFlaVdMwZ3Ax29XBILr+cIO
         DqRtCit1D2Dd/NMUNVxuy/fNcSd2IKy2AIxJpXgVXHVDhuaFgg+2tgJIi6u54zySN57h
         W1Jg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3NUqrSr7RqNySA9I1BKsPSSRfLKVve1B28vkrHHowZo=;
        fh=OlW5HfjNKI9z+eWce1JhOxXi2IdCREFCeg4ujphQSw0=;
        b=hNhfsYpf2vNBPRmYNDuxtC4lkkwwvE1MqnsBr0IF8JTQdOIMHbq7dBhIfmeRRuXIKf
         ATnsiHVYT6Db4xWwOdPru18lLnH1L3/IHnu1lFQP0szINUNr8GBWCaRGlrj8VauH5rsc
         iOCC/XXLpWcJ4N8K/0NWnHEoWIPLNmT6Ha9TBogqKIwZq/KuG1ep4TrGTAMmxVPsErQ5
         2P6FQySsDWARuYXkk7WfObvjPF6DOciYasooNa+BhdYrQRNiN9qOGefda/pnsD/iTTba
         eO+enNfUVGy7qEkvF93NJlSz69DHSB6/AAiFpt123rOcoan6hTjX358AH3n/t8LiX06P
         d00Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=c4Buh0Rw;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe16::805 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700683280; x=1701288080; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3NUqrSr7RqNySA9I1BKsPSSRfLKVve1B28vkrHHowZo=;
        b=llejiUc5S2sI+8CHOgVF+E6WMezaad0fPfD6qqliMHMyNYucd+tM76hMnsXjjie4mS
         vrhC8hf/qahNCtRgaAlxlzv684InQ6ybjdyeRA81Iuc397UlgWIxR31/yvdLgtbSwE9A
         MmUlUPGuTrEuqJNSJqMSql9wKZOFxsSG1jvJP4PSdlqsqBdXwKOLrqYZTpwzcBFMwmNI
         JVKark+o+QQt98qikDPTmVj+dwdlZurfhHxYQiYyb7K/LOkFklbXNdOpgr+UXt9KHtCD
         L08Y8gidvKud2ApIJWIq+Mt1iKWNdCkQPzgPMpMpe//rAPgX+Os4S+fNdsEAaW0jgAHA
         Fw9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700683280; x=1701288080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3NUqrSr7RqNySA9I1BKsPSSRfLKVve1B28vkrHHowZo=;
        b=NJaEXevHgDry04AdA9B+i6vnZ8NAWgXcJqJyyej9WdyTXhG4WWDlCn9BFPp2yMNQUH
         0bl5V/eBPT74SoIJvCIhn4LEmBU1cjefjKTZC9SzzBqNR6ctbcXNcFcCbmVZIBhhwvoS
         2pMZC+45jZMIrGiBIPE7jlmFsulXmxgTw7uqQOp2bUbEnjszvVs/fasRTv1Y4mVq9vIs
         vfuxA880vlqWLtuRLLZypBVys/0KZHp1BAdZ/vkwQXNBhKFqf+KFgTktHtNdvzLSN6Is
         h45iCsNFPwjJycfbKXNSQgLf4uagB/QntDBPqP9jk2DnNV84aI3aF9BtRvsqbdgeQltD
         BzXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwEorCzjUwJR80eOnUFWUjeaYLiUcHj36KsvIBIgTfkBKKrzF5W
	i96h8lXbPvWeZqHNCBvUCJA=
X-Google-Smtp-Source: AGHT+IFuyszXftzo775hSNz9Tg10HGlav29bg5071aBNzXFcj/VG5coE47Dzg5sUHs1JHChT064+Iw==
X-Received: by 2002:ac8:5f13:0:b0:423:72a5:a7ec with SMTP id x19-20020ac85f13000000b0042372a5a7ecmr4028005qta.34.1700683279999;
        Wed, 22 Nov 2023 12:01:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5895:0:b0:421:96d0:ef42 with SMTP id t21-20020ac85895000000b0042196d0ef42ls127768qta.2.-pod-prod-01-us;
 Wed, 22 Nov 2023 12:01:19 -0800 (PST)
X-Received: by 2002:ac8:59ca:0:b0:419:82fa:710c with SMTP id f10-20020ac859ca000000b0041982fa710cmr3883079qtf.5.1700683279306;
        Wed, 22 Nov 2023 12:01:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700683279; cv=pass;
        d=google.com; s=arc-20160816;
        b=UixcJQri3zN/mzFxkiFDL8KPkxcTuWX+U03F9sdD4bB9aZvRFAu0V5c4rzYLAxpQz8
         8SvPRZeaDP1T9LZ59msi5e7EPPtO3wWfnewpiMlySioBCQ1mF4Y3X3AnBzHwIfoevZd6
         EnDdSZJm/ByuhBuVfxaGdTDnfp+ijt2my1H5dZWXLqVCkdRNhmR8FC68lPNr5GDijqfd
         k7M6lyZv/WuR3PoLKRfaIqbGVnq08qHbpaSdTp3EJCbEKr3MOY2Ka4wPOyGtMSHRqW81
         hhT6fiuXo9VeK96sckT3a8JyblJWN+k9UFG+Mmb9NbNyxmFAZVIkJQVzNDwTzm10Jsis
         4EgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ku+6B/f2hbZg/RMFnqksMlwNqWlAh1NeLIbus46z+zQ=;
        fh=OlW5HfjNKI9z+eWce1JhOxXi2IdCREFCeg4ujphQSw0=;
        b=PZf6/x+48u4eSg6iElntEx7XyH5psTRaZZx9cLjjhB6tBDO+Iy4iYO2YfX1mLWsaan
         SZRYcZo5xUGI4sKBt7TUzxz9gAhRzQnW6pgUh2o8FaAJBQ+UcF+2ivNdAex/SBSVs8eT
         +h5XnTmkub1phLDwMeDPQBYrEeSbUpmkZABYHLlH4Vsj5bK4bTYJ3F4IZ7X//8pMTXmu
         QlfjdBazixJkPGy+8VI3pqGZ00pzvxLbuPZ0IlBC8sO7DS5V8ok7e/txF/fsDhdBWu+N
         Ybx1492A7E2fQHMhkwdDV32KGMYCXqUmxc5wovD1rdUySpS4V/WM6CX9IekV42HRoP67
         XNLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=c4Buh0Rw;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe16::805 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR02-VI1-obe.outbound.protection.outlook.com (mail-vi1eur02acsn20805.outbound.protection.outlook.com. [2a01:111:f400:fe16::805])
        by gmr-mx.google.com with ESMTPS id e2-20020ac85982000000b00421e709bf9bsi44982qte.5.2023.11.22.12.01.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Nov 2023 12:01:19 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe16::805 as permitted sender) client-ip=2a01:111:f400:fe16::805;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=KI9pfK3IzCKmskNuLLNjWKOsXkgT1qgimoPsE6w9Na3/r0eaq2xy9Dzjcr8CO4MqHx436SchNc2V0apf29gcuYn/XJhuBH0lieR6+TxOmeW8P3/lQDp2PM3mfm/5kthwWOseCOFtwql6WoASdJ7l0YyMzePcO4Hjuq+/A8dXV6z1kxm+ycZ8J4iU/2FseCVHZSS+Q6Pyt3n5KUzN1VrzQzohNQhzQmlyQjL7OKtkCI1ybiD3q0oxGEzltFCxDuIF0k7/VU8v/0LqO/oVDcHD8r6va+3NZc0BtlPG6stQYatX49nZJ7E/teHQgWUIkzclMevJ4dSBTUqk8n2f4vpluA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ku+6B/f2hbZg/RMFnqksMlwNqWlAh1NeLIbus46z+zQ=;
 b=g+UUrIULqN9hItuSOygRXZMgnNoeE8T7Al2rtYt2ujL/5n/gq1WQqH+BC4zMzLi7frvAi7fmCnqvefFh49SgzDqU7KWthU3zfgmrPaNrRw4ASOQ0VT6q3Q7me1DFgzSO1Ur2oa5RRKZS6K0jAvcsflyJEUpqqIFN18MjPLrlt9kkNjZKXqNLQJNaj1ynBw9uHg1MmmNo+/WMDCufYke+Qxj7ThiwQoHGZ63UpxL64+nxI1MPgCY50QIUfxz+lICf+6mI1WYSMetZrxz5S+20B7J4wvWW5l+gA2Inx3v1CJC47kjLIii/zjf3HiBLE+6GreWhLezOGB0v6JxLUVm3og==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by AM8P193MB1107.EURP193.PROD.OUTLOOK.COM (2603:10a6:20b:1ed::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.18; Wed, 22 Nov
 2023 20:01:17 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.020; Wed, 22 Nov 2023
 20:01:17 +0000
From: Juntong Deng <juntong.deng@outlook.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-kernel-mentees@lists.linuxfoundation.org
Subject: [PATCH] kfence: Replace local_clock() with ktime_get_boot_fast_ns()
Date: Wed, 22 Nov 2023 20:00:26 +0000
Message-ID: <VI1P193MB0752A2F21C050D701945B62799BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [78f8OsnKq6VggDlHJdXdRclrcXszWgly]
X-ClientProxiedBy: LO2P265CA0056.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:60::20) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <20231122200026.105411-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|AM8P193MB1107:EE_
X-MS-Office365-Filtering-Correlation-Id: ef9e6723-a192-4f11-f7ae-08dbeb95c9e2
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: UQAKRaIiU0gcqyk0DgShAMOy5HEjCltLkRQNeJ9CHrCE+vp7sI5YT4qJmmnjNpE6C6vboZxzf0dtu3spAdvzqRl7Pmk+bYwNQFOmuVcJCpkoKbWqi4VjAziSqSvI9JCYMQdyKo3vXMMy0O9urY7w/b1OzIn8j98w1q1/I8n+k6vApO+27uqh8RNR8+yC5sU6/g3/I//ATJpLuipU6Ke8fhNunyzwhLk76LuR95szd/I1o1QPbq29t9rZ6/XTBo6LoDPCgBGrNI5pGJv7dp/9bxM7aLhB0DaQU8oIRVuG+XQBYJWDYGppMakFw34EqPwFIHoELg9hcG/j6VKuC47+awQqVPlpskw3wPfjlcIhOcW6IyN9XV4GfI+yiFcqGNNv8pwlFmgeirtc3jlBh9QXtmLbMiNAmTcx+gT0kXkAFaU2Ctw/Sur5UbmF0Z7fwAZLWwM/qKAy7VaXIsg/Lx/FOCu7iqUz529hCXb1iERlkNhY7QeNmvzbBHcrkCTCeGNWTqUonOv7out/aM2M1vEnq7pagqP+Ve5oisdagnobH62WCMZr8p2RtldQ3fsJZd1A
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Eth6GuGvWtSiV7pZfMXjwvMT9vDzXPBrOtul90+uwKNpIdxDjqAJDOSK0fh9?=
 =?us-ascii?Q?TJs0KqaOg2yBbJWG7Yem4LJ3WDxKIZAn8e3JYBOmFzHzws3PAvqnePAtzzIZ?=
 =?us-ascii?Q?L1QY+QkUtTSFgjBKZgEKAOTfuG3Bpyxl6YgAejUEgRwQM+/VXxDi7C236Yvv?=
 =?us-ascii?Q?PFaz6aRyQwiJtKphARUdda2M9QrgoJeHigJPGPzZlFbeW9iXaUpinyIYTt00?=
 =?us-ascii?Q?U38Zkae+NkBwU5cyLNWb+sW4pZeruc8yEfDZpLuAbw35YhQeXiYzPxn6u0WQ?=
 =?us-ascii?Q?0WIaz6Z6va+2ks+071KU1CATwLOSN22/F51O4FR1dx0M5NehKilNZE59P52d?=
 =?us-ascii?Q?BXUVevCLEdPs7t8zxNFDiRFY5EZ2Ks98ZIxDb31/UHT5BGVJoTK3Vty+U4Rp?=
 =?us-ascii?Q?burBJj7WPbEfEWrxn1c48F8LzOUCQuHW7rTDQMAxiLjjppec/DT6VjfSDDag?=
 =?us-ascii?Q?BwFrESAvaX6jkxGpCUCIcRmXTAyYNeLuI4sFqc7mzDmUFllofx6jWJ0nvGJi?=
 =?us-ascii?Q?HzNUkCn2R3I0fG+ik08g+0Aaes3uBo2vG4/Brj8Jy+HlPHS1AxWj1D5pFE8I?=
 =?us-ascii?Q?Ct0/W1U8nvSM6PZhnWGZAmVd5VGiMTnSiGsuPGf5bN0RJGCZ4pg5BDfHhXhU?=
 =?us-ascii?Q?qqaj1oJzO/+X+EB+rHKjf528WUX3Dwwwgyfytos1mQuSQrvxvqrvn+YonnFl?=
 =?us-ascii?Q?DPV24MZgiMXucc9RAMAHiwWiDm2u0x/SSA0lrWlb+bjJx1QeXVeHI4StvuD5?=
 =?us-ascii?Q?b2xDetXCHqlbpRZZuBKE/VxUB3ZJ3mbfWvrvbOV/F6OhoUOdUoEw0gJT1KzT?=
 =?us-ascii?Q?UbSI+bVpmQdzt74w2QPb+J8L6CiumS5b1iriS3RplqIVcud09h6hrO/YAD0R?=
 =?us-ascii?Q?jA+2x+CMmnGOjMfqidpCQjqDnC8RVp7SeKOfPDT7zKa50/Q0Y0rG+grzhSU0?=
 =?us-ascii?Q?rmAlUu6vG8rgDPWLeAhioxwtIjXR2t1G0zF8qEcfz1WZ7fqhrCI0wJWOP48R?=
 =?us-ascii?Q?J6gJaaRPesxN6kPO+4i3TJ1qNcyLZeGuWKLkMHyLxi/79vNox06FuAwVGsgl?=
 =?us-ascii?Q?Ou1XoKr0eqVXBi/UVNLOmdGzOzyBBIsAe2nshn0B0rPtQPHtcpWb52HhWgDO?=
 =?us-ascii?Q?gZz+EGrkbEpDL2MAxpaEENBlksuQ/XA5H5ypzcX40FBT3kU93oL8k1tzNO4w?=
 =?us-ascii?Q?bL7ZRsUpOPcFHLFQU5CwnxClflFwd7dLFWgtXRQEffQZVXBmrHSM07xcGcc?=
 =?us-ascii?Q?=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ef9e6723-a192-4f11-f7ae-08dbeb95c9e2
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Nov 2023 20:01:17.6566
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8P193MB1107
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=c4Buh0Rw;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe16::805 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

The time obtained by local_clock() is the local CPU time, which may
drift between CPUs and is not suitable for comparison across CPUs.

It is possible for allocation and free to occur on different CPUs,
and using local_clock() to record timestamps may cause confusion.

ktime_get_boot_fast_ns() is based on clock sources and can be used
reliably and accurately for comparison across CPUs.

Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
 mm/kfence/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3872528d0963..041c03394193 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -295,7 +295,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	track->num_stack_entries = num_stack_entries;
 	track->pid = task_pid_nr(current);
 	track->cpu = raw_smp_processor_id();
-	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
+	track->ts_nsec = ktime_get_boot_fast_ns();
 
 	/*
 	 * Pairs with READ_ONCE() in
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752A2F21C050D701945B62799BAA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
