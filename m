Return-Path: <kasan-dev+bncBCMMFP7V4IARBIF7Z3CQMGQEFWZGGLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 04119B3D069
	for <lists+kasan-dev@lfdr.de>; Sun, 31 Aug 2025 03:04:34 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70edbfb260dsf34465166d6.1
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 18:04:33 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756602273; cv=pass;
        d=google.com; s=arc-20240605;
        b=BM/ZHD7jqhNL1H4E3duFQmJltSs7IieZZZSPftT5Q9Qob9jMIlS+FTFwWxrvizXxNu
         BJKG6EMXTuJa8QL11S6UShk2gttLXaYmFowkWOMw+Ne4f1zHvykTO8aseJIWOZxEDE3U
         lmt6MKf+VGJC118LoB1V5uDTP15egYhu+0a5mYiQ+RQfuZ2BdprG648+0tGJ0u7SMbck
         aHr9GUKjk9KdqZR3/ybKjAGnLYjQ/+eJuQoOu1J0JhXC7PgVNKF+cBb61MWLEAbn1tTF
         7j1la536Co3OaBtoojfRmNaYRk/DE0CLyDuXLFHPwKT46PR6z0a/uk+AYt0N9f9YdtUd
         pK7w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:date
         :references:message-id:organization:in-reply-to:from:subject:cc:to
         :dkim-signature;
        bh=eF2OvKB4DbZX7rtQGn1uG5bFqH1BhvKg6/cgdCZ+sm4=;
        fh=emZ2ouEjTq9vUDM05WodIWatP3WV+sb5mUdyUr9HtvM=;
        b=CKhRtc+At3ovqIKT9pDuNQ0b8SK4zIFdk0KkIMXcb50/Iti5vl62X+0qEDrjM98Ji8
         hTaYAgKkr2SrettkOxtYQRaxDkfScXiSbrY+mF/OMrl1q7uQzRnW9+powLypmaBdM7PQ
         RVzd6zwXnBGQPDnNRiZWb5v8DINhLMyLfC/rgBAK1BBJNK3v44T7qlubB5qUtHWk354E
         Tx++rXilCfjgq46XaIKX99Zh86PFgHbauico7DO9iFZ+G/nZQkIdF732ALm/nFqSgMXu
         2kLhLm/ewqAUp4mMGszyK+PZCCPaquM4URvzlN3rCOGw+87JSIVd4TjRVY5rhvcb9OX2
         09JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=UihOwvPq;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=R9wA0Mvm;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756602273; x=1757207073; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:references:message-id:organization:in-reply-to:from:subject:cc
         :to:from:to:cc:subject:date:message-id:reply-to;
        bh=eF2OvKB4DbZX7rtQGn1uG5bFqH1BhvKg6/cgdCZ+sm4=;
        b=n4uPa8MyrG1gJaNwC431Ij/nfziVakbVmudc0NuSKMLD9mbrpUcCxRW/pWIA7yTB8T
         zvDAssFec/zXUrlVrZLpX2s0QohZZ/aVb22zhTHPolA0p0xFLvFj/tDwwULamXbkN/Od
         UaIv7qWvsITb4TYxkQ41FYbBDfbF6jwef2eVWztlhZgXjHhur1bhnix6YDE4SOeZ1qKo
         qAJZr1AmppnXWvCERF/wmZ1na1i5cKPCgConVhQiq4I+fCn+0jI7QEXWSUsfXguQJjTX
         JGZvUT28Y1e1LuFwXqtmYJMbH8YLV+995/0LthoZ20Nr1nAk2XtXsmfV7lyLVEtTC6z8
         haiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756602273; x=1757207073;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:references:message-id:organization:in-reply-to:from:subject:cc
         :to:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eF2OvKB4DbZX7rtQGn1uG5bFqH1BhvKg6/cgdCZ+sm4=;
        b=sGhuG+4Q0+T1HmehK2aYl8w2bWSqqMOkG6DAigglEiv800s8H8c+noTdwOvnabWtf4
         4VF6fxcJjUsWSA197Bbu7dPqK+0QdFSqdKk6cQ+CmZgjA9XSHHIlMSJTWb/uKAJRROCH
         flb6M5Vklf2xJiCO2PVnYfRd3edGdDcNbxTWGsJoUEyEieMY+CxD0nc4eI6BFbxw5+QE
         JmLFfB3pfzFsQ0EzcwWJY9h74nzqzz0VS0PgrImWqG5WI5WtHtTvaQsDunIcrv5mFGaf
         w28yhhE+aOsygnrEUsvnItWrxAhwCMJQtCb+9ZgZkKRNlhcV9aXGp6wtOWJkqvNcyEvI
         EVvQ==
X-Forwarded-Encrypted: i=3; AJvYcCWdmo70JPXxkvdFGYLePYvU77mNW2N8+dCFYoJJbuUQzvmsyBqIm/3rwTWn51Ybv2c9BAVPkw==@lfdr.de
X-Gm-Message-State: AOJu0Yz7gEsg5TWfihhhg7vSAN+8p8HxO59kiFitOKeJ13358MVViWYR
	RYL+CYa5bsyUQ8C7ZlYo1d6aC5XXvV7D9ri1bpYxc6uW/GUHqMwQwPJI
X-Google-Smtp-Source: AGHT+IHdrGGDS+5/36TcV7eXqkT3PTri15qA6Bapwo3ZWWNhftIIast/W4nokivBCRleKj47SoSZkA==
X-Received: by 2002:a05:6214:230d:b0:70d:e984:ba54 with SMTP id 6a1803df08f44-70fac912d73mr36371816d6.58.1756602272677;
        Sat, 30 Aug 2025 18:04:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdUukzudaI/wOvUeHorQ5D31DYloJ83xo8hTk0rnybEBw==
Received: by 2002:ad4:5963:0:b0:70d:a451:c7c6 with SMTP id 6a1803df08f44-70df000898bls42446796d6.0.-pod-prod-02-us;
 Sat, 30 Aug 2025 18:04:32 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWsMj6l2Aqv8fvR3ZwGcCEJrBKrhP3HzBUHP7+974xOMmGAHN2BIFiMJ/m8ioLdlDw9vZrxXF91K/k=@googlegroups.com
X-Received: by 2002:a05:6122:2219:b0:531:2906:7525 with SMTP id 71dfb90a1353d-544a01c856bmr947070e0c.6.1756602271878;
        Sat, 30 Aug 2025 18:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756602271; cv=pass;
        d=google.com; s=arc-20240605;
        b=PTR2YdpzIwZ3ZJBuiXJAzs1unMuJmSOlDBJNn8sVI3RP8356x6Ufrd4yVjrBpOEssO
         T5Sn76RMXqhda0kh0p7p437BwGCOruIDgVZc7SufrDznnDf6P/07icwIofobI+S/WgL9
         RX621IOm3CF6/3bhy5FNPtKXE2FLZ6dy2td299DuCmERMjthUeIqkzHivWTA24ZpHUHz
         y/4eMiupBarhmZEx8+BXKX55fgTaH01BfCW/NLJw9eS1wknhLym9in6jsrEQ778ZN5hC
         lx/ffOZUNxyn66m4+uEWrdu5inhkuzHeqGwb/B866gr2JXqv3wOZaJ36JVozChj3Sa9B
         0ZLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:date:references:message-id:organization:in-reply-to
         :from:subject:cc:to:dkim-signature:dkim-signature;
        bh=IiBbMj4KBsefui0MeW6J0uAj7ORkuYp16o8dZUF37xU=;
        fh=+kZF3gG9KcRjuuI4SS0LYmmfeb/9/fGHMNq63gClQFU=;
        b=KnAuzTth80xK5WvN1jAk4nLQqElxwgHM+EBr8PgHibXoEsYLYLf1cBlD2s4zVpvbHT
         0qfvykvDXVFLrrJxz1YOuffB6cytM2ZhD/WAbWGSMcWFA1UbWf9aMXt+v1cF0P8I4Bxm
         kRApGJPpFZlWxV/qN9v7zWyULqMWHnMQ99FUnS7uzCOf5vW4dnOkb8B/zwlYSX85rR8v
         E1dzyw3ngS0tG2fxvn9a0Jh+c550rTxgHuSiZSSo9/mYMCmG2ezICfyJGggjTf1nCV5w
         0iTmxzavAHhkn0nVG/pXGZm8qT/d8vv6GTjqaVpLo5Ve/QuPgEDMUakA5LAIb6aKGLPI
         OYhA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=UihOwvPq;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=R9wA0Mvm;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5449854f923si179366e0c.2.2025.08.30.18.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 30 Aug 2025 18:04:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of martin.petersen@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57V09UoN011731;
	Sun, 31 Aug 2025 01:04:21 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48usmb8kcb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 31 Aug 2025 01:04:20 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57UJStv7032259;
	Sun, 31 Aug 2025 01:04:20 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012021.outbound.protection.outlook.com [52.101.48.21])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48uqrd9jva-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sun, 31 Aug 2025 01:04:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Tm7i31Xx3WuyPahxn97e+VOYFfthV7BpLIteyVe2c0km86QRzEXIcOZuEERtI+X/zphDjimXCcEEVYlefEqFWijd0Vun3Yt5yeC2if6TipxdpA+iAvxqjO26LBg6cVzfaJnWG+PRjOg+0whWgDMmezWf3fJGwpsIS7is89/4z2Vm+uLHoVyQkcNSISjHePEYuFxpY8wsqrYOv+gOL9GI0v0L7HRHv+RKZTokAqXKQw3mMofClEuU2ESrc57h+U0WUCiJIkwQCmJAwgL5aDZbEt8DthHC6dm164+d9Fb8hJB8ITXgUriFh6ps5KQ6Exeo+mfAW09XRCs5Q/n0/ZDshA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IiBbMj4KBsefui0MeW6J0uAj7ORkuYp16o8dZUF37xU=;
 b=ZHwRmC1bQRhFJpu1jasWm7fHD9TZpjYoYWak7vL5CJZPaSWoOhOW/rgxMKw9CXQ8FhoLPXlnDOQS133rnd6DQbOgTkT+wB/iYMxggo5LnFxyMrBIDycb58UcGhzxWfrX25aOIMPX3ReUtYIqQqzrsoTXdevKQg4f2f4ReeBi2/Oab6i/0xdjngSFvpyFOdC55aHB327B74s2pXEbioJEB71JXXr1RwCuTzcyeBDUS/v3WwvuyIMX/jGxALvP59hT+wHKfd2v4bqCBuGtlR0SN0/ubWbH1zghgAImTKhZO6vlUv9fFA06f/+NnPzKyzvgPYzw8IIWTHWvofHx7ThIyA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH0PR10MB5338.namprd10.prod.outlook.com (2603:10b6:610:cb::8)
 by SN7PR10MB6450.namprd10.prod.outlook.com (2603:10b6:806:2a1::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.25; Sun, 31 Aug
 2025 01:04:14 +0000
Received: from CH0PR10MB5338.namprd10.prod.outlook.com
 ([fe80::5cca:2bcc:cedb:d9bf]) by CH0PR10MB5338.namprd10.prod.outlook.com
 ([fe80::5cca:2bcc:cedb:d9bf%6]) with mapi id 15.20.9073.021; Sun, 31 Aug 2025
 01:04:14 +0000
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Bart Van Assche <bvanassche@acm.org>,
        Doug Gilbert <dgilbert@interlog.com>,
        "James E.J. Bottomley"
 <James.Bottomley@HansenPartnership.com>,
        "Martin K. Petersen"
 <martin.petersen@oracle.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman
 <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou
 <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe
 <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner
 <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett"
 <Liam.Howlett@oracle.com>,
        Linus Torvalds
 <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org,
        Lorenzo Stoakes
 <lorenzo.stoakes@oracle.com>,
        Marco Elver <elver@google.com>,
        Marek
 Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu
 <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren
 Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 30/36] scsi: sg: drop nth_page() usage within SG entry
From: "'Martin K. Petersen' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250827220141.262669-31-david@redhat.com> (David Hildenbrand's
	message of "Thu, 28 Aug 2025 00:01:34 +0200")
Organization: Oracle Corporation
Message-ID: <yq1plccfgji.fsf@ca-mkp.ca.oracle.com>
References: <20250827220141.262669-1-david@redhat.com>
	<20250827220141.262669-31-david@redhat.com>
Date: Sat, 30 Aug 2025 21:04:12 -0400
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: YQBPR0101CA0127.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:c01:5::30) To CH0PR10MB5338.namprd10.prod.outlook.com
 (2603:10b6:610:cb::8)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH0PR10MB5338:EE_|SN7PR10MB6450:EE_
X-MS-Office365-Filtering-Correlation-Id: 0dbbfba5-c14f-4943-1085-08dde82a4d4e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?xJgFBGGZmYw2SvXKCB2Vhus1HCAER32eV/AlKqX+euaRSoDBkC0HoDzAAE+a?=
 =?us-ascii?Q?XLEcxKOpGGbbXytM66Cl/dxY6t6Y+c6UwZK7AL/5umBRW97ARXn9gdnjWvd5?=
 =?us-ascii?Q?FtssEuUSn2cpoagpVo50OvNLelHX7yh4zTjLDu2vwa4zS35MLfm+y7XNLF1l?=
 =?us-ascii?Q?Ul5M1alt8AKB/NSWujbZLf7VUdGXVY7RCAmNdeyKBf6hfqp5qdevvOr24hiz?=
 =?us-ascii?Q?9oAZxdT3o30yDSS8iz8lPuPqb92roGrmxOBgE8fn36zymBWIsC4SZz3MNuqo?=
 =?us-ascii?Q?DjKd0Y6RwJC6nTnJm6YWbmtA276urkAkcIYwKjhijzXPX/nzDYy3bL+Vx4Pf?=
 =?us-ascii?Q?Te3yWb+wRUJjLPEqtGFZQazFA01cUApAPH2M0s5BmLCFCBOJWYpNszJrPKnC?=
 =?us-ascii?Q?Bumt/0lmLXfUWWtX549ce8fLDKmZBniE+VLL9SstVpUzddch9jV+o36W0Apj?=
 =?us-ascii?Q?G/QgBKWa13zOwuOcMwGm6IlFbKkhJPGicQ9YFnWeHqT8LcuqtHInN4iVYWMS?=
 =?us-ascii?Q?wBcyb/Fla6D4lZ3GXIZkq0+AG7j1MX9OTfitGWfLQdHRBPZL3EXQOTzPMwX8?=
 =?us-ascii?Q?v7y0d9l+Y9Ceam8Upk31FV4DWuck5Nmz4hi7zv6H2gBEXX+PdryQlXUF08zv?=
 =?us-ascii?Q?H1PS7pMm4k+OJgLHtofP1QVCu95LkA2slqk28APcIb03CDq6PSXw4PXWASdj?=
 =?us-ascii?Q?scMYAwR1ldxDyY0uiigMbPygi8aQU2fl10SfYeI6qBiCzt2YREKYSuqUuLky?=
 =?us-ascii?Q?7wkhaSFeBmb9WMXll8ec4iHlB8zqa7rscUcw07DjRtDcmxcT5pLl/6BLLtQT?=
 =?us-ascii?Q?pslC+Bk4CyZf2b/tVoaLAg/1FGH5frrMDEZHfAmHCrN7EIfBOsKe674hTJwh?=
 =?us-ascii?Q?rLl9FUgoia2pouhET+ycoK0zielz8QYSR4HXxlf+m+bnBF/bE5Eau1QGrFbF?=
 =?us-ascii?Q?NPbDhbRMwl+FsUKRISHJZYt4HNdDZGfP8g2JiFbc0/W+ADaSIsqw9A46vNLf?=
 =?us-ascii?Q?CMIaayEXRdEfGWpXngFbbWSJviT3X6Mpn6t5znfPsrhRXS0JdkR4koGzd7ov?=
 =?us-ascii?Q?dDE4Wm2UBJZbJKzi/x8gED3kyOqsMQmbxxD1s95sLqdAOlN70c5yTE6bHBV/?=
 =?us-ascii?Q?s71l0BcoWDpRDjjBKbw8UOzHBjbYRjFCu99ENg3ac2nWS5AxzB36F+DMLGsw?=
 =?us-ascii?Q?j3eh5FyeZ8RJHjix/WEfGjSGTsSE5/Jtis1chrlKpvkTrZ6PhKc/q9Y/VCdd?=
 =?us-ascii?Q?2UxCquG1loVT9u6RXV4ViqHPexKW6hrR/Tg31igIawz3Nm7P7XSCPjd7puxm?=
 =?us-ascii?Q?T8IHvVPvQYeZ8TFSHcZTzt7ZnKNg7GDxPMt6A/iLDta2TfqLP9fDpEizJ4+q?=
 =?us-ascii?Q?JhSKdX+ywzlYR4ACMtZhKwFPwIxzKam+baHIv94L9q2tR/RFZeHhoDKqdgKu?=
 =?us-ascii?Q?6zQSjxvMnrs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH0PR10MB5338.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?jpykIZGB9DwBkmW6dh15uCejN8KQgzW5lu2RazvyjknWa7UzHJPyFpMI+L0J?=
 =?us-ascii?Q?BCZ4hrVL2s0k6Ofqw3v7xCPlkaaRIElrkhsaJLgAYCckZyosZLafPJjhTIFP?=
 =?us-ascii?Q?oZmbiKbH3VnPCSr8k5mqjFd31t3+jk24Iw6VmRB14uQSsIIvZIokQtyn6v4Q?=
 =?us-ascii?Q?5RtKbJqfZnw5ZT9z5n5Jle1zCfK66/Df8+/OYY2fTaLgo755Xz/+tz5WsFeH?=
 =?us-ascii?Q?zTjALnGtBZ4jcy7RNug4DnYs3wPGlXjAyHdx5JCcvXUpmuFzHIhv4HIA3ej9?=
 =?us-ascii?Q?xi0juyrz3HMcDtIyC+tdtxZ8lOCogao05gY18ZoT1Clt94dl0IwJ8zi0CIqM?=
 =?us-ascii?Q?YUOxe0JGHJOoRHz4eqji09KcuJ4G42ancqqixrT4+LnPjpzV9Pg01xrbdkwF?=
 =?us-ascii?Q?A8ffIZDEKkCYXoHjO2HnLIJhL19d3bbkZKgJH/bexGCi81GtgB2fHM+pBiIm?=
 =?us-ascii?Q?yuKhW4G4G/soUD0gVUGpCdw9oh5hoNoP1qg/QGw9bSaS+kDffUsPxvKxn1r7?=
 =?us-ascii?Q?KRhd+x+33O837FjU1Ss49aTeqJKHxcAeAEDUol9OcheOcfy14pHzQhaUTrYX?=
 =?us-ascii?Q?XmGSZBwAu4j68rquSmYYZUMMRmNkeevw3Mhje4CStb/D8zvMZAxAIMRjw8im?=
 =?us-ascii?Q?IvjsV/jAbRiOEvgcMF3ZOvxSFc/aqmFstlqzl+u4TEpPJf6UNU3JQ8QqDziC?=
 =?us-ascii?Q?sQ+1o8oSSRxt1gIBxSZPswTN7PTbONh3mGZQdGyCkLZjZ8LjdapJcICjKzz8?=
 =?us-ascii?Q?V0W9pljqOuleTMqOx0e7WbuC31Cfl2UQkKUfx9xe8RwNWuB8JKip/grE4b9z?=
 =?us-ascii?Q?FfLouV6N60ElvFMJc4m58K/TbnscjtvtImqMgmagiyMil4KxsJjVNAwn3D47?=
 =?us-ascii?Q?Qc3NOJgt/0RNdxAtgD2+5Nb82Fa2/nHLGPJRGrS5l4khSFD0RPW7q3MfPlc9?=
 =?us-ascii?Q?Tx/IX53MLUnQQRLRuGbH7n7XycDomAgM0DK+UlNCUaX+H1lroj1mrZxQEPR9?=
 =?us-ascii?Q?fwWOw7Tt2X9ezXJEZ8wy1RN9vB9ACpMRVb1w12/1m55Ud7wECJ6y6qTIlBl+?=
 =?us-ascii?Q?ETuyvybLcgxACSOs9DRaeQGiNyzncJUNfr/iuOq33fLZEsGGhGoO3kQUNTDa?=
 =?us-ascii?Q?XMvRsX8v77Dyh+zX9TW3BBdNyUCfNRa8R8lf1DwoAs3fDtvvEEeuoECyUdpF?=
 =?us-ascii?Q?BR6k+AIlacBXj6Z7xqmtc/aNipENyRcIfohpYiVvJVXF9YPNzAo87NyY1xfm?=
 =?us-ascii?Q?oP9i95R1+1CPf3fEI2AGLKmmi76dY94XJBXxtuR5ErL8TDGY7mOL14yqZ4nt?=
 =?us-ascii?Q?PkTjZBuokUrn2DAIsaG5cc2TIeD7IuFA1R8nmfBIuksYOfVvzCkTE63FPRQU?=
 =?us-ascii?Q?/7DEgQHxD7OUedQkflZsmpvs1azWeV+b0Doaz32MiN9qBbIen1z4eIMCK1nR?=
 =?us-ascii?Q?bKnQfyznMcbQi/p7Qdnut415L9IUzbGS7bH+zQLhDiyQKyycHm5AwfKlcvma?=
 =?us-ascii?Q?PDnL23yWu0BRHFLZlqh5arsoKFGu5wrkJ6slffjMyx7HbFdm6t/MKSakuteY?=
 =?us-ascii?Q?AUBFnCsXhbV7Szhzh99awUW84uwOqza8cHH/67vI419Jj5csSbfRIe21udPt?=
 =?us-ascii?Q?sQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 7lVV3ydNjgpjiN011R9vzOoHWmSjCxQPA0qyGL5R14catztlz/Wl1bWkAQ67gDQLa/z/bwRjHTgczSSZAQBBsEZQs1bxHc9Sgcz+eJccQmGZasvgBNI84yXGM+iith1e4P93GbVQfTrSDG4uXCRpJ/rF7E/KKJAASn3K7W84tLLseg23/XUbjtH3PbmIrUs7tvHN4p1N1H2WJEDx9UPIBwdTnbfsXxo9/q/0PO9CchNjLwCokUsBAvwkkb8iVeVMXAZNT3HazWWdRVPWYq1ggaWV5UrV6umQK8zp0qQWnO/tWKdOOn9UbBJQcxT6XjDi4dqJeI7Gpa0Rdi/EW7HsPh7Des9uBMyQM+Q3IQBSBUempi3nzO2Jog9ntuLu70cHu8HnOnjAy58FLNfanq3OKvLOHPNaY0MokOGE98IWpH/1Y9OZSqwp3rhgrqUNwB72YD+jNYbE9PQoiKy7Xpi+aXrIpKboXcyuowTwQxukzqA42ltqhuWEKUuDclq1J4paJzA+F2/zu6U35eKBV9INA+GOELNS58HPEPprLKb+VKoH0vWYCJgIFiliI1OWJu/K2VigENBvik3t1FPBfWGUpzLtIhGP8cHEphe9Dmn/qTM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0dbbfba5-c14f-4943-1085-08dde82a4d4e
X-MS-Exchange-CrossTenant-AuthSource: CH0PR10MB5338.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 31 Aug 2025 01:04:14.1211
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: q8aK78FMiUOkUEUhU+nHpZaMMMqHDmVJhd4C7EPcSOmoRt79T6Gd1PxX+BWc9/j1qCCJ57X35cVG51wGj9t5cKY45qVZqjVNL5a0S/22fyE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6450
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-30_10,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 malwarescore=0 spamscore=0 mlxscore=0 bulkscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508310009
X-Proofpoint-ORIG-GUID: 8CIHQ8ah5b_CCHNKoQ4yaWFrXlrBvBnR
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODMwMDAzMiBTYWx0ZWRfX9daHAJ6c4dLI
 M8LvzDnc5OmcEvfpBc7m2bBJQbTKMtimNSfcg6wc000ywfCsJD1C9JGMaNH+mXo74ehEPX+jeuq
 b7kvWAgAse9wnK4blgEaXRkzWjRod4LNUOcmty1gpwrD+0dDeMB1Usf51T4hPdadyoR4bblrWr6
 y1z33mSbClThVMWJxiFhjOjv88cmXgeee+i0aNSAvdbZA7S7YAPHDJBcTF1VNZdKJz843HvnaQL
 Foim4k9zFUEKICv45AKYInm4pB2eIffSa5wVB3MTotcHww9MISVWQ3gSvXHRoPz4T3SEIaKOtHn
 08x+gfpim+ev+bPlXX60/PKhtrHDFFBSxn/6BAH01P8n+n+KxmFJ1Hd5heLle7wbAJWt+ktX0rS
 hEgMZp24ZDR1R0qcocvojpsYJINf7A==
X-Authority-Analysis: v=2.4 cv=KORaDEFo c=1 sm=1 tr=0 ts=68b39f94 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=2OwXVqhp2XgA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=5bH7z0BLeiDiQMqUfeQA:9 a=MTAcVbZMd_8A:10
 cc=ntf awl=host:12069
X-Proofpoint-GUID: 8CIHQ8ah5b_CCHNKoQ4yaWFrXlrBvBnR
X-Original-Sender: martin.petersen@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=UihOwvPq;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=R9wA0Mvm;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of martin.petersen@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=martin.petersen@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: "Martin K. Petersen" <martin.petersen@oracle.com>
Reply-To: "Martin K. Petersen" <martin.petersen@oracle.com>
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


David,

> It's no longer required to use nth_page() when iterating pages within
> a single SG entry, so let's drop the nth_page() usage.

Reviewed-by: Martin K. Petersen <martin.petersen@oracle.com>

-- 
Martin K. Petersen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/yq1plccfgji.fsf%40ca-mkp.ca.oracle.com.
