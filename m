Return-Path: <kasan-dev+bncBD2KV7O4UQOBB6EEZO3QMGQEBAXTP2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 171249846FB
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Sep 2024 15:45:33 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-6c8f99fef10sf7851228a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Sep 2024 06:45:33 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727185529; x=1727790329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cRyVj2bu/9ZxVC5f61tWVDXfSH5/qM6cCx5E4z7ERsQ=;
        b=PzG8EdOmiLt1EGWByIGE+/6QNXTLeK6cPFmzQoKt1XLRONMw0DKdffTObxEOOT87vO
         KtTnh/OOpYfsyuPQQ0QAJEC8pzth2pdYjCvH3LUi/93PSW+ivOLMpZYCO+/rCWr9LgnR
         Y24EnGhkCJV3D5+6g7ReajPGKDYWyy0B0kKsOrn+KoXBmJ7Hn5ciXjMDp+dLplp0Dh9e
         tW482X0Sls/hIrc3P2AV5M0DPFD/PK4FTgsoDEtUyZB8lxmu+Iypbg+beRL4QHRb4g8V
         WLcgvyNqpvV9WvvDc6Y66JvBtBd1ih/Pidbi7vcsjtYvmJa8qhOIxmPInEqfqvazKQCC
         NwwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727185529; x=1727790329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cRyVj2bu/9ZxVC5f61tWVDXfSH5/qM6cCx5E4z7ERsQ=;
        b=iXAEyrYAe5bEFECXILBHvvOYNfJGoFpOi6KvwpydfgOYwadjHYfvkg13ob1ufy6o0T
         Ovt7ZZlq6RTIfM4gyM5WZMM1ENb1bkvAEpSoVO/chp533aU65u52YUrn/VOhzUdxBegk
         UQoiZrCk/pZQ//gHgR89k7lcW9TD/PyxnxePKWtJD5G1UAnekiWSheXeiTDcUs9LFbmS
         oVkP7n6KDBvUIWibb2JJAxxoaw5eJBv9kjcW23L2km6D4eKwmYAp+Tqu2scXncLPTBx+
         wre/9kcGWCKo5LggDpdstupPa7MLbztc94KtMxeFwidg3tMs7tkCwH7FEgp+1MVz1hS5
         Fi2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0VTM5yQ1WJChyGSo1MyISrFETIYfZlp78vir/Jc9f8jqM5+hx7RRgs1QHGKqhLds2ENIDeg==@lfdr.de
X-Gm-Message-State: AOJu0YyLkANVZr/yCtDtCdK9olrCNzk4ZeM7a8h8wG5F/X6/8guCGbd6
	sIuF4I5bD0utMXtcZNc1cve/rAQniDEdHKQaayUfEOWJmc4n1UU1
X-Google-Smtp-Source: AGHT+IH+60wWgkSv1u4Xx6KGLkcw+pXDgRJo7P/k9srPN+gzt/6Pgpm++SMrLd/bDDJY442HRYXsjA==
X-Received: by 2002:a05:6a21:1698:b0:1d2:e458:4061 with SMTP id adf61e73a8af0-1d30a900c57mr21329338637.15.1727185528941;
        Tue, 24 Sep 2024 06:45:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9109:b0:2ca:d1dc:4a26 with SMTP id
 98e67ed59e1d1-2dd6d35e64dls3639396a91.0.-pod-prod-06-us; Tue, 24 Sep 2024
 06:45:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlnVtRxrNaWXN36aBHuqY4q7/m/teYeKRa3e2pjWrPkRPqVEsw3LCVTEJnlzk/V93r1MH8f0eCVxg=@googlegroups.com
X-Received: by 2002:a17:90a:5182:b0:2c9:81fd:4c27 with SMTP id 98e67ed59e1d1-2dd7f40abf3mr18237097a91.14.1727185527490;
        Tue, 24 Sep 2024 06:45:27 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e05b5d4009si117281a91.1.2024.09.24.06.45.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 24 Sep 2024 06:45:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: W2XPg/CYTc6LBrLxAzE5Hw==
X-CSE-MsgGUID: PoH9B1diTvygODbVTP5nWw==
X-IronPort-AV: E=McAfee;i="6700,10204,11205"; a="29070493"
X-IronPort-AV: E=Sophos;i="6.10,254,1719903600"; 
   d="scan'208";a="29070493"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Sep 2024 06:45:21 -0700
X-CSE-ConnectionGUID: /UiNBHX9TGWq9A5/ZxkVyg==
X-CSE-MsgGUID: oOF1u0MBRvmcvULPOh6jNA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,254,1719903600"; 
   d="scan'208";a="75522462"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa003.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 24 Sep 2024 06:43:47 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Tue, 24 Sep 2024 06:43:47 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Tue, 24 Sep 2024 06:43:46 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Tue, 24 Sep 2024 06:43:46 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.48) by
 edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Tue, 24 Sep 2024 06:43:45 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=oDWnlyh0sQtNh09zpy8DYGqJ5ZB58mDbaP1faTuVG62W+Eqggb1BRD/ZiZb6YFwrEqoBw3YSmE7uxLAnUtcDaF9JUr3xWAvt0zijfLDLF9bUMGj+nQ2izQ012+QlutoH+JKOMBkeVRspDR/rQiViB8ewtyZk13vOp9aOfsWTWby2eE+3Hm8MnNulQObUOwtu3PdG8CJLSLaOrtymv15aJGeHlmPe4WnzQzsv2qkIxdyySJdU9GdDAzbhOoDmoZxkBumnQoR1IzIIL5paa1EFn9CFfy17KNqX4wq2Y58ug0kSJe3eAhZqQPVGxryYN4QAuQcFbsF6B87q69IVFBdNgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Rh/357fzt79lDTq7kIN7HPPuISUtUHPjglBXbcqO42U=;
 b=A2Q64k8llrvQz8r/z/bMW+1Xf1bs8/dxRhMbY1j8EjDhc2T0i0iOFeJ79fmybLjN77Wqxs9k8ufE7xUnS+TPrkq3285bgZuFNEE3ssHMNRH6C8HnJYkrYN3r5kGXSs+kSCfDO2FCCeGEN5nWXBF1v8TDtf/iSnKabUxBTl36iJy4c7QEyLOK5kyTjLGb9pYm6ufQ+Wv1E6kTkuNP/LQ4a46loQwrKc4hPtgWCnaNdOemL3mM/f47zdbh1c5RTRD6GrJQK/ccefEa/2Xmc4ewGdyJ77Y0t5erBCyvy/60SXNgjL5+oCOvHZZqDCBtDEmRofmvHabINRmB2uMDxL0iJA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by CY8PR11MB7081.namprd11.prod.outlook.com (2603:10b6:930:53::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7982.25; Tue, 24 Sep
 2024 13:43:43 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.7982.022; Tue, 24 Sep 2024
 13:43:43 +0000
Date: Tue, 24 Sep 2024 21:43:33 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, <kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: [linus:master] [kcov]  6cd0dd934b:
 BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)
Message-ID: <202409242144.863b2b22-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SI2PR02CA0013.apcprd02.prod.outlook.com
 (2603:1096:4:194::21) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|CY8PR11MB7081:EE_
X-MS-Office365-Filtering-Correlation-Id: 729854df-cdc2-43ee-9935-08dcdc9ee7b3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?80IgR81z9HMexaMULtsO+5uLh3SIv4H6UDOLNj2U6G1/6YxMZ5AXnLyKDapS?=
 =?us-ascii?Q?ocRj+hX8A/w5hBL3HRPKA5GuBiSISU4lQTl7Z2EKIPxWv5KV0FMXKtefhqAh?=
 =?us-ascii?Q?oni31bOaOtCn99bzPyA9Ms+ZWt3dmeO1zuhwutGa/RY6N5k+wYzwTPrTf26c?=
 =?us-ascii?Q?AxeTTgga88TcORwtxxrCf/YnE+JBepubaeeMQUXLYUkis6JD05yT4HQ1cjQE?=
 =?us-ascii?Q?F6qi0Ko6cEoGhTzzGlo8uXOgRIpLJUXmgBCqQBAeQdHDkDLGY8ylu8smSIZy?=
 =?us-ascii?Q?gCfA3NDA+2L8lH2X7DNigdKihQij6wrXxXSpS8hDS6C2MjEOFsJQy88a/60t?=
 =?us-ascii?Q?w6sgXef+g9EVziOsqqjda7Va0USbqvj3g2gfb9y/qRVNFtc6HgBmEd3zUr29?=
 =?us-ascii?Q?wK0uZ6ZVLnyUaOQPYfLqUPwZ9DKgPsZkEm/f3IhrDeKooKQNp7xOkG0IUOVG?=
 =?us-ascii?Q?b8+AxZ1vALayZffeSDxED+l+jl8Ckra0xMlvhYHQ+/B/7hVEl3GM1LCEtdQo?=
 =?us-ascii?Q?E2QxWovRofQErr3og86XlF73z2N0lKg57q4++fhBlnS+H2cvOP2sBkytc9af?=
 =?us-ascii?Q?f+dt+cGJzHPcQZiuEoGyPxTQJvg64H5O7lBA9V+of5T1c/PNQ+ih+3tB5FF2?=
 =?us-ascii?Q?Qw4LTGxHc+mRuKKgmWUk1k+H/ixZCAQkHC8GPiE3yKWibekoHQUG8THzax/T?=
 =?us-ascii?Q?RJ01QWp5rzSJe1y8iQx1grpB5nYL/DXW6PzWReXC7GM4UWWlLo80JKmT4gm9?=
 =?us-ascii?Q?MAJMB1grXxkPwrYjaEcZIntHxcf6xWkncUi2vRtY7uXLodFytJ0V189522kb?=
 =?us-ascii?Q?V2FTTplzE/YRM9K1znSyRkKQNjH9U3AJ7YZfCj6mkEi36FM1pJQ3DpZxJsKY?=
 =?us-ascii?Q?zTgua2nX6NDwNpRPUq7Q4VYXYjjxEwQ/Np839VEQWV/TR1oZ69Sqn0XesIrl?=
 =?us-ascii?Q?C6hYOKqNWuTKSAif+jWU8bLNuVIATSSNIxzPgiyrYiCgSilyQQn1lTGb5gIc?=
 =?us-ascii?Q?0bLKYFPAhWypHHM4CWETYv2y/MDUO6zOwzpwcKvuckKwRJyHJ1efUVl8IdPo?=
 =?us-ascii?Q?Uxcb8HFnHwzHPvuYLPwxVxpn3COuuRuV+4GVmk4fHso/ee0PtxjxXQ4WlKWy?=
 =?us-ascii?Q?CCNlLFr65FWmEOTCZuH+Dc1+tWZybab2gTTO2HLfrP79lQvvK4E7vcgq6J89?=
 =?us-ascii?Q?yA7WeMetruX1xDgIZ1PupfQrCEKEvAFmsYkw33RlDLsi09eDvoMqb+9amCEA?=
 =?us-ascii?Q?aOQEeCmbEsQ6Q+rVnUEQbXKXIEXS1bji4AyggIrpNK2YfFeHY3MZe6t/omTx?=
 =?us-ascii?Q?Sow=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ujoGmkjwwcJ0LzMMvdFopj+vT/sjK20CQL4eqmRwjHlEWoammnYOhHA8MTdt?=
 =?us-ascii?Q?uHgPYWjpwGhuA3niVMQfalGGoPwiKxEhY3dOrw2cjx7XZ+nS/P4kGa6hz9wM?=
 =?us-ascii?Q?HSmTN5K0IonzOKFLFrSeCWk5Nv/PrRQrQ5S9tnlU6FpIDONDFSN2UHQofCtJ?=
 =?us-ascii?Q?hK5Cf7+xbz2Gh3hz64Gfx6fIqbQWqbXTO+9HbE4iX5fLtR/hGAiJSn9blJFh?=
 =?us-ascii?Q?jXZ4kaelDeeQsDNlsMNLZ42iXMNHy69bEv9nq4ZED4roszj2MUxtlImsXw9u?=
 =?us-ascii?Q?26qjQ1OpCWbPlytmu45mDbs9Nq42hmTh/xs3pd5KLEAXrkn0M+D6DRH41Cwc?=
 =?us-ascii?Q?TVwQl+lDt6nI8NRB6ggIHDV8aVBxp6BiE/QgXtkvcw90hbVvvkejSqJR0zhd?=
 =?us-ascii?Q?p2NsOapKLrrSg3LG4HYW4PeRSJ+fh2odbKv4DTJ5gzODDIR5rN4af3A99Au0?=
 =?us-ascii?Q?Ia2BiHf7GXYAqpn9RjmsH+Y9zY8cHLBsJLKmh3E9bhbKHbh2piNiFKcAh/TF?=
 =?us-ascii?Q?7gXwoxVhH6UV5oZ6UaVCmHMlRMEt+hNDG1L9N93yJt5oIh3ItBGIH60rFNiN?=
 =?us-ascii?Q?wRhGHpzuudmFS6vrD6jS+ctvGdoBFhiD9HbNcl6BkhdBs1s6VJVg2Rs2M2zF?=
 =?us-ascii?Q?kXjb5cWsSpysHRpOkqK0uC8FDl/6QJKrh4z0z1DQcKHMSA1Z1FSfiEuIcb1t?=
 =?us-ascii?Q?JglUlZJ1jKSLK/ZQaDm+B9AqkgXMtbKbBq/4X7KTTL0F1RjQPEcLPkLPwJ2i?=
 =?us-ascii?Q?vfcN/pdSuMJFlUB9T2ar4jBzRVahIJjmykT368T+z4vN3Hr32qyITuQ3zaMU?=
 =?us-ascii?Q?M9IA1+NHvIlDRPYb5IOuaNw3j/LkVU3Oh5StKTrIB/Q7PH4nyO3x1tBLv5Ij?=
 =?us-ascii?Q?pewMU6NY9hmi6tv7su2IUmVyVRaeZDKoKhUUXW1zk4SDiHIYR8Vz+T877Fxs?=
 =?us-ascii?Q?bU1TBcvX5sTgL9JPxb2b2Q1w+FLq1LDx8EAuowD+PFUL2h+GRpTTU2x6iiok?=
 =?us-ascii?Q?iiUOLL4VdWAkdZqWm+bZ1nuX2RMivXcFCo62kRwso958O2GlEeCBxj3ECVtU?=
 =?us-ascii?Q?mBCPEE9COk/sggIFuTvZl2xS+MNcNYrRRnTaCT5tT6EtqoTEi0VBDbHzgnCy?=
 =?us-ascii?Q?xJOiJgBToAdOksKEle6JTMQOoKyEbjio+s9rTBzqKTEPLqaYe0JnKh+V+bmF?=
 =?us-ascii?Q?hP4iIYS1EBuAErvByUKScYltjqzsuV3q5IvkPulaztcs56lEYzB7MzlSlIjf?=
 =?us-ascii?Q?pcakDbGZq2+314z4pbpVN/zd99SeRFsxlnEqTkn/OblKH5Vn7wj2borb5Ssl?=
 =?us-ascii?Q?r1GA/QwdabsVjXjSvRI6+tN+W6GDcE4Tk8F3B1UtzhHGmhHwLG6357LGYuL3?=
 =?us-ascii?Q?v0yavEkuJaX3DVlUWOAj89qLZ/SweuUp8RI6/Yi7q2NrEWsaMX7UmM9O2ZfO?=
 =?us-ascii?Q?FPoGvhuTffPtY/2XbZ9SK465j9p5gXaaXzM83OTEziicZmxBmx3oCxmHxuc3?=
 =?us-ascii?Q?LblZvYXxlUfl2PA/BYzZ7fuh2G6QtHD6aJDB25XtPI5Iz986nRuTUXpFhXU2?=
 =?us-ascii?Q?smYooi6K+D/cUFsnEttkcHdqs6B0MRai5CsF8JAM1R8N23MN16Z+x44tQdLw?=
 =?us-ascii?Q?vg=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 729854df-cdc2-43ee-9935-08dcdc9ee7b3
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Sep 2024 13:43:43.1611
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: LKBRMFwuJShriqdqMAiq9CKhjvZe+C2CjDuP8fHdx0CqYYosIQWOCgtPgUHWBmI5p6ZKbZ0II3ibiq/pyrHA9Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR11MB7081
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=YPUxgNxu;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.13 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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



Hello,

kernel test robot noticed "BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)" on:

commit: 6cd0dd934b03d4ee4094ac474108723e2f2ed7d6 ("kcov: Add interrupt handling self test")
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master

[test failed on linus/master      de5cb0dcb74c294ec527eddfe5094acfdb21ff21]
[test failed on linux-next/master ef545bc03a65438cabe87beb1b9a15b0ffcb6ace]

in testcase: trinity
version: trinity-static-x86_64-x86_64-1c734c75-1_2020-01-06
with following parameters:

	runtime: 300s
	group: group-02
	nr_groups: 5



compiler: gcc-12
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)


+-------------------------------------------------------+------------+------------+
|                                                       | 477d81a1c4 | 6cd0dd934b |
+-------------------------------------------------------+------------+------------+
| BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)   | 0          | 18         |
| Oops:stack_guard_page:#[##]PREEMPT_KASAN              | 0          | 18         |
| RIP:error_entry                                       | 0          | 18         |
+-------------------------------------------------------+------------+------------+


If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202409242144.863b2b22-oliver.sang@intel.com


[   16.984454][    C0] BUG: TASK stack guard page was hit at ffffc90000017ff8 (stack is ffffc90000018000..ffffc90000020000)
[   16.984489][    C0] Oops: stack guard page: 0000 [#1] PREEMPT KASAN
[   16.984510][    C0] CPU: 0 UID: 0 PID: 1 Comm: swapper Not tainted 6.11.0-rc2-00002-g6cd0dd934b03 #1 4a678012cbfb14407d2e0b76817d9700747886d7
[   16.984535][    C0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[ 16.984547][ C0] RIP: 0010:error_entry (arch/x86/entry/entry_64.S:1007) 
[ 16.984604][ C0] Code: 0f 01 f8 e9 c2 fe ff ff 0f 1f 40 00 56 48 8b 74 24 08 48 89 7c 24 08 52 51 50 41 50 41 51 41 52 41 53 53 55 41 54 41 55 41 56 <41> 57 56 31 f6 31 d2 31 c9 45 31 c0 45 31 c9 45 31 d2 45 31 db 31
All code
========
   0:	0f 01 f8             	swapgs 
   3:	e9 c2 fe ff ff       	jmpq   0xfffffffffffffeca
   8:	0f 1f 40 00          	nopl   0x0(%rax)
   c:	56                   	push   %rsi
   d:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  12:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
  17:	52                   	push   %rdx
  18:	51                   	push   %rcx
  19:	50                   	push   %rax
  1a:	41 50                	push   %r8
  1c:	41 51                	push   %r9
  1e:	41 52                	push   %r10
  20:	41 53                	push   %r11
  22:	53                   	push   %rbx
  23:	55                   	push   %rbp
  24:	41 54                	push   %r12
  26:	41 55                	push   %r13
  28:	41 56                	push   %r14
  2a:*	41 57                	push   %r15		<-- trapping instruction
  2c:	56                   	push   %rsi
  2d:	31 f6                	xor    %esi,%esi
  2f:	31 d2                	xor    %edx,%edx
  31:	31 c9                	xor    %ecx,%ecx
  33:	45 31 c0             	xor    %r8d,%r8d
  36:	45 31 c9             	xor    %r9d,%r9d
  39:	45 31 d2             	xor    %r10d,%r10d
  3c:	45 31 db             	xor    %r11d,%r11d
  3f:	31                   	.byte 0x31

Code starting with the faulting instruction
===========================================
   0:	41 57                	push   %r15
   2:	56                   	push   %rsi
   3:	31 f6                	xor    %esi,%esi
   5:	31 d2                	xor    %edx,%edx
   7:	31 c9                	xor    %ecx,%ecx
   9:	45 31 c0             	xor    %r8d,%r8d
   c:	45 31 c9             	xor    %r9d,%r9d
   f:	45 31 d2             	xor    %r10d,%r10d
  12:	45 31 db             	xor    %r11d,%r11d
  15:	31                   	.byte 0x31
[   16.984624][    C0] RSP: 0000:ffffc90000018000 EFLAGS: 00010046
[   16.984642][    C0] RAX: 0000000000000002 RBX: ffffc900000180d8 RCX: 0000000000000000
[   16.984657][    C0] RDX: 0000000000000000 RSI: ffffffff86400af9 RDI: 0000000000000000
[   16.984671][    C0] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   16.984683][    C0] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[   16.984697][    C0] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   16.984710][    C0] FS:  0000000000000000(0000) GS:ffffffff88355000(0000) knlGS:0000000000000000
[   16.984733][    C0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   16.984749][    C0] CR2: ffffc90000017ff8 CR3: 0000000008307000 CR4: 00000000000406b0
[   16.984765][    C0] Call Trace:
[   16.984775][    C0]  <#DF>
[ 16.984785][ C0] ? show_regs (arch/x86/kernel/dumpstack.c:479) 
[ 16.984815][ C0] ? die (arch/x86/kernel/dumpstack.c:421 arch/x86/kernel/dumpstack.c:434 arch/x86/kernel/dumpstack.c:447) 
[ 16.984843][ C0] ? handle_stack_overflow (arch/x86/kernel/traps.c:329) 
[ 16.984865][ C0] ? get_stack_info_noinstr (arch/x86/kernel/dumpstack_64.c:173) 
[ 16.984899][ C0] ? exc_double_fault (arch/x86/kernel/traps.c:380) 
[ 16.984931][ C0] ? asm_exc_double_fault (arch/x86/include/asm/idtentry.h:668) 
[ 16.984955][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.984974][ C0] ? error_entry (arch/x86/entry/entry_64.S:1007) 
[   16.984993][    C0]  </#DF>
[   16.984999][    C0]  <TASK>
[ 16.985009][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985040][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985066][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985093][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985136][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985154][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985177][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985196][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985218][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985244][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985264][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985290][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985311][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985336][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985363][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985384][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985409][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985430][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985455][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985484][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985505][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985532][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985555][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985579][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985607][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985628][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985655][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985676][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985701][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985725][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985747][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985772][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985794][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985818][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985847][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985869][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985896][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.985919][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.985944][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.985972][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.985992][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986017][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986038][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986063][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986093][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986116][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986143][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986165][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986188][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986217][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986239][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986265][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986286][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986310][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986338][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986359][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986385][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986408][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986434][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986464][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986486][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986511][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986532][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986557][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986585][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986606][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986631][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986652][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986676][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986704][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986725][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986751][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986772][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986796][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986824][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986846][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986872][ C0] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 16.986893][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 
[ 16.986918][ C0] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 16.986948][ C0] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 16.986968][ C0] ? is_kmmio_active (include/linux/mmiotrace.h:58) 


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240924/202409242144.863b2b22-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202409242144.863b2b22-oliver.sang%40intel.com.
