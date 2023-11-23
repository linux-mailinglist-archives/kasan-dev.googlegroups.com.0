Return-Path: <kasan-dev+bncBD2KV7O4UQOBBAW67OVAMGQEZZAAGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A0AF7F5813
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 07:19:48 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-58a276efa48sf582665eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 22:19:48 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700720387; x=1701325187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A3hbxonzZeitMypwsZeOeQ/24IDF7R3FtjQ4CMUEtKE=;
        b=HP3qJevKkn0PxrgzgBCv9twsl/ACz7lH5ZFb2lOvty+ztaO/INOPmpfZSEMxEvzNfw
         Ec35T5ti0a0lSN6L2mYm+qYataLhhFsk7eZtoqXc+OrKzKEPLY5Fe8xIk61zkWiL29vb
         qBFv3HnGHTfwUicVUPhpQsTXkWqVvftN4ebn4pk740ivZXc4GFk/rA6YWdEChMdD8z3N
         i3xavyF5CR6LO1lMmOa2Gce2BCk9OoedbLVrm2G9yIlRPF02gJws755fkfRu00zte0uW
         FZ26SQxINKBy/5iLxjORyH35shNkvsu2u813FCVUN9xM8YDPB5ju28f374m0R+cYyN5w
         Kyrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700720387; x=1701325187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A3hbxonzZeitMypwsZeOeQ/24IDF7R3FtjQ4CMUEtKE=;
        b=Ew0dxI1Gm4DIbQnxC5DEYsJ8rFcyzmtPRvQbDtSRGvnVPUULzVSp+McFwWXkTl6h3E
         +J0NQaQlAi68FcR4QN/pmqlPLI6993/kPEEmWRVvDFJ9absJBjaWl9leqbbRmujZ0p5c
         mXK59+1lpaLrqp0CP8LsGMIgEobwUtGBO0Q7T6roO5ve5bykDZrLu+TiFxEaKcxJnTwC
         R4VfkEpIlnfhKrNJ10+jEaJCLmcwlV0w/hAadUwf1sW/JsHZq7ovyZCBSE6oEjGp37CQ
         yHZwLPzBr05+wR9j5hC0/4i0s2eufwrH8qGdYwoXyxrOzwrJsVW5wVpm3rzcH//hMZV7
         lDrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxFN8nLNo7/KfYS+8f87Bsjyl16BJhxOUI1eTm6FTTxq1fOuFfz
	kfpBEn8Rwna5juRoVPT700U=
X-Google-Smtp-Source: AGHT+IFWB5Iv8tk3iPm/tELuyOiG+kuwCeY+1XKV1zHi+MvQoAwpLO3dBN8rTWrzcEvWV3VA81cJUA==
X-Received: by 2002:a05:6820:1c81:b0:589:d42b:d88 with SMTP id ct1-20020a0568201c8100b00589d42b0d88mr6192596oob.2.1700720386961;
        Wed, 22 Nov 2023 22:19:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1c85:b0:587:ac20:bf95 with SMTP id
 ct5-20020a0568201c8500b00587ac20bf95ls450851oob.2.-pod-prod-01-us; Wed, 22
 Nov 2023 22:19:46 -0800 (PST)
X-Received: by 2002:a05:6359:5d02:b0:16b:f94c:5d3 with SMTP id ps2-20020a0563595d0200b0016bf94c05d3mr3233635rwb.32.1700720386107;
        Wed, 22 Nov 2023 22:19:46 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id kr18-20020ac861d2000000b00417048548c7si70931qtb.2.2023.11.22.22.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Nov 2023 22:19:46 -0800 (PST)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-IronPort-AV: E=McAfee;i="6600,9927,10902"; a="5397225"
X-IronPort-AV: E=Sophos;i="6.04,220,1695711600"; 
   d="scan'208";a="5397225"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Nov 2023 22:19:43 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10902"; a="1014520635"
X-IronPort-AV: E=Sophos;i="6.04,220,1695711600"; 
   d="scan'208";a="1014520635"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmsmga006.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 22 Nov 2023 22:19:42 -0800
Received: from orsmsx602.amr.corp.intel.com (10.22.229.15) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.34; Wed, 22 Nov 2023 22:19:42 -0800
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.34 via Frontend Transport; Wed, 22 Nov 2023 22:19:42 -0800
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.100)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.34; Wed, 22 Nov 2023 22:19:42 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=cGBmJbhgOmlf1N5FmZqJX8jxS8tl2Bh3IoBRz569GUHAxKQVCmJWW/HM9oxAZhs2qLz8eVVWyhnr6Fz0R88drjnWaiIEikbVXUOaM6QnsHDmtBPk/pJJsr5dhId+1m3KDzn/bQs7hMnFBO1qdu3d8OUMB8z5U2w4mP9dXG0pj+OxCwE1G8/XHT4JMRQpabtZGLHQyoh1Jc8qT8fXBwY14glfRhBF9iK3gn2WFwza2KoSODNvatBrp66rNoMNRSjcFNJSMkMDQXPsuzxdaOrjOIrjg33N8Z/KEpqmn8MryHPq1A4WsknOM1rlZ4Shl7IcvH2ank4XEhlrlPx7Vq+NUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NYWUS1Xu0xI2ncLl0NPxVPD+6+v5q1yMRSfeKeGsH9E=;
 b=KSK4EkuAS6tEr42KhLq9h/e30VvdjLql0QrQOum3d6TT/rDPMErzXg7mTn71ovW/conaLllAMrjcZyaXPRb3Fj49FK9R8pSnqgNEnMwyN0YHljZLZcvWJtUIlCkdxVosRQpSzx7/YYyxQdjFoElQsIdNiLY1Ibm9sJEQ3Ad9F52AMKYFR4yjEHMbwjDKmTKMn4EnI3a84igXy/ZfTVN6taeN8MYORBi39U7/TEQoilbkndl6tu95QXdKP+t5oDaDw9+Vfh136sZJoyVB4O7UtcIaWA3hUbACDx69JfMPVxAe9LIfiLNLf3P2PBvNqKyG223IPPL6W021qqo86/7XrA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by DS7PR11MB7737.namprd11.prod.outlook.com (2603:10b6:8:e1::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.18; Thu, 23 Nov
 2023 06:19:35 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::1236:9a2e:5acd:a7f]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::1236:9a2e:5acd:a7f%3]) with mapi id 15.20.7002.027; Thu, 23 Nov 2023
 06:19:35 +0000
Date: Thu, 23 Nov 2023 14:19:24 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver
	<elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Evgenii Stepanov <eugenis@google.com>, Oscar Salvador
	<osalvador@suse.de>, Vlastimil Babka <vbabka@suse.cz>,
	<kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: [linux-next:master] [kasan]  0e8b630f30:
 BUG_kmem_cache_node(Tainted:G_T):Poison_overwritten
Message-ID: <202311231356.1e1fb71f-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SG2PR02CA0129.apcprd02.prod.outlook.com
 (2603:1096:4:188::19) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|DS7PR11MB7737:EE_
X-MS-Office365-Filtering-Correlation-Id: fe1637d3-f6c4-4e04-7e2c-08dbebec2963
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 7zt6KMbEcPxPxf7esvpA3LuFD4nj7APLzCHWRG88u9pyjI1lPXA2BCFk23G1HEKjVlZty8e7cdU+L8LFqmVWdQnD1lj68hI4sEurnorY1kGpyEPVqGxXcmTxH3+mBG4XeyJzQQ+L0UMQXe6ZbS+aI+9OnPLA51iMLlJoArLWqlO/ZRziTt+OiliZdo0vv8c7Okksu9foIh5hOApVer90qbVhqRVGbe3aPwLMWOhfY0xbfvGa7HI0EUpB1eyYIAFNmpqNshe0sE/eSaWo0bd4aNPuCQlRxElHPZgISdlL+wT8f6ab1TEJ4tADaGPG9BccxtZtAwfK1bPJ1pOXdIhGw3ylw/0t7IBPlbgKkchb1WtLeo2GprXhxhOwZOkb4oJp3b4y/B5KgHV1DrHdkkinlBjbQ8olJEBBqV8oNQeW1d1FCAObUFc83rAch8fK6T7jt5N9IP1+kQp6q9asuQHOKHwHhoWvUcSDtAKRyR9yfZX88AMasr0ga8Pvz1BTSGzpHYGvmlfCdgTsPtEf7xUrBRtm6Al1iQgjx9orG0hCM2h8igGK+EiIwbPoLslZ33e7UZpReqCdlU035PcMOzWYFeZcDDlxAmKLXHpAqDnwt2F6iVbqucY8V4e3x5xacwN5PBO+KSMzxWuep7LEuKjCoQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(366004)(39860400002)(396003)(346002)(376002)(136003)(230922051799003)(64100799003)(1800799012)(186009)(451199024)(1076003)(82960400001)(83380400001)(66946007)(6916009)(6506007)(54906003)(66476007)(316002)(36756003)(86362001)(966005)(6666004)(66556008)(6512007)(26005)(107886003)(7416002)(2616005)(8936002)(41300700001)(2906002)(5660300002)(6486002)(478600001)(38100700002)(8676002)(4326008)(505234007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?JyopAETlNlXJZ6nuFcdJ24u4Rks8um93B1GCV82ZbjpE+BM5/EdEXOpSJa1P?=
 =?us-ascii?Q?6dIItgxcIQK6nMfmg1C32e1y9wtLsArx3K0HLHZsnf401iPypEfwHAybAHA5?=
 =?us-ascii?Q?yK3SNG2pvsnPmDTMThgmLYz1bkywNCVH1krBYVc3/QPbRa3O9FRfHITLFtHt?=
 =?us-ascii?Q?Zl2Bfb5Tnmk2cgnuKDBzuosAYq+k0WuBtYl9h2S9JNTLEDOUuSqnEa/k3wjg?=
 =?us-ascii?Q?vBM/cdNYbqahxYVngX3Te0ithJjTINDFL7FmQeFhnAk0VRsoCiqbG3ZG347S?=
 =?us-ascii?Q?soPCa68ZR8actdN4Rw2srn1AwjgmtVH8VcXO2Q9bMfH+iLCwt4KF3Z75T81o?=
 =?us-ascii?Q?IVp7fvOogu3JjDvghi2/NMa2aJF3AvPTdpM8sVdlysPF7ZLg3sQ8yb0/1Wby?=
 =?us-ascii?Q?fG3dc/eHy1RwFufaH+5tqVJ7ddTye9JFkxStvKiRPgPTtjQSPR/QxDLP0t0D?=
 =?us-ascii?Q?t+4W+im3z3/OKbQP08Ksi1anXDRZBAOGJpuMtQtHhSpvZ/9J1+PNb/ThMZKk?=
 =?us-ascii?Q?c807NqyswDCWwgQP2f/voUuhQoyiHpf2VVv3cuzJLSzKHhIyIY+qEmRHFq7V?=
 =?us-ascii?Q?ArA0M1rEARbRpUcAxhxvomC+o8EyKK3l4i3s6Eg3+Sg1+hrUmyldPhU90Yw5?=
 =?us-ascii?Q?cxGDoDX4pq8sNDTMkXNSFC+bBpCpsWnR7m97PXmObJK8qM9crmAKskV7AI+T?=
 =?us-ascii?Q?wYyOgZ3n9Nau6JfQwdr3jqZ7K0um/GyE9l3+vBLVXldOXOBjJ6DZlCnhR2hY?=
 =?us-ascii?Q?RzaHnM9Lc86I1hqIJXkVv6GfWUQbqe57HuUSQQbNhkNiUXyHPfKLNR+0BX0J?=
 =?us-ascii?Q?+9PXtIojgPdE6+Na95UYTc9gOgGlJnJR8ilTUTaMPLiybcc2OLlViyZjWR/d?=
 =?us-ascii?Q?z/kGso6MxRQ90zPU9UohJDA+goIiYz1J71ow2jenfpCDV09HTeck9N6YCvcv?=
 =?us-ascii?Q?6rAGZNQ93EtC/t/H50VhsAaQ61r54GA9vP+bIFAPHYKCXStw2SZrfsCeDT/l?=
 =?us-ascii?Q?XQEijDt7VVH87dJ+ZoaEizD3C0NSgtgSNATcCVOTywsEsSYZSYbcI/2Wdn5G?=
 =?us-ascii?Q?YKEnrWTgDZudiqAP2hELcrMbBKOZ9m5IMT7n72eOyByVZ23tbcpbyrHhsLf4?=
 =?us-ascii?Q?DOsuPAyleE+YW6aDaCwj7hiH8tzbOFT0WPbgcxm1QUzJhQKzliO1l7+IShiI?=
 =?us-ascii?Q?WKpP28+H1R0Y0FX9sm0DHw7LuDbw4N16xfdEGhv7Vb3DkaGzjmGtGpKDJ5RZ?=
 =?us-ascii?Q?z/kkoG8F29fjnH/6c8AYnaanDAYtmOHWag5/K0JfCX/ChBdAJU4ZtZoaToJt?=
 =?us-ascii?Q?PI+G4G2x8lKroHGbyk0XYpqglht1TFOpYbAE1HJvL8mTxevly7PIeW757yNd?=
 =?us-ascii?Q?d1IDzyJbyiGjQ6Yo5QaT6sQHy2lj+CNUCx30TO/HNgQX6KwyOhHlIoKKCZks?=
 =?us-ascii?Q?zpl/bBG6HKKFVFTZ5vMn028qrp5pELl3XwWiWB3yRNBFFq3tBYitCAlS3mnS?=
 =?us-ascii?Q?2ce26O8IcbiKYATwEMMugqPeML6w92ri/HpfgUfDxOOTuGppTUAGP2rIoyKO?=
 =?us-ascii?Q?DeOwstFHaTO2X1NS8xF1fpW8Jmb/zDgoCrrT4hjRgxAEkNfHxxP1kqI+C530?=
 =?us-ascii?Q?4g=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: fe1637d3-f6c4-4e04-7e2c-08dbebec2963
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Nov 2023 06:19:34.5181
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 3XjNPA6J96JysIJUuTYIAE/UMwdQsRSyNI7MFnIQyN3y6a3RaL+ID15nzahEjAsxcHlAM4yv2Z9Azy+/JJml0A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR11MB7737
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="ELWQf/Me";       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.10 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

kernel test robot noticed "BUG_kmem_cache_node(Tainted:G_T):Poison_overwritten" on:

commit: 0e8b630f3053f0ff84b7c3ab8ff98a7393863824 ("kasan: use stack_depot_put for Generic mode")
https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master

[test failed on linux-next/master 07b677953b9dca02928be323e2db853511305fa9]

in testcase: boot

compiler: clang-16
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)


+--------------------------------------------------------------+------------+------------+
|                                                              | 882f84db75 | 0e8b630f30 |
+--------------------------------------------------------------+------------+------------+
| BUG_kmem_cache_node(Tainted:G_T):Poison_overwritten          | 0          | 55         |
| BUG_kmem_cache_node(Tainted:G_B_T):Poison_overwritten        | 0          | 55         |
+--------------------------------------------------------------+------------+------------+


If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202311231356.1e1fb71f-oliver.sang@intel.com


[    5.031171][    T0] ** administrator!                                       **
[    5.031752][    T0] **                                                      **
[    5.032336][    T0] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[    5.032920][    T0] **********************************************************
[    5.034153][    T0] =============================================================================
[    5.034907][    T0] BUG kmem_cache_node (Tainted: G                T ): Poison overwritten
[    5.035573][    T0] -----------------------------------------------------------------------------
[    5.035573][    T0]
[    5.036459][    T0] 0xffff888100040200-0xffff88810004020f @offset=512. First byte 0x0 instead of 0x6b
[    5.037203][    T0] Slab 0xffffea0004001000 objects=10 used=2 fp=0xffff888100040380 flags=0x4000000000000800(slab|zone=1)
[    5.038098][    T0] Object 0xffff888100040200 @offset=512 fp=0xffff888100040380
[    5.038098][    T0] 
[    5.038908][    T0] Redzone  ffff888100040180: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.039738][    T0] Redzone  ffff888100040190: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.040565][    T0] Redzone  ffff8881000401a0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.041384][    T0] Redzone  ffff8881000401b0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.042210][    T0] Redzone  ffff8881000401c0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.043030][    T0] Redzone  ffff8881000401d0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.043849][    T0] Redzone  ffff8881000401e0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.044670][    T0] Redzone  ffff8881000401f0: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.045495][    T0] Object   ffff888100040200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    5.046316][    T0] Object   ffff888100040210: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.047135][    T0] Object   ffff888100040220: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.047955][    T0] Object   ffff888100040230: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.048774][    T0] Object   ffff888100040240: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.049598][    T0] Object   ffff888100040250: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.050415][    T0] Object   ffff888100040260: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.051232][    T0] Object   ffff888100040270: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b a5  kkkkkkkkkkkkkkk.
[    5.052052][    T0] Redzone  ffff888100040280: bb bb bb bb bb bb bb bb                          ........
[    5.052815][    T0] Padding  ffff8881000402e0: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[    5.053642][    T0] Padding  ffff8881000402f0: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[    5.054459][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G                T  6.7.0-rc1-00136-g0e8b630f3053 #1
[    5.055259][    T0] Call Trace:
[    5.055514][    T0]  <TASK>
[    5.055744][    T0]  dump_stack_lvl+0x83/0x13b
[    5.056703][    T0]  check_bytes_and_report+0x121/0x140
[    5.057130][    T0]  check_object+0x1b9/0x380
[    5.057496][    T0]  alloc_debug_processing+0x157/0x200
[    5.057920][    T0]  ___slab_alloc+0x593/0xdc0
[    5.058283][    T0]  ? __kmem_cache_create+0x115/0x4b0
[    5.058702][    T0]  ? __kmem_cache_create+0x115/0x4b0
[    5.059119][    T0]  kmem_cache_alloc_node+0x250/0x2b0
[    5.059540][    T0]  __kmem_cache_create+0x115/0x4b0
[    5.059951][    T0]  create_boot_cache+0x89/0xbb
[    5.060331][    T0]  kmem_cache_init+0x94/0x13b
[    5.060699][    T0]  mm_core_init+0x33/0x7b
[    5.061039][    T0]  start_kernel+0x19e/0x3fb
[    5.061397][    T0]  x86_64_start_reservations+0x2a/0x3b
[    5.061835][    T0]  x86_64_start_kernel+0x5f/0x7b
[    5.062223][    T0]  secondary_startup_64_no_verify+0x101/0x13b
[    5.062710][    T0]  </TASK>
[    5.062943][    T0] Disabling lock debugging due to kernel taint
[    5.063426][    T0] FIX kmem_cache_node: Restoring Poison 0xffff888100040200-0xffff88810004020f=0x6b
[    5.064163][    T0] FIX kmem_cache_node: Marking all objects used
[    5.064664][    T0] =============================================================================
[    5.065387][    T0] BUG kmem_cache_node (Tainted: G    B           T ): Poison overwritten
[    5.066068][    T0] -----------------------------------------------------------------------------
[    5.066068][    T0] 
[    5.066962][    T0] 0xffff888100041080-0xffff88810004108f @offset=128. First byte 0x0 instead of 0x6b
[    5.067711][    T0] Slab 0xffffea0004001040 objects=10 used=1 fp=0xffff888100041200 flags=0x4000000000000800(slab|zone=1)
[    5.068593][    T0] Object 0xffff888100041080 @offset=128 fp=0xffff888100041200
[    5.068593][    T0] 
[    5.069355][    T0] Redzone  ffff888100041000: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.070180][    T0] Redzone  ffff888100041010: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.070996][    T0] Redzone  ffff888100041020: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.071812][    T0] Redzone  ffff888100041030: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.072628][    T0] Redzone  ffff888100041040: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.073450][    T0] Redzone  ffff888100041050: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.074267][    T0] Redzone  ffff888100041060: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.075083][    T0] Redzone  ffff888100041070: bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb bb  ................
[    5.075907][    T0] Object   ffff888100041080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
[    5.076729][    T0] Object   ffff888100041090: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.077557][    T0] Object   ffff8881000410a0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.078372][    T0] Object   ffff8881000410b0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.079187][    T0] Object   ffff8881000410c0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.080001][    T0] Object   ffff8881000410d0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.080816][    T0] Object   ffff8881000410e0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b  kkkkkkkkkkkkkkkk
[    5.081638][    T0] Object   ffff8881000410f0: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b a5  kkkkkkkkkkkkkkk.
[    5.082453][    T0] Redzone  ffff888100041100: bb bb bb bb bb bb bb bb                          ........
[    5.083212][    T0] Padding  ffff888100041160: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[    5.084028][    T0] Padding  ffff888100041170: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a  ZZZZZZZZZZZZZZZZ
[    5.084847][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B           T  6.7.0-rc1-00136-g0e8b630f3053 #1
[    5.085659][    T0] Call Trace:
[    5.085975][    T0]  <TASK>
[    5.086203][    T0]  dump_stack_lvl+0x83/0x13b
[    5.086566][    T0]  check_bytes_and_report+0x121/0x140
[    5.087005][    T0]  check_object+0x1b9/0x380
[    5.087370][    T0]  alloc_debug_processing+0x157/0x200
[    5.087792][    T0]  ___slab_alloc+0x89d/0xdc0
[    5.088166][    T0]  ? __kmem_cache_create+0x115/0x4b0
[    5.088612][    T0]  ? __kmem_cache_create+0x115/0x4b0
[    5.089033][    T0]  kmem_cache_alloc_node+0x250/0x2b0
[    5.089462][    T0]  __kmem_cache_create+0x115/0x4b0
[    5.089881][    T0]  create_boot_cache+0x89/0xbb
[    5.090264][    T0]  kmem_cache_init+0x94/0x13b
[    5.090634][    T0]  mm_core_init+0x33/0x7b
[    5.090973][    T0]  start_kernel+0x19e/0x3fb
[    5.091338][    T0]  x86_64_start_reservations+0x2a/0x3b
[    5.091796][    T0]  x86_64_start_kernel+0x5f/0x7b
[    5.092188][    T0]  secondary_startup_64_no_verify+0x101/0x13b
[    5.092701][    T0]  </TASK>
[    5.092948][    T0] FIX kmem_cache_node: Restoring Poison 0xffff888100041080-0xffff88810004108f=0x6b
[    5.093695][    T0] FIX kmem_cache_node: Marking all objects used
[    5.094209][    T0] =============================================================================
[    5.094974][    T0] BUG kmem_cache_node (Tainted: G    B           T ): Poison overwritten
[    5.095654][    T0] -----------------------------------------------------------------------------
[    5.095654][    T0] 
[    5.096573][    T0] 0xffff888100042080-0xffff88810004208f @offset=128. First byte 0x0 instead of 0x6b
[    5.097348][    T0] Slab 0xffffea0004001080 objects=10 used=1 fp=0xffff888100042200 flags=0x4000000000000800(slab|zone=1)
[    5.098267][    T0] Object 0xffff888100042080 @offset=128 fp=0xffff888100042200
[    5.098267][    T0] 


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20231123/202311231356.1e1fb71f-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311231356.1e1fb71f-oliver.sang%40intel.com.
