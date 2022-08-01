Return-Path: <kasan-dev+bncBDN7L7O25EIBBDXCTWLQMGQEKMGHE5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CE59586404
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Aug 2022 08:22:07 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id d27-20020adfa41b000000b0021ee714785fsf2231281wra.18
        for <lists+kasan-dev@lfdr.de>; Sun, 31 Jul 2022 23:22:07 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XMijXyNi3puqTvIxStx4g+AqV17hP/PFNybAZHcEb6c=;
        b=IdA3gJHumVzSliUOBXDsJ6QW+shoaa2rcCkLR+kD92BWZEowE9TOT1AHsyP6XuHbdD
         oD0AcRq9zNXWWOY+e0yUqolCkLjTWecpSn1cWbheiLPpTycHOQIfNFz51t6VX7lwjy0f
         X+WKSRTKADq0IEZgvbi66xqFFvITDhIb3Dg9iou1o1byPRbQbdvtRkuwbRUa4167rDl3
         R3lbY7MXBCbU8PZPBzqou45ZoUttYZoX2ZRsQZdgaJmREP0UfCjf3Ss5FoQo1eEx2xtp
         njls8+GwFCJVqOpZQ68QcN6hyhPvsNqQA4xTZ25HWlG6bW89vfHI63LJNftRtJPKWA/O
         vLPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XMijXyNi3puqTvIxStx4g+AqV17hP/PFNybAZHcEb6c=;
        b=VF3rWAyr6qNUT/VjveCHBecF2tU+67G5NS/NckV5FJtnHNrcYBhbbQHtByJf5hR90J
         793dLlHW/GPJI+AtHipZNDydTlyUrWRl5LgITHMCIdViulcw4wl1hJojhaUuCISbofyW
         +vlufRdq/8cI5an5Bt2yY+08dK3I+2FIYQtEhhyPDPy84WZcnNcbHhrGfyd0qoBfehZU
         O7pveuQ6sFAtQCzYkJLphYMYXuOiyF9iiUFBCKwdJS7CJlg7kHoxEnQrKPMeRJU6wPWV
         uj6Ij4eClK6ZMcPl69lGzJ5/w9hs9J/OO71CCio+KF7NBb9yon+U13p4xBsvwzVwwnMD
         pYkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2+uqUVpCaa2FrsN1mQypDLF7CIAcnNGgrKfeuFuJ39nmfqEO+L
	RLZ3kD7/rQZ1ePGNDVjgukw=
X-Google-Smtp-Source: AA6agR4ZAR9gdhq0gNwDn2H0QXWk5trY/llsdGjIenST9xo+Dig+GLMmdmrlglMs7Vv7kg7sEDfGmw==
X-Received: by 2002:a5d:6d85:0:b0:21d:bc38:c4e0 with SMTP id l5-20020a5d6d85000000b0021dbc38c4e0mr9208669wrs.264.1659334926260;
        Sun, 31 Jul 2022 23:22:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:605:b0:21e:d303:d51 with SMTP id
 bn5-20020a056000060500b0021ed3030d51ls10921488wrb.2.-pod-prod-gmail; Sun, 31
 Jul 2022 23:22:05 -0700 (PDT)
X-Received: by 2002:adf:f944:0:b0:21e:98dc:ad47 with SMTP id q4-20020adff944000000b0021e98dcad47mr9321896wrr.317.1659334925316;
        Sun, 31 Jul 2022 23:22:05 -0700 (PDT)
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id bu25-20020a056000079900b0022068e0dba1si17518wrb.4.2022.07.31.23.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 31 Jul 2022 23:22:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6400,9594,10425"; a="314893890"
X-IronPort-AV: E=Sophos;i="5.93,206,1654585200"; 
   d="scan'208";a="314893890"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 31 Jul 2022 23:22:02 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,206,1654585200"; 
   d="scan'208";a="577667785"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orsmga006.jf.intel.com with ESMTP; 31 Jul 2022 23:22:01 -0700
Received: from fmsmsx609.amr.corp.intel.com (10.18.126.89) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Sun, 31 Jul 2022 23:22:00 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx609.amr.corp.intel.com (10.18.126.89) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28 via Frontend Transport; Sun, 31 Jul 2022 23:22:00 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.102)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.28; Sun, 31 Jul 2022 23:22:00 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=gCGH9l+q68bmsf/glGsSHoU3hb5q87eM+1Kx6Ve5AucdYXRFVkKnyEI7cjCP6JRSe0mwhtICWUJdBVffr3pTa9ifmulhhnfunKqd+CbE5+4KeFMyEmTEwgpT06aSiC83Rkk6i14Wzh+iFLjGxwehW7SQLLJd2bXpDe9wWQA+9rr/76yfDL/vzCeN0/l8mPu9KvAH9+6NzWAXiRYy2r5bJi+guXzW3s+H18nTov69qovn6Z60arR+Y/55NoM+Cid2mVVofbw5mAIaDSIfcBCPOxmebulsp4lB+zMk/PCps/FEx20Bh5W3sqmKsRaaIRfZetzu7tflyTui4S6GfKd90A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5ORrpUQfxP3i4qb9oRb97nmERA7C5jGkzjaRjcsHSJY=;
 b=KvbCUXOvtqShrZ5mab+I5SVP1pRUC9CWHdDCPfNNhqkIG986i6YnabNsxAq/wXwI7QO2UV0JbQi20hKbWWbG09cJ1D0yPHdi10URrNuWRqkXZlgaxDj5yY0zeWE1WFEe8j9CzvI4GkvcbKEB5AQfkMPuH344OpURJtAj2L/agkq93mYBvF4g5I6ZSjp0cK2ntC+VgkpsX4pYt6+W+3oQMAbwTajiRLQu0xFIY9K5/QXg3QyKCUBhyujelT3WkUUVkfl3Li7o6/xufzshrG53SUpfaK0D+fUilfjWwSOUDF+Lw84wLmZkGwu2VRlK3gV5Lzy57qhIwLMKA6tFD3JQNQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MWHPR1101MB2301.namprd11.prod.outlook.com (2603:10b6:301:53::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5482.15; Mon, 1 Aug
 2022 06:21:58 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55%6]) with mapi id 15.20.5458.024; Mon, 1 Aug 2022
 06:21:58 +0000
Date: Mon, 1 Aug 2022 14:21:26 +0800
From: Feng Tang <feng.tang@intel.com>
To: "Sang, Oliver" <oliver.sang@intel.com>, Vlastimil Babka <vbabka@suse.cz>
CC: lkp <lkp@intel.com>, Vlastimil Babka <vbabka@suse.cz>, LKML
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"lkp@lists.01.org" <lkp@lists.01.org>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>,
	Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Alexander
 Potapenko" <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	<kasan-dev@googlegroups.com>
Subject: Re: [mm/slub]  3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Message-ID: <Yudw5ge/lJ26Hksk@feng-skl>
References: <20220727071042.8796-4-feng.tang@intel.com>
 <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YuY6Wc39DbL3YmGi@feng-skl>
X-ClientProxiedBy: KU1PR03CA0017.apcprd03.prod.outlook.com
 (2603:1096:802:18::29) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 69363f81-e60b-4e02-e2d0-08da7386238d
X-MS-TrafficTypeDiagnostic: MWHPR1101MB2301:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: Iia5pXKg4WJJzGUpYnGDQYT+g6HKvAbHS5HfKgNXOyomqNZG3KW8ZzPqDKGPEpt/eYuN6891DF9fiHl3q+cWcwV5AghFLrLunAzAdArp8TpxiAxqk9USzUUocRddJsl9SOO6HwE8v2nbXtYlFroei330KoMT9olZk+neJ7IouIUtYMhD3RWRgK7y1IlaYj+TjgBtBpHeCAO9C6bjhb0OCPIbJAzTimb1/Ey4jM6hU1slUonftqleMfnucY354xOWXujH0xcpU5XS/juLueuKlCYqVgg34T/f2PeBSEqv6eTyTPnL9xxjkUmIvZ11p/+8neEfpIQHwm/g9F6OI/OZ0f2JgppexOYPptm2hWIbAqRhWoinwi24CARJxMGNeddWCg1M/adEdGfIY1OhmCAjTGYy2xOdo0FF6OLN1V+EX/H1CesEPDBL72cjPGmzf6h7GjEDKP0kh2AF1HK49UFyQELtiE1tj2c4SaCDxcm6CXoQfMPM2THtFrZAzq+MhtbMtZz+4n17kaY4A+YitNlPe2hEkx//xNr7/amz+4bAZ5IKjpwcyjSHlC2/GwUmw27SCVjcFK61ljii+WNDR8/cMypl/RcTVLon9mJeTlS16MFbZ14Az4sXsybfySoZE0f8jPggVG6RDWpj3k8nPCHnDpTUnGZdgRHg+G/W2hgPHHNpe5rkJlwOyGlQavqW/jQ8V5ahP3JW07OoIEGYaozeJmjo+xBTWnULs4wUPnuDrUOHoDolgscPZ27Brju7bIVMyBqRLl10PGL2XFxaomp0u/mewZLZCepRkCYEwa9i4NDZ49OOouowP0zTPiVS9Kro
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(366004)(346002)(136003)(396003)(376002)(39860400002)(44832011)(966005)(6486002)(7416002)(478600001)(316002)(83380400001)(2906002)(66556008)(66946007)(110136005)(54906003)(41300700001)(5660300002)(8936002)(66476007)(8676002)(4326008)(6512007)(9686003)(33716001)(86362001)(6666004)(26005)(6506007)(82960400001)(186003)(38100700002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?m768fNXLHGvXQYum8S0gIFKoY94EOUd0lD2mVR+8WOF70i+ejlR2lopHweZR?=
 =?us-ascii?Q?FkCZ/HpRzuaUe4mw77hDjFSWm9nZ8h2XcjDBUawyAvfLDVstOcz4rKPOVYm2?=
 =?us-ascii?Q?Ge7aBt7QmQw8PcVjJ3d8cY7c23Lo/uf+VeNr/uUWw8SAGePqv/DEtbJhe1U9?=
 =?us-ascii?Q?Onf8hQUwX7qvuKpcrEMPxSDtkmgsFI+SlKFTdprK6OTEuugieCWNc49aoIj7?=
 =?us-ascii?Q?2MbaER+R/OB4mvfe7FZT6jWXvtO0PiZlHEvivFTCMa+t9zMWIn98Aj6+Lmt7?=
 =?us-ascii?Q?jtGSG5y3rrctr59Lx5pBBw6xwm/HmIWhbUPgG/QkIGo/XZM0tPNsEW5VC6Gf?=
 =?us-ascii?Q?iKQDhT1QXZvh/lQ4GgNILmXZf9/x5NgNHoDGYeU2CYhfsXbY7U2GFZrHtV9h?=
 =?us-ascii?Q?rHfgbZ1H+yf8lCVqTek4T0VMEZhCphBU1oQqQhqmac4/k006qRmtBRFn7y+2?=
 =?us-ascii?Q?8AamPnG37llnBrkSv2R6zKWGwUu2wOCsbL3yMr94LfPnHCVnsZW1RmS90H5O?=
 =?us-ascii?Q?tobvKH74y2T3nCs+wgsD6g1rUbXw4/z5H9i3pNCsyMOd47Ab9eqwXcLDIMtM?=
 =?us-ascii?Q?eqRqLzaqrFpqVJkoLO3oa21uzw0Sj7ZBqc/OmTy6NXMhH2hIHSu81LWc2/aj?=
 =?us-ascii?Q?21l9QqDrd6Qf0c1VzoNn1bT6JjoSvu+qenFoVJHvAeR63t1OxFsuUepGKIdp?=
 =?us-ascii?Q?8H1eRKVFaFnMMNPfNr+OxIGpaefZCtQ4ZTkGmTI+fBYufViExg23axPyox9X?=
 =?us-ascii?Q?uoB4ql23quMPPKFdijech3YiTkYVzogq2Y182mzAAhVDqhdri1f/btlrHZrU?=
 =?us-ascii?Q?qktUJDUAPEqy0T63DE69a4VumxClINye9M7d4289W1Ek7OpJgU67Wrvp7/I0?=
 =?us-ascii?Q?jzxwUWKfLcl7Gg9ceEx4/KcBYFkOlbQBZ9NFZlPSf1665QxqCDPyZ9xiX2wb?=
 =?us-ascii?Q?jpBpwstt4VuMtc0Y5+/WRyNF8ldlunEz8i/HL/O8dWgkHRN7AowkwjzBqrek?=
 =?us-ascii?Q?CIiA3Mea2x1Y2KYPhP2wr1TzvfwmpxFdAXARGybul4Qz4bW3C64UbXmJXz7H?=
 =?us-ascii?Q?daIHWA3BC0CgmwVLyy46gsTk1v5G5mjmInE2A8/r/1YCFbqPV7NW8pRA3HL3?=
 =?us-ascii?Q?z3rY7//Pumf+4qiKei0FdxCibiFwm0l5PBBvjDYxvldxBb3r0nq0wWNH5qmd?=
 =?us-ascii?Q?coDKcOr8Z4FI4F5ePW286u9+W7tqckhoWFJbZ12eFRiC+v3ixWD9Z3KZskdm?=
 =?us-ascii?Q?/PhymkQjdjknXHmc9EzOQOShiPfPrm5Thsr5Cucc/nGuiFJtigOnGM91X/62?=
 =?us-ascii?Q?gWsz/fKD9DuQJp7gYXytxROIBX1N/r8mGKNr27AhGUPUCBb20iWO2Oc/RPmV?=
 =?us-ascii?Q?H99zPGNXwD2kNYs5G9Dk8B7a5v1RH1z8a67VA3BM1t5R8BvaK7XQgsXKFXQB?=
 =?us-ascii?Q?AAnAzdg2rp+AKvCaM8GmD6i1klMC1HoASPldU3t3wHi1mifrS9yHNxQLhXEt?=
 =?us-ascii?Q?SL8v3gb8RjW9Ikhq8LghL0A33M127vC7nOo9N49lzsuk0MqbxF1jPgfDSe9P?=
 =?us-ascii?Q?u5EiKc6fNyQdDYJjz+YRmZg1j86/6jKrv93DNyV2?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 69363f81-e60b-4e02-e2d0-08da7386238d
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Aug 2022 06:21:58.7221
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: HOp3uuvxlj/yitGcG3eD0yvUwQ/MxKAz/jSKggk+Iuah61Nlx4sNLb5sTqWlaBwC0yW1N9fO+QA65fvT1bCWEQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MWHPR1101MB2301
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=MPVQr5gP;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.88 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Sun, Jul 31, 2022 at 04:16:53PM +0800, Tang, Feng wrote:
> Hi Oliver,
> 
> On Sun, Jul 31, 2022 at 02:53:17PM +0800, Sang, Oliver wrote:
> > 
> > 
> > Greeting,
> > 
> > FYI, we noticed the following commit (built with gcc-11):
> > 
> > commit: 3616799128612e04ed919579e2c7b0dccf6bcb00 ("[PATCH v3 3/3] mm/slub: extend redzone check to cover extra allocated kmalloc space than requested")
> > url: https://github.com/intel-lab-lkp/linux/commits/Feng-Tang/mm-slub-some-debug-enhancements/20220727-151318
> > base: git://git.kernel.org/cgit/linux/kernel/git/vbabka/slab.git for-next
> > patch link: https://lore.kernel.org/linux-mm/20220727071042.8796-4-feng.tang@intel.com
> > 
> > in testcase: boot
> > 
> > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> > 
> > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > 
> > 
> > If you fix the issue, kindly add following tag
> > Reported-by: kernel test robot <oliver.sang@intel.com>
> > 
> > 
> > [   50.637839][  T154] =============================================================================
> > [   50.639937][  T154] BUG kmalloc-16 (Not tainted): kmalloc Redzone overwritten
> > [   50.641291][  T154] -----------------------------------------------------------------------------
> > [   50.641291][  T154]
> > [   50.643617][  T154] 0xffff88810018464c-0xffff88810018464f @offset=1612. First byte 0x7 instead of 0xcc
> > [   50.645311][  T154] Allocated in __sdt_alloc+0x258/0x457 age=14287 cpu=0 pid=1
> > [   50.646584][  T154]  ___slab_alloc+0x52b/0x5b6
> > [   50.647411][  T154]  __slab_alloc+0x1a/0x22
> > [   50.648374][  T154]  __kmalloc_node+0x10c/0x1e1
> > [   50.649237][  T154]  __sdt_alloc+0x258/0x457
> > [   50.650060][  T154]  build_sched_domains+0xae/0x10e8
> > [   50.650981][  T154]  sched_init_smp+0x30/0xa5
> > [   50.651805][  T154]  kernel_init_freeable+0x1c6/0x23b
> > [   50.652767][  T154]  kernel_init+0x14/0x127
> > [   50.653594][  T154]  ret_from_fork+0x1f/0x30
> > [   50.654414][  T154] Slab 0xffffea0004006100 objects=28 used=28 fp=0x0000000000000000 flags=0x1fffc0000000201(locked|slab|node=0|zone=1|lastcpupid=0x3fff)
> > [   50.656866][  T154] Object 0xffff888100184640 @offset=1600 fp=0xffff888100184520
> > [   50.656866][  T154]
> > [   50.658410][  T154] Redzone  ffff888100184630: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
> > [   50.660047][  T154] Object   ffff888100184640: 00 32 80 00 81 88 ff ff 01 00 00 00 07 00 80 8a  .2..............
> > [   50.661837][  T154] Redzone  ffff888100184650: cc cc cc cc cc cc cc cc                          ........
> > [   50.663454][  T154] Padding  ffff8881001846b4: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a              ZZZZZZZZZZZZ
> > [   50.665225][  T154] CPU: 0 PID: 154 Comm: systemd-udevd Not tainted 5.19.0-rc5-00010-g361679912861 #1
> > [   50.666861][  T154] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
> > [   50.668694][  T154] Call Trace:
> > [   50.669331][  T154]  <TASK>
> > [   50.669832][  T154]  dump_stack_lvl+0x57/0x7d
> > [   50.670601][  T154]  check_bytes_and_report+0xca/0xfe
> > [   50.671436][  T154]  check_object+0xdc/0x24d
> > [   50.672163][  T154]  free_debug_processing+0x98/0x210
> > [   50.673904][  T154]  __slab_free+0x46/0x198
> > [   50.675746][  T154]  qlist_free_all+0xae/0xde
> > [   50.676552][  T154]  kasan_quarantine_reduce+0x10d/0x145
> > [   50.677507][  T154]  __kasan_slab_alloc+0x1c/0x5a
> > [   50.678327][  T154]  slab_post_alloc_hook+0x5a/0xa2
> > [   50.680069][  T154]  kmem_cache_alloc+0x102/0x135
> > [   50.680938][  T154]  getname_flags+0x4b/0x314
> > [   50.681781][  T154]  do_sys_openat2+0x7a/0x15c
> > [   50.706848][  T154] Disabling lock debugging due to kernel taint
> > [   50.707913][  T154] FIX kmalloc-16: Restoring kmalloc Redzone 0xffff88810018464c-0xffff88810018464f=0xcc
> 
> Thanks for the report!
> 
> From the log it happened when kasan is enabled, and my first guess is
> the data processing from kmalloc redzone handling had some conflict
> with kasan's in allocation path (though I tested some kernel config
> with KASAN enabled)
> 
> Will study more about kasan and reproduce/debug this. thanks

Cc kansan  mail list.

This is really related with KASAN debug, that in free path, some
kmalloc redzone ([orig_size+1, object_size]) area is written by
kasan to save free meta info.

The callstack is:

  kfree
    slab_free
      slab_free_freelist_hook
          slab_free_hook
            __kasan_slab_free
              ____kasan_slab_free
                kasan_set_free_info
                  kasan_set_track    

And this issue only happens with "kmalloc-16" slab. Kasan has 2
tracks: alloc_track and free_track, for x86_64 test platform, most
of the slabs will reserve space for alloc_track, and reuse the
'object' area for free_track.  The kasan free_track is 16 bytes
large, that it will occupy the whole 'kmalloc-16's object area,
so when kmalloc-redzone is enabled by this patch, the 'overwritten'
error is triggered.

But it won't hurt other kmalloc slabs, as kasan's free meta won't
conflict with kmalloc-redzone which stay in the latter part of
kmalloc area.

So the solution I can think of is:
* skip the kmalloc-redzone for kmalloc-16 only, or
* skip kmalloc-redzone if kasan is enabled, or
* let kasan reserve the free meta (16 bytes) outside of object
  just like for alloc meta

I don't have way to test kasan's SW/HW tag configuration, which
is only enabled on arm64 now. And I don't know if there will
also be some conflict.

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yudw5ge/lJ26Hksk%40feng-skl.
