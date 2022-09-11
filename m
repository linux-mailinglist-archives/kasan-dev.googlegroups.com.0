Return-Path: <kasan-dev+bncBDN7L7O25EIBB3NJ66MAMGQEIM4BABA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A6EAA5B4EC9
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 14:30:38 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id b16-20020a056512305000b0048aec76a1ccsf1844419lfb.18
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 05:30:38 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=am5hnODdgFAQ/QJ0we0Cvgr0SVM97tQtl9gkrhJ74CE=;
        b=r9D6IEYHR7R1J0RwmWcXdtM9aJF5Z1h+XBevex27LuogNyp0DFcI8NjpBjrUkKiPun
         LiSSHAYEOqUgvJxW+9+6iiIS2DkvFZfTC1nTji7YrEmfREgct/sM8AwY87bKvLClgy/o
         Fqn1XSNiJmy7AAUNCdZTP5XbJWWEUcoZheo7qxrjRPyem1Y7KDes9yUcMXOOJKh6qP6I
         JyqM7GGhGN0QL2afVCFtXqC0tDY5+U2aPK7r0OrB7kBL+pizrIwl+FDyO+FTOU2YxiYa
         OfxsWg6O+Cf9YshjgYYsT07W6dUNawuWcYs7HC0d3Y6DG6FynB5rRWiW+P+jLiDZ+JI4
         xpQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=am5hnODdgFAQ/QJ0we0Cvgr0SVM97tQtl9gkrhJ74CE=;
        b=kYd/gpSnpGWP4YfgCngQtcRL/I6PZw0mImN1b7eRnX9cwiI5GBQVyiuMnu+RLdfW+P
         R+3RNP6HDG+guYzJz69ejMlsM7sXa2kEfJISdcYGLSnOz6hHE7QEC0tOzZxGKZ0gk0Sl
         XamY2BnQlabqbOZcAOYTINEiRcch9+TktzAHIcsFQw/oox2YC6wRq5dos0J0GFkwc/Hn
         KKDc5ZLUuOTAuuM/EZIutueYYYVXMb0L9QgPkk6VYZTwVNVKr8vxKpD/Uta/tGP2LkCH
         DupOa9PFP8FYgieo9DXdt894n36jA2SWSbdhB0u7zdFsr7eXFtD6pYCHWnyqBFR8OKkj
         wmAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1QnM+fiapv7AwTuXvXUSySAYv52BQBnXgyNYaDI/Zwv+FZjcBz
	Kv6BWiHYAX3N+jMFQJgzCJg=
X-Google-Smtp-Source: AA6agR7SXBJLXoo/EmkVLWsIRbqfFZrgfER3UK40pYkFHiQi4OoowxFDXO/C+QxGCdKDGJgEUV6Kxw==
X-Received: by 2002:a05:6512:110f:b0:494:a534:981d with SMTP id l15-20020a056512110f00b00494a534981dmr7878178lfg.376.1662899437788;
        Sun, 11 Sep 2022 05:30:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:808f:0:b0:26b:db66:8dd4 with SMTP id i15-20020a2e808f000000b0026bdb668dd4ls203198ljg.8.-pod-prod-gmail;
 Sun, 11 Sep 2022 05:30:36 -0700 (PDT)
X-Received: by 2002:a2e:8541:0:b0:261:b44b:1a8b with SMTP id u1-20020a2e8541000000b00261b44b1a8bmr6961462ljj.46.1662899436403;
        Sun, 11 Sep 2022 05:30:36 -0700 (PDT)
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id i4-20020a2ea364000000b0026bf7cf2a41si92237ljn.2.2022.09.11.05.30.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Sep 2022 05:30:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6500,9779,10467"; a="296455246"
X-IronPort-AV: E=Sophos;i="5.93,307,1654585200"; 
   d="scan'208";a="296455246"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Sep 2022 05:30:32 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,307,1654585200"; 
   d="scan'208";a="791288237"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orsmga005.jf.intel.com with ESMTP; 11 Sep 2022 05:30:32 -0700
Received: from orsmsx608.amr.corp.intel.com (10.22.229.21) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sun, 11 Sep 2022 05:30:32 -0700
Received: from orsmsx607.amr.corp.intel.com (10.22.229.20) by
 ORSMSX608.amr.corp.intel.com (10.22.229.21) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sun, 11 Sep 2022 05:30:31 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx607.amr.corp.intel.com (10.22.229.20) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Sun, 11 Sep 2022 05:30:31 -0700
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (104.47.74.49) by
 edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Sun, 11 Sep 2022 05:30:30 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=FGaVd/cmL9fRmZvnQg2svvAsXxk0XUuZya1NfiaTtZfF/TSAjqF/my9iRk7jU29wXwD/oH3RTUYQ3nZ4tFMTwmbdMtML10897OE+YIYB42UU3uXV0hVceq3PU3RABnPwUMo+EPQxysypnwOW2DNFjVovHwoXESKmI6Wqah03PfHQQ2P58gzZ2lpcbOIQDXDgeffngHQHcXsge3eyX1YufTTig7bkhdoHVPw6AAjjWfYXDCsBIqykbrvu7gdrxlQHMaFNdVL7r1RKuV7ApEQoIOP8Vz4blDU2eTYz7fxs7EQMGK4J8DP7uxzPMbdW6bzNnaRF7M+A/KZRiFq+fBhe1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=w3MwnYxpmnLHPPoO647pGaN5JtSx2qQThGcP0skhtU0=;
 b=GwaYADbgkkIY/HtbDbRoABRPhkrTIFUKDcz4SLd153N+Kkpk5Z6otC2Kz888mV678LJJa3Ggk+xHCC05jBVou1/a9Id9D/2bgUdrngdU3K5oHOnU57HOVqDtinf9QdcTz87XVYHnu6kYBBCkthdvndkV8uhf/r+E53Jrtml5De+Qf8fGSQQd3MPiA2E2W4WsNPSCIziDNw7BK3n3LOw22yF/MBPqA4+onnbB/96jXFGffSppf4DSzHmU5+vIj9/o3pgk1KkzX2ko5LlcUPpMofBR+BtgyVGgtqmAx2g2e+p4YbYyufgqIFHiWoQMnVsMtpsy6C9L85yqejF2eUB5bg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by SA0PR11MB4541.namprd11.prod.outlook.com (2603:10b6:806:94::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5612.14; Sun, 11 Sep
 2022 12:30:29 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e%7]) with mapi id 15.20.5588.015; Sun, 11 Sep 2022
 12:30:29 +0000
Date: Sun, 11 Sep 2022 20:29:56 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	"Sang, Oliver" <oliver.sang@intel.com>
Subject: Re: [PATCH v5 3/4] mm: kasan: Add free_meta size info in struct
 kasan_cache
Message-ID: <Yx3UxJWEXzyWhuqy@feng-clx>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-4-feng.tang@intel.com>
 <CA+fCnZeT_mYndXDYoi0LHCcDkOK4V1TR_omE6CKdbMf6iDwP+w@mail.gmail.com>
 <Yx1caGQ8R2alhOKh@feng-clx>
 <CA+fCnZd1bDe9oQcCZjN+NTxs8qF3fzRoXcSZvyeCNxoX6U-wsg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZd1bDe9oQcCZjN+NTxs8qF3fzRoXcSZvyeCNxoX6U-wsg@mail.gmail.com>
X-ClientProxiedBy: SG2PR02CA0027.apcprd02.prod.outlook.com
 (2603:1096:3:18::15) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 0055d72c-a916-4980-a7d3-08da93f16939
X-MS-TrafficTypeDiagnostic: SA0PR11MB4541:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: qpdgIUp+P5MHgYIFrKJ1+SSpbJPtIqECUuj01WTCUDH79VjFENkXAWTM+Yyg0fd4z4cINrJBlMslKprhxX5X8N8Z4nEAPGUStkHcV+bRgHRUFhr9gWVsK4s7Q0bSL2No6Gz8Sw1IMIwAiu52cICHwg0itzwNkSS7q2qQvNi8QahbYhe66U3dDionX4qClKa/IbJJqZnQ9IAPL/U+PzFaUcNoayM7JziEWkpDHynYDZPuAD3uzZFz8BkmyPJc7FgHcXTz9W4zxbRH1sMklxXeslQNup/jokZRBtfgrCz1b1IoxbAlhBxB7HTx7o4y7Z81GeyDvhbbi/OggudtCq6zLr3A5bdB3xj7mWhmIpVLY97Dk9F62o34Vg1ZXUUCeMY8olov26BwIVQYkWx+aaD7KyIOS+8QLqx7fvCyuOxESlYUXUh1tI0/WmWbnp8y2NDOI2bVK5z9E7Q+8HBKfAuLom5j97/DQ0/4AjZC7DU2nFyhA0AJZmpAFVbt41fyWsstuBDnJpkSAggLMFfbj0ZkEZdRH3/tYehCvOy3pBgT+esbqW0fNti1jUynL7hvdguw1LE98MXvlcbNd6RN2hJjR0kD4FItaTuzuEi9BYyihnTpkjpkoDQl6Lb49IILIe5/StTpUaPaEfNY/Ua/yp2loNvSfh2EIoLPkKtbjcV2lkZmCAXwM1YVxkQn8B7mzBtm03fId+q7+/Z1ai+nNq7jV2J/dcetqEr1GT0oXljOcJY=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(346002)(136003)(366004)(396003)(39860400002)(376002)(186003)(2906002)(5660300002)(8936002)(7416002)(4326008)(66946007)(44832011)(66476007)(66556008)(8676002)(6506007)(53546011)(6512007)(9686003)(33716001)(86362001)(41300700001)(26005)(6486002)(6666004)(107886003)(478600001)(966005)(82960400001)(54906003)(6916009)(38100700002)(316002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?8MH3s0Wd9/Q2sOKdw4D5cO1lUOcMRHHEpvS7w9E2/f9vl+Rs5VqlfEqHhnX4?=
 =?us-ascii?Q?CGisvIgst0j8RQ+GUzRtS7oGiqAOWTpyPeJ8axNozxVO6Grr1PhmkIfx5qrz?=
 =?us-ascii?Q?Xm6OZIwclqVlYymBWIK2z0B9BU4u9n1ggiLj1T0ZRUNID9nSc3BhTAn0Iv3q?=
 =?us-ascii?Q?TXwv9UPEIaeVH9XvXy2K8jyTKbeN25nbhutnz1Hp3JA09TlV5Bjr0G9tfNPG?=
 =?us-ascii?Q?b2Koz/JTCFqSHf8I1QQVgkWWRGcUigRsACN1ssWZniGeal7F6vCow9ZrjKR6?=
 =?us-ascii?Q?bcaQC0FEua7F/tG/5M5rl5NGcK+H/Rvqg+gfkOsD5Uwmve4R+fcfIabZ8iei?=
 =?us-ascii?Q?8pniXX4kc6TL6IymY6qAcQs+O/U1vs8/bes6eHBLL7vQfwS5YfarWS/PKywo?=
 =?us-ascii?Q?PP4mn2GXLXQQk3n14frl5uGTT3PmBseoqhpp1XMovsGwE1f96IWQHwA1amJI?=
 =?us-ascii?Q?916mdVsc73LAbfvEiMiVGf1CvieD5i4ouKyNwQdYaIt1x4BVLvmietNxfSwq?=
 =?us-ascii?Q?J4RFg5/yWVgyZNsPzjts3wQ7feaCGKh8KAtrvJn0qLcFCTu6tF+uHJL5cSg8?=
 =?us-ascii?Q?dTMrlU3MSg9h+D/GUeeKv/EbdKeNUgP3bokJDBWDVaZKzwZ8pLnFyypIVorU?=
 =?us-ascii?Q?YCO7IazmZ0sz8WL8aWRNgkzVc+7X7fd5tyuQM9vwjwOoJNNRn2RVoVRxAS6l?=
 =?us-ascii?Q?QNgsh9Mh9eZ98OVqKmgmg0JazAL9PUmaGQYs/HsvNMIcLll5T8Oif+H2SpMV?=
 =?us-ascii?Q?tT28hTRPHsLE3vMMl5wuJZzQkp1l62tePA1RQx4RTFuLlOUh3iidR/4sd645?=
 =?us-ascii?Q?lBCvpq2PmRn7QdBSifKL3jjHFW/pHaj9hF4MokBVeBB3AUdjp4ltenX3iK0j?=
 =?us-ascii?Q?QVynPc5Sf2L7SLP5jyRZ8SX63l9wBsltMj9s4seU39G1OpP+tz7uu5Khu+Kl?=
 =?us-ascii?Q?Eld06l1Ov0YX+PMIPKGKdXClKK1B330ensnr6iua8jEsNtr6KP3nqKya1xm+?=
 =?us-ascii?Q?IBWn6K4LQAfqDhLce/DX9qmKgWQ398SpkAtysmSeXiQNibcwuZDdAIs4QBxd?=
 =?us-ascii?Q?I/VRc9N5HbZ+58Y0re3ToLBky4ENrTFvMA2dAdZaOJtTS+W6XUHk4d1OT1BU?=
 =?us-ascii?Q?0oKhqUjU4K8AT2Ef1qIdaZlYMGuYf+8OrHfGKhABKmSPmajECMy9PcCkbmDK?=
 =?us-ascii?Q?KE4suI5pkJ1OUywxaSTG48nAx48qRtDyWyHZ10uDMGlDRyjjRXJxOyyL8xdy?=
 =?us-ascii?Q?aqAmVf0Uh37dWFzhDlYbrR1k29SEPkgI7OKQ8CbaOhVkXrje1b6R1rHCvdFY?=
 =?us-ascii?Q?vAf8WHFKkiKAJj6xEPimcWOLMnOPxO7Pa6sY0ucJiy4Bo0/ZJI1Hwu8PrX9y?=
 =?us-ascii?Q?q7l/FUMvFG/Owx0hpO2a5p+If47em56iuBOZQZ8sJzZ2h7izvasVF31M/Foe?=
 =?us-ascii?Q?WXDM+InlUeH3oxjTLi8P2ywow8LyqWdEu13nix9aQpPr9muLI5i5IZX0xqc8?=
 =?us-ascii?Q?+8GO0dWkmRl2oQj+4qkvSJMtwzBQhj4X4l80jlnmhIkgAD6T6xlnqTgjAZrF?=
 =?us-ascii?Q?Xju+p5CtdxK6cRPf5idpfRWWErwagcJz7pc58DLp?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 0055d72c-a916-4980-a7d3-08da93f16939
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Sep 2022 12:30:28.9540
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: eHOOHYDsRvtBzlP2noPKtELeTybb0iBVPA5v6QD8tdOzAz7XTNH4wYIr2vypDzO8KlW6dr8nVi7f8AJCE70v9A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR11MB4541
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=N31WG5gy;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.120 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Sun, Sep 11, 2022 at 07:51:54PM +0800, Andrey Konovalov wrote:
> On Sun, Sep 11, 2022 at 5:57 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> > Hi Andrey,
> >
> > Thanks for reviewing this series!
> >
> > On Sun, Sep 11, 2022 at 07:14:55AM +0800, Andrey Konovalov wrote:
> > > On Wed, Sep 7, 2022 at 9:11 AM Feng Tang <feng.tang@intel.com> wrote:
> > > >
> > > > When kasan is enabled for slab/slub, it may save kasan' free_meta
> > > > data in the former part of slab object data area in slab object
> > > > free path, which works fine.
> > > >
> > > > There is ongoing effort to extend slub's debug function which will
> > > > redzone the latter part of kmalloc object area, and when both of
> > > > the debug are enabled, there is possible conflict, especially when
> > > > the kmalloc object has small size, as caught by 0Day bot [1]
> > > >
> > > > For better information for slab/slub, add free_meta's data size
> > > > into 'struct kasan_cache', so that its users can take right action
> > > > to avoid data conflict.
> > > >
> > > > [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> > > > Reported-by: kernel test robot <oliver.sang@intel.com>
> > > > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > > > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> > > > ---
> > > >  include/linux/kasan.h | 2 ++
> > > >  mm/kasan/common.c     | 2 ++
> > > >  2 files changed, 4 insertions(+)
> > > >
> > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > index b092277bf48d..293bdaa0ba09 100644
> > > > --- a/include/linux/kasan.h
> > > > +++ b/include/linux/kasan.h
> > > > @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
> > > >  struct kasan_cache {
> > > >         int alloc_meta_offset;
> > > >         int free_meta_offset;
> > > > +       /* size of free_meta data saved in object's data area */
> > > > +       int free_meta_size_in_object;
> > >
> > > I thinks calling this field free_meta_size is clear enough. Thanks!
> >
> > Yes, the name does look long. The "in_object" was added to make it
> > also a flag for whether the free meta is saved inside object's data
> > area.
> >
> > For 'free_meta_size', the code logic in slub should be:
> >
> >   if (info->free_meta_offset == 0 &&
> >         info->free_meta_size >= ...)
> 
> I'd say you can keep the current logic and just rename the field to
> make it shorter. But up to you, I'm fine with either approach. Thanks!

OK, I don't have strong opinion either. As the comment for that
member clearly stats it's for inside-data size info, we could use
the shorter name.

Thanks,
Feng



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yx3UxJWEXzyWhuqy%40feng-clx.
