Return-Path: <kasan-dev+bncBDN7L7O25EIBBIVNUOLQMGQEXWTEB6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id A754A58782B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 09:47:47 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id h18-20020a2e9012000000b0025e4f48d24dsf1097425ljg.10
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 00:47:47 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CK0J70k7AZe8g5VlT/FU3QDvnoZpapuoAc7IPbPKwC0=;
        b=IuS2FMSrNxMxzEE7J7CUQdpFAZmvSLZ2BqRKpYmomg344cnpJnCgCSnxqCuNfvyjCH
         tHiYi0Gea6SEvo8ZLBdw6vv7dc6xI4h1MkVTOWFcVm3r/X07lZEhXafCpREEmWV1mSnH
         OwU4cCfeh+R0Kh4yDaMvhc/1GTM1WhoJwU0sL/G8FMKmBfxqPOvPAXKbiavYpA9CYxCc
         J/4sRB0AekSfAJtCWVBKemzMYrHMm9dKuxPI9zmEqFQ1pLBlt+ZYUZ7rV+ZT/TWdds49
         u17PW4FeRFoagy4O7E+VtPwl7VQaaQvFnUArXemiFS9bF7YKAAhJKtXrkxr0skQxz5Nq
         MM6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CK0J70k7AZe8g5VlT/FU3QDvnoZpapuoAc7IPbPKwC0=;
        b=ZXOEY3wuVW0XON+oZISVQDbvhOvOiH3HAJGjayfTNtbARWioBJFV7B9N0o0BcC5x0u
         zjHi0RQzjmBXB7/mfE1nu5QhnYWc5A7FnbWuk2tjaGXOxiuLNW3yohzd8FSAVBxsQJJZ
         TdQoCt6MSiUvPFrXHkFyU3RIlEHEn4AarUgkwNh0psE2lG90XsLRbqOHuTvwVNCI2Dh/
         jWqdRokNV57w5FtBSjQCuV4fvaROu3wugbLhpQI5breVen01GWGK7DhVJiJCbfBE39C1
         nqCbmApPbA8KpAUvXlFCwmRPr/7L226iR0kH9cjv0wOQAfXsKKgP+R09NvIRn9JYR7IJ
         9S9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0O/mgmLdaQqYQqn9Xb8EWXvJwp2HZ8isnjcaPeynxjO3JLgvXs
	2titcmN8EliBQ+lzlczEYeU=
X-Google-Smtp-Source: AA6agR4/A56IC2yw1fq47Nnj9tjC+kDK1e2VX7OJtgywANfzKnGgQW6szSHt5rJU8q8WzRujvkE1ow==
X-Received: by 2002:ac2:43b0:0:b0:48b:1eb:d1e5 with SMTP id t16-20020ac243b0000000b0048b01ebd1e5mr2223544lfl.641.1659426467022;
        Tue, 02 Aug 2022 00:47:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1146:b0:48b:253:97e6 with SMTP id
 m6-20020a056512114600b0048b025397e6ls97076lfg.1.-pod-prod-gmail; Tue, 02 Aug
 2022 00:47:45 -0700 (PDT)
X-Received: by 2002:a05:6512:3b81:b0:48a:9787:7837 with SMTP id g1-20020a0565123b8100b0048a97877837mr7345134lfv.678.1659426465619;
        Tue, 02 Aug 2022 00:47:45 -0700 (PDT)
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id n7-20020a05651203e700b0048af33205bfsi259723lfq.6.2022.08.02.00.47.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Aug 2022 00:47:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6400,9594,10426"; a="289361282"
X-IronPort-AV: E=Sophos;i="5.93,210,1654585200"; 
   d="scan'208";a="289361282"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Aug 2022 00:47:26 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,210,1654585200"; 
   d="scan'208";a="848116989"
Received: from fmsmsx605.amr.corp.intel.com ([10.18.126.85])
  by fmsmga006.fm.intel.com with ESMTP; 02 Aug 2022 00:47:26 -0700
Received: from fmsmsx603.amr.corp.intel.com (10.18.126.83) by
 fmsmsx605.amr.corp.intel.com (10.18.126.85) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Tue, 2 Aug 2022 00:47:25 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28 via Frontend Transport; Tue, 2 Aug 2022 00:47:25 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.107)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.28; Tue, 2 Aug 2022 00:47:25 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Zm7cFH961Tkrau4qiERJlfF/tpEyX9Ac1Cv/Fv526x7wG1/0hFcNSp1Ib5bxS5/FjV3FyF/VS8p0BxHByO6Gu+WHUjRZn3RSUtv4Hr/QEMj19WX26q714WPcICG9Gbigkha0Lg3mAB2cZUTVpfvUi8a8n3hWfVIXgjAGI8nRAZ1k4lnkkR7LhVjSik/LP2P7OZ8U+Uz1gZXokoCVr9t6q00hSmZMaAMNUL54d/KPoek2n4STD3Pjncy2DgN5EY6c8m0g8Hn3Ou8PtG5AGV0NAUIlTLFpGQ7Te3N2ly8XAF9ap7mB3EQACHpGmI/Hp6EbGhz2DmFegh+gPDBKhS116g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=eBD/o3027Lo+CP2PouTNzBkDdwLpUtTuIYUhxjkcun8=;
 b=S5Te8d6+rVP3fJTALs6DCgGI8tHzwMvtMTq/AUBdsn5aa2H7vbl8mEBHDhAjtKwhw6KoErtFeDMbXOGsMKHp0xr9M//AExAkPpDgWVkCrdjYmBzRwvAjodTuHcC/Vp9vSFWajXE/v6XOiRcjuKQLQBtXLg2NUmDk2MekAq6mWkLByxpdcLLxIENCKMpoKRuLNbQzquiHMR2vWpUdgBBgShedroDLy56u628P1/xxQL6N+DuSkrV8MXbW30f2nMkBjxVSCQiYWqoUUG0MhCu80OETqajxFatD/pEKJhDCKjvMJ6DGUP8GqKpnIj9LjDrqXyI2ixtuLvdx2lo23zMwMQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by BY5PR11MB4120.namprd11.prod.outlook.com (2603:10b6:a03:18f::28) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5504.14; Tue, 2 Aug
 2022 07:47:18 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55%6]) with mapi id 15.20.5458.024; Tue, 2 Aug 2022
 07:47:17 +0000
Date: Tue, 2 Aug 2022 15:46:47 +0800
From: Feng Tang <feng.tang@intel.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Vlastimil Babka <vbabka@suse.cz>, "Sang, Oliver" <oliver.sang@intel.com>,
	lkp <lkp@intel.com>, LKML <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "lkp@lists.01.org"
	<lkp@lists.01.org>, Andrew Morton <akpm@linux-foundation.org>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen,
 Dave" <dave.hansen@intel.com>, Robin Murphy <robin.murphy@arm.com>, "John
 Garry" <john.garry@huawei.com>, Kefeng Wang <wangkefeng.wang@huawei.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Message-ID: <YujWZzctbp1Bq25N@feng-skl>
References: <20220727071042.8796-4-feng.tang@intel.com>
 <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl>
 <Yudw5ge/lJ26Hksk@feng-skl>
 <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl>
 <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
X-ClientProxiedBy: SG2PR02CA0017.apcprd02.prod.outlook.com
 (2603:1096:3:17::29) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: fd9a9811-45f8-4b3d-231f-08da745b38db
X-MS-TrafficTypeDiagnostic: BY5PR11MB4120:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: +2ZKHvZ2wg9h4IyovXhZFWNtz3TZXbpSleX/4CgvEx4BTL+ob9kjNb578v+QH2B7oAx1pXEbt/eMtV0DGdRUlyf2K4bWSN69svPtnj8PE2B80tqBegssz1hKlofYWWguMwVIAyVeizfV2L5au36/GLrFG9VAEL09Do2qfM6zQfIpNx+tcaKPdsQGHflMYpUMKAOyyf1uX51jqV+J+sCEw8ItR79UE/L98aUJvoFwqzNyw6QRyFrhqG/Zt/Z+CDx12o3ooSwZPgMp/22ZTElMcV00TugpzUmKo4SDD/BT/4ReLg82MFAA2tRI1HHcDWaA9xs2l8tLUbKwoZ+CcmdzicRJcdtQLPQbeKE40yR7gBBJrcXGru1jxZSEyVydlsWSwtswX5MFcvwJqk0l+A+wLvqSgCyF8qD1e2ttCiVmylHxFZdbspa33H5aLEF5vOKEJuL5mMOsX+cLdpzc2AIyD+s0ni3xfL6qrkQHyhpMgcjVpKm+pcHGHom44l/Cc2izpSpqfMMewwdrPLIhXA8YEBr7en2n5GnlrXBrriUmSssH6hKXb35G5bl1CGf+Y+ZTM9ELyiyDWGRPcr2tIMSfjg6Pf0S/mnMTmMAwr4zPhzQjbEcbKTmIxTWxXd6EZXyaQ9MUpuq1hrvpi/6Mq1ewTKEjWqXxHX2H7fLt58ajIK5lUZLLEPy4+WPLzwOzNWDwSX62ap/Pa6VzdmVDRZR+F6oOCa8U78b3qMXjoS3xZ4kaW+ok2FkzbnI4KYqbTWTJkxtGu+fwimjpdY4uPai25A==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(39860400002)(366004)(396003)(346002)(376002)(136003)(83380400001)(86362001)(82960400001)(38100700002)(4326008)(66476007)(8676002)(66556008)(66946007)(316002)(54906003)(6916009)(33716001)(2906002)(8936002)(5660300002)(7416002)(6512007)(26005)(9686003)(41300700001)(53546011)(6506007)(6666004)(186003)(44832011)(478600001)(966005)(6486002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?6star+EqjT9b0enhGP2zLaRdcJ65xgmHma39fxnwtmGIaaHO7Ljxx6QyOpiO?=
 =?us-ascii?Q?1jkBL9FhSz0c8AsZ+72LTmFWnJNlUplD24u5BqF7TnMGiM46kUHHSxXCyphR?=
 =?us-ascii?Q?EA9nLx40N/8D7rZymo+NxMIqcEQW/KjPJMccAd9Mut/XyO8VJoBI3w8PSDE6?=
 =?us-ascii?Q?CuKo+juK6Go6aldSPCnKIRDFpWeH0wGNGRZdKXd88nWSbS/qs0TTjWk4Jt6l?=
 =?us-ascii?Q?lPeVzA9C8+gKAHGBi0rfxBy7DvyVoS/hOD5CpMXeE8cQ/P7790xaZJBK8Y5h?=
 =?us-ascii?Q?6l1eKM/qb3s8V8/viiykm1hmzdDK6mgFYmbb4+Lg55ocMMVXSiF/Ch5RpbQL?=
 =?us-ascii?Q?h1Kdvn6q7AUjVpkoJP30b5thZ/C2R8KfZSaZS7bSQVz94kuWVZwcXPnoBOja?=
 =?us-ascii?Q?4mPdg6RDwT77PzkPuDtAp6QEcYOkHI/hZqHjLA934nk68CypKyvsQhQamx5A?=
 =?us-ascii?Q?vx0EPEDkONkVSll2P5VGyclnFGLjCjADcujn5JhO7UutuHnpRZej88Zo/ri9?=
 =?us-ascii?Q?mSX8rfclcOn5IIhh4R3SEp56WaXMeuqFJyuGy34tUaQAh4YPl75b69WLyv27?=
 =?us-ascii?Q?2ZmBc4NdKlWhLvhhMZLP/iMJC3uAcXJgQRcfjuero9Vq/fx7+CmQ1Mfa0AGj?=
 =?us-ascii?Q?bCqc14YlrtrOG7Y7PNDguj09Or3mJ9UYby7IMBWwTI4Ky7ZBUssrC6hJBftj?=
 =?us-ascii?Q?pCCiVFNNh356bdKY1cKzS+kHClLrtzb96XSDi0MdHdISP9CppMnDxQwHPLfX?=
 =?us-ascii?Q?AorNCO3ZsESsBSa9RPJcz3zZroeVFot7vNxnSANPbSyW7m/HKv7Ngh4vGbnC?=
 =?us-ascii?Q?FaGg9vDsx0+N+fMaPjpdqLe7TuwArXgpNPi1sgZ+qnMwfWfUbE182Wrw+lmB?=
 =?us-ascii?Q?rPv3d9+VPbq39IAQFPDTMJEYXiF+wn/TlOorjslAqcDHbmn/xvCcOsWAqXZs?=
 =?us-ascii?Q?vwJyef7A98jtmDky/rZH+WZrKgRWUsNZZJTKrqQi5rrtc1Omz3pSfe+PkRZ3?=
 =?us-ascii?Q?GNg3sxFQ8ZTCLr1y6JEw96+r4ehgS3amHgu7b9KJI5piWC7/itW29wf2SVQ2?=
 =?us-ascii?Q?OVOID4zQEoJHuVHb6RlOMns7GuV2C1Jd2qh4vPcFlULM41ezJCDNGk9kExBo?=
 =?us-ascii?Q?xRK7Il+HtTB+CoD4ZwraKSoLmfsfYHEk6Z89GgFBsjrfMsGXDCxuJsHRqhYn?=
 =?us-ascii?Q?E4FznKFHPLvPDwkopF9P4YqfVqtD/d2K7o4qg58sOEizBrDMqEs05YvqNI0o?=
 =?us-ascii?Q?+rmvAS7YembwN4FHxW+2gGVe04cinw9AlpSNqBat+MkSwW12jx9teMfLcoR2?=
 =?us-ascii?Q?j49zsmPDxdhJmQSuLocUEBHoYg6D7eVjf6rEJA+O+KgTY/niSd2npuZHG1ES?=
 =?us-ascii?Q?RcrBpTrqM7CuZkKjEJ6HQw9Q83iDJb5FxYMnnDhmPp+AktKn2e2mt+QuknjQ?=
 =?us-ascii?Q?o7RcZvzpMOajJX9q9pXzV0i7hpmcK96hyOgYG4R8U81U6Kry10xt6uHGxC2v?=
 =?us-ascii?Q?yYOAu4HEHQYoGJBV6DqbILIpcfa/kw9Ws3ircsW7aip+/nqh//kV4jdi+Xwk?=
 =?us-ascii?Q?ZMk3D9ucBa87B54Fd/qQuPB6EV1bduPyuyKJonxf?=
X-MS-Exchange-CrossTenant-Network-Message-Id: fd9a9811-45f8-4b3d-231f-08da745b38db
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Aug 2022 07:47:17.2327
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: KQF5fPTwPCjKtYoc1Bde98AMk8oJDRGoP7X4MsJptLomHGzBS+HCxhPwG+tr9ll9xIbf8XqzEOwDgfUlFqjUHA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY5PR11MB4120
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=U5vQYFZ6;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.115 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Tue, Aug 02, 2022 at 03:06:41PM +0800, Dmitry Vyukov wrote:
> On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
> >
> > On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> > > On 8/1/22 08:21, Feng Tang wrote:
> > [snip]
> > > > Cc kansan  mail list.
> > > >
> > > > This is really related with KASAN debug, that in free path, some
> > > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > > > kasan to save free meta info.
> > > >
> > > > The callstack is:
> > > >
> > > >   kfree
> > > >     slab_free
> > > >       slab_free_freelist_hook
> > > >           slab_free_hook
> > > >             __kasan_slab_free
> > > >               ____kasan_slab_free
> > > >                 kasan_set_free_info
> > > >                   kasan_set_track
> > > >
> > > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > > > tracks: alloc_track and free_track, for x86_64 test platform, most
> > > > of the slabs will reserve space for alloc_track, and reuse the
> > > > 'object' area for free_track.  The kasan free_track is 16 bytes
> > > > large, that it will occupy the whole 'kmalloc-16's object area,
> > > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > > > error is triggered.
> > > >
> > > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > > > conflict with kmalloc-redzone which stay in the latter part of
> > > > kmalloc area.
> > > >
> > > > So the solution I can think of is:
> > > > * skip the kmalloc-redzone for kmalloc-16 only, or
> > > > * skip kmalloc-redzone if kasan is enabled, or
> > > > * let kasan reserve the free meta (16 bytes) outside of object
> > > >   just like for alloc meta
> > >
> > > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> > > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> > > __ksize() does.
> >
> > How about the following patch:
> >
> > ---
> > diff --git a/mm/slub.c b/mm/slub.c
> > index added2653bb0..33bbac2afaef 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
> >         if (!slub_debug_orig_size(s))
> >                 return;
> >
> > +#ifdef CONFIG_KASAN
> > +       /*
> > +        * When kasan is enabled, it could save its free meta data in the
> > +        * start part of object area, so skip the kmalloc redzone check
> > +        * for small kmalloc slabs to avoid the data conflict.
> > +        */
> > +       if (s->object_size <= 32)
> > +               orig_size = s->object_size;
> > +#endif
> > +
> >         p += get_info_end(s);
> >         p += sizeof(struct track) * 2;
> >
> > I extend the size to 32 for potential's kasan meta data size increase.
> > This is tested locally, if people are OK with it, I can ask for 0Day's
> > help to verify this.
> 
> Where is set_orig_size() function defined? Don't see it upstream nor
> in linux-next.
> This looks fine but my only concern is that this should not increase
> memory consumption when slub debug tracking is not enabled, which
> should be the main operation mode when KASAN is enabled. But I can't
> figure this out w/o context.

Yes, the patchset was only posted on LKML, and not in any tree now.
The link to the original patches is:

https://lore.kernel.org/lkml/20220727071042.8796-1-feng.tang@intel.com/t/

Thanks,
Feng


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YujWZzctbp1Bq25N%40feng-skl.
