Return-Path: <kasan-dev+bncBDR6TU6L2YORBAEMRGJQMGQEDW3SSNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F7B250B033
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 08:06:57 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id l7-20020adfbd87000000b0020ac0a4d23dsf820242wrh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 23:06:57 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1650607617; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQfXb+cvhdzS3wwrXAfU6x8pCobnn7WMKCAghc62jOGzUJB9l+HR8F2Cp2WCpripsD
         MFVCky7BQzjLsqo/eOLos5fRPFfFs0fuWazoN5laXpDPzf1LxG4yDRgnPGv0/mnOBWp/
         J41mND8KcZGYAXGsCaawvCzqvlMOrVBFRBBJJEGJ6owarkSOe+xA4dmNhU9Qh0mGw51D
         l9ng1N5128JpKsdxeX47cytibd+Rd1ulrqxh+jtrnOwG/qtNDVaQIZu3cM4Ufwmh6wZ+
         adJG2XFTFPaOcgeTkOEHGxcjFTJwBb6GwOijJI9JSmYJFUInwj1fhLQqAlmNVDVf06Wf
         5ATQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:dlp-reaction
         :dlp-version:dlp-product:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:to:from:sender:dkim-signature;
        bh=SgdHzQ0jQGCkENRlo3+OE64DrUQjlP0hbm0bv5aUIYE=;
        b=fQ/95BAJT5X+M0JMZlwojnghtBv7kFJyMvtp9G+tAf1OidUmhRlP490dJ+u8D7g550
         LebIZCtB5kxIUlK7HMx5etCS8QJc/y7wKUI7CnrSeNl/jzMs0tbnobzMAm2LQmzd7foS
         IgYMVtw/2a093FXgQ43B9CfXnw8eCYVR5vEt2z/VAi8aT69L4yTARREOaV7Ysg9KvLLx
         fL7612G0sDud88Z7IgdHEe27VWeFTYge0lC+kBhQ1fMTkmEq5zGF+YlfWNQzGIqMM41J
         yF5yarD0dRawgpN4BISSeysELO+/+QzK5bIEToD3hWgq9i+oRk8gea2CIPCadnHy2CKU
         uwnA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ivaDzZbI;
       arc=pass (i=1 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass fromdomain=intel.com);
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:dlp-product
         :dlp-version:dlp-reaction:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SgdHzQ0jQGCkENRlo3+OE64DrUQjlP0hbm0bv5aUIYE=;
        b=tLplvI6MCXLAdDez/vOVMM8rUQcRV0cvZ+SH5dK0N9OpuZ4Dy+n4KitS1iJy1HhG43
         Lj8AQnfPeSVnipyU1s9TjMmSuu90+1534VLL8FRfeQJ0ouUCTikW4Q3/X9ZKz0d4VHii
         ZmzJrrPDA1F7mVs0wwpQ0OzYZ4HAfXYZNVLhsIkIo6wJT593YkAet0WrdhtRPxj/eKBz
         YtuRiZyk3bDRwzE8mst0rCSY60qVjdwjmndKGuEiQPxfTterWJkwkhm+RXnpXQJbfcjm
         B52jAmoMhXy3lUJoQi37xf2TydrTpLYW9W3tZNd8HXcpJWCL28KOoIPSBWo6AqgnYz1o
         UL9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:dlp-product:dlp-version:dlp-reaction:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SgdHzQ0jQGCkENRlo3+OE64DrUQjlP0hbm0bv5aUIYE=;
        b=yoSe2U88gijUaa13/5R/RB5gNOqJMg6WkvIO0uXx6+gpGjdm03+9dhRK+f4rvjBhzW
         CDU5ZI4WeybPCFpO3+W9HyC8tr8vlzTxp8IKVXZIqw8CNZZikPERrERZlTgrxU9YgIIU
         eLp2Vw49SVYBp+C9GmZk1SxMZdTOVFIzYNtu60aLUAO/99NwjmqdO5cgW4OzggrpsfYw
         cHY2UmzFXYyfi9KwuWXlWQgC/yRC0jh/AF1K7wWOYQR4cP6sSubOqF5THNTOA8YG+VoZ
         U58w1Ammkos3sQfApdwIlK+l39rnEcGSbwiCe7KEWKUn67bejUKsL4KDQZy9TXiINlLk
         HE4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wxJ0+YB034J8+CEWqOMAI34FS1lN6lnbT+gruVmd/r+jciwyi
	ERoxvUSRdQXIGthMzq4Xj5Y=
X-Google-Smtp-Source: ABdhPJzezVB2F5QvEyEMl8BX9mT95oziimbIgP6KUxaZYLULtWbavDP3JP58KR5FZBCUpZAV80yv4w==
X-Received: by 2002:a05:600c:1e89:b0:390:ba57:81c6 with SMTP id be9-20020a05600c1e8900b00390ba5781c6mr2553718wmb.29.1650607617184;
        Thu, 21 Apr 2022 23:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47a7:0:b0:20a:a30e:f9ec with SMTP id 7-20020a5d47a7000000b0020aa30ef9ecls9325370wrb.3.gmail;
 Thu, 21 Apr 2022 23:06:56 -0700 (PDT)
X-Received: by 2002:adf:fa86:0:b0:207:aadd:bff5 with SMTP id h6-20020adffa86000000b00207aaddbff5mr2211785wrr.469.1650607616040;
        Thu, 21 Apr 2022 23:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650607616; cv=pass;
        d=google.com; s=arc-20160816;
        b=HI8TuBGv+3MQbaJLimoanngdgO/sSLti5TMvP+aMFUrZXCf2UaL5WU/27plYGM7axn
         LP3weYdQev0yrEm/Mep2WBZB5BT/4Yhs1fjAHZ/OolSBvhfUNWePg1MavFARVLVGZLgJ
         RwrSRokqfCSJR1echR1Cs/hsr8LfTAx56lWd57sCU1POaZPzBEVpilQOb3rprWwA+R8t
         WYlH1dsY2KG7dkygk5m/kFDlzG6cesQad9ID8QordBLwBxzpt9BxP/RGZfTJmItrH127
         rloylkgAU0UZbvZyxBWdXb+IxOFCP23E+3n3Jinnv/t42YKKwUoDIZnB841MdEhMJ2cv
         pxRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:dlp-reaction:dlp-version
         :dlp-product:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:to:from
         :dkim-signature;
        bh=2JtZotz83UYLliZm8nUxSTzR6DGgQEiRmLpIPwxp0T0=;
        b=Ia89ufpauwvQVy1kKoOeZzbMRhQUzj7GWI6EV2nSf0+Vnnb1kbTdz5phf0idmdz6rM
         5yY3/iyVBovTDTCxPTz1VkM/3vsOy62K+cLrlKE0qVKBhIV4plSuYYNsOIElwPzbZzos
         oj7ol2JT3aaspbO3FyDe4uteLHP0n2o7leY6JfV4TIO94ZIgDa5ty2+FKuS9MG4F0U8a
         WNDy7SVBIpRON818K/z46zrl5t6vnUapm6t7mDLEP6LhXHLIK9YJoA7GhSiZFxA+X5oZ
         OBdunxZZq5BnAgRhIet6rkVKK7G7P7lLhAREmRhN0zKNmXls3bcWSVlroHfgxUZB7AJr
         hZ8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ivaDzZbI;
       arc=pass (i=1 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass fromdomain=intel.com);
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id l20-20020a05600c1d1400b003920a4a27e9si304968wms.0.2022.04.21.23.06.55
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Apr 2022 23:06:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6400,9594,10324"; a="289703469"
X-IronPort-AV: E=Sophos;i="5.90,280,1643702400"; 
   d="scan'208";a="289703469"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Apr 2022 23:06:53 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,280,1643702400"; 
   d="scan'208";a="658872694"
Received: from orsmsx606.amr.corp.intel.com ([10.22.229.19])
  by fmsmga002.fm.intel.com with ESMTP; 21 Apr 2022 23:06:53 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX606.amr.corp.intel.com (10.22.229.19) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27; Thu, 21 Apr 2022 23:06:52 -0700
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27; Thu, 21 Apr 2022 23:06:52 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27 via Frontend Transport; Thu, 21 Apr 2022 23:06:52 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.173)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2308.27; Thu, 21 Apr 2022 23:06:52 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=mfiBVeU+UKVK0/ewDayqELIo+SJAw81MH+hK1TTslkwXBGKvlcPQ/z4xQrSYTfw4Sz/UHAUiWYaI/nupcHaEENJY38L99c+hMncIw1yWZJedhRK7Cwg2H63liXoC7vD0w6zNWTb2TxnD52b8CXwX5guZuaBEw0/W9vcrs2OJblz6qPbHNGuZ/g4oeovS7WNdqXM5/+OtxPxMlIZ4XLydAdBTWknldIIEk4pxpJCbNe2KQqnY1kdLkIJzsmtcwiyGLKdIEZeLO7B5q4gCrLBw9l75nHI5xJRzly7Jblx1rVZEeXXrg9Qu2PSutQ2zfq4IJUl6Zajyrpl1CtLLv4euWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2JtZotz83UYLliZm8nUxSTzR6DGgQEiRmLpIPwxp0T0=;
 b=ZFoi4GZHAj5/U3ToaSFDsnMs3BQQvMx/4H5bQDF8iNugid17bq2iR+L+g3ZsaBOE0h9apgSXEUJFB/94pw1cynJDorIO1rNCs6EU7xVPtqtDraAyCgNAa4I+ohXbazRKS4TDLkTKL2iBIY+qaiiZVrP+lgRzRUuRWE/tsXkK3Gf9yvOHXDkwMpzXr3jarYYmEHJdNBC1NO+xdVdpZEJ1BXl0h1+Mm6q7cMRR60TPI/tPzMRgh3zfdU7Xo3VXz2FuVwSt6mXz1U1muUhK1oC4WZumxft66TisrvCLPT7BPydpjKz0dOPPowSlpiPxf48F+bSt4FMm6FsAqvI72xNAFw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from PH0PR11MB5880.namprd11.prod.outlook.com (2603:10b6:510:143::14)
 by BL0PR11MB3060.namprd11.prod.outlook.com (2603:10b6:208:72::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5186.15; Fri, 22 Apr
 2022 06:06:43 +0000
Received: from PH0PR11MB5880.namprd11.prod.outlook.com
 ([fe80::c579:f1c1:28b3:610f]) by PH0PR11MB5880.namprd11.prod.outlook.com
 ([fe80::c579:f1c1:28b3:610f%8]) with mapi id 15.20.5186.015; Fri, 22 Apr 2022
 06:06:43 +0000
From: "Zhang, Qiang1" <qiang1.zhang@intel.com>
To: syzbot <syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, "dvyukov@google.com"
	<dvyukov@google.com>, "elver@google.com" <elver@google.com>,
	"glider@google.com" <glider@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"syzkaller-bugs@googlegroups.com" <syzkaller-bugs@googlegroups.com>,
	"songmuchun@bytedance.com" <songmuchun@bytedance.com>
Subject: RE: [syzbot] WARNING in __kfence_free
Thread-Topic: [syzbot] WARNING in __kfence_free
Thread-Index: AQHYVWBphb2PCohozUq39I4KMWUL3az7cxXQ
Date: Fri, 22 Apr 2022 06:06:43 +0000
Message-ID: <PH0PR11MB5880BDCCB36A273368245C87DAF79@PH0PR11MB5880.namprd11.prod.outlook.com>
References: <000000000000f46c6305dd264f30@google.com>
In-Reply-To: <000000000000f46c6305dd264f30@google.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
dlp-product: dlpe-windows
dlp-version: 11.6.401.20
dlp-reaction: no-action
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 33896f6c-11e8-4c0d-f23e-08da24264679
x-ms-traffictypediagnostic: BL0PR11MB3060:EE_
x-microsoft-antispam-prvs: <BL0PR11MB30609D4007D08890F85C7DEDDAF79@BL0PR11MB3060.namprd11.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: CCFHkxpDhLD55d1EooeSCZh843QycM3bSyv8ZPJuakt38tQqN/0SsRSaN3RZ0hch4cfsjobUXdH++zXjTfPVnH+aaczoIdINXO4B8uKestSd1jZVjFA0SNHpFfYKbJIB73WlNgKa2nuCBvBLKaFclKpM36LyE9K1OMdI1aoFDXTAyjuG3B4Gm9Y1dPnhMZQG5pjaZFNfDOZAeBDC3cqaannswd+aWWbVOh452jrU1aw71taOZA/MYKN1awhA0fFyyc2nWgFI73cIuaw8bbVqd+dTIXGUKsd3P1O5WYiUdwZ7o6DNBTKo+g9gP6BY0iW+cIKBDpxEUVfycIfZHUSrlrigA6WXZoAYwwkgPd++bnvRu8S8PSi1EehLF1t/pPlMhEInGqTpklE3kn5uNZqwod11/wAikGR+jUAIWIl3rsLFcDC7K3ohwf/RGL66KuAQOeIzGsZb8e8j0m8ZFMkVC2kiLALH9B1bDgDSXbAcBf+p9KG/Ha1DQBG+eiiviVOmo7e65xCoSMMP5d5SF61mG7d7F6ULDnUXAZR6TS9pZ+h78bYrPedcmrZJaGGyk6HuP0vtTGDIBM0LosswCitnmOYNhKJkwabUhWArQ91NiB0M20/Lg9q4nCH5mBFe7dLSQDD8IY7GAYsemsvAfYh0ombNA5f59OLakSUbeS+EHfacyTYPNBuSbX8ZFlWAP6go3CU8zTxQcdD4QAmYEW1wIkAv3f52jukOLJGXs67+WhiDlSp+LTe8nT9Emci5lOtPiS6WPcghIeQZhpya7A10hh0/wGjB81keHK86yEfHrG08YZhOxUVDxHvyF8IYElch1UuFpzY44jwHt6ZWEq05sdJRN2DCiRNawB+xTk6M23M+LkBRnDW/QI1Maqx/NfSP
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5880.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(366004)(76116006)(966005)(2906002)(186003)(7696005)(66946007)(9686003)(66476007)(5660300002)(921005)(38070700005)(82960400001)(38100700002)(316002)(122000001)(55016003)(6506007)(110136005)(64756008)(66556008)(66446008)(86362001)(83380400001)(71200400001)(8936002)(45080400002)(52536014)(7416002)(33656002)(26005)(508600001)(8676002)(99710200001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?THR2dGcwK3lNMHZjMEVqRmwyTFVlQTM1YUJ4WFBJV1dmWDA2d01OVm91UjE2?=
 =?utf-8?B?SDBkNCsvbDFoaGNSdG1VN3ljRDN1Y1I3Z0xHSFNxV25CSktIenNoVXJOUmVn?=
 =?utf-8?B?NDlqUldSaTlEVTYyVFJKSlFMVE9oYlN6WmY5b2IxU1lrRWIrODJQTlRMN2Fn?=
 =?utf-8?B?NTlBSzBlNnMrd3NVSTdNMGp3N0U0U0tJRDRDOFFDdHV6Q1ljTEVaUTNTa2JW?=
 =?utf-8?B?dVVTN0pLa2pJeGlpNjY3MUVwYXJIYnhHeFlqeUFwRTlNL2liNmxtc1NTQzY0?=
 =?utf-8?B?Z3I0UjlEa09CQnV2RHV2Vmd1RlFjMnlKWGRJdER3MHlkWXRoQVd1bGQrMmVZ?=
 =?utf-8?B?K21JYm4rYnRaTFpWODNYRm5tSDVMWjJmeDV5VWZVMEJIK3JKQ3ByTUQ3Z3Qz?=
 =?utf-8?B?Y2dmaG5LOE9zRitDSDRzenIxVXVHeGVYT0hNWGhBSEpIL3ZzR0w2dzlmb2FC?=
 =?utf-8?B?QXpTT3FKYkZEVGZVRTNSLzR4YzVjUk5ZUHUwZlB4bzZFRStWbEFEUzRyZi9I?=
 =?utf-8?B?K3pMaEdmaHhrWVBIMTV1UElPYVI1dUJwazY2ODJpWHpVWXprc2FMTGtCaElr?=
 =?utf-8?B?OFdEWlplaXd0RXBXczNZdUxQNjlNRmsrd3VFU0VBblZPKzVwNWVhMnhta0VV?=
 =?utf-8?B?djRsTG9hYTVlWjJzSnhwc1J0UUJEMFJMREpmQThDMWk2cjM4SjZaZGUwZzg5?=
 =?utf-8?B?dTV1d3Zjb1RRcFo3T0c0eDhtSnlYUkpERzNNVnBiSUlMMS8wTWZXWkNmakJY?=
 =?utf-8?B?YVZXUTBBdW8yelVGMHRsR0F5TldObXBGYy9hVm5VV2huMDdaNWlwd1ZUTE4z?=
 =?utf-8?B?dzZ2WHNMUUhBOXlmZlZnV2pwaW44RU4yYXFZeVVJUHlKTnlIMDlHUTRkZ2Zz?=
 =?utf-8?B?Myt4bkxZYjJIUEZ3YUFkd1E4Y2YxUGxtTzVMekNWZUdZd3d3bDMzWjNEVUJF?=
 =?utf-8?B?ejh2cTcxc3Nkem96dHhLaGc3SG1iWk9DQnNFTWxxdUM1UXZDaTZMaTQzbFNP?=
 =?utf-8?B?eW40enJrVU0zaWUwSWEzZVd5czBaeXpueGZMYjhlUkJieExMSnFZL2xQWC85?=
 =?utf-8?B?N2M0K2VERjg4cWJMRlByT0tqM0R5OHltSEM4YThmMGV6eU9LU0ZmdHFnZHBh?=
 =?utf-8?B?WjJKcTVHTUd2REVmdFAwVlVNcUc4UUdqcXlwekZzdU9oY2dHUlJ0Q0U1eWJj?=
 =?utf-8?B?Z3FXbWw1MFNLOHc5TU9ycVQrUllWR0RVZmViQ2k3NFdEb2pLQTY1VmhUN09Q?=
 =?utf-8?B?Si9INEJtQmtBcURIaXdiSzR4TzIveDlmTWM1ZXA3M2N1c2Y0RmhONi9QODI2?=
 =?utf-8?B?NHFDNlZFVDlOUzJPNmxvNTBTKzBwbHVjZndNMVhRV24xUFBJQnp2dm1FU05y?=
 =?utf-8?B?a3lyUzdmbEo1NFg0NlRUUHdrZ3BSY0U5YjZncUNDbmorMzAwM1ZhY05KVEZS?=
 =?utf-8?B?aXVDa2xxUXE0NXJkdU0vZm9pQUZ1bkxiT3ZKZ2ZNcWp3dGVKSVQwY2Zac0tL?=
 =?utf-8?B?VlhVNkJtUGFnUVZ2TmhSWmMwUVJnWkZkajlJT1krdXNSNVU5WDFRTmlRLzN4?=
 =?utf-8?B?WUtzQTlMMHdnQld4eCtuclZZZlZ6QlkwczNidGF2dTl1VG9DZ0VlaDdnRkM3?=
 =?utf-8?B?VlM5TisyRmFoVVJ1U3d2OG5ma25zYUVuY1ZydjBGNm9WKzZKalhUR2NnZkdW?=
 =?utf-8?B?bStjeURuVnpmbkNDMXVTbUlCQTJoVmg4cDhsMCs3QmRGRmkxUDQvd0tPREdp?=
 =?utf-8?B?TGpzRnJPbUZZSGNkam5xUWRRSkJLUnFSZkdoUE5idEw1eEFsTkptSzh1RjJi?=
 =?utf-8?B?VmhXbzJjdU1FUjNGZ3RiOVRvUDJ4SXJaakk1TUZ1VFE5VFMySmxrWmhIaWJt?=
 =?utf-8?B?UWl5TVBBdDRrVlhsOFgyT2Erd3ZhaytHb012eEdRMmlCVTMvZTQ1RkhqdTlG?=
 =?utf-8?B?VDV3Tzh2VFZQRWNtUVh0eVVkRDJJR3JJbWxHeXZsVk9lOEF1bnNFdUExS2JH?=
 =?utf-8?B?TlBIZDYwOEptdVJCNjgwT005eUNlZ1FKQmlUakJsdVJYbTJZRUZRUzZ5emlJ?=
 =?utf-8?B?UEIwUmFydHZzMThBZXFMbVdKSGlsS0puYUxlQU41WjZ6eHY0ZTNZeHg2Tzlq?=
 =?utf-8?B?VVdScG0xRmpKdjVCZTJsc2Y0alJFVytJQXF3ZDQ0SlQ1cFBzVTF1RFp0enA5?=
 =?utf-8?B?SlNjbWFnWjVwbGFyQkUrRzFaVkNnTlgyUzVCclByMmJ6ZmF4MStXWHllQXkz?=
 =?utf-8?B?ZDl0Qmp0cEpkTjYvWE9CUHNkRkpHMVZPNU9ZU1ExUldiNDZLUTBRNGk4ZGpj?=
 =?utf-8?B?SjlhSUZvUWs0bDhTdlRGWld0TG12WG15bVBLaHl0ZHBHaU93TUpFdz09?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5880.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 33896f6c-11e8-4c0d-f23e-08da24264679
X-MS-Exchange-CrossTenant-originalarrivaltime: 22 Apr 2022 06:06:43.5631
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: yy+jBfQF7LlBqWv3LNEl+3q820tusxb0/OssCOesllIiy412dlYzunTls5p+0KvZi/PBt9FPOvZ1cZrWZE8gRg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL0PR11MB3060
X-OriginatorOrg: intel.com
X-Original-Sender: qiang1.zhang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ivaDzZbI;       arc=pass (i=1
 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass
 fromdomain=intel.com);       spf=pass (google.com: domain of
 qiang1.zhang@intel.com designates 192.55.52.88 as permitted sender)
 smtp.mailfrom=qiang1.zhang@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

Cc: Muchun


Hello,

syzbot found the following issue on:

HEAD commit:    559089e0a93d vmalloc: replace VM_NO_HUGE_VMAP with VM_ALLO..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=10853220f00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=2e1f9b9947966f42
dashboard link: https://syzkaller.appspot.com/bug?extid=ffe71f1ff7f8061bcc98
compiler:       aarch64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
userspace arch: arm64

Unfortunately, I don't have any reproducer for this issue yet.

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com

------------[ cut here ]------------
WARNING: CPU: 0 PID: 2216 at mm/kfence/core.c:1022 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022 Modules linked in:
CPU: 0 PID: 2216 Comm: syz-executor.0 Not tainted 5.18.0-rc3-syzkaller-00007-g559089e0a93d #0 Hardware name: linux,dummy-virt (DT)
pstate: 80400009 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : __kfence_free+0x84/0xc0 mm/kfence/core.c:1022 lr : kfence_free include/linux/kfence.h:186 [inline] lr : __slab_free+0x2e4/0x4d4 mm/slub.c:3315 sp : ffff80000a9fb980
x29: ffff80000a9fb980 x28: ffff80000a280040 x27: f2ff000002c01c00
x26: ffff00007b694040 x25: ffff00007b694000 x24: 0000000000000001
x23: ffff00007b694000 x22: ffff00007b694000 x21: f2ff000002c01c00
x20: ffff80000821accc x19: fffffc0001eda500 x18: 0000000000000002
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000001 x13: 000000000005eb7f x12: f7ff000007a08024
x11: f7ff000007a08000 x10: 0000000000000000 x9 : 0000000000000014
x8 : 0000000000000001 x7 : 0000000000094000 x6 : ffff80000a280000
x5 : ffff80000821accc x4 : ffff80000a50e078 x3 : ffff80000a280348
x2 : f0ff00001e325c00 x1 : ffff80000a522b40 x0 : ffff00007b694000 Call trace:
 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022  kfence_free include/linux/kfence.h:186 [inline]
 __slab_free+0x2e4/0x4d4 mm/slub.c:3315
 do_slab_free mm/slub.c:3498 [inline]
 slab_free mm/slub.c:3511 [inline]
 kfree+0x320/0x37c mm/slub.c:4552
 kvfree+0x3c/0x50 mm/util.c:615
 xt_free_table_info+0x78/0x90 net/netfilter/x_tables.c:1212
 __do_replace+0x240/0x330 net/ipv6/netfilter/ip6_tables.c:1104
 do_replace net/ipv6/netfilter/ip6_tables.c:1157 [inline]
 do_ip6t_set_ctl+0x374/0x4e0 net/ipv6/netfilter/ip6_tables.c:1639
 nf_setsockopt+0x68/0x94 net/netfilter/nf_sockopt.c:101
 ipv6_setsockopt+0xa8/0x220 net/ipv6/ipv6_sockglue.c:1026
 tcp_setsockopt+0x38/0xdb4 net/ipv4/tcp.c:3696
 sock_common_setsockopt+0x1c/0x30 net/core/sock.c:3505
 __sys_setsockopt+0xa0/0x1c0 net/socket.c:2180  __do_sys_setsockopt net/socket.c:2191 [inline]  __se_sys_setsockopt net/socket.c:2188 [inline]
 __arm64_sys_setsockopt+0x2c/0x40 net/socket.c:2188  __invoke_syscall arch/arm64/kernel/syscall.c:38 [inline]
 invoke_syscall+0x48/0x114 arch/arm64/kernel/syscall.c:52  el0_svc_common.constprop.0+0x44/0xec arch/arm64/kernel/syscall.c:142
 do_el0_svc+0x6c/0x84 arch/arm64/kernel/syscall.c:181
 el0_svc+0x44/0xb0 arch/arm64/kernel/entry-common.c:616
 el0t_64_sync_handler+0x1a4/0x1b0 arch/arm64/kernel/entry-common.c:634
 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:581 ---[ end trace 0000000000000000 ]---


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB5880BDCCB36A273368245C87DAF79%40PH0PR11MB5880.namprd11.prod.outlook.com.
