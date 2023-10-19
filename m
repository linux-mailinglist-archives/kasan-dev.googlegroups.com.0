Return-Path: <kasan-dev+bncBCY3HBU5WEJBBHWYYWUQMGQE32KSCVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id B06AB7D00DC
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 19:49:19 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1e9a82ec471sf2806fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 10:49:19 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1697737758; cv=pass;
        d=google.com; s=arc-20160816;
        b=aNr/wB2uJHQ8jMxmthSvwreoNhhgS/hJ40JWYT52f3XMPlEFKq+mjnuY/ppfOSJFKf
         OAj4jik/9ME1+pCMaLHR2PEpWGzJJXWgo5/9MPMLEbSIvrQtb/4axYYfEbr+hsRLlxBT
         p6IKskmUEGMVHt8OEyuf2HV3NOmokenT5ZBQMCcn8ggTajotA3+LuY9govQWqaiKL405
         CgjngM8LDMTEW2doRPJMLFK759VLlw6497Xf1XuEaWA//pr8mv7tF0viOdUc5x93jnJJ
         Ozn5YtkHsXCxals3KROQlSnr8Ix7AkzsIduVj55X+PqpUFc0e+6451LqRc7DCA8OtGoS
         DIEg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ISgboHUmQSPms5X03HtpS7H6n0TUwjJvGYdqk4FU8XQ=;
        fh=kROyfhNNMWOcgE0Eh9VU7snXGZ0pT8B1zNusBz9HcAw=;
        b=vj6c/p3zMZ2yHAihUXJGxaEkNtc+V/p4cLu1CPR8nf2wNrc0pH3z2ihD3VQYvZK6SR
         JBnGESmc7Wv0htZ6vxizrGw0CZB7ErcBMmlKiGxOAoQdqHPWD2TMrXuPpbuSwChsQoIo
         qvyygpR9gH1NU7ienilywwFk1nt56Ef3QsYfrJpizkmkN9uDa8cm6hDHX5F4DSINY9kz
         u8h8riVVsh96c1W/SHTpfAi1h2VOkMfAgWO9ki0oQNCi5CQbNJyxhcnEATMe+CYmerwO
         2npWJQgezEXM1f+oL1RB81yPlnTsHNIkgY6V2xhgXZs0vykijC06I4hcNgUbLNgWfjJZ
         VZEg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=notP3Zmh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TDvHNFHJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697737758; x=1698342558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ISgboHUmQSPms5X03HtpS7H6n0TUwjJvGYdqk4FU8XQ=;
        b=qtghzDYAOAm46fBeLmFTJfwkCo5m0BeH9iPr3mmMMWl8UvU6l6QSEOXWTl2wPRQ9D6
         HYtWy0h9RRQDnpk9TVqcvy2gfRB88zjpn26qD2F1pNeIix1tiY9BfVoy9pbZveU5i3Wu
         hsLhBuALUp+x3DsPU68HQQwqNh3B64mAkwls2u4hLZI9dE3T1Mt7vr7gVC9+DrSy2GCy
         +KponWIj35kORs5Nnzq1cnyGuWZe6+4xPcUI5MiW+eHh2z47qtQCe7ztamrLhzuFlLoA
         GMaeARaSZ+5QgcZHPVx4YvaKOQlIG1pqKzEoBlL5HHb1GtKtZmCz7wD/7g8ySkrZoy4G
         WeoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697737758; x=1698342558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ISgboHUmQSPms5X03HtpS7H6n0TUwjJvGYdqk4FU8XQ=;
        b=NRnvIF5+wJoYLOqpP3nK0xPL33gbZgzaidp6wUFwAyOZHXyLdaX9HMqXVRFISwfmTk
         mzW/BwEILwvu6KbFHS+GU4W6kP+WCUP6fCIySdkHiFDiKKF3sHOdGxfBcLl3yGUOqsvq
         f77PE99PF3ZMEi+Evp1jryKG22pdKrmHNwAFdX4SBq0rJccgcztPxl2f6mfaBRLGrXlS
         GJ//hQeKUk0wI1GbkmB6OaEdIt+81Gfrsx5n30FEVR5BcCTBbwnYWokIz8qVi6LyJh62
         TEtCLEM4dOBB6zTLl07WldSKjTFwNbxESbKqSeKbB8uaAefWUpYVOlTglJNI9BhqBVgy
         an5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzrBBhIxAUlIS6SPrCuhipkNW6H4Hriu54amUZIrfJ5PbwzPtnD
	iJibrzmjTFTvLJMQAt9AIoM=
X-Google-Smtp-Source: AGHT+IF+ZyCaSUGujYOXPtHx/NwldECZgWyd+fYCuiQcIC/jjdT9DkcXztRP0LXjBf6w1YYS6RmPRQ==
X-Received: by 2002:a05:6870:7ec2:b0:1e9:fb1e:8704 with SMTP id wz2-20020a0568707ec200b001e9fb1e8704mr3288790oab.21.1697737758204;
        Thu, 19 Oct 2023 10:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:971f:b0:1ea:d76a:4f02 with SMTP id
 n31-20020a056870971f00b001ead76a4f02ls266617oaq.1.-pod-prod-03-us; Thu, 19
 Oct 2023 10:49:17 -0700 (PDT)
X-Received: by 2002:a05:6870:1056:b0:1e9:892b:eaa0 with SMTP id 22-20020a056870105600b001e9892beaa0mr2850702oaj.9.1697737757382;
        Thu, 19 Oct 2023 10:49:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697737757; cv=pass;
        d=google.com; s=arc-20160816;
        b=O4LKwsBqhn7dxwB8TmR91MdTVYTA9VLgct4OpnuXOJExRqwhKt+LZuhtibfeSLmkLf
         EbVeTewDUKPE6hyaVGmHz95ZWVc4Mb18a7Ugf7cG9bcDgjlP7FZKtWcehLen9iB8G/cT
         F2AZ8408w/J6ryEkAgtr1ted89uBmgzM0twd/CNu4r+q15UYxD0XqvXjFeahEYxf4mrY
         YIA0rAagvi9/Fu9BY7jZoOd6FLGLnKkXshrtXr4q3/KFmHWm1Ydu/y7mNXOXJh+67WF0
         Qy05hnu8rBTMAZ2ogd/SDLfC1cg74SV+4y41F2zj89CMy6AdNVGvAt+Cch1jw3GjzGfu
         0P3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=STJkREwQU5Azpux098T0xlwWhDbiRae4yb6Vh5hJUQI=;
        fh=kROyfhNNMWOcgE0Eh9VU7snXGZ0pT8B1zNusBz9HcAw=;
        b=tabaPCBRxJk1qRc1GhZcVq/IBTeRvlucTlfGwv2sxssj6N4Vk8rzlAJ4uFU9BXhy3e
         VgFf9Pw+iq+Kh9V0kQDh8xWRYPQfKVqgYLaB2/rB0kPuZZF2zKn7nA4fdBNWkoeFAlEC
         rTT8s96MgIaAsRXRy7ddlauH43k//+dQyAQgoIeBizyXg7ooVuBm100UHoyXBgo1LBLW
         deaV1p55S7UkYDY2+CN5ygN5sdFYkDnRkWrK5UktuBfPNq3dD+BzQF1m8Xm5Dm1C/jPb
         y1bNvWtu0m3FXEv+9fWiiELLpxssqgHPK6WqzIa5vJMWc86YAyRlWBhBopnbVsh78iGR
         bUrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-03-30 header.b=notP3Zmh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TDvHNFHJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id y18-20020a056870459200b001eac55e3d6csi391706oao.5.2023.10.19.10.49.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Oct 2023 10:49:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of chuck.lever@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 39JGDu5E019754;
	Thu, 19 Oct 2023 17:49:12 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3tqk28uer3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 19 Oct 2023 17:49:12 +0000
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.19/8.17.1.19) with ESMTP id 39JGXcS3009572;
	Thu, 19 Oct 2023 17:48:57 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12lp2168.outbound.protection.outlook.com [104.47.55.168])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3trg0r1khb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 19 Oct 2023 17:48:57 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=f+aSwFOkC/HPEpH2iDV0f876GzNy6WmI5rh3zK1ERPrlMU1easZd+thldYncqyS9joQC1GRkyOP05aD9S6oGiA8U1BpObedYUAWOqZYozgFEwjSF5/vUIWAtaBr1qmTdjoVb61vFHOZLYDZ4f/1kGovXYH8Dcg4azpmKzptZxEKbaFgnJdqgYPrZOveeKxhAnBq9Vitb5YcIYSPQwwifsa+2TWEUuj+SA/YBDtQMZrwbXX6vKYJrTDJz6tQ16UZgjVtigUTDRsoRdIzDycVGOh6//YQ+E2eG2voZWY6fItRO9ZmWhbb8NzmrehkMOGkd34qyR6pJNkEmtXEL72GtWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=STJkREwQU5Azpux098T0xlwWhDbiRae4yb6Vh5hJUQI=;
 b=BrtRRcVmUsQqbtOwBGiuUmStsPsFG+bE6QSgYmB+vF2lP+rmaZxQc9nf1oCySyiTifSoIqsFGL9V6QIvuAn5FtaFQ23Exmbb4nnGnYm+niYZgEfzATn53K/T/g6BcvjF0bhOdxD8QgQgXipVcCOa8D+PYm/fTOIea1SJyX+7NZkfa1jlGU5DKgYhU5T6Lviclsocerp+MhZxg22hIKN+RwvxOJRRm1wLzRO/yWr+8ljf+mqVSLUELjis0rZu/uDm2kdpz4biMQTsgDCytaAJqWhYHUSGoP98V1SXeXxZsxH9ULWi/ploxjMu8wyQuU6Xq6TuyLYWlj/P8oflvxjBhQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BN0PR10MB5128.namprd10.prod.outlook.com (2603:10b6:408:117::24)
 by SJ2PR10MB7857.namprd10.prod.outlook.com (2603:10b6:a03:56f::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6863.46; Thu, 19 Oct
 2023 17:48:55 +0000
Received: from BN0PR10MB5128.namprd10.prod.outlook.com
 ([fe80::215d:3058:19a6:ed3]) by BN0PR10MB5128.namprd10.prod.outlook.com
 ([fe80::215d:3058:19a6:ed3%3]) with mapi id 15.20.6907.025; Thu, 19 Oct 2023
 17:48:55 +0000
Date: Thu, 19 Oct 2023 13:48:52 -0400
From: Chuck Lever <chuck.lever@oracle.com>
To: Matthew Wilcox <willy@infradead.org>
Cc: Chuck Lever <cel@kernel.org>, Marek Szyprowski <m.szyprowski@samsung.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
        linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
        kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
        iommu@lists.linux.dev, Christoph Hellwig <hch@lst.de>
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Message-ID: <ZTFsBG+WebEDqJMl@tissot.1015granger.net>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
 <ZTFRBxVFQIjtQEsP@casper.infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZTFRBxVFQIjtQEsP@casper.infradead.org>
X-ClientProxiedBy: CH0P220CA0003.NAMP220.PROD.OUTLOOK.COM
 (2603:10b6:610:ef::31) To BN0PR10MB5128.namprd10.prod.outlook.com
 (2603:10b6:408:117::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BN0PR10MB5128:EE_|SJ2PR10MB7857:EE_
X-MS-Office365-Filtering-Correlation-Id: 6232df8b-8bb3-4f40-039d-08dbd0cba9fe
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: bFg/XjCy6sWCZCYhEi6pt3ye2Vc+CYRqG7kAnGYL/eqqukvbPSY7kbmdXkcKJQAcWCP7UR0hFz+UCAGnDD+5CI03P46ZYZEBUxlANGxbbgVHbPjloTFRHEKUnIAev2XeO4IlL373Cp5FvHrK1dvd+mJZR8o/Z43mwfCEQBAPNpvFP7OosZrDH6vbhVSJh6IIODnY4NBKGjvn5fQu8uhGqKLJmbzGCFNX6K8CLfxTwtC65bBXuOKnkJqpCYHEOeCNsWODOqjpH7zeylfmHgqhOY6GoCK9ssrmx22ujlDT779Wvvj1dIzWH/CR2x0cAnComkIS0ZiKaQamhppDNTgOoEdQirO42YLxtFLdowKrvIb+HS9Z5Wu5Kg97XptkzT9P7mvrlu0ODgmWoXn3qBjSkUSRg7KO1ZXjPNMwhcof0uY9npmyFdS2k2YXh4aMyvz+QsBOxGlKSwBPtdDPBkCA8ErQjJcI8v2nNIrE3vOJkmc+Tcq+wZdsNJGv4Cq1E/7lIokQmKMTKK1a1UF/96MsYUo+rjTXVYuNOK689VSiGTcRAWxCnRUwTvCHOVl0pXVnFbBRQAh566T2cNql4dKO/67jAdDLgvH4EeWlU9G+HKA=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN0PR10MB5128.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(396003)(39860400002)(346002)(366004)(376002)(136003)(230922051799003)(186009)(1800799009)(64100799003)(451199024)(54906003)(66476007)(6666004)(478600001)(66556008)(66946007)(6916009)(6486002)(6506007)(41300700001)(26005)(6512007)(9686003)(316002)(7416002)(5660300002)(4326008)(8936002)(8676002)(2906002)(44832011)(86362001)(38100700002)(67856001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?85nkG2i7p26q+Z6dzitOTc/iQwaHcTP58IwaTYLNjq7+qC/FhaBdzxp6/zGr?=
 =?us-ascii?Q?Sa3ZSI5cGDgWFqaEjew4hHh6pJP5Hp8mqts5mXZSRbNG3TQWqmlZKeOEobiT?=
 =?us-ascii?Q?YBf2k+FzwwX1+mekDzzsnofym+bCwPEUH8T48OkL8kvDT7/o5uZC/oWRRzun?=
 =?us-ascii?Q?1KVu+kxeL5LKPhMvicduXJupQMLbZcN3OGb85UreSe20TgsrWNrWNdIy2xIe?=
 =?us-ascii?Q?Wk8qzZgSDToSVJ2vU5mOcskFTfqXXJhKpRXofMLOkVjjBQ0lOtNUvaldC+f8?=
 =?us-ascii?Q?0/f2mAEfEJW8aS36TZIAEkzQQcsoJQ+TAWEpKH7vPQ2HHGKjW6Y4ClnghDmW?=
 =?us-ascii?Q?nP6QuH//PHAROUAH/p+WSlT0IXqwGHxjkTt+UK3wOmvv6DxrNCSstjjYLODb?=
 =?us-ascii?Q?ED9XlZNTnHL51ocqAkNAzYOPeqG/5B2S8ldCD9+QuyhKT4NiaO+RPvCRF0Za?=
 =?us-ascii?Q?U1CQS2aW0j415VybnSF4lT5SXOg0XzMsibHOCxOUniWCbmiYGG8HAG8Er5Rp?=
 =?us-ascii?Q?C6BID1/rKBQgTxzSmcH3VOguadKGpjnPAZcxlrGqyrkr5TNl9wlV0nB7BR1/?=
 =?us-ascii?Q?MKnrfKe6kSydIXWPGrC5S6ILsk23JqEOqcnKn62KSP+xDfL299EEJRSXbqcF?=
 =?us-ascii?Q?hh8FGjOVDTzUwU7wF8s9uXyNbtGuEWkTHBR45ahM8WHNKDadlRxNBXWLi/+R?=
 =?us-ascii?Q?13QO5bKPj5m5ScWXsm81mZJ1aU1GvpwWMi5edKqWJPqqMvbjJCNJwokwjIj7?=
 =?us-ascii?Q?8OTdLx0LQCZdkhmSB3aVjLswspgoVYctA/nvn1UyRv+zHZdf4j8FTvoqrIlB?=
 =?us-ascii?Q?e67ILguLCoAWOlaFabAoCfTMcTbDuerkx8KOI6fEfJjfDNBdyfajYfq4l3Vg?=
 =?us-ascii?Q?6EUJbFBV1uTAz0cJ5n2QtpCub30Y9NjqgAkIXsfiSCuYsYW+kYhy4MLxcxY2?=
 =?us-ascii?Q?0GFeLUya/0zKVtsip7l3OBbIvLimgjIzolVY92sO0+2xheiRTpjGS/E3/Oh5?=
 =?us-ascii?Q?xoJ3Wbb0s8oq7C4jAy2NGPXWKqzJvmENfn4xtS9EkRhmNwvnIHs9I4QkTZtQ?=
 =?us-ascii?Q?kSI56YPWrqPG2iel9SR+wt7WGqqjI6em2LJD3ew5LKIkXKLyfhJ+cbg4NJMF?=
 =?us-ascii?Q?+V1akaF+bi6brmoDplznB0ditBvWA5u+w/AZqUpbYkhe1yyYXRhN4YLqFU4H?=
 =?us-ascii?Q?iLC+k8g6VxrM4xg4xX1mgvK3tgdUEuXKohtnt6N51p/vrXMWStf4dzFhsSOe?=
 =?us-ascii?Q?M6OHewBJSw8Rj0oZqSPpHbLZb8GynsWjEGOEJn5NuSP6caHr2GDsIyQXJt0u?=
 =?us-ascii?Q?s0aHOO7qzdEpmqagoaS34dXV0fHSWmbUU0Un/YFNxLUZK2/NocBjlbez5TfV?=
 =?us-ascii?Q?VIgWiMkWrzamjbRmRqhVof4sTBYGoMBZws8hL+J4OFe0KG5pItadZub/o4Ol?=
 =?us-ascii?Q?VD7WINadKXIOvIjhbVlL/f3QMsQwnB8YtjdV3JsGahQtV+9raFzv7bKfhTzN?=
 =?us-ascii?Q?f2+oW1Wgsq6TgQiEcFMRd0WCC9TH5OvEgl6s2hoa9mO5Oyca0rmkilEOP9DQ?=
 =?us-ascii?Q?kKayHmAtrTCXMAe8RJPiHu1vQVtYvUZuXycXjg8rLshcDyeG8MfWHM5dri6Q?=
 =?us-ascii?Q?WA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?us-ascii?Q?wRKBI0g30SlLYYFzf6kY6VcCExyhqRG97s3TRnTAvZQC71ks7P+tFcQdH/e2?=
 =?us-ascii?Q?kgTLkkNFMT5NwvfsOXLe3c+inS7lzkzNzKF6I+8+xTD8FIa/FUqtZ4KC8UdJ?=
 =?us-ascii?Q?eDXxzD/R5c44Iws/EkytKRqPvDhKmRFpY6KR2MzPyQVmW58k4BlOqXsCrMEP?=
 =?us-ascii?Q?ZfQzY+N4CtILW8HWLFG+IPRuMdKirE2HuR4sa14p+t7h47b1Y3C0bHzVn6hr?=
 =?us-ascii?Q?CR58eFeGU/tH7IEzmWs0obePJnaHE2K0sZdpELgcksNnoTHqQXfBVCUEOIw3?=
 =?us-ascii?Q?IVWm3cSJ4wBppiq74eNGVJK4Fz0IKC8sowNS2OhYZPDN21luUphSQwd5si6A?=
 =?us-ascii?Q?EIAH3n8o0vp2wt5AKhCy4zTk63RqKuzAxlUq307QX6fPa1f8nuuaXt6byb8C?=
 =?us-ascii?Q?gAfhmLWyHMCKWKNkSBvC23fQ8NdqWuLKANb3rlV2Rs4Ic3Xb7DXpRNU1oJu9?=
 =?us-ascii?Q?4zJMUbVbLG6BMagkUalkAIrOjyM3abn3qa8qBRwNIS2C/XJPTqeXOZ65nOZK?=
 =?us-ascii?Q?QSilpPBC5DjZ/MfYRpOV+riYG/HhbrTpw8H6MU2c76+NzQazcAFogXuJmfjN?=
 =?us-ascii?Q?XiQmGSlMr/dWPTb33yuwumrR1eZzKc8XpBXs5KpVXpRE67u1ZL9YeiX1T8PI?=
 =?us-ascii?Q?VmG3uvoXvIZYBVekg3enuaOpg1UvWhFs40vSR7FU8ol9KaqvKEzAgFbHA0Ge?=
 =?us-ascii?Q?SbjsEIOOj72fmaibNpXb4lQl7uNzZCJQpOlnZ2BIUJYwQZQpYZuMMRm9Joec?=
 =?us-ascii?Q?eV5iEwrceeAU3zEqm95GR9I665LCjxkEIX6O86VgdCYzjp1hk8f018RRGaTj?=
 =?us-ascii?Q?f3J7gO8kLSuzBCWO9QvAvRWxePS6mrGiJFA7PZQyZ0QmZcBB2PznmdtYeKvc?=
 =?us-ascii?Q?lK6UOFDL0z7IFyIg7ZutL6N66MtB6y2cetPuVGYHJuingD38bE4k8Di3lMBA?=
 =?us-ascii?Q?llkeS6LWS3ml788puYUOPPMo+gSvDrRJ8PvnZO0MEWZAbFmA0NdRLkf5ApLh?=
 =?us-ascii?Q?oWfV1DkXZlmD1N6zhxZrSnA/VA7nDhbqLbpoTujIAzvLpnNsVUbcOdA0zZVg?=
 =?us-ascii?Q?FFbZ+cTGePMDBXbyYXjyvHFWLfge5CbXQFxx/ARaX84j/ud2Bt0=3D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6232df8b-8bb3-4f40-039d-08dbd0cba9fe
X-MS-Exchange-CrossTenant-AuthSource: BN0PR10MB5128.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Oct 2023 17:48:55.3210
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7TQFjU6znYeVV0fQDWZ87QEa0qWe4Bs0rZ9ORB5iEfPJdNH6kc2tK4sxOx19F0NKcc5ELpQptDWGcRZ4RpXssg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR10MB7857
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.980,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-10-19_17,2023-10-19_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 spamscore=0 malwarescore=0
 adultscore=0 suspectscore=0 mlxscore=0 mlxlogscore=999 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2309180000
 definitions=main-2310190151
X-Proofpoint-ORIG-GUID: 7ZIxdGim6n6RCOTVFanS2vSWQuvnL1La
X-Proofpoint-GUID: 7ZIxdGim6n6RCOTVFanS2vSWQuvnL1La
X-Original-Sender: chuck.lever@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-03-30 header.b=notP3Zmh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=TDvHNFHJ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of chuck.lever@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=chuck.lever@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

On Thu, Oct 19, 2023 at 04:53:43PM +0100, Matthew Wilcox wrote:
> On Thu, Oct 19, 2023 at 11:25:31AM -0400, Chuck Lever wrote:
> > The SunRPC stack manages pages (and eventually, folios) via an
> > array of struct biovec items within struct xdr_buf. We have not
> > fully committed to replacing the struct page array in xdr_buf
> > because, although the socket API supports biovec arrays, the RDMA
> > stack uses struct scatterlist rather than struct biovec.
> > 
> > This (incomplete) series explores what it might look like if the
> > RDMA core API could support struct biovec array arguments. The
> > series compiles on x86, but I haven't tested it further. I'm posting
> > early in hopes of starting further discussion.
> 
> Good call, because I think patch 2/9 is a complete non-starter.
> 
> The fundamental problem with scatterlist is that it is both input
> and output for the mapping operation.  You're replicating this mistake
> in a different data structure.

Fwiw, I'm not at all wedded to the "copy-and-paste SGL" approach.


> My vision for the future is that we have phyr as our input structure.
> That looks something like:
> 
> struct phyr {
> 	phys_addr_t start;
> 	size_t len;
> };
> 
> On 32-bit, that's 8 or 12 bytes; on 64-bit it's 16 bytes.  This is
> better than biovec because biovec is sometimes larger than that, and
> it allows specifying IO to memory that does not have a struct page.

Passing a folio rather than a page is indeed one of the benefits we
would like to gain for SunRPC.


> Our output structure can continue being called the scatterlist, but
> it needs to go on a diet and look more like:
> 
> struct scatterlist {
> 	dma_addr_t dma_address;
> 	size_t dma_length;
> };
> 
> Getting to this point is going to be a huge amount of work, and I need
> to finish folios first.  Or somebody else can work on it ;-)

I would like to see forward progress, as SunRPC has some skin in
this game. I'm happy to contribute code or review.

If there is some consensus on your proposed approach, I can start
with that.

-- 
Chuck Lever

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZTFsBG%2BWebEDqJMl%40tissot.1015granger.net.
