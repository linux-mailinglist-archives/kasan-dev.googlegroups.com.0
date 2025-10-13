Return-Path: <kasan-dev+bncBC37BC7E2QERBIEUWPDQMGQE6YXFWTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (mail-yx1-xb13f.google.com [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC80CBD25A6
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 11:45:06 +0200 (CEST)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-6362c194f7bsf9247176d50.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 02:45:06 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760348705; cv=pass;
        d=google.com; s=arc-20240605;
        b=UZn9jmJjj8bQYVpJI+Lm5FIglOy9+IaSrL6JZyOUrJelWXE4CTLyeiOm2zy5AVE7gF
         nKTai4t28vj2vKsPo5eO7u3SjcNWgp2vse9avfGbfQe8Bbp3N4tmM3wchSThSdJukzn8
         Hzv+2JX2s8w228+ArrVX714E0t4J+pocr27yCCRKJWD+oyjgagk4c7lW54OtQRMSVAKO
         IfmSjWefJxzBIEq7hkJgQbpRXXpImfTvicbyop83KHu4jzOF4ia4vRTAzKM00slH0qQ4
         M+EtuAkPz5dnCnMcSBR2zJV0cXm9NhDFi5EctkfQ1xIwlGU5h1ANcg1zO384s8U1JWso
         s8zA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/Vb0r9KpsETizKomfmYwBFRVY+rALx/2nTl6TUopzn4=;
        fh=fyQrTxTd6QvldXJDPMIWPfht++ar3YX0rkMVWdmH60A=;
        b=h+vk0oxt3PdZLDTu+Exp00ZG2EFSpXLothwm9gSgz+CuedOF+Rj2orjFv6vMgT2G54
         SYi5pjH7J6dbu9LMlC43L3hiiyIFz90RTLTMs8Pu2RFBYQlDlNiYcgQ4zqEp2Mb9JzMa
         KM+UtISkN+rNSfm91h7Z3h43wuU+LLGTPGZdb/vpFWWNMSOd3cYD02QZuy4KVW7mBnIi
         DsUh7jAcxR2aOiqmy5JNJCaXXUXzkhid2yxgH++FzsS4Yl/rN6E8SEOUzbKI08QxRgcN
         CU9Os/u71ATx8LndjY5EbSvbiG/c995G8njtDOiih/PkJDMV8HlMpZiU6viVkd5dvuq1
         vv7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rKDxCrQj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=b284yC46;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760348705; x=1760953505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/Vb0r9KpsETizKomfmYwBFRVY+rALx/2nTl6TUopzn4=;
        b=mzMJA2AvoAnmdUJmINZ9zB2hOjGfdi+IDmIoFrNzVCWCnQDIdqOx4cyRYgl1Dbx0Eg
         W5fU7R2Ikh01p2D3cuDKbQRCIKtFmt/pGWAsSgpuBPawjyYEt2zN2OhXNz46dNiedHd7
         IeXYu8V1gL1pXDwHLzhNQTm0rAuanz7F7Hv2rH1CHS+ZfqryRfKAyEAownOXjDDMIvrM
         JYqCPVvW88bTXmQ+YmTu8HH/LrjMJPAI4WjPomZR/6V+R2gL85ucP1q5ywO4fKBL4LmE
         hr74xsgi2rlBIf7QyoefQAqF9iEFFCgAbWAVS5yEMx46QsC0o4UHrQkEgjoVbRUvEsDL
         flWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760348705; x=1760953505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/Vb0r9KpsETizKomfmYwBFRVY+rALx/2nTl6TUopzn4=;
        b=Y0v3T0P8IxgSjIX/6IUSlE3mqSsimIPMuXamAmttNUlrbNYTunsc5WCwE6TMm/jbrT
         Yx6LQvAeMwee2EqfqKKsAla7Od8DZ+05o4WdQR8a4BqrBbRoiIIqw61dlWrzkhhzpQY5
         UiulCb4x9YAkFhDr+9Vd8CdXkVsGCJYdH5gb+lTNyceDmAP1k57IjeaKkDtEQSGqYkEw
         8ZMeaB3isfJ9GBl7sX1PUroteW6E1T64O+JzR29R5At86p6MDQoPLL1JSNsc6X3KWfLl
         2LseXD+nWHTWEFJy7RFffqdNJ7b85seTKby/kQ1TZyOlKgwKT8aBg9eiJPbsN9xHsV3F
         4HtQ==
X-Forwarded-Encrypted: i=3; AJvYcCVs5BhwhcNixEwBa4tzuR3bVxtq3cPjvDCvFBaseq8s5WDljrEa6TiwZs8teQS4uxu4N5651A==@lfdr.de
X-Gm-Message-State: AOJu0YykQ043200uYrUtpiMUaCPR8iaOU6gVY1h06ZnhzUeWvpegHFU6
	IgIjYbZ6YOE1L3g+UNQwmz034HJTAl32B24aV4TtDzneyIkNpIfWC7K/
X-Google-Smtp-Source: AGHT+IG+Q78eWqQeonSSaTfJrBnu7AY63gYoTlvBhD0MY7fBMf3O5SYE1X/7JVuwXVkHooTlY+TkrQ==
X-Received: by 2002:a05:690e:4142:b0:63c:f4eb:1b0d with SMTP id 956f58d0204a3-63cf4eb1b25mr7865804d50.22.1760348705121;
        Mon, 13 Oct 2025 02:45:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6KHubUu5o536xkbXYNfcwO+grsQoapaMiglSbqV+pIdA=="
Received: by 2002:a53:cd51:0:b0:613:bd05:6471 with SMTP id 956f58d0204a3-63cdf8adffals3857871d50.1.-pod-prod-03-us;
 Mon, 13 Oct 2025 02:45:04 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXd1SiDjG+YnfEEwQrQuVqubbUOMVi1Ctpoku/UYVLIjQPVxejj4ysG+P3QXYbi+wZeHx/X28L9+8U=@googlegroups.com
X-Received: by 2002:a05:690c:6c91:b0:735:4676:83e9 with SMTP id 00721157ae682-780e173e245mr218358627b3.29.1760348703904;
        Mon, 13 Oct 2025 02:45:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760348703; cv=pass;
        d=google.com; s=arc-20240605;
        b=D1m7I+ABVM4xQfrxlHlhSG8V4yPFHAOgqajskpCEpsz8SfuKsJaX2Vk0+GrVE2ASVQ
         D1zTWx/T257DODhXR8t6Fm9TxxoE7c7h37iUQVdwKEKzXZ/9FaMUBlRhxRw2VRgA3PdG
         58gZS+bP5m5AoLc2/JgHmJpB+ywXjl0vp1M46Dt46FrV62/vgDthO85ML9B3iwT46K4J
         t5bFJD0lBbyl+DetCqDvTeqJrn1w/XCxtpfCCndzT+h2wYpuU/omQ2gFHoiZXllQsTHy
         fjX0z83i6YgWT/SxpHNvR8Vrh82+w5wvC6m/GIQoROMYXWDKnBwF3ycjMbPsh4cXnVSA
         sEnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=oRyn/CQ8bqZfJa3iQ16zRDxPRhriok3gUztWOnL0nu8=;
        fh=kFR7lM4bxPHcaSQIwu4vsaDBmni6g0pd/SJSFdpf8NY=;
        b=FWD/4dmeuU1XYOczI6s0HcfH3dS1KQsixwfWUyZvEoQUPnIFo+uBCRP64PbBnI1o4L
         jljVBdsqFSIy1DMFnkuhTxisXk8MKURW3T+Gw7f4OJgdx+1pxCF6ET5pZTbVACFAFt2Q
         91uMrPJTgdoUswDPLEEjI8SGSNeADOC3pn6oGLVo5v0h/i3jbbvs2WXt/NyENeF4l6Cx
         rwazsjkIn/FwXfGvt3jvK1uO+IRse/cw7RGs3OOUqz76h2JrSjmyJJsVe6Pe67OjytKj
         /hKgB08Rx2PDLVvv++peCRfaqwTM2Gi7Cqj3Jlu60603MW6RbRKWL+9WoKl/KJxdti4W
         +2Kg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rKDxCrQj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=b284yC46;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-63d01a51f10si236035d50.2.2025.10.13.02.45.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Oct 2025 02:45:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59D7u42i032445;
	Mon, 13 Oct 2025 09:45:03 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49qf9bsvk8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 13 Oct 2025 09:45:03 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59D9N8db037734;
	Mon, 13 Oct 2025 09:45:02 GMT
Received: from sj2pr03cu001.outbound.protection.outlook.com (mail-westusazon11012028.outbound.protection.outlook.com [52.101.43.28])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49qdp7bbr6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 13 Oct 2025 09:45:02 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=V3reIiwgrxUwiwVWpJGW1TyJ4bcbDNoUydwHVnCFZZD4qbhFVdZGHSq+Wr4YN3mcWpoatCvGgf4fHw/utlleJNdIuU4Exj+MD57+/Q7GREgA80oAozELVW4Q0SEyHxsLa0edCs5FGAJwJMtOKNNclgXTwV2gcu5Y0c7PpZM9LptOfq9evi81FKSW43a8nEBtbmU0xVORpr50v/gan0EV/Xlg3m2AyTtc40Dm+VJNHwpj11LR9Xzp6EtJ4IH267xtdH9D/UOQSMXac1TKdpVwz56MK8+D7FOq3dfJJlXz0Uthhap1+3ONlHfaZajkyxCUrDMKzd9RixeDVn2uD4+Tvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=oRyn/CQ8bqZfJa3iQ16zRDxPRhriok3gUztWOnL0nu8=;
 b=qViA8WuXpXBs/TtmR+R5y2VVS/ohyw1WpCNCOVIyEpf4/zEY+buKSgj0nOIHAaxkGg0AA5TRFvweIYR1w8aUmxVFnestZQjm/lgyic/95mMWyGc0Oq5/h/zdOebAp/CIw79CGKazaigvQ8GddZMnLdg42QHaixvFxoXiP7GT3nhd/+aIvQ7/fr24js/CdiVQldF73SNeRiyTPoHYV5eEvFySzzRW3C4vA4sjtisNupvL7ttJDUKlIfDLc2QFhsU2zdjxX8mcwkKbwTSIO/jL8b0vuEtw8KgsHom6X6Mls6H1VEzzYp/VaPo21ZreyJ0eZ9/ehWwkRBy/2AvdXm7TfQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA0PR10MB6722.namprd10.prod.outlook.com (2603:10b6:208:440::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9203.12; Mon, 13 Oct
 2025 09:44:59 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%4]) with mapi id 15.20.9203.009; Mon, 13 Oct 2025
 09:44:59 +0000
Date: Mon, 13 Oct 2025 18:44:50 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: kernel test robot <oliver.sang@intel.com>
Cc: Alexei Starovoitov <ast@kernel.org>, oe-lkp@lists.linux.dev, lkp@intel.com,
        linux-kernel@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>,
        kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
        linux-mm@kvack.org
Subject: Re: [linus:master] [slab]  af92793e52:
 BUG_kmalloc-#(Not_tainted):Freepointer_corrupt
Message-ID: <aOzKEsav2RubINEO@hyeyoo>
References: <202510101652.7921fdc6-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202510101652.7921fdc6-lkp@intel.com>
X-ClientProxiedBy: SL2P216CA0215.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:18::9) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA0PR10MB6722:EE_
X-MS-Office365-Filtering-Correlation-Id: 6fb8e9cb-95c7-40c2-2d8c-08de0a3d2c69
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?DSxjdvJrPpEhBbH5RiKVAR6If2/7l8WYQisCiQyqeWfRZq15dVW++MJXxbHu?=
 =?us-ascii?Q?I5gKg0h+Z1WzYgRtWPfUBH3DKBAJl5VhmqmJhm0SU8UPcfzhWtf0uRD615/W?=
 =?us-ascii?Q?uRI/qofvsvX1+4Sg09/ZUpzXoiv1izj+dzPJSEu2lWHcfBJi5MeiBViKzwX5?=
 =?us-ascii?Q?agKsvrlaKhKwkwU4f76zfupmXp5fy1H+6rcnyi4pEwKXIYUUTjGQ2kuYGyMY?=
 =?us-ascii?Q?cvZopROhhBfDfyoDqpPtthsgqFoaMsOuc8gQfjOumgOvDiRbeu/9zrdt8CCQ?=
 =?us-ascii?Q?4R2iFYqnhUz9w8nuhxu5kD+OapWsC83boVZCpH3ZDRg3HeNKyYkL+TN94Ho+?=
 =?us-ascii?Q?zlU+rBsW25XZxVHhE/HhHXpH/klXr/1+ibxSeJTjjGrTrOzSe1EzOMeI+1zm?=
 =?us-ascii?Q?g04PMwFILK1TT02e5ZqBAwzc/o0RBP40D0Guw2kfWsDOYa7uDcUEzj/yMtzF?=
 =?us-ascii?Q?vOfBcH81u8ibB2O84ea8e685E9dtvcMkxVZGNmrv+SNxWsFQY2yhIHYX8ZQ2?=
 =?us-ascii?Q?/ub8H5KxZo/0kiyneCTd6eHJIGCv47IoovcQo7wgWbAbWfFzeSMuCzDV1132?=
 =?us-ascii?Q?vTcCWZUDh0bdTkLrI21E5BYjLDPe3meENJP5HleKpWJE4k1twDCg4PxA0IU9?=
 =?us-ascii?Q?y41OZc3wXtI+xJx8vFxhSPutVW9VXrlJqnjxPCvnBclITuixSROfJ2LXs1Ly?=
 =?us-ascii?Q?S07wuPq78CeCM5FKg2yGI/MFDz9tYZSwq7TCG6cb68eoAKeVWDvTvJDkkb43?=
 =?us-ascii?Q?laQQ0rKNBEXiMdhOsYwOOpiFRzorS9H8PNvxsIznSWX4nXvScq94qf3/xG05?=
 =?us-ascii?Q?jTe6JJ4a3h70rN8F1FSodxjE0SeMoFG2cPd62g7YJu0nzIDwc91O9MUnW37Z?=
 =?us-ascii?Q?Lbx0vGfc89YJigSg439/+i9xTLBAYvxzDgZM1BRBzYeMvDcyeCv/F3iFEBEW?=
 =?us-ascii?Q?auDSj1DvW04p+hUixFS+KbrjYSrS6BgYd8RbDo499mWDds1h61EoSWsJK41G?=
 =?us-ascii?Q?apFUdS6atm9k5zPcnuI1v+rF/C2cc2ZNOST88bMk//IbPxKhGcDprSFB4Azw?=
 =?us-ascii?Q?5/TihnYG9N8j6mxj3rQIzKqlHDSV/YoZ9GblJcwshkTF0rUe6/ODnJUVEc2M?=
 =?us-ascii?Q?chfDEoEf4hAxeuwh9ntEGLM6HE26euhkAhTslyZk0OI9dmepodRB+mHVcOZR?=
 =?us-ascii?Q?rVpU2GtQzihOPtINQG5sB+GjimZJd93cGyp3oFi44mn8yClWDqNJgjCvive6?=
 =?us-ascii?Q?6+oizJLWll6yEEDMGiTHneqUX5bK4w6ovjP6fQOV+zOqY6d0IkgVgmgohSjS?=
 =?us-ascii?Q?NutI2luuZK/3QGWJVf8btL3zk0s80+S1RPFXgK75FqhMTSyhIFB9RwjKvhwf?=
 =?us-ascii?Q?baAJcBE052T3ZOOGHnKzY5gbQIsE6ylDfpXUGfG4M0eR72nMQ6O3cGESfUtI?=
 =?us-ascii?Q?83YsWTCY8JdlczDzgUXkVRVWc7ColUZYsFHfTd36nJ19TBUf5ChT1w=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xwCbISZS1SEeL/hssGHWecuY+JUH//U1RTkffgvLBS5Qh9Voh4YC+WKmgfs4?=
 =?us-ascii?Q?4TR3jahAElL0savek5FnaIt6lPr+aQdV47UwexixSTsVC2XVSV3sFk2u8r6u?=
 =?us-ascii?Q?69qmkAj9Fb/XFR1DdnWI6G8z0EaSMA0Coy6DqNPGrju9nAE3wubzlk8KP+8q?=
 =?us-ascii?Q?S5o7Hd+GafxXqJb7gWzjeCQ87y8vLvTRTHFCX5dxNvJpJkEJy1iwODmUx4JQ?=
 =?us-ascii?Q?ThoaPNpWxABmQzv2l6bqpTCO2Zzp6V9mLTCH4YBHrTs3A7sdxL/IYjx5+0hb?=
 =?us-ascii?Q?QEYeXIYC/25dXTKdqZVz6/zgHtzHA8ADh7bJxU7AiXszgwMgCZMQcbL6pZTr?=
 =?us-ascii?Q?uPX4lWDWOq1aPVxa2H99C0LxQ1RE942yBVynzxMUhJtoRJtn1rSLA8RDDEe+?=
 =?us-ascii?Q?ck1KaVw3repSTCFEDhVLFxCENYIZuFtbyLPrzPQ1+hPYVybVWpz3h5aqzvsG?=
 =?us-ascii?Q?7k2kYoVFqKy9pQH8H9xwxC/rj2fWSpM5fmkI4O/pT0lLZdS1YBjYY/HedVPt?=
 =?us-ascii?Q?7I/pXTjpql/VLJU4R1+gtgSArL8VeBcXa2jbslk9V9KGiT32crRFzhuWRFre?=
 =?us-ascii?Q?F8LSP4Ug+AIGKApiZ/8Or32w7xDumZsSTB4GGyNj64VJB6MBEv/lz5toN5cP?=
 =?us-ascii?Q?BX+iTKr8UIWWSH6Ci2fyUpmIENiNLneRVAdgN3RSUo5jQ+3lCJqAY836VISP?=
 =?us-ascii?Q?u/GO7r4sgl5vFK0CGDXN5FVClZa8g9p4lHe2FRywV3gVxmERHnr5Ub97VhaG?=
 =?us-ascii?Q?mzfuU9kyq8EaJbxZ/Ew3d+K3rdhKlGKdVqKFD48ThMG+A7n2B/KJg4PIf3mh?=
 =?us-ascii?Q?C//uqGKHTKsNInCqhbMRPubSWTla32RbvgQ3U96d8xu3Bpl92K1iPN/LhONb?=
 =?us-ascii?Q?SIQkIfL317OkXH4SgVmxqSmtJf2y96wioaTC3RDX9I74s8KBIvhEho23WLH+?=
 =?us-ascii?Q?+E3njZiF1y3ANXL4JvIdaxBxKaE/+FIN4FRjvBP1iX9NvgHJgxU41JBA/O8A?=
 =?us-ascii?Q?+HZGLpvARrQzXcw+eY1Dgvg029GK4RnL4EkGVhKeFyZHV5M89+H2+04cZgAr?=
 =?us-ascii?Q?aJSrWeXwvRaQo3eiWIYsdPAThqFri0XKqg8AVnlSjZ9Lvdd2VEvQdI9sF1tF?=
 =?us-ascii?Q?+ZCxXIr1HyDCizYJB4hXuBPKzBU+YS/mlqdkyk/7Znplo+iV6G2flloOJ+PS?=
 =?us-ascii?Q?hWkGyCgnnN4ZEy+uhLuA7hSJ7PEC1epTfj/sDTmWqKr/XCHu2nA/AZyHIWoy?=
 =?us-ascii?Q?5HFSVAUjTtQmaQnROhCttPgVf7wzfPnu2ZEKFEqERrBHkDYTYuGOINKHztZa?=
 =?us-ascii?Q?TvZDB8eIrj2qdpdZzOA9nu77UgxJ8Xbla4cMTtjieAy3PCpsQZjx4/PAeBDW?=
 =?us-ascii?Q?IvvrwYAssTvox4s5+LOfPVmYlP3U8mVDc+OD4XhSQIyFEvzUjamh6Ltkflcj?=
 =?us-ascii?Q?jcGu6dNDTOwiJBxUlz2YG720LePLyh9n6lZiTqvf8e4P5YADOEWTzaRssnod?=
 =?us-ascii?Q?8PPEL4B6zKDctNwxcFu7F4obTv/nvc+EN22FwiTHqrY/M0tbT5/xuvKB2hvn?=
 =?us-ascii?Q?3/QOL+rq0yzoqTjO/lSO1eIHkOs27pZRkYV8uPan?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: wNlnlZjvm2dizuNdBcskd7T3mshkIHQX4xyUPQxuLGzlcoxvZ4104aXz2b6CHFHLRtv9tkAwGHXAAnNHA53mGCkwjTOSakQscEp5Y8nj879f5Zzs+mXbxr3fUpsKZUlxda/IOwb9w2ofN8+iE9LCCFJ+QT8I0Fq6VeOf+50eXTmfypy0E7E5U607pZdOitSJEzZ8RMdKPBiByo1+kX9v17PZb49Y8a3VF5j8xn5Gr7c+iTlBynR1zlmCFXXIQmrqTyJ5LkYE2IjsYDfQMBwOZq6oRLY2sz7f3WgUAMTkk2MhJwC4Le/JUbkqXSeJv9qyJP9Ny8qo1NEFiKgOV3ls4g5jOY/rNfYgW3VtKXYq0EilgoNmfUk+W2gzX3FeVM/++mh4op4trcd2pHsivib+LaljA6u4UxeWojRIjqJPFtHHicOdx3GfnyRBIN8g4W1dzvKQQchKoKo32qisYAO9mrkd0NeGHFnslTgqops87NGKQyL6irUWQCylnZVT8PTNopAqcxCRPMWCTuyEjBk2H9Si5CFR7xB1RupzqRWRUXqsw9Dl8L0a6w7rJbssZUMp0is64PzkYscxmsd7x/trQuip7Hls/YrJzkPlC8jgCho=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6fb8e9cb-95c7-40c2-2d8c-08de0a3d2c69
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Oct 2025 09:44:59.1743
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: nR9wOOuBv9TIKA2jP72poJdqLnY6D7/2Cw153UkRiPQOImMsHZEvk0afif89yWT6Aiq4DHMsZ+0VKvsSSXQO+g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA0PR10MB6722
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-13_03,2025-10-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 phishscore=0 bulkscore=0 mlxlogscore=999 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510020000
 definitions=main-2510130046
X-Proofpoint-GUID: Gb6SvwaZlsXadu62cuLNiq1KwGqR9ATK
X-Proofpoint-ORIG-GUID: Gb6SvwaZlsXadu62cuLNiq1KwGqR9ATK
X-Authority-Analysis: v=2.4 cv=QfNrf8bv c=1 sm=1 tr=0 ts=68ecca1f cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8
 a=3Y2S3A5N9a6kCw_Y0SMA:9 a=CjuIK1q_8ugA:10 a=cPQSjfK2_nFv0Q5t_7PE:22
 a=HhbK4dLum7pmb74im6QT:22 a=pHzHmUro8NiASowvMSCR:22 a=Ew2E2A-JSTLzCXPT_086:22
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDExMDAxNyBTYWx0ZWRfX59j1Dgh30DXC
 FrRMZ35esv+/hNdi1RJh1Yf5OiyaoPb8zn/08pxqtfeET8B3FIlgh/MiXM4XZR7fIJDiGDTiygW
 b/Cd9WAGzJI5bidH2iNbTAKAzbYPEJs8d6Xiil8Mr879nTbp2U5jOzTmmrrFiGEaQ3ChBN0Djkn
 sCGHK7d8Q5/fFWLVu+qqaWjbYOU0zSOfVGMZJi1LdmYufFddJPubgB/0FQOQmF7509B0pQ3/Ncb
 nlXrkFJYKqwS68I/Dzc/yw0pWy0xO3lepvO/OVwcDVsc+4IN9LU7uFLa2loJs38yY1VgtO64NWc
 7iNnmAOfBn1FgfBhOkCv9YO9US/sf4NNmatog8Fshyw3GzzE1ypZdEd85kyaXNeIktg6mL4lO59
 sDLKW9ygzNdgrzNIyxCVLEXyHIo0pw==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=rKDxCrQj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=b284yC46;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

On Fri, Oct 10, 2025 at 04:39:12PM +0800, kernel test robot wrote:
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG_kmalloc-#(Not_tainted):Freepointer_corrupt" on:
> 
> commit: af92793e52c3a99b828ed4bdd277fd3e11c18d08 ("slab: Introduce kmalloc_nolock() and kfree_nolock().")
> https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git
> 
> [test failed on      linus/master ec714e371f22f716a04e6ecb2a24988c92b26911]
> [test failed on linux-next/master 0b2f041c47acb45db82b4e847af6e17eb66cd32d]
> [test failed on        fix commit 83d59d81b20c09c256099d1c15d7da21969581bd]
> 
> in testcase: trinity
> version: trinity-i386-abe9de86-1_20230429
> with following parameters:
> 
> 	runtime: 300s
> 	group: group-01
> 	nr_groups: 5
> 
> config: i386-randconfig-012-20251004
> compiler: gcc-14
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202510101652.7921fdc6-lkp@intel.com
> 
> [   66.142496][    C0] =============================================================================
> [   66.146355][    C0] BUG kmalloc-96 (Not tainted): Freepointer corrupt
> [   66.147370][    C0] -----------------------------------------------------------------------------
> [   66.147370][    C0]
> [   66.149155][    C0] Allocated in alloc_slab_obj_exts+0x33c/0x460 age=7 cpu=0 pid=3651
> [   66.150496][    C0]  kmalloc_nolock_noprof (mm/slub.c:4798 mm/slub.c:5658)
> [   66.151371][    C0]  alloc_slab_obj_exts (mm/slub.c:2102 (discriminator 3))
> [   66.152250][    C0]  __alloc_tagging_slab_alloc_hook (mm/slub.c:2208 (discriminator 1) mm/slub.c:2224 (discriminator 1))
> [   66.153248][    C0]  __kmalloc_cache_noprof (mm/slub.c:5698)
> [   66.154093][    C0]  set_mm_walk (include/linux/slab.h:953 include/linux/slab.h:1090 mm/vmscan.c:3852)
> [   66.154810][    C0]  try_to_inc_max_seq (mm/vmscan.c:4077)
> [   66.155627][    C0]  try_to_shrink_lruvec (mm/vmscan.c:4860 mm/vmscan.c:4903)
> [   66.156512][    C0]  shrink_node (mm/vmscan.c:4952 mm/vmscan.c:5091 mm/vmscan.c:6078)
> [   66.157363][    C0]  do_try_to_free_pages (mm/vmscan.c:6336 mm/vmscan.c:6398)
> [   66.158233][    C0]  try_to_free_pages (mm/vmscan.c:6644)
> [   66.159023][    C0]  __alloc_pages_slowpath+0x28b/0x6e0
> [   66.159977][    C0]  __alloc_frozen_pages_noprof (mm/page_alloc.c:5161)
> [   66.160941][    C0]  __folio_alloc_noprof (mm/page_alloc.c:5183 mm/page_alloc.c:5192)
> [   66.161739][    C0]  shmem_alloc_and_add_folio+0x40/0x200
> [   66.162752][    C0]  shmem_get_folio_gfp+0x30b/0x880
> [   66.163649][    C0]  shmem_fallocate (mm/shmem.c:3813)
> [   66.164498][    C0] Freed in kmem_cache_free_bulk+0x1b/0x50 age=89 cpu=1 pid=248

> [   66.169568][    C0]  kmem_cache_free_bulk (mm/slub.c:4875 (discriminator 3) mm/slub.c:5197 (discriminator 3) mm/slub.c:5228 (discriminator 3))
> [   66.170518][    C0]  kmem_cache_free_bulk (mm/slub.c:7226)
> [   66.171368][    C0]  kvfree_rcu_bulk (include/linux/slab.h:827 mm/slab_common.c:1522)
> [   66.172133][    C0]  kfree_rcu_monitor (mm/slab_common.c:1728 (discriminator 3) mm/slab_common.c:1802 (discriminator 3))
> [   66.173002][    C0]  kfree_rcu_shrink_scan (mm/slab_common.c:2155)
> [   66.173852][    C0]  do_shrink_slab (mm/shrinker.c:438)
> [   66.174640][    C0]  shrink_slab (mm/shrinker.c:665)
> [   66.175446][    C0]  shrink_node (mm/vmscan.c:338 (discriminator 1) mm/vmscan.c:4960 (discriminator 1) mm/vmscan.c:5091 (discriminator 1) mm/vmscan.c:6078 (discriminator 1))
> [   66.176205][    C0]  do_try_to_free_pages (mm/vmscan.c:6336 mm/vmscan.c:6398)
> [   66.177017][    C0]  try_to_free_pages (mm/vmscan.c:6644)
> [   66.177808][    C0]  __alloc_pages_slowpath+0x28b/0x6e0
> [   66.178851][    C0]  __alloc_frozen_pages_noprof (mm/page_alloc.c:5161)
> [   66.179753][    C0]  __folio_alloc_noprof (mm/page_alloc.c:5183 mm/page_alloc.c:5192)
> [   66.180583][    C0]  folio_prealloc+0x36/0x160
> [   66.181430][    C0]  do_anonymous_page (mm/memory.c:4997 mm/memory.c:5054)
> [   66.182288][    C0]  do_pte_missing (mm/memory.c:4232)

So here we are freeing an object that is allocated via kmalloc_nolock().
(And before being allocated via kmalloc_nolock(), it was freed via
kfree_rcu()).

> [   66.183062][    C0] Slab 0xe41bfb28 objects=21 used=17 fp=0xedf89320 flags=0x40000200(workingset|zone=1)
> [   66.184609][    C0] Object 0xedf89b60 @offset=2912 fp=0xeac7a8b4

fp=0xeac7a8b4

the address of the object is: 0xedf89b60.

0xedf89b60 - 0xeac7a8b4 = 0x330f2ac

If FP was not corrupted, the object pointed to by FP is
too far away for them to be in the same slab.

That may suggest that some code built a list of free objects
across multiple slabs/caches. That's what deferred free does!

But in free_deferred_objects(), we have:
> /*
>  * In PREEMPT_RT irq_work runs in per-cpu kthread, so it's safe
>  * to take sleeping spin_locks from __slab_free() and deactivate_slab().
>  * In !PREEMPT_RT irq_work will run after local_unlock_irqrestore().
>  */
> static void free_deferred_objects(struct irq_work *work)
> {
>         struct defer_free *df = container_of(work, struct defer_free, work);
>         struct llist_head *objs = &df->objects;
>         struct llist_head *slabs = &df->slabs;
>         struct llist_node *llnode, *pos, *t;
>
>         if (llist_empty(objs) && llist_empty(slabs))
>                 return;
>
>         llnode = llist_del_all(objs);
>         llist_for_each_safe(pos, t, llnode) {
>                 struct kmem_cache *s;
>                 struct slab *slab;
>                 void *x = pos;
>
>                 slab = virt_to_slab(x);
>                 s = slab->slab_cache; 
>    
>                 /*
>                  * We used freepointer in 'x' to link 'x' into df->objects.
>                  * Clear it to NULL to avoid false positive detection
>                  * of "Freepointer corruption".
>                  */
>                 *(void **)x = NULL;
>
>                 /* Point 'x' back to the beginning of allocated object */
>                 x -= s->offset;
>                 __slab_free(s, slab, x, x, 1, _THIS_IP_);
>         }
>

This should have cleared the FP before freeing it.

Oh wait, there are more in the dmesg:
> [   67.073014][    C1] ------------[ cut here ]------------
> [   67.074039][    C1] WARNING: CPU: 1 PID: 3894 at mm/slub.c:1209 object_err+0x4d/0x6d
> [   67.075394][    C1] Modules linked in: evdev serio_raw tiny_power_button fuse drm drm_panel_orientation_quirks stm_p_basic
> [   67.077222][    C1] CPU: 1 UID: 0 PID: 3894 Comm: sed Tainted: G    B   W           6.17.0-rc3-00014-gaf92793e52c3 #1 PREEMPTLAZY  2cffa6c1ad8b595a5f5738a3e143d70494d8da79
> [   67.079495][    C1] Tainted: [B]=BAD_PAGE, [W]=WARN
> [   67.080303][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
> [   67.085915][    C1] EIP: object_err+0x4d/0x6d
> [   67.086691][    C1] Code: 8b 45 fc e8 95 fe ff ff ba 01 00 00 00 b8 05 00 00 00 e8 46 1e 12 00 6a 01 31 c9 ba 01 00 00 00 b8 f8 84 76 db e8 b3 e1 2b 00 <0f> 0b 6a 01 31 c9 ba 01 00 00 00 b8 e0 84 76 db e8 9e e1 2b 00 83
> [   67.089537][    C1] EAX: 00000000 EBX: c10012c0 ECX: 00000000 EDX: 00000000
> [   67.090581][    C1] ESI: aacfa894 EDI: edf89320 EBP: ed7477b8 ESP: ed7477a0
> [   67.091578][    C1] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00010046
> [   67.092767][    C1] CR0: 80050033 CR2: b7fa58c8 CR3: 01b5b000 CR4: 000406d0
> [   67.093840][    C1] Call Trace:
> [   67.094450][    C1]  check_object.cold+0x11/0x17
> [   67.095280][    C1]  free_debug_processing+0x111/0x300
> [   67.096076][    C1]  free_to_partial_list+0x62/0x440
> [   67.101664][    C1]  ? free_deferred_objects+0x3e/0x110
> [   67.104785][    C1]  __slab_free+0x2b7/0x5d0
> [   67.105539][    C1]  ? free_deferred_objects+0x3e/0x110
> [   67.106362][    C1]  ? rcu_is_watching+0x3f/0x80
> [   67.107090][    C1]  free_deferred_objects+0x4d/0x110

Hmm... did we somehow clear wrong FP or is the freepointer set again
after we cleared it?

-- 
Cheers,
Harry / Hyeonggon

> [   67.107872][    C1]  ? free_deferred_objects+0x3e/0x110
> [   67.108728][    C1]  irq_work_single+0x65/0xa0
> [   67.109517][    C1]  ? exc_nmi_kvm_vmx+0x10/0x10
> [   67.110312][    C1]  irq_work_run_list+0x49/0x70
> [   67.111598][    C1]  irq_work_run+0x13/0x30
> [   67.112335][    C1]  __sysvec_irq_work+0x31/0x180
> [   67.113193][    C1]  sysvec_irq_work+0x20/0x40
> [   67.113929][    C1]  handle_exception+0x130/0x130
> [   67.114690][    C1] EIP: default_send_IPI_self+0x46/0x90
> [   67.115541][    C1] Code: 10 74 14 90 f3 90 8b 0d 44 12 21 db 8b 91 00 d3 ff ff 80 e6 10 75 ed 0d 00 00 04 00 8b 1d 44 12 21 db 8d 93 00 d3 ff ff 89 02 <5b> 5d 31 c0 31 d2 31 c9 c3 90 bb e8 03 00 00 eb 1d 2e 8d b4 26 00
> [   67.118357][    C1] EAX: 000400f6 EBX: fffff000 ECX: 00000000 EDX: ffffc300
> [   67.119453][    C1] ESI: e3a744b4 EDI: 00000000 EBP: ed74798c ESP: ed747988
> [   67.120512][    C1] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00000206
> [   67.122323][    C1]  ? exc_nmi_kvm_vmx+0x10/0x10
> [   67.123079][    C1]  ? exc_nmi_kvm_vmx+0x10/0x10
> [   67.123844][    C1]  ? default_send_IPI_self+0x46/0x90
> [   67.124887][    C1]  arch_irq_work_raise+0x2d/0x40
> [   67.136148][    C1]  __irq_work_queue_local+0x7d/0xf0
> [   67.137164][    C1]  irq_work_queue+0x31/0x80
> [   67.137861][    C1]  defer_free+0x88/0xc0
> [   67.138648][    C1]  kfree_nolock+0x28e/0x310
> [   67.139653][    C1]  __free_slab+0x255/0x270
> [   67.140674][    C1]  free_slab+0x3f/0xe0
> [   67.141574][    C1]  free_to_partial_list+0x1df/0x440
> [   67.142787][    C1]  __slab_free+0x2b7/0x5d0
> [   67.147520][    C1]  ? shrink_node+0x2a7/0x310
> [   67.149260][    C1]  ? shrink_slab+0x266/0x4a0
> [   67.151002][    C1]  ? shrink_slab+0x266/0x4a0
> [   67.151677][    C1]  ? shrink_node+0x2a7/0x310
> [   67.153337][    C1]  kfree+0x6e8/0x7c0
> [   67.154927][    C1]  ? shrink_node+0x2a7/0x310
> [   67.155561][    C1]  ? shrink_node+0x2a7/0x310
> [   67.157219][    C1]  shrink_node+0x2a7/0x310
> [   67.158828][    C1]  do_try_to_free_pages+0xdc/0x460
> [   67.159562][    C1]  try_to_free_pages+0xf5/0x150
> [   67.161292][    C1]  __alloc_pages_slowpath+0x28b/0x6e0
> [   67.163233][    C1]  __alloc_frozen_pages_noprof+0x311/0x360
> [   67.165155][    C1]  __folio_alloc_noprof+0x15/0x30
> [   67.166890][    C1]  folio_prealloc+0xa9/0x160
> [   67.167616][    C1]  ? __vmf_anon_prepare+0x70/0x100
> [   67.169438][    C1]  do_cow_fault+0x4b/0x1f0
> [   67.171212][    C1]  ? rcu_is_watching+0x3f/0x80
> [   67.172994][    C1]  do_pte_missing+0xe5/0x380
> [   67.173688][    C1]  ? mt_find+0x154/0x370
> [   67.175381][    C1]  handle_pte_fault+0x20a/0x360
> [   67.177160][    C1]  handle_mm_fault+0x1a4/0x440
> [   67.178905][    C1]  do_user_addr_fault+0x1e3/0x440
> [   67.179640][    C1]  exc_page_fault+0x59/0x1e0
> [   67.182691][    C1]  ? pvclock_clocksource_read_nowd+0x190/0x190
> [   67.183626][    C1]  handle_exception+0x130/0x130
> [   67.185384][    C1] EIP: clear_user+0x64/0xb0
> [   67.187106][    C1] Code: 00 00 b8 50 2b 87 db e8 0a 7b fe fe ba 42 00 00 00 b8 53 61 13 db e8 9b 1f 16 ff 89 da 83 e2 03 c1 eb 02 89 d9 31 c0 8d 76 00 <f3> ab 89 d1 f3 aa 8d 76 00 5a 89 c8 8d 65 f8 5b 5f 5d 31 d2 31 c9
> [   67.192838][    C1] EAX: 00000000 EBX: 000001ce ECX: 000001ce EDX: 00000000
> [   67.194893][    C1] ESI: ebb68e60 EDI: b7fa58c8 EBP: ed747e40 ESP: ed747e34
> [   67.196892][    C1] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00010246
> [   67.199084][    C1]  ? pvclock_clocksource_read_nowd+0x190/0x190
> [   67.201015][    C1]  ? pvclock_clocksource_read_nowd+0x190/0x190
> [   67.202993][    C1]  ? clear_user+0x64/0xb0
> [   67.203649][    C1]  elf_load+0x1e1/0x210
> [   67.205361][    C1]  load_elf_interp+0x358/0x400
> [   67.207199][    C1]  load_elf_binary+0xaac/0xdf0
> [   67.209031][    C1]  ? _raw_read_unlock+0x58/0x90
> [   67.210775][    C1]  exec_binprm+0x18b/0x3d0
> [   67.211490][    C1]  bprm_execve+0xc7/0x1b0
> [   67.213251][    C1]  do_execveat_common+0x1b8/0x1f0
> [   67.215058][    C1]  __ia32_sys_execve+0x2a/0x40
> [   67.216813][    C1]  ia32_sys_call+0xf28/0xf90
> [   67.217503][    C1]  do_int80_syscall_32+0x53/0x2c0
> [   67.219303][    C1]  entry_INT80_32+0xf0/0xf0
> [   67.221070][    C1] EIP: 0xb7fba092
> [   67.221648][    C1] Code: Unable to access opcode bytes at 0xb7fba068.
> [   67.223619][    C1] EAX: ffffffda EBX: 02380764 ECX: 023884c8 EDX: 02388504
> [   67.226356][    C1] ESI: 02380764 EDI: 023884c8 EBP: bfe2b794 ESP: bfe2b674
> [   67.229021][    C1] DS: 007b ES: 007b FS: 0000 GS: 0000 SS: 007b EFLAGS: 00000292
> [   67.235135][    C1] irq event stamp: 0
> [   67.235815][    C1] hardirqs last  enabled at (0): [<00000000>] 0x0
> [   67.236788][    C1] hardirqs last disabled at (0): [<d973f5a4>] copy_process+0x6f4/0x18d0
> [   67.239586][    C1] softirqs last  enabled at (0): [<d973f5ae>] copy_process+0x6fe/0x18d0
> [   67.241811][    C1] softirqs last disabled at (0): [<00000000>] 0x0
> [   67.243308][    C1] ---[ end trace 0000000000000000 ]---
> [   67.244517][    C1] FIX kmalloc-96: Object at 0xedf89320 not freed
> [   66.184609][    C0]
> [   66.185960][    C0] Redzone  edf89b40: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
> [   66.187388][    C0] Redzone  edf89b50: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
> [   66.189695][    C0] Object   edf89b60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
> [   66.191175][    C0] Object   edf89b70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
> [   66.192701][    C0] Object   edf89b80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
> [   66.194259][    C0] Object   edf89b90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
> [   66.195753][    C0] Object   edf89ba0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
> [   66.196836][  T248] sed invoked oom-killer: gfp_mask=0x140dca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO|__GFP_COMP), order=0, oom_score_adj=-1000
> [   66.197239][    C0] Object   edf89bb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
> [   66.197395][    C0] Redzone  edf89bc0: cc cc cc cc                                      ....
>
> [   66.197402][    C0] Padding  edf89bf4: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a              ZZZZZZZZZZZZ
> [   66.197406][    C0] Disabling lock debugging due to kernel taint

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aOzKEsav2RubINEO%40hyeyoo.
