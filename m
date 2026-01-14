Return-Path: <kasan-dev+bncBC37BC7E2QERB66DTTFQMGQET64ESEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 61A66D1C81B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 05:56:29 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-890805821c0sf293339546d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 20:56:29 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768366588; cv=pass;
        d=google.com; s=arc-20240605;
        b=FTlqLl7ToVkHjaHlvxrBN/XoCBY1xBcgik2IblqDEi1i/fI/QUb6+6Cb4BQb9jr/gI
         nriNYH4NQeEODFrieguSiVyIixVrZJSOjXZGjaolySBw/+3S3mh6qtckQm2indJatZS5
         9TFUCbQsy244ov3qHjMqUVv3THvKRGziCDGB8j/hBx1NCHswwCqSePeH6VgbFKDtTjBG
         fk94vMpclxGUAT/R+2vLr+1Cld8VCP9njxqRYFbIA5cTkA3wP0BYfdw8KkbrFDcNG1OZ
         l6Joqndn/E1FIG8P/5nqbtQoH6p1jypStw0VhjMtzi71Vfgnks/YEqrfyxu8R3Sy7mdw
         7YpA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=vY8VXOG8ki7x3nmQIuGhB6dp4BC5PjRBz/GZxS/KklE=;
        fh=AaghGTf05DFYYk58SEvOBh3UjzjmSuYQn1pvOu8a93o=;
        b=Occ5IeyBDELGYlrsQuGgUicMxkaMG25QjQE5HRL4e8nGNdm8beBOsHQhHwdk6tkVE4
         Gl1OuqYXHHXEne2e0Kf3RHoMD91JZ8MRXWwSS6l5lM9e1bpYhJZojJAKHCKchICLIgXE
         FPC4V4DIcmBjNcnOgp/TMQ2KYEwRsdDgCKaI+6S4na4mLxUIrvqF+xlcFLXhTN/MYnXR
         RdS6PxS/j0GF/ahIMog6nYMbkNdpBkIF/Ej4vdVMv0vh5VZ05MhXCf0YJznP+G3LOXVB
         LF7x+hcwY6F220y/2xlxq9aS369itu1e+noDZbZ15WCDYAgt/AIcLxDZR5Ahho5HeNk2
         kqbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BobCP4eT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=D+9ZvI3S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768366588; x=1768971388; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vY8VXOG8ki7x3nmQIuGhB6dp4BC5PjRBz/GZxS/KklE=;
        b=vq/EooU8gE6QNlaibH0L8QM6KiQpaQ0qZRC8tJ2VVW2k33iVI2rm/Vz/P55gEVYNNR
         LpTOI+RYOAbdiA6EryBZxsnK+RWx5Z9Mroou4chiEZ0hspfXjqPSjDPdX41EB19KKkoK
         qv7PcrMTn6/SjdT2I+46ufOPcmwh6vQqZDGC51X8GSuSldLqU9djfwxC169SEUxp17Ls
         +fC+h49G5efRp1HOoEVgJ1xkuoREA1ONVP4gdLpjVdtoLHH2X93MzAl7vTuk/F/U0y94
         x7TAdmMyic6yIG1JTbGOv9WPifiS6DfACOXlUM0BELuNRqqo5uKf2IgxNPWzkcvyquaP
         Z0zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768366588; x=1768971388;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vY8VXOG8ki7x3nmQIuGhB6dp4BC5PjRBz/GZxS/KklE=;
        b=qdvbs8p6UXJ/k6ZoWX20cM2gBrXjfxqAhM+f9SMhzoRZKRjF1oYPP6LhhsoJp50TPR
         lmMR1XkYaY3zA/kf7p1xuHRFcSYUeid4MTmu7rSSXwNtPQQIUzzkWV5rExU+DsrTjB1O
         8FYWVNSbpSCT/H81Jx1csF1emnpwnRwYPnN/sVMzh0riAvCGRY8elVFuvzf0rQ2dWAAa
         sjXv9zaVH6ZHhtkeA1Vs+YiX+C2T9nT2/mGwnZi3sMLWlQMY6IBff6fMWa1qxHpany3X
         c4XXtD0sDJk+ptz8p0XmJF7OVCxL6N/YvWNoX0nQqdECIj54bJ+dT8qHdiBk+EMzf3mO
         2EvA==
X-Forwarded-Encrypted: i=3; AJvYcCUokrlvdkG+V65hB4E5dyBX8+gpYBIbI8omj+Vih0N5jzItmXCfg+/dx7/lX4zehyh9w6rhPQ==@lfdr.de
X-Gm-Message-State: AOJu0YydTF5YyVWk5abLmT75QPHx0J1Pf/cwJwPPFZcKZfKy9FlkY41s
	ZdLEsmFSrXT3ceU3y37IcYY3k/J2t+pXNzzY3n67WbGp3P8MyYBKos8R
X-Received: by 2002:ad4:4ee3:0:b0:890:247e:dce2 with SMTP id 6a1803df08f44-8927431b6b2mr17851426d6.1.1768366587792;
        Tue, 13 Jan 2026 20:56:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EgnJujlKXlPzb3ogINmxnXbaWIqA6QYhJsHrgHu/2w4A=="
Received: by 2002:ad4:5f88:0:b0:882:7510:5ec3 with SMTP id 6a1803df08f44-890756cadd3ls195770236d6.2.-pod-prod-04-us;
 Tue, 13 Jan 2026 20:56:27 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVtE3L+Z93DeOX3aOlDRcgFyueeitx0i4g6QkLZIiIU5oSNs6YvL70eHESW+X5LOPk1H0Rt+5iSINQ=@googlegroups.com
X-Received: by 2002:a05:6214:2623:b0:81b:23d:55a8 with SMTP id 6a1803df08f44-89274408d21mr18657796d6.59.1768366586922;
        Tue, 13 Jan 2026 20:56:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768366586; cv=pass;
        d=google.com; s=arc-20240605;
        b=kaVa3ackthKr8m6x+TGvggEECwQmmu7qI0y7SRHsP/SrQsYk4XsktMXPejCVN188gj
         0JyiXk3fW+cPRIFp86sUcJOe2IQ067zdyJv27mwgE1NiJkcAclxYIHrO6bdlG/NWJLuf
         Tw7rMONB0/7a8cyEFEqUfmbecrsdeH8B5B8xDWGOL9AxYtOt0ouOzZ7Rf90hqXH80ghw
         G+goTLShk5siVfwdGrGkT02h8hrvT9LbGEedPHUJLzugLv21y7dOMA6Bct+MHPEyGy5v
         vDJE03sLyEFmejVfspOvRGabCX8/2RBbO1NzuqWPGPL9/o5t1HXKVopUNL6OXCGxwHWN
         QGBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=3/RTBrbaKeEwYDH/4MeKnnwSSPOM/dUfy4keA9S4lAg=;
        fh=kceCFzMIgve5i5+gz0p/EEtyI1JcVUwOSRB4LdjPUvg=;
        b=hTWPrJpyhbYeSr3kBIw71wusAiSHuz/PW1uZaTM20Fq/QqrL1YpM7zsgQ61riHKfTO
         FjXf0iF6gpFirXpucSgBNZ4MaePZYof0j/ia4Cyrfxu/aNIjyEkjcGl+tsS7l3+Awp/A
         BAuqpKtiBPNp86qTshwKttEBCGgsgFKrz3AEKAYjxUvwnEOBZ2CSCc2BAfrHsu066iS7
         Pt4rG7uybgAJhkWqHQ9+gaXt6nRbp1Ug2EalHvUfEfMYBSCy4wt5Njaq1otpiWu7Tr+l
         xLwaknVFyjG+EEhV7stm6ZwEAVuKxGbzsayTRBhuEF8bwKyBBW0HVY+qhAJtf0BwIxC5
         4vSA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BobCP4eT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=D+9ZvI3S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89082cf5c46si6126876d6.7.2026.01.13.20.56.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 20:56:26 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60DGDcCg3333478;
	Wed, 14 Jan 2026 04:56:24 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bkrp8mpkv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 14 Jan 2026 04:56:24 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60E2SQQ3004635;
	Wed, 14 Jan 2026 04:56:23 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011015.outbound.protection.outlook.com [52.101.62.15])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd79jcr2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 14 Jan 2026 04:56:23 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=KI8UmTwBs8xEwIZNFXGrcc47Ymj+aPZLsAJ0DLJL3PAbloDXmSCWlXvee//+iYNuxGWAdmkA9dQ9VDOAGsHvk8P5p+DS0dsaMjqEMQpU15eGSJoKQvuFkhIjXSBwKqE4/b+WwVvhWwJxLCp55O/N+89P3QfVNebV79VeOveZEgv565yqkkKcX65R6qugcEpgSbYm7uKVpHygE6ixEceuY2HwaC2b0T0NarM3Y6qpfEfLO2ZHGLBiaQQSBgF6j7WU0RdKOPa8b2JpWBqToGRWKaR+QQJOABo8BEG9XCitj+1+JcFxXvX0raYItWuyALotUts8Ko26/ra940KLG5aZXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3/RTBrbaKeEwYDH/4MeKnnwSSPOM/dUfy4keA9S4lAg=;
 b=KpjgDuzApqTlof3qjTU/sGhkEBdtapf+Fg7ZVwxk13AgNV5sPiDQNzrk0HO0mx+dkKh5J4n7ifRP/dXRM+hiCxNYs8K4rN74WKRNUWgNxmGb4bTeM37gdC8ATjCRPziggbejeOEJ2BTnRBzlRM1HoLuu7sRPi6u8X1kLrE/TMN9A1ngfMwmrFi+Z8EQ2REj44a0e4KzQVyH5+wwQ+PpY9GU5hyvvPGZIRsJKtRkPqAo+mgAJDXPFaxL2NFQyJnhFQDq/z2eD/PBTIjktRiCF6ahUybGHX8Mp3Fq/MSC6C/abOM/kayZA9uKEHAMgp52PorfCAMF7CmXm8Fv3pHJtZg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB7218.namprd10.prod.outlook.com (2603:10b6:930:76::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.7; Wed, 14 Jan
 2026 04:56:20 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9499.005; Wed, 14 Jan 2026
 04:56:20 +0000
Date: Wed, 14 Jan 2026 13:56:12 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com,
        kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
Message-ID: <aWch7G1ovZtHVadM@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
X-ClientProxiedBy: SEWP216CA0141.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2be::8) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB7218:EE_
X-MS-Office365-Filtering-Correlation-Id: e6c8be54-f28a-434f-7fec-08de532941e7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?MB17o+6cdv7IcId4Qo+gtl1pn71OFk+LNnAYQl9yCTaGb0JDNGhNlpmhMG4k?=
 =?us-ascii?Q?H8PSmbIHhCo8+FMCVLad7t1wuY3hmKnjoIIEBQPzGMkSzBa8nybTLyDgEe2c?=
 =?us-ascii?Q?yIpdGxvpBCvQa8Aq5LwBnJlJ6yoE20QBFrGTH+u2n9aI6dQ3ByV+UGz/h1te?=
 =?us-ascii?Q?ycFI0vBJOZfB74J1+W+B6GDmOERk3bpw4WfcYP1TfSK52vVFIlBHTRJQj90R?=
 =?us-ascii?Q?ce5uxiswo/qWIUycGiVOfXSPuf6CsseRR60vi3eq+77mgjdouBVkyVg8/HPF?=
 =?us-ascii?Q?DHS5a9MVa7DZdbmA2/JX2118MzoD82yUfpaTC0ku9WbxmCA8XlpyHcI2Kdq3?=
 =?us-ascii?Q?Zq0y6ZirFDk6rNKSVYnMBaMqtCs7WqE4hf3/tlrXylvvkAtg5oX5Ih5ReYD6?=
 =?us-ascii?Q?ehHiwl2ILqbB0THFI1fqwI5j0/V4OdbBBmeEuQqGmuHeMxcouM3776ylhRq9?=
 =?us-ascii?Q?fbt2vmsTG5xRxKdXfo8qwnK68hK68Z/kFARO+BKCCJtMcBtskdD67lp53K9D?=
 =?us-ascii?Q?jmJjOSf52bqrI9jbq2SUb5BCh/FkDO0oUAcsnmbex8NU0TCuzgW+LsiBeFZ1?=
 =?us-ascii?Q?PzT1ZmMcQEFprX5Zd7dB5ENOHLEM/MvUb7M5i0EwY8/+a2rykPOJ+bjw5Q/A?=
 =?us-ascii?Q?YdtI+4GN3xJA/scoK4G/gUt4DYdKP0GrOdyZ8D3vtlsrBLu1ZTit7h8RRNU1?=
 =?us-ascii?Q?54UoFd4+pW8HMN7iNjGK1Xj4y1u8HCcThLhvkRldYPHLY4Ih+A8qf7JvLmRJ?=
 =?us-ascii?Q?/eFv1xvtl2pI4xhrQtyJojMd1w+Wx8NIt+Nz5OrzKJN/QGhA0PoTUH5JDVlc?=
 =?us-ascii?Q?LEioRnqc7w43dLA8HHBvIPXsset/7AAAiTnB+U3yJLBQmvQPsAxNBjW4S8t+?=
 =?us-ascii?Q?8wZ4uIIl2b6GCazJ3cvf2MMS+2/IdXjSaoHFrnKipWhAP9qmRQbbd7xG3Di5?=
 =?us-ascii?Q?WEfhwVUBFnJ3uF9P1VzVTobLA8L2hzONJg3hW/dBiHRZ0xJNRpIlxKeTot0m?=
 =?us-ascii?Q?k/dEzzBiBVgF+COYUXmYb/whhGkOa+qu+fpU0u++a9vf+N0CMGoDbolmyIyl?=
 =?us-ascii?Q?pI+EwWjWHnf1pqWl6zxl3r9S01OoIN51VULvunX/fN0NLgCQSdZK647l4YuZ?=
 =?us-ascii?Q?g8cmMYpeXG3wH2RPIw5gs2bGFaVcGQtBlT+YEUeXjgH9ubDsdj9+BmgF/fDR?=
 =?us-ascii?Q?E2ObD5qrK5Au9awMbQHe81OQaqxZI52X54QbtU2Dc7uUuUUimb4GGH4uRIlz?=
 =?us-ascii?Q?tjFt9mvOx/5WfRmqOAw+zDV11Iaybv87V4cCQWgg7eJvn90dxNH7Nw/Nd6Yl?=
 =?us-ascii?Q?Pq+1c8BN5/PpSybPi3fEOBj1AVrXCPH6+/gZuT3iI5GPDMLXw/zWHKN+SJnD?=
 =?us-ascii?Q?ZsGQ5vQTzxuL6Y97/cISChZAH+8wS1NzceWGcmGEPhzJL3PCxoc9obwP4Hgr?=
 =?us-ascii?Q?JUU5UvZVuBBAIBkRVd2X/Hbs8ctrysV30WuZ6jwNj408wiU39BvMvg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?8G/+Dop5jrqA+ELuPyyi9Vg9BblW0WszvrlM61ud9uUWMqo+OmyfR0hs1kzq?=
 =?us-ascii?Q?tAf9N7YMC7PEYe2sl+vKZHZvjZkY4k1F7qkCcIs+FjSHpWP5UVv+IsDBqCeL?=
 =?us-ascii?Q?yWQiQbG8Q+KWYWU9/sENM2P84BfY8MHcWApYOzI8PjffF3z9ih6il0/hkkEr?=
 =?us-ascii?Q?6MJOTvsHdxikoZByXRR/yVvBYQ+LgyK6vQxDsFGQZOQ64ZEgfmUlbLdvS+zW?=
 =?us-ascii?Q?R8H33SzG3dcmGs3qsLLIk8GG8ud4lpCpzeY2sE4ny8HDIW++RhBIsAZwkrfK?=
 =?us-ascii?Q?DbGkFGWgwntFqqcha3RKC9Ei4ajHjhvh1f+mN/SPcLZeqkdckf2osXG9tCnI?=
 =?us-ascii?Q?mxG23EQjoYX4tmv3mxDjJaNeOSWnbua52sxvIM55rmzy9RgfZaTwmaqM6w58?=
 =?us-ascii?Q?rGCch3OoWEyFYK6mASueLGkHnEfdVMw6/51zumH6uNfUY5vbWBHeLrHUEs39?=
 =?us-ascii?Q?EWY8QFT49cd3KuTV9IuH+AFt2tO5PZW5v9UgyROOGhv8+agVeJ9gGWmmEso4?=
 =?us-ascii?Q?tGs8faIGacZYs5grjfTF6IAlX7cuQfJGuhwfAf301/eyCMQ2VVzj0EGoLWcB?=
 =?us-ascii?Q?qQ/OYyIXD7ikp8vfjr1tiUCUh3eKBF8Zn8Sj5b++Ny4WrMsMFjB7DlBLMBjc?=
 =?us-ascii?Q?dR+s61mgiJivt1DP5OLviQYikcFJcG1SBrhQg1/ycfZaTK7tPem1PyAt7+8c?=
 =?us-ascii?Q?VIhnuf2A5FK78dK8pzfhgR/wlVCbzYbIPzBesv7MkfUC7f3aoTFyxiZRYEV6?=
 =?us-ascii?Q?46KBR1evoIla0EFo3fE5B3UWsFCKGFfxHtTR4v5yueQqHclVIZBTTW98CTwW?=
 =?us-ascii?Q?iqKUKuJ0j99Btss42zotZWx6Hev5z1aMs28eM/fWCmEXQEbs8gTMF5ttnNGx?=
 =?us-ascii?Q?cB2B9tHk2e/jx5H2sby3QZkjswIDS7izBrwPtBuJfbzjj8tJak8KmMM4/+4h?=
 =?us-ascii?Q?oHdIxsU4STLsjYiUQEnmT7VOO7EEILn+FbK6chUZwq4bft3NvIyrGdZTL61w?=
 =?us-ascii?Q?fvayGrqg6QJXeRrRSeayNx0xC0eGYTCNZeMHPgWWor8jQ3FmwBelDrvkbcIm?=
 =?us-ascii?Q?grGtmLtNAYp6OUpriJJ9WUEM6UbMl6HYx2Ak5PNNxApUEkhcSkinS5PQ/uqh?=
 =?us-ascii?Q?WwjBgGjGaHU/fTCEFAxrROnnkHKxRu965RvGXeNIbigpmkQJ/8b2AWVIo6O2?=
 =?us-ascii?Q?wzvhdAD3EiqztLVE1w7RoGdLTgnSN/BI9SnDK/lIUuONNWNJmHb9fiXlJMU5?=
 =?us-ascii?Q?cWl/XI/U26m4Ml7B6/q1c08odmzaZwqms21YlO9MBXVuJqCssIzYs8AEN+nC?=
 =?us-ascii?Q?nmqIyuTTLE+rVHzAs3/v8voiPtO49hYCo9FKguk1JZdkRDCdxdCB1muVlKgs?=
 =?us-ascii?Q?O0XgG1oFdEkXsijSfkeY6dGOlGWGTooh858C3yL2uh+SonVu3od0aHVab19m?=
 =?us-ascii?Q?emOphtIEDOB/VCZNftveJmxpopLJ6ccYSM14WvNOPi9u5GZBXMB461//zMA0?=
 =?us-ascii?Q?L8wA5xudXrdeiQx4j+9Mycu4mM1CFmFtXQqxLX+rPK++JsEQmaxwnhMkMK5Y?=
 =?us-ascii?Q?q7Om0c6xB50DByRHNuUNfHi5HgYLH1pag3ROBgkX83vS5JQWIThFR8ROeBJM?=
 =?us-ascii?Q?SBoLFMuKQYKquIoQYNraxUsBvPHRkv1fA6MUEmO+YLCkGAaFFZTvH1wVE/Iv?=
 =?us-ascii?Q?oUGTWQtQ5C8r7bI9lrkEX7isHv6pIs+zx7tQJ1o5V5fKbFGWRCMwdRuNdOnO?=
 =?us-ascii?Q?kMGOiahdCg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: y6vW0wOzd9cykaadmp5apOt20uCbwQE1c7UlcP5a0uDQQUTI4fPiMs039U65NhhChw2p3UvHHOrJk7/FhfXc4UbiH1Mo39nda75AoM1VJA9rt6+a9nx+vzKtoL933/gYsiMqZ2+/tCBG4H6h4NL/RqlDu///RGFA+ZuaNfwDp3/UKBJMkL1+m/QZkruUWq5efNaRxPK6OKSvoEeHZeVwD7WUwSue9tbR7ltrqnx2QSA5z6HywI+PtyNw6XAX5cQJwScv3Aegflgum5Bcgb2gyo+dPdw6oJc6t6qDihX5aIZrq37sC7jguZet/jt5LR6vzLfsF3gK6xdR5gBXe6g2P4hCOMEsjulw3G5SFVWR+gFe9t8CmsTSVJCLadncJn7x3XuGk+0FF3MFqIV5NzSurkgZ//iOeXxoBiS5o94KdkWGCfKaWE+vFhPHtfd3j/MAhmueB7EXhuAWPjGIe90ArUNIi8JLJ85sIBxkYVwzNw8g8501KN3n0jVT5m7ZpEawX1wJYqJIqhBD10z3EH8lU6Zj9tBR4Ta/SIR//G9MB/6ELIEDQIFFeeGLkYGVgvv4UsWth8gNQvf4bSQcEypmql7+BHv+T7PH5hrfsi8Njeg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e6c8be54-f28a-434f-7fec-08de532941e7
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Jan 2026 04:56:19.9361
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: eLGpymObKUVB6rjHlY/Jg0iNY7FEnqFjQ47rt2RkAVZ6/I6DJzVnH1yAcwu3UKH0wTbKlBkqX2Ae0EuRFHfkyw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB7218
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-14_01,2026-01-09_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 phishscore=0
 mlxlogscore=999 adultscore=0 suspectscore=0 spamscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2512120000
 definitions=main-2601140035
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE0MDAzNSBTYWx0ZWRfX9j5TVR2lW5CO
 MNJEu2XPgvHdg6u1eJMxlrggmU2mEcoTgC2lglwJfqFvN3AmdEpFxdJFpY1q4kpXfh8CrBmWxgM
 PV4rcW7zW3W8UVRpoWf7qbPgRo4MdbuiWNckrazWv9WTvMkJIY5w2wd7NQiIMv2DwyzgGX95LXL
 nIZABoEaPHre+PWvLs5p5na9WaPXRAH+gp35ggmpmZlmxINVnidB5Q+xzYnDZFGPN2tUd3jgj6y
 BhWjX8kTvzt9ogfxa5vulGjaoYP/ejbjTYtEkFDdukNNMFXm6l5zU/Ka/zhJ6tGIKicJHPPbwA9
 V473mhCOCgcP7Oj3TAhfbEuQrXmi8gmKwU9TB7u+TzqNcRbxNCO8afJaeCsnIDu5D8XSBDvh5El
 bS/2BUS4mrKN7T5NcntKt5WOUAA3II4/UAd9gflXCV2/gFdDKRd/rYC5udYkhyn9OeqzlZF/TZN
 +6zE6MeqyIGLf5CvW4Q==
X-Authority-Analysis: v=2.4 cv=YcGwJgRf c=1 sm=1 tr=0 ts=696721f8 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8 a=yPCof4ZbAAAA:8 a=w9RPrIt6g6G62PjUTAIA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: OjfZuQinCFXOcMX4gZ7cPFxXOOByEunw
X-Proofpoint-ORIG-GUID: OjfZuQinCFXOcMX4gZ7cPFxXOOByEunw
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=BobCP4eT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=D+9ZvI3S;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Jan 12, 2026 at 04:16:55PM +0100, Vlastimil Babka wrote:
> After we submit the rcu_free sheaves to call_rcu() we need to make sure
> the rcu callbacks complete. kvfree_rcu_barrier() does that via
> flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
> that.
> 
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
> Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
> Cc: stable@vger.kernel.org
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

LGTM,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

and I reproduced it locally and this resolves the issue, so:
Tested-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWch7G1ovZtHVadM%40hyeyoo.
