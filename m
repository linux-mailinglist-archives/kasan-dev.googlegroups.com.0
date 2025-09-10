Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJ54Q7DAMGQE4YGOFDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CC04B521B4
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:23:05 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-61e790c631csf4899eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:23:05 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535784; cv=pass;
        d=google.com; s=arc-20240605;
        b=LF3SbxtLLsEL7bIT2HmBL+hB8Yg2GKU/c0up0HxtmJy6nuhwC8wHryxcTc9/9JHAlm
         JpEpOJvPx5F6miaAe+nF177kLqvunUMJGe2ruhYnErp5tDypKXrah2Uc1+PYh7BajFh+
         azNq6Z70aGK0o2js3FrJwTcOeW2AnKEuGADdZ8kQJsMA9BG0SdJ5iRDtRgBZph8MQl+s
         I5Levv9YwH5w45Ufv0WiLgU55thpxlIdVmuRepuMHp3MeKaty+tVJPLCqmBXskCgAejE
         w319T85076H2OzsoFjym0cKAataFdM3qH1i2UtadNa7LSxIJ8u6le02aklUdTW2d73yg
         ku+A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hvv8sNRCHpEcEAeBcOn0eUHaiU3ckp3M4I1SP6rOkvY=;
        fh=7nTIc/NAxTqA/I5l2OW4zePsAgrT7/Z7N36DoBIEOL4=;
        b=XPN15GVR9/ZE8hvWWl3VuUUI1e2U4Rcnm2nYjOfmb8yI/J83c62bmJLxn1sNA/yK3L
         DquuRsvmtUv2Bscc6Ck00jIu+HehHs+C5A33/o08B1/3uBMLqy/I/k0GxqSULHE3e8vC
         tl5uoa0t5LQOyw0SxVhD3DJoo0hSAz2J1Os2Rq3k08OkBeahEmuYVcRP+xRkEZWoGtbD
         J9+M9Sw8I4AsJvmPjl6i3QclVet0Zx7ngkozlhLuJlE36BUi4fSFiErWVU/LIdQfxmDS
         6g2tDbAysc5+ijCnJtIBnG1Zk2vLKjRyRbL3g+HdJqHjTn24+l5v/WHpBqkeHaWUgH6P
         EWVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=YCi4R1uC;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Df48JT5U;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535784; x=1758140584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hvv8sNRCHpEcEAeBcOn0eUHaiU3ckp3M4I1SP6rOkvY=;
        b=d4Z0ttVAngnjFgzrcQ82fO7qzdalQozf8bkhMPzVwiSTOH3uZIQLm8GUGxGzFbkta0
         qhSYLuttZAvSUeB6PQLzQVTl6+0GSNDYA8yLOrcIDc47udOiBRRPh6MkiVM/lsuy6ilj
         dHsxKhv2kIOLafH6Aqn3Cf4hknlD/b9xgeT3WJao/ZSY1mXMBkDv3T8wPMGO6GjeLssn
         lkG8jgTytEozutT7VlIjD/ux86DgcQDViX1NqfvXL9rrOYd/gsJLZbtCoFfQO3wVN+92
         39MrJzNgZ/DyCL183Da/I6CxazvVzbx83JK+y7u1jO2y1AKyXUaGWZaS5CEZSK06JqJ2
         9Clg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535784; x=1758140584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hvv8sNRCHpEcEAeBcOn0eUHaiU3ckp3M4I1SP6rOkvY=;
        b=n0y5G2Ku1SmbWYN/MPuaqO6hB25pE6slPIr0MjA/pTeXzeJFxV6f9KY+/lmRaEYk61
         deRLCP5KCIDBznekVKn3Q+cHdqFC8FeM+W6iiTs1ZEVG98qYisYoKI64Vhsv9f9/CWaX
         eef+2RYe5dP6FdOdlX+g0Ui0nMMhS0mpPnj3HdM6xfnJV1lbXlSos3+Zp6HNev19Jcq1
         SaSHHaZrgs4mkYBcNhFyV4WhR6KzUQvTyixMWPDfAMGGGgo1Qjbqw20Dh3mlqGLX+GwJ
         5/S8SBQzw2rUV2cfwhEk4CdXvT0Qa+Ae8/b6VNgbto7jFhMEe+oMegbhHfcZG6Py69xn
         c/1Q==
X-Forwarded-Encrypted: i=3; AJvYcCVBxehGw2wWw64KPlKaA6JA3FvHqpAbKasZLWBpu9dYDRU1N1MhloQQikp5EL6yu0KNVahG7A==@lfdr.de
X-Gm-Message-State: AOJu0YyPP42BCxhZDGtY00FAE3MHh1Hz4r8WsO6KpB8f/kSNi+lNqbiF
	7A1pHz8DE3+nQfFjNp4lN90buIS9WrRhpj7Q6KGj3rvF23Ylu1T3sUX2
X-Google-Smtp-Source: AGHT+IHsLNUzjdqwdorM1NGGM4gNTOwI8fNo2iagCTqu/CGSsE5cJvP/4Goxe4jr7j/+yKZaVzUl2Q==
X-Received: by 2002:a05:6820:1687:b0:61e:7903:1da3 with SMTP id 006d021491bc7-62178987abamr6747163eaf.0.1757535784035;
        Wed, 10 Sep 2025 13:23:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeOnN5IYGw/vXRlTlXLWEeZZ0wgxZx9RE8FN1Uf5kHtKQ==
Received: by 2002:a05:6820:2916:b0:621:9037:deeb with SMTP id
 006d021491bc7-621b451fdd3ls18855eaf.2.-pod-prod-03-us; Wed, 10 Sep 2025
 13:23:03 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVim7NG0CyBOXFf49ftfV/yDZmvlLGXYSUxXyE481RPZde7Gtz3Bf8uQhaNsvoDRRnpAeWfhm3iJbA=@googlegroups.com
X-Received: by 2002:a05:6808:d48:b0:438:1cea:e487 with SMTP id 5614622812f47-43b29b4a41cmr8108388b6e.29.1757535782828;
        Wed, 10 Sep 2025 13:23:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535782; cv=pass;
        d=google.com; s=arc-20240605;
        b=jB+1Tx1nVgvf6vggAFEIGTTvVBrOmmlQsyW4wj8R8/M6Peg+TkopujUQ4M0FqFabgW
         uoiSRRfDUgshbuu6igT/PAOFiY9V0xEStE6GMiLcIz1Xo0uyzo1FqjnaX62CFLd0QNwd
         bAPxoxe532FWdXipWajLZcrLYiM5JixeTeoqTWfn7Rre6TC3y8lCdDij8GOvAVmx49Lt
         4NfAPmExdBim/4KDTp3Gi/UEtd2Tm0KaO7IklzfRLyYv/mqyFZx7Lx34BU8nfHTBxJov
         +32+WjdT2J1cnG82flup1b/vmFRwzNXF/ykHkfI47qXKz8QYVJSYPL8UxCVW1Pt1fhVO
         frHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=IVbNDlVw+eURPO9iHs0KXWvQ4h/K7M0XR3a0ma1z+sw=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=JZb8n4om8tu4s3yT+IxrP1AVvI55vog2BYiqor+MKn7/w9caNRxtnSfJvic36QpsLA
         p7nDZbwIJ/3KUCdgzplSng5RmuuFbgHff4ql94PaskwjASBK4SCbE9KJSGHf4/K79noy
         2Vi5UVDgOFvN9WBY5NrjWgz6UfMc7oOdf/dmGG4Yv7e5HE58zA0p+Y0twbX3TFyLUFk/
         bgzVFCIKSDv6FIfl5JTWXbVbC2y4Ps48recvL4OAZrH50NPAQZSVTs3mVuYZXL7JCbwm
         lNjmRWzL6Ve0VyviSjGpY9ih25EIG7M/jGfoHxeD0/Yp2iZZzPUWG2E6LSeMOK9jq5sb
         STmQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=YCi4R1uC;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Df48JT5U;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43b383d9bbbsi467571b6e.3.2025.09.10.13.23.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:23:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfrVv005320;
	Wed, 10 Sep 2025 20:22:53 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49226svyy1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:52 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AILGpi030662;
	Wed, 10 Sep 2025 20:22:51 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012027.outbound.protection.outlook.com [40.93.195.27])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bdbfhxc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:51 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=fSjGiPaj4KV6P5guq2kSqWLFAciUkBOqGFeIY1r4R+OSV+a3vv6xWdv3CHtefEIF0KouIJSLh10Ec1U/76qpqZp7Xg+N9IDf9/5X+RnKQ++c2dBHaWqmoZbcVl+n6cQky/Byy6AmTgGfUqMfh4z4bkSIzwLixCzSxmsb+q2OUrOxd91HkpBArDEZ4l8Fq/uB4h6ceh5sr5WoYN8WCltu38OnP9HZTNUf6f7+196R2+SDRk4mrfs2kSY/Az0qCZ8bpfZmymLF+qBnqAHYYjoh6BUM0WG1EZ+zclC4DwDE3h2I3bZFPCbL0dzNlM7Tcz4J3/prNMNXBfhg5VGRa8uVew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IVbNDlVw+eURPO9iHs0KXWvQ4h/K7M0XR3a0ma1z+sw=;
 b=SVLkg8Ulcdl4Moi2VVj4QYauw13yFmxAaGXQ82iGTxTiGVG09DeyfHBeUa29zw7ebdlaIP7+TxUWlBO9L8pj+7ugoFpTRejpkul698mCaA0OoIR4dgdofbGNccFLq6G+bYYcPNwMczWgbthEThBCLMYryR8mFV7M+ArmQCOGXSqycqbtGQeVXLNddDS2OdhyyIf6Dkf73jN8nJwJrLXV6CnL4ZuDyjxcLGuA/2YutBpOH39tr5Ey0InMjDdz56RTUw+r8g2InJl+tEZDoAI/uRaz1ZMJ3i/YS7/nWRtUia7Nix8p7U/M2zxsOcamCSKLThFg2xzCanqgZmvKrqG9VQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6278.namprd10.prod.outlook.com (2603:10b6:8:b8::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Wed, 10 Sep 2025 20:22:47 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:47 +0000
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Dan Williams <dan.j.williams@intel.com>,
        Vishal Verma <vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
        Muchun Song <muchun.song@linux.dev>,
        Oscar Salvador <osalvador@suse.de>,
        David Hildenbrand <david@redhat.com>,
        Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Reinette Chatre <reinette.chatre@intel.com>,
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
        "Liam R . Howlett" <Liam.Howlett@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: [PATCH v2 07/16] mm: introduce io_remap_pfn_range_[prepare, complete]()
Date: Wed, 10 Sep 2025 21:22:02 +0100
Message-ID: <96a2837f25ad299e99e9aa1a76a85edb9a402bfa.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVYP280CA0042.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:f9::23) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6278:EE_
X-MS-Office365-Filtering-Correlation-Id: a8bd8325-0e26-4c7e-3dfc-08ddf0a7cea3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?gcN7WcyUQ9SzIi5z+Pyvd29sJV4ifxA3Xxkjl6bKpNuGFMIXjKiWqy0QaUjW?=
 =?us-ascii?Q?iA6TsVb2mDNh6rqCli1A6oYhJiFd0dXVLhEnNBUEdE9AKnKyqK5y8v7AeQbH?=
 =?us-ascii?Q?zKMuaFvis36fBS9YkxFElJlSV8/bDHGg4vuYYP1ZPHJLpLl+tf7pfN+xZv13?=
 =?us-ascii?Q?NE8Wc0kYGwmOCCOqKJhs2eDhMITaZe+yK7TMyJpANN5NlFBlJPFajaabWWjj?=
 =?us-ascii?Q?UsNAi9fXvT9Yb4z68MTIEo9HGX5aAmxDhgfBqPmoX4Nq7YrFNU4CyoJaKiiW?=
 =?us-ascii?Q?60Mkter29X3tEpBF4MyJ/rF3JtKwR5FeYX05KjVFC6dtzaxyGnQHI158r3mD?=
 =?us-ascii?Q?wPog6gS+P4wJ1mauPZZMgFnruUEOrUqeG/96dgUbYxhvm7WUIhbDNEBPakoO?=
 =?us-ascii?Q?XUCWWkL/F/rwRU8iWiVMK6Kb9yyjBV4vE7kyrI/7Gy+t7wrgtTf2LcsP6z68?=
 =?us-ascii?Q?g3R0kuCwDpwzCAc/Oi/lgeHG/i9EpxzbPoXoH4zIFcFQLQ5ZqDzUd40rV2KO?=
 =?us-ascii?Q?CKa1wxEj/c0EIPh4D5DHu9YiLUD0CmyAbq41h/b2WRwXqWasr+4snBVf47LS?=
 =?us-ascii?Q?/8MLM+/HqsisoEs1L0v3wOPCGL54m7yMCy2LrnhMGe0aK+50ChafeqQJ3ock?=
 =?us-ascii?Q?YRCm0g8IQZYg1ovntPMCxAvAaamQIPqd1N5ngd5XmyhyZC0lhu8gj/3tIm7g?=
 =?us-ascii?Q?+tEh1iBsEDMlIcsRz6/NOUauP2+3EHXTH9PBm8y3WAYDErT3wWZcYb7PpJge?=
 =?us-ascii?Q?rFE9UtI9gTZol0zVCUIGytgfdvJ08Ur5M2es1N+xp7j2/28hZGsX9tWgNeeh?=
 =?us-ascii?Q?iIsmpwzQGy2T5ePKcaqXYrK2dmISLzD0FAlcFZFhMLwWn1t8EKn9gyTU5276?=
 =?us-ascii?Q?U6uuWVFIEOUdOhGsYBu8ItnpTGxz/wwtKl4xtV5maFXOVl3edD3Oz5vHpq0F?=
 =?us-ascii?Q?A3UG6CXdlBWllwk5Zu69O2y7tHvyMEA5NAEPkDRswCMZBi/+4VxJZ8kI83sZ?=
 =?us-ascii?Q?g+BAVGoU6WrIY7f6thf7pJFqwxAexUIU3725DzxTrK4uMuVYBkH9gpcu9XWo?=
 =?us-ascii?Q?D517xzyC1Ej3okMnQkZBTaSia2vDCBC1t+0i0UkzysJvEXQq9n6KXHw/vnKM?=
 =?us-ascii?Q?FtOQxcHputg9GUR2KREgHZJrFkOclo6OxnfhmI/OK03FMNHO+L/cnhO53ZUN?=
 =?us-ascii?Q?K5ANKhEJoUFKUnaHhTGsslbbEqXyu2WqQTrcnqA2HmakR0ioU7mCuTNRPuu4?=
 =?us-ascii?Q?wJm2FQPJm5J80PX8W5N+MNs1LubjLqiNRXq6J8uzt9p7H/upjXgunNVqAUi3?=
 =?us-ascii?Q?z2RlDMup78Rena1Ec6Lr60Zl20x1QIaT4/mbMSUF2yN+pfCmS/tdPu6sEN+b?=
 =?us-ascii?Q?n/DCtxQqWQtnIpOda0jl0EykJt1ow0v5/ReasxePhI8ug0ORE1cWhNV3IWis?=
 =?us-ascii?Q?ICDquIajwOc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1HDAok4mn/p+sK58vCWxKe6x6nhTrOFOf9SXVwtcLcdeA/OfIqUT5oVnXurZ?=
 =?us-ascii?Q?YielZ19G7S3mC2U0guAtD/zpIkTEPns6Ud+GrA08U3752Uf9l2AC/By8uWAz?=
 =?us-ascii?Q?IZDlNlT5CftQPeR7VT0NJ/sVc4h77Y2fonVC8qZKB7LESgiLek04uiyUcV+m?=
 =?us-ascii?Q?4f3EsAyXHrxTSMPB/h9hdvRjmuUBiGSq5dNqsN0udpzhgDQB12dArkv+ExAg?=
 =?us-ascii?Q?/qGNmFVAaV2uSpPbdO3fe4z/5eo7LwI7ktzHf28yU3KczCZ55aqjzdvlBfMn?=
 =?us-ascii?Q?bOZpPTHwj8pUrT5mChonjqf1VMm+6GsefpufGo+CWcvAN4rAtVCMpkUYHp9/?=
 =?us-ascii?Q?SxF/aHHSSULMzFRiwJiIju4qE7+5/eDclGNo6wfJJxkxWZH4rbVj4lUVAvYB?=
 =?us-ascii?Q?/0Rl5N/sSO0npm+4ggRGrwfWnlPM0elA1VEIRc6mkGEUrUlyKnb0M/Q0EQEe?=
 =?us-ascii?Q?NuBxk3DEz15Dpebcc5iq51PPX5dDZB3H7sxXhY3uqeBYj2zKA3x+fjpxHjvL?=
 =?us-ascii?Q?Q9dYhJyb3trT5tR3ZI5esHuv9X07Ecl/3cijcly66ShvItW3edLJJ3DQ+vCy?=
 =?us-ascii?Q?ASTRVKqxqloApId3p3ZySWpBQCNDTr9QZa46StSxLakGrqfek11XgAsHDh8m?=
 =?us-ascii?Q?3rJpzmB5m5JiJUNCJ2zZ24X4x5NEOcZq3UDmVid+zNuahUGuMxpBFh2GLHns?=
 =?us-ascii?Q?om6ZhhktfbR7uWbCuU7GttOt816wRAJk91BCq/I47qhm0lnPFOEP41lnjwAq?=
 =?us-ascii?Q?xbUqiNQqaD80Mo9OoIekwjoHgtDkzElFER3hwTqB5+JqDyzvSzYrNzViBqsQ?=
 =?us-ascii?Q?ErWArywsgqJYY4v9+M4Ls1HZQuPTVZlW2OB0VmCW8wBFdbUE3zvlwra3zTzC?=
 =?us-ascii?Q?2V3qo0GdhJk5O7HIXFWvy/Sxpye2DguAwskGegs8tx473sANpmqBYPvv9a99?=
 =?us-ascii?Q?XWGsuEjunAPG2QwYUGK6IdC8wfqqujyAag7HSYpDr4gPMP9/d8LHDGSfdFHI?=
 =?us-ascii?Q?FmAygHfqIqPybTc63wqEyn0FzwH1VNxFJ/3qB0GoioxFO/OYIrEwDk9pxEiH?=
 =?us-ascii?Q?whHNHY/94ak3Qq83/LSynB7tW+zrtEbS4iIZMIvCmWA1Xnd+hMY7R4KEXWM5?=
 =?us-ascii?Q?SuawiucYFwIlpsL7c1eV+S1Auzhwi6nwZB1/iHs7Y3+khjdcaTAePBqc30XO?=
 =?us-ascii?Q?1yaDFRJzNC+nSAxgKNSuQOrChBJ5zm82V46AqAmhB3Sx0Py4rxUpcSoa2KKC?=
 =?us-ascii?Q?yItRiFJq7PK3lB2z//LA6IZxEXR8pce80BJv30mH1D+oEFWvXRZ1oS7YHW5V?=
 =?us-ascii?Q?FNnsoO2lKu6MvvOK9Zyfv0Gbtk8CfNFxWod9WJOMlSjmKo9Batb6Xa1JVrV0?=
 =?us-ascii?Q?e7AycdsfazeJ8S9fEJrX7q3rSE7xb/CAzgRJ6DY2ynUiJkkPR90feD1dIKn3?=
 =?us-ascii?Q?cefOu/XKDaA959sp+2+gPqrsBrljULqwWB0RffCLy5JUrHpQf+RND6670Ok3?=
 =?us-ascii?Q?xup+Mu2vwUwoXCNxzDtrvJt91g288hdsYeBHph7vU96VmUBAnYn+P9XI/5qb?=
 =?us-ascii?Q?brVUWZJWzdYweMLIsKQ12bp5/pgT26KsfvLuJXUaGvgsX9aLdqZQWNmGee8X?=
 =?us-ascii?Q?dA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 3gzlO6s7UMtWPBb7ffmtGFR976jimqlUWPT+tlWjAGUnkyzMdwC2QTeMsdjW5pFwN4852C+yLvdV5hzuqb3y25FHkw5odGKCBF0K1AtMm2W6sqwcxFjR4K2TVSx3ehis9I5jraclndz2iRKBbmagY3phl7BDH/ZvYkpDFyip/Z+YPOvUIxOazHIZKO+Pfg0n2VGpPf1OIHjRlJGPjhV7CjK5+CUHga15gjc4+iVstWmwdMWWQAC0yZcRTZRyVH76wJz0mkiEl8TYTQiba1uK491tsl+XNscjf+OmPQKEI8A/XmNmCNiVQF4hX8syalGlNy2+AM09ZGERUUzGrs4fITJzjnohuNr0e6gNseEeU+vA/N+OrdNAtw9qwdRVzu17H3/1DExtXvHSnS6DASRcdmNVYs/403cBZefE6uwG1FhOnjeqkOHr0/BecKHxan4yO/TJVKRX9dlDDCILKM499TEJHlKisWDGS759KqZyxzZdOSgxki56tK/ZBFtnbxWC5TQTlv/9w1Se3d4i7Ghl2efm7jvdzHSqX5I+ZmQToXr6M3MmEa+BWG1cuLdEdn1ZhZv769V+dvqtKZjCqquo9vyrEyHZl/FneXsbP1E3Ld0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a8bd8325-0e26-4c7e-3dfc-08ddf0a7cea3
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:47.5266
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: q6f1+hedG/lA8c6dwZEHr8DQNVi7rkkkMsbeTe8ykD6pAp0gZ0IaZnSE9y7cLw3sZ+jC2OqUlw3fKgCEP8pD6rIjezHnqG4Q1wKVBn4UGgA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6278
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509100189
X-Authority-Analysis: v=2.4 cv=QeRmvtbv c=1 sm=1 tr=0 ts=68c1de1c cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=dJYOUp3rnrVNQsztrgsA:9
X-Proofpoint-ORIG-GUID: KZ4tEBcScLiZ40271UO4gVlXo6Q-_dwA
X-Proofpoint-GUID: KZ4tEBcScLiZ40271UO4gVlXo6Q-_dwA
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1OCBTYWx0ZWRfX8tRVpVAC+Jw+
 qBDxfOz26+XJZ+sQWY5/g5o8NaMZCoFtck0XKQpCUB2/lWGzXENWjyOYvY+zIgdcczGdmZNAe9E
 gDuch3c1f8Z26wwBugchmY9SnWDFDejepAP6Q1mkIAtJdXbZZ8nQK9Oy99lBRgGSaXTM2yTk7GI
 kKo3tg9Ke0CA4WUz85SO5Sp/3o3tWZBCNFdw17ynJ2axPcRGcO/ffQcRVtyYFPpbwEZsfGDY5l5
 b5cKiK6wspxdIo3leNi2otJCTs9r7WWCpGCBkXMUvMISz84csfnpSWfx9dgql0siMlgJpVcXTlo
 KD0z9wdmlV9xxFOC4YPqxbZRQXAkzdpMTniPzBU/gxYAWIiMTuyHcFoQZjeLNPoUd9TBDdwIGY4
 b0Hwa9TN
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=YCi4R1uC;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Df48JT5U;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

We introduce the io_remap*() equivalents of remap_pfn_range_prepare() and
remap_pfn_range_complete() to allow for I/O remapping via mmap_prepare.

We have to make some architecture-specific changes for those architectures
which define customised handlers.

It doesn't really make sense to make this internal-only as arches specify
their version of these functions so we declare these in mm.h.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 arch/csky/include/asm/pgtable.h     |  5 +++++
 arch/mips/alchemy/common/setup.c    | 28 +++++++++++++++++++++++++---
 arch/mips/include/asm/pgtable.h     | 10 ++++++++++
 arch/sparc/include/asm/pgtable_32.h | 29 +++++++++++++++++++++++++----
 arch/sparc/include/asm/pgtable_64.h | 29 +++++++++++++++++++++++++----
 include/linux/mm.h                  | 18 ++++++++++++++++++
 6 files changed, 108 insertions(+), 11 deletions(-)

diff --git a/arch/csky/include/asm/pgtable.h b/arch/csky/include/asm/pgtable.h
index 5a394be09c35..c83505839a06 100644
--- a/arch/csky/include/asm/pgtable.h
+++ b/arch/csky/include/asm/pgtable.h
@@ -266,4 +266,9 @@ void update_mmu_cache_range(struct vm_fault *vmf, struct vm_area_struct *vma,
 #define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
 	remap_pfn_range(vma, vaddr, pfn, size, prot)
 
+/* default io_remap_pfn_range_prepare can be used. */
+
+#define io_remap_pfn_range_complete(vma, addr, pfn, size, prot) \
+	remap_pfn_range_complete(vma, addr, pfn, size, prot)
+
 #endif /* __ASM_CSKY_PGTABLE_H */
diff --git a/arch/mips/alchemy/common/setup.c b/arch/mips/alchemy/common/setup.c
index a7a6d31a7a41..a4ab02776994 100644
--- a/arch/mips/alchemy/common/setup.c
+++ b/arch/mips/alchemy/common/setup.c
@@ -94,12 +94,34 @@ phys_addr_t fixup_bigphys_addr(phys_addr_t phys_addr, phys_addr_t size)
 	return phys_addr;
 }
 
-int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
+static unsigned long calc_pfn(unsigned long pfn, unsigned long size)
 {
 	phys_addr_t phys_addr = fixup_bigphys_addr(pfn << PAGE_SHIFT, size);
 
-	return remap_pfn_range(vma, vaddr, phys_addr >> PAGE_SHIFT, size, prot);
+	return phys_addr >> PAGE_SHIFT;
+}
+
+int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
+		unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, vaddr, calc_pfn(pfn, size), size, prot);
 }
 EXPORT_SYMBOL(io_remap_pfn_range);
+
+void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+			       unsigned long size)
+{
+	remap_pfn_range_prepare(desc, calc_pfn(pfn, size));
+}
+EXPORT_SYMBOL(io_remap_pfn_range_prepare);
+
+int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, calc_pfn(pfn, size),
+			size, prot);
+}
+EXPORT_SYMBOL(io_remap_pfn_range_complete);
+
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
diff --git a/arch/mips/include/asm/pgtable.h b/arch/mips/include/asm/pgtable.h
index ae73ecf4c41a..6a8964f55a31 100644
--- a/arch/mips/include/asm/pgtable.h
+++ b/arch/mips/include/asm/pgtable.h
@@ -607,6 +607,16 @@ phys_addr_t fixup_bigphys_addr(phys_addr_t addr, phys_addr_t size);
 int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
 		unsigned long pfn, unsigned long size, pgprot_t prot);
 #define io_remap_pfn_range io_remap_pfn_range
+
+void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+		unsigned long size);
+#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
+
+int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot);
+#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+
 #else
 #define fixup_bigphys_addr(addr, size)	(addr)
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
diff --git a/arch/sparc/include/asm/pgtable_32.h b/arch/sparc/include/asm/pgtable_32.h
index 7c199c003ffe..cfd764afc107 100644
--- a/arch/sparc/include/asm/pgtable_32.h
+++ b/arch/sparc/include/asm/pgtable_32.h
@@ -398,9 +398,7 @@ __get_iospace (unsigned long addr)
 int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
 		    unsigned long, pgprot_t);
 
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
 {
 	unsigned long long offset, space, phys_base;
 
@@ -408,10 +406,33 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 	space = GET_IOSPACE(pfn);
 	phys_base = offset | (space << 32ULL);
 
-	return remap_pfn_range(vma, from, phys_base >> PAGE_SHIFT, size, prot);
+	return phys_base >> PAGE_SHIFT;
+}
+
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long from, unsigned long pfn,
+				     unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, from, calc_io_remap_pfn(pfn), size, prot);
 }
 #define io_remap_pfn_range io_remap_pfn_range
 
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+		unsigned long size)
+{
+	remap_pfn_range_prepare(desc, calc_io_remap_pfn(pfn));
+}
+#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
+
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, calc_io_remap_pfn(pfn),
+			size, prot);
+}
+#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags(__vma, __address, __ptep, __entry, __dirty) \
 ({									  \
diff --git a/arch/sparc/include/asm/pgtable_64.h b/arch/sparc/include/asm/pgtable_64.h
index 669cd02469a1..b8000ce4b59f 100644
--- a/arch/sparc/include/asm/pgtable_64.h
+++ b/arch/sparc/include/asm/pgtable_64.h
@@ -1084,9 +1084,7 @@ static inline int arch_unmap_one(struct mm_struct *mm,
 	return 0;
 }
 
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
 {
 	unsigned long offset = GET_PFN(pfn) << PAGE_SHIFT;
 	int space = GET_IOSPACE(pfn);
@@ -1094,10 +1092,33 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 
 	phys_base = offset | (((unsigned long) space) << 32UL);
 
-	return remap_pfn_range(vma, from, phys_base >> PAGE_SHIFT, size, prot);
+	return phys_base >> PAGE_SHIFT;
+}
+
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long from, unsigned long pfn,
+				     unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, from, calc_io_remap_pfn(pfn), size, prot);
 }
 #define io_remap_pfn_range io_remap_pfn_range
 
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+	unsigned long size)
+{
+	return remap_pfn_range_prepare(desc, calc_io_remap_pfn(pfn));
+}
+#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
+
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, calc_io_remap_pfn(pfn),
+					size, prot);
+}
+#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+
 static inline unsigned long __untagged_addr(unsigned long start)
 {
 	if (adi_capable()) {
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 0e256823799d..cca149bb8ef1 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3685,6 +3685,24 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 }
 #endif
 
+#ifndef io_remap_pfn_range_prepare
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+	unsigned long size)
+{
+	return remap_pfn_range_prepare(desc, pfn);
+}
+#endif
+
+#ifndef io_remap_pfn_range_complete
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, pfn, size,
+			pgprot_decrypted(prot));
+}
+#endif
+
 static inline vm_fault_t vmf_error(int err)
 {
 	if (err == -ENOMEM)
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/96a2837f25ad299e99e9aa1a76a85edb9a402bfa.1757534913.git.lorenzo.stoakes%40oracle.com.
