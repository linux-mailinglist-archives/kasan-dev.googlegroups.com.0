Return-Path: <kasan-dev+bncBCYIJU5JTINRB5PIYPCQMGQEY4VCRUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF9DB3AF51
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 02:29:43 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2461c537540sf20598375ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:29:43 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756427382; cv=pass;
        d=google.com; s=arc-20240605;
        b=NVtPzNyU2axmFL338NUMTKMGyL3zf+ko/Jc5OQwvAL+naoiOy2IrocvgSZZNTKRQ73
         PVvdT76gwPgP7aM0r/b4Rcy4tyMpT/qwVTbirPfa9MeAsNUzdtixQbqmPaPcxYc6Z632
         Laigz+FDAunLoumt8FEPAY0UEIKM5goi/TkqEj4VeugL0T+W6Jja7ZusisPhKXWGboW/
         KAf1PwQRIKDYClHcBGWekM0OWEgz0mZRoy5bf5QR92b6Rt+13OfWSm4H+iLRJgNClvEe
         9g+ikd3yKmjdkqHEMn4dOoVxQex5olJCrgFvk2JoXb447hOtJv2P9CB0N0HpqtpjrbJO
         3sow==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Sj4vVAxZecvDL+Sv1Wn+mLfWjadLNnprpUK0CQnrSlQ=;
        fh=6TDB1XbQ2aSpkCpK1yrRH8iJFsfpVgu9rPb9v9a4KTE=;
        b=HLBT5SQf7svgWRs0NBa7kcf9IyDaJqnY2QIOVyJdXKrIVbhb5pnKNw8iAfuf1kb5IH
         7HgDkt58dQ6r25bL0oNuLcuQah8dpTPljSutz7d4DY9m1yx0ZJ9KEECHwRMIyDTIaOK+
         MV4JYe5P8/rhBHnRFgMbXUtvUHfY3glWh8cwy1mdbcImuwh7Vv4hcgGA+K0BCLy0MSG1
         LfWNIEo9i7M1LpVZSM0K8trfUk+67RT+3yEN8XDO9DUvTUi5CQ/GWW7okv6G8kyayHUj
         et6qgWa91rNbTvab1Nb4C/f+tHPoSIA5u/DJK3McqTJjXqb0DhqcIR9kwewdngPem3Rj
         eiHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=nhXSu7jG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=fjTFsQtD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756427382; x=1757032182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sj4vVAxZecvDL+Sv1Wn+mLfWjadLNnprpUK0CQnrSlQ=;
        b=OHJ8s+2mVQXcewCXFCKKJOqU/Wuz2MnXGjer2ApKaf/VHe3gdVdPsyz+58o2xOL6AU
         33q4Y7WowPBjFtYGFIhvli7en4w7rRlnwzZJNm+OKKbCc4UFlfPOfzYm7E/EYH76EG02
         kbB7PBLQytz5E+9uAgbVWSoJd+K1z01KITAnW64GjdujHqrs14LZ1f4ugsjPiqAQMqUm
         q3AXc+Kcf2PHsaPIfcwS01Z5/rqYay3cGVZ2R1x9yhRVpwO+P6YwZnbNUN5u7qOujJHK
         I6iAO1a5F7pg2JeTBxgxPE+QMdqD+fE72NH9JP005V6z7pORCRYNteKoj69MlfSubO+P
         Jk2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756427382; x=1757032182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Sj4vVAxZecvDL+Sv1Wn+mLfWjadLNnprpUK0CQnrSlQ=;
        b=r4LqE4Q+RuZhfRQeFtq4Iy0E+6Ymk4+gacoV7Xwk51YGodxNoRYMFA3Xohn0DgmLuk
         JBZLI2RBiITJsUE5y6gFDqziX0UN5bnCnb9oTwEJUdDB5SozZ5j1ZvSHJjl1RF7OgvAX
         7cpaWX4TbONXZkLfsA5M6DB9fOYlBUtPePeFaAICA+8uR+xmYRmT9Hf6R7tMK5IcW5Me
         81u+BZh234ame3XsF/EjEoRw0A5y9+NFQr3+EHsnI3vIu5jrHl7PXsW1OtZVGWOZKl5B
         YN59OMoo1Jo/fQcjeFt04420zkYNKX1lMCJCPXSOCb/vtftiCp4K5HHsO5ijBb1udPYm
         uk4A==
X-Forwarded-Encrypted: i=3; AJvYcCU3HFsesa4GmFXuEwmNS9Wry6MRDNrlTE9eXJQKUgnP/deQev5FNhV/pvtfFAgcaocL9O5Zhg==@lfdr.de
X-Gm-Message-State: AOJu0YxUI+PtfpJj/UPwH/F5W03CHDM3pvfvAauEBaj21aRxCJEmLguE
	JTsH/pNJPoH3TW87YUSLqu5Zy87jrFKbIFwlLvDMluOKX1iTzCBZmLSq
X-Google-Smtp-Source: AGHT+IFFX8GQf+GTRnBsBy932k6j4dYhDWlFu5XvbjgOwD2fqqSDASx654WmUrFzHZQ9JWvwfEcWyA==
X-Received: by 2002:a17:903:11c5:b0:240:3b9e:dd65 with SMTP id d9443c01a7336-2462ef44573mr314218655ad.38.1756427382025;
        Thu, 28 Aug 2025 17:29:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGIBC0Vmbw/QvaWEVuOG+4vZlzsrNNBZqTE2g8qdTd7A==
Received: by 2002:a17:902:d18d:b0:244:6c39:335e with SMTP id
 d9443c01a7336-248d4e38d3fls11314745ad.1.-pod-prod-05-us; Thu, 28 Aug 2025
 17:29:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVTYHqIjnWFrQXYAn6lqP0Q2V0PoFW+6DPTtkILiourJ3sXjkf89Uz2LgzWQMXGYWm9X7cbIHt7hdg=@googlegroups.com
X-Received: by 2002:a17:902:e783:b0:246:d98e:630 with SMTP id d9443c01a7336-246d98e09c1mr193691155ad.44.1756427380687;
        Thu, 28 Aug 2025 17:29:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756427380; cv=pass;
        d=google.com; s=arc-20240605;
        b=EEa0pC9Bb5/RP4W5Wqjh8g545p4oBbVS6T7abs7qMaZ8S1EuXa0iVVODondOvngNGQ
         m7tlA5UXvYtp7axiFFCzsWMt2XJjD4I06C/QCD/foiPbr/dQnu5uc3R0E6alNbFQwAPM
         RexaclT6h5tVYQSnfFB/fTSOJVErU/sWLB2X1YzKvB8n2/eUp/ZuIoFHbm7VJD9yvS3u
         fuLIza8pOj1PQWevE19hxZGJuNmbDr6p0zQQ4bkUjA7objB1DGkezuxHesk+obwFX6ul
         apBgOEBq2OjGl7bTRmCU8ZpIdR29ENqVQ3fy27z3yWAfMlahLGPyQhNu/YXafd7QsTmj
         9efQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=7co799GYQ3s9+HiQt8B79X4fTR1elTZSB+dVFw5DFSo=;
        fh=/NXSmiGzCNKJtcJAZgCp7Iz6ZuisLElw/IRMxG5G5dQ=;
        b=NpkGaw9nskzwhXjmraCkt7bdyAxC7fYCqXnyuoUIgxPH7ZCss4c1XxxYRDcblTfqHE
         yfGnw8ubQmVpixajAuQw7pIkPALBgrjxWo+ZVvNfYjjHinfwRz/KNHq5LMOnyyEnPqQQ
         X/XqoZwfpDD7E+oRFKkQgrtRHbxFXQBaqVlLonvY/AXRXAVqg8rgEInHTA7k1RdaNCK8
         PpaTlGvHm0fltLxzzQN+g7zr9ruOuCmgPrusp3ZpQwmn8Wuyc4RRsw8w0SGZVWddY5S0
         2K4gDfs1zMcas37T6zKQrFMBT2LP7Y0hws5bHUiJv4PYw6W8Z9hsxgmohbPJln1JoIzp
         Cwig==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=nhXSu7jG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=fjTFsQtD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2490659ac10si426655ad.7.2025.08.28.17.29.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 17:29:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SLUukF002663;
	Fri, 29 Aug 2025 00:29:31 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q48espfh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 00:29:30 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SN6fX4004995;
	Fri, 29 Aug 2025 00:29:30 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10on2082.outbound.protection.outlook.com [40.107.92.82])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43cnwnc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 00:29:29 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=alv0MLskOhFu1dTSbh4GAE1tnNMCO//0VTh4xRAYC2W0tJUzpIrnAO8+oPJmf0K/3bQxXO5VuvJiOqatTVExlRZQQ0AMF2+GLZnyOLMS7QhxNT1T6r2P42EBJ3Y74YbWAP0XPBqBO7B+Y6SbRVXU5eSRj1j1/Gn8aUGqz+UojX5JMQl61xjG1iVG9weS5jmHW7z28yhGj0vMPMswsAu2m1XRf/5ePgNpbYe2K40K/CxsDpBYbrfRhuM2+EnLUanBFrGoks3lgUkh7fR6FPJ49EK3jD65psTzpimVky0yjOGQzgPrCsCrTrGaKIMu3PWQYoByfLHc1V+D05CRlIIH1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7co799GYQ3s9+HiQt8B79X4fTR1elTZSB+dVFw5DFSo=;
 b=kOU49YrstILTnh9rUbVic924GhxH5lgnJrKuxjtpDFSUdbt+PvZLTlkmpWrKp27Cgkbd4fpqYUx7iXBc2F3AOSVhNFD61E5OwY7XHA3MfV0YW00bg7VcZbPYLoo4aHG+VAeJFOE3rIVdkXwNE7RA476caVvscxdF6XzU50/HN2TUrsGqZ5QCSf+4JU5neLHHivIc9tJoOr4SYsR8dBcMzgVMzy/W3YnPox9/G8L14ajtPVjE6m9aBCRIczF4GM6txdjfNkot6E0EiZJ3GzgRuG1nqnxEeiuJssJJm+6lXHt02pdE3Uol/OFm9iXgT7If+ZEtWUOXO4M3WwqWxmT5Fw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by PH7PR10MB6481.namprd10.prod.outlook.com (2603:10b6:510:1ec::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.17; Fri, 29 Aug
 2025 00:29:22 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 00:29:21 +0000
Date: Thu, 28 Aug 2025 20:29:12 -0400
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
        "Jason A. Donenfeld" <Jason@zx2c4.com>, Shuah Khan <shuah@kernel.org>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
        netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
        Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 05/36] wireguard: selftests: remove
 CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
Message-ID: <faqp5sdyrkcaatjsnvoxssck7l2qf2e7kivuepobmc5zdg4mnl@b5ie7764mkqi>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org, 
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	Shuah Khan <shuah@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>, 
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, 
	iommu@lists.linux.dev, io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, 
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, 
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org, 
	Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Marco Elver <elver@google.com>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, 
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, 
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, 
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org, 
	Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-6-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-6-david@redhat.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: MW4PR04CA0172.namprd04.prod.outlook.com
 (2603:10b6:303:85::27) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|PH7PR10MB6481:EE_
X-MS-Office365-Filtering-Correlation-Id: cde7407a-9262-45ae-453a-08dde693194d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?rCTIcoIGcxsmdQiQZdSZki80GEYdQkG6vXkBErKdHFnT8WkPrpoj7RgIdn85?=
 =?us-ascii?Q?2T1YQQLbGN8Xo5CqM1JTphVorzyct3pzrgCqRKdXljpb60FDy8DnCYHX05KY?=
 =?us-ascii?Q?IPvHW1KYLbHv15yC3mGX4OYGjmQZ+zj1yZS01VY1zSUdh7d55113oP3JWzfH?=
 =?us-ascii?Q?TnfZJxT/UnL99JrHJLNYew4Ei48+BsY6vo6hcFiDO52bMqba/keF/qjx11DR?=
 =?us-ascii?Q?p+ZH2bz+fpAyDEJgYSUVCjHVf52RGfq/RDOafusCLMz23q9sWE5LKZ5BFS2X?=
 =?us-ascii?Q?MTSbluHnc4u8XhxAYGwmlHXqgne8+fFwd7V6Z9emVh127QX/rNS/BCmqDPxC?=
 =?us-ascii?Q?+p/XbBw3JivIAXddFB3PHxRw4aAAhtKqkKgy/o18+mvg/UkO+EoeOs6naagh?=
 =?us-ascii?Q?k1SME7QXdPmh2q9otLGlh7hHam320ohhUCfMxXE8eafN2uTVhMJjTm7FaUNB?=
 =?us-ascii?Q?PXI7T5upfH8MAXKjDyHHw5ugT4AaUWW6m5xeh4Pf1n7Onam1YaZ56yX0oeEq?=
 =?us-ascii?Q?UrWX6WZRk+0JEMbB+yQwAMzDTvKEIR18fayb+IpVsveYhy0T/LtIwrp5MYW9?=
 =?us-ascii?Q?Dosh9aJXmmcTYw4jTKh4eChIA2dgPtOXTcWcKlu5KkiukvYlrbvuJl/b4hUx?=
 =?us-ascii?Q?QafLrypII90eyBAs8BFX8J7GFh/UtNXMbDTt5D8UwoUpFuTug2CA5wgidY4T?=
 =?us-ascii?Q?D31v2lZqZuM/B2S33BoHCuXmoJour/+N5tL1grlCQJ/HEXIei/kFqMNB1GDM?=
 =?us-ascii?Q?tXOw6r5CyN1NoAwNLZlTwjh2fvbGF1dMTStyCrBVEaMsU2mC/gzxt6HiBnQM?=
 =?us-ascii?Q?KJfoAHhUmH+EUmfPDLwaGjgjQOdZ54ursjK+rQbQsJP16H4nTC/E02JbwC3T?=
 =?us-ascii?Q?Iq9KCYO9A2+5YAggrfZ+9hDyEVhFO2aHGYUH9T+H2n2/uNr3/Yr1MUWKejg3?=
 =?us-ascii?Q?zs6Iz8ezLHIa4bYyGMHNEg6TJ/vxrsFpWv0PKRJsR+myIn3IbSdb+qMB6xEF?=
 =?us-ascii?Q?TwoyChDnTKkpGJP94zw2TCLLYPz91j3tpFfIv17Ze7tsPhQL2+nAxrmkGvNJ?=
 =?us-ascii?Q?4BYmq5AWAFzI+EfYSKj0f1RanvJhRXRsNoD50rvv5zdPD2yqwQedK1v4FYlh?=
 =?us-ascii?Q?OdwhBLef/LcQyRlbu8/8npeIjj96spJ2EbOIGpca1CJ9iwDN3W6vFPPo5nEN?=
 =?us-ascii?Q?CO1d2FgKGpUPNLPmXoY0EVKzGxYori1AdxiIH7TuPMqZnHGG1J/+i9NR7ug+?=
 =?us-ascii?Q?Zqu86fYo70fsWRHXVQA6QqkT+o9rOjHOzwWlgHsX5Cdo5PRHnOO06UxumQeE?=
 =?us-ascii?Q?FxVLSm8EV2pQRLmjBc105XJTtwsnrsEIULHEJiKayzHY5DwMQQye393SEQl4?=
 =?us-ascii?Q?vducpUwMHYQKnLQxzsaw674GqMELxEzkWbs//hhpzhEofh9ZaA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?yFy4+6XqsJ+IW7bVX9hEFhMg12KI54isEmcEcn2G2a1Z07+ju/NEKZutsk7K?=
 =?us-ascii?Q?QHSKWZ+aRdbFRJ/jUzDZcMAEXDG3Mrls8nEtGfeoXK7mZAEWNl9jl8N/FqgB?=
 =?us-ascii?Q?063lMa969WMGXP+Z3QkyDq+3KC+bjZKNHyHv2eOyC50O46Hmr5G4mbKOkE92?=
 =?us-ascii?Q?DMI2YAFo6f5GpkkEiIqfy0JyWfigDOQqAnr4jBZzBZbZm9ndzEhKC52JOPok?=
 =?us-ascii?Q?RVtpIwvEulvd9a4EVNe9FjRQAE8w1XWhsJCznAPtPbNL+/nVlIIQm/9gGpHW?=
 =?us-ascii?Q?a/jzIC4ji9PDVrWM9usz2wX8ErRd/YaUW0IG47AqTV4cLZwEh6SoMD7PnTer?=
 =?us-ascii?Q?fGoJs8aByY2d57ejiJJsSE/oXViSq5umKC5vxEH9IMXlsPJPR2lsWKP1IJ0f?=
 =?us-ascii?Q?vq1lVOqLee6lOrrSgIcIPYobztp/Kl++gVq40PzUs5UnEOx3dcQUuYcOjAWt?=
 =?us-ascii?Q?IabhmraGsI62/6NRLjJ5RNoKuuoChiTQJS9WmFVax48Euq37yJICGlhx3VRy?=
 =?us-ascii?Q?RkK0ZxYpfJ5Z/3sbeR5onL8BmGqvItHmsC9KRTXtc0hpna1uNPMK/mv1+MbJ?=
 =?us-ascii?Q?+OWIMT+fl/V1zcYNid5Ngv7g+zeHPF+h9+KlaZSk7JEVc01BydhYm847E/yq?=
 =?us-ascii?Q?PZwQ8XhWMcuJ+OBIZE9CoVQUtg/J3kgY4DXRoQWLyAUwpIr7WG/fmScPdEzh?=
 =?us-ascii?Q?C/8SxBNtJn5tD5oE1EAOlgvgB4aV4tMDWiMd73nx5Xi0MC5ndGr4AsRsWgOq?=
 =?us-ascii?Q?poizh5nYKWF1Xsu1DhI/QaZ7Xo7ipEbSNYv8bPrW0F8jXlsmIFf+4/gxh+LG?=
 =?us-ascii?Q?aNVJr/vblzFGbGve/l44Uz+Fvpq/DNdWSCrqqW39YOEo4OJnAEWhdRBzWO0Y?=
 =?us-ascii?Q?JiEr3bCSSvEaY2d9RLPQ0kOIe7wW4IJhGESB0j9GscEz1yYymCaXRoqJF+ts?=
 =?us-ascii?Q?dDn3ZO4QVauwwkqC3La1bhmbUO7yDU77BZfYp1xq7JjGWH1F/n38bXA+GvKd?=
 =?us-ascii?Q?RfMf1aecnf6m1qa9eAH9ETWZFRK767Zkb2JGDVuke6ZNgiPO4q3d41I5CG50?=
 =?us-ascii?Q?U3L8IPtCBcRr+scQX+wRklGk48tGJpiaQe8Ifh5FNnIzF9U3aXG8LzD6OzhQ?=
 =?us-ascii?Q?QEaT0HhtCWxXlYqPbHySP0O3cH6DS7OlPKtYGr/fYKPKLZxt+ZBRUM+sD7Qh?=
 =?us-ascii?Q?vqz6O6tmpVn58dufOJrt02J1RLSu7DoSRvrCLj1fdTMQNrGtXZV4jFOhU44G?=
 =?us-ascii?Q?6dp7GzMfN8NlVfL5tuAm/KsHoepLcy7g0s/gz7TgI0VWcmpO/IdecJ54eWBM?=
 =?us-ascii?Q?xTgy0AYYDSGTGc+uBdakI9PYjmptzUGXrrWYtcME/K5uDr0LJwiyYGzguAnD?=
 =?us-ascii?Q?Ouo+OXkcn6tQOBUsV1yOeTpnw5EDULhTiJIoMFkwibp18H/bWUQdt8ZnKpWM?=
 =?us-ascii?Q?FwhsTeOmd6HDNx59a2kIvrGYFrBZ39lZDJ46jSuoWByeOSdS3RZFuNyvPkdr?=
 =?us-ascii?Q?eg2qihkZ7RA8sxlXb0tvQTTJoZ0/kKx4jo/7nA8foxPwkgmthVKIWS7KMpI/?=
 =?us-ascii?Q?wjyfKHJeIsr5EpNPjSRS41+BS8tUcEYr8nlUjBfiJch5Pd8zL2CwKS8ZURXZ?=
 =?us-ascii?Q?sA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: FgBTxNNJPuddJ5TX7T0qn+Sm1T1X8ikMwLPkPJWVf6rf+aTK3sVybk52zWqzIDsgztyLlASoicVM5erMu19+DstuXFizMReQaQ3gm0ErbU69ON+vduG6hbFmk2Uj1CZ5Bp5fs79FbhyS70AYKlMEK0JX4KNItOCcXt/GcXVmB6SjiplCu/G8tmtrkI/djNTV52092GBIsgfzqhqOZcJY8VWBX2iBiCilEWnU+0EUssdPAvteD8SZQLeTHLXrSHGwCml0rjBAf53pDHvC5KS6fklPbwura0TnSHCtc0oZ0UyvPTyVCkZRnrkBVRWdbUi8mpT+tjSD7s/uXUQak58fQQg5xmGijEQEfCL9JIM/ajvdMxtt+agCNywKGpRj5gHBJqZ7epjSwEmiRNmXv2kSqAEIQZpxX/1qF6VccnulkugYVCKDlPSUyC6SrBlg/imuh6qxgGzRktra6a4bqxrQjire4vO+1kpQdqFRRD97XVPDaZbt9yQzk2RTUqnFcjSIXvcFTO468KwSMWC7fs9rJAHkUpbuPYHBE1szIuHmrzaVSmrxaA0oYkZDBrH+ZF4SVGg9nwzmSREL8/4yKuucgclSqikLUe6T5jWV9XamIuA=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: cde7407a-9262-45ae-453a-08dde693194d
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 00:29:21.8200
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: V9MmB6Lao6UPCh4P8OTAs3ObyvJnyn+uI2dfja5kJ8I244B+0icxOrY5Cr8fiAvtNJCz5ou9l/Co8UcCg4W5ZA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB6481
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290002
X-Proofpoint-GUID: i9eAXED2WWudCeVYHg1Avbk_R_mGcXuR
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNCBTYWx0ZWRfX2akbItr/IGRd
 9ylyFRPDs2DGYA0VeNupiDhV/+HsP+oei0AzrLfowBT3zBAHOpRsWITS4v/I8pRBeTjU8WqrnEs
 mQDvOGAld6PhX6hf5kZ119KajKC823oUsEbHxna/AA/5iMaELDfDw1XL61g5/zoGgUWyJxRi6Xm
 rRH6GRI4WEc9huQbc+56I77vnwM76Fle/IHAcW5GEDYKMbZ6O407GtOFGMdxU0e6vYhzSDv2xLA
 Ri88nwKapKUkXr0cVaIeu4PPJqgG7oIejpJFZP3WJ+nGS2hU6wvch0RFOl7OQO1dPICDDky8pi4
 oAVkTkyWusMDN9WxpeOQkzlmR2cz0WUN8aoQ2WRzFQZIEXo14IGe1nPoxQxzrHv6ah1FGbXFQYQ
 xIxpyZNH
X-Authority-Analysis: v=2.4 cv=FtgF/3rq c=1 sm=1 tr=0 ts=68b0f46a b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=VwQbUJbxAAAA:8
 a=UGG5zPGqAAAA:8 a=yPCof4ZbAAAA:8 a=S4hedQ7f9s0DpHPo1gAA:9 a=CjuIK1q_8ugA:10
 a=17ibUXfGiVyGqR_YBevW:22
X-Proofpoint-ORIG-GUID: i9eAXED2WWudCeVYHg1Avbk_R_mGcXuR
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=nhXSu7jG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=fjTFsQtD;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Reply-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
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

* David Hildenbrand <david@redhat.com> [250827 18:04]:
> It's no longer user-selectable (and the default was already "y"), so
> let's just drop it.
> 
> It was never really relevant to the wireguard selftests either way.
> 
> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
> Cc: Shuah Khan <shuah@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  tools/testing/selftests/wireguard/qemu/kernel.config | 1 -
>  1 file changed, 1 deletion(-)
> 
> diff --git a/tools/testing/selftests/wireguard/qemu/kernel.config b/tools/testing/selftests/wireguard/qemu/kernel.config
> index 0a5381717e9f4..1149289f4b30f 100644
> --- a/tools/testing/selftests/wireguard/qemu/kernel.config
> +++ b/tools/testing/selftests/wireguard/qemu/kernel.config
> @@ -48,7 +48,6 @@ CONFIG_JUMP_LABEL=y
>  CONFIG_FUTEX=y
>  CONFIG_SHMEM=y
>  CONFIG_SLUB=y
> -CONFIG_SPARSEMEM_VMEMMAP=y
>  CONFIG_SMP=y
>  CONFIG_SCHED_SMT=y
>  CONFIG_SCHED_MC=y
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/faqp5sdyrkcaatjsnvoxssck7l2qf2e7kivuepobmc5zdg4mnl%40b5ie7764mkqi.
