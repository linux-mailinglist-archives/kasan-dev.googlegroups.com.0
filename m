Return-Path: <kasan-dev+bncBAABBF6W73GAMGQES4RFSGI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id QHuiGhqrn2m1dAQAu9opvQ
	(envelope-from <kasan-dev+bncBAABBF6W73GAMGQES4RFSGI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Feb 2026 03:08:26 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 07AC01A0061
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Feb 2026 03:08:25 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7d475e17bd3sf16986455a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 18:08:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772071704; cv=pass;
        d=google.com; s=arc-20240605;
        b=NIlfMbP7N2RS3iCPrTggcbbjrhpLS7bBXXx/Z0Yi3QOvZRSThotigXPs4i0Njh1cBm
         kSHFGtlPHPXW5Rvv8QFuU855qIuOCc7Q1Y3gPG7sJ+DZR288y/+O5M/X0dcvyjgEpdRr
         ig+8VpRiXaZX90KW9+YEQK8C1xzTx+x+oBYUaXmpYbkhG5wJk05ptE0lmDAVn4TJGJ4p
         bduSsvbApwcjXM5yEYNnWohxPu6LQGlQhgvQydnJFk8pILZukt8IxhP6T6UIoQQ0RF71
         EKFjW6uuqVx588W1SFlzERh5cmlegZStL44M78oc1H1S9c7AUEiVe6jfJHBoMV/Nrv8s
         MQ4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=/N5WXYb3hVlP/yk746waFRIcZ9jDzqJMEHAigMdSijk=;
        fh=/yFYwJx/FrAf4IGGV8kMuXo+VU1GTl9tmkEPr3hzyQE=;
        b=ib8c1KJSeoFHJ38KKENEygSyzI70sECIiGHUBWjN+LHfZxu9N+lwNW4lfd0spZXIrX
         t49MXgGH3m9QLR1gDJZYs2r3GDai1GwmIwF/Eix2zSgEUS0TJxsdspBdVlM9tkx39Sfy
         rK/R/26n/B8g80UBsPFhnPZNBGprc/PYSr5lnFG59atFTjwXmZEog3LBVjmTfmzIjnXg
         1/+hkI7T69+Rf2LKVGok4CWJDkfW3AVW2MoaQ6x+FeBHU2Sz0qwGk+Esg5rLUqdnSbPp
         qEtDOg3e8oYpmuEftFz4Fnmhnrzxqubbinxl823lqrGNbDJCQkacsuFnF2un3Il050UI
         ZnUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=IOQR4tXi;
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772071704; x=1772676504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/N5WXYb3hVlP/yk746waFRIcZ9jDzqJMEHAigMdSijk=;
        b=UIHtdFzwgVUMhHdtSmkmU4mvB59r+unmpnw+bija5ijyfDysgQGVwXgePDKGvpN5HJ
         X8E/7iTHNGVPadhw3+k4bSPIDPgmpCDcWjoG/gRFxnil/ZwkfUeUomulo/iByHrHhr/h
         +XxgTh1FwERGy8L7qhAbqLHHvC446SHK4tp0rUjEWFpEveOQIz+0NzXMAgbQTMi0eH6t
         c0s09ywKKgA4RaOB2v1JnKOXNmxr1gmOA3ctAVYZWS7FhbBn37ny1DogvRaoHPVtJa3K
         +7hi9PpMJr8ej5XvWQehSYY0uCGTgV+cfCTkdQKZLxyzGoqAiyVSDVo6LCle1FlKlnU2
         lLbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772071704; x=1772676504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/N5WXYb3hVlP/yk746waFRIcZ9jDzqJMEHAigMdSijk=;
        b=HZJHIgasAoRdGTelOiIF3sa4aGCN9+nIc7PnLVAF8aHPy4SFZAJoLn848f28waQd0w
         dbyktoLgbMFW1sWE3tTG1vph3S2zCyy59OSQnd+mTvWnewfTo9XbOtOvksh+ara86gbj
         Or4Th3TLs5SVzFBKYr9sA3/K32roc3ii6s/0cW21Sz2wjgh2aBM17OSXAOVsVkb1098T
         s2kFPFG4ueiBEPXSkfFOMQci+GoezbFU+7NIFM6npxcdAy9AZ0JKFa8fiANrOp0ynpA5
         ALokuEFi266RDKQ0FuJrbcV2sivs4r33ChYaO5DMQdncpiXrolfgSfNfxDuFa7OkMEso
         Uj5w==
X-Forwarded-Encrypted: i=2; AJvYcCVyHjr9CGKtuAdlyq4Uql/iqhI+RzeLS6fvz63Qego1bdCira/a2mJnQvvQyv6T0RpSLtNSvg==@lfdr.de
X-Gm-Message-State: AOJu0Yx19Av/BESOuiSp1SRm51n0jGW3IKCUu1k9ZKxVBq5pa7/VFkcA
	2E+Pwiex9vC7OgTqZkX+8Z6tNObI6M6b0Of6tS2rtZjYlQMyc3cDlfTS
X-Received: by 2002:a05:6870:f147:b0:414:9285:c243 with SMTP id 586e51a60fabf-41609e40e33mr690307fac.21.1772071703826;
        Wed, 25 Feb 2026 18:08:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hg1qcX/7I4GLhml/P7sC8hK1rh3M6w1jg3+1yEzEcq/g=="
Received: by 2002:a05:6870:21cc:b0:3fa:9f2:b79b with SMTP id
 586e51a60fabf-415ede7d060ls510654fac.0.-pod-prod-00-us; Wed, 25 Feb 2026
 18:08:23 -0800 (PST)
X-Received: by 2002:a05:6870:2c85:b0:3e7:eba8:327e with SMTP id 586e51a60fabf-41609f09447mr654698fac.22.1772071703054;
        Wed, 25 Feb 2026 18:08:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772071703; cv=none;
        d=google.com; s=arc-20240605;
        b=DbeLvg+lXmZWfV9CRfnh8lqkpRiX9eZIiPcGuySGGmSFh4skZUsvZxXkdam3qYWYPJ
         hi6xr95/DHvpaLC0c2DsDhTNBFuk3vR5vLkPAZlmvSQuxFxpNv59u+ESWh5NErRMudaJ
         bKevsnVS/elgf5RBySnrrm4dJuavlnL9dHPpDcchkr2YQykkEknkf/whFK4CvRT/Zc/v
         6cppAvdK0yASn75aVCnt98bwN1VPr79nCF57kDKNEXsw1xWEKYCMGmr4WnMIFc6MdbSk
         Ch5NXEMmFFM+Fj7eceLdFo22TXDhYwTOCaEYtZQAbqYxofndZwvOVTmaEX1fgvC8/C4X
         6ugA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=zfLTltYqSe/ND3M3BYUM8dCDtPCvqn6CcMqbwUsZ0UM=;
        fh=b3TVP/gh9SPFbfdE+bFsNLsK8pX+2k4lsPJ6/5Fk0gQ=;
        b=SL66R/Ta6FZBAbm6vk/lh4f90O39MvzvnD5ZrvDC29kb4EDfr7nkYOiPDCzijTGEUQ
         L3dmqFWckJB5d5212W0fyZqu0Ve87C+D90WkuKjiRlkro/9rritVRYAAix4qRMGfyHcl
         Ty2bFddgYY0mj0X3SO8CS8xa5QL1eK9kWTT0083DqA75CDBdI5Oipo1GLBni+jtbl0Dn
         o7fiMAmeA9ffCF3qmDu8CxttiP7103mK5lrQYsxfYpcT27IW37SSNE+SZDFaIAZDBEKn
         OZSOHF+D+SL6xuSRSY3QOVHjqEW5JkAOjqo7whTrizf4FCSADjkqktZ0DuWkO9zUFze7
         dyfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=IOQR4tXi;
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4160d1787f1si20500fac.3.2026.02.25.18.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 18:08:23 -0800 (PST)
Received-SPF: pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 61PNvr2F3277797;
	Thu, 26 Feb 2026 02:08:17 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4cf4k5ydtk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 26 Feb 2026 02:08:16 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 61Q01ANr012453;
	Thu, 26 Feb 2026 02:08:15 GMT
Received: from imran-metabox.au.oracle.com (dhcp-10-191-70-123.vpn.oracle.com [10.191.70.123])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTP id 4cf35g4s58-1;
	Thu, 26 Feb 2026 02:08:15 +0000
From: "'Imran Khan' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        catalin.marinas@arm.com, will@kernel.org
Cc: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
        linux-kernel@vger.kernel.org
Subject: [PATCH] arm64: move early allocation of kfence pool after acpi table initialization.
Date: Thu, 26 Feb 2026 10:07:48 +0800
Message-Id: <20260226020748.1282208-1-imran.f.khan@oracle.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-02-25_04,2026-02-25_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 bulkscore=0 spamscore=0 phishscore=0 malwarescore=0 suspectscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2602130000 definitions=main-2602260017
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMjI2MDAxNyBTYWx0ZWRfX2TM68zV1/Igv
 ZBcYjFroWrZvAlnjZ/KbBpt9iL1lUGHL9kDrje7zIejD/opofl1Y6AOsbbE+5GsTLnFENk41E2H
 NczCtDRCgedaQyUiURiYG7lUBQY2KvLkvdBD+bpLMU2Edrp4+ifaCFRm8XuZdqKinxUAGTxKymb
 IeqsbOe04gvLs6RrWPo36yEWi4FZUc9GzAnxI9RcPiALdgO9KeS2bO4ppqJnzYPzvNNcqIkl3//
 LBlYZIGGaTnTtAhc5zmkq6DEgI1sVDHokDMSI+KxR2geU+myPqTkz7UNl5qCOQ+X4M1Qd0pmgkY
 41HKcNznto3lnkDb4dCK14mu0jMk0l3VWHtB1b2Ugt14W1vmOO4v7g3AsNhs8/TvVefvo1C2Ikq
 LBU5PV3Wbt3mRbPlLEo7qHm4hYCeQfhC8s7VQjPy+kWTlgCR7SaH6EO/xXRkghJFOF+j/AyCv6p
 XVDhdhhPbZWE5cLJJlxgrcn6F6qZmgBIerMeMZq0=
X-Proofpoint-GUID: AihCWpVNfZLyPvFnjNs5e6EBuo6MKpnA
X-Authority-Analysis: v=2.4 cv=b9C/I9Gx c=1 sm=1 tr=0 ts=699fab10 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=HzLeVaNsDn8A:10 a=VkNPw1HP01LnGYTKEx00:22 a=Mpw57Om8IfrbqaoTuvik:22
 a=GgsMoib0sEa3-_RKJdDe:22 a=yPCof4ZbAAAA:8 a=U-mDAgou2R5dctFzu_EA:9 cc=ntf
 awl=host:13810
X-Proofpoint-ORIG-GUID: AihCWpVNfZLyPvFnjNs5e6EBuo6MKpnA
X-Original-Sender: imran.f.khan@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=IOQR4tXi;
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Imran Khan <imran.f.khan@oracle.com>
Reply-To: Imran Khan <imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	MIME_TRACE(0.00)[0:+];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,oracle.com:mid,oracle.com:email,oracle.com:replyto,mail-ot1-x337.google.com:helo,mail-ot1-x337.google.com:rdns];
	RCPT_COUNT_SEVEN(0.00)[8];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TO_DN_NONE(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	HAS_REPLYTO(0.00)[imran.f.khan@oracle.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBAABBF6W73GAMGQES4RFSGI];
	RCVD_COUNT_SEVEN(0.00)[7];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: 07AC01A0061
X-Rspamd-Action: no action

Currently early allocation of kfence pool (arm64_kfence_alloc_pool) happens
before ACPI table parsing (acpi_boot_table_init) and hence the kfence pool
can overlap with area containing ACPI data.
For example on my setup I see that kfence pool of size 32MB is getting
allocated at physical address 0xc3c570000 and BGRT table is present at
0xc3e512018.
This is causing KFENCE to generate false positive reports.
For example trying to access BGRT binary attributes, reports errors like:

[  101.153638] ==================================================================
[  101.153639] BUG: KFENCE: use-after-free read in __pi_memcpy_generic+0x14c/0x230
[  101.153639]
[  101.153642] Use-after-free read at 0x000000002b4fde1e (in kfence-#252):
[  101.153643]  __pi_memcpy_generic+0x14c/0x230
[  101.153645]  sysfs_kf_bin_read+0x70/0x140
[  101.153647]  kernfs_file_read_iter+0xac/0x220
[  101.153649]  kernfs_fop_read_iter+0x30/0x80
[  101.153651]  copy_splice_read+0x1f0/0x400
[  101.153653]  do_splice_read+0x84/0x1a0
[  101.153655]  splice_direct_to_actor+0xb4/0x2a0
[  101.153657]  do_splice_direct+0x70/0x100
[  101.153659]  do_sendfile+0x360/0x400
[  101.153661]  __arm64_sys_sendfile64+0x70/0x1c0
[  101.153663]  invoke_syscall+0x70/0x160
[  101.153664]  el0_svc_common.constprop.0+0x108/0x140
[  101.153666]  do_el0_svc+0x24/0x60
[  101.153667]  el0_svc+0x38/0x160
[  101.153669]  el0t_64_sync_handler+0xb8/0x100
[  101.153670]  el0t_64_sync+0x19c/0x1a0
[  101.153671]
[  101.153672] kfence-#252: 0x00000000e0140f78-0x00000000451bb320, size=256, cache=maple_node
[  101.153672]
[  101.153674] allocated by task 8328 on cpu 0 at 99.989222s (1.164452s ago):
[  101.153679]  mas_alloc_nodes+0x138/0x180
[  101.153682]  mas_store_gfp+0x198/0x3e0
[  101.153684]  do_vmi_align_munmap+0x168/0x320
[  101.153687]  do_vmi_munmap+0xb8/0x1c0
[  101.153689]  __vm_munmap+0xdc/0x1e0
[  101.153691]  __arm64_sys_munmap+0x28/0x60
[  101.153693]  invoke_syscall+0x70/0x160
[  101.153695]  el0_svc_common.constprop.0+0x108/0x140
[  101.153696]  do_el0_svc+0x24/0x60
[  101.153697]  el0_svc+0x38/0x160
[  101.153699]  el0t_64_sync_handler+0xb8/0x100
[  101.153701]  el0t_64_sync+0x19c/0x1a0
[  101.153702]
[  101.153702] freed by task 0 on cpu 0 at 100.057612s (1.096089s ago):
[  101.153722]  __rcu_free_sheaf_prepare+0x11c/0x260
[  101.153723]  rcu_free_sheaf+0x2c/0x140
[  101.153725]  rcu_do_batch+0x158/0x560
[  101.153727]  rcu_core+0x110/0x220
[  101.153728]  rcu_core_si+0x18/0x40
[  101.153729]  handle_softirqs+0x128/0x340
[  101.153731]  __do_softirq+0x1c/0x34
[  101.153732]  ____do_softirq+0x18/0x38

The place of warning remains the same but freer and allocator stacks can
differ.

Moving early allocation of kfence pool, after ACPI table initialization,
avoids the above mentioned overlap and prevents false positive reports
such as the one above.

Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
---
 arch/arm64/include/asm/kfence.h |  9 +++++++++
 arch/arm64/kernel/setup.c       |  7 +++++++
 arch/arm64/mm/mmu.c             | 13 ++-----------
 3 files changed, 18 insertions(+), 11 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index 21dbc9dda7478..25c66f8059d6d 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -19,6 +19,11 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 
 #ifdef CONFIG_KFENCE
 extern bool kfence_early_init;
+
+extern phys_addr_t arm64_kfence_alloc_pool(void);
+
+extern void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp);
+
 static inline bool arm64_kfence_can_set_direct_map(void)
 {
 	return !kfence_early_init;
@@ -26,6 +31,10 @@ static inline bool arm64_kfence_can_set_direct_map(void)
 bool arch_kfence_init_pool(void);
 #else /* CONFIG_KFENCE */
 static inline bool arm64_kfence_can_set_direct_map(void) { return false; }
+
+static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
+
+static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
 #endif /* CONFIG_KFENCE */
 
 #endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 23c05dc7a8f2a..2e9ec94cd4d5b 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -32,6 +32,7 @@
 #include <linux/sched/task.h>
 #include <linux/scs.h>
 #include <linux/mm.h>
+#include <linux/kfence.h>
 
 #include <asm/acpi.h>
 #include <asm/fixmap.h>
@@ -54,6 +55,7 @@
 #include <asm/efi.h>
 #include <asm/xen/hypervisor.h>
 #include <asm/mmu_context.h>
+#include <asm/kfence.h>
 
 static int num_standard_resources;
 static struct resource *standard_resources;
@@ -280,6 +282,8 @@ u64 cpu_logical_map(unsigned int cpu)
 
 void __init __no_sanitize_address setup_arch(char **cmdline_p)
 {
+	phys_addr_t early_kfence_pool;
+
 	setup_initial_init_mm(_text, _etext, _edata, _end);
 
 	*cmdline_p = boot_command_line;
@@ -341,6 +345,9 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 	if (acpi_disabled)
 		unflatten_device_tree();
 
+	early_kfence_pool = arm64_kfence_alloc_pool();
+	arm64_kfence_map_pool(early_kfence_pool, swapper_pg_dir);
+
 	bootmem_init();
 
 	kasan_init();
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index a6a00accf4f93..5a7215daa9ce5 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -1048,7 +1048,7 @@ static int __init parse_kfence_early_init(char *arg)
 }
 early_param("kfence.sample_interval", parse_kfence_early_init);
 
-static phys_addr_t __init arm64_kfence_alloc_pool(void)
+phys_addr_t __init arm64_kfence_alloc_pool(void)
 {
 	phys_addr_t kfence_pool;
 
@@ -1068,7 +1068,7 @@ static phys_addr_t __init arm64_kfence_alloc_pool(void)
 	return kfence_pool;
 }
 
-static void __init arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
+void __init arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
 {
 	if (!kfence_pool)
 		return;
@@ -1107,11 +1107,6 @@ bool arch_kfence_init_pool(void)
 
 	return !ret;
 }
-#else /* CONFIG_KFENCE */
-
-static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
-static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
-
 #endif /* CONFIG_KFENCE */
 
 static void __init map_mem(pgd_t *pgdp)
@@ -1120,7 +1115,6 @@ static void __init map_mem(pgd_t *pgdp)
 	phys_addr_t kernel_start = __pa_symbol(_text);
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
-	phys_addr_t early_kfence_pool;
 	int flags = NO_EXEC_MAPPINGS;
 	u64 i;
 
@@ -1137,8 +1131,6 @@ static void __init map_mem(pgd_t *pgdp)
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end) &&
 		     pgd_index(_PAGE_OFFSET(VA_BITS_MIN)) != PTRS_PER_PGD - 1);
 
-	early_kfence_pool = arm64_kfence_alloc_pool();
-
 	linear_map_requires_bbml2 = !force_pte_mapping() && can_set_direct_map();
 
 	if (force_pte_mapping())
@@ -1178,7 +1170,6 @@ static void __init map_mem(pgd_t *pgdp)
 	__map_memblock(pgdp, kernel_start, kernel_end,
 		       PAGE_KERNEL, NO_CONT_MAPPINGS);
 	memblock_clear_nomap(kernel_start, kernel_end - kernel_start);
-	arm64_kfence_map_pool(early_kfence_pool, pgdp);
 }
 
 void mark_rodata_ro(void)

base-commit: 6de23f81a5e08be8fbf5e8d7e9febc72a5b5f27f
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260226020748.1282208-1-imran.f.khan%40oracle.com.
