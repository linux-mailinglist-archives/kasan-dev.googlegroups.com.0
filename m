Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBJOYRGZAMGQE26E7T5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id CB7468C4799
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 21:38:15 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-6f47c380709sf3076671b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 12:38:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715629094; cv=pass;
        d=google.com; s=arc-20160816;
        b=WR9oCSKF4SZdYNbl/95VXYd1RTRnp4I7VwQq9QftvUNzIC1J86chMTOdwyHKzuCCPD
         WxA76f/KdcYpTktLkURZj0mjUPHQQiidM4eFXe+UcHDzJvGA2h/xowmnZy8h4ZmNxHIk
         25fJNPwFMSNQmwTcn7xuesCDPbYbrpMcyZsKgccObK4PJwkOfF/utIw6cyXYTNXIBPCq
         rRwGq4rNKk0Siz1fCwjRqGsnkV9MSZIQ/vc5GBPiS/E6p5MdOq5DqFLmsvaZ7Qxtl8mJ
         11FNjXYSIXq4Fz3qI9JkwTZDngTbQyzPit6Y7wbPADVHtuNLAMAsl7AHLLwzhR9/NrVV
         e7gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=tL8pTCF9UJDgGbgdFqWHq7Ebgs80UU2ZM1caZQbkmg4=;
        fh=Op1V3nYuBmkbF+D+dmhs64yULLSa8IEdujw0oY5dVYc=;
        b=h8ksE/tC4WFP5XMV/e0rH/VUxQdrtVpwF1RpyDeNzfLylppLjACJltmK6aAhVX694S
         QdwWI+MtfL1ux0VGPTW+5VVLMXP8VmffKaZUDx+ypS5s6rqLUknaea8uXbZFvpuWXajl
         JzgB4go/ceoC9xLJpDHNiTp5l2POGdtPVZOcqFY3RF28Ep8i1synSTBC2PCmBFl05aMF
         GRBMeoZvr1iy+eZuh6z1HQyTy84HEi9L4d8q5GSCc8xIIu9YBk0DHIN4IWuBi5m5HzJd
         kVc0+IKtO0fijaprij8PPsyLHbi1g/H4HfvyTeUe+mHG6qmTdQEaAozMPC5/oTnh9XJD
         CcKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=IbB6uTSl;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715629094; x=1716233894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tL8pTCF9UJDgGbgdFqWHq7Ebgs80UU2ZM1caZQbkmg4=;
        b=IQ6Laa4gfVWO58uLjqDm3ZsdZiBo2nFoaqF6L9ZKIO1BB7uxVXXOOJgUQYK0dhlI+5
         ZdUQ5tFp+FsP0EZ6HV/YamfOddP8xeh7yG0rFj+1sbtgmv2DrIj1hbyhGo592aR0Qn7z
         bfS1TssgTHo68QKp4V5tm1m1qf9YQdAkRwoIQa/45RmxpGPZTC3GphJ/g3Y0jUbKCkVm
         EIrqne6B8yJ0/trW1H8DMLLr+LOKP5fLKpTaoJ70J0rQP42XsPxyPXCbqoECWBY4o72Z
         4IQk0hTYvZtWt8IXQEwQPjDhG3EXy4s2YBfnAzzvv06h3qfk+6Q9Md+X9n1Hn01XDae/
         ic9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715629094; x=1716233894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tL8pTCF9UJDgGbgdFqWHq7Ebgs80UU2ZM1caZQbkmg4=;
        b=KTa8YGE+uPfkEfj4LPSkLmW39jyDRi7Ucv5/qXj+YaV+Uc6ZtXWUfA++r7TFuqIajw
         8d5jUedAjddvp0yHEaTch/kr7Wby0v4i1r6RnIO7i+q4diiPJwgRUX4894COmKFi8rsm
         PNAl5dtlUF2qGdKugyK8BR9SWNGVFx0d2J6ag/4VbhU+zq0rENHBI6w1OPcgpL2UZmmV
         9zQBmGc9uzNhWDxvbnynHXzYCGxd+eLMl+5r6B42+uIGI99DU3ct9oVvOOErKZXZBiQs
         phI/4NBj8ogUNCsqMdzVXqDbTeF4TkZi4TnBtyyddzhNNG0RclOgHHwG0KL/bGSPr/se
         1d9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJjc7RY1MCtTEV0wP7L2z41D87GaV9oUaG42dei5bC2Fe0JLgPNZOt1GpeZK3vFf7yU/6x9sa6TROZ4y17JnmvOMtWlLVFTg==
X-Gm-Message-State: AOJu0Yx+srw9D+RP2MZH7nEnUEis/Bh+siZGHWrB4FpjYYIJMWmsZHmG
	Z7glzynVzcPUZ8ySLRBcSumzz40lUd7tONwJdRB3HY+ZOridaSaq
X-Google-Smtp-Source: AGHT+IFG0jcT7I4k1P3aCgiLd4FpuNBpAzbY+aAOZdYwo2FCa7RbXsTIq44vW1iMbMRbhSx8YST2HA==
X-Received: by 2002:a05:6a00:13a2:b0:6ea:b1f5:1134 with SMTP id d2e1a72fcca58-6f4e03466e7mr12186233b3a.27.1715629093901;
        Mon, 13 May 2024 12:38:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:301e:b0:6f4:78b1:6b79 with SMTP id
 d2e1a72fcca58-6f4cae1657cls3326298b3a.0.-pod-prod-04-us; Mon, 13 May 2024
 12:38:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+4+9gKMtiuz6r2xKQGO66wNYPsjJ1r1MQFfCiY6U18gUz5A6H5hiwijzZBTvN5OwjAtPntGe3QAU+GFpxNDc7eAHC/4DKYA8Yww==
X-Received: by 2002:a05:6a20:5b19:b0:1af:438e:7484 with SMTP id adf61e73a8af0-1afde201d12mr8769281637.59.1715629092646;
        Mon, 13 May 2024 12:38:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715629092; cv=none;
        d=google.com; s=arc-20160816;
        b=cG9ve4YjTqX0YHwtSIujfsAgGwcO//nDFGenuk6FHc1pgf7V2U6ojOn5QxQ3s/NVPR
         SxY31O5Eof+0sO8Dt9FjA8TqxJDK669PtmbrYdc8S/UeoUnqmJ/iI9vwvhhHZ7xH9L6f
         orwzO+IxqUj+rr/rX1o8k9dqKVn3OBgnrThBnFnu2HLWwURRwGwKzJETjWqJCFL9dRXa
         Gg3V9DcPKZXXQLij7TFmYOAmHeP/1wMGOSyu6s+YZmZODinL2e6jU4EMFYeWFqUX+Veg
         g30se1NnMPpO7uVaAuAYiPyiY/A7W6JsdGIl49X7gOtQJp9nfXlTHzFLqT7u3fIvek+o
         nPSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=bFyFaa/NQXCcTpURCq6Gc7kDIXa680HCq1Qyl3U6MHo=;
        fh=eDdK40krtWyjNnSFs4h2SepZVdd7qicqp3ugeX6jaYw=;
        b=xc64zlT9O4AZh6EKUzRskfKJ4V1i11UTEFtweD6dZrceTYRIyP+p/0uSisIBgCwmV0
         FG/6qf2bOhT6FCTaz6V2PAkpZhg8//aPRZ1ELrQib76lYSSTP5sX7vXkubV69RI3ZlPb
         X9uN77vC0HuOPDnKpNRofqowroAdLLEvw5+DqBXwAOiDm+qryAnlrDkC+/KTvHNE+uJv
         sX1KiNdVuIseDD6KPOAP84s7NobLdBPmwnUJ5JmdSQAF3m7ZPRpTGMllhODVKvhtuQ+A
         09MyF5l+xNGV+YMOd/rCeF7/R1U6QKRu3pV4h1ouutEXim2BRf7OnU4N5FRWt0sYj43S
         vArA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=IbB6uTSl;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-6f4d2a97184si619604b3a.2.2024.05.13.12.38.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 May 2024 12:38:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279869.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44DJ8f9U028204;
	Mon, 13 May 2024 19:38:04 GMT
Received: from nalasppmta05.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3y1yp5cfa7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:04 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA05.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44DJc247026805
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 13 May 2024 19:38:02 GMT
Received: from [169.254.0.1] (10.49.16.6) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Mon, 13 May
 2024 12:38:02 -0700
From: Jeff Johnson <quic_jjohnson@quicinc.com>
Subject: [PATCH 0/4] mm: add missing MODULE_DESCRIPTION() macros
Date: Mon, 13 May 2024 12:37:37 -0700
Message-ID: <20240513-mm-md-v1-0-8c20e7d26842@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAAJsQmYC/x3MQQqDQAyF4atI1g3oqKBepXSRcVINONOSqAji3
 Z12+cH/3gnGKmwwFCco72LySRnVo4BxpjQxSsgGV7qmbKsaY8QYsPfBt65h6qmD3H6V33L8f56
 vbE/G6JXSOP/Wi6TtwEi2ssJ13f5/iul2AAAA
To: Miaohe Lin <linmiaohe@huawei.com>,
        Naoya Horiguchi
	<nao.horiguchi@gmail.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Minchan Kim <minchan@kernel.org>,
        "Sergey
 Senozhatsky" <senozhatsky@chromium.org>
CC: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, Jeff Johnson <quic_jjohnson@quicinc.com>
X-Mailer: b4 0.13.0
X-Originating-IP: [10.49.16.6]
X-ClientProxiedBy: nalasex01b.na.qualcomm.com (10.47.209.197) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: uKwSFenHOLiW_NjIv5wDDoqkhrTJ3KjA
X-Proofpoint-ORIG-GUID: uKwSFenHOLiW_NjIv5wDDoqkhrTJ3KjA
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.11.176.26
 definitions=2024-05-13_14,2024-05-10_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 bulkscore=0 suspectscore=0 clxscore=1011
 lowpriorityscore=0 spamscore=0 malwarescore=0 phishscore=0 adultscore=0
 mlxlogscore=804 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405010000 definitions=main-2405130131
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=IbB6uTSl;       spf=pass
 (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

This fixes the instances of "WARNING: modpost: missing
MODULE_DESCRIPTION()" that I'm seeing in 'mm'.

Note I'm not using an "everything enabled" configuration so there may
be more left to fix.

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
---
Jeff Johnson (4):
      mm/hwpoison: add MODULE_DESCRIPTION()
      mm/dmapool: add MODULE_DESCRIPTION()
      mm/kfence: add MODULE_DESCRIPTION()
      mm/zsmalloc: add MODULE_DESCRIPTION()

 mm/dmapool_test.c       | 1 +
 mm/hwpoison-inject.c    | 1 +
 mm/kfence/kfence_test.c | 1 +
 mm/zsmalloc.c           | 1 +
 4 files changed, 4 insertions(+)
---
base-commit: dd5a440a31fae6e459c0d6271dddd62825505361
change-id: 20240513-mm-md-9bdb524ea9a8

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240513-mm-md-v1-0-8c20e7d26842%40quicinc.com.
