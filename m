Return-Path: <kasan-dev+bncBCM3H26GVIOBBXMD62ZQMGQEIJKBXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ACBA91AAD8
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 17:14:40 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2c7e48b9f80sf8892785a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 08:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719501279; cv=pass;
        d=google.com; s=arc-20160816;
        b=AOXi79aYDLw8/BDBsHZ0PW8ZZG4zM0G5dsdyclhIT5+FjWnJtzjZ9OPlqE0AkPe9JJ
         KvS2BV6XVbMBMjAHA3wjPff0jtr6lWkcX55SIiM08m65wqu+8f5rso37bK4XJXNd1Z+p
         0gEUk+786qFU+QYzFvrTHKbEC0J+7UfPGpg8n0ZxUoKT9QB9J3c0x6VpmLM/QtiCmsg6
         MITl1vTKYQKJztG3gGGzRJ+SpR2UISpAYoMGAuRMTZxZy+eDzvy+NIaKtLGp5AqiBoDA
         eoRVJg4pLJwavPxHvWy1Y1DuqYyq4/79KCONuKfpao5GIZPoHUEOGxnEnUugeWl7xD3D
         pOPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sNF5M8d8SSSA3nnsJktp7dA90HlYDw8AraS4pSI+Yc8=;
        fh=ZXUw8YtXfVm4Ea2MpCM1K/uDbZtIYEGaR0xdFTkxus0=;
        b=VCdagOg3RG0vWB3P8Bed10Xvd6yRRqj2VOc7e6DZdonvy4zSPRc29daMK67akJ8I+2
         yeAB6M6I2XJYMy6awY4Cl/KG2c0kG2CfPNeDKKqcd7ejSbVadW1dTA3f1G4S/b/jl1fy
         OAQEGQMHYDDbOWV1nCoqm/Jn/WeF83P0wa7o7/5EbjLEvIjNwPIWr0FvwqcY1po8ziwM
         FfVhcowezN8cO8kx91tgVnjTbWAvofUo6RUVHPWha4t5DQ71eP2V55+eAJZLQLRxhhyN
         kpaWS2SIXztfVD/RjHUic1V/G3oLTglEPS21i2ClAJHts/lvg2ckkpEy/ri8gfnhJDaR
         oswA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="fJh/dX8Q";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719501279; x=1720106079; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sNF5M8d8SSSA3nnsJktp7dA90HlYDw8AraS4pSI+Yc8=;
        b=JR/zCB3jgfpfElhhQxJLqXoRBOkhMWZEauqMnyCfsuSoreTOFHz7/MwbUR0mvGiSOe
         5qkF8PofGaVxrB1oO0PRCfYNBtztFZ9GnpP7ZmB8kOWYnvVttUN+zc+ImV8CS1pU+7KF
         HwrOJmdLhqV3Tz4uDzIA9bP3n2tNW1/ouspzkJ5r3fR4JFZV1tjH6mVNIY4wrVS8JR2Z
         rS5vvrL/MCBOywRPw0tMN0VL+QswLuJxnF95nkyXxmRKyt+8GtxRqgljJnLmLwLeoqhN
         oFIoJPsdu4wLlw+9qlgPtSXo0wug/6GTMl7fKdphYdC2UgRbC3RoCdU119zgXTd3R0cN
         zGOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719501279; x=1720106079;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sNF5M8d8SSSA3nnsJktp7dA90HlYDw8AraS4pSI+Yc8=;
        b=SGR8556PBDpPAWYmN4/OIkDPR2wFBUEiosuh7GWwu6Jz2okxJQQsXxfTmrySiPdKkD
         Gs3h0FgjehO681COpdqMX3mRkYP8QRYa5hYeyF4yr8Ynt4qJ41WSsH1TZOOz2up+TnTr
         WO6Y+I7zZNpROJdxrrRC17f4WG57TIA7S32EYPJemk2y+B/Ip4NGJrS1HEO/+4XUuj4c
         o8yukb+5OTGB/VPfl22qTvXVDvx5kliOwr2opMjr6RJnIcL3UMlldgNrXcwmhkUjj4ld
         77Vs2Lx+1oh3Fdwx2hZuKQDiyiWi8X79+7aFen1h9Ez+C+XQK+SjXiJvsvT23vlw901P
         TcdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTJp++dqO7cb1mYooaY4Gak35FFuIw2YyKRLveZV7jXi3H7IZgeiOMHctHQG26IgSSeSPuUnZasCpxmljuMBfUunemm+2aGg==
X-Gm-Message-State: AOJu0YzX2JPmUH34nYwIRiiR36ZLPD1SKHg9Ow8AG+Btb2BFBBMK6RyO
	2nuaIDI5AXf4lryALV+nWl6uztxO6Z0iRb4YfMGq8JM+SYd//5lT
X-Google-Smtp-Source: AGHT+IFVeoiiaeUp4bPpnSAI/foMoDXobkYDfBlPvpRsI0gjSo2wBB9VOVoGC01nsh7A4DvR6TGDmA==
X-Received: by 2002:a17:90b:3003:b0:2c8:e660:6756 with SMTP id 98e67ed59e1d1-2c8e6606b97mr3189578a91.25.1719501278668;
        Thu, 27 Jun 2024 08:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3041:b0:2c5:128e:23f with SMTP id
 98e67ed59e1d1-2c8e47556ddls824918a91.2.-pod-prod-01-us; Thu, 27 Jun 2024
 08:14:36 -0700 (PDT)
X-Received: by 2002:a05:6a20:2904:b0:1bd:28d1:fc5 with SMTP id adf61e73a8af0-1bd28d1113emr6192422637.6.1719501276684;
        Thu, 27 Jun 2024 08:14:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719501276; cv=none;
        d=google.com; s=arc-20160816;
        b=xXTXeF1TtveloGz5qUfpymJhVijzxaERhTV8dPbH43wIEB4W9FM7T5K1cEKeuDofaT
         mDmqUh5i5vDDfJhmln2xy9LLtQ0xJX8DLOY717DAsloF0OiehD80aS8AwsLNpU4r30LL
         hnioqxhEvvetIepd1Iz44Im2TQsDYx6TxB2bz/RH0o/g4ibctVibDDKiFKMjykxGjO0s
         ioxxmXBlNUFOJ2527cTqoK9NxxejqtX0bLw2nrv4ZumKk4X1PvruwNlkYdA1AoQB3G0j
         L68huPhAeVgPOuoxNkw3gqWjYIuo0nIQS0n87imV94xzQrTQzTTNofV2HL95CjxzHSzo
         ALoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QdDAGtNIksLN3TSRjQF5b124MTmCkp/A2KggmGZ7GMg=;
        fh=vb5BkVztxUtCuYuo/HDI25G/PG/z7Sdw2QggywAtCNI=;
        b=HSRKDSSN/ekqyRHq/C2cP1kLpdNtv/UB5jQ87UJOxEfGtndouHX5wwq02hN3pbk4Zv
         TwH2h6/1XAu+O5HtD6ysZUiXWCGRIYhmmtWMTcSMdzEK8DOJrk3+2spXzDnkp06wARga
         SWh9to/az7ELmEKlVbFctksZYM9KdblQkzaSUAQ+QFlfgSZQFM0i6sgvJ66W5zo0n6zn
         J0WeLURQcJqpLmLRiDzMPTxrqh9tOyXyjjw0cxbIO+TO59T+NfMNEcTx/vOnkDwbks3P
         k92Zyj7xguzwsLbr2IOIvXDQKeOuxPi3tIY/Y1l5b+p3if5+fX/PP9UhzSL7QS33RyRV
         qWbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="fJh/dX8Q";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-706b4b01f4fsi63358b3a.6.2024.06.27.08.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2024 08:14:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45RF47r2016202;
	Thu, 27 Jun 2024 15:14:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 401909r9fc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 15:14:35 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45RFEYQY031080;
	Thu, 27 Jun 2024 15:14:34 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 401909r9f8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 15:14:34 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45REMfW1008184;
	Thu, 27 Jun 2024 14:58:01 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yx9b13fdy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 14:58:01 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45REvvDD55509334
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 27 Jun 2024 14:57:59 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 62E992004D;
	Thu, 27 Jun 2024 14:57:57 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D34A82004B;
	Thu, 27 Jun 2024 14:57:56 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.182])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 27 Jun 2024 14:57:56 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH 0/2] kmsan: fix sparse warnings
Date: Thu, 27 Jun 2024 16:57:45 +0200
Message-ID: <20240627145754.27333-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: y6p9zJc1wjXWp-Ja6k75xUtEZP9K9CNK
X-Proofpoint-GUID: ON2OLEdnX9O3qYUGjGa9cm7TJjNipMIl
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-27_11,2024-06-27_03,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=483 lowpriorityscore=0 priorityscore=1501
 malwarescore=0 suspectscore=0 spamscore=0 impostorscore=0 clxscore=1015
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406270113
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="fJh/dX8Q";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

Hi,

Kernel test robot reported several sparse warnings in the KMSAN code
base [1].  They belong to two broad classes; fix each in a separate
commit.

Best regards,
Ilya

[1] https://lore.kernel.org/linux-mm/202406272033.KejtfLkw-lkp@intel.com/

Ilya Leoshkevich (2):
  kmsan: add missing __user tags
  kmsan: do not pass NULL pointers as 0

 mm/kmsan/core.c            |  4 ++--
 mm/kmsan/hooks.c           | 15 ++++++++-------
 mm/kmsan/instrumentation.c |  4 ++--
 mm/kmsan/kmsan.h           |  6 +++---
 mm/kmsan/report.c          |  2 +-
 5 files changed, 16 insertions(+), 15 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240627145754.27333-1-iii%40linux.ibm.com.
