Return-Path: <kasan-dev+bncBDXL53XAZIGBBIMQWPEAMGQEBAWXNZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 01929C3C436
	for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 17:09:08 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-33da21394adsf1488268a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 08:09:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762445346; cv=pass;
        d=google.com; s=arc-20240605;
        b=JtwOAuldl+6gl5xexCpq64gJJAVWiG5uoswnKSzhvS6njLnGEwROSKwXheUH7ULXU5
         BWW+atM1ITvfob/fSWhIsDy25YNxYH177wQaugerJiwDaJftPZhtK/b8PAqNInctCWIO
         Rxarvjz/BIspmRsVr5jBsaUP6r+JXoRbPgRlVPWQ3tCruWzBYFlf5dazGWLKe9RYgQsG
         ATEA7BopYPXCs/Ha7FYhDzb3C5xz2MK7yrdp9rKrT7d1DmjLPg9F0oKttIDMwin2z7y5
         ihDJJYbrONUT/hi6PnEVL/pbejl0YNDi05w1t5L4cFJ6Z1an+7bmxLPn64SRpUU4GnwI
         GYZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=IHYu58Er/hFnwIxgctCf3ks1pNywPhnvCJzmTV9hlZ0=;
        fh=u4zbFySQ4AfbXqsjcTsgQAiwVKScqQ+G5+2f3dwcnoc=;
        b=RhOXO3v8Kf6Srz5EvZMI2gM2niA5LUl8irj2wqCMu6XFaLns4gADCOVtk3oS6OHA7f
         xzVKPW4+b5PZT6N+7AWHMf6OjNGmmwZCy9ydpMXBSvSp1TOWjK7cbNklVizKxVYxIQkL
         xkRgTtYVQC0o9Qr58UAv2JjQhFLKw2SDfRoVis3niyWZVWTvc5SJpSZ89BwhcasIKn92
         xr8npnWgWsPaEY+z6olnYGI8SbGYpVsDv+9A5BYcn3uRS9pYfFr3vv5SYUxkgJ10Miyk
         ALD3YbOn6DT8bXMhRS+V+Ed1DQOS3DDZ4w35UFz5rs5SYVPLIUfgoJ6/okUqhVS1VgCg
         gdgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Age+i2ve;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762445346; x=1763050146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IHYu58Er/hFnwIxgctCf3ks1pNywPhnvCJzmTV9hlZ0=;
        b=iNJlU+q9PqmlFIbUtBjmlNrt8PpmNJIL/R1+YhA3s7aXRkpXBlvOF1L6b4M/1q5ayA
         TcaYXrhQcxqYBHWPWnECxWTtxhRmE8vcQk0Z57ffst6AQHSkh0ODeeet6sGkCEnPFzVe
         W8sr6zV4HcSsJfkk8usDyRJpNUZ5WEbZDsjW0NxVOkVO1kFHCp6ZOzKri8aXb5FqKOj7
         2UgDtxqT3e+Qc4mjQIbCur2O2Ig8Kd6vT6/7Tf1SkCfiTX3juwunWDPklEP8uskUUeFx
         Sv+jEt7FKovKVUeXXPUWVvlcxlVVdUiqFYNE1wtoOj73xwH+WhBHK/wHpFTfbkCknyNE
         C8ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762445346; x=1763050146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IHYu58Er/hFnwIxgctCf3ks1pNywPhnvCJzmTV9hlZ0=;
        b=mTnk6P92WEXvDEJevNBMurkIJBuV/mG+2+pW/ccJJYNCjfCcnGbbYWtLyc+rgyCUXK
         d1lzdYqkwJQzqYKIFkSRzIANJQn+thPb1jdXvUu9zdBdXqgDwJ3fiPbJH9GVxNl9iFF8
         NShI4fovL+8Ncus3sqwMbYT3dY0lizQfj+Cv5nIlvq+YahzmjqCN89DkJ/8Og70HY9sU
         8nbNXGn2KFulI++8P+soWUuziVPBAcP2fkSMgthZnDjaEbWTDrwypHqjRxOaoZtg1EXo
         qB8d8d3xm4nfIE6u2t657t+luatOuN4Otl1VTCMQRCRH6kvu4qsDfrZJjcTuzb8Q7ARg
         N4Kw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXxda2S5//+UOC8tdFgGge0cpCW0HwcL91sUYjQWvomjGazp5CCMx08Opu8nQCwksivjG86Ww==@lfdr.de
X-Gm-Message-State: AOJu0YxqoOH85RXR+ngImOxBRe6cs3GvSHKjU5VhRTVOSbxKO355RuEo
	qspGDCjxPyR9EKzfpKgoyWTflOx4MkKZQ3bAemhgmD7G8tNTM4ETY/RZ
X-Google-Smtp-Source: AGHT+IGKFjNuUU9Qft0LSoqs6jhJgvgGmdNfUVi3S92mXyJFbmN+gfO6K6+6ZXggftibvX4LZ2ol1w==
X-Received: by 2002:a17:90b:2e4f:b0:33e:2934:6e11 with SMTP id 98e67ed59e1d1-341a6c45622mr10700773a91.11.1762445345657;
        Thu, 06 Nov 2025 08:09:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aq9jQDP+ubklSmUVx0g5J3sQW3NVoYsb6bDm6EYeE7hw=="
Received: by 2002:a17:90b:3e84:b0:330:4949:15b5 with SMTP id
 98e67ed59e1d1-341cd2d6162ls1496923a91.1.-pod-prod-07-us; Thu, 06 Nov 2025
 08:09:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV54H+wiCgCpahxqFVafit9KuNkf8wGvHiE1RJ0FGUrbdQ+olrwBZLS6VnBUblBuGG2dXSdCSUaH6M=@googlegroups.com
X-Received: by 2002:a17:90a:bb82:b0:341:8ad7:5f7a with SMTP id 98e67ed59e1d1-341a6dc8ccdmr5770559a91.18.1762445343892;
        Thu, 06 Nov 2025 08:09:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762445343; cv=none;
        d=google.com; s=arc-20240605;
        b=hza2FD8trWrrSuJqLxOA+phj5d3Rx8t4rzgd5WCtsS8+cksiEMaI8sUiz7SXhqnP1S
         ERM1I+tir8qBWc036Nn6r0zuxILESo2lvIS5Md1uZE599LGOI0LjJENfFkhm8vVTlGKf
         /b4r5nMd/uS84Op12jjO3XzjXW6nUEH6mq1BARkojnG5vS74nf0iUjGpu/ygWvMZlLx3
         nEgw1NOLjoMzFCAjvFJF3CWyeS2Lva4Yo0g0Cy6HVW3uUmAhMG8gvR5ZaElLsqwHi5BY
         hvRFedpJxfiXS7uBtxskI/r93VBAJ7z2FsmXfsYUhWqei9Mr68kEIRQ6+qZU0peACiIm
         ellw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kBkC7zrPOewXW/Pk0CVDrxMn8x8sMd++XtEVOn85zQ8=;
        fh=05xDZPCJVkot3PeIiD3W9iaPvWiXB7vxfuBVYOsVC1c=;
        b=RkcL/rVGlXSUdyhw9w7CjHajU2feU9FYZCqgdQ+U27NH2oQCGhUWjdGBaRD5tp7uTB
         ajVOWsieXWy5+G/ISH59vlrc1PrI2UMCyrdq5P6GksOsYfo5wPzkXmXFXswfAxJYAEvK
         rQISEgAGggJ+lQTS6TjHGxsMRbirg5Q8I8ZEu+xniV5xV8VbCd7BMUjnGqIxsS9GCgB+
         BQul8VcCS4g4vAAvQJzh/wH6ioCTQfFex7aalKJDBCDFkPHOOsdMlvbEQ1ihy16do/AJ
         3Ab5H9cORH/1lEbvI1iFdDTYsRHtGzWQOznt4IV9dVS696ae2ILC4PaRxnmeqyOgYN66
         u6Bw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Age+i2ve;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-341d12110fesi45454a91.1.2025.11.06.08.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Nov 2025 08:09:03 -0800 (PST)
Received-SPF: pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5A68oc4A030782;
	Thu, 6 Nov 2025 16:09:03 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a59vur6gn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 06 Nov 2025 16:09:03 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5A6G5juR007347;
	Thu, 6 Nov 2025 16:09:02 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a59vur6gj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 06 Nov 2025 16:09:02 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5A6Eddvg027371;
	Thu, 6 Nov 2025 16:09:01 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4a5vwypfgj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 06 Nov 2025 16:09:01 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5A6G8v4h32113122
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 6 Nov 2025 16:08:57 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 59DE220043;
	Thu,  6 Nov 2025 16:08:57 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 65D9820040;
	Thu,  6 Nov 2025 16:08:56 +0000 (GMT)
Received: from li-26e6d1cc-3485-11b2-a85c-83dbc1845c5e.ibm.com.com (unknown [9.111.24.158])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu,  6 Nov 2025 16:08:56 +0000 (GMT)
From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org, Heiko Carstens <hca@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>,
        Juergen Christ <jchrist@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>,
        Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Subject: [PATCH 0/2] s390/fpu: Fix kmsan false-positive report
Date: Thu,  6 Nov 2025 17:08:44 +0100
Message-ID: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com>
X-Mailer: git-send-email 2.43.7
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: JOWFrIeWMqn245vgRdby_F5E58YycLMN
X-Proofpoint-GUID: RJ6XjdSFawZ2LFKDN-n-5Vl7DDYv_MyV
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTAxMDAyMSBTYWx0ZWRfX1ELoPqIfaNGt
 pAGzcEvZn/IFCkh4ow9Wt7zqiZLP3CvoGPoEwl7ACHl0M5ihGA8+jBbE1F9O5mP34x/ZxB59+Hv
 wGII6SGUw1pp8AyxgFjzqUgev8DzvHk6HXlnRqqv/1hIJlCAvPxVUG7a18lAgtrV+FZkovdbu8z
 +Zm9Ywgkn4KJ72fqd0/dT5ypV12/sFlm5OYRbqorr+KF9jh28OJbCRzujL7BanbQi02FAYYTRkT
 7qX/geCOAyFBHeYH581bkuHLB7Mq6avMqfhliGyeHLcoPMONQEXOOf/l4YHr6ooOMInFyaekoi6
 U/Pt3mXlAN8xAmMZXjmIVfgzRE4U5gSD+hlVeXtlX26SOoYRpNclm8/fxTYnTrGyL9DiKdjb7id
 +yBQJcQIc9/mAcdEnuQphbZQQ9z2sA==
X-Authority-Analysis: v=2.4 cv=U6qfzOru c=1 sm=1 tr=0 ts=690cc81f cx=c_pps
 a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17
 a=6UeiqGixMTsA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VIxkIzLlmwRAJRPTlxkA:9
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-06_03,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 bulkscore=0 adultscore=0 impostorscore=0 spamscore=0 phishscore=0
 clxscore=1011 malwarescore=0 lowpriorityscore=0 suspectscore=0
 priorityscore=1501 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2510240000
 definitions=main-2511010021
X-Original-Sender: aleksei.nikiforov@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Age+i2ve;       spf=pass (google.com:
 domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

A false-positive kmsan report is detected when running ping command.

An inline assembly instruction 'vstl' can write varied amount of bytes
depending on value of one of arguments. clang generates kmsan write helper
call depending on inline assembly constraints. Constraints are evaluated
compile-time, but value of argument is known only at runtime.

Due to this, clang cannot generate kmsan write helper call with correct
size and a kmsan helper is implemented and called to correct this and
remove false-positive report.

Aleksei Nikiforov (2):
  instrumented.h: Add function instrument_write_after
  s390/fpu: Fix kmsan in fpu_vstl function

 arch/s390/include/asm/fpu-insn.h |  2 ++
 include/linux/instrumented.h     | 14 ++++++++++++++
 2 files changed, 16 insertions(+)

-- 
2.43.7

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251106160845.1334274-2-aleksei.nikiforov%40linux.ibm.com.
