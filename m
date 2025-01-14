Return-Path: <kasan-dev+bncBCLMXXWM5YBBBTPPS66AMGQESLNVNXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 864EDA10062
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 06:36:15 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2a3c59f8c1csf3257799fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 21:36:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736832974; cv=pass;
        d=google.com; s=arc-20240605;
        b=MDS6q2jVNWRWKHJkgz77nfgCdHkb0qtQW9HaRdt8C91MzEw1sUL1bDb0gsn+LZ5r5R
         okSjCRfNEXdC8RARjkPy25o/oVYH8+w4S7kNxP+z42i2ydyzWp2wpCiSx5r9FJ3uL+ae
         I5lm9c/eDKrolHFkz+5ni5XzWBG+Y4omydnhRlpYo8HkYLZuvv/boqI89cX8/Ivj6aJe
         f3QqIT7zz3IQaDtS44RUfNi1/4OFUyajiXIaG12+xgtx+wY+eRGoVwxWySOsm/RHqS02
         detKaxqBYq7ShgObtZB1bUFfNczWw5eXbpCf6T5q3y5gh4T+Bsci1yOWEcvwt1Yz39Oz
         ekYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=EhwVeMbpIC32b27tnfWncl238UUeep0IR8qdkq8LeWI=;
        fh=VKjQ37Z/HKJgPCeuwkBWBsrYGXd+Qk+8I0qcqKVY7Vc=;
        b=cCYcYn3XmSgCFAnOWqaEDpuD7ZmSuGhqDu2DnYGyUCXxTTwBCT+KFRt8V1VKOpKp3m
         L/DNDlYDATyR9h+Oj3Cz7FXveQW/umiuohwQTKEmxzoBzE9RI1A7c23vCCtyO4QexFoc
         oxUsgrve+ILtAgm4FQL5aiW4y0fqSxjHNY7DtwRqKKpFL8EG8Dzw31GMK34rj+EccTjS
         ICNmlTEVVZvMfTIFVt7T8K69CudVQmT/JogjoDiDPQwig/1dioOFbpeCQW/bGe04mwz+
         oM2gfOK2teIl0bfYUcn6fQoKEgBpC0gDyAO/Yse2PnNQ/aEeq1tIn6sGBpzPJjaCq2eV
         G2Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=JCcY18Jy;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736832974; x=1737437774; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EhwVeMbpIC32b27tnfWncl238UUeep0IR8qdkq8LeWI=;
        b=oKqPfFDhDpOl0V9pM9fUeFW5i1ZRcdK0VOm1m627u8zDL3Q74cwxrcz9Ee+dQk6G75
         HKqgRls94pZPjjPFIggr6ojCdcSCb7U/FasDmDalL9F1kOmJ/NKkoMDxJlHJRo6CPlf+
         PEmTcrNLPMQG3yFWGTIuqfsqDcL316VvQkT/1CQM5/hytv5JkO0sSdjMn1TlnsVhRqUB
         UAxx67ZeLKlscosTAMvXRhTOTmes6t+1n64oF0qWgKF5Yy+eMZqCc2ki6mXIH5hfxpLf
         S8+szJT8xBZqT35hyxmpvBj9H1xpgOYE01meHAMckd0n8BzrPleYABsPo5r84jp+GVlc
         j//Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736832974; x=1737437774;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EhwVeMbpIC32b27tnfWncl238UUeep0IR8qdkq8LeWI=;
        b=tzVHwubMS+E1zFxNQCxnLJjwGtpryw1rPn6MosJkYwhRsz1J9KM92/M0M2S+BQK88M
         n9V2hi03NCnWkFxhfmyd4EnG+Bm/yfDs6c57a6S8bHAmfqjDwqGxqB7Mo0pVRMWCEThs
         91tTKG6hYcxo9ZC3TyxM1CFeinx/w1+pYBMQki1S3bQbTDn+0ze9qr2LEaCYp+2MboFz
         61CyAqQiopvKHvFrBxCQBGCiYQh0rVOzJdJzTRt81b1vJUYqO4+8Rgz6Q07kH/DoHJL6
         ohDjTChlqP8h3l2R10yUekNZp03LJ4ikieb7T7nH2XIGWW81UyBvr+WnEz199iu4lmCK
         zxbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5bJ4vqprE6sUhTJC6hUgHXzRPGvU9OLE7ei4Cro7hbPIWfFSwR6qaNyM41b8Tdq3y0fIwtQ==@lfdr.de
X-Gm-Message-State: AOJu0YxiMuhIddolAp4XxYjZj0Fnjr4Z3i6pUfsmTQy9Z2UWrlXPjs1p
	4Y1XjkqOt4afnmx2xFLaNEynsvAM+lZNoH+cKW+auo0Auabvtd03
X-Google-Smtp-Source: AGHT+IFow12sJecsBoFvyOhekalbiau9crLdJSCR21S5K7Dz+1tDJSznbJNFCbO1H8be5OcvRqnJOA==
X-Received: by 2002:a05:6870:6ec7:b0:2a0:1162:425a with SMTP id 586e51a60fabf-2aa0697f881mr14096340fac.26.1736832974038;
        Mon, 13 Jan 2025 21:36:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:2204:b0:2a0:117a:3eb3 with SMTP id
 586e51a60fabf-2aaad6bb1a3ls3623424fac.2.-pod-prod-07-us; Mon, 13 Jan 2025
 21:36:12 -0800 (PST)
X-Received: by 2002:a05:6871:418e:b0:29e:69a9:8311 with SMTP id 586e51a60fabf-2aa069e2f99mr13190219fac.36.1736832972366;
        Mon, 13 Jan 2025 21:36:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736832972; cv=none;
        d=google.com; s=arc-20240605;
        b=img6Yh4ExpKGyz+go9PFrYCD50zL8jbAzTiY2dTi0KltfyrBcVv0YmZL6M1XHog6Zo
         ragObR+mHdTwU7L4G4Z6GDyyKxHpMT4thHwKrM1zM+hvwV9+J2ki4IUCKHN4lDMpHaxI
         vH2ejfuJmW00eSlrqr5o0i3YsBB7fy78MQlrUy6FjrAOBFKAcHGxDttjITnIMmfZR5ib
         UJQD6WOWbpa2e4DfQMPjyZ964OtOTLEo8XpkR/Yhv9fW/PUlGrKjRYgZFJGFamS3MKA8
         vvIl+cNmJ1MHFqijwDue7G4Wkuuq/0saI0AoSBPgViBcN7Mbf8ga+FHGlaVqRTcOzN91
         Q8oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=SnTIiCvc99mwVePAnY7xDBhzjlSnYyKXixXlpKzOnM4=;
        fh=IrFMU56A0U8g6WEnzuhC3mVEK/1VXa8G0j09OJ6Nq3U=;
        b=T9EvpTuc19vtJrg6lihfNrOrdJNr5uHj2BApLW35f4hxNU3rumvGKPQyQ8oOgOCJvJ
         3rHm3fvFj+iaRMSiDBjEEHKfYLdfZ+WzpQgbvTWXFYnGi1QLaNjEy7nXVppqon9PC9b7
         yOh6xCXaYZVAQGLmSNCRgVNvGX+7EyH3z9a8gQBPIfsh8qf0IrH1MN4md7OEspZbU8DZ
         64wTUMd57qBpNdnyk7yjOyaFYaPV8e6xSK+X9Ip7RwzzXxzOQO4nxrdCeJSfSVm4Y7vq
         5EaZX6bjHCcS2dKIWEaHBDiX+N6Aiok4mo2P9Gb897QbyKc3N87quDf8uTUrJROdtNPP
         LQmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=JCcY18Jy;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ad8054fc16si507347fac.2.2025.01.13.21.36.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Jan 2025 21:36:12 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279862.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50E23rPd008664;
	Tue, 14 Jan 2025 05:36:06 GMT
Received: from nasanppmta04.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 445eterdbu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:06 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA04.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50E5a5VP031710
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 14 Jan 2025 05:36:05 GMT
Received: from la-sh002-lnx.ap.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Mon, 13 Jan 2025 21:35:59 -0800
From: "Jiao, Joey" <quic_jiangenj@quicinc.com>
Date: Tue, 14 Jan 2025 13:34:35 +0800
Subject: [PATCH 5/7] kcov: add the new KCOV uniq modes example code
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20250114-kcov-v1-5-004294b931a2@quicinc.com>
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
In-Reply-To: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Andrew Morton
	<akpm@linux-foundation.org>,
        Dennis Zhou <dennis@kernel.org>, Tejun Heo
	<tj@kernel.org>,
        Christoph Lameter <cl@linux.com>,
        Catalin Marinas
	<catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
        <workflows@vger.kernel.org>, <linux-doc@vger.kernel.org>,
        <linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
        <kernel@quicinc.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=ed25519-sha256; t=1736832942; l=11230;
 i=quic_jiangenj@quicinc.com; s=20250114; h=from:subject:message-id;
 bh=Lulb9I7d15ITpgpA7vYK556BzHyWX5kLFMs7zHurtPk=;
 b=PsYnlyeqPpQvbH0Tjx/23z40jyNSYl78V1dqIGIKdCPIfjW6tQcTCFyzJ9UvXBOuXjtWtUwDB
 TAqwKIXfgCUBSNrKOSChk4WtD7SAjYOBbZ/LvHcIKI1yVt1GRWOuj8H
X-Developer-Key: i=quic_jiangenj@quicinc.com; a=ed25519;
 pk=JPzmfEvx11SW1Q1qtMhFcAx46KP1Ui36jcetDgbev28=
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: wnv8w4hud187Ydr9CX1bF6ILuw6Aa77S
X-Proofpoint-GUID: wnv8w4hud187Ydr9CX1bF6ILuw6Aa77S
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 malwarescore=0
 phishscore=0 bulkscore=0 spamscore=0 mlxlogscore=999 impostorscore=0
 suspectscore=0 mlxscore=0 lowpriorityscore=0 priorityscore=1501
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501140044
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=JCcY18Jy;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
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

- Use single program to select different mode.
- Mode [0|1|2|4|8] to KCOV_TRACE_[PC|CMP|UNIQ_PC|UNIQ_EDGE|UNIQ_CMP].
- Mode 6 to KCOV_TRACE_UNIQ_PC and KCOV_TRACE_UNIQ_EDGE.

Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
---
 Documentation/dev-tools/kcov.rst | 243 ++++++++++++++++++++-------------------
 1 file changed, 122 insertions(+), 121 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd247c6c40afcbf1e6c4e22e0562176..061ae20b867fd9e68b447b86719733278ee6b86f 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -40,11 +40,12 @@ Coverage data only becomes accessible once debugfs has been mounted::
 
         mount -t debugfs none /sys/kernel/debug
 
-Coverage collection
+Coverage collection for different modes
 -------------------
 
 The following program demonstrates how to use KCOV to collect coverage for a
-single syscall from within a test program:
+single syscall from within a test program, argv[1] can be provided to select
+which mode to enable:
 
 .. code-block:: c
 
@@ -60,55 +61,130 @@ single syscall from within a test program:
     #include <fcntl.h>
     #include <linux/types.h>
 
-    #define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
+    #define KCOV_INIT_TRACE		_IOR('c', 1, unsigned long)
     #define KCOV_ENABLE			_IO('c', 100)
-    #define KCOV_DISABLE			_IO('c', 101)
+    #define KCOV_DISABLE		_IO('c', 101)
     #define COVER_SIZE			(64<<10)
 
     #define KCOV_TRACE_PC  0
     #define KCOV_TRACE_CMP 1
+    #define KCOV_TRACE_UNIQ_PC 2
+    #define KCOV_TRACE_UNIQ_EDGE 4
+    #define KCOV_TRACE_UNIQ_CMP 8
+
+    /* Number of 64-bit words per record. */
+    #define KCOV_WORDS_PER_CMP 4
+
+    /*
+     * The format for the types of collected comparisons.
+     *
+     * Bit 0 shows whether one of the arguments is a compile-time constant.
+     * Bits 1 & 2 contain log2 of the argument size, up to 8 bytes.
+     */
+
+    #define KCOV_CMP_CONST		(1 << 0)
+    #define KCOV_CMP_SIZE(n)		((n) << 1)
+    #define KCOV_CMP_MASK		KCOV_CMP_SIZE(3)
 
     int main(int argc, char **argv)
     {
-	int fd;
-	unsigned long *cover, n, i;
-
-	/* A single fd descriptor allows coverage collection on a single
-	 * thread.
-	 */
-	fd = open("/sys/kernel/debug/kcov", O_RDWR);
-	if (fd == -1)
-		perror("open"), exit(1);
-	/* Setup trace mode and trace size. */
-	if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
-		perror("ioctl"), exit(1);
-	/* Mmap buffer shared between kernel- and user-space. */
-	cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
-				     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
-	if ((void*)cover == MAP_FAILED)
-		perror("mmap"), exit(1);
-	/* Enable coverage collection on the current thread. */
-	if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
-		perror("ioctl"), exit(1);
-	/* Reset coverage from the tail of the ioctl() call. */
-	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
-	/* Call the target syscall call. */
-	read(-1, NULL, 0);
-	/* Read number of PCs collected. */
-	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
-	for (i = 0; i < n; i++)
-		printf("0x%lx\n", cover[i + 1]);
-	/* Disable coverage collection for the current thread. After this call
-	 * coverage can be enabled for a different thread.
-	 */
-	if (ioctl(fd, KCOV_DISABLE, 0))
-		perror("ioctl"), exit(1);
-	/* Free resources. */
-	if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
-		perror("munmap"), exit(1);
-	if (close(fd))
-		perror("close"), exit(1);
-	return 0;
+        int fd;
+        unsigned long *cover, *edge, n, n1, i, type, arg1, arg2, is_const, size;
+        unsigned int mode = KCOV_TRACE_PC;
+
+        /* argv[1] controls which mode to use, default to KCOV_TRACE_PC.
+         * supported modes include:
+         * KCOV_TRACE_PC
+         * KCOV_TRACE_CMP
+         * KCOV_TRACE_UNIQ_PC
+         * KCOV_TRACE_UNIQ_EDGE
+         * KCOV_TRACE_UNIQ_PC | KCOV_TRACE_UNIQ_EDGE
+         * KCOV_TRACE_UNIQ_CMP
+         */
+        if (argc > 1)
+            mode = (unsigned int)strtoul(argv[1], NULL, 10);
+        printf("The mode is: %u\n", mode);
+        if (mode != KCOV_TRACE_PC && mode != KCOV_TRACE_CMP &&
+            !(mode & (KCOV_TRACE_UNIQ_PC | KCOV_TRACE_UNIQ_EDGE | KCOV_TRACE_UNIQ_CMP))) {
+            printf("Unsupported mode!\n");
+            exit(1);
+        }
+        /* A single fd descriptor allows coverage collection on a single
+         * thread.
+         */
+        fd = open("/sys/kernel/debug/kcov", O_RDWR);
+        if (fd == -1)
+            perror("open"), exit(1);
+        /* Setup trace mode and trace size. */
+        if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
+            perror("ioctl"), exit(1);
+        /* Mmap buffer shared between kernel- and user-space. */
+        cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
+                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
+        if ((void*)cover == MAP_FAILED)
+            perror("mmap"), exit(1);
+        if (mode & KCOV_TRACE_UNIQ_EDGE) {
+            edge = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
+                        PROT_READ | PROT_WRITE, MAP_SHARED, fd, COVER_SIZE * sizeof(unsigned long));
+            if ((void*)edge == MAP_FAILED)
+                perror("mmap"), exit(1);
+        }
+        /* Enable coverage collection on the current thread. */
+        if (ioctl(fd, KCOV_ENABLE, mode))
+            perror("ioctl"), exit(1);
+        /* Reset coverage from the tail of the ioctl() call. */
+        __atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
+        if (mode & KCOV_TRACE_UNIQ_EDGE)
+            __atomic_store_n(&edge[0], 0, __ATOMIC_RELAXED);
+        /* Call the target syscall call. */
+        read(-1, NULL, 0);
+        /* Read number of PCs collected. */
+        n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
+        if (mode & KCOV_TRACE_UNIQ_EDGE)
+            n1 = __atomic_load_n(&edge[0], __ATOMIC_RELAXED);
+        if (mode & (KCOV_TRACE_CMP | KCOV_TRACE_UNIQ_CMP)) {
+            for (i = 0; i < n; i++) {
+                uint64_t ip;
+
+                type = cover[i * KCOV_WORDS_PER_CMP + 1];
+                /* arg1 and arg2 - operands of the comparison. */
+                arg1 = cover[i * KCOV_WORDS_PER_CMP + 2];
+                arg2 = cover[i * KCOV_WORDS_PER_CMP + 3];
+                /* ip - caller address. */
+                ip = cover[i * KCOV_WORDS_PER_CMP + 4];
+                /* size of the operands. */
+                size = 1 << ((type & KCOV_CMP_MASK) >> 1);
+                /* is_const - true if either operand is a compile-time constant.*/
+                is_const = type & KCOV_CMP_CONST;
+                printf("ip: 0x%lx type: 0x%lx, arg1: 0x%lx, arg2: 0x%lx, "
+                        "size: %lu, %s\n",
+                        ip, type, arg1, arg2, size,
+                is_const ? "const" : "non-const");
+            }
+        } else {
+            for (i = 0; i < n; i++)
+                printf("0x%lx\n", cover[i + 1]);
+            if (mode & KCOV_TRACE_UNIQ_EDGE) {
+                printf("======edge======\n");
+                for (i = 0; i < n1; i++)
+                    printf("0x%lx\n", edge[i + 1]);
+            }
+        }
+        /* Disable coverage collection for the current thread. After this call
+         * coverage can be enabled for a different thread.
+         */
+        if (ioctl(fd, KCOV_DISABLE, 0))
+            perror("ioctl"), exit(1);
+        /* Free resources. */
+        if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
+            perror("munmap"), exit(1);
+        if (mode & KCOV_TRACE_UNIQ_EDGE) {
+            if (munmap(edge, COVER_SIZE * sizeof(unsigned long)))
+                perror("munmap"), exit(1);
+        }
+        if (close(fd))
+            perror("close"), exit(1);
+        return 0;
     }
 
 After piping through ``addr2line`` the output of the program looks as follows::
@@ -137,85 +213,10 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
 processes only need to enable coverage (it gets disabled automatically when
 a thread exits).
 
-Comparison operands collection
-------------------------------
-
-Comparison operands collection is similar to coverage collection:
-
-.. code-block:: c
-
-    /* Same includes and defines as above. */
-
-    /* Number of 64-bit words per record. */
-    #define KCOV_WORDS_PER_CMP 4
-
-    /*
-     * The format for the types of collected comparisons.
-     *
-     * Bit 0 shows whether one of the arguments is a compile-time constant.
-     * Bits 1 & 2 contain log2 of the argument size, up to 8 bytes.
-     */
-
-    #define KCOV_CMP_CONST          (1 << 0)
-    #define KCOV_CMP_SIZE(n)        ((n) << 1)
-    #define KCOV_CMP_MASK           KCOV_CMP_SIZE(3)
-
-    int main(int argc, char **argv)
-    {
-	int fd;
-	uint64_t *cover, type, arg1, arg2, is_const, size;
-	unsigned long n, i;
-
-	fd = open("/sys/kernel/debug/kcov", O_RDWR);
-	if (fd == -1)
-		perror("open"), exit(1);
-	if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
-		perror("ioctl"), exit(1);
-	/*
-	* Note that the buffer pointer is of type uint64_t*, because all
-	* the comparison operands are promoted to uint64_t.
-	*/
-	cover = (uint64_t *)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
-				     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
-	if ((void*)cover == MAP_FAILED)
-		perror("mmap"), exit(1);
-	/* Note KCOV_TRACE_CMP instead of KCOV_TRACE_PC. */
-	if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_CMP))
-		perror("ioctl"), exit(1);
-	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
-	read(-1, NULL, 0);
-	/* Read number of comparisons collected. */
-	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
-	for (i = 0; i < n; i++) {
-		uint64_t ip;
-
-		type = cover[i * KCOV_WORDS_PER_CMP + 1];
-		/* arg1 and arg2 - operands of the comparison. */
-		arg1 = cover[i * KCOV_WORDS_PER_CMP + 2];
-		arg2 = cover[i * KCOV_WORDS_PER_CMP + 3];
-		/* ip - caller address. */
-		ip = cover[i * KCOV_WORDS_PER_CMP + 4];
-		/* size of the operands. */
-		size = 1 << ((type & KCOV_CMP_MASK) >> 1);
-		/* is_const - true if either operand is a compile-time constant.*/
-		is_const = type & KCOV_CMP_CONST;
-		printf("ip: 0x%lx type: 0x%lx, arg1: 0x%lx, arg2: 0x%lx, "
-			"size: %lu, %s\n",
-			ip, type, arg1, arg2, size,
-		is_const ? "const" : "non-const");
-	}
-	if (ioctl(fd, KCOV_DISABLE, 0))
-		perror("ioctl"), exit(1);
-	/* Free resources. */
-	if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
-		perror("munmap"), exit(1);
-	if (close(fd))
-		perror("close"), exit(1);
-	return 0;
-    }
-
 Note that the KCOV modes (collection of code coverage or comparison operands)
-are mutually exclusive.
+are mutually exclusive, KCOV_TRACE_UNIQ_PC and KCOV_TRACE_UNIQ_EDGE can be
+enabled together.
+
 
 Remote coverage collection
 --------------------------

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114-kcov-v1-5-004294b931a2%40quicinc.com.
