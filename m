Return-Path: <kasan-dev+bncBCLMXXWM5YBBBZ42QO6AMGQE5DLOF2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 57DF1A088EF
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2025 08:34:01 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2161d5b3eb5sf32877865ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2025 23:34:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736494440; cv=pass;
        d=google.com; s=arc-20240605;
        b=U0hsHIx4lkGXkS7jRZ3yUTYZEs8orN5t/ZRN3ifWakTyVH7bScqHmfIkYWy2dYBI1/
         UywXtKXphupxud50SE8RQg95ybQZHEHIInK7ExHkznJmp2w06TrVt0Wvx/ubdlQjrTsv
         2d4oTRGzvy2iSl76XJDCEPhRxILJpK8OkO86PmIMXQHFWQ6p8r+21gSTnL/9JX1A35r6
         swuwkNReVp4CjPm1ohT67ql4umgdyfOECzXUNNTrodVkVn3dKyikei2i0jGkL4Y6yM3L
         80cnyjy1ROjya/rwj4hsLkYJ8BhU7WGEqobzieBtcp02zqslzpKqRPNJ+h77cdXmUgz0
         bOcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=u0WV/xojPj1JRTUlsiMhn9l25y8yoHBFXXUBxUiQG8k=;
        fh=5hMWBrBXsSojA+K6TuEeB0/SfpHpOm9bTXHYDSybnig=;
        b=T1ldhWpm6lU9xAN3irdcS2dfktI+dsLl/TjifffgE8aKSLMEBKuL2ktNxPq6qeAGV8
         IKe5LPZ3sQRNVQ62NbUO+XmC8oos4tPJc3QrSuLiBC64qWTBwCqvQ1y5SWIzoNprAsuj
         Gf1U591rMflRzbEN/kQT4+X06l/IuldYL3XcYwZ9cTKAATn4TlXypiZTvAtRxk4lalhf
         +PWSYPSsVPBS+1nckYLAlmmiJr4xeGOoceuQGczrFQ4FDFjcUblUdivDZvs2O/78IxoB
         rGkuV+XZAin8MjeVPb4XGxdcOJTPC7P/3WYkGf6ZFHgOFpy95Hz/aFTCL3eQcHG7DUF9
         6R+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bukpYRsE;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736494440; x=1737099240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u0WV/xojPj1JRTUlsiMhn9l25y8yoHBFXXUBxUiQG8k=;
        b=suUTz53/61Lqi5KP0iY0ZMepEOyM0zMLTudomjLxn6g+vS+WJG/1dkpA5/8uDaR136
         iws0u5167rmhBx6vsb4D/FMc0pwV4zWdxJwJMfyAfhv1TqKK3AlIkjFHwaHMaDbmiCs7
         sJF53aN/cpssMEd676Xbc82k7l07olILiGuHHfcRNIEvBZrNvmtQZOW+1P6zT+4Uzo7M
         /eDVX1ewGnGOs3nvomrgkLfYAErsLZf7PfpOt7rKBZ+OuXzB552rDXKxNBRAc7UpZQbD
         w5DyKHvPFsuVErxdV1Lw2zPdvWdmVNCRKQKemQ+noRQr8dAdK7QCH5u7m9H+9ftsbVfJ
         bAcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736494440; x=1737099240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u0WV/xojPj1JRTUlsiMhn9l25y8yoHBFXXUBxUiQG8k=;
        b=IuQKY5LLeeyM47KF53zDCBiDYgp7SkkIhA+VBVVn0vXiaThN73WHvRcD+UbO8hHPur
         WW5iD/vHkpayA7hsPBOgGwyrFNQueY2N76DSYfz+blQXr36yNmpe0i2gWvA0ZI4u7G/2
         Au/jqeNn5PjD3QeAfz/53+tpm/nmidyEpz4r6n6trtuEstwbHyn/WROM0lhBmArgH1jG
         MIi8ItShgh+hSTkeohIyQ1EUr1N8lIfKgldFmBsNu/50DfLyksI2frgT6BQ7l7BReZ0+
         2kVjgrbj1bZPBiEkfTPxiuY3WNPwv2YzK8ljRBXS88PELUYA6fdXqBA1DZDdyHBETjyv
         zeUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9rNe3wK3QRXCq62TPC+0xiCT6CZ+JgznY78Gu3EovR9We/gjgqErzPxruqUMZ4KigjXEQQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx79FbtDGxosFbA31263319RSEH+QvswQTw3CTE8oH9XQ64dtov
	r4Di7uGCNdJXhYss3Ol/5IidWMhKlVYjldez3sAxb20d+9mpRXtm
X-Google-Smtp-Source: AGHT+IHIv51IExvyTDh/5KjG0vBJ8QMGScNyYfRaftAKG18cv2kI83gURgn2FVcAzFQmQYExfjRzuA==
X-Received: by 2002:a17:902:e74a:b0:216:2e6d:baac with SMTP id d9443c01a7336-21a83f649e0mr161507685ad.29.1736494439450;
        Thu, 09 Jan 2025 23:33:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:740b:b0:216:2022:d81d with SMTP id
 d9443c01a7336-21a8d3182e3ls11358915ad.1.-pod-prod-04-us; Thu, 09 Jan 2025
 23:33:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHCSXL4D8W2WZ8MAe1wO2v4T2yYSZltvM8LGaB+sq8f3zzHGABKN8LN/WZOKqOP6+025s8PwNNNlg=@googlegroups.com
X-Received: by 2002:a17:902:d48f:b0:21a:8716:faab with SMTP id d9443c01a7336-21a8726416amr123656855ad.16.1736494438002;
        Thu, 09 Jan 2025 23:33:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736494437; cv=none;
        d=google.com; s=arc-20240605;
        b=ezfK+jTZyDfO9Uv/McBM3MmJUnm2jsoxIpIZSd74rVsxPZjuyulnhkJhChaLY07mav
         z5PGC8IqNYwt5/FNYHqTrOSHAE68ESscUB+OFNko6+LnDTI79qMb/laD0D9oebUSYCVD
         CPeI9d8wiThhTItHLlDt+GTAs6Lyhbz8puSHf4ZN9Cb0P4ocVdpB9iHC6Dvl5A8dcaF0
         R7U/XQwktmB5wVulkY95QLyowqI8dNQNd2JZTvlbSvW9gUKzRUftFv8lI1X2WseM05tf
         y3lw2PypTXJCiBsRA3LZKOXXqUU18eW4FfTH5lw5ZabopZpEZyfEA5sgWJ6CslgeWZQI
         mWTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3+9t1rRuGHMVzqqec2xQDl4hgo74dmloCbzvERAf4HQ=;
        fh=uBv8vvG0uQ8bt+gQkLVNnK/uvBIBJgmoqAl/IKR4olI=;
        b=iSaIHn2I4n162tUZu4nRqst/1X4E3nXxJxHOu2XydTClUGTx8cIrNcqNj2PztkT4Ht
         IFVMeYJ3F2OV5K2quwz6RD8DZY1/6o8U9cADv+PaxlaDayFzFB/NKjf0iVmR3haxePn3
         tvk1ZJk6A812yi8I2DQ7B032YXQZVZE/1ex7GsjwrWFHhSf1jDZjO/SmQF02nReVV1OK
         /uH9TxZ19ofLzY/CL687Jv1XNFaYi9Ph+KaomXaVS78bm0h/MfM3sq6u1t4TzFIbTHwW
         bGMsrII0KQ/cOhWO7f0XKuJUUTJ0jIWSOThdTmHE96LZPvFCEWJKBx/i0ovykpQ7qPPC
         NWxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=bukpYRsE;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21a918a60dcsi1149225ad.11.2025.01.09.23.33.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2025 23:33:57 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279865.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50A0Xhbb029006;
	Fri, 10 Jan 2025 07:33:50 GMT
Received: from nasanppmta02.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 442s450tjm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Jan 2025 07:33:50 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA02.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50A7Xn3F024025
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Jan 2025 07:33:49 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Thu, 9 Jan 2025 23:33:39 -0800
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: <dvyukov@google.com>, <andreyknvl@gmail.com>, <corbet@lwn.net>,
        <akpm@linux-foundation.org>, <gregkh@linuxfoundation.org>,
        <nogikh@google.com>, <quic_jiangenj@quicinc.com>, <elver@google.com>,
        <pierre.gondois@arm.com>, <cmllamas@google.com>,
        <quic_zijuhu@quicinc.com>, <richard.weiyang@gmail.com>,
        <tglx@linutronix.de>, <arnd@arndb.de>, <catalin.marinas@arm.com>,
        <will@kernel.org>, <dennis@kernel.org>, <tj@kernel.org>,
        <cl@linux.com>, <ruanjinjie@huawei.com>, <colyli@suse.de>,
        <andriy.shevchenko@linux.intel.com>
CC: <kernel@quicinc.com>, <quic_likaid@quicinc.com>,
        <kasan-dev@googlegroups.com>, <workflows@vger.kernel.org>,
        <linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
        <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>
Subject: [PATCH] kcov: add unique cover, edge, and cmp modes
Date: Fri, 10 Jan 2025 13:00:56 +0530
Message-ID: <20250110073056.2594638-1-quic_jiangenj@quicinc.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: 1Pm85by_0Rbncz-Zr18gcLvCbr801r2f
X-Proofpoint-GUID: 1Pm85by_0Rbncz-Zr18gcLvCbr801r2f
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.60.29
 definitions=2024-09-06_09,2024-09-06_01,2024-09-02_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 mlxlogscore=999
 bulkscore=0 adultscore=0 priorityscore=1501 lowpriorityscore=0
 clxscore=1011 suspectscore=0 mlxscore=0 impostorscore=0 malwarescore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501100060
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=bukpYRsE;       spf=pass
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

From: "Jiao, Joey" <quic_jiangenj@quicinc.com>

The current design of KCOV risks frequent buffer overflows. To mitigate
this, new modes are introduced: KCOV_TRACE_UNIQ_PC, KCOV_TRACE_UNIQ_EDGE,
and KCOV_TRACE_UNIQ_CMP. These modes allow for the recording of unique
PCs, edges, and comparison operands (CMP).

Key changes include:
- KCOV_TRACE_UNIQ_[PC|EDGE] can be used together to replace KCOV_TRACE_PC.
- KCOV_TRACE_UNIQ_CMP can be used to replace KCOV_TRACE_CMP mode.
- Introduction of hashmaps to store unique coverage data.
- Pre-allocated entries in kcov_map_init during KCOV_INIT_TRACE to avoid
  performance issues with kmalloc.
- New structs and functions for managing memory and unique coverage data.
- Example program demonstrating the usage of the new modes.

With the new hashmap and pre-alloced memory pool added, cover size can't
be set to higher value like 1MB in KCOV_TRACE_PC or KCOV_TRACE_CMP modes
in 2GB device with 8 procs, otherwise it causes frequent oom.

For KCOV_TRACE_UNIQ_[PC|EDGE|CMP] modes, smaller cover size like 8KB can
be used.

Signed-off-by: Jiao, Joey <quic_jiangenj@quicinc.com>
---
 Documentation/dev-tools/kcov.rst  | 243 +++++++++++-----------
 arch/arm64/include/asm/irqflags.h |   8 +-
 arch/arm64/include/asm/percpu.h   |   2 +-
 arch/arm64/include/asm/preempt.h  |   2 +-
 include/linux/kcov.h              |  10 +-
 include/linux/list.h              |   2 +-
 include/uapi/linux/kcov.h         |   6 +
 kernel/kcov.c                     | 334 +++++++++++++++++++++++++-----
 lib/Makefile                      |   2 +
 9 files changed, 429 insertions(+), 180 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd2..061ae20b867f 100644
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
diff --git a/arch/arm64/include/asm/irqflags.h b/arch/arm64/include/asm/irqflags.h
index d4d7451c2c12..f9a4ccceefcf 100644
--- a/arch/arm64/include/asm/irqflags.h
+++ b/arch/arm64/include/asm/irqflags.h
@@ -90,7 +90,7 @@ static __always_inline unsigned long __pmr_local_save_flags(void)
 /*
  * Save the current interrupt enable state.
  */
-static inline unsigned long arch_local_save_flags(void)
+static __no_sanitize_coverage inline unsigned long arch_local_save_flags(void)
 {
 	if (system_uses_irq_prio_masking()) {
 		return __pmr_local_save_flags();
@@ -99,17 +99,17 @@ static inline unsigned long arch_local_save_flags(void)
 	}
 }
 
-static __always_inline bool __daif_irqs_disabled_flags(unsigned long flags)
+static __no_sanitize_coverage __always_inline bool __daif_irqs_disabled_flags(unsigned long flags)
 {
 	return flags & PSR_I_BIT;
 }
 
-static __always_inline bool __pmr_irqs_disabled_flags(unsigned long flags)
+static __no_sanitize_coverage __always_inline bool __pmr_irqs_disabled_flags(unsigned long flags)
 {
 	return flags != GIC_PRIO_IRQON;
 }
 
-static inline bool arch_irqs_disabled_flags(unsigned long flags)
+static __no_sanitize_coverage inline bool arch_irqs_disabled_flags(unsigned long flags)
 {
 	if (system_uses_irq_prio_masking()) {
 		return __pmr_irqs_disabled_flags(flags);
diff --git a/arch/arm64/include/asm/percpu.h b/arch/arm64/include/asm/percpu.h
index 9abcc8ef3087..a40ff8168151 100644
--- a/arch/arm64/include/asm/percpu.h
+++ b/arch/arm64/include/asm/percpu.h
@@ -29,7 +29,7 @@ static inline unsigned long __hyp_my_cpu_offset(void)
 	return read_sysreg(tpidr_el2);
 }
 
-static inline unsigned long __kern_my_cpu_offset(void)
+static __no_sanitize_coverage inline unsigned long __kern_my_cpu_offset(void)
 {
 	unsigned long off;
 
diff --git a/arch/arm64/include/asm/preempt.h b/arch/arm64/include/asm/preempt.h
index 0159b625cc7f..a8742a57481a 100644
--- a/arch/arm64/include/asm/preempt.h
+++ b/arch/arm64/include/asm/preempt.h
@@ -8,7 +8,7 @@
 #define PREEMPT_NEED_RESCHED	BIT(32)
 #define PREEMPT_ENABLED	(PREEMPT_NEED_RESCHED)
 
-static inline int preempt_count(void)
+static __no_sanitize_coverage inline int preempt_count(void)
 {
 	return READ_ONCE(current_thread_info()->preempt.count);
 }
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 75a2fb8b16c3..8d577716df42 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -20,9 +20,15 @@ enum kcov_mode {
 	 */
 	KCOV_MODE_TRACE_PC = 2,
 	/* Collecting comparison operands mode. */
-	KCOV_MODE_TRACE_CMP = 3,
+	KCOV_MODE_TRACE_CMP = 4,
 	/* The process owns a KCOV remote reference. */
-	KCOV_MODE_REMOTE = 4,
+	KCOV_MODE_REMOTE = 8,
+	/* COllecting uniq pc mode. */
+	KCOV_MODE_TRACE_UNIQ_PC = 16,
+	/* Collecting uniq edge mode. */
+	KCOV_MODE_TRACE_UNIQ_EDGE = 32,
+	/* Collecting uniq cmp mode. */
+	KCOV_MODE_TRACE_UNIQ_CMP = 64,
 };
 
 #define KCOV_IN_CTXSW	(1 << 30)
diff --git a/include/linux/list.h b/include/linux/list.h
index 29a375889fb8..3dc8876ecb5a 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -1018,7 +1018,7 @@ static inline void hlist_del_init(struct hlist_node *n)
  * Insert a new entry after the specified head.
  * This is good for implementing stacks.
  */
-static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
+static __no_sanitize_coverage inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
 {
 	struct hlist_node *first = h->first;
 	WRITE_ONCE(n->next, first);
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index ed95dba9fa37..08abfca273c9 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -35,6 +35,12 @@ enum {
 	KCOV_TRACE_PC = 0,
 	/* Collecting comparison operands mode. */
 	KCOV_TRACE_CMP = 1,
+	/* Collecting uniq PC mode. */
+	KCOV_TRACE_UNIQ_PC = 2,
+	/* Collecting uniq edge mode. */
+	KCOV_TRACE_UNIQ_EDGE = 4,
+	/* Collecting uniq CMP mode. */
+	KCOV_TRACE_UNIQ_CMP = 8,
 };
 
 /*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 28a6be6e64fd..d86901bc684c 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -9,9 +9,11 @@
 #include <linux/types.h>
 #include <linux/file.h>
 #include <linux/fs.h>
+#include <linux/genalloc.h>
 #include <linux/hashtable.h>
 #include <linux/init.h>
 #include <linux/jiffies.h>
+#include <linux/jhash.h>
 #include <linux/kmsan-checks.h>
 #include <linux/mm.h>
 #include <linux/preempt.h>
@@ -32,6 +34,34 @@
 /* Number of 64-bit words written per one comparison: */
 #define KCOV_WORDS_PER_CMP 4
 
+struct kcov_entry {
+	unsigned long		ent;
+#ifdef CONFIG_KCOV_ENABLE_COMPARISONS
+	unsigned long		type;
+	unsigned long		arg1;
+	unsigned long		arg2;
+#endif
+
+	struct hlist_node	node;
+};
+
+/* Min gen pool alloc order. */
+#define MIN_POOL_ALLOC_ORDER ilog2(roundup_pow_of_two(sizeof(struct kcov_entry)))
+
+/*
+ * kcov hashmap to store uniq pc|edge|cmp, prealloced mem for kcov_entry
+ * and area shared between kernel and userspace.
+ */
+struct kcov_map {
+	/* 15 bits fit most cases for hash collision, memory and performance. */
+	DECLARE_HASHTABLE(buckets, 15);
+	struct gen_pool		*pool;
+	/* Prealloced memory added to pool to be used as kcov_entry. */
+	void			*mem;
+	/* Buffer shared with user space. */
+	void			*area;
+};
+
 /*
  * kcov descriptor (one per opened debugfs file).
  * State transitions of the descriptor:
@@ -58,8 +88,14 @@ struct kcov {
 	enum kcov_mode		mode;
 	/* Size of arena (in long's). */
 	unsigned int		size;
+	/* Previous PC. */
+	unsigned long		prev_pc;
 	/* Coverage buffer shared with user space. */
 	void			*area;
+	/* Coverage hashmap for unique pc|cmp. */
+	struct kcov_map		*map;
+	/* Edge hashmap for unique edge. */
+	struct kcov_map		*map_edge;
 	/* Task for which we collect coverage, or NULL. */
 	struct task_struct	*t;
 	/* Collecting coverage from remote (background) threads. */
@@ -171,7 +207,7 @@ static inline bool in_softirq_really(void)
 	return in_serving_softirq() && !in_hardirq() && !in_nmi();
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
+static notrace unsigned int check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
 {
 	unsigned int mode;
 
@@ -191,7 +227,125 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 * kcov_start().
 	 */
 	barrier();
-	return mode == needed_mode;
+	return mode & needed_mode;
+}
+
+static int kcov_map_init(struct kcov *kcov, unsigned long size, bool edge)
+{
+	struct kcov_map *map;
+	void *area;
+	unsigned long flags;
+
+	map = kzalloc(sizeof(*map), GFP_KERNEL);
+	if (!map)
+		return -ENOMEM;
+
+	area = vmalloc_user(size * sizeof(unsigned long));
+	if (!area) {
+		kfree(map);
+		return -ENOMEM;
+	}
+
+	spin_lock_irqsave(&kcov->lock, flags);
+	map->area = area;
+
+	if (edge) {
+		kcov->map_edge = map;
+	} else {
+		kcov->map = map;
+		kcov->area = area;
+	}
+	spin_unlock_irqrestore(&kcov->lock, flags);
+
+	hash_init(map->buckets);
+
+	map->pool = gen_pool_create(MIN_POOL_ALLOC_ORDER, -1);
+	if (!map->pool)
+		return -ENOMEM;
+
+	map->mem = vmalloc(size * (1 << MIN_POOL_ALLOC_ORDER));
+	if (!map->mem) {
+		vfree(area);
+		gen_pool_destroy(map->pool);
+		kfree(map);
+		return -ENOMEM;
+	}
+
+	if (gen_pool_add(map->pool, (unsigned long)map->mem, size *
+	    (1 << MIN_POOL_ALLOC_ORDER), -1)) {
+		vfree(area);
+		vfree(map->mem);
+		gen_pool_destroy(map->pool);
+		kfree(map);
+		return -ENOMEM;
+	}
+
+	return 0;
+}
+
+static inline u32 hash_key(const struct kcov_entry *k)
+{
+	return jhash((u32 *)k, offsetof(struct kcov_entry, node), 0);
+}
+
+static notrace inline void kcov_map_add(struct kcov_map *map, struct kcov_entry *ent,
+					struct task_struct *t, unsigned int mode)
+{
+	struct kcov *kcov;
+	struct kcov_entry *entry;
+	unsigned int key = hash_key(ent);
+	unsigned long pos, start_index, end_pos, max_pos, *area;
+
+	kcov = t->kcov;
+
+	if ((mode == KCOV_MODE_TRACE_UNIQ_PC ||
+	     mode == KCOV_MODE_TRACE_UNIQ_EDGE))
+		hash_for_each_possible_rcu(map->buckets, entry, node, key) {
+			if (entry->ent == ent->ent)
+				return;
+		}
+	else
+		hash_for_each_possible_rcu(map->buckets, entry, node, key) {
+			if (entry->ent == ent->ent && entry->type == ent->type &&
+			    entry->arg1 == ent->arg1 && entry->arg2 == ent->arg2) {
+				return;
+			}
+		}
+
+	entry = (struct kcov_entry *)gen_pool_alloc(map->pool, 1 << MIN_POOL_ALLOC_ORDER);
+	if (unlikely(!entry))
+		return;
+
+	barrier();
+	memcpy(entry, ent, sizeof(*entry));
+	hash_add_rcu(map->buckets, &entry->node, key);
+
+	if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_CMP)
+		area = t->kcov_area;
+	else
+		area = kcov->map_edge->area;
+
+	pos = READ_ONCE(area[0]) + 1;
+	if (mode == KCOV_MODE_TRACE_UNIQ_PC || mode == KCOV_MODE_TRACE_UNIQ_EDGE) {
+		if (likely(pos < t->kcov_size)) {
+			WRITE_ONCE(area[0], pos);
+			barrier();
+			area[pos] = ent->ent;
+		}
+	} else {
+		start_index = 1 + (pos - 1) * KCOV_WORDS_PER_CMP;
+		max_pos = t->kcov_size * sizeof(unsigned long);
+		end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
+		if (likely(end_pos <= max_pos)) {
+			/* See comment in __sanitizer_cov_trace_pc(). */
+			WRITE_ONCE(area[0], pos);
+			barrier();
+			area[start_index] = ent->type;
+			area[start_index + 1] = ent->arg1;
+			area[start_index + 2] = ent->arg2;
+			area[start_index + 3] = ent->ent;
+		}
+	}
 }
 
 static notrace unsigned long canonicalize_ip(unsigned long ip)
@@ -212,26 +366,45 @@ void notrace __sanitizer_cov_trace_pc(void)
 	unsigned long *area;
 	unsigned long ip = canonicalize_ip(_RET_IP_);
 	unsigned long pos;
+	struct kcov_entry entry = {0};
+	/* Only hash the lower 12 bits so the hash is independent of any module offsets. */
+	unsigned long mask = (1 << 12) - 1;
+	unsigned int mode;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
+	if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_TRACE_UNIQ_PC |
+			       KCOV_MODE_TRACE_UNIQ_EDGE, t))
 		return;
 
-	area = t->kcov_area;
-	/* The first 64-bit word is the number of subsequent PCs. */
-	pos = READ_ONCE(area[0]) + 1;
-	if (likely(pos < t->kcov_size)) {
-		/* Previously we write pc before updating pos. However, some
-		 * early interrupt code could bypass check_kcov_mode() check
-		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
-		 * raised between writing pc and updating pos, the pc could be
-		 * overitten by the recursive __sanitizer_cov_trace_pc().
-		 * Update pos before writing pc to avoid such interleaving.
-		 */
-		WRITE_ONCE(area[0], pos);
-		barrier();
-		area[pos] = ip;
+	mode = t->kcov_mode;
+	if (mode == KCOV_MODE_TRACE_PC) {
+		area = t->kcov_area;
+		/* The first 64-bit word is the number of subsequent PCs. */
+		pos = READ_ONCE(area[0]) + 1;
+		if (likely(pos < t->kcov_size)) {
+			/* Previously we write pc before updating pos. However, some
+			 * early interrupt code could bypass check_kcov_mode() check
+			 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
+			 * raised between writing pc and updating pos, the pc could be
+			 * overitten by the recursive __sanitizer_cov_trace_pc().
+			 * Update pos before writing pc to avoid such interleaving.
+			 */
+			WRITE_ONCE(area[0], pos);
+			barrier();
+			area[pos] = ip;
+		}
+	} else {
+		if (mode & KCOV_MODE_TRACE_UNIQ_PC) {
+			entry.ent = ip;
+			kcov_map_add(t->kcov->map, &entry, t, KCOV_MODE_TRACE_UNIQ_PC);
+		}
+		if (mode & KCOV_MODE_TRACE_UNIQ_EDGE) {
+			entry.ent = (hash_long(t->kcov->prev_pc & mask, BITS_PER_LONG) & mask) ^ ip;
+			t->kcov->prev_pc = ip;
+			kcov_map_add(t->kcov->map_edge, &entry, t, KCOV_MODE_TRACE_UNIQ_EDGE);
+		}
 	}
+
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
 
@@ -241,33 +414,44 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	struct task_struct *t;
 	u64 *area;
 	u64 count, start_index, end_pos, max_pos;
+	struct kcov_entry entry = {0};
+	unsigned int mode;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
+	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP | KCOV_MODE_TRACE_UNIQ_CMP, t))
 		return;
 
+	mode = t->kcov_mode;
 	ip = canonicalize_ip(ip);
 
-	/*
-	 * We write all comparison arguments and types as u64.
-	 * The buffer was allocated for t->kcov_size unsigned longs.
-	 */
-	area = (u64 *)t->kcov_area;
-	max_pos = t->kcov_size * sizeof(unsigned long);
-
-	count = READ_ONCE(area[0]);
-
-	/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
-	start_index = 1 + count * KCOV_WORDS_PER_CMP;
-	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
-	if (likely(end_pos <= max_pos)) {
-		/* See comment in __sanitizer_cov_trace_pc(). */
-		WRITE_ONCE(area[0], count + 1);
-		barrier();
-		area[start_index] = type;
-		area[start_index + 1] = arg1;
-		area[start_index + 2] = arg2;
-		area[start_index + 3] = ip;
+	if (mode == KCOV_MODE_TRACE_CMP) {
+		/*
+		 * We write all comparison arguments and types as u64.
+		 * The buffer was allocated for t->kcov_size unsigned longs.
+		 */
+		area = (u64 *)t->kcov_area;
+		max_pos = t->kcov_size * sizeof(unsigned long);
+
+		count = READ_ONCE(area[0]);
+
+		/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
+		start_index = 1 + count * KCOV_WORDS_PER_CMP;
+		end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
+		if (likely(end_pos <= max_pos)) {
+			/* See comment in __sanitizer_cov_trace_pc(). */
+			WRITE_ONCE(area[0], count + 1);
+			barrier();
+			area[start_index] = type;
+			area[start_index + 1] = arg1;
+			area[start_index + 2] = arg2;
+			area[start_index + 3] = ip;
+		}
+	} else {
+		entry.type = type;
+		entry.arg1 = arg1;
+		entry.arg2 = arg2;
+		entry.ent = ip;
+		kcov_map_add(t->kcov->map, &entry, t, KCOV_MODE_TRACE_UNIQ_CMP);
 	}
 }
 
@@ -432,11 +616,37 @@ static void kcov_get(struct kcov *kcov)
 	refcount_inc(&kcov->refcount);
 }
 
+static void kcov_map_free(struct kcov *kcov, bool edge)
+{
+	int bkt;
+	struct hlist_node *tmp;
+	struct kcov_entry *entry;
+	struct kcov_map *map;
+
+	if (edge)
+		map = kcov->map_edge;
+	else
+		map = kcov->map;
+	if (!map)
+		return;
+	rcu_read_lock();
+	hash_for_each_safe(map->buckets, bkt, tmp, entry, node) {
+		hash_del_rcu(&entry->node);
+		gen_pool_free(map->pool, (unsigned long)entry, 1 << MIN_POOL_ALLOC_ORDER);
+	}
+	rcu_read_unlock();
+	vfree(map->area);
+	vfree(map->mem);
+	gen_pool_destroy(map->pool);
+	kfree(map);
+}
+
 static void kcov_put(struct kcov *kcov)
 {
 	if (refcount_dec_and_test(&kcov->refcount)) {
 		kcov_remote_reset(kcov);
-		vfree(kcov->area);
+		kcov_map_free(kcov, false);
+		kcov_map_free(kcov, true);
 		kfree(kcov);
 	}
 }
@@ -491,18 +701,27 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long size, off;
 	struct page *page;
 	unsigned long flags;
+	void *area;
 
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
-	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
-	    vma->vm_end - vma->vm_start != size) {
+	if (!vma->vm_pgoff) {
+		area = kcov->area;
+	} else if (vma->vm_pgoff == size >> PAGE_SHIFT) {
+		area = kcov->map_edge->area;
+	} else {
+		spin_unlock_irqrestore(&kcov->lock, flags);
+		return -EINVAL;
+	}
+
+	if (!area || vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
 	}
 	spin_unlock_irqrestore(&kcov->lock, flags);
 	vm_flags_set(vma, VM_DONTEXPAND);
 	for (off = 0; off < size; off += PAGE_SIZE) {
-		page = vmalloc_to_page(kcov->area + off);
+		page = vmalloc_to_page(area + off);
 		res = vm_insert_page(vma, vma->vm_start + off, page);
 		if (res) {
 			pr_warn_once("kcov: vm_insert_page() failed\n");
@@ -538,6 +757,8 @@ static int kcov_close(struct inode *inode, struct file *filep)
 
 static int kcov_get_mode(unsigned long arg)
 {
+	int mode = 0;
+
 	if (arg == KCOV_TRACE_PC)
 		return KCOV_MODE_TRACE_PC;
 	else if (arg == KCOV_TRACE_CMP)
@@ -546,8 +767,20 @@ static int kcov_get_mode(unsigned long arg)
 #else
 		return -ENOTSUPP;
 #endif
-	else
+	if (arg & KCOV_TRACE_UNIQ_PC)
+		mode |= KCOV_MODE_TRACE_UNIQ_PC;
+	if (arg & KCOV_TRACE_UNIQ_EDGE)
+		mode |= KCOV_MODE_TRACE_UNIQ_EDGE;
+	if (arg == KCOV_TRACE_UNIQ_CMP)
+#ifdef CONFIG_KCOV_ENABLE_COMPARISONS
+		mode = KCOV_MODE_TRACE_UNIQ_CMP;
+#else
+		return -EOPNOTSUPP;
+#endif
+	if (!mode)
 		return -EINVAL;
+
+	return mode;
 }
 
 /*
@@ -600,7 +833,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		 * at task exit or voluntary by KCOV_DISABLE. After that it can
 		 * be enabled for another task.
 		 */
-		if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
+		if (kcov->mode != KCOV_MODE_INIT || !kcov->area ||
+		    !kcov->map_edge->area)
 			return -EINVAL;
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
@@ -698,7 +932,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	unsigned int remote_num_handles;
 	unsigned long remote_arg_size;
 	unsigned long size, flags;
-	void *area;
 
 	kcov = filep->private_data;
 	switch (cmd) {
@@ -713,16 +946,17 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		size = arg;
 		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
 			return -EINVAL;
-		area = vmalloc_user(size * sizeof(unsigned long));
-		if (area == NULL)
-			return -ENOMEM;
+		res = kcov_map_init(kcov, size, false);
+		if (res)
+			return res;
+		res = kcov_map_init(kcov, size, true);
+		if (res)
+			return res;
 		spin_lock_irqsave(&kcov->lock, flags);
 		if (kcov->mode != KCOV_MODE_DISABLED) {
 			spin_unlock_irqrestore(&kcov->lock, flags);
-			vfree(area);
 			return -EBUSY;
 		}
-		kcov->area = area;
 		kcov->size = size;
 		kcov->mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
diff --git a/lib/Makefile b/lib/Makefile
index a8155c972f02..7a110a9a4a52 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -15,6 +15,8 @@ KCOV_INSTRUMENT_debugobjects.o := n
 KCOV_INSTRUMENT_dynamic_debug.o := n
 KCOV_INSTRUMENT_fault-inject.o := n
 KCOV_INSTRUMENT_find_bit.o := n
+KCOV_INSTRUMENT_genalloc.o := n
+KCOV_INSTRUMENT_bitmap.o := n
 
 # string.o implements standard library functions like memset/memcpy etc.
 # Use -ffreestanding to ensure that the compiler does not try to "optimize"

base-commit: 9b2ffa6148b1e4468d08f7e0e7e371c43cac9ffe
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250110073056.2594638-1-quic_jiangenj%40quicinc.com.
