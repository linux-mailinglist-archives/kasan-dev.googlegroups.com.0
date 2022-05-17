Return-Path: <kasan-dev+bncBCWJVL6L2QLBBNM4SCKAMGQE534F7IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EC32852AD4F
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 23:06:06 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id b13-20020a92c56d000000b002d125a2ab95sf137593ilj.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 14:06:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652821558; cv=pass;
        d=google.com; s=arc-20160816;
        b=CtRtKfvv9qSGSIMznyOmjIq2hYdOgXwX+RwSjHyXRFSL9cBeagJm0l2elPSOME61GB
         TGyGYgD9EwD7VbEP0BPthxtcyiW4GqEyrccFVvi8wemVoNFWs9ja9cVPhMTqfLwd2z3O
         r7gc8PQnF1E0YJ8K51yaeobACeQTxt/Qo4bxKBL85QIlHMPj9+4e5BGIdjwTvcfGMten
         qL+VbJGYbAdCyeUXidZDpx7jt/cRAem+QQud+bk0i9x7/RAUEZ0bDyFSmQI8fV+Fg5eF
         S3jCuTJbudL+/1ZJuRPZ5lS43bQ5UMMJRv21hp57roTXKheR2FUnu4HTlpMdPb7l4yXM
         XN8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-hdrordr:ironport-data:ironport-sdr
         :sender:dkim-signature;
        bh=1T7st5sGF/Pnmv/HkmvUnBHBDLIJ6J6GRYTmJyKHJuI=;
        b=SHO1lw5ZGOcmWTITRe1l8uCb9czCanJtzwgQLNZvoZ3itNktA8gZBYK7S+AutCucKc
         o9Yc1MP19AuW4eXa6x0iBrCkN8lbF0LsnnvyyKRDYacnxybmoFj7DpUTgk2m8DUv+60Z
         tpEQFTqHgZ9hfkbX0YWLX5lNj4mWf474Hhh2OZKMwnD4uZe3iJET5VFmm8xxRV8mKnoa
         2AiHvwDvKwuRZc1nKkXqstFKuWkgs72aLt7Bxaukcwnk2jqJvUPLP44hkJvIHug9VL+n
         Q0PublOKNmHge1GO1Zl7Kysco1o+I3kb12u+t4axTCsJQhbcCYZLD+T9h6ozibWuWhop
         XvAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liu3101@purdue.edu designates 128.210.1.216 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:ironport-sdr:ironport-data:ironport-hdrordr:from:to:cc
         :subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1T7st5sGF/Pnmv/HkmvUnBHBDLIJ6J6GRYTmJyKHJuI=;
        b=n1xZiw42pOL/Xcl5jkBC6Q7e8Vsfae9YUA7Jl81TNQxU7p2BEuntNsscmc6ADz4zmA
         vI0FRrE3aDmhRKI/+GVihBZfmvrCL36d72sZSdiNzL+tftcoUgtLy2a2nwylGZff3oO+
         N5R871ksJQxL/AF001eyoEs++pb+edPYKcmrfOn6qhJSkOsV0/LnKEFujHOF/BFmGcvs
         0uWdKeK9svufQ8THEpyBo+bcD3sMGGeHNLFX2bSIoqHLXU9dys4t3mLYwgdJcon/kF6j
         hwASsGXxzEVPtY2yiCFU9rs3FrN1YoZo4RH3dcqXp7+CdzWd+VCTpG+nAJoIjNBIwMXg
         NluQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:ironport-sdr:ironport-data
         :ironport-hdrordr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1T7st5sGF/Pnmv/HkmvUnBHBDLIJ6J6GRYTmJyKHJuI=;
        b=1bBBYOS9Ha7biNVCv+Q6QQqVn0IDzJYYa8wbWogxIFe8A92ZQr9xUtVTmCT2Rojwd/
         lwekSFRiLpRHU33NzW2B/A0knGZReeEQnQ5LoshIcEgEDM1i1LeZ1KXUtwRXUBmaJ3wp
         eGjSvzw0bbtVEmZc6ZSRUYMXAsUeuZSaQ0HHWgB146fE0kCGuFSdjpQNx58GeBFVWfi+
         LWz4QCa5E0Ct1AMi3YgPqNQEtSUhpEkAzQtjbFK4pz5NNLx/GW6op+Iyojflugs/Hq/7
         gjPRzC8ycTe4QxNks7ph1JCfjD1jUVwPR20SMhyFMkCSifmQRjph5cOlN8aNZjXyl/ou
         +a4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530N3J/F8d64ZFdt3NDS7z3TwI7aSFYa8eeh/WwI2fG6GFHipLK4
	grvVKsPF+xXSBX13b1Ezxik=
X-Google-Smtp-Source: ABdhPJzPItjGQb6F6/bo1oEeYY760bohlDmGC3YJUHRan9oNBER+DbcI0IpR2eksrJphoOLvJWJBPg==
X-Received: by 2002:a05:6638:490b:b0:32e:51f8:85b9 with SMTP id cx11-20020a056638490b00b0032e51f885b9mr3412456jab.294.1652821557809;
        Tue, 17 May 2022 14:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1913:b0:32b:ca33:6c9a with SMTP id
 p19-20020a056638191300b0032bca336c9als3424719jal.11.gmail; Tue, 17 May 2022
 14:05:57 -0700 (PDT)
X-Received: by 2002:a05:6638:2603:b0:32b:a724:2b8c with SMTP id m3-20020a056638260300b0032ba7242b8cmr12500534jat.278.1652821557353;
        Tue, 17 May 2022 14:05:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652821557; cv=none;
        d=google.com; s=arc-20160816;
        b=jF1FaHxt7V7ouB1zlvY2erSa9EkTiqYpTOQwSOqLOwB9hSysr38A3iOtdS+HNzr7Hw
         yoOPT9KDbDRWEgpfZEPV+v4hPafd1IVk+QQcpO1+i0+alsRxtE9xOi1IvJwH1NzrXhje
         ce8HT2oUclpoG5wqYRzmBY+aeB31mPEhTU9vwZQfNoFqmbQkEQcY62P0Zl3RyYfDS9DD
         W+Qtb6e/LYfe/kcoYjO8Pv7mLaX7uhPMASvfNaY0K3NnmkQBJIZ2UaQnXO7ySyu+7Z2W
         aNIZBVf96K/noGtbfisv3uqLIfG6Zbw3Tn8GieXD8lCfF7os0L/Bv7Ydw8ZMgEdOomRK
         JBcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:ironport-hdrordr:ironport-data:ironport-sdr;
        bh=dMH1bUxeRQhhldvkLxx1ZXn5m8NCYB26+WJk7qgYmgE=;
        b=Gysaogmg8BpRq1WRBndtd6PUF3pAGXbj1r19I6rrROu0o+nuNcQvuFbHYul5QxdJrA
         30Yu+CdkSuCPvTEWS00SUf1EY7qqeDlClGev98UHwEss5e8GODwm0LvXlA62PDynZg0f
         L36N3Z6OuS3mQ4TcV9VMl5G1uylYNNVCqtp9DMZdHc/19HLEPoSWod73A267mFy1lzFX
         LMroSqspQU6FIilTxtmTd/utXw7rN52GVxaVw+lSAZtrs5SvNJBjOVEgPVwYV0h4D34G
         J+EuABWQl+zhmSQMhcvK+F1b2933dBSGUaJFYRPqpH2rAKJ/AgXn67MqdlNdcIqx8VRz
         pSIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liu3101@purdue.edu designates 128.210.1.216 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from xppmailspam12.itap.purdue.edu (xppmailspam12.itap.purdue.edu. [128.210.1.216])
        by gmr-mx.google.com with ESMTPS id t8-20020a028788000000b0032b603bf16esi7575jai.2.2022.05.17.14.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 14:05:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 128.210.1.216 as permitted sender) client-ip=128.210.1.216;
IronPort-SDR: EcolU3GOREYZm/yLvCkxnMomZ4P2+F8XKSTXJZwD7ykZzATvIXRq0ND6JFHoTju0qgPOocEOFw
 3izNZ5cAw4zGVlFzAY/yqXE6hfboe8ZhQ=
X-Ironport-AuthID: liu3101@purdue.edu
IronPort-Data: =?us-ascii?q?A9a23=3A4FZru6rMG9kMKZqXIALiJi0rfWleBmIbZRIvg?=
 =?us-ascii?q?KrLsJaIsI4StFCztgarIBnUPf+PZDb8eownadnj90MD7Z7UytRgTwo6qSsxQ?=
 =?us-ascii?q?SwRouPIVI+TRqvS04J+DSFhoHqKZ6zyU/GYRCztZnOD9BqrLJb7qnxwifOBS?=
 =?us-ascii?q?rbmUbaWIj1rSRJpDiotlEs7yeI+h4dph/m/Ah+M5YOp+pGPaAf91m4mKH8Q5?=
 =?us-ascii?q?oKCtAhr4Kb4tgQeswFsfvtMplLfyyQYActHd6G8Jnf1WKdOGeu+S7qRxb215?=
 =?us-ascii?q?DqBrQ8wEN+4n/D2flBTGuzeOg2Hi3x3Xam+g0QS/XVugvZjbPdFMBVZkTSEm?=
 =?us-ascii?q?dx12e5hj53oRFd7JLDIlcQcTwJcT3N0M5pA9eKVOnO4q8GSkxDLfnawkfVjC?=
 =?us-ascii?q?EY6Yd8R9uptWzkc9PoUOWhQKBuYwfqr2r6mR69hitl6dJvnO4YWu3dByzDFD?=
 =?us-ascii?q?Kp2GsmfE/WSvdIIji0tgs1uHOrFY5ZLYzRYahmdMQZEPU0aCc5jker01GPzd?=
 =?us-ascii?q?SZU9ACcqaYtuTCBzQp9weCwdtHOPMSXX8lIkwCVqn+fpzb1BRQTNdq+zzuZ8?=
 =?us-ascii?q?y783baTzXOjAI9CRqel8vNKgUGIwjBBAhMhU1bm8+KyjVSzWo4CJkEZksb0Q?=
 =?us-ascii?q?XPez2T2CIikN/GEiCTc5EREBoMPS7dSBDylk8I43S7IXgDocRYeMLTKhOduL?=
 =?us-ascii?q?dAb/gfhc+HBXFSDg5XJIZ6pzYp4mBvpUcQjBTJYOXVUHVNtD+7L++nfhjqXJ?=
 =?us-ascii?q?jpq/TXcYtfdQVkcyBjSxMQyail6YWfmCsyGEV77bzKE/vAlTyY04AnGBj/j5?=
 =?us-ascii?q?Rg/fJO/a5Glr1XX8J6sLq7AFAnH5SBCwpPGqrlQUvlhlwTUKAkJNLWo+q3ca?=
 =?us-ascii?q?GT0mUN1E4QssTmh5hZPeKgMvmgvex41bJpslTjBJRW7VRlqzJNNLWaparFfb?=
 =?us-ascii?q?IW2BMAni6PnELzNX/bYdNdfYZ5vcCeI+ShvYQib2GWFuEsliqg5fJuWb+6jC?=
 =?us-ascii?q?nEVDalo1j2rX/xb2rgurgg6xGXOVdX4wg6h3L62enGYU/EGPUGIY+R/67mLy?=
 =?us-ascii?q?C3R8ssEbpPT4w1CSuHjb2/a/ZN7ELygBRDXHrj3rcBGLrPFKREgAHw7B+Lch?=
 =?us-ascii?q?74tZuRYc21uvr+g1hmAtoVwkTITXUH6FDg=3D?=
IronPort-HdrOrdr: =?us-ascii?q?A9a23=3AkbjXja00TIewCBBEiw4LAAqjBAokLtp133?=
 =?us-ascii?q?Aq2lEZdPU1SKOlfq+V7Y0mPHPP+U4ssTQb9+xoW5PtfZqjz+8S3WB5B97LNz?=
 =?us-ascii?q?UO01HEEGgN1+Hf6gylPCHi++ZB3eNJdqRkFZnWBVx35Pyb3CCIV/Et3dSO7a?=
 =?us-ascii?q?jtr+bX1GoFd3AIV4hQqyB0FwuSD0UzbgxPH4A4G5qX7tdGoT3IQwVzUu2LQl?=
 =?us-ascii?q?4IQuXKutWOu5rjYRsXbiRXijWmvHeO5KP2GwWRmjYZSS4n+8ZHzUH11yv0+6?=
 =?us-ascii?q?iqrvn+8RnY2wbonvNrseqk7ddfCcSQgowuJirhkQa0dO1aOoG/gA=3D=3D?=
X-IronPort-Anti-Spam-Filtered: true
X-IronPort-AV: E=Sophos;i="5.91,233,1647316800"; 
   d="scan'208";a="461971464"
Received: from indy05.cs.purdue.edu ([128.10.130.167])
  by xppmailspam12.itap.purdue.edu with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 17 May 2022 17:05:54 -0400
From: Congyu Liu <liu3101@purdue.edu>
To: dvyukov@google.com,
	andreyknvl@gmail.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Congyu Liu <liu3101@purdue.edu>
Subject: [PATCH] kcov: fix race caused by unblocked interrupt
Date: Tue, 17 May 2022 21:05:32 +0000
Message-Id: <20220517210532.1506591-1-liu3101@purdue.edu>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liu3101@purdue.edu designates 128.210.1.216 as
 permitted sender) smtp.mailfrom=liu3101@purdue.edu;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=purdue.edu
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

Some code runs in interrupts cannot be blocked by `in_task()` check.
In some unfortunate interleavings, such interrupt is raised during
serializing trace data and the incoming nested trace functionn could
lead to loss of previous trace data. For instance, in
`__sanitizer_cov_trace_pc`, if such interrupt is raised between
`area[pos] = ip;` and `WRITE_ONCE(area[0], pos);`, then trace data in
`area[pos]` could be replaced.

The fix is done by adding a flag indicating if the trace buffer is being
updated. No modification to trace buffer is allowed when the flag is set.

Signed-off-by: Congyu Liu <liu3101@purdue.edu>
---
 include/linux/sched.h |  3 +++
 kernel/kcov.c         | 16 ++++++++++++++++
 2 files changed, 19 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index a8911b1f35aa..d06cedd9595f 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1408,6 +1408,9 @@ struct task_struct {
 
 	/* Collect coverage from softirq context: */
 	unsigned int			kcov_softirq;
+
+	/* Flag of if KCOV area is being written: */
+	bool				kcov_writing;
 #endif
 
 #ifdef CONFIG_MEMCG
diff --git a/kernel/kcov.c b/kernel/kcov.c
index b3732b210593..a595a8ad5d8a 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -165,6 +165,8 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 */
 	if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
 		return false;
+	if (READ_ONCE(t->kcov_writing))
+		return false;
 	mode = READ_ONCE(t->kcov_mode);
 	/*
 	 * There is some code that runs in interrupts but for which
@@ -201,12 +203,19 @@ void notrace __sanitizer_cov_trace_pc(void)
 		return;
 
 	area = t->kcov_area;
+
+	/* Prevent race from unblocked interrupt. */
+	WRITE_ONCE(t->kcov_writing, true);
+	barrier();
+
 	/* The first 64-bit word is the number of subsequent PCs. */
 	pos = READ_ONCE(area[0]) + 1;
 	if (likely(pos < t->kcov_size)) {
 		area[pos] = ip;
 		WRITE_ONCE(area[0], pos);
 	}
+	barrier();
+	WRITE_ONCE(t->kcov_writing, false);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
 
@@ -230,6 +239,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	area = (u64 *)t->kcov_area;
 	max_pos = t->kcov_size * sizeof(unsigned long);
 
+	/* Prevent race from unblocked interrupt. */
+	WRITE_ONCE(t->kcov_writing, true);
+	barrier();
+
 	count = READ_ONCE(area[0]);
 
 	/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
@@ -242,6 +255,8 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 		area[start_index + 3] = ip;
 		WRITE_ONCE(area[0], count + 1);
 	}
+	barrier();
+	WRITE_ONCE(t->kcov_writing, false);
 }
 
 void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
@@ -335,6 +350,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 	t->kcov_size = size;
 	t->kcov_area = area;
 	t->kcov_sequence = sequence;
+	t->kcov_writing = false;
 	/* See comment in check_kcov_mode(). */
 	barrier();
 	WRITE_ONCE(t->kcov_mode, mode);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220517210532.1506591-1-liu3101%40purdue.edu.
