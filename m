Return-Path: <kasan-dev+bncBCLMXXWM5YBBBFWA2KGAMGQEOJNSK3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id BE7614540DA
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 07:24:23 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id y25-20020ac87059000000b002a71d24c242sf1299202qtm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 22:24:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637130262; cv=pass;
        d=google.com; s=arc-20160816;
        b=RT3RBY0G9g4koJrwf87CMqGmUP6dD1RsupmDMG3fFy3QAsZiVIUTDxTdwdFFhO3LKa
         Y9Jb2YTXsbocXxliu2RQ359DYGPyQ08v9UUI1jDCLrNv5cum5jKk5s8MZxxdB/EChjOg
         FT4v2YTC7LTHJhJ2JqE9TvMzMR5wvTHLa7US1vBkM9qhmokDs7F1boeFYNzffniuGq+l
         uZExXFAV1vXtLBaoOjcULZfDutj7m1MkxWj6UdaQjnSgS+kcRDAzPUiHSTkiOAvYerjN
         QMhxQJNVpv2lktOkcg0ygRpl84qUy/UnBGu+QY3FQaR9+MFcXgfJ3ps1xyGtyuQwY28r
         BkIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=j13cLNUo5kJWJ8gm8NrEB8iyrjQ+wKUoRHW9jYqzsTI=;
        b=evW/bpR4TzBK4i4IgnxPgItTSLpiRWXalsBBCK0EypCvmLLdd1Xf2ssFhQCqdCuDkg
         3APZQuiLhnKSCfoNTUsYnrUzdVCqNzpaGEkeD9y+iuwv6kY6Oh7wRoFfkyGk2IUUStxC
         C4LbpgdXidVeWitmEXQfXjWDjIpuv/s4Fkth087nVR4V/QcRV/HVm9xJhmAuWwanddqR
         CA2UPqBA9qI2Bm4XnpmaqDQTPHrTBEQ3x+ZiGfiST8qEVqZEYu/E/dHQOt8UwS7Fvxls
         JxuSLZdbjGsVqknFR0iXWsW0ylgbgGdU5IE/FE0q7huUr9Scr/eHSh4fxTVBESa3qRzw
         L/XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=SPKO3wiQ;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j13cLNUo5kJWJ8gm8NrEB8iyrjQ+wKUoRHW9jYqzsTI=;
        b=RRv80oAjzJueYu/YGuPOR51Y/Tr6EZXdILFis3fDZeqMzK40g944kGXmaMk9EN47gE
         7jjtyyfTG2T1Wdpas9y+J8GHB1QwihpDaytgK1OlkNgwu4dJwhfXfLFJJj0XLLEqAZaG
         xcN6QhE97Ia0mxDK1rpT+mAILT66rlF5SP9GjOT0F0LFPFPrIHaSs1SXWxiLAt6DpqSY
         ZaQJUSCCZ2X0IOO9wyQc41tRSKV8d/UyBC9A8zYlVjkY5/J1Dw3K8JFfzH7CSSo6bBN2
         bXIRbnWkxJm/nxjDj413siw/UHuBl+LP2LrygMkwFQx01qcV/egXUDZX6pPb593bJwa2
         nzsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j13cLNUo5kJWJ8gm8NrEB8iyrjQ+wKUoRHW9jYqzsTI=;
        b=GH1+gS4SjGoQe1gSLT7QSpcQ19cI9ZaZAMWmI8r199jsdWdrklrb4CVUDghvkNO1C8
         RYYqU75mPah9Ert+oYkMp1DKRnwJhVl7kq1lAqgwCuBvD2sCljenkr92u111qNzINGE4
         35TgkFydzLpP3cHUvWatGEpNQ3PeuPyafVJ+z93Z28ZZcof/kGsmto3XXLOuSRdXVRfo
         0uJdMqHG+Gt8XQpuvlknwaJCTCtH8zObrZZlCGaF/m/+GGfNH0QMlrdIQ9rG58S4c/XI
         q1IxfepV64h6hYSdknkYlxOA14rLyYrR/rLk9Eivt3Yhg+ww1afYfTtY1R9vQX7fj7K4
         8wqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531J4Ow0pr9T9dZUo4jNg99cHCE7eW20lWskK3PJxOZkGATHOtQz
	cNDP9hbOBMVjFD/UWStRB18=
X-Google-Smtp-Source: ABdhPJxiSEw88RI85+F0YixstXASjW8x8N933WCby7OY3i2EpdzdfkLq+fQ0XyZyBBSbeRvq/IjkOg==
X-Received: by 2002:a05:622a:2cc:: with SMTP id a12mr14620017qtx.101.1637130262762;
        Tue, 16 Nov 2021 22:24:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1aa2:: with SMTP id bl34ls4624381qkb.11.gmail; Tue,
 16 Nov 2021 22:24:22 -0800 (PST)
X-Received: by 2002:a37:a590:: with SMTP id o138mr11088953qke.174.1637130262274;
        Tue, 16 Nov 2021 22:24:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637130262; cv=none;
        d=google.com; s=arc-20160816;
        b=gbA5x+2SVsobz/1cN3uI+2aBwigWyx2Q152iUpfitBTHpoY7GVa0I9J6mJW+WOS3/3
         MEDu3+AI+q1rD3Xzixr+85O4BHynUfz4GkTv/Fs6Mj5GsNL9qd+ta0sCxzGss6ZD2s4+
         /m8vR70YLiFvIWXK3Wg6sGhGnczGZM3fOO4BrHnlGfEWwEtMuO/9CsW7G5tfYpXscdfp
         O5yB8/n5t3QHhaTGtsGtOx50h7YFZcwWNi9jBLSWuyTpwZmXZDN/G3P94RsVDBv39SR4
         XDoRPTfD0W5aXaO8wjQtcGr0ePK+CMqMz+BVATuE2qtosSKRSYWlFPjKain4k2GUV0sD
         8cng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=zIX62yKEAzemloLlCjhxAEBsl3MuZkL1GfPZwoTxoW4=;
        b=f7ot3Bl+qEtM80oSoB4rNTgLq+o/P9YFviXIy7FHSLi/R4ki1b/lHRe5BSBaIfOP+o
         1Gy4ZOWR9OrB7kxIVw2wNL9zpxiFiBclq9mb8VJrezMLSBCsEPzaMc0ZSWIvQ4lYzS18
         SjaXXBKpC4imTYbUqB+FhYUMjTQFnk52Vto8srA05evU9110aktPtZhpnIyU0EKISH6p
         MEk1A0nWPVvWQ6MPoFUmLEm71f7PigTFdwZHJSOFZ2RFwI5ngAxJKui8Nhd9kU7nsSTt
         d0Slps1SQAu6ax3Ujz8MoC1xa1x0gzCfO+Ad/ZcM8gtFAZMYRsKiUIKfjwTlmNhj11SX
         ZwEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=SPKO3wiQ;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-01.qualcomm.com (alexa-out-sd-01.qualcomm.com. [199.106.114.38])
        by gmr-mx.google.com with ESMTPS id s4si593854qtc.4.2021.11.16.22.24.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 22:24:22 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as permitted sender) client-ip=199.106.114.38;
Received: from unknown (HELO ironmsg-SD-alpha.qualcomm.com) ([10.53.140.30])
  by alexa-out-sd-01.qualcomm.com with ESMTP; 16 Nov 2021 22:24:21 -0800
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg-SD-alpha.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Nov 2021 22:24:20 -0800
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Tue, 16 Nov 2021 22:24:20 -0800
Received: from ecbld-sh063-lnx.qualcomm.com (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Tue, 16 Nov 2021 22:24:18 -0800
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: <dvyukov@google.com>, <andreyknvl@gmail.com>
CC: Joey Jiao <quic_jiangenj@quicinc.com>, <kasan-dev@googlegroups.com>
Subject: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Date: Wed, 17 Nov 2021 14:23:54 +0800
Message-ID: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
X-Mailer: git-send-email 2.7.4
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=SPKO3wiQ;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as
 permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

Sometimes we only interested in the pcs within some range,
while there are cases these pcs are dropped by kernel due
to `pos >= t->kcov_size`, and by increasing the map area
size doesn't help.

To avoid disabling KCOV for these not intereseted pcs during
build time, adding this new KCOV_PC_RANGE cmd.

An example usage is to use together syzkaller's cov filter.

Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
---
 Documentation/dev-tools/kcov.rst | 10 ++++++++++
 include/uapi/linux/kcov.h        |  7 +++++++
 kernel/kcov.c                    | 18 ++++++++++++++++++
 3 files changed, 35 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index d83c9ab..fbcd422 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -52,9 +52,15 @@ program using kcov:
     #include <fcntl.h>
     #include <linux/types.h>
 
+    struct kcov_pc_range {
+      uint32 start;
+      uint32 end;
+    };
+
     #define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
     #define KCOV_ENABLE			_IO('c', 100)
     #define KCOV_DISABLE			_IO('c', 101)
+    #define KCOV_TRACE_RANGE			_IOW('c', 103, struct kcov_pc_range)
     #define COVER_SIZE			(64<<10)
 
     #define KCOV_TRACE_PC  0
@@ -64,6 +70,8 @@ program using kcov:
     {
 	int fd;
 	unsigned long *cover, n, i;
+        /* Change start and/or end to your interested pc range. */
+        struct kcov_pc_range pc_range = {.start = 0, .end = (uint32)(~((uint32)0))};
 
 	/* A single fd descriptor allows coverage collection on a single
 	 * thread.
@@ -79,6 +87,8 @@ program using kcov:
 				     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
 	if ((void*)cover == MAP_FAILED)
 		perror("mmap"), exit(1);
+        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
+		dprintf(2, "ignore KCOV_PC_RANGE error.\n");
 	/* Enable coverage collection on the current thread. */
 	if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
 		perror("ioctl"), exit(1);
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index 1d0350e..353ff0a 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -16,12 +16,19 @@ struct kcov_remote_arg {
 	__aligned_u64	handles[0];
 };
 
+#define PC_RANGE_MASK ((__u32)(~((u32) 0)))
+struct kcov_pc_range {
+	__u32		start;		/* start pc & 0xFFFFFFFF */
+	__u32		end;		/* end pc & 0xFFFFFFFF */
+};
+
 #define KCOV_REMOTE_MAX_HANDLES		0x100
 
 #define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
 #define KCOV_ENABLE			_IO('c', 100)
 #define KCOV_DISABLE			_IO('c', 101)
 #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
+#define KCOV_PC_RANGE			_IOW('c', 103, struct kcov_pc_range)
 
 enum {
 	/*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 36ca640..59550450 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -36,6 +36,7 @@
  *  - initial state after open()
  *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
  *  - then, mmap() call (several calls are allowed but not useful)
+ *  - then, optional to set trace pc range
  *  - then, ioctl(KCOV_ENABLE, arg), where arg is
  *	KCOV_TRACE_PC - to trace only the PCs
  *	or
@@ -69,6 +70,8 @@ struct kcov {
 	 * kcov_remote_stop(), see the comment there.
 	 */
 	int			sequence;
+	/* u32 Trace PC range from start to end. */
+	struct kcov_pc_range 	pc_range;
 };
 
 struct kcov_remote_area {
@@ -192,6 +195,7 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 void notrace __sanitizer_cov_trace_pc(void)
 {
 	struct task_struct *t;
+	struct kcov_pc_range pc_range;
 	unsigned long *area;
 	unsigned long ip = canonicalize_ip(_RET_IP_);
 	unsigned long pos;
@@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
 	t = current;
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
 		return;
+	pc_range = t->kcov->pc_range;
+	if (pc_range.start < pc_range.end &&
+		((ip & PC_RANGE_MASK) < pc_range.start ||
+		(ip & PC_RANGE_MASK) > pc_range.end))
+		return;
 
 	area = t->kcov_area;
 	/* The first 64-bit word is the number of subsequent PCs. */
@@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 	int mode, i;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
+	struct kcov_pc_range *pc_range;
 	unsigned long flags;
 
 	switch (cmd) {
@@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov->size = size;
 		kcov->mode = KCOV_MODE_INIT;
 		return 0;
+       case KCOV_PC_RANGE:
+		/* Limit trace pc range. */
+		pc_range = (struct kcov_pc_range *)arg;
+		if (copy_from_user(&kcov->pc_range, pc_range, sizeof(kcov->pc_range)))
+			return -EINVAL;
+		if (kcov->pc_range.start >= kcov->pc_range.end)
+			return -EINVAL;
+		return 0;
 	case KCOV_ENABLE:
 		/*
 		 * Enable coverage for the current task.
-- 
2.7.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1637130234-57238-1-git-send-email-quic_jiangenj%40quicinc.com.
