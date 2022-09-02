Return-Path: <kasan-dev+bncBC7OBJGL2MHBB65IY6MAMGQEOYA3HRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id CC8975AABFB
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 12:01:31 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id v1-20020a056402348100b00448acc79177sf1075941edc.23
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Sep 2022 03:01:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662112891; cv=pass;
        d=google.com; s=arc-20160816;
        b=QGLLLoUvoLPXlsCh3WXsN5QsVBBUfOLEV8xppqfzRoUePrM+WIX8vqAcV4SvmlUtY3
         i2G0SPz0qTOgnePXFs3271gimP9Og6q7lkkhVt7wUze+OxHidDQbhjSHMbS/X8rdDCp2
         SVwUfnOLxQ3ZSTuAsOJzoTwEODEcr5hNvrM9lRc5YPAchZn60CIlVimWWMSYF1H+hUSo
         Qg1KAM5CHt2BWAYNRnmtQIlLcCyZ0fDi1rixx1W3uxVSqmZrhap/CIywLIirZsanIpWL
         g0/aLbIvNGiNa4Isq0fRXdWE0hVVFRsY8s8T/vj8gUPSNtRTlWesevPTvh+zE2GpCziZ
         lj/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=sr+HZluvhlWT+xGmPFW8Loz/lpIsQtJiDdQKmXWvKgU=;
        b=iDWEjqKW3Fmu9oSJ83NATTWPxkyqR6GACyzh8y3Wx++QOe+P9ODvNE1P+Q2P58enYV
         KzB1Z+GnluHjAMdJd9LDPjV4UfY1AS8ZjKwjE83STidNBtKsTU1GvhPIfWv7IUqvLXaX
         uEzTbZrmvu57/5Sgy+7rhAAjQwVJ9pwv5R+BarrxfoPC438Z0vrz4aX8QtKZKSxO6CNN
         q13CKqoW8a6o8z0fUsKa5EHMVJXSFpdkDUlQiYCF79ZkJoZXd0FOmJkUT+n8oPuKUyWA
         thys0DrzcDoRTSSGiAJXjP6QqIaX28oRWjBKfivFESSe3VQLJUOUH5fMRroDmP8DxyDU
         IPYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JIu9bTSk;
       spf=pass (google.com: domain of 3edqrywukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3edQRYwUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=sr+HZluvhlWT+xGmPFW8Loz/lpIsQtJiDdQKmXWvKgU=;
        b=txHdKvHZG9qF9OslfxlPvHwM7VdZ2LTp3YMwbnH4pad/jurU1VxrWxv2vsC68/rxEd
         PUxCdgfgcXAKWHDedg7BB6ZeTELbueB4z8wIdDYKLtIECNr0viHfteGJsvgybshaOXjp
         AV99gMfthpXQ6CLHCdjGKXZvigIc8kNrVS3PEquLO2TEX8X8EcBJaooyI1BCFOQ/iSrI
         wON4ooiDnxXeKq1lI4EJ5gNfgtLsjMhrbeEJ05YTD4Xb83LLe1ktRBKnaiYnVSFEMLgW
         dzWpatye+aAmFP1XoO/v6uFjesA4VCvxp9myUF/QHAyaQAwLBA/vWLREEEYn5/kbHQon
         XVbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=sr+HZluvhlWT+xGmPFW8Loz/lpIsQtJiDdQKmXWvKgU=;
        b=T/WekWD5ziTgweFLMMQe41D/8Ddl0urE/7oWoo0KWu5TmsoGLZp9f9DiYVyquMe4Mk
         brIpGQ0FTcj9nCINtR3lGcNRFviKxq22t225BFv4qcmNMUoDvEYUZO2hYUYzf+VJVorx
         3fRaYe//dx6ucUsyQaQz5dHp6nw/CEhHtgD/0Wzdubu6fB0dSF24B5gOIFttZMnATC3V
         jyI/lgabRdH5ucLO9xbsKbRHKhUaL1A2Kbw/ctDvN05SWBeMAQi4ibgvSNbQUeRztd5I
         nGaTU8iVUatqOhFoInP2asHi4Qd9WNBPzoJK0Lc44P9OW5ELJ5OnDaR/GRs6/xsxluPS
         /PCQ==
X-Gm-Message-State: ACgBeo2esGS26UIBOyzbzSOYBTcBmeZVz0IZmsHvh7fvjF9HZa3hFhMO
	pAEa3LONedmBDsVEZajl2Hc=
X-Google-Smtp-Source: AA6agR4AqMTRfC3gW7vXdbTuLJCzdXrbthXDabWdcJK5udd3PZx5AL+SmlQEQjW7cLhX/Oe2TlTTHQ==
X-Received: by 2002:a05:6402:34cb:b0:448:9fac:20a0 with SMTP id w11-20020a05640234cb00b004489fac20a0mr16879943edc.160.1662112891233;
        Fri, 02 Sep 2022 03:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3f87:b0:726:2c39:8546 with SMTP id
 b7-20020a1709063f8700b007262c398546ls679126ejj.8.-pod-prod-gmail; Fri, 02 Sep
 2022 03:01:29 -0700 (PDT)
X-Received: by 2002:a17:907:7613:b0:73d:ca26:1ec7 with SMTP id jx19-20020a170907761300b0073dca261ec7mr26140174ejc.511.1662112889860;
        Fri, 02 Sep 2022 03:01:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662112889; cv=none;
        d=google.com; s=arc-20160816;
        b=EU59zMweDm5a6LYVwO2iC+QcWHlC4psQNuNDP5fwJ5njsqBHweWCEWdQ/fhv/eLNhZ
         nE/aRwJhhsgu4A1FUQdifrj+pu3aVsXsn6JBckA9har6gXfyxz7bjSazi/YLICJX+Yv+
         LpIJiMTSbqZz/NQQ5r+gHN+V02rSPfDhYtFhEl8bbd5rhi/3ac/+0jMpNaR9OVFz7wan
         LoUPLXU+uWK6wetxqll4G2oD7Bt1Ysm+d6/d654GrADrW41yomAg9O/SlKyd6C1GgS4f
         Kp5EbDBthopZZ3dsnk6XkNPUoeijY2xKLOxbJE2U2TZ59qaHqICSmsFtgDEaxpC+6fbg
         1K6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=hEVwDu/wAWLZN7jGwPsqk/ffr8euR5CaDbdaYqqibfI=;
        b=VUwzaXlU/G7d+RvS2KJ7/+dhMpjw2Ljgl4BqA/NpWWaPLZfue2Sqny1g2RMAPlRLPZ
         rd/iUCFislDDrOA52ANnPGAEH93izQOI/+kjTD51OJuzvge+SNvLMfCdQGsgn/PBiN91
         nG5I8ZCIfamrXTQecUWp9KrHMkfKpRpvncyqcErloOsNF+h6iFwS8yrfqq7LITAuJ8ha
         m3JakQ3rwW7nGs/mDDxayvmd6Je3l1y+IfLGaxj6nJL+VfJuznV3ThXUCqB7x04g2WeV
         5v7ylo5LZzq52vryizw6eWQfblS7KKKoAnz9EVmjpQY06RU6g3o6AQM5eaze0xjmGbEZ
         6TJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JIu9bTSk;
       spf=pass (google.com: domain of 3edqrywukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3edQRYwUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id a20-20020a50ff14000000b0044608a57fbesi65371edu.4.2022.09.02.03.01.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Sep 2022 03:01:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3edqrywukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r11-20020a05640251cb00b004484ec7e3a4so1086531edd.8
        for <kasan-dev@googlegroups.com>; Fri, 02 Sep 2022 03:01:29 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8d53:41f1:1226:8e63])
 (user=elver job=sendgmr) by 2002:a05:6402:1909:b0:447:f0d3:a9b1 with SMTP id
 e9-20020a056402190900b00447f0d3a9b1mr27751544edz.100.1662112889512; Fri, 02
 Sep 2022 03:01:29 -0700 (PDT)
Date: Fri,  2 Sep 2022 12:00:57 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220902100057.404817-1-elver@google.com>
Subject: [PATCH] perf: Allow restricted kernel breakpoints on user addresses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>
Cc: Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JIu9bTSk;       spf=pass
 (google.com: domain of 3edqrywukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3edQRYwUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Allow the creation of restricted breakpoint perf events that also fire
in the kernel (!exclude_kernel), if:

  1. No sample information is requested; samples may contain IPs,
     registers, or other information that may disclose kernel addresses.

  2. The breakpoint (viz. data watchpoint) is on a user address.

The rules constrain the allowable perf events such that no sensitive
kernel information can be disclosed.

Despite no explicit kernel information disclosure, the following
questions may need answers:

 1. Is obtaining information that the kernel accessed a particular
    user's known memory location revealing new information?
    Given the kernel's user space ABI, there should be no "surprise
    accesses" to user space memory in the first place.

 2. Does causing breakpoints on user memory accesses by the kernel
    potentially impact timing in a sensitive way?
    Since hardware breakpoints trigger regardless of the state of
    perf_event_attr::exclude_kernel, but are filtered in the perf
    subsystem, this possibility already exists independent of the
    proposed change.

Signed-off-by: Marco Elver <elver@google.com>
---

Changelog
~~~~~~~~~

v1:
* Rebase.

RFC: https://lkml.kernel.org/r/20220601093502.364142-1-elver@google.com
---
 include/linux/perf_event.h |  8 +-------
 kernel/events/core.c       | 38 ++++++++++++++++++++++++++++++++++++++
 2 files changed, 39 insertions(+), 7 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index a784e055002e..907b0e3f1318 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -1367,13 +1367,7 @@ static inline int perf_is_paranoid(void)
 	return sysctl_perf_event_paranoid > -1;
 }
 
-static inline int perf_allow_kernel(struct perf_event_attr *attr)
-{
-	if (sysctl_perf_event_paranoid > 1 && !perfmon_capable())
-		return -EACCES;
-
-	return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
-}
+extern int perf_allow_kernel(struct perf_event_attr *attr);
 
 static inline int perf_allow_cpu(struct perf_event_attr *attr)
 {
diff --git a/kernel/events/core.c b/kernel/events/core.c
index 2621fd24ad26..75f5705b6892 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3176,6 +3176,12 @@ static int perf_event_modify_attr(struct perf_event *event,
 		return -EOPNOTSUPP;
 	}
 
+	if (!event->attr.exclude_kernel) {
+		err = perf_allow_kernel(attr);
+		if (err)
+			return err;
+	}
+
 	WARN_ON_ONCE(event->ctx->parent_ctx);
 
 	mutex_lock(&event->child_mutex);
@@ -12037,6 +12043,38 @@ perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
 	return is_capable || ptrace_may_access(task, ptrace_mode);
 }
 
+/*
+ * Check if unprivileged users are allowed to set up breakpoints on user
+ * addresses that also count when the kernel accesses them.
+ */
+static bool perf_allow_kernel_breakpoint(struct perf_event_attr *attr)
+{
+	if (attr->type != PERF_TYPE_BREAKPOINT)
+		return false;
+
+	/*
+	 * The sample may contain IPs, registers, or other information that may
+	 * disclose kernel addresses or timing information. Disallow any kind of
+	 * additional sample information.
+	 */
+	if (attr->sample_type)
+		return false;
+
+	/*
+	 * Only allow kernel breakpoints on user addresses.
+	 */
+	return access_ok((void __user *)(unsigned long)attr->bp_addr, attr->bp_len);
+}
+
+int perf_allow_kernel(struct perf_event_attr *attr)
+{
+	if (sysctl_perf_event_paranoid > 1 && !perfmon_capable() &&
+	    !perf_allow_kernel_breakpoint(attr))
+		return -EACCES;
+
+	return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
+}
+
 /**
  * sys_perf_event_open - open a performance event, associate it to a task/cpu
  *
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220902100057.404817-1-elver%40google.com.
