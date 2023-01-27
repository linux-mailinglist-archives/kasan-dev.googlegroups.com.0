Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQPVZ6PAMGQEOMJXQ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 50B3F67EACF
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 17:24:34 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id v2-20020a2e9602000000b002904dcec88esf525808ljh.8
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 08:24:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674836673; cv=pass;
        d=google.com; s=arc-20160816;
        b=X8RIni/8Pxsxy2Lp+7Y/gV8duM9HjL9rxP0PZd29CNOh8Xo1Lwvs+BfCp1N7I/bfAH
         e/TDB3v6yz7fGGRhYiBoFe/LUV+yi4Yr61Sq41g+qtvbbSoIBXC06lOTbVQDTy57yeQI
         kfr9gjwIFHVilgQRB+9JOoQ9UzFrh3gx0tYCSMukRLRrb5D8cIyLPlWW4LfC9Vy5k0W/
         MQntagAFWvGV4MPFP9CcZC4bBEuFC+5RGCmokzL1hLGMJDMEHZPdjEH+RVrw0y00I9K1
         P6tNLVAi2pUNowYGT02qZ6dbo6GSs0XxYWYrU7tfHb7icVpKk48V6yTye87imlBXx1wz
         is4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=XLG59BjhdynZ79LyuA/4pfzRT39fM1QL/ApFnRMSPLc=;
        b=qcR76GR5CRJqfltkj+1//sH8eCaQOZu7izfodwBir5XG9K25nCsF4TAxLN36GEkTUY
         JP1KunX8/UtdNSuH8Vvt9vDQixck2YE/fVy0sIVeNPJKBILKj5iL9MqPRg1Oyy+dvLwv
         gwLZLxYCa251wzFMoXxbTLdnVryuX8wxhP01ko63sDvYl/qnmyQuOOTDaM3XeHMyalUi
         plStyk0e2HmU6SP+/awkejbKn9rmesFeEmwAwbl2W2gF3zOVS94cSkpEYVz/UdVZOT/Y
         87WYuuTUUWTliN/aZmHIVZkMGvzf/RNkkui3YfyDIRHXC1HVPoeoWgheFZf4JC+vNhfX
         Noew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fYvcrw82;
       spf=pass (google.com: domain of 3v_rtywukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3v_rTYwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XLG59BjhdynZ79LyuA/4pfzRT39fM1QL/ApFnRMSPLc=;
        b=JEboXeF+/L0K4ZymWq0jP3Cem9TSsLbkzHP4NNR7gNg1db292xu1wwHsbnIcPQfqMV
         jxCwkROAZfVbBZJO2Cn5akTQJiZ+eKlHKUa85h7eK2b2Ag16PsH/tJNtI2p7H+V29r9Z
         uVYe3GzVD/yWqulv4JhdEVY2kkA2PUE5DwV2hNRHaLyqqu3Rpban0szSQTQTfS9V0gsh
         6ZnV7OZEXv2LrK8DTvqlxm9eJZf5pjs1VluCsDVkcuhn9jmjU3yNkbo0X0QcoxT3ytm6
         UDFAJcshNBI/TWOsfa/Ngr0t2x0T/nAvpaCeh4BfakMXYqPSgLnJ48DdXEajN5SZY37H
         EFMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XLG59BjhdynZ79LyuA/4pfzRT39fM1QL/ApFnRMSPLc=;
        b=Itf/ryp+Phiw5sdwNNEAwaJK1dOEvL7Dgo1wd4e7vIO05oMMgnArFQLB/W6aqYRO4g
         E8jp7vJZVJZiHMRSGYPQGXXN9D0LEkPzJ0gAO88cc1sIIq/y/m+PhS/B1/XKI6DRHEFj
         Ut24F2GdVAoyzE8UvhwjSVuopDzSyTUvPscusiaUcfX1zR3t822G1lXHBfplIsPvAHqG
         dT9Kivudzo4t1da8QFjN2ClOkALxU6SGb39gpIaBIPofpPJqDwiTwM6NgvTMRUVhJkMS
         hEZoFjRf0E64pCwos+SR9nMRd0HAVvuq64tIiUUHt5ALB0qslBa/R+t37CviSnbp6+We
         ie4g==
X-Gm-Message-State: AFqh2kpDou20d5MzgCVyrwSPFjTzM+wFMm2ABC1kXXheN14Rl9o1HVsJ
	Iw2VCBUKfAtR6QguigX7S+M=
X-Google-Smtp-Source: AMrXdXvaRkNvvKiwFI9nse0ShBqKVx8ns/5Ew91yjUApI1puWnY95vu4m5C2Im29dPFbgxZxV6KVfA==
X-Received: by 2002:a05:651c:1253:b0:28a:a1d3:572f with SMTP id h19-20020a05651c125300b0028aa1d3572fmr2560245ljh.20.1674836673604;
        Fri, 27 Jan 2023 08:24:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1146:b0:4cf:ff9f:bbfd with SMTP id
 m6-20020a056512114600b004cfff9fbbfdls335412lfg.1.-pod-prod-gmail; Fri, 27 Jan
 2023 08:24:31 -0800 (PST)
X-Received: by 2002:a05:6512:3d07:b0:4cc:a19c:7d93 with SMTP id d7-20020a0565123d0700b004cca19c7d93mr16316041lfv.43.1674836671888;
        Fri, 27 Jan 2023 08:24:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674836671; cv=none;
        d=google.com; s=arc-20160816;
        b=OO9RqBrr1ag7WlaOMHxqhmC4ecoVpWJ2o3mV3x/DljOuFNM8M+zk0DCTg3bBPWeu5i
         1DnAp5eU+yWh7SDNY6Zez6ybNlogekaZBOBRbZ47qiO2jMkT2sMDUzNcPN7IFcd+F7fk
         L9TJetSPSul33mYhJ8uPS1r1nfh/BJZw767CXOFGElKSLpAqPm/EJyf+QaK13w7/RRAQ
         +EQM+bNEEd4TSHGxxrawXmg5ww3z1l23aJanmxR6yLghXNF0ZwdEJohRBQBSdaE0b2Zy
         wIzG5zLbsswSr7EbFTf/tpVgCuU0np9CdNyP4Ml2ZggRwWRGECZgmEQApvLXg9pXfoU0
         oLHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=+ZA1LVGRnTSLVUFMxUOcf61woTjOoeoiKjydCG1Ukv0=;
        b=I0tdN15V3lW586LzoiyDlY6ODGs2kTNvj1vzrtX/mLxEjxDd5uj2kBu5b+0fobXbRc
         sATtYyQyGnxhpzmes+KKn4nitgOorZY9E3TB2o7Fmzsnx2NeN7baQ+4HxPWpdph2I1Rz
         3JKqnCYmXRMLs2ldi7ew7nkfaZUfg0LmJkSEa36rpRh9vmyY5aRbcJxlM659dhe5e/Jr
         ybVpE22JqQ3kE9RSmfO89vcc/L3BThMvzcbBWv1R0m3SgjGddYjNYIrz/eeiAeUlrIrK
         InU3f9QgdgqO+IvZ/6x6xvFxe+QCY168d6Mtt+DNGrUNPdBryFQXKclVPKCns329Swnk
         glgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fYvcrw82;
       spf=pass (google.com: domain of 3v_rtywukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3v_rTYwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id h6-20020ac25966000000b004d5786b729esi301415lfp.9.2023.01.27.08.24.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jan 2023 08:24:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3v_rtywukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id s3-20020a50ab03000000b0049ec3a108beso3893639edc.7
        for <kasan-dev@googlegroups.com>; Fri, 27 Jan 2023 08:24:31 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:19a:e00e:4f5d:59d8])
 (user=elver job=sendgmr) by 2002:a05:6402:b63:b0:4a0:e4bd:6ea4 with SMTP id
 cb3-20020a0564020b6300b004a0e4bd6ea4mr1477810edb.35.1674836671255; Fri, 27
 Jan 2023 08:24:31 -0800 (PST)
Date: Fri, 27 Jan 2023 17:24:09 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.456.gfc5497dd1b-goog
Message-ID: <20230127162409.2505312-1-elver@google.com>
Subject: [PATCH v2] perf: Allow restricted kernel breakpoints on user addresses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fYvcrw82;       spf=pass
 (google.com: domain of 3v_rtywukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3v_rTYwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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
in the kernel (perf_event_attr::exclude_kernel=0), if:

  1. No sample information is requested; samples may contain IPs,
     registers, or other information that may disclose kernel addresses.

  2. The breakpoint (viz. data watchpoint) is on a user address.

The rules constrain the allowable perf events such that no sensitive
kernel information can be disclosed.

Despite no explicit kernel information disclosure, the following
questions may need answers:

 1. Q: Is obtaining information that the kernel accessed a particular
    user's known memory location revealing new information?

    A: Given the kernel's user space ABI, there should be no "surprise
    accesses" to user space memory in the first place.

 2. Q: Does causing breakpoints on user memory accesses by the kernel
    potentially impact timing in a sensitive way?

    A: Since hardware breakpoints trigger regardless of the state of
    perf_event_attr::exclude_kernel, but are filtered in the perf
    subsystem, this possibility already exists independent of the
    proposed change.

Motivation:  Data breakpoints on user addresses that also fire in the
kernel provide complete coverage to track and debug accesses, not just
in user space but also through the kernel. For example, tracking where
user space invokes syscalls with pointers to specific memory.

Breakpoints can be used for more complex dynamic analysis, such as race
detection, memory-safety error detection, or data-flow analysis. Larger
deployment by linking such dynamic analysis into binaries in production
only becomes possible when no additional capabilities are required by
unprivileged users. To improve coverage, it should then also be possible
to enable breakpoints on user addresses that fire in the kernel with no
additional capabilities.

Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---

Changelog
~~~~~~~~~

v2:
* Commit message (motivation, more explanation).
* Apply ack.

v1: https://lkml.kernel.org/r/20220902100057.404817-1-elver@google.com
* Rebase.

RFC: https://lkml.kernel.org/r/20220601093502.364142-1-elver@google.com
---
 include/linux/perf_event.h |  8 +-------
 kernel/events/core.c       | 38 ++++++++++++++++++++++++++++++++++++++
 2 files changed, 39 insertions(+), 7 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index c6a3bac76966..a95a6b889b00 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -1463,13 +1463,7 @@ static inline int perf_is_paranoid(void)
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
index d56328e5080e..0f1fc9aef294 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3174,6 +3174,12 @@ static int perf_event_modify_attr(struct perf_event *event,
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
@@ -12289,6 +12295,38 @@ perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
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
2.39.1.456.gfc5497dd1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230127162409.2505312-1-elver%40google.com.
