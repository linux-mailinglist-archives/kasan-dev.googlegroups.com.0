Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWXF3SKAMGQEJXNVOEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A1F153A091
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jun 2022 11:35:23 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id u2-20020ac258c2000000b00478e5471097sf678401lfo.8
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jun 2022 02:35:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654076122; cv=pass;
        d=google.com; s=arc-20160816;
        b=k0Soi9haxpR6UdR9sDqVxJ0gWpeNRO6zqGgYv0yhgUKwbFSBqEpZbXLQp+Gdpltrnq
         wv1MUYHEhp9J2ePdOQRYC9inm/LdsXO9ZwyFmfaGyqOYRL/XZC3zpSPNjZwXjitZpDZ4
         0wWt/AlKr/23HuCJGEG+0eKCedYPwSAQmzxtJkEDsDQdEtTzpLz6v+kyfkEIizg5b6/P
         uQtfnpl639FpAlCrRDbuZYbT/DmgyE9rufJufaQpLR39dN6PSwWlTkhtJ3Xl5F37LVak
         u8GyVq1yd1Fgj2LCfMSNbl4vKQiUzuDUGzvQQ0QbpRO9hJJ7hSrkCuA/BiWZ1nQvfxCi
         f3bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=FUcyJcgAz+Fwyws93IHk5KZmyCneevKMGDH+H3t/iF0=;
        b=RJSjCgLODIN+/KdT12k51NoZinqXJrax6B6LNj08jV5Qb64q+qa5YIJ/f5CREKk8Dd
         DkCbqaTt5ieFNN65j1eev54ugDL9OEDgx4PUJTsWMTMfmWh+3ZPECNLFI0KhQ0HEBW6i
         EJUiNf4C2phg6cV+suqXLl7VPB9Rn0q7fQXnvjDjFaP+7Rra8EwLpQ/w1ADE0KzfpUcY
         Kj68wVg0ouGpzsq1cnQ+8jJAIHd+z/fWCiQehQWhchP2bJRQCBwqg2/hQit5cRo3g16Q
         aiBoFECMNHf9K3PGL1esOFx7FnqtZfp+I9oIRepJVyZ3l7meqOm6dAHY3RSSoICKSIjO
         Z+fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fU3U+u9o;
       spf=pass (google.com: domain of 32dkxygukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32DKXYgUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FUcyJcgAz+Fwyws93IHk5KZmyCneevKMGDH+H3t/iF0=;
        b=Hzpu5xndDJv3BtPjxGt1mR6QnMUZI4CRMM6WynKxSalsgq/dSR/ddwGJ7BlI/Zs7We
         1+5DEUCqVrWb23g6AldsXYqZ/t47bPMbyJ8cdyVTZIhjjFjaeMDDruul1rcbntgZQ55O
         y/YKaMOohlpdbViY1WIljRvHBjFcgFqBCg1eUchu7DQfJsRGzxdAWgK9P5n8W9ctqArD
         YCRwFXVuly+6/BdNYTUOYlgqgT07o5XdNV7NHOtAQmHm8qydG9Ky5lAwxAJopcE7kkWP
         DZwdmbvsdyR/TieLqNWj+yQPqrg/smCFV86s6q0bQQwWjcw4in+OdHRwqFKkopVaVzdq
         9beA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FUcyJcgAz+Fwyws93IHk5KZmyCneevKMGDH+H3t/iF0=;
        b=rJxh/KBzns/7e5CBs3W9H18fYzltZ474UsNk1sveP+3SXEBmPLvtFGzuxL1zXKegFR
         PBZWqmk+ySKyZb07dMaF9bqyr4C+0FW+JCld/L7FTeXVwK8wqXD+urLTohw1meDG9US3
         NV5VZJjdoQhY9bvDGBRfsRK2nXnUFDqtBb6daVYWoQ0kSuB8/eewiLk/tLo7J+B8jiTF
         uTcadUxu2VMM9jEmKDYFYRcDemsBZDSTe9J7yEvgqO+/+d62qhmMIgpYdqzbnEQ4wpmt
         UToasATY7DwTTidLjbk77S6aNm+3xV7WrgpcmDKNWE8t+bFi6XY+0hZLVSeiqfHMl/iR
         E3ww==
X-Gm-Message-State: AOAM530ANp44pCOyyjalQJP4GAsZGoal4RVxVCwRGuq56mTYPzVHuRt3
	96930/LPk7rZsvjK70in/Nw=
X-Google-Smtp-Source: ABdhPJyXHV+CWIe5vD/9SMkqIkaUxWm3PzxVCAs/LIcbdy/8kOwZWohuVNTkmmbpEu3Xebza4hGOAA==
X-Received: by 2002:a05:6512:239f:b0:478:5c6c:ee0a with SMTP id c31-20020a056512239f00b004785c6cee0amr41265020lfv.664.1654076122402;
        Wed, 01 Jun 2022 02:35:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10cb:b0:478:7256:822a with SMTP id
 k11-20020a05651210cb00b004787256822als1324742lfg.3.gmail; Wed, 01 Jun 2022
 02:35:20 -0700 (PDT)
X-Received: by 2002:a05:6512:39c1:b0:44a:e25d:47fd with SMTP id k1-20020a05651239c100b0044ae25d47fdmr46164236lfu.580.1654076120889;
        Wed, 01 Jun 2022 02:35:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654076120; cv=none;
        d=google.com; s=arc-20160816;
        b=P4kfdD1EDLqA3C+Ii0KA9JECxtf7FY9JR6rTNC3fPVjNS6eRZk0Vl85ZR0/zlI3inY
         fOWMjI/xdX5dVqpomwDHFoW76oYVpUpCaGXpTw8HJPq7IMXkVriO/D+qIurJp+dzdbTU
         mUpH3nHkFH/ayG8tjEFm1BOBY12GieLKnDUh0rGkAPtJVuxbFp0rahan2L8z7iBTcneT
         +o57Ld72fk5pWCexRuMOQGGmRQGogv3xflCMDj7oE8f/f8+m3l3qzqEr/y0jhknItDKP
         2X6sQHSjFAbZYVPSYuhMriKMLegMoJ9Q+aC5ctqZUJx7DUT4UsXAsGJBJbmVTJJMZlJL
         +qTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=nAAyFhVOk4u65vleHIjgu+W4rGODUec3akAhRLx+y9I=;
        b=nA7qf/hojW8i+2Q6d2g5DA2rG+9kheuaOK57uyQaS9UVRx8TizLuLVuUL5LSZ8uGHq
         MVgh3K3/FqzN9Mz2DWFuxj7W9H2CBbWkxcv1Gxp1bCyq6jwm7W/MrHIY+Oaz6O/GlQ3Z
         S0cp4F4KMv7L/vpPCVSQjsznF4LD+swWVkLFrMMRVAM/ZI0t51HhQl1jeP0cCfFaD27z
         nt5eTJqPky3Y0PfnN0f3AUk93cUxqZs9Ipl5T7sJoN9UP+Bze0Ff49h0Q1s/61QvNvRh
         uHt+2SPf2LI/VusgmnwM2V0oWnG2jcYNDHpH1LgA1tBC7fhBHf6BP2Xo+IKxAtVUy9Yi
         5dGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fU3U+u9o;
       spf=pass (google.com: domain of 32dkxygukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32DKXYgUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bp22-20020a056512159600b0047866dddb47si52921lfb.2.2022.06.01.02.35.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jun 2022 02:35:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32dkxygukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id m20-20020a170906849400b006ff296bb911so660216ejx.6
        for <kasan-dev@googlegroups.com>; Wed, 01 Jun 2022 02:35:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:ed43:9390:62cb:50ee])
 (user=elver job=sendgmr) by 2002:a05:6402:2211:b0:42d:cb9e:cbf with SMTP id
 cq17-20020a056402221100b0042dcb9e0cbfmr18833360edb.76.1654076120249; Wed, 01
 Jun 2022 02:35:20 -0700 (PDT)
Date: Wed,  1 Jun 2022 11:35:02 +0200
Message-Id: <20220601093502.364142-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH RFC] perf: Allow restricted kernel breakpoints on user addresses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Thomas Gleixner <tglx@linutronix.de>, Jann Horn <jannh@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fU3U+u9o;       spf=pass
 (google.com: domain of 32dkxygukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=32DKXYgUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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

	1. Is obtaining information that the kernel accessed a
	   particular user's known memory location revealing new
	   information? Given the kernel's user space ABI, there should
	   be no "surprise accesses" to user space memory in the first
	   place.

	2. Does causing breakpoints on user memory accesses by the
	   kernel potentially impact timing in a sensitive way? Given
	   that hardware breakpoints trigger regardless of the state of
	   perf_event_attr::exclude_kernel, but are filtered in the perf
	   subsystem, this possibility already exists independent of the
	   proposed change.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---

RFC:

We are looking to identify a set of constraints on perf events that
would allow them to safely be created by unprivileged users when
perf_event_paranoid > 1 && !perfmon_capable().

Our current (and only) event type of interest is PERF_TYPE_BREAKPOINT.

Any thoughts?

---
 include/linux/perf_event.h |  8 +-------
 kernel/events/core.c       | 38 ++++++++++++++++++++++++++++++++++++++
 2 files changed, 39 insertions(+), 7 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index af97dd427501..06c2ed46cbf9 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -1348,13 +1348,7 @@ static inline int perf_is_paranoid(void)
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
index 6eafb1b0ad4a..f37047cfcb2f 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3266,6 +3266,12 @@ static int perf_event_modify_attr(struct perf_event *event,
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
@@ -12104,6 +12110,38 @@ perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
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
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220601093502.364142-1-elver%40google.com.
