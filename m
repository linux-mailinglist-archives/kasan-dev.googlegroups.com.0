Return-Path: <kasan-dev+bncBDAOBFVI5MIBB5HPXKGAMGQEQMZ5BAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 54CB944ECDB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 19:52:37 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id y40-20020a0565123f2800b003fded085638sf4321868lfa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 10:52:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636743156; cv=pass;
        d=google.com; s=arc-20160816;
        b=clyb04M+J2mHg2BUOZF9PHCL2ejh72am50kXaSweiCpUYzK5RyaATuSdVPpiZzxTD7
         WubOxvrBhmIXHU5tgQlry59KSJSXInk+bK2LtuE6BmVOtSOES5f6CGp2SPgkKFqT3r89
         0Mr6CZSlM4EWvNsHvsDvMM2lf4jS4HCKtzjDQNTz6gtJHg1WoGbAgumNy+Lff7fXGksb
         7gxS60JUh1UdBDMRntBUb6VPpXcehf2l6HmULnKuWlqoZWz78qjuniWEnJUqImJcLxuw
         K5zgCTHV1kRJZOFmer9MOEMWiHBjFQTJR2V+ARMyoadlcAOMB5IUzSKV6I2xv+q5/84O
         KiMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z4s/oJKCf9wN94wmpEzFh8VYIxu6t6crLnUANygIps0=;
        b=IY8duwlnH6odfyk/h323h9iK+XwGxsF5hb/pC5/vZWH+AYGN2uO39Nc3WT1PwCv7QK
         4wu+Mk9vvhgUCcVWnSZQOM6/H550HfxJ0CUzH7SB9kGWAt8vadimB0Y+Z3i7jJAsgboq
         0evJaTeTwowC5TYQt/l417b7UadyYqkgdbGXpBUcw/JDR174GgQ2EqpiFazoZteS+ERG
         Mae2uNKK584FsGnHi0DhuJlfMbT3qi1960pSLFNebrDNjjfWNmV4PWs2wjLE1KehRNdA
         3CIhYlzQegzXszg1IpdrLUvv4GkF+VBuq9AYZ5U0X/5mrnsz1QnzLrfSd9sq5qV3pflc
         tFmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z4s/oJKCf9wN94wmpEzFh8VYIxu6t6crLnUANygIps0=;
        b=HbpZWWMR9Tevq8W6OoEaE70NzVTkdB6oGRBB3E0sQRAliZXWPBPbUIOamgR928eyFq
         LhRFXjXHkz8ZXk7hdCXYTm9tnWXSAK/OPcXhZcZ7TuKNEn3ouql3UBRzSwJ1yw1lXbEp
         ZiB9Is0ZEuRAwfGaVorAaSMW1cYlMF9y599Q4B4dI9Dg5765LtarkdNDlJmkrxVUqtKt
         XtMzF5dbVGNgVIDPCKep7c63cCHhy5jzuGiK6T5fyRWTjOtO0hcLM+/bKYxj++fTY880
         iV+9WnO5+WNAcvyD+1FXZ+p+cQtdVC+IyFsJRHdFJ+HANb4e+vsmqWG8Tjmp0QC8VFXY
         B3Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z4s/oJKCf9wN94wmpEzFh8VYIxu6t6crLnUANygIps0=;
        b=XyiJqB+i9uDVBR4pgmjcvjQeQUWakhXnH87Weh3oTE4UHUovXyLIGvHGqL8GMY4Rfv
         w+l5OX89PQjHUsmsAyf/n3EqwXsX0MOQwJdcmiC5LXCaFMVJNAnxLP9dQTdS7hFx8yth
         aU+0kVi7Zyp2/DKDd/mDd4peUqhFxd0F4ERaeI/I3ZrkXZ41g53TlDJKZV6RXz34dNKG
         c9ibq8A/P8Bw4mqryuU1fraCjtxdJsGRG38V/4wMEGPlWmfOisxcVVQ4xd9MqeEAYBMu
         xX3QMuViXI5HFRDDUnXDC/aehsTbOruOECfpDiyY8+UQWhJUgSPm5ORQ3oCKfIvscgh2
         2zGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sUUaWeQNTww8P/qfFIEYHHTDRn2rrqgjZJ42Nwn/2CjGla0A1
	scHj+L8y9/hWaOaEfBV2XM8=
X-Google-Smtp-Source: ABdhPJxTH0Y8nU7YwhJpw/vmovfARCCI2JFAAYHd/BVeLGV9LC+DP+FtRV0WOxZAxPpuUJKU/csPuA==
X-Received: by 2002:a05:6512:3d94:: with SMTP id k20mr16606046lfv.116.1636743156813;
        Fri, 12 Nov 2021 10:52:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1314:: with SMTP id x20ls2951841lfu.1.gmail; Fri,
 12 Nov 2021 10:52:35 -0800 (PST)
X-Received: by 2002:a05:6512:a81:: with SMTP id m1mr15556279lfu.306.1636743155835;
        Fri, 12 Nov 2021 10:52:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636743155; cv=none;
        d=google.com; s=arc-20160816;
        b=YpVwxRCdJ+/9LKt7GRLCFAR2JU+H3Xg8KfIggZT2TETblnPyk/CW0gVjCtpSCHeYIW
         erSTVpsgqqxx3WSd7BLv0/heuxgMBwHWoRwbJ6vA3y9Cgqqsa5CwHyTPs57+CWWvie08
         b9Dv/zj2OGxJZZoXFOcY9zW9+TacMXA9f5DaqK3emdO6GiRl9BDVgHinZYEsF4EfaCFi
         U1JeNWd3F0CJPLX0//jRLN9UB0hKEOfBVsFY03OGBWvKQjuwwJ6aBoZALy2VVcM+54xu
         +AlMNJpbpmWFrgBHOUOiVg9/BNNOXYcwiFsa1X2ZeM5WW7QPVxZThyYNlUtjUlKKfZjk
         tzdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=nJTrapFHBRSdIt87iunKBdpfKrwqKWrlavibBPV8s9M=;
        b=d3ASI7pkx0XXbxO+sKhn06Bx6h0NdwPuaFR6m1E7PD9yLKl17tpnYN1nmWl28aIMgj
         nBoWcCyX6jbzCzddqteikNj9jtDSUGDJVm80d0YF+TNlGOc3JOkUogF2EU4U3sDBsGRm
         EGvPblutPErCBbZRxcrorveLyLQZcge92PWCXeV3XiUjjRAm6EdwnxEHnsFROn1HpmQp
         g3mKGG0VKTv2P7KUnkKdylGms9xRs/u4rI0G7Cf11SvxS+oJ6j5iJkLbU/LzERBDqGyQ
         OQOvcQMcwlrXIuwDm+ZW4U//dNn+r5hmuKnaFwMmRuGrVu85eTushv1Kzz0K1qgsTlWs
         NXqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e18si533477lji.3.2021.11.12.10.52.35
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Nov 2021 10:52:35 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 64369139F;
	Fri, 12 Nov 2021 10:52:34 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 9E8273F70D;
	Fri, 12 Nov 2021 10:52:32 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v3 2/4] preempt/dynamic: Introduce preemption model accessors
Date: Fri, 12 Nov 2021 18:52:01 +0000
Message-Id: <20211112185203.280040-3-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211112185203.280040-1-valentin.schneider@arm.com>
References: <20211112185203.280040-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

CONFIG_PREEMPT{_NONE, _VOLUNTARY} designate either:
o The build-time preemption model when !PREEMPT_DYNAMIC
o The default boot-time preemption model when PREEMPT_DYNAMIC

IOW, using those on PREEMPT_DYNAMIC kernels is meaningless - the actual
model could have been set to something else by the "preempt=foo" cmdline
parameter. Same problem applies to CONFIG_PREEMPTION.

Introduce a set of helpers to determine the actual preemption model used by
the live kernel.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
---
 include/linux/sched.h | 41 +++++++++++++++++++++++++++++++++++++++++
 kernel/sched/core.c   | 12 ++++++++++++
 2 files changed, 53 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 5f8db54226af..e8e884ee6e8b 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -2073,6 +2073,47 @@ static inline void cond_resched_rcu(void)
 #endif
 }
 
+#ifdef CONFIG_PREEMPT_DYNAMIC
+
+extern bool preempt_model_none(void);
+extern bool preempt_model_voluntary(void);
+extern bool preempt_model_full(void);
+
+#else
+
+static inline bool preempt_model_none(void)
+{
+	return IS_ENABLED(CONFIG_PREEMPT_NONE);
+}
+static inline bool preempt_model_voluntary(void)
+{
+	return IS_ENABLED(CONFIG_PREEMPT_VOLUNTARY);
+}
+static inline bool preempt_model_full(void)
+{
+	return IS_ENABLED(CONFIG_PREEMPT);
+}
+
+#endif
+
+static inline bool preempt_model_rt(void)
+{
+	return IS_ENABLED(CONFIG_PREEMPT_RT);
+}
+
+/*
+ * Does the preemption model allow non-cooperative preemption?
+ *
+ * For !CONFIG_PREEMPT_DYNAMIC kernels this is an exact match with
+ * CONFIG_PREEMPTION; for CONFIG_PREEMPT_DYNAMIC this doesn't work as the
+ * kernel is *built* with CONFIG_PREEMPTION=y but may run with e.g. the
+ * PREEMPT_NONE model.
+ */
+static inline bool preempt_model_preemptible(void)
+{
+	return preempt_model_full() || preempt_model_rt();
+}
+
 /*
  * Does a critical section need to be broken due to another
  * task waiting?: (technically does not depend on CONFIG_PREEMPTION,
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 97047aa7b6c2..e2502b8643b4 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -6638,6 +6638,18 @@ static void __init preempt_dynamic_init(void)
 	}
 }
 
+#define PREEMPT_MODEL_ACCESSOR(mode) \
+	bool preempt_model_##mode(void)						 \
+	{									 \
+		WARN_ON_ONCE(preempt_dynamic_mode == preempt_dynamic_undefined); \
+		return preempt_dynamic_mode == preempt_dynamic_##mode;		 \
+	}									 \
+	EXPORT_SYMBOL_GPL(preempt_model_##mode)
+
+PREEMPT_MODEL_ACCESSOR(none);
+PREEMPT_MODEL_ACCESSOR(voluntary);
+PREEMPT_MODEL_ACCESSOR(full);
+
 #else /* !CONFIG_PREEMPT_DYNAMIC */
 
 static inline void preempt_dynamic_init(void) { }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211112185203.280040-3-valentin.schneider%40arm.com.
