Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5WEUKBAMGQEX6CBDCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 59BAE333A41
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:41:59 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id x11sf12523503ill.17
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:41:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372918; cv=pass;
        d=google.com; s=arc-20160816;
        b=KjLqbhpfO2KBPxz2eax5Dsv2yenMwJcC4yI2jZ6hvTlSbLFCd7az8qjyU7xYvx6+58
         Oqw98rXk+/UPsnEmEjzA4CPvDmzNvHNlpD1yQXllzZ4J/AoVZZFeHYZwsnIWDoURMFtk
         RlJ5QBGKTiOzie7jPFC9lnG2N1Ek+kT6EqR9TL6z5QLEvOq/g9ucKt6QPNt7H2WOhIzv
         tl0rf6HIZsns8G0KcEixh9Gy90QHbnUKegWf8G+COX7p1r20rvFl7/ftHSDAnNoBYX1E
         Ax2mH/dMTpMYZQtJAQqB0R9m43fQxEiGJnIpiUSsX5qj11RYzAl10Am86bpS5Mlkzmey
         tiCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=en+oWAucX1oESxf1IYSvPbD2RXRo/gbPkGn2CBfcUfo=;
        b=dH/cZONqMn5HjNyNMIAKsanGCQWQWbDCV6hJC6ie3n220o8wVlCzQMgCuIqOBprC0D
         wXY7nMkGYlCjOwuZah7c18JlrA1+L6thWioq+QZc3GpJ16cUZcR3w80ZoVlGLFEnzPqB
         r5zs8QyUAbjOqQAmfErBXVOJCDWAonhzmiDNBv2L7w4xP9TzJAxU8wvGntJ+/MCw+Co3
         nFKJhNX3B8jHArvRom2GxWodQTTzPhYN4z4oZlmlA7nAdP1xKS8A8VC6dZZyoeJSxwuT
         gKhksW0rxhmTKLrqIVuGu3wazNRCeexyljNTZhNUMkwpSdwmc383iad2LGI7YcWqyEit
         boeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1jQ16Yb;
       spf=pass (google.com: domain of 3dajiyaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3daJIYAUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=en+oWAucX1oESxf1IYSvPbD2RXRo/gbPkGn2CBfcUfo=;
        b=MDmyLNklr+Kbyj0cSHHfGgTVRFtW5xOEnQDJRbS2mve8WynT4TI0Z7LnWd6HnAtNI/
         5FAzLV/bl5V+fgZ9Nddf8tLxgPwETtXJuwaJJlPVp9unOoZONwljCeBZScDKfr2Y7MXw
         3mfgvc/yjJ3G2WT+MGLDbK3lNYm23o6fcCWWFR/pgmkgbaz6ciO38Jk2boDJ4VMCEiHl
         l3DynPWHPG9lY93Nqn2aExAHs9mWu1+a62MMzAKgmp6ETl59vNj9myjUcaQO7LAHALSK
         UxjenfP1NXF88A8CETLNMJ177y1UW1QWSKwIrSp2yAmclrNEvGt2B4H/toPEfjy2Lbag
         +56w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=en+oWAucX1oESxf1IYSvPbD2RXRo/gbPkGn2CBfcUfo=;
        b=nYEZdzlu2Z4A/qpckrjGR0k2uyUeOUjgUSk+yGN4AtEBtCi2q7kccB9yGDxZrctC/f
         SFy6QIScRrHSmKl9MiJSGSD+fFvscPZOknQq5aPtMOgIem9gionJgJLqQLQCR2i/OxwO
         MVBM1gqHbBdORpYs8a95WJDsR5xFzE2i9PHl7HwUck8HvlInqj+xRJq6Wm2iNt0PTWqM
         be7EP3OUfwYHrUtMniDAX8zvPezeQSQf6tc0Q76tVxE3L9TiS7wFpe9PjfuOp9TYzZUP
         hL9z4a/1F5q/k1h1/9GVlF65Cpwv82kmpnCDV5kYIBJYQPTKO5ICBBAefEPXlUsVlwDW
         Adww==
X-Gm-Message-State: AOAM532w9dher9lqwbG9ZzZIKk38PBW2AOGBDQWZ6Rq+dkAnsE/wZoh8
	QYl7Prk/FscKKJ1NVqDmtqk=
X-Google-Smtp-Source: ABdhPJwkFow6/caO+bISvoTdgD3KNrJ1ugEwyYa207HA9AUxW7pzfwE0W0ZXYVeDC1S7EjS0mLKONQ==
X-Received: by 2002:a05:6638:2711:: with SMTP id m17mr2252506jav.115.1615372918450;
        Wed, 10 Mar 2021 02:41:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:da52:: with SMTP id p18ls398702ilq.11.gmail; Wed, 10 Mar
 2021 02:41:58 -0800 (PST)
X-Received: by 2002:a05:6e02:20e4:: with SMTP id q4mr2157895ilv.197.1615372918048;
        Wed, 10 Mar 2021 02:41:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372918; cv=none;
        d=google.com; s=arc-20160816;
        b=ElcnxQv5GbR59MvJTyTnB9Lv6Vvq5FkVIDHS9FNRYliiYhvOfCnoMMrVqOvi1bIQbE
         z/qQxFyu/oeN8lPh+9V5U5TDbM7m9AUlN1/jOfSO0swSNHTkOq8Zc0Ol1sTkrlBWV0hg
         9Kdug4GQzEonD8bOCyHgRfJV8hHrG8w70u5gRiSNjXEyHIg1zS7mqEd+d9CJMswI2Cgh
         8FNw81EsWdIK3OLMnwfqmg9OwpvJdDtVLTIJfqst4/O8Lr8NYLGKpLNb/7++Z0auBAri
         +sJnR0BqrVv6LDMpifmQI/oV/ItcpTpHfGZmHVZh/mr1FXcDkv8dJ+4gwshMYaKowji8
         k4eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dOVfTFewU2OVBxfkqxI1NPon3rxqJk0MP/D8NHNSqQA=;
        b=slVPoyCvpyI9xO6Enva9QXQ04GnS2BMldHsBDDtMPlpmfxbaIziYbE2GR01F4SpnxE
         nBpX+oX0GZXk4s0BLpQrEEkkIG/1zhCjI/BO2gYV+JsTl4befUmZcR7BU+1ZdKnmuSI2
         DPQn7cZ93r9Xaw3Euah12QPbtGMxDKKZrRjt86Z09YOXoX2RKXGkJTcIfGf0YcVTJdWZ
         WgSVCDt3hIxJu0n4vO+4QERSufrdVlf5Aw+2X/LOaJpk4CeHaR5sSCgFpJaygoOcuQ9+
         8fUbBbC7opij+hdK0VZzvXH7V2+Sn54ZizylhSHKIHQ1SpCRH8dOLTjTrq9O9wHWIHPl
         34Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1jQ16Yb;
       spf=pass (google.com: domain of 3dajiyaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3daJIYAUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id p17si261591ilm.3.2021.03.10.02.41.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:41:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dajiyaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id o70so12371346qke.16
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:41:58 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:ad4:4991:: with SMTP id t17mr2036844qvx.33.1615372917507;
 Wed, 10 Mar 2021 02:41:57 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:34 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-4-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 3/8] perf/core: Add support for event removal on exec
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q1jQ16Yb;       spf=pass
 (google.com: domain of 3dajiyaukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3daJIYAUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

Adds bit perf_event_attr::remove_on_exec, to support removing an event
from a task on exec.

This option supports the case where an event is supposed to be
process-wide only, and should not propagate beyond exec, to limit
monitoring to the original process image only.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add patch to series.
---
 include/uapi/linux/perf_event.h |  3 ++-
 kernel/events/core.c            | 45 +++++++++++++++++++++++++++++++++
 2 files changed, 47 insertions(+), 1 deletion(-)

diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index 813efb65fea8..8c5b9f5ad63f 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -390,7 +390,8 @@ struct perf_event_attr {
 				text_poke      :  1, /* include text poke events */
 				build_id       :  1, /* use build id in mmap2 events */
 				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
-				__reserved_1   : 28;
+				remove_on_exec :  1, /* event is removed from task on exec */
+				__reserved_1   : 27;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index a8382e6c907c..bc9e6e35e414 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -4195,6 +4195,46 @@ static void perf_event_enable_on_exec(int ctxn)
 		put_ctx(clone_ctx);
 }
 
+static void perf_remove_from_owner(struct perf_event *event);
+static void perf_event_exit_event(struct perf_event *child_event,
+				  struct perf_event_context *child_ctx,
+				  struct task_struct *child);
+
+/*
+ * Removes all events from the current task that have been marked
+ * remove-on-exec, and feeds their values back to parent events.
+ */
+static void perf_event_remove_on_exec(void)
+{
+	int ctxn;
+
+	for_each_task_context_nr(ctxn) {
+		struct perf_event_context *ctx;
+		struct perf_event *event, *next;
+
+		ctx = perf_pin_task_context(current, ctxn);
+		if (!ctx)
+			continue;
+		mutex_lock(&ctx->mutex);
+
+		list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
+			if (!event->attr.remove_on_exec)
+				continue;
+
+			if (!is_kernel_event(event))
+				perf_remove_from_owner(event);
+			perf_remove_from_context(event, DETACH_GROUP);
+			/*
+			 * Remove the event and feed back its values to the
+			 * parent event.
+			 */
+			perf_event_exit_event(event, ctx, current);
+		}
+		mutex_unlock(&ctx->mutex);
+		put_ctx(ctx);
+	}
+}
+
 struct perf_read_data {
 	struct perf_event *event;
 	bool group;
@@ -7519,6 +7559,8 @@ void perf_event_exec(void)
 				   true);
 	}
 	rcu_read_unlock();
+
+	perf_event_remove_on_exec();
 }
 
 struct remote_output {
@@ -11600,6 +11642,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	if (!attr->inherit && attr->inherit_thread)
 		return -EINVAL;
 
+	if (attr->remove_on_exec && attr->enable_on_exec)
+		return -EINVAL;
+
 out:
 	return ret;
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-4-elver%40google.com.
