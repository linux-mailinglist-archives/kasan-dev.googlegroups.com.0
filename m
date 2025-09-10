Return-Path: <kasan-dev+bncBD53XBUFWQDBBU4XQTDAMGQEYRC6VMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FF16B50D26
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:41 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7724903b0edsf5224753b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481940; cv=pass;
        d=google.com; s=arc-20240605;
        b=EqlniWs/pyqsfLbWzPxmM5BXxC2atldWoW5i+sJRaJY9BR1AlzUgA2vzoiP/6jJIoX
         Wrt8dIoPtis+luE/Sq6KRII4H4XuHZVePHA1Ok+/JXxtWpeRcDOtgVQFnLbJY+ge4gWU
         nDfIg8xSUIjng4wZwDsqWfg1vpptgHub/O1cY5nmGBkv0kptxYDPfaFzkv6EHPXEmw1/
         GwkSoCWewJUsT5oklNW9i+AOVqbKEOafFfSQxZ/l8G4FmiWXGFQkNWlBHnPWQlcHZlfV
         dZp3/4Fa/N85qx7Icug+mkVO/g3xfoYm9nrkzWLo2YcejaSleRHaNILgA8x5d18yJYVB
         1NVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=xa3MwyOqj2OPKci4S8qDmi9PGtQxbFMthq8gN99L+8o=;
        fh=kDDq7YYMyhFMvfTuTlNFQgyawMRZFBz9HkQmAX+3Uk8=;
        b=Ku9gLEeNgkb8+ytZVj2AYMjpxvE58OcZQr8c3QL/qeKh2FXOTTJUgkFeFGjQCgKDs/
         zcO6p5aJDs1Gpfu4fA8eZl+nZGz+GcYiVMKLSOExxM3/uwE2CpU9VRcyXmmoOYaW2BEN
         +zbCRNH2FBek+XjlLs6d2gBftoJwEKy5K48xrGuPjr80bQ8pFMalX8BhAfv2es5+QrZs
         dV5aysPg+Kr+u/lAw3hzh0iFBaqydAvhnc/Rg0u+KPG/ha1h0+PubVreJpHNzpNRvGKA
         zou8VGfr5cw41+IId6wmYfiVL5KUWH6cPsjW9ccVGtVp0htaaaflGhSTOcCyl8qM9Rel
         3OYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ahS73XUr;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481940; x=1758086740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xa3MwyOqj2OPKci4S8qDmi9PGtQxbFMthq8gN99L+8o=;
        b=C44y3y3uWWzr7OZZeGlQ2e41MrRi74hrxiSb8hi0No5oCAJxK3BNsy3kv8EbA+cf89
         GpZqsNOkhbpuDmQ/LKvlEyYnFUu1S95spt8Ai9hjDPAWkUkCqJ9UxlAXYXQmcYA2uH7v
         A4D5ggwEAEK6+SP2CdJe14nDm3PQvEKmCejjt+zOnHepJidY5Mm7juGc34Bh8RP6FjdG
         kxgsKWuq8bzt3qgiQjjtFq2DiWlbLArjB1+o31Ge5967xMukBBRzmP07b4RYgrO94Len
         FG4qEnUmJVUiBroN9KVKqqOL3L6i0ESWadD2h5E4NwsqAx+J1cnqsP3q+u6AIcyYzyye
         DWpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481940; x=1758086740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=xa3MwyOqj2OPKci4S8qDmi9PGtQxbFMthq8gN99L+8o=;
        b=BNujjjhFExBGDkyqN88LkPAVpqpxdEOI+Guz0wll/FTB6WPi8PUNzRH3DS+LbIFdIH
         RzU2oDLDfC45f5wYOoKtfrz1UVzg5/pWzn2sxnyPOIFwj8iUdWKm71QA6HQrxk9RG+pK
         aWjJjFkFs8Dz6SuQoHW1l4k22s0mHicM8cl+ej7orixOGgLW/ooqxK3JvfuOZ/PaaZCu
         gThT9Ly62E5lpc1/JMo/GINdN+i+JqvmsvRLHKZhDH0sXajmyjuiWoRmpinh6FZB9DAU
         GGeakce8zj9rfgQk3PeOZpUu/Mg1o+305d4DgV3rzASeLXQRrkUinTIHbyAR1q1bBToa
         0PJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481940; x=1758086740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xa3MwyOqj2OPKci4S8qDmi9PGtQxbFMthq8gN99L+8o=;
        b=oTqxo65MXqnrvE48WEpNtmu/UUA6sk4uehWikWPfe3337flZ61LDw3djahmluNHLdc
         CdSMk4cqlixwG0lBUtu52Aw+t0XEkgisjyRE8gajsa4KmvNtubiAu7mXCB+ysUHiNVke
         a0hjdzS8Yi0nsM5/SBD4cdtZ8jud2iq8SZNn5fNG4X0omMQP741Ha97/EemxrgnOZCEa
         L/DBb+dmKgK8QRT+X375ozrUmfBnPLlH4nQj39oWMFSgHgPkSac1KzFNvThAaXQM9Dh0
         8a5/xxrS8gdDNPLDzLhK9oThMo8hHocEtt158GgPepgxV2JQ8107e6tTPJ6d/sHsooa3
         XrKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJLFFza5b7N9Xh9q0eY0BBxww5nHNyeicdBJnQ4rmUdmUF6Sspi5nK52pdHgI2v06HraoHKQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywn7BJNfGGK8NqWVBydYsqCjdmZT/SEehJ8hAm0yCDTMq9thrAg
	5BkgirjULuDk8znc7eo+id813oPI54WHjZ08al97936B3xa71UTsIGYz
X-Google-Smtp-Source: AGHT+IHuVUHy154XhfxhC/RhNUTW5D2Qi/f0yeMB7XGN9YQfyBhn8mf3AVPAek9K/ahTVwqxKBFFCw==
X-Received: by 2002:a05:6a00:2d9d:b0:772:6c9c:c49a with SMTP id d2e1a72fcca58-7742de24e02mr18183720b3a.28.1757481939881;
        Tue, 09 Sep 2025 22:25:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfgYShgAsYHAeu9J+vdtXPEi0Iaql7yCk+4OyBO+5zmsg==
Received: by 2002:a05:6a00:138f:b0:772:4cac:c175 with SMTP id
 d2e1a72fcca58-7741ef0b122ls4807857b3a.0.-pod-prod-02-us; Tue, 09 Sep 2025
 22:25:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeRwxWkR56cHTv+Z0uU1LmEqywKbtejrdPUtwAsaQeO5pp+K8niseAjjzelFYa2CfzKmySL+aYuso=@googlegroups.com
X-Received: by 2002:a05:6a00:2191:b0:772:282d:5a68 with SMTP id d2e1a72fcca58-7742de597c7mr16180331b3a.29.1757481938470;
        Tue, 09 Sep 2025 22:25:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481938; cv=none;
        d=google.com; s=arc-20240605;
        b=g9OEBvyRG4JtEZUQWUqZwiG9oiAaAYT/0FXT4U1gQHVXMf1MDtlzhW3uWan2GNdkpr
         GDthJy1XDuATQlpevFBv42G+4B0gihT137iH9Kwj6Xzz/k0P7ZYizvhEQw/kay3VqAT8
         szf594g8/pVza+mIhf8DEqGowc8o/GFr3rUewp55d8B+MuXDNS9CjclKn0myBH5MCKFZ
         x77qAnuAjDRdwnWJje/nCkNMGgtB+KurisYCAROaADq2irHvEyoORE8ojS65p0KbRlpw
         xmN2kWfzQ/GfVimhUUmSB/c2NJorOUqzIgAE6TxMapz8VDEVHwTQCnHPyyytfBz36d+M
         keXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RI10mDfREFn5Rx/uTs3tJDtAseKlBmy4SikYDBaNSc0=;
        fh=xcp9N0cNlmfE+Po3nPxEvnUw30rQItL4Nlt7lB8gNsk=;
        b=EvGd9XTY0W8iPovu0mlLWYW9QhSbVzH3JUq5QeiKpkpkul44JR4o03I5uclVMv6Kul
         +/t856cqgGuBI6t3BLZGoqoyx/duxZbI/Z13CUs6dWK1byS7RBq5jDG1M17XaoU1wJ2F
         lQTMZe+0hgrVibf32yUM8IqxGeyatz1UYUSmcl8nraRJJmc/iDgp1cHeXBhzqdJM6QzH
         XCEy4GR9eJOgjz5tjKnCGzat60v67mBp/0WJSGryhrBLkD2Y/FB3IsG6A/0DBDFeafiS
         YgProIMY1jUQNeH+qd0wXoaqkC/lG8EfFKXrqzqfpiVgdKyuCpFMAp8jYODne/hAv/sE
         z3+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ahS73XUr;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7726452229bsi477115b3a.4.2025.09.09.22.25.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:25:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-24eb713b2dfso43442785ad.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:25:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVeH59SG3pIPZqMNIxgqiZDtM2wD6ttCOHMNaRNb1Lx1OFllsEiGwZ+ZeFIBECGtJlkKdNaCBZxwYQ=@googlegroups.com
X-Gm-Gg: ASbGncvaWIAswQhmQVjpGySGyRrdIJvuiMc1gtLncv+bT1EBgDRILDMo5VZMMPB844v
	9ME7Le7fMZkk/koXvTmqWuXChcFfEAvlupUnQ/Xe5zOohRI20bZ5MoFIFZkeWd6uwz4B99JlrYS
	eW4+7CxLLv/Sv7OiEUNBQP2A31efX9ei+zbDRCSFEvsNOxFbQaox1t6Txu0nLUAfSnD9xwHH7ND
	lT0ooW92XlIU0Q4r5s5TnEjqDplABK9EYeNsPwpE+AQ1u6uJ6gxToX1V2IazpgZXTWkukSS+ZUY
	MWp6OcEPJzng1zheVs8KZYe4dFN4XL1KeWayNVCAsCt3+AB6l4NESqg40uSHJDxmXshLk0gxu37
	75itVDANCglKdn+4aqpRvRiYsCNkZbi/6vg==
X-Received: by 2002:a17:903:288:b0:246:cb10:6e2f with SMTP id d9443c01a7336-2516ec6f1c3mr207113305ad.26.1757481937933;
        Tue, 09 Sep 2025 22:25:37 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.25.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:25:37 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 06/19] mm/ksw: add HWBP pre-allocation
Date: Wed, 10 Sep 2025 13:23:15 +0800
Message-ID: <20250910052335.1151048-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ahS73XUr;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Pre-allocate per-CPU hardware breakpoints at init with a dummy address,
which will be retargeted dynamically in kprobe handler.
This avoids allocation in atomic contexts.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  4 +++
 mm/kstackwatch/watch.c       | 55 ++++++++++++++++++++++++++++++++++++
 2 files changed, 59 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 277b192f80fa..3ea191370970 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -38,4 +38,8 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* watch management */
+int ksw_watch_init(void);
+void ksw_watch_exit(void);
+
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index cec594032515..d3399ac840b2 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -1 +1,56 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/hw_breakpoint.h>
+#include <linux/perf_event.h>
+#include <linux/printk.h>
+
+#include "kstackwatch.h"
+
+static struct perf_event *__percpu *watch_events;
+
+static unsigned long watch_holder;
+
+static struct perf_event_attr watch_attr;
+
+bool panic_on_catch;
+module_param(panic_on_catch, bool, 0644);
+MODULE_PARM_DESC(panic_on_catch, "panic immediately on corruption catch");
+static void ksw_watch_handler(struct perf_event *bp,
+			      struct perf_sample_data *data,
+			      struct pt_regs *regs)
+{
+	pr_err("========== KStackWatch: Caught stack corruption =======\n");
+	pr_err("config %s\n", ksw_get_config()->config_str);
+	dump_stack();
+	pr_err("=================== KStackWatch End ===================\n");
+
+	if (panic_on_catch)
+		panic("Stack corruption detected");
+}
+
+int ksw_watch_init(void)
+{
+	int ret;
+
+	hw_breakpoint_init(&watch_attr);
+	watch_attr.bp_addr = (unsigned long)&watch_holder;
+	watch_attr.bp_len = sizeof(watch_holder);
+	watch_attr.bp_type = HW_BREAKPOINT_W;
+	watch_events = register_wide_hw_breakpoint(&watch_attr,
+						   ksw_watch_handler,
+						   NULL);
+	if (IS_ERR(watch_events)) {
+		ret = PTR_ERR(watch_events);
+		pr_err("failed to register wide hw breakpoint: %d\n", ret);
+		return ret;
+	}
+
+	return 0;
+}
+
+void ksw_watch_exit(void)
+{
+	unregister_wide_hw_breakpoint(watch_events);
+	watch_events = NULL;
+}
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-7-wangjinchao600%40gmail.com.
