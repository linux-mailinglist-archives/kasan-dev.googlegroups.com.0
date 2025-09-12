Return-Path: <kasan-dev+bncBD53XBUFWQDBBEHER7DAMGQEWFEQJEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 77904B548E5
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:34 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-8063443ef8csf638880185a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671953; cv=pass;
        d=google.com; s=arc-20240605;
        b=e5gTg9KN+EPt0Ayz5bVYgK0pAZEnw3Ou1w5dwZqw/MQUSu/eoYJdJKbV5OMkEHqQ+j
         TeWJHq5VGxrfm06um9uqPoIxhcOWAJId++9Xq+3OxX4SL7b0CiX2hTzH9C7URM2O+ufV
         sfuFSQzFPjENM1zJ+EYjspS/0ndRTqdQfaT39PeLLl4OlBOJScz/jfeS8OjzU/GNlQsV
         dQhaPCOf4onYDmI6kxKnekOx9QnVO1kTkABl12iyo7u4vhJe5peaS4s0g2l7jEDAPY/X
         vsZSGPOAWWBNN6VCuwZDqXFr6syfGL6rglmRUS2YI1RigfmkWve4Wpd46YH9y/n+kwxv
         dRjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=HMy5zoaMzbFeWCD2xjEzcmccyBCgHGpTXl3lMKkmhX8=;
        fh=UR3DJk3B1jPCM4m02YPUqjIGFWFneEZqIpztkvUwObE=;
        b=CsEHu3UEddHe30kjRGrhDJ1+zAIiWjLwlNOLy+XDQBlmaiSmNMEcSQfGj6YMyhGVTh
         Kd2ppYBISINGRKggJ5hfYUEP0GYZMv0jNEyGM68ahVpbcakyYSWc6y2sIvfitcVfUwk5
         DMo/3sRHUmiPS0QhuJ0ZsHmCdCKmNSBy8deaqmbSIKWqLpGexFRGk2Y9Tk+Xkp71j/h+
         lqgrejNJ5jK79uz60UBjG6P//2pbm7H81SwulvVse6LwytCYuDC7J3Hz6Vjtb4rB7X5/
         iF05exAgEhDAVUcLS8h2Vrgw4y8GN63EYL3D5HsqFzfsDQ36sPa65lFGDKorVXlMdk9V
         gjag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YYCbeu66;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671953; x=1758276753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HMy5zoaMzbFeWCD2xjEzcmccyBCgHGpTXl3lMKkmhX8=;
        b=p+dlFrcHk/3V8EwRkn/TEGtDnPEhB95Q5vebYbcZ64SihdXHoOcpWvw0HIzbK60jiQ
         nwl3OmUxprr3a/IFwwMacgMU9rYUTUEsTXk9A93VOS5Dw//zuFSTLZDYcn7CBH71hf0w
         c0r6KvIMCOQ4QBIIduJGuQ2aNpoSuf2yuWx9C4O6yZY5bBE0MohC8DsJqA/cwa6zk8aw
         Qf0CSvARoKVDuYMNHy66IUp1n8h3rbuqEePOOYA94hzUhggu2LVwwkRAG/ydeU8V+OnM
         My1bQBtjPZw0gsRH2RVeDSX+DOTZtcTM+DksClhLi0vIXAAC9YC33lemaZs45YI9AKzw
         Vl1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671953; x=1758276753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=HMy5zoaMzbFeWCD2xjEzcmccyBCgHGpTXl3lMKkmhX8=;
        b=DpfcIl82F9e0qlrC0opub2mTZNtE609zJRxiS9lSySfrM9P1ZlZB8XwsVrEBV+3kgA
         YTn7N+7FlsXkqXAGpBNg6NOkVAhyDeDVcK5XCYwOdXm3rop3zyxu/WTwyTPfb5ufBz0d
         v+pJpfpI8iU1QSs43DAgy3PAQLjiukTe88XcIXyZXjWiu9mBS5Gwi2tv65OrlXgP02Nu
         Ic1AunSVKRiKWTiYpUQD113QsVivW8ZuutdjKXEbmeqVuAvVlm1E1Q2fPZimv3L91YEv
         t9tzcu+DLI9EeYMz/78LbOlA4BsYAwdJK3+QTGYm0fH9kCe8CCclxuZbggM1iAO9l6ly
         lbwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671953; x=1758276753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HMy5zoaMzbFeWCD2xjEzcmccyBCgHGpTXl3lMKkmhX8=;
        b=V6MA85a+AjuTYxkXRpSC4oPXpUl7r/4SUjeB3SC7lkq1kdFo87FPHIoBMb59A62kI3
         shtjrjBsyC6qZFqPK8qa+gYsGdB3WJ9ey0yzynReDhXQF411bxCy+vi5JIcQ7+zjTJ23
         m24ADq7HoLNxqPtCqN9zWvDKESKXhPA5cP5zXABvvjqBlv1bYAvLvJDJ7QFakHyDG+iP
         fiqYFumitEh3nb62psdbNHGOBaJAfEHF9u6O6LhtkXDjAZgZd27ujHYt7R1n9NAum8YH
         jiue/atfSEhkeHByicaKo5MzGSrMqi6B35qU2rm+Hcr0Tjv3TUYvJCbjyy1DS+uUjoNa
         87IA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsOxxZDCQvKNPr55sVoGHRD0DmRuvIR2tLAAIRsic+YTxpobsFH1uNCnvuKl8AFYZ4tiNVxg==@lfdr.de
X-Gm-Message-State: AOJu0Yy4EL1z2z9b+XnDmQRuFnC5A+izT47kxk0Ce8aAqg1V0a0/jeoh
	HDeti5Q8E/gG5Eocon/bh4z7qtURb/CDkklmX6GyLc5oddMk+eBM9UtK
X-Google-Smtp-Source: AGHT+IF0F42SudICc9KgG3h/AZU9TDe82Ox9RetSepTriX4B0wlSmA1Gq9M7Y/PwLxMtdIPI21SFHQ==
X-Received: by 2002:a05:620a:7008:b0:81d:25f0:2fa0 with SMTP id af79cd13be357-82400e0e52emr280684285a.79.1757671953175;
        Fri, 12 Sep 2025 03:12:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMjqI5ke7kS0zKqFj1MYm+Tf0V/CkizM5yScnxdSrcFw==
Received: by 2002:ac8:5949:0:b0:4af:19fb:76cc with SMTP id d75a77b69052e-4b636cad4f4ls33798731cf.1.-pod-prod-04-us;
 Fri, 12 Sep 2025 03:12:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFANLP/yAmtbfvYFgYd6jf9cGe9txuGVrFqvgozl/dKlOF153ISkc/vhgcLXQhBUDYFo22yAyQJTQ=@googlegroups.com
X-Received: by 2002:a05:620a:aa14:b0:806:76ea:bce1 with SMTP id af79cd13be357-824001886f5mr274408985a.68.1757671952164;
        Fri, 12 Sep 2025 03:12:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671952; cv=none;
        d=google.com; s=arc-20240605;
        b=XYl3AueMlMv7BjbLDCFK409Qo1CtT8NIZWSmlShvELVG8Pc0mctHNygPiH48KfFt/v
         XuGvR8+96/hBjaYpizqo+Mxu0e0z/5HYKI8uZU4smN1a80eKBSel26sya8rUaCj8S1IY
         saGYBwKlCSxPPDHkDs/r/h5OuD2n+k9/n9vRJy7s6IJ+AW0UZ53v7ugr6Q7IsCnWIUu6
         Ch3HhpOfH2QpdAVpnOA02erbtcuCXvAzstgnYalSUNLvHI6HlmlRDfoZuEx+DKXEWp7i
         IelL6P1Q4oIJ8V6EK9ffJ0R7H8h7PjguZVQfv6qV3v+MC8HnSPuDQuK6Khx3okg2m4iq
         FiiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=J0CmyIyII1+MjAJi7HJRtv0YVAXaAwAF3MNYXoEmi5A=;
        fh=P0oxy8v8rTxgTbeBWqH0AaaZWfx6NOC1/lpezGOnVJ8=;
        b=OCp1s1xALtnJb/4dODKObokXq6OJa9CSE1ODiDoFVMxn4EW04QDaT0crrF32pwRv7d
         FhVQopdmoiiIu7UDlHFyJbZbexk6H1HRqqG3mkXi94e5aw/7ZztOmtSOLx/t/ZMGVADJ
         6enXAz4go301RwvKiofoRxtjn2mDtPmyI1KlCWHlGqmORJAnUqWqwdmLJKoN/qw+8cst
         zvHYJejIt7gAUh5i2IdH3mSJqkAVIRiI7pWM/+/ClALim46lg9sr4mh0lEE7fxNW5Jai
         Hqtc+M/cntY7I4Nb7BwwATm6TXHZ/our+dOX1+SSZdEQ9zQH6wF1C9X6is987Jau47Gw
         ZuMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YYCbeu66;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820c88d548fsi17876985a.2.2025.09.12.03.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-b52196e8464so1091818a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURq31fGFnnXnq+D36tbHOPUyLTjLtCx9G5gGI6A/M9/TBjvZ0bE7yISHoH8V3Bnboqo7Qf+FYsDX0=@googlegroups.com
X-Gm-Gg: ASbGncvgUOW1TcJVH+DTOabkh/d/XZX87c6woXxqswtHposMbprbtTxTIbaq/93ln2j
	yulcwTIZyUi0hk9emajfbj281ps4ZCoR3kpgcMhlNvuj74lCuAozscjIWH7d5IDP7Hee1V8AtnV
	lmqI2KR7Pnqp0SJ/1iJZC02ZnxoHTDG/Z1TVYcUNCeWxBryj7ZBbYZtAb8dXmkR/luaWBPymFgc
	/1KL+3IdJCRFuAKh5a/DNgYyhpr6og0F1k3o/d4chAaoVolLBf4uQq51SC4HfRn0bHyYVufiTWL
	mlOCj0ygJSpewlDk/QEgXj2um0YVLsQ14mmvfYUCjT1emfrnYfH0AFeM7BRFn9bvzZl7CI4Q0kd
	SeVoz9/j9q4F+WuhtCNJcUzroxSpyn/sFCv+PgYo=
X-Received: by 2002:a17:903:3c2c:b0:24b:2b07:5fa5 with SMTP id d9443c01a7336-25d26663dcamr29087525ad.29.1757671951122;
        Fri, 12 Sep 2025 03:12:31 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c3b4f1127sm44400285ad.147.2025.09.12.03.12.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:30 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v4 07/21] mm/ksw: add HWBP pre-allocation
Date: Fri, 12 Sep 2025 18:11:17 +0800
Message-ID: <20250912101145.465708-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YYCbeu66;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Pre-allocate per-CPU hardware breakpoints at init with a place holder
address, which will be retargeted dynamically in kprobe handler.
This avoids allocation in atomic context.

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-8-wangjinchao600%40gmail.com.
