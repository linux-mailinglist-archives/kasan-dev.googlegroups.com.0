Return-Path: <kasan-dev+bncBD53XBUFWQDBB4M2QTDAMGQEOREQ3YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F1FCB50D4D
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:32:35 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-319c9bb72e1sf9583698fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:32:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482354; cv=pass;
        d=google.com; s=arc-20240605;
        b=CwCWnAX+37OsC94Ixt6eKa7FGrMmGgkaW7S5LiA+zg8KRCXySXh+GvmTar3/JDIWev
         K0GnNUpoCUZdgR0Z47ikXNA+uaYSLN7Iy3Wug3TmoTC0C5k30sPtMO4PdulgD2bDc8QI
         SswIr7AtBfXEqi1ej5OE8PpCgfHS/aETScMzw/IwX4mZU8XHwiMrXqolvxK0/+Vcwia1
         K3ngrS6Sc6BPqUjRcP7vz4Ds/Tnq3y9IFi0DqTZRuVvzspvzGB0YxUI+LWdmakWhM8Zm
         axnWfQDZjzRSJViVRgPEpme/Zt03vvGoetPtuCMKryTiautSkIns9R5Y41qv+VvEFTen
         60hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RNqLS6H5jJz52FSGxSa/1RfHjMjGlLRHvBeY8e4sHkg=;
        fh=0RLMgM9qB51fmp5Qa4JhOzIQ1k1dMInpbE97NMloG7o=;
        b=NCeNL/l5IfUXEixfHTTtuWeq8dwzgjGrbTAJ0G9Hr/pG2WManQSSTZ7xybqG+Q9Afg
         FPgu8s1hH44Afwbo4lyUbLW6dh08PQOuxb7iF9G0+7mH8Ddeptc+prvcxgQxXdR1NVUS
         NWN5I8JxP9dFC4bd2H33yyF6H8h+LTfeoGKFY5jdQgEwvt4X7qY/3auek5AMxR3aYmWB
         Awp7ZMnug1Ow9bP1piUXDSFUOHLicmn/qe9dcTfBNTCbU1q1fOKKNL36DqilLih7u8Rn
         9RBnSitC+YMI9gwGOS1SxpFU/MTtjvoYiWjh1QV+Wf69QaibhxAhHWrkQEFq0Nvgn6Kg
         Uszg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nM63+aDo;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482354; x=1758087154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RNqLS6H5jJz52FSGxSa/1RfHjMjGlLRHvBeY8e4sHkg=;
        b=lpb9m5S905S6o1I/5QzwCVXObMJESDqYNannlC5d/rGYm/TpwDmXipyN564BDgA8eg
         8nCCG0gsoJAagdWuJkOuhCz51OsqKZ7YHQlAbvG3FZ4sjniHPgEYJZP6i5fn5ZmB6814
         GvbJ0jjCXbJSj4QBtCC+qgpkWLLkyrtU8UJQ5L72+/fXMMXGaCZkFgrLsLq6jSae+BJ0
         on5nclLQAQji1VfTYvRf8ztFqYLWsYS5jtN87vKgKMM6kJ2431iDKfhQlVbWvHC5xwWt
         xUP54VtXe1M74jRml0mctVjewOh0Xr0wLc7IeL+JQVkoRzhIMEMuKF0CuTTXCpVWy7hg
         5eZw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482354; x=1758087154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RNqLS6H5jJz52FSGxSa/1RfHjMjGlLRHvBeY8e4sHkg=;
        b=DyDPIe3wubt/VpBhA6xASJm67/VEU9wJnNFw8JZ/OqS5cn7vfB5JLg02gKw9M1T+mT
         Sac2/kh5crHgi0QpA99Y5aeASwshgPgEC3j1xisS+5Hcg2GFTTtaocqBWu1w6VDUsu7A
         /9wZIYqYeFVgkSHlKsDUPDSmL0vLISgInOiUQAN8+Vq0hpwqhG/EeWHd/FpB8JlhUR2Z
         ptr24pHjJyBaRpx+ppOW4D0wumFD5lJ5EufwuPiAlmPCl8pZl+q+GMD/S4EZFqHio1on
         n/atZJ76jxlvgyVoyjRIeh0SIvxBv/cLTnMezU8OHQx6ikyL9kDpOePKGGwrpw9CE8BY
         yuAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482354; x=1758087154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RNqLS6H5jJz52FSGxSa/1RfHjMjGlLRHvBeY8e4sHkg=;
        b=Q1rFaSPeqQgpiShuidQjBKVGdzEzCLQeTLVJ3917txXIjySFAdmEFbfsySc4wzWu1K
         TdHO64r7Xc2/2zSwfSU9gMoV3CaNBevrpxhqII/Qg2iu0V8CE8YrTDSR6ia9f5O5ip8w
         RfuqWeuAZ3zIIVzFPuhNq8nGTl0tujZzjktpaLa9fQMvH7yO3IdCwwWoylLRALQZOZvo
         xS7Adc59exMi813x2jWY/w1/Oc3k96HpeIu8+cGDMhXMPhd993qNCts6CvIKa9EmhdIv
         1hFGWKQ2gS/BJSFPR499SeTx4aTX6XPjdsf0T6wyLIvX1U/YSUWGlorYWcKLhNPvQwyp
         CxSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUudh1zRkZKgLUu/Lx/M87zHNuouPefsRRvMOzhoMxGZiq2jF5Ck91Vqsuzzbem4/Tso5VBhA==@lfdr.de
X-Gm-Message-State: AOJu0YxGzfCrb3HDnKJc3hE3lJxePt1fhY8B9SYoCGOo1RzHZhf+w4tW
	bgdEC+Fk3DPLrpXmcmERPWQ/vOEKfDTBzHjoQAj1dzFa0wdiLoKvTPbn
X-Google-Smtp-Source: AGHT+IEgiXaBpPhA8pNi9kZ4N5tj3CwMm7NH8zeOpNM6RXWqMJpV349wIPeZSpJ3cY/HtJbDVpRkZg==
X-Received: by 2002:a05:6870:701f:b0:31d:8964:b4aa with SMTP id 586e51a60fabf-322626475ddmr6912902fac.6.1757482354081;
        Tue, 09 Sep 2025 22:32:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6JQqXt47gD3aQsnoIcA2Pv8skcbzfhrd51lel30Ms00Q==
Received: by 2002:a05:6871:181:10b0:31d:642d:3aab with SMTP id
 586e51a60fabf-32126e748f7ls2293590fac.0.-pod-prod-08-us; Tue, 09 Sep 2025
 22:32:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrSNua7AhJBtzFRsxzJIOixQLnohJ9w8W8iRrynynqd017dYXLxNW+zQfW+Hp9AcNKo1PyLSqtdiU=@googlegroups.com
X-Received: by 2002:a05:6808:1a17:b0:438:27af:3ff8 with SMTP id 5614622812f47-43b29a07017mr6527801b6e.7.1757482351894;
        Tue, 09 Sep 2025 22:32:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482351; cv=none;
        d=google.com; s=arc-20240605;
        b=Osvg7R5nPkvj0Xam1ul/Ubv1rcMD7BlSh0ywjCZFXRGXmtroN+GutAhM3UcMkgYgEA
         Jvs6HTKbaU8cNikRgHavcBuGCyfXf+ZWNNX3xk7uKbdwpy278mynLvzridW2+0TDc0p+
         T5lJvLkY//c/bg+wWq0qa1R+HNtRP/GvSHgASNIyT7YQfd+bjFZaHBO5a/pMc0zEpqRT
         Sv6GpyOiAmDUhgklUCOjY1BrllziJUmKm+riydq5ZvcHkqwW/wrzfQqGW6mNCM1achaB
         deJqclc/ZzEqFNPVlNA1LlVpF1NOuoUXNy9pjsTy1EQR0KHq16/HuaJq2i8gOz59ToYS
         3RSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3evZkOOAwLovlQ4xAZyrzRxNzWtrzok12LdiaOixdrk=;
        fh=LCSv1QAPJ6C/UCCJptiVpjeOPHl25hr1hxAwmthlTAI=;
        b=Qyet55+wEFtx3TGcAirjIc8ptsZiDdAy3/KrzUP0uQk4jqBDaL6/YQ5iDidOaiVTBL
         tEAsAY4ZikzBjNBVQRqw2d6oTJ8+WtoH2oTF7yLhBn3XzD1ELtZB3tU3oABS18b0itkN
         cr5nGR27UnfFjLyABRQGvgAmZJRk6GzfmFAK3USzqwe+N2oJSQMmeE7II/8MywQjZ3Zv
         Qe3/V7Bb155NIA/0Byx9LgmOECjvSIgbQYcgNgFu9LfZT0kPZ4PquRkaSR8ep2wfmFxc
         HUZjt4o4OfwvUh60NyjroXlyZQ0eIHvGdWOFylXkwEQCy2VZNSar6lasVTF1buqkgtpj
         zp2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nM63+aDo;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745a33b347asi692883a34.3.2025.09.09.22.32.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:32:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-772301f8a4cso8965868b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:32:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVDeNCU7o2BnGb1ZCovg6yl3v8nvqfTsYkQ0izdreByVHBxqXr4du/6XorQtjxBeQlvHQu9/6kfBC8=@googlegroups.com
X-Gm-Gg: ASbGncu+bTuVsVT5wPUVlqeoZytp+f2ydbYonhQOW4lqlOQagrHWd9/dNL6FdSDA7bt
	2ryDOekTywJpmNmU6YgV2k5+5Md7Cf3j8kgpwkLI7wYEk8JbyzN5dKi5Yjw5fJxRcMnBlRekV7q
	WHZQahAJFnV5twUoXZStW/Xc+XjnJpfpJje2il5/LV/kX++UrdzeqrVWYaQlWARg/SdBnKx8em5
	Pm6WNIGfgxwAUmxXP1BZ0HYVfs/aRW2DE/iEAvr4ESiVTyi7kMWgD35/4QGUWATKzrTfQxcHp6S
	+tjKe9G244e8OB8ZJrTfFGR6cxVKB4IWGFR8tdtna/v1pibihnx0nP+m70feEKqoaAxu+MGzJB9
	vwDxEBkttXFUl7xPBwqLSQTPdETJtEK/YRu+6JdVzuo7Sw3Pjnw==
X-Received: by 2002:a05:6a00:84e:b0:771:f69a:c426 with SMTP id d2e1a72fcca58-7742ddadc99mr21024675b3a.14.1757482351351;
        Tue, 09 Sep 2025 22:32:31 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.32.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:32:30 -0700 (PDT)
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
Subject: [PATCH v3 11/19] mm/ksw: add recursive depth tracking
Date: Wed, 10 Sep 2025 13:31:09 +0800
Message-ID: <20250910053147.1152253-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nM63+aDo;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Track per-task recursion depth using a simple hashtable keyed by PID.
Entry/exit handlers update the depth, triggering only at the configured
recursion level.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 100 ++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 98 insertions(+), 2 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 3ea0f9de698e..669876057f0b 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -3,6 +3,8 @@
 
 #include <linux/atomic.h>
 #include <linux/fprobe.h>
+#include <linux/hash.h>
+#include <linux/hashtable.h>
 #include <linux/kprobes.h>
 #include <linux/printk.h>
 #include <linux/spinlock.h>
@@ -15,6 +17,83 @@ static struct fprobe exit_probe;
 static atomic_t ksw_stack_pid = ATOMIC_INIT(INVALID_PID);
 #define MAX_CANARY_SEARCH_STEPS 128
 
+struct depth_entry {
+	pid_t pid;
+	int depth; /* starts from 0 */
+	struct hlist_node node;
+};
+
+#define DEPTH_HASH_BITS 8
+#define DEPTH_HASH_SIZE BIT(DEPTH_HASH_BITS)
+static DEFINE_HASHTABLE(depth_hash, DEPTH_HASH_BITS);
+static DEFINE_SPINLOCK(depth_hash_lock);
+
+static int get_recursive_depth(void)
+{
+	struct depth_entry *entry;
+	pid_t pid = current->pid;
+	int depth = 0;
+
+	spin_lock(&depth_hash_lock);
+	hash_for_each_possible(depth_hash, entry, node, pid) {
+		if (entry->pid == pid) {
+			depth = entry->depth;
+			break;
+		}
+	}
+	spin_unlock(&depth_hash_lock);
+	return depth;
+}
+
+static void set_recursive_depth(int depth)
+{
+	struct depth_entry *entry;
+	pid_t pid = current->pid;
+	bool found = false;
+
+	spin_lock(&depth_hash_lock);
+	hash_for_each_possible(depth_hash, entry, node, pid) {
+		if (entry->pid == pid) {
+			entry->depth = depth;
+			found = true;
+			break;
+		}
+	}
+
+	if (found) {
+		// last exit handler
+		if (depth == 0) {
+			hash_del(&entry->node);
+			kfree(entry);
+		}
+		goto unlock;
+	}
+
+	WARN_ONCE(depth != 1, "new entry depth %d should be 1", depth);
+	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
+	if (entry) {
+		entry->pid = pid;
+		entry->depth = depth;
+		hash_add(depth_hash, &entry->node, pid);
+	}
+unlock:
+	spin_unlock(&depth_hash_lock);
+}
+
+static void reset_recursive_depth(void)
+{
+	struct depth_entry *entry;
+	struct hlist_node *tmp;
+	int bkt;
+
+	spin_lock(&depth_hash_lock);
+	hash_for_each_safe(depth_hash, bkt, tmp, entry, node) {
+		hash_del(&entry->node);
+		kfree(entry);
+	}
+	spin_unlock(&depth_hash_lock);
+}
+
 static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
 {
 	unsigned long *stack_ptr, *stack_end, *stack_base;
@@ -109,8 +188,15 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 {
 	u64 watch_addr;
 	u64 watch_len;
+	int cur_depth;
 	int ret;
 
+	cur_depth = get_recursive_depth();
+	set_recursive_depth(cur_depth + 1);
+
+	if (cur_depth != ksw_get_config()->depth)
+		return;
+
 	if (atomic_cmpxchg(&ksw_stack_pid, INVALID_PID, current->pid) !=
 	    INVALID_PID)
 		return;
@@ -126,8 +212,8 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 	ret = ksw_watch_on(watch_addr, watch_len);
 	if (ret) {
 		atomic_set(&ksw_stack_pid, INVALID_PID);
-		pr_err("failed to watch on addr:0x%llx len:%llu %d\n",
-		       watch_addr, watch_len, ret);
+		pr_err("failed to watch on depth:%d addr:0x%llx len:%llu %d\n",
+		       cur_depth, watch_addr, watch_len, ret);
 		return;
 	}
 }
@@ -136,6 +222,14 @@ static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
 				   unsigned long ret_ip,
 				   struct ftrace_regs *regs, void *data)
 {
+	int cur_depth;
+
+	cur_depth = get_recursive_depth() - 1;
+	set_recursive_depth(cur_depth);
+
+	if (cur_depth != ksw_get_config()->depth)
+		return;
+
 	if (atomic_read(&ksw_stack_pid) != current->pid)
 		return;
 
@@ -149,6 +243,8 @@ int ksw_stack_init(void)
 	int ret;
 	char *symbuf = NULL;
 
+	reset_recursive_depth();
+
 	memset(&entry_probe, 0, sizeof(entry_probe));
 	entry_probe.symbol_name = ksw_get_config()->function;
 	entry_probe.offset = ksw_get_config()->ip_offset;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-3-wangjinchao600%40gmail.com.
