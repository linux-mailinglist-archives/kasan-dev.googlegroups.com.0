Return-Path: <kasan-dev+bncBD53XBUFWQDBBW42QTDAMGQEG3TD5MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id AEDB6B50D49
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:32:13 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-329ccb59ef6sf7389827a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:32:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482332; cv=pass;
        d=google.com; s=arc-20240605;
        b=XLhFArUWcNCTpvQkD5iOt9LPZenYPOIHzoUgsS00qtPQ1jg3003LRF26ZojGX59auR
         XV9ZYzEGxidR4K9pg960tnclB+9QUI+GTUhEqQdXxow+SJ7HAjeO7jtoZO5Nojz0Shtd
         XVIBBcE4CxCh1PDF1GlMftG5NVNnmftkxKv2gqZmV3n05RouNjXRwqQP+i3WgybwoVoG
         JfGoFTToNvtmgTmFRsApy+ujLzcmfn8gePcLgY8lW9bzmGICxd9dJslcLeF9sUJWyQr1
         8ZW0f/9ZD55J1RolrCJ3y9jI4uh8Wwn8IGAeG4ZOYZvRQJtfgDTm2eiKvu6mx22rDW55
         14/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=5QlVifLH/QzKvn932RpdLEiGktQWf7E6bAYIqlhNOOE=;
        fh=524WedcuCQ4a+fsxp3KLOlba0nEu6Any9VfHxOM2F8o=;
        b=UmuVgifuBjWiFp0fCRbgpcfNpAR5dyDbgFpKnlANNRGOcbq/JAaR/TJbHjItuQnUez
         Yu7jIqZH1O2BjHQ68tnZ7U2NbhbNPPcS6MrwwgMCI55MZf7Exa178AnM8q6hUAZvnQvC
         gbtAWiwYCrMyV8Km/HhmmyZojKHGlFbxHUDz+Ep5BK+2UOJKeGrtRTisWHpQsmTvCalN
         jFrpAjKd2Aoh3BjVlOM59GOTZjLP+yplqRGD7s/5I4RWxyPXI8PQQJZBSjjEpsCQ0wSu
         +kc7BKqKZ64+0U1x4BkLTwNKgn+bSZWSmzeKsv0fQ92sN1zY1Q02TNFHhwTc/6VeUPY8
         EpzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LBUazTi9;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482332; x=1758087132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5QlVifLH/QzKvn932RpdLEiGktQWf7E6bAYIqlhNOOE=;
        b=gQQ0LfvHssr9fZsJKQ8SUvIYGlL680ByX16MSx2DweDyCa8+MQa6/sSC6TyMKNvsaC
         XOK/vxUDK0wAKB89VDZZlPKYogzEICV4NJbJRN1fVkbk/etgKY2eRO0PyxNv57dQCAKu
         o4Y1xxwfriCLH5WE0dsP+LayM89d2GYDnak0bheV9CZK1mqWX4TSNpG09KvBM+Ul8X93
         xb83uUSuANjZhF01/wyETPwOcE+mRLwz6x62snS/Krv6K/k7UgByIQU4g1bUfcxkHOpv
         bgPyM+iprTA6zxH6aqF92EEfqr2Zo7xI/KD5NrUFpjO3cWMLxJol5ZKE6zNSakMrXLLk
         9aOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482332; x=1758087132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=5QlVifLH/QzKvn932RpdLEiGktQWf7E6bAYIqlhNOOE=;
        b=U7sZwJF1QYlo3nJhSt94TAxd9DV2GFygG/HeusDJ+dhJ0CoSUA18r/8gmdepMV+lbb
         at8VW0nuEeKOXuU8LP0WLxYT3kzVww7ytnWbHpQ/xWpHSN0lzImIaYreD8ierT2uo1hR
         nRLnFaJfFUB8kqFdQD9A8N49q//MG1LagD6/Z5YdunO37kuDSyqYs2ux3KMM338bE7RT
         4z7AKDLz3x1NnxSXqfSrrxxCIXKoRhfYeoegCkOLcc0wyVwe/Ob+BLtgDl63c84ir5iU
         ZVGzK0kpuSWRUXrfEskrAfNjPDVdSXjFvuD3KfRIlbLjQA+Lo92Afh6hQ+SNT+uUGyId
         0xWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482332; x=1758087132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5QlVifLH/QzKvn932RpdLEiGktQWf7E6bAYIqlhNOOE=;
        b=uzvBIeh1rtgFdAa3FdRYXIDEBZYfJBkq3IwLXR/Wqoyx5UBLjkOtkYOtCvCQEv06Xi
         sfPSIGjK9DzKw/V8Zhj+X0RZheXoxxX4T8W7Opf/pz+NI/3/yEEU3NTtNb2HVdOj2sj8
         hrLjHt6k2Km0No4Jlbl7hVb1cFsc61CSTjnWe5repH4j3d9wETNg+kQw8XePLTKZMvdZ
         wd03eGqkJiqb5pF9AIu87rBSLQSeAsx+sQ9T1SnVjrpp33/RMc8NvdU42CeVy4rYekc5
         miaoWYx6UG/1zeD3Bj20o4TEPHE8hj3eP6wbb/Fo7QfcReE5K5sOG3DVbixVEdHw/QiG
         DQ2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOmSGmIItex3L94ShfZY8OqUMyGqWT2XZiLPO2SDhcOIahZGfR8XGK5GojOYkYnLv/jppcpw==@lfdr.de
X-Gm-Message-State: AOJu0Yyx0prIEzsqiXphLpThqBkpwMmsz6fSP+YtOJV6fEuKNq0+F0Tg
	YgdGNVzWVCcY9VNz4g58qM15CKtznVynzl+OjkBJnLNsyVaOfTfC6xKF
X-Google-Smtp-Source: AGHT+IEPs0av5Obav+r+PF+XDx6vLRTOwLpn45LLFKuF9/eSiaBkn4RamL6mRooVvIXClVx87zToGA==
X-Received: by 2002:a17:90b:48d2:b0:32b:5f2f:f675 with SMTP id 98e67ed59e1d1-32d43f7d78cmr17176965a91.19.1757482331880;
        Tue, 09 Sep 2025 22:32:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZciD5KEaf3T00uya74kzzHIo8BvWRWmtFMqoaZw8K3sWg==
Received: by 2002:a05:6a00:882:b0:76b:b326:ac43 with SMTP id
 d2e1a72fcca58-7741f013f7bls5979044b3a.1.-pod-prod-09-us; Tue, 09 Sep 2025
 22:32:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN8ZfWcfofNOWJyBkLWVcBbX5T0EInmnThQbKE0u64RkB/jAoru7lYiOYNS76IcipIsy9XO1OOVCw=@googlegroups.com
X-Received: by 2002:a05:6a20:a109:b0:250:720a:291c with SMTP id adf61e73a8af0-253430ae481mr20791165637.34.1757482329881;
        Tue, 09 Sep 2025 22:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482329; cv=none;
        d=google.com; s=arc-20240605;
        b=JkV+XJHZQEiLUyUBZhF3R77ljOpQoue8U9vRwPxCqt5dvsKwVzzOAAgJTRABgKLJfQ
         bgxeb0vL/X8XrakgqRTDop9npMM1v7Nai3SMTGzcezyNochgD2f0nB3YNKWOIGqmc1vC
         h4n97JSeAc3HepYCbTaJPQns9qQeA2TqS/LA6MzKy2A65KF3+N8v0+dFpL+Ozv4MhwjU
         TnGeuE/i17tCdY+vuml9M4HqDHiF/io3eHVaSUFZ7Fw27U/vCwuVdZdjXUsITjnFTia8
         T2QLMtPCBdrKssRb+nrk1PQitDBW+I397cIHYaicHSkw9QhxcDmJul1r6RYbxyFelpVJ
         uZhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jTX/18/Ng4CVcL/DRFC+Yv752wszrnD9hcMkiFmERzI=;
        fh=rRrnsLquBSmNC1+yCWlJ1xJ0yqiCeTcmHGYiVgMxUfM=;
        b=PznJadcVAqa938fDqwNSAvg2n2kSMEp70DyF/NDsnSHSC3kZykn6VifwoDV3x9itdF
         VBy+dlXV+0zDFa+SibD/lex9vlI+ajH/9xGmly70KVrF12KxcjWaRUAF4FmKyo7zDiH6
         epbxhcRBWyh1NBFYmoRqMZgRL/qOxHEQbMMMu6/d5ASVbfiMDrLAsPGoiyBE5Yqb7q3R
         SZAiSTHAKOBZibVJM3DTAq35f2emfut5PLSalPM4bgvxxL3j8F76b2TeHF+1Yff/C3Jl
         0H9heJv3TkLOauAYzyiJ6jUnufU2RUAKvbLaBQRJi5fI+648FSKwXNupY2LaPGOHQv0g
         lUBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LBUazTi9;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dbb4a9988si47152a91.2.2025.09.09.22.32.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:32:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-77251d7cca6so5397852b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:32:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXEFN6YZRLFhcnFzOlnTanKdnR95h8LXRB/JQ7OIbGj73/boXO+LAXeildcxVRZ66sly734Hwk2EJU=@googlegroups.com
X-Gm-Gg: ASbGncspS05etUTiiiUxIlCoALN+8duDRxPepd9GMx8RvxdjDCFlBKbMGieTbMwoDqE
	nwv16xIzgaWPF9UOtMUTimr2HRVhDcr9NHdqJTqljruf3PuDxRz0dQEk+1/l9Z9VjIqKzwiLYT5
	dVa2xWTvIZhovjXK/IqF2Ag8/k+yjn+LJi6zqvK/402tF9ef4v6Og5yY5WFaLhh8DUoe0k3aOAD
	HLsrA2OZQ8rdi/8rxNeoMnXFXl4/u5TaCdbnH1eDYGJKNCyV+5dYDs+Xm/JiQrSo0OfsDkl6CJ0
	VM4w72azcffW5XSDOt58nHDwMSyoGzPoIas5nuJBWLOXFmIWRwFmwVE1PaoLZd6z5QvzJllrTkH
	h1NKqdW+DqKXTyI7XTDLJfRyutaYBQjiwSb2CjmdxcE5oF4x3vgeWnZt4Dm7fxhUk/SZXMQc=
X-Received: by 2002:a05:6a00:13a0:b0:770:579a:bb84 with SMTP id d2e1a72fcca58-7742dca7eb8mr15301351b3a.5.1757482329364;
        Tue, 09 Sep 2025 22:32:09 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.31.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:32:08 -0700 (PDT)
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
Subject: [PATCH v3 09/19] mm/ksw: add probe management helpers
Date: Wed, 10 Sep 2025 13:31:07 +0800
Message-ID: <20250910053147.1152253-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LBUazTi9;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide ksw_stack_init() and ksw_stack_exit() to manage entry and
exit probes for the target function from ksw_get_config().
Use atomic PID tracking to ensure singleton watch.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  4 ++
 mm/kstackwatch/stack.c       | 99 ++++++++++++++++++++++++++++++++++++
 2 files changed, 103 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 2fa377843f17..79ca40e69268 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -38,6 +38,10 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* stack management */
+int ksw_stack_init(void);
+void ksw_stack_exit(void);
+
 /* watch management */
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index cec594032515..72409156458f 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -1 +1,100 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/atomic.h>
+#include <linux/fprobe.h>
+#include <linux/kprobes.h>
+#include <linux/printk.h>
+#include <linux/spinlock.h>
+
+#include "kstackwatch.h"
+
+static struct kprobe entry_probe;
+static struct fprobe exit_probe;
+#define INVALID_PID -1
+static atomic_t ksw_stack_pid = ATOMIC_INIT(INVALID_PID);
+
+static int ksw_stack_prepare_watch(struct pt_regs *regs,
+				   const struct ksw_config *config,
+				   u64 *watch_addr, u64 *watch_len)
+{
+	/* implement logic will be added in following patches */
+	*watch_addr = 0;
+	*watch_len = 0;
+	return 0;
+}
+
+static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
+				    unsigned long flags)
+{
+	u64 watch_addr;
+	u64 watch_len;
+	int ret;
+
+	if (atomic_cmpxchg(&ksw_stack_pid, INVALID_PID, current->pid) !=
+	    INVALID_PID)
+		return;
+
+	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
+				      &watch_len);
+	if (ret) {
+		atomic_set(&ksw_stack_pid, INVALID_PID);
+		pr_err("failed to prepare watch target: %d\n", ret);
+		return;
+	}
+
+	ret = ksw_watch_on(watch_addr, watch_len);
+	if (ret) {
+		atomic_set(&ksw_stack_pid, INVALID_PID);
+		pr_err("failed to watch on addr:0x%llx len:%llu %d\n",
+		       watch_addr, watch_len, ret);
+		return;
+	}
+}
+
+static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
+				   unsigned long ret_ip,
+				   struct ftrace_regs *regs, void *data)
+{
+	if (atomic_read(&ksw_stack_pid) != current->pid)
+		return;
+
+	ksw_watch_off();
+
+	atomic_set(&ksw_stack_pid, INVALID_PID);
+}
+
+int ksw_stack_init(void)
+{
+	int ret;
+	char *symbuf = NULL;
+
+	memset(&entry_probe, 0, sizeof(entry_probe));
+	entry_probe.symbol_name = ksw_get_config()->function;
+	entry_probe.offset = ksw_get_config()->ip_offset;
+	entry_probe.post_handler = ksw_stack_entry_handler;
+	ret = register_kprobe(&entry_probe);
+	if (ret) {
+		pr_err("Failed to register kprobe ret %d\n", ret);
+		return ret;
+	}
+
+	memset(&exit_probe, 0, sizeof(exit_probe));
+	exit_probe.exit_handler = ksw_stack_exit_handler;
+	symbuf = (char *)ksw_get_config()->function;
+
+	ret = register_fprobe_syms(&exit_probe, (const char **)&symbuf, 1);
+	if (ret < 0) {
+		pr_err("register_fprobe_syms fail %d\n", ret);
+		unregister_kprobe(&entry_probe);
+		return ret;
+	}
+
+	return 0;
+}
+
+void ksw_stack_exit(void)
+{
+	unregister_fprobe(&exit_probe);
+	unregister_kprobe(&entry_probe);
+}
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-1-wangjinchao600%40gmail.com.
