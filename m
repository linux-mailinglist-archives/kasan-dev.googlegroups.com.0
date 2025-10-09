Return-Path: <kasan-dev+bncBD53XBUFWQDBBL5KT3DQMGQEANK5LLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id A20E0BC8A0E
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:53 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-9228ed70eb7sf329002239f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007472; cv=pass;
        d=google.com; s=arc-20240605;
        b=hZ2eDkfHg4j+yxXfcPK+QZwgG+qUlZkcwDpTD2+VqXvzQ7992MSxUnTKcOwg0iRaOx
         gxhpQ4s2jcmeBmlTgzdxgxKOajlYYzApmgLlrBrwi9nS8U1QEMnc33C4HUpCU2kKOS41
         DKc/cZuNpa10nyyJkFFe3FgqI7Kt1z7/MYqm7L2JcAoALDkJGqD3YxGNLBZinEUH2PVm
         FG3bo7ZRF1h+/2zyrvFz2akrEIzEYyv75h+2M23IMkQui/GF7r7BgBZGfWy0js7oTCXA
         awyhTnjG6tSvyVhT+qtahD4SSrOZ2PrP+EkNbrGmsxcZASozeliUEeVu9kaoPG+rDWYg
         6Jqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=j0uqeSpeLEAGvP8SUEik/vFMEXrkf0QonP0mfb17YOY=;
        fh=+R/oVTNWB8TZ7foNAiUZDmy/8o0DQd5EdHupjH3LAoE=;
        b=J3PbRdD66xVmYe3PwWNPOUFx0RxMG6r6Sq8uVayMlvCZLAV071AH/ILv2BG2qAymaH
         0YgdSnZHhbDfzeKQyNvOe9MEdpwur66JM8Qg3E3OS2XXjT+BeqKi9FlFskiqCJ54JchY
         Ctlw4l10+OT3GigKPJs8yqJ/4n1ljXmCPW1x8CHellQ3FBm6TXSh9RNjzRa2tejv+i8X
         9GiCw9QJqZnPBMUe3zVZqUAv4ESKDB6PqKUEj1IBRkGXa1R9+ZVyGNVTZbDOIkpl9Z/R
         GXht9b1EXPgMXdnUjjw+iRs4Tac7Xk0WWVdK9+aJtOsFevjPaTkw40PpfQ/ck6FabY5l
         xYsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JU6lweqs;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007472; x=1760612272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j0uqeSpeLEAGvP8SUEik/vFMEXrkf0QonP0mfb17YOY=;
        b=c9/soCm/YbJC3MPeyJa1DWlQNQrUStc6fKTVynDY437g/dBgn1ago/PuaSvo6bG4tk
         yd7GecfGtQCsRSirEa30GL28hkU3l9VcDAGGk/onPrG0tuZbzDpIOLtvuBB/PqHx/dI2
         5AQDxDBYvSwl9N5A8pmfZt01763bd81uEIFxOC571k2NNi/fcwv0PGdgG2TMKHsPazMl
         1D5zMzaxJPC2qBhk2iahBrw3tB7KrKQFm4GfdhcXQeYTGzBQi4WTFT52drVsYRzgssqH
         AfB6ZA+QL9474o7gDjZqF3yf79aUjfMUzZxyqF0dVk2D2trpgsDfwxPqszrftjopT3Yv
         6ODg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007472; x=1760612272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=j0uqeSpeLEAGvP8SUEik/vFMEXrkf0QonP0mfb17YOY=;
        b=BWMGnHEmxis6GoiltQupDlL7k2SeGvG1D+UHLfXorRdp3wk/oDv8EzxxapSsdGer6p
         aacCZLi95ixZE0jJL1RkUsnrDxqSOnJ31PfQc6zlKLlKaFmwxhuSSfHwHR6yMLscdRaX
         n/KQ4lpYrVaU5ksdCJGLVxP/X4oNaE0PxzKTGBbkY64qwH7AnD39Gt+jke/QJvtJZ/0L
         8KBCbDUYtue8FG3+Te7hOe9NlKLIMp3Z0ONO0XqXmLqbt1jPtLlEcILEtvE7E8SMHo//
         /5zZQXsJ3kqAL+K+RFyQis+d1E2zXoyEXlrFQw2/3W7Tw8IxOKpKGHEPhf86BX/CMdsg
         1Gvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007472; x=1760612272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j0uqeSpeLEAGvP8SUEik/vFMEXrkf0QonP0mfb17YOY=;
        b=tir0ZnE6QTSU4riJ2c7vODPeXy5qnDg6EfMgz3lFDUv9YDoFAc5iura2HHSEbRfy1i
         XJ+Gd8Odar9mtaP66Cpkdm6BIF348J2LjCge8Gp10L6x2EpS0QuFgZ3NMYHW5AnKGzVt
         66mF5tbPa1cZrDsHNC4RW3SiFVqzAm6j/Gg6sMRO08ScMcWaK/U7ckzRQQFG2gs6jfJl
         yUF7sAC9/MzBOJgkgGxwNRekClaSOejUCYAnkyM6OgPO1F4tBw9AqGCmJpG2DwhBXzfe
         1AtXcT45rvJ9wE0PjW5blygBVXr7hjSIdeS+s7l+SEJiysSEzv2CHmRs6ISKObb06TIw
         /qHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSh1z7qztbeNTpPr8amet2Jtt47wbqB0ebXglKUvfZxThSyAAdoEtCCslWzL+Um2iAVE4VEw==@lfdr.de
X-Gm-Message-State: AOJu0YxPCmYKQGkXC8s+8AZbk2KfN6YWxvo4s7C9nJC52gU26LFhKkb3
	sOq6nAuZIjIRSWBtlQzROyNIZ58Ok2vUQSDdRHQ+jtkArzKabNWxPJ76
X-Google-Smtp-Source: AGHT+IEnidf4dS/NxXMOVQP2+W1AFYCmLhefeLOjkk/tQ4GE4/SlK8Zz1gghk+KjQN4iZ6NIp3y/5w==
X-Received: by 2002:a05:6e02:380e:b0:424:80f2:2a3 with SMTP id e9e14a558f8ab-42f87346febmr64424845ab.6.1760007472200;
        Thu, 09 Oct 2025 03:57:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7wm806ze+GePTW1McuKIpi4xs9JN8oL5UtV9SfATK6fQ=="
Received: by 2002:a92:ce90:0:b0:424:2e6a:bc5b with SMTP id e9e14a558f8ab-42f90ab0b7cls8613465ab.1.-pod-prod-05-us;
 Thu, 09 Oct 2025 03:57:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOXqM/zWFPZoItTK+QZMjMzioJDO1vJd5SBW88vgVrbbbOuy11TtAvFwHoNNgE1mSIPc+LI3w4oWc=@googlegroups.com
X-Received: by 2002:a05:6e02:1906:b0:42d:8acf:a6e2 with SMTP id e9e14a558f8ab-42f873be85emr60074355ab.15.1760007471394;
        Thu, 09 Oct 2025 03:57:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007471; cv=none;
        d=google.com; s=arc-20240605;
        b=lr68xPN4uHUHq3U69ryzkofVtp/keI8xACsmQyoqrdnqHNDYMk3HrgvaEz+QfWARen
         xdZsUFkH2GOtsIuyxPCAr5ONiPjNNTajIn4d6gUu0bSazdHA356YukECqeF+G3b/F4bC
         lBDyQ3p4N6ab5l5OQgNL2nGP2XVbn84Av33fRdxbSqznWqH+S2ChLJoi54K7WjXidNzt
         elNiQYRiS7CCNCMNKq0OwZphtsFcCQJp0/6RPTDT16gG29yLZ0iIoku5buJVf7Xfy8rM
         qBCuVws3XA7NhZCaSFUUn1Mp3vt1/jbje8GuYASQ6AtMfxLW5PyRK9n3AuC150bcUf+K
         eZzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dPor1AiTaHON3BhVq+NCy46wTls72eqNmMOTROEZDIU=;
        fh=rCmzGFYkkl/Ja5vxfaLEA89ITv9Sy9JpQ9Qr0KSCDII=;
        b=K3dkTNUEfCwshQuTgKqdw+bf7yy6QH7TUOo2s8y80Vc9vwujwNH6Xsz+XT6DfoPaJQ
         lqh2QVZTLs9X6ldgAU7FbOAxXjqDEB9HJWES+B9x98jwlSv5qqAKoBOva0Yf+jBt802n
         vZcBCKQQ/LtdQilpGB9eBNJ8537ND2+8jJEIvCNCCqP2mpIF5l+HhvFQbee5HuScV/38
         YpGc/4vo03EeKbY2y5vLjlYpXNafYKd9VjxfXrE5HpPq8d915C4OpbsfMLQkrYhkkBYK
         tMc87IxBr6AUyd96FKA5vtp4oJokN9clqSMxYf0yCXRfzlHnRxPE/t7QNmT3lggQOfKN
         mECg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JU6lweqs;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-42f9106b0c7si869335ab.4.2025.10.09.03.57.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-3322e6360bbso802989a91.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUYA9hLOm4Ea84fDa3xCvNxzlpV1hK4sLYUBssFZixLW9hwIyiM3hGsLlnoJaazkH7tcFMz6SjGfm8=@googlegroups.com
X-Gm-Gg: ASbGnctoRFCzUqtoJvJ9W8piU2WjDddS7gAPy2SbcIaFlbbvnYhDUCDqqSkISTXO50Z
	gzF+kxewSl6BiNrD0ANrHCgtxTJBhHAox2qZsSIPy/aYBkHbetQZKx4gbdzQRicVv8uPcMX6UPN
	MyR4W2SojFmFPidmPSIGgHYXIjOr29bLnf7dry6xV5PfQ3NRE6p0eeRK/vMRepFuZp/r6zV8t7B
	GPh6pLVQW3y647Ewhazm4VOkIo8LUWaDLTW3ouvEBPVwm7wl0Kuf5bYibGzX7n3LobOzHlrGUoR
	aZs7UUsKnajaN10xUeDxyE1jPG2eHMNeAmWlR23OSZ+qrwGxlfPh0jUwtJgBMxv5wuO4c5a/KAr
	mgfbt3lPlubnji4LMQ/+iD86xA4EFgu+DKM+Ve+i25F5JOnUJweLn6SrUyESz
X-Received: by 2002:a17:90b:3ec1:b0:335:2823:3683 with SMTP id 98e67ed59e1d1-33b5111491amr9148774a91.9.1760007470702;
        Thu, 09 Oct 2025 03:57:50 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b513926fesm6702757a91.21.2025.10.09.03.57.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:50 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v7 11/23] sched: add per-task context
Date: Thu,  9 Oct 2025 18:55:47 +0800
Message-ID: <20251009105650.168917-12-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JU6lweqs;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce struct ksw_ctx to enable lockless per-task state
tracking. This is required because KStackWatch operates in NMI context
(via kprobe handler) where traditional locking is unsafe.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch_types.h | 14 ++++++++++++++
 include/linux/sched.h             |  5 +++++
 2 files changed, 19 insertions(+)
 create mode 100644 include/linux/kstackwatch_types.h

diff --git a/include/linux/kstackwatch_types.h b/include/linux/kstackwatch_types.h
new file mode 100644
index 000000000000..2b515c06a918
--- /dev/null
+++ b/include/linux/kstackwatch_types.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KSTACK_WATCH_TYPES_H
+#define _LINUX_KSTACK_WATCH_TYPES_H
+#include <linux/types.h>
+
+struct ksw_watchpoint;
+struct ksw_ctx {
+	struct ksw_watchpoint *wp;
+	ulong sp;
+	u16 depth;
+	u16 generation;
+};
+
+#endif /* _LINUX_KSTACK_WATCH_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index cbb7340c5866..707b34f26264 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -22,6 +22,7 @@
 #include <linux/sem_types.h>
 #include <linux/shm.h>
 #include <linux/kmsan_types.h>
+#include <linux/kstackwatch_types.h>
 #include <linux/mutex_types.h>
 #include <linux/plist_types.h>
 #include <linux/hrtimer_types.h>
@@ -1487,6 +1488,10 @@ struct task_struct {
 	struct kmsan_ctx		kmsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KSTACK_WATCH)
+	struct ksw_ctx		ksw_ctx;
+#endif
+
 #if IS_ENABLED(CONFIG_KUNIT)
 	struct kunit			*kunit_test;
 #endif
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-12-wangjinchao600%40gmail.com.
