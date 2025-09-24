Return-Path: <kasan-dev+bncBD53XBUFWQDBBT5WZ7DAMGQEG6E7RTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AD80B99A7F
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:45 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-ea3ebdd9eeasf7167408276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714704; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZaFzAvMkDQvlAoWna3PnITxQFpiTwtrjpRbLklqHiu3rbcscx7kKXjmBhHi1An40aN
         LHE2UW0iCPPoKBvizeshE7MWPp7y55glK4kd2sT3vn9jZ0WEDpzhFcc/S12eKpwwelC5
         YduzZYcZ5zQTQ/D1CcE3MlNnXoCZ6FuWqxs5x/a8+9ba28i1wl8BBAMnh/egwa75tuWZ
         USPMUWaC0cMZ6ITc7eKL//23t47TD8X5gMvcssu8gjmJ5ut/M6pbYhglPpGf+SZmHxwJ
         XwkiOsjYjVj9DTYyHOE9RsWAvoWelxwiqmDYbTdjZILh59hjAqHuoUTjGGmxT6Azjfoa
         e1cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=P63bmvKOiPx6uRevtOmcz2Dv2U1G92qb+b9q3jen7fk=;
        fh=N7JMaTT5ghX+6DatVmE6rohIGy5Qx63MEGtjIOeyiCk=;
        b=BRvt7VFM7k98AtNLY6UpgkDilWvYufTLlCMd/JsgR2VRNFs+g0F2TWk27lRf71NPOy
         u+DOyLk1k1OJgk3nc+w3IV+L83EJe9H3EM9q5LkNQj3/3623/870Kq+q+1Fu/2MIjTzL
         W/knp3aSvisC7SDe6RvlpjNnZg8knIhu5wMU94GPzjXspJxuHbAzlGWu410wG6+/GHgQ
         rNnQnEACFE3VGZMwFG5WcuWD6msl+nAv1hldMU0CSUkzcu1ClvrhBtAMmqm6S0Zy+uD2
         8XTIJQg9mqd00BEXzh6cqMok+mYQkPkMinAU/tS6OWuipch0EwiyUxVt5Z33OhchR8Lm
         +wgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bgNci9qP;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714704; x=1759319504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P63bmvKOiPx6uRevtOmcz2Dv2U1G92qb+b9q3jen7fk=;
        b=myl1/fdLffT6O/gMX5/BJnh8fV2ha/6Fxvs5OfUGkyxcSdkXcwFohppCDOT1DKkm6k
         IYrrtNQi7L8xTmPPtI9gh1j8XIpP3GzZx5fWgK5HpXROmtW/BXlhiU5TQgQafVr6QXyw
         1/66na7lITMndeImkNirmH4HWQ/+cxqpU9t+R2+Hj9aF845waaXViRpVp9zZVJvyBgGm
         HbQrkNtAA4T4e9H6Sm+6cVtHljFHq8cjUwJhjSuM2N0nH8cU7ypTnL5LemONRov5i68k
         EXf99W55tlT16JgGtquzyKAg9Q1G14GCm2xParw8w+YL2rWx/U+fYoYHOJPrIAxq+ZG8
         OHUw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714704; x=1759319504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=P63bmvKOiPx6uRevtOmcz2Dv2U1G92qb+b9q3jen7fk=;
        b=QpWVmfwJn2OmIySFYwbfMXmr01vv4l1olKaB9uknjBlIy2H/rAqlOcW36awPeDDMGC
         0EQy+QmBOYemydoaMH6H+buOr8N9+Gg9SzO65cR0ZlqTLp87nQ/UPsVvm1gqOH6CRF+f
         Gc/Pr1onV/xHRkEH2zmApMGePYUDLmFQ7mtFtSvI6P8wbFtN4LcB5P81djMbCGTdk5Tf
         Ab/IMp/1MrxQ+ahqsJhL5QBMFBFbUT0LuUdvEMv23kqAlBTXfhDbu2NLrfEYB8LFMqnW
         ZbhTsbEfOIoVCYa9AVF/YzY3FNqLlhMNU7XAcEaapzsb5MHLqVbRQnjmzV9JtOOg9f3Q
         wTxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714704; x=1759319504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P63bmvKOiPx6uRevtOmcz2Dv2U1G92qb+b9q3jen7fk=;
        b=SdvMFoHuV5tjr6MQYArKEpYTclHS9Rta5KSxe0dg2QLB3GdMKKopdPgsFjx+oAu9u/
         n8Ap62jl9lYdsqDerZnpM0PktMsa44sgLpWtTnfDJbw3rOo224zaQFFeZQ/h3mC38Wyb
         j3ITUx1y2hdLAfVfcG+z8oh2LLT3NpH/QX91pFWOqyAKshogMzcR/uo+TWZn0zMzUyN1
         mdMPNTi8KdHkExEjhi8N0igSXIAnb+DrnnC4/icNvdM8wV+34A6+8Y3bQoL68P9BklLt
         YGD1GTlXVU3vBpIO5duUL9FMGTKUk9w5bGSJAl1JIZyGXwjnqtJ3BjlzFkiJ64An3mkq
         bSow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXavAxB8nwr1kGfsYmL2PXE3AA7pDMLtcvAE0kKx5VTy8AfY8YgOlWL943jzIz8mzSUcxpr3g==@lfdr.de
X-Gm-Message-State: AOJu0YxmdSEITF3KYuK/a+gdIPRxBf5rLLxUCyFSrd71P8TKKNcgG1h6
	xKoexGY3MuH37Dx8h1ClSH0C5+SUgh2ZJwMZ/4IkfSj9rju6sgN8oJGR
X-Google-Smtp-Source: AGHT+IFxK7ptN43QjVe4PYp7GbOeWjcS1ux4mpj6w1+RpX1dICRZd/GWHrXOWCkU6F6Wx+uTz6DP0w==
X-Received: by 2002:a05:6902:1248:b0:eaa:e8b7:a5ba with SMTP id 3f1490d57ef6-eb33123d9famr5509299276.48.1758714703693;
        Wed, 24 Sep 2025 04:51:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4QOWPPwK9ePc5dfQpHx0uA7Ri0HUJcHPw0Ghz2/cN3VA==
Received: by 2002:a25:49c2:0:b0:e9d:6e39:6d48 with SMTP id 3f1490d57ef6-ea5d1157e81ls3893984276.2.-pod-prod-09-us;
 Wed, 24 Sep 2025 04:51:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUibZhYzsQJCUfpXZcbHAZHYHXPqXSHS4oaPN3gN3QdkOJFgrpmzVg1YMZzWCSX3xq68mpWr9ZJxM0=@googlegroups.com
X-Received: by 2002:a05:690c:4b92:b0:73e:376:9119 with SMTP id 00721157ae682-758a6f8f2b4mr52679497b3.49.1758714702822;
        Wed, 24 Sep 2025 04:51:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714702; cv=none;
        d=google.com; s=arc-20240605;
        b=kjWjf0y/DADVFI8F8ZPd7XTjb5rmFqKqypFOTi21qzNHdBWdBHIkdlJG8fv84EBRBb
         iBhTDg8FiFOUa/GgfPfBHe8gWmKWyzXLRAV85fdr79x2alupuTio/a+BUM9Lf+Qti/we
         8fbytc7CJGNAZQsxR9rlP6HkkFyeSJ/7JhzDd+ZSkPyZaxt1hhPralYBfTMVdAu6bCkx
         AkvEkR31HQkSkDPZu1tKviYPOQOqncnLEuHlymDUWrWsul2q5Jn+n754M5qab61zyfwe
         s4fPEgBTe+XoT7+8yaNHGRug2mCfmZBKg9fz2ZFv7YMeegdupSi04/Eoa/ZK8zj3q+5d
         v0nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bd/jIJYyk1G6SYf0mNQVLBMDX4oiGoErfqkyMXn4+LQ=;
        fh=igi7AjCyFqP2dcuyCIShyqflgCnNzmzHyQQBI+rGoKw=;
        b=P569xgQQyshBatoWXV1Gnjmev1rF1SbzIzmDAYodlm15HmG3A3YKvwvjz1MXavUdLy
         +I/Ca66+rRJhMtouJss6231uTxc0Ni8yvZ1lhicYIK8CRAUVTTveiV/W70mPceFNZuBV
         70HgSkM3p9o4JLI2dHw0CWmac0vOIFZ53jD2IFrc5C6V+ccxhVO0iq6lp9nGikCIan6G
         V+kknSwkWNntvTv3zPUEWpnlnZ+HD8nqHwJQboQqdJEMMNZPh8RNCRnJ7OyAJ+bGANNd
         ykmV5yphbN3kxnAkvbuHWHdaVguPzafaQ1O5OUhoQY+jDDPmWfYiB75iP1lbGFCdhpIy
         rqRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bgNci9qP;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-635380b3cf5si146887d50.1.2025.09.24.04.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-b554bb615dcso2307615a12.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU+ETV6AWIYhF7zV5ltCQNQfZ+GNzwmwibaFRHIrWou3gxaVW36ebuaQ9M/QsIVtPQ9gXFH5FbF568=@googlegroups.com
X-Gm-Gg: ASbGncsYMOqRn1hgZDjDaTZvO+f89lafcgececWmCHFsGtzw/Wk9lmbnore1LJqClQN
	Y/HQ49JinDtqnheSUjsNccbI5oDjxnHJczgN3tFV6u361z2LnVpZY/lsjFTzwqOVXVZnbDMM4ZW
	x7Bl6az9c2s2dHLdoU2a94KbAT0qgrh6WRhpNHS4B23yU+5km02pgOLJRTg8n7dT9eLKz4fgHkK
	73WeMj5nT2p3WEy2uylgEI525RRI+cbjT9pIzdgZqmr17OlV+19MTDgH6nFUQ2GAKBE+QxjAHOP
	2KOWey8lpK9bydMaxT3RvIrv4LGZC7SDXaskWbFFb6RmhmH8BLMloEQv3TX41KeBiE+h+F2yDPX
	8wwZ6UgXmFAUGVu7LL602DWTjaQ==
X-Received: by 2002:a17:902:ca94:b0:276:b1ce:c094 with SMTP id d9443c01a7336-27cc543160bmr45804925ad.29.1758714701852;
        Wed, 24 Sep 2025 04:51:41 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-269802df74asm189691615ad.94.2025.09.24.04.51.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:41 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 02/23] x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
Date: Wed, 24 Sep 2025 19:50:45 +0800
Message-ID: <20250924115124.194940-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bgNci9qP;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

The new arch_reinstall_hw_breakpoint() function can be used in an
atomic context, unlike the more expensive free and re-allocation path.
This allows callers to efficiently re-establish an existing breakpoint.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/x86/include/asm/hw_breakpoint.h | 2 ++
 arch/x86/kernel/hw_breakpoint.c      | 9 +++++++++
 2 files changed, 11 insertions(+)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index aa6adac6c3a2..c22cc4e87fc5 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -21,6 +21,7 @@ struct arch_hw_breakpoint {
 
 enum bp_slot_action {
 	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_REINSTALL,
 	BP_SLOT_ACTION_UNINSTALL,
 };
 
@@ -65,6 +66,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
 
 
 int arch_install_hw_breakpoint(struct perf_event *bp);
+int arch_reinstall_hw_breakpoint(struct perf_event *bp);
 void arch_uninstall_hw_breakpoint(struct perf_event *bp);
 void hw_breakpoint_pmu_read(struct perf_event *bp);
 void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index 3658ace4bd8d..29c9369264d4 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -99,6 +99,10 @@ static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 		old_bp = NULL;
 		new_bp = bp;
 		break;
+	case BP_SLOT_ACTION_REINSTALL:
+		old_bp = bp;
+		new_bp = bp;
+		break;
 	case BP_SLOT_ACTION_UNINSTALL:
 		old_bp = bp;
 		new_bp = NULL;
@@ -187,6 +191,11 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
 	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
 }
 
+int arch_reinstall_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_REINSTALL);
+}
+
 void arch_uninstall_hw_breakpoint(struct perf_event *bp)
 {
 	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-3-wangjinchao600%40gmail.com.
