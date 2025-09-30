Return-Path: <kasan-dev+bncBD53XBUFWQDBB4EI5XDAMGQE5SE5GLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D2F3BAB108
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:46:10 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-4297610aacasf33718015ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:46:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200369; cv=pass;
        d=google.com; s=arc-20240605;
        b=JeCVtyHT+roru58qFhoPofpUufzSmOPBahlHEd9/agUiG8YP5217UG3u0Q8ujK2+IC
         n8Z29f8oNMjQzWcIFoaEKDZ0UBiCM+UWHgfcRmmGYsT/cGODmd1UXJbFcjvimo4qgaqm
         Yj5ngPitN0nqoZQ3GvmRTqyOrjFaPHDaEuv+ufXeGBOg0HA36Ds3gw+VAe4+hMP9VwBp
         wPIUPgaa3jSEA76oEKmTqmpRTlNWHIbD48xPHw1bUYfkYtKzfWX0OhMWlxVuKKsgRb/g
         cFGPKLv6hS474Q7g2nnNzCg/0lrH6yxD6/urv+84uszXWF6DNhrp164+zP5EszfdLhkR
         +rQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=aMEH4CjFeg6xEuicmrK4EGHpFNgyF5tYIlafNfIeknE=;
        fh=6helpsKbTTy3wEQ721fGFVNAPGVaAYcvdIlhtoDxDEs=;
        b=i5so3wJA/a6/HtxxQz363dtee10mpoU/QmSAcEpwiu/zqLyYoWzX7vL+0cFuUaSKWC
         jbkfIR1BtV0p6lCn5qQsdTl0T8C9Ft5kWZzjm6om4FoGHUrnjkiI8BXAgMs3vCNLwqQV
         arb3MpBMudxY5bdgm4LkwnDFe6Vzz/E4B4GzUKGWUrKnkkUomCnZAqAWz3DXUw8PkRKj
         jP5VaL8LniUCi8CbCeeA/lxuINTGJPk0/ZxFHp3TRncdCSexycAWL98dOCh3/FKTf+VL
         JBAmIYVP8bqQQ9JGkpXxpJYuQ9Dgco2AyDo9ursTUQ0gZrgm0O2cGaMtjeyiTQeHIAju
         5QfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Ln/0Y2oQ";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200369; x=1759805169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aMEH4CjFeg6xEuicmrK4EGHpFNgyF5tYIlafNfIeknE=;
        b=ubt/+OIISCwPL8pNCyLlYYAymAWBlXSy9MpUAzSCn9WFguM3+14nC29+eVpk5QoLj1
         HNLFMvU1fC/gmzLq8onNXEbdjv7PwkXwKb3Ffqfh7YueEZiXnXvPlmtQdBtxGoglI3Dr
         D58SqywWA/R/LDIXCOgcVQ9EGvEOSQABFQzlpf2VAFKQDT/w1XPFaxIfjNf4c5at/vvs
         mHaaanCNsLbgP+V44A2lgkg6xe1s+97Hqsywwa/l5mSfPJ0qvY3QbB4CJ2DeFcGDdnug
         P0hGugLfG29/y1huRp1hS1hQmHporDLHlcxo9D3y8ne2W2HoEv1yEDWOCg09wYtVPbOi
         ysgg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200369; x=1759805169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=aMEH4CjFeg6xEuicmrK4EGHpFNgyF5tYIlafNfIeknE=;
        b=HxJxWr3zxDJECgZsXDsUiRDTNK2pYRBOIjFUbuo82fo94dPt24ue2eEKPdgwYAI8bE
         lfI+xqhJ8AZAvsvbgw7x00dz9MVN9WXMmWBK1w+bk98tlLwCxSmNcao/yUtgqvtBDrMz
         8GC8YmjlyKTTMSMlsv4tXIZ6Ty80FYBXjsM7LnntrwHMH6G0U9bV08GOB4jPJ2I7iQLM
         d19bf+zsA6m/lbWC/uyD8mbv1Krem7v5BUKPRhqfAkkPUd+Vj5etcVu3kC/WobxnoEcg
         K9xNaTfGw4RvTIz2xLo7Rk+Mm7+z/+6zI9jX43uyFHo+YSJQ0RSd8fVW5JEqzfuqBpZq
         s45A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200369; x=1759805169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aMEH4CjFeg6xEuicmrK4EGHpFNgyF5tYIlafNfIeknE=;
        b=cqYmtP+Esu1CJR6IEjZ969iD+p06Y5L1lkKn3ZtpbPBsIU8Ep1w8ZBpE4Ul2RrCElL
         nv6KPZYrjylQe+P/gv1nQLRDdpFWLw3FYc5LWIPrhqXvaawM9bh9U+djeZ7aOmrU0rIJ
         21EqMH5Tk8Mcuow5wXoTfBnLhDOrcXEM3GyiOilImtT3X+WRWaJyLnD38que4+7OJY+T
         PpJ53Nphay48Ex5UCospspsF6f9MkJ+/BD4zgFFVF/azy/+Kn3JZrpMmtSdHkLK8g0U8
         ZpaaqZFn+o6bdF2P3ITa1L8OMCBmxvQ1ITKkvAuImzKFVFS+/2bb9QuTmNBQgoUyTtpS
         AL1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjYRWcAigHwpKjcJCeG6fJuuXNb163sser9JJDdz6eg00sQ16RhdGRcPR9Kcqq2SM4z1PJ2w==@lfdr.de
X-Gm-Message-State: AOJu0Yw+OWPD5LCDrAjs9QrafpPO0YrDx03VGg2nt7bVV7H7dpnJytDp
	Ek5QKEb3H2AIiMfShpOXUxn93ZqTauxbTfbesfrYjpIZuZDMjKEispSW
X-Google-Smtp-Source: AGHT+IHPBh9jYaZ+RIRZ4uZxKNr6Xi3AKyehlLtMVrBc/5K7jMCLMuaVXPcuYynhv6pHYlb6a7pr5A==
X-Received: by 2002:a05:6e02:3e93:b0:3f6:5e71:1519 with SMTP id e9e14a558f8ab-425955fce57mr268902835ab.4.1759200369092;
        Mon, 29 Sep 2025 19:46:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4BV3Urw/BKY5SL4GiOgUmx3lTV835/uPk9Ph2eq56YAw=="
Received: by 2002:a05:6e02:5e09:b0:424:1289:9cca with SMTP id
 e9e14a558f8ab-42595659700ls28939845ab.2.-pod-prod-03-us; Mon, 29 Sep 2025
 19:46:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqIJZYiogTiSPJhijPt4w2AbfCtnthNfLRO5yBHGWHquwvJIF3RLVX6st2NEwcg/9wdHWNimy8XCM=@googlegroups.com
X-Received: by 2002:a05:6e02:3c87:b0:425:71bf:1148 with SMTP id e9e14a558f8ab-4259569078cmr284260115ab.30.1759200367955;
        Mon, 29 Sep 2025 19:46:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200367; cv=none;
        d=google.com; s=arc-20240605;
        b=EwNuxUgvhdQ4WRDHL01BQWdVq9M9HWdgVMigmB04uO1yJflkmU3gZFQUHKOC6UGTFZ
         52vj8rqtayEBl57XE6p4WAUshOVOWU4mXdQJ+UTzFxfIXrCSuHcdkrVn8bA1yEeDgIoo
         kZoKsXdXx3RpTJIJCgmdK3MpYC+E9oh5TPw01IFE1DiSIpBBp426UfyKMrglvXnPBD9c
         z+CL7mHrR+pfLO8RsWkWrnhx0I9WkZsil/mPYwO4JrovQqyRWDEO0m/Q5rzxXJtS0ZMt
         7cI8dl2YIxuOpMtUcuShPtNN2KETYDMUSBtsittnk1jbkxQv9ue4e21oYkAgyLy/IHr7
         Yo+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9bGi3tzoowdq7F8N73OupFeSpGLIzMxuMKRIXFA+k0I=;
        fh=J2ML91LPYikKgJYvoF5c1Q4WiU8xElRRFUUwr8L2hx8=;
        b=Vfzh7RUShbs51o8k2CH5H1JDd64N3O5208zLHuibBoh+Js8Ixo5EyVgmGPjP4nKOIo
         T+tG7nxM9rrnNzt7JZ76LSRcM67NKleiTYa23pBoSihdV07cnSZtYTJ7qwjlDPuE+lSa
         cZsEWon7dxIvwuLB0hqQ///bZ8ngNB/JS7TdhL/kCJGfkOGzLf2pqQymRkshZ23pSszz
         8SvQVlmPqD7i19kHIcrpi99Wpu6Rr0X91h2rQoihOX6XOMS7z8g+SrSFDXY4+HVr7qWC
         WIm99SV2bfvapg4KgkAbpU9JnPWdFcGL7Go/jIrL1/QM/EWn0FKMTZcwAXdfe5XW9ZMg
         ESsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Ln/0Y2oQ";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-573b57989fcsi167946173.3.2025.09.29.19.46.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:46:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b555ab7fabaso5234690a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:46:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVas/1F9n6oQEdUm8e4UJvoJKOUEcj61umI2/oE+5KBHc36LLxme0f7aK4++/ul5wWediq/DFnTl0Y=@googlegroups.com
X-Gm-Gg: ASbGncsHem4sPu0P78Y/fm61sdPXOK9kO/gFSRlmLj9BShvhDje/WmqHNJcHySVnLkF
	w48gTzZ5oiu+HXfQM8fp5JrP3Vzj70JdcvRCwlgj1MhaY3HooQUWfgDPHxGSv8S7A+EGxYvK5bu
	Vk4byNPzWpbb6q+F+r5xKNjeli7aWdcH5SuUuKO++iuLZS4jWQYsPq8PlcB5kv0stCpwbplOO04
	xvO0jJEAImBr6fCmu/ewr2JBlcM5SeaZFSCDSZRbFv1G7Ovd2MFLCbQ1HkSjBNGmHyFIAyhZmoM
	mfYyeKoflCUgvxhOKG5wBntIqVnhpEO2mPaXiO5u0VGdee8UaozVaqE7wdnuEoXVHByLErTQZs1
	xMqfgaxdA6IxBieh/ilYIXCut5xbtUT5oZmAEMsWoIr63mNOAeb+VhAKqsIVLShPVL1wkyInimj
	h1
X-Received: by 2002:a17:903:2ace:b0:268:f83a:835a with SMTP id d9443c01a7336-27ed4a64485mr174059075ad.60.1759200367052;
        Mon, 29 Sep 2025 19:46:07 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed6881fcasm144484295ad.93.2025.09.29.19.46.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:46:06 -0700 (PDT)
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
Subject: [PATCH v6 22/23] docs: add KStackWatch document
Date: Tue, 30 Sep 2025 10:43:43 +0800
Message-ID: <20250930024402.1043776-23-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Ln/0Y2oQ";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add documentation for KStackWatch under Documentation/.

It provides an overview, main features, usage details, configuration
parameters, and example scenarios with test cases. The document also
explains how to locate function offsets and interpret logs.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kstackwatch.rst | 314 ++++++++++++++++++++++++
 2 files changed, 315 insertions(+)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 65c54b27a60b..45eb828d9d65 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -31,6 +31,7 @@ Documentation/process/debugging/index.rst
    kcsan
    kfence
    kselftest
+   kstackwatch
    kunit/index
    ktap
    checkuapi
diff --git a/Documentation/dev-tools/kstackwatch.rst b/Documentation/dev-tools/kstackwatch.rst
new file mode 100644
index 000000000000..7100248bc130
--- /dev/null
+++ b/Documentation/dev-tools/kstackwatch.rst
@@ -0,0 +1,314 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+=================================
+Kernel Stack Watch (KStackWatch)
+=================================
+
+Overview
+========
+
+KStackWatch is a lightweight debugging tool designed to detect kernel stack
+corruption in real time. It installs a hardware breakpoint (watchpoint) at a
+function's specified offset using *kprobe.post_handler* and removes it in
+*fprobe.exit_handler*. This covers the full execution window and reports
+corruption immediately with time, location, and call stack.
+
+Main features:
+
+* Immediate and precise detection
+* Supports concurrent calls to the watched function
+* Lockless design, usable in any context
+* Depth filter for recursive calls
+* Minimal impact on reproducibility
+* Flexible configuration with key=val syntax
+
+Usage
+=====
+
+KStackWatch is configured through */sys/kernel/debug/kstackwatch/config* using a
+key=value format. Both long and short forms are supported. Writing an empty
+string disables the watch.
+
+.. code-block:: bash
+
+	# long form
+	echo func_name=? func_offset=? ... > /sys/kernel/debug/kstackwatch/config
+
+	# short form
+	echo fn=? fo=? ... > /sys/kernel/debug/kstackwatch/config
+
+	# disable
+	echo > /sys/kernel/debug/kstackwatch/config
+
+The func_name and the func_offset where the watchpoint should be placed must be
+known. This information can be obtained from *objdump* or other tools.
+
+Required parameters
+--------------------
+
++--------------+--------+-----------------------------------------+
+| Parameter    | Short  | Description                             |
++==============+========+=========================================+
+| func_name    | fn     | Name of the target function             |
++--------------+--------+-----------------------------------------+
+| func_offset  | fo     | Instruction pointer offset              |
++--------------+--------+-----------------------------------------+
+
+Optional parameters
+--------------------
+
+Default 0 and can be omitted.
+Both decimal and hexadecimal are supported.
+
++--------------+--------+------------------------------------------------+
+| Parameter    | Short  | Description                                    |
++==============+========+================================================+
+| depth        | dp     | Recursion depth filter                         |
++--------------+--------+------------------------------------------------+
+| max_watch    | mw     | Maximum number of concurrent watchpoints       |
+|              |        | (default 0, capped by available hardware       |
+|              |        | breakpoints)                                   |
++--------------+--------+------------------------------------------------+
+| sp_offset    | so     | Watching addr offset from stack pointer        |
++--------------+--------+------------------------------------------------+
+| watch_len    | wl     | Watch length in bytes (1, 2, 4, 8, or 0),      |
+|              |        | 0 means automatically watch the stack canary   |
+|              |        | and ignore the sp_offset parameter             |
++--------------+--------+------------------------------------------------+
+
+Workflow Example
+================
+
+Silent corruption
+-----------------
+
+Consider *test3* in *kstackwatch_test.sh*. Run it directly:
+
+.. code-block:: bash
+
+	echo test3 >/sys/kernel/debug/kstackwatch/test
+
+Sometimes, *test_mthread_victim()* may report as unhappy:
+
+.. code-block:: bash
+
+	[    7.807082] kstackwatch_test: victim[0][11]: unhappy buf[8]=0xabcdabcd
+
+Its source code is:
+
+.. code-block:: c
+
+	static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+	{
+		ulong buf[BUFFER_SIZE];
+
+		for (int j = 0; j < BUFFER_SIZE; j++)
+			buf[j] = 0xdeadbeef + seq_id;
+
+		if (start_ns)
+			silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+
+		for (int j = 0; j < BUFFER_SIZE; j++) {
+			if (buf[j] != (0xdeadbeef + seq_id)) {
+				pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
+					thread_id, seq_id, j, buf[j]);
+				return;
+			}
+		}
+
+		pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);
+	}
+
+From the source code, the report indicates buf[8] was unexpectedly modified,
+a case of silent corruption.
+
+Configuration
+-------------
+
+Since buf[8] is the corrupted variable, the following configuration shows
+how to use KStackWatch to detect its corruption.
+
+func_name
+~~~~~~~~~~~
+
+As seen, buf[8] is initialized and modified in *test_mthread_victim*\(\) ,
+which sets *func_name*.
+
+func_offset & sp_offset
+~~~~~~~~~~~~~~~~~~~~~~~~~
+The watchpoint should be set after the assignment and as close as
+possible, which sets *func_offset*.
+
+The watchpoint should be set to watch buf[8], which sets *sp_offset*.
+
+Use the objdump output to disassemble the function:
+
+.. code-block:: bash
+
+	objdump -S --disassemble=test_mthread_victim vmlinux
+
+A shortened output is:
+
+.. code-block:: text
+
+	static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+	{
+	ffffffff815cb4e0:       e8 5b 9b ca ff          call   ffffffff81275040 <__fentry__>
+	ffffffff815cb4e5:       55                      push   %rbp
+	ffffffff815cb4e6:       53                      push   %rbx
+	ffffffff815cb4e7:       48 81 ec 08 01 00 00    sub    $0x108,%rsp
+	ffffffff815cb4ee:       89 fd                   mov    %edi,%ebp
+	ffffffff815cb4f0:       89 f3                   mov    %esi,%ebx
+	ffffffff815cb4f2:       49 89 d0                mov    %rdx,%r8
+	ffffffff815cb4f5:       65 48 8b 05 0b cb 80    mov    %gs:0x280cb0b(%rip),%rax        # ffffffff83dd8008 <__stack_chk_guard>
+	ffffffff815cb4fc:       02
+	ffffffff815cb4fd:       48 89 84 24 00 01 00    mov    %rax,0x100(%rsp)
+	ffffffff815cb504:       00
+	ffffffff815cb505:       31 c0                   xor    %eax,%eax
+		ulong buf[BUFFER_SIZE];
+	ffffffff815cb507:       48 89 e2                mov    %rsp,%rdx
+	ffffffff815cb50a:       b9 20 00 00 00          mov    $0x20,%ecx
+	ffffffff815cb50f:       48 89 d7                mov    %rdx,%rdi
+	ffffffff815cb512:       f3 48 ab                rep stos %rax,%es:(%rdi)
+
+		for (int j = 0; j < BUFFER_SIZE; j++)
+	ffffffff815cb515:       eb 10                   jmp    ffffffff815cb527 <test_mthread_victim+0x47>
+			buf[j] = 0xdeadbeef + seq_id;
+	ffffffff815cb517:       8d 93 ef be ad de       lea    -0x21524111(%rbx),%edx
+	ffffffff815cb51d:       48 63 c8                movslq %eax,%rcx
+	ffffffff815cb520:       48 89 14 cc             mov    %rdx,(%rsp,%rcx,8)
+	ffffffff815cb524:       83 c0 01                add    $0x1,%eax
+	ffffffff815cb527:       83 f8 1f                cmp    $0x1f,%eax
+	ffffffff815cb52a:       7e eb                   jle    ffffffff815cb517 <test_mthread_victim+0x37>
+		if (start_ns)
+	ffffffff815cb52c:       4d 85 c0                test   %r8,%r8
+	ffffffff815cb52f:       75 21                   jne    ffffffff815cb552 <test_mthread_victim+0x72>
+			silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+	...
+	ffffffff815cb571:       48 8b 84 24 00 01 00    mov    0x100(%rsp),%rax
+	ffffffff815cb579:       65 48 2b 05 87 ca 80    sub    %gs:0x280ca87(%rip),%rax        # ffffffff83dd8008 <__stack_chk_guard>
+	...
+	ffffffff815cb5a1:       eb ce                   jmp    ffffffff815cb571 <test_mthread_victim+0x91>
+	}
+	ffffffff815cb5a3:       e8 d8 86 f1 00          call   ffffffff824e3c80 <__stack_chk_fail>
+
+
+func_offset
+^^^^^^^^^^^
+
+The function begins at ffffffff815cb4e0. The *buf* array is initialized in a loop.
+The instruction storing values into the array is at ffffffff815cb520, and the
+first instruction after the loop is at ffffffff815cb52c.
+
+Because KStackWatch uses *kprobe.post_handler*, the watchpoint can be
+set right after ffffffff815cb520. However, this will cause false positive
+because the watchpoint is active before buf[8] is assigned.
+
+An alternative is to place the watchpoint at ffffffff815cb52c, right
+after the loop. This avoids false positives but leaves a small window
+for false negatives.
+
+In this document, ffffffff815cb52c is chosen for cleaner logs. If false
+negatives are suspected, repeat the test to catch the corruption.
+
+The required offset is calculated from the function start:
+
+*func_offset* is 0x4c (ffffffff815cb52c - ffffffff815cb4e0).
+
+sp_offset
+^^^^^^^^^^^
+
+From the disassembly, the buf array is at the top of the stack,
+meaning buf == rsp. Therefore, buf[8] sits at rsp + 8 * sizeof(ulong) =
+rsp + 64. Thus, *sp_offset* is 64.
+
+Other parameters
+~~~~~~~~~~~~~~~~~~
+
+* *depth* is 0, as test_mthread_victim is not recursive
+* *max_watch* is 0 to use all available hwbps
+* *watch_len* is 8, the size of a ulong on x86_64
+
+Parameters with a value of 0 can be omitted as defaults.
+
+Configure the watch:
+
+.. code-block:: bash
+
+	echo "fn=test_mthread_victim fo=0x4c so=64 wl=8" > /sys/kernel/debug/kstackwatch/config
+
+Now rerun the test:
+
+.. code-block:: bash
+
+	echo test3 >/sys/kernel/debug/kstackwatch/test
+
+The dmesg log shows:
+
+.. code-block:: text
+
+	[    7.607074] kstackwatch: ========== KStackWatch: Caught stack corruption =======
+	[    7.607077] kstackwatch: config fn=test_mthread_victim fo=0x4c so=64 wl=8
+	[    7.607080] CPU: 2 UID: 0 PID: 347 Comm: corrupting Not tainted 6.17.0-rc7-00022-g90270f3db80a-dirty #509 PREEMPT(voluntary)
+	[    7.607083] Call Trace:
+	[    7.607084]  <#DB>
+	[    7.607085]  dump_stack_lvl+0x66/0xa0
+	[    7.607091]  ksw_watch_handler.part.0+0x2b/0x60
+	[    7.607094]  ksw_watch_handler+0xba/0xd0
+	[    7.607095]  ? test_mthread_corrupting+0x48/0xd0
+	[    7.607097]  ? kthread+0x10d/0x210
+	[    7.607099]  ? ret_from_fork+0x187/0x1e0
+	[    7.607102]  ? ret_from_fork_asm+0x1a/0x30
+	[    7.607105]  __perf_event_overflow+0x154/0x570
+	[    7.607108]  perf_bp_event+0xb4/0xc0
+	[    7.607112]  ? look_up_lock_class+0x59/0x150
+	[    7.607115]  hw_breakpoint_exceptions_notify+0xf7/0x110
+	[    7.607117]  notifier_call_chain+0x44/0x110
+	[    7.607119]  atomic_notifier_call_chain+0x5f/0x110
+	[    7.607121]  notify_die+0x4c/0xb0
+	[    7.607123]  exc_debug_kernel+0xaf/0x170
+	[    7.607126]  asm_exc_debug+0x1e/0x40
+	[    7.607127] RIP: 0010:test_mthread_corrupting+0x48/0xd0
+	[    7.607129] Code: c7 80 0a 24 83 e8 48 f1 f1 00 48 85 c0 74 dd eb 30 bb 00 00 00 00 eb 59 48 63 c2 48 c1 e0 03 48 03 03 be cd ab cd ab 48 89 30 <83> c2 01 b8 20 00 00 00 29 c8 39 d0 7f e0 48 8d 7b 10 e8 d1 86 d4
+	[    7.607130] RSP: 0018:ffffc90000acfee0 EFLAGS: 00000286
+	[    7.607132] RAX: ffffc90000a13de8 RBX: ffff888102d57580 RCX: 0000000000000008
+	[    7.607132] RDX: 0000000000000008 RSI: 00000000abcdabcd RDI: ffffc90000acfe00
+	[    7.607133] RBP: ffff8881085bc800 R08: 0000000000000001 R09: 0000000000000000
+	[    7.607133] R10: 0000000000000001 R11: 0000000000000000 R12: ffff888105398000
+	[    7.607134] R13: ffff8881085bc800 R14: ffffffff815cb660 R15: 0000000000000000
+	[    7.607134]  ? __pfx_test_mthread_corrupting+0x10/0x10
+	[    7.607137]  </#DB>
+	[    7.607138]  <TASK>
+	[    7.607138]  kthread+0x10d/0x210
+	[    7.607140]  ? __pfx_kthread+0x10/0x10
+	[    7.607141]  ret_from_fork+0x187/0x1e0
+	[    7.607143]  ? __pfx_kthread+0x10/0x10
+	[    7.607144]  ret_from_fork_asm+0x1a/0x30
+	[    7.607147]  </TASK>
+	[    7.607147] kstackwatch: =================== KStackWatch End ===================
+	[    7.807082] kstackwatch_test: victim[0][11]: unhappy buf[8]=0xabcdabcd
+
+The line ``RIP: 0010:test_mthread_corrupting+0x48/0xd0`` shows the exact
+location where the corruption occurred. Now that the ``corrupting()`` function has
+been identified, it is straightforward to trace back to ``buggy()`` and fix the bug.
+
+
+More usage examples and corruption scenarios are provided in
+``kstackwatch_test.sh`` and ``mm/kstackwatch/test.c``.
+
+Limitations
+===========
+
+* Limited by available hardware breakpoints
+* Only one function can be watched at a time
+* Canary search limited to 128 * sizeof(ulong) from the current stack
+  pointer. This is sufficient for most cases, but has three limitations:
+
+  - If the stack frame is larger, the search may fail.
+  - If the function does not have a canary, the search may fail.
+  - If stack memory occasionally contains the same value as the canary,
+    it may be incorrectly matched.
+
+  In these cases, the user can provide the canary location using
+  ``sp_offset``, or treat any memory in the function prologue
+  as the canary.
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-23-wangjinchao600%40gmail.com.
