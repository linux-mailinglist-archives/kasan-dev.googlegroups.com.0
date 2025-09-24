Return-Path: <kasan-dev+bncBD53XBUFWQDBB4V2Z7DAMGQEIEE3DDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 448AFB99B7D
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:00:52 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-746b28ff4c5sf30610417b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:00:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715251; cv=pass;
        d=google.com; s=arc-20240605;
        b=DgjHIXU4LTQEnraBtnVc8RsBD1W2hzHRbpRhMZmSzYpri2mFy3b1h8Ds66Swhyy8E4
         hnNSWiIF9vqJXTwRND4KxkksB4ExWfZF68GEdP8Mc7FZ6SWUaSbhRhpYCzgQGfaN2KJR
         UeIt6FcqOyZU3kEhQr6CHETOTQqp4Ou9DQPXR1WotX5grsAkuNtxivKf8hBZnBjWrS38
         Q8kQPKJBUimps4SbrXv9EKIRFYVolxYUaX7jPGulFNsuIjike8/qZJ3ti9j2O906GeMb
         10K67eLbE9mW/7Yfd0vNyMRw9GTAjgPWBXzOHK3cSUchj96TKXxf+BLBgqvqqd9cphcq
         lhfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=54hU7NFD1ywApfGwk1NNW9ErEKMHa8hQbNVch7OyxaI=;
        fh=jo48Xh+71rOGyIv+CJXZonUZISx0+lHz/7V1WKhH8ek=;
        b=ZBaPlNN8+tM1rL35SQLZrxjnaSoiinCsxwnj0PVgwMkdAt4FH1AXO0QtuxJuL21AtY
         qJkVxeHbLPR2J2Ly2oFqzVWQ69fLLts+ljfds1UqQsKJdSS3i/Psm+0EhpEZ6qvFPzpN
         PijpS+jQbWXugS1s62vd+3KM9jOUXoBahiX+JoBEn+MOU570Gj/WNpg+/cq9PNGStx7V
         C7ntm60QcXGYLbraLEInwAWX1XwRhRO3GPRxtJjPSRaZCqxUaSF/CdnGVvRY8I/YqOMF
         kZZLNjIVhQUNR5o89Z4hAiFzocXS8W1SSPV7X8J1spW6//QuqKxL7mpcDvFC99j9DClH
         xsrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RqXC85AZ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715251; x=1759320051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=54hU7NFD1ywApfGwk1NNW9ErEKMHa8hQbNVch7OyxaI=;
        b=KiycOtlyBvoL3eAL8Yn9PDlPH1QqQVUFkjG8Q4ENjQEm4qT9TMxQ0N1RZqXksD4ez6
         h9QhsXiBCkdsl6Hs/M7x7Md7OCj86aJ9pqtcCZRrb4h775VgCmW3KvjvZOjd6sdvf7J3
         86l+Do77HdYoFpSiM8RkRdYdKuju1mVt497FAwTSk8KSvFAeKdU2IdpGH9Spgao+g8px
         D5/j70+Ht4MQhk5Ax4jPL8/41UDgRPYR4jSpGKfAMr/Zxn7E3nDwayitXWIevqB3vDY7
         ogkhQc1h8VcxFMxMWy/BRsKG9Wp1qPqUQIiV/qn0WueSw4bNNr9eIxRB2jN+k1XeOtZq
         zc2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715251; x=1759320051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=54hU7NFD1ywApfGwk1NNW9ErEKMHa8hQbNVch7OyxaI=;
        b=Y5cOuPiwdxNqSJitxXY6pfNw9u92frACemlpJGLO2h0xL33u8oOEgTVDjldCCA0cRP
         23YU2IudHxJGFiHSksR+yS61N8+lFW/2Ocx2xtzLc+5LdlyNvBSjGFD+3zOR/HU7PPIq
         oDcCXMP71f3tCVXyzPyjB/0ks4uDG9eiDdRuUQR7D/uabfgjK2qQwOAuo3EqhMz1GXYk
         tJYuv3DRb2XrTxRmtq4CIME1S8vnmasOmPYIVCB9pPM11lTg1bsiI3G/eQS0GV7TtyM5
         wgiUid1JNgFIdk1NHuwgVZ9aLrZAEGK9URK+xV0IpkeeIZixPxNMQt32+k2vkSMaPkSY
         tgHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715251; x=1759320051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=54hU7NFD1ywApfGwk1NNW9ErEKMHa8hQbNVch7OyxaI=;
        b=gnRilPjqskRDH/B8kes7tce7oQa3BGusmCUb0JVXI7i4wpiztFirwI8w78nR32js4Z
         uHhaTjRzZGELs2qyaLLILQdKTm4FddfUtJsylXI1meNjZjvu9Jpe5F18vjQpgrVoxqAH
         4Am+0xJyXyeLT+Jg8heveLN++D56VGbjJTkV0CdvlLz9meU3sMAWW525olWLc1ZCuh4Q
         kJrLu0CNmUMGHtFNiKkV5mM6Fgh3D+UgmMZqt/GTuyLopqj7I0EqgX3D1xkNJjLhjavd
         M/LSzmoYugOz+G3igbfDvYe7SuZwj74ZGQ3o1SFMFs2KPXM8uDJDQafsUe47vIrNRFck
         gZaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVr0EUNXLyqilxAiEoivfcp6fYzpM/5O7CFYpJ74dsH6/3Ilgnl53M9HP38dE6qpOZl8jG3OQ==@lfdr.de
X-Gm-Message-State: AOJu0YyxIhFq7Z5cEwcAXQKrQOQh/sxCAD2nyPEb4f5TF2OzknX23QCS
	bWE+VlZ3ZQ9s0CjN2y/19i9ddDJPliRxEJnTn15H2wvQg10Jetuc7M4r
X-Google-Smtp-Source: AGHT+IH70z5u1GkpDlqcJ8u6sh2hCtlSPgS84S80D6webVcYveyg/OyvKwdlFyHJ4lnzBq+ogt7cAw==
X-Received: by 2002:a05:690c:d96:b0:745:17a6:83c8 with SMTP id 00721157ae682-758a6abe427mr48077397b3.44.1758715250840;
        Wed, 24 Sep 2025 05:00:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5H68RBEN9tCxkG0+9u2bdL1H0v0c8G0ES+C64bvMDEQQ==
Received: by 2002:a05:690e:15c2:b0:625:bcff:51d7 with SMTP id
 956f58d0204a3-633be1026b1ls2620195d50.2.-pod-prod-07-us; Wed, 24 Sep 2025
 05:00:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1a1/OUh595UY7iVkOJiuhCQgPn4UK2Fn/O2000UCUHVhrEMiCeIlj2zXjDM9hDAeO8Fa6VkI7DiU=@googlegroups.com
X-Received: by 2002:a05:690e:4308:b0:635:4ed0:5718 with SMTP id 956f58d0204a3-63604665e51mr3126630d50.50.1758715249326;
        Wed, 24 Sep 2025 05:00:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715249; cv=none;
        d=google.com; s=arc-20240605;
        b=ODpcftbUg70YDRw4Y41QgCp/VK4tB5x/lg/AxNB0EfS3O0bk39Cn31v35VagIs3gh8
         gytpZ/NsOn4c0mX1rHbKDjb9QCbijxjDnmwk3l7aiQkLI67lxptYTO1JJarz3ho9rRi7
         E7kw7PFmpkZqdWJS6XyDdFVi9zjNLe6iV2j0ttCbtU1wAx7c/aVWPImTbP5+ln4lRlIr
         QvLJZhFDgt5XQJE4xjP5MJDe/VRZCMTaR1fi6FFNWzc0kYAoOq5vqaJaL0ipaHkEhYS1
         rNbhnzjogeL7WLWcMN5sq+J2JpcUGnDTf7VvpfJbRCJCJQZGFoVwsiSg/rmYt5zapFoR
         mdYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l3XGYZ1mTVo1cX+yb2z67UYPJCwM1YcVlAKDPd0GQ2Q=;
        fh=YDvK5c9x4oDsY650YsOpQKizq3qF9iOCahBSsWN7jTc=;
        b=XDqIN7mv8oKMoJEeQ3RQEqZuoXvkYUQOJceIhN2r2BlCB1RSrZu8q4xUa9rq8f6ASZ
         jVN00wO2h0fQsKqsvhFeYbP7udNtxF0El+99+KdZ8Mh8P470dE6sAShmzntCGM7krmi/
         BY8CSutXAqoIIN75DOXlbqVJ+4SUGcKwkU1xZzOw9416ilXmkMk8fC/zt1I4vdfL0c+I
         RmcVwc8BPHxteUxTOXv65o7ONm4W5nnRwC5C0YQGrRutx/kh7FnRwy1pYsFL7NIQw4Wh
         Nq+lhxU2uSE2wZIWTEsWLQdZfI0SHzZ7dLLO9aNyKcmHL129qxRxbZO6UIeznfe52yQp
         wE9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RqXC85AZ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-762ff1394efsi62267b3.1.2025.09.24.05.00.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-77f3405c38aso2988615b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZPO7Z/lrC0QA5+IOUxfDCkV5nNMEVsJFTyTYKE6eEv6W9gtNPVNCC2H8vlGbAuc5QnCFx+ZbOyfE=@googlegroups.com
X-Gm-Gg: ASbGnctyjuN0dx6M1eY7U0queKCxt2rvNai7DZCqZb1xy16Vr92XQPSAlsm7Rq2UqAW
	fzMbjZ8QBIB7ExlgWRmsCx+STtgfgoL9n8E9ZTiHYSZypwxE8X3u5OH/vEcq8yFgn/+FwB+ztVb
	pHeVHxFpbM+qV2UDXX1r54H8bxkvJb8CwwrZaYb5sUVYax4tNqLvoOGYGg3T+c98vb4OtESzLiR
	a5/04PBuvG4vahR47aSR8yPmMmyzAy43tLCx1jCvrQ11WQxsN8ZKsKY4eP0xpBwAbofwDd375BK
	FSyImoo0+ifAkeqnuErrZzxbcJHMwD+W0sGs3Z3fFMQ/W5GvpLZxD9Dx5qZeS2C/tU+zCgEDWQw
	QwWg6oytA8Z2fZIhQQa6Hydc=
X-Received: by 2002:a17:902:d113:b0:269:82a5:f9e9 with SMTP id d9443c01a7336-27cc79cb20bmr41740315ad.29.1758715248144;
        Wed, 24 Sep 2025 05:00:48 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ec0d14344sm19610475ad.126.2025.09.24.05.00.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:47 -0700 (PDT)
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
Subject: [PATCH v5 21/23] tools/ksw: add test script
Date: Wed, 24 Sep 2025 19:59:27 +0800
Message-ID: <20250924115931.197077-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RqXC85AZ;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide a shell script to trigger test cases.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 tools/kstackwatch/kstackwatch_test.sh | 52 +++++++++++++++++++++++++++
 1 file changed, 52 insertions(+)
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

diff --git a/tools/kstackwatch/kstackwatch_test.sh b/tools/kstackwatch/kstackwatch_test.sh
new file mode 100755
index 000000000000..aede35dcb8b6
--- /dev/null
+++ b/tools/kstackwatch/kstackwatch_test.sh
@@ -0,0 +1,52 @@
+#!/bin/bash
+# SPDX-License-Identifier: GPL-2.0
+
+echo "IMPORTANT: Before running, make sure you have updated the config values!"
+
+usage() {
+	echo "Usage: $0 [0-5]"
+	echo "  0  - test watch fire"
+	echo "  1  - test canary overflow"
+	echo "  2  - test recursive depth"
+	echo "  3  - test silent corruption"
+	echo "  4  - test multi-threaded silent corruption"
+	echo "  5  - test multi-threaded overflow"
+}
+
+run_test() {
+	local test_num=$1
+	case "$test_num" in
+	0) echo fn=test_watch_fire fo=0x29 wl=8 >/proc/kstackwatch
+	   echo test0 > /proc/kstackwatch_test
+	   ;;
+	1) echo fn=test_canary_overflow fo=0x14 >/proc/kstackwatch
+	   echo test1 >/proc/kstackwatch_test
+	   ;;
+	2) echo fn=test_recursive_depth fo=0x2f dp=3 wl=8 so=0 >/proc/kstackwatch
+	   echo test2 >/proc/kstackwatch_test
+	   ;;
+	3) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/proc/kstackwatch
+	   echo test3 >/proc/kstackwatch_test
+	   ;;
+	4) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/proc/kstackwatch
+	   echo test4 >/proc/kstackwatch_test
+	   ;;
+	5) echo fn=test_mthread_buggy fo=0x16 so=0x100 wl=8 >/proc/kstackwatch
+	   echo test5 >/proc/kstackwatch_test
+	   ;;
+	*) usage
+	   exit 1 ;;
+	esac
+	# Reset watch after test
+	echo >/proc/kstackwatch
+}
+
+# Check root and module
+[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1
+for f in /proc/kstackwatch /proc/kstackwatch_test; do
+	[ ! -f "$f" ] && echo "$f not found" && exit 1
+done
+
+# Run
+[ -z "$1" ] && { usage; exit 0; }
+run_test "$1"
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-6-wangjinchao600%40gmail.com.
