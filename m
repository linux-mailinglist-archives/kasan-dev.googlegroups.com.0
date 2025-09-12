Return-Path: <kasan-dev+bncBD53XBUFWQDBBVHER7DAMGQEGGY7ZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BC46B54904
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:42 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-718c2590e94sf62658796d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672021; cv=pass;
        d=google.com; s=arc-20240605;
        b=lGt58hBOpVRCer+rwz6YFFIdMvqTR/YUU3srD1gb8AEjEU1uD/Ruxb7EnQICmHW33O
         XTN0wY1+Fb9vI/CKAUgFRIyllxntgEZikPvJQRh6cdoiEgHIPTyN6Cn+rkZQtE75ppI0
         h8sXf0wG4z90S2sJNeCl6QVLSzfRbgEIYeZM0VZ7jsIvIsncL4hqwTmBqLklr+n+0ic7
         7nGs36FBvw4E+MMYoSw1dSuDnJw3yUieqDSgaKpYqaWNJH1q/5hrlXi/FlPgZQsfJcDv
         WrOwvncE0V8LbvaDQDprs+CyLFLULdBax75Tohp9479qcsBO9tHQAXQLJJ3C6+bRwOHy
         1bRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=pnnBhHiDiOQfgX/hn3beXQb6ZCVZrdhJbOtOQ56I8AQ=;
        fh=dg/vMAHrjl5YCYotTxF5M4lW8SmDZPOAuRT1uJrLqBI=;
        b=SKea0LAbz9TxpdxGGle0bpS4cnlDKBuUXcy7bBHVHKh8vIX9zY2EARcUWijfeLTGdC
         rMxLIC2CrzdIVm/A7pu++PBN4FR8hzEgjUnOoBNdEnQbkhnXnZq5uP58mLbFBnOdqUM0
         Dkc85V69TqEzrFziNPkjXKBle0mcWd3EUs1RCJXe/Ft1G4Ydd1NO+QCGrauzbZeQeSGJ
         5/XAfD28XpSLsAZLyaqSqLBbB92CY8Ie1E8wqNEaiqwu9Dr/aQqmI6QGj67Pp3Q20e/M
         xK6BQSyoPfYdfLiaS+Z8Iw6UzXnqcvfY515P+TxURXUnYGX3OWt/Qf8OhAG0JUA3u/ZE
         aRfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YGNaVxWt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672021; x=1758276821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pnnBhHiDiOQfgX/hn3beXQb6ZCVZrdhJbOtOQ56I8AQ=;
        b=CGWkNo75XJbrWmSfgJ4PfTBtspUeJffNpgEdN8zKNE8xEYuiY0PNMbtJNaw+BnmR1O
         gvPMhpE9nckA0F4GqWIferPz4URiZq2mF+zWx/W+ZNt2J0UZ0gasiDqvLe8XhAYLRp5L
         D8ePj/hMLwzD0RSNNxwoyJvnTLRnUilb4G3JuEwxOMsPKM6LdP4zPFSP+4yNG9sWHU37
         aYE0jCdKLILhOVoh+P3N2DAl/RKkhaXmKTimduo2iDIbW3prsS43kjBZQRi1z1N7cI3P
         j4C7pRY/47QKG3ToG8IbsM2+Qw/8k2dA6kJOx0oyqKFQ+YiVE074f/OJC+ut10/tTB06
         pAOw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757672021; x=1758276821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=pnnBhHiDiOQfgX/hn3beXQb6ZCVZrdhJbOtOQ56I8AQ=;
        b=V5vLSiv0Lr06B5jZibfOixQd9kQ29kSkgdOn4MwwhJAzZ1Bn5b6CapmwZzpxatMBdb
         24bAU7NkWIuGMirBu1kLy9f5Srj6yHT/0XTCOcvNPpVloFrx33EpQvla7QFx/yChYdd4
         xCt6NJSB6usadCdp5OMkvepndqIYKcnnuQMhNmdmBVL0cmfIFvgq3Z564+FJom2aM2kG
         268PkzEWxvhsTZWcZ0CsRPbWU9tBxnguLFsBAqfKIetnZN37HDguB4DWaVtJOdlShggD
         C2ybEnnR4H9j24pCIwaAKI/MgX6gtLc12ZunaQw8sguQcVaT/XdktZS1InFwVtfYrfm/
         4aJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672021; x=1758276821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pnnBhHiDiOQfgX/hn3beXQb6ZCVZrdhJbOtOQ56I8AQ=;
        b=W9e/m2/cbTKuRvSyekG62dPlkE5R3ANadILfl6bT7TMYyxGnmqxoPb7isl/EKnxm++
         d7hw/6/5wlyReabQZ4MVJe8QY2g0nbtf6xbyAUpDqDM6vHR6BbhBP59BmOQXckQ3RG/G
         onuHs/PnuG1DxrEAvHx4TygvstvPmZEhhyMJGoo6WztfSJef/imoTpZy4YI8f7FTgeLJ
         zy649iLvhw3aQWeHGfvDXR2WQoQeY7CdQWB1pYzdq8cMYiobD72icS3nIpRZf5NOB5kh
         Q+dCv4Cn96nehINx0JpqoxpiNzgGjQA01DyL0r9vF4QxPVeSO/hnbj+KJqCC706o9Vuo
         rrXQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsEP9wZ4KBkKwgITVOdSAADYnmWw0Htu6Qm91rRJPnmRdwQLLMvVhoS133a2Th5uM2LdXKSg==@lfdr.de
X-Gm-Message-State: AOJu0YzoW7RDr8Qc2xQSFiB8KX/wGe1QvxUfJfd6V+NhRiGQNjhAIWdB
	4/KAZ4Fdd7EF2viyJWGYCP24bF//fqShyzIoHTevMMgx0aVrUZedb7Kf
X-Google-Smtp-Source: AGHT+IEYoh5uEV72HpPWEFWOQ8WkrfW93A4fYG/SSpm4SHBGAMgyPDGaIX/zS9ItaPVA3eUq8UmrIw==
X-Received: by 2002:ad4:5d64:0:b0:720:e4bd:d3f3 with SMTP id 6a1803df08f44-767c0e2a58dmr23547186d6.26.1757672020816;
        Fri, 12 Sep 2025 03:13:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7odMt+wM2ABPdWG5/x4JhnrvLFux2ytoQBXJJlXG9uUw==
Received: by 2002:a05:6214:8085:b0:73c:41e2:c5f7 with SMTP id
 6a1803df08f44-75cdd9360cbls23359486d6.0.-pod-prod-00-us-canary; Fri, 12 Sep
 2025 03:13:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxFRvV73urol0+suiE+nwjizqf22a0QOWe/VGaieOm93oAur7ATmorauLRgH5imF2PvREZNaJl5Y8=@googlegroups.com
X-Received: by 2002:a05:6214:528f:b0:719:c4fe:292 with SMTP id 6a1803df08f44-767c0e2a209mr26414126d6.27.1757672019608;
        Fri, 12 Sep 2025 03:13:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757672019; cv=none;
        d=google.com; s=arc-20240605;
        b=MBNUehFvVksIJQCJb5w4W3ggDequNtZDmN9DS9nsIkUrEOZ5mmmqYLXbVNExM0TugX
         lnC8CToRm16ESjUeBYelmrzZOjr8U/5A8BNfC3pIDZpo+m/DmEkOMP3qwz8VNKYmxhrS
         Qfwd8fxPgZVovWCr8DZGvnLl88oD7RRWOYSooj0MdscFAB5f4C5H+6O4qJ9xJbvosv21
         C9ul9yv1QaRyLiYJJA/YHYw1yKiF4/gAvcwul/LbVT551GuFp86v8vJyHZBDYaPktd/X
         BZmN7iEEOkhTvLMU7TWEEr7oElsIt4u/XodJry+wK2JdadvVTDXzh0kH+EYe4DOnUeir
         go9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bn+/3FE5CmsLxOS0M5YahrLvDpar54OOYFHjkWGVE7o=;
        fh=wtGSoy3q/7IMxV2eVO9BEyyyrORLfy0oAhA13PC5T8s=;
        b=KvYFPb9BaxHh3EHnOdcdEwY3JGLROtZH3cMX1nFCtZK4g+qna7AmGpYmCoAovWZaTN
         dt7JaEGVWiqz9C7lIzAlVY3sPvk9LXQXb+2v73ns7QhfyId9tyUbxwDfcI0RsLv7Gzmo
         0q2IbxhwbIDarZHkhTYJHQswuWcZh0RtGPiFXyTXELYrOtsZJBU0BIYWwSpvOLPVz8hb
         mBYg0hsa4WYiy28zY/7O6kmYTGjumW9tz7HNXdSvc7PI0YxG6A2xFeAOCUp4VcCwYoW9
         CWFb4oCPOAxP04Z8dvKrxcAKHZLUV5j02LjGEGJZIaxBLNUtl06eV2ZXMGLtBsm1y4of
         i72A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YGNaVxWt;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763b97136c0si1772396d6.3.2025.09.12.03.13.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-25221fa3c9bso21540265ad.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWRRLrw2vekv2Do0bLL3HztxftEfAN4GJ8f7SYo+rzntfnVJPdT4gvdiuaGXM/BflT7c/4LzmEEdhU=@googlegroups.com
X-Gm-Gg: ASbGncuOSxbTy+2DgwrLTlG8yrbfzL6/oJiyTvjjB/EK3pWtLsVIOWGsehk5aNvyD1v
	eW5qySqcFq3txMNmx3XPm9amNvDSo/86OdStnf6tmSI0bqI8S7mJVWMLgE0XRLDXw4yNUptuYyI
	Yj7y9tVQSCn/aWACcO8LgBZpdamGsZ290WdVMpl5Lk1j9/gDZ3Bb8f8eNcDchaRbnqJLqledSVb
	xb9oBEQGrukLtpqUftwxAsl8KHP5W2iqn4pzAJJmEYtC60S1WMi3DDnAAc2NosAiVgfEse7OObC
	mvPiv8n2MyOr0EzjtfDy89FYnpkVJe18lI6oHw9mfNsg6Ub6LgioFGX3dTdBoKcTROIOBVEZpKk
	HH06w/MqzSfS9d7mtcVJqqWJ3PQrVA/n+LxhEGYPy9++Dm9SUrgnged7r
X-Received: by 2002:a17:902:ef46:b0:246:571:4b51 with SMTP id d9443c01a7336-25d2da1100dmr32684915ad.29.1757672018598;
        Fri, 12 Sep 2025 03:13:38 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c37293f0asm45182095ad.43.2025.09.12.03.13.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:37 -0700 (PDT)
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
Subject: [PATCH v4 20/21] docs: add KStackWatch document
Date: Fri, 12 Sep 2025 18:11:30 +0800
Message-ID: <20250912101145.465708-21-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YGNaVxWt;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a new documentation file for KStackWatch, explaining its purpose,
motivation, key features, configuration format, module parameters,
implementation notes, limitations, and testing instructions.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 Documentation/dev-tools/kstackwatch.rst | 94 +++++++++++++++++++++++++
 1 file changed, 94 insertions(+)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst

diff --git a/Documentation/dev-tools/kstackwatch.rst b/Documentation/dev-tools/kstackwatch.rst
new file mode 100644
index 000000000000..f741de08ca56
--- /dev/null
+++ b/Documentation/dev-tools/kstackwatch.rst
@@ -0,0 +1,94 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+====================================
+KStackWatch: Kernel Stack Watch
+====================================
+
+Overview
+========
+KStackWatch is a lightweight debugging tool designed to detect
+kernel stack corruption in real time. It helps developers capture the
+moment corruption occurs, rather than only observing a later crash.
+
+Motivation
+==========
+Stack corruption may originate in one function but manifest much later
+with no direct call trace linking the two. This makes such issues
+extremely difficult to diagnose. KStackWatch addresses this by combining
+hardware breakpoints with kprobe and fprobe instrumentation, monitoring
+stack canaries or local variables at the point of corruption.
+
+Key Features
+============
+- Lightweight overhead:
+   Minimal runtime cost, preserving bug reproducibility.
+- Real-time detection:
+  Detect stack corruption immediately.
+- Flexible configuration:
+  Control via a procfs interface.
+- Depth filtering:
+  Optional recursion depth tracking per task.
+
+Configuration
+=============
+The control file is created at::
+
+  /proc/kstackwatch
+
+To configure, write a string in the following format::
+
+  function+ip_offset[+depth] [local_var_offset:local_var_len]
+    - function         : name of the target function
+    - ip_offset        : instruction pointer offset within the function
+    - depth            : recursion depth to watch, starting from 0
+    - local_var_offset : offset from the stack pointer at function+ip_offset
+    - local_var_len    : length of the local variable(1,2,4,8)
+
+Fields
+------
+- ``function``:
+  Name of the target function to watch.
+- ``ip_offset``:
+  Instruction pointer offset within the function.
+- ``depth`` (optional):
+  Maximum recursion depth for the watch.
+- ``local_var_offset:local_var_len`` (optional):
+  A region of a local variable to monitor, relative to the stack pointer.
+  If not given, KStackWatch monitors the stack canary by default.
+
+Examples
+--------
+1. Watch the canary at the entry of ``canary_test_write``::
+
+     echo 'canary_test_write+0x12' > /proc/kstackwatch
+
+2. Watch a local variable of 8 bytes at offset 0 in
+   ``silent_corruption_victim``::
+
+     echo 'silent_corruption_victim+0x7f 0:8' > /proc/kstackwatch
+
+Module Parameters
+=================
+``panic_on_catch`` (bool)
+  - If true, trigger a kernel panic immediately on detecting stack
+    corruption.
+  - Default is false (log a message only).
+
+Implementation Notes
+====================
+- Hardware breakpoints are preallocated at watch start.
+- Function exit is monitored using ``fprobe``.
+- Per-task depth tracking is used to handle recursion across scheduling.
+- The procfs interface allows dynamic reconfiguration at runtime.
+- Active state is cleared before applying new settings.
+
+Limitations
+===========
+- Only one active watch can be configured at a time (singleton).
+- Local variable offset and size must be known in advance.
+
+Testing
+=======
+KStackWatch includes a companion test module (`kstackwatch_test`) and
+a helper script (`kstackwatch_test.sh`) to exercise different stack
+corruption scenarios:
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-21-wangjinchao600%40gmail.com.
