Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6CTTYQKGQET34Z7XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B346144186
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:05:28 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id i24sf997394lfj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:05:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579622727; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZEIQom9FkSje2GzRv2e4K0VzsnVYFgd24fTEZMad3X/onLIW6d0bIttcfqCgjQ/MMk
         xm33jnYWuwCJULXEyvQlRfq7tfW62KTHtxRFu7aSqBa8xIFoWMXwejl5n5mGW5F38kRb
         UfDRE2ulAEAss2gqV0/+HtIFQUXICV+3/3nNjYEIwv9hzysi1WxFapIBGS+7nKIb+Vtd
         awRd3H+sJZWuWWsWN6wF4+WAxABdTHzebLWnlkHaOP1cgzeTJp0z89Kv9FZSTO0+Yxlv
         /EfsD+5By6s8/9n4bnzyRizIb8rhe8NdIw9IpLAK5Iel3yp68wN17TCYrpgfzI1mS7vV
         pZsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=wNO1KVYVsgcEZjCVvJSx3c6ssE/GM6kFQRErcz3i7y8=;
        b=leLSjm+2t1j+lKtE0NFRvYGkfIKxZ7A+S3Vs2IccftBza5Cj+aoRYWsyMTBRS8BBY6
         PAPshoYAOaiYWR1vqrA5NWgBStBBtXyz6xARWHYtnP2hOkzXiHq1E07o5H3IbZQzEXNF
         yQZnkzaj686Y9NbJzBgQGjWr2DikJcIZZ7cfWHpEri/Nr0fuGB1XtKCbUsOhEIvYAApu
         n8ZFELVnPUsXxBSUvOrhwOCM/v7mF5zAbd/RggNn9IwmZAiFqukLrc72qcw6BWqb6Iwt
         tBFK/t0eTaPKM9FLiAhi47QWi+/5fQfCpQE7LcfYQ9TuuLPWkwmw5lIptbXNYf2t1c7c
         qs7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FBbFhbGM;
       spf=pass (google.com: domain of 3rsenxgukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RSEnXgUKCRw6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wNO1KVYVsgcEZjCVvJSx3c6ssE/GM6kFQRErcz3i7y8=;
        b=O5OTWk71oeGZdsotCmDhr8+yzcsQ9fNqc0Tytzu5LxXgi6oejerKALf7mXeRssTeBJ
         ZegxwgUDUc/9CD53wuEzdaPv8DwCrP1qJwfP2MoxlsAImlkHg86jZ6NlEyzbdRCIfIPj
         Gndc+aiG4ptjTwBky0v99aOh1BiXVFPNnoUNYjplMwYHjwGye1wyLauXVNVIoxIQ7iwu
         fhSuU31jTFMu2xEJ4RbJxwZRLlPO9ytUPnKkUt2It1J2SMAlwjt4N9BXNYdZLRB1AvIz
         z/ScaCYlEQtEzYUUV8LP7GYg2Oq+7vUyzJH/uH7OZKUZK4VVoC2HxU3lrs4v5fueFHzO
         zT6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wNO1KVYVsgcEZjCVvJSx3c6ssE/GM6kFQRErcz3i7y8=;
        b=gLL4e7ZpYRouEb1sSk1kt5sS0dn+D0k6x+BkphVRVv/oDuo2mVSw+yStAvjsEdwd70
         1EUahMypxy1rZ5NNJ0gmf21PWKeCxytdwoaAPTL3UW0TiAuhU5jwWXp0dDkBb8inNLyN
         VFNO0Nu9NGzKnG4SCMG7YO6U6plS0jqSTDjmE15ft45vaiFCfBl/kG7qZutNUno0kNQR
         1ghBT5Ts89bn8MxQaxFol/K0HUtOCoopeJtWdq7gy0edlQlFsk2qQyUPzadsg9bXVbIZ
         xY6dkEa2+lKJSebLw4exNF4BapFunTBNldYF9yGOGILu0EN4Vs+rjjcN6QtAZR18oPm9
         NQ6w==
X-Gm-Message-State: APjAAAVkSDUBgz0TxVFVtxgzDZWZ0007wN6Z0x5jpiohkZGjxBjsUvP5
	SqMuX2dEf64VyVJoqiO2WpU=
X-Google-Smtp-Source: APXvYqwG8ZtKOlM2TLy3CUwWMj77X37irmGPTsmtQ9gYHxQ+eaUVYEY4GQI09JceLW8XY8axwFohFQ==
X-Received: by 2002:a19:7515:: with SMTP id y21mr3019613lfe.45.1579622727546;
        Tue, 21 Jan 2020 08:05:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c8d6:: with SMTP id y205ls968260lff.4.gmail; Tue, 21 Jan
 2020 08:05:26 -0800 (PST)
X-Received: by 2002:ac2:4a91:: with SMTP id l17mr3114566lfp.75.1579622726848;
        Tue, 21 Jan 2020 08:05:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579622726; cv=none;
        d=google.com; s=arc-20160816;
        b=OL8N5+IBA9/4S/dIcgJUCrevgZbvfyku/rc1Ylo9OFYJslZPANHALlXPzWiHRkoKyI
         S96Nd7BHN2kgTqchm57WSdLV5dfgjvODJ4LWPlEHHLyuJh9+Sqjrwkol1rhAfhxKkD4j
         bnmnFfOSKbjGHh8fn8YL7TZFl5YKy5nMESHd8qKQWA35xEWOBuYM6iLA8HPTZyIK619m
         HiKXlVGIOxnkl/ZhESVOeYk24DdGcY9sHz1py2YlPr2P1LcQO/NvxpmB54zCphUHU6/k
         eWeXpFBJ32SZEa3FooyD8ls19C2SA2xvp6Q9fFsg3ivg8uSL7tgorJRQ0Lyw6bpWgXlz
         HB6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=3X3r+FgOCgofu61vtdHWB37xIMZxsUR5auYodQTv4sI=;
        b=R6cAQk82YJ7gKKF/XRrfHEKW82SUH7hT51pNpoZpicCkReZhofmkGSRSNdyOWgt9XZ
         8zvm35SOAz5YKrbUNH4AWPv5+2WRqp/EaWAoV//v0dW5bC2cpRks2YB0vuXaDn5ppgbq
         XroBodCgaub89t6xEEHVpu1THE6qrJlBvOeCbIvUoajWnKkWZrVrkcglNEgu6SzVwbcV
         35KYgegE6N+mR958OsoJYZQIebGhVANVxdv3nCgALgpKximeDiH38cUXxQa7T0+ne+E6
         +q1noQrcuqTIrcjuRzbmxEeEyqQfe2ivRshvqQJPoEcrjiAuafhDJ05cwF3uPBdEa8FW
         ni8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FBbFhbGM;
       spf=pass (google.com: domain of 3rsenxgukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RSEnXgUKCRw6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a4si875300lfg.1.2020.01.21.08.05.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:05:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rsenxgukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v17so1495597wrm.17
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:05:26 -0800 (PST)
X-Received: by 2002:adf:b193:: with SMTP id q19mr5973633wra.78.1579622725966;
 Tue, 21 Jan 2020 08:05:25 -0800 (PST)
Date: Tue, 21 Jan 2020 17:05:08 +0100
Message-Id: <20200121160512.70887-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 1/5] include/linux: Add instrumented.h infrastructure
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, dja@axtens.net, 
	christophe.leroy@c-s.fr, mpe@ellerman.id.au, mhiramat@kernel.org, 
	rostedt@goodmis.org, mingo@kernel.org, christian.brauner@ubuntu.com, 
	daniel@iogearbox.net, keescook@chromium.org, cyphar@cyphar.com, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FBbFhbGM;       spf=pass
 (google.com: domain of 3rsenxgukcrw6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RSEnXgUKCRw6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

This adds instrumented.h, which provides generic wrappers for memory
access instrumentation that the compiler cannot emit for various
sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
future this will also include KMSAN instrumentation.

Note that, copy_{to,from}_user should use special instrumentation, since
we should be able to instrument both source and destination memory
accesses if both are kernel memory.

The current patch only instruments the memory access where the address
is always in kernel space, however, both may in fact be kernel addresses
when a compat syscall passes an argument allocated in the kernel to a
real syscall. In a future change, both KASAN and KCSAN should check both
addresses in such cases, as well as KMSAN will make use of both
addresses. [It made more sense to provide the completed function
signature, rather than updating it and changing all locations again at a
later time.]

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>
---
v2:
* Simplify header, since we currently do not need pre/post user-copy
  distinction.
* Make instrument_copy_{to,from}_user function arguments match
  copy_{to,from}_user and update rationale in commit message.
---
 include/linux/instrumented.h | 109 +++++++++++++++++++++++++++++++++++
 1 file changed, 109 insertions(+)
 create mode 100644 include/linux/instrumented.h

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
new file mode 100644
index 000000000000..43e6ea591975
--- /dev/null
+++ b/include/linux/instrumented.h
@@ -0,0 +1,109 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This header provides generic wrappers for memory access instrumentation that
+ * the compiler cannot emit for: KASAN, KCSAN.
+ */
+#ifndef _LINUX_INSTRUMENTED_H
+#define _LINUX_INSTRUMENTED_H
+
+#include <linux/compiler.h>
+#include <linux/kasan-checks.h>
+#include <linux/kcsan-checks.h>
+#include <linux/types.h>
+
+/**
+ * instrument_read - instrument regular read access
+ *
+ * Instrument a regular read access. The instrumentation should be inserted
+ * before the actual read happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_read(const volatile void *v, size_t size)
+{
+	kasan_check_read(v, size);
+	kcsan_check_read(v, size);
+}
+
+/**
+ * instrument_write - instrument regular write access
+ *
+ * Instrument a regular write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_write(v, size);
+}
+
+/**
+ * instrument_atomic_read - instrument atomic read access
+ *
+ * Instrument an atomic read access. The instrumentation should be inserted
+ * before the actual read happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
+{
+	kasan_check_read(v, size);
+	kcsan_check_atomic_read(v, size);
+}
+
+/**
+ * instrument_atomic_write - instrument atomic write access
+ *
+ * Instrument an atomic write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_atomic_write(v, size);
+}
+
+/**
+ * instrument_copy_to_user - instrument reads of copy_to_user
+ *
+ * Instrument reads from kernel memory, that are due to copy_to_user (and
+ * variants). The instrumentation must be inserted before the accesses.
+ *
+ * @to destination address
+ * @from source address
+ * @n number of bytes to copy
+ */
+static __always_inline void
+instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
+{
+	kasan_check_read(from, n);
+	kcsan_check_read(from, n);
+}
+
+/**
+ * instrument_copy_from_user - instrument writes of copy_from_user
+ *
+ * Instrument writes to kernel memory, that are due to copy_from_user (and
+ * variants). The instrumentation should be inserted before the accesses.
+ *
+ * @to destination address
+ * @from source address
+ * @n number of bytes to copy
+ */
+static __always_inline void
+instrument_copy_from_user(const void *to, const void __user *from, unsigned long n)
+{
+	kasan_check_write(to, n);
+	kcsan_check_write(to, n);
+}
+
+#endif /* _LINUX_INSTRUMENTED_H */
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-1-elver%40google.com.
