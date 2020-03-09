Return-Path: <kasan-dev+bncBAABBOFGTLZQKGQE5Y7FWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CB5F117E7CA
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:25 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id j2sf7125829otk.14
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780664; cv=pass;
        d=google.com; s=arc-20160816;
        b=K8f5dKeSJRX27p2D4vGMXE7RaC0uoTYOEcJ4yZMRmw+Iid7mRkawp3t9o7XRnqMDHJ
         U2wQVuzXY+GakWDVV8NeKgXj70tnZLq6ayvBowoV6dclpLmJX47uGpGbkt9sFhPEHxS5
         ji73gu+To4siLt9QOArZJrMvHhUkW0bqH/avrf/Vbndj3dNsCNyAASZ3obD3SS2iLxCu
         otm9oO1EGp1Q9GiY/jBQWg2Q1py/RCnfehUNwYi12uiOC5kyOpCMuTDMKeaegDkQY6qL
         bkkuNB41KM/+KSJYr55RBHNjdyeGYALdxVCjx808fCUa915jJZq0njT3wmwvGFK0gFjN
         nLng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=POkovdNO0XEA+CPeZS5jXJlxu0JtpKCzCQTJYDWtqZA=;
        b=zWzmI46hCw2VhvHZWzSQUDK6Njkr9jiVj1TPMRU/vWOCHSda3j7jpEZVF+8dzuoz1Z
         pVZzThyiGLTF8TD+HtyK9EfLP9rn+8SWtBcOq7cfj8AGFYbmy6fr9YpnIQC6UZwGdNXE
         rmW7lPcJeXBbaQkAU9VFt8TiWwChdjuDveRKmT7jbmN9S6fnDBgONCXal+IjdemqzJpR
         T676qMimJ7lkT5KK/JwqR6UrHCGEgtyDpa3VOHZ7BJHoZTF0d/HA2iwQQPYO130fEo6P
         5N5jz9aZgkgvsWS1E/lP8E2YCrse0IzC2H5ueIIyPdcGZatSRNQMTJhHHCoDLTm0fFkA
         ufNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gBP08WFE;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POkovdNO0XEA+CPeZS5jXJlxu0JtpKCzCQTJYDWtqZA=;
        b=anbZKZaQMgrLdvn+LyxcVNGixKGDgLpnuuNM2NiVHBFgbUFdpXGFO6EWLNa4b5zaaW
         gLZB4E2yyv6ww1n7/MEz9CSwRDD9kWG3csrMUW4EBJpxX4LIHu2uFcEYE1ina1E/RSqG
         W5n19qzeWN6/S+NfkRwxlb2KdXr2ZDIpmeTAcRcN+tFshb85sdqzzrsNkFQPu5njK6gj
         6d+vmL562KEepTm3wtLtsMU1Xe6XZ8SIh7WOkPTSiWv+io9CKIncRoSQxVqTM343T0C5
         /eSot3MjtUkW9sDJzOe0AxLjjQKzVJ+kh75KJfoUJkpeWB5zgZyGP3jxF4mBcN9ewXFc
         imBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POkovdNO0XEA+CPeZS5jXJlxu0JtpKCzCQTJYDWtqZA=;
        b=XUsP95fYzglIzf1tRjUci23eXYYUOWHNELRPPz63GGDAihLk/GealqOBJ9UkPGTT3e
         h5DoRy7+ItdN79Cn9ljKQ1DCd0vF5X8VbDD4jQT1d2eDiU6T/nVlDYxPpr47d1NdKFU+
         HTBiYrKt+awnqtcaSt0JKzPAgi495d19rPvNjEhEtpU34K5E5jh5olI7RmPznSL59ths
         5LxQHDoqHMJ1ChIkBk6am8pmQrfAR8Qm920cTevd59RwilE5L+HytDYuP25WiTThpZrZ
         zROlQjZM9kW9hAFkKQ5fI6MvEot/UlOgd/1OXNmdaTkyCkElLTFQcHRda+qgwfAxPPFJ
         sA8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1aeELSxOBbBuyeRRL2ZjGsGKuuBib2VvCgdTqYBxFwtWLB4Q5/
	yHk2zxBpiG1JwaXksV7hjvQ=
X-Google-Smtp-Source: ADFU+vvWdBgw7/7HxE6smBxb17/b2gMpV+7SqeOUy/AB/bsLGeBYBGUTmIxZxtqnLFFA82+5Bwjaiw==
X-Received: by 2002:a9d:64b:: with SMTP id 69mr13591041otn.237.1583780664722;
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6143:: with SMTP id c3ls3554189otk.7.gmail; Mon, 09 Mar
 2020 12:04:24 -0700 (PDT)
X-Received: by 2002:a9d:3e89:: with SMTP id b9mr14300901otc.3.1583780664298;
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780664; cv=none;
        d=google.com; s=arc-20160816;
        b=iPDVGRh2du3eTk6Nw7IRt3jYGMuHnEnkkWM2M2TGmgnqLyTPsLR7QzCYrNMtwzFpx7
         mc6/fnvZa1sjZfMU47Cf8GW+ZvRGFNVvtNDuN8LDOMILUCn6c+Sc3AoOcJSebBSdCUVY
         671+rF5eZRfuVeU0+CqjPBcNu4JR28Y8OVPNL4ixQik/9FLAuJa4iq1dGz/iGtn2vJxx
         KjGspmTdQbmtSUlLwwaaAwThL7rRyh8XZ/Ch/INU8l+oPSsRU7VNUEGxShwCJtyj3Sin
         4K1rb/ONH+ym/VO4d99iXjDceCTalqOT8xHGWj35zTDFo77lmGvtQWX1cVi+20pSDNV3
         lHtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=ESjGuEh/7vDIgTOakNw1fEVh5przYruzl5Pm0sEzWcg=;
        b=CSwcoN9ovwnyB3pdN1Md8FBqIMzDpo2npmvxxj4Skt9vS2K3ptmy2eRYiYdH0LRPlm
         7D1EcmuZSlPQMv87AnLMOi+wMN8Yw8Q9V0JGl3cGRC+5mAa9FNcR6r0TXk2mBC2NJG+C
         Ep8K4Ay7Xwt61u4SX71a+5rPscELa8K8P79QyMrhk41sDyb4UJc5c3uVUrUogTID8fzk
         H/n8IkAOZlcrON/sdOxawPnvxJsnBpjdNfabnpss2nPRmtPQs8/c8AKrxep33VjLbPcF
         9zYEbgKQhxFFpgJLyxd0++8rbce9PaMrjhnyY0034c6jvwK0V0vGD9bU2BX4lX/bjB5b
         LvYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gBP08WFE;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a63si50355oib.4.2020.03.09.12.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 69A8124649;
	Mon,  9 Mar 2020 19:04:23 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 06/32] include/linux: Add instrumented.h infrastructure
Date: Mon,  9 Mar 2020 12:03:54 -0700
Message-Id: <20200309190420.6100-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gBP08WFE;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/instrumented.h | 109 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 109 insertions(+)
 create mode 100644 include/linux/instrumented.h

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
new file mode 100644
index 0000000..43e6ea5
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-6-paulmck%40kernel.org.
