Return-Path: <kasan-dev+bncBAABBX75WT5AKGQEECDD7KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id E0D1C25809D
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:08 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id k185sf3583571vke.10
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=tMd/cjAGhVg3qugg9Z4Pk1kf0i4YqtRpRa/bbV4hZgxymqNYrHbe95Bu45HslXfe7g
         MrCH6o5SU94DaimFD4u7qOS8pa1+lvXI4ODkrIlQa0lmgXsLkhPW78WT9sE3qwwGc9Vj
         fonF25A8Yf6ThCGS8xN3lmw+UdnZ43OhLhnNcyXQLF+OoOZc7AjXNG1YcTL9A4SRiNdm
         lSgjt61dUt+DJdEw8CEJPRfL+hWUpBHSRUN2c0TOGaybYMLxrZKW3afAOcEbboWS2mFK
         uU4jNicNsc6+rYQ3BEqdb3jLccQZHiqM+a7dGBmda4kKdoATwkmDu99I541na+2jZHWd
         3Icw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=6OIUSYouoBnh4q+UBJAOfqObw9FzInX1NA5/KQDvt7A=;
        b=hoirUq0pHWHHfX0BkcuOMUr8KzwR8n1YSLfo6RFe61qycI3mFgaV3gR+o5BBAmi3Qr
         h3eonS+k2FmTHjw2ZVSM6BDBBnQTNpESG8yF4TCUsId6A8po0vk25nCQP7ac8dwAmUmV
         /Ocii7azDa4UZrzMwAdDlu+yuEfFJFV8a2TnAmuJVC/NcG4n50GcWmXotvBzPKqNmKi5
         RrktWNg5SOtdpImNxiU3Sw/c0JWeCYd8WVf5O0mgbwPa+o+ABn3E3TAv16OzFI/05O37
         Oz1u3wJHoDkVQZwYkPks6yYpusaipSPa8OO1yrBldmpiotCpd3mVQq7MHvTBMVhWbVSL
         DNYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=b8pU6DyK;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6OIUSYouoBnh4q+UBJAOfqObw9FzInX1NA5/KQDvt7A=;
        b=nJB7wDsPtqnJorSLtL1hbBq1HbNlk3BNC92V37bgiO7mtzQonyH1Z5nhkZS+SQslZx
         0iuIzX1s+gcdtDfuLND9RdCz1cPnUdW2Lg2XhVHVq769CcvqRCKghjS0EloczWjasyGZ
         6pkdtJ3hYLUy/CfvqiRf4ywHY2hkYXSQPk9nmhWe/ozQP5clo4qvsdl16/oKO5zTBIZX
         c0AaExZ7Yguhbfjcf5fcELbVrdkuRMWWTTLHFxA9JQlOYwLRKGqbQ10g7qY0TtdC2nHH
         IjV36j/BBdReasZxhFtBiR0mhzRvfyDwE4dRm3Pk6gr2uwS+iQQyHpN70rU39pisgzxE
         O6Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6OIUSYouoBnh4q+UBJAOfqObw9FzInX1NA5/KQDvt7A=;
        b=UtfoNFQ0dUPprnmlNHYKusU85lwZvhGiVqEyenj7xYZFcWQrb1AdJE3VTv4RQT3boz
         ADrkzva/+/rQIZUCe7GDllzi3pby+ohNF2kip3Z+W5zUAasQT3tBIIMmmqgLE9ID8bHd
         H3qoOOom38RwAjUUoZ/vA6TymA+hfZURaKwm/HsRUzXYCIVDotTb4Y7HigGfFkCsg4Ou
         jPzZbhtzqJZ/wxUDYb4mGD9m3C9KnrMvlzZrltGG9Jl8zSB4WvBx4ZalO51qOpvQ42Fe
         Yg+J2t8jzut1Zkg69IL7XuSjBhO0Fbg5Z8uvKVruYwAUMqrttvfyqqxG5XokK0ti4FKR
         HkwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TktNeKsR99BvQPJAOkb3PgpobKPlHAK9rRbAeemhS0KFaREaR
	cWfyEMru1N+RjHMg/zaIUuM=
X-Google-Smtp-Source: ABdhPJwxTIYkkFOj/HiSExR68GQl1wgyXaFxX9FE0yAYV2uBg6j/p+wEKC+SYIgv4tfEwiDXQnsg7A==
X-Received: by 2002:ab0:6053:: with SMTP id o19mr2008393ual.77.1598897887916;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9cd5:: with SMTP id f204ls368614vke.9.gmail; Mon, 31 Aug
 2020 11:18:07 -0700 (PDT)
X-Received: by 2002:a1f:2444:: with SMTP id k65mr2261118vkk.33.1598897887524;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897887; cv=none;
        d=google.com; s=arc-20160816;
        b=AKc5fYnOFNw/IM4h9iJDeeXbbtl8X7gk9IXwrsJjeCVVUq6xf/Cr3kvP7OWLT4arYG
         Dt5pjDb2A7aW1i0BvJ3uh9MZ/JpyRpCIuUWVp6PVXHqR3hJqTuhwa0MBv71OAFsJvfRQ
         WKb5rPW0r9Dr6ds4j236S7bOxmdj3fqhrhafd6zz+0LTLG//jzw0FzFyy46pwIwjzTC/
         w1Ppf6hQ4fs23+0L6WAOcSTIS08sfSCg1clk1cgRvkzohJyPAx1BQ4o41hOJZpTcj+ml
         62loGKdh+RDuJ8Otu8gZudbQO9PRAaiaws6KQM3EctnCd2A+4y/KQ/kFQeZjFLuJJRkk
         ZYXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=FzlibcFUYhKhvemTGogIl85zkwQ9q8ScU4gmbWD8RGM=;
        b=Ivoq0T3yIZ3ozqod443c1R7SNKZdsI1na5Je0Hdp48KRQPqIm2j2zSTagzzOnLvuRj
         M02H/Akwe47bae38qRPSF729xt38WWZ+ExYwew+htuAVIpXaIgFBlESU1J1uec12uOvo
         vEuEYr48huDyI1rxg7Ky4ZfZW487y3xQu9+K/f25zl4DfgyCcpaBcBffRjDdVmHSoMOO
         eHPDCpL2TatpMmNCF28n/mz4A4emv9PqLldik16YX+FYgg58g9gt6ibebfd6eAb0D5Et
         SbMP5NHmumfxs/UY5MQ+cq126lNlyhVBnrOqs6T6kttM5JkCUZy6l4vlM9I3X05HAIW6
         Yq0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=b8pU6DyK;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y3si520667vke.2.2020.08.31.11.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 52F822071B;
	Mon, 31 Aug 2020 18:18:06 +0000 (UTC)
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
Subject: [PATCH kcsan 01/19] kcsan: Add support for atomic builtins
Date: Mon, 31 Aug 2020 11:17:47 -0700
Message-Id: <20200831181805.1833-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=b8pU6DyK;       spf=pass
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

Some architectures (currently e.g. s390 partially) implement atomics
using the compiler's atomic builtins (__atomic_*, __sync_*). To support
enabling KCSAN on such architectures in future, or support experimental
use of these builtins, implement support for them.

We should also avoid breaking KCSAN kernels due to use (accidental or
otherwise) of atomic builtins in drivers, as has happened in the past:
https://lkml.kernel.org/r/5231d2c0-41d9-6721-e15f-a7eedf3ce69e@infradead.org

The instrumentation is subtly different from regular reads/writes: TSAN
instrumentation replaces the use of atomic builtins with a call into the
runtime, and the runtime's job is to also execute the desired atomic
operation. We rely on the __atomic_* compiler builtins, available with
all KCSAN-supported compilers, to implement each TSAN atomic
instrumentation function.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 110 ++++++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 110 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 9147ff6..682d9fd 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -879,3 +879,113 @@ void __tsan_init(void)
 {
 }
 EXPORT_SYMBOL(__tsan_init);
+
+/*
+ * Instrumentation for atomic builtins (__atomic_*, __sync_*).
+ *
+ * Normal kernel code _should not_ be using them directly, but some
+ * architectures may implement some or all atomics using the compilers'
+ * builtins.
+ *
+ * Note: If an architecture decides to fully implement atomics using the
+ * builtins, because they are implicitly instrumented by KCSAN (and KASAN,
+ * etc.), implementing the ARCH_ATOMIC interface (to get instrumentation via
+ * atomic-instrumented) is no longer necessary.
+ *
+ * TSAN instrumentation replaces atomic accesses with calls to any of the below
+ * functions, whose job is to also execute the operation itself.
+ */
+
+#define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
+	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
+	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
+	{                                                                                          \
+		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
+		return __atomic_load_n(ptr, memorder);                                             \
+	}                                                                                          \
+	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
+	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
+	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
+	{                                                                                          \
+		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		__atomic_store_n(ptr, v, memorder);                                                \
+	}                                                                                          \
+	EXPORT_SYMBOL(__tsan_atomic##bits##_store)
+
+#define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
+	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
+	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
+	{                                                                                          \
+		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		return __atomic_##op##suffix(ptr, v, memorder);                                    \
+	}                                                                                          \
+	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
+
+/*
+ * Note: CAS operations are always classified as write, even in case they
+ * fail. We cannot perform check_access() after a write, as it might lead to
+ * false positives, in cases such as:
+ *
+ *	T0: __atomic_compare_exchange_n(&p->flag, &old, 1, ...)
+ *
+ *	T1: if (__atomic_load_n(&p->flag, ...)) {
+ *		modify *p;
+ *		p->flag = 0;
+ *	    }
+ *
+ * The only downside is that, if there are 3 threads, with one CAS that
+ * succeeds, another CAS that fails, and an unmarked racing operation, we may
+ * point at the wrong CAS as the source of the race. However, if we assume that
+ * all CAS can succeed in some other execution, the data race is still valid.
+ */
+#define DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strength, weak)                                           \
+	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
+							      u##bits val, int mo, int fail_mo);   \
+	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
+							      u##bits val, int mo, int fail_mo)    \
+	{                                                                                          \
+		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
+	}                                                                                          \
+	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
+
+#define DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)                                                       \
+	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
+							   int mo, int fail_mo);                   \
+	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
+							   int mo, int fail_mo)                    \
+	{                                                                                          \
+		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
+		return exp;                                                                        \
+	}                                                                                          \
+	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_val)
+
+#define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
+	DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
+	DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits, );                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits, );                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits, );                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits, );                                                  \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits, );                                                 \
+	DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits, );                                                \
+	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
+	DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
+	DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
+
+DEFINE_TSAN_ATOMIC_OPS(8);
+DEFINE_TSAN_ATOMIC_OPS(16);
+DEFINE_TSAN_ATOMIC_OPS(32);
+DEFINE_TSAN_ATOMIC_OPS(64);
+
+void __tsan_atomic_thread_fence(int memorder);
+void __tsan_atomic_thread_fence(int memorder)
+{
+	__atomic_thread_fence(memorder);
+}
+EXPORT_SYMBOL(__tsan_atomic_thread_fence);
+
+void __tsan_atomic_signal_fence(int memorder);
+void __tsan_atomic_signal_fence(int memorder) { }
+EXPORT_SYMBOL(__tsan_atomic_signal_fence);
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-1-paulmck%40kernel.org.
