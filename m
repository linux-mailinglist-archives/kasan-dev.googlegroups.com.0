Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXK7T3QKGQELCNRDDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 68052213B3C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 15:40:47 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id y16sf15325231ljh.22
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jul 2020 06:40:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593783647; cv=pass;
        d=google.com; s=arc-20160816;
        b=xz8flmlJkm68EeHLbcRIhqfSU2ca1+EF6Qk8fFnCyw1E64cAWRquMEZkW06iacwvx1
         hbXVsl473bjdG8tR72fCymI9ioqtgmrmJ8tz0/M93qu4aZboYfIHpOdlEZEjW6gXlkjf
         HBEDMSq+2go7uylYlk8wjGX1x0vH0aeVCx6AjEC3klCT0NbqKjox8Fe31GvbassGw20M
         VoDGb/0hu1Iks2V7gODQjLgTkPUdhokVjmUO9TdiwsImWwiB6N+Be5pkbG1017WN/ixd
         8v1z+tbiDFnQLpOi7eTIA1mcL7DYYmrMNBURM8MeQ1r4t2wf9n2k9wIQvK107AVSyidg
         o52Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=FSRS3dla6Waj+8qAVUTWQaCmmIJCnpJOs4uj5k8Hg1U=;
        b=EyhWCb6z2vxGmj6ftbKgIASfhSjKgNkiOhVLWngsjLTzWs0A1aywFM1T3mGDq4y/mc
         A1BQwpn4J9vGs06wFExZLpSfsGR5Rz78sAJ9snYvdbbJ9ZFqpMFaVhqG9QKM+tp5Le96
         jBJ5YO3/PX7z2JyFr/BzR26zVextqF1j+WL0qQjvBqrCm8eCAisLXmvSg9oS01Tn1WAJ
         llKehtec+es5P9Xidq8j/CuSrFjc/ojcF7/dfEcS9rHxZqA79ZSepHaRAtMAjuZ2rulb
         Vosfaj5QGDcnFZag0ZUQQjhJIn3iLOId1SUk+/WbS0gd6nOt0M3DNKyDK3cENU1XyGwg
         B3xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QC8bEzwg;
       spf=pass (google.com: domain of 3xtx_xgukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XTX_XgUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FSRS3dla6Waj+8qAVUTWQaCmmIJCnpJOs4uj5k8Hg1U=;
        b=XbPzcuvTjgMiVDMt7cBrReJgCJx+ysmKxgChDR41jYDWColW1Kc8VjSB3M/C+aOCPl
         Pgsk797gApf/HhaeGPqGcoUY5+QXCWgKkzjUHmHsMRYOGhJvb5Ah69FBqwb2hqSHvCFU
         g7d19w2XxizJkC4H5qzwr96zKMGjv2SLvUuCZHlzgYt2RPY6kPlDdZGfb9L0O+Lh7V+x
         niBJM0uigXqt5zznC4lxxdEbF8YT4EXBtRqTFzfZYdftPiXtl1WmgWgQ6LHgPocr0lmC
         vaYNdjW5C15PzSwOYScMVhXuFj++0/klMBRmIon1oG4f2GMrQCkauMMqQVz7GfhIxkUb
         ZsNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FSRS3dla6Waj+8qAVUTWQaCmmIJCnpJOs4uj5k8Hg1U=;
        b=XlMDAENwcWNSoB7blpmCSz1N99NdYeb9XP67qPWK910YGHxtqtUqeMTyczpEQ+6rIi
         mTubthiuzmlSdANnGngz6y5P/YJUVYMIQ+EB80Nacb9BE+r0VdqOw3MIbOK4pa0lqsFW
         +p4OUxhLsk1iLq9xwnejaN63sktV3O/cGag9/BDyEZvk07hNY1i/tR26Z2akgdSwveZz
         ERa2Tzn9jeX6L9MP4BnsMOpSxjKZR/MMva0vl1wGslrgURqWbHemQdpw9m6Y/mgS4h+q
         Pcaiclh9v1h6IwWc32H1SP5nYHARMgqMNEDaM/p/cusF6w+bVQ60ox8WqnJ+QOnSu4ln
         HS9g==
X-Gm-Message-State: AOAM533XMsw++uvlqs+w2FGyQ15eV+9yTseoar12dJ4/qV17PKhNm+9O
	Ih5GR5VR/xJQs3jswQGYnP4=
X-Google-Smtp-Source: ABdhPJwxGT7TAT2Al6ZuIPhxZkd778pftXUVv0fG/U10XiE1GvVIRrPAArN0jwJj/eyr33Fwwrrfvw==
X-Received: by 2002:ac2:4295:: with SMTP id m21mr21761789lfh.186.1593783646819;
        Fri, 03 Jul 2020 06:40:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7102:: with SMTP id m2ls19156ljc.6.gmail; Fri, 03 Jul
 2020 06:40:46 -0700 (PDT)
X-Received: by 2002:a2e:2c18:: with SMTP id s24mr12227482ljs.291.1593783646085;
        Fri, 03 Jul 2020 06:40:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593783646; cv=none;
        d=google.com; s=arc-20160816;
        b=BcNe5KM3OuumM41GSTuqn2m90q1r5on4e5YMuOD4jWwHvfxbklDMOzT3T9NBPauWfp
         6p0YiTZupyNNUTHoEoE8pmzwCySCPJCbv4CQdZa+JA/iLWrJA85kr9+MxRmWn7Br3Abm
         VbtT4Ue7BUUUsiNHlaQKX3xoJrjhPgYSDgIr3fnoqbwLhQLEiyX2xofDO4CqOXyPYbtk
         N4ZcXxM6plNG2PT46YP0VIirYdk9uE3vhB/Dsht6PSycBZe0Jjj6WsouDH+xc2UyU2Bi
         5xfA/QLld5iPUzobBLK0iN5jl83brALHAeySUBHx4f7Oqm58SAin3f/pccIgqEDMtfzt
         Yvsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=ls5EQRkUxBZzP7EqUh1IKI2XSD94zleYx8ufPET2dw8=;
        b=GNCoxMgaItRKCHEQMYdOCmAggoXRbDX2QX7Y1vSzZXDkA9cQgokogy/fJROj9AOBeV
         wQ3N67Sc4wV+W8E6CkGFSqhK3Dp5DZA0QmEXpKZMZuSAAENdj02YAlFUBvu2mDj0XODx
         BBjplWeL4Os9kqtE0Rb7jKuPvQ3MqV0kquyFKIoSKn/dOoK1UIvUA/x9JS1CQiwmZVeA
         EskXpzbb9liTuP+16lzKQAdgu8C2Zgj8HR00+7GwNC5YJoBIsLFNA+dCf5wJRnjB9X3G
         1EPthwedSwAEKUkUAz0VmfqqCyv511jxHfev2du2IYwkcq2TQFEnaZKYJVO4utJd66JH
         Cz9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QC8bEzwg;
       spf=pass (google.com: domain of 3xtx_xgukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XTX_XgUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e2si109459ljg.8.2020.07.03.06.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Jul 2020 06:40:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xtx_xgukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j16so26270160wrw.3
        for <kasan-dev@googlegroups.com>; Fri, 03 Jul 2020 06:40:46 -0700 (PDT)
X-Received: by 2002:a7b:c4c3:: with SMTP id g3mr38298704wmk.126.1593783645449;
 Fri, 03 Jul 2020 06:40:45 -0700 (PDT)
Date: Fri,  3 Jul 2020 15:40:29 +0200
Message-Id: <20200703134031.3298135-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.212.ge8ba1cc988-goog
Subject: [PATCH 1/3] kcsan: Add support for atomic builtins
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QC8bEzwg;       spf=pass
 (google.com: domain of 3xtx_xgukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XTX_XgUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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
---
 kernel/kcsan/core.c | 110 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 110 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index d803765603fb..6843169da759 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -856,3 +856,113 @@ void __tsan_init(void)
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
2.27.0.212.ge8ba1cc988-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200703134031.3298135-1-elver%40google.com.
