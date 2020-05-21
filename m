Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI45TL3AKGQE6VMNQ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id DCBCC1DCF79
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:28 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id s13sf5837180ilt.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070948; cv=pass;
        d=google.com; s=arc-20160816;
        b=wxHfiREX+KB27peYE/5TdvfVcGR9vK0Fsf2qA6TCIPdFF37L3HeftYrbAq1VKq2HCe
         TojeVcOtFLQsWug2Ffn8BWV72sXlcZ9oCD9j50QNT+VbGmuR7K80q+CvFqzUo33jQfHs
         0Rb7lolitATXHMDHFW+vwhofK50cyCLttaQHJs/du3dM1zPsZkfyhoI+BZOxL4sWk3pQ
         3NxIIr8kW0yyfr97kMIRlCIx39+1wB/6TM9NwQjX1CsGDcRgZvGiK6Xw5EmQ5Y6pXDuP
         G5jN9ShFsiEWYiVT6Lg8/605X7vI1IwFv0Ih8tLgqE8FDAkY2a8tqjnehMAi5gxVlgot
         3n4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zdHbhk4DuBqwU2duaS5n51XLBffpMewiBINN8gB5GC4=;
        b=shvWfgogQeuDUX/czirciibri2/M4Yzsm8qTFGeah4NuLvxkmWcbvfijw85ar79Dws
         bW9d79+uX8z6nSRDTTxq6KQpHP212ufarGbWJaaUfFCnolK8quPnuE1ooE28cT/TEvR6
         y8jucb342qjCt4Xwm96NkJXJXrexlPteFvb9sTUcmqnEsS95S8oTLCgKSKcY2dblUfXA
         F1xTXdVKZFcNOOoxSb2WjsClSaT3oZ3qTn92bjD2WgW7w14bPFkPs9g6urKgAafjapqn
         KHt+ClgBCAav+OVQAenED6RVWEMVSnYPeDXPCKfZok46csCw3nW9Nv/6jACE0XiVITR+
         O+qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b9oWgHML;
       spf=pass (google.com: domain of 3o47gxgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3o47GXgUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zdHbhk4DuBqwU2duaS5n51XLBffpMewiBINN8gB5GC4=;
        b=BkF9e4m+JCgvHBXHrGct9CmMfmC8FVjxSJw9fYgkeDqBnJAopbNIHIxwmslNPXGXNR
         3ijqAV5molET/r2wQtGR1sKRyACQtOXuiKx1ew3wTN8LD+Il4AvWGueDDFHCFvERzx6a
         dxFNKotuNBcAg/Pokz15Moq4h1MnxAYMtGZ83XvH+sT1Ku4Ut57qLQb7LqO+AnzXlgjx
         X9A9orBbUPGrI7xW4NwIKr5UYdmowV3s0R+L22n8T9QbGFSh6Y3Lkn7Zncptgdpu9B9+
         rUSXCLmlXbOMesw2+iHci2HgfDJxnIJbsH5VEsfRQZUucTqjtMAyC6N9Qff8YIB+3pNV
         r1eQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zdHbhk4DuBqwU2duaS5n51XLBffpMewiBINN8gB5GC4=;
        b=PVHvT2baFEDK4v07dVAns0qkVnATdfXE3rv+CmlVQ5UhCF92R1c9QwkQmWaiMPCBAB
         a9EhXCsHTT8OUmWk5MDFqnxwVpZmX1/TgswOEXq8tZXwOVtODYYRINOGKRH/fSlF8VU2
         LNcQnkNHCWG0930DHT/2vDBl9NdYo12kle2pH0CIcPa0MAVWy0OvzklHo8EWC5oqVIvJ
         BcKZNt6xerHPLTakwh+NZbkXRPu3NvbiF2JALOgCV+3736B2McTfxiEpy4m/3BaWM1Gm
         lu+9FmmoZ0WSUT8NHPa4KtC+3YbTNmPBOWti/ZIneRtj1j5zyue41zFKFS2fcNbLcYrj
         q4vQ==
X-Gm-Message-State: AOAM531bIi5KfclTv55CYZMO5Mz+W5gMfxXoj/ChHz3CJffekbUTxc66
	9NEcaAaVgI46Z+6O4eUoYt0=
X-Google-Smtp-Source: ABdhPJx5j8t2mCmYz3xFTz8waW/QMxGW9u8wGJb3eRcGK8o6YeSzLHgReaCaa2A5MdHbqGwVG4VSzA==
X-Received: by 2002:a92:d88c:: with SMTP id e12mr9262954iln.197.1590070947846;
        Thu, 21 May 2020 07:22:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:da05:: with SMTP id z5ls646975ilm.10.gmail; Thu, 21 May
 2020 07:22:27 -0700 (PDT)
X-Received: by 2002:a92:de02:: with SMTP id x2mr9037691ilm.267.1590070947453;
        Thu, 21 May 2020 07:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070947; cv=none;
        d=google.com; s=arc-20160816;
        b=gLchJT9xPsmgWLqc0QyL1E1P6RnWxFz8PDmROBWsnOnXjOxZMw9K7sMHcGfDLk76Cz
         w44EGQzaGLGQiOSFRZbBN7vavXjoptLddbtDlzTLN2QMMTjFyoLFzqERG/WvaqfYgXeh
         MPKlNCbpa+nJW8rlXGnigwu5uEE6Fmed1UqKtkVcvqARnIkGwJ/CqPGsQQS66zN7Idx1
         a0emX2qhVZKMU4MP+NDCnlIlEy/Gx9E2gOjdGITNhCPi9oJn1HMok4JbSXwoep1B1Qb2
         zp1GmvHqV3UnGpkHFuJI3O/WokuLpGHC/EKhn5QHOuGE8q4Z/RNI+PD1zVxTM0B0hgSU
         gWrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PC9Hjj7vUN5/seVEDSBqpv8gGPtTVfQoZ63r2GRfhtk=;
        b=ILzVB+/cGrjiThzmLISKlHz+aWCsGSkS7o50+Vj5TOyCnkXrH/cUjICC+gJrueM1ts
         5riycVXc000vvX1VewuhiVUsQw9g6C3Do8GmQYzJciszrGsZCjMuF3QSrYFMLiRK+x9d
         IgOl84ErdEIRp9LQSF9+iU0ssICyE2NqhU4Mbqb8jaDyjo1wt3cHUOtiFCYT0m+Cbq4q
         pHduPB872jhJ2Y3Tg69qD7e08bX6UiKKEuVykGp1u1PsZgONvgeMQjwxnHkLvX+iaf8I
         kf/7AZm/rPAtS36izMU9crweM/XK/Hk2fHdxcwTQgMXALt/148WuRU4HWHGUjhLHoyNN
         gWeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b9oWgHML;
       spf=pass (google.com: domain of 3o47gxgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3o47GXgUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 2si364181iox.0.2020.05.21.07.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o47gxgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 186so5478427ybq.1
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:27 -0700 (PDT)
X-Received: by 2002:a25:6cd6:: with SMTP id h205mr15954705ybc.404.1590070947070;
 Thu, 21 May 2020 07:22:27 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:39 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-4-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 03/11] kcsan: Support distinguishing volatile accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b9oWgHML;       spf=pass
 (google.com: domain of 3o47gxgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3o47GXgUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

In the kernel, volatile is used in various concurrent context, whether
in low-level synchronization primitives or for legacy reasons. If
supported by the compiler, we will assume that aligned volatile accesses
up to sizeof(long long) (matching compiletime_assert_rwonce_type()) are
atomic.

Recent versions Clang [1] (GCC tentative [2]) can instrument volatile
accesses differently. Add the option (required) to enable the
instrumentation, and provide the necessary runtime functions. None of
the updated compilers are widely available yet (Clang 11 will be the
first release to support the feature).

[1] https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
[2] https://gcc.gnu.org/pipermail/gcc-patches/2020-April/544452.html

This patch allows removing any explicit checks in primitives such as
READ_ONCE() and WRITE_ONCE().

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Reword Makefile comment.
---
 kernel/kcsan/core.c    | 43 ++++++++++++++++++++++++++++++++++++++++++
 scripts/Makefile.kcsan |  5 ++++-
 2 files changed, 47 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index a73a66cf79df..15f67949d11e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -789,6 +789,49 @@ void __tsan_write_range(void *ptr, size_t size)
 }
 EXPORT_SYMBOL(__tsan_write_range);
 
+/*
+ * Use of explicit volatile is generally disallowed [1], however, volatile is
+ * still used in various concurrent context, whether in low-level
+ * synchronization primitives or for legacy reasons.
+ * [1] https://lwn.net/Articles/233479/
+ *
+ * We only consider volatile accesses atomic if they are aligned and would pass
+ * the size-check of compiletime_assert_rwonce_type().
+ */
+#define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
+	void __tsan_volatile_read##size(void *ptr)                             \
+	{                                                                      \
+		const bool is_atomic = size <= sizeof(long long) &&            \
+				       IS_ALIGNED((unsigned long)ptr, size);   \
+		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
+			return;                                                \
+		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0);  \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
+	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
+		__alias(__tsan_volatile_read##size);                           \
+	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
+	void __tsan_volatile_write##size(void *ptr)                            \
+	{                                                                      \
+		const bool is_atomic = size <= sizeof(long long) &&            \
+				       IS_ALIGNED((unsigned long)ptr, size);   \
+		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
+			return;                                                \
+		check_access(ptr, size,                                        \
+			     KCSAN_ACCESS_WRITE |                              \
+				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0));   \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
+	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
+		__alias(__tsan_volatile_write##size);                          \
+	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
+
+DEFINE_TSAN_VOLATILE_READ_WRITE(1);
+DEFINE_TSAN_VOLATILE_READ_WRITE(2);
+DEFINE_TSAN_VOLATILE_READ_WRITE(4);
+DEFINE_TSAN_VOLATILE_READ_WRITE(8);
+DEFINE_TSAN_VOLATILE_READ_WRITE(16);
+
 /*
  * The below are not required by KCSAN, but can still be emitted by the
  * compiler.
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 20337a7ecf54..75d2942b9437 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -9,7 +9,10 @@ else
 cc-param = --param -$(1)
 endif
 
+# Keep most options here optional, to allow enabling more compilers if absence
+# of some options does not break KCSAN nor causes false positive reports.
 CFLAGS_KCSAN := -fsanitize=thread \
-	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls)
+	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-4-elver%40google.com.
