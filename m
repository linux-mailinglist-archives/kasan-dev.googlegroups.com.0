Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKNOZCTAMGQEMRRNNMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F108773996
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 12:21:30 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-4fb93743baasf846565e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 03:21:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691490090; cv=pass;
        d=google.com; s=arc-20160816;
        b=WuAXN8DgHkRQbJOhX7tVJ+9UBJosabxwBNA/JdRF/1vpMnm85G+RNX57QfGKypS8vs
         shdWwuKQ0duolGQpmRXf1sSDRvIsYXM+oCRNF+GeAwPSIikrqIM3Iv16YMEBBDVmiCaz
         GLLClEcL492kxXxfKrAAjMMfkGhDtkhZ804xzvtEnZzD7pQ8iASd76fW46/EJqmYzbUI
         AXxivQ9/KFS2XXDRchzp2KvgbyAu+KE2m8E8G+SjCsOA7YcPZkHPpQPytIVuKbW8EwUe
         AE+inn6p/+xmh3jH4E1v+gyMUEXHIjRrKAaHLmcxsZpbUuuAFN1bDYIzRm6AqmyUJb8m
         liAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=hIADvr+2xW6+pVgZ0DB6LJrwkKJlNLxAy4ILYbRTAAU=;
        fh=0+1A2GTyPkIZP1JqAjZ2aq5svYM3vBrC3jkZRiGb8LI=;
        b=YO/Wsmk8MWMS9GZWHUEpwRQEiEuSByAWlskYzdwnKsJumeD78w0PxK8NklJVMLaRhS
         BvafpK9Fq4XdPpBdAkpQFgBCl0Cllyxr0ujXVYTINUaH3IWaY30QDRIbyZByGcaK0XBT
         UHx2FV0SZNAUGqggcjIUSyVI33mbTzHnEz+VYSuMLYFJ/SHFtXjTpm5z++i5l7V4j/8q
         n4MGoKlMeOjeq/yuWk66yX8MPzqtl4T3b/3RtRD+7Poq6POfzaZDN56voGO9mRgsc5p5
         a9UHedyBaXrBmWFkZYEuT3oCKng7EPE1XfFFU/OZo/aPNS+uPUd/3US4LxzucIzCNAL/
         5xDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UcRiSP5z;
       spf=pass (google.com: domain of 3jhfszaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JhfSZAUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691490090; x=1692094890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hIADvr+2xW6+pVgZ0DB6LJrwkKJlNLxAy4ILYbRTAAU=;
        b=ShFObqZ7k5FHqTptLg00CFJNXKVPITcs5zAT4W4hvuBya4iIlQzkGkdK0grgDGl4jN
         mYtKyYPU8h0H9E53PLb9RXDRoBwEV6RVaRXeV1qBXgc6dVeJOWsRjIeFyon0x5OJTh7D
         TxiER0FiIuzrWKrWw5LBs7UuYlVDAAGMlTWfTPxYnUI+CJFMq53vTRCls0rGLXikfLG1
         kW1VSM6M942gzmg6/AhbyWPGyI4v9sspkxQ0GoiwbopCOVirBkO+H6MxzD8d5aTHkkLD
         yXPEyREtg2GIUFruvb8ge5zuOCD6k0lGp5rwql3UJiPH7cqcd4Pwsqh6c3G/vWyObVyX
         tATA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691490090; x=1692094890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hIADvr+2xW6+pVgZ0DB6LJrwkKJlNLxAy4ILYbRTAAU=;
        b=dzyuwt5qX79rM7lM3tU4gHPjJVVqVy9+ASc/PaPgb7GUaqTt3PEjV4YxSZBMoB//Ah
         enYFkqKHeBVLTPAjf/xds1Ud985pkyI+fsOuIY5sTU3vsbQTiU1RrCugui94b2tXKIde
         SpfPm6m+o+1ifbCAHK+pNcu7aTB83LNy4USD4JGqXuXvoZyAR/3GymGuOpryzCB43kol
         riVolMHZELozG+WWewj56N4KC38w9Be5zJ+Ox++Dw2WcKWZdOnpZdSQPz8tLA8SuIYRf
         IHAyYU6MPdnh8i1+/qC9J6fLXuMtQeHK6qrtPgjsKga/nhOdFqQ8TOukYh03OYuukUak
         SVGQ==
X-Gm-Message-State: ABy/qLZYqXzQDu95fUKtujqNXGEwUiB2BS79vYSXGpDEAo9XgkpR92KB
	oTJ1oYOo8e9b3uSE+2C/zJI=
X-Google-Smtp-Source: APBJJlGJBKJcu1BJuDjLWHyuQm4J2FzhsGyCTh/f/+w74eVEIQcGAzebsHnVKXWXytefrCfGdW8WOQ==
X-Received: by 2002:a05:6512:411:b0:4fd:d2de:76e8 with SMTP id u17-20020a056512041100b004fdd2de76e8mr15703891lfk.6.1691490089411;
        Tue, 08 Aug 2023 03:21:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f95:0:b0:4fe:1d8a:4d7a with SMTP id r21-20020ac25f95000000b004fe1d8a4d7als17046lfe.2.-pod-prod-09-eu;
 Tue, 08 Aug 2023 03:21:27 -0700 (PDT)
X-Received: by 2002:a05:6512:2827:b0:4f8:5e21:a3a9 with SMTP id cf39-20020a056512282700b004f85e21a3a9mr10315701lfb.45.1691490087404;
        Tue, 08 Aug 2023 03:21:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691490087; cv=none;
        d=google.com; s=arc-20160816;
        b=eAYTayj4FICYP12RSK42m6mgQNXM1DCpqcSJo/DJnnhfh0Rve5TzbRRUZDQpLW2IEA
         ynhhmrPMGgcVKFLZmWBOMcyjANA2AZTUVGGlzWgL3Og0TU5FID+dB3rgUD6a30dGjGu6
         yBmffizoB059vuVizVOahxsgJF5H46vDO9v5G3cQkOv9AxnUH98lxpdqgjfFzngvDjUF
         S4o3bh017xou/wfbjr+g2SCSWNMnOKp45NEZumseYWGYyl5ZJ5wDDL8Ce5MFhzNE8ae0
         GkVUvWK+LPLdyB10efeESV0ZmF9re7jOLfuZCsmhPZNXFZn3b0YZn8mLTyIJoN99nnZL
         RgXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=hmnOfvRNRbQKO2Fig5tO7oMJZvMK80sR98XXmZHYIOg=;
        fh=21lXPMSK2yK/sEXDyQrJ/fRnyJ9/L86+gRgt0otc1Cc=;
        b=Lzi6mF8g0Qn1/jKRwGd06sOsKm3hleh3K8cx1+9E6IvKwksDN6jFbpOIAgT5iQY/Px
         vbFai2Ko/Z7yKZON1z77seZbQE0rthbs98QB4sXTGjeNEtiPcTnNDdqHxtFcyGt39Jxv
         q+CPwgobFEVk/5G7JlbAV7WnR/Re/lZhLg+x2af3Y/HTcb8+6dxw60lQVOMA7framOnn
         kjT9txGdEXaZHdjvGe4XxazvF23miS8C1M5mABsEgPrCNP2fYt0bzNs3q94rmqmDLnnH
         q8bpzO/J1BJLo1GhWoRb4+XTRl21dUK+kd4SUlmRb0mBi6M7iNP0xtwRtQbv7WtXcyc2
         9CJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UcRiSP5z;
       spf=pass (google.com: domain of 3jhfszaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JhfSZAUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v21-20020ac258f5000000b004fe3478235csi657892lfo.7.2023.08.08.03.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Aug 2023 03:21:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jhfszaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-30e3ee8a42eso2549577f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Aug 2023 03:21:27 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:39c0:833d:c267:7f64])
 (user=elver job=sendgmr) by 2002:adf:f0cb:0:b0:317:5e4f:9097 with SMTP id
 x11-20020adff0cb000000b003175e4f9097mr74564wro.7.1691490086705; Tue, 08 Aug
 2023 03:21:26 -0700 (PDT)
Date: Tue,  8 Aug 2023 12:17:25 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.41.0.640.ga95def55d0-goog
Message-ID: <20230808102049.465864-1-elver@google.com>
Subject: [PATCH v3 1/3] compiler_types: Introduce the Clang __preserve_most
 function attribute
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=UcRiSP5z;       spf=pass
 (google.com: domain of 3jhfszaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JhfSZAUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

[1]: "On X86-64 and AArch64 targets, this attribute changes the calling
convention of a function. The preserve_most calling convention attempts
to make the code in the caller as unintrusive as possible. This
convention behaves identically to the C calling convention on how
arguments and return values are passed, but it uses a different set of
caller/callee-saved registers. This alleviates the burden of saving and
recovering a large register set before and after the call in the caller.
If the arguments are passed in callee-saved registers, then they will be
preserved by the callee across the call. This doesn't apply for values
returned in callee-saved registers.

 * On X86-64 the callee preserves all general purpose registers, except
   for R11. R11 can be used as a scratch register. Floating-point
   registers (XMMs/YMMs) are not preserved and need to be saved by the
   caller.

 * On AArch64 the callee preserve all general purpose registers, except
   x0-X8 and X16-X18."

[1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most

Introduce the attribute to compiler_types.h as __preserve_most.

Use of this attribute results in better code generation for calls to
very rarely called functions, such as error-reporting functions, or
rarely executed slow paths.

Beware that the attribute conflicts with instrumentation calls inserted
on function entry which do not use __preserve_most themselves. Notably,
function tracing which assumes the normal C calling convention for the
given architecture.  Where the attribute is supported, __preserve_most
will imply notrace. It is recommended to restrict use of the attribute
to functions that should or already disable tracing.

The attribute may be supported by a future GCC version (see
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899).

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Miguel Ojeda <ojeda@kernel.org>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
---
v3:
* Quote more from LLVM documentation about which registers are
  callee/caller with preserve_most.
* Code comment to restrict use where tracing is meant to be disabled.

v2:
* Imply notrace, to avoid any conflicts with tracing which is inserted
  on function entry. See added comments.
---
 include/linux/compiler_types.h | 28 ++++++++++++++++++++++++++++
 1 file changed, 28 insertions(+)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 547ea1ff806e..c88488715a39 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -106,6 +106,34 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
 #define __cold
 #endif
 
+/*
+ * On x86-64 and arm64 targets, __preserve_most changes the calling convention
+ * of a function to make the code in the caller as unintrusive as possible. This
+ * convention behaves identically to the C calling convention on how arguments
+ * and return values are passed, but uses a different set of caller- and callee-
+ * saved registers.
+ *
+ * The purpose is to alleviates the burden of saving and recovering a large
+ * register set before and after the call in the caller.  This is beneficial for
+ * rarely taken slow paths, such as error-reporting functions that may be called
+ * from hot paths.
+ *
+ * Note: This may conflict with instrumentation inserted on function entry which
+ * does not use __preserve_most or equivalent convention (if in assembly). Since
+ * function tracing assumes the normal C calling convention, where the attribute
+ * is supported, __preserve_most implies notrace.  It is recommended to restrict
+ * use of the attribute to functions that should or already disable tracing.
+ *
+ * Optional: not supported by gcc.
+ *
+ * clang: https://clang.llvm.org/docs/AttributeReference.html#preserve-most
+ */
+#if __has_attribute(__preserve_most__)
+# define __preserve_most notrace __attribute__((__preserve_most__))
+#else
+# define __preserve_most
+#endif
+
 /* Builtins */
 
 /*
-- 
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230808102049.465864-1-elver%40google.com.
