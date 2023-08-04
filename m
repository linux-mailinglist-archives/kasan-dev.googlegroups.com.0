Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK77WKTAMGQE7GRVUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3809076FCDB
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 11:06:53 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-51bdae07082sf6070a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 02:06:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691140013; cv=pass;
        d=google.com; s=arc-20160816;
        b=eyVj3nnZJdbXNffsDZ6YRdTORdZWt7T2yzgY3uYRm9M1Jha1mRBGq6HvPxUKKKfCJo
         Wck0ogH70l0LfwuDnLBjH64d468/ByW7K5c3WVzYteLP9ef4p7Ppzn1JuuIPExrnkMyR
         8SdtRZq5CiT7Bjn30AYMShEDLJ8gBmoIYuJkmbtBHVLn01dfoGiWd0kffZYquxaohTvG
         ghyE7AjlTQqpLHLKXh4BYJ8fH+sm+bEr7CwQ184oBiul/i0dj3ecCuDfCfGwkizrJOWV
         d0grARgJ9kpkUE0SqYCGFTNjzKaN6czDNVUXQiaEiB1FoJqCBKKW8LYWWIjAs0UkQMOE
         9FRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=IBD3jw/4ncnaHBJDi3ZCxGPn3OlqwPMatMJbHpAfTqE=;
        fh=3EsCV1kjHdS/GYEZbaUoPw6fO/lAfz1JWLpP8sfLAPw=;
        b=l5k4n1HTvdz+tzBlb7UPG503dp23+KQse29D+F/2kYOR88nZApUR1Hx7k5RYbVFU/C
         bePxnjr2zjvtUllf0nSynB34eYkPtD34zXDiFbgQIJT3jvHgCd6K1gLdpC0J5s7RtFEh
         ZQlx/dhqlAqqH5DRogLvC2aD8/4B/czd5SS2+62bAzfLZ5MVmsS2NOENRPl9RybWRKNF
         zqyqWj28AcUzthham6JFryQdiJ5kYDFbh7eXvOrxZTGrg+MnUAvU6AJkNdDNa07QFUyD
         ksQf/QHgcQ8beDva77TBm64RjhsF66EwMKXdirBKGRoRYNIh0vJUAcY+TpTBDb5MMErN
         Wlig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5+NdHYLi;
       spf=pass (google.com: domain of 3qb_mzaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qb_MZAUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691140013; x=1691744813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IBD3jw/4ncnaHBJDi3ZCxGPn3OlqwPMatMJbHpAfTqE=;
        b=KKNH1L+wrnC4oNNK0Hm7qYp4gam/ZQm+gbZYLquZHcMsRTZqrdQkbbdl9j29h55D5l
         TEzy6Wtxo9yhjA7d5byxZsb7bCFqufDRS19kQUS7CTh/2NGp7gai5b2St+rj9vLAxQUr
         VvgytM1QZgjA/WSto8fDj8/eghOrZO24AtGELMM98X7c484lsxVH9pFuPUkicfOJwvzN
         DmZYLTTkZsXk0ED2Ezn8t4zclbny87Fct0BWALYGZ3vab5tTCk9sTuGi9FXbXdcDhS27
         zBXC90xBqygkj+6WnQ4RYQ8yN9OGPhU8YPXj1WLi6SQTBdTEj+V4zLEQWOykh84v4/L/
         O/fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691140013; x=1691744813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IBD3jw/4ncnaHBJDi3ZCxGPn3OlqwPMatMJbHpAfTqE=;
        b=BHZTTWj6mkyl9HIwD/s81CpFn/S7UNFCsSTJ6OzkDC582Km9XBSKRIWjGy86t5EVLX
         dvvGfi/MjpPDl/XcAQtewXw0ucHCBciMAynKz+PJE310hWrM55xBMqdxKVzRFUVOK5rF
         8oSDOXc/V0t1dfPxwd2V1aN9C+yE1wd2dMD6+0JzTRcPF/g5cd8iPT0zw/Q3R4eYf9eS
         6+ZkBUKZXz2d77+KSbYVxJcFu5EWJDvPI9gPRLfcomldJMy/GIasWUro3J6oPfq/4cW5
         lmQ4Frv7h+/MujqPtpTrKxqGSoeWpxfARhwTe5QFYSSYP/tD8xIQn2nlhhFoF+Z1pR93
         K2dQ==
X-Gm-Message-State: AOJu0YwYGnPHEtIvLsyS9wOftlKZsfu2oZqVI78ek6IVnq/KNEBd5wr5
	HIFmKjk4rdSZ7ZVd1KX/k0k=
X-Google-Smtp-Source: AGHT+IG0xi1FSFCUm3U/+TFV2PZF5OsCX+bCObfby47AUac5sI1Fggjsyo7sKizhT0MM2jD0TeZZrQ==
X-Received: by 2002:a50:8d19:0:b0:523:13df:297b with SMTP id s25-20020a508d19000000b0052313df297bmr48729eds.1.1691140012215;
        Fri, 04 Aug 2023 02:06:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:dcc9:0:b0:523:10be:e7f9 with SMTP id w9-20020aa7dcc9000000b0052310bee7f9ls43861edu.0.-pod-prod-00-eu;
 Fri, 04 Aug 2023 02:06:50 -0700 (PDT)
X-Received: by 2002:a05:6402:2752:b0:51e:4218:b91b with SMTP id z18-20020a056402275200b0051e4218b91bmr1459212edd.1.1691140010328;
        Fri, 04 Aug 2023 02:06:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691140010; cv=none;
        d=google.com; s=arc-20160816;
        b=tTPkeTxKqA2w1qrCrM3aMPkHwayJ8j+pSOzYZMO4tQwYbHVPmg+66ctZL93NzjiVyv
         B8nj1UtiSEDEGibxJqrEGhXGP79+ZOVhpHvmgCsNetEoK9EAbMIWXy8Zum+9C2u77fuB
         1pCHu/Em8Uq+IEm/V1WUR0/t3U5fI+3KYTtaeNHRDjNn4uMaspiSGDCGxq5vzbzUQ1rR
         N8j21t0AIejP+ZpwvJEDjVTwa4JFoCxOjCqcZ9TW6fIqdjsKzBQ/gry8L2tkYxWJWTMz
         OnV23iZ7r1hvWPAa9LIm8uvdOYEc3YurTSp7trz4nBaTu5trdZdPtjxqtrqvxc02sHBi
         ouLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=mbDuRBO1V21kY8Ln+XMGj8tah/dM0ZngOK9DCSez6Ds=;
        fh=J68g6MH/W7wOt124Z8Lp4h64rxBVPLWDnNTMQSSfdjs=;
        b=EjSwMYaAH2b9auBySOkO9s75RgaYvF7SHRidgf/faHJfvdVmKgMXzgDEvJEYpWKISx
         HD9frPSQYjgnae3qLu10yFckMP9b6oUmeCx1yKvsuWdaIEzHFglapNw6NdrnIN08G21X
         FLDMwlpVIERxqgzIDv92LfcRMJlQVRvOaFZ0evpjWxxPNOnIz/dfIBoHmRUXZzUIezBN
         sJKRevGNk2+6PDCY3Q5guiW+wCEMg9iRLhzIfZmyRssQrZ6ZEjdSfpyya3LjzOUyH9Ir
         IoBDdDpf00ohJCOXv7KSKFZetHAKQmuK8QvSUUx5Ydvk6k/pPB+GvqTR2Mr/qz8Ud0K2
         V+Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5+NdHYLi;
       spf=pass (google.com: domain of 3qb_mzaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qb_MZAUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p16-20020a056402501000b0052174fd486fsi133692eda.1.2023.08.04.02.06.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:06:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qb_mzaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-313c930ee0eso1032175f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 02:06:50 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:2ebf:f3ea:4841:53b6])
 (user=elver job=sendgmr) by 2002:adf:f587:0:b0:313:e68e:885d with SMTP id
 f7-20020adff587000000b00313e68e885dmr6006wro.13.1691140009920; Fri, 04 Aug
 2023 02:06:49 -0700 (PDT)
Date: Fri,  4 Aug 2023 11:02:56 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.41.0.640.ga95def55d0-goog
Message-ID: <20230804090621.400-1-elver@google.com>
Subject: [PATCH v2 1/3] compiler_types: Introduce the Clang __preserve_most
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
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=5+NdHYLi;       spf=pass
 (google.com: domain of 3qb_mzaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qb_MZAUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
recovering a large register set before and after the call in the
caller."

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

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Imply notrace, to avoid any conflicts with tracing which is inserted
  on function entry. See added comments.
---
 include/linux/compiler_types.h | 27 +++++++++++++++++++++++++++
 1 file changed, 27 insertions(+)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 547ea1ff806e..12c4540335b7 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -106,6 +106,33 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
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
+ * is supported, __preserve_most implies notrace.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804090621.400-1-elver%40google.com.
