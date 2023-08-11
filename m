Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHVD3GTAMGQEMOUBY5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DAC87792D2
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 17:20:00 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-56c13bf96b2sf2189612eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 08:20:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691767199; cv=pass;
        d=google.com; s=arc-20160816;
        b=b+IdsmubmeK6OFrc6YHKeQL/XTjWOwztrVeguz1HiHe29IP2p6NQgX37cA1FcTW8qq
         DYIKXGvHIO9ch0IR9fzVSg7gF94/NXRckvBAnfcfEHPB5IOgCAv97+lNXNlzMtdEpmAy
         kBjCuLMdoc5sng2SnKlpCYtP6I8pJnavMPvPkaEQoNgG8i2pyLbwQly5m5bWBbJkLgDi
         mxDKsmyAu7v7Kn+AAQW53E4Iyl9+PGrTE1Axw2TfUZHafaVW+LM5DDLXIdUoTlP6a5md
         3iuYzGMhFxgwNDtBZRkQLZ6MGeUODRLdZMoJfXCKHCC+z43pOEUUFimA+YYJ82EL/Wvu
         wdZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=MXjn6ilJiGMOVI/KJHQ3sOj4UL1tUHnIHo/Fuj9Jyp8=;
        fh=qzUwxS9h9GHZXLKRdSveNA0UW/h6SdpMH03X1Oyv03c=;
        b=cawOWg897hqpMTYwffmmT6YfQ01N5MYjyu499pyjgnbwFhFAak7nJQYruDtNU+B/mP
         KWUuT5Zuy8tf0cXMK1q2+XJsXv5glqPoj+ieBpOhXVorBX9rhHsChWpwszYiOnEd6eyR
         vFJ937gTdP0zcURzbauldMPzs2Y0EUEth7DM2F9hJHONH5AFG0jHEBrt0TJAfc2fQa7h
         TIxkLUZbo754hyXxktuMZuZpwqAk3p13VKK50PowdyxhYT9a7FUrpDGbKCDySdWXKxTb
         ESh4yyD2dRs3fGaFxY5ahjDINIWoSMLVZPO0xM4g4ihcXPqNntkhC1ZzfgT0df7Gv99M
         N8xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5xqJ+9vO;
       spf=pass (google.com: domain of 3nvhwzaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3nVHWZAUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691767199; x=1692371999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MXjn6ilJiGMOVI/KJHQ3sOj4UL1tUHnIHo/Fuj9Jyp8=;
        b=N0/jAHT2zRAUsvBrR8qvVqKD+hQZXw0VTZK1RgKQfyaM3CQ3Uq/3+8sgoFIsXIXH0O
         8dQ3eo3ayGeIR5ZehT8hXFJ2G/UDVhXblxKKbXlEbefsP17TkzhMVJwEbSWeAWoZUu9b
         N+T8OE8Szo/ZHxDILCoibhniwrslAeqhMbpVlWoTCdTVld/qvbsi1aqXcLHnzzoE9y7u
         Ae05HHQudBmSjqkCK2QPrvho0g+zc7RQw5aXz8YxJNwPX16bW/Ohli96gX5uH7x5JmR0
         Jux0pmjn81RlFD+qpMnsYQN14MmScLLHqTbLIG44aICIXkNfGrBEwHiOqiqf/gwesCoq
         W9Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691767199; x=1692371999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MXjn6ilJiGMOVI/KJHQ3sOj4UL1tUHnIHo/Fuj9Jyp8=;
        b=fcArWz3cLlAf/bLw5bDcJo/zkrO0PQZ03rYztGDRPKtfC25FIGHqk+duWSxgnv8KIS
         LcNFLaDQjezEtk6ZXYm/Xtb3CIH0UZHjThOSi6KB28UcRTebF6vnpyKGQMCyfTjXgxTs
         BEKS/VpHlO+lknU8tMFxTQS5uwWdMu91j9DqQfgRbFQjRSLiMDaQYbjdjO/TSqYifeBH
         8GjVrCMa2IGSPMiwVDOVLrGmPdgL7SRyxnGJIkGhnrEWqihzfwJ6RBLQFUrwA7XiGiEZ
         UJV4BLMAuscmBBICITFkLiaLEcj9xpu+PuXz8lX4UAOVE+n90qvEgRXxaiTIgA0FldH4
         E55w==
X-Gm-Message-State: AOJu0YyAZeUnz5sDUdVPAJ2yZuqTfyQa6Y020SLiTCwygnYS7xV+3V5t
	7CaJR33zC9JtBzMIDlLJe8g=
X-Google-Smtp-Source: AGHT+IGcWLIkyaAs79wVa4pZxBmZNu1+4taTLQOkei5DtBy0v7+G1mxm3zfi1dBGeqYVhT5VwVMoLQ==
X-Received: by 2002:a4a:d1db:0:b0:56c:e4b7:2c0d with SMTP id a27-20020a4ad1db000000b0056ce4b72c0dmr1719564oos.1.1691767199004;
        Fri, 11 Aug 2023 08:19:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5890:0:b0:563:492f:3514 with SMTP id f138-20020a4a5890000000b00563492f3514ls1857285oob.0.-pod-prod-09-us;
 Fri, 11 Aug 2023 08:19:58 -0700 (PDT)
X-Received: by 2002:a05:6830:1497:b0:6b7:319d:281e with SMTP id s23-20020a056830149700b006b7319d281emr2084031otq.19.1691767198246;
        Fri, 11 Aug 2023 08:19:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691767198; cv=none;
        d=google.com; s=arc-20160816;
        b=mRFcJl/kPrS4SyoDpziQiAPZz3Mi3uTF7jVJoE+7DjIzJRktahVHFZP4PQftwe5PU0
         n4DJZxTTbsoTwjnWe8DQquLdrCTqA8iVvkIePgKiyRsPsSR5tPTNOZGdj7pSk7k8fQ1i
         Dj4D0GbRbhMqpVJYzsM09lqSVwDAEKTPUruOm5ip9Zckp4VUb4QuX/+tbY8ewQVIKroU
         /ZcazuQ1/a2UGTFl/4EXB0WPGAauM+TaulWBHr4NXMxRcz8Itcyh+0hKeIF3HRkt8cPt
         dKXSttFYQimgqpbJNgUUSvme/n6zHRjvh9CbqqwizUZUYlGd7FQGbl0/xCnb/1AMbeEA
         iuUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=1vaThr58cHhzt3vCJBdqBIs2Yl/3Z2jvMp4OgQvCHVc=;
        fh=xh/g7dNJbwYr9WVB3rCguj1R0VLL65UcAaOvl7LeWOQ=;
        b=QiMJZAsQ6Y7UPSoaPQj9FFPILM5k99r8aIos/IPUCXf3fEkXGrZ8OteNyPhHzKGWsC
         1cLXNh0TnDjnLtSpjoKQdmWAx+Ot12vCqv2LaQLHJZpAuoIDWC98ciOf+71dLk4y+ehM
         ZMZTIdK5X2C2br2CP5Ds7nyivqdsSxvbt/VuxHqj0mjN1wztOOCgonIZenad68dE0tSj
         bUrIBTI1Akn1riMpSxb5xG50G/dW8h8rf79u23Ci7fXIySgkPvA8W/jgFx0dNI38f1gR
         Vikz0O4g9UoMMP+pk5vjmLvmBQVpqDUEL5bnTqoqa20XXr/ZafnM6o1qDZ7un5hCN8Fy
         hUEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5xqJ+9vO;
       spf=pass (google.com: domain of 3nvhwzaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3nVHWZAUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id y21-20020a9d4615000000b006b885923798si333544ote.2.2023.08.11.08.19.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 08:19:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nvhwzaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5867fe87d16so25179957b3.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 08:19:58 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8dc0:5176:6fda:46a0])
 (user=elver job=sendgmr) by 2002:a81:451d:0:b0:589:9d51:c8c0 with SMTP id
 s29-20020a81451d000000b005899d51c8c0mr41482ywa.2.1691767197794; Fri, 11 Aug
 2023 08:19:57 -0700 (PDT)
Date: Fri, 11 Aug 2023 17:18:38 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.41.0.694.ge786442a9b-goog
Message-ID: <20230811151847.1594958-1-elver@google.com>
Subject: [PATCH v4 1/4] compiler_types: Introduce the Clang __preserve_most
 function attribute
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Paul Moore <paul@paul-moore.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org, 
	llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=5xqJ+9vO;       spf=pass
 (google.com: domain of 3nvhwzaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3nVHWZAUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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

Note: The additional preprocessor check against architecture should not
be necessary if __has_attribute() only returns true where supported;
also see https://github.com/ClangBuiltLinux/linux/issues/1908. But until
__has_attribute() does the right thing, we also guard by known-supported
architectures to avoid build warnings on other architectures.

The attribute may be supported by a future GCC version (see
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899).

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Miguel Ojeda <ojeda@kernel.org>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Acked-by: Mark Rutland <mark.rutland@arm.com>
---
v4:
* Guard attribute based on known-supported architectures to avoid
  compiler warnings about the attribute being ignored.

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
index 547ea1ff806e..c523c6683789 100644
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
+#if __has_attribute(__preserve_most__) && (defined(CONFIG_X86_64) || defined(CONFIG_ARM64))
+# define __preserve_most notrace __attribute__((__preserve_most__))
+#else
+# define __preserve_most
+#endif
+
 /* Builtins */
 
 /*
-- 
2.41.0.694.ge786442a9b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230811151847.1594958-1-elver%40google.com.
