Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXNX6CQMGQEZHRFWYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B46939367C
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 21:44:55 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id b44-20020a05651c0b2cb02900ec3242ba00sf714561ljr.17
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 12:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622144694; cv=pass;
        d=google.com; s=arc-20160816;
        b=t02l3hF30SAqsq7yqGiS6HurgYAw0NW0y4yFwisejoUpkyf3RgnuyO0Pb8IhA/9IWr
         HlrjU2gXtkhQcKSbvhWUy+TJkM67JidpZ/PQ+eQzGHotg7pK18gwBZqXnBqYRTpfYTrR
         i1AtQ9hQ3P47OYYTIubML0E7NejbaEXe614BHhQrf+dOs/i5ilxjKVXBEi7JFI6wuQP9
         2SAGsMx3svGxGwzDFFv7PTsteQ7Fm6htaAflnXR4CMt1Xk2OStYZiIYuOH7A67RjJAIU
         GOOV0LlR8U521BjtYmPlS9UaMy7hEXzFbPMlahwP/mIzDkTj2CXByd/Szs0d0b6AHEqX
         ZDLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=6NThG3ildhGOUK2Klx5uo2/edkLTavmVmlyryPwi5e0=;
        b=DlaW2D5TUMxuSqFkshCYxm0gz0QOivdACiglgXnMQBpcugvEGwk6etwsn/R8pEW3CO
         cxYobbfcuMjo86S3XXDYCLZSbridzbXZiVflBsdnWnbjFobHT7xdrry0DsN0210Sss3Y
         UfRZwk6IvsbK8MHcPXCoWvERJSSeT/DxSs2OqHsmISjuvEk9gf6wG6tNCJqJ7uSEh/oo
         MIA8DCecjzAzs0AnxRkTSWshwaFyPI9KzgOUg621kGNLe3MdSrGoCESqzUpXxGS5JGGn
         ND5ZRug7QZX0PuvkceZfXi6os0o8luNWdM1Uxtr5Lg5kjDvjOkbHL6EoYzvSN88aQAfJ
         GaSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tiNPJmmI;
       spf=pass (google.com: domain of 3tpavyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tPavYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6NThG3ildhGOUK2Klx5uo2/edkLTavmVmlyryPwi5e0=;
        b=jhAuQt6NbXzf+0mMlt+fh0nFCnDV7aewfMJG1uEPRl51q/f4AtOaJ80qH8Us/hqvLS
         nThVNpdNPFbJxJzBwHx1qIwatfL8hua1SYV+He7QuQz3JnbVi5AwqehMyHJcXpRpzi99
         4/hoHya5nkTkDFegbHCfRDZDZo+g6nzT8k6Rw/KlHTmynWtvSPF3LwUEY2AXBIFfau3s
         imnGXeYnxvpbKmmWSF+/6PJXrs8EZxMU/Ftl7WEHjqC5JLrlnV0bla7eCpUCfDMAnjUY
         8jN1NFjTRmBWMyYM7yKQdH21Bt2WxSjpZKStC27jefTSG77i3hSWE5X1clXBQE+N7Zd2
         9gqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6NThG3ildhGOUK2Klx5uo2/edkLTavmVmlyryPwi5e0=;
        b=K1078DY6iVSILxOG51VQOTVnLQcVZS6XFldt4DIXtWWLF8tQxcCN10Dm73aRqfzaYU
         KzED8TmIjaH+k/PXyFExEun7Cpncybqh8khqwMB05nM2ZLerVtUN6A0IWJx1LNk7dZew
         1IvtGSCXCujrAJ4ymp5iM340i8euiaZFpipC1jh62tbPzk5BlCC+w3MPXcBa5rBsfZCj
         vcfA6UX/rN3iL0uYj8Hlos+NJvI8KXTmSfcFSF2xOoHrGvrRv7dQvuXWlAQmi0WBYGfZ
         ZY6vTEPeBiSZSkJT+jbWGT4C4Y8qRPMi1rmZ473Sa0GY7aF2CaTygjvX5VIFxg2ktncQ
         cZWA==
X-Gm-Message-State: AOAM530n/X0l7yNVALtIe7b6FrqvkSYeMOfdKfm34Ga7hA9IHQpUNcnd
	zOFOpAxVotGWKhRioSKNbgA=
X-Google-Smtp-Source: ABdhPJxi/4xcd0Ie0HEIn0r9QKqS916DTbiNimT7gPXkvj2ufPbjwgTihfH6v4H025EuAIMEgwf30A==
X-Received: by 2002:a2e:8859:: with SMTP id z25mr3888291ljj.186.1622144694689;
        Thu, 27 May 2021 12:44:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf0f:: with SMTP id c15ls903682ljr.9.gmail; Thu, 27 May
 2021 12:44:53 -0700 (PDT)
X-Received: by 2002:a05:651c:a06:: with SMTP id k6mr3831846ljq.347.1622144693528;
        Thu, 27 May 2021 12:44:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622144693; cv=none;
        d=google.com; s=arc-20160816;
        b=q2hrcwI0V7PzVWe+ojcwKHIocsXgVsAbyART/vJeoToXNjxx9gtwp4w5VW3IaJTVm3
         QsgCSUMMNq3wTBH0kMyVO1oEMqm4GrMFXVYnyqeG4Tw/wI1vySfdRTNsFb+vIHnNHkZX
         T2f4eO9AnNbxtsmEKxQA7UJ3jrxtv9GaV3HvlZt8bEes8/495dYqVwmEUAIYmnA7MyAM
         B63iDZkjYNINKdI+X2HnfdPaZxjihrSXGTFhVBlRiWB3JLeuE1RtfXDwSHbZp9NFWGKm
         D/96zzWBMIYu35XGhnvf09y5tQ3yNr93fdjSi0IGY2ci7iWXRfmccKSsdTF/ALIvj5Ip
         sivA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=XdQqGBQo4mWdmTmqfcsPAW5aXAD9T8KofAFcju284Qk=;
        b=Z01ssTVmLCjQXYtsklzsF7cbCoG4NDazoZ+W0XysPYfiS3rHZivfXuKRqnoesMYjAm
         bdXjCIm6xXXYRM2ny1P7qk6n/qFwcXfyg00m/7WYGLriAc7/7H6U1WhMRbfZgtv8SZIW
         avaM7ZdK6HJXqBFQeQ10zmoNQdKo1qH1YKb4UJoq2MxdxZ6jCrkvX2EVJAndYmdxeXP1
         cGWPCIhFGcSNKkISRkuZpnNQdpsju7Q7jGE8Jvt8wH+rVjv8PqXy/XxpuKO7/3kPvxlV
         uJdYxDkPDiQA7zeHj93/QDTu/iC7OR3SauyPydY4bu+47424Eh/Rno9dslgTkYs559Id
         tYqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tiNPJmmI;
       spf=pass (google.com: domain of 3tpavyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tPavYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c6si107882ljf.3.2021.05.27.12.44.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 12:44:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tpavyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id w3-20020a1cf6030000b0290195fd5fd0f2so568118wmc.4
        for <kasan-dev@googlegroups.com>; Thu, 27 May 2021 12:44:53 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:d65:1a6a:e560:4abf])
 (user=elver job=sendgmr) by 2002:a1c:a401:: with SMTP id n1mr8834184wme.30.1622144692871;
 Thu, 27 May 2021 12:44:52 -0700 (PDT)
Date: Thu, 27 May 2021 21:44:48 +0200
Message-Id: <20210527194448.3470080-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.rc0.204.g9fa02ecfa5-goog
Subject: [PATCH v3] kcov: add __no_sanitize_coverage to fix noinstr for all architectures
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, nathan@kernel.org, ndesaulniers@google.com, 
	ojeda@kernel.org, keescook@chromium.org, peterz@infradead.org, 
	will@kernel.org, nivedita@alum.mit.edu, luc.vanoostenryck@gmail.com, 
	masahiroy@kernel.org, samitolvanen@google.com, arnd@arndb.de, 
	clang-built-linux@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tiNPJmmI;       spf=pass
 (google.com: domain of 3tpavyaukcw0pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tPavYAUKCW0PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

Until now no compiler supported an attribute to disable coverage
instrumentation as used by KCOV.

To work around this limitation on x86, noinstr functions have their
coverage instrumentation turned into nops by objtool. However, this
solution doesn't scale automatically to other architectures, such as
arm64, which are migrating to use the generic entry code.

Clang [1] and GCC [2] have added support for the attribute recently.
[1] https://github.com/llvm/llvm-project/commit/280333021e9550d80f5c1152a34e33e81df1e178
[2] https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
The changes will appear in Clang 13 and GCC 12.

Add __no_sanitize_coverage for both compilers, and add it to noinstr.

Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
if the feature is enabled, and therefore we do not require an additional
defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is
always true) to avoid adding redundant attributes to functions if KCOV
is off. That being said, compilers that support the attribute will not
generate errors/warnings if the attribute is redundantly used; however,
where possible let's avoid it as it reduces preprocessed code size and
associated compile-time overheads.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Miguel Ojeda <ojeda@kernel.org>
---
v3:
* Add comment explaining __has_feature() in Clang.
* Add Miguel's Reviewed-by.

v2:
* Implement __has_feature(coverage_sanitizer) in Clang
  (https://reviews.llvm.org/D103159) and use instead of version check.
* Add Peter's Ack.
---
 include/linux/compiler-clang.h | 17 +++++++++++++++++
 include/linux/compiler-gcc.h   |  6 ++++++
 include/linux/compiler_types.h |  2 +-
 3 files changed, 24 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index adbe76b203e2..49b0ac8b6fd3 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -13,6 +13,12 @@
 /* all clang versions usable with the kernel support KASAN ABI version 5 */
 #define KASAN_ABI_VERSION 5
 
+/*
+ * Note: Checking __has_feature(*_sanitizer) is only true if the feature is
+ * enabled. Therefore it is not required to additionally check defined(CONFIG_*)
+ * to avoid adding redundant attributes in other configurations.
+ */
+
 #if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitizer)
 /* Emulate GCC's __SANITIZE_ADDRESS__ flag */
 #define __SANITIZE_ADDRESS__
@@ -45,6 +51,17 @@
 #define __no_sanitize_undefined
 #endif
 
+/*
+ * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
+ * with no_sanitize("coverage"). Prior versions of Clang support coverage
+ * instrumentation, but cannot be queried for support by the preprocessor.
+ */
+#if __has_feature(coverage_sanitizer)
+#define __no_sanitize_coverage __attribute__((no_sanitize("coverage")))
+#else
+#define __no_sanitize_coverage
+#endif
+
 /*
  * Not all versions of clang implement the type-generic versions
  * of the builtin overflow checkers. Fortunately, clang implements
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 5d97ef738a57..cb9217fc60af 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -122,6 +122,12 @@
 #define __no_sanitize_undefined
 #endif
 
+#if defined(CONFIG_KCOV) && __has_attribute(__no_sanitize_coverage__)
+#define __no_sanitize_coverage __attribute__((no_sanitize_coverage))
+#else
+#define __no_sanitize_coverage
+#endif
+
 #if GCC_VERSION >= 50100
 #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
 #endif
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index d29bda7f6ebd..cc2bee7f0977 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -210,7 +210,7 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address
+	__no_kcsan __no_sanitize_address __no_sanitize_coverage
 
 #endif /* __KERNEL__ */
 
-- 
2.32.0.rc0.204.g9fa02ecfa5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210527194448.3470080-1-elver%40google.com.
