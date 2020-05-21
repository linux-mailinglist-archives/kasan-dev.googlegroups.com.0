Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAODTH3AKGQEZ2M22JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 63F991DCBAF
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:09:54 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id b137sf2666533vke.18
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:09:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059393; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLPXSBbBbS+jF7MmHRok+b2H18vDgFS0SNlR8ZDNEBfLP9UYzUSImUk1UQOL1E+Fzr
         uJI3gMw1+K4UV+KFwb+mu0hvK9jazM3yDselJFXVHWvs9U9+pefomEtJoeiM1/erCeLg
         6K9euhQINgfbd5PNRGWTg7JAY3F7s2DI+74JE1bUqRCsy5DOmXjX65rngI3TjyVfx8kL
         fVA9DXq+zBgAprpda3PtcSJo/BIRV46JeMTAg3IDbHeljBA29JBqk/oXWFhBlwlTdq1S
         tfRHfA16UQj+oVGmSsCQ4TalgY7BTE/FLOUrxAPqc0LlX+e3bs2R264kQd0lDKREbnRL
         FYBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qfCeUL0k120wMNBQuzDZ3VdR6oTeegaiWiR8ElLEvVY=;
        b=IOaoUFWbkSqLCfODBkN3MbDswxZAQvWAb3e55X9ShVBDU2birF/2kZlIXXmFl1bj5T
         23ddL0otVIcm48pcFSd/ONvzb48OFReZmNQUreWjRjxkSfcriUap13EiHpdwvcSF8iEY
         VDjkPQLszoDCA9UHzos2/J7cJ4uavhEat0GgqPiK9/IMkDU8qWt+MVzfoHcLnxoBo+ME
         vfHZrT3PUZZp8Jj82sTZmmg1awWQoETtxqPmNRhHfgA6XLvCg+PH0pwHVuXu6xTyBPqK
         MPW1jqjWC6bkvSTMMkyHOJIumsKDQCt8HrOWBFG9La2N10en0oJ4kRX2pRxMuOnV4Rsp
         4qMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D0acVnUv;
       spf=pass (google.com: domain of 3f2hgxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3f2HGXgUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qfCeUL0k120wMNBQuzDZ3VdR6oTeegaiWiR8ElLEvVY=;
        b=qb9j4x2x0D7XDKkeB15+SR8voVXXnouklTd5at6G3TigMyuLoRVnZymmQnnK+plQpv
         3zmsxqJF+i/9ChrGHNr293aQT2gDLVq8wovp5rdKMgHiItqZEpNs6YoKvhQfmyfbV+HU
         5MAmYEuL1m96J9UsatyNeHvCu8lTNbJpUYz7mjE26u+cV/DljulTJBiKYzdr3+xKmFmV
         0Vw447Se+lOwB3n3sb+wdcxzw4Xun2vgFK+LABaIqNYKPKAp36zlgFw2aYvxK1qAWk/R
         oZZdJkB3wqQTsWmCKDvTUoSc/Kk2yHcAm4PMXN0c98dhy4sO+qHRz5SL6vVmaf4FJbll
         alCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qfCeUL0k120wMNBQuzDZ3VdR6oTeegaiWiR8ElLEvVY=;
        b=PYyG2OadVGPwOHvLnbpeC1HCuHRqTt0fz/LHaWBk9PRurlrFmrILUJWmlhdhgBBauA
         O6iZ7MBbTf/TPOr+HOAoeEJneJCdaz1WL1YjJ9gWCLFOhs/tyFCvwlJj8wN3LnLEbbdT
         eb5nxHyj7TzWjuGuU98e7mGOkc4Pdnh2ArJEmDnS8lUiPkHsgujIcdGhScSTjGOecjRB
         QhCKjnH53k7eYYJ2SgKr3xMK5iZVEyAf1/03DXbU3e6eYuECGZUKmg3Cfp1Ng3mMnMpQ
         OvsPHMGdCXiNlQ6yUOlNIVlbGILQcvuMNu8ywNBrl8HV1pS0aa0i/pRj3H//nHSrjLbe
         senQ==
X-Gm-Message-State: AOAM533aTeLNUdeU0yZm6m5ekf10TJNaF/TVrmJlC96queYsCDxL+crN
	I+otHF+19/+H6S5la2ZMZrU=
X-Google-Smtp-Source: ABdhPJxFilIJJtXwQ8oU06hfqb6mMqe2/ygH9TKFsgMtXKuq3UvH+N6lnZbE4d7CMNAIO4LyyFNZfw==
X-Received: by 2002:a67:edce:: with SMTP id e14mr6512567vsp.235.1590059393453;
        Thu, 21 May 2020 04:09:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4504:: with SMTP id s4ls57500vka.3.gmail; Thu, 21 May
 2020 04:09:53 -0700 (PDT)
X-Received: by 2002:a1f:ea06:: with SMTP id i6mr5384151vkh.36.1590059392948;
        Thu, 21 May 2020 04:09:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059392; cv=none;
        d=google.com; s=arc-20160816;
        b=Mu7Ud/aSYyDXgIA8Jno7+QJCuYt8LnHVsUEiaC4ePRR5AehxG8z0jpUty9f24MzjR7
         QdcY+JvhuF/9g+fwDNf+MqK9HgXQlvr7VioI1Ipn5utCrEhxwHKJVtLtF+WSCtSUFwqG
         ZGZd6/7q9HQmASF9B8RoiMoOv+haYqGiqao7FmPs7a8Ps+4IhnGY3yJYaaUce4ZHd6Hk
         UfETVwDTutxAqVey30XO+VAsYCtbu8e7SFWpbzzNrVbRLBxUE4PGIRUJUPP3ogiiMpw1
         WLYaBAOiglF9SpcQHkBPW7GxO7TOYtm7ypyx6NJVSZkVd2kSu35himTM7xxTYbta2ARy
         V+bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Rd50Ui3HZ2EL9EcMGbbjqrEeCeIHgbARzkGzMmh8b1c=;
        b=buG87e69+QmnM/3flx+Worq7DHM7rdy9/rNWeuLmJQt7Xgbhtw3Zc7oiMeULTmOiCX
         aZ0ZoCRIpKMUJV3WM1Kbo090lNJh4MgZp6IjH8cXaEMT3TWK9+PjixLpHDCvR67QaS+N
         daXbs5ZRYAZ51uoeVHxiJQdSy93DEq6QPAmegd7121CWY5z870n2/UMg9h2GDmu7f/uz
         PA5qTcU+CkbLTGzGz2v6lCIaru3v5R/rrwVdYJqpSWGQLSD3goemTOra9urgzvncKzQR
         36uN48wrplSYUQRKqqrsmJSRk9ScuMVReSh+aKsbcBsVpRalLSZBdiuRMIWDfbyvq6v9
         ZL1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=D0acVnUv;
       spf=pass (google.com: domain of 3f2hgxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3f2HGXgUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id 137si386805vkw.5.2020.05.21.04.09.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:09:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f2hgxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id s65so7180989qtd.21
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:09:52 -0700 (PDT)
X-Received: by 2002:a0c:e744:: with SMTP id g4mr9331224qvn.55.1590059391368;
 Thu, 21 May 2020 04:09:51 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:44 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-2-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 01/11] ubsan, kcsan: don't combine sanitizer with kcov
 on clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=D0acVnUv;       spf=pass
 (google.com: domain of 3f2hgxgukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3f2HGXgUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

From: Arnd Bergmann <arnd@arndb.de>

Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
with -fsanitize=bounds or with ubsan:

clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]

To avoid the warning, check whether clang can handle this correctly
or disallow ubsan and kcsan when kcov is enabled.

Link: https://bugs.llvm.org/show_bug.cgi?id=45831
Link: https://lore.kernel.org/lkml/20200505142341.1096942-1-arnd@arndb.de
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
---
This patch is already in -rcu tree, but since since the series is based
on -tip, to avoid conflict it is required for the subsequent patches.
---
 lib/Kconfig.kcsan | 11 +++++++++++
 lib/Kconfig.ubsan | 11 +++++++++++
 2 files changed, 22 insertions(+)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index ea28245c6c1d..a7276035ca0d 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -3,9 +3,20 @@
 config HAVE_ARCH_KCSAN
 	bool
 
+config KCSAN_KCOV_BROKEN
+	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
+	depends on CC_IS_CLANG
+	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=thread -fsanitize-coverage=trace-pc)
+	help
+	  Some versions of clang support either KCSAN and KCOV but not the
+	  combination of the two.
+	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
+	  in newer releases.
+
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	depends on !KCSAN_KCOV_BROKEN
 	select STACKTRACE
 	help
 	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 48469c95d78e..3baea77bf37f 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -26,9 +26,20 @@ config UBSAN_TRAP
 	  the system. For some system builders this is an acceptable
 	  trade-off.
 
+config UBSAN_KCOV_BROKEN
+	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
+	depends on CC_IS_CLANG
+	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=bounds -fsanitize-coverage=trace-pc)
+	help
+	  Some versions of clang support either UBSAN or KCOV but not the
+	  combination of the two.
+	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
+	  in newer releases.
+
 config UBSAN_BOUNDS
 	bool "Perform array index bounds checking"
 	default UBSAN
+	depends on !UBSAN_KCOV_BROKEN
 	help
 	  This option enables detection of directly indexed out of bounds
 	  array accesses, where the array size is known at compile time.
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-2-elver%40google.com.
