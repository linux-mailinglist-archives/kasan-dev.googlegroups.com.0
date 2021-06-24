Return-Path: <kasan-dev+bncBDQ27FVWWUFRBTP5Z6DAMGQEZMB5B5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63D393B258D
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 05:41:02 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id t5-20020a922c050000b02901edcb27f61esf3165866ile.15
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 20:41:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624506061; cv=pass;
        d=google.com; s=arc-20160816;
        b=pw3k2UaeeeAcbufZMDk4ZKg4LniVWgSzv4wTusPqnaqwScJE4n9w92iH3/SslmsPa1
         wOXmOJ0xbdFIba/cSJnLWLhACGMTWnzPaTnpAZXLQFm5dpxtPXoNyv3UgLrvWFGD0BIS
         5AayfWj4ietsfdbze/LLzoaqI/AdhlyFejtw3EBxBRt13ouqBrYGGbPR5nN4m7yPfmQO
         ZMVerzG1PZmA5IK4mhUbGOmbO/AE2OrnX5ZY/zRvbfQiPXSCMjvvTJq62rtwyYKP0uFh
         4fYHYhlvHrctBGXhS7ZgNxX3wX7g1nzDfakZx0HxRJGaxpptiHh2veSyS9+bdC6VUuAX
         XQCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cUw4oU0s3FJhJShuLS8ibpqcK3MSyDBTOi21fDRzdto=;
        b=EA/SZ2A1jKJ8pfWl/tZlp6UgOTVylBACMMjkVflTRJoJFXxBoj0yQkj4eUYgXq9OJ9
         c7eILU90tekEdtSiERaPExxO2SWTEWbAcfz0czOn5QIiU/VFCnxn7n1ixzs5YFdkaLEc
         7JzBJy4J9rPqAIK1Falz6DRz3AQMPyRhFo7PtCjCKkhFsXPEfgx0cORYtdJmKv2p6C4o
         eDdBPr15vIcqsauTYE2V+4MKgPFxiLhNyx02veslNqCUN5IkpT+PESNXFcyoLVBLgA0Q
         wCZC7z/sVDaV9RwIex/rCWqGrBHKJudccwfXCZce3qt7nex+Jou+KnTb/Wa1mTfsb48z
         NPyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=D8DjGwJU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cUw4oU0s3FJhJShuLS8ibpqcK3MSyDBTOi21fDRzdto=;
        b=Y42YenZ03mSTWEMd8vOBSN82jUC/3sc0YFnKnh/8su9d8tcQ/uKE8dhka6Bk4xZb31
         Q829nLy67fq/LHS3bkXyrhBwuJQaK+pWOp+r0CulfH7fgV4JdEBY3su6be2q9QF75+nq
         fUnz8K4jKCVyMJV85tZWJiOX1aRTBLuy+JmzebjxqIi+/wZGPcEtQqmeOJsWGWUq2DPt
         kXDHjf9K34Q0P5fGH9AMkGSQrsKHr0Q5488jRlM2GswLqbniLk0WEFlsgWV1j7ORE1Zv
         AWmTMYYhrlUfgvgES4DUBXTr3Rlg3Mio7e5TbKd+PDjFfXV1aLsRqc1Jly4FFGfE1FDj
         Ng7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cUw4oU0s3FJhJShuLS8ibpqcK3MSyDBTOi21fDRzdto=;
        b=X/uHZYyCv3N3h/S9+eHh4m1K5bQKuTa0NhHQdsKMSwQFSXCPjK2o6DHPajK97wu/jM
         3cChB8COqG/vvtYgL7tqJqLXyIkvkpfiuav5LlfaLNBazEuJsYcoDB+LFO3/l4QKqEsb
         J17OZ/wBszflp5qabD8x7/W0Ph8w4lCOCTqoC2jlRxXa5nA2KWRV7RdwEgQxLdIVZSxe
         bFdudU3iXsL8hYwamueZBTQZq7bild6Wvsv5tzr4+8r33qzIRj1+RSVVcqIhvVOPcT65
         X9xsWT+AIZxWyD4MP7oSOYaAULQ7MY3hJS3TGJhr0A7kcGC8Pt7EwU1+vr0cK2BZvbCZ
         EHGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533E70f6KGw83tjd/KCt7IJp/hmJSaxKxFWJ9H4qMqrsv5j1FjEP
	dJEBeD5LSwtc4wY5dG5NKas=
X-Google-Smtp-Source: ABdhPJx5ndqEeFDZ9B8wk26DpkQIU0bIvzIpgEycr8pDlO1kmOsHwwLEmo9C/jqDGnJI7mRtBzGGqg==
X-Received: by 2002:a05:6638:13c3:: with SMTP id i3mr2722259jaj.140.1624506061160;
        Wed, 23 Jun 2021 20:41:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d205:: with SMTP id y5ls1039328ily.9.gmail; Wed, 23 Jun
 2021 20:41:00 -0700 (PDT)
X-Received: by 2002:a05:6e02:20c3:: with SMTP id 3mr1965437ilq.131.1624506060783;
        Wed, 23 Jun 2021 20:41:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624506060; cv=none;
        d=google.com; s=arc-20160816;
        b=XJocmNN+IQlHRwYB0wR94ZiEIubQl8BGrUJ/67u6MuHadPfi+hvDNFXy5nNmFkDpzT
         TtOc0JXZx7UR2wSai3p3e6unDJpepEU027Ikl78Ly+rE5Sx7rZ1sLz2ooGKmjp7wulYL
         Ay6hj24cqI84Ku5bonmI6K2XHrz5CiJ9e4lC2qHSkXMOybomWlZk95uMS1DmbtjoyOtY
         o7ebYSWFI56tja1dnCUSraSy1hqTw+aUPCLrftEs8gAiaUvC7aTIs3/WKTfJPhQkfE3v
         oaBHT3VzzFqQ+OiHfqYj8j6S2bzKOQEtgEfC3T9ezrO6R7zX80Q7Vq5PIv7Jn8JIWSej
         cwwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sf2vC4DdejXn0TlyY78AewZhU0SgkUPuFBMazAbHZK4=;
        b=F4jb6BKWu5FwySNicUV/qDV5ZJswJp4uM3CVaU7F5xG2WN3pKMVeLmykMGFBWfvmEp
         yPyjdsB8T/lKmS7SLPQtKnvhEErR0BBltkNTlWjjOZka/sXniW0dw7PfoTHo2OLA83oG
         tGydfFSKYGsWZiq4rhBCV1rEpABbCYcgVPhK+tvWi+oNL/Rt+eleUNN1OzEQqKaOH7zW
         V0hoAC2/3+C87WqvqzECmvbUtyMauB2cpE3txN27MKzhhvwVcYhyv0TYMu8FTT3CBx25
         Q4LkJohfQoAHQtWbBLbzZWyrVxObZgRybqEhRKNdp4kWYIMXNyL8pAZX+kw7+vpKUK8O
         sS2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=D8DjGwJU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id x4si87944iof.3.2021.06.23.20.41.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 20:41:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id y4so4002930pfi.9
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 20:41:00 -0700 (PDT)
X-Received: by 2002:a05:6a00:138f:b029:304:2af5:1e12 with SMTP id t15-20020a056a00138fb02903042af51e12mr3014900pfg.5.1624506060335;
        Wed, 23 Jun 2021 20:41:00 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id p6sm6789262pjh.24.2021.06.23.20.40.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jun 2021 20:41:00 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v16 1/4] kasan: allow an architecture to disable inline instrumentation
Date: Thu, 24 Jun 2021 13:40:47 +1000
Message-Id: <20210624034050.511391-2-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210624034050.511391-1-dja@axtens.net>
References: <20210624034050.511391-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=D8DjGwJU;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

For annoying architectural reasons, it's very difficult to support inline
instrumentation on powerpc64.*

Add a Kconfig flag to allow an arch to disable inline. (It's a bit
annoying to be 'backwards', but I'm not aware of any way to have
an arch force a symbol to be 'n', rather than 'y'.)

We also disable stack instrumentation in this case as it does things that
are functionally equivalent to inline instrumentation, namely adding
code that touches the shadow directly without going through a C helper.

* on ppc64 atm, the shadow lives in virtual memory and isn't accessible in
real mode. However, before we turn on virtual memory, we parse the device
tree to determine which platform and MMU we're running under. That calls
generic DT code, which is instrumented. Inline instrumentation in DT would
unconditionally attempt to touch the shadow region, which we won't have
set up yet, and would crash. We can make outline mode wait for the arch to
be ready, but we can't change what the compiler inserts for inline mode.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 lib/Kconfig.kasan | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cffc2ebbf185..c3b228828a80 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -12,6 +12,13 @@ config HAVE_ARCH_KASAN_HW_TAGS
 config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config ARCH_DISABLE_KASAN_INLINE
+	bool
+	help
+	  An architecture might not support inline instrumentation.
+	  When this option is selected, inline and stack instrumentation are
+	  disabled.
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -130,6 +137,7 @@ config KASAN_OUTLINE
 
 config KASAN_INLINE
 	bool "Inline instrumentation"
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	help
 	  Compiler directly inserts code checking shadow memory before
 	  memory accesses. This is faster than outline (in some workloads
@@ -141,6 +149,7 @@ endchoice
 config KASAN_STACK
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
+	depends on !ARCH_DISABLE_KASAN_INLINE
 	default y if CC_IS_GCC
 	help
 	  The LLVM stack address sanitizer has a know problem that
@@ -154,6 +163,9 @@ config KASAN_STACK
 	  but clang users can still enable it for builds without
 	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
 	  to use and enabled by default.
+	  If the architecture disables inline instrumentation, stack
+	  instrumentation is also disabled as it adds inline-style
+	  instrumentation that is run unconditionally.
 
 config KASAN_SW_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210624034050.511391-2-dja%40axtens.net.
