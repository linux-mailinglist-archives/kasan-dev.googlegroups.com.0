Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXA6CFAMGQEIVZSWWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 753B6422414
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 12:59:59 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x29-20020ac259dd000000b003f950c726e1sf8647348lfn.14
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 03:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431599; cv=pass;
        d=google.com; s=arc-20160816;
        b=kBPSLI6VrLvxrtn7ZyeJ8c7Q2cuHeO/drGjBRhMd1k7c7cB8i6PxmM/b2kJJ/Zgt/A
         /LQLvrx/K5S7PaDgqrggI7QvBAn+qIZEafeodyULIv94u99Z7TiN4k7If1Pud8KSiycL
         app0e8xJqwn3WS/l+CeuSVB3+7w2+bg9KPRqWas2gxtVeFHdzVTRqp940Flw4/Dp1F81
         9AyZvtmdigJGSQdVPpzjOf9jmx1ck1bGjFTd5quE3RwtNf5aTnz2POo6BfoDvMTjLVXX
         nLGdhuJB+DfLx6KEJk437YJBPfdV2lFyEUGuMrC59SvKaFvsV81kWhYmJhkFFRZR9ndH
         PDJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=2HLx7ua7WPMirsGSyRmOvIm2YVXjkYlIwicNxrby9wE=;
        b=Un5vPFGUgNPecGqxXlQfiZKQdIIuFdMYQO+oVqbwljW32Euj5fsr91XTmYDsAd7RaR
         1ZkxbrXeIu4+wwCJhcN3zBXWkmoJlkHPHet7+8qrIRyP5KzXHj9ldfF30tVE+xb+5bbW
         KckLxxjLvYSbZVHa+Tp4IB9lZfLPOyGepT1BUdO9i+vPAcEPlmStlP4gqhit7KcOdJq9
         whwQDyykuqXEywjVmEH+ccmvGR66wlU5qhs8xnZxp7LzcW/LbFhW69vlvuo20lGse/iz
         x1KQzGkZ7MgQ8Fmn/W30x6EaY7G7YhdqXkL7NT5nTcgfu86qGUIy4LoFezmWgswFQkp5
         XhOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JR+7ySSA;
       spf=pass (google.com: domain of 3ldbcyqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LDBcYQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HLx7ua7WPMirsGSyRmOvIm2YVXjkYlIwicNxrby9wE=;
        b=TyPisDH9bV3dH8xWz2ltCDnxPnjlRq9nlJdMg+VBJHLUh/Oi/eelFdmsIWKK4r5Poj
         27gl9upiyDj5Aj6OhOxJPYl+odzbyMHG6XX/G2MQ1YX38sCCLetL3hP0jB41/uJeoSt+
         jzNGLS+o4HKWUmbYxupSyPfo51xSmRCm9F93n75eo0p2g2nQp4/RfrwHUkWXDICJEZE6
         LEUmJlVFNOkVco/KsQMPXJuHD93IYQb0bBrrTYnwkClMsBc2pJyyThn8ost605QwWiT5
         1wkqJjqcHerkdqV18bxu3/Sb0nhYl0AkQXG/zsv/zZIHOnvQkROziNPC0Hr9hi+l7pXp
         2yZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HLx7ua7WPMirsGSyRmOvIm2YVXjkYlIwicNxrby9wE=;
        b=q0/deM2ke8/+8U35Apewg85/CgcJTWl5I47lmKveEZ++vFEWSwbahJUyeqUc0S8+/5
         +r4yZjSyuC5te2+JXr6yTHz0m4cgPIRpgAA1IPM8X+tlUzAwRbSMqFFRKLtxFAwD+Sbi
         poGppv5jcPXlrFqcErWMoNXdhpC2wFq2ApPNTaduT/AFplZeSJPb9oe05WhvGjYbmsUe
         N/WeliHd8vPGyWijTTJsT5IBXNgt6WkHfpFQ9vSrGfLOiGT+dxnyNCsBMAMm6VV+7LwE
         XRIlMfNoGJ00foFGmzaxvgpF+gnzIugYipuuYJsUlrdgLa6wCUAHaq3Yy82Bv9b4WtBb
         Ms9A==
X-Gm-Message-State: AOAM533gEZK8s9+jp1eIaijBlChAcA+F/+An2Z95zhoRs/4b2lQ8O4oI
	YvdqkapvWCaJ3CMkEZC/sRM=
X-Google-Smtp-Source: ABdhPJwsKRdJyH6iRh7sf8b/9BapiRxAT/XhORn8fAuKVbelJWAmtZQOmeUzzbwOl/vkGMVLzNtFrw==
X-Received: by 2002:a2e:8787:: with SMTP id n7mr20428966lji.278.1633431598943;
        Tue, 05 Oct 2021 03:59:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls27746lfu.2.gmail; Tue, 05
 Oct 2021 03:59:57 -0700 (PDT)
X-Received: by 2002:a05:6512:1593:: with SMTP id bp19mr2824046lfb.65.1633431597871;
        Tue, 05 Oct 2021 03:59:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431597; cv=none;
        d=google.com; s=arc-20160816;
        b=JZkKU9zWg+P7YUfIBU2lwHjoc7nay2bWRzdM6WdWTZwfS+lAMxoFdVyE/wj4/T1LlK
         YjSN22EieRS5tKb/WfUW/YYTDkMdjNuGcKysJb8/sM6pQBsD8SFpYVxdo1NVcbiHIM4b
         lbUp324ZI3mS3RTESJLHUczNCGEE4PQjl9KfWZrkQ9AxdwpoqeHF7JcEXQh1z0iwBFuD
         XWKA77N/5RXJ3XuQXVZLtDoXI392pzYumyB68FuVzf+tKWRap2hI+4Al/9qngSNAFqB3
         nY1bA+7LdrWTals1XWg7HPqMLDs7KtiFb09rcTkT3gZ2hu7ig3CwJW/sK8Z0PYuVBJ//
         6Frg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=8oN1Tye/sfpVxOoza0f1n5GzdtTeuegmg43uvYtdPIg=;
        b=JVtmiFZW4IYKHlTTisWnykrggZBVUQzYCL0jP5t/p2pxc2g9zu+VGck2uOUVffB5pF
         +jOa52MBwHFfRDFWrutO+WuSDrSB1hr0u2GI7h0QkQ3Kp/GCJyA/loC8oe4+8tQOhl8Q
         4yKKWcMnJoHV6N+2fgrOns4DT5l0GgdhlaonE99i5T66okPadcaa7g406LMxy911CHv3
         osxOmBcKeNm8SyQyPxzhew+kQR9Y+2s7uLUU8JnMo+xwd9Su+JsNdIrmgFYzXWWlD4h+
         +j+RaCIURknYTdzIAhNy/4U1hxwptJg8QUz6V/9arV3+UnU0CRVO0AGYv5ya08sBdx5A
         b2Bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JR+7ySSA;
       spf=pass (google.com: domain of 3ldbcyqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LDBcYQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id e14si878240lfs.11.2021.10.05.03.59.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ldbcyqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id a22-20020a7bc1d6000000b0030d7cab7223so338397wmj.6
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:57 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:600c:3b26:: with SMTP id
 m38mr553969wms.0.1633431596812; Tue, 05 Oct 2021 03:59:56 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:48 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-7-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 06/23] kcsan, kbuild: Add option for barrier
 instrumentation only
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JR+7ySSA;       spf=pass
 (google.com: domain of 3ldbcyqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LDBcYQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Source files that disable KCSAN via KCSAN_SANITIZE := n, remove all
instrumentation, including explicit barrier instrumentation. With
instrumentation for memory barriers, in few places it is required to
enable just the explicit instrumentation for memory barriers to avoid
false positives.

Providing the Makefile variable KCSAN_INSTRUMENT_BARRIERS_obj.o or
KCSAN_INSTRUMENT_BARRIERS (for all files) set to 'y' only enables the
explicit barrier instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.lib | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 54582673fc1a..2118f63b2bc5 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -182,6 +182,11 @@ ifeq ($(CONFIG_KCSAN),y)
 _c_flags += $(if $(patsubst n%,, \
 	$(KCSAN_SANITIZE_$(basetarget).o)$(KCSAN_SANITIZE)y), \
 	$(CFLAGS_KCSAN))
+# Some uninstrumented files provide implied barriers required to avoid false
+# positives: set KCSAN_INSTRUMENT_BARRIERS for barrier instrumentation only.
+_c_flags += $(if $(patsubst n%,, \
+	$(KCSAN_INSTRUMENT_BARRIERS_$(basetarget).o)$(KCSAN_INSTRUMENT_BARRIERS)n), \
+	-D__KCSAN_INSTRUMENT_BARRIERS__)
 endif
 
 # $(srctree)/$(src) for including checkin headers from generated source files
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-7-elver%40google.com.
