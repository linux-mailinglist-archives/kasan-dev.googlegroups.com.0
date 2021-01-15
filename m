Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDNNQ6AAMGQE3CUES4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E4942F82F8
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:18 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id h25sf471750wmb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733197; cv=pass;
        d=google.com; s=arc-20160816;
        b=XlLcIqP7mklvlgzGYRxkfTTZ+ifYPCCEA8palEFw+Q3rcVaM33FgiGrTov0HiSALJB
         m3sXU2mISgtKc1G8r84BrX2PRKhVels0kldLiR4w5IuUJamdryWTSF8X3QObjo2bB7Xv
         QP6ZENtJnhHI9yBXcthPAhnFKHD7B5OlwxzUxS+SvIgfMFA6/hIFLlOyX7iB54SlSLLC
         tSUp8IViYd/hBReo7JdEJayGUWiiJRPzFOi/75R8TNDSrP2Kj/6u1g9bVExOlGUBQoMv
         leY6tGUxMsHkPg2W6bu+za101e4bMncmQZGlQ5yyiPnutR1L/tuuIbnyKHetl/IpOKlR
         Bb2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OlbiD4sJSi8I/BVF5X+ZCNApedLwdEdN8yWQm+tLd0s=;
        b=ZoGXhKfz8L3rgMsn6JT4TkXEhpfglH1BwHbJgQKwTXWsOXVnuQ+IWsFu/WrTnWyHLM
         sBJ3QyoDhJbKSwbqeFNhDPWr7HFn/cfKm3oY8gMzsJkh0goHw5HCdnQYRHglN84HhTXl
         OvDnht/l0ZfsEwo6Xho+geKpQRZ/cp+9ESeveLxZ4GVmZkyszHAOWz5SX+v7eFsYDXmJ
         b7vr3M3C0rqI61WWQVYPliC7SFJfqXE4D8TRFiC6WMIbpAz3IwjR3eD6W50tRH9XBdcl
         UduQaf6XukzY58qGw8HhGfPeDd/JYLdVpuY0tDR+Jhrx+oQ1wMsfleXvMa2wHEHKQzUq
         WYaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="rvX1/hyT";
       spf=pass (google.com: domain of 3jnybyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3jNYBYAoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OlbiD4sJSi8I/BVF5X+ZCNApedLwdEdN8yWQm+tLd0s=;
        b=n2BCdve/RVEaBn+vb5CSOondzM2F6eyXWFQ56AsnWY+gEWcgaZIjAQMIDzGfBtNnut
         90QOM8H4RyUXoa/RJn5AgjknmsWn5JkZCCN4OYMYDBXoc0pBs5BXH3hLkL3mLPxe8zr2
         FouAZD/07XLDjpnjYE7szwnIg2n+4RxRLJF1UVi2bEh7x8rBT8JyzMzO8RTzfDtHC9Ap
         Dmt8P9QLcwHEOzEsKRMdaUBsGW7NcU9jSGfrx5U+dmnzkpvoBZV27cB1jno8bxQmDnpl
         ANWE/L9E7v7wre43Lg2Fw2FSmcllVmpHrKLoZsDOo08xMVPLN9LdOl875BwrhgcT28zr
         HM0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OlbiD4sJSi8I/BVF5X+ZCNApedLwdEdN8yWQm+tLd0s=;
        b=Fow0AcBmSCWNKLvE8QL8UMphhtUhNmehkGhjg6JWncyhHE4RDtrB4m6yVTJhzElAm/
         5A9qmQ2cU9pMjUBhd/hcnzL1lOFYIQnbYgNY46k6gIKACtKohLVjnVNHA1PmGaspfbkD
         SDf1U2plTZiPQcQ9oAjgNM5ox3mB6ejH6l37/2lf9XTJ9Dw1P/Di55RmDvZQVMUM6DEl
         ZLtIYH32L6cH8XZIjBBZ24ctbiF7iVgCRDPOs/07tLpIsLv3gDJ6tRZNgbTk7NtuuJiP
         CGHI9/Cwf0lBwFXa9UqaXmHVDsTqBXcfuQZJfhvSg5uyx63/dvtBV4UpycHdA7EBaL/O
         INeQ==
X-Gm-Message-State: AOAM530D9cWi1GH2BGFhZOylvuXMzVQy1Hurot4QsMWI0iKBAqaiRifG
	C8/l8Fv5JAmwoYGrFx5yCPs=
X-Google-Smtp-Source: ABdhPJxuvcfcplOW7ckyuzU55vctqXJvb+HhMPOvUV/9753NVFrHcDna4lqQDrso9gURNy/Vgf+7VQ==
X-Received: by 2002:a05:600c:22c6:: with SMTP id 6mr9761607wmg.33.1610733197780;
        Fri, 15 Jan 2021 09:53:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:66c5:: with SMTP id k5ls931282wrw.3.gmail; Fri, 15 Jan
 2021 09:53:17 -0800 (PST)
X-Received: by 2002:a5d:4f10:: with SMTP id c16mr14150597wru.398.1610733196901;
        Fri, 15 Jan 2021 09:53:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733196; cv=none;
        d=google.com; s=arc-20160816;
        b=eWzAUKxol1FF1kg5osJIhT4ev/S61D9Q/GXqTHQfeLbQAFik1TU8ly72n470MJl8nC
         d2xIzX9ToIOl5uCcxBrspfbhy2KSESbvbGPtPQyySvfC9jHWwFNbYKQEuMqr3YluFpjH
         GNidIqhULrrC2ITlRw9I3C8vADbmTKo+bvT/zcF8tfd+79OguaBsLO6hPP0nrW2q7kW2
         6mQPoZwWTHvMrgbgrqCrGsTuBhVo8r8cGBjA94FwtOonAQAWzvq78zs/4J/AAuyYtZ4n
         CpJ40FWQ4VymWcna1f3YbpemVXcRE9v5V8uW4wpoHJEVHC8N0RwpM0N64zPqDqh0ECgy
         y2MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=HQul2+mx68GlfTrevBbbyn+9Sc9/a5lDU2srZLIr3Ck=;
        b=BhzL9kPrGrWJ6eKT9/iD7VOEqDJ6qS8iJIJsFg0dn2zyaHiujdvH3MtdnEEnhlwhhB
         54/tTgltOg5lYGb9EgtN2Dm68/YKj4aD3spHZYb9BUOIF4nEtsZvjWcGueUCW6eG+KI0
         aEgsKRbc9V0a4ueABBS/JeLIlkBLUMWUETNGK12S9/7hDYrxjU+bdLacLQ90WlLI8KTc
         XgN0Dxd4xDHSweiv89AKHHSbrI8Uwl2KegPkyGs0Hsks+3tDZLeNh9EX0EbsNp66HHW/
         4f1/24Yy25m6Kzh2YHYc6UywcYiSNDMj9v+4VX35BRrgHvWUAeTcp99uxWuW86bITmwz
         CeXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="rvX1/hyT";
       spf=pass (google.com: domain of 3jnybyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3jNYBYAoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d17si606325wma.4.2021.01.15.09.53.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jnybyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s24so815421wmj.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:16 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2e88:: with SMTP id
 u130mr9830496wmu.83.1610733196486; Fri, 15 Jan 2021 09:53:16 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:44 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <f08250246683981bcf8a094fbba7c361995624d2.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 07/15] kasan: rename CONFIG_TEST_KASAN_MODULE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="rvX1/hyT";       spf=pass
 (google.com: domain of 3jnybyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3jNYBYAoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Rename CONFIG_TEST_KASAN_MODULE to CONFIG_KASAN_MODULE_TEST.

This naming is more consistent with the existing CONFIG_KASAN_KUNIT_TEST.

Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 8 ++++----
 lib/Kconfig.kasan                 | 2 +-
 lib/Makefile                      | 2 +-
 3 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 26c99852a852..b25ae43d683e 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -374,17 +374,17 @@ unmapped. This will require changes in arch-specific code.
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
 
-CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
---------------------------------------------------
+CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
+----------------------------------------------------
 
-KASAN tests consist on two parts:
+KASAN tests consist of two parts:
 
 1. Tests that are integrated with the KUnit Test Framework. Enabled with
 ``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
 automatically in a few different ways, see the instructions below.
 
 2. Tests that are currently incompatible with KUnit. Enabled with
-``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
+``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These tests can
 only be verified manually, by loading the kernel module and inspecting the
 kernel log for KASAN reports.
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 3091432acb0a..624ae1df7984 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -192,7 +192,7 @@ config KASAN_KUNIT_TEST
 	  For more information on KUnit and unit tests in general, please refer
 	  to the KUnit documentation in Documentation/dev-tools/kunit.
 
-config TEST_KASAN_MODULE
+config KASAN_MODULE_TEST
 	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
 	depends on m && KASAN && !KASAN_HW_TAGS
 	help
diff --git a/lib/Makefile b/lib/Makefile
index afeff05fa8c5..122f25d6407e 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -68,7 +68,7 @@ obj-$(CONFIG_TEST_IDA) += test_ida.o
 obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
 CFLAGS_test_kasan.o += -fno-builtin
 CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
-obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
+obj-$(CONFIG_KASAN_MODULE_TEST) += test_kasan_module.o
 CFLAGS_test_kasan_module.o += -fno-builtin
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f08250246683981bcf8a094fbba7c361995624d2.1610733117.git.andreyknvl%40google.com.
