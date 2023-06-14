Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUU3U2SAMGQEXJDLB6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F4672F9C7
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jun 2023 11:52:20 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-4f74114059dsf3482733e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jun 2023 02:52:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686736340; cv=pass;
        d=google.com; s=arc-20160816;
        b=sWASjbdmi9M215XhQ7mlIySsbLWrGfW6WDNPXmmOBOtRSm8DlgRjIPaSrf0rAb9IoV
         iUX59Lc84Qk45z21kNJXEpkM2tmfh5K8rQW8haWSImuTqh0QWjm6H0FBZeIhM24UdTQK
         ZvN+ODFjnSIv9skclxH6NUR95o4NoCQW6RZ00fIcS8dyJgwNwVoT9vyN52X1n4krUZkh
         kmaCZwVetS4PbCodMZu/SyaMPdi/OzpqDeHCZnYHgk+PXNYZMvhpAlccNUXCTCPcnf9I
         avHtdHXyt8JvrtIq9Ns1NuBXn2kFbOTfM8BgEOrHJZUk9TEHWeeYlzbyFmkHd4H9ZU9F
         ZP5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=bL4trKFf14nNL0QE+F33AhEz8aRp5dP3cT+mcUilVJ4=;
        b=cTTBITQp0fmy0aXWMfIUv+HMZ2bBIE889KV9lE8mR4LsFjFOC1oLmRZ71dIPtNjqi8
         DMD6wJf+MHYEnSghw59S2J4gFmWBSkdx6jV7hxYAEejKdI+1f0FSLVq/7BsfVWCTEC9I
         vf/PchsPK+CDoSexFBRVynDFZWSi8lL5uGTrxRW9XihgoETzo+5Zo4stbyrOFMqk3d9p
         4DYgO+F9S9UmUQayZGwPU8vHT29N90R8Y2vm3ZDccPM6DcvjfvkDX8bMGkfElryvCDHL
         qjrC+MOiVL6GNp79qeXSNsoECdEibrixyuxJJkOt9dGvp+xfrOp88qtqiZ6Zl/IwZPcZ
         727A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=geOqKiSn;
       spf=pass (google.com: domain of 30y2jzaukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30Y2JZAUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686736340; x=1689328340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bL4trKFf14nNL0QE+F33AhEz8aRp5dP3cT+mcUilVJ4=;
        b=MIGa/GoUU1mZVdl8TkOnCsbmclLmzdTFnJtRnFv36nnBQ4Nto2dcsu57eCLlyM2YMk
         H/viFI3Tf6vqg+RNzz8ZgGa0Uf15uNGa5PfQSXmUWZBSzOAZ9ysRY+WAKx6ewHlrofbm
         mLA6WOn8bLa7g27rlr6hXWIJbvTb6t0eP3bVDcqT6ThIrcdCjmgK4b4JfsDbIizTJvRN
         kFsygJkGPfZ/PCOWQIUMgtHFXx6BpFggg7Q+TW0h9+xeUH8fe+vxSeRnmvHgclX+R+od
         +qSeuPuAFN0SOb+NKUp7XUVHSnhh9nY86B/OHEjaYRXRnHM7JYwlgHzYXOHmvmjMte6Y
         FXnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686736340; x=1689328340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bL4trKFf14nNL0QE+F33AhEz8aRp5dP3cT+mcUilVJ4=;
        b=hpYDhB2zPTFGCHKGwTDs9ZRWGK091Kq40UDrd/m2MAOUyxyUYdZO4HzIGWKQdPvQJB
         2EnkEyGK3g4bj0FOa9Iuj8yd0pU5Fir33mn+FKA5xUaqCXAKTpm5LI+qcx4xdX6yEiQ6
         bpgCQvqK3Tu+WOXfODm79KHVi80Fk7NV4I89AKmOktMeIalVbA7og8tSmubyZN/ZE1yH
         i6I2Sem/S/DtMcyWwe7FDMCtYC3GXgDArxSUNaKHuxAnhOcbuKNAWQ+aniHpFQDu9CSa
         m6p81KyKSzqTikacekNywS0hEr53YzTUwQsszeDo6NwlHRyVuGkpI1TU5cd9dsVtmIG9
         k5hw==
X-Gm-Message-State: AC+VfDyL0zsjYeh2+uJriHSyrJdFOu0i6pcFdn6Wi3c+a1pMgfQ0HAC4
	WmILkmAy4k/FfN7w3gyfN5c=
X-Google-Smtp-Source: ACHHUZ4NHDv5HqTvEAVZi6tEvQRifEyhJbfNDhLogfqG6sYwXh1GMcSOxxRGpphTTMQqDCyJstifgQ==
X-Received: by 2002:a19:e34f:0:b0:4f6:1c08:e9bb with SMTP id c15-20020a19e34f000000b004f61c08e9bbmr6693527lfk.63.1686736339216;
        Wed, 14 Jun 2023 02:52:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5110:b0:3f3:15ce:e16c with SMTP id
 o16-20020a05600c511000b003f315cee16cls1162321wms.0.-pod-prod-01-eu; Wed, 14
 Jun 2023 02:52:17 -0700 (PDT)
X-Received: by 2002:adf:f1c3:0:b0:30a:e511:e65c with SMTP id z3-20020adff1c3000000b0030ae511e65cmr7873366wro.37.1686736337640;
        Wed, 14 Jun 2023 02:52:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686736337; cv=none;
        d=google.com; s=arc-20160816;
        b=YjUo5xzdrp8tXW+uCHv2Tt4Q/yM3xlJBa2iwt00Jfx8lk8gtPcHEIjoWgoSqrr41q3
         vMc5wlQhPMKQyefh2JAnPIZ2Kv/v+RC49s5Hr8XmNxWb7OedOOPDqxe6uP9OU2N/rNAM
         vdNSLN5Ff5XmIFzrokBH6N3p+Y76kv23jjCoqei03RE3Wmzv1sl96jPv9fCpu3MrbBTP
         EcVhF6d60dWhU2mhez1r4V5jlVwH08ZqXIYqTXpf3YbC2rPsmxr/7pCGeDu6+T0B4LAq
         OGNHn89ZNMmyeLbqHOVSuwe91Be4+1tfrhAD1TdA4Sgnd7hmFq+gAgDcYLrjsQN3wEqj
         VdQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=FmWeC77NBNaRdAHWwSRuR6SPcKNZqe53/vQrn9mW/UE=;
        b=fcculWa/SNPGkSKMBn0giyxRZg/Fhd/ZgwxP86Yu8SrZiKHWvJqzRpLa4k0rtxcsaB
         vKg2ysGQ8ZcXqzPwVaIH+TlAJp3KImC2V5AeettaOkGoe3RVsogWS+4cxxZhzZXrevuN
         bdCmyuNtx33uTIbs6lJsHK09K8kpk2WMhK+Na19h9MDtQeXqxJf+W8RjNx1dvXrm5HPU
         cFfb7gB2cniBx5/eEHH+Ug/HQhNMHM77miDQAaVOE+Lo6nAEQi/WVu52DGEWlZfyyX4t
         nbkcT3FeoPJvk9Bg7e3JypSoNeekjJHD0fPoitTqcqdM85bKY+VwtrSE1A1sHCEZW+UH
         h5pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=geOqKiSn;
       spf=pass (google.com: domain of 30y2jzaukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30Y2JZAUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id az13-20020adfe18d000000b0030fbb0abf70si494657wrb.0.2023.06.14.02.52.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jun 2023 02:52:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30y2jzaukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-94a35b0d4ceso50931966b.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Jun 2023 02:52:17 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:980:a2e1:a81a:5ba8])
 (user=elver job=sendgmr) by 2002:a17:907:2e01:b0:974:5eb6:74f2 with SMTP id
 ig1-20020a1709072e0100b009745eb674f2mr4428432ejc.14.1686736337234; Wed, 14
 Jun 2023 02:52:17 -0700 (PDT)
Date: Wed, 14 Jun 2023 11:51:16 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.41.0.162.gfafddb0af9-goog
Message-ID: <20230614095158.1133673-1-elver@google.com>
Subject: [PATCH] kasan: add support for kasan.fault=panic_on_write
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Taras Madan <tarasmadan@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=geOqKiSn;       spf=pass
 (google.com: domain of 30y2jzaukct4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30Y2JZAUKCT4jq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

KASAN's boot time kernel parameter 'kasan.fault=' currently supports
'report' and 'panic', which results in either only reporting bugs or
also panicking on reports.

However, some users may wish to have more control over when KASAN
reports result in a kernel panic: in particular, KASAN reported invalid
_writes_ are of special interest, because they have greater potential to
corrupt random kernel memory or be more easily exploited.

To panic on invalid writes only, introduce 'kasan.fault=panic_on_write',
which allows users to choose to continue running on invalid reads, but
panic only on invalid writes.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kasan.rst |  7 ++++---
 mm/kasan/report.c                 | 31 ++++++++++++++++++++++++++-----
 2 files changed, 30 insertions(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e66916a483cd..7f37a46af574 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -107,9 +107,10 @@ effectively disables ``panic_on_warn`` for KASAN reports.
 Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
 parameter can be used to control panic and reporting behaviour:
 
-- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``). The panic happens even
-  if ``kasan_multi_shot`` is enabled.
+- ``kasan.fault=report``, ``=panic``, or ``=panic_on_write`` controls whether
+  to only print a KASAN report, panic the kernel, or panic the kernel on
+  invalid writes only (default: ``report``). The panic happens even if
+  ``kasan_multi_shot`` is enabled.
 
 Software and Hardware Tag-Based KASAN modes (see the section about various
 modes below) support altering stack trace collection behavior:
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 892a9dc9d4d3..f8ac4d0c9848 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -43,6 +43,7 @@ enum kasan_arg_fault {
 	KASAN_ARG_FAULT_DEFAULT,
 	KASAN_ARG_FAULT_REPORT,
 	KASAN_ARG_FAULT_PANIC,
+	KASAN_ARG_FAULT_PANIC_ON_WRITE,
 };
 
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init = KASAN_ARG_FAULT_DEFAULT;
@@ -57,6 +58,8 @@ static int __init early_kasan_fault(char *arg)
 		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
 	else if (!strcmp(arg, "panic"))
 		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
+	else if (!strcmp(arg, "panic_on_write"))
+		kasan_arg_fault = KASAN_ARG_FAULT_PANIC_ON_WRITE;
 	else
 		return -EINVAL;
 
@@ -211,7 +214,7 @@ static void start_report(unsigned long *flags, bool sync)
 	pr_err("==================================================================\n");
 }
 
-static void end_report(unsigned long *flags, void *addr)
+static void end_report(unsigned long *flags, void *addr, bool is_write)
 {
 	if (addr)
 		trace_error_report_end(ERROR_DETECTOR_KASAN,
@@ -220,8 +223,18 @@ static void end_report(unsigned long *flags, void *addr)
 	spin_unlock_irqrestore(&report_lock, *flags);
 	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		check_panic_on_warn("KASAN");
-	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
+	switch (kasan_arg_fault) {
+	case KASAN_ARG_FAULT_DEFAULT:
+	case KASAN_ARG_FAULT_REPORT:
+		break;
+	case KASAN_ARG_FAULT_PANIC:
 		panic("kasan.fault=panic set ...\n");
+		break;
+	case KASAN_ARG_FAULT_PANIC_ON_WRITE:
+		if (is_write)
+			panic("kasan.fault=panic_on_write set ...\n");
+		break;
+	}
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	lockdep_on();
 	report_suppress_stop();
@@ -536,7 +549,11 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 
 	print_report(&info);
 
-	end_report(&flags, ptr);
+	/*
+	 * Invalid free is considered a "write" since the allocator's metadata
+	 * updates involves writes.
+	 */
+	end_report(&flags, ptr, true);
 }
 
 /*
@@ -571,7 +588,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 
 	print_report(&info);
 
-	end_report(&irq_flags, ptr);
+	end_report(&irq_flags, ptr, is_write);
 
 out:
 	user_access_restore(ua_flags);
@@ -597,7 +614,11 @@ void kasan_report_async(void)
 	pr_err("Asynchronous fault: no details available\n");
 	pr_err("\n");
 	dump_stack_lvl(KERN_ERR);
-	end_report(&flags, NULL);
+	/*
+	 * Conservatively set is_write=true, because no details are available.
+	 * In this mode, kasan.fault=panic_on_write is like kasan.fault=panic.
+	 */
+	end_report(&flags, NULL, true);
 }
 #endif /* CONFIG_KASAN_HW_TAGS */
 
-- 
2.41.0.162.gfafddb0af9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230614095158.1133673-1-elver%40google.com.
