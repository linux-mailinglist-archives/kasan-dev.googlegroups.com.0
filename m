Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2V27XGAMGQE3UKJGPY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MCnLA21dn2lRagQAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBB2V27XGAMGQE3UKJGPY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 21:37:01 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F0DD19D515
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 21:37:00 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5a10765f675sf50523e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 12:37:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772051820; cv=pass;
        d=google.com; s=arc-20240605;
        b=LU6iN2g0KhmYAZdVocqNVf/UMouwNRfONOAI2CTQ9TSG60v/poVDvXL+/tuGT0wfYF
         /hM8O1Z8rN5t8uvW1P2tifTFXC0bLuPjs6KvxdWmcGxXjFB++hIn/lQKUT5eUHHhURzu
         eBIKcAYrDJ0fLWUstKtj37jIT26yRL4Xylgu55evMm4G2LsFm/wM9PqGjsU2qw/b/6rD
         Qm5rd2l8r7uRVpbNifvFkdmfDNrTdzcCLuXZ9qbzoP98S9bVKzwoXN59rQa7WyIXY14c
         qFIPV+EtFUMF5KyidWZVR5GGTlXkW2DHb/xipSTf85mG+WYDPF7hF7huAFqP7bnHraRY
         Er9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=XIulgwdktcKECQHlXb9xJhGd9NW16pD8LVITBYVfdv8=;
        fh=85vQnVkce17cfmdN10qfek8QINWXZE0C49GWMyRJj4M=;
        b=QuS5fjCiz5HJ3HcbseM/NV+HP00BSkacvK6xBISX6yT4F6FrkrMWAwohnJ6w/KRELg
         bqoLjpGR4aOo+rqLroU8n+H83WVeBFU1+3mg8BgK8F7qcFRV9rNuAZC4tPdDi+pwaHhP
         WpNlS4mKbT6bNkXdkGZXZs82wa5UwkQC8QNZUlAf84YhNiOF8/bpEKDJHG8za2FPe+hM
         5RkXgTrAiptDmzk0tGjI2G3Tp+V8/teRmfIrVT4My7SUX2p1JcrGU2/uRTkrnIkXh/kt
         vmSonJ0zV+MADNP9cGzQApT2IH2QDWaBMXNAzMlb7aLTa9XC/0wbtn6v/3ru6mAz0x7s
         9b1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rmAd87C;
       spf=pass (google.com: domain of 3z12faqukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Z12faQUKCfIYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772051820; x=1772656620; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XIulgwdktcKECQHlXb9xJhGd9NW16pD8LVITBYVfdv8=;
        b=NzvdFrUKxx5ZzfJAQsSCpTpDM+baRfeCZsHv9fmqMVB1lfXaiFPlXUOS9aElufkbgB
         Dc2//CYnQIoo9aeKe3b5NsfSHGjuyCarvKjW7JOSb1MscAHG4ywBokNTUIAk3xzF+058
         hdEx09wqgmTxe3XshQ9rIhxXq0tQaNSVBvpY6tgcmaGHhqTW8g9A8BnwlZIAkWnckq2f
         woCcELtXdymWfNy3nuZ+OhsKMsXUFFF5zypXIj7FxVhr7+8Px0Feq8ZsVDCWbwByQEWu
         VzcpyAnUddIwLFCL6OqHeAp7I6tzxOYJi8VXfAJ8d4lXdQ1TJWhCgsEClrg88EkZ1ZBo
         5+Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772051820; x=1772656620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XIulgwdktcKECQHlXb9xJhGd9NW16pD8LVITBYVfdv8=;
        b=ZIsgG3O0d1V0eW7+WGfP21ENjUB9G0+tRnttUKQKuzhLv1okG11lCYvzy6bpNX84ou
         QSRZId39NIT1t2KErsMNJTGLK6kcNml1u+N/AwfgqxCflgDz08G4KdpvLSTo8V5c8US2
         UzMmw6pu+jIBVDszCyg3XSyogZfp3UztanWXZT8CL9f7k/UhwqmxDvPni0cYm91um8pz
         o2Mq6EpbURkEafHM3pdmeBzVnv2wutmo19/AzedUCu3CoBoo71pX+Ls9I+cDrAXvWiZN
         /ydxaIzrxDW7JYN8x9DeGXpFvfw/YRXmCfBE8B5JW7Jc1j/8HWdLRFQLajMakjGSiaan
         2Ifw==
X-Forwarded-Encrypted: i=2; AJvYcCUv8PNUcirAnLaqzK+YyMNYfBeL+Njf0s64wEmessEjkFGPg4ya03HcjtHueBVN/U1OeU+t9g==@lfdr.de
X-Gm-Message-State: AOJu0YzG3bpMfA3jWlfxb0AisodNyH3gZ8D0jvfUjkuledJC8krnshKE
	EOUTh36OA/tK9opO0LumVY4oQmdeMRCq0RfYiBeRdnpvaYoveVTkd1cp
X-Received: by 2002:a05:6512:1252:b0:59e:39af:a70c with SMTP id 2adb3069b0e04-5a0ed9c1406mr5125664e87.46.1772051819260;
        Wed, 25 Feb 2026 12:36:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GDakG37J4MQgJ6bopN1ASBUWOtgZR7CKrbb4zf3qOYAQ=="
Received: by 2002:a05:6512:b0d:b0:59b:7324:a12c with SMTP id
 2adb3069b0e04-5a101702fa4ls353480e87.2.-pod-prod-07-eu; Wed, 25 Feb 2026
 12:36:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUlkxlnDeSekkMyfP27IBSbMYM+YhfwbP7yEo79PsQgcYGoxmY77ZtCTzkq0sG08Kit+sYNlWM2mbE=@googlegroups.com
X-Received: by 2002:ac2:4bd0:0:b0:5a1:515:a692 with SMTP id 2adb3069b0e04-5a10515a76bmr815590e87.10.1772051816377;
        Wed, 25 Feb 2026 12:36:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772051816; cv=none;
        d=google.com; s=arc-20240605;
        b=ZnTumnxXLKYOAl5DuQ0doOqDSAsDWB9sbaI6sb5m7En2dDkkTvv45Ft19gFqAegxR8
         uu+Es/mKwYXCt5Ubahz81kkE1SZaZxp8QFAt++i5vTov1M1qMP/s/f/BO0/edPduOlFN
         mfZ4UryWbmthvv0CGzUXSSTnRf06oLvyOnwQf0jZY2t/TmfziTreQYW3O+a2+dF5+BGT
         GOO+9ffLceFiDm/nZkUCOD/sAVMUINekTvc2jOVVhcBx4FL97Qw9HsTqb/8UJZmIKmyl
         T1aAOc/f9nCPX5FKwPr87jpoW2wnqtBniLVTcHD9hGSnxJJEFXVAovSjUwbZfeyRZ6oT
         gcHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=3O3Me7fgwyHmdf0v5rLq8O8sd5sCO/cE1nxT2vqkXJo=;
        fh=SXY9JR81PhdPtLV6x5olorKnXeiQGJoeOOUFVHsbdyE=;
        b=Cqi3MifSAiC8J09g8LCYyN6CZ4KJmXQ3dLX1P7S0+Q3ZsxiUmmay1du9qsgn5v9jxA
         J9UGucpktjHAcL3v7N6eN8oqyYhNU6EaFANh0LKwjeF71uZhPqLSHYcieVeL8vD7z3rF
         UwYg8Bq7tVMES6T2po6n620fBpTZ2mbZ5pt/x5TbMBSDjcRRGUOlCtAgj59pFAHm6MRW
         EwZhI2Fmo4pNIi98ssay5M+rte5Kh3RpJXAG2stJ5zLbnNiEKfdx5DuXrMUVAg4aonEV
         OuPmyHACvFI8w1uS7oX5+2D9p497TlQX13Bd+fs27YwMDIf+ZsipqzS6eJb4uFBnsla+
         2JiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rmAd87C;
       spf=pass (google.com: domain of 3z12faqukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Z12faQUKCfIYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5a1093e5a56si2333e87.6.2026.02.25.12.36.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Feb 2026 12:36:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3z12faqukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4806b12ad3fso1375975e9.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Feb 2026 12:36:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU7P4DF8CCsp5nOkBImxbx+XQ+Puu61OCacIePRyn/Pr6VChkxt4Xj8PLKsJZiHyLV51Ibl66pnnRs=@googlegroups.com
X-Received: from wmbjp9.prod.google.com ([2002:a05:600c:5589:b0:47f:c96e:8381])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600d:6409:20b0:483:78c5:d743
 with SMTP id 5b1f17b1804b1-483a9637a19mr199333935e9.28.1772051815765; Wed, 25
 Feb 2026 12:36:55 -0800 (PST)
Date: Wed, 25 Feb 2026 21:36:05 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.53.0.414.gf7e9f6c205-goog
Message-ID: <20260225203639.3159463-1-elver@google.com>
Subject: [PATCH] kfence: add kfence.fault parameter
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Shuah Khan <skhan@linuxfoundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-mm@kvack.org, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1rmAd87C;       spf=pass
 (google.com: domain of 3z12faqukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Z12faQUKCfIYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	MID_CONTAINS_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MV_CASE(0.50)[];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-0.995];
	RCVD_COUNT_THREE(0.00)[4];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBB2V27XGAMGQE3UKJGPY];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: 9F0DD19D515
X-Rspamd-Action: no action

Add kfence.fault parameter to control the behavior when a KFENCE error
is detected (similar in spirit to kasan.fault=<mode>).

The supported modes for kfence.fault=<mode> are:

  - report: print the error report and continue (default).
  - oops: print the error report and oops.
  - panic: print the error report and panic.

In particular, the 'oops' mode offers a trade-off between no mitigation
on report and panicking outright (if panic_on_oops is not set).

Signed-off-by: Marco Elver <elver@google.com>
---
 .../admin-guide/kernel-parameters.txt         |  6 +++
 Documentation/dev-tools/kfence.rst            |  7 +++
 mm/kfence/core.c                              | 23 ++++++---
 mm/kfence/kfence.h                            | 16 +++++-
 mm/kfence/report.c                            | 49 +++++++++++++++++--
 5 files changed, 89 insertions(+), 12 deletions(-)

diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
index cb850e5290c2..05acdea306b2 100644
--- a/Documentation/admin-guide/kernel-parameters.txt
+++ b/Documentation/admin-guide/kernel-parameters.txt
@@ -2958,6 +2958,12 @@ Kernel parameters
 			Format: <bool>
 			Default: CONFIG_KFENCE_DEFERRABLE
 
+	kfence.fault=	[MM,KFENCE] Controls the behavior when a KFENCE
+			error is detected.
+			report - print the error report and continue (default).
+			oops   - print the error report and oops.
+			panic  - print the error report and panic.
+
 	kfence.sample_interval=
 			[MM,KFENCE] KFENCE's sample interval in milliseconds.
 			Format: <unsigned integer>
diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 541899353865..b03d1201ddae 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -81,6 +81,13 @@ tables being allocated.
 Error reports
 ~~~~~~~~~~~~~
 
+The boot parameter ``kfence.fault`` can be used to control the behavior when a
+KFENCE error is detected:
+
+- ``kfence.fault=report``: Print the error report and continue (default).
+- ``kfence.fault=oops``: Print the error report and oops.
+- ``kfence.fault=panic``: Print the error report and panic.
+
 A typical out-of-bounds access looks like this::
 
     ==================================================================
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index b4ea3262c925..a5f7dffa9f6f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -50,7 +50,7 @@
 
 /* === Data ================================================================= */
 
-static bool kfence_enabled __read_mostly;
+bool kfence_enabled __read_mostly;
 static bool disabled_by_warn __read_mostly;
 
 unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
@@ -335,6 +335,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 static check_canary_attributes bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
+	enum kfence_fault fault;
 	unsigned long flags;
 
 	if (likely(*addr == KFENCE_CANARY_PATTERN_U8(addr)))
@@ -344,8 +345,9 @@ static check_canary_attributes bool check_canary_byte(u8 *addr)
 
 	meta = addr_to_metadata((unsigned long)addr);
 	raw_spin_lock_irqsave(&meta->lock, flags);
-	kfence_report_error((unsigned long)addr, false, NULL, meta, KFENCE_ERROR_CORRUPTION);
+	fault = kfence_report_error((unsigned long)addr, false, NULL, meta, KFENCE_ERROR_CORRUPTION);
 	raw_spin_unlock_irqrestore(&meta->lock, flags);
+	kfence_handle_fault(fault);
 
 	return false;
 }
@@ -524,11 +526,14 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	raw_spin_lock_irqsave(&meta->lock, flags);
 
 	if (!kfence_obj_allocated(meta) || meta->addr != (unsigned long)addr) {
+		enum kfence_fault fault;
+
 		/* Invalid or double-free, bail out. */
 		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
-		kfence_report_error((unsigned long)addr, false, NULL, meta,
-				    KFENCE_ERROR_INVALID_FREE);
+		fault = kfence_report_error((unsigned long)addr, false, NULL, meta,
+					    KFENCE_ERROR_INVALID_FREE);
 		raw_spin_unlock_irqrestore(&meta->lock, flags);
+		kfence_handle_fault(fault);
 		return;
 	}
 
@@ -830,7 +835,8 @@ static void kfence_check_all_canary(void)
 static int kfence_check_canary_callback(struct notifier_block *nb,
 					unsigned long reason, void *arg)
 {
-	kfence_check_all_canary();
+	if (READ_ONCE(kfence_enabled))
+		kfence_check_all_canary();
 	return NOTIFY_OK;
 }
 
@@ -1249,6 +1255,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 	struct kfence_metadata *to_report = NULL;
 	unsigned long unprotected_page = 0;
 	enum kfence_error_type error_type;
+	enum kfence_fault fault;
 	unsigned long flags;
 
 	if (!is_kfence_address((void *)addr))
@@ -1307,12 +1314,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
 	if (to_report) {
 		raw_spin_lock_irqsave(&to_report->lock, flags);
 		to_report->unprotected_page = unprotected_page;
-		kfence_report_error(addr, is_write, regs, to_report, error_type);
+		fault = kfence_report_error(addr, is_write, regs, to_report, error_type);
 		raw_spin_unlock_irqrestore(&to_report->lock, flags);
 	} else {
 		/* This may be a UAF or OOB access, but we can't be sure. */
-		kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
+		fault = kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
 	}
 
+	kfence_handle_fault(fault);
+
 	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
 }
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index f9caea007246..1f618f9b0d12 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -16,6 +16,8 @@
 
 #include "../slab.h" /* for struct kmem_cache */
 
+extern bool kfence_enabled;
+
 /*
  * Get the canary byte pattern for @addr. Use a pattern that varies based on the
  * lower 3 bits of the address, to detect memory corruptions with higher
@@ -140,8 +142,18 @@ enum kfence_error_type {
 	KFENCE_ERROR_INVALID_FREE,	/* Invalid free. */
 };
 
-void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
-			 const struct kfence_metadata *meta, enum kfence_error_type type);
+enum kfence_fault {
+	KFENCE_FAULT_NONE,
+	KFENCE_FAULT_REPORT,
+	KFENCE_FAULT_OOPS,
+	KFENCE_FAULT_PANIC,
+};
+
+enum kfence_fault
+kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
+		    const struct kfence_metadata *meta, enum kfence_error_type type);
+
+void kfence_handle_fault(enum kfence_fault fault);
 
 void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta) __must_hold(&meta->lock);
 
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 787e87c26926..d548536864b1 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -7,9 +7,12 @@
 
 #include <linux/stdarg.h>
 
+#include <linux/bug.h>
+#include <linux/init.h>
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
 #include <linux/math.h>
+#include <linux/panic.h>
 #include <linux/printk.h>
 #include <linux/sched/debug.h>
 #include <linux/seq_file.h>
@@ -29,6 +32,26 @@
 #define ARCH_FUNC_PREFIX ""
 #endif
 
+static enum kfence_fault kfence_fault __ro_after_init = KFENCE_FAULT_REPORT;
+
+static int __init early_kfence_fault(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "report"))
+		kfence_fault = KFENCE_FAULT_REPORT;
+	else if (!strcmp(arg, "oops"))
+		kfence_fault = KFENCE_FAULT_OOPS;
+	else if (!strcmp(arg, "panic"))
+		kfence_fault = KFENCE_FAULT_PANIC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kfence.fault", early_kfence_fault);
+
 /* Helper function to either print to a seq_file or to console. */
 __printf(2, 3)
 static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
@@ -189,8 +212,9 @@ static const char *get_access_type(bool is_write)
 	return str_write_read(is_write);
 }
 
-void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
-			 const struct kfence_metadata *meta, enum kfence_error_type type)
+enum kfence_fault
+kfence_report_error(unsigned long address, bool is_write, struct pt_regs *regs,
+		    const struct kfence_metadata *meta, enum kfence_error_type type)
 {
 	unsigned long stack_entries[KFENCE_STACK_DEPTH] = { 0 };
 	const ptrdiff_t object_index = meta ? meta - kfence_metadata : -1;
@@ -206,7 +230,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	/* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
 	if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
-		return;
+		return KFENCE_FAULT_NONE;
 
 	/*
 	 * Because we may generate reports in printk-unfriendly parts of the
@@ -282,6 +306,25 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	/* We encountered a memory safety error, taint the kernel! */
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
+
+	return kfence_fault;
+}
+
+void kfence_handle_fault(enum kfence_fault fault)
+{
+	switch (fault) {
+	case KFENCE_FAULT_NONE:
+	case KFENCE_FAULT_REPORT:
+		break;
+	case KFENCE_FAULT_OOPS:
+		BUG();
+		break;
+	case KFENCE_FAULT_PANIC:
+		/* Disable KFENCE to avoid recursion if check_on_panic is set. */
+		WRITE_ONCE(kfence_enabled, false);
+		panic("kfence.fault=panic set ...\n");
+		break;
+	}
 }
 
 #ifdef CONFIG_PRINTK
-- 
2.53.0.414.gf7e9f6c205-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225203639.3159463-1-elver%40google.com.
