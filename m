Return-Path: <kasan-dev+bncBCXKTJ63SAARBWVLZXGAMGQEA2N2PXQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id VqzvNNxVk2mi3gEAu9opvQ
	(envelope-from <kasan-dev+bncBCXKTJ63SAARBWVLZXGAMGQEA2N2PXQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Feb 2026 18:37:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 69DA8146C0C
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Feb 2026 18:37:32 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-658c19d5ca0sf4563091a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Feb 2026 09:37:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771263452; cv=pass;
        d=google.com; s=arc-20240605;
        b=YGxqkFjdG++/EFkeLzQcyWvVIlUveiNKcz+UXWQB5XpjOu/r38MaQva5EZcwOL64LH
         UK3aD2CwRsGQoq6DlSYRwt/XU9NoWyIJiGsAjqI6ppKVibtxcGrwJEUkhCBe1gvTqgqe
         YE757GJyeFPbvk042UsHEg95i+n/rfhDEpJewCUqBBv5l3X20aHebU2Jcm/lWX1yEXUm
         TYkX69vJtaSMOdyUN7wr8kfgP1OuZYtwZpDLdTHYfeE7M3gYFEYVCt0EO2xTIg7HisjE
         oGizcMJNGfoUWEDb/cabe2bXi2dL4Bxn7dxLICiYuz/hzLhORQVkg9DTF1zGSdO9vHO7
         7EkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=3GIf+24NNVTMOL3jiLEyopYeBSfCcxaxi0Nc2Oe3Zzw=;
        fh=6AEqZ7JeOXQUnNrMD6Zaej542toCihOK3EbkQI8aeSc=;
        b=AG95uWpHVV5cVjkZvl+F41V5A8/SyF079l8XMAHUGzVjBGA/AR42em3qKKdFgVLAVu
         9dZysjhh6+UPKAHAGN3PWmniqqynVmQeCv0tqJC/Hc5cnNeBZfBWQhQ2UtCAW5Q1apxk
         qDxvXmxez4fF7SFJPNeGZIFed3j6ZohJlO4ZS8PqVyl/oRBbz8TN8F3kEIvIc6voDygk
         To1I2fFMoeBrY74Co+hjSGTgF4w9KLX4yRJafd+WZKX+PZAsBPucHWwm1xRja+AXx8sF
         geX4rItY4S4fEg62n5ZS2r/HtZ6AL2qAQF3whF44hYYsb5hRvqIAAeDWLEmtlDMEr6d1
         yAlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4e31Ms+E;
       spf=pass (google.com: domain of 32fwtaqykcsuophjlihpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32FWTaQYKCSUOPHJLIHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771263452; x=1771868252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3GIf+24NNVTMOL3jiLEyopYeBSfCcxaxi0Nc2Oe3Zzw=;
        b=REp3hZ4V5RSWp6tl8O+j0yRmabctHPtw8if43tPDRABRaF2asG0Njvyabsfqja6KCK
         4JUHlf3VCfd1QW2oeSz99lz1fGt9shjpKprZ0rUWJW66ecuYyefU07mLO9KqDyUUsnTw
         MS47skOVPULTH8f40T4RTAVRZjz9CxqycIi1q+Uaz4JvZr/eelkciwdJxbTI1zgGIa+c
         qwMPMQ1bx36nt0M7DW43i2uLLhbaUbuKVLzpo/VzN3Tk+kgHj30gCuY9OdItNgcADi0K
         VS3UMWcqARyHO8d/WJpPYOtjn7Vq8v9uJFImpUQ0SZy/4+/US+RgSy9ZLDNAG44Jv0S2
         FZdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771263452; x=1771868252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3GIf+24NNVTMOL3jiLEyopYeBSfCcxaxi0Nc2Oe3Zzw=;
        b=krfc9/4zDVgnrk+4oltz9l1zI9vI157Ku4dY+Itklm/1PAB+DjI3ls9PCHGsi4VKjf
         BtskR9RloXdNpOaXpDeWQdcMJdkjBlfL40VQxhuWRyYL0fNBGYVwpCn+QmZlt/tUhm5Y
         /FRJj+p3eIlfEZ9Cg//H3A7B2/aRC1lPtwbnuRFm/VfjUO6IyL0TAtDin+JofXIRvy+f
         cSa47/Mylka25UQYP7KPhENwlg0WiX8iXiXVfgm/DC2cQakjEURg6tAkSAA/uw2tE+EV
         NcUUvNd+oIiMXps/TBIw5iJe4imUk+h03bql1vjB+whNB8dlS2xAdMncssfTM+RO44Ot
         FzIA==
X-Forwarded-Encrypted: i=2; AJvYcCWPzZMllKs9rhVN3Pz6n0WgmAEKgMmXMkuXtMteIVOGJvtYCtZscx6p4IvqJ0iOC4HOOlBq2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxh7O4OE0ExT1vDkZ0H3buHTVpOpYRY5mOO0/+khcxZxkVKazGH
	qpCGHFZ944kM7hS8ZB7W/8VPog2zpvYd6tJtra4kf/9lycCHx8Ccsvdb
X-Received: by 2002:a05:6402:1467:b0:65a:3527:c5d1 with SMTP id 4fb4d7f45d1cf-65bc424a4d2mr4996700a12.2.1771263451327;
        Mon, 16 Feb 2026 09:37:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FL1DOif2W9XVnTUDrvm4SK6fyGwC6a/cUCQhzWSg04tw=="
Received: by 2002:a05:6402:f17:b0:659:49cc:698e with SMTP id
 4fb4d7f45d1cf-65b9dab605dls2190397a12.1.-pod-prod-00-eu; Mon, 16 Feb 2026
 09:37:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXhdfW4Yn8mdfVR/zSEj8K+nczCnze4I8PzAH7/tNhPesxli/O9N+SpYT6y+vgmgXcEV6WFRtnNECg=@googlegroups.com
X-Received: by 2002:a05:6402:a295:10b0:65c:65b:e854 with SMTP id 4fb4d7f45d1cf-65c065beed0mr1606999a12.9.1771263449331;
        Mon, 16 Feb 2026 09:37:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771263449; cv=none;
        d=google.com; s=arc-20240605;
        b=O+UTeB9C1c9dzoEhxgARTDL+ErDufQ1HPg1J1hc1Ycc7WSVFzqIRzRBygyvKu2Si//
         rDvgXDeip8SG1XpMp+WkhiHKSktMJtvJJqKTP+MbtDrYb0I0PeXX/pTgKwMCuZjAztH5
         EqGF1kzZ1/3zR1y4La24cklNpuvW+L8kWb1W6Bzq/syQNSfmNcG++Crr5QDm1ORsmslG
         J1m9nH3WzKjLmc82PHHXq07LgzZZcPg9yNt4Zc3inh/yFnZcgxlOG/FBw3pH9d9W1pcn
         LwAqA576WrJmzS+PV56D/h6gwbrWk/4V7SOqqQf0jiSPTW/1DWSgNrkc5sL+S6sQ8FDD
         24ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=+CGgBuWMwayfOcIDbZ2XGNgXYWYl77pKODg5gAEKr8g=;
        fh=WTWBdBSffB9fq7OhwVjF8rkZqcsLBZKe7mlJwQlk7S0=;
        b=T4IUbU1Zaxh92hDLIymtU0tA0O+APV9fwXR1vwcDFHKDB8L4mAmfULJ3IZvh0bFljz
         c5pVxiIBQ4VccdLLOVNFpWGHIy4XLXKlUnSFmwHAVclUzhsvwybAkIGFWCS40208Lit1
         nEU8Hi6g894L3ube+pd4tkCzc6/9MMp03stzWcWtcRKtkFlU9J1gP7SkFHf3T8tEZm18
         bBAVpIf6R2m1XLeuU5C7KFzdsPgS/IXKJ+CmGyS2NZyhpSGmctsaKGOY+p4fhCfznbZ2
         BddeiSQwMq0dYvCrSUuktP3m0ug52k2v8In5nFLTvUYD/8Os7oUuTZ8CSokSWFxsVqA0
         DGFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4e31Ms+E;
       spf=pass (google.com: domain of 32fwtaqykcsuophjlihpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32FWTaQYKCSUOPHJLIHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65bad2a2f41si226704a12.2.2026.02.16.09.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Feb 2026 09:37:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 32fwtaqykcsuophjlihpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4837907ec88so35270935e9.0
        for <kasan-dev@googlegroups.com>; Mon, 16 Feb 2026 09:37:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVxUVHH5WN2+mTO4NqWiZDdKTlDfmcM5xP+smD7tkAKu599hziM8mfQ2lR4znKSQv19KtNzY+9tplA=@googlegroups.com
X-Received: from wmog12.prod.google.com ([2002:a05:600c:310c:b0:47e:e20e:e9a5])
 (user=nogikh job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:c04b:20b0:483:7eea:b185
 with SMTP id 5b1f17b1804b1-4837eeab9e2mr101249885e9.16.1771263448876; Mon, 16
 Feb 2026 09:37:28 -0800 (PST)
Date: Mon, 16 Feb 2026 18:37:16 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.53.0.273.g2a3d683680-goog
Message-ID: <20260216173716.2279847-1-nogikh@google.com>
Subject: [PATCH] x86/kexec: Disable KCOV instrumentation after load_segments()
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: tglx@kernel.org, mingo@redhat.com, bp@alien8.de
Cc: x86@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4e31Ms+E;       spf=pass
 (google.com: domain of 32fwtaqykcsuophjlihpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=32FWTaQYKCSUOPHJLIHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MV_CASE(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCPT_COUNT_SEVEN(0.00)[9];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	HAS_REPLYTO(0.00)[nogikh@google.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBCXKTJ63SAARBWVLZXGAMGQEA2N2PXQ];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[]
X-Rspamd-Queue-Id: 69DA8146C0C
X-Rspamd-Action: no action

The load_segments() function changes segment registers, invalidating
GS base (which KCOV relies on for per-cpu data). When CONFIG_KCOV is
enabled, any subsequent instrumented C code call (e.g.
native_gdt_invalidate()) begins crashing the kernel in an
endless loop.

To reproduce the problem, it's sufficient to do kexec on a
KCOV-instrumented kernel:
$ kexec -l /boot/otherKernel
$ kexec -e

(additional problems arise when the kernel is booting into a crash
kernel)

Disabling instrumentation for the individual functions would be too
fragile, so let's fix the bug by disabling KCOV instrumentation for
the whole machine_kexec_64.c and physaddr.c.

The problem is not relevant for 32 bit kernels as CONFIG_KCOV is not
supported there.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
Cc: stable@vger.kernel.org
---
 arch/x86/kernel/Makefile | 4 ++++
 arch/x86/mm/Makefile     | 4 ++++
 2 files changed, 8 insertions(+)

diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index e9aeeeafad173..5703fa6027866 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -43,6 +43,10 @@ KCOV_INSTRUMENT_dumpstack_$(BITS).o			:= n
 KCOV_INSTRUMENT_unwind_orc.o				:= n
 KCOV_INSTRUMENT_unwind_frame.o				:= n
 KCOV_INSTRUMENT_unwind_guess.o				:= n
+# When a kexec kernel is loaded, calling load_segments() breaks all
+# subsequent KCOV instrumentation until new kernel takes control.
+# Keep KCOV instrumentation disabled to prevent kernel crashes.
+KCOV_INSTRUMENT_machine_kexec_64.o			:= n
 
 CFLAGS_head32.o := -fno-stack-protector
 CFLAGS_head64.o := -fno-stack-protector
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 5b9908f13dcfd..a678a38a40266 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -4,6 +4,10 @@ KCOV_INSTRUMENT_tlb.o			:= n
 KCOV_INSTRUMENT_mem_encrypt.o		:= n
 KCOV_INSTRUMENT_mem_encrypt_amd.o	:= n
 KCOV_INSTRUMENT_pgprot.o		:= n
+# When a kexec kernel is loaded, calling load_segments() breaks all
+# subsequent KCOV instrumentation until new kernel takes control.
+# Keep KCOV instrumentation disabled to prevent kernel crashes.
+KCOV_INSTRUMENT_physaddr.o		:= n
 
 KASAN_SANITIZE_mem_encrypt.o		:= n
 KASAN_SANITIZE_mem_encrypt_amd.o	:= n
-- 
2.53.0.273.g2a3d683680-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260216173716.2279847-1-nogikh%40google.com.
