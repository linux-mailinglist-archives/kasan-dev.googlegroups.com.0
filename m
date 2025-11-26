Return-Path: <kasan-dev+bncBDTMJ55N44FBB67ZTTEQMGQEEL4FXXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF9FC8B4DC
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 18:46:37 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-948ffd40eefsf2059439f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 09:46:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764179196; cv=pass;
        d=google.com; s=arc-20240605;
        b=IhnkcjOgiy6XJJEEStekdRQ+27Q8AkyWPFdYrAYiGl/WVmQ0Oz7jCnWCTGeUuYFcXA
         Wdtb+f4fotvZH8nfehrPJe8PEBaZA0/VXlbmg5sRF9MdiEf7D9UqeeSusVRsNblOndfi
         Cb2ZWvtWc67ky1LBSXq4p9F0mkj3HK78iG51AdVZEX3h+N1gVrvhX0qRIQo8vtvgt5ms
         03i/qSfJU2aLMY7HfTxPdk5tDBMEQJXlcyMMdJBAF7XArnQOJbidcfdtPTQwcq1Pm4ME
         1dLfElRQd4WYmE3ZetaRi136JOvwev/HYkFsOj03kx/jH/gLbJNvx2vq2ifCMcNm6VFq
         7Lpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=TkysRJO5o6Gfq+9Jfr2aZgE7mzPkODouhATqxVXYslY=;
        fh=cun6PZqQSwwoXNCE0DRrx8I7GV5jj5UVpBbK9uD9Dc0=;
        b=WWTPMsF5RjqMCvmfV/zM3yq7YKhVo37yH2NRn6NZae/ufR8e9OW7pDY8oeg2Gfa0RS
         Y39PLJuwxgCJjGbt0U0480kfzCFJLd1XgGf3tHjQTK8P3Vo8QvCmF7qBSO47ZrWlmset
         HRhzmsXIGCFhi/5wmZKc4AN/MTqQLe8k/3bL3Jx0JuQkkUNESOImemFzzGj1uyqWL2gV
         9FsvWTdsQnQ8Wd5pMOExjkljGfUKwvXn1dl+7kcxw/QMrXF9wwmqc66UXhyMY25blPnn
         Bv0lVxUQrO+jOvCXHb+OymIvDZbz490V0n9Q8s/ijutkALxZ72KdEfEL+M3Be8vhOoJb
         J7FQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764179196; x=1764783996; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TkysRJO5o6Gfq+9Jfr2aZgE7mzPkODouhATqxVXYslY=;
        b=XelWYSqWnZgkbGeQM+B3f48SITFwG6sTemOuxSmrVDIIEtkP/IpOQm1gZ672p5qYpV
         Bf8cSWziTaloBmmCEHk088ei+ZJAMvAWLKuMK/oZuEHrBhEqajCh0G1B1MRDFhwquyb+
         V65rFx9tHYSmPlD+DQdEkFtr4zQKu0z/m9hzHXEE35zaVMjWRqxeG0ONBzRB3N+rDY6y
         7kG7H7wF8dvbF3f91O55Al+xzgNrT8NZPwt6J9VfbZEJK7qoMaO9oTa6lQxGAIvB07hO
         QD/RSu2YrG+bP5SB5ZrOcWxcONYJov+wqgPAA82hr0AfYwGTy24iThVYw+CDx4HVD8Y5
         H6yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764179196; x=1764783996;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TkysRJO5o6Gfq+9Jfr2aZgE7mzPkODouhATqxVXYslY=;
        b=qBU/tzhZnsgXqrXwPfZH4qcN2jUpUUl0PAiDK/6/BDbA02ES0bCFnOoF0G0ZHaRgYt
         oQreITkFuc4ImWXoy4eKpqs0pIIEoGMNi2a4cn31NvI1rUDpHREFSMv7tUh8ufzLkHhf
         t4aWmEUUBsCBjf8mc4bBq1dC4Zv5j3F6tQsXPandM1HKJZdvfADpBN54ighagzCbDQsu
         8PMXJxOM2svMWi4cH5w+iAyJ3XxuLc1tLAV6h4AfYT8pbiG8XcrSGZnxeYrHJvzU2WK2
         dBEiMRhat1PN8W1sCUwa9sLdt+8HZuAZxrFnI63PJh5+eJACq4+TeccRzQV3tIIm4Kvo
         hQlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/+UUbDpCKalwm5tF2UMwHcXDXdc0WeC3HXJFrdup6d1wal+qmvT1j1bmrGGpHo6ZmdcYxIg==@lfdr.de
X-Gm-Message-State: AOJu0YyiZFB1uGFb0F0WJF61NFkMTdJZrtix409KgOr7O2C/28hp+PKO
	ed7C9RlywNF1FzrlIH6wSPlUgIxz1KbZkpD58i95hmIFfoFzbphtcG31
X-Google-Smtp-Source: AGHT+IHEuc2cGxasYKI6CPt7htXMoluvbKr48n/hG5iUeEhSzluTLwa/vkGzFyT7Mtfwunj+rBSGwg==
X-Received: by 2002:a05:6e02:3c81:b0:435:a148:393d with SMTP id e9e14a558f8ab-435b98fa9d2mr150799965ab.41.1764179195629;
        Wed, 26 Nov 2025 09:46:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZBCEzJEOkorzW874FNBinoDbg9zbG/oBFa1hu84noC5Q=="
Received: by 2002:a05:6e02:1a63:b0:433:7ab2:fb9a with SMTP id
 e9e14a558f8ab-435ed3f543cls102065ab.0.-pod-prod-06-us; Wed, 26 Nov 2025
 09:46:34 -0800 (PST)
X-Received: by 2002:a05:6638:6374:b0:5b7:33d3:6f6c with SMTP id 8926c6da1cb9f-5b967a7bc85mr13287824173.15.1764179194738;
        Wed, 26 Nov 2025 09:46:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764179194; cv=none;
        d=google.com; s=arc-20240605;
        b=imF3w5zumA5xnKSIYO4+tpYNLTEQ5+LQrEAwtIer0snFQuqnZ3coqU1tXwds+BZrgM
         c50UH+IPH72f5YZgMtcRLeAyeehsPiykAHegsryKjHN0WE5ruXYj1o0/TgkdJFzgu+EZ
         uArag1LvMrJ+aUzpPMEtN7iH1CR/7jTPmMc+3Q3uPdBfiBc7xo2FEnbOO3hAtdHMSVRl
         LDUi5hMk69hf8Nb9idarQWsA16A/09lH5jH3BC4n6LujTkvEWiEgF5ZbxSjVsWZqe8a4
         47bTvGsY0RtuR52Nf5kjT7bYE9xnKhgLWeIp5ZHJbVusdgLIt/cuLzYHzJ9BDelFa3Ox
         RlZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from;
        bh=ngh5WCQQNN28DIPnbePNrqfYLwUi0/9012QJtQO9mIo=;
        fh=2ztqT1j68xvnGrkOBZRCjT/DZFi/r6shVZYZNdQpMoI=;
        b=LtXn4ad/TGY5neHhVhjmMNOGTnxOgAUKeai67jn8CIYdbmHCSCGS321Lol1KJkkbeC
         lPl7RKMeGsYUCeuigOyY6xCPo4T6JsS9vZAbhXcS3ABklOefzoipqDKtJocMRmvu8KlF
         /H9EAVb8x4Hcc9lSqDI8+5OAEbJCTL12b/issMzvRcg0MCGPb1HlbIC7rTpTl0Bmt6Gs
         hDnvqiuLiX8F3xr5OfKqY3/dIkW041gGtW79iX6YlrM2WymITnwJub9nOyS6AzfIE39M
         imY76egj4s25SihLag+BWwOOblE65ofpOCBbqbyPGSUcPzkPfu/DLYEgu5wlW0Gu4OcO
         H8vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ot1-f53.google.com (mail-ot1-f53.google.com. [209.85.210.53])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5b954af6da2si629138173.6.2025.11.26.09.46.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Nov 2025 09:46:34 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as permitted sender) client-ip=209.85.210.53;
Received: by mail-ot1-f53.google.com with SMTP id 46e09a7af769-7c6d699610cso35163a34.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Nov 2025 09:46:34 -0800 (PST)
X-Gm-Gg: ASbGncsUKdRl0uJRCuDsCHeh8WVYJzKXTdRXXyjQpD+pOsRuXKvGPU3GohBayLKnC29
	XjXueUHFAAKQ1aP8aG/tt5sJZFb6Or4Tmd8jYEv/TsJh1VuuqjYFIhMW1sugPZ4jyG5O/YjLQjB
	/T0ZllDLnT0yVhwgOQAgxCW0heqlbNRjNiBVj0Sb/Xx3bb72c+O8c6nUz9yjN56W4niEql6GAlm
	xq4czCOV4X+Tx8Q4oNknniQBuSzNf9z6zU5fw51bAOyeI+2P9+yC3RSEUegpIfyO921lplrdAmK
	h8ORNuyNTDIGBi8D08Iq6isCm2MC3U1wxd+V4oWmPv7bgUut9+hUtwPWOHOyNI5IuFpT2hdFqsZ
	s720YqVRXbDLIzL8Gt1SynRb4prku72Hj8gV0YGC7X+y8dw4YM3oZSJoKodO2TReOWyugx504Pj
	FzuGH7JNU4CtAarg==
X-Received: by 2002:a05:6830:6751:b0:7c7:6c4e:ad2 with SMTP id 46e09a7af769-7c798f9e05fmr8496172a34.11.1764179194223;
        Wed, 26 Nov 2025 09:46:34 -0800 (PST)
Received: from localhost ([2a03:2880:10ff:44::])
        by smtp.gmail.com with ESMTPSA id 46e09a7af769-7c78d302329sm7761526a34.6.2025.11.26.09.46.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Nov 2025 09:46:33 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
Date: Wed, 26 Nov 2025 09:46:18 -0800
Subject: [PATCH] mm/kfence: add reboot notifier to disable KFENCE on
 shutdown
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
X-B4-Tracking: v=1; b=H4sIAOk8J2kC/x3MWwqAIBAF0K0M9zshtQe6leijbKwhsFCIINp70
 FnAeVA4Cxd4epD5kiJHgiddEcI2pZWVLPAEU5tWa9OpPXIKrBoTnI1utq53qAhn5ij3Hw3j+34
 KGHzxWAAAAA==
X-Change-ID: 20251126-kfence-42c93f9b3979
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kernel-team@meta.com, 
 Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-a6db3
X-Developer-Signature: v=1; a=openpgp-sha256; l=2763; i=leitao@debian.org;
 h=from:subject:message-id; bh=9U+GnrSlG5sCxW9pY3HRrBJ7UI24sm2FPtmuWSKIX9Y=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpJzz53hh71o0dkkgQFrG2kU74cUuCamS+nyHar
 AitaN7UfBmJAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaSc8+QAKCRA1o5Of/Hh3
 bddLD/0ZiqTCTHMsIVZgo/sRS2o3c2kxOP8WK2lZX7zOxZdIUVFdd7ttiVQk6+oIvRnJ1mC7qYZ
 r9TZMBjc6E4WZI/P/iyRUxUC70JfDQs5mhERpJz+xWX4x7GcB2R0HymsyOkKa18wLCpuM3emKMX
 wv7rzT4xwoaiY6KVRkJr+YMLm4XWKRDIHcfg25U9khuh9I21EkHAJSmGEW0Rpp43h/gW0kTEaMv
 /mtMN0PtQZrKzsKJcNawEiornCfbPvUfoZ+GN0vcgJD7WzFNdz5F2tXtik7SRALjOXju7ABthTY
 xz8MAhLuGM+62d4gY7bPKrOwjOAaL1HFj5zdGKUXNvlWkXBL1j3KPMlDgUvdnMT07QlUu43i2aX
 0oN8rkdKyG8JHEhJwCTeWbANuwCLHEXltDwBWfoRoA97/RtVCQ0s3X1fVt5bgUBINMd10cjVKGM
 i54kz044jZeCJcIxr/Z8iF2uUXQAuR6QptQsf9yOrtFbC42Sply8HtAALjc7/STmWOjUGKAQJbb
 KnMU3RYqZZRhNmrv90GeEKhVp8WzcQd51JoQiDS+tVzETKzkrCGhjUgAcUXWbJZTINVVA2wSENr
 A6wG9LBV4aAkQi48ioTbXCXgTj7cPxlDp8KZOiXy37Z0Q81ZOolT2JEnL8JGqn2kOAptNBm46ng
 tT/lpt3LrS7mibA==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.210.53 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

During system shutdown, KFENCE can cause IPI synchronization issues if
it remains active through the reboot process. To prevent this, register
a reboot notifier that disables KFENCE and cancels any pending timer
work early in the shutdown sequence.

This is only necessary when CONFIG_KFENCE_STATIC_KEYS is enabled, as
this configuration sends IPIs that can interfere with shutdown. Without
static keys, no IPIs are generated and KFENCE can safely remain active.

The notifier uses maximum priority (INT_MAX) to ensure KFENCE shuts
down before other subsystems that might still depend on stable memory
allocation behavior.

This fixes a late kexec CSD lockup[1] when kfence is trying to IPI a CPU
that is busy in a IRQ-disabled context printing characters to the
console.

Link: https://lore.kernel.org/all/sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu/ [1]

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 mm/kfence/core.c | 24 ++++++++++++++++++++++++
 1 file changed, 24 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 727c20c94ac5..162a026871ab 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -26,6 +26,7 @@
 #include <linux/panic_notifier.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
+#include <linux/reboot.h>
 #include <linux/sched/clock.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
@@ -820,6 +821,25 @@ static struct notifier_block kfence_check_canary_notifier = {
 static struct delayed_work kfence_timer;
 
 #ifdef CONFIG_KFENCE_STATIC_KEYS
+static int kfence_reboot_callback(struct notifier_block *nb,
+				  unsigned long action, void *data)
+{
+	/*
+	 * Disable kfence to avoid static keys IPI synchronization during
+	 * late shutdown/kexec
+	 */
+	WRITE_ONCE(kfence_enabled, false);
+	/* Cancel any pending timer work */
+	cancel_delayed_work_sync(&kfence_timer);
+
+	return NOTIFY_OK;
+}
+
+static struct notifier_block kfence_reboot_notifier = {
+	.notifier_call = kfence_reboot_callback,
+	.priority = INT_MAX, /* Run early to stop timers ASAP */
+};
+
 /* Wait queue to wake up allocation-gate timer task. */
 static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
 
@@ -901,6 +921,10 @@ static void kfence_init_enable(void)
 	if (kfence_check_on_panic)
 		atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
 
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+	register_reboot_notifier(&kfence_reboot_notifier);
+#endif
+
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
 

---
base-commit: ab084f0b8d6d2ee4b1c6a28f39a2a7430bdfa7f0
change-id: 20251126-kfence-42c93f9b3979

Best regards,
--  
Breno Leitao <leitao@debian.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251126-kfence-v1-1-5a6e1d7c681c%40debian.org.
