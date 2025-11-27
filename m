Return-Path: <kasan-dev+bncBDTMJ55N44FBBEOLUHEQMGQESSMVGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id F3A46C8EE1D
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 15:52:03 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-435a04dace1sf8404995ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 06:52:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764255122; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xg3PnE0UfcWty5coIkDwqFWpMhIYcjI9/4rWxKRnP4LUWsg5mFXnRV0VDNcYuKu2tb
         LO1s5IlIYF0VDzrO9LkrQw7p1Fl2LVo/D1ha8TDVa5KwjnwJCLT8dn+zzs+WG+PoKSEf
         8DqBSzxFXgWzXprTZnM4XBkRfF8uIQT+QoijJiuCfFPBJtTT2HLA3EdrQMaUcLxac60+
         jzlhz+dy1mn5QalH3xVNN7IvFMuRLrWCl7VeNh9j8CQN+2Pn2iGet8VGM4pKReumOPGF
         GxuH48ewFr253jA9wXBBDUdq9PJcR5UflRtBMyA4S+k6QA7bI3xNuM/w5TTrbK9E5+4U
         0mvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=VljAShwH9ma41K5DkWKeqiF1m7WhipU9VMQDiMMjAw8=;
        fh=3pSqkC3uMzl8jS8SbBsCOe0l5X1+oKX5xe9EzoPD2Po=;
        b=Nh5gY6/Q3FzKB6DWMbONVA4s+Day6Fd4lUaMLIlj0R8/pZG/J4GAzlJQuT7SSl75Cb
         TrEvqNOMermZJe/a0ewPziWZBqHhZVaPKHVK6L/0KwX7b52by2YqaH/lDNPYNSiZDVzE
         LbvsljCWvOS6SpSfE15akqsD+nw+SWN1OdUNtRevgFHp43VwbA+4O1CpSbUaoJqAEM8W
         k5e4DB2m/6rpZvqkjETQXZo1IryZAM4KSzQDKu3P8l22UhE94bJly94R37vZtxfOeuWn
         Qtu0LF1caRpZWwqBIcEBm9Lj6igwrWd8mcAZfIIrJxTXXa0qRfqsPyurHQWSrgUOVgm8
         mrfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.161.45 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764255122; x=1764859922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VljAShwH9ma41K5DkWKeqiF1m7WhipU9VMQDiMMjAw8=;
        b=aNdeBjnaCJHrUNoyy+8ynufhH5MSXVCYrKcQXUiFJTc/uyyZj2CfxVk80+Dsgzh1u1
         6pdEmD4+RyOUbZH/SKwc63KTIi30zTSNWQTe6M8WVbrU3RP4cXnzPLPlrmE4vkvkArW6
         riXRlMGBeNAg+PqGn7HBLMz/5G27PcudYUwURMrrpLg+7yYMUXSj7Mo5cg3he8Zaa8hH
         M4lQ/092RIknY/0W+cW2EH7uwg6CA8MLd72WP9VZoteRe9aeB/D6mTEfK4NdhIxZe0ny
         K+EabUIKP7WCLbmZzeFH10rmFZdmvp4z7e+d+9fQvaBrziecG8cBD3Gp1YHzHqvTmGJP
         1tdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764255122; x=1764859922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VljAShwH9ma41K5DkWKeqiF1m7WhipU9VMQDiMMjAw8=;
        b=R7yUbjU1Ww79KvIiSe0yPfJ7znhoCpaX1W6UV6vD6SpmVqX44Csxe9xfWe1SF50czH
         lmfos6BGCiMsKuJRoiS93e2nub7uI/qZiPmAgAGx3Sh8usEpjLwA2I+EH5PgtE3hNfiZ
         rlEnpz6nw/KmpxJH7e4sQmuIvBSCtWuEUZrQLizhKdjQ0/K3G807Cr6qmds3eiYYR7aA
         IxDsqKVYwByGXeFH54nSCJopm3FeD8Y2NoCgcqDmvPSg4v03NZjlNXZ0AplrhwAaoRa2
         BtA3Em9ce/PVWWe4dXP82RIdPAPHjCPahJcLypt8E5fAlKh8a939hbygw7qztb1w6NK0
         d1gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8CBBHjJ9UpdxLg6jkGaI+Uh2WTyYe6ZKpJGbrkGY6J79C57rqd1aXl/kRFWmK6eMHp0Kpvg==@lfdr.de
X-Gm-Message-State: AOJu0YxUbV4Rzj7dC6kLMTXI0/gOONvtlkv+VUhEMolWAMmLLH2hB7+3
	7cJjYd3lCSHFgcj5fqfgHTcZsoJ9xHZbwSRbU3qAVWc5m7y6zRWBiS0p
X-Google-Smtp-Source: AGHT+IGN/3jXbceymhuZlWWhNn5DMyRZWExs9PiMP4q4+w6bRPCzTq6/slmWTVKE4Wjmq0Gf23Tnhg==
X-Received: by 2002:a05:6e02:248f:b0:433:5b75:64d6 with SMTP id e9e14a558f8ab-435b98d77f7mr245956065ab.28.1764255122227;
        Thu, 27 Nov 2025 06:52:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YVZ/ehZU9J9HWfxuKthO4Mp2x7wAzay1EKNDjw9baedA=="
Received: by 2002:a05:6e02:164c:b0:433:296a:df25 with SMTP id
 e9e14a558f8ab-435ed47eef2ls4850765ab.2.-pod-prod-05-us; Thu, 27 Nov 2025
 06:52:01 -0800 (PST)
X-Received: by 2002:a05:6e02:12ea:b0:434:a86a:f162 with SMTP id e9e14a558f8ab-435b98631camr176647185ab.16.1764255121098;
        Thu, 27 Nov 2025 06:52:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764255121; cv=none;
        d=google.com; s=arc-20240605;
        b=DMAI6cl4Zf1NVychdJz9Pum+Ta8W2sW6dZyZACznhWXjSh+4tPNa8O0j0zBCQjsiIk
         j3QWHO8Pxq1b4Knb0Y0GrEud/+NTesbBcryk25ehpqZXuKDQV2cS5icd9K17lSVbv7Bw
         zbt5HnKAgvwQVYT4KTUQcVE//IG3tMRt+n5pzk1NmnZoYxyhwz6X497hdMDaVIINdd2N
         s5C6eqSLuwJPoja0jIfxvXvXgJlR9N33INhcbucMyAQeAaYv1a6jZJRawY2y5Dw6Ytb2
         Ey+lmuei/LZ77a5OLgip7WYePTqsMdrSP4PVS4S/yNIJWK1tWAXDLDueC+Td/Dfe3HTW
         zXsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from;
        bh=cAIzZlwt931JkoUZjg2FOr5ixA966v/JOvVIg0npcNI=;
        fh=MsU911CITPkIjgg7H7SJS+znHcvlHe1UD7sHsAXEXlA=;
        b=KCVcKnUSAv4XOwowpLRJpWVYRIhO3QGF1jJa4/duw5vi+K7sUHonE0aChsdj4wdVxw
         EzvD3g1goPGtsUKRPgGQ0yWhyDEN+Wevy8j0Uny77bfK6s402pDHRKPzZwZNM71+1BZE
         T/sKl2sBULgZ41WF5GGiBw8O/nkAJJuoCgvK2y2SJ4FVIPGWrFMl7BJsPrVMmPPUEOu+
         /JqfQe1YDXtedbVh0OTZzl0vQW2fN57u8k0388s3ujUi2yNrtIW581WdXxDhEGNHAaZa
         /etx+JFHzsBhXS+4C1anICEb9rAwjIVawqqDQ4481vncFF4UHPYVmkPdP/zDWabsLeXl
         Pr1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.161.45 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-oo1-f45.google.com (mail-oo1-f45.google.com. [209.85.161.45])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4369d725576si623595ab.0.2025.11.27.06.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Nov 2025 06:52:01 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.161.45 as permitted sender) client-ip=209.85.161.45;
Received: by mail-oo1-f45.google.com with SMTP id 006d021491bc7-6593155d8d6so488318eaf.3
        for <kasan-dev@googlegroups.com>; Thu, 27 Nov 2025 06:52:01 -0800 (PST)
X-Gm-Gg: ASbGncsl3jlEmEEfhdVffD81LVDwHKvVpgxG03dGRE62PnBO6GY8JlrVG4SsezgU43d
	CbEvAj39NWTEL05e6SYyXD1rqJUug0LA744MBzvdxNojyglwLRNRgKMwaNMO3Z9OSKvQWi3I7gE
	apYmsI0MywzRdgptgKFn0Lu57MlQ9ZWpckHjYvYPB+V6x6A1iwdWLue1NarJrorxGaM09h3LRw2
	rRiLq4zmEiLVj8X5QLuZxMPmfWf5ZG2luZoDzyqrK/UVG6aTcQqzyg79bT0l1y9GMTRtZc4sTCY
	RKUi7GsXS+fmZB8PucJ72n9JhHo1e5efoPkP7pQCL4aVSzSp0oBGO3iyI12fDGcNIgv5iO+hpLl
	gwD7nQ0VLGdqrthK103ROGnEspXrnTwJgMUgV8ge3cXRWePre55XXqcj6F/nnhBW5HONgJPkTXy
	061WuRR+v4+BNolA==
X-Received: by 2002:a05:6808:21a4:b0:450:f45e:f4a9 with SMTP id 5614622812f47-45115a2eb3amr8969148b6e.19.1764255120607;
        Thu, 27 Nov 2025 06:52:00 -0800 (PST)
Received: from localhost ([2a03:2880:10ff:5b::])
        by smtp.gmail.com with ESMTPSA id 5614622812f47-4531708e744sm431286b6e.11.2025.11.27.06.51.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 06:51:59 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
Date: Thu, 27 Nov 2025 06:51:54 -0800
Subject: [PATCH v2] mm/kfence: add reboot notifier to disable KFENCE on
 shutdown
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251127-kfence-v2-1-daeccb5ef9aa@debian.org>
X-B4-Tracking: v=1; b=H4sIAIplKGkC/2XMsQ6CMBAA0F+53EyNVwRsJ//DMJT2gItJMa1pN
 KT/bmR1fcPbMXMSzmhhx8RFsmwRLegG0K8uLqwkoAXUZ90R6V49Zo6e1UV7085mas1gsAF8Jp7
 lfUT3sQFcJb+29DneQj/9KwopUp3rmcLg+yv5W+BJXDxtacGx1voFZj9m850AAAA=
X-Change-ID: 20251126-kfence-42c93f9b3979
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kernel-team@meta.com, stable@vger.kernel.org, 
 Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-a6db3
X-Developer-Signature: v=1; a=openpgp-sha256; l=3057; i=leitao@debian.org;
 h=from:subject:message-id; bh=La8G30hl9qem1PV0MHxUCDzheJkZdQA86wiUtuO0D5s=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpKGWPOQkKx1HnYBIusPuWFSi1zEKgAagB3QQqt
 OCZwoLBZX6JAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaShljwAKCRA1o5Of/Hh3
 bb5qD/sFLPYK6ITq6kgbAyxqkbZNfmJ60A+CPwbjNtm8XT727QN5Zu9W3ONIdtd4AasadA+qGOM
 qjDQscvF6Jqm8M5++IbkBuAb/dOGZ9TEiD5WtK8qwFeWFDdItO6H+pvFxUHj/hki3zstK70/9BA
 dB1ILdAJBqtzW0SM8zJ+mNN5uQCAIbh8QNamqioC6twnkJ7WoK9u39f9FfyC+ZCIQ2HL/mFGwtC
 EmKnY6+9hYwruwBF++2d44yCoaHTRjRnMHrFhsrJbhR2sYnhN3yC7M0G5OqwYhjserxdcmYVAxB
 oEm48SGyNmeK2r+9vcJOpSzh7yF3Yv+YMh70dZbY58he1kXuACNklOMwe+apkA1k3BT5nkRIu8l
 275PckhkwGZhlXVZkwqQ77hNYV6oJrkeh/CHHA8gfRbPysFcnlIn0z2E+cl2S58D6rEttEMJH7A
 QjPJT2prC0+KKql8M3EGoqhZ6l4zJlIbFhZLft1V1MypIsLIbgTzfd0pcdyEEDyTA3VvJO1Y9Ra
 UAjKln6TFsArkYDcZimLTeTVRxOAkvlgvhZDs49MGFtvyYCzBp53BCLXv+mV4+GnMfD3rqcF09+
 ktyKFkRGNqJEb/J+y2SaGlte+it0n37XphkvXKIjM7GYEQey9yI6ZWLGQtzULDou7EIeLx3l85Y
 Cbq0Nap2eYSJfPA==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.161.45 as
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

Cc: stable@vger.kernel.org
Signed-off-by: Breno Leitao <leitao@debian.org>
Reviewed-by: Marco Elver <elver@google.com>
Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
---
Changes in v2:
- Adding Fixes: tag and CCing stable (akpm)
- Link to v1: https://patch.msgid.link/20251126-kfence-v1-1-5a6e1d7c681c@debian.org
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251127-kfence-v2-1-daeccb5ef9aa%40debian.org.
