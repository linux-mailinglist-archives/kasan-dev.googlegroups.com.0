Return-Path: <kasan-dev+bncBDTMJ55N44FBBT55VHFQMGQE5I7TSOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B0D1D33537
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 16:52:49 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-88a2cff375bsf45893306d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 07:52:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768578768; cv=pass;
        d=google.com; s=arc-20240605;
        b=X1URgPnX/ffAEcBS3GwK28FFKu9laS4RwPEKGqQZ4M4VoFe5PmQ7nLv+OPSIeRdnfi
         /fW8osVc5MMcz2LlZwPhi89bH7YEo844TynQ5AwUeFrGL3L8B8I91LIgSPncZyXCrNY2
         PY9SlYApLe2KH26F7PHB5dCBbGWyFCHQE8RZiVCQObXAEJZbAkyZeiCLTVVNph5kbnWM
         hThzUCqF3bH2IYl2T5jDHa+u3tewjd7Vq9Hvq1rI+OYFJJatt5xH5xOQEiv3USR1Usqc
         SIM4VsYWFWMlRT84tFmqrL8Uged0YeMOwl+dG2dhovlT1MJ3Qxqqey0SNJejvL2cxTJt
         9RrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=gBrUeaf9XO/mykkAVb1Rl0u3lesU2cX1Cn7FgOC/9Rw=;
        fh=0xJZ9yHMIJvLi6qYZJfTP3MbpUGbvuatGV68a/1UE+A=;
        b=Wnxq9yt55rrMlt4iREjY9fWOqnlNm2162BxmgnzPk0aC3x4+3qz03o7bd4L6fXfksq
         TihB8Y/dEAqKQoioLMBIJlcWh4rxMMvpNimPwRX98zjEoQ2sowAgKPLoV9Ugr82tMwo2
         cvJpie+EAlQaCw+2xHJd2ijCJgYq8E5fXllBuxp+jlBluYbMrdx+wOqxIpLeC63o5kmC
         2tBX5eeXSisA4Gi5aInmiODANQUxL59YzcQTicfq0lDaJSoOKSSvL5hWFNnRoSXqPGOF
         7go3hp7q0kDHk9FdLyCJAvkwHCYpGSR/ekgJO0K6W2XA2GL6U3geR2lc0DXahInKwgHD
         pMBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.222.170 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768578768; x=1769183568; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gBrUeaf9XO/mykkAVb1Rl0u3lesU2cX1Cn7FgOC/9Rw=;
        b=TdDkSjnHd1MsrLxdZG7d1NSs73Rda4EI/VRql7VRt6oEdNV5edG9EUcPiUrAAsBdwy
         0xJ/wSyTc4skgg4fhNrJUCv1p2yMdoDrlWYfR/qLCji5tYs9KjKN83br3nVUfJTKVjid
         lJBzve4r3Qe1DiQUcRGT3Vi/SkL7gKGr/tvmBSGqI/P1jKynODHgKbJmDcNVaKBHZnZ5
         HtiqTP/MKUNfiRrmGFKUmYM8rxh7Kt69KLlq0B6JRC+i/o35Z2o0nY4QQn0TRAcyjlwy
         QiLxI0Oh06JC6kKQZKmTXcF1YNAJJcDoQrnm+tC4PtGmuxAad3rg7K13d7AVuoO7VhEb
         mMZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768578768; x=1769183568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gBrUeaf9XO/mykkAVb1Rl0u3lesU2cX1Cn7FgOC/9Rw=;
        b=C4w7uTcBvBKc5WFrc0NAFvbjE27TaL8y+vPibIi6Gs59loVs1QwYTWYmMKdsT15IJx
         pxst53D/8xOgEqhJTSlrJMJFa/S86MYcrn2Gi7o96rfmnyW2KecEJTDsyGyv6dkcBBmR
         qvngCzB3p4mNkNCTkm/v8OK0M4J5NJcUe00P/pltGL8mv02snmLZm5J3+ua7TdA/zstt
         I7SxvMS1qdAZENxmgItWXHHShBcG6EEpHIrXZFtmXLCZjySVoWi2ydpjjVEZJ/4nvFrI
         AB8CJ5nM9/MMT9+5EyxKoNo2oSaFRWqeNNm3prru/P1bVicWemPGXy1TFTkZ07PLuIId
         6FSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmzjP1/PyiVUgK16D7oQ6594qlZnCv8AfDGDJmpVNbYCsoz3R7BijBiABQ2Lo92vGXCYu4cA==@lfdr.de
X-Gm-Message-State: AOJu0YzDaaHF32j4Kpu1O8wNINCA3kgNgFsiS5MgCoR8CntVIFBFvKd5
	tkl3x5/1dwr6vqnZpWqQI5v7lSyhXTMA7c6UpSMm0O6Qr9QKTx7tOGgu
X-Received: by 2002:ac8:580e:0:b0:4ff:c61a:c8a5 with SMTP id d75a77b69052e-502a1f0d315mr41935181cf.49.1768578767673;
        Fri, 16 Jan 2026 07:52:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F5AKIv4hUfRfK/DU8G3/ffLx3GMLM+JPYa9syA0oKa4A=="
Received: by 2002:a05:622a:91:b0:501:47f4:eaf7 with SMTP id
 d75a77b69052e-50214a1714als35068381cf.2.-pod-prod-05-us; Fri, 16 Jan 2026
 07:52:46 -0800 (PST)
X-Received: by 2002:a05:622a:38a:b0:501:4ff5:ae3 with SMTP id d75a77b69052e-502a1f0d883mr45318941cf.42.1768578766552;
        Fri, 16 Jan 2026 07:52:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768578766; cv=none;
        d=google.com; s=arc-20240605;
        b=RfSd8eO+m+qw4tjVzs0ubd19IAiUkZ3ZN4EwUMjX67m3+vsEGm86Ou9EiD0eVbLNXF
         yYAypWdQqY2+jNMMYNk0jMN8R82V5JG9Rx8WdbTBzFeCCS2BGK0ZGXdzQIK926LDJe3e
         mB9jCaW2ZVTC6dzoqggN5PznbKyUUqOBt/N1Hv/zCsu5fs/Bmk9ISVoORtDyvK/xhdLK
         P9rRHb5cSlgK3hh5zGOUHPyqS7+whels5QlNhKgqK1TLiVTeuIv19eJBXoGTq/XZaJBI
         NqNB9XoakAjlHagR5TE+tK4PPgqbCbRhS6nrAppLgyvjTYfc4O2X92QK+2iwTmFO/xg/
         l1SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from;
        bh=pvIuhV9+sNv3iCssx0o0Pe32iUx/gKwQFY7jwtHcvQU=;
        fh=7Y7efXs7CCA8DCyj4bvhXlKc9cl0fzXdIR4iQCodwR8=;
        b=G+ywj1STJoSskbreMhtft4Q7YQI5EeGgLqRfuYjaGASHS2h8Ub7DoGhgOMq+WZyQUZ
         HDDQT7ctgyUUYneBS5aWqI4GWBZGQ7Z0pCYbQyCGOdMQ1vDlAS7V9q49I3q8+HwJhasg
         6X72DpdPhWcF9c2JNgMTGlZJGKvwivQ+zLL+RzGRGfJ8kJy0zPm5zOLIR99IZY/xorB9
         +i2wxDD9oGBpUKmCEajWERQeDBOAFYmcK9kKxpSBkC/KP/8luSnxBO9seJ7EgHjpf+dv
         YG+JNAflmZycdIwp+XeMjrc7X2nXm9pX2sMvGuWyMT3IeCN3wnSVY+4Zbh3ptqrJCUfZ
         NUPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.222.170 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-qk1-f170.google.com (mail-qk1-f170.google.com. [209.85.222.170])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1c1786esi988511cf.0.2026.01.16.07.52.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 07:52:46 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.222.170 as permitted sender) client-ip=209.85.222.170;
Received: by mail-qk1-f170.google.com with SMTP id af79cd13be357-8c52e25e644so207619785a.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 07:52:46 -0800 (PST)
X-Gm-Gg: AY/fxX7C4EDwJn66f4VJ6xDbSLHwEcZ+N6JXHSn8BXQrjdpDx0Q2DaJB0h1EQ/pb81e
	m0NwWVQND3cTmrc7AEvkUVS1rPsrX01KmQUIzej19jk4sm7KNlEiVctqV4GZPBveSJ2eH836joS
	gSFaUu+B4VE0X3MkWOMzEkzYmeWFLSnsUzcBkH096YCSNwrNID6067nhF5x738KQMSW2mNB/aeF
	9EQBKkUdB8M4fnOEsBhr+Ayk6v6Tuctwy6CtnQtmRpEGDaicj+KYmTb3jBxYCtlonu3q97vwpwJ
	IFP31TrvgGbFw1FR+9hpdoGEjTJOVH3YkpB1Z8zP+3d7t4WrPhWfKRV+7iqeAIjpHkWszOJGToq
	AI3rKSpyb21k+qCTVGAvVJBSsYcRTZf0uwipRCzRdKLbhBX9FyhVq5OmLg97AbDwbU3VXQa2YSQ
	5WhQ==
X-Received: by 2002:a4a:bb17:0:b0:661:1cbc:45c2 with SMTP id 006d021491bc7-6611cbc4928mr409451eaf.16.1768572623144;
        Fri, 16 Jan 2026 06:10:23 -0800 (PST)
Received: from localhost ([2a03:2880:10ff:57::])
        by smtp.gmail.com with ESMTPSA id 006d021491bc7-661186dc702sm1263388eaf.6.2026.01.16.06.10.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:10:22 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
Date: Fri, 16 Jan 2026 06:10:11 -0800
Subject: [PATCH] mm/kfence: fix potential deadlock in reboot notifier
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-kfence_fix-v1-1-4165a055933f@debian.org>
X-B4-Tracking: v=1; b=H4sIAMNGamkC/yXMQQqDMBAF0KsMf20gCa3UXEWk1OmkHYUoiS2Ce
 PeiXb7N21AkqxQE2pDlq0WnhECuIvD7kV5i9IlA8NbX1rnajFESyz3qaprGXnt/u0THjIowZ4m
 6nlnb/V0+/SC8HAP2/QeVxSfzbgAAAA==
X-Change-ID: 20260116-kfence_fix-9905b284f1cc
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, clm@meta.com, kernel-team@meta.com, 
 Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-47773
X-Developer-Signature: v=1; a=openpgp-sha256; l=3280; i=leitao@debian.org;
 h=from:subject:message-id; bh=6c0reEst+EIZA2PaSJbeOygkyAUIcKW0sGGQ6IOzV48=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpakbN6YhptWCcXUtZJrdJi0Sq9v6y2NypuVlhA
 yll/P7R01+JAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaWpGzQAKCRA1o5Of/Hh3
 bbf8D/4oIWJVhIsaxEVusMGtLueC27JQrU8Qczg0pBer7m8PD7bV1s+HYYH5xxfhf8jnL+fwFX/
 Y5UKCbWen/HKE7lnSDIjQRFp/XpFIWYk9cMBu1/yItTsV0deSxajEFTHSHlBvGREXJ2gfntDAVN
 pJ3sXJrRxGeKsW0ElHzjSOFrwKeYpDHPMb4s0aXMOThEUZYboel+XK+nB1ulTaP+FkFlBiyMcM2
 hQG6b7KGmqi7hMUdiHUDm4k9nfdNECUObvqOdVyiJ8NOLs5GwyiIFMWvEjxMzHUTTB7a3IyeIce
 oK6u/BNhCT5AMpJf+QHz7DTQO2WfSJOb9rXCqe+7B5x+WiOQDWH1AyNVpLDVm8jo+LYFma+XwKN
 xCOUE9yJlAItKA3dOqNKhYhmgRJlJdRgNlEj2gU4sD3R1IsB4rBx6HLaVWgYYKe8ZAxGPNVE+3q
 KlF6sEG3hSFkc6foQrKPjVbFGqfcwh5yvRjUJ/k2CzRAA5vWGwRXkDcOSiAgFXbi+BW9WeNJMGO
 R+ntiHljO8OBuvxiDFIbPQPYiAPZaOLsgkxsMZl3ySAaavBcVryqykSbLsbyVGVsonEY83pEhoh
 mX9DqV2Q/qGcKbYsBMsGNxYlhe5beqgS7pyFd8rsBc62nZ/tf8S/piARqgtqyC6Mioj3jg3I9rx
 phWuOGd9v3zpcWw==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.222.170 as
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

The reboot notifier callback can deadlock when calling
cancel_delayed_work_sync() if toggle_allocation_gate() is blocked
in wait_event_idle() waiting for allocations, that might not happen on
shutdown path.

The issue is that cancel_delayed_work_sync() waits for the work to
complete, but the work is waiting for kfence_allocation_gate > 0
which requires allocations to happen (each allocation is increated by 1)
- allocations that may have stopped during shutdown.

Fix this by:
1. Using cancel_delayed_work() (non-sync) to avoid blocking. Now the
   callback succeeds and return.
2. Adding wake_up() to unblock any waiting toggle_allocation_gate()
3. Adding !kfence_enabled to the wait condition so the wake succeeds

The static_branch_disable() IPI will still execute after the wake,
but at this early point in shutdown (reboot notifier runs with
INT_MAX priority), the system is still functional and CPUs can
respond to IPIs.

Reported-by: Chris Mason <clm@meta.com>
Closes: https://lore.kernel.org/all/20260113140234.677117-1-clm@meta.com/
Fixes: ce2bba89566b ("mm/kfence: add reboot notifier to disable KFENCE on shutdown")
Signed-off-by: Breno Leitao <leitao@debian.org>
---
 mm/kfence/core.c | 17 ++++++++++++-----
 1 file changed, 12 insertions(+), 5 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 577a1699c553..da0f5b6f5744 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -823,6 +823,9 @@ static struct notifier_block kfence_check_canary_notifier = {
 static struct delayed_work kfence_timer;
 
 #ifdef CONFIG_KFENCE_STATIC_KEYS
+/* Wait queue to wake up allocation-gate timer task. */
+static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
+
 static int kfence_reboot_callback(struct notifier_block *nb,
 				  unsigned long action, void *data)
 {
@@ -832,7 +835,12 @@ static int kfence_reboot_callback(struct notifier_block *nb,
 	 */
 	WRITE_ONCE(kfence_enabled, false);
 	/* Cancel any pending timer work */
-	cancel_delayed_work_sync(&kfence_timer);
+	cancel_delayed_work(&kfence_timer);
+	/*
+	 * Wake up any blocked toggle_allocation_gate() so it can complete
+	 * early while the system is still able to handle IPIs.
+	 */
+	wake_up(&allocation_wait);
 
 	return NOTIFY_OK;
 }
@@ -842,9 +850,6 @@ static struct notifier_block kfence_reboot_notifier = {
 	.priority = INT_MAX, /* Run early to stop timers ASAP */
 };
 
-/* Wait queue to wake up allocation-gate timer task. */
-static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
-
 static void wake_up_kfence_timer(struct irq_work *work)
 {
 	wake_up(&allocation_wait);
@@ -873,7 +878,9 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Enable static key, and await allocation to happen. */
 	static_branch_enable(&kfence_allocation_key);
 
-	wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate) > 0);
+	wait_event_idle(allocation_wait,
+			atomic_read(&kfence_allocation_gate) > 0 ||
+			!READ_ONCE(kfence_enabled));
 
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);

---
base-commit: 983d014aafb14ee5e4915465bf8948e8f3a723b5
change-id: 20260116-kfence_fix-9905b284f1cc

Best regards,
--  
Breno Leitao <leitao@debian.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-kfence_fix-v1-1-4165a055933f%40debian.org.
