Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKNHR74QKGQEYDHQW7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FE652340FA
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 10:17:46 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id p15sf6852242qvv.7
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 01:17:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596183465; cv=pass;
        d=google.com; s=arc-20160816;
        b=hN7sLSMNNXsBReBp8C4KI8Git9dbxHEakkesOP0aAkDWkNZ5dhSUnLOhCyjriBseTC
         5l8xb82uM+6goSj/lMQmYT8H1WIGPPqZumlvCclJjUlTopC4o+Ixq5EZPqfxtv52imgs
         /Zm7Uzp3EAVFfW+XBaJzwL51rEURYlh4a9o6/8w0nsVYBj9YKgJ+p+RTb6X0Mpnb4xpU
         arC394A0LzNt59SBrDfK2enS51+JjTt1XUDqmUEE4JgP6o9+VVpsad5z4egedKip63Ka
         oAcwYhuTe30Crk5KOSBJThM4Tw34kOIWwAhiuQLbz3xD0g9j+EQ51wDfWPCnpMjN7Arc
         6dww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=2w/eln0zXfoluyqufRVvb61jp2h/o9S/qh07gTVt/zk=;
        b=TsH+cbQajm+6ObdiT222Km6uLa7w1t4pDYof11s+N9y16jEbSSKdKMuQPOM7ialPBj
         k2xDorGnDBWJPNu1jLyL/y5Qxa2xcF24r+bYMU26pp3vQCW6cqaOTAon+KIMfIYnH2b4
         3m2x6oGy1B9DnCe3BdD4FI3s5WRRjHhbNq9BEePzpTucjB0TLku7PsyQpPGY6YOPCQ4D
         Xh/8xfsTSVFMdlJG8/2GBcBhU6jwOoKXjhVBPqH4nKFBRIXjOwUC25ezFKsYmQe46uys
         YHa/lnnm9J4Qp1iaZIc+VvWocde5I8tOKNk5OBSFMqtCGdxPWP9SriQRxr08ajO/ImaP
         nTfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GfWMXUHr;
       spf=pass (google.com: domain of 3qnmjxwukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qNMjXwUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2w/eln0zXfoluyqufRVvb61jp2h/o9S/qh07gTVt/zk=;
        b=InV8jWmNGi+UTzZ6OpvW/YSsOfsdVzK3/eUf/k8QyHXRFFQy67Ljuciz+3UrX9+uGH
         zyVycsqSkh/E5EufQCaRBudn4haJ6P0JIReaEl5XtpSU+On4vvzczTyP6ST2COBBzXAD
         ClEsstf1BYeE2wUldgsYU/vj+8k+HtlUmU3er5Pxw2g8v0cWEbGh0t6Q/XZ+BAO/2Y7M
         bXriFLwtbtaKNko/QQYfvQFu3T9cCb+rEjYFaJzLYi2LarNuOHkOfpQi4C1//OsmNqAq
         USPhJThx8jzNKRms07EaGrhsUcBmL9PrlfQa8l9tZnvLPNKvOxzq0ONjlqlluc3bfcZA
         PCxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2w/eln0zXfoluyqufRVvb61jp2h/o9S/qh07gTVt/zk=;
        b=KuooeAOn7xfUush1EPxwaSrt+AhmN6gyTOC8oH7ortozfNxJdXOHnpgwI02+KzG/uo
         oWJ2v5zaAPCZeyWSLdiIBPRbMiDRiy5bNRAAwnHpsdskEH0teTFeGz+PsmtLcaH5+TMo
         vIreinBRvH+8iYo8aUW4erqSYGt9i8sR8eSzy9dhWIKN+l8mzT/dwJOYvWMg0NlTokl+
         IBtRbIFYUbFnRxZt2EIJnKZt2L2o7YngN3sMsXU1SpQOIJUgGV27MZ2YqrMElvFifeJr
         1QV7Vm68s6/TzgMSq3Jfc4BrjoGN8zvDV+Q4yhrDYOx+ACyoUP6XDgRUSeeeTgkGIPAO
         0KUg==
X-Gm-Message-State: AOAM531KWw0szpNAGBR5wei+H8c9NUCqelNNhLPNRiDIHB9JqrgZiZgX
	XFMG4NNX7nuuKNDj2mqxVJc=
X-Google-Smtp-Source: ABdhPJxY4rn1BSMFplMZQwKxBxWAmBy8jFxCDNks/ceu1pETFRcfWEi6J6K1hZ28rMSMk66SYB50mg==
X-Received: by 2002:a37:44b:: with SMTP id 72mr2892829qke.494.1596183465392;
        Fri, 31 Jul 2020 01:17:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5c02:: with SMTP id q2ls3811626qkb.11.gmail; Fri, 31 Jul
 2020 01:17:45 -0700 (PDT)
X-Received: by 2002:a05:620a:48c:: with SMTP id 12mr2934902qkr.452.1596183465037;
        Fri, 31 Jul 2020 01:17:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596183465; cv=none;
        d=google.com; s=arc-20160816;
        b=vG+PK0+S03tDg1iqdLiG/07NoDakLqU4lectNs8WLw4T50oSNmRuWW12yHxxn/68vr
         ln7WDonhD01dhIGjLcsB6m+UTpSpGNgvKmnQ2q3qx5j8FapcSXX+/GY42l4SalDS9Go5
         donLihj6V+wEyW7Q3myOPqd99DrMzxmmHhvd8jTsYMVBBuWJn1AWacBW2BLWRaNPvxmX
         nuZASn/rtiPiGvPttoSJKoQiCOBPl8lgef6dQwnjjzevBhVcNsY/GB6PUwCBot9w/2ig
         1ndkj6tnkAIaarInjAqagrW47HtVeV2HQ3AhMAzrCxPYiiR9nUk9aGmEHue8bSyGk+n1
         VTEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tNfU9OUwAoAvypXurhc04zFcnAktGmnq+u5MEjWOcsc=;
        b=A+Ujy3LcwBoPP/gzDggb0sqpJG/Q8oXJerz3AZAPXCi/LVx+Zkgvc8PkAUBKZgxNZs
         c8NqwuOCk0YgJdY4QKSNjiVuM8/Aa7PiRY6L50xreWGWhRLno5CmWGDIR2i+efHhmHVM
         ifTxEXa70qhFi71zY5EleIBDYMLSt3N9+YEznqMQNSDbfJMqPXA7lYOYOmRosiUZsLPg
         bhq3aFJrKE8fMoWQqpHYjNGBYJHG9uS/2ONhQ0Yy+d5cHvJbr9hN4B7WhlFm52SE+vuV
         Tp9Maj/ILOpcFnMXvQO+JMWcFAOB39C9VSRZfwd47y4V2oZaHTvF/zq+uIaDT9Z21JBz
         QSkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GfWMXUHr;
       spf=pass (google.com: domain of 3qnmjxwukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qNMjXwUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id o2si374266qkj.4.2020.07.31.01.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 01:17:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qnmjxwukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d6so20337499qkg.6
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 01:17:45 -0700 (PDT)
X-Received: by 2002:a0c:e30c:: with SMTP id s12mr2979100qvl.138.1596183464651;
 Fri, 31 Jul 2020 01:17:44 -0700 (PDT)
Date: Fri, 31 Jul 2020 10:17:22 +0200
In-Reply-To: <20200731081723.2181297-1-elver@google.com>
Message-Id: <20200731081723.2181297-5-elver@google.com>
Mime-Version: 1.0
References: <20200731081723.2181297-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 4/5] kcsan: Show message if enabled early
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GfWMXUHr;       spf=pass
 (google.com: domain of 3qnmjxwukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qNMjXwUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

Show a message in the kernel log if KCSAN was enabled early.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 8 ++++++--
 1 file changed, 6 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e43a55643e00..23d0c4e4cd3a 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -1,5 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 
+#define pr_fmt(fmt) "kcsan: " fmt
+
 #include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/delay.h>
@@ -442,7 +444,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 	if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
 		kcsan_disable_current();
-		pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
+		pr_err("watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
 		       is_write ? "write" : "read", size, ptr,
 		       watchpoint_slot((unsigned long)ptr),
 		       encode_watchpoint((unsigned long)ptr, size, is_write));
@@ -601,8 +603,10 @@ void __init kcsan_init(void)
 	 * We are in the init task, and no other tasks should be running;
 	 * WRITE_ONCE without memory barrier is sufficient.
 	 */
-	if (kcsan_early_enable)
+	if (kcsan_early_enable) {
+		pr_info("enabled early\n");
 		WRITE_ONCE(kcsan_enabled, true);
+	}
 }
 
 /* === Exported interface =================================================== */
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731081723.2181297-5-elver%40google.com.
