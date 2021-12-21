Return-Path: <kasan-dev+bncBCXKTJ63SAARBCUSRCHAMGQEW4ZQFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F7C647C495
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 18:04:11 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id u8-20020a05651c130800b0022d6dad0418sf444844lja.11
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 09:04:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640106250; cv=pass;
        d=google.com; s=arc-20160816;
        b=ExxqPVOZmE2dz7CSGGNs2ECX9lunJ0F5qEOEMueUndHt+n7o3UhC5bZWST5fR8kmkd
         3FU8am4wDShxlBRGHg7XXqyU19211kDBOpT53w9IcoVXrW1ugitiEJq8wD9yhU3psKl0
         nLwb072o46DgKZIHcD03nzgfuesmXLBCCbwV7ahv0sK/jcqz5gDpC/EGodIrMhutuOYn
         o4mA/KLaFchbaJx+/4lQSkaD8B7LYWRKr3zfpG/1uH+97g7n/ExDN7wb7UcZsexmYAv+
         Tvez648i0BVXqBgdjEd4xpFQF7KDZ0jJ5pCBFiDpuAakR41vgncOWQS1TPsPBs4e/IGS
         kYIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=gDa17OQDm4VQ9D1Viclh7xPKeNUDEXnrN8hZEsxngbY=;
        b=fsIpJG6xlmUOkacc0RaYw++JYBEgJyLSqKb0+0fT5TWLilIowpD01x+zGVY+S7dlNa
         t/DOSytfob5v0LBwnncNBV+Zau6hYTmWhCWGKPh8ztNWsaXE8Hl48UQk15n6yFJk/Avw
         +NrrhS96rTmvN995BG7H8hPY/udkCtQvdIoscoL8nDqVB7YLUYZZ15XkQAusR4EzA5HI
         F1FT0rX3ss7e0G6QaO7AG0e/xIq+Nea431pRTD2Gu8dzTr5Zw6Kn7WHMuidDXJJMJTsi
         w4V4rnUm7XLDe3akjSy5l4bBBEUgiqtuBsUJZIqjlns8+Mij68EjXBQ1GO+B+NcN30I3
         eoEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mt6SflaH;
       spf=pass (google.com: domain of 3cancyqykctcghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3CAnCYQYKCTcghZbdaZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gDa17OQDm4VQ9D1Viclh7xPKeNUDEXnrN8hZEsxngbY=;
        b=oxYfKwA7OUoC3V9nW0csBdynj6SHhOdDaP2ghrt8mZygkX3CE4/w1b2UJIkNEhx66Y
         pKu8B+EGwGHiIsrmVLLSuYC2/deGnUHTFXWqbSSLo6qU/4pIg7LlsRGQYc2zDl6Tzplv
         4Q+aEQX/EkjJZB65vbMInNKfxjWOeC4bHtmtXnuEURfuofz9xwEwip/lK54uPFP8ZJwG
         OzW98jJYjjY9O9vK/1N+HvzpV6lj5BjpW6cfoJZolJU6kTn/t7iS3vDKs2pKM9/uD2M6
         LcstrBGyarDu/lThGP7+7138vciJ0xiF1r1klTX2NgCmX8nBbULVJPmjfUs+1w+mhJYL
         ps7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gDa17OQDm4VQ9D1Viclh7xPKeNUDEXnrN8hZEsxngbY=;
        b=V+rlgb4Sw/wlPF+LuTzGBVrd+CSls4+bkEWhRSnoVLI1WpuKnenedMXgs6EX4R60Ia
         Im5M47Q6rdgUQeA101DsIVi/8xPggXCcwd2UNrzbxnePHiCcXb/xYVmK3jprkqYgOEa3
         CnGDEENx4kaQ2W91cAHIzntVnjq6oZl39EpYZkAnQnGL/Vx7huIQV6Nx2tCXMN0oZLDT
         ir+1QSn1PqwdB5vqBlYNsaJtuj6YDC3prBpBlvrG2dCccHHpFgYdSLtAEPWPIRuAxVHh
         Y7vpEKHyGUHYXQOxDJCctU5SesC5uUtKeqkgFTJ0BqgWNDjuEFgUUw69yKbb3wx6vzcn
         E+Tw==
X-Gm-Message-State: AOAM531VaZBl/dKM2vZj9c4JH2KDhpgqONHlBQongMgOWJWP6tInIYmq
	lqAiqlXgLwqlm/nC0z05DBE=
X-Google-Smtp-Source: ABdhPJw/aFA7kywsHgRQBt61hGDkFnISHAo5cITHQD9u9C3HkcyAoPfFb/ovbQUWaAOnvJGsxVZkcw==
X-Received: by 2002:a2e:9dcf:: with SMTP id x15mr3329394ljj.432.1640106250474;
        Tue, 21 Dec 2021 09:04:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls632261lfh.3.gmail; Tue, 21 Dec
 2021 09:04:09 -0800 (PST)
X-Received: by 2002:ac2:51bc:: with SMTP id f28mr3772154lfk.222.1640106249534;
        Tue, 21 Dec 2021 09:04:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640106249; cv=none;
        d=google.com; s=arc-20160816;
        b=N5f0TexoosCxvE8/WEw7GWu9UqiYVT2ZACpb7UxmaKSaYSizZgohbKD9ck4OvHkCb8
         AYwaTC4P1ch2WE5l6t+F8V34mcyJe+2VlyCrrFNMVMCcvwA4O5iZlrKLfZh/nBgMkQmw
         MMlPK6/Yr2N8PFTSoqFIjHTk0zWwCQVxIFoAlGIrDBPKy0mTxeamVfSrHB7CKF2VLRiu
         tP8XutQLee9NAegJLF21Y+DjjjyUvUG7Fjrr5QJDmsFP5KzV8yXe9OJ3WotdmM8Kq1wL
         Go6fGkG71ivrEN8yJQnq2f/leDX4OeMBmvU7AZqcUvXNUYWKkqqMP1o6xHjskHgl+57I
         ROHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tAooiWC6s3hGfLWdFjLduilnhzXlkBJTQtprgFsbC0o=;
        b=GIib/5eTOBBCPNzFSLBF2VUnlZeAgmwlz0GR7NejCO00n97ZwmUrO78dWCamqKg84q
         fTVYvLV2cVQ7+NX8VuqNraGY+pz2EtWuBbhdga6Kgc0+PZ7w4OGMPKarPWyg3aCY7fPD
         yxqPaSQlaMISZ55UdrlxNQ/GcVdGdbjjVYYWeoHVf4ZDFGQc2h3bCNr94yk1U4oo8Zr3
         2X5CBNv4slfC7JeMMnseTqxHqkNpRxoftuKWhGkZIp4JH6irz//ppE81ylToZGHxLRA0
         HwWZX2iZgLLErCcdKuk5fXlG+0bzLLwTnsv0iTW69RuajtUSbTKRhF5o0jevj5mDBwqP
         fvEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mt6SflaH;
       spf=pass (google.com: domain of 3cancyqykctcghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3CAnCYQYKCTcghZbdaZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id e18si1037933lji.3.2021.12.21.09.04.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 09:04:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cancyqykctcghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v18-20020a5d5912000000b001815910d2c0so4876889wrd.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 09:04:09 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a7b:c219:: with SMTP id x25mr67034wmi.1.1640106248480;
 Tue, 21 Dec 2021 09:04:08 -0800 (PST)
Date: Tue, 21 Dec 2021 17:03:47 +0000
In-Reply-To: <20211221170348.1113266-1-nogikh@google.com>
Message-Id: <20211221170348.1113266-2-nogikh@google.com>
Mime-Version: 1.0
References: <20211221170348.1113266-1-nogikh@google.com>
X-Mailer: git-send-email 2.34.1.307.g9b7440fafd-goog
Subject: [PATCH v2 1/2] kcov: split ioctl handling into locked and unlocked parts
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mt6SflaH;       spf=pass
 (google.com: domain of 3cancyqykctcghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3CAnCYQYKCTcghZbdaZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Currently all ioctls are de facto processed under a spin lock in order
to serialise them. This, however, prohibits the use of vmalloc and other
memory management functions in the implementation of those ioctls,
unnecessary complicating any further changes.

Let all ioctls first be processed inside the kcov_ioctl_unlocked()
function which should execute the ones that are not compatible with
spinlock and pass control to kcov_ioctl_locked() for all other ones.

Although it is still compatible with a spinlock, move KCOV_INIT_TRACE
handling to kcov_ioctl_unlocked(), so that its planned change is easier
to follow.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
---
 kernel/kcov.c | 64 +++++++++++++++++++++++++++++++--------------------
 1 file changed, 39 insertions(+), 25 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 36ca640c4f8e..5d87b4e0126f 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -564,31 +564,12 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
 {
 	struct task_struct *t;
-	unsigned long size, unused;
+	unsigned long flags, unused;
 	int mode, i;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
-	unsigned long flags;
 
 	switch (cmd) {
-	case KCOV_INIT_TRACE:
-		/*
-		 * Enable kcov in trace mode and setup buffer size.
-		 * Must happen before anything else.
-		 */
-		if (kcov->mode != KCOV_MODE_DISABLED)
-			return -EBUSY;
-		/*
-		 * Size must be at least 2 to hold current position and one PC.
-		 * Later we allocate size * sizeof(unsigned long) memory,
-		 * that must not overflow.
-		 */
-		size = arg;
-		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
-			return -EINVAL;
-		kcov->size = size;
-		kcov->mode = KCOV_MODE_INIT;
-		return 0;
 	case KCOV_ENABLE:
 		/*
 		 * Enable coverage for the current task.
@@ -685,6 +666,43 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 	}
 }
 
+static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
+			     unsigned long arg)
+{
+	unsigned long size, flags;
+	int res;
+
+	switch (cmd) {
+	case KCOV_INIT_TRACE:
+		/*
+		 * Enable kcov in trace mode and setup buffer size.
+		 * Must happen before anything else.
+		 */
+		if (kcov->mode != KCOV_MODE_DISABLED)
+			return -EBUSY;
+		/*
+		 * Size must be at least 2 to hold current position and one PC.
+		 * Later we allocate size * sizeof(unsigned long) memory,
+		 * that must not overflow.
+		 */
+		size = arg;
+		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
+			return -EINVAL;
+		kcov->size = size;
+		kcov->mode = KCOV_MODE_INIT;
+		return 0;
+	default:
+		/*
+		 * All other commands can be fully executed under a spin lock, so we
+		 * obtain and release it here to simplify the code of kcov_ioctl_locked().
+		 */
+		spin_lock_irqsave(&kcov->lock, flags);
+		res = kcov_ioctl_locked(kcov, cmd, arg);
+		spin_unlock_irqrestore(&kcov->lock, flags);
+		return res;
+	}
+}
+
 static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 {
 	struct kcov *kcov;
@@ -692,7 +710,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	struct kcov_remote_arg *remote_arg = NULL;
 	unsigned int remote_num_handles;
 	unsigned long remote_arg_size;
-	unsigned long flags;
 
 	if (cmd == KCOV_REMOTE_ENABLE) {
 		if (get_user(remote_num_handles, (unsigned __user *)(arg +
@@ -713,10 +730,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	}
 
 	kcov = filep->private_data;
-	spin_lock_irqsave(&kcov->lock, flags);
-	res = kcov_ioctl_locked(kcov, cmd, arg);
-	spin_unlock_irqrestore(&kcov->lock, flags);
-
+	res = kcov_ioctl_unlocked(kcov, cmd, arg);
 	kfree(remote_arg);
 
 	return res;
-- 
2.34.1.307.g9b7440fafd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211221170348.1113266-2-nogikh%40google.com.
