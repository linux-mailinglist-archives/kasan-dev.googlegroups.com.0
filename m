Return-Path: <kasan-dev+bncBAABBTPZTO2QMGQE2CO5P7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E3F793EB1B
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 04:22:08 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2ef311ad4bcsf31381381fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 19:22:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722219727; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlxvu24+a5yuWHpQoXAD/5I5m8GkDFscKCR2yUFpeqkV/CvxUbXYxTlb82Aulvodec
         lnagrZwjBkhX/NSqD3qrRUkxnCGcJ1i9S0TnSL3eD4xttrKQccVw62nBQmotaEFRyQTo
         Pl3s6UXx3S0yhqxtN/bh6sdQfSw9H9Cs6kQ0Y7U82S+6aIpORPe8e2sF7uP5+vpgovon
         mWWHreVIXTCYvNvT1yBRXfKQhpNCIU3DSAIjDON8nfuYJlyDKqJEPZxUA7C+cDuuw+Au
         /wEKUDMiPZV5MwsO/DZ7j/KPksjdWqZVLc9oYVJcYrBSZhEFzqQMx0idJuqxULH3VGf0
         h2ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fGZ7UlKwSAfyH9ehDMCaS8lmgdVQpVwX6ge/p2l96v4=;
        fh=k36tlb+eI89ou7e5ATS3L5sh3InainnmdazNFPmCSRM=;
        b=QMSWLnEmsxRA0nXBiHiIKmY1CYh+50m84O5dtGP8DAVRU6BQwNbUO0K0dA6H01YwkF
         Rx6dPjR0JyqTH3MQCMTiBU4TpbboPFct9bjetbLCil+hZVw5w5YqX4H+RzIXgOIgRMvq
         Ha9X3Q4bz5qCxDk3b5jnozwcG8Jzj0E3q9fE/PIHSCHMRDb20j1JjQp9ARyJAFs0oTCU
         qmMzi+bvU/LGLjPtJnnNYhN0pJn1O1j2kxbvgRID08d1JvMgx5ckU7S8gEzxqMDgg+4h
         bKFhF+P8sXTuaRgAJlJAl6RA71SVRl3XetEM+VZEAMNp1KLr7vNERB8BQqJ68MclW9y1
         ggiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=htsvdPzt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722219727; x=1722824527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fGZ7UlKwSAfyH9ehDMCaS8lmgdVQpVwX6ge/p2l96v4=;
        b=tHcvsLUIdgynXZPTurT0/OfhtdUjR0f9/jxEb8F5CVeHrug+f26LO4k86oOUD3KyMs
         laAlyuZ6Qo2xaE4BbNuqWOqHHuV5KEdVcSCVdZgkDOfdjQWJ5S/2xWdMZ7R4ezR2yGbG
         Y9ML7ZQ4PPSYTnrRIViSlLhABJyc+K84HOEB+CAqh1RZ8iK7yrApcYp02dZ+NSRD7LhE
         TWsIvYx37/hyBoCVsicC475/251l/tEkc4LFwD4r0N4maJoUmgE/xNWvkUzfI/Sk+f1Y
         AsLRMlvqpPYYtw2jZz6lTuUigwuq4cTT8o4zMZndDuS/wb8Xllps3M6zTw8dhCZbr6yT
         0fJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722219727; x=1722824527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fGZ7UlKwSAfyH9ehDMCaS8lmgdVQpVwX6ge/p2l96v4=;
        b=WrzJfzDNoDbQSnFHqH/9itu32TehkGeZfEDx5SqKaLYSSzk9LhW6aHOMwK4MIRYnt7
         co2MOMMu/WKsA+a/L/I50GXtXMtpRtvh0idC9FI/hRmumBO7PaLqwC1sRqj8lK5Y9X62
         yhqxP9L35k6KYGqP6iMZG8M/dDl7YXmAUp7Bb4R9dJyWvVXW1EV9VeeiPBpLseUoNsKM
         i+Dk8K0sV37lpju78u26qO9seDldWsadDSVMLSjmE5nfVuIR9Hm9RrM/rNtBgSrauFPN
         +Rq9gTM0wWdQYtXEm5tPXzEpJXF2Yc/nS7HVhyWM/ujshZgjDaAkwceQiNkO8NOELBBJ
         gRYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeBansx8jGm0ISTs6OhAwVPiQxvQbIWudJZC6GNdSse8MOzewUhwUdHowGSXAo1SjzgOUSWARDuwYCIjkv/8r74hUliqzlNw==
X-Gm-Message-State: AOJu0Yx/hMsYSO3r8hAeChuHSxeQ96EIo3wHT3eFr5a07uo31+BusAtw
	ExB26GcNnMkG27KvNBTc927nAo9m3lbXDKRoXaFST6ebzLuqQGS9
X-Google-Smtp-Source: AGHT+IGO6hrUFCLouZUQAT/t1e/KeVcUNDWPGtbErF/5aUcXBr1GjnEQ994Cf7DTYu13eaodNn9TWA==
X-Received: by 2002:a2e:88d9:0:b0:2ef:2c4b:b799 with SMTP id 38308e7fff4ca-2f12ee1b0d9mr38316101fa.28.1722219726076;
        Sun, 28 Jul 2024 19:22:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4015:b0:599:9c73:c397 with SMTP id
 4fb4d7f45d1cf-5ac0d2d997els1952932a12.2.-pod-prod-09-eu; Sun, 28 Jul 2024
 19:22:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXy89co4cjFyMdhlx/beE/ID9RMhA1h7cazFQyxtcfyHA2HT2WsBNwjUwrQNdDbGNvND5V0DHUYUia9Rtd7erQTb+e9+7JPAae3Iw==
X-Received: by 2002:a05:6402:2553:b0:5a1:32d1:91a6 with SMTP id 4fb4d7f45d1cf-5b021190442mr4460916a12.22.1722219724330;
        Sun, 28 Jul 2024 19:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722219724; cv=none;
        d=google.com; s=arc-20160816;
        b=djOfMvrtqhckGKGVbkUUJ8crVH5OQfbgGkFoSN5Dy/uFb1mD9e08PaaE6zH2Ef/ljF
         8xt8llBdQipkS1wMEHpIAUwAGVhBHtj/nZckHLXtiu+J9XADi16l3jc17QlNNJdgWWws
         shglow56putXIhQG7S4kzeMgBkfjP/ECC1AQF5/LWVfVEDjFiLts8LHqwrCJiJVhAGCB
         r16EXCJ0GME/EQ4HihF/9RPjOzL0ljf3m+6zcGzIVqlIEf6bmpDAIfV6EQZZF1cMBpxs
         yh2D7ztIaN4fdNDcL3lLaqEPQwTf/nGPyeLO67qaaNf/OGQvndUk0S3dWcmMEYGW9q3R
         FDjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LsRQ18TXosCV7Zr1JLjd4CYqcPz8tKyiBF4C+fLmLDs=;
        fh=WQYUdvapQMt7hY1FJvb7urbRwjRqqfFhsJxVQbUf9J8=;
        b=OYlKbuJg4lpUPuL/kvU6UvT7fK/WzuUET5N2jfTuDBlSq1HCPYJ+3qNd+8s7V3TpHO
         nw5PZJQkAN5RAaqUEuya8n65PAm9BoExtOLPJU3EP1WVtrQxlHgr+LNS8BQzQZ7KCcA1
         h7IFaytPMn8icdi1dQ3cz3952D8IILb3b8bNDQ0Awkmmwivd50UJSbnQvldP81Lf0XBC
         CjNh6dorW1KUybC0gaXQMXAQ1f/s+stD42FIwA+ZHi/PZJODD0CfukZGhz59nR20aeCl
         ac9r3OD7JheBQ1KnLGJt/33JD+1vwkOQQgPDU7ftFTEOWnVSu3wLFxAWDw8AS4fb/LtD
         ltWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=htsvdPzt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta1.migadu.com (out-188.mta1.migadu.com. [2001:41d0:203:375::bc])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5ac63b5639dsi230447a12.2.2024.07.28.19.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 28 Jul 2024 19:22:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::bc as permitted sender) client-ip=2001:41d0:203:375::bc;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Marcello Sylvester Bauer <sylv@sylv.io>,
	linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com,
	stable@vger.kernel.org
Subject: [PATCH] kcov: properly check for softirq context
Date: Mon, 29 Jul 2024 04:21:58 +0200
Message-Id: <20240729022158.92059-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=htsvdPzt;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::bc as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@gmail.com>

When collecting coverage from softirqs, KCOV uses in_serving_softirq() to
check whether the code is running in the softirq context. Unfortunately,
in_serving_softirq() is > 0 even when the code is running in the hardirq
or NMI context for hardirqs and NMIs that happened during a softirq.

As a result, if a softirq handler contains a remote coverage collection
section and a hardirq with another remote coverage collection section
happens during handling the softirq, KCOV incorrectly detects a nested
softirq coverate collection section and prints a WARNING, as reported
by syzbot.

This issue was exposed by commit a7f3813e589f ("usb: gadget: dummy_hcd:
Switch to hrtimer transfer scheduler"), which switched dummy_hcd to using
hrtimer and made the timer's callback be executed in the hardirq context.

Change the related checks in KCOV to account for this behavior of
in_serving_softirq() and make KCOV ignore remote coverage collection
sections in the hardirq and NMI contexts.

This prevents the WARNING printed by syzbot but does not fix the inability
of KCOV to collect coverage from the __usb_hcd_giveback_urb when dummy_hcd
is in use (caused by a7f3813e589f); a separate patch is required for that.

Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=2388cdaeb6b10f0c13ac
Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")
Cc: stable@vger.kernel.org
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 kernel/kcov.c | 15 ++++++++++++---
 1 file changed, 12 insertions(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index f0a69d402066e..274b6b7c718de 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -161,6 +161,15 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
 	kmsan_unpoison_memory(&area->list, sizeof(area->list));
 }
 
+/*
+ * Unlike in_serving_softirq(), this function returns false when called during
+ * a hardirq or an NMI that happened in the softirq context.
+ */
+static inline bool in_softirq_really(void)
+{
+	return in_serving_softirq() && !in_hardirq() && !in_nmi();
+}
+
 static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
 {
 	unsigned int mode;
@@ -170,7 +179,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 * so we ignore code executed in interrupts, unless we are in a remote
 	 * coverage collection section in a softirq.
 	 */
-	if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
+	if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
 		return false;
 	mode = READ_ONCE(t->kcov_mode);
 	/*
@@ -849,7 +858,7 @@ void kcov_remote_start(u64 handle)
 
 	if (WARN_ON(!kcov_check_handle(handle, true, true, true)))
 		return;
-	if (!in_task() && !in_serving_softirq())
+	if (!in_task() && !in_softirq_really())
 		return;
 
 	local_lock_irqsave(&kcov_percpu_data.lock, flags);
@@ -991,7 +1000,7 @@ void kcov_remote_stop(void)
 	int sequence;
 	unsigned long flags;
 
-	if (!in_task() && !in_serving_softirq())
+	if (!in_task() && !in_softirq_really())
 		return;
 
 	local_lock_irqsave(&kcov_percpu_data.lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240729022158.92059-1-andrey.konovalov%40linux.dev.
