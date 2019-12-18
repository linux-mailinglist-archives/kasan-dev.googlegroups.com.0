Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBUHE5LXQKGQELH4HLZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD0D12577A
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 00:12:16 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id t3sf796415wrm.23
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 15:12:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576710736; cv=pass;
        d=google.com; s=arc-20160816;
        b=I1ataDQMP3MA5vQfuL3/MpGUDSbGMqImrXyMXT4DzflZv1+xbJZ8pgbXShhZLw22WI
         UqtadUK/AjP2biNiv76HGZ9JUDGlJn2nINR1goISx2atNTPCrgc4tRf1im+ZXzaMOVWY
         9g1NVKAwWFTQjljYYWOpZ//1Rl/QAoWf9S57jJ7jdztZzm5138QYhqr0UlXD84HI8rQn
         Jk1LmPITrrncrFY3gF9Ryn35jhm8N7VSxsyaA54xcN0XXvh4tU0WLiA0XC/JtahPPSjk
         /llfDqsV7CXw2CgLDmm7Kdn7pJVji1eOuaPOJNHNTZ+IW6+RWqL4fZ1PpzDObc7fMc0T
         Wzug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=LXB7z38F3oZ5NS/7iSnqHUha13t7VjsOtCX0kgdsfHc=;
        b=B27TtlZqFJPS+xyLQ+M6jEQhxo5/wzekjCKIhvLefFByyZfjNk0zQZrNnyfW5pXhDs
         QxiiFXevlSuCDpBaS3IaD7y5sJ5p/Sd17oxjml7U+A01RFSJqbIwNNjtHiJ+B9H9QRIa
         50Arfu8XsDUfOE5nrkWPGWHe+TXtmm0HWPEX0D5j08sD/N3+hwKu/PoZLMbbDlH8rAgW
         PZuoNC/0hCfHTq0L3S1fWr9cjdBVraZ6+cCXdSYiu/TPScS2rN/6/pbB/H1tXHaB1E2W
         2ICidVUhnKn98635ozrCQ6nIjRa396sL6W9NSIJ9ogbO9LjEj6qc6mHJN4jphCd4uPaj
         a09w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cvPGswJD;
       spf=pass (google.com: domain of 3t7l6xqukczq7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3T7L6XQUKCZQ7yBB54CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LXB7z38F3oZ5NS/7iSnqHUha13t7VjsOtCX0kgdsfHc=;
        b=E9Kj0GHQF7BSLBHZTQ1ROfYHiZj8+5RHTVRXtlwi2r9Jz77ODofqqICVKn0kGTAucx
         wNiVXkjGivcG6ae7oy689ePfLal5X4B/k6MYSwaVplmYpU/IdClTxFH1KKoHrStJAz5p
         BLyjzSvGScQuYG3YYZsQgw5/WrDFFIPnWdc/mGwIj8AyM8MNMwNXZHpJKJM/0pkGqHBw
         enmXoQES2H7rFerSOZQwlwhQie/VJjbkWwL9ehJnM3r2Miv0RTCweKZupKWA63pdJMwg
         TI+0K7BFgsalukb2eB8hZZgYdo17Hpr1brvNToVD890snuc5YOR7PBxrh7dIG7iH/dGd
         +URw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LXB7z38F3oZ5NS/7iSnqHUha13t7VjsOtCX0kgdsfHc=;
        b=a/2BWE0a8ij7ba1BVoj7M7h7/oh3yksTyUs0t6p6yka2mqC0QHgbFJqB6sjtCZPs0i
         7wvywldoqMm29Div6t67QlDN1bCasaRt4xcwf9vDv/5CuPxsa1h2kCoLLFQFUByWlm36
         crRnjLBxulucLIYw/awkv3hP8BfFeBygl3Y1ab7urm1bb9jSLlbfb6SLa9U0gHYscZ3l
         FR4xVytAIeyPZ0SiRucOltpiEzrtSUTm8cagRJ6Nkjupo8zhCgCqv+MnDEWtqjPwdLyJ
         mGS1iqrWF52Hz28k4WLTvIOPvOlJ60gvohl8Afal0XfKbDSH60zg2nAIkt3AmI9aD/ob
         +S4A==
X-Gm-Message-State: APjAAAX9QBpBJB7sA+cYouTQIE3foGnj9qQXFgkeUV+sEbn1V+/dUQ2S
	YQTBxlhSKiiWEfuzrKA1KZc=
X-Google-Smtp-Source: APXvYqx8coCq6KYml0pFsoHVhNktO75R1w9edrsJS1G/2g8jO695P/0bxoiEDzIuVBEQ3QrK2DQSsw==
X-Received: by 2002:a1c:1d16:: with SMTP id d22mr6336195wmd.158.1576710736325;
        Wed, 18 Dec 2019 15:12:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6385:: with SMTP id x127ls1190986wmb.2.gmail; Wed, 18
 Dec 2019 15:12:15 -0800 (PST)
X-Received: by 2002:a7b:ca4b:: with SMTP id m11mr6224381wml.164.1576710735805;
        Wed, 18 Dec 2019 15:12:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576710735; cv=none;
        d=google.com; s=arc-20160816;
        b=ltzIGvF8ihLGnvgmaWQzIbdNm8HhK2lDLTQ6BYNnW/n9g4SCBF/9y22imXlX9MpnVO
         6yha73vjQ6FNqjLAS2TTrxHrT2YwZoEpcLEYXJew33Y6lMv8U4OZGbY8PTKFfrQLk0Lt
         2FSG51hSDAH9WpkEAJhzpF6QmUyAq/DSDaFCfhAb7QWOTwBFF6iVdMO9oLG38iqvnCA9
         vm5EruCDWGQPnjz3jcD39JlwN8bOck6YiCBr+CMPeETiIcnhek7dFebxlhAGfQnmQIbo
         CrzVPfjl+bx6CdIGOQ12PTJEvR9dIyEnpnFhh+Q1gMAM6V1lBLMGRmVyZLpWAyci0/4X
         QtCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=O7cRpxVyt8uxMLcyDyuXxaiEb45NcHrYdQjrFEEd8is=;
        b=UxMVJl94NYYYXCNHfXhbGeGbCs/TQ0jT9eIcNDHeR/R6Yu2uxnNn2t8U6NQy78aaf5
         K1Hjz5+2UDfFQzrBst390KoP3Z2vS6YKHFQ0EOeWqenMvVzga6LwqOzmlehZ2xsSbj0X
         la2LFdQHl+Z4k9C/lZrW6LnQGqciO2Rreo7uIqCRm4enoCWy/wi98zbL1WJRb43YQbA1
         pqyoXiy4Z4dfaOdeIp7xHi60ck9IKean/xm91dP/87JLQe2NV030GX9UAQC4Q8mzp6bB
         fHuAKEtrQMMQSN+/eDEuq0wYB/ugZhEBB2cwvoJqt8YrIOt/q4xZqxKiXCZXINilc1zN
         jNDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cvPGswJD;
       spf=pass (google.com: domain of 3t7l6xqukczq7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3T7L6XQUKCZQ7yBB54CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u9si203237wri.3.2019.12.18.15.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 15:12:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3t7l6xqukczq7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j13so1491628wrr.20
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 15:12:15 -0800 (PST)
X-Received: by 2002:adf:81c2:: with SMTP id 60mr5454204wra.8.1576710735282;
 Wed, 18 Dec 2019 15:12:15 -0800 (PST)
Date: Thu, 19 Dec 2019 00:11:49 +0100
In-Reply-To: <20191218231150.12139-1-jannh@google.com>
Message-Id: <20191218231150.12139-3-jannh@google.com>
Mime-Version: 1.0
References: <20191218231150.12139-1-jannh@google.com>
X-Mailer: git-send-email 2.24.1.735.g03f4e72817-goog
Subject: [PATCH v7 3/4] x86/dumpstack: Introduce die_addr() for die() with #GP
 fault address
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cvPGswJD;       spf=pass
 (google.com: domain of 3t7l6xqukczq7ybb54cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3T7L6XQUKCZQ7yBB54CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Split __die() into __die_header() and __die_body(). This allows inserting
extra information below the header line that initiates the bug report.

Introduce a new function die_addr() that behaves like die(), but is for
faults only and uses __die_header()+__die_body() so that a future commit
can print extra information after the header line.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v3:
      new patch
    v4-v6:
      no changes
    v7:
     - introduce die_addr() instead of open-coding __die_header()
       and __die_body() calls in traps.c (Borislav)
     - make __die_header() and __die_body() static
     - rewrite commit message

 arch/x86/include/asm/kdebug.h |  1 +
 arch/x86/kernel/dumpstack.c   | 24 +++++++++++++++++++++++-
 arch/x86/kernel/traps.c       |  5 ++++-
 3 files changed, 28 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kdebug.h b/arch/x86/include/asm/kdebug.h
index 75f1e35e7c15..247ab14c6309 100644
--- a/arch/x86/include/asm/kdebug.h
+++ b/arch/x86/include/asm/kdebug.h
@@ -33,6 +33,7 @@ enum show_regs_mode {
 };
 
 extern void die(const char *, struct pt_regs *,long);
+void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr);
 extern int __must_check __die(const char *, struct pt_regs *, long);
 extern void show_stack_regs(struct pt_regs *regs);
 extern void __show_regs(struct pt_regs *regs, enum show_regs_mode);
diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index e07424e19274..8995bf10c97c 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -365,7 +365,7 @@ void oops_end(unsigned long flags, struct pt_regs *regs, int signr)
 }
 NOKPROBE_SYMBOL(oops_end);
 
-int __die(const char *str, struct pt_regs *regs, long err)
+static void __die_header(const char *str, struct pt_regs *regs, long err)
 {
 	const char *pr = "";
 
@@ -384,7 +384,11 @@ int __die(const char *str, struct pt_regs *regs, long err)
 	       IS_ENABLED(CONFIG_KASAN)   ? " KASAN"           : "",
 	       IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) ?
 	       (boot_cpu_has(X86_FEATURE_PTI) ? " PTI" : " NOPTI") : "");
+}
+NOKPROBE_SYMBOL(__die_header);
 
+static int __die_body(const char *str, struct pt_regs *regs, long err)
+{
 	show_regs(regs);
 	print_modules();
 
@@ -394,6 +398,13 @@ int __die(const char *str, struct pt_regs *regs, long err)
 
 	return 0;
 }
+NOKPROBE_SYMBOL(__die_body);
+
+int __die(const char *str, struct pt_regs *regs, long err)
+{
+	__die_header(str, regs, err);
+	return __die_body(str, regs, err);
+}
 NOKPROBE_SYMBOL(__die);
 
 /*
@@ -410,6 +421,17 @@ void die(const char *str, struct pt_regs *regs, long err)
 	oops_end(flags, regs, sig);
 }
 
+void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr)
+{
+	unsigned long flags = oops_begin();
+	int sig = SIGSEGV;
+
+	__die_header(str, regs, err);
+	if (__die_body(str, regs, err))
+		sig = 0;
+	oops_end(flags, regs, sig);
+}
+
 void show_regs(struct pt_regs *regs)
 {
 	show_regs_print_info(KERN_DEFAULT);
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index c8b4ae6aed5b..4c691bb9e0d9 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -621,7 +621,10 @@ do_general_protection(struct pt_regs *regs, long error_code)
 				 "maybe for address",
 				 gp_addr);
 
-		die(desc, regs, error_code);
+		if (hint != GP_NON_CANONICAL)
+			gp_addr = 0;
+
+		die_addr(desc, regs, error_code, gp_addr);
 		return;
 	}
 
-- 
2.24.1.735.g03f4e72817-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191218231150.12139-3-jannh%40google.com.
