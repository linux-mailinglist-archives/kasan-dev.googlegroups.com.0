Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBXNVXHXQKGQEK6TMJKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C0573116EEF
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 15:31:58 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id e124sf11826774ywc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 06:31:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575901917; cv=pass;
        d=google.com; s=arc-20160816;
        b=cE4QE1xw45KNAtDy+7/gmsT3Z/z4XasBYNlCQ0QoCXHAMBMJpxNRLHFxiQef/QnoeG
         xdn8N55N/tz+0v8EW5JIOx4lm2t+fH+Flhmr+eubuEOyGz3OuhS+2MLgF3j2hA6gzxE9
         MSvxI7Y5m3ryWbeWhYzI3ME82sN0vhJmhyjiPhEDy8hEHPUWw3rAlADm/8EEoCDDYhvG
         Lmp51WFe3uysM/TnYrolxURLqydFIY6rGN/MY4l7DFQjw+UCL7t/uNWkTuhOVkgjWLpJ
         +WfxUyhScfVwpnsuKwsF+XPTEHdjWR2HvmC9c8HLW0q3665DiMtR6clgsyZy6W3ghfCr
         XDEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5Bqz71Xbt9af6ctn1YTLlMTIpRlwlnd0TokPET9m62A=;
        b=yymJN4afHrk/zeZY7d74poB5iCgJMNhbg+gAwFAuxNISVlaxEYGD2slZDOsmV5/6o9
         leeCml5nn2EFYYpUhKp/3AxivcZEY++HXWQkzxhFQUdkmA5JU0KSIcL30AIvYJrkhtvm
         3+xRMUJTknvlx8uj+/qIWlVJOvPpQ+DkK+RhRQxA556jAls0GGICsR5/KNzTebJ3ts2E
         4b5fO6ORbVvX6j7mikpyci1yAiJrZDrp3hFmkjJuptW0n2rUjCi+RWYuVDngLT9fSU6w
         DOsOKlwiUvFg7Ljc/gKJAyCpuoe6XvLlAIKB9aIm4yQRrgFnZ7nIy7Jg82UgUjK9I5sa
         2cQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c7JyKFkn;
       spf=pass (google.com: domain of 33fruxqukcuemdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=33FruXQUKCUEmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Bqz71Xbt9af6ctn1YTLlMTIpRlwlnd0TokPET9m62A=;
        b=FQWEp2bmWBpJbkjqQMV7ZijOhC/qefLDDw8ZnV0Av44tFlAWkJXDE0IqRqwoDJ9op3
         PjY4HG3PsbzMQE9XVNj44/7HHEI3LbuccjZGD4X0BdMkKxP2RT4FYgPldXKEwKOlgYC5
         nuTQCgCr51pv0WLYC4Pg/XkLPVVgLdOaQh8qBwu+DoNUsrlYbQalF7Hbg5Ee4RATliJ0
         YmKeuBBOG0TvoY2A63/4WftynL7eEdTcxNWFIEaRzXvSDgzwEPwMDlapIAjtm0yASJo6
         7UK5NwuaCaK33KAO4DCUCwa03z4Z4lsNd/dvVDpWMjatjjmKOhfMQcTNR2X33H4tXhVq
         Astg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Bqz71Xbt9af6ctn1YTLlMTIpRlwlnd0TokPET9m62A=;
        b=KRwtT72P7pOvpQ9UD2WCQa3FWWpIv1tlqsvhnISPNgEZvxdU/XpdGVI3zANi7Y64aJ
         bVpoKHdUKNIgAT4TlVtmE1k6y38Sw5DpLKlhXckQB+E3sdMrL1/ZLfQCs1AZf2VpA025
         Kc01Dtjlq47eNE13UxhhMFMXBcpDWg17FOic4+Q1NXbyuvgNiKyoX10WjlY74iQymxqg
         5gY1tp6YDkE2z19x2MhW4i/NEcmLmsk1oruhO2j2rkdGbDRsAEQA5EJGLJHSPqVI3Cya
         4f1am8P9GyXKhIGo6lLHt+xKAmqBGCbj41tnnDSScvS6kAlrk2OaZs59KmjpHqSxyVEb
         oS2A==
X-Gm-Message-State: APjAAAX4mZxHnFqhdM3ePi3rRqDiDXKRyMgbvcZWD2+DdsHsPLDwX3hA
	Sik7eJr0BxaUAbwschOiV5k=
X-Google-Smtp-Source: APXvYqxqDIXG/4ya+Jk+yim/+wNydgneJDu0Vvqsl2cgvzebzf7yZpHqH6V/lcbXGeG0XPe+v2QgUQ==
X-Received: by 2002:a25:1087:: with SMTP id 129mr21198396ybq.399.1575901917689;
        Mon, 09 Dec 2019 06:31:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:59c6:: with SMTP id n189ls2013119ywb.2.gmail; Mon, 09
 Dec 2019 06:31:57 -0800 (PST)
X-Received: by 2002:a0d:d403:: with SMTP id w3mr19332797ywd.197.1575901917199;
        Mon, 09 Dec 2019 06:31:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575901917; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJ/KXrTPdscwn8Q2mKKwJYp9y/aS4/3fQC7eoH2y8UO3VWTDOEkIU4jPe0/nYkTUlU
         ACp+IsvdZfcs2XLwJd/Yz8Rlpk6fP0BmoyNdcnrwjOULkHUXwLVlWJLMOvbQjNq3j/NG
         9IsJ8E2cz7IDxj0OIQ41ltiFaCsLp9ogTNyj6qJELaAzh+AojposAqeriIB8pIaelz21
         EEhL80wb5BfmlVmK34eO+YXOlshrHWaq6mdAsyk5tkAkC9ZhCIKq1aJ8bICI+g2w0bX/
         FZxp8VGWeD1BKTG9b9w5lNRm8ngqtfcDGd80Mcq3m8YGhK/DK8cNFrn01dRqSQU08Ekv
         0h9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=g+A0f45IRCzFODlDzia7ir2GSqO4sEP6+0Dk2zsbcZc=;
        b=rG7VsH4mRftBLIttLvDoIk9FYh8LOlzkyvhdw8t7urKoNkavGP9ipoN9xO1JSgamtS
         Iils1buITos0SGBuRwpbrqcsr4n5Fg35tJNyZS0mQMujIwC+R9Mxi3UqECSMVZ41BbpK
         rBDtLOfMEkFm1HaRe10hnAWhFXarNGhpv8pDy95kjC6i0xz/wMrjXIhIRt5LLNoULbX/
         JhbEaxP7Nk+dRxyLgrMUxpbJE1bNy04hG5dXPEqqVvubmdJUFLMSFS9QzXDZ1gIp51mf
         Dkm1EQVKlcJWDqSzWUDVzIjSotj8uU2lwBse1IfJ1mrK87BaJi+SdRMa7RrL/woynqF2
         nR+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c7JyKFkn;
       spf=pass (google.com: domain of 33fruxqukcuemdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=33FruXQUKCUEmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id j7si1406423ybo.5.2019.12.09.06.31.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 06:31:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 33fruxqukcuemdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id u10so11728724ybm.4
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 06:31:57 -0800 (PST)
X-Received: by 2002:a5b:350:: with SMTP id q16mr19288549ybp.392.1575901916740;
 Mon, 09 Dec 2019 06:31:56 -0800 (PST)
Date: Mon,  9 Dec 2019 15:31:19 +0100
In-Reply-To: <20191209143120.60100-1-jannh@google.com>
Message-Id: <20191209143120.60100-3-jannh@google.com>
Mime-Version: 1.0
References: <20191209143120.60100-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.393.g34dc348eaf-goog
Subject: [PATCH v6 3/4] x86/dumpstack: Split out header line printing from __die()
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
 header.i=@google.com header.s=20161025 header.b=c7JyKFkn;       spf=pass
 (google.com: domain of 33fruxqukcuemdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=33FruXQUKCUEmdqqkjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--jannh.bounces.google.com;
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

Split __die() into __die_header() and __die_body(). This allows callers to
insert extra information below the header line that initiates the bug
report.

This can e.g. be used by __die() callers to allow KASAN to print additional
information below the header line of the bug report.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v3:
      new patch
    v4-v6:
      no changes

 arch/x86/include/asm/kdebug.h |  3 +++
 arch/x86/kernel/dumpstack.c   | 13 ++++++++++++-
 2 files changed, 15 insertions(+), 1 deletion(-)

diff --git a/arch/x86/include/asm/kdebug.h b/arch/x86/include/asm/kdebug.h
index 75f1e35e7c15..a0050fabce42 100644
--- a/arch/x86/include/asm/kdebug.h
+++ b/arch/x86/include/asm/kdebug.h
@@ -33,6 +33,9 @@ enum show_regs_mode {
 };
 
 extern void die(const char *, struct pt_regs *,long);
+extern void __die_header(const char *str, struct pt_regs *regs, long err);
+extern int __must_check __die_body(const char *str, struct pt_regs *regs,
+				   long err);
 extern int __must_check __die(const char *, struct pt_regs *, long);
 extern void show_stack_regs(struct pt_regs *regs);
 extern void __show_regs(struct pt_regs *regs, enum show_regs_mode);
diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index e07424e19274..6436f3f5f803 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -365,7 +365,7 @@ void oops_end(unsigned long flags, struct pt_regs *regs, int signr)
 }
 NOKPROBE_SYMBOL(oops_end);
 
-int __die(const char *str, struct pt_regs *regs, long err)
+void __die_header(const char *str, struct pt_regs *regs, long err)
 {
 	const char *pr = "";
 
@@ -384,7 +384,11 @@ int __die(const char *str, struct pt_regs *regs, long err)
 	       IS_ENABLED(CONFIG_KASAN)   ? " KASAN"           : "",
 	       IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) ?
 	       (boot_cpu_has(X86_FEATURE_PTI) ? " PTI" : " NOPTI") : "");
+}
+NOKPROBE_SYMBOL(__die_header);
 
+int __die_body(const char *str, struct pt_regs *regs, long err)
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
-- 
2.24.0.393.g34dc348eaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191209143120.60100-3-jannh%40google.com.
