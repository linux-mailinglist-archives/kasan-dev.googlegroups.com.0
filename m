Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBSMX7TXAKGQEJJN467Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E63C410C0D0
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 00:50:34 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 109sf12771124otv.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 15:50:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574898633; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPi7m3UwBGa3ZVPN0QTo7eZlZZiyYCA8LDBTuVl9bQg635ANKBFEgURVwc06wW2sDY
         yrLYxFSPJIEw9K0BhqyKTa+Uc9+CGH0Jh49+HQp/QL4bJn8CqngyFA/Jn1RMkngELURZ
         wRXfGLUEWWNBT2l/Hlkg29Yo1hn8Q0hjG5RO8QxIRDD8LlfpFYwh6ZbYIU62fvPtSJir
         ZK4bfo4jWfaoVi74nWBNhq7U59+3GeFaKYuihWdSBjTP4l4y7ZkZDHnmf/m53vGDgb0s
         +opbWZA2EnWz9YcfKo0XZp7/rh2XXYHGvU3CFxFKe/lepS9hInR7jxO0o7gUZ1kGm7VL
         5MNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OuSznPpXL2YtDvdvCmGu8LdQnO24l23Y9R4vY+Evo5I=;
        b=OMvJu0UbOoS7DjFr5S2XJejdQMUl+eGRsQMp16pYIyyPJcJ1ZrvWEGXtmZdjYVcz/c
         Kzcq5sOUyohHAdv++eO8no9WzC24yAu3QK1Xa2wQ4hPXUd0htG7TltJgOgAQLCWKmhwY
         dvuiTE0RzVAFEU+1J1RfSX/UnqUq/GUPd/knrLuCD1f7MGfCU507vQmYIrPGGE+KhXYT
         STyvw+kSEpf5slee5NQauR8oKWzclmxF7Wwy41ubn/2OGiBSC4ggM9ejUV+slOsn+R81
         wfsfCWQ9bLTkTy8JLIHpVoRk77ivD7HHdMhC2uqscygvZbn1FcKI7if+ZFU2tTsOjYQE
         9XDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XTj0qLai;
       spf=pass (google.com: domain of 3yavfxqukcve2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3yAvfXQUKCVE2t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuSznPpXL2YtDvdvCmGu8LdQnO24l23Y9R4vY+Evo5I=;
        b=df4N1yrd7YQJJ5PEatRJXuWr8szCYBDLsNk3sklGZZzGd7mRXSs7ycbDxNYcq9p3A2
         U5Tbq1eCwRGcsa+mC5OVhQxCwmclqico/RkDx/oiAXg/9tgpZb9/s1f0m2j5n29/yypO
         HAxxtcmECw+j4vy3R0hRfi6mwAG84R1qvSeMc5aZN09zhFLq7xUvmCWO2FnIMzStNxPO
         G+crXLjhqDt/Xz2WWAiEGaHkoTInjX5Ucm14e4MBCqdXZbyR24n8eSUy+DBcrolTrZG2
         diVp776zOCZ3H2SY+KSK3UnCNdYF99uroNOfm7xeehGFvd1BrlQ6LWVhLkh6uToCcwic
         7JEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuSznPpXL2YtDvdvCmGu8LdQnO24l23Y9R4vY+Evo5I=;
        b=rGLC8WZV1BJR8EY++Erpw/e13dvMIHWjbiwITPMViiSG5IeRsWzR70vtmz24yu8WFB
         YDB0eDqsKeGov7U/a/4etR7xkKB7eb+rLD0WYnT/3zmilvT7+l70n3irhqTnZA2xWfCA
         XzYaDZBescMIi9Y+mQ+A52V2xTCiXC6tij12V5eu3jkL32oWMv10wH/SHWksWPuRRgAw
         oB0IQXtB59e2gD8vopAtAZvP5uslYD+u9fKl+Yb7FZGIivrSoYA3bArKWveRbEQuk8C8
         LydcwfqHa7kbRg6eISHmmd67QfCiMEvxwV10QSYZpWRUxNSXUEXnmXBnguSRWkVIfP0t
         n9Ag==
X-Gm-Message-State: APjAAAWIwdjHm+dUkC9004jLhonzN/DLPiXALmD3mvoJMX0NMzTNz3Pk
	CQ3q3yYCxnS6vqE8DGBsQvE=
X-Google-Smtp-Source: APXvYqyD3N92mcVb++0SbSdfaCuweXLtp8aTJnMtdzXVJXJMbC8XQhuRsfNF1JnmdNZYlix9+XYQEQ==
X-Received: by 2002:a05:6830:14d2:: with SMTP id t18mr5271129otq.349.1574898633465;
        Wed, 27 Nov 2019 15:50:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7085:: with SMTP id l5ls3887644otj.11.gmail; Wed, 27 Nov
 2019 15:50:33 -0800 (PST)
X-Received: by 2002:a9d:7854:: with SMTP id c20mr5725068otm.79.1574898633035;
        Wed, 27 Nov 2019 15:50:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574898633; cv=none;
        d=google.com; s=arc-20160816;
        b=GLoPDnFsDNx5hq8q1BjtaQ0wYNhI9ZAz5iukew/2wOs6YVoII0jghkjOlmT9J8B37t
         rczMhMspmfpAnfj4X6ZLhZuLvQ4zWsJnonmzOKHkJ5TPhALU9tmSgbCYE0nZIcXEoX5o
         yxMLw9Hzi7lmeY06KOJAdPxzF9J6Py3fG1WNsRPFXAGgj8SshZ0qaHxdaOrdtzaTv9hH
         75W7E4ntSQ6UAZ3BnzFq5bcYIxXk81Mq4LI8hY7LNoXNya2YIqXnGt9fcJ50KMg/wOoy
         kEwVxYEa2An+eky6HED1FlPzJ+t6nmKeNlhuniu/WE6FhOg8z8+chbT0us+/i955wZ7l
         2hzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=K4LUBLgA9sviisQdtAyBRSaHeHi+ait99CAeemp5RxI=;
        b=N/aXad8AzJyi1fsFs2uYOz3OqI0pM3zlH1H0/s+nxu5pOmqP8cxNysYRMh9gCiVjly
         z0h5Mq6sOxA2sgnR3gvI5QHwBoCeUx03T//Kvx6SsVDFCd06/nTxmQR4zS8knZf6JmRi
         UpbDQF7rE8Y/YvZFvqRNChfgydrHRxR8/8DqfbLrt8l84aQOrJjTx9xmDix3e4M3aaXQ
         4B8mx9C2+t443VVdoAPhPBvrg3QkXw2jnszexp75eYIBvWPthFPlXbjXhjbFoEnDfwdc
         yNySxukWX/CdHug+eRzUGKoo6dpPme6WjRu3utEV4jF4Zeof7/MDnse/63YowNioXNbG
         76yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XTj0qLai;
       spf=pass (google.com: domain of 3yavfxqukcve2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3yAvfXQUKCVE2t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id r23si592521oth.4.2019.11.27.15.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 15:50:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yavfxqukcve2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id e23so10710437qka.23
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 15:50:33 -0800 (PST)
X-Received: by 2002:a05:620a:a1a:: with SMTP id i26mr4001256qka.383.1574898632384;
 Wed, 27 Nov 2019 15:50:32 -0800 (PST)
Date: Thu, 28 Nov 2019 00:49:15 +0100
In-Reply-To: <20191127234916.31175-1-jannh@google.com>
Message-Id: <20191127234916.31175-3-jannh@google.com>
Mime-Version: 1.0
References: <20191127234916.31175-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v5 3/4] x86/dumpstack: Split out header line printing from __die()
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
 header.i=@google.com header.s=20161025 header.b=XTj0qLai;       spf=pass
 (google.com: domain of 3yavfxqukcve2t660z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3yAvfXQUKCVE2t660z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jannh.bounces.google.com;
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
    I think that it's nicer to have KASAN's notes about the
    bug below the first oops line from the kernel.
    This also means that tools that work with kernel oops
    reports can just trigger on the "general protection fault"
    line with the die counter and so on, and just include the
    text from on there, and the KASAN message will automatically
    be included.
    But if you think that the code looks too ugly, I'd be
    happy to change that back and drop this patch from the
    series.
    
    v3:
      new patch
    v4-v5:
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
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191127234916.31175-3-jannh%40google.com.
