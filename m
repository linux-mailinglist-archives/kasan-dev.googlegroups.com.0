Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPVO2TXAKGQEB6ITYSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 585EC1037AC
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 11:36:46 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id t11sf10889385edc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:36:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574246206; cv=pass;
        d=google.com; s=arc-20160816;
        b=gqZgpNoYe4lt3ssdRJNxHXCRE9XUTAg1dggjg+8MC7dJCXt6Tp++rBBzitVc8839BR
         epi4xDy0qUie4L3uZ/waSaoBry9mfrB0xy3nBH1rtAYEJ77RhzovD9gD8F79zy7lHNZe
         1IszvV4lWCuiAkkgMKBMlzlCHRQVQjTGEFuX2qwH8YjudyyfuF4rKP70h6SpGbDHnmrx
         oO4Oag/tamkDXv/gfvNfLXk023Hf5bKPUpFyvZ8/u8YhW0doIPcaUMyVR7fg5tBM4Ade
         S0NUki0v//fHNj6eNcU5ARrcmKDF4u1JfSTzP34NR0ZZ+31cjGAXhLVAS6zHeSNtM77v
         XxyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=cq4wWS9LUe9vLkmNKmfGKFqAourjZWX1lFfS54yFo7Y=;
        b=N2gjyObpLIGT10VsbfKrrzDCzTdGqFJOraGXZYDPzG/KT/99oHTzzVnrgcxCKgVJ/k
         jA9iVxuYuVGKYJ5ypYDuCOJgpDs54YeEYu430Mn3BRwsjF0FA1pw64x2fWC6nvw+2E67
         bruc5hDoEmjPYaafB9SpGrxv8jVBl/F2q4qn9WBWWkIbzhYtx6flWrVoUGZmMLkjhR3H
         mGyTYJPrlBNEBp/yYQTHwICwy0SwWM9xYNfa7fBuEd/6WZ0ZP/4Jw5MR9TI9+FrxSDqj
         oLOGAhH1tf3en2D/YhAq8GvwJF52jxW/HoLCtoaNrYj3mxEX5a+ifO/oYZiIn3l4I+l8
         X2hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tui1Nt4v;
       spf=pass (google.com: domain of 3prfvxqukcbqduhhbaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3PRfVXQUKCbQdUhhbaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cq4wWS9LUe9vLkmNKmfGKFqAourjZWX1lFfS54yFo7Y=;
        b=JUbLoTyVm1TSFRILoxZbZoxNi6MbRPz9ng9cL75fyOOTVBQc9CU0ii3kXKcAmUWlXX
         zLKStDClFOHBpubv/vDf9eOaoVIrDJT/QBb6hugpGVxCuDihAg2L5pHcX+oolEptWM9L
         TJQ7WXBLKd9BjCqVIaho5PQl2cfZNDAlUCdNhN+HU+4T6CaYU32r8ZUkv1XdgCC5E0hs
         bqdR0CGLDt58W4gfV09THJoo85Fz0VULqvKLtkywdnfuId7TON5mqZx/MlSOUPPu5myN
         XMwRbsTwJTd6ZB5Sv4MJ7R9/naBCCyRMXkAGN0rYV98e+xR6w6fHqbRXN/7JzjtM2FBR
         c0SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cq4wWS9LUe9vLkmNKmfGKFqAourjZWX1lFfS54yFo7Y=;
        b=DPH7WOq4dCeWlQLyMBHXuXjK6eIlk2bKBcI/R6E6pW5KXWSbXpUNBQt19WuVQ7mnMV
         8/46aWMKecBhD09eyW9cA6m5Rz3AFbS2UsurWy4w4ua5NqzN03fYZa5XdnmP2qybYjZs
         WhsCInSkabyT/7HxP9WX9c8SAoYhuJqs9K614PO70oW1VjV2UVkH1L4ryLrGxVznWmbT
         UpDr7drJ8zFiGV9UMevAGcqKHVR1+8CfeW9Nk3sCK3I8XWX/IWrhEl6HRJIjJEQ+GRgl
         RvMaKjp1HvrT+k+lxANjfwTCFsxUnTuTgNcOuE9ess99H1FQav7NPttG2x8MkvvfivKq
         t0Hw==
X-Gm-Message-State: APjAAAVWT1wpgUqn85l99jtacA4RiNXZIvQq0UjTg+WSVHUpi4uOioY2
	QoTeFiFNOGJyP9/qYgAH1xw=
X-Google-Smtp-Source: APXvYqyH6XA4H8PNO3zHQHTjCCgeHNcbpFKMTrST2ZlnCaOLIUKRHA9XFnFcLxuBWc+kRE/ltZkOyQ==
X-Received: by 2002:a17:906:11cd:: with SMTP id o13mr4407192eja.272.1574246206067;
        Wed, 20 Nov 2019 02:36:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:590b:: with SMTP id h11ls899939ejq.10.gmail; Wed, 20
 Nov 2019 02:36:45 -0800 (PST)
X-Received: by 2002:a17:906:245b:: with SMTP id a27mr4585085ejb.192.1574246205631;
        Wed, 20 Nov 2019 02:36:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574246205; cv=none;
        d=google.com; s=arc-20160816;
        b=QXm+C0tOzIZQrHuOyoeCmaB8oMTqnESXWq4KO19pa7nTv0Y/PUAd9CJkngO5qNCOwk
         Rxxf4j1NuMXccA4QjYbA0QqzIpstZfsmV8IEym5Ka/YitxTg96COmJ9pNhV6UA549HOK
         dnaqY9Fo/Wmzoj/oTl4M+f31ciXPskg65jWECR1U6CygTa3jwCohrxkmn+UWw+np0V2I
         RQqj0qt+6BhQcM2elaWf3umq4AiLzv6kKHzDCpAOsuc/ct6IYNMX6uwfB1M1Mjh+ZWxK
         EmgTPWU38rluyJcfYKZU132ZYQIbmt52ltNbNNwam8ChDxYYKMBWecDpYGCj9rQtlSLJ
         Vo4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3jcoEPgiQXFa9z4hbTeIhzthfQEzp6tYNwxRvoMQSWM=;
        b=t4GJEqqhXE85ROejZYmnoAByyozTq30+eS4YX9H7nhw319XNM8I1GPWqTdBQHlkG55
         kV/hAtLE7/nUEQ1qhNRk/czF3WqmIdiC4HYwaHMjVVc/yO+1Y99t3FO/bB896noJlyJy
         PQwXEDQ+0rvBE0KB516/665GWHcBbWBwqSJ3mlcQqqTio8L1jDyOCfp2qFkLj+DhCTW4
         uuE7eUCiriptONWGCgV42XbeQunzaWT2tYGAmiad2A9vRu5k9DbKti37wrVV3XD8H0+A
         Zekuq/z++O/1rVE03EUV06eHl/ao5KkKL8D/Q3U7L36/YY+9KjjUeeuuKd01vMx6ZwCV
         Oplg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tui1Nt4v;
       spf=pass (google.com: domain of 3prfvxqukcbqduhhbaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3PRfVXQUKCbQdUhhbaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id x16si172781eds.5.2019.11.20.02.36.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 02:36:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3prfvxqukcbqduhhbaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id g13so2702645wme.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 02:36:45 -0800 (PST)
X-Received: by 2002:a5d:5227:: with SMTP id i7mr2305287wra.277.1574246205243;
 Wed, 20 Nov 2019 02:36:45 -0800 (PST)
Date: Wed, 20 Nov 2019 11:36:12 +0100
In-Reply-To: <20191120103613.63563-1-jannh@google.com>
Message-Id: <20191120103613.63563-3-jannh@google.com>
Mime-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 3/4] x86/dumpstack: Split out header line printing from __die()
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tui1Nt4v;       spf=pass
 (google.com: domain of 3prfvxqukcbqduhhbaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3PRfVXQUKCbQdUhhbaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--jannh.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120103613.63563-3-jannh%40google.com.
