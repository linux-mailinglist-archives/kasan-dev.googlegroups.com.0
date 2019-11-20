Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBIXD2XXAKGQE2GTXJ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 94E681041A9
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 18:02:28 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id y22sf3744pjp.17
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:02:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574269347; cv=pass;
        d=google.com; s=arc-20160816;
        b=kMyyXzoHP4qbX4b25oavLIeTYAxbzWM5Ska4ewC9wRkST4JggGBDsXUMM5XKq3zffR
         oHLGOgQ6iKzZLYiW0x7HyCu8qkXQrArT089cbEF/HC+R11dWIEtjf3jObmBrTIz+9l/T
         QlAothDe7PwoYX5vu1PAt/+tNE9DYLWA8CH9XO+M6pWLROewMA4iwkZGhrz3eUvEuMz/
         FtXpdrX+cjW84Obpn5i/6f9/b9RA2eebW07qMrdzHPi0nclNAXZhYo/p509YMzfqJPfH
         xWrsqjpx5AdSO2P//QwcrI29uk5P6aTZZKJaekouTca7krljpznmshS6wRfgUicCc2uL
         FbwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OuHaLpfAoum6FOHcxSxcl3bWwVvAKu+E17yOxhmaXHs=;
        b=u6daOmJ6K5COWc8gZ3p1MnpHuusC5Q0g6oAICEL8ZiI9fn23be2q3xmF1MUE9hJTiI
         2rrOCw7Klfk3XeUbzjhm6drkhVrBj39XOcE3VUjhfvECUTgrQEKXIgqIhcnEZvvy4j3P
         OIlHtgZoMqDJHnRBjBHTVWzTibC+HP4DQC4jYVAahOcxTi2o47nFXdae/DlRxLIKroR1
         S0VOQlI+3ZwAFDRA31TODHgtTrCEqzZOGVV51sqJthy68XzQHjiyiN/vwcip8EcliE/z
         EA+7VEdhc6C/jq403RWfeHKiYGGJRix8fR+1jHIL7azpw7fP5lhMsc2sMISnDc8CkeD+
         7Zlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OkqfK8U/";
       spf=pass (google.com: domain of 3oxhvxqukcc43u77108805y.w864ucu7-xyf08805y0b8e9c.w86@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3oXHVXQUKCc43u77108805y.w864uCu7-xyF08805y0B8E9C.w86@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuHaLpfAoum6FOHcxSxcl3bWwVvAKu+E17yOxhmaXHs=;
        b=bcJRjOYh2eQmEFE4VmlYprh6Ln4e3wqoQs4KBKNPagnNAE7LNZWh2DTOxh/QjUnyJD
         Lqvzv0ySuKL2GweU5Voc19+AHVbXFw9RR7TGCIO3zFINuVQJcSFJ4wZ4Q3Y5fO5LJxt3
         8fUoh0OOLF/qfmC7FuB4/cXWDir8jjkSFLpYXKL0IhyGtCVKEfNUjDDNGNkaowlniojm
         k4ZL6SYVC0ub1lNJlV6ZXHNwUdHvtES34j/PEtnAEhSkwJMuHV9IFiU5HkrsDiRmO6z8
         wOYmUVQifJ4M2/djubc9ZENsrj/cJ6nEYe1Q1LwsIlQ1CEY4xw8ssrBPckLTxE2XKse+
         Vujw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OuHaLpfAoum6FOHcxSxcl3bWwVvAKu+E17yOxhmaXHs=;
        b=KDUOgWQmQZ8OszTd6k7N3EUwEzGMkxh5pDC/5LWfCiydQQF4tj40h7p0BVpO5tH0DL
         nzPf1fYc0C5zza0SF6l0bl2bNX9s36VutO8rXg1acjIO/uX3ieQznvdJJftZck2YY+LJ
         JG/+rpgZdxx69QSgZWtRq4HJIYVcVqLM45xwTJs8IN1m2zTu0g8Etit/vX01ho2ve89w
         cydji9cWZ1YJtZiw6WVjV6utmzJn7BEC9+FG2dCziwVRFtFqwYRg+WMMF4cN7UOhkNN3
         tKPhIQ9lMh9vp//GQZBLTJJzCal0O2hKtpOWeLq7KPxGYTLNsRnJJQKOiRpEV5oKSESZ
         0T1w==
X-Gm-Message-State: APjAAAV1/sudVoprVKn+XIjuU3meIQryb5Wm0Li8E+XkWrMW/nAzPbXZ
	8ZGRj1ZmvDoHpRbfQUFIeag=
X-Google-Smtp-Source: APXvYqxvUyK3D39MlJxzBsP0rX73b8BsIVXBXxXhvMfPZ5QSxX+h90yLhplip81N0ZBFizhAIGTsPw==
X-Received: by 2002:a62:180a:: with SMTP id 10mr5332135pfy.40.1574269346849;
        Wed, 20 Nov 2019 09:02:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1581:: with SMTP id 123ls690526pfv.11.gmail; Wed, 20 Nov
 2019 09:02:26 -0800 (PST)
X-Received: by 2002:a63:d551:: with SMTP id v17mr4493397pgi.365.1574269346322;
        Wed, 20 Nov 2019 09:02:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574269346; cv=none;
        d=google.com; s=arc-20160816;
        b=OaZCF0PT/HE8F3q7977jcro5eheft6d5nBvXhK3HZ6Iqaf29iZ5Y0fZpHn/6GkiBki
         zv1Zu2K5LY8a9n2ZduVMyy8mKLowJrb/6XOGrhyRR3CDRbPu5TcIKf3QT6rJXsT4VbXt
         jTQWgR7Kqs49lNQUCsj7b7qTEgvNmj+6tnxlaW1TjKTZMjtMb3G1wXkd5wDiL1vN77xU
         t+UWT1lsKrR6tGHOv5XlDaLwC9e/jauoHArE/3H05BMy+dDwHpO9HOVjjaZ+Dz43Qzht
         zLtu4YcFQQ6Vk3uLcrxqecS9h/wsaWFNcYRQbW3DZP+Y2Br3Uqa50HIm/96Uvt58BlP9
         Hkaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9d7hes0bN3fI4cGZa6ncDGHqqVf+/vhZC1EMTLMNG+s=;
        b=KFi4275uOOrLVfFVYbnf+rAMviXoDr8LGR6t6GUv2IideULMoCaqN4uey4w4rYF36b
         lzhvQlzPnYwFyLloSzcD643hZ1900171TjsC/sHMN0hHXENacyxspfZ/GiNi+IF7g08n
         BNNg8R+pOyn9q9JIkGhKl9+kW1h2ijUW7LaphQ8giuHBzE6BFt1oazVVKy2tbefrtKZB
         0JF238uWI83AuMLJVyEKQOMsYp6FfVvJSieshX1RosDStEGDDwzCwrqfQuv7y9asVhRM
         Gn8tbC8AJtDUVChcFfvu+ndPv0VgtjQNGh3NzclvUe2dk7fLx5321CU9wQVBcJuh9Upx
         6qAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OkqfK8U/";
       spf=pass (google.com: domain of 3oxhvxqukcc43u77108805y.w864ucu7-xyf08805y0b8e9c.w86@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3oXHVXQUKCc43u77108805y.w864uCu7-xyF08805y0B8E9C.w86@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id w2si284343pjv.2.2019.11.20.09.02.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 09:02:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oxhvxqukcc43u77108805y.w864ucu7-xyf08805y0b8e9c.w86@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id s17so86074vkb.5
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 09:02:26 -0800 (PST)
X-Received: by 2002:ab0:4e2d:: with SMTP id g45mr2371300uah.29.1574269345276;
 Wed, 20 Nov 2019 09:02:25 -0800 (PST)
Date: Wed, 20 Nov 2019 18:02:07 +0100
In-Reply-To: <20191120170208.211997-1-jannh@google.com>
Message-Id: <20191120170208.211997-3-jannh@google.com>
Mime-Version: 1.0
References: <20191120170208.211997-1-jannh@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v4 3/4] x86/dumpstack: Split out header line printing from __die()
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
 header.i=@google.com header.s=20161025 header.b="OkqfK8U/";       spf=pass
 (google.com: domain of 3oxhvxqukcc43u77108805y.w864ucu7-xyf08805y0b8e9c.w86@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3oXHVXQUKCc43u77108805y.w864uCu7-xyF08805y0B8E9C.w86@flex--jannh.bounces.google.com;
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
    v4:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120170208.211997-3-jannh%40google.com.
