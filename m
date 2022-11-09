Return-Path: <kasan-dev+bncBCF5XGNWYQBRB5MNWCNQMGQECSFLVPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC5A7623410
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:54 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id f132-20020a636a8a000000b00473d0b600ebsf848468pgc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024053; cv=pass;
        d=google.com; s=arc-20160816;
        b=k/CCUoJxq0EQpE+uTTGiNcmd7vf0pOER7eId8stN5ipKEtXcknp2Sx0g7D2KyTC3Wr
         A6aurflNk181EnugHeDaO45Yhndy/xJKvtcVYrOi7RXOqI8zlzM6CIHEmVqDIsoT2bC8
         4nF5W9orbub3xrH3aQpqTgJc6VLcsUq7QU208G9Uz+HSdIVdzpfwGTFbZc0bjdqxnHer
         1OERqFdtbWZeuYwErvhrA0zyMRzDNwKf1iHENFA+mp4UhmSqiksBIzR42EApg14xSipJ
         foBC4rg9GMOI8JzsmOkhEMKtaiUIIOc5zO2W4CvpAc3VBQ0J2p8D7LXuQ0n7RApHlX8z
         Hdsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=l14ZrVgWsFJ25MEOLzvJFLkXgUCR8koX0PU6BF4BkVE=;
        b=LLSehiCyg3AxG2UvEsiRn87/k65y2Ra3pYsiyt4wBjxkNI3eP+R9uvlnCflboY1RMp
         8o2aC4YmMa1GB6FnX1Bd0eD+fiNPwvCDT7R0nElG9Yv0jyfeHSqyBRDX6//eWZ8SNzad
         sMyP9jray7l4FCiwY41ZNxafFvcXTPAN2SCYGOEAphaUC9iBz1PUeten0R8tzJrf6QHU
         x6gLq/1Nel6mZLXex95z4s5wd69HjnxQL2trJV1wyGxAPQ3A86iwCG0bf7SF5oU51Uwd
         yypBtgCKQzq9AFoqUkNUwvrTz/ANs1VWZpTW1pwHSjkHMFNRCt0HhjLnYRopMqKBNwaV
         4rXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Gka6JzDy;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l14ZrVgWsFJ25MEOLzvJFLkXgUCR8koX0PU6BF4BkVE=;
        b=C6YzrzPPGZ41YXcpXlZnJA0DzkOda/rXepH8cpN+6bWRSyHuEECesTEcXEQyA4iO2o
         K4avOTkES0j+W/Dkc1VSSAYyzp3OMPxnFC+zwibpTR3Dhi9Ds6cghwNzJQNIY+lxOTem
         PUafn41E2yKFAOx1eQoUxSmC4VpNbueHXuYtX3f+R7IseTJLPz0w4as6fMGdp0S7mgNb
         GMDDM0tpUoKNMyPuxwytmtgWB7AMSo+zM6/55cvUsIP8aa30+XlXr7NamQVYXWgDaOXM
         lUr43uZg/cKtQBnAus1yycwTMzlKYaqBKc4whw49sndUHEqyRmXaWUtSJpeOLmibX7Y0
         nQYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l14ZrVgWsFJ25MEOLzvJFLkXgUCR8koX0PU6BF4BkVE=;
        b=pjzigr8N4EzbsIWoMsi1tdytPGLat449M0HKiqqcfXTe+SznBqleVdHq99oLiXcPk2
         BqSBNMqfYQfGnnY54dpAtJsSrsNkgamNyQuU29wpyfiDjh6RIWIuRKlv75QQxlSnYTDe
         6KWzea/MgGiz+NYF8WQRgZyujzMueHbPIzwJEJIY2kJwKa3BAiIZZK+zguBai2hz5npf
         tWq79ZorUL6Ye7feoWdVJVpD1jvZUG/WvdJ+U4t9lrKX3xCd648g4ZHtkI6pDMs1oFpD
         oT8W+REj1ybZ7ux0I76pPZKjwwUdGQqUOmM4rLubkiD+DzP3yEGwpkQcRYf49mHa3a/J
         gfyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1vHNpLllit/sfkmYImJqaFrIbUIml8Ebt/hT1vfi+DSXf0vFk5
	RC7xivCqotgjsQFWwy6jaGs=
X-Google-Smtp-Source: AMsMyM6LWuCp7U6z8hNo7K4oETOcopAA1nQ6MYAWMqLux40cJGzDT+TYV6fiRJoRmMpExt7lBPWgbg==
X-Received: by 2002:a17:90a:ba05:b0:213:b1c2:ff88 with SMTP id s5-20020a17090aba0500b00213b1c2ff88mr62818972pjr.240.1668024053145;
        Wed, 09 Nov 2022 12:00:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:39ce:b0:20f:adac:8c6 with SMTP id
 k14-20020a17090a39ce00b0020fadac08c6ls2298296pjf.1.-pod-canary-gmail; Wed, 09
 Nov 2022 12:00:52 -0800 (PST)
X-Received: by 2002:a17:903:32ce:b0:187:143f:4c4d with SMTP id i14-20020a17090332ce00b00187143f4c4dmr58681992plr.135.1668024052347;
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024052; cv=none;
        d=google.com; s=arc-20160816;
        b=myaJsdw3c40AdYNyqDlL+MYb5U1d7+NaU5t1AUUL0Ps7FKZcAlQ3pQvNy+U/CTkLNl
         KqaZj8Uhdqr1vD2y0M95JdI7ayB6GGLZPGooA2WhIDLL+jgDiY2umfM5rQjIwM8AF5Qu
         bIgyKWqwH41so/OwUaUIZQlAUbfLKQAuqy/Jj9cCY6Kd2AZV+WRD7FsmpfwKptGLaMYr
         xBPME8atX4D1EdctCj8pz9Jx7WynOjjmprxY2imzYbCEtneJizKfxC09KlBrBxAedxAz
         s/DqUjr+hgAUpJQCzzzpwo5u4ECda7s27lhEaU+NC5amDT+sYsa1ffZdO4NrzgjXps+v
         HtLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TOl6z/umIA2dhnmGMIG6cWX9VY1K0BEEK1Uosuato8Y=;
        b=L4TzszkIemQCWEctoxZPZqC/2rDoC4IUyBRppklk5wCnax3WYqZb2Gsz1f79Zn+e65
         whWZwEd9aVzNNN3aXUcT8iewn4xmWe+Ett0skx9+R/KKsJph0lYMXl8n+u0LaJdB8noX
         GWMFoPijK/9Xxrc5cRz8KG4dyH2+9/xJyYqx1IbtTMTedczHs2GQNQIV2rScRTWHaQZn
         QYC7nQrSlN6nxj9Tbo9cOBZxhIPVyF3dHO/xZiIGlrqO2JYwgyw0/QH6TFAKWTQxy4fa
         BOnD2QhunlKd/niIKHofuLe65IoV06lKUtxaYYrmM+pYTuG7oW/m6jECcM5crjgVMOQK
         YBeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Gka6JzDy;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id mm14-20020a17090b358e00b002101aa81909si123119pjb.1.2022.11.09.12.00.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 78so17103270pgb.13
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:52 -0800 (PST)
X-Received: by 2002:a63:5150:0:b0:46f:be60:d1eb with SMTP id r16-20020a635150000000b0046fbe60d1ebmr45016359pgl.82.1668024052025;
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id a17-20020aa794b1000000b0056eaa577eb0sm8654375pfl.215.2022.11.09.12.00.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:51 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 1/6] panic: Separate sysctl logic from CONFIG_SMP
Date: Wed,  9 Nov 2022 12:00:44 -0800
Message-Id: <20221109200050.3400857-1-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1192; h=from:subject; bh=IoW4clR1Z0l0tOPQKCaXz5ByKX5rPTSXg36TIGSUe64=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbv1LOBj/eV9FJ9roBnkkNtYxaBPhV1cL6wlgbR D9gETvCJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG7wAKCRCJcvTf3G3AJlUtD/ 97OgZ7IMn3jz6bT9vmc/YgFyUCFPLVBPbEk8QBykQqQITpRvaIn71jcxvGnQ6p0uGNEiQuoxc7AhU1 ah6MKCbYMay02cZ0WqCIGOnGcoH30Chbhu1peQ1QPCY24ArACK+DU5g1FSe2/rMFXFDBh7omd2GKVR jA30ciu1aIlQ//Lo8ZE5yW3VVKAGBhuohwQ04R/CawrVz/qXjSl/RqgyiXkINJNOCcytNkFPPcJBhQ 889xaIIzfX5NijRPr8S8tmJcGnNbLAuSV+ejNRUMQAWnbtbHZNBFUJyL2w3GPFqGOy5polHHUb6EQG Z7Cvlc4eOt4GP5drNlw+1smVVa68Oj+DTzuTkUEYpUpc0ajYX63hOFn2eMC1e25/l+5Sl2jfjT58ZZ 5aZrHCGfBHK7mrz+AL+7NkF9PHD1iLGqXT4tMG0mNbpftOn/h93mg8RKDi6vusCqKUwgQsYY4Q6B2l Mg9AP9hEjp0dtI2NCekNW23wvTElrzNMqldUgwJjvGnft7gCT4wsIqR/rzl92YKChzX3P9e0jfoSco nPPCFRMXOhY100moOq2KtKG49g/Ms4RvvyFP1Gmo+m3ppsvsqeBp7apapgTsE6pKtVzWkcgAlBArGI /0UUIHG03P7pOXIEOq/Ec7ouKxipBwYsM8AvUGRA9D9IDd7bcKz5j/VoZbBg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Gka6JzDy;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

In preparation for adding more sysctls directly in kernel/panic.c, split
CONFIG_SMP from the logic that adds sysctls.

Cc: Petr Mladek <pmladek@suse.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 kernel/panic.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/kernel/panic.c b/kernel/panic.c
index da323209f583..129936511380 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -75,8 +75,9 @@ ATOMIC_NOTIFIER_HEAD(panic_notifier_list);
 
 EXPORT_SYMBOL(panic_notifier_list);
 
-#if defined(CONFIG_SMP) && defined(CONFIG_SYSCTL)
+#if CONFIG_SYSCTL
 static struct ctl_table kern_panic_table[] = {
+#if defined(CONFIG_SMP)
 	{
 		.procname       = "oops_all_cpu_backtrace",
 		.data           = &sysctl_oops_all_cpu_backtrace,
@@ -86,6 +87,7 @@ static struct ctl_table kern_panic_table[] = {
 		.extra1         = SYSCTL_ZERO,
 		.extra2         = SYSCTL_ONE,
 	},
+#endif
 	{ }
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109200050.3400857-1-keescook%40chromium.org.
