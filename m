Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKMLQ2AQMGQEQ6QYNYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E8113313DBA
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 19:40:42 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id v7sf17758564ybl.15
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 10:40:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612809642; cv=pass;
        d=google.com; s=arc-20160816;
        b=j87/1UVeMuD0kzZ1qaDs/fY9IrDhvaW0p+GqI5IWgBwYJnwenjC0B2hN3XT0aXGgc+
         0EF/Ajbx7BFNlCGta1NboRkPrx4RTknK6w+5S8lOGv0Taao6whuK7tiw00m9+7Rv1Q5m
         Z657BVWan01B0kL4CQoEBMmoA/0e+iBGBOBiOsO0wk1CRM920dKnf2MFCPeWbwMwV+9h
         WWkxgsYcZAMcbPWlvuwO2jNDyhZQUuTwJP077yVPVxXlLa9Qws5cUc1GHfW5xdAJKmMP
         bTDk0j2G6MQXTvSsa/LUXGyoopaVOqRuI0zbm3Ln2sS6FHbtVOj/5q3D4yrxQz597/Ag
         aO+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=VC59t++DX+CJ7cnFL/ROLBOwNzVaRt6K1UOyohddmKw=;
        b=NyW9qjTer1/rdd9ubvlTsRABowZAA7eSSWX8RciBiH2rSSD0dYYLUlT+qN/vGWAhqu
         3mTnb5dWtBr8WtZSyxRq0alvrm6Srvcl1uNWlplE40OaV4vbElHyQocONcChw1z4ZXc2
         2BF9f3F/1DgVIOz4e1BMBICXMsRuUWxRxKl4Zs/o1LTY260ZBtbp53yFAyA5RtpLgZgw
         kV23YArYCaMpqJYWnyaw/m0dCytrFWYPbUykZdJZFmL+MdZSpIL8/HogIUj5rJf0MLBz
         +L3NuFtXx9wRm89kVpfmtezw+eKc3rH19CqfMPAcNnLG8AL117EFGawRJ7IcI0aUJ2Xn
         W/Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OSxYfK3d;
       spf=pass (google.com: domain of 3qiuhyaokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3qIUhYAoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VC59t++DX+CJ7cnFL/ROLBOwNzVaRt6K1UOyohddmKw=;
        b=I4g5rDTah9LV5yPcen2mtewo2AOtpYtApIHZt3kw4nPsqR5Z9+p4zHy25O8DGG8ASn
         8UA8r+LWE220lwpRZ0VlL5IT/bXXUppg9kabRWotN9DyrgkX4VNgmnDF5qA+SQawwiyo
         NUqmSvQ+ac16iNx9i/Bz8ruU/Wrf/AiWDlxkRfZ6v7HS4IrezfXhfnARWXYvDuSmkW8l
         /WIvzJUmGmjwlNusKBKCt0NQ0P//lHLIjX4osUL4yPsldLQ+P5T3Twvc+RCwNnGk1PIM
         bJa6iT7tePVOKTbEPGPDBPD2OoeCiatCzyz2yMrXQ66cjzGDbrA35KojyM8sjc/enb/F
         eqVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VC59t++DX+CJ7cnFL/ROLBOwNzVaRt6K1UOyohddmKw=;
        b=G65abUkC4suY9/n8tHd/geIF3YYHbd1Om10RkDD6v8HBwcJAATBpTylS7OV0/4/Yvj
         FZr9xIwhzQF3VLaqGKHlFsvgSIyExOCDc2YmYQQyq6GTDWwoIyhiG0cmogOJ+UFAa7/z
         g9yYLMVT/WNyQMRuTFDTidZ9+sjU0ExBPWwIERkiZNqSWbhqqVRrJyBYsgXnpG9xpx35
         cQ1q/tL9ekF6D6cvlnuLLJ6CYH93pxPZEvWefKVe/IjI+f7OCfHyba0rs9/ib2PYtxGM
         pqySklZQ74CpQnpjHRFiQS1cCn6DT3uh2+GZMR3juWDceVk7hF1abIj+U2pvK5KtzgQp
         L0+g==
X-Gm-Message-State: AOAM531EBP1+tqmLfDf4YZFnNPKKQ3DfI9+alniMXKpHk9vW2SFDImJ8
	Mz/PxcrkkqxQhwfBZFHXl+4=
X-Google-Smtp-Source: ABdhPJz6dNOo4/h6tYRESGBGFGJO9S/LMQBh0X3A39yIioAq+RTJSKvPn0p351CL+XI4/e+dVLOnXg==
X-Received: by 2002:a25:e654:: with SMTP id d81mr10774197ybh.207.1612809641932;
        Mon, 08 Feb 2021 10:40:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3006:: with SMTP id w6ls8943034ybw.4.gmail; Mon, 08 Feb
 2021 10:40:41 -0800 (PST)
X-Received: by 2002:a25:e08a:: with SMTP id x132mr29428479ybg.121.1612809641669;
        Mon, 08 Feb 2021 10:40:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612809641; cv=none;
        d=google.com; s=arc-20160816;
        b=G79fMzaHYQldu5AGClutdd/SF/FrPDbR1Qe7kArywayHwkDvwjUrhxSSvMTz8Flwfx
         whW8GxsEnUk8yglGDe6oJVzX8kcnwgz5b1hwbw81RePVbP6gBVNEgFVHQ5StTH05s0td
         SJkx8gT1RUT+nDjKWbHuQtoqxBEfgVobqj2lPH2DDiHuCaYbyDbw7tjnW3s7k4cxSP4z
         idMjHAsDBavMyOpGKwK/NX7TA9XZ8T2r2NVRAuzcZx6iL+a+4s18pHb3WozbrG7mrpWW
         0B6os6Jn/UIyIdbbez5IqErEZKoK+iIlJEH75MwcMeue0ZblDiT5AuXXTQb8OE5LwqHP
         SRUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=H9qB3jddJUOiem40qnE4VNfE96DiVHMNVUIiz3DWDnA=;
        b=hwVqq14+qePF9Lr+BJZIaDn/wn1JhBFVE0vqk8MAyO2fUIK7a0vmEf6+T4RK57zRUh
         jHRXz+6ZV18uEnuh4mDDtvHGoaFtfVZz+/xGzyjqNqMMkFYe36FgIf87C4v+eDM6Ml01
         a+cGnKfCyWiIyYILAfLo0QVBUVDU1d6jOB3KtlAPBvYNXF5wuHUgPBZ6AtJcooM3pUh5
         0belmGs6HdPBwT36H54h6bYQfUIxLFUIFGCMcr5FQN3kmEOU44bwG+lxwkVhONZRa40b
         Da5ywvCzX5nnAgaPBO3G/FEqkTQCKP6SdzTp0hFJP5F3uOLaf1MpEfvP1LlTqhkt+ty4
         IU5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OSxYfK3d;
       spf=pass (google.com: domain of 3qiuhyaokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3qIUhYAoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id i194si886751yba.2.2021.02.08.10.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 10:40:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qiuhyaokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id h13so11260216qvo.18
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 10:40:41 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:55a0:b27b:af1c:327])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c1cb:: with SMTP id
 v11mr13766499qvh.59.1612809640525; Mon, 08 Feb 2021 10:40:40 -0800 (PST)
Date: Mon,  8 Feb 2021 19:40:36 +0100
Message-Id: <6678d77ceffb71f1cff2cf61560e2ffe7bb6bfe9.1612808820.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH] kasan: fix stack traces dependency for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OSxYfK3d;       spf=pass
 (google.com: domain of 3qiuhyaokcuedqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3qIUhYAoKCUEdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently, whether the alloc/free stack traces collection is enabled by
default for hardware tag-based KASAN depends on CONFIG_DEBUG_KERNEL.
The intention for this dependency was to only enable collection on slow
debug kernels due to a significant perf and memory impact.

As it turns out, CONFIG_DEBUG_KERNEL is not considered a debug option
and is enabled on many productions kernels including Android and Ubuntu.
As the result, this dependency is pointless and only complicates the code
and documentation.

Having stack traces collection disabled by default would make the hardware
mode work differently to to the software ones, which is confusing.

This change removes the dependency and enables stack traces collection
by default.

Looking into the future, this default might makes sense for production
kernels, assuming we implement a fast stack trace collection approach.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 3 +--
 mm/kasan/hw_tags.c                | 8 ++------
 2 files changed, 3 insertions(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 1651d961f06a..a248ac3941be 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -163,8 +163,7 @@ particular KASAN features.
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
-  traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
-  ``off``).
+  traces collection (default: ``on``).
 
 - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
   report or also panic the kernel (default: ``report``).
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index e529428e7a11..d558799b25b3 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -134,12 +134,8 @@ void __init kasan_init_hw_tags(void)
 
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
-		/*
-		 * Default to enabling stack trace collection for
-		 * debug kernels.
-		 */
-		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
-			static_branch_enable(&kasan_flag_stacktrace);
+		/* Default to enabling stack trace collection. */
+		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
 		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6678d77ceffb71f1cff2cf61560e2ffe7bb6bfe9.1612808820.git.andreyknvl%40google.com.
