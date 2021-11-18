Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEV3CGAMGQE46M6ZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 629DD45567E
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:37 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id l6-20020a05600c4f0600b0033321934a39sf2707430wmq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223097; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGOzpAKotCbaECMCgolcoyhVujEF+wAcUpo3WPgF3QN9rPJHYO3mt6VK9Kzw32EcRd
         mmSdDzTt9wYwUjyEEE84pUIxdclNI03aKYMDo5mJjUC14t/6WLXcmb5DdDQ00hdCb+yk
         J42HiFVqd9J/FH8uQjwaAFouwkkeV5/roqBZakYiDT49CZGk3+Eetdc67KLG0t0DlcMN
         8SOAUs6KK8++/FKN203JOrC1IESZQS9AMGsow10yjCfs5Zx/ueExKPyCSVE/Stnn+tI9
         OymfuzstHZqkL4elFdQ15Aa3c4hoYFXpCF2MqJosiOiXBGcjHI9WIkgyCeOJSURJPB+i
         IW/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=x4b+nEUPnylUfGyk1XKE+Dx1Jm4jztTI6TADH/OUF6w=;
        b=vr47UttSIZcY4WcTTDLdr0UDhDEjH+q2cb+mxvwK71EWoGcVqz+3OUDN9qVHDnUSgM
         CR8aXeANgURWsFLZyrx+hVsfBGCaFLVgXp1HHwgeGPU5IaP+K8y3xRpHMX/eGw9zlp9W
         Qon+mT7oZcQoNlM5P9+Bf35dQlEmJcf/qe6ztAFgcHewHZdPltwZ9V7jkm6LAFKLo4cF
         I/6QmWrdQLVsTWJmonP97hgCq8K2+iWfsp25neFEhxjU3wdrVpMY0wVoSnlmpbcLOqS3
         lurrtWRKQ+Fk4xgxquMAwlcBKyOsb8ukxlW8uFhLtPlqlxDCdu2L1r57Y6uNrJjrp4QF
         BA9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="n/UFmav1";
       spf=pass (google.com: domain of 3tgqwyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tgqWYQUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4b+nEUPnylUfGyk1XKE+Dx1Jm4jztTI6TADH/OUF6w=;
        b=ofNkvmYKZzEVN/igzn4wTlBhMad2tlRR87RLbC3hpHaqnyL+42F8doFEOPcfBkktIn
         Wqu0nKMCilD50RPEvC9i0hgMgIdHe+knTge+f3/i1pYsDkTWb2//9RQOE5dFXIgz2cer
         kq2+/zq+VGc766FGkIT6A7ru+/WZ7tfNipn/2a0IFWS60ZKKK7otBuVL9w6VorAYxhwW
         lG8xx7TEdWup33omjSYRcz3BLa0ZY9FQIGMZZqRiQlo58hYFulzYRLdF+yupPtyvtegq
         VKbeGFViE/Fq1uXBXCSVoPi/nwbZwE/zUlbzGRiBy3nQ3i1s51KGUJ+bnBy66ag3UuXY
         teSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4b+nEUPnylUfGyk1XKE+Dx1Jm4jztTI6TADH/OUF6w=;
        b=QaEWPC2E8EhzQWzcuN2mbLGjprvrFHMBsI1h8krJTJIGzZIv723MZBbSKKKzeiTX2+
         UkdbGM91j8fd3VPiMXAACykuE63IG0iP4GdpA2UYKHZGYnVBwx42VawRXhRncJBWWNnc
         Pfq51ubsTL8JPtcElezWkFj/oCJ8EIW23k9P9v65yV2GTYkaKNPVDK++XilvywZCUtl2
         XVInwpIGTHe3a9Ul/TJSYnXWl/URQKWLSCR2v91bqrXCLL6snfYk6HIMT6sh5SwRDDmB
         tzX6c6TCIzh+URGa4TsnljaWz7wr3xr+9E5syZZf5hXaBimWVStWxQdJDA+DRDoDdkeR
         2T4w==
X-Gm-Message-State: AOAM532xa3UihLN7MYenUFxqlkYqHpmfLiCMjX2u7YhOZStu05uUAJyV
	anAb3dOyYpO6Itodd6+ufg0=
X-Google-Smtp-Source: ABdhPJw12Y75fWoejxtFKYjFQms8C0w8V5bR9oB0OEpQjtY5Fc1878BC1ex0uLn7oicvpyAgWsM7uQ==
X-Received: by 2002:a05:6000:1acd:: with SMTP id i13mr29480134wry.398.1637223096984;
        Thu, 18 Nov 2021 00:11:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls4704680wmb.3.canary-gmail; Thu,
 18 Nov 2021 00:11:36 -0800 (PST)
X-Received: by 2002:a7b:c38b:: with SMTP id s11mr7428290wmj.29.1637223095032;
        Thu, 18 Nov 2021 00:11:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223095; cv=none;
        d=google.com; s=arc-20160816;
        b=dYTWDD+geW+373WSK3YbolummLlswRFuOa/VHOnLhvoWIP8SdjoX0VDD8RyqfD7CUd
         UUFm1ewLqWGetp+Jhw9bcdkvMDH5J0alFt71Wqn6tXrwBxhiuoN16COTpcx0pCrVUiIF
         wB3BTQn3yR0uJDraxMIFaKjmBvHY0dXSRdHxv/Wo/fpvzVnOLZd51PQev2cMXUd7SgE5
         sM1GHcNQnC4cZQqgHjVYZ1xREd9ySTqHpKPn8Zyw1avQK9K0lMnvr4xdpkuMs3a/yffg
         7fqTEPuhZeYtphKi/P0FO1xLSh44NdmGZQ9pwmy8Tsq9iOLTEDDQZ2SSa9b8BxX4+QG/
         1nGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=T9LcpiESjlbrW6ACmq5IFNnAkv2Wwnn3szo64Ts4MTU=;
        b=BwD45lemyVntYaG84f23n7em2XOJfWKYnPz25Wy14Ek3AXJljFuyRJMXdOwnw8A8Dq
         bLfvKIiAxJHGC9IhmoMcEJnFkVzmlJB6KWIGIahPlJDoukKD9H1XqA9DO0wdmZ1cnls7
         CSqfuxpEVpoXqQ2Mao7IBpEnAQ8UXshkjYBk2fjB8oCi+yQ4ny0JvytdjrxYk8KV/FTE
         HAwOGTJ611b9G8OHeRIhdH1UkH6X2orG+76Od0HBnhAI9vV6xJhYqVkYpXuTAaiPrLGf
         Z5CeM8/HrDFwrMKRi695H1u88wt6UJWoJGkWizxrRe1UwvAvoFTktMKTjLkq8CEmHva4
         UrcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="n/UFmav1";
       spf=pass (google.com: domain of 3tgqwyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tgqWYQUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d9si114369wrf.0.2021.11.18.00.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tgqwyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n16-20020a05600c3b9000b003331973fdbbso2747332wms.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:35 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:350c:: with SMTP id
 h12mr7414150wmq.123.1637223094553; Thu, 18 Nov 2021 00:11:34 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:19 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-16-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 15/23] locking/barriers, kcsan: Support generic instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="n/UFmav1";       spf=pass
 (google.com: domain of 3tgqwyqukctcxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3tgqWYQUKCTcXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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

Thus far only smp_*() barriers had been defined by asm-generic/barrier.h
based on __smp_*() barriers, because the !SMP case is usually generic.

With the introduction of instrumentation, it also makes sense to have
asm-generic/barrier.h assist in the definition of instrumented versions
of mb(), rmb(), wmb(), dma_rmb(), and dma_wmb().

Because there is no requirement to distinguish the !SMP case, the
definition can be simpler: we can avoid also providing fallbacks for the
__ prefixed cases, and only check if `defined(__<barrier>)`, to finally
define the KCSAN-instrumented versions.

This also allows for the compiler to complain if an architecture
accidentally defines both the normal and __ prefixed variant.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/barrier.h | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 27a9c9edfef6..02c4339c8eeb 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -21,6 +21,31 @@
 #define nop()	asm volatile ("nop")
 #endif
 
+/*
+ * Architectures that want generic instrumentation can define __ prefixed
+ * variants of all barriers.
+ */
+
+#ifdef __mb
+#define mb()	do { kcsan_mb(); __mb(); } while (0)
+#endif
+
+#ifdef __rmb
+#define rmb()	do { kcsan_rmb(); __rmb(); } while (0)
+#endif
+
+#ifdef __wmb
+#define wmb()	do { kcsan_wmb(); __wmb(); } while (0)
+#endif
+
+#ifdef __dma_rmb
+#define dma_rmb()	do { kcsan_rmb(); __dma_rmb(); } while (0)
+#endif
+
+#ifdef __dma_wmb
+#define dma_wmb()	do { kcsan_wmb(); __dma_wmb(); } while (0)
+#endif
+
 /*
  * Force strict CPU ordering. And yes, this is required on UP too when we're
  * talking to devices.
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-16-elver%40google.com.
