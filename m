Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMU5TL3AKGQEMQTM4WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id DE91C1DCF87
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:43 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id x10sf5437989ybx.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070963; cv=pass;
        d=google.com; s=arc-20160816;
        b=r50ZmplR7juUJwr5XXCJ05GI/F9ebsAfngDPL0k9tjvvcqXtedtYF9kkdgcaB3Npoc
         pF1q+W4tYvqOKKC31VavArBHNJzwszBUy5wIkpB/7sZ0g1cNwF1nVryp1PYpIYsrOFEN
         tXteKhdtqJq8ATwEF55yyFRVq/JbO1dJvvsw+HiLX4dTB0PSTtihVcDCvhdgIGfGxLFU
         iL5WO7aWaIMhj/jjPERspXTWKq7hjVesguuuzA+zMKe1NgV+um70WEpWiTVE5wOQhHoZ
         JVt+LK+gNCpabM1WQFsd50BZLtqLkKey06ILkLdIAPjo2miWsq/ZF2oBNkAOhshGDeJ7
         a7OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=40xls5SFX1JUEegEj4dP4L3KrL7W3QTH4qrFFWGG8m8=;
        b=Bdi336tUoy4UjUz6YD92dTve5kavsdbg/DYxTAJtHn6pjvcLbxcu1pkU2jzt8fHj/I
         7tdJo+rJm2Z4nLIsuDLuZDqQaDfKUB7OECU4nNEGfJxpCvQcoCWYaVMDcY7PYEWwryxm
         obyPwfL+Wm0DsPQU6myhnBS3SEufnpfXJXkfgS55XVb07tj4jzrO6UrMAag0CjQFAZjc
         A+Q421fg/TOCDWj/RMkfiBelZENdiDpIkc2pfInZt2uMY9+hGe6ECVy/99KdM/nCk8M9
         6g9B15wQ74INjNsRVmoGvWQb6rcMsjk3rOcZuE9Of74MgZn40YNUNNTV09bk5+Yjp8xz
         mozg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="L/OPRcba";
       spf=pass (google.com: domain of 3ro7gxgukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ro7GXgUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=40xls5SFX1JUEegEj4dP4L3KrL7W3QTH4qrFFWGG8m8=;
        b=C24TQ1SfaqL3gFSL99hRZ+KhzhCtdF676DUNpQCmOvSq+x8b+gkWb+cnojHIumBwc1
         6aaaL0It2X8VidIWVGBHJQN1LFumXmAUc6w2fgGz0GphMJ6D3kUlKrotx4TUFDlMZA9E
         1+I3hUXcZp31Y6+YPRHh+olWA2/GtBnP4TFuqPbQkZJ8w8PEwPG4kH/wa09Hp6R9ZWEz
         lmjC6YAPKb455L6gXBR0LJL0ugPRL6pKh655LHTwymBVTBxMztLZ33c6oDQL8JTHkwDm
         JUWxODYVnWaRRwzgI5q0QlO9NnJIGrng+nWiWWFzXMFy8PLHwf/3+Hy6Mhl/qDQXO4QG
         FGmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=40xls5SFX1JUEegEj4dP4L3KrL7W3QTH4qrFFWGG8m8=;
        b=Qk5iINIUu6kqoynvW78FKAfHklWOydTvNfzBrFvY1vfFxREFEYsuBsnhkJxvZemUMs
         kITTCgtIVesoj6Acrp+Z0X3Fu3drwbzVV+Wbq/UjKDyQFM+GkSLvY4eMx8R1TxzIDqsP
         3pVPNNHo8M92/lW8FoQ/NeiafadMGP4MeXXlOgoQW51iLYn3LmE8ZtxcntusoZRwkqIs
         WJ3ybeaPAOkTtFtMPglsyBA8urSomX+OASqKXd0o+a8Tcv1/YlbyGSHflpWUpIlYQG20
         tZl3CjU8dgCNPh58BmOOhv8yyZqJ/7fVpuMUeSwhIgSz3NSce+/5g2b9VLW/5HMortfX
         J8Rw==
X-Gm-Message-State: AOAM530sy6EE1gmmyvGZe0tdX07aanwm5FjMdon48XEkPjB/1sfHT3gD
	4y0p2i00twk324dP9eon9M4=
X-Google-Smtp-Source: ABdhPJxoCvLw2GTMJo9el4Tbp5GcbsYwAMxH/6we7yX4Hp6SO02/ywFJk2Vuki8aX8mXuVeSO3nWcQ==
X-Received: by 2002:a25:d353:: with SMTP id e80mr16043719ybf.374.1590070962964;
        Thu, 21 May 2020 07:22:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:678b:: with SMTP id b133ls800551ybc.5.gmail; Thu, 21 May
 2020 07:22:42 -0700 (PDT)
X-Received: by 2002:a25:4f44:: with SMTP id d65mr16721563ybb.149.1590070959198;
        Thu, 21 May 2020 07:22:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070959; cv=none;
        d=google.com; s=arc-20160816;
        b=FSPYe2YyXpcyojHGchm7Kp7yttL576h6TcyNLsmF4QqhcKkWmf2c2MGN/sFQc/4FoL
         iB8pXVrmhY6txbjjCld1BvHiSDhTTwr3E9Q1IyA9LDBkGDlFch/Z0qml4Un5kQk3oM38
         YVO1vmuCPVNbH/rJ18aDQk4D54rfZwExIClwD+wrGtGhIpKgcCsVs/ecO9cpP6+UULqu
         Z1Wn2Hcv3qmeSHVWvbUnZYYzQAnLdd1ur6UgbJdNMQVwXhNqmvifEIMfpT8GXYPvaR5E
         0/frDufCHt0SbbKm2eeN/sFKrTZSMQLki13XHbky/qR5JbTLdi7i/sdkEqRCiHyyt7OU
         mu6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dz729bx1Pa1pF4PgJy0kCf9Utra9WlCLoUyt1P9z0sg=;
        b=wzbYw3hzaiaFrPWRpKlo4gfK3mLsaGNUNOWHmAP4knOSXO2soE16AzCiK+CtqaPXGN
         MzXVK6UjKEAy3raz6r6tbM9xLuN+UAUxg1y6QrWxHAxNOIfyppTPo5bA6LhCMU/UqIiV
         JjrteZjnblM0klk62ef3YjM2ZwAOgCnA8PWKU0//OX4aAxfp1o5JIdyhqx/Lh7nnW/LW
         uFNbdJwB5nQ7K5soYthel/K2p5PinaMvKlqRS+pQMSpsG2YavEZNxpm22mYazPGdxZGa
         8hv+7YLbjmUXR/2R5Uws7f6lzq3utTU9cnazwoiJ34rwwwirzMbt2G+VVGAQrmq70n9E
         h0WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="L/OPRcba";
       spf=pass (google.com: domain of 3ro7gxgukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ro7GXgUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id a83si490548yba.1.2020.05.21.07.22.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ro7gxgukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 189so7556090qke.17
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:39 -0700 (PDT)
X-Received: by 2002:a0c:c991:: with SMTP id b17mr9979723qvk.16.1590070958659;
 Thu, 21 May 2020 07:22:38 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:44 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-9-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 08/11] READ_ONCE, WRITE_ONCE: Remove data_race() and
 unnecessary checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="L/OPRcba";       spf=pass
 (google.com: domain of 3ro7gxgukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ro7GXgUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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

The volatile accesses no longer need to be wrapped in data_race(),
because we require compilers that emit instrumentation distinguishing
volatile accesses. Consequently, we also no longer require the explicit
kcsan_check_atomic*(), since the compiler emits instrumentation
distinguishing the volatile accesses. Finally, simplify
__READ_ONCE_SCALAR and remove __WRITE_ONCE_SCALAR.

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove unnecessary kcsan_check_atomic*() in *_ONCE.
* Simplify __READ_ONCE_SCALAR and remove __WRITE_ONCE_SCALAR. This
  effectively restores Will Deacon's pre-KCSAN version:
  https://git.kernel.org/pub/scm/linux/kernel/git/will/linux.git/tree/include/linux/compiler.h?h=rwonce/cleanup#n202
---
 include/linux/compiler.h | 13 ++-----------
 1 file changed, 2 insertions(+), 11 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 17c98b215572..7444f026eead 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -228,9 +228,7 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 
 #define __READ_ONCE_SCALAR(x)						\
 ({									\
-	typeof(x) *__xp = &(x);						\
-	__unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));	\
-	kcsan_check_atomic_read(__xp, sizeof(*__xp));			\
+	__unqual_scalar_typeof(x) __x = __READ_ONCE(x);			\
 	smp_read_barrier_depends();					\
 	(typeof(x))__x;							\
 })
@@ -246,17 +244,10 @@ do {									\
 	*(volatile typeof(x) *)&(x) = (val);				\
 } while (0)
 
-#define __WRITE_ONCE_SCALAR(x, val)					\
-do {									\
-	typeof(x) *__xp = &(x);						\
-	kcsan_check_atomic_write(__xp, sizeof(*__xp));			\
-	data_race(({ __WRITE_ONCE(*__xp, val); 0; }));			\
-} while (0)
-
 #define WRITE_ONCE(x, val)						\
 do {									\
 	compiletime_assert_rwonce_type(x);				\
-	__WRITE_ONCE_SCALAR(x, val);					\
+	__WRITE_ONCE(x, val);						\
 } while (0)
 
 #ifdef CONFIG_KASAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-9-elver%40google.com.
