Return-Path: <kasan-dev+bncBDAOBFVI5MIBBQOVWCGAMGQESTQ7XXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 97CBC44CA89
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:25:37 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id v13-20020a2e2f0d000000b0021126b5cca2sf1013901ljv.19
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:25:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636575937; cv=pass;
        d=google.com; s=arc-20160816;
        b=yKnO26lSVO2YAcggARnwpwtMrb/YkOXJHNHAUMp5xtBetPLIaAAh0dZXD4FN6XPuYn
         7tLMpit8FAPIeZr70rKh2h9bRj8483XeV/rCAdinZRVgNF7GwAyI1Iu5REcKxUFFkaJR
         C4+vdZTC7lQYqxltLTDmfs8wMVA/JpfePsbT0w78cldXOpPETjRV62s0huhv7JkS00FE
         0Lu2edc8Gt8T27fT6uwtrBTjy4/nj+Ykf0jk0KiZGTIkv2a4taA/aN2AOS54+Qw4cdZQ
         FV9C6ZOxbevhEYTcDE+lm0XTGh80eqZVzrQzxLFRydn8VbFn9guJBas6fZmi/6euuTY7
         fSQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FWl+OjVGtT9yNj+oc+PJr5sgsL7osptSZEWuQZQ+1+w=;
        b=M5E0VJfYVLb5HEAhx6EyQctbaNzwn1xGE33IK/CXbwnjlmY2V/cI/9+ck1TtGAulAt
         XHZPBxxcp0Dv6KsDmt3vRgY/1BsLFOzT12zeO03qeFZpcrdCnMeyXzXq1tRL/lE/glcE
         VYCSDaPLfMGSGU9pRy/kmWtMUMvwucDdX8W+GpSkbZHC4rjTv2dPB4teIvx1ppEdK3Ey
         hQXMyk4PlIIgn2DkzBIYwWauVeANw/X2nYIFloaSLKywITvAZe0ZPZ/ATbMxeoOMsUaT
         7N1TRlWrAx1+qqx+BUjdrhlvC4Z9sNxxHY7wd5XKzcM/HfC50h8YMN+14qrTTSXybzLZ
         17/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FWl+OjVGtT9yNj+oc+PJr5sgsL7osptSZEWuQZQ+1+w=;
        b=PhSpQdpIJcEzmk5zq5wWLiBa/jnMG6YYG/yZcHmrao7Cd4sgJ7vrI1KoaXcogGxmfH
         J6tOSKyW76j1sprL0leo/J4MureS2M1qCGDy7IzBRLvO4sNWAvgxSTCE8bvuC4u9TxZp
         lMKjzHnXk0LPoz7hRHAXHgubM897NP+Vvw0+IeokdQ502eMLLaNkULi6Zm2lEYLm71kR
         +mZbqc4IQNgz9IveJBCXmFnmT/yEgtYGRwaC0ui1UTWyet4tz2YCN0LGmXDwoSQvx8wp
         4lpN2PRxmm1ENz+9Y+kFMrUcqnpik6y0244YHnmNvUQjczimzx3LX8nC68RGbbu24xXj
         vg3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FWl+OjVGtT9yNj+oc+PJr5sgsL7osptSZEWuQZQ+1+w=;
        b=7dOTfFE3Des7wIHrDW1cSv0OQ03eBN6TA5Thy/mfPAkBAPrw69B9K1aXVFL5aasAJw
         /E4WUM4OsBD7JkbbjCEeKI+O9XzV2ieR+f03JcgHMA7QJHWIsdRM3WklwKzBwgB+GaEZ
         dKPmEiEA01zhUosJ9NotuamfGZ/mupUVCJl8c332nK9VzbnvzTbisvn5KS8rg/Olz3tJ
         TeIao//C8Sh/XjLLs6xFpmBmryJZ3uY7DDWTjvrQ6dBWsKShv+qvRA70M0DCzlBtiIUr
         ZWzn+7nXoNoBirjOmLSMDCP3LeunQXKVMKh0HkTd2JzXrOoXh8DMFX9/CF664u9QZELN
         E+AA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vgkcM0DpECYd1sYjFAxQzznxq9arQgdfiaPeYfitesDzWBAYs
	9zWKtk5kyTtIVrEOZtJwyF4=
X-Google-Smtp-Source: ABdhPJwwQgB+8gadlkWgEAnLPX8aWAM/MUvusuD/+LiU+ofBm1CZxMw6b081ef0DJJEiyXH9SmRwcQ==
X-Received: by 2002:a2e:a211:: with SMTP id h17mr1661583ljm.486.1636575937214;
        Wed, 10 Nov 2021 12:25:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1314:: with SMTP id x20ls760749lfu.1.gmail; Wed, 10
 Nov 2021 12:25:36 -0800 (PST)
X-Received: by 2002:a05:6512:130e:: with SMTP id x14mr1861318lfu.98.1636575936201;
        Wed, 10 Nov 2021 12:25:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636575936; cv=none;
        d=google.com; s=arc-20160816;
        b=kIkYG7c+KaPglZ5gotnE4zduRIDE4o0ZwZCU5XmlPIcKneSgWz1RIJgexxSc+6d9n0
         GOMf7ehm9cQXyBhwuAlW3X1jfQNMaty8HxXS+Yy1iX2ZEtZ9Q87d8JdvvqFvit5US3bJ
         jqyG+R6577qHQgziK236R3jmBN6iZ75fTYoqtBYrFDc7W/2W2vD6tYaR3e9r1/IiGm4s
         f0OpQZnWEzaiMhy8km7b+0Ca8BlHTxc8u+c///eiGe8gwidv7hcf1iEUIvCuBzuCcvEe
         JDjtFCQsvFjXsCqwQ7C9rtdxwhDjBYSTA3MHK336p9SAtQ/QG1FiKphJrMs2/EBxP8md
         3WOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=eNl3zPxf83KGB6XrlK0lOZ/nCKo57ld0xY/zy/4cauE=;
        b=1LW9QUVJlBBV8DtBOemLDWs5RMEVSoFNwVptfLVMpHst6K8ymKjSOZ0Ix+kFIMMl5Z
         Jp3T8qGAwF5m7NbzuVqtRXV5csi8PV/+i6VqkO6meDAAxo88lp5u3Zg9fE258x7NQrKx
         k6CS/76O0IP2qhl9ny0skacGAKCxeOaLAYFgWHIAR80AbHc0XKqUHCAmY6YqvmR7LG5L
         G33wx4OIcFMsZTnVp17VZ5bxB0P+RZbx9jawXy7sstGqDPuAtG8sABqYvSUj2o49AamT
         6ruYD5oRp1kvnYn2o2m+8uW1HpJQEgtMyvrk8taQ0HC7XUs8W9+MmNEE5uof0kslbWv9
         I1jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e5si65054ljf.7.2021.11.10.12.25.36
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Nov 2021 12:25:36 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E93471476;
	Wed, 10 Nov 2021 12:25:34 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id AE26B3F5A1;
	Wed, 10 Nov 2021 12:25:32 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org,
	linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v2 5/5] ftrace: Use preemption model accessors for trace header printout
Date: Wed, 10 Nov 2021 20:24:48 +0000
Message-Id: <20211110202448.4054153-6-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211110202448.4054153-1-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
preemption model of the live kernel. Use the newly-introduced accessors
instead.

Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
---
 kernel/trace/trace.c | 14 ++++----------
 1 file changed, 4 insertions(+), 10 deletions(-)

diff --git a/kernel/trace/trace.c b/kernel/trace/trace.c
index 7896d30d90f7..71f293569ed0 100644
--- a/kernel/trace/trace.c
+++ b/kernel/trace/trace.c
@@ -4271,17 +4271,11 @@ print_trace_header(struct seq_file *m, struct trace_iterator *iter)
 		   entries,
 		   total,
 		   buf->cpu,
-#if defined(CONFIG_PREEMPT_NONE)
-		   "server",
-#elif defined(CONFIG_PREEMPT_VOLUNTARY)
-		   "desktop",
-#elif defined(CONFIG_PREEMPT)
-		   "preempt",
-#elif defined(CONFIG_PREEMPT_RT)
-		   "preempt_rt",
-#else
+		   is_preempt_none()      ? "server" :
+		   is_preempt_voluntary() ? "desktop" :
+		   is_preempt_full()      ? "preempt" :
+		   is_preempt_rt()        ? "preempt_rt" :
 		   "unknown",
-#endif
 		   /* These are reserved for later use */
 		   0, 0, 0, 0);
 #ifdef CONFIG_SMP
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110202448.4054153-6-valentin.schneider%40arm.com.
