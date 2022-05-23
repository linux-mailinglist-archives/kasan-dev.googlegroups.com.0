Return-Path: <kasan-dev+bncBAABBDF7V2KAMGQE5ZVROZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5255553116D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 16:51:57 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id m31-20020a05600c3b1f00b003973a563605sf3133525wms.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 07:51:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653317517; cv=pass;
        d=google.com; s=arc-20160816;
        b=OG+IqQwM/zLsnEHkGfEq+hFoXWlyI5kPOijWRNr0By0F8jaK99sJfl7E6/3CRsJESp
         tAZsgNxlEjhOPonBQjM7EguIIyu8tOFLUoYqAjqq50vQIWb7qwKCfSHEVMV9M1nwJmFq
         v1BzuYAEeBEETo/QQR7j3RFHhCUXMWIuaqHVDmTNPEbhw4fxcmhQwMBwaVDR6u0h/t/5
         CQ2F/h5pQV9O0EHHc+5duoT9B6cWeFrCf268QjFNvENXhJ+tFTWB0F+OrwubgHeKNFnS
         0h/2m4Z9t8SIKnnE6Tw4KfZ5vSMcaSaubJU/O1A1PRNNd34PRe0eRkx+6zws1mw7SVB1
         J8ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WO5tCXSjyLDkRo9U+VCt7XFjbiGNP73iAoldo3bU1jg=;
        b=nvnamL+RE5/hvbeMKFEfJmh3K+PZLsMJmigBqFnEHtSxHDluwwUaP8CC9I7MoAMhZE
         k6uj3crSCwT4RqwmCdiyTzo+I4ziiJMZwk3BtnYSeUUHSmsx3yBLMILs8kXvzlsZTcEl
         IR/QbjXlwpZgt59QFOdaQbg7dBzR3pg7izLg6yJk/anl9u3rXX2CX4ZSTeT0gEZHKTHi
         NFq5SAamcYh3uJyHRMVCcyfo8OPRI1dNjfABJa2Y1GeZ4BFlF33lxoKjRYhTCJIVOyMl
         KeLGQS4b07irSu99r2jfPv6Y6D3TAX8UIi2fxWDxtAZWGHIo3TrPvGGp6zQvHPt7PT/w
         alxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RIxsqyTM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WO5tCXSjyLDkRo9U+VCt7XFjbiGNP73iAoldo3bU1jg=;
        b=bepY5ECekVtgZpKyFzsoDjMvj8UnP1JB6+5AMs1Pk5q6vMjrmpZ/DLl9Vx8AfiUdPd
         xWbS6xDU9MGbEtKvaQgQFDl4EqZxARRLXyyxZs07RD8ZVOk79enEL8zZbbHPMa67HeCR
         lEZsN069orsYwzbLhLdIDsRccMgeqxxJoawGIOeWlhDJOsvTBMLViV5Fyq2ueSmquSXu
         jsMxWFyWKxELYaswvG097jBMQs4riXHehtZQyA/UFe4Y0VCh6Zm60tKiUtLZhEf5CemT
         rX2ZxN1kYfnjV9FvcLgu6zoQgZuhVKIxdeRkPKqcBCqvwAuWHC/oNwdxG2vARs7bwGnb
         LK9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WO5tCXSjyLDkRo9U+VCt7XFjbiGNP73iAoldo3bU1jg=;
        b=FZJMgK0cmmA+AW/xz0vNn87jaOwilqGnZzvxw9S+rGsp7sfXIZ47HXke+73T8NzjQ4
         Ca21ImB6LG7kJ0UnGyCJtPilTr4A7ON3mWnrOemc4vjqGbxDLty0VUykabDtvd7pAeKl
         rZYeWzEXZccCqFkDXQ8LfNSGBXlib8xo0aUaGnBTSeqTUgw3LNZpggUnoK5hsVZiEO4O
         W4+jxc9IvaFtKv80vdoQNK9THRdFRpNT+sQl4FOTVE8SlMCBlYxbYPtSO2CAXUbnmbDy
         q+wWBesFUXtY7cTfJa173QdgebluysiX5cASVx2OzO3iKD/g27mpCL+8leHdiTLnIUCp
         nJkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pp3+Qfjm8dKzXLJfccxLj3FbclwTSsARSdfYZ6RIDY4RHxpHG
	6ap8TwVRrG8lg+dKY4B3Rf0=
X-Google-Smtp-Source: ABdhPJwCgU2xK7F+832Mh5tAsHEeRFOmBSM7XdI8VHRfzmKpTEsXNIpSMvAbMvseADjtW+ehtjU6qw==
X-Received: by 2002:a5d:588a:0:b0:20e:5d56:4f18 with SMTP id n10-20020a5d588a000000b0020e5d564f18mr19601830wrf.140.1653317516943;
        Mon, 23 May 2022 07:51:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e0b:b0:20e:7a8a:8c81 with SMTP id
 bj11-20020a0560001e0b00b0020e7a8a8c81ls12212656wrb.1.gmail; Mon, 23 May 2022
 07:51:56 -0700 (PDT)
X-Received: by 2002:a5d:6481:0:b0:20f:ed13:f28d with SMTP id o1-20020a5d6481000000b0020fed13f28dmr306350wri.719.1653317516146;
        Mon, 23 May 2022 07:51:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653317516; cv=none;
        d=google.com; s=arc-20160816;
        b=0QXyOWxNAYQhK86dN40TW7iuc5VfGTIutUfAknRAG+SZVzs5n94gsyzSYDMI9ejINX
         ZQsORxdEoLj9rzGwFxR0eub+vSWciWEhdcXGQ6GaFYJqP1hOAHvPPx7qJAGVirbiRXMr
         b9mOk5aEwgcohrKZxitBzcO+RBjftU5WFnKHsUcYgLpVjOx+Kguvv3HJPtV/O9OD7sna
         kOnNQmrvel5dNqQkX0pLBl5qj+9nrC2Or+3x/4wankhF/svOER9tj4qC/W1qw8WywsPy
         CoRj8u8OyddTDn4vevx0zrDOWK9PtxAogIV6KgeG1PXFT6XEdkE4pd4O64uLWUJVnd6c
         kgAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=HrBttuHNouCVJd8EaofzeEzAduf8tjD2M1BbP/WSMfw=;
        b=T4sfb8D7rD6rvVdNLa8lyEkOQao8vXZMf0OPW1FF2Dv3u4xdeWQg2RZ6DT6fd+J98/
         vUtgBXpl7CWJCSDxkqh9krrah/vg5V7QgzMpxqzx4RPG9yZKNg3r/RkBWI0hJohjRh/i
         eC41RXstkacGeZcTSTinQNldCCPnpYMog4PeQ18pbN25tfQaes5jh8yXNTDDiw38YL+q
         OvAU/RhXJRj8xpXBxTwjzLYklKDNM6wgZd6tifVxTdu5CP+03LzypMsIqFmSGHDQUbLl
         UNCN/+eFK4CyaVffjQ96NlTI876s4av4c4ZMoyjiLSUmeDiM4KBbkXxV1LaDzGu6tdNh
         7SyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RIxsqyTM;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id ba11-20020a0560001c0b00b0020e674a0d19si204607wrb.0.2022.05.23.07.51.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 23 May 2022 07:51:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 1/2] arm64: kasan: do not instrument stacktrace.c
Date: Mon, 23 May 2022 16:51:51 +0200
Message-Id: <c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RIxsqyTM;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Disable KASAN instrumentation of arch/arm64/kernel/stacktrace.c.

This speeds up Generic KASAN by 5-20%.

As a side-effect, KASAN is now unable to detect bugs in the stack trace
collection code. This is taken as an acceptable downside.

Also replace READ_ONCE_NOCHECK() with READ_ONCE() in stacktrace.c.
As the file is now not instrumented, there is no need to use the
NOCHECK version of READ_ONCE().

Suggested-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Updated the comment in Makefile as suggested by Mark.

---
 arch/arm64/kernel/Makefile     | 5 +++++
 arch/arm64/kernel/stacktrace.c | 4 ++--
 2 files changed, 7 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/kernel/Makefile b/arch/arm64/kernel/Makefile
index fa7981d0d917..7075a9c6a4a6 100644
--- a/arch/arm64/kernel/Makefile
+++ b/arch/arm64/kernel/Makefile
@@ -14,6 +14,11 @@ CFLAGS_REMOVE_return_address.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_syscall.o	 = -fstack-protector -fstack-protector-strong
 CFLAGS_syscall.o	+= -fno-stack-protector
 
+# When KASAN is enabled, a stack trace is recorded for every alloc/free, which
+# can significantly impact performance. Avoid instrumenting the stack trace
+# collection code to minimize this impact.
+KASAN_SANITIZE_stacktrace.o := n
+
 # It's not safe to invoke KCOV when portions of the kernel environment aren't
 # available or are out-of-sync with HW state. Since `noinstr` doesn't always
 # inhibit KCOV instrumentation, disable it for the entire compilation unit.
diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
index e4103e085681..33e96ae4b15f 100644
--- a/arch/arm64/kernel/stacktrace.c
+++ b/arch/arm64/kernel/stacktrace.c
@@ -110,8 +110,8 @@ static int notrace unwind_frame(struct task_struct *tsk,
 	 * Record this frame record's values and location. The prev_fp and
 	 * prev_type are only meaningful to the next unwind_frame() invocation.
 	 */
-	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
-	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
+	frame->fp = READ_ONCE(*(unsigned long *)(fp));
+	frame->pc = READ_ONCE(*(unsigned long *)(fp + 8));
 	frame->prev_fp = fp;
 	frame->prev_type = info.type;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4c944a2a905e949760fbeb29258185087171708.1653317461.git.andreyknvl%40google.com.
