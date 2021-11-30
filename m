Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRM5TCGQMGQEE733PWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 61A284632BD
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:09 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf6060520wme.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272709; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zq3IE5Oz5tD7pIQYRPvOuLqa5Rcl7EOIsjR7Vt54s2ge1wz8MNJH/S57FnFneCJ7Gp
         byFU1/kGvml5BKv3jwukd1jGVWlmCNoVBS9QSufg5xslJKA+E3xbezHbSZSRKEUy3YJw
         W8dWpqwskG6nRJ0OMQcPmQXue1xP54MlddIASK5DZkhSABemp48nNCyf5gYCzYiwHewh
         LhXh2PI/Gwbsy4U2pyGl75NVxWqcD0lQvYuGwUbmMFKAWYi8/UoMqZyp85QFaDuDS1aH
         Ca1peJGWkAqdssyGFtJr9v/r6kuciwcqWDtdP/OQugmiRmh5riuAg4mRU8FCERL+3ALS
         rahg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=aUVPSkNq8YXOH7uLD8meDjhYTPMFrEyKqZa+CCpE5pM=;
        b=UhX/opFMJs3i5Xw2jZH3GUk9vHbNRdQQF1xOfc1wRmOGSd+i1ukhPNJnJBJ882bE3r
         pxwDuFz7FR/atIEIoWcmPbo7ZCwl2nCP0SWgj7zdjMh5/MHDJ6w1h1f4bLPUnUG3laWC
         HQksc9VXn5ciaV0lZula4yHQzCM76B5AxGRs1vJSaa8U3ESC3zduqfb4wZWtZrLMdU1i
         tMjEMZ5eHwZugHtvONO8TBPvE1dk45+X19iLEDzPH9rWzmbk8DHviH4YWuHHYyPQcwEi
         t8tAnKWBJo/LQv9x7U3iBBNNhBw2YrRL7Sp0U+xgEYWuyL8Yy+1oDXTE0uBMM+0jF+tv
         doXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hs4LlI5l;
       spf=pass (google.com: domain of 3ww6myqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ww6mYQUKCYwu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aUVPSkNq8YXOH7uLD8meDjhYTPMFrEyKqZa+CCpE5pM=;
        b=beMU5Nw2qEN7Nn0srcDzKa0AF2K9Ka2A+pAWdTLMiN+5Kp2OZlSWqkvWAcOoYgnyQV
         WlNfTwuchlW1klN11qPkNV3HGNszyzFV6Q9AAO1Ef6hp6KaSplNsIOMtwxEXOGqp6bkl
         X605q5cceDHPw9oFiRMrgbphSqRSlcMQ2Ts88Z3dw4vH+echB2YSEtds0jUcgxQj3LHV
         e3t2dzBJ21cSdlYnWcDdUMVsC/2+Ob+3+QOy+dOcOjAyPob6E8nS0t3CmUOuFZStOdVi
         aM9QS6bcnZ3/VMO4GGayIRrYREMVjhRqESf1+toJmz1dVhtnhPSknDf6C14FjXoKEzhn
         6AMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aUVPSkNq8YXOH7uLD8meDjhYTPMFrEyKqZa+CCpE5pM=;
        b=mX7k85Whms2C8XHfi+kPGEnqTw4SqgEwttkkgjJF5wmyapMrfKx2oybdfJqKEk3QUE
         ukaJNVcuBhYuBWhYpsMWwZKTSq6O3ScwwG44tB2fZYTw3UjrmLxD8kH9AFsZR24F+f5f
         B3fz1r9RccC3YjSsXXbNK0IPZuilNNtj46ZNIw8g1CE2UEd0TpxoZ7RGLzFfW26RaqKW
         t/AhN57IBIkq7+5+WJNdGo6epVk0CF674KPg+Y2C2AGYAl4bvjjBljZq7sN93hJC1HoV
         THB17PScOY8ZwvWeFHRAkxSKZPcpypXKoTyGbu2xQeEhayhB/dVN5CFGyuwgquTzt2fw
         YgBw==
X-Gm-Message-State: AOAM532peFDaYWQlpmtOqKC30O60fULpm7TIniGq7RTWQWdPi3vbhcS5
	LRUeaDTvu0OBAdQsjNX+0/Q=
X-Google-Smtp-Source: ABdhPJw7kFUvUAw9BkkFG0uuVanWXUges0RcUL546dGYqeU4P1jw9AlKfuW6rwcl8/uXz5ZZFLQM1g==
X-Received: by 2002:adf:f8c3:: with SMTP id f3mr40051933wrq.495.1638272709220;
        Tue, 30 Nov 2021 03:45:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls13074392wro.2.gmail; Tue, 30 Nov
 2021 03:45:08 -0800 (PST)
X-Received: by 2002:adf:aa9a:: with SMTP id h26mr38236557wrc.437.1638272708277;
        Tue, 30 Nov 2021 03:45:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272708; cv=none;
        d=google.com; s=arc-20160816;
        b=MiTC0uKFDCwWa6mHOQbhfQBBIB6lCQt/eVPMW2U5guRfOJw3cWBzcGWyF4AOEf+XLw
         EzKzy/LBVq7bdLAomUPxIVDknmZTptKNzP/h6ANjrRL9GVW8hRyRgSgVfg3rj6vviYzd
         y2YgXAeARO0TiHIqZ9Y5JiCLNodpwa40hwGWEFZDAbeRhVSRcHKc7zFn5UzrEMu0Aw8K
         dvQdPauCRnAljuDhgCyL5iJE3ubUhpExQ6v1sgxehC17xlpZY/WzU1H6+UJO3Um7EBBF
         lRPh/FToulJeyJIo7cdIY1YctmN5bCwi5lJ+5skoM7OWv5/Wb+sgLSwZmP+36TBCp/tu
         qzGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZmySmV7nXgp7ZU44HAHRwN8PhZWnIeFNi9/5LSGaJn0=;
        b=m8nxbrB3HmuWywjW26jpDc7qiAZuHggoIgTI8ppXbXuYpFDJHmkI0caFG0W3xu2twC
         sNKRR0zRhmAgipjFvjuZNZ3ufgPQiBXK+qzBJT+oVzyk7hzo5IBS13+iLgi2Zawo5OF8
         4UrVW3QuEuKQ9wnTi58/+OkSHD87XFj8hnO3ns0eKjfyNNWvez6P+lAzoK+z1i3QbQ3B
         BTqBQAHXaySAl6fkuNx3STe9Q8kSNfAmoDumog0tgHx/jA3LXyd7snxcovOaLsyiMTd6
         23fXN+C1d+dk1znldj216pG4hxxoRvbkG1Tje3X30Ywxc73ND+qhuhho/pX2+RkmNQ9i
         h8VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hs4LlI5l;
       spf=pass (google.com: domain of 3ww6myqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ww6mYQUKCYwu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d9si847513wrf.0.2021.11.30.03.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ww6myqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id a64-20020a1c7f43000000b003335e5dc26bso10282263wmd.8
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:08 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4f0b:: with SMTP id
 l11mr625318wmq.0.1638272707028; Tue, 30 Nov 2021 03:45:07 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:10 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-3-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 02/25] kcsan: Remove redundant zero-initialization of globals
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hs4LlI5l;       spf=pass
 (google.com: domain of 3ww6myqukcywu1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ww6mYQUKCYwu1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
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

They are implicitly zero-initialized, remove explicit initialization.
It keeps the upcoming additions to kcsan_ctx consistent with the rest.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
---
v3:
* Minimize diff by leaving "scoped_accesses" on its own line, which
  should also reduce diff of future changes.
---
 init/init_task.c    | 5 -----
 kernel/kcsan/core.c | 5 -----
 2 files changed, 10 deletions(-)

diff --git a/init/init_task.c b/init/init_task.c
index 2d024066e27b..73cc8f03511a 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -182,11 +182,6 @@ struct task_struct init_task
 #endif
 #ifdef CONFIG_KCSAN
 	.kcsan_ctx = {
-		.disable_count		= 0,
-		.atomic_next		= 0,
-		.atomic_nest_count	= 0,
-		.in_flat_atomic		= false,
-		.access_mask		= 0,
 		.scoped_accesses	= {LIST_POISON1, NULL},
 	},
 #endif
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 6bfd3040f46b..e34a1710b7bc 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -44,11 +44,6 @@ bool kcsan_enabled;
 
 /* Per-CPU kcsan_ctx for interrupts */
 static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
-	.disable_count		= 0,
-	.atomic_next		= 0,
-	.atomic_nest_count	= 0,
-	.in_flat_atomic		= false,
-	.access_mask		= 0,
 	.scoped_accesses	= {LIST_POISON1, NULL},
 };
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-3-elver%40google.com.
