Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG7LWKMAMGQERYDU5QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 085D15A4C40
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:28 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id e13-20020a19500d000000b0049467449c44sf1375915lfb.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777307; cv=pass;
        d=google.com; s=arc-20160816;
        b=MH8pV72c2rlcVGTt4R5duySrtyazsOXkeMSUjlZq+4EZJbFtNtW6HGPtp9RNQZR9sv
         7ftv3i2SI9jn+U/y5skqqXpvlGTajntYPhEN6JAPchyYpwK+OEESmeFHBqAuVeI88UdF
         IfhRtKtaI5IfBUitTmVvrIXyx7OofjXlnBwYOLWNOVvlT9IJXmaBzNKhULhieoaxR5sb
         Xmp2FBzGNx2QMAgDXvZ6j3f31kY8upKu9DRjk9b9zK25kOSUhm1tO5bleqmWaRrO1c02
         +c72i8h/xhQ210ALTtjvW0UVLbG0pVDqgQ/wP03b9f9davKpHGdf2LsUKcgIdb987HqV
         CPNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XW8Cr8rBzGHv37Xaloi+WfYYV15f6L6Jtu4tg7kHNf4=;
        b=M5IAjup3cWw1fD/6wlUk2eCGBhzd5gvPY7c5LHIMnl5Xv9XZq1+eLjwQmdH9XsV1CA
         +KDdTxrA6MdKDT+AbrAT3mvpBbbVvSlzcg3nDrCEv1KaEba3fk1m3sn3pXn757lrJgdn
         UOnxZNXSrcGusEtx74Q5e3ZgFHKOqnJuRSKTlzyUwOhC02SZhGphI/7qVum1Hb7ekj4d
         cRlqzHOabmBIWn5eD2vpLkZT8i6XejPGYTzK6mEwAf9bGMxWfehnLZXnHxwDqKYiPppD
         ERYkBJ4eQPYkGHAQQNgIE5nZJFP84aaT1tbjQ9MMqZxSZlyDQUwCANqnQQIkluEZskr+
         nvhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DUROuHk1;
       spf=pass (google.com: domain of 3mbumywukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3mbUMYwUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=XW8Cr8rBzGHv37Xaloi+WfYYV15f6L6Jtu4tg7kHNf4=;
        b=BFGm7AYR3vPS8ngw+z4SR7PhNw24jsC6vijhy9DbI6FK5Kd2lUHQMjoeeAs3xo+Ha1
         DM0Jmdpqro+5Mz+O8RohfYbPBqTBEfD2nCi2VlfziE2JKUy4Q+/zu9UuR1x57YOWwBnM
         i9Ybu1gh6VhTKYSW5B5Q9xBRMQGZLpzCBen+UQsCynzA/+YVxOoe3987Mudxy5bBxcP1
         bDILz6AZMfdgDPwFIH2A7EpzYtuzub1lrWcHDhZAUrCtUFdpzNqzX4TQjTOpG1zlzqFD
         2pFDimGVX+oxkvMo+ammzqwLM+Gryzn+6ZuapLmsH0QJgpGkVdWWl63tIQpcx2WlmCQv
         J1ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=XW8Cr8rBzGHv37Xaloi+WfYYV15f6L6Jtu4tg7kHNf4=;
        b=OgyavIHHBC7DUIbrvDTHQNprXa3dbiTtn4HpQChw3JW6Sg1LwjC5oaF7GdI0btio3l
         2kRKBJ94wYhPuVCTvPl67Z1uBudb4PRt7rx2selLq2zw+znQ2wopj3gdY4jvTYkev02l
         7F9HjBSsMEJth3Y4hZXr8+WZNcjVK0UgAfYCSa7tSDQRpruXCvlc8DcV86mGV3dkkqJV
         oyRDjQkUPIA3Ij0EjtdPM1O/DGbvVrcc85MDNcv0IcNRce2IXzPvTWpI/eyhHgilbFmG
         TJWC53MMkvtYtsV3+l3x3LQlIWEsPRqsnbiWXbc7avgO1zK5Etua/dvVUqA0ofbnUTE+
         djwA==
X-Gm-Message-State: ACgBeo0q9Wi5UJqwUG7ORsrAk9ptr4HxWcjo1i7X6D1Awq3I0+Gk8+45
	OylHf7zcB1eAiYfdY54N064=
X-Google-Smtp-Source: AA6agR4mwhyIHhLybmdTN8HuRp3EkX7l242FSYXtHE59zg9ng8uYVcJL+/n+/3m13V3dbzAFVgM23Q==
X-Received: by 2002:ac2:554d:0:b0:494:6d3c:5895 with SMTP id l13-20020ac2554d000000b004946d3c5895mr1392204lfk.319.1661777307555;
        Mon, 29 Aug 2022 05:48:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls4760660lfo.1.-pod-prod-gmail;
 Mon, 29 Aug 2022 05:48:26 -0700 (PDT)
X-Received: by 2002:a05:6512:1395:b0:48d:81b:4955 with SMTP id p21-20020a056512139500b0048d081b4955mr6011670lfa.307.1661777306148;
        Mon, 29 Aug 2022 05:48:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777306; cv=none;
        d=google.com; s=arc-20160816;
        b=LpM/hw1sGeAa9O0MMOnDLZ/z+rgkF/vvabgHO1cJpiYQNjuTpaHDaa8K9O2sWO4ECB
         x4eJ4630NDbLFU1pRHzpGFIzTF7f+ON2pIreB6fHw5QDhDkkCJu087cCGgT7cFbn8yUK
         eTpqwOczlZj+TV+E9jcwANBSsqgzGdnvdPaT9P3mhCpwsblY0P//ShyGKvg2x4XWhbeE
         boAlYpIfVK+ehEzJO1UsSNeTB5vXUC1Ok+nSE+w6sUZUsyBoIbg6XOoq3Nc6rgwvcJ6F
         OppCedYynF2fJrrl0xUnk24uXelvZGPonqLuqkG5H01EAqKY4ftcNveLVPPuv8APpYMK
         t0Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=o7nFvD+bAzzd8hTxdy6J5SFI8QAvwQGuiGUQWboy0hk=;
        b=GC5axLjfcqAwQyjf6a09fwIg6eRWFn4EvoGJis73tHPplYdjxr/6rKAuXLDng/H4gU
         8IN72zYFMaXl2cRUJ1KC+Bh6XhB6Q4wZp5Y0AgmCUlFPsqMeq0xlN4zykptMkwI45qYz
         pJdna4pJZ2kNtUWSF6wz8vq05fnAkSzil3PzET97FpI6OREXOHkr2+zVp8BR9+qkFbVT
         Hoc0VhJ6ik32Pm9ljfLlcHH1Xehy3AusDRwFSjIPJssc6ErtZLa/w4AqOTozgFnROP55
         h0e4yEt8rzfu/KJm+tkPEVPrDIrJhpUO1e+QsMnVtiSivGiPeojIQkwuwUMj3VAx0SNI
         5jvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DUROuHk1;
       spf=pass (google.com: domain of 3mbumywukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3mbUMYwUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id m18-20020a056512359200b00492f1480d0fsi309857lfr.13.2022.08.29.05.48.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mbumywukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hs4-20020a1709073e8400b0073d66965277so2218232ejc.6
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:26 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a17:907:75c6:b0:741:75a0:b82b with SMTP id
 jl6-20020a17090775c600b0074175a0b82bmr4672915ejc.465.1661777305817; Mon, 29
 Aug 2022 05:48:25 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:15 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-11-elver@google.com>
Subject: [PATCH v4 10/14] locking/percpu-rwsem: Add percpu_is_write_locked()
 and percpu_is_read_locked()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DUROuHk1;       spf=pass
 (google.com: domain of 3mbumywukcvy29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3mbUMYwUKCVY29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Implement simple accessors to probe percpu-rwsem's locked state:
percpu_is_write_locked(), percpu_is_read_locked().

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v4:
* Due to spurious read_count increments in __percpu_down_read_trylock()
  if sem->block != 0, check that !sem->block (reported by Peter).

v2:
* New patch.
---
 include/linux/percpu-rwsem.h  | 6 ++++++
 kernel/locking/percpu-rwsem.c | 6 ++++++
 2 files changed, 12 insertions(+)

diff --git a/include/linux/percpu-rwsem.h b/include/linux/percpu-rwsem.h
index 5fda40f97fe9..36b942b67b7d 100644
--- a/include/linux/percpu-rwsem.h
+++ b/include/linux/percpu-rwsem.h
@@ -121,9 +121,15 @@ static inline void percpu_up_read(struct percpu_rw_semaphore *sem)
 	preempt_enable();
 }
 
+extern bool percpu_is_read_locked(struct percpu_rw_semaphore *);
 extern void percpu_down_write(struct percpu_rw_semaphore *);
 extern void percpu_up_write(struct percpu_rw_semaphore *);
 
+static inline bool percpu_is_write_locked(struct percpu_rw_semaphore *sem)
+{
+	return atomic_read(&sem->block);
+}
+
 extern int __percpu_init_rwsem(struct percpu_rw_semaphore *,
 				const char *, struct lock_class_key *);
 
diff --git a/kernel/locking/percpu-rwsem.c b/kernel/locking/percpu-rwsem.c
index 5fe4c5495ba3..185bd1c906b0 100644
--- a/kernel/locking/percpu-rwsem.c
+++ b/kernel/locking/percpu-rwsem.c
@@ -192,6 +192,12 @@ EXPORT_SYMBOL_GPL(__percpu_down_read);
 	__sum;								\
 })
 
+bool percpu_is_read_locked(struct percpu_rw_semaphore *sem)
+{
+	return per_cpu_sum(*sem->read_count) != 0 && !atomic_read(&sem->block);
+}
+EXPORT_SYMBOL_GPL(percpu_is_read_locked);
+
 /*
  * Return true if the modular sum of the sem->read_count per-CPU variable is
  * zero.  If this sum is zero, then it is stable due to the fact that if any
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-11-elver%40google.com.
