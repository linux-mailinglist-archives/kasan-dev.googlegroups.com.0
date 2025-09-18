Return-Path: <kasan-dev+bncBC7OBJGL2MHBB25DWDDAMGQEMPVIM2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id CE3BCB84FDB
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:36 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-b041abd4854sf111534766b.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204396; cv=pass;
        d=google.com; s=arc-20240605;
        b=fbWWx6rWV2J98IBXUT3/sqzUnYI4JfseSFhvWiYQx9NEpZ2peMfIN/ZlLTCbNY4mKr
         IpZ9GM+nS1xiLXyNuvkpfpK6RrmPm15yy1KUXTo9Pw2RXvTIbQ0De/g6BdNQiDd8+Exl
         xjFgphvS8lED/VFKc4NsAlpsYAeTFAmI0xC6mkmX3YhlydDxA+4QMtYws6O7r/mkuEEG
         +oupn0GNwbomPDOZVmIlwRVW7F/9FfIA8lhW2xJfPTSGFVEHYsyI0pXWaMa8J2aOHqzO
         iQoWBfCi/wAPjKoTvkohCEzLcnAZ+ZJP8KrXd4GNun3qUK5V2sOH6GpXkARm3RlMfC50
         6QbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9B/YOkkaU3Q3u8L8u9cHbR1wjNHWsnyYzlM4L4kYGcA=;
        fh=NyIKLTLKOLGHfzWZ6qNy3P+PlC+c/emzWlMpqLyQpl8=;
        b=iwX3XR8+ZkUyjBNh8KboB3OfZGKR+GCicw7HWheSfmmzx7vfWddQasUKEyEwfWBGWm
         GMui//5oTlGdHv0yJLs5gNCOkGGKLOH4h0xbu+f9miRTAmz130phIaJUD2LQvpAnMUu5
         QoSQglis4UFeMUrKAJWG/TGhx80qWzD03bo17Yu4CcA8vKgtlSf4CkRoa1qo3XzLpj9u
         7L9Vfm5QxEU/9YhIsAtdL+5fMMB3AE8j67TvEvgWWP5AWzfQQ7jwuzMlM2VMQkPzLy3N
         fWQa3/pLC8YV6AdUyB5bSip1FMh4a1ijShPxtGRrplaOZX691YmWqm8t8GKtqEAy5301
         wZSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iHpbM5kg;
       spf=pass (google.com: domain of 36bhmaaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36BHMaAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204396; x=1758809196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9B/YOkkaU3Q3u8L8u9cHbR1wjNHWsnyYzlM4L4kYGcA=;
        b=qonoAsmiQbh58aBcxspdtNgQvxuyPBSwAQF1nWAYoC1O5xzrjG1jhkldkMMO4V5zAc
         4uNijGbXnG9tyz9D73pC52Q8JwlnggDy+bcKDywHIujgtFd//y5q5cLQce1h1gnT7hKq
         rxcURXEgwE997ZLXGc6Pg5RaEEss/gUL0nu6gm+/+N0kNrHBC2ox9YOJNbXVJf39xoVQ
         ffMf9OIDHP2IFb5PVMNsvbJreU6IzYivgKNxzze+0cG7Oo3KYYR9CHBG6ZfIOaDebH2E
         jSqPz3hpPYRcNcHbhP2KAQECmFgK3z0um8sgUXL7YjdCK2hpkYuUxVqYnQ1jbYvm3nBO
         B1cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204396; x=1758809196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9B/YOkkaU3Q3u8L8u9cHbR1wjNHWsnyYzlM4L4kYGcA=;
        b=SljUA06QXRm3N7wm1RCtnjpgglQD9M3rS+Ph6iYA2Na+UeulUnUNVBsy5LFMFJM5h0
         bXbqAA8ZEUxGB/hav3c9KB+cLYZtya7jWuNc9Bsf28nZicVulDwnoz6odYyRbR4Ey32o
         swRpY6RLmG9L3xvoIrzn9YFD6oCHAUiPoXJSILrbbZiszhcOBU71ZrYlmtrhZKDRnYP0
         ojrAZJtlUg9xa7lmSwt9j7BuTR7bTCcOgMcq2xj9yzURY+XPSpXEMS+j0wmaq5pxMcFH
         wbVqZQwXD0HLpcITunM6RHHaL3WCqO9wsVSLiHna9LlNTndCAzhI2prGpFUI+jLtSyzE
         62OA==
X-Forwarded-Encrypted: i=2; AJvYcCVBseYiYBOqLc3ZZoUkEe6BeRG2hV5/QoFENcEBRB3moT8t6BbPuN1PtL4rcO+8CWBpL7/fEg==@lfdr.de
X-Gm-Message-State: AOJu0YxfKRqnlleJFO3lnbjWkHlXHnCmTLtYJo32LUv14S2iXaOwniMz
	o4Xz99F7U8PnhEeshrTOx5XV+81ewc4oxQUqTMAGGk4q6s/8OteCXqP+
X-Google-Smtp-Source: AGHT+IFwJoZUmsejnR4PjranSEEW9xXgJiTTEt0VMme9pBYmvy2L2ycxxwd7tDOQ0pElbmdJnwB2hg==
X-Received: by 2002:a17:907:3ccb:b0:b07:c94c:ba16 with SMTP id a640c23a62f3a-b1bb86d7023mr667385066b.4.1758204395857;
        Thu, 18 Sep 2025 07:06:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7vn8p8IEm7xsAuPL38LGf0tOySRNdNNELq3zpYbfStRw==
Received: by 2002:a05:6402:d4a:b0:61c:d171:4f48 with SMTP id
 4fb4d7f45d1cf-62fa773b7afls642118a12.2.-pod-prod-01-eu; Thu, 18 Sep 2025
 07:06:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwFim8lbSb+y8j8RQuyIcHVzQmKgv+kvg/xTTvNDRPODtQdsz8GfIICHjlrttTpSPJ4OP2nJh1eRU=@googlegroups.com
X-Received: by 2002:a17:907:3f1a:b0:b04:7107:9758 with SMTP id a640c23a62f3a-b1bc0e86595mr666588166b.43.1758204393090;
        Thu, 18 Sep 2025 07:06:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204393; cv=none;
        d=google.com; s=arc-20240605;
        b=Df79IAA7Va+gD0ELI0CYqoN6S0P35CPOnXMBROdLQ2fw8d1+owLs4n8wcpk5E0648u
         2R3X5p+SW9ySt9W2t1jLrHaerTDvs0Rvaud5mW+6cSc+DTJ+ns3r2D6QItiIuEjOgsYd
         MoavRMxoLADTTIp+7AdZg8s3/kV/g0CnHlZ0SOdTbQ5MZ1VQNXyj/sVxOYWgPltLFAE1
         4Uz0lUGZ+U1DPxozp5MLmCPocKyKZrABm4+poVctpj7+/NRuzP287xKzC18c5fUZedqd
         /a022mUI8tNrueP78K1CaSB3+toM7nG/mZhkxbJdrCpsZP8WclU0SFwEL5wMa55n31Ry
         yMJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=i8w2QAEoYIuf5bb1DymlH6d9mwXwlVHoZjcMp7ct6B4=;
        fh=LGXhETKjFspYVuwsl0WbIkh5mdxLUbWnY5T060E6wBQ=;
        b=IuwvvS6zwWJprCvPMfzGDsV3u8S+c0iLwTFOFpksYhyR3SAxNw5uU73lKq/Tb7L0ps
         GjefjDMFNoilEi2B2dzg6gyv26ZQtAsvkknfXmyhdjO6VIE5W8JkcpszAc+MtdPrWfuk
         WxzWEgtUAIjR5+LGpfQysUvaYZA/t90qUBe/G4uXRQo8/b4kp4ac5bL00FCe5R9NdP6m
         vqvCsfL/X5yRzFPEjry3PBU3eBjCd28DLGLHFJsQAzAwg82epUlOe+dC133qfsmdVaWP
         6Pc0u2+gz24720lB0NK02sf4etIO90M36gUpRzKD7LDMY5yYBHS+kTJfXi19GPrJ3djM
         szcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iHpbM5kg;
       spf=pass (google.com: domain of 36bhmaaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36BHMaAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62fa5f34c70si46682a12.5.2025.09.18.07.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36bhmaaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3e98b439450so522307f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxgpIH4oy5//vJsA9ZOJWXKXRENejNAU4/LaDyTrUhO7i6NTt6WvTFRQI65I+6hEwyIWPcWf/jsAc=@googlegroups.com
X-Received: from wrbfr7.prod.google.com ([2002:a05:6000:2a87:b0:3e7:6467:c475])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2506:b0:3da:27c2:f51d
 with SMTP id ffacd0b85a97d-3ecdfa5f1bamr5332225f8f.45.1758204392094; Thu, 18
 Sep 2025 07:06:32 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:35 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-25-elver@google.com>
Subject: [PATCH v3 24/35] compiler-capability-analysis: Introduce header suppressions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iHpbM5kg;       spf=pass
 (google.com: domain of 36bhmaaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36BHMaAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

While we can opt in individual subsystems which add the required
annotations, such subsystems inevitably include headers from other
subsystems which may not yet have the right annotations, which then
result in false positive warnings.

Making compatible by adding annotations across all common headers
currently requires an excessive number of __no_capability_analysis
annotations, or carefully analyzing non-trivial cases to add the correct
annotations. While this is desirable long-term, providing an incremental
path causes less churn and headaches for maintainers not yet interested
in dealing with such warnings.

Rather than clutter headers unnecessary and mandate all subsystem
maintainers to keep their headers working with capability analysis,
suppress all -Wthread-safety warnings in headers. Explicitly opt in
headers with capability-enabled primitives.

With this in place, we can start enabling the analysis on more complex
subsystems in subsequent changes.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.capability-analysis        |  4 +++
 scripts/capability-analysis-suppression.txt | 32 +++++++++++++++++++++
 2 files changed, 36 insertions(+)
 create mode 100644 scripts/capability-analysis-suppression.txt

diff --git a/scripts/Makefile.capability-analysis b/scripts/Makefile.capability-analysis
index e137751a4c9a..76ef93ce2466 100644
--- a/scripts/Makefile.capability-analysis
+++ b/scripts/Makefile.capability-analysis
@@ -4,4 +4,8 @@ capability-analysis-cflags := -DWARN_CAPABILITY_ANALYSIS	\
 	-fexperimental-late-parse-attributes -Wthread-safety	\
 	-Wthread-safety-pointer -Wthread-safety-beta
 
+ifndef CONFIG_WARN_CAPABILITY_ANALYSIS_ALL
+capability-analysis-cflags += --warning-suppression-mappings=$(srctree)/scripts/capability-analysis-suppression.txt
+endif
+
 export CFLAGS_CAPABILITY_ANALYSIS := $(capability-analysis-cflags)
diff --git a/scripts/capability-analysis-suppression.txt b/scripts/capability-analysis-suppression.txt
new file mode 100644
index 000000000000..95fb0b65a8e6
--- /dev/null
+++ b/scripts/capability-analysis-suppression.txt
@@ -0,0 +1,32 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# The suppressions file should only match common paths such as header files.
+# For individual subsytems use Makefile directive CAPABILITY_ANALYSIS := [yn].
+#
+# The suppressions are ignored when CONFIG_WARN_CAPABILITY_ANALYSIS_ALL is
+# selected.
+
+[thread-safety]
+src:*arch/*/include/*
+src:*include/acpi/*
+src:*include/asm-generic/*
+src:*include/linux/*
+src:*include/net/*
+
+# Opt-in headers:
+src:*include/linux/bit_spinlock.h=emit
+src:*include/linux/cleanup.h=emit
+src:*include/linux/kref.h=emit
+src:*include/linux/list*.h=emit
+src:*include/linux/local_lock*.h=emit
+src:*include/linux/lockdep.h=emit
+src:*include/linux/mutex*.h=emit
+src:*include/linux/rcupdate.h=emit
+src:*include/linux/refcount.h=emit
+src:*include/linux/rhashtable.h=emit
+src:*include/linux/rwlock*.h=emit
+src:*include/linux/rwsem.h=emit
+src:*include/linux/seqlock*.h=emit
+src:*include/linux/spinlock*.h=emit
+src:*include/linux/srcu*.h=emit
+src:*include/linux/ww_mutex.h=emit
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-25-elver%40google.com.
