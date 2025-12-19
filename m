Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAPHSXFAMGQEXCEVFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id BFD7CCD09AD
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:14 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-59a1b74aed9sf399336e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159234; cv=pass;
        d=google.com; s=arc-20240605;
        b=J7T2P7ZUZZEyLkOQKYkdlF2+vbqK5hPomNjlBCw21D3vowvuJOlOsI6Up0LtWHVDfG
         5xLtTb2M4VELVN7EJ/xQ2hJHyU58XnAYPGpt7vzUhQKx1J+r43/vszKFWvqhbfY92UJi
         Y2TW4KmXIRVYVx9WP31Grb+8SkMldBKgPu/i0wpMh41HhzYvoDj7h93L5e+OPlUTa38P
         PouOyX7DEbk/amAiXM9u40g5Y215UhT4fEo0uSzqPeh4jPNB956SLF0FmKQ7IjsrKJV/
         TraAcfVEtdogcRYadpG+mO4JUJPTuJ+JLdNG3zo7QEhHicc+g+y7e98SOABO+iBXElIh
         3ENA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DkWpgIbu9x4UopiH1zx2u4AfN8Iyxn4S4CoWqZd/Fjg=;
        fh=+x8IL5gSxpmyGOCtYUc95MpA9/T5iYo+WNnAxTZFW+w=;
        b=ZnR7yRAmTFBlnUAD6tACxWpLVHVnnU47oIn9oZiLLF+g2ngj/MA5BWGLiVHcRBPY2s
         ZEhKXkfXLjOQ/048rm7hSJ3mUp71WUAP8GxokCcwwto3wK5B//YlhQCRRJ15O2e/k/9x
         dnKD4ivaBmsdvKN8DP+DyjsUgIrNafxnsic1ctmcWazY4VXdB6bYxX9U7GOyLtQVp6Gf
         QbToKv5sinwa/SphgrXqy2DJEDbXHX4QTyroRX6cNyJI7/UYl3kAQUAm1H+YX0IphXuu
         mtuvm5606RCDH42pDYeXYsFJESThpFYAg7EzNynPzBrl/LWkZ/il8SvnBkVasN/U4m7w
         03QQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k+iCIYpV;
       spf=pass (google.com: domain of 3fnnfaqukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3fnNFaQUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159234; x=1766764034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DkWpgIbu9x4UopiH1zx2u4AfN8Iyxn4S4CoWqZd/Fjg=;
        b=gMr6sWpGoBb9vzp3bBh7DDyN/Ks/vI1TcBwqYkNOGpZyyEb5F6cjZ72vKHnmer/XzM
         Oa3StB/HXXwQGXxO7dzYU9u5L/78eFlelWR5VHT1vykEUP2k3LwhfiEN0xniWGaTNt5G
         hHTG0SxhrVdlrYA4Z3twWinemVcIbypkvINsVg+emyzabgqvv0sAWe0bt8etDh5MdzXA
         gDrv6Ub9wDCvyTRlqlKZ7iyBpqYlZm/oj4IuUVbtmNoPi0L93+ZCyr0mwrrulk9Zfb7Y
         XhqbrYvRSS6scAfEg84Lf/dpir3YCI1XnKFYLtlFoK6i6k4sETAM33IRcWtqN+0XCRoz
         tVQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159234; x=1766764034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DkWpgIbu9x4UopiH1zx2u4AfN8Iyxn4S4CoWqZd/Fjg=;
        b=JkH422QLBU4QJLTWAGBmTgm5E4uDIXQgeVsLgJvtHXtSFj1BXJ66gFbape9R7MOstk
         C+sWFwzOJUNDNC8ej4JNG+yHV429f87vvFGcF1XLi6pFGQjFYBOYfrgE7J8DPzj6J+hx
         wOUtaO+To3DiyszN8IWzmR7wpUUj1hMcrgBmIFAdPCdL1gMj8OlOJKAkJYtPQmMt7WfU
         4Q8e1kW+Y3gt+Zl9d1zCYkBya/zd9lJt95rJnhgOMWjVi+QbnF2ipHt6TnIpjsTEDI8s
         N0CJ3Th59FKUwaXl8yTMN1g9HiH5lYD62lU5pnTXdFEOneFUYdyv7s/WFyi8O4Z0tVUY
         rNfw==
X-Forwarded-Encrypted: i=2; AJvYcCWQjbMeRHcWUTumoeW1bMQABUC+S3fExhd/cOzaSOiHTUraXrUX4O87LtdpICoZF7TwEJ/KRg==@lfdr.de
X-Gm-Message-State: AOJu0YxqlfJ1BADAscqft7yP3LK44TX8PQA/oXhJYC+n4bv6F4hed33W
	FyHiL7VticGzyAlRdRw/rxu5Y07x8dp47+Vxjj8M40Z8eveRq1ujybge
X-Google-Smtp-Source: AGHT+IFp89ntaRz0tY3ATzp6E7NW9Js6HGSZW0fGRivzEhI1EGe/Yp6No6ydESxChL3u8Dkok+n9dg==
X-Received: by 2002:a05:6512:ba2:b0:59a:1240:dee2 with SMTP id 2adb3069b0e04-59a17d77452mr1284836e87.12.1766159233909;
        Fri, 19 Dec 2025 07:47:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYoGf+J3aer5LqJhOAzCYRs3I8yTu7zySd8oIbbU9wJ7w=="
Received: by 2002:a05:6512:ba2:b0:598:f802:e2dd with SMTP id
 2adb3069b0e04-598fa391dd1ls116466e87.0.-pod-prod-04-eu; Fri, 19 Dec 2025
 07:47:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVv79tdfbSNuKVzCTpBMDII1xRHxVw6Q0eDvd0aSCHeY3hVy/+xTAMBaQrQvEP4tHOkD2LnCaMqpPg=@googlegroups.com
X-Received: by 2002:a05:6512:61d1:10b0:59a:19e1:3c86 with SMTP id 2adb3069b0e04-59a19e13ca2mr661813e87.30.1766159231041;
        Fri, 19 Dec 2025 07:47:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159231; cv=none;
        d=google.com; s=arc-20240605;
        b=i8IMg4DaDUCb/k9P98akI1JGLd53FX59nECuC1+GM1yAxiJ4c+700rbtIvtfD7HymE
         dpfWnVvVZuSHRguiR3keZWL78pnh4LZ/wN37NsgAEr94fJwoW0xpdkeMWALlPcXIBUcf
         AFellarfuf4MShkut5kfHU8f+YPBqcPeHCxckm5b9l5+cNwfe9YpOlVK+6VubRQbg5u1
         H3Tv0++sb0qTbWdtu582AwdTkgfH1V4w0uPxBAkG6kv6Tlv9m0ovkFlZtyqmZVZ652nI
         fExjordVe4AOpEUaOCKiKBubKgO8LBwArHTrnANqp5QmiZlyqZB3vVfd3F7ZzxVlhtNz
         Hx7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=J3sgEnhMWMLOYj1/OofGWKavVFtW6YP1ndiLQ0rOu/8=;
        fh=5C99ednVRx2X1qTl/l3jJM6BCQAFahusMTeKThbHa9o=;
        b=dMn2M9fExGwET1yE5qiARZgdkzufVnnnQ5AAO4mbLDnn+tmzxdohxREe74ZL1LprBB
         7mwbQ98Up9IUgAz3OzdzojGqW1KwFDxvTWiPBJAhfSoIMJGAj4sSJrm+ziFb6jFUqrb8
         ZZ2i57KxTsf9RRXJXRWN5jveyZ6eQhu9mOTi+B741RZ/+TrSQF+sU7c32EKgLwI3NQeR
         FgtClD0y/BmeYlC5VtGU7BaUk3q0J1b5nqA/c8MKIbnUEjSyPYvmd/pHWXe6PC3+BO7L
         k5d2xMVbw64goaY57/UQ42Szh2x2XtfHMa1dCuhvBXI6Zb7C3NdlmLZIEg7YPo4Xru84
         I1Cw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k+iCIYpV;
       spf=pass (google.com: domain of 3fnnfaqukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3fnNFaQUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860d04bsi83502e87.4.2025.12.19.07.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fnnfaqukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477563e531cso12950955e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVQQzb1A6IZa6yQ3Dbr+k9cF7Qyjo/y1ieu4DJRucZMQrT2+EZCrKlcuMG11xQzJ4ZSgbt4/QaAU7A=@googlegroups.com
X-Received: from wmcq18.prod.google.com ([2002:a05:600c:c112:b0:47b:e2a9:2bd3])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:46d1:b0:47a:8088:439c
 with SMTP id 5b1f17b1804b1-47d1959d6a0mr26330495e9.35.1766159230294; Fri, 19
 Dec 2025 07:47:10 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:15 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-27-elver@google.com>
Subject: [PATCH v5 26/36] compiler: Let data_race() imply disabled context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=k+iCIYpV;       spf=pass
 (google.com: domain of 3fnnfaqukccsv2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3fnNFaQUKCcsv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

Many patterns that involve data-racy accesses often deliberately ignore
normal synchronization rules to avoid taking a lock.

If we have a lock-guarded variable on which we do a lock-less data-racy
access, rather than having to write context_unsafe(data_race(..)),
simply make the data_race(..) macro imply context-unsafety. The
data_race() macro already denotes the intent that something subtly
unsafe is about to happen, so it should be clear enough as-is.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* New patch.
---
 include/linux/compiler.h    | 2 ++
 lib/test_context-analysis.c | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 04487c9bd751..110b28dfd1d1 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -190,7 +190,9 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 #define data_race(expr)							\
 ({									\
 	__kcsan_disable_current();					\
+	disable_context_analysis();					\
 	auto __v = (expr);						\
+	enable_context_analysis();					\
 	__kcsan_enable_current();					\
 	__v;								\
 })
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 2dc404456497..1c5a381461fc 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -92,6 +92,8 @@ static void __used test_raw_spinlock_trylock_extra(struct test_raw_spinlock_data
 {
 	unsigned long flags;
 
+	data_race(d->counter++); /* no warning */
+
 	if (raw_spin_trylock_irq(&d->lock)) {
 		d->counter++;
 		raw_spin_unlock_irq(&d->lock);
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-27-elver%40google.com.
