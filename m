Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3NDWDDAMGQEYK3PLHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9E1B84FDE
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:38 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3eb72c3e669sf654587f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204398; cv=pass;
        d=google.com; s=arc-20240605;
        b=I234wViO5rENQ7pzFBScpalnSdaxjGSRw6JQY0INX8TVD8NKSH71HH2MjEobBJtk2M
         AqjMYxTktPLsTPaCEfaxVu0hqcW73Xq/O9GjE1960zPR78OBZEaOeCKadFgECB/JAwrJ
         JosPHOnP8TYoDIEwy2FIajM9aCbOu68hkq0uhzhXpJJHsNhJJMYKCCK7tbULoYQ3IJVV
         hxV5sNFd0RvygoCb14BTXoCgzhbXaj56U3uKWYzhNV0EZrzhW+o4LUnqeXinMZ5AknD7
         v6vygQq2JSVni8m76b6tMSdK8oSZmhM7DNPkqOUQlqLyktp8B0UnkRSMnwgBEfnk4MH6
         NEeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TIXQ9Qu8UhhgQjxj87r/eeZkA51e1IdvuW3/7/OD+yE=;
        fh=vTDNEc+ahg0Guj5X7H6cxSGiqQDH2TPugqOYq7gdfvg=;
        b=MQkhYEqxpPo50BLJ43JKE2sZ+CpYu5p6UADmGDFwbEFKlLIzNkMGtoBc/pNwnWKiAc
         WRxcLg0Ur219l+wUmUMeBMNY+bvgVrUjEhSniHSACV+DblpGhKQg91j6ifVHFnZtN/Eu
         BRs1YVjUVHI13SBq4piM3oB6Um4WdVdCt3SNqa5coQEOwdN/PWsDSiAMTSsVaL3I8915
         D30UCnkatUsYixBkpJGuB1feVBXASBwiWsZ4iXgpEzY/iQgZrQ6y2TCusOGd+IOWF+h4
         pAsnTq0/fF0GdQ7RU2nNV0gPkmjRwiIoIea/uq12oEi3lPLOejPXhuEeTM4QvK5IJzt2
         ALVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=znzCcEjD;
       spf=pass (google.com: domain of 36hhmaaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36hHMaAUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204398; x=1758809198; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TIXQ9Qu8UhhgQjxj87r/eeZkA51e1IdvuW3/7/OD+yE=;
        b=TfoOOQtmWrS36RPwPB7vF3sAww7WniHdS6pJakxqwJpaCUj0NltB4phYwqabrjiT4K
         SLvG6yruyx1TpoC4ey2a8aVK2lvaA0AtHG4P+KVnCJQ0S8HsyHaXgUL8acVfqb69uMOt
         xiOVo6S7iFj3NndN/J66/IUjGRrNyR7wOfrViTJ/H/qLptpeHo0J8mN45NQzDnvivZbV
         92ByyigIhA9/VZmr+HMS1XeS30fLVBbOMXWP9NsEGUMGBakTPwzvHmrbgQm9zHE+Fkdj
         yAeFM5U7mqHqbSAMwg/qaMdtMS4GGbTixd7XQaXnEB3OuNIeO+kHr2E4ScUOM5ooyS+/
         /C1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204398; x=1758809198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TIXQ9Qu8UhhgQjxj87r/eeZkA51e1IdvuW3/7/OD+yE=;
        b=Y5kNkfQOyBhuuKXhOMzsEn8+0BGNPVpIA5gUkzeNQgRcKzk6ik7PMSD+yYp/Hn06kY
         RSQTA56FMX5NCYBmVRbjobQQ0k+PyO3Gpmn5v6mbZtrgBtqdlYCaiVy+ra217jbvljrJ
         EcT3U12gFDOkdOiqu0CPBQzFwSrsR7Zlj6KbCuN74p0Yeus2WOwiwLQwPrhCqL86dztN
         2jt/DwCASLOnAQEUB6KJXhXsFdrvqmwge5WFSKBUyLYXSv24Lb/rL1EJhAGJ8mGu7iut
         IeIGR3k087Rc0pyP6oWqlvbsctTa+Ch8Ebbz9NdSGYZUq0sPVqvogo+IRJ9Lq7IdL6ns
         SI6Q==
X-Forwarded-Encrypted: i=2; AJvYcCVfQv8FScSAeeuQlEdIrslwhMJv0nzJ/Ctc+rean5Ib6DnaE4ds0gXPLgxXuA1FADnt62y0Ww==@lfdr.de
X-Gm-Message-State: AOJu0Yyg9uJ1sMiqjd/In+m8yhS4QoRmvaHI8skPmsYuNqIp3iuItgub
	eexzn8w5B/7iG6Dk+s8ijfePxyqSYDgaoVjOQCwo0C4oHehqrVp2HDLi
X-Google-Smtp-Source: AGHT+IHWw4fkDNOVjNgxUh97X9XyTupz3zVvtfCIYX25q2nb9dE5s2oXgMFo2v9vYGzH3oTjC3Xj+A==
X-Received: by 2002:a05:6000:2382:b0:3ee:1368:a8e9 with SMTP id ffacd0b85a97d-3ee1368b40amr1615258f8f.17.1758204398031;
        Thu, 18 Sep 2025 07:06:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7S2AahowgKfmXjwqBKZUrBnuTs44vOdWBBjuTi0jydnQ==
Received: by 2002:a05:600c:34cf:b0:45b:6fba:90de with SMTP id
 5b1f17b1804b1-4660821c89cls3097675e9.2.-pod-prod-08-eu; Thu, 18 Sep 2025
 07:06:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVuoHTn+3UCc55dveEl/TPVeXxBnJPVNxLIcU1oj6/+lBF6LC6YRDuBZDCmKCqYGD4aM4aRkBbjkQ=@googlegroups.com
X-Received: by 2002:a05:600c:1d08:b0:45b:9a7b:66ba with SMTP id 5b1f17b1804b1-46202a0ee42mr58378045e9.14.1758204395499;
        Thu, 18 Sep 2025 07:06:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204395; cv=none;
        d=google.com; s=arc-20240605;
        b=GYMvFnqpgs6Ogrh4BRsF/V4YmbnBGrhrVixp5q2onZCDbEXDxNfDq9vpODWzJ8wghJ
         AR3iC7G+7E/Q2d/MWBEv2HNaTPvNPazLlXZJ20QK14Jz1EIpw/VgH8tYr2ayo15CYQ1V
         XiFMBnp8eXRxs1rGPbFhpqKqIECM1xoqLJJ8OnGvYKMt5uw1jUOAlCMQ7jv4u37b88R8
         1LCsCzBJbbwHteLXD1TyBMIO3meRIEvj9g8R2EE9qMmvg0mua182xu11xwbIsP6U81zs
         fJIB2gvLy/J1bqbSu7aQATF8Is2FXZIODWGy3i1FO7JLJQEP9ZMamWwtvgaJHF7/50UZ
         xc/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rgYM57a4+YilIGK6iKKshTwAf6EJSKpu76VpXrklnPU=;
        fh=H8iWVT5Y6xT77CiDlZ2RYWIW1j260Wy5qBLx8S56h0E=;
        b=TBj47khrgiL9a5RNx9GAc0jlBgx6IrmSntoK7RHhR5RG5iWjAb53aUEtDvhjbPi0mk
         uq4gNTZEprhZXu4dAlbV/3tXS7QbRXEYv/OnollPJ876/zkbkq6VwH2VUbelRs6NQ8oj
         OYgfiamv9HH0ZJG9cLzCxjIP4DyEGfR7BCW4kYEqjGMAcDL43sBel0aTFXv0pqyVlBwz
         ItaMNIEUvZkfJD+IPiAg2YCW8WWzoU6bsXkMwyByVAvvmPUOcNF+kIIBwMj0NuMjPk3G
         5xaUxsdI697DnEWD42Hsho+6BFdZPQhuZ4fyZkEA4318M6xqZyivljZYjmEZm4T70xhT
         jq+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=znzCcEjD;
       spf=pass (google.com: domain of 36hhmaaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36hHMaAUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4662b08d9eesi236915e9.0.2025.09.18.07.06.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36hhmaaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3eb67c4aae5so473547f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUr+2OsB/WuNiKgDH/owL40PeZHKh9fvKOgKsVwcg3qHWpafX9z2sYx09LED59Nqe7QdJbffY8+Bpc=@googlegroups.com
X-Received: from wrbbs6.prod.google.com ([2002:a05:6000:706:b0:3ed:665b:ec9d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:adf:ce0c:0:b0:3ee:10b1:17bb
 with SMTP id ffacd0b85a97d-3ee10b11893mr1782304f8f.61.1758204394951; Thu, 18
 Sep 2025 07:06:34 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:36 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-26-elver@google.com>
Subject: [PATCH v3 25/35] compiler: Let data_race() imply disabled capability analysis
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
 header.i=@google.com header.s=20230601 header.b=znzCcEjD;       spf=pass
 (google.com: domain of 36hhmaaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36hHMaAUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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
access, rather than having to write capability_unsafe(data_race(..)),
simply make the data_race(..) macro imply capability-unsafety. The
data_race() macro already denotes the intent that something subtly
unsafe is about to happen, so it should be clear enough as-is.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 include/linux/compiler.h       | 2 ++
 lib/test_capability-analysis.c | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 64ff73c533e5..eee60adb3645 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -186,7 +186,9 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 #define data_race(expr)							\
 ({									\
 	__kcsan_disable_current();					\
+	disable_capability_analysis();					\
 	__auto_type __v = (expr);					\
+	enable_capability_analysis();					\
 	__kcsan_enable_current();					\
 	__v;								\
 })
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 12fd9716f0a4..513ad28ed06c 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -92,6 +92,8 @@ static void __used test_raw_spinlock_trylock_extra(struct test_raw_spinlock_data
 {
 	unsigned long flags;
 
+	data_race(d->counter++); /* no warning */
+
 	if (raw_spin_trylock_irq(&d->lock)) {
 		d->counter++;
 		raw_spin_unlock_irq(&d->lock);
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-26-elver%40google.com.
