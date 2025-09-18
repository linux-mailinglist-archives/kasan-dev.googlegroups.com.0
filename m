Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPVDWDDAMGQESOHUTWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A703B84F7E
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:52 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-36127062a5esf5752401fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204351; cv=pass;
        d=google.com; s=arc-20240605;
        b=ItD47h7y/6uJSefcRU7emcqbznYL7vebYisqAjZzkK0lLndoUDBnVsy+7gj2m6d+0c
         VNhVBaHKHnkAbWDFt96CKAQoXGXunRSqVwS7tyEvsQi1oYpZFIo07eAULf8K65j068nU
         653huDUtw4ZDGTr2ucbQrqRi3XWqdcqmCd6/BZxqQ26nx2Y+8y6V1NOLcWRqhJzOa4u0
         r7VdgF163uRE5955vt3mmErsXHUtKrckzDAP8ky8hYJfBiEOFWR0uHcYqSt92i4rIvbR
         c56rzCzyRjEU7MCbXdrWKxiTvR7uK/4OXu1T4K/ln5fM+yTouXO03p4fY4giplX4puEp
         kPZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bjV++kB5jxEWrWt5lGMgMtWQss2QbheXt/hrBNRUsyo=;
        fh=zlxqpcUjIKqC5R2AyCCmHZkT/07bcph8nqjIucmfh5M=;
        b=RppDsaeslPw7XY51ltfrdr1MXrwrU2jqkplULzInfVNfLwcwfiU81Rz6KX4E8ZikV5
         0s4b4Iba/eUpB9OmCWdIysDchDq3GWmTHzbm1YiJ10DPDDEvcA7IDR1Wmu7QpOVzTyR0
         FtRBzC9vECv4htOb2dImHTapj0d8Fr1S1Z0x4DEp31KU92ChYRtG+V5Em8BpZBfrtAPf
         q2q7eSGfWPAEvgY2z5N56NMKruRAzpcAvc8ugNaS8o1tuHWJNNF2ksiJStiOcAdT5XNd
         86KMiXlBAXOt6byM6B3tST4/jxsCXfnHmdhDCdCGUHJ2/7WZqRyqHQv76NbsbE2dhNd8
         KQNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Xtttxn6T;
       spf=pass (google.com: domain of 3urhmaaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3uRHMaAUKCVo6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204351; x=1758809151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bjV++kB5jxEWrWt5lGMgMtWQss2QbheXt/hrBNRUsyo=;
        b=DCmKET9qqcQ4KqV89MtYtzeONYnYTj+IA1CNupX0XBkucruesCgCyOBwKTNh/iods3
         6M9JLiu2Z1HzCAlyuTqKXbjEKCYI0N38LOm7u1/y4Z2H9yJ0x9FYq0K2hySNaqWog9B+
         iLz3SD8mQFDOEs+aLhDqzAtnq14pJM4gXL2xAwCGkjVyAfsGSk3tPaaHumQzxKKVBUhE
         PoU6uCLsjv+mSGo2WzVd1o8zq40UByzOC2gx4eewfp1xKZdHOuJTgC69wr7/+CvLpETA
         XMo3fs8eyf3zILRU+6YSQZS8sc0eOuS5tRzpNkP/HHwUn+U8+G6oRnbJnqrwMMSpGdVF
         0+dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204351; x=1758809151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bjV++kB5jxEWrWt5lGMgMtWQss2QbheXt/hrBNRUsyo=;
        b=lgIUh0ytBRmzmc76el56Lv3YsPWgJFpZYr4ZDoWdUCL/2oCSok55ZZrh10GHhhzIbs
         Cv2a9fRYwXFLudUyqit2ycruZct+nnusbN4yB4+tB2Aq/MpPgQ8ft20crvswK7ICN/+T
         zBMoOY8sytI3Sct+0KHiy5IQnL2xdVqCvguli6jKEeFFNTimyZSZUFRbOu4zGhApgMXO
         e6ARfEhKmXacN33Ld2P8lWiKBCR5xaSF0eSKQi0GPsbgPLGE5AQaMlB2nAtp2or9tis5
         YvP9OjoyKZsi/41tc6SsKdflS4s2EyQ5wiWrIrlInw/xoJElM20SyKGHAjC0jI7metBk
         tHJw==
X-Forwarded-Encrypted: i=2; AJvYcCWaIYRuvjVEXAZYJvHU6ogbuxgVLEDt79BkdaahgB3k2fHxPYJS+5QlAq+vNMR7K4TH/yX4lA==@lfdr.de
X-Gm-Message-State: AOJu0YxIuLqnL7ORWkF26sgvLLW3K5d/+xiEpqL331gfknShCN0c1ZeS
	N34EPkZRVU41XPDK/OV+7FswrXTOqAlZ1s9QlElHJpGqlWb/zP4cxGkl
X-Google-Smtp-Source: AGHT+IFGvz9e6uC2KqvEt8ZqlCAx6ATOAisoZyy21bJDHCAeEYPGJ/EP8FvH6oBuOzqBQa9BbrBO+Q==
X-Received: by 2002:a05:6512:6096:b0:55f:44b8:1eea with SMTP id 2adb3069b0e04-57799fa0668mr1675754e87.18.1758204350960;
        Thu, 18 Sep 2025 07:05:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6wmO64Evji3ALAy9T0SDXLmM9SCVsEJL392SupWX0/5A==
Received: by 2002:a05:6512:2252:b0:571:2479:7772 with SMTP id
 2adb3069b0e04-578ca7e1807ls365527e87.1.-pod-prod-07-eu; Thu, 18 Sep 2025
 07:05:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaZ8B0IIAAXGsyWQU65x0LbLvNFJnqVv8Olnz4PsUmMRrDqRKHMbEGHXgmSSftrh8fmL6F+qR54U8=@googlegroups.com
X-Received: by 2002:a05:651c:1a0a:b0:337:f2e5:9f74 with SMTP id 38308e7fff4ca-35f6310cb6emr23107991fa.6.1758204346508;
        Thu, 18 Sep 2025 07:05:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204346; cv=none;
        d=google.com; s=arc-20240605;
        b=WfmFqCE2NqFBtZatxFhsVwi+HuHiImmW8AAlbNwDm85zPjIjPeMY3+izt36ll9RAUG
         zyYEV5VB1ijfEqMrfSBuYwET27mQG7QMLgEV0GRADouoM+c+BlSgU4eg8oGGxLCXp4FW
         ov95L8hnz8nnctcTL1nrDWvVBz5apXqVEkwklsxYKMRA5xT3EIZiUtpxyI6Vp+itfjXK
         XibfU6jAa0wGm1fo2eGcn0bkPk/B0OjxKxRHdbaSLCU+Kj7cpELiV4AYVzrZQsRbdrug
         JHmAN0d4cGo0SYvj5vAb/orfvaYUd7s47ru8vIGBCpLm9RQWRxEVMbOpy9JAAqeNKVC1
         TNbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Y8a5df3Pjl9f6q04E+YVKjYiENmaUJ17VWF4NqYxrig=;
        fh=p2nbkyPpasSgkREY8BSNySgnSo/PEGpu4rPLtfGErtM=;
        b=KfEC2wd8JeK0KgN5OPLTifDQaA6oFRcnvnmIfV/FwyNkIPYHGP4CKyBbiJZj2yXVjo
         yvtzC0A0paTj9QUorhYeY6NdN5sUXBdLhB5VhN5d5NUG2cxkO/X48lqxlDVS/Cfipua/
         5ffUbH5SFzYL2PwUAg07Ww9IiJJ/HeJSJqwPiSCBFplVnZwEddAAEgEoJKhQT6X7cmiI
         aIbkmCSMQkrliqw+OhZ7GJ0js11i3wcj2tHDOWEFjnDGglIhEONMGF5Np5G5DhAbRCQB
         IsHoIe/aiBIYL0blqpPSsSeIfOTWlq/yWbrVSvN8OX/NrcALhS/srMnyCxSJQ5TQiTFM
         ARmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Xtttxn6T;
       spf=pass (google.com: domain of 3urhmaaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3uRHMaAUKCVo6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3619d4c06d7si425361fa.0.2025.09.18.07.05.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3urhmaaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45ddbdb92dfso4703165e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV7SBB3QoQgXSRnki1VTG7BZHBrstCwn7w+dKTX/bjwsBkz5f7JbEg4i0k+1E7tr1/kScz6GCtEUqo=@googlegroups.com
X-Received: from wmbdv20.prod.google.com ([2002:a05:600c:6214:b0:458:bdde:5c9b])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:314e:b0:45d:f7e4:8969
 with SMTP id 5b1f17b1804b1-46202bf788fmr56586255e9.4.1758204345502; Thu, 18
 Sep 2025 07:05:45 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:18 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-8-elver@google.com>
Subject: [PATCH v3 07/35] lockdep: Annotate lockdep assertions for capability analysis
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
 header.i=@google.com header.s=20230601 header.b=Xtttxn6T;       spf=pass
 (google.com: domain of 3urhmaaukcvo6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3uRHMaAUKCVo6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

Clang's capability analysis can be made aware of functions that assert
that capabilities/locks are held.

Presence of these annotations causes the analysis to assume the
capability is held after calls to the annotated function, and avoid
false positives with complex control-flow; for example, where not all
control-flow paths in a function require a held lock, and therefore
marking the function with __must_hold(..) is inappropriate.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* __assert -> __assume rename
---
 include/linux/lockdep.h | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
index 67964dc4db95..11b3d22555ff 100644
--- a/include/linux/lockdep.h
+++ b/include/linux/lockdep.h
@@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
 	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
 
 #define lockdep_assert_held(l)		\
-	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
+	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assume_cap(l); } while (0)
 
 #define lockdep_assert_not_held(l)	\
 	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
 
 #define lockdep_assert_held_write(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 0))
+	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assume_cap(l); } while (0)
 
 #define lockdep_assert_held_read(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 1))
+	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assume_shared_cap(l); } while (0)
 
 #define lockdep_assert_held_once(l)		\
 	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
@@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
 #define lockdep_assert(c)			do { } while (0)
 #define lockdep_assert_once(c)			do { } while (0)
 
-#define lockdep_assert_held(l)			do { (void)(l); } while (0)
+#define lockdep_assert_held(l)			__assume_cap(l)
 #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
+#define lockdep_assert_held_write(l)		__assume_cap(l)
+#define lockdep_assert_held_read(l)		__assume_shared_cap(l)
 #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
 #define lockdep_assert_none_held_once()	do { } while (0)
 
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-8-elver%40google.com.
