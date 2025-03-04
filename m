Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCUOTO7AMGQEM5ZDLMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A48AEA4D7FB
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:32 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-30bb9d4619esf10206121fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080332; cv=pass;
        d=google.com; s=arc-20240605;
        b=lA3Nk/8mZ54NwhqWQrhp6+8tAelcxxX5doqlRuY3yl9FZ3b/0ar7NEbCmWWufL8YUT
         B5fU5IXJa0clx/qLX2oadA7bejCGb16jxSjCdbGL0sQGwQprt9m3EqIT1GBdDkZ8DNdt
         bg23p4a4CpSELqcAr+MplI9nK+QUHf0Hl1b8eLhn/7H+nglxv89Hi5yBk2FDy9q1MCIl
         wltinO1e0CRgtoNZQt0DaekTQX47/sRkaXSn7/shjrLQctuezRH9cUYlRuILNiVbL91L
         bVXS1i+MRqaeySwF2pfnbb1AV/cROxTLFiLPlTqxfR68iKrrqpSo0rsl8ZAD/ov5FTAx
         UKTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZbEBXDqzL0V3Gc701sAU10oOQlFJQLp95Webr8pDaVw=;
        fh=SRFAyWJUC7Qc2GZbkClZKBKLRom+syUgk7hLqXhVi1I=;
        b=ZuLv8RCwfjWpTnzsKSyWnjU3SLjCaCQuU/7oHYRC/32+yF0Eyws3VImZHDB3SQwt+c
         8yIQibgRRFQHwVUW0Nt766vQETJS/sBzWvTGj0R/Xkt2CaBl+6G9rdpi1o5Jp62jviin
         MuHTEwSxtLwYVnJa6LeOV81ngVw1/inaWE0KAFSZJNFPjiUBhdvoR5+0xHmkDRDz603o
         H4Ze6vB8u5TpR7VgKeR2uOAgP0mKG/fsQTH7wXJCpaGXoe0gLbZNnXM9/dZu/GBQ/AeP
         xrzY9aJlimg161qKZf11XzSdSLqOYMD6xc+iYXffiegthNsZFAd8iPHYSS7qd+jE9HrV
         FSqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PbwIb0H3;
       spf=pass (google.com: domain of 3b8fgzwukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3B8fGZwUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080332; x=1741685132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZbEBXDqzL0V3Gc701sAU10oOQlFJQLp95Webr8pDaVw=;
        b=G8/As8y/6PZSOcEmg/FQGDC+pny5+UioDXO9b4lEe9Nx64jRTRr18Un7F3C2Ntk878
         mHPsAHWQ3Y2+/2G7h41IkaDdk5TtfEaktaQknTuuFcdyx3NkyoYaQVVvLoPzmWAqVApk
         i86HK6qzfLApO1ceR38qLO7slIgZL/AElCTiZ465QOE4fhfvJRoJjuoZ5r37Plq4yS3Z
         B4dFLNUgDROisN3IoA5ueilX+h0RoJ/vB+X66CcajKV+wgCS1IEVEwyYJTF2HY846V5s
         hFPqM+slUqxfkJPuFYxlye1aKt7zOPpBPf4i179CGsk8Ikuy1wEk71A3xwO77Ea/t1ut
         NvNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080332; x=1741685132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZbEBXDqzL0V3Gc701sAU10oOQlFJQLp95Webr8pDaVw=;
        b=jnZ3rLFiFgiqYQaq0dIKiA1Q92OWYWacG811M66oQrTdPMkXCEvoT3Of8R3Se9zAGV
         aC295TTzW8E9BgvvQ9Ly+mP8BU1DE7qp5gVSrmijuURJgxyEp4ARVQb4dCx34SOkfSBx
         lgqceqBL7x0oK6FYBxSpvX2x1zw4cKbaPUhcs/v7nIwNDfEOQXX5mgYMesVLzKPWpTaL
         78fiMRvjtq0qBg+9308muMsfL8nmm6tyM9LDTZEoox0L72rq8MuUzsZJnPD5CcOEICHK
         f91cAUBhaaV661EhiMRYtf1v0uxX0WuNakPLYEylMt1BaV3RcGy1PzsuDbLWrYieqL7s
         ri5A==
X-Forwarded-Encrypted: i=2; AJvYcCVinVXIju4HxnxEHw6RvL3WBmYVGtofw7od38rvyFpWMsy7j2NaluGYh9q9SdIEU5pH8Fzuyw==@lfdr.de
X-Gm-Message-State: AOJu0YwEfRts/Zof/dNa6psdT8iYjyzjPY/H6yAiF7Y5a1PdI35YzyZA
	QVHE9KEttt3jTS/DNu1ZcWabuhAr5m7kRJVRmaL6b4MLjmde8CUU
X-Google-Smtp-Source: AGHT+IHD8/OKOcTgfTNf4HPwtkd0xTfAMt3MqwvOuGK74wb9k4pXb1kwbG2ZvTCtahgns2GThQkgnA==
X-Received: by 2002:a2e:be10:0:b0:302:1fce:3938 with SMTP id 38308e7fff4ca-30b93220ff2mr57341231fa.11.1741080331291;
        Tue, 04 Mar 2025 01:25:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGMpEwu55xd/d1WXojBMvBvPtfxrOzmdwOdpANRCYq+JA==
Received: by 2002:a2e:7a0e:0:b0:30b:bda3:2e7c with SMTP id 38308e7fff4ca-30bbda330eels17811fa.2.-pod-prod-07-eu;
 Tue, 04 Mar 2025 01:25:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQ6I/T99E0HXd42dIE9ySMHXCbRWSZFzncsFbM4OE5T2/AKgIXPWa9UZ58ZfJleAGiktn5yLj/w20=@googlegroups.com
X-Received: by 2002:a05:6512:3e26:b0:549:4898:6681 with SMTP id 2adb3069b0e04-5494c31ab15mr5999182e87.14.1741080328636;
        Tue, 04 Mar 2025 01:25:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080328; cv=none;
        d=google.com; s=arc-20240605;
        b=SZb87kP7TILGyk9tWru87YOGBjDvYQoLhSHX2cZ8M9DMElBlFwy64mmDiNm+EQxkU/
         Sk69dRRAgDqjrh2fovNkQi0XQp7VXutNQbWZQuDBAcx4S3ZXbSNgjpi0KnwbVQBr06wD
         2f19+ESdyiWlAYt4Z6EXMYa6eWzUP0gpIfoC1iAFzYv9vuXKvq2afa6jV9aUeZrpX++D
         WGo/fM4BV8Ac/3f0KHF10n6ztDTUAhf8ylT3JJXAZBNuoRj1RsnOknnS7xfd566psZsu
         q7bf2d0/EBj2uwIBSfrBKMrRi5r4pwiUDsTDa0CjYmbUbdiucy4hGApUpsyf6SSjJK3k
         Pd/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Dvm+2kORFqwesy5wYS8KGKPET1JeCxDND2kfg3G9ty8=;
        fh=pjYanP9qYuCopB9shUNpAKZrPszQbmVsBv2VQkMAats=;
        b=WtV9bn6ID6wgiO1Qqj7dFwbjRrJ2pPhC7UVEkE7RseRj00Kxf0g44btcKMS9ECHVYk
         sMTVmo50Uo2dsTKgEexMtE8ruQJCOfDQ2JwFoYz/oxSk4rpQEJad9tEyTHE+fW939VmR
         PbLDWMCOlwepi/LHqESqIO1gjJ1MVprxEkO4xhmjHBEvtp4RVLCqxRn6wRKgtx6rD75x
         vhMKDiMeol8RMowCOIJyr8BYi3wvLK5rd2VhMlhIQa5SSGi5lyy8kK3vDgHkNY6mHfGH
         YWjFTbP6GeFG0Ajt+qylRnjIkwpPYKrnsWTikofy5ldmANJL8TAKG1060TxuGK+fBlNM
         VYig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PbwIb0H3;
       spf=pass (google.com: domain of 3b8fgzwukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3B8fGZwUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5495b280837si70325e87.3.2025.03.04.01.25.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3b8fgzwukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ac1dca8720cso28954166b.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVN2rh7tiXif00L0oagDF4k5M4JAZkqd/56MOLbZsnfKXP/BHerAJtqj0SnCSsUsCfKSjKk/OUwa/I=@googlegroups.com
X-Received: from ejctn9.prod.google.com ([2002:a17:907:c409:b0:abf:6374:f45c])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:72c2:b0:ab7:cf4d:9b2d
 with SMTP id a640c23a62f3a-abf261f9df4mr2143998366b.30.1741080327941; Tue, 04
 Mar 2025 01:25:27 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:06 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-8-elver@google.com>
Subject: [PATCH v2 07/34] lockdep: Annotate lockdep assertions for capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PbwIb0H3;       spf=pass
 (google.com: domain of 3b8fgzwukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3B8fGZwUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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
 include/linux/lockdep.h | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
index 67964dc4db95..5cea929b2219 100644
--- a/include/linux/lockdep.h
+++ b/include/linux/lockdep.h
@@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
 	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
 
 #define lockdep_assert_held(l)		\
-	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
+	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assert_cap(l); } while (0)
 
 #define lockdep_assert_not_held(l)	\
 	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
 
 #define lockdep_assert_held_write(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 0))
+	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assert_cap(l); } while (0)
 
 #define lockdep_assert_held_read(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 1))
+	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assert_shared_cap(l); } while (0)
 
 #define lockdep_assert_held_once(l)		\
 	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
@@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
 #define lockdep_assert(c)			do { } while (0)
 #define lockdep_assert_once(c)			do { } while (0)
 
-#define lockdep_assert_held(l)			do { (void)(l); } while (0)
+#define lockdep_assert_held(l)			__assert_cap(l)
 #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
+#define lockdep_assert_held_write(l)		__assert_cap(l)
+#define lockdep_assert_held_read(l)		__assert_shared_cap(l)
 #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
 #define lockdep_assert_none_held_once()	do { } while (0)
 
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-8-elver%40google.com.
