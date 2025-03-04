Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSEOTO7AMGQELHYZMQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A792A4D826
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:34 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-390d73c20b6sf3651973f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080394; cv=pass;
        d=google.com; s=arc-20240605;
        b=g1wpqHkVeBBjMpNZ/cg6hnCLIulC6qAX+Vyh0TjS03lSQoh9EtrtVqL8cUGYTiXcjJ
         JJ+QaBWaUhQKVUp5ds0XtiBCWknTuHQzJf6TtR+0W+0iwxKEewUYUQHmAmRPusPME4+9
         eh9HYPg+/VaS2660Xh/L0pxRVlMxC+XF7nNjhbBTWBcMiG4be38qqBlZGMsC7IzcJ+X3
         EWFSm53XiXOOe9/Zsz2wp/Tqt+AoIln3IKHemgJLT2AJ3GF54LGdPCjOVz8s2G9sHdvN
         XIMn2loyvXZWXVio9jHEBBZzeQObrNf7m8yPhcp14IqCfLE3QfneoAQC1rIePLlnAzbZ
         XrQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1uh2IgVr/R/xyCg/rQvFL7IalUvNLaLIH320k+qofLA=;
        fh=HiyWawQ2NwUImRBbpeavccE0TLdxxKNUMiDRU/1KpZ4=;
        b=QMvpB/YbpZCU7vP1m4QJhWWZgFjt7FxbKlvuW7jpY8FyLcgkEjEl+xNeH7oJdKcE0G
         3FJJeN9t6i/CQLWJb58Z4ROYsQILymRSk9y/RGFn33TIWihe/+X9aqXyQ0VC2loo93AP
         5En/aa+gsUBt9rEVJtq1Sqh+s+Smkom4Fer8dhtQ0g/AErYkZwpKjKnrAL7hQYiHqQN3
         iAPw192L26Dm20hOitFXQHpoJsE2dJO1lTZVNNgrcR/lwRya+ktgs0lYPoKyXp8HvIDS
         Rg7kO5JGZfTaiqF43W5gtFSRtGfmMLyonNYUhE8Bc3SoXv7I3L4kKupRmCbj1corajp/
         uhsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="fkMgM/w1";
       spf=pass (google.com: domain of 3rsfgzwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3RsfGZwUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080394; x=1741685194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1uh2IgVr/R/xyCg/rQvFL7IalUvNLaLIH320k+qofLA=;
        b=dVfmRQxbNI7QW/cVnqRjqesnNe8yJ3xu5NOb0SlhfWMOpzkcEIgC5bLA4riWoj9mst
         SIw1eEkpE4vTxD2Och1bp/vsShMWNbMwbE/OsTxwrNOxSRLKSwNNT0vhJK3ZjJb9dCTj
         MirnIJ8FhrTqpaA84z2rMKqaLuJpO1LVkNrs8MfYFgX+cPZXcPvm2zLFnJdNFBa2Sc+6
         wNOp0FcUMcOhyIYmbZsgfkn8H+1ysBnZ9ZPDIe2inr+XplKPmhqjeUypR+TBYIDlCrgj
         /7107g9fLCweCF9KAVvpGU7/sUbRDchLpPTXlbDr+dWMPaI9YKBTv26dAcawv33Ydkk4
         +PPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080394; x=1741685194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1uh2IgVr/R/xyCg/rQvFL7IalUvNLaLIH320k+qofLA=;
        b=sSwHqhMUJa/1fZOv9ln9TaJL2Zz9eQf0toWCQmZ2HaaLgiZWojiTob6ib+Z32gUilk
         DOv26UWbTFxla6jFD9JHn7ehxpcwNRoRjKuxMaUJJfQ/0Fccg/0Kb3bx+xxSVPJu9gup
         inR/mInSDTr/loo/AyVzaUQEcgD6ICshMcXOSqAvBQf3Db/JwEna5g8bIvdlBKLwUtUe
         nTgkyAvN+u5dW2ierW+pzGkOmShqMc6YhtGMCew7eYxSqkyXG9UVM8lnzIjtdfv8ctBy
         JJ5rMKbJOLAM5BUtdcmZvw0IqUp9i9/NK+G/CW2VJThheTJ6FgMDZKbwbCmoN6ttCbYU
         zH0w==
X-Forwarded-Encrypted: i=2; AJvYcCWXmqR7u6g8e2BVFSOn0UrgJD9iXLzzJj/N7MThG9GfNMdWcuH1yJkZIbdwExfIec9MVNt8nw==@lfdr.de
X-Gm-Message-State: AOJu0YyGJ5qls4hZqrXBxXyM4sb0EpZyci/e/nPRG8g0vuyihHrM7UGr
	NN+uSSD1FzY43IW27qQ4mM2g23ltZd3Q+r5Un4v8Omnvf8BuGEJ8
X-Google-Smtp-Source: AGHT+IFUVKyhBM5616TD/gqOUAFbIvO5va9rRew4Y7x7xd3Lk3TRsCTvR5+FBsGTJnX5xi3RDB6GpA==
X-Received: by 2002:a05:6000:1868:b0:390:e1c2:73fc with SMTP id ffacd0b85a97d-390eca27974mr16549544f8f.43.1741080393148;
        Tue, 04 Mar 2025 01:26:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEb/JtGp2bJZqMSN5CYjjR798tnavyv9nKSQmK6cYCZgw==
Received: by 2002:a05:6000:400a:b0:38f:2065:b9a8 with SMTP id
 ffacd0b85a97d-390e12f8021ls2449127f8f.1.-pod-prod-02-eu; Tue, 04 Mar 2025
 01:26:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXQ6OkXsGL4kX2ts7DU5fBYqWpMMXarDFg0Dz11HbdVL3aX1oJtKh446CDzsxk82BBVBsTdUY5kv/I=@googlegroups.com
X-Received: by 2002:a05:6000:156d:b0:38d:e3db:9058 with SMTP id ffacd0b85a97d-390ec7cb945mr12979974f8f.12.1741080390845;
        Tue, 04 Mar 2025 01:26:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080390; cv=none;
        d=google.com; s=arc-20240605;
        b=UFbOXVpBznwH5/V3CY7/u7zPnUdp5cKGOUT0bWJpn4hBFYl71HoxNhCYr8pXuhVBOb
         QrVcuUcYPGJrnCskSMf+E2reIe5JndxT6hsHUWwwBYPXqnyV7DdMpvU4wnggK6g3MDVm
         ZVB22rMJxTBfOlnFYzuxzRnd3obMInRS1nD1iWqNvVNoCpLAKARDAUK5FvB6amWQr7+Q
         WXuM0jbjtIOJ89FrGbHhUjAmv6w2BvfGKumUucbLdyfAGYiMVVJ+JFtdnjs+1b4W5yuI
         p5uKuXpendYmVcMut0NVI+o+3daQw3mbRkDGOqGDo3D7Yy0gTsPTlmNlZ9DYYFMLv2rZ
         2+5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KzDuuuaiZX8v73IeozPshNFzU/FhGyeu9jS8KRsuYgk=;
        fh=7cS4Kt05cvDVeb2bVlRyuwYqSz7UA0O+S3uXXuKs6PI=;
        b=FR9OcRS1pg1Kyz3ts82uXkMDMwm21Mz8pf7YmB7tRlnxDH0tVJV7KqY3/Ptpt8Zb7P
         a0ywmvpMzX27FWDLkonkrQOUOncR+LcVjMH+aHHCsnKSbjer8+k0iqreoclzb7FC+zEr
         ntrI9X8yWA3I8a1AqdBRuglnEsQJWceqmJtTioB/ySMZLcdg3ufAClbX63qY3h0DUkTq
         vKZjncCkuL0SxZyIfCVzJt2achAuqZ3aO4RSvxVhYWsHubUR/+9hu4tQ6T+Lr920sfCq
         093pNl1OVxkdX9O1318QnSRI1IMgQUA6a/EFmDsGxgMcXMk9h5e6S49h6sNriv+lTd4r
         ZKVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="fkMgM/w1";
       spf=pass (google.com: domain of 3rsfgzwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3RsfGZwUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e482d56csi439507f8f.8.2025.03.04.01.26.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rsfgzwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5e496b51f38so6579547a12.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWXTBX0RPHsxK0SacKo5TpoDUtUZYjs4Xv4znFviEr9Z4N3taggaCbKSUDioS90NcfSXHt4kpdvx78=@googlegroups.com
X-Received: from edbev11.prod.google.com ([2002:a05:6402:540b:b0:5e5:cbc:4d2c])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:541b:b0:5de:4b81:d3fd
 with SMTP id 4fb4d7f45d1cf-5e4d6afa126mr17250877a12.13.1741080390194; Tue, 04
 Mar 2025 01:26:30 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:29 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-31-elver@google.com>
Subject: [PATCH v2 30/34] printk: Move locking annotation to printk.c
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
 header.i=@google.com header.s=20230601 header.b="fkMgM/w1";       spf=pass
 (google.com: domain of 3rsfgzwukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3RsfGZwUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

With Sparse support gone, Clang is a bit more strict and warns:

./include/linux/console.h:492:50: error: use of undeclared identifier 'console_mutex'
  492 | extern void console_list_unlock(void) __releases(console_mutex);

Since it does not make sense to make console_mutex itself global, move
the annotation to printk.c. Capability analysis remains disabled for
printk.c.

This is needed to enable capability analysis for modules that include
<linux/console.h>.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 include/linux/console.h | 4 ++--
 kernel/printk/printk.c  | 2 ++
 2 files changed, 4 insertions(+), 2 deletions(-)

diff --git a/include/linux/console.h b/include/linux/console.h
index eba367bf605d..51d2be96514a 100644
--- a/include/linux/console.h
+++ b/include/linux/console.h
@@ -488,8 +488,8 @@ static inline bool console_srcu_read_lock_is_held(void)
 extern int console_srcu_read_lock(void);
 extern void console_srcu_read_unlock(int cookie);
 
-extern void console_list_lock(void) __acquires(console_mutex);
-extern void console_list_unlock(void) __releases(console_mutex);
+extern void console_list_lock(void);
+extern void console_list_unlock(void);
 
 extern struct hlist_head console_list;
 
diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index 07668433644b..377f21fd9bb4 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -244,6 +244,7 @@ int devkmsg_sysctl_set_loglvl(const struct ctl_table *table, int write,
  * For console list or console->flags updates
  */
 void console_list_lock(void)
+	__acquires(&console_mutex)
 {
 	/*
 	 * In unregister_console() and console_force_preferred_locked(),
@@ -268,6 +269,7 @@ EXPORT_SYMBOL(console_list_lock);
  * Counterpart to console_list_lock()
  */
 void console_list_unlock(void)
+	__releases(&console_mutex)
 {
 	mutex_unlock(&console_mutex);
 }
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-31-elver%40google.com.
