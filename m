Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG7HSXFAMGQEKXQKPTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id AB571CD09D1
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:40 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-64ba9c07ea2sf687841a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159260; cv=pass;
        d=google.com; s=arc-20240605;
        b=J6YKnJrpy31WcAcAX8mbefi16DHZ3XHMT+CSXvfsZd/uvgMELKP50HDXEoWY21eG2g
         dHutaAXLej9GgaI9fOYbdR88Mt9przG/HfTBAh6M/iVyFfbDhY5BMxmTYNZsogyRFZtz
         me4/zB5YBoD6uvU2rUbg8fmud04AQheT60fiqf+Zd299owkCV5DTGD6n/HTIAXFGcXJF
         Ykphmh6cHDP4tUlMVT/XIPC3Gz9pllD+uhy4k3JX1F2ch66yJievs4E+In/UWMZHEAQj
         vaqBk0WVudo2xGrw6rw6Hsrq+QTffoAtOS5MGIBEl523VhrDY6kZZMXGOGymjqb3UPu7
         p8aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7Eopj4/8KLQHgj7+tn9KBVQrbNKMA11hCRZqU6H6hko=;
        fh=2jIq/Eh9QXIJKijadyLW/zw07LgaT90hKhBo7zZdUM0=;
        b=TXEOXOKrGEpnRQ9R7HpXQrOig45Tsp3BiPSpDCKVniUABl3W/sIQhSVWu/vHmNkfAJ
         /GHK1jbwe5KE1K2i75KLJ0y/GPBrV4p812zojh0rp2VriOxQldxIVuA9yE85FgQWe1bo
         dvTOFpkyh5guwh+PRhpJbW4d82OtEPUfSpsNX8C/P/adq5dlfIjNpov2E+AlOhRCN8rw
         oYE33B8hvEJmO+WJsEQJI5Odmb8EBPydT+vvlmDpqH57q8B5Vrbb70Ls0S58ECAv694E
         FQr2/vQZsVFR9DwdsQ/Yh8pw9LMN8RkFAoLIy6Aoo3kG075rennNwtjHcifroMw6MQta
         r9/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HWad67ak;
       spf=pass (google.com: domain of 3mhnfaqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3mHNFaQUKCeULScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159260; x=1766764060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7Eopj4/8KLQHgj7+tn9KBVQrbNKMA11hCRZqU6H6hko=;
        b=aL7O9Piftfhqenwfa73XYzXJLF0VTaLIk8oJcNiFflITudY2FIGRATXeZY8+37g+ty
         QjiDAFsa4Y+JDev6O4MBpCb9akqK9DjNv79cPSVrTwNZtrCMysbLCxXZGhCXZ1Mrg9GQ
         IRoLHhCmSfFoajeZrJKh0jFgWe7mY/u5T3UnhYT3UfpKucxF2ojZMCJXQuRBXySpBZ9o
         UYAQL1ful2m3YDLhN3fIKrlxwSyHXsR2XwLuoFcfSRPewsklbVb24X/S/xur98hrx+yg
         QKuLlQ1XTxCP6O1+hYcUoxrhO8WXUJDlBYBlwHvgotrz+WToaAKjxp2eIaA9FOCG7BV8
         1opw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159260; x=1766764060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Eopj4/8KLQHgj7+tn9KBVQrbNKMA11hCRZqU6H6hko=;
        b=nvy0IM5SmA1Js5KlJW0WKzFrukY3ncedRQitruSKS98eI93eOsyaKsNJm/K8/k1eE1
         e9IQoWBOiUs+Httm+Gkug8Tq7aTAy7wczh3oT3axuixHwZv5hxRD8KC0+kalaV1eXXqP
         0BDI2M/0qQezxnhSj3XTyusBQs+8AXIeRvze8DP8Tao/nn7Kvi8BJibvgBj7m730zoBl
         skRXJHr/X427oRH2AUDRWdU4K6ER6qiiS5DonjoguzstmlayBWqssVoDzSyZyNuDFyQm
         lUp4CwdLBI6iUxF32mmZ/v94mgEocK3zQLdveXt7aDr2fBPgSX1YXjZKbGdTuQT4kxMk
         IG1Q==
X-Forwarded-Encrypted: i=2; AJvYcCVdbULCwTtlju15xXzYUE0O2lAffK1fPtid5MTthkTSCmdpzzM4DclVEZP8ZYtcG6jkQ0NilA==@lfdr.de
X-Gm-Message-State: AOJu0Yyzxlm4e/teoO7nex/wwMKncOycCRQByZkLQXqeQW9gigYkM4TR
	R9cpzEOxxXkR5OzauxySiK2pBECCnkfuVf1dHXdUtpkkmvhye1tMLH2S
X-Google-Smtp-Source: AGHT+IHcP35V+XUBhYOv5VuZHGjJd4b5ZuXAEKLPgcaj4s84aCOZIko0TcvEdLhClZ4CavO9DiAU7A==
X-Received: by 2002:a05:6402:358d:b0:649:9a8e:d63c with SMTP id 4fb4d7f45d1cf-64b8e941f8amr3320705a12.15.1766159259886;
        Fri, 19 Dec 2025 07:47:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbz4iuUinmheE7L6BskFLpL8JTzMnR9ZeVgMtzR3zmoFg=="
Received: by 2002:a05:6402:5342:10b0:64b:403b:d9ba with SMTP id
 4fb4d7f45d1cf-64b55723b82ls2148019a12.1.-pod-prod-01-eu; Fri, 19 Dec 2025
 07:47:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXpoxHoyZXWzA3akt110U1npRirjQaQBIJE0npW8p5SAC2sVFNXn1shCf2XRXdWQnnaBS+cH6NKvdI=@googlegroups.com
X-Received: by 2002:a05:6402:4312:b0:64b:48b1:7c12 with SMTP id 4fb4d7f45d1cf-64b8e82b896mr3047743a12.3.1766159257398;
        Fri, 19 Dec 2025 07:47:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159257; cv=none;
        d=google.com; s=arc-20240605;
        b=jja5R7S/zXAiRI7as0XyQGL9YKGTAhbTSmoSZphNWBDFsgg+kD5MQE1FLvP7BLGnII
         d55EH6yQQHOHFTGtg+ewaVK+Mh6qgREr02Ud9KBibVepaKhB+RUHGlp8FxtEf2SBJLrF
         6SW2Nqb4IkPD894vPSApojln0blFr3vhiHbbkGIzhnaxy/gdnyeaHyVYOiCG/OoV1OU9
         eeY5Xyvfq9vja2D/8KMLuY2U5VT9SZ2N/ItX7dx9heMfgYWvvwt+UaWxVVmK3c50UvPD
         PWPIz05BiRYDgJxLQU6clwos5XJ5Qhmd+fvl/eT+OKbFyvsxhZ8twfb2EmdYbeAzLhEr
         5jTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=raJvaZBiGWdUURg4IuOfBi51C0gZUEAs+Zv74eOTMUU=;
        fh=j1fS5lJ0CPneZBs8l4IrE2Pd744aNzp0vgO2276/P7Q=;
        b=jm+twbkuIl3rXxx3ZIWue094ArVYgjBMjzWAZtVHhVJ+whqSfphCdmx2gpsDRfVM2U
         jBWIWpxLBPxxdiG6TsuYXfxPJO7kd6HylK2VBsPRwm2gYlDxw2RmFV4i9d/sSbhb/qLB
         Jo6ftEy8PsBqsI6/UIPTK/dm8L0WIBZUMVLkHRDwQe0d6NyhkvQhcLsZBgJ6r+hCjGdT
         0k/+k4+HB/UbT5SGi1gxMQMgb1OdAf54tgQmN9w25LtA6HvadwntK9tdCM2P0dPgyJDG
         35+17Vo49FJqXa0WTOEd509FaDSRM64sN6dJJsvibe3xYSGd43VzttWclBS9tFLSWOuP
         kHQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HWad67ak;
       spf=pass (google.com: domain of 3mhnfaqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3mHNFaQUKCeULScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b90412a75si38531a12.0.2025.12.19.07.47.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mhnfaqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477cf2230c8so19804645e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXXxovGj/X3cPUKWexF6rW3eCaplHQq7dww+vJwhqS2k/aXpapRB7unZDiMbJK36JKau5HZiEJt8OE=@googlegroups.com
X-Received: from wmsm38.prod.google.com ([2002:a05:600c:3b26:b0:477:a1f9:138c])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4f4a:b0:477:58:7cf4
 with SMTP id 5b1f17b1804b1-47d1953b79dmr33800655e9.4.1766159256728; Fri, 19
 Dec 2025 07:47:36 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:22 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-34-elver@google.com>
Subject: [PATCH v5 33/36] printk: Move locking annotation to printk.c
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
 header.i=@google.com header.s=20230601 header.b=HWad67ak;       spf=pass
 (google.com: domain of 3mhnfaqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3mHNFaQUKCeULScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
the annotation to printk.c. Context analysis remains disabled for
printk.c.

This is needed to enable context analysis for modules that include
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
index fc9f5c5c1b04..f882833bedf0 100644
--- a/include/linux/console.h
+++ b/include/linux/console.h
@@ -492,8 +492,8 @@ static inline bool console_srcu_read_lock_is_held(void)
 extern int console_srcu_read_lock(void);
 extern void console_srcu_read_unlock(int cookie);
 
-extern void console_list_lock(void) __acquires(console_mutex);
-extern void console_list_unlock(void) __releases(console_mutex);
+extern void console_list_lock(void);
+extern void console_list_unlock(void);
 
 extern struct hlist_head console_list;
 
diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index 1d765ad242b8..37d16ef27f13 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -245,6 +245,7 @@ int devkmsg_sysctl_set_loglvl(const struct ctl_table *table, int write,
  * For console list or console->flags updates
  */
 void console_list_lock(void)
+	__acquires(&console_mutex)
 {
 	/*
 	 * In unregister_console() and console_force_preferred_locked(),
@@ -269,6 +270,7 @@ EXPORT_SYMBOL(console_list_lock);
  * Counterpart to console_list_lock()
  */
 void console_list_unlock(void)
+	__releases(&console_mutex)
 {
 	mutex_unlock(&console_mutex);
 }
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-34-elver%40google.com.
