Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXA7TEAMGQEJ5N25KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 10EB0C74CA5
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:14:00 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-596a25b32edsf38912e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:14:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651639; cv=pass;
        d=google.com; s=arc-20240605;
        b=a3RnCT1jeWJ/0QscntRCeyh6qTa+Af1b3BOMuQB/GlZfJ0LDRoqCWJGwFNxmbSmsDE
         qo6Bk2SWTgR9sF5LGCPqW3UQHhhDyu6z7DSmo4iEQIbua+bYSfHWtNCw3bdrKe0B7aDo
         TbBn1RNJnLRrcZWzlDZusRjk0/MRZMmxiqeZz7kSbrt7J3uvv95iPrZRL43JjSYVsPA+
         v2Q4M30BuBq5M03SOCCJYrjl2iKbFWcE3FwSt3yCpu2Rzp7OGWlPdOzlepBSblqS08wW
         RXdRYqKZv7CbuPqsmo5H7w5fPOeQXOhTODKjjGT2UKBSyA6VFtGHLUUqkrtmsbwiMWDx
         dUMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=wneeBIwAUqwPb9x6wzC4JOSyLx8EoJhAemManjyRcUo=;
        fh=rnsYQF76ohN0Mk2Dvh7YOrOfGRUiYIyuMlFEMbdzlWg=;
        b=jkawnyDzSVPv1L4pk5eYYlgDpKMygR4OX0MKWA9xm7b+U8KgNq+yYGVoeUBu6qF7SU
         QbeTWFsjCV/GuLAWo2UhjOOSI3PUBRPR5Cq1uO3lX8NzO48OGVYIshgFabt2voTSqNnX
         Wm6uCIyleC4Wim+WAjLTs17ckH7kBJ4mCPJ4aEF9xsX3IUUcfQ4OPggRceX/43nXoQQC
         Hz2HrA4LC7jJv7kF01Z2D4AQj0npxxHitxZUOePchNc6jkAurxUdtZQjOir4Q7u2Ylco
         MdEMpunzL3KyDlvnXFvEpwdYE28cx+scMCJfsNPCRou9drAyum+VRuT7dyUx1v2vqiad
         tFpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xwTOlY4E;
       spf=pass (google.com: domain of 3mzafaqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3MzAfaQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651639; x=1764256439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wneeBIwAUqwPb9x6wzC4JOSyLx8EoJhAemManjyRcUo=;
        b=VgUTjB6GyhtMFnuNrP8kmcek7ixWM1guWGnAoUknV8LvP77q+OIyfzYWDiGjNhiZFg
         5Ym3nHsuLw4Qo/42B8iS18eIB1cGWK16WeMHlSqhDUQz73TUd+4vrEv/REJGhu1wZOg2
         F5XF7XVsqhEX2ydi4BpNhB2Usyi86NrQx1MrbdM8zIKMcwXJz5IIZTnFsUALUZYwzB2j
         l85uD9LIRIvrwzfMOK2tfGNgV6eo/SG8V0+AMFjqdi/dr4Y2IUm+8CbxkB8mh+utIkFH
         ZqPyB63Ne1/nxYTOM3NGo5Jrvq+h8kenLhQySuBoH+nd3DyLT4ym7871+aNAuBttEAPA
         l/Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651639; x=1764256439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wneeBIwAUqwPb9x6wzC4JOSyLx8EoJhAemManjyRcUo=;
        b=ku/wY8GrK1ZvARANQ28mznfJ/fgdJqvwjnaXGQuxwk0uzFS8SOhGB6iFyQHQRuhkKW
         xiZj2V7mMsHBFKhjaZHyF8CGvZeuxDNg6l9pkYbkwzQkpH1hPVwyBK8e9lW2G5SUo4pm
         R9EamG685UiHGDU43XKrS0yxc4QPhhVqSPpQucYwvRCOGbAQNmnG8c+lASavXwLGJVV5
         KTwgN7IkZKUgWUV5dkIFz+RD23Pa5W+Dg4biCzU8Esou4ECZoWflPVHMN6h+IWXNk3ty
         i8qV5I0PqjzbcPaACtUvX93QXK3CGwaV4mYXYPf3/kad/9RWUrTB86P1f90/uKN7lNRL
         tOhQ==
X-Forwarded-Encrypted: i=2; AJvYcCV474v5q1NblLWwFU6wVKPnTo7T319BD94VlHQEuU8dscYtzfn22zBJ8p6A0u7ljvz2GmbT3w==@lfdr.de
X-Gm-Message-State: AOJu0YxeRYFGd2oe6vqTec47AinVGB/oz94XRYy9gi6hMAlO4VXG8hRx
	oN36n/mw5N23O2HAubD2uqKdaZqLL/ylifZ1AX+6Un6zYoKHNxPDJXc2
X-Google-Smtp-Source: AGHT+IEVn7GVo1kMfGN3QsEjfV5dIRokjTY+jrILpJz8Kp/Knupn4an3tnnPDt8CQIbaUAHEMIT+AQ==
X-Received: by 2002:a05:6512:acf:b0:595:9d54:93e2 with SMTP id 2adb3069b0e04-5969ea3af86mr1062529e87.24.1763651639190;
        Thu, 20 Nov 2025 07:13:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bZLyLobPaSZfpt9Po/QLeDC+PGeN4Jmpv4yQompsrJgQ=="
Received: by 2002:a05:6512:2c95:b0:596:a03d:e614 with SMTP id
 2adb3069b0e04-596a03de75dls153112e87.1.-pod-prod-00-eu; Thu, 20 Nov 2025
 07:13:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXFAdJw2X2yEWhHj7aGH/fCH8SAK824iO2KJrRvu10z+3HfLIA1j0GCZagAUNX+LpkF3SMueGVpMCU=@googlegroups.com
X-Received: by 2002:a05:6512:33c8:b0:594:2b8e:d6bf with SMTP id 2adb3069b0e04-5969ea01e64mr1041065e87.12.1763651635980;
        Thu, 20 Nov 2025 07:13:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651635; cv=none;
        d=google.com; s=arc-20240605;
        b=SF6BaPq7Xpw5CJo0W7WVkD6V1VRxwSFuFRMoOL96SVnMhu6tSAq76dSm458IaMgftZ
         sPl1iF+uekyHSFkNLSCmRL3TT+H92e4naR3ZQxA7EV27MtSuQXdc5OjQ2fkMtSFMlYFC
         dX170ZZIWDvEM267MkmZt/jCSg9pVKbGaJ2Kxl1dI8jN9d24BZPeGvN0/wip4/OV6opE
         cOMTyQ38XEogDXvE3mfqlFVieaqSLVOZX8+JjzVb+OMafnKaq9/4gMDmkj0l1LjzI4dC
         GEM9kxfWHIGLsvv6EuDCal3Q2YdgzJobIaMQ72TIW5uisH2eaiRpf4h3OX6tbSw7Uex2
         pn6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Im5hsj1DltxV90KwIidFCTn0DS8FZncDFP7kTqaMpC0=;
        fh=YRD4A4zUNcj/yLVazJqRU9mP62DzEJsG8P1OLLr+Al8=;
        b=Wlby7L1dzU7mk5MB+M69h2c6sqgjt8OfmhrSZrMbztjnEAztubxprTkVd2cdUkiurq
         RGG5VIHFvEuwGHP6+mRYtIc8M8nPVQ6iHU2s5NnjPWHqD70+BcmN9QyoW3/3gtJsbgMT
         Bc+iM+BeUMYgZfyhmIS3hhEOiBff8gbxVVsO8dti+zoV4KpCiUqLyhSw48b0Ty0rIb8J
         3sNhDyh1Q6zB4DC2HGU0ljoaHEijo+huzkGYlAmoucXonrEiRxQE4TgcIdwWeIMGqdKO
         C4c0d5lzeISPuuXubrumG+0s6l19xnAjZicCzi4BpubYtAkJVHR/YSQ1zi+wgC0sHKZp
         9Y7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xwTOlY4E;
       spf=pass (google.com: domain of 3mzafaqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3MzAfaQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba093esi48188e87.3.2025.11.20.07.13.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mzafaqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477a1e2b372so8553895e9.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVedm02gysGQOPLHfubgsqajzuZ6XMNg7jU5evfbNZxnVoF+hVv1cM0jzNQg8VqsYxcwG/Lr/vSiv8=@googlegroups.com
X-Received: from wmd10.prod.google.com ([2002:a05:600c:604a:b0:477:9c68:bd6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1c1b:b0:471:c72:c7f8
 with SMTP id 5b1f17b1804b1-477b9e1cbfbmr31262875e9.21.1763651635197; Thu, 20
 Nov 2025 07:13:55 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:57 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-33-elver@google.com>
Subject: [PATCH v4 32/35] printk: Move locking annotation to printk.c
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
 header.i=@google.com header.s=20230601 header.b=xwTOlY4E;       spf=pass
 (google.com: domain of 3mzafaqukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3MzAfaQUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
index 031a58dc2b91..1eb3c9d9d6ae 100644
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
index 5aee9ffb16b9..7646952a92f1 100644
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-33-elver%40google.com.
