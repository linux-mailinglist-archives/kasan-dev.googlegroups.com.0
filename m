Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAVEWDDAMGQEOBVBVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 62901B8500B
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:07:00 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45f2f1a650dsf7146375e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:07:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204419; cv=pass;
        d=google.com; s=arc-20240605;
        b=UA+dTwsaC0pYNLqUm3/JbyI2C4DLT0YQA2xgWwzqVpWoH7Zf19DG3sPpS66dfcXvLZ
         gdVTDgQe8aHteon9t96r9gNkIRTWLllK1/uj2g/zZuhGTyZNC2HqIfa1uPvVpGEsirRQ
         RbJPqaekANrZVMvhRmJR1zk+9aubqZSiPF9ChxGzUbB4l0iOvdaAGsnsiG7XTbdO380L
         LOPmoLJImEXkFoiUSKgp617SlDNjA3nHvkw6F4Xsuf+KinsHJV70QOTE6BvDBSP/QAVS
         5KsfFUZALrjUYetBGUEjOOtBmUSImNcHfHI8BQIUuRX/R7YsoMp6Dh8No2wfjTSE+VoA
         6JBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zfn1Cld45Q3H8FRzLJ3dnnD+YiEgyZVqNLh2RdCW7L0=;
        fh=n9kSN3rcUOlPn3M+23TK9I7XlKV1iNn+iBoYPnDsUsk=;
        b=TAiZI7ojEOrgUElncw5fKc0y+STRth6IZmSlgKPBSBdibed2xjGz/a/sPqsjhDh4dg
         nfz8MeHUxEC4pv1SxqoxnTyg9c2BJ1WnubAI748fS5mc6z2si61/cve4QjkaSP3DIzqJ
         N/bzrsHJlw7NTYbwceM1CKYyQ6dnTc2eb0LHSojADXXLGocw1CdRgAoXnRlv7CWksGZ9
         rL8kRN73ormQ6h19I49ScZdI7OAU9JOd1jBH/9XksZwWz9X2Sk6MO39zP/n2RyAfccp1
         nz40N2UIydz8U1vMKKDEswTFrDpZu5JfNOoDVihP3x14YkRJLi2eE+254Fgri7m13+Tp
         lDrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FiqgY3wP;
       spf=pass (google.com: domain of 3_rhmaaukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3_RHMaAUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204419; x=1758809219; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zfn1Cld45Q3H8FRzLJ3dnnD+YiEgyZVqNLh2RdCW7L0=;
        b=leQtW6uHOpJvbKgUCDjXU9jHKXnXSBzazWGuR1Bc2oHwU1D8krpzwbW3JDkay43n1P
         zkuoh+y2tQwI1lX/7YxfCgNqWhXS16CkUVYfpiGx4n1s2XndSQdT6Pm2iYZ0fgMOMDAx
         yj1ZpNPixlLjAKBF9vH6dXlunBswPjlkibrcAoC32SVVZ0/3G5ll6CVyMxD2HlPKl+p/
         FctsBNLH6eglaR9B5jb5lbEBOR8T8VepfBseCUxthMHXpoqdufFph8wXd43U84ucMAkg
         L+AJQPSOQ7ZD5vI+pCy22sq7jWqwc1j8ApEkvEN4TiUZqfx7nRzq+U8yOv3aGiwaY4Xj
         FQeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204419; x=1758809219;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zfn1Cld45Q3H8FRzLJ3dnnD+YiEgyZVqNLh2RdCW7L0=;
        b=phmxorV7N/yo0+Ny6KwZ60IfJWt0R7IcPUXfD8Eex0CVIcpQk7UCifBJsSolNeSiSF
         1CaU4LEtqn2DCQLS7yj1BMzZpoKMmljJDnrRi/zWJWiGGPP5Me9TgegoaMsVNZNJ5Jkb
         jdXWfxkAwBw6sK5EwYJdH7V82lDIhBZIYoFCCXdda1F1Ee/J2ADsk09WeC8E9s7i9MfW
         H9fxAbEzOnaHILYZ+D8dYmkfcuJgUaqilD1vaabW7tjhCCo9yWA55wO2Y9aHcVo7BHpf
         vmdIbjnYU1V9ZPa2TPm92Rjg43IqRIij6/U6+ovxucpAIhqD2torCvc1XSMmXyrEjXRJ
         RPdg==
X-Forwarded-Encrypted: i=2; AJvYcCWz4HOAcFqzT06nkj+CwkfZY7idIMgmDgdMZzwBDlb1yvl/FniWD8X9UGOz1dSxlbo20VsgLQ==@lfdr.de
X-Gm-Message-State: AOJu0YyCOi7J+lHSUZpWjosxxkxK2x2a8GMhMchH6a2MwF5rJKI0pEn+
	V6+fnSfyIO3hbFYcavzY/ndmQtB99GHwmsiRlFiUBreD35f3s95x7k9d
X-Google-Smtp-Source: AGHT+IHqnDhl3FCWYTboOjDgHxnwafy0wN9gj2FEtwRFqdcTv+kyJ9OWeMp3yLt9EXl/3uDCyun8GQ==
X-Received: by 2002:a05:600c:3111:b0:45d:d287:d339 with SMTP id 5b1f17b1804b1-4620683f1e4mr61882175e9.25.1758204418772;
        Thu, 18 Sep 2025 07:06:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd64gbY7AsDB+/z3qJ9ePjgoeIBG8QVdNs69zJGM5k/9vQ==
Received: by 2002:a05:600c:1c86:b0:458:bc96:3b4d with SMTP id
 5b1f17b1804b1-465de21968als3631675e9.0.-pod-prod-01-eu; Thu, 18 Sep 2025
 07:06:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViNgbXNWWXOJT08qg3CPU2B8x8Okhl4rsXDZBGKHMcV/hU5iRGUWb+7cu2CpG0VxsxYVxMR3OkOLY=@googlegroups.com
X-Received: by 2002:a05:600c:1f13:b0:456:1560:7c5f with SMTP id 5b1f17b1804b1-46202a0e7bemr56109125e9.14.1758204413840;
        Thu, 18 Sep 2025 07:06:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204413; cv=none;
        d=google.com; s=arc-20240605;
        b=NQS+OpTEgnA4GfVqQHKf7TQy8uddWegJVgauM4d1WVC6EDPscpUwBpddDvjjSqqjAD
         lHWo33QnNRnjOZWb5o74jVY1xPSJIHe4/UEeG1ih4h180u75z5bAlKwH3GWu84FfB3Yb
         I66lKeqXmjLfzronD2a4Lt37jhKWMA1JDVpcxHsboux8nT3thnWP+wfm1wFSulPDspGc
         kxtRB8fqFwpL8QZmvuv7enq9oXTOi5FAByOhD1ijaIatxoJulasu//Bbh/GxBi4/Y1Xd
         5NH6VOOYCzE63jBCc3ymvUh7LVIEKReG53nbf1pzUPPtVTKepRzfHE94i136KLwhPESt
         7Fqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=m6Ln8CuHzwdFEdgMDhrRww1RTgWw9IPMarfKDLj88go=;
        fh=/Y+MJSLqH/sNQJtGbWf1NDV4klipzp9O2r+aJeC8suM=;
        b=BkE9Mm+MX5NdZf8DJt5CdTK7bYF8RX+AdhFyEttglM+ZXRM9rk475AB6314xiiaDxN
         8SUk3opEA+zfEVgU1klCIwpXHkE3rqfRN7sHZt+JVILmz2BohbSUNjOFScHiNV5yKdA+
         FQfzkZK9V5LoDcJjNra1Ka2xK4Z7yUp8bfannILFOA1UIpAoSDhDzO/oTwjb0gaOVxuO
         y1IUxW1wX/+Nn9ycYNO6ifqpEF1E67HUnGeo2n/UYfZYNaiUC6WH5onTJQdYlSWhTdKm
         eXcJxKPhKHHUsNkE1xJBQCdahh1Q7KGWYVf9hz5smSb30HS4wMOml5py9V4LgbYEH7gZ
         qGfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FiqgY3wP;
       spf=pass (google.com: domain of 3_rhmaaukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3_RHMaAUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f32088d94si560075e9.0.2025.09.18.07.06.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_rhmaaukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45f2b9b99f0so6250275e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWv/sDX9mY1UOsQoDkKT+87AWkJwjd628it0E7YR94ntSnJuj2iHri8A69Apa4rqvjyNNjBZOb0/Pk=@googlegroups.com
X-Received: from wmbhc26.prod.google.com ([2002:a05:600c:871a:b0:45f:2859:5428])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a7b:cbd6:0:b0:45b:47e1:ef7b
 with SMTP id 5b1f17b1804b1-46506364ce0mr25439175e9.17.1758204413172; Thu, 18
 Sep 2025 07:06:53 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:43 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-33-elver@google.com>
Subject: [PATCH v3 32/35] printk: Move locking annotation to printk.c
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
 header.i=@google.com header.s=20230601 header.b=FiqgY3wP;       spf=pass
 (google.com: domain of 3_rhmaaukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3_RHMaAUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
index 8f10d0a85bb4..6bc0a42e118c 100644
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
index 0efbcdda9aab..e0bfc66152aa 100644
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-33-elver%40google.com.
