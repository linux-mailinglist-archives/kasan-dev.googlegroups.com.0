Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37GSXFAMGQE3LD4RMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C94ACD0998
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:57 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59436279838sf1548402e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159216; cv=pass;
        d=google.com; s=arc-20240605;
        b=Af/oG9YsQOywK9pOl54STF3qedckXmE02ClVPQg3vsDXytM1IfFLKGRB4r511z5TEx
         OSu3tc+adxVgvq5PF4dqvQQKcS+BMu6OM0vBRDvM2gm8a3nemIXix35T70Rb23UDADR/
         pT6WtE2/AiJGHUwBoxE3aoAxbOh79XkQ7WnE0g75ETPj2t9Glo99dgorLsPZv/LdAlxi
         3aIQsNOndieBEEPpIs+4cKPbAmvZYwedHbeKnNEBHt/G7OZ19+XY0Wb2qlBJjZVpD+4U
         g5tZ7SCtFJw01cBvEfQzHfOi/FQ/Q/lsDkcY7Pdhw/rTM/vj7oLPSP8ec3aeipIKN7EX
         LTXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YsMYyWUnKOLLSkyE6LLwv17VMm8PmaUE9CSXsvCZy8M=;
        fh=Zq1UWgpkSNoK+oOboRZkqE8zDVKm7zyB715S+L556Og=;
        b=SVye7t7hYI4i53o0uktplXfaoe0RZgc6tgcFhLqCe7OZnZ8IQ/AKeveLpZ8RS5xIXY
         wwrkAcqtNJtIbfIQygmJBUIITItRHujBrbIZY8p5h2goLnXe9g27vwDsPW8+Nqr0dY36
         JE3EokX5ESZNUjzUhx6ptjqrsSyU6693e5RQ3rEKsUIpq6wuuyDfpJh+5SkvUuXf0YsG
         g+EJRanev0YWn3eN+8QtyjZnuDP8X0dNPwBTz/GqtCtY47magcDeNJQcKDYyjYXJOCgH
         6z18PI8RwOM6aFy+Gw6v+/ETkhpCF+hFYlg3Z+346lQRiGAS5OpuqwLecGp6X9aHzQU9
         gCRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="KuT1m6m/";
       spf=pass (google.com: domain of 3bhnfaqukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3bHNFaQUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159216; x=1766764016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YsMYyWUnKOLLSkyE6LLwv17VMm8PmaUE9CSXsvCZy8M=;
        b=BNazTjudKifRwFm9URovSP9691KMg+XVDuPgKOJ7rYOU2xEwSwADaosCe9W2PKFJac
         N/cqvNPFmt4bIH27DKXrb2+x/ZEJck9JavoAWt/irVzxEgxzR6ZvIIhrqxa1xks/F0xU
         lJT7Judu6g00NZRytvEl5D2PLgWXrXM8UPDAXZwpWeMZZWKowyb84qNy2BUNhNRyPIHS
         iTca0bY4kpLbTiQV+3ZCrtMhwmNhEzFW0D3MUQI3PPdxSxl1rFqod2Y5LYqYa/JJw3T/
         MLJmdNbsQjAo/QOGfTqLHknFWlH++mMDBpg1NT0Yy4Woz6AUkk873iTSBo0D1Xg06KAi
         1KjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159216; x=1766764016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YsMYyWUnKOLLSkyE6LLwv17VMm8PmaUE9CSXsvCZy8M=;
        b=Ae5h02itoPqYHgjGdoup12NNQmg6z/hz6ZBbhydehSGw/TonBNDOrmww3tFqhJPNOy
         pUOLj0qkjiafTTnkMlaXD3KcWNWi+xL+/A0qDosUpAIcm19RYPqz3JyRcqvuF6JnTfrW
         +2UawL+2In6GSDKPL2L/kjhFEh16mxyujI5chICiRfrpvWUMRI9RjZstl3+2eDkD4JFJ
         ttres5hB5tXR1tEmtiTzyNtcLNXAZxozWCrT757O1r4M2gGneic2JSkgClD7jbWIeoOp
         apCyfCE916mBxh8uTaGzCyhVB3AojSRflI8H/nWpFClXyB+OEQBQNNkztw8/+uErtkSM
         YRTg==
X-Forwarded-Encrypted: i=2; AJvYcCWGmu3uiJ0LErTDGdBw5cf24oud1mUE9ZYoIU/jIHZoL7BBaO5jbbuIx7YR5ISUExm1EaLjKw==@lfdr.de
X-Gm-Message-State: AOJu0Yxn1QqmcbtObQ1Vmnucet73AbFF89vCN3bCqgssiQcP1AZWFmHl
	AbwA6HcBSyweL8/54Ma5qSh2E+AxG8TnTjQ6okFG2JQo/YfKcj9RRvQc
X-Google-Smtp-Source: AGHT+IFtSWTJ7IPwfQKuOKYFZRb9M3jncVSUTJJF6vn/kWralB470vruCNd9+apbikTokilvqxxQ8w==
X-Received: by 2002:a05:6512:b0f:b0:594:490b:4498 with SMTP id 2adb3069b0e04-59a17cff527mr1407414e87.11.1766159216213;
        Fri, 19 Dec 2025 07:46:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ9/pFEIZmUD+qVaMdiNtpvQVMZHLAvjU6XgyDCJFAkmA=="
Received: by 2002:a05:6512:202c:b0:599:36b:f693 with SMTP id
 2adb3069b0e04-599036bf765ls1540178e87.1.-pod-prod-05-eu; Fri, 19 Dec 2025
 07:46:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFi/WhTogjB8WFcte62Z+W9NpYUfqvglH7VZ0OvknuvIDDYftekihQDnIdCYvLrULXi7VuVfYw3BA=@googlegroups.com
X-Received: by 2002:a05:6512:3d07:b0:599:fe3:77d with SMTP id 2adb3069b0e04-59a17d5f153mr1258254e87.45.1766159213292;
        Fri, 19 Dec 2025 07:46:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159213; cv=none;
        d=google.com; s=arc-20240605;
        b=S7ucnurneoe5j0nI4gsfhighGM7Eco0IU33fpikZjHYtPCwhVsQnKtVcmbtx2kCjbj
         DY+enwvzAK8oA5A1eivPqP0SRXOjNNZYkvvaaveuSCrcVb9q14P2hk6CtHsbipXYgHcB
         GegDTaq0B0e0MbFkchAoevbPzL8f8SAP/B83HInLK1n8VkmlWX2e6VBsnTJVtYeEAVju
         XqbENb4qGUs6i3y0QJSANJFD2I/5hc55riA6NJK+tyKj+CuXBe2QNYoaaDxEbXBl9scG
         HF1QpfK4Gs5kcoNHj8W3FPQ8m4gE3DtK4FrhQz6IG3OYo9U4BT00RAAV6h5I1kF1wKTo
         Fj1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BPiD3KqRf4YAgh6EJvt9JR+cuwWr4Dg7H+dSvPnSAFc=;
        fh=VVQyzvk4bb+cR7ppdvtbJcn6oNN/ZqwiXnDqW9lGwng=;
        b=kMlbtxnDOHI6K9fHysICG/3mLs3XZdNCOinlt6yS+zow2oBG4sgHwOuHx8+46mP8jn
         jdsAyKGMCWgTK7ZAVp4gUXln/N99r7tnn6XF/huKQStRGHFhnvKMvNQpJjkV2ImobbLg
         9cfJv2fsXUjD7rk7kz4jM1oTsNh+uwMZMcAVG/6WVyM4oWD/9165KmdIzQehz0Ovhey0
         kL78WmuWkw/iOGgSvz7UyL6z7d34jOYwRkxpEMWC8tRb4Kgtvx+7HNdCdWCP5cKCMtFm
         wMQzxgXhQ4W2seQcXxH52Btr13SfdOC944IplzSO4Xpzi4l5sGJY2JIofp41R9UlabAi
         Y8zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="KuT1m6m/";
       spf=pass (google.com: domain of 3bhnfaqukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3bHNFaQUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860d04bsi83502e87.4.2025.12.19.07.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bhnfaqukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477563e531cso12949155e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXYad9wB36UVuLt88SowBVB9HYqU05uUXv3CRs+gHwmQG9aATFM42Ly1PGiS+EMOmkD05F07q0HGuc=@googlegroups.com
X-Received: from wmco23.prod.google.com ([2002:a05:600c:a317:b0:477:93dd:bbb1])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600d:108:20b0:477:214f:bd95
 with SMTP id 5b1f17b1804b1-47d1c036d6cmr18724405e9.23.1766159212483; Fri, 19
 Dec 2025 07:46:52 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:11 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-23-elver@google.com>
Subject: [PATCH v5 22/36] um: Fix incorrect __acquires/__releases annotations
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
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org, 
	kernel test robot <lkp@intel.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Tiwei Bie <tiwei.btw@antgroup.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="KuT1m6m/";       spf=pass
 (google.com: domain of 3bhnfaqukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3bHNFaQUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

With Clang's context analysis, the compiler is a bit more strict about
what goes into the __acquires/__releases annotations and can't refer to
non-existent variables.

On an UM build, mm_id.h is transitively included into mm_types.h, and we
can observe the following error (if context analysis is enabled in e.g.
stackdepot.c):

   In file included from lib/stackdepot.c:17:
   In file included from include/linux/debugfs.h:15:
   In file included from include/linux/fs.h:5:
   In file included from include/linux/fs/super.h:5:
   In file included from include/linux/fs/super_types.h:7:
   In file included from include/linux/list_lru.h:14:
   In file included from include/linux/xarray.h:16:
   In file included from include/linux/gfp.h:7:
   In file included from include/linux/mmzone.h:22:
   In file included from include/linux/mm_types.h:26:
   In file included from arch/um/include/asm/mmu.h:12:
>> arch/um/include/shared/skas/mm_id.h:24:54: error: use of undeclared identifier 'turnstile'
      24 | void enter_turnstile(struct mm_id *mm_id) __acquires(turnstile);
         |                                                      ^~~~~~~~~
   arch/um/include/shared/skas/mm_id.h:25:53: error: use of undeclared identifier 'turnstile'
      25 | void exit_turnstile(struct mm_id *mm_id) __releases(turnstile);
         |                                                     ^~~~~~~~~

One (discarded) option was to use token_context_lock(turnstile) to just
define a token with the already used name, but that would not allow the
compiler to distinguish between different mm_id-dependent instances.

Another constraint is that struct mm_id is only declared and incomplete
in the header, so even if we tried to construct an expression to get to
the mutex instance, this would fail (including more headers transitively
everywhere should also be avoided).

Instead, just declare an mm_id-dependent helper to return the mutex, and
use the mm_id-dependent call expression in the __acquires/__releases
attributes; the compiler will consider the identity of the mutex to be
the call expression. Then using __get_turnstile() in the lock/unlock
wrappers (with context analysis enabled for mmu.c) the compiler will be
able to verify the implementation of the wrappers as-is.

We leave context analysis disabled in arch/um/kernel/skas/ for now. This
change is a preparatory change to allow enabling context analysis in
subsystems that include any of the above headers.

No functional change intended.

Closes: https://lore.kernel.org/oe-kbuild-all/202512171220.vHlvhpCr-lkp@intel.com/
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Cc: Johannes Berg <johannes@sipsolutions.net>
Cc: Tiwei Bie <tiwei.btw@antgroup.com>
---
 arch/um/include/shared/skas/mm_id.h |  5 +++--
 arch/um/kernel/skas/mmu.c           | 13 ++++++++-----
 2 files changed, 11 insertions(+), 7 deletions(-)

diff --git a/arch/um/include/shared/skas/mm_id.h b/arch/um/include/shared/skas/mm_id.h
index fb96c0bd8222..18c0621430d2 100644
--- a/arch/um/include/shared/skas/mm_id.h
+++ b/arch/um/include/shared/skas/mm_id.h
@@ -21,8 +21,9 @@ struct mm_id {
 	int syscall_fd_map[STUB_MAX_FDS];
 };
 
-void enter_turnstile(struct mm_id *mm_id) __acquires(turnstile);
-void exit_turnstile(struct mm_id *mm_id) __releases(turnstile);
+struct mutex *__get_turnstile(struct mm_id *mm_id);
+void enter_turnstile(struct mm_id *mm_id) __acquires(__get_turnstile(mm_id));
+void exit_turnstile(struct mm_id *mm_id) __releases(__get_turnstile(mm_id));
 
 void notify_mm_kill(int pid);
 
diff --git a/arch/um/kernel/skas/mmu.c b/arch/um/kernel/skas/mmu.c
index 00957788591b..b5017096028b 100644
--- a/arch/um/kernel/skas/mmu.c
+++ b/arch/um/kernel/skas/mmu.c
@@ -23,18 +23,21 @@ static_assert(sizeof(struct stub_data) == STUB_DATA_PAGES * UM_KERN_PAGE_SIZE);
 static spinlock_t mm_list_lock;
 static struct list_head mm_list;
 
-void enter_turnstile(struct mm_id *mm_id) __acquires(turnstile)
+struct mutex *__get_turnstile(struct mm_id *mm_id)
 {
 	struct mm_context *ctx = container_of(mm_id, struct mm_context, id);
 
-	mutex_lock(&ctx->turnstile);
+	return &ctx->turnstile;
 }
 
-void exit_turnstile(struct mm_id *mm_id) __releases(turnstile)
+void enter_turnstile(struct mm_id *mm_id)
 {
-	struct mm_context *ctx = container_of(mm_id, struct mm_context, id);
+	mutex_lock(__get_turnstile(mm_id));
+}
 
-	mutex_unlock(&ctx->turnstile);
+void exit_turnstile(struct mm_id *mm_id)
+{
+	mutex_unlock(__get_turnstile(mm_id));
 }
 
 int init_new_context(struct task_struct *task, struct mm_struct *mm)
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-23-elver%40google.com.
