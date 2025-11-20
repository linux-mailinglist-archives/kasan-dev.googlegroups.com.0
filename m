Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL7A7TEAMGQEUIHDNMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C757C74C9C
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:52 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5957d86f7f9sf1520548e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651632; cv=pass;
        d=google.com; s=arc-20240605;
        b=eibqWuNGdqS6Z0vdumZSFy/1EIxGTJLxK1jK2HJ96TUlUnFEZINlGHuVGEPeyZ2Qmk
         vqvSppXcSvPO9TsHAFhjlqRVPG6zzfkGss1Cu4VTEIQoTPQrbiN6J6eEs4bteQuBJdVW
         MBohUnGrEFfNCYWRIxPZBk1OxEsC22Ox1RiDrHHw5mTGv+61FbriddG+5O/7LGi1NDq8
         Oh4yzJuXlicEZBQ9G20pbT8rHFp2xz6P4DBO5vMjaFFuZp2yo64rugwqxXQmOWobGewM
         sECqj6vgpCyCMiA5p0o7r1ShpBInqgfcTvtSLoUX2X3u+HWpArjL+P1eFVE59OQvPfjs
         p2YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=N1Me93/Wup49hjHBMPmeeeoldn/XoorcAFyzEk06np4=;
        fh=dq6gIJhZPiH4nU5Cu3UwNeIyQlKGe+d1N/FPpQfMo3A=;
        b=JgYQgV/Hnm3c4D31GiyA4LEPwPO7DyJiAGCaqzRVDFCuBzUATIT78EwDE7MllyyDbT
         dcl+r4PoPi48fSD7CFwt5d9AYBbPL4iU7gnELm4m71I/l1Grjnfx64jyOJ1m6r7HWWCa
         gdfZj0HHO/T4c/vRzlP6kyLSfmdfNyMwyeNHSS/YMJeB43bzb0aoiBBpUoatXhxfjrdX
         ytaAhAfF1uCo0Mg7+GdF/BcNlXOZi902v0oJxBOzJw7XNR+k+E/Jv1G7dl0wBWLwTLpG
         M5NR1Nuq2H3iZlqCV9H0411Hz+Z5/XOncO5klrC7XtJTZ8zDFI6iE/tInY9eCh8kbr9z
         QR9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wLupDezR;
       spf=pass (google.com: domain of 3kzafaqukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3KzAfaQUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651632; x=1764256432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=N1Me93/Wup49hjHBMPmeeeoldn/XoorcAFyzEk06np4=;
        b=GUuyyGZUV9Ms/kuwVcjWofzyxJUAlQ0iMlDPadeonWpRkZAvwWRs+rlkqaGAJatRCl
         UUFj4PYyOeUB1Z7jPbbruGrBIs6bvXUrV6oNRsCod+aFlED8cIXmzULwTKMgaaCE1CKI
         aTYiZAf/WJAPStTm8CT/UTrb4CCNQep92DPA8IJ8hiDuSIPj00VifNVb4bYyLBmDAaub
         XLTmB71PxkYAZAa9ysCOTK2KjcrjxAESB8CmImNdk7IzT4vP8yi3xsQXJVe9jkMuYItr
         kcyKKv9sPfTwQ4HZpN1vsdIZk/wgAAcCIl/CAY6/kW5dxG7TsVjT6EoLdrpthGxorhxV
         N4FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651632; x=1764256432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N1Me93/Wup49hjHBMPmeeeoldn/XoorcAFyzEk06np4=;
        b=n5LN6EzRHyWi1oytbFzDEQdWffdSmb6vnf6MFdV2miYcPArTbj9sngM3SZwiEhJwGZ
         pSQR+Mz3QgbTOWLpShfXU7Z7virIWqyNEuE9zhx+9xGkkF9PL2CW2XlvACv0F38b9J7H
         GSbHI7OOET1wvwFkiHPauKaNxqjTtBrfMybMPzAih3Fc0LGNfMX6RrT1yXLxCKUHDMTQ
         ShJ/Ns88sKQQ1yBd30UlpD6qBfNdKg0yvVaR38d+FtblRXcyJ0Z7YSBJ9/oNNCUDiR7R
         os8uqUB1soLknNijBTZpaNUD13yzxdYl3CnuCvu1Ntzk+0QZJEXdUMr5zaGV3F0EHZCa
         MNOg==
X-Forwarded-Encrypted: i=2; AJvYcCVXbmI1NQA3Gweqbs2k3txP79w9pACaynGjPCndCGoQRqWan1/m1q2Y7OlcaS1SFCRoB0Xtug==@lfdr.de
X-Gm-Message-State: AOJu0YwiszLHSvxXezHT4V2CRg3ziYT+H08jEw8Vp4VDBRGtuSQXF5ok
	5y/iyYKNAoha6vK5zup88ctxIrFwhU0qf02JZHhPcX88pS7eCRmwo4yp
X-Google-Smtp-Source: AGHT+IHOL8kjiB0INb9IEDPu6IVh/Aot6s4Ku3wwklRT/l4JbU0ECLhV2rSF7WLdXSFAhw8wZvMVGg==
X-Received: by 2002:a05:6512:238d:b0:57d:b8a1:832b with SMTP id 2adb3069b0e04-5969e30c3f5mr1294862e87.24.1763651631910;
        Thu, 20 Nov 2025 07:13:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b0aOIQW1FsmPhiDVN5/9O61nd8Cji2UuFtfo2eZWyKXw=="
Received: by 2002:ac2:5688:0:b0:596:9cba:f5e2 with SMTP id 2adb3069b0e04-5969dc5e702ls158725e87.1.-pod-prod-06-eu;
 Thu, 20 Nov 2025 07:13:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGWnWkRPg7tCuaA8MUPXaephjHVf2dVVOLxHx1WV99PV1/qj2l6sA5jqiD7NYhbZU5c4CWBge/XGI=@googlegroups.com
X-Received: by 2002:a05:6512:3d04:b0:595:9d6b:1175 with SMTP id 2adb3069b0e04-5969e2dea65mr1223571e87.14.1763651628818;
        Thu, 20 Nov 2025 07:13:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651628; cv=none;
        d=google.com; s=arc-20240605;
        b=PGMZ4upbYw3g1q6aEusjU9n/i9m4j9dElXFkAiQxwaAbtNPkh1UtxqS+SHGwDuDUSe
         hfDppTkhsDg23Rw52icWzRlvzYumUye0FkHxAs7sg8t12AInQHKwwwyRSxxD9FQ/3nF9
         +BSX4TbuZ28hSRxCtGpf/VtkHCB1/k3Sc5qUp83a6eEkAl/7d+SMrAs8gTrf6mjq6/lK
         gHt0VeabCBIE8l0K8I0KVbSxMIbPbUi36ws57XXF34lZSY5iPLXHwtnndZhqO0ylH7Zy
         gd7t8NF9Xa5EG3as2A71BXXx/ItwCbqYJtWR6ovjiyUUQAKzZGnNSHA37h/QxVxVOx6D
         49wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aJMOXRb0WgY3NkQlI/hPCIKlELlXVsKWBZcrKDKyFiM=;
        fh=gbryoF6tDDS65xm7kDqhL1U6nka3lQvFipagpCXu1Ss=;
        b=lAouk25W/75uHCHPOCye8Yq0p6yoIWYft0VTwF/mvDposBDpP3TrzLd2QrQg2xiYpd
         D3DHstLKWTB2dv46CgPFLfjULEZr5YcbxxV7wAFUcVZZKDwiY0+JWjMKE3gOV/z5USKg
         QLgE2FRNL0REQXMGbOYfrmCD5ogEXSrZxupgrGJt7fGOBg5vdar0t427mcsGQfbZCzDm
         IXufbPu+8WDDg0dDmOIp8ZN5EqjRt6n1Wcm9MrT4WWG5IEtEdMKV8OSUr8ikIyxL1QHj
         XDWc89PgWPsW0/JIEXkLxAhg/iU4Mybt2XK7S0x54pr8c1gcrE/i6B3A6cqpdx027Ynl
         BUJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wLupDezR;
       spf=pass (google.com: domain of 3kzafaqukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3KzAfaQUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dbac281si61214e87.5.2025.11.20.07.13.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kzafaqukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775fcf67d8so10455815e9.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWmFhDpN32FhxwARebD1lMeKWFzM0e80Z38mRLY/E9YIyd40QOvBfMiKprnKDBhvFPsLbc8O/7XdjQ=@googlegroups.com
X-Received: from wmpi31.prod.google.com ([2002:a05:600c:4b1f:b0:477:55c0:6392])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4f49:b0:477:7991:5d1e
 with SMTP id 5b1f17b1804b1-477b8a9fd96mr32224715e9.25.1763651627745; Thu, 20
 Nov 2025 07:13:47 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:55 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-31-elver@google.com>
Subject: [PATCH v4 30/35] stackdepot: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=wLupDezR;       spf=pass
 (google.com: domain of 3kzafaqukcvg4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3KzAfaQUKCVg4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Enable context analysis for stackdepot.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* Remove disable/enable_context_analysis() around headers.
---
 lib/Makefile     |  1 +
 lib/stackdepot.c | 20 ++++++++++++++------
 2 files changed, 15 insertions(+), 6 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index 59ed5f881bcb..2e983f37d173 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -248,6 +248,7 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 # Prevent the compiler from calling builtins like memcmp() or bcmp() from this
 # file.
 CFLAGS_stackdepot.o += -fno-builtin
+CONTEXT_ANALYSIS_stackdepot.o := y
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
 # In particular, instrumenting stackdepot.c with KMSAN will result in infinite
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index de0b0025af2b..166f50ad8391 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -61,18 +61,18 @@ static unsigned int stack_bucket_number_order;
 /* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
+/* The lock must be held when performing pool or freelist modifications. */
+static DEFINE_RAW_SPINLOCK(pool_lock);
 /* Array of memory regions that store stack records. */
-static void **stack_pools;
+static void **stack_pools __pt_guarded_by(&pool_lock);
 /* Newly allocated pool that is not yet added to stack_pools. */
 static void *new_pool;
 /* Number of pools in stack_pools. */
 static int pools_num;
 /* Offset to the unused space in the currently used pool. */
-static size_t pool_offset = DEPOT_POOL_SIZE;
+static size_t pool_offset __guarded_by(&pool_lock) = DEPOT_POOL_SIZE;
 /* Freelist of stack records within stack_pools. */
-static LIST_HEAD(free_stacks);
-/* The lock must be held when performing pool or freelist modifications. */
-static DEFINE_RAW_SPINLOCK(pool_lock);
+static __guarded_by(&pool_lock) LIST_HEAD(free_stacks);
 
 /* Statistics counters for debugfs. */
 enum depot_counter_id {
@@ -291,6 +291,7 @@ EXPORT_SYMBOL_GPL(stack_depot_init);
  * Initializes new stack pool, and updates the list of pools.
  */
 static bool depot_init_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -338,6 +339,7 @@ static bool depot_init_pool(void **prealloc)
 
 /* Keeps the preallocated memory to be used for a new stack depot pool. */
 static void depot_keep_new_pool(void **prealloc)
+	__must_hold(&pool_lock)
 {
 	lockdep_assert_held(&pool_lock);
 
@@ -357,6 +359,7 @@ static void depot_keep_new_pool(void **prealloc)
  * the current pre-allocation.
  */
 static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 	void *current_pool;
@@ -391,6 +394,7 @@ static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
 
 /* Try to find next free usable entry from the freelist. */
 static struct stack_record *depot_pop_free(void)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack;
 
@@ -428,6 +432,7 @@ static inline size_t depot_stack_record_size(struct stack_record *s, unsigned in
 /* Allocates a new stack in a stack depot pool. */
 static struct stack_record *
 depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
+	__must_hold(&pool_lock)
 {
 	struct stack_record *stack = NULL;
 	size_t record_size;
@@ -486,6 +491,7 @@ depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, dep
 }
 
 static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
+	__must_not_hold(&pool_lock)
 {
 	const int pools_num_cached = READ_ONCE(pools_num);
 	union handle_parts parts = { .handle = handle };
@@ -502,7 +508,8 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 		return NULL;
 	}
 
-	pool = stack_pools[pool_index];
+	/* @pool_index either valid, or user passed in corrupted value. */
+	pool = context_unsafe(stack_pools[pool_index]);
 	if (WARN_ON(!pool))
 		return NULL;
 
@@ -515,6 +522,7 @@ static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
 
 /* Links stack into the freelist. */
 static void depot_free_stack(struct stack_record *stack)
+	__must_not_hold(&pool_lock)
 {
 	unsigned long flags;
 
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-31-elver%40google.com.
