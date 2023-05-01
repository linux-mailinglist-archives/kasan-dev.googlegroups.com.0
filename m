Return-Path: <kasan-dev+bncBC7OD3FKWUERBOG6X6RAMGQEUFCBE7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B5D36F33F6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:56:25 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-32b62107509sf39239635ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:56:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960184; cv=pass;
        d=google.com; s=arc-20160816;
        b=VJ3sukX+Ge8cC0Bu9h0KGsjqInVJI7KpLAv2AZ9fBBLIQUpV+XGco1sXC3eRKMVtI5
         uFktSR2dimzg+G5XOBiZIsu734lxG4TvJM5Nqi93ezBK4GHq75UtkebPDoc9glecnR+P
         uateCi5fqjlNYRNhhlNXTCZSD0OHcXPVMuDXT4hAYYoUwTuMNJMZ1lvETyAbRf1XhEEL
         04tS0OpoztCa35r/NkITH8OxISkLoVc16Ouqz0K/p+V1LelTMtrFXtq9XOqUp6Aw2I9Q
         BWpIuEOHzAWAMQKwn70FFg8K2xbKAU0XnYOdEENZJpvIApW5Hg1N+RQiSUTo4KAyo1EW
         /5yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=V3lj+ZBD38CuA13jochUjbnLJwAKvvEMQI5ByXQkdg0=;
        b=vWM4WOrMiyBZ4jc+c9k3QGXq9wXCOwk2X20bsf9Ph91uK9sqS+Fe5Z8a5xQbCt1aXN
         cdfgneiTrMx81cn87jaUNAbQUCA0pjYi5Tn80c8ZObxMvrXhkyPgCT2oCug8XaCD4uwX
         +97tzAIA8/hz9tppky16dAN6uSf6Qi/w9hBdt0HUcr9Vz0otAwnaiodY9jBn5kCXwNG0
         12OKUcvqc3Z7LFir+mER2tkPJ0kOn8pAq3qITInBWHDpb9zhAJJ5GkffGgkgmhfmsSs/
         1CGivVQbXPES0lS4EvW/1bFSEbHOzxBPkyT1ia/e9Bp8q4OV/nxdoHfIPLwGfLZh0Syl
         /0TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ebS+MuTL;
       spf=pass (google.com: domain of 3n-9pzaykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3N-9PZAYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960184; x=1685552184;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=V3lj+ZBD38CuA13jochUjbnLJwAKvvEMQI5ByXQkdg0=;
        b=E+UFw528nOkfYNQlYn21hhv6niDKpErxsxsZ60f6iePZsojcm6YsIwlWQuSjxaFMsM
         oH4E2WNliq2GvX99zQtFY7q6ZDtl6O36m5NoHVL91JClmgA7EpJuBz8/4WOefsezJYQb
         8LAqee+nXzMTC6mFvFLjc7vidVGRbRmqNp9uMNrKhvd3U14m4dldvRWw+vJyEJO8R6rN
         ontMWdI4fdSqc/g2rebRIFMmeQH60LibkuRUwcBx1+XnxvxGBxDLkawqWoCNIL5FS1uQ
         +CCuEfKwdxLENWXXgPalXLoR0sopVfLSrdLwC7AsBYw2oCfZGFslhnnOaGtWtj+lsc11
         ApKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960184; x=1685552184;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V3lj+ZBD38CuA13jochUjbnLJwAKvvEMQI5ByXQkdg0=;
        b=js4h7XKtYCG9geyweKNBqCPf9I4s+veAdY1WkAb5YoVmCpXvoz8L5+uc6olyMt1kaG
         bbxvrN9Kz6IYcJ6lBmif1p0gVPEJh0uSTRPSZ2+PbHM6dlW2rZpSmpNAbEGBN0NMeosF
         Rt+5y/m8vEMm+162Qgq4h4wZu47m3XQXjYFXrfngWfWOEUu1JJBnQDfvTwR27WXRQ9a5
         tw+akQYzT7e3kmJT2uCIYe6v53xfetFyPfIsYzOc1BGYHeJP8cyK+l+BP+fIlBOdM6Gf
         1tJFcad7Oyu7PG990K6O6SxbwnvJGM53uaP1RUDoKDOykAaeUZle+4dM45yqkk3O9Ffw
         w6lw==
X-Gm-Message-State: AC+VfDxGhLSb5W/amw7D4mHa5hkY4UgBAfyhYiIRh+E8/LVdCIt3c9i4
	30MwUCnIyRWcEHked5B5XQw=
X-Google-Smtp-Source: ACHHUZ6hZDX+0IFk5+U9W0o3bdQsLDpJcJwMbWBbB/UkZ6hCbUaW7GWk17U0rgShF/hK53eD5InUlg==
X-Received: by 2002:a92:cf42:0:b0:32f:210b:b100 with SMTP id c2-20020a92cf42000000b0032f210bb100mr7423083ilr.1.1682960184074;
        Mon, 01 May 2023 09:56:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:3947:b0:762:bc18:99b with SMTP id
 bt7-20020a056602394700b00762bc18099bls2146495iob.8.-pod-prod-gmail; Mon, 01
 May 2023 09:56:23 -0700 (PDT)
X-Received: by 2002:a6b:f40e:0:b0:74c:b180:c5db with SMTP id i14-20020a6bf40e000000b0074cb180c5dbmr8600955iog.20.1682960183553;
        Mon, 01 May 2023 09:56:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960183; cv=none;
        d=google.com; s=arc-20160816;
        b=I5Iiw5FbnaCAF+Y9ORdXF/5BK4IOBjuJ2Rj5qIGoNZ3mvbqha9e85aQPaV86JWa5B2
         G0pfpj8gnYSpEuV2JqXjWoNxasJaGckFwFmsEpW9uG1kB4qpObHOyUr19foADwtudp9B
         xJLr3Ix2EEVG61EyHFgUndPUrc5e0kJya7zefrEvBrzPMDLcUWDpZhhIbJE+QNJoI4VJ
         hJuD/2XbjWIwiH/0ZVIEYtWm2IB7QbWCzLy4Uo3IEb9YPk3nmp7Ae/8UM7HA5PoZc2EC
         bI8UoEc8efD+HzEass7saQdnpOCCjBgDD2MFcKt1iR5Mt+9QP5wIHz0oy93GQEwGWSj0
         l+cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bfMxO5ATd5n4S/fh5B/Nudv/nxDkBrDhDPER315pa0U=;
        b=tHgOUQz0d1Q7x9aLYuJgzzpl9r88Ff3BE4Nco8n4wJAWMYJgXw6wyGkRiphw2iW84U
         MJFyhZtdqsfpMULQNi8BBPvnVRCPZBmqOGYyU/GW6LdxzWWKKWExXIXNUqkcv+3RrlhE
         KVzvc0QLz6sUiKKcqA4t0On+f5CIVKZIHJXjmuteCRZVXJgd18IsqbcjPo0dzzaTNmJh
         SzG/2pdFMcgYxi+wfOzxy0x2jOnexqxiwS0nD9eapGpogG74Ss6Ow+Ab47849UMfKI6G
         plhItj/P2zfzlAR5V6M1b2y7/wvneStdI3rtg9gRIZfluPB/3xUauY6qQchycjn/r4XF
         jglw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ebS+MuTL;
       spf=pass (google.com: domain of 3n-9pzaykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3N-9PZAYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id t21-20020a056602141500b00763b993e80esi1343989iov.4.2023.05.01.09.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:56:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n-9pzaykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b8f6bef3d4aso5547736276.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:56:23 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:8046:0:b0:b9d:c866:d92d with SMTP id
 a6-20020a258046000000b00b9dc866d92dmr3485899ybn.1.1682960183189; Mon, 01 May
 2023 09:56:23 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:43 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-34-surenb@google.com>
Subject: [PATCH 33/40] move stack capture functionality into a separate
 function for reuse
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ebS+MuTL;       spf=pass
 (google.com: domain of 3n-9pzaykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3N-9PZAYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

Make save_stack() function part of stackdepot API to be used outside of
page_owner. Also rename task_struct's in_page_owner to in_capture_stack
flag to better convey the wider use of this flag.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/sched.h      |  6 ++--
 include/linux/stackdepot.h | 16 +++++++++
 lib/stackdepot.c           | 68 ++++++++++++++++++++++++++++++++++++++
 mm/page_owner.c            | 52 ++---------------------------
 4 files changed, 90 insertions(+), 52 deletions(-)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 33708bf8f191..6eca46ab6d78 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -942,9 +942,9 @@ struct task_struct {
 	/* Stalled due to lack of memory */
 	unsigned			in_memstall:1;
 #endif
-#ifdef CONFIG_PAGE_OWNER
-	/* Used by page_owner=on to detect recursion in page tracking. */
-	unsigned			in_page_owner:1;
+#ifdef CONFIG_STACKDEPOT
+	/* Used by stack_depot_capture_stack to detect recursion. */
+	unsigned			in_capture_stack:1;
 #endif
 #ifdef CONFIG_EVENTFD
 	/* Recursion prevention for eventfd_signal() */
diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index e58306783d8e..baf7e80cf449 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -164,4 +164,20 @@ depot_stack_handle_t __must_check stack_depot_set_extra_bits(
  */
 unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
 
+/**
+ * stack_depot_capture_init - Initialize stack depot capture mechanism
+ *
+ * Return: Stack depot initialization status
+ */
+bool stack_depot_capture_init(void);
+
+/**
+ * stack_depot_capture_stack - Capture current stack trace into stack depot
+ *
+ * @flags:	Allocation GFP flags
+ *
+ * Return: Handle of the stack trace stored in depot, 0 on failure
+ */
+depot_stack_handle_t stack_depot_capture_stack(gfp_t flags);
+
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..c7e5e22fcb16 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -539,3 +539,71 @@ unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
 	return parts.extra;
 }
 EXPORT_SYMBOL(stack_depot_get_extra_bits);
+
+static depot_stack_handle_t recursion_handle;
+static depot_stack_handle_t failure_handle;
+
+static __always_inline depot_stack_handle_t create_custom_stack(void)
+{
+	unsigned long entries[4];
+	unsigned int nr_entries;
+
+	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
+	return stack_depot_save(entries, nr_entries, GFP_KERNEL);
+}
+
+static noinline void register_recursion_stack(void)
+{
+	recursion_handle = create_custom_stack();
+}
+
+static noinline void register_failure_stack(void)
+{
+	failure_handle = create_custom_stack();
+}
+
+bool stack_depot_capture_init(void)
+{
+	static DEFINE_MUTEX(stack_depot_capture_init_mutex);
+	static bool utility_stacks_ready;
+
+	mutex_lock(&stack_depot_capture_init_mutex);
+	if (!utility_stacks_ready) {
+		register_recursion_stack();
+		register_failure_stack();
+		utility_stacks_ready = true;
+	}
+	mutex_unlock(&stack_depot_capture_init_mutex);
+
+	return utility_stacks_ready;
+}
+
+/* TODO: teach stack_depot_capture_stack to use off stack temporal storage */
+#define CAPTURE_STACK_DEPTH (16)
+
+depot_stack_handle_t stack_depot_capture_stack(gfp_t flags)
+{
+	unsigned long entries[CAPTURE_STACK_DEPTH];
+	depot_stack_handle_t handle;
+	unsigned int nr_entries;
+
+	/*
+	 * Avoid recursion.
+	 *
+	 * Sometimes page metadata allocation tracking requires more
+	 * memory to be allocated:
+	 * - when new stack trace is saved to stack depot
+	 * - when backtrace itself is calculated (ia64)
+	 */
+	if (current->in_capture_stack)
+		return recursion_handle;
+	current->in_capture_stack = 1;
+
+	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 2);
+	handle = stack_depot_save(entries, nr_entries, flags);
+	if (!handle)
+		handle = failure_handle;
+
+	current->in_capture_stack = 0;
+	return handle;
+}
diff --git a/mm/page_owner.c b/mm/page_owner.c
index 8b6086c666e6..9fafbc290d5b 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -15,12 +15,6 @@
 
 #include "internal.h"
 
-/*
- * TODO: teach PAGE_OWNER_STACK_DEPTH (__dump_page_owner and save_stack)
- * to use off stack temporal storage
- */
-#define PAGE_OWNER_STACK_DEPTH (16)
-
 struct page_owner {
 	unsigned short order;
 	short last_migrate_reason;
@@ -37,8 +31,6 @@ struct page_owner {
 static bool page_owner_enabled __initdata;
 DEFINE_STATIC_KEY_FALSE(page_owner_inited);
 
-static depot_stack_handle_t dummy_handle;
-static depot_stack_handle_t failure_handle;
 static depot_stack_handle_t early_handle;
 
 static void init_early_allocated_pages(void);
@@ -68,16 +60,6 @@ static __always_inline depot_stack_handle_t create_dummy_stack(void)
 	return stack_depot_save(entries, nr_entries, GFP_KERNEL);
 }
 
-static noinline void register_dummy_stack(void)
-{
-	dummy_handle = create_dummy_stack();
-}
-
-static noinline void register_failure_stack(void)
-{
-	failure_handle = create_dummy_stack();
-}
-
 static noinline void register_early_stack(void)
 {
 	early_handle = create_dummy_stack();
@@ -88,8 +70,7 @@ static __init void init_page_owner(void)
 	if (!page_owner_enabled)
 		return;
 
-	register_dummy_stack();
-	register_failure_stack();
+	stack_depot_capture_init();
 	register_early_stack();
 	static_branch_enable(&page_owner_inited);
 	init_early_allocated_pages();
@@ -107,33 +88,6 @@ static inline struct page_owner *get_page_owner(struct page_ext *page_ext)
 	return (void *)page_ext + page_owner_ops.offset;
 }
 
-static noinline depot_stack_handle_t save_stack(gfp_t flags)
-{
-	unsigned long entries[PAGE_OWNER_STACK_DEPTH];
-	depot_stack_handle_t handle;
-	unsigned int nr_entries;
-
-	/*
-	 * Avoid recursion.
-	 *
-	 * Sometimes page metadata allocation tracking requires more
-	 * memory to be allocated:
-	 * - when new stack trace is saved to stack depot
-	 * - when backtrace itself is calculated (ia64)
-	 */
-	if (current->in_page_owner)
-		return dummy_handle;
-	current->in_page_owner = 1;
-
-	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 2);
-	handle = stack_depot_save(entries, nr_entries, flags);
-	if (!handle)
-		handle = failure_handle;
-
-	current->in_page_owner = 0;
-	return handle;
-}
-
 void __reset_page_owner(struct page *page, unsigned short order)
 {
 	int i;
@@ -146,7 +100,7 @@ void __reset_page_owner(struct page *page, unsigned short order)
 	if (unlikely(!page_ext))
 		return;
 
-	handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
+	handle = stack_depot_capture_stack(GFP_NOWAIT | __GFP_NOWARN);
 	for (i = 0; i < (1 << order); i++) {
 		__clear_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
 		page_owner = get_page_owner(page_ext);
@@ -189,7 +143,7 @@ noinline void __set_page_owner(struct page *page, unsigned short order,
 	struct page_ext *page_ext;
 	depot_stack_handle_t handle;
 
-	handle = save_stack(gfp_mask);
+	handle = stack_depot_capture_stack(gfp_mask);
 
 	page_ext = page_ext_get(page);
 	if (unlikely(!page_ext))
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-34-surenb%40google.com.
