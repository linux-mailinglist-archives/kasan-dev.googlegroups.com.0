Return-Path: <kasan-dev+bncBAABBA6UXTBQMGQEZHHUMIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5561BAFF705
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:48:37 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-31315427249sf504333a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:48:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115716; cv=pass;
        d=google.com; s=arc-20240605;
        b=IG4tt8lCQf60R/BzO2VWKdo4sU+c4z/sQamcbfXvYg/o64MCfNwOB6W31Ptj7YkMaE
         hd39dUiCCDA8YQmg0a0Gp574i/AUybJrknQnBlzkfOKm4EqfAjCPoNSRBWLh9QVp3+U1
         WccIvZzieFteGlW2F/bCgvRtr02ipOPcwEIoLMubWd9BRUOAYtetnlcxxFPIQyMHQ8yE
         cDYcDT6ipsTrq16P49Ms6bmk8cOGVPk1XfDz0im7gqa1oLo8ZoAn50stUSg1wEhzSDDn
         dzMMYxFLq6osY6J85/F09jYk8iQ0mcPrImSMI+MB7ksN9poezHAXprTb1LyP5qmB1Tov
         nScQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hjgVk+HmmjVAtA0SYi7Y18pqLkFd0/B7Ey7E0R4EyPc=;
        fh=YfCwQc+GZqCSu/Xw8nC7LB1TKwm1cGmd09M05ngQ9B0=;
        b=iEnmfTRDpy3ZQZpGZqRxxRfXVVZf52G245K8Z5GZwnv1ia4+AZRUJS0ww1mhS5a2SW
         iSNI5XyfQJ4/TilCq0/ed027qzeJoe4Nx6ERVIgL7nyahqlZo9pv3cMltFfC5sbH4mJ0
         5AJsSKswvYRTvF6/xDvE+xYxxhC0kVBvw8L/vSEvNBCwFiW6aFrB8zXuQkEEcGToBwA3
         KTma1svEL9ik6k1RYGAiNXqxL/sUFESp3x97ImlGdzh+OMJheeJ85q+Y6Kdqs7168Fdt
         xsCNBEExP09dcGyXe3tIp+JMC4K5lRuIZtmivFH+ty3OWACibncxwd29MfNUta2eaY8M
         fz/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eZnmLeDy;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115716; x=1752720516; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=hjgVk+HmmjVAtA0SYi7Y18pqLkFd0/B7Ey7E0R4EyPc=;
        b=AemczBH3hIyF0KlFULfcQ0Q4KI50CZmYq4vk8Ni379JQi0mXQIxLIGHeOAbmCIryl7
         pOD1kDw907eEJScx5gHGvcq+PspW0o8rKcZ0hgZs8upsfTrOSEUj+NDgX/T3mIa4qz+k
         WRu41CPLJvFSv3nLYmzc9yXUKbrM80QbCgBMFKVJTytk9uadVJEdR6Q6/YZhBQWPrihW
         RTtOM/KnVsCbqdJUmd4TH99m9KG4NiWvVzzl4TaJFo3O+29awMuP86OW5FtrQ3913Ibm
         zrKT/DODPm7QC3SRlyszAFFw6FRBjYfqJuW1dmaW2EMqB+CmI5pbr0X3YhWEUgwpZ4Ve
         dDAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115716; x=1752720516;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hjgVk+HmmjVAtA0SYi7Y18pqLkFd0/B7Ey7E0R4EyPc=;
        b=bZe5U7L29iN7j/pN+OfSaoZ66XZUvL9+tjNVEfNiaUoh3WzzOzkyc4MCqtKtrgbX3V
         1AOTAY14c290c3yAdZRTs0G6POhIs5BX7GILBn1/csCwZMNZ+KTNxLUXbxW8Q3JYnRI/
         vbdespNBZ3UmrLdUytnvMq9Q6xPYgh2QGMUaY2cQrUiYyQYAmr04buJpcDPBZld3LXK2
         U9398Kcb52Awcob3En0coORDEZX7RHJSx3QT1r+i7RfHz7ldyKHFQrSXupr8YBQ+kuOM
         SLrknRWsUcjJHVIQJUezmq8ewlT3OdeQtg9fEh8XAqzk9Q4XfgWQmO+FXuCwRq9eSSYG
         6MoA==
X-Forwarded-Encrypted: i=2; AJvYcCWSemvXiCB5dZ5EJTl0N/xDInZb4X66tNNL8B6k9THvNKdSI1apiboV50oO8qyWXNIcepgglQ==@lfdr.de
X-Gm-Message-State: AOJu0YylLjkhbvyn7rMofrKL/0U39hATdBo96VNX1irEOVgjLzsOIphg
	25sSD+9VRGCZ4wGrhwP0g9Z1d/3anDDkStVYs/mN40LtMkHIIR4e33cW
X-Google-Smtp-Source: AGHT+IEwbqGLIhn0YWlgfuHtcGardrW+uQIkSKx9rUDQ4LYYJrFO9uhqYE3NL0RRsARlkqBD0O3pYA==
X-Received: by 2002:a17:90b:5830:b0:30a:4874:5397 with SMTP id 98e67ed59e1d1-31c2fcf4328mr6644640a91.9.1752115715535;
        Wed, 09 Jul 2025 19:48:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeQu0mzDQjaO4KYpFsaEbXllUH8NHtmZJlCVt5d+jd3rA==
Received: by 2002:a17:90b:224d:b0:318:ec3b:32da with SMTP id
 98e67ed59e1d1-31c3c5b0746ls676771a91.0.-pod-prod-01-us; Wed, 09 Jul 2025
 19:48:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyNvWuWX7HrrveeEKC1AHg2PsiB+Ip6mo4sOU3rgUCZSFlDknXzsaz5FZAeCUBR7Bl6bVQS2CZdeI=@googlegroups.com
X-Received: by 2002:a17:90b:2551:b0:312:e76f:5213 with SMTP id 98e67ed59e1d1-31c2fdeca19mr8001529a91.28.1752115714481;
        Wed, 09 Jul 2025 19:48:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115714; cv=none;
        d=google.com; s=arc-20240605;
        b=jPMv8QDMix+b2WIn8dp9aj/OswPwE4cweJ/nUwqkCQhEkGyfvunGtKkn09bHyfOnH4
         NRh9P7FvT4papLWq5DvT1PyJVtGWc6uI7PxVZ7dLCt86H7O3e9Mh8MBp3kAcvutBBOrq
         JtGS/7Y2BDVd4w3CMCpxBeUmV8KJgvqerWYMI14mT7VFmPoPvbh7750jXeo2xsrNer70
         nVUuXhGEZH8cJAhNxyKHB/PS5Cv5LydYzvAiLvAF3gOIp7+65oHE6HeXxO6tWzKs7jGf
         zYu8kXIsA2JfmB2C/i3+M/X9gSj03c6WF9i0Z0x2wu1eOfp4UMKCzFTebkh/l/VuWdIi
         1yfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FG5EU/f/hB5bUkYkfvMhOxqTQ8gFlOM0lPZIWF+q+cc=;
        fh=n7kMCQJrry/6/0/v2g7rS6NiIhn1Yg+3PC4f8tlptsI=;
        b=NdxVnpnm71YRBXDmOEGPPvpojBKG6frIGMHqzqM9IvSTzbKJcIs3Yssdkax0b8iU70
         IZraiuu5pF3/dATzCokev96DILQrVCygOmNcYDBeCxwiXsFq9KV8yer8dah3kQGDRnnx
         W2ngoabPa6CFNTIZ9HsJ+BrR0VJN4rqTdyjVDlU+bAhgPLMwAKHhS7oEt8GLdvQnL6+g
         /rcEBRc8TyV9YiZknYD9zmJi25Rx+5eNq4j0uG7sd6PyYx44E2X0KnlxMYPS7lfYSbl1
         CkxhipRk7XNUy0oK4lxnr1Wtk+K7YqsoTHGHzL1hQG/BTaEgMSVBzjyPMg7098GI6qmA
         n87Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eZnmLeDy;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c3eb21f18si50949a91.2.2025.07.09.19.48.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:48:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 9E976A534D3;
	Thu, 10 Jul 2025 02:48:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2ED4FC4CEEF;
	Thu, 10 Jul 2025 02:48:25 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:48:23 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>
Subject: [RFC v4 2/7] stacktrace, stackdepot: Add sprintf_end()-like variants
 of functions
Message-ID: <894d02b08056c59b5acb79af73a1a698d56016f5.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eZnmLeDy;       spf=pass
 (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/stackdepot.h | 13 +++++++++++++
 include/linux/stacktrace.h |  3 +++
 kernel/stacktrace.c        | 28 ++++++++++++++++++++++++++++
 lib/stackdepot.c           | 13 +++++++++++++
 4 files changed, 57 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 2cc21ffcdaf9..76182e874f67 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -219,6 +219,19 @@ void stack_depot_print(depot_stack_handle_t stack);
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
+/**
+ * stack_depot_sprint_end - Print a stack trace from stack depot into a buffer
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @p:		Pointer to the print buffer
+ * @end:	Pointer to one past the last element in the buffer
+ * @spaces:	Number of leading spaces to print
+ *
+ * Return:	Pointer to trailing '\0'; or NULL on truncation
+ */
+char *stack_depot_sprint_end(depot_stack_handle_t handle, char *p,
+                             const char end[0], int spaces);
+
 /**
  * stack_depot_put - Drop a reference to a stack trace from stack depot
  *
diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
index 97455880ac41..79ada795d479 100644
--- a/include/linux/stacktrace.h
+++ b/include/linux/stacktrace.h
@@ -67,6 +67,9 @@ void stack_trace_print(const unsigned long *trace, unsigned int nr_entries,
 		       int spaces);
 int stack_trace_snprint(char *buf, size_t size, const unsigned long *entries,
 			unsigned int nr_entries, int spaces);
+char *stack_trace_sprint_end(char *p, const char end[0],
+			     const unsigned long *entries,
+			     unsigned int nr_entries, int spaces);
 unsigned int stack_trace_save(unsigned long *store, unsigned int size,
 			      unsigned int skipnr);
 unsigned int stack_trace_save_tsk(struct task_struct *task,
diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
index afb3c116da91..f389647d8e44 100644
--- a/kernel/stacktrace.c
+++ b/kernel/stacktrace.c
@@ -70,6 +70,34 @@ int stack_trace_snprint(char *buf, size_t size, const unsigned long *entries,
 }
 EXPORT_SYMBOL_GPL(stack_trace_snprint);
 
+/**
+ * stack_trace_sprint_end - Print the entries in the stack trace into a buffer
+ * @p:		Pointer to the print buffer
+ * @end:	Pointer to one past the last element in the buffer
+ * @entries:	Pointer to storage array
+ * @nr_entries:	Number of entries in the storage array
+ * @spaces:	Number of leading spaces to print
+ *
+ * Return: Pointer to the trailing '\0'; or NULL on truncation.
+ */
+char *stack_trace_sprint_end(char *p, const char end[0],
+			  const unsigned long *entries, unsigned int nr_entries,
+			  int spaces)
+{
+	unsigned int i;
+
+	if (WARN_ON(!entries))
+		return 0;
+
+	for (i = 0; i < nr_entries; i++) {
+		p = sprintf_end(p, end, "%*c%pS\n", 1 + spaces, ' ',
+			     (void *)entries[i]);
+	}
+
+	return p;
+}
+EXPORT_SYMBOL_GPL(stack_trace_sprint_end);
+
 #ifdef CONFIG_ARCH_STACKWALK
 
 struct stacktrace_cookie {
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 73d7b50924ef..48e5c0ff37e8 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -771,6 +771,19 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 }
 EXPORT_SYMBOL_GPL(stack_depot_snprint);
 
+char *stack_depot_sprint_end(depot_stack_handle_t handle, char *p,
+			     const char end[0], int spaces)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(handle, &entries);
+	return nr_entries ?
+		stack_trace_sprint_end(p, end, entries, nr_entries, spaces)
+		: sprintf_end(p, end, "");
+}
+EXPORT_SYMBOL_GPL(stack_depot_sprint_end);
+
 depot_stack_handle_t __must_check stack_depot_set_extra_bits(
 			depot_stack_handle_t handle, unsigned int extra_bits)
 {
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/894d02b08056c59b5acb79af73a1a698d56016f5.1752113247.git.alx%40kernel.org.
