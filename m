Return-Path: <kasan-dev+bncBAABBZHIVLBQMGQEE755SJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id E8764AFA6E3
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 19:37:41 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6fd75e60875sf49827956d6.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 10:37:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751823460; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pq/T0niH3VAu6kRebz11xdOOxDqHX7uuc/QNHicisShbQAJm3IUz9t8S7swqd0oQdV
         BMOkkqeSGm/SijhBXo4wTlBshfUog8fSACKzsBtKKNpue06Nmcg7hs7DmMIZLffTs8nR
         iHVMrSDeKmPw2XfNRQWq2au0pER/qWcOZUm1+YoICm7DtYbCdpEfIJgW5M2sOMvrB5fw
         7cOf61As6y0B56Grr6rzCRbz62xPHeAmam77Qlzls6k+uu6wKeS9YOYr2am0vGMmm/CN
         qo93rd7MP+U5AXwEV1lHolWGYdWVvVhn0DAIDUDAGHPsndPNEr0y50i8Rdl260PDamZC
         +4Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zTd0wtjfnrItVwfxiAKtKeQwmJKnoVGphWmBVtxWVps=;
        fh=DzWjtvdjDTYtRQSTacUM52eudCdSn/QfOBxEcLl+bPs=;
        b=ROA4ON00366krqlHVHcZUayib7+q4VpqysKpWKcjO73WuvFFPSNzFJUyNHyqLhcXma
         1CYOLMrsP0H4mFgoijrZj5f0rLXN5fH+DVCTxC2RuskNQhHx8+8HtQG+EBOgaJEMIySy
         klz2NQ2p6ZKRRSG3mB/ZKIBe8g6RO/MlPgcMtryFSZmNHeCSiYGgbwHHuGc/kgpGvhEm
         0ujAyOiDI8erehzaumiyARc70y0daI8kF2WyHIWoA/9Tw6F2Yovsj51dGpG5g7RoN2od
         +0A8zlJTju3H/vfEhtzoDQT9UXmD3hW5Z9kilfo91bfM84HZxaccRflMgu84TQYI5aWq
         mN2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O+0fEEWh;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751823460; x=1752428260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zTd0wtjfnrItVwfxiAKtKeQwmJKnoVGphWmBVtxWVps=;
        b=IDq8suckFB5tMSI8nBUinK7Spc3SKxQXP3Yy5HTbUlUN2DZm1huJb2VvMCZvAeafcs
         zbn4kvfxRlEa6W1prf29sGnH/GAfACzMnWEObgvmjqwWKoegFLroUO+3bO2Xi3e+FquD
         A9blSiDPRCPs5RpJgW0zFgdmcyIRmqTQ259U+oiS+1pRjQ5s3l1WMejYP3A3WD9WuhDA
         6RS2+wPHcMuSc+P/G/C55em9/aG0lFIM9zkWOS/E6ofwm9QYLlMHfIPBRYM9OBEdZ+Oy
         GvdBb3jI61KKM+AJFYZxJo8jrBTXwHaoKNhjTi/lWenJjZnKJxVNpHW77p9D9qLlFDco
         b0bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751823460; x=1752428260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zTd0wtjfnrItVwfxiAKtKeQwmJKnoVGphWmBVtxWVps=;
        b=PuJEDB1OtsuPYBlvpAWdJp+AyG6AjnzmTrnFm6fPd5Hj/tlgFJ9cKtLoVGLOwz9D4O
         nlwoeLvjxGP9MJt/J0LUT4s2GG1W6IFFkLKVnYkZRolEUhtddAwuG5hJJBpgPTVblAa6
         IwizD4HplY7xTEXZLe84uJjY3AYTAt9Rr2CZbpiodNoGFgt5+BkIAnq89vrvUWIvf+8S
         S4hKSSMd2ESkXcBLofV2LWtMw6kJY8ku7prlAQckcHOcY7Ds6vSPLVY5QM3K0dcSehRs
         JeYTwTU6Nr2zgyoLEzGqOEFaueM4Y/qoxwi8yojRyWba4wSgaLy1/nHIIapT/JNQ+ObD
         16uw==
X-Forwarded-Encrypted: i=2; AJvYcCVLBlEcN9lbggLPaniiMVHJYomzF0AVhLoBo7foWM5Z9ANwqkfdn8zK+Fz8WYa1eIlUuSgLSA==@lfdr.de
X-Gm-Message-State: AOJu0YwfDHeapPvntxsp/jbvw8DeWs+XYlHH0VvmYBMv/+4oqebn6vO0
	hnSRkfVBK+8kX4r+lAuBeEJ8Wxvi95FlKmNxBsvU9zuMQ6/h9U/ADFc1
X-Google-Smtp-Source: AGHT+IGYKl9d4ppT6/IVzW3+ZCdoWt906+Twcu/TI7MpDhGefsCp0dzkyi8wLpqauoX402JwNFsfDA==
X-Received: by 2002:a05:6214:c83:b0:6fa:c81a:6231 with SMTP id 6a1803df08f44-702c6d0e533mr147086846d6.8.1751823460618;
        Sun, 06 Jul 2025 10:37:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfKV+MYLauDYnjGNVlN5nZ5uEYp3jId10CJoATKVv/9DA==
Received: by 2002:a05:6214:2625:b0:6ff:16c9:4229 with SMTP id
 6a1803df08f44-702c9cf7937ls35136996d6.1.-pod-prod-05-us; Sun, 06 Jul 2025
 10:37:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/bDweGIZbJLWdP5NM2u4leZs6VM4MVlVkDno53LMreSv1pf9JfER929yDRVB4/Q3KbO/BeJFM9yI=@googlegroups.com
X-Received: by 2002:ad4:5beb:0:b0:6fb:1db:e9e7 with SMTP id 6a1803df08f44-702c6d32cc3mr178303406d6.10.1751823459892;
        Sun, 06 Jul 2025 10:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751823459; cv=none;
        d=google.com; s=arc-20240605;
        b=dzaHsRkWirIo8IC8a7wrAEJ6IsxLn164oxpTomKCIGTLWJ+iIBfh8IKTqMfctvc4hR
         PRxDOszi6OJsyidwMHsS4Z52uhYPWMN/2tLS01mEaRNLxlknWImvyChnVVbB5yBDE2Bd
         ClKshFDTV+vIrxQF+1Lz3OF+8FFGCnT/PcRCyJSlKdrK3BVLzQ1ad8vfC7VpYw1dMeKY
         HE2BoHk65y9FV3/nxzp8IRLc13W77Ld3Hb6GeWIhvYOfgK7inSc1T4GG/VbfLvBb64bS
         oxCClDDxRXtzuB2PIYsrs96OQ9hOn/vbslIiTxexMi9uWIzzEPgbObopK7M22dntD/YM
         svCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=khuNa9UrIARpXdom/CN8TiiKzBTBTw1yWHEH++/b0Is=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=IaxvnyhoBl6O5f5bx+AkZHXBJdLCXv0u8+5M7MIF73Lnxs14vrYiJyGJVZ5+7vih4z
         qagBkXmkjnGW0/IKLiVoOVGorNvSJPWJwDtm/w669g0Qyu7UpnVgf8EvlyRUZaoi8bf/
         dExz9XLu449Lqe/5flW1FKVpVZdcsxmB92HstnY4czbHf1UNg86O8kBNwuLFlGmvl+44
         CygXV0Jhpele+No8ivPtxo+o7Y+3Q5hlTe99INF0v2NAAI93uMzKE1Hjehlgfd06+7LF
         530tg2vhYN6GWNOgfzG4g3r0bIgvv8JznrKD9VmPTZNTDEMaARRtzUI8QqKwh+iu3Gy9
         KDRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O+0fEEWh;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7d5dbe54a35si27957885a.3.2025.07.06.10.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 10:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 80ECC61130;
	Sun,  6 Jul 2025 17:37:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1DB8BC4CEED;
	Sun,  6 Jul 2025 17:37:36 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:37:36 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v2 2/5] stacktrace, stackdepot: Add seprintf()-like variants of
 functions
Message-ID: <9c140de9842dd34096928a7c87dab4f45ef18764.1751823326.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=O+0fEEWh;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted
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

I think there's an anomaly in stack_depot_s*print().  If we have zero
entries, we don't copy anything, which means the string is still not a
string.  Normally, this function is called surrounded by other calls to
s*printf(), which guarantee that there's a '\0', but maybe we should
make sure to write a '\0' here?

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/stackdepot.h | 13 +++++++++++++
 include/linux/stacktrace.h |  3 +++
 kernel/stacktrace.c        | 28 ++++++++++++++++++++++++++++
 lib/stackdepot.c           | 12 ++++++++++++
 4 files changed, 56 insertions(+)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 2cc21ffcdaf9..a7749fc3ac7c 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -219,6 +219,19 @@ void stack_depot_print(depot_stack_handle_t stack);
 int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 		       int spaces);
 
+/**
+ * stack_depot_seprint - Print a stack trace from stack depot into a buffer
+ *
+ * @handle:	Stack depot handle returned from stack_depot_save()
+ * @p:		Pointer to the print buffer
+ * @end:	Pointer to one past the last element in the buffer
+ * @spaces:	Number of leading spaces to print
+ *
+ * Return:	Pointer to trailing '\0'; or NULL on truncation
+ */
+char *stack_depot_seprint(depot_stack_handle_t handle, char *p,
+                          const char end[0], int spaces);
+
 /**
  * stack_depot_put - Drop a reference to a stack trace from stack depot
  *
diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
index 97455880ac41..748936386c89 100644
--- a/include/linux/stacktrace.h
+++ b/include/linux/stacktrace.h
@@ -67,6 +67,9 @@ void stack_trace_print(const unsigned long *trace, unsigned int nr_entries,
 		       int spaces);
 int stack_trace_snprint(char *buf, size_t size, const unsigned long *entries,
 			unsigned int nr_entries, int spaces);
+char *stack_trace_seprint(char *p, const char end[0],
+			  const unsigned long *entries, unsigned int nr_entries,
+			  int spaces);
 unsigned int stack_trace_save(unsigned long *store, unsigned int size,
 			      unsigned int skipnr);
 unsigned int stack_trace_save_tsk(struct task_struct *task,
diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
index afb3c116da91..65caf9e63673 100644
--- a/kernel/stacktrace.c
+++ b/kernel/stacktrace.c
@@ -70,6 +70,34 @@ int stack_trace_snprint(char *buf, size_t size, const unsigned long *entries,
 }
 EXPORT_SYMBOL_GPL(stack_trace_snprint);
 
+/**
+ * stack_trace_seprint - Print the entries in the stack trace into a buffer
+ * @p:		Pointer to the print buffer
+ * @end:	Pointer to one past the last element in the buffer
+ * @entries:	Pointer to storage array
+ * @nr_entries:	Number of entries in the storage array
+ * @spaces:	Number of leading spaces to print
+ *
+ * Return: Pointer to the trailing '\0'; or NULL on truncation.
+ */
+char *stack_trace_seprint(char *p, const char end[0],
+			  const unsigned long *entries, unsigned int nr_entries,
+			  int spaces)
+{
+	unsigned int i;
+
+	if (WARN_ON(!entries))
+		return 0;
+
+	for (i = 0; i < nr_entries; i++) {
+		p = seprintf(p, end, "%*c%pS\n", 1 + spaces, ' ',
+			     (void *)entries[i]);
+	}
+
+	return p;
+}
+EXPORT_SYMBOL_GPL(stack_trace_seprint);
+
 #ifdef CONFIG_ARCH_STACKWALK
 
 struct stacktrace_cookie {
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 73d7b50924ef..749496e6a6f1 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -771,6 +771,18 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 }
 EXPORT_SYMBOL_GPL(stack_depot_snprint);
 
+char *stack_depot_seprint(depot_stack_handle_t handle, char *p,
+			  const char end[0], int spaces)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(handle, &entries);
+	return nr_entries ? stack_trace_seprint(p, end, entries, nr_entries,
+						spaces) : p;
+}
+EXPORT_SYMBOL_GPL(stack_depot_seprint);
+
 depot_stack_handle_t __must_check stack_depot_set_extra_bits(
 			depot_stack_handle_t handle, unsigned int extra_bits)
 {
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9c140de9842dd34096928a7c87dab4f45ef18764.1751823326.git.alx%40kernel.org.
