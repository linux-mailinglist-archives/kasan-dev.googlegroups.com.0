Return-Path: <kasan-dev+bncBAABBE7CYDBQMGQELNS6UPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A5BBEB00DCD
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:31:04 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-235e3f93687sf20835265ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:31:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183060; cv=pass;
        d=google.com; s=arc-20240605;
        b=B8jQ+MTDSRS7H0OcFnPAcK8Yk+ICF3Oy1RFRP5pJIZPgjTerxj6DNq5ZYn2FpjggJd
         EwKtBEMdKsPJCwM1yXPmFHyYt27jgZ8VvUMYvXhIEltV3z7lXH8GaIjCBRk+HTjqTdH1
         QSrB7w+JNEOaMDDfQHGuQPQVXUeMfryf7+1WIsj9n7Jgt3mZA6QQafb2Wd6fpJT93wWv
         2hyQYQ0wPHxn+fx0i6Ow80dQrZ+6iBGKUVcfbWYINuWbSPN7svc2cKsxPoFxVptIxGMz
         rTf0GlKAKZGYVn0WZ4a0yb1ONp08bv3I2vtIREBKrWYNKXklo3TQ0Gr4l5QkcfU2shZK
         gBpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rKs4R/eNZemenAQz1/wt9sbfg/B0tv4enjYH6GVUsNc=;
        fh=c55tvDEqFvZrJQ7Q/seTfTEABNYGX7ULMfKd/3GUI14=;
        b=RzxLOm42AqRMtrQWoEguXPsNWU04bf7aeGpTeREsvOLixNkFki5fWn3BcjnXVFhJAQ
         4yPo6dwNgiqbxD1q8pRVzM1svb2pebHq/QD24Z36IuLYRdDWh6bEtWvaqEUe9PrDNSQF
         MwbAiTG74MaqjkbMJ4PgnTiuHsHSZfdiCIQXB4HpF+oPWhuo/LzfjShQgsDWmet+Egcc
         lMwWeZ5yyIDs90IAJRl+vhbViy2I59wCGO/0RMcsQqnawiISD8kx9+1hMuxLpdSXA5JR
         S6NThV4qqf5LLKL0qtN9sddTjQIi+5AwHqMGSEQhvAQHJ8QAoT5qxiGnTX0Rqpzmg7mo
         yfMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lChuc2aI;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183060; x=1752787860; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rKs4R/eNZemenAQz1/wt9sbfg/B0tv4enjYH6GVUsNc=;
        b=AheekwOTZua3VjH/E/3TR8P5NKhYlKYqdr63LKpi8CdyEArRS7uJODSqmV3P7wiGfO
         4NPVJyHnitS+vs37Ef3sNrpzBo/EO5EeyeKdrDWDm3dxzKfEx6zbAtqKK/fTkFMi2Sf5
         zndfqGmynC4giF9G8bROOaqobVoy8e/BS5pFTmQhtlJIxuo8yg9cuO7yaYZURBo9oDEz
         pPOCGhrBagtPIZlmJneNEKg4APbNvnzrGMz3nZ7k0ao5fAkxtMofdeNw4IHQDmdQcPLY
         lnhXB5407z3+d2YRknxLsgb4BYUvyD6HydamREcz5rGEWPOSJg/jGWKfUoUbQfh5pNAB
         wijw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183060; x=1752787860;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rKs4R/eNZemenAQz1/wt9sbfg/B0tv4enjYH6GVUsNc=;
        b=O9OmdcPmzQ1Zn8rEAhg9vzTetrdsQcTC8cbhETk3N3tC0nFRJtQb/dVALaDxV/Nqxm
         wmukz1aCCinY3ozJUvbeoGBBF7BngPn6s0p2t8vbCzJp2teZT/SjiIHhaviBvanmrUJG
         2IEwlEnNM6HALy3tlduLVL3ufeM9u5/wT2AOPNiWm6a2tsDNX68GLmu/eqLjkeYtmQ5y
         EG565rdyxdQ6BLBKzWs8Gjcixtiic5HN0nRVe9mxb9pfNJKEJVin61Y2oD/NOGD77olS
         UQpngXN45mQDtefe/m/lKYy20+WVZ8I5wb/Mn8+lEiiXx0U8CncqKWLPbafTT219ltpz
         X3CA==
X-Forwarded-Encrypted: i=2; AJvYcCXlz380tfg4XB2H9WFxBadtVjGujrtwEkxBkCHkUeI8iB6odL6YDwcrTLzrZNpMKLH2N8oHbw==@lfdr.de
X-Gm-Message-State: AOJu0YwbDKO5CVVgR77jqF9yicIy6KoYxgJBaYASZJifEyoQkWLMhuBw
	QjBKDOcmJ7GFSjLrGwfjTVqv/Xhv7qxKWaIeRIzSc/7P94ju5W8FdJcx
X-Google-Smtp-Source: AGHT+IH/Zixoe+H8HfLRwEVXR2USPp5gUOoNyV/b4TPxFgG3Q5qAap+ZowAiHX18RY+hRLHdcz0ycg==
X-Received: by 2002:a17:902:e5d1:b0:234:eb6:a35d with SMTP id d9443c01a7336-23dede7d5c5mr10641805ad.27.1752183059704;
        Thu, 10 Jul 2025 14:30:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2kOZ3lpkvyeUm23pNERonXk7J+a0CnxTNoDir6r7lOw==
Received: by 2002:a17:902:e204:b0:237:e6fe:2370 with SMTP id
 d9443c01a7336-23de2e1f633ls10519065ad.2.-pod-prod-06-us; Thu, 10 Jul 2025
 14:30:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+OmYm1uUFylqxdK4LJPUtNCVnOJW2+XQlJPI3m9WfhWOA58L79LBDxwnQt8YNER/sGp4dWIigrH0=@googlegroups.com
X-Received: by 2002:a17:902:da2d:b0:235:eefe:68f4 with SMTP id d9443c01a7336-23dede7d480mr10070525ad.29.1752183058507;
        Thu, 10 Jul 2025 14:30:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183058; cv=none;
        d=google.com; s=arc-20240605;
        b=ZOJMFiYDbCayt3DADsRG4fnyTdWr3cUDMmu1RRV/ed047aQ7l9aC53hkVxelzdM04a
         2OtpFkxVbgHJ3fQ1UGtMcroJyRjlVjIJGzHIPP4jAEs64N7vg6OVzmS0IlyNOp/ITsBu
         Og26htVru9s/ui2BnLYoHC0l90rAvRSHbygpvNvDWsT61p0/zSJf/vf2+Vl7hXbbiwtW
         Wim5J7k8EZCXllCrzqdxNOtdeawnObvaAXQGIntx8BqyaP7/RhtzV6iXTupzWMkDkNkv
         j1NCA7yB139YLcHmoz+n1Wuls0h9BZUQud7mF9uuk8kIxwPjtYCyPs+SQC2oYmndOpkq
         0jiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FG5EU/f/hB5bUkYkfvMhOxqTQ8gFlOM0lPZIWF+q+cc=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=DxDlJleZfQ+7N7tt27BCreKTvobwFNsMSh31CG6ZCbQx0cKNLihLA5en8iYlLMNLnA
         Ox6wiTZ39NkhtDXeonl1V5E4w3veKoJr3lC+yde4ku02Ba4uDnOXQrQ3y5K3ZybRgYLF
         JCt9BsJ+t7H26+RtQlVvLqxfwbscbIK86J8cBFORq0xtM2IV/Mcr+3KW+PzPXlaBlOPw
         r8uqoRMMYXSk8XrWDgQl34n5terW4PR0dHrlWj7JbmSl9JhKPnHe9BaXpka/QU2TgwUK
         z7b+OmXGhvVQ+lQlfsVVkWdITfp2rLNLJPy6an/qRig0SuAGN7tXspcIcF41djgwDErd
         VeEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lChuc2aI;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de4254d1dsi1231825ad.1.2025.07.10.14.30.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:30:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 777BB61423;
	Thu, 10 Jul 2025 21:30:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9B5FDC4CEED;
	Thu, 10 Jul 2025 21:30:52 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:30:50 +0200
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
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: [RFC v5 2/7] stacktrace, stackdepot: Add sprintf_end()-like variants
 of functions
Message-ID: <894d02b08056c59b5acb79af73a1a698d56016f5.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lChuc2aI;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/894d02b08056c59b5acb79af73a1a698d56016f5.1752182685.git.alx%40kernel.org.
