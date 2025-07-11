Return-Path: <kasan-dev+bncBAABB4O6YHBQMGQEJMLNMNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B0F99B01106
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:57:07 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-408d05d8c03sf600601b6e.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199026; cv=pass;
        d=google.com; s=arc-20240605;
        b=Oz9xrzlsQmhfeTm+tbR/C529DMUGh60XO4h+fN+2GYO+OtMT2tJ4pgI0+H1qmFk/Bl
         G7WO1pBG9JRlSyvejYHA2orgKY3lyNmmk+qQbshDKR83Mr5SqUxgW3nT5UWhR66CXp+8
         5bna3lhDcUpLh68SFHEQNFwFPZ0mjlhMizySdr1MKoYYsWyZbtSHvFksYrt8EggWBDcC
         HxurpZOf0TN9OjPI6rWCeRiuHGLz7ubPysmc2NKuUbEGGy0BECvBIzmslFs2PhMs/sl+
         6v70S2UYly9P2sVv7topUsYPLTzV2XfHufBKpeRSInbRa5tSV6nsGxWn/YLZfS0nWJRk
         4HgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=uKnVmWfkut8XL91a7kHdXhpF+4l9qYf5VkVk1b8x/nY=;
        fh=UFKCzd27Yme1QhWAuV1uutoRmpFjvKRMefYOhnWfcoU=;
        b=YawtDG9xxj/zXtmT/UYFDNkRY2DOWRxeknOCYngbgDDM+2Zq2K6niroPCE21DABG79
         9h2PZ0j1/0SPmpUWK9OoJy69sVfiHDii5qMFZ6xRIIAWxaR4n/u3FaiVJj6C7AxE79Hk
         eBhBkCIuvjV0gta8GSjQw7R39imPJy/b7Qpavmvf5dtnFXCMdBnEqeOZx2HXsAZ3FNly
         uICeu/cTlx2BodaCnqwqfYj3Zgjxg37wC2G3DRV5ykHz/TzSykrOZU1dKVtVZVFKLStY
         AaWZCC5zHpmkNXgD2QDpW3UwPOgdMyOddJhnap9X2N+4eW2idEFbYsi+BR2owaEL5QB/
         zDVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b+yrik1Y;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199026; x=1752803826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=uKnVmWfkut8XL91a7kHdXhpF+4l9qYf5VkVk1b8x/nY=;
        b=dl7rhrGp56fW36twLQEyoLueIGvIOlQwXtBgMEBUi9lmb4WPmb4pxWVlKAD7cBxp8e
         8iQuM/cYB/4hhuSUG8oVo87LC3ywHu3xCVnaj7GWqKtZvOAf2KrckSMEdGcuFvB+IKzK
         7qbTQVvlqv94Ynp82Tac2XpXE8aUdqToYoj5CHkB4599wP9i5tvKMJNu2tWerRMJj28Q
         Hiex8R/U8/BDj7JGvIbHu43syC5uOLZbTUzizgID9zoLgVcItr6/e0nmtG9eMoTEC02Z
         VQZIhM0eZ0W2P9H36lRb2x5R4Nqq44jELHGYGRavLMpIMQRt6WqAkruiJFuXSfyPda3J
         R+oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199026; x=1752803826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uKnVmWfkut8XL91a7kHdXhpF+4l9qYf5VkVk1b8x/nY=;
        b=q7AIVlHxWyN81BLct4tvFm9QqRdQe38eTGd8Ag/1Ca/xnB6cNvtAcnSpioN5vpPtmD
         QNP5S0zScAMVEzDGsd3bqsQWl7SzWiQ2V03kUchOqWJ+5xMmA3o2+rOV5P16PKZu8u3J
         PmBhoegNc4+D3rie0cZjnH3DVVxXa3fT90fb7TXdatMk10FRegeiZwWQLNW/ZqQafGRa
         K5lQL3+3PO9+OkRN4QdOJC0Ngkwa/dIOFg2peRSxfdLMfU9bBhVGbOYDCoSBou2QcKCC
         dBys6N0/V8dbfZrmflGMA9WabpAGR1JmWskjJteBnBpHC4NvjarGNuDkJwbh1u8sU/9g
         CS0w==
X-Forwarded-Encrypted: i=2; AJvYcCVidGKHvhRakuoR9JZx+SaXJVl1e5WWX5pSJLedG5Gz+1nadLM2A8oywHBEKJujKxxn5ZKYQw==@lfdr.de
X-Gm-Message-State: AOJu0Yx0oZ82pvW2mF/P6jwMeFYEn7ahuhpFbFWsSiV5nnN5gvlzXQWs
	1mayJwaRGqO3N4GGn0Mwqw0YYoAR7tgu7j9fgduewFzd9L3l4V6tczEG
X-Google-Smtp-Source: AGHT+IFNvG4DbU+zIHa/JMeWrKuXX0Sox6c/6CTxN/Qmt6bPHojyjU4InewrTQA+LHTrSOaROekJLQ==
X-Received: by 2002:a05:6820:1e8a:b0:611:af6f:ee77 with SMTP id 006d021491bc7-613e6054038mr929392eaf.8.1752199026203;
        Thu, 10 Jul 2025 18:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcRqYDtUHSyz23zSc2y+OonneuXzYSPj2BOCFfCRhiqBQ==
Received: by 2002:a05:6820:f44:b0:611:6efe:3007 with SMTP id
 006d021491bc7-613d7d065ebls384357eaf.2.-pod-prod-04-us; Thu, 10 Jul 2025
 18:57:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFeyRjXmewBHLDmxsUXa1Nf5ijb/dLqembSfN/yViLt7B6SxgLN4f5D6Z379dpWIkFzeClAbC6JI8=@googlegroups.com
X-Received: by 2002:a05:6820:4deb:b0:613:d673:c01b with SMTP id 006d021491bc7-613e5d3970cmr917918eaf.0.1752199025050;
        Thu, 10 Jul 2025 18:57:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199025; cv=none;
        d=google.com; s=arc-20240605;
        b=Eye3Ra/MmfyL1KX915FqEkPnzsdpRFgANSm+aSdPvlaV6ntW7M7DthQT4CNVYGEhsh
         xnXIOfZlJrf4PNnHBCMhzAXmnspz95455Y1E9V93rRR1YUmiJ5Px8NndAq2jo3VpVKrn
         gtmdzGU1/ug+6FRKYiDqTBeVDn8/mrebHVuHe8IOXO8u4JDHXUBWlst28yZ9+iPsSljI
         yKphhJQh3LxZtHDOOtkSKKMR9KbXerq+vCRHEIWFdjsw2St2vutH7voW+aBaHFFAAESl
         4d+SKZ/xZVPl1cJ7sY/6xakO6jLj/TF2CxHHPHSh5lAtGcQA8RUVrHJqpZ2vz/qTPMvV
         NsIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FG5EU/f/hB5bUkYkfvMhOxqTQ8gFlOM0lPZIWF+q+cc=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=TNF9cUKd2JEkAhECZLGmDNf/3/AMMPCt+q+GbrGeVjmbc8SH1CRhd+I4tuCVmd82gK
         0GMFShX2Y9j/EF8HRS70ylsnTMXIzUD1Z4AGny4eHJno2LWMduKxS3zjIaYtnbK2WX/S
         NRFWCeHnsbTYJlFxNrI3wzwvFHLa4KzqLefpRIuSFka9J7EOPFy4TLzYzMo86Iew1LDC
         XA3ImRBZE1G+NO+PUgMJGRaQn/cvswtanE0jyN3b7WpTPflDa8FY+qLMH8rtE/6oyEm3
         8ppwUcgCw0XiUf/pO4+cferm9N3NQ53lO45pJHeZgmsrM93Mqr5x7y0b6uwV9P7x/Ijn
         c0LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b+yrik1Y;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-613d9d85ce8si190487eaf.1.2025.07.10.18.57.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:57:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6648D47053;
	Fri, 11 Jul 2025 01:57:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6BD82C4CEF6;
	Fri, 11 Jul 2025 01:56:59 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:56:57 +0200
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
Subject: [RFC v6 4/8] stacktrace, stackdepot: Add sprintf_end()-like variants
 of functions
Message-ID: <6c5d8e6012f06f595fbb30e3c25a88a400538ad8.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=b+yrik1Y;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6c5d8e6012f06f595fbb30e3c25a88a400538ad8.1752193588.git.alx%40kernel.org.
