Return-Path: <kasan-dev+bncBAABBRNLVXBQMGQE5N3PRYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF776AFAAB3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:14 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-40cf41ebba6sf2822658b6e.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864773; cv=pass;
        d=google.com; s=arc-20240605;
        b=PMFfBc6hHRay2DTkLqzqD8pqC4tjU0GNZE4zX/p2P41oScYqoTMw7FfUN1su+SSH90
         Mhk2TN6a1OHtF3KTHJyvVyz/3I6+rHYd2vwdAFWVxr5p6aWoKgkWaf0tKegmTiIAorFV
         UVxx/wV/NryPKp/7XRi2uCrVQ8HleZ2lgrpHXapetr/2WNco7y15BD7eGhn4o2yXOg8P
         TlB7U3a/PkyCSeFOjCBzhw26un2uQXbbUL884ghHbPfZ+uR66JVOJQM6j6LTkdHtMcO9
         ly/k+BrCx3qUwAV9k64zhEfsGl0PTJ0k6h2CZx4SbseSfcWtet+g4IIY6cZLD3euAuaV
         aUQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hSfOUmfJ2rpIWONvGNALTgWmp9cfCkWq44NU3ukuqhE=;
        fh=UUfawsic3RnzhXRJh2hhy8mvurSyYmqlMIlrVLbs59M=;
        b=DRN949/PViNcENzEYQi7avln+gsidOG+dSRp5jSImHQ+IpKPoojr9Qxe6OupN8eQ/S
         KUAIQuQwQjMAsiBKl8f9V4hT16ltkpWzIctzlFrrn7XdlOdvihsdi2vm3Ko+P5eWtj6o
         J7syi59fHF8wIGxDZByTDX9DNwWpXHUnsHoyW4sE1cFuvf1Ewcu69mJSgHhjvDJl2lNm
         4H5awYISUd7/4KT6XfPqllVhQ0/RKmqQumSIWG6ZZ+lkFpHdChi/wz74+3iss1eLkFx9
         4Fi06BhFOibWUsPNZLuu6Gib9RZEEBqPh0GmPomK2TyGruyvfHjqnHNWpSab0ZYYtsmS
         WovQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sYkHDiS7;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864773; x=1752469573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=hSfOUmfJ2rpIWONvGNALTgWmp9cfCkWq44NU3ukuqhE=;
        b=PGuwvpYrvAx8lZmSVYEjQ701SBxF11+ccq8BL4xFRwo7bb5/w541NgHJLHITikgeak
         1icP6EG/Ueq0TQr51tziNpbT8NOu9rP3J0cqybfugz8R8Znl5zH2NLmu4N/HXAfEcdKJ
         5cp8yCyucNxMKaqN1kI+zwtGhBqyGHdhFlmqrWVnUuthfBJ0ovjZw8stgdpQHbkKfSEk
         JIduU6utBQe+dn282t0TxwOrchSonkNGvxWpFmylwW1048LFBvZ2m2TeKKPLtGL/QMRO
         uW75lcNFH1cBOaqxTGMVo9pW3tFsnoDI4yz30AXNTXLiw0mxFIzbXnFdHtz/YxHLGyNL
         omZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864773; x=1752469573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hSfOUmfJ2rpIWONvGNALTgWmp9cfCkWq44NU3ukuqhE=;
        b=GilBuu3HFH6yBiMbVJRIRTGzZxQXTc3j1C27a6CqXJ1qcKUMc83B7UfnjdVlHn/xte
         yuEzt2Vf1CmxJhnPgXsBfFaMmvjRxC+/mh6sAl9pD6CHLfLIX/2Pk5/gLXzbm64QdQLJ
         dH6kXR2Of7NwgAfs7EeMlzFwzOQc1RNW7HUIwzrleac9JyZMiaNpsLg5mmsmQpBa5Q5T
         fRpXkew+d1V56MXq3uqr/Yx0fGW4osA3LL5ZTjhUoNa9r/fpMq5IJRtdoXVoizDBYSw8
         qSxdfZxYMnPdKiYcPqYBO7PnuoNwM2ztublMXNcF4UnAA/ETmwWFAo3Es3Qw/pQgO0wZ
         obnQ==
X-Forwarded-Encrypted: i=2; AJvYcCVCsFgl1tFWsiP6pdi9PEP9ey9TZ9l+kjFKU2ZfMB3utquULBeErWPVMNoQHoIU+XL6wwVnnA==@lfdr.de
X-Gm-Message-State: AOJu0YyzZEgQ/Btpw/r3w8LkG4K8j7+ORcNKE10mXgyo+sCStsd0+QM7
	VaaX9Dr73eIhX6gAssZpELo2G+ZBuJkhcHUcGIktyXrWUPDaTTdAXJsT
X-Google-Smtp-Source: AGHT+IFvX3x39rJfAUx7Gg6F/EojnI917sHBR4GdrxVPVevPhO+V8aP5PAISH+NZn2eSBazsOitBWA==
X-Received: by 2002:a05:6808:1250:b0:408:e5f8:9e2b with SMTP id 5614622812f47-40d07378d2dmr7462219b6e.10.1751864773330;
        Sun, 06 Jul 2025 22:06:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7drUYTtztRwOxtyhVkfDBhOYl4cD7PAQCJqgbatntVQ==
Received: by 2002:a05:6871:8406:b0:2e9:ad11:2ac8 with SMTP id
 586e51a60fabf-2f79b6fe7e7ls1125551fac.2.-pod-prod-09-us; Sun, 06 Jul 2025
 22:06:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCinXQHprAhq+tzr49vyICgPEyjfsA2s1rpivvWcEn1uefk2lj4VeXnYlU2Pv+n7m/rM2K3v8XpyQ=@googlegroups.com
X-Received: by 2002:a05:6870:f103:b0:2b8:fab0:33c with SMTP id 586e51a60fabf-2f796c655b5mr7903588fac.23.1751864771858;
        Sun, 06 Jul 2025 22:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864771; cv=none;
        d=google.com; s=arc-20240605;
        b=cHFe5yQzkRCAJE2rPHk902AVcTDFm9MfE9e+dKzJ30kpo3PmSE44MN2vMGtjbBzYF7
         pmyqk4v/3EXdP6TIv0Pw9cLWN77mOczMbAgHyIMhLhlRN1M1zsPPwIri5HOzJZ/kzjxC
         26ll8LDwuZ/Z6p/EF9YHU/1LRbozys5M51uv0QneOyGtcBdbD5ML9SZt273M9bnxk76O
         DO8I6V/QFii1plqWqAUhJN1jHFZ4WWOD4ZE7Orag7QCNRSFB65nN2+cfxKwwrc+SVE+r
         A/EDSbPY5J4ElX6q5eviWvRYe6qpO32Fi7tEB1RYUWBSPKg2CGkaSSuwCYrHmz5Te2lF
         Q5qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=khuNa9UrIARpXdom/CN8TiiKzBTBTw1yWHEH++/b0Is=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=ega/sawS5GB3JN3uqWxBMo+OrfaiokwrAbgaJS+ZM3l17rD8W5+UvM9rV+8s4xOJyq
         RCQUsVNldCUqy/J6G93MjGPO5SWua2cAR5lZSmkvIFhL4f0OPKhBXa1L3sUKdBmS82jM
         x01WZiSvb+rCaEPLEMqXai07EjW2POFukUYi3PSG4L+uS5vALuyn4FI8uGmZvQ0ON1D4
         NJEhK0dEuQxb28hz8YfZ/joTiW8TEfs4z8+JsN2dvSexmlmekxrscN066bxD/tkEruB8
         QIpJe+S5zkHk++QB9XGypK+/sFOGdz4kZdvFpjrmN57rcSYeBEag+XLF7FkaJj9qLEYl
         k/mQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sYkHDiS7;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2f78fe986a8si217284fac.2.2025.07.06.22.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0233346165;
	Mon,  7 Jul 2025 05:06:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 23963C4CEF5;
	Mon,  7 Jul 2025 05:06:10 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:09 +0200
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
Subject: [RFC v3 2/7] stacktrace, stackdepot: Add seprintf()-like variants of
 functions
Message-ID: <9c140de9842dd34096928a7c87dab4f45ef18764.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sYkHDiS7;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9c140de9842dd34096928a7c87dab4f45ef18764.1751862634.git.alx%40kernel.org.
