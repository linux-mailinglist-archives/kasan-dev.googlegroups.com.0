Return-Path: <kasan-dev+bncBAABBM4YU3BQMGQE2JT3Y4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54C1AAFA1CB
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jul 2025 22:33:57 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-70e33aeaad4sf24650747b3.0
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 13:33:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751747636; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vh1vqWt87D4CAb2Ez3H6VRoXEzpeDTQ8g99HDKiIPRCRxiRZ0CbrRwmICFs+0gOHBN
         zTh5Ki+jkkWqnHO7EdTzDh3HYnCk/UwCB1FFSvE/832HWuIDSM2VXsxhM5t7/N6JSnGM
         avl+yOKZTOe8MpF206cd11dQSXeHl3vUToN2adN1ZAqZvyNVRoCYbZlb5KEEyUrWvS2f
         2i4pSNYavGi/ovZn45cIqPDJWwbdLw+h4/OT8LOK/aLvCdf+KNrqy9uibRN82FZ0eAWA
         auVOSzVRZoiaEoTlv2X1l4xfg6o/DdgGsR9ah0aNF2ju9LUITU/OjiU061FWSdq0X0dn
         pJvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ePfEtpxLot3rMArzeOeJWmnT2flpyxN23aWjpbM05Ao=;
        fh=GrWh4psWs+O+1nrqkplJpohGua75dmwDhfeVyZhlG2s=;
        b=J7okNj54UAW/iWxsM8zFDGUeOi4XWMNR106DJyFwufQE8O9QZZvkmXoWDUr6QYd4n0
         bRBBmCxhpItObNMUgMn6rHWLbV/iFHy3sNm9e4ZTeY0uPb9M4AsomTlBTj4C9bdFxjJe
         pU0aWHPYwrasM4kcERkjK+ub2yaIlPCklmc6/ZxZdePpokWY0YSw4vDQMQgG/OIcXH+n
         GUfCugU9GCZ3ufA5w2TPIidwsyOjZGxqXuxGXSj8t8I0mNGn6IigRzp1ZixxDU0IBetw
         eCwTIgFDqUB7ng0pyKeFkGMF5VLr6uEkoOesT2sIJ4GQgnZ7w23MXQBAz05wj3dr3V6l
         9h7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dh1NQMIe;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751747636; x=1752352436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ePfEtpxLot3rMArzeOeJWmnT2flpyxN23aWjpbM05Ao=;
        b=Kn0w7OjBflx3krCsDcSxvnsSIR6YRCHCqiUU0CS3V3qDZOPyccWp0ILJ/Mbtur6aDi
         GEXbS6/KWhMFMV0n8BOr4xuTrHrL144GClmEcLhAZ/TBYuEBv1ZjAbVea5LeW2IFsz0h
         3jIu8TUvcPN5Jh6q3KSF0iWGATQfoue47O5hnMkJavt2yFou6PtvFwUBvar5InLNFzyP
         03/rPpa5k4XRgG4ipbQfWjwefX+3Lhz/pIhtsVkFR0cffffVeMK+RleGjI3cgho++R2Y
         lieZqFC6ceQod32Xwuk8QtbBK8TOZl2bhfoA/EbFcoYDld9j05nYAyEliwcm8cD3b6DT
         IMjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751747636; x=1752352436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ePfEtpxLot3rMArzeOeJWmnT2flpyxN23aWjpbM05Ao=;
        b=Ce9dHLFA9XGCzMPoQpZUr6bHR+ArNX5u98rMAqAJyP3nN1PCS7T6yxPX3Kco75eeF0
         dZZaRD82E7X7ZFCMi11nMfVoRQmJxCYsX5rty+lmhir4/IHojBApyGoWSy1Un1ZLegdQ
         wh2S+RLHquOkyiyBXq/mXwpJ8Xt/Bdn+sdscu2QbGofBSuDec6Ct68rye6MdFXHK5JER
         VlCfc3fdGarYYnWo/PirjaMcuEsDh9RJJ0eEMpTL4irhCg6L8HazyQ/n8nvu+399tRiF
         6cRJE7Ph5NlXVxeccCOU1Fp1krXwmqenL8iqefc6TjuyHja9tAe1/f9UI63lugvvqHsK
         UL+w==
X-Forwarded-Encrypted: i=2; AJvYcCVd67ecBtTsGzDnoY8XEIDcV0D/IGaU3e3Scvf5XcdCo3GLY8xUTKYf9Y8vFIjHk3BHLPClvg==@lfdr.de
X-Gm-Message-State: AOJu0YxmTt2KNNmfEC2rQVolWYFgQtBt/4EhU8P6zcZEyF7MFO4DiUx0
	N0W2kui53wlfpBSJa1vlJuAF+QDd8DlWEY7kJ0tnPDdX5DkbDs9jwQDC
X-Google-Smtp-Source: AGHT+IFyO3DNpCbRfsBdUN7cBMKn6PvzFYUNF27jtX0UkS2JVNK3zIlhZSRyMCegpQtDJoBdCanG5g==
X-Received: by 2002:a05:690c:9511:b0:70e:143:b82f with SMTP id 00721157ae682-7166b69ebf6mr76601707b3.32.1751747635932;
        Sat, 05 Jul 2025 13:33:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2Xo6kRbOyx2OftgOiE6RfcbFwLvL3DKgkxvSnbO8h+A==
Received: by 2002:a25:5807:0:b0:e84:2a56:5876 with SMTP id 3f1490d57ef6-e89a368b6dcls1085305276.0.-pod-prod-08-us;
 Sat, 05 Jul 2025 13:33:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBITRM0PHV4/eosnIbvGjldcQvVV+RYYLg4UnK/fPcUEdTjNCCmN6UB+MpkzMRz4ljDAVSUY+koPc=@googlegroups.com
X-Received: by 2002:a05:6902:1614:b0:e84:ccb:1148 with SMTP id 3f1490d57ef6-e89a09f234bmr8214669276.10.1751747635267;
        Sat, 05 Jul 2025 13:33:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751747635; cv=none;
        d=google.com; s=arc-20240605;
        b=CKWicDHya4rDz0LCYY5bOcH1Dl0ipDi2NeEyrfklxJCu3+LBe9Hn24a95DabQJEVy6
         4v9Z2rEAAWkQG4SQcg75R9K6pXWFx5gk6pyZatyE/PBfS/QpTvwcGqPmUD2/snP6H+Gi
         nee6wNg+ODR3hZMKEsgx+aEQvbyLNJYLdn01B75uosHDaZbhkjSMfBO1HF1pwvI+rOVD
         GsxHSAvo7hXsai6T3YJ/Fe1IMC+uTLdqaVVGHOGNw1KPKMM/XoKmLTY+Q0KerB17+ENz
         u92jvFvqJTUoI8W2YUr7+Dj+VsFyCHtZg69CaVLX96pmwYX3JNYiR9tltbMQpLS4kyiT
         ZTDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xIrzyY82ZmJ8Cv8VqsFvyXYZGUoukviQlJjqGO4bPB8=;
        fh=ajsM17EAOL6Fxaw3DPHvK/x1BqMY4iRD4b26QdTsiIc=;
        b=deDbd+Pmz1jzifn+DvXlYzPzvT0R1+PMYjqxnTlyyXceqymYry3WUsqH2EE5Zlcmnh
         mgUo/25E6boO8RrGO7zjMo5ftG1xiZ6mocHChBs9g1LA0mkrizMOwvpVWEwU1Ju5yH0b
         1ER6QJVAAVqdSDFZzqstcsU3hGmYKf1AwwWcppZ/4CIMNK/1Sjm7RqhyWCIfdOVXbIe8
         dzT2Xh1w7q/CvGxDiDEDOVKPJeUxcwxgAeuwH4Q654QAxLCX3sLVI2zyOXRueViHDbW0
         IZ2cB72JBuPVHDjHQZJdRJ20AqHjm0HT46EPGLBBm4ANv7LsewX9EqNAtn6X69HF2dge
         TxfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dh1NQMIe;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e899c137b93si292711276.0.2025.07.05.13.33.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 13:33:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DF5DB5C4B32;
	Sat,  5 Jul 2025 20:33:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9B287C4CEED;
	Sat,  5 Jul 2025 20:33:52 +0000 (UTC)
Date: Sat, 5 Jul 2025 22:33:51 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: [RFC v1 2/3] stacktrace, stackdepot: Add seprintf()-like variants of
 functions
Message-ID: <ec2e375c2d1ed006f23e31d2f6ec7b46a97ad71e.1751747518.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751747518.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Dh1NQMIe;       spf=pass
 (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted
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
index 73d7b50924ef..a61903040724 100644
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
+	return nr_entries ? stack_trace_seprint(p, e, entries, nr_entries,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ec2e375c2d1ed006f23e31d2f6ec7b46a97ad71e.1751747518.git.alx%40kernel.org.
