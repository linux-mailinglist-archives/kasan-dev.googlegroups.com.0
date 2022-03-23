Return-Path: <kasan-dev+bncBAABBL735SIQMGQE6BIMFEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id EDA264E554A
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 16:33:03 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id s8-20020adfc548000000b00203eba1052esf635320wrf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648049583; cv=pass;
        d=google.com; s=arc-20160816;
        b=hhUeZXxaURBp8dUK4xtDqN8CieuAevZFTrEH2dFM8oeOSL7UbHJJ5DQhqbFO8pCm4P
         CUZAMK1/z9TAONJFn0XMbAOd6P6abKHKyXDDBOBwduyHB5xOwtLQzxPcSIxuItkev4Mm
         fyFp9s9IPnlvWTqkt7AYXWKLhrQxBIo2HfQwCDtN/IJD4KNE0oUdpe1KrmtkE7/fmX/X
         HJi1eb0O6tzBBROvJuwgtIOXpq4X9jblhY2laf+6FCnzMidzy67SpZQCVr++GHT00CwR
         Nxdb+i6g0+U592tgJuk00RiHRk6ZQRW/cN2yKRWp+3bl3+GyeOLb5xH08jnbbWHmx1EA
         tc2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=i9xOcf0KGmGB5cyKBHAciA0CggIQz8e8S9dw20ZcDL0=;
        b=qMc1J4e6MymczGiPaKW67kPSpncFSOw03S11Fvf/rRXK7cut/XwA+dJRMjG80vB1SY
         ektwssZ+L/3QzMXJ43DYNDlf/Bk+l1BAUnd/HZpT2UoxgPoUaUFn32I7rVFOlFZ6J+i8
         F6jpdxdZCqniM92hrESidBNK4aao9vBCe5cYGsNLMZtO7PFriaoRehSQZM4fNU1q2dcL
         Xe729LOpPBuKa75q3hrsan/ekX3WnRxYux7GKwfPFGjBtbbi/YXGtNGBqILvkxKxUdP0
         HuWEekk99/eIh5A1lj2KP5yd1Co9lD5dJKu2SsF9DmMt3BKI0KigessegO1xMj19RSUs
         82vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UTJfa80A;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9xOcf0KGmGB5cyKBHAciA0CggIQz8e8S9dw20ZcDL0=;
        b=DspPVyJcKeh/awUPIMIkkK5YcyDRjPIpWXhPubzg8EL7CR6JZarhhOK2BHVHFYRRzn
         M8GtD3IPKlddpK1bXuS6HPAdCIm8go/JyISUhPefCLVrVQkugHtxe+GMuSsbvruUdwGW
         IfzWOlYwMUbjwhhnCghLhI2+JnOZOIVkY8VdhUN8Wjh6VUhQtJTGDmedkQbY4XR0V+Ml
         K/VBR3JUCRGAgOLsJBP3gk0rnCB9xXuZFJUNH2z+EIZaRAwdSDSdP2SjgBrkkjDfijDd
         ykbyfi9C2keaMwPr0NDlFv1eym+FDe2hEqzW9n9l5E2cnnC49TRl0GFBwCmaLVbAvzBU
         qyhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9xOcf0KGmGB5cyKBHAciA0CggIQz8e8S9dw20ZcDL0=;
        b=Vu8AK+VevSxDtS9U7zgfTielo0eDIKgt2aWy3CaezoSqZlG71qGq4xOzyf6AakpwUN
         i5zBOpo+X4fNEKmiDyJAAd1ZsrMAGnoNc0gdMkUHRAAV9FbIli2yBsicSRhKZQ6XEVPP
         7n8U2MybLadbhQ46HMuKsLHD0U1QWKZZNJ75V+fF8M/Kg4YLoKtlujljsD7A3in/OYH5
         LLK/6h9j/GcLxSYFZ/cLY+yoj6xsz1bEbhAqlzaZOYIxhsUpvGhE5BwvoYqbtcynf2Ax
         h5QVv+47emRJ2jBqccqQkdcqpwjWGqB1lGxrK8bjgeNy7RZ2vFXZFNiq7rMXKvOQr9Gm
         WKzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LCxrgxuGaJl22AcEthyldHiF3muLmyEq7xYK8UJfBeWRS3eF6
	rSgvbLzVKiQxEFTDISQSFG0=
X-Google-Smtp-Source: ABdhPJz6+YyrcMKGm6k114/99G3sDekWHu/yB7Vka7wXxtjqp21PXva5ztgxhmOC+92MPyWH1wLHDA==
X-Received: by 2002:a1c:1941:0:b0:38b:4af1:49f8 with SMTP id 62-20020a1c1941000000b0038b4af149f8mr9873249wmz.156.1648049583514;
        Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e01:b0:38c:9f99:b05 with SMTP id
 b1-20020a05600c4e0100b0038c9f990b05ls3152795wmq.1.canary-gmail; Wed, 23 Mar
 2022 08:33:02 -0700 (PDT)
X-Received: by 2002:a7b:c017:0:b0:38c:8a13:466d with SMTP id c23-20020a7bc017000000b0038c8a13466dmr9980251wmb.128.1648049582750;
        Wed, 23 Mar 2022 08:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648049582; cv=none;
        d=google.com; s=arc-20160816;
        b=lrKZuP3uP0kKI/yGxMsdYR5/XT4v+lNC+I4YuDi3fFqu+gkunx4EA3amEjBadZiB4f
         Fvu+9/jD8UYpYujOBhIJjHontMYV8bJ1OpZCMucPFCHmRgtcaI7Jflbtpa3Xm98RApli
         jMf1Sqg52KxWWKUL74FEUn+oQnpJ9gsXMHQRHkpMA0pas7jlUrdhH2qHUaKbkaauKdvr
         sOWfP3p1OecWNY0UjqkMnQXAZF1+Z7FJu+ZvfXybM7VIPsrrVGePNFwgWS1JHv+2YYU4
         qeW8fnSV6WJq060rm5BKyXtwSvMf6ok53xEofHD9zW3UODq1TDzJQcaLKes7Va5BxBCw
         ou3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mmc3nZQPUIWzZbIw9R7zdg/6fIrR3qfP7vluF20CZjk=;
        b=UQiMM17OFYJrBXL8Rv8HlZc6EyBDfhfRQepptEdVlqo6O7duLXlTtMgJSs4S9ZJC9w
         Qyy+/njvwZnot3ITT4CLmBkB8kB1gmAycHwBZ4yMeXwAj9aO0E30SDY3tzi/SaienruL
         xgQzlJRtnOpBuyToihomULIxqz8TdfpjtKiKS+UYGhlOGcD4wvWtryRMwS5Uuklkx4/1
         xJA2V+NlhCc2R+fCg2DFWzFfEEGFFFFksKcfSQEzg9ZVu8Wq6KLicfZhkPj1hH5CKPn7
         W859I0LTMtgVSIl6WeEBOwRxYXCPvkBI77YuixDaZToN/rS40aBEagHXahSNHPfjaHc7
         4VZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UTJfa80A;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id y1-20020a05600015c100b002041bf4e54esi27710wry.8.2022.03.23.08.33.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 23 Mar 2022 08:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 1/4] stacktrace: add interface based on shadow call stack
Date: Wed, 23 Mar 2022 16:32:52 +0100
Message-Id: <21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
In-Reply-To: <cover.1648049113.git.andreyknvl@google.com>
References: <cover.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UTJfa80A;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a new interface stack_trace_save_shadow() for collecting stack traces
by copying frames from the Shadow Call Stack.

Collecting stack traces this way is significantly faster: boot time
of a defconfig build with KASAN enabled gets descreased by ~30%.

The few patches following this one add an implementation of
stack_trace_save_shadow() for arm64.

The implementation of the added interface is not meant to use
stack_trace_consume_fn to avoid making a function call for each
collected frame to further improve performance.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/Kconfig               |  6 ++++++
 include/linux/stacktrace.h | 15 +++++++++++++++
 kernel/stacktrace.c        | 21 +++++++++++++++++++++
 3 files changed, 42 insertions(+)

diff --git a/arch/Kconfig b/arch/Kconfig
index e12a4268c01d..207c1679c53a 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -1041,6 +1041,12 @@ config HAVE_RELIABLE_STACKTRACE
 	  arch_stack_walk_reliable() function which only returns a stack trace
 	  if it can guarantee the trace is reliable.
 
+config HAVE_SHADOW_STACKTRACE
+	bool
+	help
+	  If this is set, the architecture provides the arch_stack_walk_shadow()
+	  function, which collects the stack trace from the shadow call stack.
+
 config HAVE_ARCH_HASH
 	bool
 	default n
diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
index 97455880ac41..b74d1e42e157 100644
--- a/include/linux/stacktrace.h
+++ b/include/linux/stacktrace.h
@@ -60,6 +60,9 @@ int arch_stack_walk_reliable(stack_trace_consume_fn consume_entry, void *cookie,
 
 void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
 			  const struct pt_regs *regs);
+
+int arch_stack_walk_shadow(unsigned long *store, unsigned int size,
+			   unsigned int skipnr);
 #endif /* CONFIG_ARCH_STACKWALK */
 
 #ifdef CONFIG_STACKTRACE
@@ -108,4 +111,16 @@ static inline int stack_trace_save_tsk_reliable(struct task_struct *tsk,
 }
 #endif
 
+#if defined(CONFIG_STACKTRACE) && defined(CONFIG_HAVE_SHADOW_STACKTRACE)
+int stack_trace_save_shadow(unsigned long *store, unsigned int size,
+			    unsigned int skipnr);
+#else
+static inline int stack_trace_save_shadow(unsigned long *store,
+					  unsigned int size,
+					  unsigned int skipnr)
+{
+	return -ENOSYS;
+}
+#endif
+
 #endif /* __LINUX_STACKTRACE_H */
diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
index 9ed5ce989415..fe305861fd55 100644
--- a/kernel/stacktrace.c
+++ b/kernel/stacktrace.c
@@ -237,6 +237,27 @@ unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
 }
 #endif
 
+#ifdef CONFIG_HAVE_SHADOW_STACKTRACE
+/**
+ * stack_trace_save_shadow - Save a stack trace based on shadow call stack
+ * @store:	Pointer to the storage array
+ * @size:	Size of the storage array
+ * @skipnr:	Number of entries to skip at the start of the stack trace
+ *
+ * Return: Number of trace entries stored.
+ */
+int stack_trace_save_shadow(unsigned long *store, unsigned int size,
+			    unsigned int skipnr)
+{
+	/*
+	 * Do not use stack_trace_consume_fn to avoid making a function
+	 * call for each collected frame to improve performance.
+	 * Skip + 1 frame to skip stack_trace_save_shadow.
+	 */
+	return arch_stack_walk_shadow(store, size, skipnr + 1);
+}
+#endif
+
 #else /* CONFIG_ARCH_STACKWALK */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl%40google.com.
