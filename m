Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPHSXFAMGQEAFW6H6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D44C6CD09B0
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:18 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5957d86f7f9sf2166276e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159238; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qb5GtRxBJU7yKtlFGtFURSfmiHVcspZP/I1e86yucgGo3py12yG7Tv66bj2fyMMcui
         c1bwtRTexDuUCd9liOjvwSHeXh4IXsIjbRmnGWGIMWFHGYKe7TgLSCTJEcv7WQiOBl8L
         nCPldboNpT2SAspaxjz2fyygDeCa6GVhS1Cc91YYq1LcMdl/s1h4Vp/JGcuZk7/avsAE
         21iElDKB0dYML5tjnN1Dim+WRw3iKogRSrwZT/RPsy3saJEn6Ys/o9Y3FAkLr2oh4tY8
         WQFsf3v4EJSces/dBbA2UzqQ6iJ5iGFln2wWu4n4N9sGUrseUcoS1fTJX6dQ+oV4wycJ
         kWGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Q0R/ODOpFQAHSrX/1b8dDLWpCZprgYy7kr6vjiexDsY=;
        fh=c/VuZosmZb7DJIYzsIU9Cagsz602pZ/HB8KuHyHR0U4=;
        b=cSJu30rR123ZV8wd6BivkIDjCX5Qi0tDrr5MKG/3gpGdUJdh1ASYcy22UywyiEXFT5
         JLPcDAphlYgMZ9X2O8LacMy6J0LQJPHxwiIEQs2TLeT4ChNwTe3Jj5DszOLbqzEhYQbg
         hX5BKoisBQHxcDnfbswVmdz0rWJz2Bu55uLex2Vcjcg9nOLbEAzAv3p7WCvdi5rKIkM6
         ihOXmPImCJaoPUq3VtliXtQtPzRLRRWBPvX1elgaqJL9goFIMVozioWooObSIb5iADWt
         w30S2N6DVuF1l+xVpqlPrGaOAP1CTEQxhvMeeRh6PDA3+vzjqX0x564fmhgTR6E3FQpQ
         ZJjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zYtbJ8Zr;
       spf=pass (google.com: domain of 3gnnfaqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3gnNFaQUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159238; x=1766764038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Q0R/ODOpFQAHSrX/1b8dDLWpCZprgYy7kr6vjiexDsY=;
        b=iZ6zLohQ+iqtGN9fu1sWRBVlyk19b64vAXXhU4ggpnp8ZZ+5VhP4PautSmMkgVSbYF
         9lub2vesdXPY9w7fKy5AYXdIyPE0Ge85mXmKXgSg9Fe2ZNjqAvGk3/+QqwYt7b1ZeCV+
         VHRkHAjiTfXBacGSpbxpJp7j1bLtmhdvowQgrMLGU02aSj5PvzPy3svKbZyf/4RjpRTh
         Cw6sw3nfpJcRn3JwwvOInnCDaqaAl9F7v+YGeyxiNkfIr+ripHDZiEUbMMwXf/szQ/QK
         NJ3pocb3kFTnXuIGH4nUXxnMgAE+OQ7p+DQKN+L6RbLO0xwO1Gzczl3veOz6CjGgfy9b
         6a6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159238; x=1766764038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q0R/ODOpFQAHSrX/1b8dDLWpCZprgYy7kr6vjiexDsY=;
        b=eIo/B/qr5wUYFRhUXjYZiGd+KxmkYeOKXBEVlqgkk4UeZy/LjoDUCTqjzh1QafH6Ft
         jxxiyALidTT92fLR7mrDyQIWXo7riaLDqXg6HhnmPahEobp9gMrXuzXSjYQzncSWCbAo
         F/hPOyTkym7oUPg5tq/I676QjS2jDN+xocFSSQBusAOxnvAsFbW3LJyC0234E64xSA2O
         k1yp7pjgsGFSweC9g4a1XGud5lRPRU1+BtvN9jBzqWZOdvKSUzgUhnEkOzK911nNIAT0
         xvZ//Ps5YWDKYejkGmsTzhvCOv0gzcZk5PVZBAepF20NGBPi7AOQhAQakXybnU5T5vkx
         4zFQ==
X-Forwarded-Encrypted: i=2; AJvYcCVWDcniISxydhh3zx+xIQrd/Jr/GuTY7BpF67Xrky4MdLv/MczYxvb8qak5+xhDdGGtqJrVUw==@lfdr.de
X-Gm-Message-State: AOJu0Ywa7sP/XIgwQdblUxPbaYjMDGiD1aeFbtqJnUoYCTOJw2XBlV9j
	m3LBJ7J3oe5rXIQFUJz6nrYXElEmICFG+Hcan0xzqvyl2YMXigOPAhu9
X-Google-Smtp-Source: AGHT+IH0YenmAfwznC5WNX4OP73SVTNXuHIDs2F/4oriHWtDIPmb7+cJ31je8FyNZh339AIUoJxROw==
X-Received: by 2002:a05:6512:3d8a:b0:599:105a:67e0 with SMTP id 2adb3069b0e04-59a17d60ecfmr1327805e87.20.1766159238037;
        Fri, 19 Dec 2025 07:47:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbkg6+1jHbPW02So2r5GPOE0pRaS9QXNfveh0uT83npzg=="
Received: by 2002:a05:6512:b17:b0:598:f3ba:8494 with SMTP id
 2adb3069b0e04-598fa387fcdls3529041e87.0.-pod-prod-06-eu; Fri, 19 Dec 2025
 07:47:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZF4Cwp5zEen5zeEWo+tStOzp9NMNp4MGbl9a9IEKlZTM0ANTnXcftcT4naxnbiwY/Du0uAM2e19k=@googlegroups.com
X-Received: by 2002:a05:651c:4210:b0:37b:ceac:5e51 with SMTP id 38308e7fff4ca-38121637132mr8270081fa.19.1766159234990;
        Fri, 19 Dec 2025 07:47:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159234; cv=none;
        d=google.com; s=arc-20240605;
        b=ThyhUNDEMhPOlpJH3dY0Qcx8dKlieLK8RjS0KNGojBLv2Uz0hwpOqy9moslBIquoFq
         xt8F/LTfh5R0T8zNIU6hgLZrdZn8MzdZlJVdYtKWhrnFEs6ZSXiTL97AtdYAzwslvxsM
         CmNGl47GwHM5R3gMQP9Pt1eUCwxf3yLope2vNEKbMMcgPP0dbTcPdhWaN1VgFoKTz270
         U3yrHIanBt9TTTIgYFb+CxmHOO0sjDvi330wyXmLRQeBz7DAavUFQ5adZU4fpo4+/9AE
         ls9L/XyReT+ymp8556IaQv6aior33hXD5qXbRUmtJqqu2Oh7BWXA5i3+yXPaR2JQOPya
         Otrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Oz8u5mnRRtKrmwrW53CCOIRd71oba2M2eRROatW6JBk=;
        fh=8dVa0EG7W1Mz2gDWg9pgvjSPxGTJ7UBAJ01P1AyiHbc=;
        b=MakG/WeJIKtgYlstNy4tJOT7GRMD178pLBRi0dfRdlvF+4a4nSCAWgSaj0zXONpO0A
         /EAObowwEYYMCMnWKmMArt23LwBHYcuKCmQAy8yiWxZg+04AU73qIwtGBvBmuSCtxgO8
         WRqgkKFj+cY1eTm7dIapfXESsPLs04FFIEBqc2z9wckNnLFYQO7MX+CLEQnKxtgyuBY6
         KhVatjipriEXHxKBZ20skr3HK0BvgFPAeEFoc/tqSN/XzhJGS8xeuRFACRy9lwrbwEjJ
         u4YWTT8AOxfPB2envbYdKoCfpqlJUUG64y+TxCWsoO88X7NwCIglGg7CRxH+Xo5zXyVR
         +0PQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zYtbJ8Zr;
       spf=pass (google.com: domain of 3gnnfaqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3gnNFaQUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-381224efdc2si386711fa.3.2025.12.19.07.47.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gnnfaqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4779b3749a8so13975045e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVdrAncNs4AxqY87WabFzQeNAMl2PSJ4vEgmD0381Y012tFkywLnmnCIQKNrKXDwi5mQaA9BSGyY7w=@googlegroups.com
X-Received: from wmdd3.prod.google.com ([2002:a05:600c:a203:b0:477:54e1:e29e])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:c16f:b0:47a:810f:1d06
 with SMTP id 5b1f17b1804b1-47d1953bb06mr26654055e9.4.1766159234094; Fri, 19
 Dec 2025 07:47:14 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:16 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-28-elver@google.com>
Subject: [PATCH v5 27/36] MAINTAINERS: Add entry for Context Analysis
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
 header.i=@google.com header.s=20230601 header.b=zYtbJ8Zr;       spf=pass
 (google.com: domain of 3gnnfaqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3gnNFaQUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Add entry for all new files added for Clang's context analysis.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
---
v4:
* Rename capability -> context analysis.
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 5b11839cba9d..2953b466107e 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -6132,6 +6132,17 @@ M:	Nelson Escobar <neescoba@cisco.com>
 S:	Supported
 F:	drivers/infiniband/hw/usnic/
 
+CLANG CONTEXT ANALYSIS
+M:	Marco Elver <elver@google.com>
+R:	Bart Van Assche <bvanassche@acm.org>
+L:	llvm@lists.linux.dev
+S:	Maintained
+F:	Documentation/dev-tools/context-analysis.rst
+F:	include/linux/compiler-context-analysis.h
+F:	lib/test_context-analysis.c
+F:	scripts/Makefile.context-analysis
+F:	scripts/context-analysis-suppression.txt
+
 CLANG CONTROL FLOW INTEGRITY SUPPORT
 M:	Sami Tolvanen <samitolvanen@google.com>
 M:	Kees Cook <kees@kernel.org>
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-28-elver%40google.com.
