Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF7A7TEAMGQEYK4UMMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id DED83C74C7B
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:28 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37a39ed76c8sf8461581fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651608; cv=pass;
        d=google.com; s=arc-20240605;
        b=gij6tCQewfRxnV0NLZMbOMHkosm/J7/sV9czmxAFsQMObAyItxZEzrAHxHOK17KEkg
         Na5xxJEHmmwYu67eqlkmSOPm1vuMMTWeJ2mqah5Wc5Uua1KQmY75Sb8TVeul4CpOsXmU
         4kZCnKmHyE6pycbdBiUDt5POsOEri4+YQvSMbflIblLezgFOhfezq7DWQ8vigIn0juP7
         D4mHeV3Akq/JSZrxfP6SnDVSFr2XlJ8D6oHVarPWgxQdgulQOaURYbD00nyYxUjRtvCM
         P5OJZGWTMxhLJB+51Bzhqt/h7nCWyk0FtJzUtSzhwzXwEdoTpcPXlDPBa0+uSly9f/ON
         Sd8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nK1jDSILd6CNKdRUSTf422mdsj0+B4xYkI28RuD3bz8=;
        fh=2NwBkIyxfDLxnSER08/coMz67aZzYEuJaFvafTJIlcM=;
        b=UlO2ynqoJr8VJDAwjiswkv09c0r3SrrpC6NQ83GviDH1oc2WgaET+gDTHrkdoSmxc5
         vSw92dFB6W6nfqd5aca5e35RBjqdNIWri5Z9PuiPxjoeQ7D9F/PuTqfcTldiEUPgHcVw
         nh1IyyCQe4L38koFk2RDbfyrfJMVFPW+cQTAZK4ZLiI6+8VDxG03/Zw/aisncD5bK9RR
         WmOvK84xjaiU/6vnLH38jtktFDTH6SI+74GoQ6LViEd3iOllyCbum3+06kVOW29Nslno
         BCIXKY425uf6cbc06Ib7atPYBx0QGUmjhlsXB/RqsxP28z8/kRFStPkp8u9S1V4p1DaG
         ltOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jmNAMFI0;
       spf=pass (google.com: domain of 3fdafaqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FDAfaQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651608; x=1764256408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nK1jDSILd6CNKdRUSTf422mdsj0+B4xYkI28RuD3bz8=;
        b=He4qTieDjTnHxDffMuxqsoKzogmGS11aPdbofOoB3sdw/tXvQ9/467sNgO9pQQBOfO
         ZEc5LDPiYZ3jpcYOfH5NIAWVBm8wDbW/dGRNf2STapGoG2IhY7hgVG8jjBmUM2nEnIPx
         Be8Jh7cTxekEDod1y4k1L92W9yhP835oBEySwh/ipWHsUtR8OvA7H0LAaidaZ8XyuoTK
         UCUZPW4yJnsw8vcRspbcnWYWTgw3dlPjGlBr75vSqEBHx2QvOsrhR5raquqVlgGpKMiP
         PEnmUgBtsChICdozgcXONxCmkD0f88VkzRZEOSoXILZiiC3EYosbw4+hV97xQd3SbJdm
         eIYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651608; x=1764256408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nK1jDSILd6CNKdRUSTf422mdsj0+B4xYkI28RuD3bz8=;
        b=hFBwFCO+QtuoqBBk2Vtd2TUl1t1Yl5iLSUcXiXWokKCOAZEAx6/YxY04iHXTwtNzaN
         GTFUlEklHg2YfpGPcYj0yBoFU+NfwuYNXuyI5NenSJFk+eM68gqQkTDYSu7RBhy7JCi7
         lqsr5xMQBF+F0SxJJr8x/MgGd+mLVhXXCDwZIsuFxDgfHsId8rjAEW8B6wKvbiXauIXk
         Tyd045xjN1qF+Ef+lDlYgCIkU/xB1eUycT8DI3vzVgxaw+ZxL8WwafltZbjwXoOHd3lK
         T6qdKnKggxOn2HYkmniXupurlTZ6WKlx94dS5yFXzWGzy7QG7MdH7zDrTLjOSqhkGmYp
         3/6Q==
X-Forwarded-Encrypted: i=2; AJvYcCVZJjdtqQY0sO72Y8BVXscxC/VtA5xvbYGTrR273nixUcz1XUEi9LEOl0wYi1H8WDYLN1NMmw==@lfdr.de
X-Gm-Message-State: AOJu0Yz12Ko1FP5/grx+aIeeeJ85mBJZu7czxO6cDuP30hvHwTSYIHMZ
	l0vugrqM+n+5uestebfOm5oEdYsGnrOd74uKB/iw07tGPTCV4onlkVnv
X-Google-Smtp-Source: AGHT+IF6mkMFWlqYp43VjWq0JwxMX6dqSpGjZv8A6jwtkAyVucoENOJspuKDxrabaL3RSZW8QR6Cwg==
X-Received: by 2002:a2e:7219:0:b0:37a:2d8c:c0a8 with SMTP id 38308e7fff4ca-37cc67b51edmr7794531fa.34.1763651607996;
        Thu, 20 Nov 2025 07:13:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b1JK3v8UVxHulUVh4Ci6mcQ3kjrSr5s0ZJ8ue1Nfm1oA=="
Received: by 2002:a2e:88cf:0:b0:37b:97ac:627b with SMTP id 38308e7fff4ca-37cc69f16e7ls2778201fa.2.-pod-prod-06-eu;
 Thu, 20 Nov 2025 07:13:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlsB9WC2v+Sk6Rp/gF0V49474nHeAKxYGSKspzSy2NlShI55qoiwAtgGddvvVNS07+TeqHNw2U1bU=@googlegroups.com
X-Received: by 2002:a2e:9c13:0:b0:37b:a737:d42a with SMTP id 38308e7fff4ca-37cc6752b68mr7831091fa.5.1763651605227;
        Thu, 20 Nov 2025 07:13:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651605; cv=none;
        d=google.com; s=arc-20240605;
        b=c/Br8ACH2EdnAGoegFo3CLdOYqmTFlO2uGE/g/QpMOxadidKv9WSZq4nJWqB82bzas
         dW2BsiEZYxclcxmEUZXc0L0xkzFYn8/jziMpT8tUDX3mMgW1qYXzgYLXPTbKzux4hbXw
         n/STgP8mcptSMVx1ii6I8rqt1mVfZQWNb76Jxh1MrrhSA4cDVwfxkgFZZCM+gi8prMus
         M4zTTKA0VFCMYIGPVjeGyc9oblUSqar6N631U/HGnzgFWLxf8fQbYdvwUnfEiZmRSfdl
         o8n/Uomi0cDab8Xov3xH6TzKbrq0nZzd+cR5YBoEBZoeqrBDUHELB856V9FtAnH+OYw1
         jJLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=e0QY5sCjABQs82s4Ju3ZdPJK85+Pyg+eamRrTOstnfs=;
        fh=XnBCi4s0OWD2fVlcr1rCcuyHnetvRF8Q6R/Vw7Vkp30=;
        b=jttFtMYnFqErJ3OEQuETQs2VZrXrjgf+xpEdtAuNs3q8dLieoCsPelH/MfQsZKU/NH
         y+Y5zUn8fMfflweZBFLaPtUBnJoKgZv2iM8O1d1oNZAZgxuuuaxm6qkAwXHPA4teTJy8
         NUIOFSXg7ndwqBVNQF9/XrQPZ16hOkxOiCkrlvdnV9KSDtPg1f8Gh6oi18Mftw7cAmOl
         6YLzrKS/0oIcmlalnuL3PejQmlsiIOJ7ilZj9+BTdjorFCRUKDCTavHkzJ8e52ZzU5s+
         GJKdWDOzOX9weUSaaPnecGz9lfNO2+eqor9+NUHaxo8yF9t3khcVb+K7kqbuva6E22Yx
         I3OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jmNAMFI0;
       spf=pass (google.com: domain of 3fdafaqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FDAfaQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6b974f0si439131fa.7.2025.11.20.07.13.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fdafaqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-429c7b0ae36so658569f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVT3WUMeXYuqSOfC5XiQa+Eb+6qp0EebpDbxdq8FdCVRz37YPNPieb96GL8GI5jwWyQL+1RizpdQ28=@googlegroups.com
X-Received: from wrbfq12.prod.google.com ([2002:a05:6000:2a0c:b0:425:6f4f:8f67])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:adf:f8cc:0:b0:429:b8c7:1848
 with SMTP id ffacd0b85a97d-42cba767dd8mr2702228f8f.19.1763651604278; Thu, 20
 Nov 2025 07:13:24 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:49 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-25-elver@google.com>
Subject: [PATCH v4 24/35] compiler-context-analysis: Introduce header suppressions
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
 header.i=@google.com header.s=20230601 header.b=jmNAMFI0;       spf=pass
 (google.com: domain of 3fdafaqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FDAfaQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

While we can opt in individual subsystems which add the required
annotations, such subsystems inevitably include headers from other
subsystems which may not yet have the right annotations, which then
result in false positive warnings.

Making compatible by adding annotations across all common headers
currently requires an excessive number of __no_context_analysis
annotations, or carefully analyzing non-trivial cases to add the correct
annotations. While this is desirable long-term, providing an incremental
path causes less churn and headaches for maintainers not yet interested
in dealing with such warnings.

Rather than clutter headers unnecessary and mandate all subsystem
maintainers to keep their headers working with context analysis,
suppress all -Wthread-safety warnings in headers. Explicitly opt in
headers with context-enabled primitives.

With this in place, we can start enabling the analysis on more complex
subsystems in subsequent changes.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
---
 scripts/Makefile.context-analysis        |  4 +++
 scripts/context-analysis-suppression.txt | 32 ++++++++++++++++++++++++
 2 files changed, 36 insertions(+)
 create mode 100644 scripts/context-analysis-suppression.txt

diff --git a/scripts/Makefile.context-analysis b/scripts/Makefile.context-analysis
index 70549f7fae1a..cd3bb49d3f09 100644
--- a/scripts/Makefile.context-analysis
+++ b/scripts/Makefile.context-analysis
@@ -4,4 +4,8 @@ context-analysis-cflags := -DWARN_CONTEXT_ANALYSIS		\
 	-fexperimental-late-parse-attributes -Wthread-safety	\
 	-Wthread-safety-pointer -Wthread-safety-beta
 
+ifndef CONFIG_WARN_CONTEXT_ANALYSIS_ALL
+context-analysis-cflags += --warning-suppression-mappings=$(srctree)/scripts/context-analysis-suppression.txt
+endif
+
 export CFLAGS_CONTEXT_ANALYSIS := $(context-analysis-cflags)
diff --git a/scripts/context-analysis-suppression.txt b/scripts/context-analysis-suppression.txt
new file mode 100644
index 000000000000..df25c3d07a5b
--- /dev/null
+++ b/scripts/context-analysis-suppression.txt
@@ -0,0 +1,32 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# The suppressions file should only match common paths such as header files.
+# For individual subsytems use Makefile directive CONTEXT_ANALYSIS := [yn].
+#
+# The suppressions are ignored when CONFIG_WARN_CONTEXT_ANALYSIS_ALL is
+# selected.
+
+[thread-safety]
+src:*arch/*/include/*
+src:*include/acpi/*
+src:*include/asm-generic/*
+src:*include/linux/*
+src:*include/net/*
+
+# Opt-in headers:
+src:*include/linux/bit_spinlock.h=emit
+src:*include/linux/cleanup.h=emit
+src:*include/linux/kref.h=emit
+src:*include/linux/list*.h=emit
+src:*include/linux/local_lock*.h=emit
+src:*include/linux/lockdep.h=emit
+src:*include/linux/mutex*.h=emit
+src:*include/linux/rcupdate.h=emit
+src:*include/linux/refcount.h=emit
+src:*include/linux/rhashtable.h=emit
+src:*include/linux/rwlock*.h=emit
+src:*include/linux/rwsem.h=emit
+src:*include/linux/seqlock*.h=emit
+src:*include/linux/spinlock*.h=emit
+src:*include/linux/srcu*.h=emit
+src:*include/linux/ww_mutex.h=emit
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-25-elver%40google.com.
