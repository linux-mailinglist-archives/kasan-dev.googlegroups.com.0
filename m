Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7A7TEAMGQE6DWUIMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 46979C74C73
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:25 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5944d65a8f5sf546247e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651604; cv=pass;
        d=google.com; s=arc-20240605;
        b=JEJ1i4cl20nBL9XTxhYeXonnCA7GrUPsqruhqUU12Ke5CGmLj8IO/Eexb1JGCD1rUG
         tMEU4hnkkUTPaijwnX+xgElMSMSCvm0QnIA3bDxvuCvKGcPU0UuXve0JtXD0PKnBMHos
         evga8vrFeecEmBt8v7y1ScsX2qZA3CjB1hfkaKhdEES2iL4FQ3A1IyVkDEPP1vd6pDM7
         shZoSyXPXAIX+1jPJn/hqDO6YtS60aAe68UTbZYGlx68Brji7B8UXAOJ7bFohH9cv5Vv
         4H15i3PEhHmlmPnL4otpvgXGOdX/Ez9SInF9hlSN5YNtHbjxHpu7/33B21MTwSMQYV9f
         4/Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=UvRLr9fTiMu67/mz5dEhZUF3DUBMfI5CNKqTgUTFT2A=;
        fh=LdjRFZqIqrStwoqDDtI7rHf+JwgisfIUTAYzK0G3RBo=;
        b=Ctv+gJi1W/kH6xG0MPYa42Fis7Rz5XFKXOR3LOzG+vT6+G5qQXG9wMWMyZfqJbHVYX
         GJVai0Jgc/9DyS0q3RKn0DtHw9j9sApJgsPNsqePA1nCxQO6b+GhZ5ayNRvfxB6yC4Ui
         YFUuQ187KD2n2YBozLvb5hw9byGzorlq9cr2WNGwtiSVGc4KlV1FKaW7Au/EuWwWd4fj
         I5noFHa2LcpUQxKzqz0Bkv55dlztUuOwz7qQpGvg8/vmgoYNqTnY1Jy3MHA1DnfDPPJU
         JZNS+vyk7TTHMZDUIEyJeyvU5/9u3ThZv5mN3ai0A7YmXBIL5/a7CtGQOALeDmBJrkZ7
         Xjzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=saJGhIHL;
       spf=pass (google.com: domain of 3edafaqukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3EDAfaQUKCT0dkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651604; x=1764256404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UvRLr9fTiMu67/mz5dEhZUF3DUBMfI5CNKqTgUTFT2A=;
        b=KliT+axeDWhs1L48er6e4uCvf5m7lGhzvAMUD7CXeeX+2bIxFQnSnNHP8WHRB+1qrG
         za7q54RW6EZpkkS0rj/YzLQ0qbhfEQgihU7tMw/mUUQ8AP6LkU+vR9S4J6t9wnhEu+4X
         SKeh45/HDcKZy7Flrowf5p4E08qqWhWZhRlfN2tSSMOxDsX7+g11Of5ttnkx5yNTn2tj
         VRE9aGl5ud93X3XRFskPIGuqaP4XHnYDIvCYp0g6vR047Kp1aP1634jfqaAQkIyKZRT4
         nYMfPAyRRy0vDkzVFzjjtuitg62dqbGH5//YzIMUbtwf605oXGnXkiLSV0vXRJL1AwOl
         8FIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651604; x=1764256404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UvRLr9fTiMu67/mz5dEhZUF3DUBMfI5CNKqTgUTFT2A=;
        b=krAXqDGGPIkInSa+x7OmpoIzWe9Up1q1iqSfSt9wPgPBuQvTDbRJrH0kTDsrTq6G41
         iwI6/RAuk+Q/hCpet6WCzhVAI8PRWaDBlxgsfAfYzBkv/g7n1PnG26BtJDbOdVR5CuK7
         ZAiOX/dmeo9ltvgoEla6DWApYaIMJDN6PCeQpl6GKHOIp9wKx2G30RooiFku+pyWvrYK
         u6CrL9NLUOHRJC4a1RagRLNVxQrluIWvVPTMU+k846wSU/q6IPCvRDY93JhBEwAsdGdl
         ERNeJKyO3xisc2136YZvx+Gc1jKnPDAAJ9n0NAr8dEDoWJE1HfQgy9z9cN4AOHzKSUpr
         9EAw==
X-Forwarded-Encrypted: i=2; AJvYcCW0w94WdQtmuTjsZNjBTlLwqru89s/v/RDa+p1yrDFK//gPNx7ZmwrjOOwzBmIHceXuHu0trQ==@lfdr.de
X-Gm-Message-State: AOJu0YyCvRtn+3l/2d94UrWJYzx9aFKjeb2VOr5w2WdVCwQcxQaYVk3i
	KLwfj8HcbVG0ajFrIOUypCs9gRwYoILMvWTgsyVDmQgot93zfVJ013Xn
X-Google-Smtp-Source: AGHT+IHtDDZ+RrKH0n0WRm3zucLuCuYoEdzBe9IxvESA/7VkrbFKGV3YLMhGWXVTBQSoXUHyg60jNw==
X-Received: by 2002:a05:6512:e84:b0:594:1957:a36b with SMTP id 2adb3069b0e04-5969e2d0657mr987694e87.2.1763651604314;
        Thu, 20 Nov 2025 07:13:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YDwhoF1wKMsBWqJkSw/w+MPmNnTUZ/vy0pUgc6HGC88g=="
Received: by 2002:ac2:4f14:0:b0:596:a184:68b6 with SMTP id 2adb3069b0e04-596a1846964ls113683e87.1.-pod-prod-09-eu;
 Thu, 20 Nov 2025 07:13:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWLYtWE3GqrCQU/rPawfPnC5+VvameuV3ktgulrD2MswaJeIkHvm+TMylB0x+M/7A/+GcRKMTtSUfs=@googlegroups.com
X-Received: by 2002:a05:6512:1391:b0:595:9d6b:1174 with SMTP id 2adb3069b0e04-5969e30ab1amr1029888e87.35.1763651601062;
        Thu, 20 Nov 2025 07:13:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651601; cv=none;
        d=google.com; s=arc-20240605;
        b=X2/z9/gHMzbpzhjKgHiBumHZVj5NBzNG4ibP9v1W15iRsntdYBwi9Q3ghB2H29WH0Z
         5FWIXtJjIRZRGuCSV+SHj8JP4RaUYkBFH3uAZDeGw7+FKxduQYFhBXkGW8g1lqq2yGDn
         GRZYWZKGRuKjpuex/SAZoS42o9SDuIjqq8uq+Z2/jb/Q7kg/5OTzNF8jOFjiSPJiBBeZ
         +73yxn4hWUOf/KxvTGTPmBI44iXRJRvLUk93a1KRXwRKbiGuDuxCBiCkoiz+5ekbUcnv
         5rln0LCbI5Zr9JNIueDb1tJ5Q5Ppnhy6hJSaRy9x0njLt9CKrjyJGMk8CF4JYxWwPK2y
         K1dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hnrOsDiUA3Jbc7VaJ0HrkQb/VaIIv56J10QiPSfXr78=;
        fh=hX+jMyQ5BgGOic9UGEQk/HeMuGYjdnEbn8xGd2zrXGg=;
        b=BrFm0uSK+uLmcqDKenXqxEZ1/mpV+je2ixNm75RLlYcqjqYZ7r58orzTSv87DtRo/e
         R2CTzJv4dfndHsWGej7BuQCZ3Dj9EFtBe6qei4PoRfeM2XlZncU2X3gdRRvtqRCFY3Ai
         fShEdwtswweuS9DYnP2xChU2Pl6LngWHcxoijX9EPJvsVr/uy9XNSR+1gI0xW0fi6KbM
         aNRwFLHjo79QqtYwR9klcfVNscA9UoxHIPbYso44rwMkVRm9cgxqL0fHPDYaqoP3Bk+r
         R0NUK7SSbfbVbWNqePP1G7uQ1gBuodwZ/plLQLUbwnbFPs07AziPtP1qg1WBHGK0CoJP
         NCpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=saJGhIHL;
       spf=pass (google.com: domain of 3edafaqukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3EDAfaQUKCT0dkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba093esi48140e87.3.2025.11.20.07.13.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3edafaqukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477563a0c75so5573575e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXMCNWhbD3O/9uKQfKb+uqJ2cJ3cxyNpJslhIYXq+fo+JTz0AqTQMvWj5e61UkE2KFE1ytf/8JskOg=@googlegroups.com
X-Received: from wmo9.prod.google.com ([2002:a05:600c:2309:b0:477:81d8:54c6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4704:b0:477:7d94:5d0e
 with SMTP id 5b1f17b1804b1-477b8a9ab58mr32475085e9.27.1763651600324; Thu, 20
 Nov 2025 07:13:20 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:48 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-24-elver@google.com>
Subject: [PATCH v4 23/35] compiler-context-analysis: Remove __cond_lock()
 function-like helper
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
 header.i=@google.com header.s=20230601 header.b=saJGhIHL;       spf=pass
 (google.com: domain of 3edafaqukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3EDAfaQUKCT0dkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

As discussed in [1], removing __cond_lock() will improve the readability
of trylock code. Now that Sparse context tracking support has been
removed, we can also remove __cond_lock().

Change existing APIs to either drop __cond_lock() completely, or make
use of the __cond_acquires() function attribute instead.

In particular, spinlock and rwlock implementations required switching
over to inline helpers rather than statement-expressions for their
trylock_* variants.

Link: https://lore.kernel.org/all/20250207082832.GU7145@noisy.programming.kicks-ass.net/ [1]
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 Documentation/dev-tools/context-analysis.rst  |  2 -
 Documentation/mm/process_addrs.rst            |  6 +-
 .../net/wireless/intel/iwlwifi/iwl-trans.c    |  4 +-
 .../net/wireless/intel/iwlwifi/iwl-trans.h    |  6 +-
 .../intel/iwlwifi/pcie/gen1_2/internal.h      |  5 +-
 .../intel/iwlwifi/pcie/gen1_2/trans.c         |  4 +-
 include/linux/compiler-context-analysis.h     | 31 ----------
 include/linux/mm.h                            | 33 ++--------
 include/linux/rwlock.h                        | 11 +---
 include/linux/rwlock_api_smp.h                | 14 ++++-
 include/linux/rwlock_rt.h                     | 21 ++++---
 include/linux/sched/signal.h                  | 14 +----
 include/linux/spinlock.h                      | 45 +++++---------
 include/linux/spinlock_api_smp.h              | 20 ++++++
 include/linux/spinlock_api_up.h               | 61 ++++++++++++++++---
 include/linux/spinlock_rt.h                   | 26 ++++----
 kernel/signal.c                               |  4 +-
 kernel/time/posix-timers.c                    | 13 +---
 lib/dec_and_lock.c                            |  8 +--
 mm/memory.c                                   |  4 +-
 mm/pgtable-generic.c                          | 19 +++---
 tools/include/linux/compiler_types.h          |  2 -
 22 files changed, 162 insertions(+), 191 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 2936666651f3..e53f089d0c52 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -113,10 +113,8 @@ Keywords
                  __releases_shared
                  __acquire
                  __release
-                 __cond_lock
                  __acquire_shared
                  __release_shared
-                 __cond_lock_shared
                  __acquire_ret
                  __acquire_shared_ret
                  context_unsafe
diff --git a/Documentation/mm/process_addrs.rst b/Documentation/mm/process_addrs.rst
index be49e2a269e4..25d551a01f16 100644
--- a/Documentation/mm/process_addrs.rst
+++ b/Documentation/mm/process_addrs.rst
@@ -582,7 +582,7 @@ To access PTE-level page tables, a helper like :c:func:`!pte_offset_map_lock` or
 :c:func:`!pte_offset_map` can be used depending on stability requirements.
 These map the page table into kernel memory if required, take the RCU lock, and
 depending on variant, may also look up or acquire the PTE lock.
-See the comment on :c:func:`!__pte_offset_map_lock`.
+See the comment on :c:func:`!pte_offset_map_lock`.
 
 Atomicity
 ^^^^^^^^^
@@ -666,7 +666,7 @@ must be released via :c:func:`!pte_unmap_unlock`.
 .. note:: There are some variants on this, such as
    :c:func:`!pte_offset_map_rw_nolock` when we know we hold the PTE stable but
    for brevity we do not explore this.  See the comment for
-   :c:func:`!__pte_offset_map_lock` for more details.
+   :c:func:`!pte_offset_map_lock` for more details.
 
 When modifying data in ranges we typically only wish to allocate higher page
 tables as necessary, using these locks to avoid races or overwriting anything,
@@ -685,7 +685,7 @@ At the leaf page table, that is the PTE, we can't entirely rely on this pattern
 as we have separate PMD and PTE locks and a THP collapse for instance might have
 eliminated the PMD entry as well as the PTE from under us.
 
-This is why :c:func:`!__pte_offset_map_lock` locklessly retrieves the PMD entry
+This is why :c:func:`!pte_offset_map_lock` locklessly retrieves the PMD entry
 for the PTE, carefully checking it is as expected, before acquiring the
 PTE-specific lock, and then *again* checking that the PMD entry is as expected.
 
diff --git a/drivers/net/wireless/intel/iwlwifi/iwl-trans.c b/drivers/net/wireless/intel/iwlwifi/iwl-trans.c
index 5232f66c2d52..12016bb00596 100644
--- a/drivers/net/wireless/intel/iwlwifi/iwl-trans.c
+++ b/drivers/net/wireless/intel/iwlwifi/iwl-trans.c
@@ -548,11 +548,11 @@ int iwl_trans_read_config32(struct iwl_trans *trans, u32 ofs,
 	return iwl_trans_pcie_read_config32(trans, ofs, val);
 }
 
-bool _iwl_trans_grab_nic_access(struct iwl_trans *trans)
+bool iwl_trans_grab_nic_access(struct iwl_trans *trans)
 {
 	return iwl_trans_pcie_grab_nic_access(trans);
 }
-IWL_EXPORT_SYMBOL(_iwl_trans_grab_nic_access);
+IWL_EXPORT_SYMBOL(iwl_trans_grab_nic_access);
 
 void __releases(nic_access)
 iwl_trans_release_nic_access(struct iwl_trans *trans)
diff --git a/drivers/net/wireless/intel/iwlwifi/iwl-trans.h b/drivers/net/wireless/intel/iwlwifi/iwl-trans.h
index a0cc5d7745e8..10b38d09cddf 100644
--- a/drivers/net/wireless/intel/iwlwifi/iwl-trans.h
+++ b/drivers/net/wireless/intel/iwlwifi/iwl-trans.h
@@ -1063,11 +1063,7 @@ int iwl_trans_sw_reset(struct iwl_trans *trans);
 void iwl_trans_set_bits_mask(struct iwl_trans *trans, u32 reg,
 			     u32 mask, u32 value);
 
-bool _iwl_trans_grab_nic_access(struct iwl_trans *trans);
-
-#define iwl_trans_grab_nic_access(trans)		\
-	__cond_lock(nic_access,				\
-		    likely(_iwl_trans_grab_nic_access(trans)))
+bool iwl_trans_grab_nic_access(struct iwl_trans *trans);
 
 void __releases(nic_access)
 iwl_trans_release_nic_access(struct iwl_trans *trans);
diff --git a/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/internal.h b/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/internal.h
index 207c56e338dd..7b7b35e442f9 100644
--- a/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/internal.h
+++ b/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/internal.h
@@ -553,10 +553,7 @@ void iwl_trans_pcie_free(struct iwl_trans *trans);
 void iwl_trans_pcie_free_pnvm_dram_regions(struct iwl_dram_regions *dram_regions,
 					   struct device *dev);
 
-bool __iwl_trans_pcie_grab_nic_access(struct iwl_trans *trans, bool silent);
-#define _iwl_trans_pcie_grab_nic_access(trans, silent)		\
-	__cond_lock(nic_access_nobh,				\
-		    likely(__iwl_trans_pcie_grab_nic_access(trans, silent)))
+bool _iwl_trans_pcie_grab_nic_access(struct iwl_trans *trans, bool silent);
 
 void iwl_trans_pcie_check_product_reset_status(struct pci_dev *pdev);
 void iwl_trans_pcie_check_product_reset_mode(struct pci_dev *pdev);
diff --git a/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c b/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c
index 59307b5df441..a45358841243 100644
--- a/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c
+++ b/drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/trans.c
@@ -2327,7 +2327,7 @@ EXPORT_SYMBOL(iwl_trans_pcie_reset);
  * This version doesn't disable BHs but rather assumes they're
  * already disabled.
  */
-bool __iwl_trans_pcie_grab_nic_access(struct iwl_trans *trans, bool silent)
+bool _iwl_trans_pcie_grab_nic_access(struct iwl_trans *trans, bool silent)
 {
 	int ret;
 	struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
@@ -2415,7 +2415,7 @@ bool iwl_trans_pcie_grab_nic_access(struct iwl_trans *trans)
 	bool ret;
 
 	local_bh_disable();
-	ret = __iwl_trans_pcie_grab_nic_access(trans, false);
+	ret = _iwl_trans_pcie_grab_nic_access(trans, false);
 	if (ret) {
 		/* keep BHs disabled until iwl_trans_pcie_release_nic_access */
 		return ret;
diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index 6990cab7a4a9..03056f87a86f 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -329,24 +329,6 @@ static inline void _context_unsafe_alias(void **p) { }
  */
 #define __release(x)		__release_ctx_guard(x)
 
-/**
- * __cond_lock() - function that conditionally acquires a context guard
- *                 exclusively
- * @x: context guard instance pinter
- * @c: boolean expression
- *
- * Return: result of @c
- *
- * No-op function that conditionally acquires context guard instance @x
- * exclusively, if the boolean expression @c is true. The result of @c is the
- * return value; for example:
- *
- * .. code-block:: c
- *
- *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
- */
-#define __cond_lock(x, c)	__try_acquire_ctx_guard(x, c)
-
 /**
  * __must_hold_shared() - function attribute, caller must hold shared context guard
  *
@@ -405,19 +387,6 @@ static inline void _context_unsafe_alias(void **p) { }
  */
 #define __release_shared(x)	__release_shared_ctx_guard(x)
 
-/**
- * __cond_lock_shared() - function that conditionally acquires a context guard shared
- * @x: context guard instance pinter
- * @c: boolean expression
- *
- * Return: result of @c
- *
- * No-op function that conditionally acquires context guard instance @x with
- * shared access, if the boolean expression @c is true. The result of @c is the
- * return value.
- */
-#define __cond_lock_shared(x, c) __try_acquire_shared_ctx_guard(x, c)
-
 /**
  * __acquire_ret() - helper to acquire context guard of return value
  * @call: call expression
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 7c79b3369b82..d0c89022a823 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2813,15 +2813,8 @@ static inline pud_t pud_mkspecial(pud_t pud)
 }
 #endif	/* CONFIG_ARCH_SUPPORTS_PUD_PFNMAP */
 
-extern pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
-			       spinlock_t **ptl);
-static inline pte_t *get_locked_pte(struct mm_struct *mm, unsigned long addr,
-				    spinlock_t **ptl)
-{
-	pte_t *ptep;
-	__cond_lock(*ptl, ptep = __get_locked_pte(mm, addr, ptl));
-	return ptep;
-}
+extern pte_t *get_locked_pte(struct mm_struct *mm, unsigned long addr,
+			     spinlock_t **ptl);
 
 #ifdef __PAGETABLE_P4D_FOLDED
 static inline int __p4d_alloc(struct mm_struct *mm, pgd_t *pgd,
@@ -3116,31 +3109,15 @@ static inline bool pagetable_pte_ctor(struct mm_struct *mm,
 	return true;
 }
 
-pte_t *___pte_offset_map(pmd_t *pmd, unsigned long addr, pmd_t *pmdvalp);
-static inline pte_t *__pte_offset_map(pmd_t *pmd, unsigned long addr,
-			pmd_t *pmdvalp)
-{
-	pte_t *pte;
+pte_t *__pte_offset_map(pmd_t *pmd, unsigned long addr, pmd_t *pmdvalp);
 
-	__cond_lock(RCU, pte = ___pte_offset_map(pmd, addr, pmdvalp));
-	return pte;
-}
 static inline pte_t *pte_offset_map(pmd_t *pmd, unsigned long addr)
 {
 	return __pte_offset_map(pmd, addr, NULL);
 }
 
-pte_t *__pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
-			unsigned long addr, spinlock_t **ptlp);
-static inline pte_t *pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
-			unsigned long addr, spinlock_t **ptlp)
-{
-	pte_t *pte;
-
-	__cond_lock(RCU, __cond_lock(*ptlp,
-			pte = __pte_offset_map_lock(mm, pmd, addr, ptlp)));
-	return pte;
-}
+pte_t *pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
+			   unsigned long addr, spinlock_t **ptlp);
 
 pte_t *pte_offset_map_ro_nolock(struct mm_struct *mm, pmd_t *pmd,
 				unsigned long addr, spinlock_t **ptlp);
diff --git a/include/linux/rwlock.h b/include/linux/rwlock.h
index a2f85a0356c4..53ba394e9c51 100644
--- a/include/linux/rwlock.h
+++ b/include/linux/rwlock.h
@@ -50,8 +50,8 @@ do {								\
  * regardless of whether CONFIG_SMP or CONFIG_PREEMPT are set. The various
  * methods are defined as nops in the case they are not required.
  */
-#define read_trylock(lock)	__cond_lock_shared(lock, _raw_read_trylock(lock))
-#define write_trylock(lock)	__cond_lock(lock, _raw_write_trylock(lock))
+#define read_trylock(lock)	_raw_read_trylock(lock)
+#define write_trylock(lock)	_raw_write_trylock(lock)
 
 #define write_lock(lock)	_raw_write_lock(lock)
 #define read_lock(lock)		_raw_read_lock(lock)
@@ -113,12 +113,7 @@ do {								\
 	} while (0)
 #define write_unlock_bh(lock)		_raw_write_unlock_bh(lock)
 
-#define write_trylock_irqsave(lock, flags)		\
-	__cond_lock(lock, ({				\
-		local_irq_save(flags);			\
-		_raw_write_trylock(lock) ?		\
-		1 : ({ local_irq_restore(flags); 0; });	\
-	}))
+#define write_trylock_irqsave(lock, flags) _raw_write_trylock_irqsave(lock, &(flags))
 
 #ifdef arch_rwlock_is_contended
 #define rwlock_is_contended(lock) \
diff --git a/include/linux/rwlock_api_smp.h b/include/linux/rwlock_api_smp.h
index 6d5cc0b7be1f..d903b17c46ca 100644
--- a/include/linux/rwlock_api_smp.h
+++ b/include/linux/rwlock_api_smp.h
@@ -26,8 +26,8 @@ unsigned long __lockfunc _raw_read_lock_irqsave(rwlock_t *lock)
 							__acquires(lock);
 unsigned long __lockfunc _raw_write_lock_irqsave(rwlock_t *lock)
 							__acquires(lock);
-int __lockfunc _raw_read_trylock(rwlock_t *lock);
-int __lockfunc _raw_write_trylock(rwlock_t *lock);
+int __lockfunc _raw_read_trylock(rwlock_t *lock)	__cond_acquires_shared(true, lock);
+int __lockfunc _raw_write_trylock(rwlock_t *lock)	__cond_acquires(true, lock);
 void __lockfunc _raw_read_unlock(rwlock_t *lock)	__releases_shared(lock);
 void __lockfunc _raw_write_unlock(rwlock_t *lock)	__releases(lock);
 void __lockfunc _raw_read_unlock_bh(rwlock_t *lock)	__releases_shared(lock);
@@ -41,6 +41,16 @@ void __lockfunc
 _raw_write_unlock_irqrestore(rwlock_t *lock, unsigned long flags)
 							__releases(lock);
 
+static inline bool _raw_write_trylock_irqsave(rwlock_t *lock, unsigned long *flags)
+	__cond_acquires(true, lock)
+{
+	local_irq_save(*flags);
+	if (_raw_write_trylock(lock))
+		return true;
+	local_irq_restore(*flags);
+	return false;
+}
+
 #ifdef CONFIG_INLINE_READ_LOCK
 #define _raw_read_lock(lock) __raw_read_lock(lock)
 #endif
diff --git a/include/linux/rwlock_rt.h b/include/linux/rwlock_rt.h
index 2723abbe0e7a..f5fd96e0800e 100644
--- a/include/linux/rwlock_rt.h
+++ b/include/linux/rwlock_rt.h
@@ -26,11 +26,11 @@ do {							\
 } while (0)
 
 extern void rt_read_lock(rwlock_t *rwlock)	__acquires_shared(rwlock);
-extern int rt_read_trylock(rwlock_t *rwlock);
+extern int rt_read_trylock(rwlock_t *rwlock)	__cond_acquires_shared(true, rwlock);
 extern void rt_read_unlock(rwlock_t *rwlock)	__releases_shared(rwlock);
 extern void rt_write_lock(rwlock_t *rwlock)	__acquires(rwlock);
 extern void rt_write_lock_nested(rwlock_t *rwlock, int subclass)	__acquires(rwlock);
-extern int rt_write_trylock(rwlock_t *rwlock);
+extern int rt_write_trylock(rwlock_t *rwlock)	__cond_acquires(true, rwlock);
 extern void rt_write_unlock(rwlock_t *rwlock)	__releases(rwlock);
 
 static __always_inline void read_lock(rwlock_t *rwlock)
@@ -59,7 +59,7 @@ static __always_inline void read_lock_irq(rwlock_t *rwlock)
 		flags = 0;				\
 	} while (0)
 
-#define read_trylock(lock)	__cond_lock_shared(lock, rt_read_trylock(lock))
+#define read_trylock(lock)	rt_read_trylock(lock)
 
 static __always_inline void read_unlock(rwlock_t *rwlock)
 	__releases_shared(rwlock)
@@ -123,14 +123,15 @@ static __always_inline void write_lock_irq(rwlock_t *rwlock)
 		flags = 0;				\
 	} while (0)
 
-#define write_trylock(lock)	__cond_lock(lock, rt_write_trylock(lock))
+#define write_trylock(lock)	rt_write_trylock(lock)
 
-#define write_trylock_irqsave(lock, flags)		\
-	__cond_lock(lock, ({				\
-		typecheck(unsigned long, flags);	\
-		flags = 0;				\
-		rt_write_trylock(lock);			\
-	}))
+static __always_inline bool _write_trylock_irqsave(rwlock_t *rwlock, unsigned long *flags)
+	__cond_acquires(true, rwlock)
+{
+	*flags = 0;
+	return rt_write_trylock(rwlock);
+}
+#define write_trylock_irqsave(lock, flags) _write_trylock_irqsave(lock, &(flags))
 
 static __always_inline void write_unlock(rwlock_t *rwlock)
 	__releases(rwlock)
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 7d6449982822..a63f65aa5bdd 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -737,18 +737,8 @@ static inline int thread_group_empty(struct task_struct *p)
 #define delay_group_leader(p) \
 		(thread_group_leader(p) && !thread_group_empty(p))
 
-extern struct sighand_struct *__lock_task_sighand(struct task_struct *task,
-							unsigned long *flags);
-
-static inline struct sighand_struct *lock_task_sighand(struct task_struct *task,
-						       unsigned long *flags)
-{
-	struct sighand_struct *ret;
-
-	ret = __lock_task_sighand(task, flags);
-	(void)__cond_lock(&task->sighand->siglock, ret);
-	return ret;
-}
+extern struct sighand_struct *lock_task_sighand(struct task_struct *task,
+						unsigned long *flags);
 
 static inline void unlock_task_sighand(struct task_struct *task,
 						unsigned long *flags)
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 274d866a0be3..77b215c4124d 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -213,7 +213,7 @@ static inline void do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock)
  * various methods are defined as nops in the case they are not
  * required.
  */
-#define raw_spin_trylock(lock)	__cond_lock(lock, _raw_spin_trylock(lock))
+#define raw_spin_trylock(lock)	_raw_spin_trylock(lock)
 
 #define raw_spin_lock(lock)	_raw_spin_lock(lock)
 
@@ -284,22 +284,11 @@ static inline void do_raw_spin_unlock(raw_spinlock_t *lock) __releases(lock)
 	} while (0)
 #define raw_spin_unlock_bh(lock)	_raw_spin_unlock_bh(lock)
 
-#define raw_spin_trylock_bh(lock) \
-	__cond_lock(lock, _raw_spin_trylock_bh(lock))
+#define raw_spin_trylock_bh(lock)	_raw_spin_trylock_bh(lock)
 
-#define raw_spin_trylock_irq(lock)			\
-	__cond_lock(lock, ({				\
-		local_irq_disable();			\
-		_raw_spin_trylock(lock) ?		\
-		1 : ({ local_irq_enable(); 0;  });	\
-	}))
+#define raw_spin_trylock_irq(lock)	_raw_spin_trylock_irq(lock)
 
-#define raw_spin_trylock_irqsave(lock, flags)		\
-	__cond_lock(lock, ({				\
-		local_irq_save(flags);			\
-		_raw_spin_trylock(lock) ?		\
-		1 : ({ local_irq_restore(flags); 0; }); \
-	}))
+#define raw_spin_trylock_irqsave(lock, flags) _raw_spin_trylock_irqsave(lock, &(flags))
 
 #ifndef CONFIG_PREEMPT_RT
 /* Include rwlock functions for !RT */
@@ -433,8 +422,12 @@ static __always_inline int spin_trylock_irq(spinlock_t *lock)
 	return raw_spin_trylock_irq(&lock->rlock);
 }
 
-#define spin_trylock_irqsave(lock, flags)			\
-	__cond_lock(lock, raw_spin_trylock_irqsave(spinlock_check(lock), flags))
+static __always_inline bool _spin_trylock_irqsave(spinlock_t *lock, unsigned long *flags)
+	__cond_acquires(true, lock) __no_context_analysis
+{
+	return raw_spin_trylock_irqsave(spinlock_check(lock), *flags);
+}
+#define spin_trylock_irqsave(lock, flags) _spin_trylock_irqsave(lock, &(flags))
 
 /**
  * spin_is_locked() - Check whether a spinlock is locked.
@@ -512,23 +505,17 @@ static inline int rwlock_needbreak(rwlock_t *lock)
  * Decrements @atomic by 1.  If the result is 0, returns true and locks
  * @lock.  Returns false for all other cases.
  */
-extern int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock);
-#define atomic_dec_and_lock(atomic, lock) \
-		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
+extern int atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock) __cond_acquires(true, lock);
 
 extern int _atomic_dec_and_lock_irqsave(atomic_t *atomic, spinlock_t *lock,
-					unsigned long *flags);
-#define atomic_dec_and_lock_irqsave(atomic, lock, flags) \
-		__cond_lock(lock, _atomic_dec_and_lock_irqsave(atomic, lock, &(flags)))
+					unsigned long *flags) __cond_acquires(true, lock);
+#define atomic_dec_and_lock_irqsave(atomic, lock, flags) _atomic_dec_and_lock_irqsave(atomic, lock, &(flags))
 
-extern int _atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock);
-#define atomic_dec_and_raw_lock(atomic, lock) \
-		__cond_lock(lock, _atomic_dec_and_raw_lock(atomic, lock))
+extern int atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock) __cond_acquires(true, lock);
 
 extern int _atomic_dec_and_raw_lock_irqsave(atomic_t *atomic, raw_spinlock_t *lock,
-					unsigned long *flags);
-#define atomic_dec_and_raw_lock_irqsave(atomic, lock, flags) \
-		__cond_lock(lock, _atomic_dec_and_raw_lock_irqsave(atomic, lock, &(flags)))
+					    unsigned long *flags) __cond_acquires(true, lock);
+#define atomic_dec_and_raw_lock_irqsave(atomic, lock, flags) _atomic_dec_and_raw_lock_irqsave(atomic, lock, &(flags))
 
 int __alloc_bucket_spinlocks(spinlock_t **locks, unsigned int *lock_mask,
 			     size_t max_size, unsigned int cpu_mult,
diff --git a/include/linux/spinlock_api_smp.h b/include/linux/spinlock_api_smp.h
index 7e7d7d373213..bda5e7a390cd 100644
--- a/include/linux/spinlock_api_smp.h
+++ b/include/linux/spinlock_api_smp.h
@@ -95,6 +95,26 @@ static inline int __raw_spin_trylock(raw_spinlock_t *lock)
 	return 0;
 }
 
+static __always_inline bool _raw_spin_trylock_irq(raw_spinlock_t *lock)
+	__cond_acquires(true, lock)
+{
+	local_irq_disable();
+	if (_raw_spin_trylock(lock))
+		return true;
+	local_irq_enable();
+	return false;
+}
+
+static __always_inline bool _raw_spin_trylock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
+	__cond_acquires(true, lock)
+{
+	local_irq_save(*flags);
+	if (_raw_spin_trylock(lock))
+		return true;
+	local_irq_restore(*flags);
+	return false;
+}
+
 /*
  * If lockdep is enabled then we use the non-preemption spin-ops
  * even on CONFIG_PREEMPTION, because lockdep assumes that interrupts are
diff --git a/include/linux/spinlock_api_up.h b/include/linux/spinlock_api_up.h
index 018f5aabc1be..a9d5c7c66e03 100644
--- a/include/linux/spinlock_api_up.h
+++ b/include/linux/spinlock_api_up.h
@@ -24,14 +24,11 @@
  * flags straight, to suppress compiler warnings of unused lock
  * variables, and to add the proper checker annotations:
  */
-#define ___LOCK_void(lock) \
-  do { (void)(lock); } while (0)
-
 #define ___LOCK_(lock) \
-  do { __acquire(lock); ___LOCK_void(lock); } while (0)
+  do { __acquire(lock); (void)(lock); } while (0)
 
 #define ___LOCK_shared(lock) \
-  do { __acquire_shared(lock); ___LOCK_void(lock); } while (0)
+  do { __acquire_shared(lock); (void)(lock); } while (0)
 
 #define __LOCK(lock, ...) \
   do { preempt_disable(); ___LOCK_##__VA_ARGS__(lock); } while (0)
@@ -78,10 +75,56 @@
 #define _raw_spin_lock_irqsave(lock, flags)	__LOCK_IRQSAVE(lock, flags)
 #define _raw_read_lock_irqsave(lock, flags)	__LOCK_IRQSAVE(lock, flags, shared)
 #define _raw_write_lock_irqsave(lock, flags)	__LOCK_IRQSAVE(lock, flags)
-#define _raw_spin_trylock(lock)			({ __LOCK(lock, void); 1; })
-#define _raw_read_trylock(lock)			({ __LOCK(lock, void); 1; })
-#define _raw_write_trylock(lock)			({ __LOCK(lock, void); 1; })
-#define _raw_spin_trylock_bh(lock)		({ __LOCK_BH(lock, void); 1; })
+
+static __always_inline int _raw_spin_trylock(raw_spinlock_t *lock)
+	__cond_acquires(true, lock)
+{
+	__LOCK(lock);
+	return 1;
+}
+
+static __always_inline int _raw_spin_trylock_bh(raw_spinlock_t *lock)
+	__cond_acquires(true, lock)
+{
+	__LOCK_BH(lock);
+	return 1;
+}
+
+static __always_inline int _raw_spin_trylock_irq(raw_spinlock_t *lock)
+	__cond_acquires(true, lock)
+{
+	__LOCK_IRQ(lock);
+	return 1;
+}
+
+static __always_inline int _raw_spin_trylock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
+	__cond_acquires(true, lock)
+{
+	__LOCK_IRQSAVE(lock, *(flags));
+	return 1;
+}
+
+static __always_inline int _raw_read_trylock(rwlock_t *lock)
+	__cond_acquires_shared(true, lock)
+{
+	__LOCK(lock, shared);
+	return 1;
+}
+
+static __always_inline int _raw_write_trylock(rwlock_t *lock)
+	__cond_acquires(true, lock)
+{
+	__LOCK(lock);
+	return 1;
+}
+
+static __always_inline int _raw_write_trylock_irqsave(rwlock_t *lock, unsigned long *flags)
+	__cond_acquires(true, lock)
+{
+	__LOCK_IRQSAVE(lock, *(flags));
+	return 1;
+}
+
 #define _raw_spin_unlock(lock)			__UNLOCK(lock)
 #define _raw_read_unlock(lock)			__UNLOCK(lock, shared)
 #define _raw_write_unlock(lock)			__UNLOCK(lock)
diff --git a/include/linux/spinlock_rt.h b/include/linux/spinlock_rt.h
index 817a1e331cd1..348db067c318 100644
--- a/include/linux/spinlock_rt.h
+++ b/include/linux/spinlock_rt.h
@@ -37,8 +37,8 @@ extern void rt_spin_lock_nested(spinlock_t *lock, int subclass)	__acquires(lock)
 extern void rt_spin_lock_nest_lock(spinlock_t *lock, struct lockdep_map *nest_lock) __acquires(lock);
 extern void rt_spin_unlock(spinlock_t *lock)	__releases(lock);
 extern void rt_spin_lock_unlock(spinlock_t *lock);
-extern int rt_spin_trylock_bh(spinlock_t *lock);
-extern int rt_spin_trylock(spinlock_t *lock);
+extern int rt_spin_trylock_bh(spinlock_t *lock) __cond_acquires(true, lock);
+extern int rt_spin_trylock(spinlock_t *lock) __cond_acquires(true, lock);
 
 static __always_inline void spin_lock(spinlock_t *lock)
 	__acquires(lock)
@@ -130,21 +130,19 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock,
 	rt_spin_unlock(lock);
 }
 
-#define spin_trylock(lock)				\
-	__cond_lock(lock, rt_spin_trylock(lock))
+#define spin_trylock(lock)	rt_spin_trylock(lock)
 
-#define spin_trylock_bh(lock)				\
-	__cond_lock(lock, rt_spin_trylock_bh(lock))
+#define spin_trylock_bh(lock)	rt_spin_trylock_bh(lock)
 
-#define spin_trylock_irq(lock)				\
-	__cond_lock(lock, rt_spin_trylock(lock))
+#define spin_trylock_irq(lock)	rt_spin_trylock(lock)
 
-#define spin_trylock_irqsave(lock, flags)		\
-	__cond_lock(lock, ({				\
-		typecheck(unsigned long, flags);	\
-		flags = 0;				\
-		rt_spin_trylock(lock);			\
-	}))
+static __always_inline bool _spin_trylock_irqsave(spinlock_t *lock, unsigned long *flags)
+	__cond_acquires(true, lock)
+{
+	*flags = 0;
+	return rt_spin_trylock(lock);
+}
+#define spin_trylock_irqsave(lock, flags) _spin_trylock_irqsave(lock, &(flags))
 
 #define spin_is_contended(lock)		(((void)(lock), 0))
 
diff --git a/kernel/signal.c b/kernel/signal.c
index fe9190d84f28..9ff96a341e42 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1355,8 +1355,8 @@ int zap_other_threads(struct task_struct *p)
 	return count;
 }
 
-struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
-					   unsigned long *flags)
+struct sighand_struct *lock_task_sighand(struct task_struct *tsk,
+					 unsigned long *flags)
 {
 	struct sighand_struct *sighand;
 
diff --git a/kernel/time/posix-timers.c b/kernel/time/posix-timers.c
index 56e17b625c72..afb63b2cdc98 100644
--- a/kernel/time/posix-timers.c
+++ b/kernel/time/posix-timers.c
@@ -66,14 +66,7 @@ static const struct k_clock clock_realtime, clock_monotonic;
 #error "SIGEV_THREAD_ID must not share bit with other SIGEV values!"
 #endif
 
-static struct k_itimer *__lock_timer(timer_t timer_id);
-
-#define lock_timer(tid)							\
-({	struct k_itimer *__timr;					\
-	__cond_lock(&__timr->it_lock, __timr = __lock_timer(tid));	\
-	__timr;								\
-})
-
+static struct k_itimer *lock_timer(timer_t timer_id);
 static inline void unlock_timer(struct k_itimer *timr)
 {
 	if (likely((timr)))
@@ -85,7 +78,7 @@ static inline void unlock_timer(struct k_itimer *timr)
 
 #define scoped_timer				(scope)
 
-DEFINE_CLASS(lock_timer, struct k_itimer *, unlock_timer(_T), __lock_timer(id), timer_t id);
+DEFINE_CLASS(lock_timer, struct k_itimer *, unlock_timer(_T), lock_timer(id), timer_t id);
 DEFINE_CLASS_IS_COND_GUARD(lock_timer);
 
 static struct timer_hash_bucket *hash_bucket(struct signal_struct *sig, unsigned int nr)
@@ -600,7 +593,7 @@ COMPAT_SYSCALL_DEFINE3(timer_create, clockid_t, which_clock,
 }
 #endif
 
-static struct k_itimer *__lock_timer(timer_t timer_id)
+static struct k_itimer *lock_timer(timer_t timer_id)
 {
 	struct k_itimer *timr;
 
diff --git a/lib/dec_and_lock.c b/lib/dec_and_lock.c
index 1dcca8f2e194..8c7c398fd770 100644
--- a/lib/dec_and_lock.c
+++ b/lib/dec_and_lock.c
@@ -18,7 +18,7 @@
  * because the spin-lock and the decrement must be
  * "atomic".
  */
-int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock)
+int atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock)
 {
 	/* Subtract 1 from counter unless that drops it to 0 (ie. it was 1) */
 	if (atomic_add_unless(atomic, -1, 1))
@@ -32,7 +32,7 @@ int _atomic_dec_and_lock(atomic_t *atomic, spinlock_t *lock)
 	return 0;
 }
 
-EXPORT_SYMBOL(_atomic_dec_and_lock);
+EXPORT_SYMBOL(atomic_dec_and_lock);
 
 int _atomic_dec_and_lock_irqsave(atomic_t *atomic, spinlock_t *lock,
 				 unsigned long *flags)
@@ -50,7 +50,7 @@ int _atomic_dec_and_lock_irqsave(atomic_t *atomic, spinlock_t *lock,
 }
 EXPORT_SYMBOL(_atomic_dec_and_lock_irqsave);
 
-int _atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock)
+int atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock)
 {
 	/* Subtract 1 from counter unless that drops it to 0 (ie. it was 1) */
 	if (atomic_add_unless(atomic, -1, 1))
@@ -63,7 +63,7 @@ int _atomic_dec_and_raw_lock(atomic_t *atomic, raw_spinlock_t *lock)
 	raw_spin_unlock(lock);
 	return 0;
 }
-EXPORT_SYMBOL(_atomic_dec_and_raw_lock);
+EXPORT_SYMBOL(atomic_dec_and_raw_lock);
 
 int _atomic_dec_and_raw_lock_irqsave(atomic_t *atomic, raw_spinlock_t *lock,
 				     unsigned long *flags)
diff --git a/mm/memory.c b/mm/memory.c
index b59ae7ce42eb..1741953142e6 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2215,8 +2215,8 @@ static pmd_t *walk_to_pmd(struct mm_struct *mm, unsigned long addr)
 	return pmd;
 }
 
-pte_t *__get_locked_pte(struct mm_struct *mm, unsigned long addr,
-			spinlock_t **ptl)
+pte_t *get_locked_pte(struct mm_struct *mm, unsigned long addr,
+		      spinlock_t **ptl)
 {
 	pmd_t *pmd = walk_to_pmd(mm, addr);
 
diff --git a/mm/pgtable-generic.c b/mm/pgtable-generic.c
index 567e2d084071..808f18d68279 100644
--- a/mm/pgtable-generic.c
+++ b/mm/pgtable-generic.c
@@ -278,7 +278,7 @@ static unsigned long pmdp_get_lockless_start(void) { return 0; }
 static void pmdp_get_lockless_end(unsigned long irqflags) { }
 #endif
 
-pte_t *___pte_offset_map(pmd_t *pmd, unsigned long addr, pmd_t *pmdvalp)
+pte_t *__pte_offset_map(pmd_t *pmd, unsigned long addr, pmd_t *pmdvalp)
 {
 	unsigned long irqflags;
 	pmd_t pmdval;
@@ -330,13 +330,12 @@ pte_t *pte_offset_map_rw_nolock(struct mm_struct *mm, pmd_t *pmd,
 }
 
 /*
- * pte_offset_map_lock(mm, pmd, addr, ptlp), and its internal implementation
- * __pte_offset_map_lock() below, is usually called with the pmd pointer for
- * addr, reached by walking down the mm's pgd, p4d, pud for addr: either while
- * holding mmap_lock or vma lock for read or for write; or in truncate or rmap
- * context, while holding file's i_mmap_lock or anon_vma lock for read (or for
- * write). In a few cases, it may be used with pmd pointing to a pmd_t already
- * copied to or constructed on the stack.
+ * pte_offset_map_lock(mm, pmd, addr, ptlp) is usually called with the pmd
+ * pointer for addr, reached by walking down the mm's pgd, p4d, pud for addr:
+ * either while holding mmap_lock or vma lock for read or for write; or in
+ * truncate or rmap context, while holding file's i_mmap_lock or anon_vma lock
+ * for read (or for write). In a few cases, it may be used with pmd pointing to
+ * a pmd_t already copied to or constructed on the stack.
  *
  * When successful, it returns the pte pointer for addr, with its page table
  * kmapped if necessary (when CONFIG_HIGHPTE), and locked against concurrent
@@ -387,8 +386,8 @@ pte_t *pte_offset_map_rw_nolock(struct mm_struct *mm, pmd_t *pmd,
  * table, and may not use RCU at all: "outsiders" like khugepaged should avoid
  * pte_offset_map() and co once the vma is detached from mm or mm_users is zero.
  */
-pte_t *__pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
-			     unsigned long addr, spinlock_t **ptlp)
+pte_t *pte_offset_map_lock(struct mm_struct *mm, pmd_t *pmd,
+			   unsigned long addr, spinlock_t **ptlp)
 {
 	spinlock_t *ptl;
 	pmd_t pmdval;
diff --git a/tools/include/linux/compiler_types.h b/tools/include/linux/compiler_types.h
index d09f9dc172a4..067a5b4e0f7b 100644
--- a/tools/include/linux/compiler_types.h
+++ b/tools/include/linux/compiler_types.h
@@ -20,7 +20,6 @@
 # define __releases(x)	__attribute__((context(x,1,0)))
 # define __acquire(x)	__context__(x,1)
 # define __release(x)	__context__(x,-1)
-# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
 #else /* __CHECKER__ */
 /* context/locking */
 # define __must_hold(x)
@@ -28,7 +27,6 @@
 # define __releases(x)
 # define __acquire(x)	(void)0
 # define __release(x)	(void)0
-# define __cond_lock(x,c) (c)
 #endif /* __CHECKER__ */
 
 /* Compiler specific macros. */
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-24-elver%40google.com.
