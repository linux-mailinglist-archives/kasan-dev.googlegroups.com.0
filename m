Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEPOUHWQKGQEG44L7QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF07BDAF57
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:37 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id m16sf530055lfb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321617; cv=pass;
        d=google.com; s=arc-20160816;
        b=JXX166ekPbh+S5Li/as50JyDscFrlOlpc5+NTcsvPV+MCyk142xKo4elBrRFMbrApo
         tDwYq0GC+GL1VlNe2kA8nnvJY0m8DCgR4aB0D7bMkTC4H6Chk2+x5IxbBFWcUFVH9tfb
         DZAt8ufX1r4OYgz/Y8oMFX82CNsQIkUfVJi0itP553peg5KBxQzpajWOWwxx6L6481uv
         +Ln0skuce3gaA2N+qxirJL5T+BWwVkNc8ky1omHnmLGu+VLfDdQMadnQ5whccqgYXcQl
         SInZe7R/Zrvg4fD5zqTmWghO+j3E/JV9HEKBpL64XAD3lZHL0Mz/8iwKwkMiZ3WWL8gH
         NObw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3h7KVLtBztiD8/laoY3jzBZ9bWM00ynvqelnCMOUcg8=;
        b=Bz4ZHwzgY3RBRXLXRIxH1wU4br8l7vGb4GA/gvgCIOYhE8S72NSgUOn2L7c/BLEq9A
         pcgflKvPmrkA+HYoTIouavqWYX+06JUqVWeRVBC5JKVrqj2gKUDQuMKjwk3nyIwptyQa
         1uddh98s4Z64pLvL3e6SFF1yiVX08UX8IKmy3spxB0/bAN2SB/dbz+ATtnFhAIh/oWX6
         YnBNu0ATi10Fsz6PBHqFmTMNHG5Tjh+aJ37Ex1lQgW7DyZVMoCXIQ1o1xfGc66mLIAtK
         j/RRVg1rpArdGr/0iXMbPscY9JbDppTzlCCdjlb9t0l0Id7Jx/rnnAbA0PM6wM1eKEI0
         VAew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=voVDOFtD;
       spf=pass (google.com: domain of 3d3eoxqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3D3eoXQUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3h7KVLtBztiD8/laoY3jzBZ9bWM00ynvqelnCMOUcg8=;
        b=qvwJF1l8q/mExx5IBqMYBqxM9pL/RPwhl3gpErvwSgpPaj9Bo5fc+kJBp4Y1AWtw/7
         qqR7udccZNw8bEfiGcbAAhbog2NX+OeaWwZ3Eg0ciS0smFfQdB0hki42/xra06SpUvUd
         g1QzYh7dxoUCZThmstXsDI/rmfXtZLMtJ/Gp1kgiPTwL+v/y1ZX1paOch05DhxSwzzbM
         cRgs/RSfm7n7jbwLhcRxitLOvu8CCepH2xe0x5HwYPPUTay5iFv7tbIvzjeDVkyQTeLX
         nURcgrsYn3TkRaLMitaHF8aJxuTXA7s+z30oQWllWM6+mM39ZOipz5aPvAJAT0EwbMLF
         e6ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3h7KVLtBztiD8/laoY3jzBZ9bWM00ynvqelnCMOUcg8=;
        b=q+sfdXUneqI9vjNlro9vDiz2FMd351ftqhQxO5F97+hWXulbxYcdF84yHEepBcbHPs
         vtDIUnOS0rwTIN9uDM6bzgGWKk8XwhnGbGtaTk+HB1UP7EXj/XWitvuMXxMGFWo+nIic
         FIjja5JeXT/wz3rNpf1T88dzk6vxs0bvspnL1OiD5mP6G7ynEh54CefJcH9a91itYatp
         wNe08YwP2hFXZfes3+I7DbECiJ7a5Ie9p6SdnzZ/84qxPuROTtfi8WGKuU2jU4GZPa6q
         P8KkeAXoDPPY2HmvPkl5s4x8w0AXBs4oXTDzsb8DaBV4GqZUlOCyOk5zUqehcSFYI3pr
         ICaw==
X-Gm-Message-State: APjAAAV82tkj6UUiJbb18vWpnwGI/NA+dIdGt/CiYVzwy7eqBOkqp176
	m4p4SkpyUVy6uhx+dAJ3Tx8=
X-Google-Smtp-Source: APXvYqwRIQd9lqf9ws9VztQAT9RQC9XsEBxMqoVye1tOQxmrxJStGCAOvvlz6Sg1NzXqtbrp4jRPEQ==
X-Received: by 2002:ac2:43a8:: with SMTP id t8mr2559241lfl.134.1571321617318;
        Thu, 17 Oct 2019 07:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4190:: with SMTP id z16ls236874lfh.7.gmail; Thu, 17 Oct
 2019 07:13:36 -0700 (PDT)
X-Received: by 2002:ac2:46e3:: with SMTP id q3mr2524133lfo.147.1571321616683;
        Thu, 17 Oct 2019 07:13:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321616; cv=none;
        d=google.com; s=arc-20160816;
        b=l1poym0hfZuXUc/YVg9f3gPgZA+HjG6NZNyIN1OIa701KZGdc8qRKi/CI8vM/u+Evm
         PB8T4f43irzCt8Ta48LND5PcSuh2oN8TKnwDbR6rPkeIjqO1qKgO81RYqvjNByIrZWXA
         8nBwCCkMEPaFjTOcK3jX7Mf4d6v5zLMKjJ2Ra3PayCt8hoVZS9HemQoeQ9EQjASKo5YY
         q6xpns3fsj+0dN5AM9Aqgk4d99a1z1LmlhaKPSGhSnvfF2fv4bHjxJ+eve3VInNIFBHO
         5QDhbo9o0kxH8j85wi+lFtXHOy6gWhDuLWuSo8V/8lNkMMlpUXggkz4QR8Vf19uDG5+a
         0BIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Or9Dc22i/7f/YW0tvEwykVYSyBSv8lYxv1cGbeL+tYY=;
        b=PH7dLjcY+P7qfk7dFqbhh2GeUy8dED5OoivMXRHpmey7/20kCaLAxa0or24VFszFui
         9WZR1ue9H0+W70iR5Lzn7eS+Q4iYpbwNZ63GLQKYj2TQks41rEF3rl8SxA42jXy/rSXl
         Blbq2QLoUfj65GXzF/nJHdmMSAIvCL9XaSEbOuCh0URcTJ6hSEjVMo8yWcLgYkGV66S8
         EOAudle1pjP/QAkYL3K3SmdhmGSFeYLsCV+5hjjnwKCbVarAj/PG/QnoBYte7jvHRHBY
         3phhPQJ2L4feskf8KbIVPQiwiSXNYQGL0wjjMhbUOqmpjlCbA4FY3ki0f78K1bGdhWtt
         VrJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=voVDOFtD;
       spf=pass (google.com: domain of 3d3eoxqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3D3eoXQUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id z9si164335ljj.4.2019.10.17.07.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d3eoxqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m6so1123114wmf.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:36 -0700 (PDT)
X-Received: by 2002:adf:db4c:: with SMTP id f12mr2777929wrj.379.1571321615653;
 Thu, 17 Oct 2019 07:13:35 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:13:00 +0200
In-Reply-To: <20191017141305.146193-1-elver@google.com>
Message-Id: <20191017141305.146193-4-elver@google.com>
Mime-Version: 1.0
References: <20191017141305.146193-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 3/8] build, kcsan: Add KCSAN build exceptions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=voVDOFtD;       spf=pass
 (google.com: domain of 3d3eoxqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3D3eoXQUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

This blacklists several compilation units from KCSAN. See the respective
inline comments for the reasoning.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/Makefile       | 5 +++++
 kernel/sched/Makefile | 6 ++++++
 mm/Makefile           | 8 ++++++++
 3 files changed, 19 insertions(+)

diff --git a/kernel/Makefile b/kernel/Makefile
index 74ab46e2ebd1..4a597a68b8bc 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -23,6 +23,9 @@ endif
 # Prevents flicker of uninteresting __do_softirq()/__local_bh_disable_ip()
 # in coverage traces.
 KCOV_INSTRUMENT_softirq.o := n
+# Avoid KCSAN instrumentation in softirq ("No shared variables, all the data
+# are CPU local" => assume no data-races), to reduce overhead in interrupts.
+KCSAN_SANITIZE_softirq.o = n
 # These are called from save_stack_trace() on slub debug path,
 # and produce insane amounts of uninteresting coverage.
 KCOV_INSTRUMENT_module.o := n
@@ -30,6 +33,7 @@ KCOV_INSTRUMENT_extable.o := n
 # Don't self-instrument.
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
+KCSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 
 # cond_syscall is currently not LTO compatible
@@ -118,6 +122,7 @@ obj-$(CONFIG_RSEQ) += rseq.o
 
 obj-$(CONFIG_GCC_PLUGIN_STACKLEAK) += stackleak.o
 KASAN_SANITIZE_stackleak.o := n
+KCSAN_SANITIZE_stackleak.o := n
 KCOV_INSTRUMENT_stackleak.o := n
 
 $(obj)/configs.o: $(obj)/config_data.gz
diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index 21fb5a5662b5..e9307a9c54e7 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -7,6 +7,12 @@ endif
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
+# There are numerous races here, however, most of them due to plain accesses.
+# This would make it even harder for syzbot to find reproducers, because these
+# bugs trigger without specific input. Disable by default, but should re-enable
+# eventually.
+KCSAN_SANITIZE := n
+
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
 # needed for x86 only.  Why this used to be enabled for all architectures is beyond
diff --git a/mm/Makefile b/mm/Makefile
index d996846697ef..33ea0154dd2d 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -7,6 +7,14 @@ KASAN_SANITIZE_slab_common.o := n
 KASAN_SANITIZE_slab.o := n
 KASAN_SANITIZE_slub.o := n
 
+# These produce frequent data-race reports: most of them are due to races on
+# the same word but accesses to different bits of that word. Re-enable KCSAN
+# for these when we have more consensus on what to do about them.
+KCSAN_SANITIZE_slab_common.o := n
+KCSAN_SANITIZE_slab.o := n
+KCSAN_SANITIZE_slub.o := n
+KCSAN_SANITIZE_page_alloc.o := n
+
 # These files are disabled because they produce non-interesting and/or
 # flaky coverage that is not a function of syscall inputs. E.g. slab is out of
 # free pages, or a task is migrated between nodes.
-- 
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-4-elver%40google.com.
