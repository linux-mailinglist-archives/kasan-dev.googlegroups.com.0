Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL5PTPWQKGQEP6YVTSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BAA15D8B4B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:19 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id s16sf662950wme.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215279; cv=pass;
        d=google.com; s=arc-20160816;
        b=gLNTtbV74td5vuQGZmsL28iNEDYRyA27cbSPzAqpZ2RdYOvyV8va34KiQ+gqGgh8bX
         ZlGtlDKN4sK9qPqS16++JATycloeD5hNZyPduDiF7DFV15sTREM7KWxDWv6QfJotDnfD
         ZvGI21MGL+Is4NVnJPz2t9gj2Qer4qTYSQ60Z00Jq643acSfkOjdn9vz5+c3B+MpcqK1
         nZeJ1Jikl2lUBhEyaq5DnpNTlDqkf1F5gk8oeNx8+taCjzbl8QViFuNrRigNOXjdw3Q3
         2QMXzxfnJ5/Qg4RBdZTjJAWOTxTx9aBe6UnsQxRJKr9Sz540EaW6tY6wgfQNKoS4g203
         ZTJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Q+Hy6fxekuE7TQjTuBEEJDA3WElKrulKuLyY22shPTA=;
        b=VcafmS13/Q5BgTkGqKAK+i4p+AvIhHWecN9+/X+dam1Eyhp77puMjzTUwUHFi7AWQn
         hEr5IlEeESgY+C0XXfZGhbXsK6eNr12tPhDq9NZn8uwz0r/QIELVz7FT/7h1H14DwOfC
         I5zls6AInopZzg4W6+B7X+sUJCNYHceCCn8sQFMpjtolDnAXD+tjJPGpLvIV3VLVp/LE
         6f+6KzDtMWnGBZ3kdwjKBUQtd5zeggFLFnrXA6OwUseDYoKJr5LBpsPF7WLEjA4Z6nv9
         AU7vv2SbpDwAdc0LaxWoqm43K1Y+A/x/E8+oIAtELoM10mTmXWm6EgvSfqagBIUxkjHc
         Tc6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WKlCHYh2;
       spf=pass (google.com: domain of 3rdemxqukceoqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rdemXQUKCeoQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+Hy6fxekuE7TQjTuBEEJDA3WElKrulKuLyY22shPTA=;
        b=psYO8hmA7hh0Bkow9HGNSiuJ8UJteNHmJE0B+AVckG3tcbMiauWl+KQS7xsTB33KV2
         6rlnnW4aKXXfwzPhy41Dyp/8bFrVRISsR+324B4fEtzKgb8hhk1REiFG0h98WfBvK+xp
         rrWuWJ9fA4XZ6NP5IqUhLNF1q1jcy49ySm2VLg55dtXtrp//88QCLmJ4GfKOv7vQDeDX
         yNe1Mcvbah5PB/A4tMOjAUDbUxvmONKosm1PJbVKtmQzrOnP9j3moqslAkDduAct4Nhz
         uqGjEUWxMU+UK2KMZq5Q38vpVhTC9yKsvQ9ny7P5rYJfhx37sV6z7Vi4GdtG46sAJyLM
         yVdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+Hy6fxekuE7TQjTuBEEJDA3WElKrulKuLyY22shPTA=;
        b=bbD4AxpTajuaxpaHOs3sKnBgn28MKr/GTVob0kC2pT0eJ2UvTZP8owmNr+ijp8XpCH
         62pnFLQ2+Xf4Cs+fYC9eu+3Q3+WU2O3D8Bki4IvSYwnniMClXWyIEhVOJENOJ/lU3msk
         +pxzesK61+CvgfeZ9710vNu1iFm0EK8EL746CybKWpAQOZ5H1Otk7kxX4XsscoQdAiVu
         rT1Qx3UoKeZXaQntBMh5wNFpvPjC59GZjjmqNJahz1Hk6lvhJzc/6FSa5huCbfJZPrnf
         X59W5HAe+4roWY1eU+qC6V98kBZYx3WwKmrr9yB5iCOAtiZwWAIsoQMQyXEms0ufQedQ
         n3dg==
X-Gm-Message-State: APjAAAUSHgSGiKXZMsKc8CTqwErpWvQfqGIgxDzuIITb13+8usYbBnjk
	rS7PGrLvrOTejcFuE1XUIHM=
X-Google-Smtp-Source: APXvYqyDfG/cTopXRbMNiMg8ctdRam5XvmhrMGsfKJ9E/i7tgEVCvIsbOd3wV74bpfEDEERmmNz5Lw==
X-Received: by 2002:a1c:a516:: with SMTP id o22mr2544098wme.116.1571215279449;
        Wed, 16 Oct 2019 01:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dccc:: with SMTP id x12ls7925012wrm.3.gmail; Wed, 16 Oct
 2019 01:41:18 -0700 (PDT)
X-Received: by 2002:adf:d850:: with SMTP id k16mr1198271wrl.204.1571215278802;
        Wed, 16 Oct 2019 01:41:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215278; cv=none;
        d=google.com; s=arc-20160816;
        b=X9w4qyR5l7hAv33rMdmsW2mKlBRRA5ywBk2DtM+f6QMTxpYc7YUoI0B7wyihc8zrli
         RonZ4DjyMsCcxEb0vzX0NHnxNdo/SaBMgn9RsKafu8xKqjJH0qpGgn1kfuexqAi4vYHL
         Mh8hkVMlF7Q23QH0XLyVPuDI1vGwcrWy2PlT30VUSIKtASRqSIJEhLt491Q57azKVaCm
         ldwztl/PP+WqKkzgRMrXPYG2EU8o1yrg+Y4GAnlhvfHCQTwvbOo6gVcunSpd5YYoKb6H
         GcHrbP49lJsTGiZIF0d7Z0d7NnqCxxdT32susjD8wD/y56X88wzJhXSfwvYyVpnUh0Ny
         95wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yDFha54hv48kEXnfmjDw3jNhkPyH3I98qNMyU9YzKxs=;
        b=jsPw3sX6Craigg58Gpn1rliZLJS4GrWON76m/3Vvk90jnJ0pR7Bcl7YC4yta0eYiGe
         dytNxxtudvO+PhwTKpEcqMNggB65pLqoWYeT7ams9BS81/2/eijPZmfeeYijhPruHtfy
         0TNmEj1xjb+4RKmEndIfw/5bqLBZQyCkUyHpIHoqSmchJxtSalQ+aLy20EhsCwUfCuWV
         JGq42eyB0/la/2h51synVfcWGwk4zZSJB2oDgzAis7xMjayMgWSjnq90V772q+ZDmsJ7
         7DlbyS7eUL5TiAoC0BdAfW5r5GWSVK2s2H7tpkZoj05ET5TltlwC96ccrVCLGIJiVXR8
         o6UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WKlCHYh2;
       spf=pass (google.com: domain of 3rdemxqukceoqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rdemXQUKCeoQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e17si240941wre.3.2019.10.16.01.41.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rdemxqukceoqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id p8so7079775wrj.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:18 -0700 (PDT)
X-Received: by 2002:adf:fa87:: with SMTP id h7mr1713158wrr.304.1571215277931;
 Wed, 16 Oct 2019 01:41:17 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:54 +0200
In-Reply-To: <20191016083959.186860-1-elver@google.com>
Message-Id: <20191016083959.186860-4-elver@google.com>
Mime-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 3/8] build, kcsan: Add KCSAN build exceptions
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
 header.i=@google.com header.s=20161025 header.b=WKlCHYh2;       spf=pass
 (google.com: domain of 3rdemxqukceoqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rdemXQUKCeoQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-4-elver%40google.com.
