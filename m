Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMHLQDXAKGQEQ7U773I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E9CEEE254
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:29:06 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id t76sf4229092pgb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:29:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877744; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIpiAK/ygU/KR+qENEP+aPdgZYLCEzu96QosKznsEUMJedTMs3efuQIMonNKBwprg2
         MF8h0BXGzxREOUcmJVjfmqIiFSHp1PUd4d1/2IRrJ9C0VtuTSNBDYcDgy2/Bgfm6qxdc
         Qmva5LLhoLp+NQhGcWm84fBPwDiBu8VHMQN5TCRSx+g2KlmsY8jl/YAS4YA2LYfdUJ2I
         EjUTgrNyw4ON49CEWvtSnLGMLFyC1R7KTeO89wWPXA11k3nbHIJbO6uV76NvYrIxeP1x
         +qDVfkIEnAnK9GunOeWqiy1RwPu2kzFispuGyCHNyO/qCtW3FvfvTiwZRlhCCaWAKIxH
         Zccg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yerSZSLXVwhBKEoIImhIzMpCD7rbdXwyZ/BxQku4JLA=;
        b=sHru1xVYzOKNtO0ZfyTE1WHEdeqywEancUS3i14y05UoXgSy+gzlg/NnsRHGDAJZ98
         tYY5psVannTbo89P8WfLbmpeXzPDePKkG++SILPlE/VByU5f6OeWFCOTzyLXhlbN518b
         UO008OcSOk/2t/QvJ3y1fj2OFhcB0yOJiLN7nFyH1NMT8g1w4rD5fv6DQW7UYk8ypzwH
         TD//Qy/SxXOL+MkAUBsRtPwRL2M6iq1GOn7JIMESlhuMPVZdVWv3E87g6AFoBPSHAtyi
         Zf1Rpyyc6n6IXhBd6nWD+oQ97DhAnMMvD3nt5bO4oWQAvgkl1VhBSh53eQ53XpEKtJiy
         ZFWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LohiqOAc;
       spf=pass (google.com: domain of 3rjxaxqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3rjXAXQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yerSZSLXVwhBKEoIImhIzMpCD7rbdXwyZ/BxQku4JLA=;
        b=NthIlQQOHlDYsYW/zQk6X2oPVQgDxTiprJf220UdvrsOb43El9VueLxjHzW6PPOUfL
         pOh2N56iqd0vIj2gSbhK0p2lV0kZ/NsCugQIHZzF8KyVSOqKwZV65zrL7k2tEgZjQqJi
         dCF8Z0Pps0PjcFAtmZDWdUVwhUgUruho7MK/3V7gYhNdwtO0RIrTaGERFXAu2F8kVVgR
         AQ470slblfqi5SCxifh/xO86Ni8VQvEIJhENwuXkluKvtYWgtBqcuJXwdesk3NJVLrI7
         Z2tsoI2P2uCZpEDZvchF+ivyN6ZvN85Elb43+teX4jG+mlJWMJcm77+UNA2YPhfL7tkO
         BipQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yerSZSLXVwhBKEoIImhIzMpCD7rbdXwyZ/BxQku4JLA=;
        b=YXYUcLX2WgoRXUgsexcaN791HV/hrFasXVUhIih9e4hsHl5FmSRGc6P1YRmILd2L15
         tpXHbauZHmCZDegfNYB/Acw4VbzdQrpfNCIkj207dIGEti91k0TCNrBWjk4zDxPuuWj3
         F1X+XWI2ye9p5xm4OqnvfsG3mbUVfxpf43AQsF8cF2hWvQbeWupwfaSQOWUpybDMuc+0
         3V1fO+oOckBfQDJ3ssWD259V3Xch9Vc+UT91cnNNJP0AzVt8K/3Qs25zWwbD6zOs8sZX
         pRb1CB0dPnUmv+m/Swx+TGQym6KbV7UwUneGwOi9YLch0wRVf7MWgJD3qBqBn/rwaaqy
         E0zg==
X-Gm-Message-State: APjAAAXs/1imYzgJNf8QyLutM5CqdbS9anqbienT7DrPE+998yONmE/O
	tk6508KpEsXBhMvdzEb5d5o=
X-Google-Smtp-Source: APXvYqxgpTREQGlzSIXTB07rYKZeo49rwCMkZLa0MQeEeh7yg+PbVdyDqtJhLKo6O/HdMctP4hqoOw==
X-Received: by 2002:a17:90a:8806:: with SMTP id s6mr36035410pjn.109.1572877744429;
        Mon, 04 Nov 2019 06:29:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1d56:: with SMTP id d83ls253340pfd.13.gmail; Mon, 04 Nov
 2019 06:29:04 -0800 (PST)
X-Received: by 2002:a63:3443:: with SMTP id b64mr29514534pga.93.1572877743897;
        Mon, 04 Nov 2019 06:29:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877743; cv=none;
        d=google.com; s=arc-20160816;
        b=rO3TY3utoqXXerCOBDSS1ikZkuJyz6fymcZbCB3cpMz4OdG/uGT1+4HwIy3mMWs452
         ltHRz8Tib3Mel3rSuCKqPBvVrVVe+aQfdYGrfwP3OpAnmckDj7Ifp157QyWyaHyGykaq
         OoEHZy8wSdvG6YdTi2AlDOP2sayCfcABr67RamFg3B8n82LmoZqgbu3am3emc+yHzISW
         /vtfg9fTFGTqg2A/8VtAOSo5Vmz5cqVlx38XR+G9yalcVvizJFHK8EPNOrwG75QpJFr8
         3n3arDNhhjQI+8FbEA6wbZWX6MQMTpK9qGBNkqp17qLSa/noqrKdYlAGJESm3yngbaUQ
         4DKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=pDhjw8llKKibkxwiEHjLwKfV0zoLrBjVR8XQZovar/g=;
        b=aCMs9uOvlGdzvx8KVhWv5Wn8wB3Y3y5W995NeP5+uy2LJb+cZ+Ybv/qR2EOv1t4YBA
         im1f4TQnW5zFJ5D2uRxrgqBINDq8QLHORghwv9roeodShCKLSr+DZwTH5p8htUtTig41
         6hOxUjCddhQ1mmJkxAG6dpPWrm4JLluXySY2XlihKzkpYxCHT6W0a/tklbpSAxwuZnYE
         NLmG3BZ7LctrQ9KuBUaQbrbMFlRIXc+AcJKW44sDWfgCRsDE1PxhwHTlatfscUpE6twA
         Qo+gfDxDDf+JhW6cXl+Cd+kNSXOexGEllOKkKzV8xBnD4kGTqrWRvnf4n+5WbyztraQM
         o6sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LohiqOAc;
       spf=pass (google.com: domain of 3rjxaxqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3rjXAXQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id d9si695247pjw.1.2019.11.04.06.29.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:29:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rjxaxqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id y24so566411vsq.23
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:29:03 -0800 (PST)
X-Received: by 2002:a67:fd8b:: with SMTP id k11mr11860157vsq.43.1572877742637;
 Mon, 04 Nov 2019 06:29:02 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:40 +0100
In-Reply-To: <20191104142745.14722-1-elver@google.com>
Message-Id: <20191104142745.14722-5-elver@google.com>
Mime-Version: 1.0
References: <20191104142745.14722-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 4/9] build, kcsan: Add KCSAN build exceptions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LohiqOAc;       spf=pass
 (google.com: domain of 3rjxaxqukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3rjXAXQUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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
v3:
* Moved EFI stub build exception hunk from x86-specific patch, since
  it's not x86-specific.
* Spelling "data-race" -> "data race".
---
 drivers/firmware/efi/libstub/Makefile | 2 ++
 kernel/Makefile                       | 5 +++++
 kernel/sched/Makefile                 | 6 ++++++
 mm/Makefile                           | 8 ++++++++
 4 files changed, 21 insertions(+)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index ee0661ddb25b..5d0a645c0de8 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -31,7 +31,9 @@ KBUILD_CFLAGS			:= $(cflags-y) -DDISABLE_BRANCH_PROFILING \
 				   -D__DISABLE_EXPORTS
 
 GCOV_PROFILE			:= n
+# Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KCSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 74ab46e2ebd1..cc53f7c25446 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -23,6 +23,9 @@ endif
 # Prevents flicker of uninteresting __do_softirq()/__local_bh_disable_ip()
 # in coverage traces.
 KCOV_INSTRUMENT_softirq.o := n
+# Avoid KCSAN instrumentation in softirq ("No shared variables, all the data
+# are CPU local" => assume no data races), to reduce overhead in interrupts.
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
index d996846697ef..56c1964bb3a1 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -7,6 +7,14 @@ KASAN_SANITIZE_slab_common.o := n
 KASAN_SANITIZE_slab.o := n
 KASAN_SANITIZE_slub.o := n
 
+# These produce frequent data race reports: most of them are due to races on
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
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-5-elver%40google.com.
