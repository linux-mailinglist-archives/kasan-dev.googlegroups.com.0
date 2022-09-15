Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXX6RSMQMGQEB2EPLDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 413AF5B9E28
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:07 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id gb9-20020a170907960900b0077d89030bb2sf5492189ejc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254367; cv=pass;
        d=google.com; s=arc-20160816;
        b=CvvvPsnnymLT8n7gIn9RIKJGwSBbFmFJ3S/Fy32OeTiLb94vpfyZgviDIz0Jk0ZIun
         uhA0jUMBfzcFbVdUvKClSBL/QiwNDRSglZdsR9kLfqzOKURPgDvapz7SJKs7PR8ChsOM
         mr64GyzDzE8BIvwGiRSOuWp4xhDCIPfSULBAvulWDTj+u6Fn3rI6PY22U5TgljkBX2CV
         f9c5uVMyTYFGrGlQAS2PwmPAOm34VK8VICs5m1L24ybsMUYs5KX9y1oa8qFkFpcu1JVm
         a4k9gSkeKj2b4U6gn9/8zgUW8n1nMceFbm2rlorvJsZR0O+MSET8YEJI3r0j/3kQ81Ct
         45Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=lpjNeNgTl73Jj4k/hWG+uKUoqgUDl2sgCh2kSGGXWKk=;
        b=Jx9Eu7Q/KuvuwLbsQNH8txq0UEiPvS1ViaQoHWfUdeU+CdWjPj1hoxRnGzB7u3yEm0
         8IaUIHqu+9MnM0WWwkQzr+b4NlJH1If5ayiBZUzPCnsMFg2sHtmoD2L4lJ+l3X+S4Fa5
         vB/9z64eUL7vkYNLUVgvEr+xC4B4pJ2W1AK8SGuk4cl5LfTo184AN34m8pFUfDQYQ2XP
         WkFkrd+PnjsRnggbMfkdIt2/DmrXWEddRNTcJpWbf6vBpy4nkbwoQGyc3UgR3gg0q1zW
         Z8B5PckXfZnZ96773PoGI+c7plqI3wz42dgJg7r4sy+8OtqzHSWjkffp9PRxKI5guKH3
         sTQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DoOnWn76;
       spf=pass (google.com: domain of 3xt8jywykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3XT8jYwYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=lpjNeNgTl73Jj4k/hWG+uKUoqgUDl2sgCh2kSGGXWKk=;
        b=HRwsYunN3Vnos/NO0MbexFzySygu69IrYPKsVrgVgCrNCxSlURes4i8gE5zDZMOEHk
         3ujgTpxKiG71TDC2KB0BLKp45l8RqcImclU88kDP44vmObF72KvxTCTHrgfcwjU7AnW5
         GJqOjEjshDIyZaLK5v+zk7t/3kgKhq10Ht36srJ+Hpy/cHAzYgaZ4grfyIuglYJa2Hgt
         e9+OGVyrcNT3083+3NC5bcmdTI+HHAaP625VQ/PJKiQ2Do7Ln+YV204eCGVwIYdtjmAx
         7oeJGUJG5fY3FTD+vddo28jF8apQ7v1uZ0R03vIRJ7KD8uCvvfqKDISvKzmovP1DoUe4
         ZrWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=lpjNeNgTl73Jj4k/hWG+uKUoqgUDl2sgCh2kSGGXWKk=;
        b=XLiejIQ01YTdmjbjyAvJ+NXQ/Z+BCgYzxbUnKpLvmDFdAtziDUtJaIOQ7lh+OGdUiC
         H0Z5a7BTeydEPQVUeoD23yn0/lYbvBMpfkjO52KLWvb6FXS+g7cw0+ylKMIO4Fa7qaBT
         MkdMZ9nrtlsFzMfT5vjM6IyjENvceJ0HbmOr2nLWISzHVkPUzDj3yQB9roP9PUUfeIeQ
         3eXo7EYvZTOf4H27p70O2krPVPzo3gCewBVM8vhLoThCzCFThZrRdYPpK5ZlM6a/H1V8
         ioJMRaJ0MFHPLxQil7bn4qk7bOfvK4oTfvBJee5RS96kg7zGLyObK5AIcm15BWS6gc1v
         GEbA==
X-Gm-Message-State: ACrzQf2kG+ZINtI0KzwiUxZkQT/uTa6PW2x1g2Vgnl0i1Mfsjp9ZC4mB
	1iGvKHHrT1CwPGNWTuwQBco=
X-Google-Smtp-Source: AMsMyM5wRl3Sct6WGHGgKhjewPRtGyc1x9VQgo1gBoooM58hT+SycLZ93YwCgC36Vxt+FvZ19zYoOA==
X-Received: by 2002:a17:907:7d9e:b0:771:db66:7b7c with SMTP id oz30-20020a1709077d9e00b00771db667b7cmr279454ejc.393.1663254366986;
        Thu, 15 Sep 2022 08:06:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520f:b0:447:ec6e:2ee with SMTP id
 s15-20020a056402520f00b00447ec6e02eels2974404edd.0.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:05 -0700 (PDT)
X-Received: by 2002:a05:6402:1704:b0:44e:b523:585d with SMTP id y4-20020a056402170400b0044eb523585dmr296606edu.22.1663254365913;
        Thu, 15 Sep 2022 08:06:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254365; cv=none;
        d=google.com; s=arc-20160816;
        b=FNkbavv/LAv+YyFGSxL+7+V7ZTecWUbkTi+Ii1KOuQ2BV937//dsa3Wba0Du+MM578
         t292Y3FWZvk0r/PtbzJ6xPQTuyKpo+RbFeXof8EOEYQgGHVk7IZREHwaZFOXErDbc/mc
         EymYrdwmY/6bgdlSpEFOfuU+PNUKH3PF6nmBUqtE+akS4xxIUeDorjVolmY85l3mhgj5
         vgjPEQ90D4FC2hHc8qfaXuX6vCrtGJJzT+tlISyCcHvwoNKqttmfjP4VXNFIIoutjrXJ
         CAIK6Y+7UYacsZS0F04Wph//Xf9adbTqr44CpUsAl+0kWCbNV+R2n+20vJJeCUaOZd6C
         s52w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ByRxUK8Sn+pDB+Gp2EKIbiaRYh/I0Prcbbdv1W00JlM=;
        b=Z9pcUKyEFranpqqJ5MA/bs2/8DzjyGjkTnobZEmNaXvoPDk6GC/m6vw7qREOhfV19F
         G1bHY/UWKxa0a8NggZ77dLXFzUYkB5rPgp3B6GEoDtbblgE5OHEhm2wam3Y64Oj8Z2ML
         nl2MtrJ8MX5ZO65c18bL6+vouJyu7hia3NGxYemomeStlgz8etJDVCsBegDIO0mexyrF
         2+VmTkrtUYf4v/l4BtoTGeF4kPrqCcqvpc34MwDg0H8uu3pSrJHK3Fg5Rw7MbqeBrIkb
         hZzKgtkMTMLOONgoWMzePyEICdDTwNbXJLj114s9HWo1fmDxllt3Rknl+bd/u78Huxwk
         LGmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DoOnWn76;
       spf=pass (google.com: domain of 3xt8jywykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3XT8jYwYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id s20-20020aa7d794000000b0044ea33a8ac8si700824edq.2.2022.09.15.08.06.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xt8jywykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gv43-20020a1709072beb00b0077c3f58a03eso5567126ejc.4
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:05 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:6e1c:b0:73d:7806:3c5e with SMTP id
 sd28-20020a1709076e1c00b0073d78063c5emr336232ejc.36.1663254365501; Thu, 15
 Sep 2022 08:06:05 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:06 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-33-glider@google.com>
Subject: [PATCH v7 32/43] x86: kmsan: disable instrumentation of unsupported code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DoOnWn76;       spf=pass
 (google.com: domain of 3xt8jywykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3XT8jYwYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Instrumenting some files with KMSAN will result in kernel being unable
to link, boot or crashing at runtime for various reasons (e.g. infinite
recursion caused by instrumentation hooks calling instrumented code again).

Completely omit KMSAN instrumentation in the following places:
 - arch/x86/boot and arch/x86/realmode/rm, as KMSAN doesn't work for i386;
 - arch/x86/entry/vdso, which isn't linked with KMSAN runtime;
 - three files in arch/x86/kernel - boot problems;
 - arch/x86/mm/cpu_entry_area.c - recursion.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- moved the patch earlier in the series so that KMSAN can compile
 -- split off the non-x86 part into a separate patch

v3:
 -- added a comment to lib/Makefile

v5:
 -- removed a comment belonging to another patch

Link: https://linux-review.googlesource.com/id/Id5e5c4a9f9d53c24a35ebb633b814c414628d81b
---
 arch/x86/boot/Makefile            | 1 +
 arch/x86/boot/compressed/Makefile | 1 +
 arch/x86/entry/vdso/Makefile      | 3 +++
 arch/x86/kernel/Makefile          | 2 ++
 arch/x86/kernel/cpu/Makefile      | 1 +
 arch/x86/mm/Makefile              | 2 ++
 arch/x86/realmode/rm/Makefile     | 1 +
 7 files changed, 11 insertions(+)

diff --git a/arch/x86/boot/Makefile b/arch/x86/boot/Makefile
index ffec8bb01ba8c..9860ca5979f8a 100644
--- a/arch/x86/boot/Makefile
+++ b/arch/x86/boot/Makefile
@@ -12,6 +12,7 @@
 # Sanitizer runtimes are unavailable and cannot be linked for early boot code.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Kernel does not boot with kcov instrumentation here.
diff --git a/arch/x86/boot/compressed/Makefile b/arch/x86/boot/compressed/Makefile
index 35ce1a64068b7..3a261abb6d158 100644
--- a/arch/x86/boot/compressed/Makefile
+++ b/arch/x86/boot/compressed/Makefile
@@ -20,6 +20,7 @@
 # Sanitizer runtimes are unavailable and cannot be linked for early boot code.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
diff --git a/arch/x86/entry/vdso/Makefile b/arch/x86/entry/vdso/Makefile
index 12f6c4d714cd6..ce4eb7e44e5b8 100644
--- a/arch/x86/entry/vdso/Makefile
+++ b/arch/x86/entry/vdso/Makefile
@@ -11,6 +11,9 @@ include $(srctree)/lib/vdso/Makefile
 
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
+KMSAN_SANITIZE_vclock_gettime.o := n
+KMSAN_SANITIZE_vgetcpu.o	:= n
+
 UBSAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index a20a5ebfacd73..ac564c5d7b1f0 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -33,6 +33,8 @@ KASAN_SANITIZE_sev.o					:= n
 # With some compiler versions the generated code results in boot hangs, caused
 # by several compilation units. To be safe, disable all instrumentation.
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE_head$(BITS).o				:= n
+KMSAN_SANITIZE_nmi.o					:= n
 
 # If instrumentation of this dir is enabled, boot hangs during first second.
 # Probably could be more selective here, but note that files related to irqs,
diff --git a/arch/x86/kernel/cpu/Makefile b/arch/x86/kernel/cpu/Makefile
index 9661e3e802be5..f10a921ee7565 100644
--- a/arch/x86/kernel/cpu/Makefile
+++ b/arch/x86/kernel/cpu/Makefile
@@ -12,6 +12,7 @@ endif
 # If these files are instrumented, boot hangs during the first second.
 KCOV_INSTRUMENT_common.o := n
 KCOV_INSTRUMENT_perf_event.o := n
+KMSAN_SANITIZE_common.o := n
 
 # As above, instrumenting secondary CPU boot code causes boot hangs.
 KCSAN_SANITIZE_common.o := n
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index f8220fd2c169a..39c0700c9955c 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -12,6 +12,8 @@ KASAN_SANITIZE_mem_encrypt_identity.o	:= n
 # Disable KCSAN entirely, because otherwise we get warnings that some functions
 # reference __initdata sections.
 KCSAN_SANITIZE := n
+# Avoid recursion by not calling KMSAN hooks for CEA code.
+KMSAN_SANITIZE_cpu_entry_area.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_mem_encrypt.o		= -pg
diff --git a/arch/x86/realmode/rm/Makefile b/arch/x86/realmode/rm/Makefile
index 83f1b6a56449f..f614009d3e4e2 100644
--- a/arch/x86/realmode/rm/Makefile
+++ b/arch/x86/realmode/rm/Makefile
@@ -10,6 +10,7 @@
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-33-glider%40google.com.
