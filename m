Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5UG7SKQMGQEEDCANWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A1DC2563512
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:50 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id 7-20020a170906310700b007263068d531sf845017ejx.15
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685430; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uqwh0WDX6IbcFDhCOowifXGjC1ALsCBU2Tw4rw0YZrNPSYNqW1LDwibNQD4+T/Qfze
         ROon+/POdmmHh2YV5it5z5+gLFwUnTPM7XUSz2+sknDzQAVdi2+3AJ7puQJviodNjBYC
         NM7ZKem0xETYBg5SCr8dWN6efd/vaoHB9FixssdvYnJ5StjSSZ3DFwEjR2G6lAzVSn6f
         MN+KwISA65Se5A4lKApDY4myUbF6i6VbaZYtxC0OsFSLqZBQBgwXCN0nV8lWkspRCbEz
         wS8+Ub8oUtlFK0K5QH/mz5MexzNBkwkYFtDoL2cLZxAYRqv7OwHRaNerVNYQGbkJHTnX
         a9yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Klk/VBICLEBBJcf/uNkq8HtZtvLtvgzzLKSNfci85iA=;
        b=SNT6/ijoxwO67JMP+LNofQlYzBxv3UBPKWLnl85u6LgFttoovXOTq0sSrybWCVTtcK
         HTZSjpDPAvsgVDJ5/vqz0Dbt3vC+c8zTls6O3WyIzEcQtljnQGdS6OeigApwYtxBvmfe
         eJqb300Nxot7VOhlZ/2FTBjJOu6m2syyc6vILKykX/KsRuGDmn4zqbd5Li0sXzh/rPYj
         in6pJM2ErNLNEPsE3Oymv30vpnlSE+T5vV8xLrXwPuaC5kIJiz6ZWBKCUN79XA3qillk
         gSFHy1tWIa6/6laTJMMhUazrRwPxZr+Qf/H+jezjxvU/krQubAzFRGS5qzHvneQHJ0Zo
         jd9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hUrPjZ5x;
       spf=pass (google.com: domain of 3dao_ygykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3dAO_YgYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Klk/VBICLEBBJcf/uNkq8HtZtvLtvgzzLKSNfci85iA=;
        b=OHIqalPvwFl98jKrbCEqIHSKeF4N9gX7AycT29bJX9yrY5fFs/kws40vlWO3jy6uO5
         hw7GGIt4XhNXQG0EaPGKtPIdmCakIc5TgRjgJ38IVcRq5rS3ktYIILqBDpEMowhxAY8q
         kIvjd0QoGTaQhbIZc0PFrg5eEq3S+A0cbK6nK3gimGuQ9aXGKirTnwM7/GTs+Pyx/MmC
         dcRnjNQQxsH8R8sTv7BGHhXyl/jlrBPlfJO6d0dYVaT+PdWujpREPxc/jiovLsu7Z7Dc
         ez2Db+fztEVqvA0GtSwgd3p9iqHt5Lqzs7wjAtyzcVxIKV8Q5cQlueYIxSeTiKGWb5q/
         /jBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Klk/VBICLEBBJcf/uNkq8HtZtvLtvgzzLKSNfci85iA=;
        b=4tLNg7u7g2OxE/JXSf/6TYmJX2Edl1H7r3nNx2qMnxNg3IFvrJyR2ULu/KTjzhOzmb
         m81O/uOZIWA9OZ2TbOCBWiRkXqE39lFxWdc4Xag+hSzC+V4J7lwwFplIkB2n45U1glJK
         AuTWj2UaCLjbF6VUpnh8Ue3ya2azTKa1FtPpDJ1SjhsH2gT63NrWsowY1bjGVmu7Nur9
         ffj0BsV8l9L7oF+pkp8cQ3kdjIES7WGxE9oLawkOs2EonJ/pT9wADmV5fmdGmH5IY8eB
         Z2jpkkaE+nIboE+xgZ/FlFamLfgNoG3GG8UoTEn2kOxDqxk1RCz4xeN4ku3TNbeECjiI
         LBuQ==
X-Gm-Message-State: AJIora8nkOdLXqrxPiMRhRIbVznjgZwqIvsdCYrBhKL77z0ruW1F/1sc
	AhKWygyRJOrBNccVU7pYLZg=
X-Google-Smtp-Source: AGRyM1vz8IZz2+opchoDrnYegSfE2qkNrjpEyaY281vWhJ/bCE+94h3l3DLoekj4iP7xG5rCAmL0Zg==
X-Received: by 2002:a17:907:6d96:b0:72a:87ba:446d with SMTP id sb22-20020a1709076d9600b0072a87ba446dmr4380443ejc.574.1656685430335;
        Fri, 01 Jul 2022 07:23:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c9:b0:435:95a1:8b64 with SMTP id
 x9-20020a05640226c900b0043595a18b64ls368545edd.2.gmail; Fri, 01 Jul 2022
 07:23:49 -0700 (PDT)
X-Received: by 2002:a05:6402:3305:b0:435:8b1a:8fa1 with SMTP id e5-20020a056402330500b004358b1a8fa1mr19599923eda.32.1656685429477;
        Fri, 01 Jul 2022 07:23:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685429; cv=none;
        d=google.com; s=arc-20160816;
        b=zlShdVFLVTLD2DM9KMyZUpoKQMCbiBLyy0hS4stTw+J5IHmmanDr2wc8d1WcLR2VbC
         KQ9xJioFq50/y4TnpjBqLKlEopE/8XrLtye8iOaAM5bc321G0Cz7yAG4BiGSpCME336U
         KzIhz5Ok98Rz9YkeWChf+W7q3VNO52Ex7Yzw1SQbnOrFbUiGrOnZ/Fm+Wxdfk2DefMJG
         ccVY8WVbjW00uR3/ink4kk7Fz4AzJ5fAo5Omdn3Xg+a+qlN0c8h7Nimzk784BexPUP2c
         SPPX5jD1ioTSVpfsddFgOBLdAUfDzaFdYYFcWtzBGRhjA9LCS3E4H7I7rAiWLensVXoa
         fhLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=prMZkaWSelYFGUo1Yp0oSlk2FGuv/jH48kix0SjfSqo=;
        b=jEMIjiS0mkhSB+Uei7hhWJQe1gE+ZqTU40yAH8ArC5w3zxtSRhwWG/c+4HIWPZU56w
         3vKDO9NGYNTuj2NGKeBrJ/RR7NLMbpH076pFSl7m/hhHr1tiklnaoe90dbVCxs3EDpTs
         83ppgg9k0ozJ3LsVNOWqfc9IacJFzpOhhWepXV0WwIF+XFDc/A3X6xAeIZuwCRk4ReGk
         OrpoAEV0F27zaowr/jlyZmyyLvdmasAFOF6QWXOWIjR6UtQ4Aa1fHv9a4+uzyVBR213x
         F9YelHmxlDPPsVIIB8YTgZsl4XSRGucBWrDDbwA0r9RnReBQAncJaueG36Kpap2jk4dc
         Wx0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hUrPjZ5x;
       spf=pass (google.com: domain of 3dao_ygykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3dAO_YgYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si737088eda.2.2022.07.01.07.23.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dao_ygykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id f29-20020a19dc5d000000b004811c8d1918so1181066lfj.2
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:49 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6512:2622:b0:481:5b17:58e7 with SMTP id
 bt34-20020a056512262200b004815b1758e7mr2552760lfb.600.1656685428893; Fri, 01
 Jul 2022 07:23:48 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:37 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-13-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 12/45] kmsan: disable instrumentation of unsupported common
 kernel code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hUrPjZ5x;       spf=pass
 (google.com: domain of 3dao_ygykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3dAO_YgYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
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

EFI stub cannot be linked with KMSAN runtime, so we disable
instrumentation for it.

Instrumenting kcov, stackdepot or lockdep leads to infinite recursion
caused by instrumentation hooks calling instrumented code again.

This patch was previously part of "kmsan: disable KMSAN instrumentation
for certain kernel parts", but was split away per Mark Rutland's
request.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I41ae706bd3474f074f6a870bfc3f0f90e9c720f7
---
 drivers/firmware/efi/libstub/Makefile | 1 +
 kernel/Makefile                       | 1 +
 kernel/locking/Makefile               | 3 ++-
 lib/Makefile                          | 1 +
 4 files changed, 5 insertions(+), 1 deletion(-)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index d0537573501e9..81432d0c904b1 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -46,6 +46,7 @@ GCOV_PROFILE			:= n
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index a7e1f49ab2b3b..e47f0526c987f 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -38,6 +38,7 @@ KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
+KMSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # Don't instrument error handlers
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index d51cabf28f382..ea925731fa40f 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,8 +5,9 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
-# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
+# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
+KMSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
diff --git a/lib/Makefile b/lib/Makefile
index f99bf61f8bbc6..5056769d00bb6 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -272,6 +272,7 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
 obj-$(CONFIG_REF_TRACKER) += ref_tracker.o
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-13-glider%40google.com.
