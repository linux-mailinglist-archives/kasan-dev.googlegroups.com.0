Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2NWQSCAMGQED4JEW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 47344367A16
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 08:44:59 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id z7-20020a67ca070000b0290220c083d3acsf4225321vsk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 23:44:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619073898; cv=pass;
        d=google.com; s=arc-20160816;
        b=CMlOVQWKug91tFjMSODN8gPQxM07zsnTv6QwxrR1wkwDuaBE7a1aAnJbik5PSPodff
         XCbgJWa4Ok5IQqGqgqb4cJu5komGC4PBwGVbmZeRqSzpkHorPWIdXyeKj0yS2X9NV2SO
         kTt200vlOwRbSWv6XNgU90ZH/XniouY3CAZTqrVu7jbJZbUTRimq/q18QQdVSGBe41SP
         mbe00ubWmatd/H2wTK4HJlqO8jAWR5GGz7+cCMHriE4ZdLy3VbtmjThZVH+5td14ClDs
         NTZGYWUhZbDvw77sQK6T8Pdrc/0cSL+gSPXPVVahl7ZiXMRE9fxfdlFV3Sl4auydlPkY
         kHvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=mNKe4BK6kjJOkuWIwhkq2XsmIQXTHkc72MnLncBrM5o=;
        b=MXxwXh6/mWIztsafGyG+y5NAu27k8EK/8v9mUVsRGBFzrKA3AyI0BvrSg4fBIbSh4q
         wOQQCa5F2YHX1y22eNng9z6K/4OfLN+bTgY/bBzelGyV8ClcOxEmrAbREyxkeYq1t9ZZ
         HY7I5nNdtw/Tl0py41jCGLX0u211NoqFtVds501dQis/BXXlxmb3CXavcbh5zQMonIbr
         T5MhxoF1k0wYRK2Fe0OGUb7ZZf8t4iwTxStBdkfx6+yrD6ywJvwuGWOTJguE9jqua9mE
         oEo3xR0X40s/JVuNW5fBxOwywnT3OKj/8llsu/iDIWmxniK0lfgSBTwN35e/mlTNYw+5
         eCjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b1iMBV9G;
       spf=pass (google.com: domain of 3abubyaukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3aBuBYAUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mNKe4BK6kjJOkuWIwhkq2XsmIQXTHkc72MnLncBrM5o=;
        b=lhfLM3qw7sD8mLHXDkWJ4HrRpofaTNIOXfgT+pVXyBPXY9nz4YusVpDkx1ujmnKxCG
         okuNjBiz4HZIyrL+mRA9FuUZflmLFyqKMCfFWD3le35SQXnLjeNCTr52A1wJ5tZ3wAJh
         LNGm4kqahAgQHAcAp4BX8Gvt6SFuA3eIWdFIJ4Pdm8w+f6zwoXa83eotDbnwWosemLzh
         TxK6f1sbtbrIlMsZ6lSHepBcAzRhyoHnBRIZFdbm+cPeAtOgC7ym44XtxvX35ju7rjJi
         93WkGjgR6X6spgOqORqt6yeLLnrME/mEvIz9vp9fiVKHo64xpYavaKFUb2REMNy+XyEO
         rChA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mNKe4BK6kjJOkuWIwhkq2XsmIQXTHkc72MnLncBrM5o=;
        b=q/qphztZ3cFLWiALaObwt22wZGsZMtKAyP2hktFz1kHONV4zqWVFZsmC6V4LNgFvCc
         5u01q5HiQ1ni5tPZPU4OlmDlKFJ+IBAgI1Y5cRNaT849PKruIsURW92/DMTaBFmyJCSh
         gOiMXEL14VqvRzY5DpBPUM2HBkkiSHGE2FoxT7FvRUBjLOtXHv74AWJSZZMyIgsvMTc7
         DmGcM16DD+S0v5RNZMbklh82J2jiVt/XV71YQmzZGNzpudCET/Lfx2yFFijWLsK0whFp
         /9owPqOPZwkBOJ0nfg1bkIRPhZ1z42p7en3hJtPD0DpRK/5K9u51hXwI54d51pG13Kdh
         xkeQ==
X-Gm-Message-State: AOAM531yDKKLVV405QoNvPTEZhvdNIFFifzgQ1uVfTYfuotUHMTQUENr
	t1F5FDXK1ya5SlqZYHHf9L8=
X-Google-Smtp-Source: ABdhPJy7rOi8fBtFmKh9q7B7muWivnn4LWWRhKD+O8HhLIXsJmHKQMRUCRji2qpXCj1v3dOcY2Jevg==
X-Received: by 2002:a9f:3e97:: with SMTP id x23mr1080414uai.80.1619073897963;
        Wed, 21 Apr 2021 23:44:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2702:: with SMTP id n2ls785609vsn.2.gmail; Wed, 21 Apr
 2021 23:44:57 -0700 (PDT)
X-Received: by 2002:a67:af0d:: with SMTP id v13mr1156848vsl.48.1619073897266;
        Wed, 21 Apr 2021 23:44:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619073897; cv=none;
        d=google.com; s=arc-20160816;
        b=s4tH82+zBGp+xtbi/0WC9Ri3f8hQOijuuBp4uWDJwFPvFNRNwaDxOGnHvqfmHGxhdA
         C8qzilmTkb6UwhmLEq9cfkYSIescsztkdhuXeoGD8S+yJkrUh0JJ9Br2bylceN1N14td
         F+P1MJNEA2dhDNjvT9gvHjLNqGqXKgkox3tjleaIzNB3AFPCYxU7crnlc/AhVM2fV73I
         Kgp/Y89lTF1BlWWFV+9TDGhkMbWQm2lj1DWRXY8soZxYA9gEkHkD6x8UfrEhZpfgGPLU
         Rr+P0AaD6DaJL9UlU+RNk2phvBe72Ir+NylzFwOQSEfWUG42LJ7VLwebrYpcD897BHW/
         btXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=l+qKKt5CthNo7gsKeiDmyb/kZ1TcAtPvmD2Gk6Cbjnk=;
        b=MXYPKzOFZua4BPAdjX6W7mT4hBk5UnL5MF4gZrdDUfPsmlOaCAbjVMhiZ4D5EhglRf
         idEjgIyS4v1mW8NB5uYbqcs2n6i78sEF7x/ricYVbOmAsRI47E7XEmUXufSKaGNgGtDN
         LUVFXBUhLvM0m2N3iToWyHhFjUCHQarvGpA1giiSvUOSoIA/7wxvphEigws7dfBEF3F8
         Z2P9rHMxdp0DdN7rw4GIqIPP0gZn8R1R22gm5BYy7oLJiKK9X2pu4VtfbgA4eArJo3vV
         dAKpQCPnqnv8EVT42MBjkZeFokblduAHrg0KEJ2qzKSF1fr/VCPPTdukvAtg368vvzni
         3wXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b1iMBV9G;
       spf=pass (google.com: domain of 3abubyaukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3aBuBYAUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id t13si464771vkm.3.2021.04.21.23.44.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 23:44:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3abubyaukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id t126-20020a37aa840000b02902e3c5b3abeaso8458843qke.10
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 23:44:57 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6273:c89a:6562:e1ba])
 (user=elver job=sendgmr) by 2002:a0c:f454:: with SMTP id h20mr1734578qvm.40.1619073896837;
 Wed, 21 Apr 2021 23:44:56 -0700 (PDT)
Date: Thu, 22 Apr 2021 08:44:36 +0200
Message-Id: <20210422064437.3577327-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.498.g6c1eba8ee3d-goog
Subject: [PATCH tip 1/2] signal, perf: Fix siginfo_t by avoiding u64 on 32-bit architectures
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@redhat.com, 
	tglx@linutronix.de
Cc: m.szyprowski@samsung.com, jonathanh@nvidia.com, dvyukov@google.com, 
	glider@google.com, arnd@arndb.de, christian@brauner.io, axboe@kernel.dk, 
	pcc@google.com, oleg@redhat.com, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b1iMBV9G;       spf=pass
 (google.com: domain of 3abubyaukca0ryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3aBuBYAUKCa0RYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

On some architectures, like Arm, the alignment of a structure is that of
its largest member.

This means that there is no portable way to add 64-bit integers to
siginfo_t on 32-bit architectures, because siginfo_t does not contain
any 64-bit integers on 32-bit architectures.

In the case of the si_perf field, word size is sufficient since there is
no exact requirement on size, given the data it contains is user-defined
via perf_event_attr::sig_data. On 32-bit architectures, any excess bits
of perf_event_attr::sig_data will therefore be truncated when copying
into si_perf.

Since this field is intended to disambiguate events (e.g. encoding
relevant information if there are more events of the same type), 32 bits
should provide enough entropy to do so on 32-bit architectures.

For 64-bit architectures, no change is intended.

Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>
Reported-by: Jon Hunter <jonathanh@nvidia.com>
Signed-off-by: Marco Elver <elver@google.com>
---

Note: I added static_assert()s to verify the siginfo_t layout to
arch/arm and arch/arm64, which caught the problem. I'll send them
separately to arm&arm64 maintainers respectively.
---
 include/linux/compat.h                                | 2 +-
 include/uapi/asm-generic/siginfo.h                    | 2 +-
 tools/testing/selftests/perf_events/sigtrap_threads.c | 2 +-
 3 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/include/linux/compat.h b/include/linux/compat.h
index c8821d966812..f0d2dd35d408 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -237,7 +237,7 @@ typedef struct compat_siginfo {
 					u32 _pkey;
 				} _addr_pkey;
 				/* used when si_code=TRAP_PERF */
-				compat_u64 _perf;
+				compat_ulong_t _perf;
 			};
 		} _sigfault;
 
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index d0bb9125c853..03d6f6d2c1fe 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -92,7 +92,7 @@ union __sifields {
 				__u32 _pkey;
 			} _addr_pkey;
 			/* used when si_code=TRAP_PERF */
-			__u64 _perf;
+			unsigned long _perf;
 		};
 	} _sigfault;
 
diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index 9c0fd442da60..78ddf5e11625 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -44,7 +44,7 @@ static struct {
 } ctx;
 
 /* Unique value to check si_perf is correctly set from perf_event_attr::sig_data. */
-#define TEST_SIG_DATA(addr) (~(uint64_t)(addr))
+#define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
 
 static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
 {
-- 
2.31.1.498.g6c1eba8ee3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210422064437.3577327-1-elver%40google.com.
