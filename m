Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4YQ6CAMGQEQ7X5ADY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 92EC136870B
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 21:18:32 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id f5-20020ac25cc50000b02901ae61aa1b18sf5356279lfq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 12:18:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619119112; cv=pass;
        d=google.com; s=arc-20160816;
        b=TgsgG02jBmVtn9jUpUrCiMFvhgEMYfNf3M5Dndd8EhJB/F9YXj5a+S6eZwrqjUDqFt
         LKOSMi+9vgq2Gel+JyhWBVoKbg1m3thkYs//xc4Qvjuahn0f81NYAohzBudkyOgcC+sJ
         J2wObJmBTrDyUtgWVrM76PAn03Rpu/0vwo7tiditSDvxWwbX6jeCeDsyohTTKFR9UQkb
         PQNtl3LuAjQHTRYvJIRL1uCkImThPP57ylEK4G2djcp6XTt2rRIQa0IuROmagZrfVHqI
         yDZVC8KHef+SrfZWV9kp4Tb7Yf0INHNMOeWISnqeuDudC+v+zByb6oRa1oVw49T6b7KZ
         18tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=gUApt4ydUG3XwozkoQcpJ4vwccrhr7EtVJXLYTPckTY=;
        b=O3YnM5oF3MkvY1gkitwtPpCJeyqGtGLvrNTgGgquowax4yo3VbW+yWEBAUGnpx6v1w
         9F1pA2txcusqpQKbnzA5ypTP2Z3AGA5Wg7bHdb6z1Fml6i7lEOrrUT7oCnCUWsueT8R9
         RrznT/qdl1ItieZHxgw4w2etfUJb//Zz3C5S8QRk/013r6ORCj+3j+f8HibaHyfp23kB
         vvvpn2FAjZmnuBAO9wq9esy8K1YNQdzF43lJzt+haY0vhUoNO2i3dh2N5qhNd7xdrDwi
         +mqlbNm1eRs5BUoB0XmpZm4yzywuGcNhFQyyKlXbRBcZU8GwfOxk1DTly/7xpLU5MQPb
         cNMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CTGWG2bw;
       spf=pass (google.com: domain of 3bsybyaukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3BsyBYAUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gUApt4ydUG3XwozkoQcpJ4vwccrhr7EtVJXLYTPckTY=;
        b=bqb3n83T+I9HclfxMJiS7RUHMxgeIUyMLmMwpuUmpqCtU48C6t+GZdGJd9O1NG1Msb
         Htsl5kNpadPU891vVrZbeHkZfhIFyzZ0ruDdKtFNZrLgYRbSy60YcUVLnRDRXt1x5Jjh
         VAWtwPSoFcGISqdqmeq1FEq7pXDgvJFwPnq9WYqodyvjD/vigB9W3LhuAsDpqpk0ai/b
         HuIG4VCt+xUHRIVMtBT0dX+lXYVf2nfm0C+mozmhvPKx2fMo9e1zF5nSFYQ/NBA3mvxH
         dvdSepYlpRjnclDR641HEpuTa7o2OCCYiFkl1sr4c6E7h1zDLaNIHHV5xpwyVthKuv1F
         U4Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gUApt4ydUG3XwozkoQcpJ4vwccrhr7EtVJXLYTPckTY=;
        b=FufRfLcRreFipJRIswL+0jG1gpSNCXygDKV1aj6k/GCgE2bAb8b+01Zpc9Zu8yV6ol
         q5vrrKFsbLRerQciLTnw4KXo80uNJjvvIhEo5G7i2kEvBeiVkHNssF8CRh7PT4xMYAjr
         V4WYgzMrPFEyOv+PvYFXcRpNYUOKJp8W15LkyjguaKBRDa2o3FdHObqsjNlY1Phcb+Sn
         T0tT8CCmQGGgC3fQIvvP7s72dADMQONf2QQPXPBaAgEy/vyAPdc7cvLJIIfI8x2UGgex
         TqBvVZayCweDZ3vuO62DjDSwegUDjudhqpLe7U2qJ3lUUOCC5NytoRfrEOP1ftM1jHu+
         quDg==
X-Gm-Message-State: AOAM532uH/WOa8/n1gGd2wkn/3kaPxtPUClX3lNGytCICuFR4/zRaUc2
	jyQc5+2VtbjP9Y2SAuIEcwo=
X-Google-Smtp-Source: ABdhPJx+nKi6GCHpsjmJG/PqWJklKrun96sPImq18/WcHA2D86GxHZ2gsBA8OAAr3cz0PRNWhEO1Lg==
X-Received: by 2002:a05:651c:119b:: with SMTP id w27mr222108ljo.237.1619119112067;
        Thu, 22 Apr 2021 12:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:507:: with SMTP id o7ls1650583ljp.6.gmail; Thu, 22
 Apr 2021 12:18:30 -0700 (PDT)
X-Received: by 2002:a2e:5347:: with SMTP id t7mr216802ljd.263.1619119110644;
        Thu, 22 Apr 2021 12:18:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619119110; cv=none;
        d=google.com; s=arc-20160816;
        b=xvKVGVv7x9xhmNtp/Y3mMVDgjYHYyhJP7eqpPVUwkkITWwEBEVJYR0FXi0Y6O+2eY1
         IUQhoo6HI8bPbvb2AQND+bpJy5clRB4KP674uMQKVSy9ny3B8nLCyafyndjtFfMf+uDM
         613bQRnRgo/mqJPc6LuI2LuhI+/81oT11X9y2RFEKxFefRaPzDJqUIA6aVxZxxw2vCP/
         qC9xGlId31y8SVf8wYVphpT9BqJ0rDQHs/iqVSJLPJ233AJiZC9l4JwjkQAFbJlj/oOw
         LydzzbgInef7FBo2+f7y7alO8gS/XfxmYQ+QuTKHnZOy+9fZr2JmxkaVtcFJzViU+9Hg
         OQZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=MG1E5LmNjEnO9dOxTFKDeqsCA70+WVWf6tsEnOy3w2I=;
        b=elPcZCwzcGzZyBUy00pirapB8syXo9s60eP1WqVJ6QC0vUv7LIV3RbLpgpjVkzdju+
         LO+t+Fan7DF0H6UwG2ucWIOKiwHECT+EHjF0A4KgmjOz9Und3CkxLC2EkN/xKBaEmyQO
         FSRCNc8idGF0uNX9Ce5sb5MzeDPdfOMURjHK5QxLGkqxBMoZJppaTMTJ7hksvJLnP/Rf
         6ffUNwuY7owWnoeSKD+xYfzMb9dSrbfY2w+TgsV6Z7wZkp4j8mBeZrLCD65bYVi5zl9S
         pSzKRFzsn2Q24bHCswBiaFh0FwNmOezGiYh7CXxZ0qkiBCED8EalysM+u0uOSBdKKEKU
         XLgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CTGWG2bw;
       spf=pass (google.com: domain of 3bsybyaukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3BsyBYAUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id r2si421221lji.7.2021.04.22.12.18.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 12:18:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bsybyaukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t11-20020aa7d4cb0000b0290382e868be07so17271362edr.20
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 12:18:30 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:145c:dc52:6539:7ac5])
 (user=elver job=sendgmr) by 2002:a05:6402:1004:: with SMTP id
 c4mr17333edu.364.1619119110010; Thu, 22 Apr 2021 12:18:30 -0700 (PDT)
Date: Thu, 22 Apr 2021 21:18:22 +0200
Message-Id: <20210422191823.79012-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.498.g6c1eba8ee3d-goog
Subject: [PATCH tip v2 1/2] signal, perf: Fix siginfo_t by avoiding u64 on
 32-bit architectures
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@redhat.com, 
	tglx@linutronix.de
Cc: m.szyprowski@samsung.com, jonathanh@nvidia.com, dvyukov@google.com, 
	glider@google.com, arnd@arndb.de, christian@brauner.io, axboe@kernel.dk, 
	pcc@google.com, oleg@redhat.com, David.Laight@aculab.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CTGWG2bw;       spf=pass
 (google.com: domain of 3bsybyaukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3BsyBYAUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
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

The alignment of a structure is that of its largest member. On
architectures like 32-bit Arm (but not e.g. 32-bit x86) 64-bit integers
will require 64-bit alignment and not its natural word size.

This means that there is no portable way to add 64-bit integers to
siginfo_t on 32-bit architectures without breaking the ABI, because
siginfo_t does not yet (and therefore likely never will) contain 64-bit
fields on 32-bit architectures. Adding a 64-bit integer could change the
alignment of the union after the 3 initial int si_signo, si_errno,
si_code, thus introducing 4 bytes of padding shifting the entire union,
which would break the ABI.

One alternative would be to use the __packed attribute, however, it is
non-standard C. Given siginfo_t has definitions outside the Linux kernel
in various standard libraries that can be compiled with any number of
different compilers (not just those we rely on), using non-standard
attributes on siginfo_t should be avoided to ensure portability.

In the case of the si_perf field, word size is sufficient since there is
no exact requirement on size, given the data it contains is user-defined
via perf_event_attr::sig_data. On 32-bit architectures, any excess bits
of perf_event_attr::sig_data will therefore be truncated when copying
into si_perf.

Since si_perf is intended to disambiguate events (e.g. encoding relevant
information if there are more events of the same type), 32 bits should
provide enough entropy to do so on 32-bit architectures.

For 64-bit architectures, no change is intended.

Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>
Reported-by: Jon Hunter <jonathanh@nvidia.com>
Tested-by: Jon Hunter <jonathanh@nvidia.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Update commit message wording to be clearer and mentioned __packed, as
  pointed out by David Laight. I'm sure some time in the future somebody
  will wonder and perhaps run into the same issue, so let's try to give
  as much background as we can...

v1: https://lkml.kernel.org/r/20210422064437.3577327-1-elver@google.com

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210422191823.79012-1-elver%40google.com.
