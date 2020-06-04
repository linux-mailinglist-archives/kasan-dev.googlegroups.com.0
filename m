Return-Path: <kasan-dev+bncBCV5TUXXRUIBBE4Y4P3AKGQEP6U3MVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 078821EE263
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:24 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id t3sf603473lji.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266323; cv=pass;
        d=google.com; s=arc-20160816;
        b=FuWqUjys5Gg2MgiMfslwspreeueWgP/d2EFatP82iFp6cGWO0AW3tUpHxbm+WPfaO3
         4zMkhymwkNR6dsWchcgdBT5Eaqm8qHcYntW+5Lxd/34wgxXcVTQB12H/p7ZVAFaS576w
         7TfJw2b1yrVP5soXD4zU/jTF6FO/gvRpOJwmONMpyRbJcNSBuUKKmCXUGQLprWzeFd3R
         6H1yd7Xsl1Si38O6dSTPdbTArOxbqZwE+ji4Ie/vM8SReeI+CCdOvziU+I+b+JuaI2PL
         zteboH1cJqOfaj0ELIJCaYqFTTOgnItZdHt4qAiPB/1OD2hjXfVZUDHIzHUv6iKaCyZ7
         JMUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=Z4vgzFlEGVOAvvmBb6Z2LGpHd3HQRIsnMbfFPVATaEI=;
        b=GFrwkR8+S8osNFQspEVpTJAwKeomh0RxhxF7oo8q0vgTMKdjeh+Uxw6DEZ4VYYTAfQ
         vgC1HkomS97Gy5GjXKf0WkBTwT19/ETbUDFdlBS+gh6FPyYEK+q9cJGYZN1o1+TpmaWe
         x2UqOjjGbt8jJZEpjMZpaKxZjD8CjOBBIEqulxHwdmLOZeyPFTN6b+ioJR/YxOmUXoqn
         sQS0LJh7Y2qCxrKlT6FKN1fXQ83APVv4erahVf0k4/yxKqoW3PRR85NYCVsnnwchFfgB
         dSL771b/fVz6EggDuLtaYViBZC2qzMoigLDd4/gDABTgJW0+B5j6fSIkTxUtkAJf24mp
         k2qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=DsqAMDU1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z4vgzFlEGVOAvvmBb6Z2LGpHd3HQRIsnMbfFPVATaEI=;
        b=mjkLX6H1DgbnHh2eN8cwi3if9mpw2Tk6d0i18pqUAzfQH4Ybsus4zkUKQ9EIIh+uMd
         dcIlBYXy65tWAoHF5ogZVmSqY+tZZqrMwZRWcDcwbfnTKxhSOU4LIK7v8Yl7CalqkOwL
         ICK7pPcZvszLtyNK5Ji5FW0GbnYyUxRTLivcyQuPukTJ0yDaaAJgZLRTmZqeLxtaJd1U
         3xkC2BoC1MslumDin/Wh6vzk5412QfRnBxIHWEPTtFpFXyvOsVJjHHkFubNpsLYsPU1G
         NT0Dj9woiX2HnFpW6AJayYRCSresckTxYKRXxIz9eG+XRxSF9jsXl4ChAXch5CECGt8Y
         jHkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z4vgzFlEGVOAvvmBb6Z2LGpHd3HQRIsnMbfFPVATaEI=;
        b=jFnHEOT775z3HQWBxYdbABmTblDyHo36nt8N2RjOROnCeatb62vdAjJ32AAHyX1fZQ
         cT//BLTM/bzpJgor+ZFQ1y2Ag8Q5UK55ydVPE3i0w9yBArSn7AksrQJclx9ujoFjyJYR
         Jk991OGXxc7MNJhAV4GE0wLXq7WMWUmgTAMSH3X4D0VCnzdpANxH3th6U/oLaZHcKC02
         8YWS/GicGr4aoS6kIE7Covxk+1K3UV7M9Pm8/mRwl6YOpXzTJdhzXmJfjNaFba9eDrND
         5qk9/D0zqTSYLrnFHR2xH2z38Ame30M43UbgZpQsid9UA5gEifZDRNG568rm32/6K1xP
         noag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532J4lKfi3PNRqvIdif+ms7khbmNvL4FgR2LPMNyc/7nlk/zWXEw
	Ed9pIlFU945IlhNqfd2ywZE=
X-Google-Smtp-Source: ABdhPJysfli08hclSqwnyWgAosG7M9Ub/WFvfpHfaOFYvyqjHDN2WiJY0Sj9Wuwz38/syJN5KEw4EQ==
X-Received: by 2002:a2e:8246:: with SMTP id j6mr1762039ljh.54.1591266323456;
        Thu, 04 Jun 2020 03:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a8b:: with SMTP id p11ls1079232lji.9.gmail; Thu, 04 Jun
 2020 03:25:22 -0700 (PDT)
X-Received: by 2002:a2e:85d2:: with SMTP id h18mr1945252ljj.367.1591266322725;
        Thu, 04 Jun 2020 03:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266322; cv=none;
        d=google.com; s=arc-20160816;
        b=nSwCImRJKmUULarNbNT8fKqF2OPF8L/+G0nR2T7PDXYnhsXQbwv6n5E4foVe0QzW/d
         kEqlbzxuE0UyjwuqyuxF0M63ff7orSBj3Sowv1VHloO/xtboxJ6FT50CBVbHhd+I7sqy
         84OKrbeYe79ktt+xuKN5rS4txai4eXTpLUAjsa7MJbov/yg8MSxWuaiE09a7mQFRGpY8
         X/87tW20J/NHdWc88tuIsRrgTsdX+T6fsuk2McaSj6M48ut5+lmlZQJqzTIyAc8edOCR
         HTCiPT14V1zceAgYrVxSDw9nQD92zraUz+gxfOPtFaLAJg0z1sCaD9F1GYXDz0zYbEjp
         wmhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=v2OvG7tLuUOfVg0mt6uzXQB9ddwSE7MfPjtV2q2apbU=;
        b=rrFzvgsAc6e9lCbr8UgPRrdHzCiqLB/PV3C5ga9VV96wfIm9S6wLV9UeJISJOMFyhG
         pFtZKarhcAPdWuvxUFFty6UdEH2RA0oyLBznGzNegfGwdveD1NINcpRFIr5+Q2fWYQLS
         LR/zjxkz5xWeJwCwP7gLGP4O3aj2+wvA1/hx6OU3Np5798o1vED1hahSlCekDtHEaSuD
         pyg2jxzgKGoyyo+plQZwvA1qmNKKKruJfPwvQzSnRe5hEI0r2EaN67Iaf+E6a/I81UpH
         /mL5wA1F3yo5cdEWmqFwfkFlIP63DaFmlUSokow9P4FPnHW7z2ERwIc50UcEYS9j8kcb
         /lTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=DsqAMDU1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org ([2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id k6si289720ljj.6.2020.06.04.03.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:19 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3e-0003tk-Jg; Thu, 04 Jun 2020 10:25:10 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0F18C306E4A;
	Thu,  4 Jun 2020 12:25:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id E33F220CB4767; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.193173789@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:46 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com,
 syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com,
 Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Subject: [PATCH 5/8] compiler_types.h: Add __no_sanitize_{address,undefined} to noinstr
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=DsqAMDU1;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

From: Marco Elver <elver@google.com>

Adds the portable definitions for __no_sanitize_address, and
__no_sanitize_undefined, and subsequently changes noinstr to use the
attributes to disable instrumentation via KASAN or UBSAN.

Reported-by: syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Link: https://lore.kernel.org/lkml/000000000000d2474c05a6c938fe@google.com/
---

Note: __no_sanitize_coverage (for KCOV) isn't possible right now,
because neither GCC nor Clang support such an attribute. This means
going and changing the compilers again (for Clang it's fine, for GCC,
it'll take a while).

However, it looks like that KCOV_INSTRUMENT := n is currently in all the
right places. Short-term, this should be reasonable.

v2:
* No change.
---
 include/linux/compiler-clang.h | 8 ++++++++
 include/linux/compiler-gcc.h   | 6 ++++++
 include/linux/compiler_types.h | 3 ++-
 3 files changed, 16 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index 2cb42d8bdedc..c0e4b193b311 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -33,6 +33,14 @@
 #define __no_sanitize_thread
 #endif
 
+#if __has_feature(undefined_behavior_sanitizer)
+/* GCC does not have __SANITIZE_UNDEFINED__ */
+#define __no_sanitize_undefined \
+		__attribute__((no_sanitize("undefined")))
+#else
+#define __no_sanitize_undefined
+#endif
+
 /*
  * Not all versions of clang implement the the type-generic versions
  * of the builtin overflow checkers. Fortunately, clang implements
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 7dd4e0349ef3..1c74464c80c6 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -150,6 +150,12 @@
 #define __no_sanitize_thread
 #endif
 
+#if __has_attribute(__no_sanitize_undefined__)
+#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
+#else
+#define __no_sanitize_undefined
+#endif
+
 #if GCC_VERSION >= 50100
 #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
 #endif
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 02becd21d456..89b8c1ae18a1 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -198,7 +198,8 @@ struct ftrace_likely_data {
 
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
-	noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
+	noinline notrace __attribute((__section__(".noinstr.text")))	\
+	__no_kcsan __no_sanitize_address __no_sanitize_undefined
 
 #endif /* __KERNEL__ */
 
-- 
2.27.0.rc2.251.g90737beb825-goog



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.193173789%40infradead.org.
