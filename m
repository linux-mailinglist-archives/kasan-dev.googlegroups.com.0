Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJU5TL3AKGQETDN5E4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 473561DCF7C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:31 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id 189sf7555676qke.17
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070950; cv=pass;
        d=google.com; s=arc-20160816;
        b=owpwCO0gedcTV+uC3dMt4rNCJdDVXsaDTtDzH3sEKCZ2Vl9hDyGOfbm2DgfGbDc0V4
         sP5EH1/oi4u5BfaesoH2/9HRzOhXMYdvGcE4TXzlo6AudHZQItT7Q2vgqYPw6l/ogt/g
         J7hCplg0TbR7ftgMrPf3ZH3GaZXNZRMKx3xuU5A47JDgUaqZOwJTX0PGQVu8b2VMFbw3
         ZZw4vsVnMK/VBykQEwB2ewGYcQebflhOrTUCDaw5nz9T89o3p+D/zGsfHGNGtFNPrY5F
         NBEdQ5fc7RPxJTxGPxyBGj6oxtQ8rZiANtJxE7c0E7GviWvGfZ5/3J4zFJ9LOO2KRyVd
         yxFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=nT2dQNQ3l9hHDryhkku5sxmxPw2yHUF/4TnBqIEXchM=;
        b=L6qKHSr38p754/6BIb5SLCpCYfPlqYNcxvuSAxyJir8QamiQNFom0OsV2gzco6P50c
         w2IBpNZBbgKJKZxRsr1jcPL1adU80EWam94al+Sv+50vBMEO50ERG/4Bj0Yuw8cop+5N
         yTdP9BUgDqbs3Trd+uNSRAFVfXwAtAKOtQ1BfVGR9POEalfGHRkihJok3azmODSU0hyC
         sX6Fn1PzEkWu79i1rmjdAZSpCYsU/1xBsA9779QRLcGqFhwAAFpK0TyuTk2bLdfHux4k
         vnzSgDNRkrC/DR0x+UkToeoXnVGIGs5Z6Kww5ss0sUEkWnGFgq2giyzLQPZjhAhB8STO
         aaZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZKStJW0o;
       spf=pass (google.com: domain of 3py7gxgukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3pY7GXgUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nT2dQNQ3l9hHDryhkku5sxmxPw2yHUF/4TnBqIEXchM=;
        b=OAJO3c04iJR6fSjlI+4nmnpZ4Br5ftotnnH37hcj7gtaymooINBBN84LDHX0/2r59i
         iafMyW1uyCB9HYA/qDHnPALZfMrnilEtmiB3VgjpXKtwYQ1fIWiI0oS+B3dpOdoWJBR+
         bAPxo5TI1i5dMTk8i/iCtS24xayG49aCAXGhWXnvTJGvfoI/u5V/CpyCT40woz0mfNJd
         P5qSVW+pm83YtfuvXnX9o3AYI1YHJpOM1mCOGO0LhUnsbXM42sSC12HITU5EVhhMhTP/
         d+IWBMLjNgXmlnPJ7VKfakuAEVlvTbhmpu1VJAGl8AKAZPvcZfjfh3OUjKkQG5Ch63L4
         vc/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nT2dQNQ3l9hHDryhkku5sxmxPw2yHUF/4TnBqIEXchM=;
        b=ieBaKSaByctnSBpaNmNwgIVkzGOyyb1sgSvwowO9D/trwORGpkISBYDCOg4xyoFYgz
         tAT0ATeYyGTaNHTrPXBHRYrtYK9yB/vTwMEBuIpmXD+q22DREZGHiWNsnyuxfN60VUmN
         rqKkxriTBpDnR1A6gxva2e79dyLXVceblqpKUPPWgwavihl2m4TOpzfuBAUNVcyda/VK
         OnsqF7pT8UxpdirTSGI9jExPzcu8DllppaZizWdveMVeVeSnG54SRcXOI5LDYC+H9vh+
         UnsW8cZSlap8ZeF9DXwL0ROweCBfrDjhn3TNY4N9y7mwepLGsvSxvSc1bA5gRzFXPAfc
         QzQQ==
X-Gm-Message-State: AOAM532QAcAJ0Px4+xIegw7IRW0OjWf1UeoAVQ09NJkxpZtHlw5vuvjv
	DDhSQhIkqOQf6BA2/ES3sQo=
X-Google-Smtp-Source: ABdhPJw24PnTr38St52uoNr4Cr6Vet1gpEgpVZEOsdNf1rHlAMJD17w3lfdvqX+XZz4FphY8uwnF5g==
X-Received: by 2002:ad4:4cc9:: with SMTP id i9mr10384759qvz.126.1590070950344;
        Thu, 21 May 2020 07:22:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b85:: with SMTP id 127ls689777qkl.6.gmail; Thu, 21 May
 2020 07:22:29 -0700 (PDT)
X-Received: by 2002:a05:620a:2202:: with SMTP id m2mr1748461qkh.47.1590070949826;
        Thu, 21 May 2020 07:22:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070949; cv=none;
        d=google.com; s=arc-20160816;
        b=DUrHigc7fImIF2HRXaQjGwEL05Y9Lq+kjDrAOjU5FZpMO/2/xXWUo1/Ti9lrBPe7m1
         WPACrhvFkoxB2t9Rvfsv4BFeIVsL3Jpl1GFrggM5r1DdqyL2YHraW1Os2NR1b6wzoYS3
         3FRNhp+7t9FrLbzoW/9aAMbwDqFs/54zLliCgfH2M1Df1t5htATwDLHtzCKzN5i9ymSI
         /lFgUKUJyqHfMTEIgZvsi9rdrDVYEAjkzbedkYEc/Nx0rv5eJjmfqw4MIIXj8vPdduEp
         AQUe0Wo4zknsJU3j2sg+LyfdA+nNe+eMxCQaRNeKzoQ9cbUvWGEOIHi9a8Pg6R4YE24K
         kbCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Brlwg7pmXrMxrU6QOfUVrfzRnJMhki/06xHbbYhdDQQ=;
        b=PaptxCpy7mAHCEUIm11KC2litMQx3L+AnsYki/PnRzfL02cmjM1VAqz36fjRUTP6Ac
         1QOCNbqS1xm2vX9nFjPYWkFRI4Ir+3VHkOuuuTUd87dwhAClXKzMINbp2SbGU0U0aYSK
         EDhdAD2szZmN/QpFi0M4yvMcComlrel9P7vQDJHKbnlvVMy+k3d1CTCh6mvqfPS0KxGD
         Xe4dqzxpzsgjAhea5EC0MDx2HbFDfQIBG2iemjpYHFVeILQs4YlfCK/aepG1aZSYzaWt
         ZDaF5vHebFsk+EnJr59kJQnfllPiTlZYjVD6H27iAuwpQSq6ZTNruWaVOxoZlO+mgaZr
         V5QA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZKStJW0o;
       spf=pass (google.com: domain of 3py7gxgukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3pY7GXgUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m128si465306qke.3.2020.05.21.07.22.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3py7gxgukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id m1so5486183ybk.5
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:29 -0700 (PDT)
X-Received: by 2002:a25:3214:: with SMTP id y20mr5166798yby.362.1590070949416;
 Thu, 21 May 2020 07:22:29 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:40 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-5-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 04/11] kcsan: Pass option tsan-instrument-read-before-write
 to Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZKStJW0o;       spf=pass
 (google.com: domain of 3py7gxgukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3pY7GXgUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Clang (unlike GCC) removes reads before writes with matching addresses
in the same basic block. This is an optimization for TSAN, since writes
will always cause conflict if the preceding read would have.

However, for KCSAN we cannot rely on this option, because we apply
several special rules to writes, in particular when the
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC option is selected. To avoid missing
potential data races, pass the -tsan-instrument-read-before-write option
to Clang if it is available [1].

[1] https://github.com/llvm/llvm-project/commit/151ed6aa38a3ec6c01973b35f684586b6e1c0f7e

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 75d2942b9437..bd4da1af5953 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,6 +13,7 @@ endif
 # of some options does not break KCSAN nor causes false positive reports.
 CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
 	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-5-elver%40google.com.
