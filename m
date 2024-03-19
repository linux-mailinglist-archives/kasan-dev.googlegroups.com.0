Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMP642XQMGQELGIJANY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 93846880276
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 17:37:06 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-60a2b53b99esf124174477b3.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 09:37:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710866225; cv=pass;
        d=google.com; s=arc-20160816;
        b=04DYFHwlyTyxIAb/gyp/sHV2WDhM2MuG03uYr64hjj1ia9uRR1sRsL9cgB2CNtd+JQ
         HHISkQ+UrJE2OHUGL/vMrpCoyOrqpKKiIag46f9KrE84jz8Q2eePv2KCZkWs3+3MuTf4
         0D4Q6EsHeXNHnpiXiIH58frDQLBlwoH5kXQwCtR3tK3wveM9hJEgLRIK7MIBPtjYHanW
         PkiQg+9nmgtzvMShY8ght1oy9QC9t7LOYi5mgj9VkPy5OAb5u9p1DUqvQ/VvGPbYJLKn
         qG1UNJJF+YwdYbBuzkuaeFlrIPRNqo74hNTNJQxLHrbe8Vvo+rQGuO464nMYJD+WhKDn
         hU5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WPWQ3Pasx9ACdxZ8E/2KuIo1bce9IqwWOVo7JAEpzQY=;
        fh=VkfpEW9nwqV6WihCMRdShHKo9sjvzUkZ2FHdlI0Zfyg=;
        b=TeAbfkHfA8Dwx/y6LcE2GqgoLcOqhwJaZh5Xo9rbFUpSneh5vHPpL0bF9drgiYMc8C
         WQbp7uB6mjWXpVHwPHjOQtbL2Mp4r+wmC/fkixfY4ikenuUF06eJZzfnRRzoutCbSTsw
         diBCv4KOhBZLx2+f0/5ReZAzHJZnRGTh9Y2NgJtlO6D5L7n7xWUC4RJs5wLGB+jszHpB
         v6QXjBZRnblTaHsIpV8ouqmwOFlxpHJMga+vz6cXdyljPMWDJU8mi1INEOTMc1Cgs/x3
         +lw/PiCu4YYKEYBsAM0mTJAVh1jLlcGMPRvb4xiY1LINIGIcsnKb/69xc/ZGXICFuOgf
         ORaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xtc7jwO4;
       spf=pass (google.com: domain of 3ml_5zqykccsx2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ML_5ZQYKCcsx2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710866225; x=1711471025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WPWQ3Pasx9ACdxZ8E/2KuIo1bce9IqwWOVo7JAEpzQY=;
        b=vPAyM8GMGV+CmwlA/teB4njapluhGq/RUolO7m4s/+bZtPKXDiHzskCiRU2dWANtiO
         AIDL7bmvtwf4enl4CX0BI9jN77oYTB/61hznxvhxMWtUW3h0btwp4Ay6TpyHYpXefMZl
         0JuW5o4hsWsZ2wZBG7k933AITpuf5sJGiNb4h4lHUybd7psBQwE81TYLgfNYvsWOX8Pd
         bAa5n+F2nwCO5M7mMRuGVIixD1rj8vbFlsZ3dKZKbV63kNQRiIijtpiwEDAGAo4aKAkj
         pBBmBTxcZL59+qLOBxsrmlHlFKLZiOkAEWY6l6Weu6LnqhvtMuBEyS2mdODb//o0bhZJ
         oQPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710866225; x=1711471025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WPWQ3Pasx9ACdxZ8E/2KuIo1bce9IqwWOVo7JAEpzQY=;
        b=kZcmLyXtJ12LmRfVYzzCHzTomblPDTpNZdgSC/S8rb7zWYtV7GNw7w415L3YQjTTbI
         fF20nqpDezkbJidld3HBys4xAfqw/s7BWyl6Biud3PJQLyDH08gjxxOSQ+ImUBnDp6Vp
         XhSO0A92erc2v3kBLFYtIPBfqWZKhYk8Ffjeo927FLY12Y0QyzE8zGkxSId3BKwMp2cm
         Orl8L9gYHf5imNJsFi3e92lj1MHD0NQikKTOXD8f0D0ATIB3L1klXF1yb9caU6kn5l0X
         s8bhncjWDIXHtoYOs65tTrvidSnRmMTpA9RgvQAizM0SypKp9JoN8xq5HJbyFwW0m0JA
         T2NA==
X-Forwarded-Encrypted: i=2; AJvYcCWXbhKZMj4CNSGIKT+HrPlguHNuRSiKVG/reflcbbw9sVQHliaZVWWJ0TyuIjoO4z0qWyh6HH8Q9q+i4rwzpckXFpvowcsb+Q==
X-Gm-Message-State: AOJu0YxebAGa/tOjAqQvdhlwJp59s5z3J2wgjHKGG2BmgMsddKu5Zu1Y
	o8LyqSKloBpYvULhqYRsN0oSOMoY2woPPhB33WLHzXxLa8q88bnn
X-Google-Smtp-Source: AGHT+IHFtXEyo3fJlD3uFqTu8O9Hi6v7oYKISLleswqc3XC69zHlaOc5Ej7Cty38Kt0l7gkTUHdaDg==
X-Received: by 2002:a25:2613:0:b0:dcc:245b:690e with SMTP id m19-20020a252613000000b00dcc245b690emr11057362ybm.40.1710866225226;
        Tue, 19 Mar 2024 09:37:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b30d:0:b0:dcc:be89:34e3 with SMTP id l13-20020a25b30d000000b00dccbe8934e3ls313889ybj.1.-pod-prod-05-us;
 Tue, 19 Mar 2024 09:37:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcQn21PDW55BsM1nvGzKhUSqOn9SrZ9Isk9hG5Gr9HIql564dXsNqlMzI6waYwmNC6Zez54N5zb43SeAO3fkgF/wPAri32D5MABw==
X-Received: by 2002:a5b:543:0:b0:dc2:3f75:1f79 with SMTP id r3-20020a5b0543000000b00dc23f751f79mr10986104ybp.23.1710866224503;
        Tue, 19 Mar 2024 09:37:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710866224; cv=none;
        d=google.com; s=arc-20160816;
        b=0apu8OSv3EL6VZnd80B4uMqswjvkdYAZQ2gZJNuuozr9ou1sPd9j9nB24HOgVEBL0w
         aII1UoGjk0Np6eFapuiOWC4jf2IaQBvCeiRpVMlyDtevLpZPdu3+KHg0PSjHnDCdjwRb
         Twxim4Ij7/+FJQMA/IEd7BTAda/144Rj65esX5f0cqp1mrQroAWjIn2G1EmnykM88JWl
         qIaZjxU1NHr0XiDLUmxGDbscz2GkDuuUy4XFfsN5mHyU5kFJL3X20BGvdB9Qojja8HFp
         WJvSxBNAZa8cQcHktuNqVvp+W7Gh4oHpUcQvW5B12Ium3vhkavNQpWbH59uzgQv+rTVv
         lrRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=k4w49nfOoRyLntHEj6xF46Ct9MhFoMry9itEqGksxZs=;
        fh=HyxIai50qYUJS6gLDiO9MQwwQEpBMp89NVroa3J5AZ8=;
        b=iOheuNSZ6hudiMGXpyJASQ3RGOWwzVNloDeC4ffu8aMS0rHkVzLSmtb1YLwsnej9dB
         FV63/P/Ajnqee9rmaH4C2VpxfM7YUAB0tLI2utKAakaMOUG6i0C1D+hEykp4Ivw8oJhd
         PZ+y6tjpEnzNI6NNCfGvy1xeACwux4aSxpsd30r+JiPirBLPFg1tLb7nxL4r4Z3pnugP
         CaiqX2pS5vCs2GaLpRG7+wMuJQqgMiNop8NK4kzyvHpOajWsTUtkkIdHi0bFQkt4egfW
         H+DIC9pfTXh2U9euPvZWTZ7HAHlo+j3MAIRS7tOeejWjEwZwof6xJ4oqVFjERi2O0TVP
         Gppg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xtc7jwO4;
       spf=pass (google.com: domain of 3ml_5zqykccsx2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ML_5ZQYKCcsx2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id y22-20020ac87096000000b00430c0f89cddsi616020qto.4.2024.03.19.09.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 09:37:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ml_5zqykccsx2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60cc8d4e1a4so109045817b3.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 09:37:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWuv5bQMvwcaN1PxzYsdacs9ZM2y4wltshUTna+iafWeIqHgXToEGUANvzqwRPByPd6spO3TYE2jjUTG5UgSG1o7sXS0SFvnx80vQ==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:2234:4e4b:bcf0:406e])
 (user=glider job=sendgmr) by 2002:a0d:d413:0:b0:60a:3d7e:2b98 with SMTP id
 w19-20020a0dd413000000b0060a3d7e2b98mr825284ywd.4.1710866224161; Tue, 19 Mar
 2024 09:37:04 -0700 (PDT)
Date: Tue, 19 Mar 2024 17:36:55 +0100
In-Reply-To: <20240319163656.2100766-1-glider@google.com>
Mime-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240319163656.2100766-2-glider@google.com>
Subject: [PATCH v1 2/3] instrumented.h: add instrument_memcpy_before, instrument_memcpy_after
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xtc7jwO4;       spf=pass
 (google.com: domain of 3ml_5zqykccsx2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ML_5ZQYKCcsx2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
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

Bug detection tools based on compiler instrumentation may miss memory
accesses in custom memcpy implementations (such as copy_mc_to_kernel).
Provide instrumentation hooks that tell KASAN, KCSAN, and KMSAN about
such accesses.

Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
Signed-off-by: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
---
 include/linux/instrumented.h | 35 +++++++++++++++++++++++++++++++++++
 1 file changed, 35 insertions(+)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 1b608e00290aa..f5f81f02506eb 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -147,6 +147,41 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
 	kmsan_unpoison_memory(to, n - left);
 }
 
+/**
+ * instrument_memcpy_before - add instrumentation before non-instrumented memcpy
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
+ *
+ * Instrument memory accesses that happen in custom memcpy implementations. The
+ * instrumentation should be inserted before the memcpy call.
+ */
+static __always_inline void instrument_memcpy_before(void *to, const void *from,
+						     unsigned long n)
+{
+	kasan_check_write(to, n);
+	kasan_check_read(from, n);
+	kcsan_check_write(to, n);
+	kcsan_check_read(from, n);
+}
+
+/**
+ * instrument_memcpy_after - add instrumentation before non-instrumented memcpy
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
+ * @left: number of bytes not copied (if known)
+ *
+ * Instrument memory accesses that happen in custom memcpy implementations. The
+ * instrumentation should be inserted after the memcpy call.
+ */
+static __always_inline void instrument_memcpy_after(void *to, const void *from,
+						    unsigned long n,
+						    unsigned long left)
+{
+	kmsan_memmove(to, from, n - left);
+}
+
 /**
  * instrument_get_user() - add instrumentation to get_user()-like macros
  * @to: destination variable, may not be address-taken
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319163656.2100766-2-glider%40google.com.
