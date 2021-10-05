Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPXA6CFAMGQE3R47CKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE0C7422427
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:15 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id r4-20020aa79624000000b0044b2d81afd9sf10870695pfg.4
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431614; cv=pass;
        d=google.com; s=arc-20160816;
        b=cdv8DMB1nQZC+n8B5kpQlhWH5KV6T0uRAshQ2BXJbdBRrL31iM3jcbhbLNY1psg0ep
         lhbjH/r9PTocs1tJg1ibxyqOSCpMkxD9F2/AEt7c6XLmXlWybPDjtaxBWdBesAX+RpOp
         8Kg9O/u9Yc8/vMeT+szcyUsgkUYsAHuKjtL8LezphRnW3NDBjXRFBXXgfKv0WCn43uDK
         B+SjNBxLS8QIwEbbj/0pKgQJqILkTEDbeirdnJJGj+eqURGWAKhAhusfNIKDLm8trMrl
         c1fIGIc1tprSIiSWF80lfPuFV0J0hNSIK8B2vJirN33Um7CIk6noamALKeJdMoDIUJAg
         3vqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=akgI2xlxqa6rFILYOayVP2wtUviEyUdQ7npGbcqOeBY=;
        b=LnzrLrn8goAX//eqi/CDf9Qmrx8FqcxuEvDam0CUYvRiO8Dn2EFjkUi0dMnFbbW9UW
         YT3bo8MbIO9K+FfyHUUrZvahywKXIZLlGerNjMnJgdw9XecKPfRZPYXWFne8gqycBRMi
         9HRcHNkPT4w/0mfZKkhA4ZYypl8JH4phb+voO4fnSuc1ak18woBPknWYl8S/Z9gHRi+R
         S3Gu4BLbJCoRIV/0zRgUfwaXABgPdleMpIAyIVVFs6cfFWe70O5W6hBgUzIlP/0XLXVU
         HoISa6ivcfIDTeorfLhStb5p9sNe6LX5KdxzDzMJ+azRod/lTvNWMX87vJQPuX7ZOipt
         uthw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="p1/pKdO+";
       spf=pass (google.com: domain of 3ozbcyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3OzBcYQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=akgI2xlxqa6rFILYOayVP2wtUviEyUdQ7npGbcqOeBY=;
        b=WZJ8hdqtubM62m6EHssOxVyF+QOLmfZAmz5tspYDXrSUDSjyAiatdoI5RpORy5vhLQ
         8fXxvWc6S2D+aF68HoWMJrSOBhCfBXo5usxSmdBwS4S2MjcTFi6DZpujlLNsDAiZ9v6m
         q0Zv2k8kkrZ9180PCXdTj2uOI/C1aYDGSqRcSKHAI3A+xnKmUIpadgmI6Pf6Mbk4I79G
         Flpr8LXKdThcFa4sGG5GGhgV8fT5ecGIS4WJCR9GzL3QW4zIXfWgjRasLSjQg1o/ClgO
         3hFDhvlYAYWp+6qnnGBo4oA+GUZViztbOJs2D9nHbVwdQNWN0HxCggkj9rROnC+FAZuP
         /Rmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=akgI2xlxqa6rFILYOayVP2wtUviEyUdQ7npGbcqOeBY=;
        b=Os/LueclnZZ7NqfzJcCAG7+/GhZG1bT1LaRHASZeDXl4C1Vl5iU+79nZAx20+26L71
         aoCXXwe+3jv5ZUXJVvucyC3GwaMY4enNVzpzJbEUwP5VQM2+/lV0wLghEPpcRTCE7rUD
         Euz5FAHes5E1kyDI3XHfFIaTMaE0KnMwh0IkuhOI8+VlUKS2NuzcYFLm1uVModWm/yw0
         37qxQnsCBUfrZGi7Us+LpbWCU98LHg7YDl6mm83WSInlbRtlsww1VHcZBlyqnQNa+jH9
         DtF61LH2bPR9D+MOO0auI64i+tVb3Znl9UgdoCeVpzCx1ntrc/9+cIVpUPBmIvUeJaYI
         q6QA==
X-Gm-Message-State: AOAM530ZhIusLInz8T07EZoDb9oJU1mqnJo46E0IX7IMaLvstHOrzJKU
	zct3KYxRjqLWwpTTlDvIIVg=
X-Google-Smtp-Source: ABdhPJzz1vHR6+bkS7buX5BsP2acn6VAvI/3lTHevWk/co0dl+fautOb+gTk0YQRW4Kw846dTDgENg==
X-Received: by 2002:a63:d205:: with SMTP id a5mr14854108pgg.30.1633431614623;
        Tue, 05 Oct 2021 04:00:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:de07:: with SMTP id f7ls7634471pgg.10.gmail; Tue, 05 Oct
 2021 04:00:12 -0700 (PDT)
X-Received: by 2002:a65:6187:: with SMTP id c7mr15189964pgv.317.1633431611951;
        Tue, 05 Oct 2021 04:00:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431611; cv=none;
        d=google.com; s=arc-20160816;
        b=XSAH3qsn4u8FGXk1dqwxmGmpPhEsGi9mvCWakwHbB5+8URXaFI3Zn9t2YGprLsRfBx
         psvncIrA5YZ+uyEHAvvg/TMHxEsg7NCA2ezLEgYtgk/bBqr91SfH7eog/fydRXUOxCMg
         MuMXn4jg7xI4Hd0cKRciUXAP7G+4LY6i0HVa0zFVka1LyCkASv+I9f5kP0g15Tmq5lsC
         pakGsVJb776yjhD5U59+aDPUMJwjMqJeSUTahAXaVOKleGYpBC5OCU5du3/K+DP7Yh6n
         aIiU6OLqihaL4Ts0SerPt+MH/RlHndYhQHbNxb++Qc9M9MPOG3inzcy96mrLZZ/Fxhs5
         jMhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qua6hkgX1DqgYC81lcf9MuNL3xFoQ65uNHSjN4wVu7E=;
        b=xV90lOZihY7K+5N2iWZ2k0XAo2Ct5xbm0XOXYZPMs4njxQkqYWf7xmVXQG3i7DLHI2
         eyfx8wd+Km+oScJdnrOWjCPfwA7q/FB31jInzBjVshwwLrJPfRIreZNg5GPs8qXpMCdf
         ccyEfkCagvJdJ6SEtkmdpuNq32uzFGADzrgJkvm3ZsSKIf8omQvFa99eEmRTNkDDXZYK
         kZ+yytvjdVbv+wxTJmFvDxzpPmsXi0/RjfrYT/LJgEr651kTuOiIR81ozT5o5ZH8BOt7
         HddqZ2o+X6GQfWhUKjWfLBs7ROMkKcBGvFTAxgu0Q5XiPeUeDPbfc4XwnNNcuev60fyd
         kr6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="p1/pKdO+";
       spf=pass (google.com: domain of 3ozbcyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3OzBcYQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id a69si839998pfd.1.2021.10.05.04.00.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ozbcyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 90-20020aed3163000000b002a6bd958077so22834481qtg.6
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:11 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:1083:: with SMTP id
 o3mr436313qvr.57.1633431611175; Tue, 05 Oct 2021 04:00:11 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:54 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-13-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 12/23] kcsan: Ignore GCC 11+ warnings about TSan
 runtime support
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="p1/pKdO+";       spf=pass
 (google.com: domain of 3ozbcyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3OzBcYQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

GCC 11 has introduced a new warning option, -Wtsan [1], to warn about
unsupported operations in the TSan runtime. But KCSAN !=3D TSan runtime,
so none of the warnings apply.

[1] https://gcc.gnu.org/onlinedocs/gcc-11.1.0/gcc/Warning-Options.html

Ignore the warnings.

Currently the warning only fires in the test for __atomic_thread_fence():

kernel/kcsan/kcsan_test.c: In function =E2=80=98test_atomic_builtins=E2=80=
=99:
kernel/kcsan/kcsan_test.c:1234:17: warning: =E2=80=98atomic_thread_fence=E2=
=80=99 is not supported with =E2=80=98-fsanitize=3Dthread=E2=80=99 [-Wtsan]
 1234 |                 __atomic_thread_fence(__ATOMIC_SEQ_CST);
      |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

which exists to ensure the KCSAN runtime keeps supporting the builtin
instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 4c7f0d282e42..19f693b68a96 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,6 +13,12 @@ kcsan-cflags :=3D -fsanitize=3Dthread -fno-optimize-sibl=
ing-calls \
 	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=3D1),$(c=
all cc-option,$(call cc-param,tsan-instrument-read-before-write=3D1))) \
 	$(call cc-param,tsan-distinguish-volatile=3D1)
=20
+ifdef CONFIG_CC_IS_GCC
+# GCC started warning about operations unsupported by the TSan runtime. Bu=
t
+# KCSAN !=3D TSan, so just ignore these warnings.
+kcsan-cflags +=3D -Wno-tsan
+endif
+
 ifndef CONFIG_KCSAN_WEAK_MEMORY
 kcsan-cflags +=3D $(call cc-option,$(call cc-param,tsan-instrument-func-en=
try-exit=3D0))
 endif
--=20
2.33.0.800.g4c38ced690-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20211005105905.1994700-13-elver%40google.com.
