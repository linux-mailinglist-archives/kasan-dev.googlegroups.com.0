Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6U5TCGQMGQEANQDZVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 07AAE463302
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:46:03 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 201-20020a1c04d2000000b003335bf8075fsf10324429wme.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:46:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272762; cv=pass;
        d=google.com; s=arc-20160816;
        b=gSHtSnagk/JZzH/v+6vZINI9UWP4GuuhtWu9f07QmjNW96o3Z2gdeokrg5klwjEuFE
         zPK0bbSzbp9kMz36OzYNA62ABXPVIXaf4rAcU/jBdiDUz+c7K/m8ShvZer82JeikHAQS
         0rng1EHopApHc11RkKxhJuIH48mzWQJb7JDoNq1jP7dZR2WUEK+x79Xhks5t7jABOJhD
         axGCSnZOMIojJnuKqUsGaX3EdmSA/S6CPU7jekVBHALoyJ54TsjzQhogPke0lYrYBt8h
         rh+SByfeVz+0iWIDfSTXNginJ9HI2R9VPKFtelWjySM9or3WilROFtZOTv2kA/VPf20J
         P9Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=gr9yJaviNzSXdAHPrIZ3gKwCVFL3VQaBfWF/6RMfj3M=;
        b=vPfMxoPgxlawtG+Z2+hPLfY1CpzoVttEqZf3jROID4V43UXEZg6szNL2I3AhlbDKRp
         NOIHxRGj/n41GuivLF9ha1qRQ1p67/UIijSjlVgVMaZ0emtrsn9yTYkyKNDdMNkJikCN
         uvXlxQUkKvH9nFHHspa6wB9SW/fpDGBF+t3n9uyCvbVycf/CDIPzeH/r7TY2kDDaCCpV
         PiTlsP2NByDl8IRObc/t6G/uQx0s+ONAxcc8SvuXo+gieI4M71V4BuPyvjbcAft/iZUP
         AMsuDagHv1QR3R27jj5sEXl4bnNePXm6vELK2TeBIo/cXMqyMmRPGjibyQGdI0wYFLlB
         ByTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ZydYBw/E";
       spf=pass (google.com: domain of 3-q6myqukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-Q6mYQUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gr9yJaviNzSXdAHPrIZ3gKwCVFL3VQaBfWF/6RMfj3M=;
        b=Oci6nHd7XQdpcOS/ZeCHsafdHRQm5fN5DNtWFt87+gBBalXoMNRp8xfmI0OL7Gzd7i
         Lq+D7EQjSCkDEXC4/q9qvIG3YI2JT1QgjSmOcij2bOVRHNqM2fmLN2rCk3jg5iJFsL2/
         MJ8ArB3CoElRkVJnnMDSHsuAVVVVjrQJ4X97yWPyMNHwOz1pXY1GzBwhYJ9/MK6F/ptW
         ymTwLfDoQIZ774EWCH5STezUSTtKRx4iuem0GHfGg55WSImk5G2ZbdXT3Urm7ZScPIdx
         Uchn+jnu+a2vBLRIcveCpF+iLhiz6bc7ImLA9Hx5Teg0hlRb5FZU62o9x/z59ND3Qx26
         kYmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gr9yJaviNzSXdAHPrIZ3gKwCVFL3VQaBfWF/6RMfj3M=;
        b=BJrzQy19/+Ew17rRZyy4F9TYMPCqF6wGleOc1RFLvuB05LrT/hKl0FT/V7eDvzmZkn
         8eEFLbyus6xfN8H4r6UF5VIvsX7gv8/J71FwYw875VQp9qaSbWWcyVKNkpdfCm9npECX
         QrASKHeI96WWP0wTQvHV1KaPGwSS0ANlmLUgnnlj+A4x5b3lyBv8vnu2uJhccuDw+6JE
         BsdFobUzrc7GJ+avh5ul8Rpby3Mgq375IrI3G/hnYD35oXONBMJ8hIzyNfl8JYh8paRv
         oo7Q8jLJ21TxYHJSi670/c/Qop1vTJc6JCyQoLbbUSXbWe2E9keU1KH0Uhkh4Mzv9O0b
         8O6w==
X-Gm-Message-State: AOAM5337JOt0oOsdVYcsr1QFV0KECr5EqIdQpK2SD5/fuyyDy9ZVkmPQ
	roGQjvruXJcI7SK1KG7+mvo=
X-Google-Smtp-Source: ABdhPJyhk4NfLWlq/r+/6NY6aUfalQT5qK5oA8UYCaYSaBxDyyODmMIvi1ij+r2q9PtJXx4ok7m8Aw==
X-Received: by 2002:adf:d22a:: with SMTP id k10mr41108625wrh.80.1638272762799;
        Tue, 30 Nov 2021 03:46:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls13085240wrr.0.gmail; Tue, 30
 Nov 2021 03:46:02 -0800 (PST)
X-Received: by 2002:a5d:6886:: with SMTP id h6mr40914128wru.287.1638272761935;
        Tue, 30 Nov 2021 03:46:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272761; cv=none;
        d=google.com; s=arc-20160816;
        b=hnh3cvlszUnEpu64LlWsAZdhWOChqHkqoRGnAUG4i3Za5DNpr+mpO55ERi10K2/+8J
         90e2plkFh/UP+L0iZxuz/D87JDiEujkdFp5lrqDDLQsZn8ePujzWQEj5aUgNe/FQNvmg
         jSdM6SrNUsAq4Z+7nkOQ2UJXR7EqGNn3zHheiOR9Buj6z1SGS5+wiGTjOGsMJcX4PNfh
         Bc8J5j+I0m47dhULgpB6sVaWixvNLHdrRoB79ABqukn9ZotS+kCrVOazwYnvAueB+eDy
         DrskvvWApvJ9m6ZsifNJRWUCGjNkzuZzy9PM4GAEnkxHiPDDsgHt4NHqMI2cOerQO2H1
         qjfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=hHpI+TkJP++fcdc46vUsOPoUrJOI1E0VxBDtAT4JUtM=;
        b=auaSCoXWoGfQIR/6B6DaEaDU9hXfyQnOE1oaZ6AEZzJAjo2ycg0sOKwyMKlAXdC/wa
         kVuAFz9C1GDOhpW2HrIF5h29QJbQ2/x0FqDm/GJhcgThn/97VmAKycEFry8vgH7qxObQ
         M/nCh9NFleENIdlHLlmWsDt9WGpy2UfzeNc1FqeMBa4EAbnVGIo52a9eI636rh7cFFL/
         3uXL/tETv/p9EEhvjZgkH0qQhjl0w+fITzKQP0O6BWRORExPN6+6X/rP1VMk7RqGxO1i
         C4H7w+ese0D8yVTGD+Toyi0subb46/EdzHwD6/vK0wWKchiNC97mwSK6CPMbtWyesiGN
         q4kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ZydYBw/E";
       spf=pass (google.com: domain of 3-q6myqukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-Q6mYQUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id o19si341912wme.2.2021.11.30.03.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:46:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-q6myqukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o18-20020a05600c511200b00332fa17a02eso12697787wms.5
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:46:01 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4e07:: with SMTP id
 b7mr4217301wmq.16.1638272761639; Tue, 30 Nov 2021 03:46:01 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:32 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-25-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 24/25] compiler_attributes.h: Add __disable_sanitizer_instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="ZydYBw/E";       spf=pass
 (google.com: domain of 3-q6myqukccimt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-Q6mYQUKCcImt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

From: Alexander Potapenko <glider@google.com>

The new attribute maps to
__attribute__((disable_sanitizer_instrumentation)), which will be
supported by Clang >= 14.0. Future support in GCC is also possible.

This attribute disables compiler instrumentation for kernel sanitizer
tools, making it easier to implement noinstr. It is different from the
existing __no_sanitize* attributes, which may still allow certain types
of instrumentation to prevent false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* New patch.
---
 include/linux/compiler_attributes.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/linux/compiler_attributes.h b/include/linux/compiler_attributes.h
index b9121afd8733..37e260020221 100644
--- a/include/linux/compiler_attributes.h
+++ b/include/linux/compiler_attributes.h
@@ -308,6 +308,24 @@
 # define __compiletime_warning(msg)
 #endif
 
+/*
+ * Optional: only supported since clang >= 14.0
+ *
+ * clang: https://clang.llvm.org/docs/AttributeReference.html#disable-sanitizer-instrumentation
+ *
+ * disable_sanitizer_instrumentation is not always similar to
+ * no_sanitize((<sanitizer-name>)): the latter may still let specific sanitizers
+ * insert code into functions to prevent false positives. Unlike that,
+ * disable_sanitizer_instrumentation prevents all kinds of instrumentation to
+ * functions with the attribute.
+ */
+#if __has_attribute(disable_sanitizer_instrumentation)
+# define __disable_sanitizer_instrumentation \
+	 __attribute__((disable_sanitizer_instrumentation))
+#else
+# define __disable_sanitizer_instrumentation
+#endif
+
 /*
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-weak-function-attribute
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-weak-variable-attribute
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-25-elver%40google.com.
