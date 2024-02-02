Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDUC6OWQMGQEWQGSXRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D097846D91
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:48 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-218edabc073sf1757960fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869007; cv=pass;
        d=google.com; s=arc-20160816;
        b=avYe9Xmr8Tp6qSfpFg9HSqrZL6shV73qdXXl/1q9kSQCCcx4xuS8ndp14uhPgDI7gR
         XLVsxg/6A8WNxOeWKNQtHQ4YhdSCPADKh9OfnbnBshZxDgRj8j8pz2uiQggw9Jo5m5BW
         8aR1ASuCtsn0UjWiGm8butjb0qCA1KscD33dTJ6ZlVyjk+vk17WjBcTqCEgmlTesUzu/
         pzBfRu4ay8VVfHBwoYz5ZzqKQ78EH/rzuCoDB61B4CtTUi4YYyd4EEvdWjAkvEGwd/Yj
         3by1qzyX1AMXv9KPkrwCbWO224tMinAT3IfF94FYNoHey8NDSYTgvEVTkvoCxsuPhh83
         V1Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jfBrcna1HrG8sAxkPkvWLNDwIjoHU6uNEReIltddFkk=;
        fh=nTv4Qkoikgmev5T/Mqv00wrIfExmzsGgLyvaWqT6UKM=;
        b=bxdT8nNy8zCfptdphQ7NHrqtZqQPN0IRfXSGXQ7+ZF8DkBc6BQOKbmbeU51/usTpU0
         ScmrSVeUGnsQdRqNcmLlacfsf0O05LL5wBoBpSuo1TrjUTK9+vmIW0x0itU2QEG4+xSQ
         JYhisWSSNE8JpZmu27r2vyyfwTwnSyNIE+eO8xQxCmh9z+dT3w+iCjYs4l9ksstp/XWs
         mzrIbH12Ua4hVYAVF1Eq2EeOsExdCvyQ5kuA5kKPCyRjjVaegCe7kld7IinNko/bDgJ2
         LTSlmvwC+GXhLZs+QpdWdoLqdsH289c4ez1REaq+rYhkm9B2UJMNI1kX6YQGCI4ufF2p
         9Wsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="SVeY/h/G";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869007; x=1707473807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jfBrcna1HrG8sAxkPkvWLNDwIjoHU6uNEReIltddFkk=;
        b=hr5ys1RavTKjUPi+Ig7326SL+30QM80GqwWEUHWBr2fTEc2I56Z7faYBvCpd30VoPJ
         ngSh0lGzZpHgV8smV8f8V8jWLlvd01PwPVQ9Xm0DjrWZbo9dlk8J7RCxe6PQ/Q+fVIrM
         w2/xH3XufaJbll7xWgKkWGDt6H9IGnClus2eAKEKUaFY45un/hKCtUyPSDeApH1rUwzf
         BfJRv1FCk2He0lyYPgqR7Z+Rrekbfveg1gMBOuZna5Jadrj1C0bMYlsFkMt0hM3sTd6U
         nQLCQn6FfxOYcjCg1SYa15ok1csE5ajyxSrb05v2cjddKYh+pfVW32LKtT5nAq5rSLRB
         74qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869007; x=1707473807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jfBrcna1HrG8sAxkPkvWLNDwIjoHU6uNEReIltddFkk=;
        b=NTdexxkM7hPp2KnWgMnRots6pKw2BOvoKy4d07sV23Gx20UQd7nv5eiV9W5B9XrN7A
         gX1NQ18zTl3Qm9fdSKfr1q490XHl12gkH9bnnPtvQeS82Mab9VISjbpzBtLo9qDaaqH7
         k7LNnaCJYrJuI4W9ZKT6gZ2MxUjdPTfteYHnvloaQx4vFeWiGSgDrKSSLnbc5pfdNfq8
         dmgV8JnHGL1Eyu6CQrn3BG7nULZYFFBl07QQ8muF+GG/nKRgMrTKkWNHzZ9+LndUpPXc
         b+Z6Xlx0wWgFdvIaSRCWYGxTQ+UIAZv6hlF/tSQKUg1PW825Q6d+RCd4x3TQAHxL7nfK
         ipyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzWg4nrd3jofyTYr4XOkLNSG1PHNmwhznTpYNTe4B0z+6NRbu7G
	U74CL9U/TZUo/rBCZVDBzEkTac2+zTgFRChsYJog6t+1F9IymEmT
X-Google-Smtp-Source: AGHT+IFr1n7t22BNzAggzV150lNmsfPsVW24e+SF7zBVudMHQvqeXhfzs32ZqOJLz1chKzcPPPLpRg==
X-Received: by 2002:a05:6870:4149:b0:218:de11:6e45 with SMTP id r9-20020a056870414900b00218de116e45mr6339477oad.24.1706869006864;
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b528:b0:214:fddc:92b5 with SMTP id
 v40-20020a056870b52800b00214fddc92b5ls1365749oap.2.-pod-prod-01-us; Fri, 02
 Feb 2024 02:16:46 -0800 (PST)
X-Received: by 2002:a05:6808:110:b0:3be:494e:9379 with SMTP id b16-20020a056808011000b003be494e9379mr7042519oie.16.1706869006194;
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869006; cv=none;
        d=google.com; s=arc-20160816;
        b=bYKDxK1xsct6j8Cw1t8A+0WRVcT19MrXjcCbX766PpFiL2COOgC9QvzT5t8mHRIsf8
         k0CiZv5kLJ6iMWWvozJr1IYr9GOPbPq9wn0uqPZyGZDP8TB6vBpbF7iSBWjIrSuGulfk
         MpYE0TtRMWdOV+lmtgd9GjWMNvjOYA/srV3ay4lXfM5scTmZjvReMAK7UmSQb0QTDJYX
         /QR4dy3aXrC6rxxlPx6KpMQ1jCq9Ls2uKu7bknLGgRW4JqmesF3K8VFipd2uOQ91efrZ
         KlqjOGJgJFeVrQ1Cz3a6VPCxUxuor0LzJ/C6NmNH4mXhJ2CECO/MzqjUMDQJ8ABPQcJ1
         QZ4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VqHYD682nla/ZHS426F2Ic30I1reUytKpu6/CiCUuio=;
        fh=nTv4Qkoikgmev5T/Mqv00wrIfExmzsGgLyvaWqT6UKM=;
        b=QOpGmrqwDXfBofmFtFbuvRuNAhPm8BrL9XwkY2tenaxUuSVVieJpm+K3rV4RO1XAYD
         tFqbS2acW75SsAjcaI4Y4PS4vMV29vW/TbGcWMO2+Os/UiGzzl+KdoTyYCaiyDkht+NQ
         lfdFurFDh+DGahCFNTvUUlaRMg0LFKdKwwsQ8jJTfYbsKKJPrAY8ICHFtzBv+5N+msmH
         88eyvCRCKEjyJWafzaMM8kN7gEoKTW699ryv9N/Qpl6aXbJF9nkXJXoO+ACp0MsjLEHj
         YoDp5RIv7Qb3nUPcaoDXFkcDfi91xHp6KTZxuPf3kVF0EGUMW28y3eYtu8NR4K0NpUDJ
         sSBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="SVeY/h/G";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCUoZxvUmcTPm/ru2/AG4T9rkAhPlZUOYrgr/Tr/r5VZz+bE2JDq8jRqa9946/7byzcUq2vjs5PvpdlWim1rri71+FHqQjThv7LjNA==
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 9-20020ac85949000000b0042c0768d5fasi15650qtz.2.2024.02.02.02.16.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-5ce2aada130so1740948a12.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:46 -0800 (PST)
X-Received: by 2002:a05:6a20:c70e:b0:19e:4eb9:ef71 with SMTP id hi14-20020a056a20c70e00b0019e4eb9ef71mr1120171pzb.30.1706869005816;
        Fri, 02 Feb 2024 02:16:45 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCUCIEC55517ryfx43oBGCFPd8+5dFYouZiV+CV5D+1pxdT6zQmvhdO5M7/v+v/0+oZ2ZKP7VrQbUgL/+VtcBvzZ9rochjM8ars8Ug9esO0kT5v54cAWR0SHeW4ire1WrcpFdFbQ7SfADox8Xxuh1jWS9wKjvP1bnnGlurfrPhqFs9QRBElWuWefb3AEu1hNKBjI2XxtHG4piQidM2SA6fjrWTt7uKR80kZSYBnGt/pWqyBNpyMmyOT/5d2v62lhhMyJrS7pUdeoQynMwhnOc8nOrPbqdyl4MRtTlrrtDCTufoYgPLWVMS0QmnBG2k+X/GobQNKpih7jbb/I55VHYapZPs3oS7wqBoFtthOQggR6Wr+lxoN4x8xKKwIGyfs3JdsCis24f9SYLTTCP9azwT4ogrQdvnFzfa8+iy3SPzY4RDWbCAFghuVydn2Y33c4hZl+THJ9JDrTaEd4ANQWc6gqumPJ3fQKU/fSJH9aykK/aQ+AenQA63NHiGImFoI9oWyPnzAjr7y7kXVTN7aDJ0nQMth/WEFtVDO7RMZUzMoA982f8aJ0qXSavU4KPEQx75+c+RK1oy3Z8IF94lIN9ED1UJszMvSRYvzaryIPixZ9wmONfyzrZVVHYE39Ac8Zq5CfYfgk8Pg=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id g18-20020aa78192000000b006d9a7a48bbesm1233974pfi.116.2024.02.02.02.16.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:16:42 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	linux-kbuild@vger.kernel.org,
	Fangrui Song <maskray@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Bill Wendling <morbo@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 3/6] ubsan: Introduce CONFIG_UBSAN_POINTER_WRAP
Date: Fri,  2 Feb 2024 02:16:36 -0800
Message-Id: <20240202101642.156588-3-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240202101311.it.893-kees@kernel.org>
References: <20240202101311.it.893-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=6190; i=keescook@chromium.org;
 h=from:subject; bh=NkiEcsGlCZJdDWvQkJb/8yMO5oe0d2E5DUKWEGSWQdQ=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEH83ic3PPh75cmRopeu/CT8AfoDx9L/zyas
 Z3T4rMEfOyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBwAKCRCJcvTf3G3A
 JoHiD/wK4/yqji7UFxhFl81jgo6lzacdRREgM+v/EzDzSlWEk4v/ikFRWbpa91WiN0Qak9XbAnz
 t+Iy1CRNEXFaG0DC2B+fN12n5kGnacf0wuU3362+aaDsSeb7D31lpNZevbRP23nPQs7nce8hyuT
 YNNkhojvoHIcOgH7cK/PtEch2tgM/Rc9uzc/DqE+gcTJY3DgLHfU+T+0O1fh2/Y5t3ZKd10kNZi
 8RfnqVuqRo9MCZ+F0lz/AksQ4rZ0O6GunQ3g1dVnvurEwqGqbhEpH1xL/kfrpQdXcSkB6bWeQ4d
 kaFqttOn7Yxorvdm9nGSsCJTfzsxpS7t0eIxnYmgGyNkTN/pqqGTGM8+1IRjOaDJ1669sBKPq9W
 /VqiRbRr40Yx0b31xtNjMMrbyEL8VjOBBHFwN+gV3PV1uKwk2HBthmmRfpXCn2FU2xjlPWF0+xb
 MP9Rrv3tHCr1rv7aAeUao8KooIiVoWkxUgQC0616IP7k9Hm3LUDvdS5VTxzyXoymxcT9xrkNp8D
 kADO5HIwv09ScgEvVsI++iIGf3x4n/QQO9sY85utNvEGE9KAb5yta4SHxnYjcmYE/7c+YbOp3q3
 nl+gU8NALxVPOeuFNxZeCdqRg2Hc/0QGVjbuQCXLG3yWgDVonUKve5mSxOsioydG3jiIsFLRJFi uVGyAk/WJ7pksww==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="SVeY/h/G";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

Gain coverage for pointer wrap-around checking. Adds support for
-fsanitize=pointer-overflow, and introduces the __pointer_wrap function
attribute to match the signed and unsigned attributes. Also like the
others, it is currently disabled under CONFIG_COMPILE_TEST.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: linux-kbuild@vger.kernel.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 include/linux/compiler_types.h |  7 ++++++-
 lib/Kconfig.ubsan              |  8 ++++++++
 lib/test_ubsan.c               | 33 +++++++++++++++++++++++++++++++++
 lib/ubsan.c                    | 21 +++++++++++++++++++++
 lib/ubsan.h                    |  1 +
 scripts/Makefile.ubsan         |  1 +
 6 files changed, 70 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index e585614f3152..e65ce55046fd 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -293,12 +293,17 @@ struct ftrace_likely_data {
 #else
 # define __unsigned_wrap
 #endif
+#ifdef CONFIG_UBSAN_POINTER_WRAP
+# define __pointer_wrap __attribute__((no_sanitize("pointer-overflow")))
+#else
+# define __pointer_wrap
+#endif
 
 /* Section for code which can't be instrumented at all */
 #define __noinstr_section(section)					\
 	noinline notrace __attribute((__section__(section)))		\
 	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
-	__no_sanitize_memory __signed_wrap __unsigned_wrap
+	__no_sanitize_memory __signed_wrap __unsigned_wrap __pointer_wrap
 
 #define noinstr __noinstr_section(".noinstr.text")
 
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index a7003e5bd2a1..04222a6d7fd9 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -135,6 +135,14 @@ config UBSAN_UNSIGNED_WRAP
 	  for wrap-around of any arithmetic operations with unsigned integers. This
 	  currently causes x86 to fail to boot.
 
+config UBSAN_POINTER_WRAP
+	bool "Perform checking for pointer arithmetic wrap-around"
+	depends on !COMPILE_TEST
+	depends on $(cc-option,-fsanitize=pointer-overflow)
+	help
+	  This option enables -fsanitize=pointer-overflow which checks
+	  for wrap-around of any arithmetic operations with pointers.
+
 config UBSAN_BOOL
 	bool "Perform checking for non-boolean values used as boolean"
 	default UBSAN
diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 84d8092d6c32..1cc049b3ef34 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -56,6 +56,36 @@ static void test_ubsan_negate_overflow(void)
 	val = -val;
 }
 
+static void test_ubsan_pointer_overflow_add(void)
+{
+	volatile void *top = (void *)ULONG_MAX;
+
+	UBSAN_TEST(CONFIG_UBSAN_POINTER_WRAP);
+	top += 2;
+}
+
+static void test_ubsan_pointer_overflow_sub(void)
+{
+	volatile void *bottom = (void *)1;
+
+	UBSAN_TEST(CONFIG_UBSAN_POINTER_WRAP);
+	bottom -= 3;
+}
+
+struct ptr_wrap {
+	int a;
+	int b;
+};
+
+static void test_ubsan_pointer_overflow_mul(void)
+{
+	volatile struct ptr_wrap *half = (void *)(ULONG_MAX - 128);
+	volatile int bump = 128;
+
+	UBSAN_TEST(CONFIG_UBSAN_POINTER_WRAP);
+	half += bump;
+}
+
 static void test_ubsan_divrem_overflow(void)
 {
 	volatile int val = 16;
@@ -139,6 +169,9 @@ static const test_ubsan_fp test_ubsan_array[] = {
 	test_ubsan_sub_overflow,
 	test_ubsan_mul_overflow,
 	test_ubsan_negate_overflow,
+	test_ubsan_pointer_overflow_add,
+	test_ubsan_pointer_overflow_sub,
+	test_ubsan_pointer_overflow_mul,
 	test_ubsan_shift_out_of_bounds,
 	test_ubsan_out_of_bounds,
 	test_ubsan_load_invalid_value,
diff --git a/lib/ubsan.c b/lib/ubsan.c
index 5fc107f61934..d49580ff6aea 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -289,6 +289,27 @@ void __ubsan_handle_negate_overflow(void *_data, void *old_val)
 }
 EXPORT_SYMBOL(__ubsan_handle_negate_overflow);
 
+void __ubsan_handle_pointer_overflow(void *_data, void *lhs, void *rhs)
+{
+	struct overflow_data *data = _data;
+	unsigned long before = (unsigned long)lhs;
+	unsigned long after  = (unsigned long)rhs;
+
+	if (suppress_report(&data->location))
+		return;
+
+	ubsan_prologue(&data->location, "pointer-overflow");
+
+	if (after == 0)
+		pr_err("overflow wrapped to NULL\n");
+	else if (after < before)
+		pr_err("overflow wrap-around\n");
+	else
+		pr_err("underflow wrap-around\n");
+
+	ubsan_epilogue();
+}
+EXPORT_SYMBOL(__ubsan_handle_pointer_overflow);
 
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
 {
diff --git a/lib/ubsan.h b/lib/ubsan.h
index 0abbbac8700d..5dd27923b78b 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -128,6 +128,7 @@ void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
 void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
 void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
 void __ubsan_handle_negate_overflow(void *_data, void *old_val);
+void __ubsan_handle_pointer_overflow(void *_data, void *lhs, void *rhs);
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
 void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
 void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 7b2f3d554c59..df4ccf063f67 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -10,6 +10,7 @@ ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
 ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
 ubsan-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)	+= -fsanitize=signed-integer-overflow
 ubsan-cflags-$(CONFIG_UBSAN_UNSIGNED_WRAP)	+= -fsanitize=unsigned-integer-overflow
+ubsan-cflags-$(CONFIG_UBSAN_POINTER_WRAP)	+= -fsanitize=pointer-overflow
 ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
 ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
 ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101642.156588-3-keescook%40chromium.org.
