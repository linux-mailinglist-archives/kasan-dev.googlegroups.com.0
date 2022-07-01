Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYEG7SKQMGQENKKD2GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8329C563509
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:29 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id k6-20020a2e9206000000b0025a8ce1a22esf494716ljg.9
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685409; cv=pass;
        d=google.com; s=arc-20160816;
        b=uZWY+zu79VP9R3SXKuotYe+hwM1ZfpJ3Ym05mi80iPMVtABajR/oxuADQnkICjTbci
         lhs4iKY7aSPZ9VdKzsoaf9k4ijeGkFeaRjT6P84w2QHIi5ZRVSa3cafn8YHJ3KWZkh4K
         lZ1EPVsEGTx1fj0nqjOh5aiZ5gCkeCn9PIzNErpTmF7J6e1Tg+tLVJDnoPMKgAlJ8LlU
         wnTsFjktakAr7TKnvwoFfBjimWVjkRE6ipaD/SyO7BGi/ufDhKl1oEVdxSRpS5KigS8i
         CDkYHM009Yx3C95o2paRCyYAsXLfp4j/pIe+Bpw/0TTigamETSjlpJtZXIKp/3HqiMPR
         Gypg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5aJ/nJDus8CvWwsEg9LHWP+2DWw8M4gHGmjHowUVSE4=;
        b=IkZUlCOC2hHq1sioGtut9G4430OE4shJUzoTvmPxTzX+jG74htqYWzEIsZZJf19Ci3
         aThYAwGyShs00oOXnl6XsLdt5mSiO58MRvfrwrwaWC/3Je98y/x8XuMU0w5syYDixqIF
         Qwznau7DFin5udNB9z7Iyo5//BuUqVxSeIuqJyLJq51kSFVK6Op62sJFOWJ3GXxGSgCk
         LS2MvLo5xlzjfwH+iDARVA8LYjw/0OCbJ8sxI9+9sezs2T+Z85SQpCh1qN/IZ1th8TC7
         yiQdm5antS5DZOvOTsPFv/FocnaJeOqfOb6vQ6FWq5pB2Huk3g+4lQzXpsgFpqpuh18O
         vblw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AHKrqjSK;
       spf=pass (google.com: domain of 3xgo_ygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3XgO_YgYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5aJ/nJDus8CvWwsEg9LHWP+2DWw8M4gHGmjHowUVSE4=;
        b=dV5FzcO1decNCWdJJoUHwH9NdDpeoCMOM8fi0rj9Uebyb4N6QvGhLmgE9grEB1Ctbv
         nvW5N6y2IV3Ts9m741HiiOPkxQWisAQTT5d5UK2N+29uyeELU4f49Y/LUk1G5axJz0TL
         Ah+vhg0FIi1CGEdrt/cmEvXJVm4jwze4+A4Ju35awnCSaJ5h/DZz/ZHCY3yWXLVkta46
         DJvzr+JZFzLD9JuTEJi57niimswRyeKL0fmjXQAOPWMpkJk1ItaCoV3WqITDzBGQQxFz
         rtCz2RvpHlnw3tSFWTy7ET3hUTGT/kYRK2YB1LRZYVZY2IgwgDQEPXfj+DHdPmT394yV
         tpRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5aJ/nJDus8CvWwsEg9LHWP+2DWw8M4gHGmjHowUVSE4=;
        b=c3b69oRLAwop17AQuw8oNTQ7onxHgnkZ3PhaYspx1CzigXlmsjcQ2SgRzwOmX9afOr
         pVh0QXTB2yuVJrQFkGaxOcrXy7wVg/ppb/c5XqB0ibwY7vDfiHrp1VvaFYSoijcqziDm
         ExE1CpGZt0OyWSj+qj25IdZOBULgeq3m80ewS9fV3mIFjE603eiTrbSAWQKcas2D9vQc
         kCA9JhIVZB3MqzY4dAiYxC5D4dr/85b3LuZmR9fiBvTR4hLr0WywTnjf1vQ3lVbFV4IS
         LGAcvhH3lMh+oEKH3f//5A8xYtPFyjtm15LgXcLcTCk8gE1BF9zuFVAQ15UePds5qAgl
         kxJg==
X-Gm-Message-State: AJIora/2+C+wwDbFRY7uC+h6EW3/LiPXPu+wmbpnPZCdM+yL6NUxn5Cb
	RaBzEcqcpyTlwMICQ0lppq0=
X-Google-Smtp-Source: AGRyM1sLG4G7l6kFdWY4sV+n8e8nlMRqfu7AADpD7HXLPwAWYYMCVAysW2YR5CdAPQLV2gJ4CdDHmQ==
X-Received: by 2002:a05:6512:33cd:b0:47f:ad57:70d7 with SMTP id d13-20020a05651233cd00b0047fad5770d7mr10148845lfg.558.1656685408900;
        Fri, 01 Jul 2022 07:23:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls85791lfn.2.gmail;
 Fri, 01 Jul 2022 07:23:27 -0700 (PDT)
X-Received: by 2002:a05:6512:1522:b0:481:3964:1ca1 with SMTP id bq34-20020a056512152200b0048139641ca1mr9091568lfb.14.1656685407700;
        Fri, 01 Jul 2022 07:23:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685407; cv=none;
        d=google.com; s=arc-20160816;
        b=cf2hT9byV6a53KKcp/AD8V228SnOlz3LQtNbVLcw8l09IL/MwciUbbsIfvwRz6ouAU
         hC3NWeeu9hFtZZ8l42xkkHZ+7aSD3hgCVrM2y4KGmlVE9Y+OA12mx1WDHE7NoW74fBoj
         shbVBETmSUAE7BDanNRZYOT16TQMX8o+TTmASZcsMR7mLY73jGOfPmxHsnPNBNb+arDO
         v6vLoiK+TY063+ojL4L+Qvqs6Q4uf9KzGRhCgA/6cKV6YWqsxpvrRMGS19UV3LHfDnXx
         1Zjm5wJFAJ0M/0E/ttZPJbKsdjfrQwrblhZIlHI8ldQH4VzgTZW+8+f9pbCGZW4TE0E6
         ju2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=g6pC2DAwiUBeK1TSxgdl5U3IOE2AcDc9FK6KiXQeXic=;
        b=sXBRSj0M2EwV/ExBEJmU+OtVNf/UlmId9fFrB8UpMJPrTsoidY89HdGxigdKGNvHxs
         wSARW40nxxGPdmSpwGBxUquMU/ezvd4SGx1DZoxO7eU/NY4zDKT3o3iCxMSVhQgop2cg
         PJJluEXB6iqqatHTeyW2Ico7jrCt2FEl6I3KE1Wy37fBre03igdRZbuMQ1b3jLwFfMrT
         OapqFC78bbRhmtrc2hy3jCEqwd0LjlZcE2lsVFjb1BcyMUxtCy7enuLVgwVYBGWh0k0J
         s65soLhRP7eXTVQg5RTA5wJI7xBxb7yEnRxj7EJqIyNXHNCHzhIoiu5YkgMJpqDzfQW1
         WPqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AHKrqjSK;
       spf=pass (google.com: domain of 3xgo_ygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3XgO_YgYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id o9-20020ac25e29000000b0047f8e0add59si1067088lfg.10.2022.07.01.07.23.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xgo_ygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id w22-20020a05640234d600b00435ba41dbaaso1881758edc.12
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:27 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:97d1:b0:722:e6fc:a04 with SMTP id
 js17-20020a17090797d100b00722e6fc0a04mr14570630ejc.217.1656685406971; Fri, 01
 Jul 2022 07:23:26 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:29 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-5-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 04/45] x86: asm: instrument usercopy in get_user() and __put_user_size()
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
 header.i=@google.com header.s=20210112 header.b=AHKrqjSK;       spf=pass
 (google.com: domain of 3xgo_ygykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3XgO_YgYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
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

Use hooks from instrumented.h to notify bug detection tools about
usercopy events in get_user() and put_user_size().

It's still unclear how to instrument put_user(), which assumes that
instrumentation code doesn't clobber RAX.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1859fdf5cc485a2fce
---
 arch/x86/include/asm/uaccess.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 913e593a3b45f..1a8b5a234474f 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -5,6 +5,7 @@
  * User space memory access functions
  */
 #include <linux/compiler.h>
+#include <linux/instrumented.h>
 #include <linux/kasan-checks.h>
 #include <linux/string.h>
 #include <asm/asm.h>
@@ -99,11 +100,13 @@ extern int __get_user_bad(void);
 	int __ret_gu;							\
 	register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);		\
 	__chk_user_ptr(ptr);						\
+	instrument_copy_from_user_before((void *)&(x), ptr, sizeof(*(ptr))); \
 	asm volatile("call __" #fn "_%P4"				\
 		     : "=a" (__ret_gu), "=r" (__val_gu),		\
 			ASM_CALL_CONSTRAINT				\
 		     : "0" (ptr), "i" (sizeof(*(ptr))));		\
 	(x) = (__force __typeof__(*(ptr))) __val_gu;			\
+	instrument_copy_from_user_after((void *)&(x), ptr, sizeof(*(ptr)), 0); \
 	__builtin_expect(__ret_gu, 0);					\
 })
 
@@ -248,7 +251,9 @@ extern void __put_user_nocheck_8(void);
 
 #define __put_user_size(x, ptr, size, label)				\
 do {									\
+	__typeof__(*(ptr)) __pus_val = x;				\
 	__chk_user_ptr(ptr);						\
+	instrument_copy_to_user(ptr, &(__pus_val), size);		\
 	switch (size) {							\
 	case 1:								\
 		__put_user_goto(x, ptr, "b", "iq", label);		\
@@ -286,6 +291,7 @@ do {									\
 #define __get_user_size(x, ptr, size, label)				\
 do {									\
 	__chk_user_ptr(ptr);						\
+	instrument_copy_from_user_before((void *)&(x), ptr, size);	\
 	switch (size) {							\
 	case 1:	{							\
 		unsigned char x_u8__;					\
@@ -305,6 +311,7 @@ do {									\
 	default:							\
 		(x) = __get_user_bad();					\
 	}								\
+	instrument_copy_from_user_after((void *)&(x), ptr, size, 0);	\
 } while (0)
 
 #define __get_user_asm(x, addr, itype, ltype, label)			\
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-5-glider%40google.com.
