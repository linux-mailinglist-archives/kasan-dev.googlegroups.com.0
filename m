Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WCUCJQMGQEV3THRMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 780DC5103DF
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:35 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id w34-20020a0565120b2200b0044adfdd1570sf7878285lfu.23
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991475; cv=pass;
        d=google.com; s=arc-20160816;
        b=jcFNMLD1+4wNWkHBKnSG0ZAaGGqZCjeJqMP8VL8d3DunqJU3MfOLV3Tbrc/VIeXPer
         D2ubIojajEFWIUuPepzZLMxdVmfWdfZidmzhbaQMMU4OOCEp9LEWCga/W4QpwV4Wtany
         7pkKAr3Hw+jQZUl7dRAd9BAC0vJyb5dwTuYAY/Oz+b6N0Jk6dYL76q2H+ISY9FBgsESb
         lM1TJwwww+m1TVtO0C4SEXfy+5XWbg0lKxtvVcm5nScj1xiVc5RRhwUw/DclbEEJHVJj
         UHXBzocPXHKDinHTm+Yq5BXWr+9zkRjvGoIbDAwiWXE26cndBh0OuJDFlumxpP3s6Jwc
         l7EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=AbgfAQqdMGH4G5L5YZG/wUcWxPIwHvfHDH9HmSBT5pc=;
        b=YKfGtY+YgX48yNBgcdTCGP+pNiwIv/xo0gbds5UJXtdDwoD1AF1oivEQ3bpCz9BpBU
         U6jTjpMpDyeh7V1zZKDVTBL5Zhh7bvaWEbyK1FuniVSNosOBIw4G1zgifRKdnezNoj0p
         aqHcjOTkdx4JtwrTM4Ouk52kpW1c96RJ0J4isnDbqOb3Waen/Kdbqtj7nund/jlm3cSu
         zt8XoXk9hvdgqvZdmdkgidq/OVfoOwq5U5wGG8jib4RErVF6haU3kV+h9xWcaIMVTnhi
         6EQTvn2JJCs3qaVQDyvlujBMTPd2luoOTvE36qntqrdHh8/QFRtrunIQHYv4ZdIq74dg
         NIAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ul2x8GzR;
       spf=pass (google.com: domain of 3csfoygykcw4sxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cSFoYgYKCW4SXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AbgfAQqdMGH4G5L5YZG/wUcWxPIwHvfHDH9HmSBT5pc=;
        b=soX1x7KxkVUDkvcP0ur48ermBeNWAd7GQjYlSwUPI9uZwHyrffy7+lS6rgQqFXcDRz
         iB1p8KfySVWbJbo+XoVgaLGkLEuUYEGpft6ABQdWh9W9wwTZZ/dmyZYpjItgC2lDWfCX
         UzfZoMKADdW5aeeyoAnIRmjXEkYNtj29kg5U8X3wIbbM+BTfXIawH+h+pVsRwYphyVVm
         Ag8DdXNpLZRJsbyunl44tw5Do4f0QAtvM8da6r2y3D61HeCOBbCf0Jh8sdgyCFlL5aXC
         34IwtB/zkAjWcNtdUGn9vUc8TuKcOz1hpApMdh1h/5EzW8kX4gb3Vbt/fzCyIMv0yLyn
         8QAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AbgfAQqdMGH4G5L5YZG/wUcWxPIwHvfHDH9HmSBT5pc=;
        b=knK5/29fAGucsaJoggAk1nIlC4mVSP6m/b1hQ1FWZ7koXw/pEa74PCEF3x08petlLi
         7/XyNA/wpe3QEW85WXxsZRz1fUX+UXr48BhEvS1V4r5TckaiS9PtQEpEpUnUodHVSCcZ
         IqjH1SpW1izdaN9gMeWQp4U511HUocmUdIu4wRNqMXTpwiMbNPnImPxHATG2Hc6fzKnV
         +IgRibyogNo/sqjqKz9zQOq1tiT86jMgMXWKnqhZcerWhF5dejjBiNDrY5FR3AHjFonR
         5MyfdlLvbbCVdCZycHeXnRoTPQPl0w0OWTqTtOPX8lio6njNIrn6tfnRwEyUqArm4RJ5
         fO6Q==
X-Gm-Message-State: AOAM533RxZ3vmWzoZJjsiA7gjH00h+x9u+eyN50VpMd+aoCg2d57RdaN
	8MMibQNeBWWShKceGG/Xa/c=
X-Google-Smtp-Source: ABdhPJzb7gBtJKJTSR7Eg9dWiffqQ6XyTMtCvHkuv5K+BNKPQAgRWSObxCssxNg0OTfSa8ZIJ3vCTQ==
X-Received: by 2002:a05:6512:c03:b0:447:7912:7e6b with SMTP id z3-20020a0565120c0300b0044779127e6bmr17327597lfu.508.1650991474891;
        Tue, 26 Apr 2022 09:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2815:b0:471:b373:9bb9 with SMTP id
 cf21-20020a056512281500b00471b3739bb9ls2090362lfb.3.gmail; Tue, 26 Apr 2022
 09:44:33 -0700 (PDT)
X-Received: by 2002:a19:385b:0:b0:472:ecb:f659 with SMTP id d27-20020a19385b000000b004720ecbf659mr5868241lfj.386.1650991473789;
        Tue, 26 Apr 2022 09:44:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991473; cv=none;
        d=google.com; s=arc-20160816;
        b=aF+P222ceiThiC2xyKmQbbuVHFnTm6n5N9owa5DYPr+dYwO9rjMn7W16b7Zd2xZqrx
         0RkVXR0RlAvQc/K472SSBQ8h/Y6tjWt0bkSygdWbzsSaGJFJbxcaOQIIxoudhJ3Qaa1n
         XdNKhc9gN0r9kp8+EM8Y0kDIWzyZQS9x9a0HYlxAB0enA1NIbBS1uMXEY1HrBmsE8ZZ3
         bi2cIsMg3jXKk4aDMF3J0VEP6sQvrRchpCQ/ckOpyXcEt5X4XeNAvF/hMTQrFPu7rM1Q
         S7osMlNz3Hial+Es2PIWGsKIpQRrAFb1eqk6EVKH1VMwgASsOaKbq4X3GmgfvMRd+Nsv
         jtQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=n1CPd29HHKe3iLELt5x5zSxX1l0GlMUVKgGqbXsXPsc=;
        b=T/lCWppVKjVDTmQ4r0Y/3GhllfQSNkpWhksfOCVvNCAyutIa3USpEtkf2MmuxZBRtt
         sGU3uupZv5+0SgCS7wcFB/M2f3Qya3iuJ1oquNsorQUWKC4PVxAaSzNtxTYQWdVnIrVd
         wM1s6b83qP/P3ZXnOGUqNOf7jCjOHiXDjYXPdSLDPx+jnBrDXxNgnwcrqWf2hHK7muSG
         EMRg/HyjL0NxHX8k2Obfcd6M12KhqWlFVPAhvuMlFmpoaUutT0EmifA6csfI1jS1gdMV
         isNlmA4KqQ8gag962C9O6Mxrf+AfvEioWE6Tn4vGx240ezNBmu2HmbZZMOrh+aMAZjTX
         4jPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ul2x8GzR;
       spf=pass (google.com: domain of 3csfoygykcw4sxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cSFoYgYKCW4SXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id e11-20020ac24e0b000000b0047193d0273asi781363lfr.8.2022.04.26.09.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3csfoygykcw4sxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qw33-20020a1709066a2100b006f001832229so9338084ejc.4
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:1385:b0:413:2bc6:4400 with SMTP id
 b5-20020a056402138500b004132bc64400mr25986634edv.94.1650991473255; Tue, 26
 Apr 2022 09:44:33 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:34 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-6-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 05/46] x86: asm: instrument usercopy in get_user() and __put_user_size()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ul2x8GzR;       spf=pass
 (google.com: domain of 3csfoygykcw4sxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cSFoYgYKCW4SXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
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
index f78e2b3501a19..0373d52a0543e 100644
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-6-glider%40google.com.
