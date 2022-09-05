Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJOV26MAMGQESL7HR5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D95015AD251
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:09 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id n1-20020a7bc5c1000000b003a682987306sf1674396wmk.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380709; cv=pass;
        d=google.com; s=arc-20160816;
        b=OQxOElauffkaT/nYU0WuFrcJoRcNND8W7oNHOOoRinWNMmpi1e0baC2EncnjsEZFyI
         HWpZM8lR3NMCEkNlxgR+kPusE2mfHez76yIrQTBNICdVHSGfYPs7eruEAAO1s4iPTJPu
         f/Hf1bZQyAXdvT4p6qiQV9l9B9J+MHtIdinJR+/sF04b0lqk95/mf6HqTrIgiDOR36sL
         n6bf9xsdJ3IBX827XDMfoyWRqQmbKnPqhYEO3AZ9dlr272HHXr5/SG6fWoesesIrFeKZ
         wrcdlIK5cA0vF1Un9qjLj1oVB5xYlmpxRhaI5Ajrdo8HlDUh8DINmy994w0MhT1Qdqkw
         whHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RIUHYnWNAfUe9M/zLI380eMpqdV8DJAoO7pZQEiWIS0=;
        b=uR+eMAuohaR1JZhxj1MHuDNUUWhjeKvEt7ch6eExsILTGPioCV4mcU4ECMzIAolIBK
         xo0Kj9lFQo2fpaDR9kqnDF9cp2UafD08vxMiOQB+6DyJJIS+HNR9Wn6ylgighzDvm5Vx
         aGx0cgwy/FCG8enA4hRPCZiuuhXWeVzt8i2OrH7mN+tUuSOmuagBdoUMVBUuXVFscabO
         IIu+O3UmdqWsNwAYxSyIn8fUxOR3JrWuzNQ2UiOigWJQdLA2YtNh6dXgRAKqpl2YftzN
         BuczfCpUsaREnRB2z+Q9AYhzix9eFSDJpeeWROpyHQdnu+PxCT+B8xLwdAbQl7Sigulb
         LtNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tGEGAx8u;
       spf=pass (google.com: domain of 3o-ovywykce4wbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3o-oVYwYKCe4WbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=RIUHYnWNAfUe9M/zLI380eMpqdV8DJAoO7pZQEiWIS0=;
        b=O3kzM2u/PQFhAo9KfcYz3Red9nKF9GSTNHx/QoN+uObu0iVXRYCVTlx1w3vBRUhY3v
         1COyFAOCrOS2ASPGBAt5HU14JzANji4KxbOTy879iglhoPGKoKpAHtukqQ8vpA2BcCIH
         BMs5SOG8PVP6NUmXpj319dJlHjoZ/TbM3eHluw0P5C4lyHZz80VSErPd+TYi8Q+iuJZ8
         fmEqJm2l4CPeJEWhHxToV/CDMW3RwqDUO2hjT7Io/mG19CT/zW75lQ6WB2/wVPtiWUIp
         2rNELcgaw80xhmG2ftYDgisRikpRENarsyf3W4PjG0sZgK/wKcpzFUhrTPHRyQH78kO+
         HP0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=RIUHYnWNAfUe9M/zLI380eMpqdV8DJAoO7pZQEiWIS0=;
        b=M74MfqJUFrX2b+eybVk4PUcW4mnt/AivlQ2s3khd/59uoxp4nNz28moIJLQf3PJvIc
         TRhchjHGxoIZZM4UPa+jytw2cLpGIMWLTyoN6SqIt+v0Wu7nJfaRFDwdfc1O558YNve3
         FDDDpSYR5220R8VlqK/mIq/Nih1OmYveZXnVTRDKeUul1vM0oAddHZJfUiUGv+F2U1iN
         QFzzOkl7deJsVomZp77ahpDxxBd/Cob1wVXDO0RfUILOgfMoUCSC/JB1fjBr4gWJZhLu
         CmrlhnK/nc/x5mP4FxSMq5IRuBGAhG7Oxj7oE8Um3yPYxo6zhCncU8PR/x1jKwW1DB1C
         Pn6Q==
X-Gm-Message-State: ACgBeo1q+kumI1jw5D4jaqOhflqwxdRgXV4w25ZXBJFJG2LbZo1E0xIq
	lEgsrLgU6piD6hh4WHg6lZ0=
X-Google-Smtp-Source: AA6agR6cJk0Mltq6ki1b5s6mPBWtkooiwxakNrFCuToMpOvIsnGyY/Zcvq6mpa2y5wkvNbl/MN32Qg==
X-Received: by 2002:a05:600c:1e04:b0:3a5:c83f:76bd with SMTP id ay4-20020a05600c1e0400b003a5c83f76bdmr10564800wmb.191.1662380709339;
        Mon, 05 Sep 2022 05:25:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:257:b0:228:a25b:134a with SMTP id
 m23-20020a056000025700b00228a25b134als3154163wrz.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:08 -0700 (PDT)
X-Received: by 2002:adf:fa11:0:b0:228:bfb5:d56a with SMTP id m17-20020adffa11000000b00228bfb5d56amr1318881wrr.353.1662380708341;
        Mon, 05 Sep 2022 05:25:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380708; cv=none;
        d=google.com; s=arc-20160816;
        b=sMoyEi1G9aGKDsBlqolXKnP8264WASXUSGR7v97ezK17HKm63PXYhJUJMiAqiQkK1M
         m+XbPffTbBhSiN7Ge04+gEvOHUppODgjFOyqV+wBv4VRRV/2JTkmwrtzf0jBHENGUCDS
         4wYXDQSKvy8vTOWCDozpnG45fRqhJC1zUcipLuTY/wbJc1X0zEVgiGkONY1h+a7SL4Ky
         XAHhLHI4dJL0U9KxGSh+7v1rKvVMkML3YaOxXnZsWcopte7E0ihQ7ZkNu/2q2zwLV6JP
         dOY16E2jEQmGVyeIxy1a7JO8+B0gCVYY7+tnRLzL/ezsSTiMD80hvfH2jIp+8lzf5Avc
         KlLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gSZzwrXvhkj2wpolUx3YVTouxdXHw9PaTEDZ4n2e3I0=;
        b=qCsz+rBU1aLdqMTgm7YumtqKsCCqAA5QeAxfx/zoWaNyQ9gzsI3aCml55lycmbxtAp
         Llk8sWlsDHwNxUkjUjbTxmzqsLCc+//I5+2Z4XKgMnobkD3dldjpZLZ72jsBlUrMTMJX
         YRMKzcLSLhdktPukGh+mKvCDa+WcvIQTL3opIGacIDe1sKyS77euU+w4Ee/GM6DbE1Qq
         myi24tTKU1xB4ITKNWtcCYV3dRaMoQ0r5mWQAH+nnU4XVEbFXS7Y3NYfGkeU29xRcU7j
         GhMZqPaahGNB81Sdz2lJOSw7qo13Pf10XKi8WKK8+F2ejR5IAvKTGRe+l8CNBXOt5Cp2
         7/UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tGEGAx8u;
       spf=pass (google.com: domain of 3o-ovywykce4wbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3o-oVYwYKCe4WbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b003a83fda1d81si881237wmq.2.2022.09.05.05.25.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o-ovywykce4wbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id w17-20020a056402269100b0043da2189b71so5639888edd.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:08 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:4414:b0:434:f58c:ee2e with SMTP id
 y20-20020a056402441400b00434f58cee2emr43097203eda.362.1662380707978; Mon, 05
 Sep 2022 05:25:07 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:12 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-5-glider@google.com>
Subject: [PATCH v6 04/44] x86: asm: instrument usercopy in get_user() and put_user()
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
 header.i=@google.com header.s=20210112 header.b=tGEGAx8u;       spf=pass
 (google.com: domain of 3o-ovywykce4wbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3o-oVYwYKCe4WbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
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
usercopy events in variations of get_user() and put_user().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v5:
 -- handle put_user(), make sure to not evaluate pointer/value twice

v6:
 -- add missing empty definitions of instrument_get_user() and
    instrument_put_user()

Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1859fdf5cc485a2fce
---
 arch/x86/include/asm/uaccess.h | 22 +++++++++++++++-------
 include/linux/instrumented.h   | 28 ++++++++++++++++++++++++++++
 2 files changed, 43 insertions(+), 7 deletions(-)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 913e593a3b45f..c1b8982899eca 100644
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
@@ -103,6 +104,7 @@ extern int __get_user_bad(void);
 		     : "=a" (__ret_gu), "=r" (__val_gu),		\
 			ASM_CALL_CONSTRAINT				\
 		     : "0" (ptr), "i" (sizeof(*(ptr))));		\
+	instrument_get_user(__val_gu);					\
 	(x) = (__force __typeof__(*(ptr))) __val_gu;			\
 	__builtin_expect(__ret_gu, 0);					\
 })
@@ -192,9 +194,11 @@ extern void __put_user_nocheck_8(void);
 	int __ret_pu;							\
 	void __user *__ptr_pu;						\
 	register __typeof__(*(ptr)) __val_pu asm("%"_ASM_AX);		\
-	__chk_user_ptr(ptr);						\
-	__ptr_pu = (ptr);						\
-	__val_pu = (x);							\
+	__typeof__(*(ptr)) __x = (x); /* eval x once */			\
+	__typeof__(ptr) __ptr = (ptr); /* eval ptr once */		\
+	__chk_user_ptr(__ptr);						\
+	__ptr_pu = __ptr;						\
+	__val_pu = __x;							\
 	asm volatile("call __" #fn "_%P[size]"				\
 		     : "=c" (__ret_pu),					\
 			ASM_CALL_CONSTRAINT				\
@@ -202,6 +206,7 @@ extern void __put_user_nocheck_8(void);
 		       "r" (__val_pu),					\
 		       [size] "i" (sizeof(*(ptr)))			\
 		     :"ebx");						\
+	instrument_put_user(__x, __ptr, sizeof(*(ptr)));		\
 	__builtin_expect(__ret_pu, 0);					\
 })
 
@@ -248,23 +253,25 @@ extern void __put_user_nocheck_8(void);
 
 #define __put_user_size(x, ptr, size, label)				\
 do {									\
+	__typeof__(*(ptr)) __x = (x); /* eval x once */			\
 	__chk_user_ptr(ptr);						\
 	switch (size) {							\
 	case 1:								\
-		__put_user_goto(x, ptr, "b", "iq", label);		\
+		__put_user_goto(__x, ptr, "b", "iq", label);		\
 		break;							\
 	case 2:								\
-		__put_user_goto(x, ptr, "w", "ir", label);		\
+		__put_user_goto(__x, ptr, "w", "ir", label);		\
 		break;							\
 	case 4:								\
-		__put_user_goto(x, ptr, "l", "ir", label);		\
+		__put_user_goto(__x, ptr, "l", "ir", label);		\
 		break;							\
 	case 8:								\
-		__put_user_goto_u64(x, ptr, label);			\
+		__put_user_goto_u64(__x, ptr, label);			\
 		break;							\
 	default:							\
 		__put_user_bad();					\
 	}								\
+	instrument_put_user(__x, ptr, size);				\
 } while (0)
 
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -305,6 +312,7 @@ do {									\
 	default:							\
 		(x) = __get_user_bad();					\
 	}								\
+	instrument_get_user(x);						\
 } while (0)
 
 #define __get_user_asm(x, addr, itype, ltype, label)			\
diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index ee8f7d17d34f5..9f1dba8f717b0 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -153,4 +153,32 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
 {
 }
 
+/**
+ * instrument_get_user() - add instrumentation to get_user()-like macros
+ *
+ * get_user() and friends are fragile, so it may depend on the implementation
+ * whether the instrumentation happens before or after the data is copied from
+ * the userspace.
+ *
+ * @to destination variable, may not be address-taken
+ */
+#define instrument_get_user(to)                         \
+({                                                      \
+})
+
+/**
+ * instrument_put_user() - add instrumentation to put_user()-like macros
+ *
+ * put_user() and friends are fragile, so it may depend on the implementation
+ * whether the instrumentation happens before or after the data is copied from
+ * the userspace.
+ *
+ * @from source address
+ * @ptr userspace pointer to copy to
+ * @size number of bytes to copy
+ */
+#define instrument_put_user(from, ptr, size)                    \
+({                                                              \
+})
+
 #endif /* _LINUX_INSTRUMENTED_H */
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-5-glider%40google.com.
