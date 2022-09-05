Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTGV26MAMGQEP5F7ZBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED0D45AD25F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:48 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id gb33-20020a170907962100b00741496e2da1sf2279891ejc.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380748; cv=pass;
        d=google.com; s=arc-20160816;
        b=UQQrVxdcrEtrWpmk1GF8CI/kYtZuid1Dr95cPGk39dAtGliHTVjbmZ1ofZ9uP7zDHa
         k90F41sOVPmLsjpGhuf9nmwpqehug1Mpb9OJMdDN6eqkpjOzTu296YHPNxUo5kHqbfLF
         K1b4UK1MG7J316Ufuuhdk6F6SSsGVoLBBtpU3S0d8zNVI6c3tVnXIEGnsCcftgl0YWFp
         JmeA2IlcYlb8+SbmcY0/zKU5VdI4z3dDJ5WGj3axi4sq4NkbvYeIS3tb0TqnkhBimpnS
         wnQrhmg6aOFOFPNLAOhAefC9uyqmu5L4iGn4KjJ1eSUCr28zfbb74tU0PQRFq/UwYu+v
         3dEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EHXLBDVNSterU+Tb03k3r98He5Wdv15I3XHEmw305FA=;
        b=f8DDapwZVjJW8L2Y1VX0N/kevy4gnxjrM6XSR9S3iV0tcS4Dkm9wTdyTvAvsc8PiWE
         ArmIaDjKKFty86zynPffkDIT2G2Q9LUCfWi4gDUx8isY7YZXMQISNcOrwHAbFhb8Ff7i
         LsRPaKD+vBv4Qvg3ekpwttFi+hAo7kfFDXtqtEZMrFEMGczZcVM4G64C8j6uVviTp0u9
         +eKiK/kGYuZJ8QCKoETnzmWsFlxYGyHQi8rKHxNDeVTp1cQVy9mT9erIRlcAjJg3Y2kR
         8zUr12KgFWjfGbPT/Le98a2zBD9byhFzc2urUus8GqDFHlkL3MWEP1yB1ke0pYLQGRnl
         l0hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AsRZmg4F;
       spf=pass (google.com: domain of 3yuovywykcrc38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3yuoVYwYKCRc38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=EHXLBDVNSterU+Tb03k3r98He5Wdv15I3XHEmw305FA=;
        b=KcJMMX0XISWbikkW3Tn/ycgqI1DVwylmUYSyZft1rSuZPfWGjg4PcBEmoqoH4cYNtX
         n9XUfveUQ2c4XViqKJkEJRBnh/s9Gf1ZxFZU6U/jzOyITlHJEFmiPeoA/8OlKAajIAER
         bPd2Bt93M3s21I/lvIbwDQhJcC1ruVCo84pmHB0dKSsGhDMMqwjOyRe/ubcOnl8G2CJL
         DpQiGQeu1nqF4GNmk6YO4mIAuFT/iKFamrReLgaEgh4iwEtgb3M99fYZNYpFkhPoJKuH
         o7yn3kVL5ke9u4TLlvEyt75XI5tFfsy7Wv0hEUSAbHk675TO0KpxyR+e1Rcq6YuTyYuf
         cNLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=EHXLBDVNSterU+Tb03k3r98He5Wdv15I3XHEmw305FA=;
        b=JRt5tFcJp1OhnWdR9sUZJgt19eYPM0EKS1pLMrH6uAbJZ4r4czxsS2zEjjOyVlIiNT
         B6vAHaU8jYChG7uehvE8uL1rBlEJ/poNMbuUj94WXrOYcvAtac9dv2uZxwNoTu+k04wz
         0nY+dbA77X+sTWeQvUcXMk8qOm9aTNbSR+F3mXi3Rl55e2TVaB0yCJkr8NUvrG6I+dcM
         1AoaDsVNGoLILOHpBrWvBA/Pes0eLsk1APhajK/gFy0ktYTM96dBQmlyRVA90bffc70U
         uwcqFBIVEI+uMAriSkv6SPFNtDT+uEI9hrSCatLAKUEHm8xPlH6DiKbASwxVq/h4iq5p
         i+SQ==
X-Gm-Message-State: ACgBeo35t1SclzBm7MVgNlU2JN4pwHTRQ87j9YiXjPGW/mSCJE14x0wA
	8/Vk3tlJlnD6a0SA2kRoVOY=
X-Google-Smtp-Source: AA6agR5x87m7ohtYaiyzmHLv8bTLudy6ieqluveQ8hn6EotTgg4dgotnDMSS8G1XuUsnO63oD2qb0g==
X-Received: by 2002:a17:906:ef8c:b0:73d:db10:8825 with SMTP id ze12-20020a170906ef8c00b0073ddb108825mr33904600ejb.445.1662380748682;
        Mon, 05 Sep 2022 05:25:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3994:b0:726:abf9:5f2e with SMTP id
 h20-20020a170906399400b00726abf95f2els3413813eje.9.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:47 -0700 (PDT)
X-Received: by 2002:a17:907:3d90:b0:741:346a:6e46 with SMTP id he16-20020a1709073d9000b00741346a6e46mr30481284ejc.279.1662380747224;
        Mon, 05 Sep 2022 05:25:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380747; cv=none;
        d=google.com; s=arc-20160816;
        b=wIQd1zo6yQGXTE35UNRdXyd2z5WGR/7KEGvoGKAR1ETJK7r9zQJA27GbhEtDGzVDbk
         +vHiNVLQiOw/sz2qoDg6B0XLT4akfLMjD9dyi3Ww45Y8NAlPTB5MLv3bs4c3Zir5SZtI
         dpcsLmo5D5/5v9clcQKbh4ZBJkP21izldfvqQJ5HeK8An/Efznw1EjJ7/5z2OBkckfGE
         CRZQ/t6xWjtxmADnPRrgGDIoKyhlET8iZq3IvyJi/rTPiUrT9RUdENZT2n9DnGtpbRUT
         xaUv48sNrmVecB6QwMigNvM61O0mJ7XoTAozG1CeIN3KKH9GWmsqpA1hFRZcIvRM3Ffl
         g+UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=78o9fcmZe1rakLyEcoaxPY9Q3UwZCgWFE2+savdbFCc=;
        b=U2NJ1QsXyalVP29ToEQ3aGUNRTmpde199X3/Fse+msO7yyYNFOexrWLo/f7Fy1pVtY
         tSBkeiKt/i23ekLn0QR1IPirIm75KDsv8VW2LavCyzLrUW4CM58iDB0ucL00lsUoSKbl
         KKodfciA2SF/z43MIvr9wTSIF1qt1vOzxe4v1aZxPNmE6NLogkTwwaQolw9GkTHt1jQh
         fgDYD5JqR+1wlG5Lf2fQiEfs/hF4pEKfk0WOT3CsnTav7btR2uWdpkKXITCW2O+8hQEm
         iwWB2lJhMyYTLhO1R8NIAEDaZmG5x22xRqQVQR2TSV/0d7M6FRxrfHjqeSRoT6YsVw2b
         QMLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AsRZmg4F;
       spf=pass (google.com: domain of 3yuovywykcrc38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3yuoVYwYKCRc38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi373709ejc.2.2022.09.05.05.25.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yuovywykcrc38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f9-20020a056402354900b0044e0ea9eb2dso2758406edd.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:47 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:9bd9:b0:73d:da74:120c with SMTP id
 de25-20020a1709069bd900b0073dda74120cmr32752711ejc.412.1662380746896; Mon, 05
 Sep 2022 05:25:46 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:26 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-19-glider@google.com>
Subject: [PATCH v6 18/44] instrumented.h: add KMSAN support
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
 header.i=@google.com header.s=20210112 header.b=AsRZmg4F;       spf=pass
 (google.com: domain of 3yuovywykcrc38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3yuoVYwYKCRc38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
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

To avoid false positives, KMSAN needs to unpoison the data copied from
the userspace. To detect infoleaks - check the memory buffer passed to
copy_to_user().

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v2:
 -- move implementation of kmsan_copy_to_user() here

v5:
 -- simplify kmsan_copy_to_user()
 -- provide instrument_get_user() and instrument_put_user()

v6:
 -- rebase after changing "x86: asm: instrument usercopy in get_user()
    and put_user()"

Link: https://linux-review.googlesource.com/id/I43e93b9c02709e6be8d222342f1b044ac8bdbaaf
---
 include/linux/instrumented.h | 18 ++++++++++++-----
 include/linux/kmsan-checks.h | 19 ++++++++++++++++++
 mm/kmsan/hooks.c             | 38 ++++++++++++++++++++++++++++++++++++
 3 files changed, 70 insertions(+), 5 deletions(-)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 9f1dba8f717b0..501fa84867494 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -2,7 +2,7 @@
 
 /*
  * This header provides generic wrappers for memory access instrumentation that
- * the compiler cannot emit for: KASAN, KCSAN.
+ * the compiler cannot emit for: KASAN, KCSAN, KMSAN.
  */
 #ifndef _LINUX_INSTRUMENTED_H
 #define _LINUX_INSTRUMENTED_H
@@ -10,6 +10,7 @@
 #include <linux/compiler.h>
 #include <linux/kasan-checks.h>
 #include <linux/kcsan-checks.h>
+#include <linux/kmsan-checks.h>
 #include <linux/types.h>
 
 /**
@@ -117,6 +118,7 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	kasan_check_read(from, n);
 	kcsan_check_read(from, n);
+	kmsan_copy_to_user(to, from, n, 0);
 }
 
 /**
@@ -151,6 +153,7 @@ static __always_inline void
 instrument_copy_from_user_after(const void *to, const void __user *from,
 				unsigned long n, unsigned long left)
 {
+	kmsan_unpoison_memory(to, n - left);
 }
 
 /**
@@ -162,10 +165,14 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
  *
  * @to destination variable, may not be address-taken
  */
-#define instrument_get_user(to)                         \
-({                                                      \
+#define instrument_get_user(to)				\
+({							\
+	u64 __tmp = (u64)(to);				\
+	kmsan_unpoison_memory(&__tmp, sizeof(__tmp));	\
+	to = __tmp;					\
 })
 
+
 /**
  * instrument_put_user() - add instrumentation to put_user()-like macros
  *
@@ -177,8 +184,9 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
  * @ptr userspace pointer to copy to
  * @size number of bytes to copy
  */
-#define instrument_put_user(from, ptr, size)                    \
-({                                                              \
+#define instrument_put_user(from, ptr, size)			\
+({								\
+	kmsan_copy_to_user(ptr, &from, sizeof(from), 0);	\
 })
 
 #endif /* _LINUX_INSTRUMENTED_H */
diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index a6522a0c28df9..c4cae333deec5 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -46,6 +46,21 @@ void kmsan_unpoison_memory(const void *address, size_t size);
  */
 void kmsan_check_memory(const void *address, size_t size);
 
+/**
+ * kmsan_copy_to_user() - Notify KMSAN about a data transfer to userspace.
+ * @to:      destination address in the userspace.
+ * @from:    source address in the kernel.
+ * @to_copy: number of bytes to copy.
+ * @left:    number of bytes not copied.
+ *
+ * If this is a real userspace data transfer, KMSAN checks the bytes that were
+ * actually copied to ensure there was no information leak. If @to belongs to
+ * the kernel space (which is possible for compat syscalls), KMSAN just copies
+ * the metadata.
+ */
+void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
+			size_t left);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -58,6 +73,10 @@ static inline void kmsan_unpoison_memory(const void *address, size_t size)
 static inline void kmsan_check_memory(const void *address, size_t size)
 {
 }
+static inline void kmsan_copy_to_user(void __user *to, const void *from,
+				      size_t to_copy, size_t left)
+{
+}
 
 #endif
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 6f3e64b0b61f8..5c0eb25d984d7 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -205,6 +205,44 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
 	kmsan_leave_runtime();
 }
 
+void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
+			size_t left)
+{
+	unsigned long ua_flags;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	/*
+	 * At this point we've copied the memory already. It's hard to check it
+	 * before copying, as the size of actually copied buffer is unknown.
+	 */
+
+	/* copy_to_user() may copy zero bytes. No need to check. */
+	if (!to_copy)
+		return;
+	/* Or maybe copy_to_user() failed to copy anything. */
+	if (to_copy <= left)
+		return;
+
+	ua_flags = user_access_save();
+	if ((u64)to < TASK_SIZE) {
+		/* This is a user memory access, check it. */
+		kmsan_internal_check_memory((void *)from, to_copy - left, to,
+					    REASON_COPY_TO_USER);
+	} else {
+		/* Otherwise this is a kernel memory access. This happens when a
+		 * compat syscall passes an argument allocated on the kernel
+		 * stack to a real syscall.
+		 * Don't check anything, just copy the shadow of the copied
+		 * bytes.
+		 */
+		kmsan_internal_memmove_metadata((void *)to, (void *)from,
+						to_copy - left);
+	}
+	user_access_restore(ua_flags);
+}
+EXPORT_SYMBOL(kmsan_copy_to_user);
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-19-glider%40google.com.
