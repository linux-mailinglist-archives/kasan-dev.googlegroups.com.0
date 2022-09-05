Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIWV26MAMGQEN4GKAWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 416455AD24F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:07 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id q16-20020a1cf310000000b003a626026ed1sf1670865wmq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380707; cv=pass;
        d=google.com; s=arc-20160816;
        b=oroI3d9BM1OWx33UVVDHrU1qU/a3X6KEAvuiwoq6+lQT8LaXTzkbRieQ3iiO+EpaE0
         GzsxvKBUEy31QZhvqWy/i/U+K2Jilx9n0Olisr+RNReBqA6k0BSZc/5kmLpmWdApKNHT
         uHaZz55b7AnZmLjyQ8knWYrMz1aaIEEAnlDeC2RWvFjTTCCruhh88hub5uLMTIY1g4oI
         6cwJjwqn5HMmG3mrsS8uY7V/iw6mYRXu8RiYFVblo3+ITvDnJG7WcGnQQzK9wHLnycTw
         cLdxwPkoNGw7OpcDSk3kH0MLZ07BHibwXiaqHqTkuGbJ2jFY/dkHuFING6AARb+/qcBC
         pLhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=xuZUrmUmxK7krR3LeGVAufZIJFHlCfEHvMGCHBjVrVM=;
        b=PunOvbNKy6nBrRoeLoXHDjeyhuLnn6Oivjt8wJ/3tFbhmq6x3WwXYfneHEY5hzdajE
         vnj3iXlIZ7idmRmBhjxbCbiucUwdlYdO8G+oL72O1noU1tLfLR6G50XjymRl8fTnEofb
         lgEMpDCl9SfsUsp0NRV20j/WNGvugNobDjDTDC1nWdTbgxFWC3ZnagW9YaaIdjXcyjq0
         mSIrVIPBQIAVDqeqQsa2jOvQLBP7ndbgQfm0mCx74laQnyV1X+cOd9dziowMqcnVxXW8
         1vAdv1WDQelzyHTtXIuw/ME19nXg8+TrZ4aieyn729QhFnAvyKecoMQ+YZRsO8z2KAbP
         sJVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dumDoYlx;
       spf=pass (google.com: domain of 3oeovywykcewuzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3oeoVYwYKCewUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=xuZUrmUmxK7krR3LeGVAufZIJFHlCfEHvMGCHBjVrVM=;
        b=aDa70Looj9aEUGlsfr7DEAdVqDD8xexGUybE0tduTAb+b6uEEeV0SdcfSnO3KgovkX
         xBfWDFvbbWVQ6yCU3ITTm1mF2/P9oI0n8IyzUlTiyr3bjnw5qPol7Dt+wHgZCUXetr8G
         60Hgs6hBB75FGqtdsoiyu8C5Dd3DFjnbBSXW0PIkJ3k7CXinrU4bKVzC2IX24tjsQj90
         tplkNRP0yP2uiHWvGZT01W8qpzQoTwpZzGosjN2mKRt8hISXBYpSSsSNxovnz5a+uhRJ
         Rq013cPWGRSgdOBOXc79U9AkE96wt9/F3I2+lwtsYqzqT6jIGUnBlEyzI99cIYv+X3WE
         Ycrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=xuZUrmUmxK7krR3LeGVAufZIJFHlCfEHvMGCHBjVrVM=;
        b=YQImRPqTmW18lLtWdHDNO9kK4vdlKjrv+R0wvWNrRwRJuytkxqvLzMwT31ymrw3Bwh
         UWdIYl+FXyPGrJWc+riAx5ot0RVlv5bX7JOdAzLOcjSd41s5VqG+XpvCAC+vJRgqPPQi
         llO+MhKF6GhJ2iRNmbEy14ok9+NMdEQn1zjW/wx8USpRddGqoMiEKSCgK06L1sKaXM3C
         pARo9nvVhsGf5ZUn3qQqHnmAg+7o3K+fMyvoPuWEeN1HRpEpHojb2enY27JhO8hamlnz
         IHWZGALOQvlZ3+cfc9px38ZaKhENq7e82BpiLatYua6SwAZ/X/+J03RiZ3Dx1GLTIttv
         VRhw==
X-Gm-Message-State: ACgBeo0tgLzVMOOdgocXHDNTLyVORBgl61VQqMQWxUGHh2Elbk6W4lPi
	c2Ko+s/Q2gkvH1QRHFg64NU=
X-Google-Smtp-Source: AA6agR4HYO+Z0W0W53DRlp67fABHbufrfrwkpiHEoAM0SE//IIYMH4o2F/aB3iQxgpek/RYnVs1YqA==
X-Received: by 2002:a05:600c:a199:b0:3a5:dddf:ac6d with SMTP id id25-20020a05600ca19900b003a5dddfac6dmr10441763wmb.44.1662380706941;
        Mon, 05 Sep 2022 05:25:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c059:0:b0:3a6:6268:8eae with SMTP id u25-20020a7bc059000000b003a662688eaels3804589wmc.0.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:05 -0700 (PDT)
X-Received: by 2002:a05:600c:3d11:b0:3a5:cd9b:eb08 with SMTP id bh17-20020a05600c3d1100b003a5cd9beb08mr10830195wmb.82.1662380705588;
        Mon, 05 Sep 2022 05:25:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380705; cv=none;
        d=google.com; s=arc-20160816;
        b=l26ye0FXsFt2uUprq76snQ2hBdhQNeMJEqbgRcNzqvv+c5+dDjj7POsSqZyRPzLU4Z
         UEYM/KvZXO5xjBCuwdHHo5kN/PG1UT4HH9E+GC6zJg/jhOXgBuniyBc/FYPsK9CsEOLJ
         ViQf8bTWtJDYxl22Mq5CTHeWiY7qu7FCO6G1xuwodADyyZT5bmgns2MzEOIRxSAb9w/U
         Alw0XKITNhBLTZT3ZRr4Tf9QljuOFZ5r3ibMUUzIxSF4gHykoZc0LLO69znP8VKSrn67
         T2vhxAK4FB743rsqogZDM0REhFhq3LIFkaAZ0SRolCE3j75WfkJc6NRnpjgNImfwVJQr
         mlCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=msgzHzsxvMZcLqG5jRq1WtDuSKgOL7FjSU3mDqU1uyE=;
        b=Wnsp0+D0l0RdwI3a+ghkhnCHZp6K8IJP1IA8KBmgdLcgpT5K+18T36VXkn3XsDEPVr
         7w+DoIupmzaDY94aoJpEwkyTuy2CKDNQ1qRuYpigYc2vV2oXzq/f92reoh9UIsAerJTq
         r3IoDRkydLD7Z8UiTGYv1vWe76sIYUQwQA7zQ1JuzRRHm6pKroJ8OeZBEycKlRa6S0lX
         d1hLZnvNg9fyr9wx367z5e9xoagGsOCJuSkzlrVRrUaCUNSYPbk+lME7gSnk4r3cf/lV
         PGLbBsgc7NYO5T5UovXYpEDGkVXQhMP92CSDFREgG+rZDudd3ganUOMtXEJ/f14z5hu1
         OHRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dumDoYlx;
       spf=pass (google.com: domain of 3oeovywykcewuzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3oeoVYwYKCewUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si1178450wmb.2.2022.09.05.05.25.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oeovywykcewuzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id w19-20020a05640234d300b004482dd03feeso5725915edc.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:05 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:448b:b0:43b:5ec6:8863 with SMTP id
 er11-20020a056402448b00b0043b5ec68863mr42758320edb.377.1662380705217; Mon, 05
 Sep 2022 05:25:05 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:11 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-4-glider@google.com>
Subject: [PATCH v6 03/44] instrumented.h: allow instrumenting both sides of copy_from_user()
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
 header.i=@google.com header.s=20210112 header.b=dumDoYlx;       spf=pass
 (google.com: domain of 3oeovywykcewuzwrsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3oeoVYwYKCewUZWRSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--glider.bounces.google.com;
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

Introduce instrument_copy_from_user_before() and
instrument_copy_from_user_after() hooks to be invoked before and after
the call to copy_from_user().

KASAN and KCSAN will be only using instrument_copy_from_user_before(),
but for KMSAN we'll need to insert code after copy_from_user().

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v4:
 -- fix _copy_from_user_key() in arch/s390/lib/uaccess.c (Reported-by:
    kernel test robot <lkp@intel.com>)

Link: https://linux-review.googlesource.com/id/I855034578f0b0f126734cbd734fb4ae1d3a6af99
---
 arch/s390/lib/uaccess.c      |  3 ++-
 include/linux/instrumented.h | 21 +++++++++++++++++++--
 include/linux/uaccess.h      | 19 ++++++++++++++-----
 lib/iov_iter.c               |  9 ++++++---
 lib/usercopy.c               |  3 ++-
 5 files changed, 43 insertions(+), 12 deletions(-)

diff --git a/arch/s390/lib/uaccess.c b/arch/s390/lib/uaccess.c
index d7b3b193d1088..58033dfcb6d45 100644
--- a/arch/s390/lib/uaccess.c
+++ b/arch/s390/lib/uaccess.c
@@ -81,8 +81,9 @@ unsigned long _copy_from_user_key(void *to, const void __user *from,
 
 	might_fault();
 	if (!should_fail_usercopy()) {
-		instrument_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
 		res = raw_copy_from_user_key(to, from, n, key);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 42faebbaa202a..ee8f7d17d34f5 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -120,7 +120,7 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
 }
 
 /**
- * instrument_copy_from_user - instrument writes of copy_from_user
+ * instrument_copy_from_user_before - add instrumentation before copy_from_user
  *
  * Instrument writes to kernel memory, that are due to copy_from_user (and
  * variants). The instrumentation should be inserted before the accesses.
@@ -130,10 +130,27 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
  * @n number of bytes to copy
  */
 static __always_inline void
-instrument_copy_from_user(const void *to, const void __user *from, unsigned long n)
+instrument_copy_from_user_before(const void *to, const void __user *from, unsigned long n)
 {
 	kasan_check_write(to, n);
 	kcsan_check_write(to, n);
 }
 
+/**
+ * instrument_copy_from_user_after - add instrumentation after copy_from_user
+ *
+ * Instrument writes to kernel memory, that are due to copy_from_user (and
+ * variants). The instrumentation should be inserted after the accesses.
+ *
+ * @to destination address
+ * @from source address
+ * @n number of bytes to copy
+ * @left number of bytes not copied (as returned by copy_from_user)
+ */
+static __always_inline void
+instrument_copy_from_user_after(const void *to, const void __user *from,
+				unsigned long n, unsigned long left)
+{
+}
+
 #endif /* _LINUX_INSTRUMENTED_H */
diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index 47e5d374c7ebe..afb18f198843b 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -58,20 +58,28 @@
 static __always_inline __must_check unsigned long
 __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
 {
-	instrument_copy_from_user(to, from, n);
+	unsigned long res;
+
+	instrument_copy_from_user_before(to, from, n);
 	check_object_size(to, n, false);
-	return raw_copy_from_user(to, from, n);
+	res = raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_after(to, from, n, res);
+	return res;
 }
 
 static __always_inline __must_check unsigned long
 __copy_from_user(void *to, const void __user *from, unsigned long n)
 {
+	unsigned long res;
+
 	might_fault();
+	instrument_copy_from_user_before(to, from, n);
 	if (should_fail_usercopy())
 		return n;
-	instrument_copy_from_user(to, from, n);
 	check_object_size(to, n, false);
-	return raw_copy_from_user(to, from, n);
+	res = raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_after(to, from, n, res);
+	return res;
 }
 
 /**
@@ -115,8 +123,9 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
 	unsigned long res = n;
 	might_fault();
 	if (!should_fail_usercopy() && likely(access_ok(from, n))) {
-		instrument_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
 		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index 4b7fce72e3e52..c3ca28ca68a65 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -174,13 +174,16 @@ static int copyout(void __user *to, const void *from, size_t n)
 
 static int copyin(void *to, const void __user *from, size_t n)
 {
+	size_t res = n;
+
 	if (should_fail_usercopy())
 		return n;
 	if (access_ok(from, n)) {
-		instrument_copy_from_user(to, from, n);
-		n = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
+		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
-	return n;
+	return res;
 }
 
 static inline struct pipe_buffer *pipe_buf(const struct pipe_inode_info *pipe,
diff --git a/lib/usercopy.c b/lib/usercopy.c
index 7413dd300516e..1505a52f23a01 100644
--- a/lib/usercopy.c
+++ b/lib/usercopy.c
@@ -12,8 +12,9 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
 	unsigned long res = n;
 	might_fault();
 	if (!should_fail_usercopy() && likely(access_ok(from, n))) {
-		instrument_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
 		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-4-glider%40google.com.
