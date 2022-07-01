Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXMG7SKQMGQEX7TDD6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CDB31563508
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:25 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id w22-20020a05640234d600b00435ba41dbaasf1881713edc.12
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685405; cv=pass;
        d=google.com; s=arc-20160816;
        b=1H0CXzEzOJmpqmh5GcprFFa+Nw7nMWyLX7WyhOsYKvzivE6CZBCw5Y2bd23xLcRkOs
         c8TR45I4N3E8eZrBQHUFceeRARUCXeups5QATdYOdfSPcIJxWLaaSgwxM+zoTAwGqLp1
         mKimnolPPBPWS0rfkvG7QITgqoVUW0UBj0pKCFQ0+Jb5cPhmtCcviq3fH5aPigq+SmRi
         B0Ck6iwQHhsJ19J4iX5txRX/mP0WIYov1Pe0BuJZpyJ5+xdG8Pq3ykaGeC4bfVLnt1as
         nK/ip9f4HNRGGtoPXEjXYo67rHk+0YcBfuZ36DUqMNJXSjjANxxFvE34SaiZ4sEX/Zml
         jwxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=nrvyNHB45AmsWI9iSQ7KahKFC33IJMvGWNlGh6yAiTo=;
        b=QtiIOc23jJN38OSivYkQ8A4vW4ygJtICi6TbIZmcYHu7EOOUTI2ZAKBeZwhRyaDt6q
         Dj3Lrlj8vrJL1ys5wqdZhqTiGbac8MgBXD4H+QklLzZE9s50mO2+T3tKMceFrspa/gzT
         xPJcpRu5S24tNBFF4HYFSdhOMcIHUnMeHcqtqNDRmRgEClkr9g0hj2oaUKqkP44dtCFj
         HsI38dQf3CVC6nFXeF5UC8l3eldNQGYKKRmkOwHdBIIHJNTyxFydg/j7OxVGCRJum8UC
         zaRMSb2bFKo7P7kkj6LgNnY5BfvjdRaSLfVOpQDF24eOy/c2ksyHT2lwv2EaQBbfC8R7
         Q4kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BrwjnieB;
       spf=pass (google.com: domain of 3xao_ygykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3XAO_YgYKCXsfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nrvyNHB45AmsWI9iSQ7KahKFC33IJMvGWNlGh6yAiTo=;
        b=louWCH8wuk7SYPmp6rjaks8hFYT/E1RU1YfTmwL7xZG3mAjrv04IBhkjCT+hH3I75g
         59OjRAUkR52C1ESYx3GOr60SSDMszTKRL5K84M6q977Ez5dSyeVmHNjbwksCVIJHdV/X
         r//rFhC2/lckuk+NEo4lCK68x7xi1Zfy9l0n+F/up4de55gKjJZ7u/x31qC/af5Fntc0
         fXGxKWCTeqwj/y2s7ete3DJRgUezrwJnuGGFimjnoi7P9vPKFTfmiQDQjswYAUaEYzuc
         BPZFUNflNbCXZ1H8TQ84aHlpk51X4Jbm7sKWKjoQCxFas1/Pq4pOPIHg0hAsLw1hRu0f
         fxJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nrvyNHB45AmsWI9iSQ7KahKFC33IJMvGWNlGh6yAiTo=;
        b=hghDbm2+DIpLq6E16odgX3dUcYg4idIRHTZooSP8GeoL0GQVI/wXOkFJMb3Pvj7kVp
         C0YebqxTnzJLxCi2SI7S12Ca9tsCdRXApuDVjTUXVEHdTJiGS+HjYVtTqypCZ0bacGJO
         BQHzA8cj1JywCWIZwgbSURSLOi5i5EcXCiRviHz5lLjMj9ug5GjTvAhlFhVdwfiqYZaC
         tc8DRHkIBW4wimpPxkfeTCITCdz41SFpV3N4BnHFf6J/3T8q5SDN1idfHxfoxv2kCWrv
         otNSHldtPMzeALAnUSntbwv23iTcjOhR2GSoxd+iEyl/zERtrjIRqdTmpRPB2AMK7wAR
         AUuA==
X-Gm-Message-State: AJIora8e7/NrkpSiZDDg3QWcaSoV7Qbn72FlIuTvAOnj03XZPNY7te/1
	Iddp+a0niwPsgBBdupTOEyY=
X-Google-Smtp-Source: AGRyM1vle30n832mxFQdZIfOqbTQ7yAGpHVJ7aaINwqdJKuGWlJXooS0Etw6GtHrQmCmgjp65Ded0w==
X-Received: by 2002:a05:6402:380a:b0:437:d11f:b8b0 with SMTP id es10-20020a056402380a00b00437d11fb8b0mr19281508edb.425.1656685405539;
        Fri, 01 Jul 2022 07:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c9:b0:435:95a1:8b64 with SMTP id
 x9-20020a05640226c900b0043595a18b64ls367325edd.2.gmail; Fri, 01 Jul 2022
 07:23:24 -0700 (PDT)
X-Received: by 2002:a05:6402:5188:b0:437:618c:c124 with SMTP id q8-20020a056402518800b00437618cc124mr19253990edd.233.1656685404549;
        Fri, 01 Jul 2022 07:23:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685404; cv=none;
        d=google.com; s=arc-20160816;
        b=iIlqfFH4GjvRN1g7iAywL0wwUth5oaBifEn0KsLB3NJ1DMskIJQ3a+VeSmr2B5/RMB
         GJiSbXoV/vrzn48P8+k4oZvt1aza9lx77dZRVMKm5JGWSxI+Nb9G7FHgW1yq1FFOVhkz
         BV8WC7AeM08MUsvywQYZIAQUFrboJgFg44t98oX9f4+OJj5AZcu//StthcDeflVbhJEr
         /Yg/llUvfUAYyh3lFfn8bY4an9vIyN9H+QtUTfLIajoKRrdYE4U4PInj4ISM4miuQV+R
         dlKz6UK6wKl81+ZH78gA+y3yIlDYOFi9/nzY3B90MowBBzoVXliY36tCFvjYeXRY69ia
         vHVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=DM2lItfZBVLN/C7PGBgjPtkXFa/DP0+N1ALBTGezmzM=;
        b=SZP9RyrFtvzk34TBxgFMlQC3QrefLMoA1aEQnJ3V5vEOFtcEYW5yTpUK52k1+WupEZ
         Sz43OeUvrb299ahmARw/x/WMl44BinC64+Ib/InFEFVOj/Txt9zSXQwed6+3moy5iyU5
         pSlUh9oxizBAvRvwJlUUZPZ+epb1M7B/rgZGoJTVAEMCRBqCrWlXIienALTtyxXnBimz
         JWMD+PixpI3QFCTbgLIm/0aBkmsY1fvkcTR6IL2m0YWb/rNzJCW8y61JFvWqTrHBPtoJ
         d2NS6IkeU4/4DpyhPSyu7F7lgNYNg57PlB5DmuKOjrjxrNsQnS9OihMBVo+7O198UIjG
         InHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BrwjnieB;
       spf=pass (google.com: domain of 3xao_ygykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3XAO_YgYKCXsfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id i24-20020a0564020f1800b004319ce84356si914904eda.4.2022.07.01.07.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xao_ygykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id e20-20020a170906315400b007262bd0111eso841293eje.9
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:24 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:aa7:c2cf:0:b0:435:6576:b7c0 with SMTP id
 m15-20020aa7c2cf000000b004356576b7c0mr19716710edp.18.1656685404238; Fri, 01
 Jul 2022 07:23:24 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:28 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-4-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 03/45] instrumented.h: allow instrumenting both sides of copy_from_user()
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
 header.i=@google.com header.s=20210112 header.b=BrwjnieB;       spf=pass
 (google.com: domain of 3xao_ygykcxsfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3XAO_YgYKCXsfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
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
index 5a328cf02b75e..da16e96680cf1 100644
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
index 0b64695ab632f..fe5d169314dbf 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -159,13 +159,16 @@ static int copyout(void __user *to, const void *from, size_t n)
 
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
 
 static size_t copy_page_to_iter_iovec(struct page *page, size_t offset, size_t bytes,
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-4-glider%40google.com.
