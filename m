Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEH6RSMQMGQEMXOBLOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 510EE5B9DFD
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:04:49 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id e4-20020a195004000000b004979e6a0c88sf5645752lfb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:04:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254289; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4aMmoOvSXWeLHx5RcdKOWtopIKnDJXQRyDn/+1wp98tF/YIFAocluIsBIwGf7tITJ
         ppwqkelgrCn9cKNi0hJHH/YNWPJM1Sj2/Eg/xbHgnvvJz5D1XTAUahDx6hxriQJXmpRz
         9Hh5wndiV67SGeyyM9Up5xlRoExtYvkd0unpelfF+Nb9JHntLPuzQH6D7vH6GUtev/OM
         l+Wo8kyBO3PIfVV7AQSasjq08z7kCspoQPYzESECNGSy6UDtk9iHJryS9pPvwziHUjOi
         +iP/HwcNkc2xBO0JUG7jfd3ZSQY+eEk6ftclZZGXVg9ZRBNWUpiqDQCOMIHs0pTM3clO
         AMNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Uk3IMW3tuVV7H87fv35A02JMsRBbyyI4u/RugzCIC08=;
        b=ab1xLXqmWNXquOiWLAr3BzD3Z7T+4mNfqJB2LsKP2g1ftz+LPGhrL4ll6vHHKk73AF
         oWfIY9aer2Vq3slYce0FIgAJEPmxeOerzGLhTn+IlATSE9fUZmWwXdKMS5aj6Hi4sQAz
         Gahi2E3F8yrd3wI4ktObmczATcrOzDeRuTdt72cnn2LLSZu8ywIsTk0cZxhuVhnZNxgM
         +906EOvrBrU6KS3JT9gdySGRSycyrUi51x+gjX7GL2qEDNGHD4emFcVMClz7bZkM1BbC
         KoldvaZXbSpjxz4L2lZT//7kidpLxRiDg672vEfQTf3LtYeWo7QQl3RACz9oA5nWw5vy
         qg0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OJ1zZnED;
       spf=pass (google.com: domain of 3dj8jywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Dj8jYwYKCTkbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Uk3IMW3tuVV7H87fv35A02JMsRBbyyI4u/RugzCIC08=;
        b=dXnPXmLV/WUx/tlwg+UY8GE0Ys6Ri3wMRpAGWs36gOXkrCpXTIIAUg3n3QZT9rBrgF
         ofdIH49Wa0MJi3leE19xewd2m/OJHUNSVKxviONLY4dUO3EPe2/JEjacYt0m05WfpS5l
         Cz69d/Xf7CJP8yKEyS3bMfzY6ajlPrnOd4+LuTum058lEDO+0yaN2gzLNfI6BKGfSoJk
         /2vOO5VHyWIbZIEueVfS6zYumFS5f5S7jqCG4XZuuwLwgJHlYi4HkKO18QjDmB3rCAxc
         b53cSFE9FmiHxJIjUNDHa6pHNL4t8mVrTw7G2Cel1My9NioQ2mMiEYDPRpJa8nrFfV4F
         pGJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Uk3IMW3tuVV7H87fv35A02JMsRBbyyI4u/RugzCIC08=;
        b=L3W05/DgFWJ3PkRtpNDMWqmtRBWTRQnp4DesjrOrfJKY7sPAE0z/f/uySZjl6LVrCW
         Niv3+/XsPFy/XQ7onsXRr8z6XvOcPPGMS5Q4BB5c1GeajhGLGkk5fcUt+t+/CrDPFKUV
         qwvc1xS/dnD34LbPfs89cdM4+PO4tMs8/awrcB5R1D1Xq+fp5ylZAxtBNtJZbJ3oZWUV
         Jc1KlCnP354gv/9qf8WLAtg9rl+Ek1/lmvnzbJ0T/5xRGm/1pcdq9JSxLf0UWWLOujCK
         PWB7dYj3UCcAAuzmtnx5lbXASnW4QrVDqxMsU1v/6ObCzpCbH3kdjG5Y8p/k0XaMSTEb
         7caw==
X-Gm-Message-State: ACrzQf0riv/rzK6eECCQjrEeTEoD9oVleEeMB0kZwz/ynsz02CbhRpwg
	ui+ebyZhP/dTNOnyPnbL2GY=
X-Google-Smtp-Source: AMsMyM4kZ2QfrFfK8HHXvXR32iWXFdUfiWdqYFFL+ZnU/qxqCIhh6QXHEXyvBiH5uBnxhSkd8YUivQ==
X-Received: by 2002:a19:dc4c:0:b0:49b:ec86:fb96 with SMTP id f12-20020a19dc4c000000b0049bec86fb96mr118517lfj.440.1663254288680;
        Thu, 15 Sep 2022 08:04:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:36c9:b0:49b:8c05:71a5 with SMTP id
 e9-20020a05651236c900b0049b8c0571a5ls1225875lfs.0.-pod-prod-gmail; Thu, 15
 Sep 2022 08:04:47 -0700 (PDT)
X-Received: by 2002:a05:6512:201b:b0:497:a29d:25c1 with SMTP id a27-20020a056512201b00b00497a29d25c1mr129776lfb.276.1663254287054;
        Thu, 15 Sep 2022 08:04:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254287; cv=none;
        d=google.com; s=arc-20160816;
        b=a+cibgF7P4hJGIyVWzF79jz4IxWg4qlpVrRzipMvV523BcX0UaYJNpvTRKOLStKrTf
         53zIG/EBKmJqIJIZDAsYNll48ZtrPQzqk/YqAqW6KRLjpzxYQsFKs4KzmIq5IP5BbK6D
         HaaBSb6aD8Q/MO375A4spj0S7VlfmckYdUi/ohxjaMrV7tJkaCf+qfi9oGCyLyTLEx83
         a57uqzdyKe1IOwuEWXJSe1uxl64pQwmBL3qpDxL+SETUGazDF3a/VnI/PDxeFOK39aaV
         CA9Csn5s9MBU4tC//7ME9Ovn83uplWmred3TRezLD3tQ0fh0jhxoFE2GP0eiPta7CTdn
         /GyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=msgzHzsxvMZcLqG5jRq1WtDuSKgOL7FjSU3mDqU1uyE=;
        b=d2SSM92ODf+p0puzZaf7HEzHNVinVCcvct9+574Y3gm9uiPb3rtyIaan6dMIwbtlIO
         j9Q/B4LIbh+6OIUYY7QZ/aeMyiG/aoNC3foBuHcmmzlqyqbDejalChbYDYR3qg6poKH6
         JqtHZHgCmxzo8AF+jQ3pyOQV50E65s9QU6/8bcZvSNOiB2oGFwM4kHTDQw1a+Skmy+Me
         zYywjPEHHru5qo2rWKT44pXLjG7M+iv7G/Q+dLHPOsfYM5eZSpL9DrBayrmiSYf1WIXv
         qA9UAl+o2ymkPbC2cI8MuVSXUgyt4R5SdaGOJcGMsWXdpehEDjygIZQP2rvQdBadzwDj
         rNOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OJ1zZnED;
       spf=pass (google.com: domain of 3dj8jywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Dj8jYwYKCTkbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id a8-20020a056512200800b00498f2bdfdcdsi549526lfb.3.2022.09.15.08.04.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dj8jywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y9-20020a056402270900b00451dfbbc9b2so8662298edd.12
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:47 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:7612:b0:771:db66:7b77 with SMTP id
 jx18-20020a170907761200b00771db667b77mr309998ejc.228.1663254286414; Thu, 15
 Sep 2022 08:04:46 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:37 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-4-glider@google.com>
Subject: [PATCH v7 03/43] instrumented.h: allow instrumenting both sides of copy_from_user()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OJ1zZnED;       spf=pass
 (google.com: domain of 3dj8jywykctkbgdyzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Dj8jYwYKCTkbgdYZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-4-glider%40google.com.
