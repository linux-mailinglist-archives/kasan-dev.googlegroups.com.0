Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVW67L2QKGQEHCIX6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 844871D52EB
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:03:51 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id mt16sf1964181pjb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:03:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555030; cv=pass;
        d=google.com; s=arc-20160816;
        b=lF0SGFhSfosH72Co3FvPnoIpZQSIZxaKrQpQyTF5TYcWvBZxlLiC2z6W7a8e7jdEeP
         jTZCzqCE87P9mSAS73FqolOLLNDb+s4MBhARU2HG16UPVuM7HmiRu9RbMqNtvD5f8amc
         Sh9mbbhvreWaq2rJk0bufIgQ6flYRaCAC57+qGvsJha22BJITC4rhfzExakdmBPvwqhe
         vXsDAHl7HHydCr/4dejNzCegGRRmnmUpOahdERM4k/BL4qE32ro9CquYciO9Xg7GUr6e
         aFAPCdDyl12FxdVeHRJOhLPjLqtIBIPtFFWAqEEBK2U7byQM8XzlyPghuuWmqB1h4gDg
         oakQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=FeG3Nk5KC4nG7h1CTE9Mxpe04wz7WOnwLMGv8v1FChM=;
        b=H5yjFnL6Y3hXHG8KEfE4zO1/A0SI4TDoqCr1dQXTWM9x6x4zmpPe3YF6L8g+LyNl0T
         M/ciXS1LNvXswB2GoG5HX5RDu/FwrN8hXpHf6p7BGU9LWZkzwXpyBT5a84vusRK/tci4
         4PEJiPEI0TUpmdN82USFgIOmqXuFTMh6TIOUqXJIj1/HU+FjlxLetc4I6eqxTouZnhbH
         8MS+pBcwKlJUOqICkU4jet7K8lHzIBevBwq6lg+pl9+4HId5PIEobUMCa47HV+kr9pG2
         5EEgnPPScNMo0QkO69wxt8vQJGMJKQONjctjRfamH89MpDGGYjusu6Wp/EBks7LJ90eb
         vHEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ppjy+eUs;
       spf=pass (google.com: domain of 3u6--xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3U6--XgUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FeG3Nk5KC4nG7h1CTE9Mxpe04wz7WOnwLMGv8v1FChM=;
        b=PtFxrsAbFXjAQjXC4iS/DB/nWeNhjNbaJNmr1uCFohxel64pWzm03qyiFx1tMKUDVb
         V4e1k6qwJrGbXabAFZBj2p/eQz5rezk+Hi1ixnEr4Tqp27UZOX+zeBEcCiJR4rT9mGRM
         tSaVJFd2U3mMMSndU8fd0h6JWa0boPZp4Oo71+4tib94uGvepEOk0bfYOjdRIdyiUUR3
         oAf7wHMgLo4v0Pj9mRsHnJYJMPonmM6KhqMPsz8ME0rrkPSyBeJWqYG/N7DcOthuJ4Sw
         vPlM8MEVnnkQnj3beTcdzo6FxVenvIjq2gTKVCELG1aGk6HY0/TcXHJgT7AefDwOf64g
         ZCVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FeG3Nk5KC4nG7h1CTE9Mxpe04wz7WOnwLMGv8v1FChM=;
        b=TQqo/SacrGPddSaxty4e8UwFQ5Nmas4G3qA6ngoVJ4Bsn/6gosaUTu5GBMC2d7Yh42
         1UbK3uAvWgi2WT4qtHa/LrYPCRoWVTXCOsFD81nYqmHAZGou8dGvSBYzxCCVBLuYwYfP
         zP7ZStY5GE+zlMFvpXDjPeL8dGrK8RG/2mUV/6eu7cnSs2ZiAo9EEpSKNUzaZrU8q0i/
         mU3LyZXdU7b9yjbFhcQyb3uNeKKItwEtAULYMgx1VZ88uzILpxhSaq16t/swu7LrXB5j
         hY32ohx3v/scGbp54X2zgfhW3Sd5zduWq99YpSG+ydFHdJPDP5CmbMaDzG9RYymryAc4
         55Dg==
X-Gm-Message-State: AOAM533Cc4nKBxTzs7xqmWJ36Ym2/aBBkRZ1Qkzo6CAN2t/zwF1x7pW1
	GmbFlQkNKrH2acyegNV0SPU=
X-Google-Smtp-Source: ABdhPJymCblkYklIvf9q1q6P6CUSEwxL7ffbUcdTSdBL8ggiZHut2CZIor3pN5Fql3r7xKN21Fy11w==
X-Received: by 2002:a17:90b:3017:: with SMTP id hg23mr3672947pjb.150.1589555030120;
        Fri, 15 May 2020 08:03:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:191c:: with SMTP id z28ls817864pgl.11.gmail; Fri, 15 May
 2020 08:03:49 -0700 (PDT)
X-Received: by 2002:a62:794c:: with SMTP id u73mr4550528pfc.56.1589555028822;
        Fri, 15 May 2020 08:03:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555028; cv=none;
        d=google.com; s=arc-20160816;
        b=jK1ezoNEkONCiuhfWaK1Rr8ay3LcCZjtHCA1OnnP3JW8pirmNURrciaezrESmHeYvv
         2e+p5WiUqtOhzeFE18JA10qKyDE7JKTaNdXqrXBk++rRFLWNKf8gxHHKJ80Pnp90cXjz
         Bws/rZYBTUprcZywk60+XQO6d/FPZL2Pyahf67w+en1yQnE/ETKURVt0A37bBe4DQSuj
         eVg6QIosbAAbG2t8W0goLEzzgRx4pPsv95f8vrpTKaRDLyhnAUc6Cw66SZShR70pUijn
         I3p8syRbY48pmAHS2Luo9YaflRc6FIUkZS9n2MVTujht/0AogTpDrDnDmRrnOLHGt0lK
         yMpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Rd50Ui3HZ2EL9EcMGbbjqrEeCeIHgbARzkGzMmh8b1c=;
        b=Yb+hphHF3krmlhnqMWDuGKF9hoZahs6xoaQ33EXLm1ekrOcDE7ocOQ3M+xqlWTq6zk
         TYLE+zGv/WpSCI0mCxEI2aECWterKO4cXwE/zUHkU4CvOFCF5bRzAR5NPe87b0V9CrI/
         vMJBivbUzeqz/Kbm2qAjpNZEswt2Zh+KSy/nbSWg3tLW9JDRAXxWZU6yhwTMXTuIirP9
         xrSMQBK5QCpc7TnJOLcyZ2oEicWDIy6Zty9JdVPgqp7XM1OsXoB+aTX20IYpZS27HvuT
         IeQJ1stTLDOeRrKwgB75c50+qmbI+R7A6dlE0Ylg4bToMIgNj65V8tv3H+9/3Ym9qyxL
         MWJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ppjy+eUs;
       spf=pass (google.com: domain of 3u6--xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3U6--XgUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id e6si217585pgr.1.2020.05.15.08.03.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:03:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3u6--xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id y7so2859813ybj.15
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:03:48 -0700 (PDT)
X-Received: by 2002:a25:60d6:: with SMTP id u205mr6281104ybb.440.1589555027743;
 Fri, 15 May 2020 08:03:47 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:29 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-2-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 01/10] ubsan, kcsan: don't combine sanitizer with kcov on clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ppjy+eUs;       spf=pass
 (google.com: domain of 3u6--xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3U6--XgUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

From: Arnd Bergmann <arnd@arndb.de>

Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
with -fsanitize=bounds or with ubsan:

clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]

To avoid the warning, check whether clang can handle this correctly
or disallow ubsan and kcsan when kcov is enabled.

Link: https://bugs.llvm.org/show_bug.cgi?id=45831
Link: https://lore.kernel.org/lkml/20200505142341.1096942-1-arnd@arndb.de
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
---
This patch is already in -rcu tree, but since since the series is based
on -tip, to avoid conflict it is required for the subsequent patches.
---
 lib/Kconfig.kcsan | 11 +++++++++++
 lib/Kconfig.ubsan | 11 +++++++++++
 2 files changed, 22 insertions(+)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index ea28245c6c1d..a7276035ca0d 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -3,9 +3,20 @@
 config HAVE_ARCH_KCSAN
 	bool
 
+config KCSAN_KCOV_BROKEN
+	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
+	depends on CC_IS_CLANG
+	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=thread -fsanitize-coverage=trace-pc)
+	help
+	  Some versions of clang support either KCSAN and KCOV but not the
+	  combination of the two.
+	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
+	  in newer releases.
+
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	depends on !KCSAN_KCOV_BROKEN
 	select STACKTRACE
 	help
 	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 48469c95d78e..3baea77bf37f 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -26,9 +26,20 @@ config UBSAN_TRAP
 	  the system. For some system builders this is an acceptable
 	  trade-off.
 
+config UBSAN_KCOV_BROKEN
+	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
+	depends on CC_IS_CLANG
+	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=bounds -fsanitize-coverage=trace-pc)
+	help
+	  Some versions of clang support either UBSAN or KCOV but not the
+	  combination of the two.
+	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
+	  in newer releases.
+
 config UBSAN_BOUNDS
 	bool "Perform array index bounds checking"
 	default UBSAN
+	depends on !UBSAN_KCOV_BROKEN
 	help
 	  This option enables detection of directly indexed out of bounds
 	  array accesses, where the array size is known at compile time.
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-2-elver%40google.com.
