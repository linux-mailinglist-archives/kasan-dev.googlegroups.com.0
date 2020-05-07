Return-Path: <kasan-dev+bncBDEKVJM7XAHRBNHN2D2QKGQEMVJDGCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A40F11C9674
	for <lists+kasan-dev@lfdr.de>; Thu,  7 May 2020 18:26:28 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id b16sf2579944lfb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 07 May 2020 09:26:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588868788; cv=pass;
        d=google.com; s=arc-20160816;
        b=oSJfwaDVYdH+hqk7pGsUV5O5CenlxxN3zGADKLgWVF9OQp3a0dLeP5R23nEGQqW1ed
         ZN+8QpQMa6zyHa/lPVOI5ZLqCzwKKTNqfjXyHUG9gJJXfzDpr6Sepiwb1oZERAHQpot0
         +NriPFsSRGMz5oN90jJWGTMTpKuyOo8qUy5+61gawQnelDmguBPa+WKPaA/q/9V3F3Fy
         bgHcA23xB9K1UUJsvozSPFKApRCJj0HFhksdFZ80X5wXhz5jrPHL2h3yXeoFIW+e6hur
         PrJ+rvq6gcQnYwAoDFh20YJ67hQ4Anc1xGFDRhx+m4oMmEWHIL7uMGBX4x5VVgrF8Zy4
         EGfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b+lsTlqrQJbex/2kqD5HPezSRdJMg0jKf1dWrksWc+o=;
        b=oQJmMBaDEW48/ZpQIDj26DSsu3lqi6W0X1uUrX/iNYNmaWO80hkvtkRRqAYmvy6MJl
         TvtKpayUEOMY/rHcTipQVvVNeU5zMsFOZENdXFtPAiwOsHclzQYzc1braIK6qOzJmmh9
         Q617rHJS6IIbI50qrSw0xUdAld7TPDUBkEIBxIUZNLuPRKRk7kez4+T7985J78eBDi11
         AqeWhcVJucIQpUm2CBGED1+4K52x8jV2UwY6MbK5nYn7Y+EQ1AWliCFUUgs+Vs3vux16
         vAS1eKCbfe/fBiOeVIsryVIxAYoP7o+cGfWDmWmj34zuC7c7EXfUSPSCRHx0I3nLgFGn
         DWHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b+lsTlqrQJbex/2kqD5HPezSRdJMg0jKf1dWrksWc+o=;
        b=qyUxDePfMK5U6MPZiPC7s+MSPa0PQ7zrMhTw+62zEDSn/OSMcHZoN0a8gBQgrLbjxw
         sC06MMd0Rv9S+HIaW0+D5JK8n7XVHqTqD2XJim6ckebdZyMWyuu1U1sSXLqlmtRi5CVq
         0vxiq8UlFz9Ne2AbacJ/p3U+l1s1QvLeS4rpMMc2keOzqwZouFNvgFzzNlzle+JymqZO
         r2ZjfVmZfbhzzLXpr3BTgEOQZbFkNeIxyJ9/MhUVUDeNl7wP4cQ8YlYbCJZxhDvC9BoH
         AFUDCPSpw3ti/yeHoA/IVnO0jvpGIkzElDZXXIp/Ai+Z5hW7mHTh3NpW5heyawAkhCzs
         4zfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b+lsTlqrQJbex/2kqD5HPezSRdJMg0jKf1dWrksWc+o=;
        b=NxSNKxcHvh86HDiGqVumKk5ny/1+V6/ANXqfPoNpsYBgrwxNFOCad2YUc/heXhvFuS
         GKt/gfMu+z5uu07uWHKLD4HDEmyvu+2pLLbdWyor6B1gwy9fNN5qibQ5q/XH3jiHr0z+
         BIMU0ilZ+rXhcGd9yhV08BWViDB1mHNl7j21B8ZjIzlPms85JnxZb8aWtWsEGBB56S1C
         EToF5hsPA3+1W3XDdT4wnM/7ny+Ev0EpIuQS6BlQqHDz6yQ5UuKqyGQE05rexZDwOOhj
         lOvlyMn4S6HRzsMGWyl/H4O2CE0OpU/yE6BGC5u2/SnqqKWWXbvMyP16oFWTPl7unWq4
         Iqjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZnMSLgr7P0JKVotuTUrOZXt7zrywiPWWCRexNuvpojrdw85vME
	C2Q99lUn5qBhx1xXv3nXxZg=
X-Google-Smtp-Source: APiQypJZxxT8EL4WSznvLWo1/21M2xEg588Osoy7/dbOITTYbls8LVmlAvUwjE6hfsZbRXyMEluJ6w==
X-Received: by 2002:a19:4285:: with SMTP id p127mr9205400lfa.46.1588868788162;
        Thu, 07 May 2020 09:26:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4285:: with SMTP id p127ls1468671lfa.10.gmail; Thu, 07
 May 2020 09:26:27 -0700 (PDT)
X-Received: by 2002:a5d:4112:: with SMTP id l18mr5103963wrp.230.1588868787540;
        Thu, 07 May 2020 09:26:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588868787; cv=none;
        d=google.com; s=arc-20160816;
        b=AGiJNYVZtLAsq0eGHpUsSP3mmVeLOr28SlMI1jJHAqwc6pnvDeg2L8rheNZ0VxdG8o
         BTK5gBAVUs7TO8Kcm+EdIXJQSuh2Z3Y0ywEPzWacjXlrzNMS/Jvch9pb2ex6XnzoMpY9
         jhsnquMagbZeiCXLw1kUk34nDtlnhfHTUa0ccxLXhQtg6vmczwcOC//A/14IcaoiuqXi
         /xxx6i2BTjAgOmN2PEszK08Fc13FlMN/WYBV9a22rxC6aOtmdbvjiUTbVviEE4JcAqwT
         VzE9qau0IUa09Ee3xj7ZpYxuCQQlqhCm3MQBjTvqc8vQqzTlNwZZoiEwIhmBEonQ8Uus
         h4iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Xe++zp+Hh05Jlb+pK4WuxmZYz2xBi5Dm+GojoZZXueA=;
        b=oNYlMNdpQADz6Shh1fpnMH57F2mY2CsqWKsWHAc5aIeV/eEUR3eaRIYtRSVLlCIgYd
         6eKmwnG+2DatoJ2eI4ShfRFSFziAOLw/6lytKp43na56AwkBeu0rBrZlAG9JlMcBQp+M
         yK+z6FkYwf+9zSHhbr3YpkOdalt3ps6efkGX18t/1PyUG2VcEhYu+eq9fyc2fSXgkfbv
         VYY0hrC2U/8l6/tV0NsmVtMoQDJweiMoDL63SFufDE59hNNAfLsIUvZEHAbdsOSbV5Hl
         uH2kgGP7JnagiJFtuYiTB+XKvHz5P7hnHjOqIy0guUxuoMFhHvuSDK0gXbubi6O4NzO5
         CF5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.74])
        by gmr-mx.google.com with ESMTPS id m4si389756wrn.5.2020.05.07.09.26.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 May 2020 09:26:27 -0700 (PDT)
Received-SPF: neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.74;
Received: from localhost.localdomain ([149.172.19.189]) by
 mrelayeu.kundenserver.de (mreue108 [212.227.15.145]) with ESMTPA (Nemesis) id
 1MWRe1-1jeBD910tn-00Xufr; Thu, 07 May 2020 18:26:24 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH] [v2] ubsan, kcsan: don't combine sanitizer with kcov on clang
Date: Thu,  7 May 2020 18:25:31 +0200
Message-Id: <20200507162617.2472578-1-arnd@arndb.de>
X-Mailer: git-send-email 2.26.0
In-Reply-To: <CANpmjNPCZ2r9V7t50_yy+F_-roBWJdiQWgmvvcqTFxzdzOwKhg@mail.gmail.com>
References: <CANpmjNPCZ2r9V7t50_yy+F_-roBWJdiQWgmvvcqTFxzdzOwKhg@mail.gmail.com>
MIME-Version: 1.0
X-Provags-ID: V03:K1:Wu355d2keiT+DomNoCv1+GG6rk5RbqLzx+vkGjzDKtS+V3yIyQG
 6ihXPPX397wJmWAjP409EOBm8Lb7F4b5kdcec4kIwwwPQ3FN9b+jjt07gItE5RG+npOFhnF
 AtoA281a5IOmWhWqiiCkA8G/24I7wTZjfyMeqvC3+U5TxLO3coNrS27G7XjimIPp7D7H7O0
 AYIUgrAAEr4H3ddktCgrA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:bhWFnq9NWHo=:5tJlgXF+2Bv3nOEYTE0p9j
 NPqVpsQ/jxgKgi/vuEMU/q0I1znfnkbRj0TaJf7uMzprYNs6Z8WavH+Z0aIicQn7Qd1FAwuFA
 Xu3bmkkHmAjseqOjycwICf00icuCxzQFsCLKadIjQnpkZHLArutNStKOOg/rD/m9Zj7WEdEVs
 w1EWLd8ATnolfxyZfLfwGsaGV6zrpcSgy+wmQwCmKaa+7pQKxMzCvINVssmZxTaARcZJGb4kV
 UzfQ0DYqOigKSL8pC1Xt+piE5vr0Iwu0xfZzgiuzHUMnhQ37ra6wWPVkX2rPjuAHG+K1mPzfW
 aXC+84ux4k7hrjI5CmAQbb6VO8aTQE8k0fHTYoTTDMD+6Uo/XhkjQxe80wJWNBOomNtJ3nkD+
 3Z2MlGwgb892a/RLG/q9E3dDrsaAaRm0YarN0ljlJMhmeNA3oNMJDfK/1j2KI05P8Z6ynWsjr
 FFGd4tEXMOQHYZyp658iTwKGTpNtUDIz+NPtj3gFUd+OaBAU8t03wupeM5cUzyCsKwU92jGvr
 UEMvAhCl0mfH/Jh0wgfYydHKyJ6Gu2EV3cEjvf+J4TlKdE4sQvDDxcqoHXYvd3+lRPFNMOXBJ
 8Rxayg6e5/Upae+M7PwLfv89k1XL2VTeyz6Th/E30Dq71RUqt1rsPVmWg7nFnQ1Vyq1TTYauU
 6csJmqx1idVdulaXD70scaCmRvzLsI2pXDKhifXGNCEbJxeZGVpNRjdps2bdmpunI2PA57K5g
 fZ90kS53ULz00soz5VfAUg4LcH85CoZwE8YJWrYr9o0M8BgD0emMo8PmqGMyQIICOAvs/dXKF
 QJZfjlEvR8vhPJaFCyjkQX+mXRROG0zX7xkjfNm1qVeAM12amA=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.74 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
with -fsanitize=bounds or with ubsan:

clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]

To avoid the warning, check whether clang can handle this correctly
or disallow ubsan and kcsan when kcov is enabled.

Link: https://bugs.llvm.org/show_bug.cgi?id=45831
Link: https://lore.kernel.org/lkml/20200505142341.1096942-1-arnd@arndb.de
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
v2: this implements Marco's suggestion to check what the compiler
actually supports, and references the bug report I now opened.

Let's wait for replies on that bug report before this gets applied,
in case the feedback there changes the conclusion.
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
index 929211039bac..a5ba2fd51823 100644
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
2.26.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200507162617.2472578-1-arnd%40arndb.de.
