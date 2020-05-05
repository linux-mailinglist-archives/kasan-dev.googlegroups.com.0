Return-Path: <kasan-dev+bncBDEKVJM7XAHRB5PNYX2QKGQEKB2EAUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F24E1C5940
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 16:23:49 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id e14sf284663wrv.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 07:23:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588688629; cv=pass;
        d=google.com; s=arc-20160816;
        b=M36O4UBaHTI6ECLlr7iUMkjkKjKfZEXPSXFsF6c21115tFOvdlDFqEEN8VIV++UnmY
         tE/bWCmrfzU8JR+i5uw5iYJShYq/weOi6xcHJN369x2x8GgqTZqkEvZNYU6nTwMVmlmE
         /HG5QE/zkGHlI56Twfh0BMnWwZkCG2GPd8/Xhhu3kwDCzQNQFSfjt3ZErGwIt23Zgt89
         fkOCpzCIeQE46uKp8Mq8yHB3KHHSY4lUGYWYKfDSwpYQSg32KXVZ+ehG4yXO7bYadOSo
         PZfjeMlSXIgzVAQZZOLAAdHjH3vJQukO+ja/W3MQZtjEI1qu4WR8j2UHE6kMPXfQqL5Y
         sqtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=EXOh0CGF4ttQX63jC6lYTaZNO2ADV2sEpcrNLK7AtOw=;
        b=L4LC18E65jKoFzTB8xuwR7kDrmqvgVMPdVYncnSms5GmLg0un3FOTt/eW/9PAvXZ7W
         uRBi1Tf0YOJtcxMmATwCsPLJ+4st8vr7bGTMJHk3PNAuGmSPtf9mz68mETtVVpDKQZGh
         Gogr3buj5FPERpm2Thh7LdBjZ25J6BZWv+PpacJM5GVkR2krrMotVgUewZpRDzeYX+yp
         7KpxvsU1Ph2NAITy+IFckPB/oBrQ8zreoSTg+MSInqM/Yuh6N4XthDkGAI0cCbbtqNIc
         O3p7NXfu9rqdIELIok6jbW+EW5ax2sxTuoGwaD1j3Orb6oObf29HmQ5EXWvWieKpo1fQ
         R/RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.133 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EXOh0CGF4ttQX63jC6lYTaZNO2ADV2sEpcrNLK7AtOw=;
        b=lYmCZriUDvoPGKRDWlYyK3wCXZJJz3RC9BGVsC90inQUQBhbiF2pehG+BptWiqMfT/
         GNu5zucSbunETv6bKGHuWmR32g5OB0qSjIqzwv8UjR9e6jt5iSgKD1NSx5D94jgs7u+H
         TS6MMQmuYIQkWLiXCEyGvBJ4D1fBjEkPxrhVhaQSN0INSS7/9vWL/I9nQQceRFKl8pMq
         Fnmi8oDwl53vTEQAYu2/vbk9xCV5a7aIiATXDzRYdUn5LAk/VdR/NZVhFKzKu4O7xWfM
         BPtNGqQhOmhfonIwTYxSNl3e2k0VAz7rGb7SoRjOOr5m1MDohbVxwVxrn1yMFDW15zo9
         NV7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EXOh0CGF4ttQX63jC6lYTaZNO2ADV2sEpcrNLK7AtOw=;
        b=b3Ja2c1S+qdRJGw82OrMC7wSyb55tQ85W8teGVMtGPgPMNE8Md9ftEi7XxV886QE1C
         AAls9RbA2m5LhRkpRx/I0fBX/Ax76aDl+3w1ybz0VkEMhyeOCQVSdrQfMkJ2nnxeUABy
         V2sjOhA1j0RNvNsPTKpeM8n9PuWYEV75DhsRYCTO9fqR6JXoqonI34jtudWIJTK6I5aP
         b8z+ug3aK2w0eb3Fm3cqinyK5AqwH7TggTVb/wPrwVkq1on6i8TUVQkn64+fIyzYP6B4
         YrkAFGx+jISOyOXBzcjUyj5euocNedP5p6S8sskWiM6zHpBryOOn4hpH+HlqdxnMK67d
         p39A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYaOOebp7xE42aHb0QmnheUfOnfRMjvEk3vG5uSwlehsyzcqUbJ
	y6KLq1WmS/WfmpnJpxyAv0U=
X-Google-Smtp-Source: APiQypI4VeJj8kzrua2Bgwu+u/oyYhOsXDBW04mOyM/7wvPT+bhEL+my06mAnqBQxkeVKuSKobDUwg==
X-Received: by 2002:adf:9482:: with SMTP id 2mr3824506wrr.328.1588688629095;
        Tue, 05 May 2020 07:23:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa52:: with SMTP id y18ls3629524wrr.9.gmail; Tue, 05 May
 2020 07:23:48 -0700 (PDT)
X-Received: by 2002:a5d:4704:: with SMTP id y4mr4192396wrq.96.1588688628409;
        Tue, 05 May 2020 07:23:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588688628; cv=none;
        d=google.com; s=arc-20160816;
        b=bUZPdlOzWTOkI+Ln94sCv3Rl9x71ab8tj3lrFR2kqvd+u03qZOQiVzXOEevG8TDJuo
         7/kZL9L5AZXf/pzFyJgHzfv2QmNzk4o6FNM5sWUoW6gGUabGyIGoIriemi4OsrWPzcH7
         TjZbb0CMwHDes/gLXSzATg6IhMsP8FUh+AFfIZ6AQl789Kqu/Fl1R5Wz+uviOM9+CaHN
         A22NkAcEHCPhOXCvhhgs15UhU2hmwauKVQu8IpaTq6MF4/qdkjrsdEsexG77jxT81Xb/
         WXF/awOhSEA4dU1B15r/wvn6l/RZ4z3Jc6a8NkD8bmkqmJ9ftjdCOV4/3zMssUmLt03B
         9TUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=yWF8ElnkGd/20Oa5vCY8ksE6XbahroP7edCjO0yHack=;
        b=CCpYwcBBavnher3qlKDEDj+iIQDKI9jUx4Iq3vPf889yhFfHKtRs6WEQTYQd12Dyuc
         CA/BR5NTzsBtwmUz2jNUsYqgvvOS85SxMebtu+kEnpLJkH3sJtnpPk6lG1AxVHfseOo2
         uJVn5riNEu3vn9ctox9BLUmvsxq23pSi9eBb07UWYAJkp29/B8+3xfM54YQ+sOkphFFq
         lzN5JQ6tWyx01Qq+Zc91KMEtAhySwiy8OmDpQEGZx03FPK7d8IQSxxm+W4+5vOJ8MDqA
         jjRysgoUIVqbnkFA9oPpc7VVDgJjVUGfTgI9llyvcjScb/MOcUe51wTZamWyexJy9s0F
         8ldQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.133 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.133])
        by gmr-mx.google.com with ESMTPS id h8si101469wro.3.2020.05.05.07.23.48
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 May 2020 07:23:48 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.133 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.133;
Received: from localhost.localdomain ([149.172.19.189]) by
 mrelayeu.kundenserver.de (mreue011 [212.227.15.129]) with ESMTPA (Nemesis) id
 1MacjC-1izfbf1FxC-00c78g; Tue, 05 May 2020 16:23:45 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Kees Cook <keescook@chromium.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
Date: Tue,  5 May 2020 16:23:24 +0200
Message-Id: <20200505142341.1096942-1-arnd@arndb.de>
X-Mailer: git-send-email 2.26.0
MIME-Version: 1.0
X-Provags-ID: V03:K1:JkuyWhciBA/aX1Zn4ELUz4dlGvSAU8bKJNTZp0muHfNY70Is8/z
 PQV0xJ+scnfPXeY8VAGsx2N/Y2vXgGDZheALBVwZUXDSKdy2bdNc8Z2PrkSNFFxkx37YLNh
 Z8uFSR+Q7ZjuSdBRCdR+4L7yllPzaAJwmQMpAN3CrAdUbrJKkmJ6Yo+c3wz3JnveMWcxobE
 SMNSE9VDqfPQ8hFKI4AlA==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:tgXZYycAEVU=:lPwOc28vx5ScJrO1pHRcB0
 rxw0c5/ZDaDv7RJ/qbwYGydXNqqS6uzeVUc8MMG6ZeFq8tvKV9VIQc94u0AUEJjq6ImT5Ergq
 rQxaX/chIPGX53mBVBYn5xBOCx81eKmeB1EdXqJzVg7JqFW28UAA9cF59rYJ+gE3SIdVE/nIF
 SokPSHNDCMEspvYRh2CrNorucNVYsEL/AgJXbpn0PZl9zEzBI/djdSgv9/LrxhTmZHy6RNLUE
 0XwXuejTHjC9EKHXgxGmyIUKmcS1mLFyNsb+DxbdrfVMpE+7sgaqvu+wu/hPojVWMIQjmLQbw
 va+xgLG/Q6wh540kMi4yAggUI1qc+YuH3XnvyvGWm2EaSZiGURifJrwzJxYs+AKd6GMY3+3xx
 zsL2tW4o/QFVkXVNR5JSV3Gu/lrOox2IkJ/5AU+5kja6VhXCRbRnwK5syP3xa5FrLAa90z7GG
 KNGS1FYIS9p3t30+hicKEV5lf0yAA5vL0qUdN1K3S4R/r3h85XmgmeGlUrrcVOfjUpZYA2dk9
 zyS+Yy009Ly3gp687W8jivoGTTrxYJZYlepNS6lt/8vDb/J7ImpIIdirdhF/M54Hi8mLahoX7
 g8zh43nDHnieM2fROES6HZX+c0J9kkqV93/zcCVqpNhkDhw3WXoG5WeNSe67smre82rl1zcVA
 5LXl/C86XYD+LkZA9jjKLiW5xzOyR51h9YDAo1kKdMaxGYkMb/H7k3r8glnjcp9ECirj7K+Qe
 QfHceo3s8uzaulP7M3XrRegVhnYM9NriiEa192ZQQ2KEDUHhvlVvyy+FLDJHDDwAZ7rl3MTQ9
 3itAByRmtW1leBvDn6VsH+KZvYoOScPZVHB3svSQALiyIgicBA=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.133 is neither permitted nor denied by best guess
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

To avoid that case, add a Kconfig dependency. The dependency could
go either way, disabling CONFIG_KCOV or CONFIG_UBSAN_BOUNDS when the
other is set. I picked the second option here as this seems to have
a smaller impact on the resulting kernel.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/Kconfig.kcsan | 2 +-
 lib/Kconfig.ubsan | 1 +
 2 files changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index ea28245c6c1d..8f856c8828d5 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN
 
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
-	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
 	select STACKTRACE
 	help
 	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 929211039bac..f98ef029553e 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -29,6 +29,7 @@ config UBSAN_TRAP
 config UBSAN_BOUNDS
 	bool "Perform array index bounds checking"
 	default UBSAN
+	depends on !(CC_IS_CLANG && KCOV)
 	help
 	  This option enables detection of directly indexed out of bounds
 	  array accesses, where the array size is known at compile time.
-- 
2.26.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200505142341.1096942-1-arnd%40arndb.de.
