Return-Path: <kasan-dev+bncBDOILZ6ZXABBBSN6V72QKGQEEIC76KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B56A1C0FA0
	for <lists+kasan-dev@lfdr.de>; Fri,  1 May 2020 10:35:22 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id c6sf1470899lfg.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 May 2020 01:35:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588322121; cv=pass;
        d=google.com; s=arc-20160816;
        b=lXzXrgX3GyK4KG5JRHuOKA5yJ1dEDL/q/TawdsYmImQplqT+E83H3pVmnEUdsIp4lO
         6UBXbfNKEJXGOKe5Y2Q9rQ0uXV6pIF4iB06JyUAxW2Lj9mQlgwjHffuoGoswAzSZWvXU
         Xv443Go8OwYYOpzByLtArVqyycaznfiyKIR14/ReT+7SoeZLDEhroTvKboBtSiO2Y/5B
         G/RPcP9gxLhrUu9oOX1DABR/0yuPIkaVm2as/ba8MfykHvgxC5K9wUSG8lQY1+6gUAOv
         CKJtrA1EXxUtd9B41LyU++vxnKHniS5JlQB/jz3cqAjcwUBs3UgDROliBH3I/jIDKzvo
         U28w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=L0PWJamtXSd6iBdL/49G4m1XST9DnkK4sSUYNC+ROnA=;
        b=Zr40b1vGmrquY2dbVKXQQ6QHSBWvxT+lfetaVJMlxrUja0cqwp63ZKlhjF4WsAZUnk
         BEcnzyFI5rWkoxwrT66G72goSYlqF8qVHB7+h+HuXjb7BHhTlVXrG9i4qY9cPM+u4Cz7
         jr5iA9R/tsY22RvqWIxZC+U6KNeL99+HTJ2Iv/rpRMX/yAAU0Mly+YTPLjv9gy2U/FW1
         wCw1Rld/7vD8fHfhVCTU3EsINeFYyD+B1MET5r3Bv4N8SXmpTUVSDMsbezN5Rd/8Prl2
         bcaJV/asIE+EENg0HayKRcuf6tFfLBEICVYjRoQevCPBh3J7bP8XKJjtv7NFhPLENAIA
         uCeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=v3aIzTXf;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L0PWJamtXSd6iBdL/49G4m1XST9DnkK4sSUYNC+ROnA=;
        b=LHi8h5cxrpr8P0FluwcAhBiRfFJdyILD3VTQpWCSmHuuFOgbifuU3JSMncQXZzr1G4
         1rfNGRrD1pNm6Htybhuj9hF+OQo2e1tESrGvm8ch62rIJ6iycYiLe+ncBjaDX+wavcms
         WgDhwAbDvBOjuN0g3FFVvRJ6ymCCiJqxLkMKbBsbqYqvuUn7oyPbfzvdTkzH4gV9vhbM
         h9Py1TpmYASrfsOpCm7kBXzCZvnS8j+ZbuQDTAuSLtg9t428BVyHethmclMAhFvgto1v
         QQYdR046zZpHVF7RkVC6yhJi0YhGdI1poD43343Xq8+4FKq9Au5EWEEgI5SaN4rnnLdM
         /Irg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L0PWJamtXSd6iBdL/49G4m1XST9DnkK4sSUYNC+ROnA=;
        b=n9tXtWj7Eiqit73N1U+8rvnmLXSjXlDd/iumt1gqOQYMtHx4k3T/oKW/z1ZG4qFpco
         zGZ8IuOJnxm3GvDliFTWG/220//2WSb6n6K6Isd7XwZnZTi785ayZonDGFEO+Q55RP+K
         VqHtKzcklPtqRGE0KeSqm0kwmNu35Ymjgb05IbeaVRbfg0Pu1SpXJmPJJtvqJ+t1l7Y3
         RU5iGFPBSu/AJJg6YRqbV2LrT4TwfgQt0fumf13Z8cOhx/8SjL6UtgVeQVEM5f5CFtS+
         r8w5GJnsnpvR7WU6qJFzCng4vZYpUWdDm04ZRyI60c10rrgTFvGfqZAEHhH3GtrP63lj
         LzCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYZFyf3djD5C3uml9kBfPQnChpveWSyjePE2jvJ58i/bqyMSh8y
	n2024nMm2/GmPG96TsQdhxE=
X-Google-Smtp-Source: APiQypLrwHDrFwEkpQOgBT26tzd7JXn9aeaLENQuP7+cCKG2TlZ3YDGoCEyJfe3cWD+hAZ//46dRqg==
X-Received: by 2002:a05:6512:10d0:: with SMTP id k16mr1902339lfg.71.1588322121638;
        Fri, 01 May 2020 01:35:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:288:: with SMTP id b8ls1192304ljo.8.gmail; Fri, 01
 May 2020 01:35:21 -0700 (PDT)
X-Received: by 2002:a05:651c:112c:: with SMTP id e12mr1809025ljo.127.1588322121071;
        Fri, 01 May 2020 01:35:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588322121; cv=none;
        d=google.com; s=arc-20160816;
        b=UIxwZQHHINcwEFzenx+LRP+kwUZLgdwdUB01SEexZQkLug01tFGwTFECcF3ZSh+vni
         9EdlBslXkH/HQP6SyCtoY68MS2nSVAs7+NuqQUxEi1BYT3F91PxtrLWpPSgxKtxShsrv
         Yo3e0UjHPx3xlgotQ+ekz1a89d3uuLY9bCFOtLWfynh56ydC+I9+U1NzowUIzcqt0tII
         eHmOisKIw50RLgFECg4Exx+kwK9AmWvRcKR6b/pdNjFoMmdlUnfjOTDYZ3w/8U1ANOLd
         Ijebdyhsf4oDAhcfrNisIeDUKxkbWAy+FXGAfJNplqLqz6ioSx/hfX/iIUshvx/4QDWV
         qSZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=uxqGfQnbNLpuSbmHYR3QsXvpUsDHwV7ckml89C19bGY=;
        b=qY5zU5mRBTeuHWtRBSCH55SjD2PkgBcTaw51jO4nIxyTLOjxw5gMHj5BYnw0idfBq4
         R2FnxLZMKmUOcjqGgSDMFX9yv1linP0+jLKSZQXtCb7/ar5pV3yZ/+SiVpg0vZ/DzmAY
         XtEAY6c8rqpCtRp7yv9yeTvtHhWjr3L2LU2FLIuvSPcTa2J8Q6MX7k4GIGHZAWDOPy6k
         yNO/rQJjNzXHFMrSymJwCUkzFkbQFfTsGFr6LOqNZDi3kPsFoHDs1PGkF5QDYrV7wv0S
         vGAOOQyXqcwMh/SCiHs6KQf8Vz52yJqQuY4Snu+Ek+VfL2TRjEglWXbCF0mXh76D5v0M
         yvKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=v3aIzTXf;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id b11si139590lji.0.2020.05.01.01.35.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 May 2020 01:35:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id b2so2022899ljp.4
        for <kasan-dev@googlegroups.com>; Fri, 01 May 2020 01:35:20 -0700 (PDT)
X-Received: by 2002:a2e:3c05:: with SMTP id j5mr1710060lja.280.1588322120443;
        Fri, 01 May 2020 01:35:20 -0700 (PDT)
Received: from localhost (c-8c28e555.07-21-73746f28.bbcust.telenor.se. [85.229.40.140])
        by smtp.gmail.com with ESMTPSA id t3sm1543110ljo.51.2020.05.01.01.35.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 May 2020 01:35:19 -0700 (PDT)
From: Anders Roxell <anders.roxell@linaro.org>
To: brendanhiggins@google.com
Cc: gregkh@linuxfoundation.org,
	tytso@mit.edu,
	adilger.kernel@dilger.ca,
	elver@google.com,
	john.johansen@canonical.com,
	jmorris@namei.org,
	serge@hallyn.com,
	linux-kernel@vger.kernel.org,
	linux-ext4@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	kunit-dev@googlegroups.com,
	linux-security-module@vger.kernel.org,
	Anders Roxell <anders.roxell@linaro.org>
Subject: [PATCH] kunit: Kconfig: enable a KUNIT_RUN_ALL fragment
Date: Fri,  1 May 2020 10:35:10 +0200
Message-Id: <20200501083510.1413-1-anders.roxell@linaro.org>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=v3aIzTXf;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Make it easier to enable all KUnit fragments.  This is needed for kernel
test-systems, so its easy to get all KUnit tests enabled and if new gets
added they will be enabled as well.  Fragments that has to be builtin
will be missed if CONFIG_KUNIT_RUN_ALL is set as a module.

Adding 'if !KUNIT_RUN_ALL' so individual test can be turned of if
someone wants that even though KUNIT_RUN_ALL is enabled.

Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
---
 drivers/base/Kconfig      |  3 ++-
 drivers/base/test/Kconfig |  3 ++-
 fs/ext4/Kconfig           |  3 ++-
 lib/Kconfig.debug         |  6 ++++--
 lib/Kconfig.kcsan         |  3 ++-
 lib/kunit/Kconfig         | 15 ++++++++++++---
 security/apparmor/Kconfig |  3 ++-
 7 files changed, 26 insertions(+), 10 deletions(-)

diff --git a/drivers/base/Kconfig b/drivers/base/Kconfig
index 5f0bc74d2409..c48e6e4ef367 100644
--- a/drivers/base/Kconfig
+++ b/drivers/base/Kconfig
@@ -149,8 +149,9 @@ config DEBUG_TEST_DRIVER_REMOVE
 	  test this functionality.
 
 config PM_QOS_KUNIT_TEST
-	bool "KUnit Test for PM QoS features"
+	bool "KUnit Test for PM QoS features" if !KUNIT_RUN_ALL
 	depends on KUNIT=y
+	default KUNIT_RUN_ALL
 
 config HMEM_REPORTING
 	bool
diff --git a/drivers/base/test/Kconfig b/drivers/base/test/Kconfig
index 305c7751184a..0d662d689f6b 100644
--- a/drivers/base/test/Kconfig
+++ b/drivers/base/test/Kconfig
@@ -9,5 +9,6 @@ config TEST_ASYNC_DRIVER_PROBE
 
 	  If unsure say N.
 config KUNIT_DRIVER_PE_TEST
-	bool "KUnit Tests for property entry API"
+	bool "KUnit Tests for property entry API" if !KUNIT_RUN_ALL
 	depends on KUNIT=y
+	default KUNIT_RUN_ALL
diff --git a/fs/ext4/Kconfig b/fs/ext4/Kconfig
index 2a592e38cdfe..76785143259d 100644
--- a/fs/ext4/Kconfig
+++ b/fs/ext4/Kconfig
@@ -103,9 +103,10 @@ config EXT4_DEBUG
 		echo 1 > /sys/module/ext4/parameters/mballoc_debug
 
 config EXT4_KUNIT_TESTS
-	tristate "KUnit tests for ext4"
+	tristate "KUnit tests for ext4" if !KUNIT_RUN_ALL
 	select EXT4_FS
 	depends on KUNIT
+	default KUNIT_RUN_ALL
 	help
 	  This builds the ext4 KUnit tests.
 
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 8e4aded46281..993e0c5549bc 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2123,8 +2123,9 @@ config TEST_SYSCTL
 	  If unsure, say N.
 
 config SYSCTL_KUNIT_TEST
-	tristate "KUnit test for sysctl"
+	tristate "KUnit test for sysctl" if !KUNIT_RUN_ALL
 	depends on KUNIT
+	default KUNIT_RUN_ALL
 	help
 	  This builds the proc sysctl unit test, which runs on boot.
 	  Tests the API contract and implementation correctness of sysctl.
@@ -2134,8 +2135,9 @@ config SYSCTL_KUNIT_TEST
 	  If unsure, say N.
 
 config LIST_KUNIT_TEST
-	tristate "KUnit Test for Kernel Linked-list structures"
+	tristate "KUnit Test for Kernel Linked-list structures" if !KUNIT_RUN_ALL
 	depends on KUNIT
+	default KUNIT_RUN_ALL
 	help
 	  This builds the linked list KUnit test suite.
 	  It tests that the API and basic functionality of the list_head type
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index ea28245c6c1d..91398300a1bc 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -46,8 +46,9 @@ config KCSAN_SELFTEST
 	  works as intended.
 
 config KCSAN_TEST
-	tristate "KCSAN test for integrated runtime behaviour"
+	tristate "KCSAN test for integrated runtime behaviour" if !KUNIT_RUN_ALL
 	depends on TRACEPOINTS && KUNIT
+	default KUNIT_RUN_ALL
 	select TORTURE_TEST
 	help
 	  KCSAN test focusing on behaviour of the integrated runtime. Tests
diff --git a/lib/kunit/Kconfig b/lib/kunit/Kconfig
index 95d12e3d6d95..d6a912779816 100644
--- a/lib/kunit/Kconfig
+++ b/lib/kunit/Kconfig
@@ -15,7 +15,8 @@ menuconfig KUNIT
 if KUNIT
 
 config KUNIT_DEBUGFS
-	bool "KUnit - Enable /sys/kernel/debug/kunit debugfs representation"
+	bool "KUnit - Enable /sys/kernel/debug/kunit debugfs representation" if !KUNIT_RUN_ALL
+	default KUNIT_RUN_ALL
 	help
 	  Enable debugfs representation for kunit.  Currently this consists
 	  of /sys/kernel/debug/kunit/<test_suite>/results files for each
@@ -23,7 +24,8 @@ config KUNIT_DEBUGFS
 	  run that occurred.
 
 config KUNIT_TEST
-	tristate "KUnit test for KUnit"
+	tristate "KUnit test for KUnit" if !KUNIT_RUN_ALL
+	default KUNIT_RUN_ALL
 	help
 	  Enables the unit tests for the KUnit test framework. These tests test
 	  the KUnit test framework itself; the tests are both written using
@@ -32,7 +34,8 @@ config KUNIT_TEST
 	  expected.
 
 config KUNIT_EXAMPLE_TEST
-	tristate "Example test for KUnit"
+	tristate "Example test for KUnit" if !KUNIT_RUN_ALL
+	default KUNIT_RUN_ALL
 	help
 	  Enables an example unit test that illustrates some of the basic
 	  features of KUnit. This test only exists to help new users understand
@@ -41,4 +44,10 @@ config KUNIT_EXAMPLE_TEST
 	  is intended for curious hackers who would like to understand how to
 	  use KUnit for kernel development.
 
+config KUNIT_RUN_ALL
+	tristate "KUnit run all test"
+	help
+	  Enables all KUnit tests. If they can be enabled.
+	  That depends on if KUnit is enabled as a module or builtin.
+
 endif # KUNIT
diff --git a/security/apparmor/Kconfig b/security/apparmor/Kconfig
index 0fe336860773..c4648426ea5d 100644
--- a/security/apparmor/Kconfig
+++ b/security/apparmor/Kconfig
@@ -70,8 +70,9 @@ config SECURITY_APPARMOR_DEBUG_MESSAGES
 	  the kernel message buffer.
 
 config SECURITY_APPARMOR_KUNIT_TEST
-	bool "Build KUnit tests for policy_unpack.c"
+	bool "Build KUnit tests for policy_unpack.c" if !KUNIT_RUN_ALL
 	depends on KUNIT=y && SECURITY_APPARMOR
+	default KUNIT_RUN_ALL
 	help
 	  This builds the AppArmor KUnit tests.
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200501083510.1413-1-anders.roxell%40linaro.org.
