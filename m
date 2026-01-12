Return-Path: <kasan-dev+bncBDP53XW3ZQCBB3MWSXFQMGQE5LBSPPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B6E18D15009
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:46 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-59b2da78573sf6382816e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246126; cv=pass;
        d=google.com; s=arc-20240605;
        b=CbKeiQ/YvOZQSrxS46JHGzneEhrDPUL/zRyqXzYUfp6iSirqgxefRIMqaHRQv3XkF/
         akURiKklotv4s4UtmdDNt7kFQKX8urhTUdGimHphWSxQRmlkAYqKGmMmAnPLNDHNRIDQ
         i9SIrzC7NKYEV00BxnSYDWv4gswznVtg2EaiA5Z9IA79Q34myYu+nb5XU9/LLsGmJXdq
         hRtbBMU6Y169GFD+eLFP/oEi7XqCqeTnkVA66Fp/nheuczLLZQPcMtu28iDnsDdMz1cW
         Ewg7o4i72mugLVwgfqYFxDOyHC8odH3rcNhaobhYcTlMvZzCm82Guzr7xvoU1iMj1ciV
         qAYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nBM3pQc4/JKnLRz5yPMz9SqB4PqtQmro2hzScolxsPU=;
        fh=CJksOem8EuUp7r7lJXFM4KbECbz8vZ1nFUenF0LREZE=;
        b=brm0wtkKY+LbcvTSCYYqHrk7a9Hieg04gu0W8KZMaOsDqv9sYxG9BBl+ePlKM/mLT0
         HxmsecOl/txu/RDVyQ+9WoyGfLOJveW1BPkBDB+ACngGrj5wWo9dgAA7sd7fmJ3JI1q/
         cJJXw/IuhH0BayWAt5bcjsgxwciR7YmHvuqLHuaSKryW+WvZj3coU4z08F82Ob5rba0d
         eOYi+LWUuryWYdgqqn/z2rRey30E4RowD8rzSe+WDIIbFa5fDXMfwgcrVs7okt+c9zD/
         qyKw1ZzG7dNKC6N38UY2yQyetfpKlEGKly+6dXUVLQ6rgTmkmYt5siZ4ssmK9Aia4xDd
         WpCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=msQWhsqb;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246126; x=1768850926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nBM3pQc4/JKnLRz5yPMz9SqB4PqtQmro2hzScolxsPU=;
        b=Gtsmz5pLiN5B60J0JC3X9RQsntmId7KUGKDKxD0Ues74pkziXO7NdO1b8ZA1u3DOD/
         dYRTpMl1MKVwsFmV4B8KUjDHdTK6nY6ez1TB2ZpjkWymW+qK6m4brH5NpCDjx1MKsZmZ
         HYk0qDbi6d1f96tlGusOQTefGeuM5VVHkrHQ7/ubvTyf6e8mfSe1cyrVxIiQ8yp4kQAg
         2Re2QVyHoAWbskbG57265TNID+lH5HsaFLa7et5apM31uDxPugm4bAIdTp8I1yD7lsZW
         KU0VpLFX7Pr6yAylGXR2mymozT++3L6TgE06yH0v/L+bvqit349JDCBiP07UoRWEQEWe
         xHSQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246126; x=1768850926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nBM3pQc4/JKnLRz5yPMz9SqB4PqtQmro2hzScolxsPU=;
        b=TtyHULlZTqYxx25iH1W3ev2mW3txnREHffuVXmDv7niflhp+8L1NejAHrF3j0c3pyY
         2C+P5I8KenA0mbb30uo0vG0wSdoytgoXotOVKbR176qNA30nKGYWUMhd9JOR/2U98rRk
         c1a46EWH/c2LeL/cS2fJ5aZVLnusUlyEUvv5i4UZg9NuC2C5cTbAC6L5TU4GKMV0CBf4
         pts2irxEbyb803YhB3YvbDI+8RxNrS9jzaJX3kCFUIb5xxCHfYwp59tXfGHPXcAd/y2A
         tRnLZztNgJPPmqTBvy5obWEOnZEPsU/It6ifvp8RX9EqQyM1fHdPe4dCQ1ikm76PlnmE
         xNLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246126; x=1768850926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nBM3pQc4/JKnLRz5yPMz9SqB4PqtQmro2hzScolxsPU=;
        b=mZ4oEB+xlP4nfNVtGtoOATCyEiEYHGO13wxHPyuClg4Q8rNTYxIULG2QdtDJTuttnj
         44p80CF6Skh4lcMmMq4xQUcF+uNlpkAYqOY79HD80ml7XYJaSeZsIrmiq63fPIFbAHod
         A47cb8S8G0fF5Ed4lrLytc1wT0ed2qdQ/8KLy8UqubwPA7KnPmly+fyXqceplqx9VbKS
         9b7MicastTXE/6D8cEtBLjQzA8Yb1jhtZQxtrjVXwFmPBKotVS+0rUhvdx+PnK/+v381
         7CfPgzhz3JO0AnvL5+ZHQPmnPNgMf47iKFYoTP/bsQ8u7CRJUOchzErqjy7hBZ5GI2zw
         Gpaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2Hz7GrvwS4T2FCdeLu+RZ87O3HxIP71zGz+sG7XD7w8scoml5pMi++J8KoeI+x1VbrEoIKA==@lfdr.de
X-Gm-Message-State: AOJu0Yzy0MrcSIn8bq7Ff2iwJLIMll+Z2GsOweDuyTu1NTP9hZy5JpxL
	yd2wbkNX27/EsWPOGnOV8PZI3ySUuSdNNvvD/zQBlm3VBqTMFXpAhH7t
X-Google-Smtp-Source: AGHT+IE9JVSPEfZPo4BdtF9qvRW2jN1bfHmQKRAsZCAH54It3HDK8uPwl0I2apXV1pcv8/Gts2aF5g==
X-Received: by 2002:a05:6512:4010:b0:594:2df2:84c8 with SMTP id 2adb3069b0e04-59b6f036b35mr6379531e87.33.1768246125575;
        Mon, 12 Jan 2026 11:28:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GEHDorNz6Zq7yWbAC8mupaHn45O1bkp2llhXIydbS/XQ=="
Received: by 2002:a05:651c:4410:20b0:37f:b4e0:a50c with SMTP id
 38308e7fff4ca-382e91b6ef3ls8506701fa.0.-pod-prod-03-eu; Mon, 12 Jan 2026
 11:28:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYo2c9/0xeOlyvNA7Dxu/oxj5l67335cjdX26LiwtWKIfQyGXVJRbEadoR3AeJJbdcTVOFju+HUUE=@googlegroups.com
X-Received: by 2002:ac2:47f2:0:b0:59b:715b:4fee with SMTP id 2adb3069b0e04-59b715b533emr4365185e87.10.1768246122375;
        Mon, 12 Jan 2026 11:28:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246122; cv=none;
        d=google.com; s=arc-20240605;
        b=I3MOF24Udddt10HqOWHit4lodyWONGbx/htmPVmED3c+dNB6QioaKzm2xyL9nhlVkC
         AtWI7EuOOIWEcJ7AWj+aAWgBuN4wSMcq2E96NfQefVF3qJBrHw65gRbv6sHOoeytOref
         qb++X3LXIP+rmbKIVLD7O9setGQZ8uPMT/Z+rC26SLkjBy2Py3DC4KXxdW391QTduVFd
         5nE7PxjU2WYL8Q6Hs2k/4KxcGuB4aXi+SR1DmAM83ojNbYCE2/DnCdq8fMvgx+h4ty65
         jN3+6ICiHcTPqHxTnzmfQMkzkvbEM++4ZGX0HYh1W780cR5s/CQBm6n46DWyWaU0ElFK
         5YDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=F6pmlmleIFnHYbLcLeHzqqQV2depV+HvaEyub6pwhNU=;
        fh=NgL8YiIK/qshsuqkjm8M7WHF84+D7ORVSAovmHHtHMY=;
        b=ZMsZNkkPlRtmO9ntx6m/u/G/6s/igmU8s4NWGK51oF6raKBGsvWG5a4wyIOJZ3DOuQ
         +QGmBG+DeoB5QaJsfoEIJRS8vGGSA+0PZcJlu32MZq2cg62vBRNoQq5tZ2p+up1JK5Io
         mJx7KqrxI8b1tzjsglYbV4dHRdybkI19BzrSHgI8OuZokHeSl/wIfN1q04OSAvy8biYt
         xbYegnGnu0jblXGGbVSsUt9C06C0uXhwSne378ALDq5LhZq6avCqtpNCBnRfd9h3+ka/
         95r0paXb8glLN4axTyD1nzPLUina5sXOpHb1JWrdEZ/A2pQZ8QEhcx53tEi/nKKke0pS
         UTgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=msQWhsqb;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b6f504593si249104e87.4.2026.01.12.11.28.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:42 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-6505cac9879so11448129a12.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUc/aSuKTD7uD1UU98btMYGRjN3rAxyM3h1vC8S/6rFypVk+YI+NUbBmviFEfDznnH8E1gWQBy0BJM=@googlegroups.com
X-Gm-Gg: AY/fxX6dzmMW59yU2HPqdswFKM3i/PCk5xt952w7Ql1sxj+0xr90CgEiadDO/yN0V1w
	kueTWJ56FQjdImRWEnI/p1VXD8Sm7Gf0vI+x7oTegczVonwYkPOO99atsf+Kw8ZEDq0QdyoPMJO
	5qm7gXBCHR/g2Jv6zB6fvhVBjGLr3ATikbcmbNatEvEWsUty8PBE80iPlm6yQOQwTgDUKoKW4LU
	7dka3fiBRw/0LWotnO05Ubah8JOYrv0+8fdWYc8nH1H5Wf2wOszhPo9nqfgs3b2LP/KWJaBzR8t
	OcSPefic0goA7v6EdOcEzO2Snex/BDgCZm5anCXMfRHA+37+eAbhS5QDHd+ovWqnMqgPAc+vjIr
	+wiaglBeETyMGj7zm4FIer3ZorDR822bNr+Ws2MFhWS+j6Pth/P7JSGXPO6AUogMDp89IP2heWA
	01ebt6d4Adyy599Kol4Lwb8ANzXV/8J8GN+V1wn/tW+3xWN6sMww==
X-Received: by 2002:a05:6402:42d3:b0:64b:6dfc:dd34 with SMTP id 4fb4d7f45d1cf-65097cde534mr16779217a12.0.1768246121349;
        Mon, 12 Jan 2026 11:28:41 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:40 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	ebiggers@kernel.org,
	elver@google.com,
	gregkh@linuxfoundation.org,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	mcgrof@kernel.org,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	skhan@linuxfoundation.org,
	tarasmadan@google.com,
	wentaoz5@illinois.edu
Subject: [PATCH v4 1/6] kfuzztest: add user-facing API and data structures
Date: Mon, 12 Jan 2026 20:28:22 +0100
Message-ID: <20260112192827.25989-2-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=msQWhsqb;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Add the foundational user-facing components for the KFuzzTest framework.
This includes the main API header <linux/kfuzztest.h>, the Kconfig
option to enable the feature, and the required linker script changes
which introduce a new ELF section in vmlinux.

Note that KFuzzTest is intended strictly for debug builds only, and
should never be enabled in a production build. The fact that it exposes
internal kernel functions and state directly to userspace may constitute
a serious security vulnerability if used for any reason other than
testing.

The header defines:
- The FUZZ_TEST_SIMPLE() macro for creating test targets.
- The `struct kfuzztest_simple_target` structure used to register tests.
- The linker section (.kfuzztest_simple_target) where test metadata is
  stored for discovery by the framework.

This patch only adds the public interface and build integration; no
runtime logic is included.

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>

---
PR v4:
- Remove the complex FUZZ_TEST macro and associated dependencies,
  including domain constraints, annotations, and de-serialization,
  dramatically simplifying the flow.
- Drop unused ELF sections (.kfuzztest_constraint, etc...) from the
  linker script, keeping only .kfuzztest_simple_target.
PR v3:
- Reorder definitions in kfuzztest.h for better flow and readability.
- Introduce __KFUZZTEST_CONSTRAINT macro in preparation for the
  introduction of the FUZZ_TEST_SIMPLE macro in the following patch,
  which uses it for manually emitting constraint metadata.
PR v1:
- Move KFuzzTest metadata definitions to generic vmlinux linkage so that
  the framework isn't bound to x86_64.
- Return -EFAULT when simple_write_to_buffer returns a value not equal
  to the input length in the main FUZZ_TEST macro.
- Enforce a maximum input size of 64KiB in the main FUZZ_TEST macro,
  returning -EINVAL when it isn't respected.
- Refactor KFUZZTEST_ANNOTATION_* macros.
- Taint the kernel with TAINT_TEST inside the FUZZ_TEST macro when a
  fuzz target is invoked for the first time.
---
---
 include/asm-generic/vmlinux.lds.h | 14 ++++-
 include/linux/kfuzztest.h         | 88 +++++++++++++++++++++++++++++++
 lib/Kconfig.debug                 |  1 +
 lib/kfuzztest/Kconfig             | 16 ++++++
 4 files changed, 118 insertions(+), 1 deletion(-)
 create mode 100644 include/linux/kfuzztest.h
 create mode 100644 lib/kfuzztest/Kconfig

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index ae2d2359b79e..5aa46dbbc9b2 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -373,7 +373,8 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 	TRACE_PRINTKS()							\
 	BPF_RAW_TP()							\
 	TRACEPOINT_STR()						\
-	KUNIT_TABLE()
+	KUNIT_TABLE()							\
+	KFUZZTEST_TABLE()
 
 /*
  * Data section helpers
@@ -966,6 +967,17 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 		BOUNDED_SECTION_POST_LABEL(.kunit_init_test_suites, \
 				__kunit_init_suites, _start, _end)
 
+#ifdef CONFIG_KFUZZTEST
+#define KFUZZTEST_TABLE()						\
+	. = ALIGN(PAGE_SIZE);						\
+	__kfuzztest_simple_targets_start = .;				\
+	KEEP(*(.kfuzztest_simple_target));				\
+	__kfuzztest_simple_targets_end = .;				\
+
+#else /* CONFIG_KFUZZTEST */
+#define KFUZZTEST_TABLE()
+#endif /* CONFIG_KFUZZTEST */
+
 #ifdef CONFIG_BLK_DEV_INITRD
 #define INIT_RAM_FS							\
 	. = ALIGN(4);							\
diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
new file mode 100644
index 000000000000..62fce9267761
--- /dev/null
+++ b/include/linux/kfuzztest.h
@@ -0,0 +1,88 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * The Kernel Fuzz Testing Framework (KFuzzTest) API for defining fuzz targets
+ * for internal kernel functions.
+ *
+ * Copyright 2025 Google LLC
+ */
+#ifndef KFUZZTEST_H
+#define KFUZZTEST_H
+
+#include <linux/fs.h>
+#include <linux/printk.h>
+#include <linux/types.h>
+
+#define KFUZZTEST_MAX_INPUT_SIZE (PAGE_SIZE * 16)
+
+/* Common code for receiving inputs from userspace. */
+int kfuzztest_write_cb_common(struct file *filp, const char __user *buf, size_t len, loff_t *off, void **test_buffer);
+
+struct kfuzztest_simple_target {
+	const char *name;
+	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf, size_t len, loff_t *off);
+};
+
+/**
+ * FUZZ_TEST_SIMPLE - defines a KFuzzTest target
+ *
+ * @test_name: the unique identifier for the fuzz test, which is used to name
+ *             the debugfs entry.
+ *
+ * This macro defines a fuzz target entry point that accepts raw byte buffers
+ * from userspace. It registers a struct kfuzztest_simple_target which the
+ * framework exposes via debugfs.
+ *
+ * When userspace writes to the corresponding debugfs file, the framework
+ * allocates a kernel buffer, copies the user data, and passes it to the
+ * logic defined in the macro body.
+ *
+ * User-provided Logic:
+ * The developer must provide the body of the fuzz test logic within the curly
+ * braces following the macro invocation. Within this scope, the framework
+ * implicitly defines the following variables:
+ *
+ * - `char *data`: A pointer to the raw input data.
+ * - `size_t datalen`: The length of the input data.
+ *
+ * Example Usage:
+ *
+ * // 1. The kernel function that we want to fuzz.
+ * int process_data(const char *data, size_t datalen);
+ *
+ * // 2. Define a fuzz target using the FUZZ_TEST_SIMPLE macro.
+ * FUZZ_TEST_SIMPLE(test_process_data)
+ * {
+ *	// Call the function under test using the `data` and `datalen`
+ *	// variables.
+ *	process_data(data, datalen);
+ * }
+ *
+ */
+#define FUZZ_TEST_SIMPLE(test_name)											\
+	static ssize_t kfuzztest_simple_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len,	\
+							     loff_t *off);						\
+	static ssize_t kfuzztest_simple_logic_##test_name(char *data, size_t datalen);					\
+	static const struct kfuzztest_simple_target __fuzz_test_simple__##test_name __section(				\
+		".kfuzztest_simple_target") __used = {									\
+		.name = #test_name,											\
+		.write_input_cb = kfuzztest_simple_write_cb_##test_name,						\
+	};														\
+	static ssize_t kfuzztest_simple_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len,	\
+							     loff_t *off)						\
+	{														\
+		void *buffer;												\
+		int ret;												\
+															\
+		ret = kfuzztest_write_cb_common(filp, buf, len, off, &buffer);						\
+		if (ret < 0)												\
+			goto out;											\
+		ret = kfuzztest_simple_logic_##test_name(buffer, len);							\
+		if (ret == 0)												\
+			ret = len;											\
+		kfree(buffer);												\
+out:															\
+		return ret;												\
+	}														\
+	static ssize_t kfuzztest_simple_logic_##test_name(char *data, size_t datalen)
+
+#endif /* KFUZZTEST_H */
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index dc0e0c6ed075..49a1748b9f24 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1947,6 +1947,7 @@ endmenu
 menu "Kernel Testing and Coverage"
 
 source "lib/kunit/Kconfig"
+source "lib/kfuzztest/Kconfig"
 
 config NOTIFIER_ERROR_INJECTION
 	tristate "Notifier error injection"
diff --git a/lib/kfuzztest/Kconfig b/lib/kfuzztest/Kconfig
new file mode 100644
index 000000000000..d8e9caaac108
--- /dev/null
+++ b/lib/kfuzztest/Kconfig
@@ -0,0 +1,16 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+config KFUZZTEST
+	bool "KFuzzTest - enable support for internal fuzz targets"
+	depends on DEBUG_FS && DEBUG_KERNEL
+	help
+	  Enables support for the kernel fuzz testing framework (KFuzzTest), an
+	  interface for exposing internal kernel functions to a userspace fuzzing
+	  engine. KFuzzTest targets are exposed via a debugfs interface that
+	  accepts raw binary inputs from userspace, and is designed to make it
+	  easier to fuzz deeply nested kernel code that is hard to reach from
+	  the system call boundary. Using a simple macro-based API, developers
+	  can add a new fuzz target with minimal boilerplate code.
+
+	  WARNING: This exposes internal kernel functions directly to userspace
+	  and must NEVER be enabled in production builds.
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-2-ethan.w.s.graham%40gmail.com.
