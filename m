Return-Path: <kasan-dev+bncBDP53XW3ZQCBB7O6WXDAMGQEYUQN46Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A0D71B8A1EB
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:06 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3ef9218daf5sf476536f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293886; cv=pass;
        d=google.com; s=arc-20240605;
        b=MH/oAIw0cAn4WoER7ZMkjRODukCz35Bu9XPbfmjaG2U3CPs26UCF3GCxzPCrvAZRLq
         LWUrBLpKDYaH7m+mwOdgPzqfvsOcywFyXOEww+eFSOw7xTuUJc+AUxweDyBK95pKGcBz
         3PdQSO2sg78WGZH3IVG+dX3/iEk2O0YrjBGo6MQ+HQGB9aD6eqBJyWgemUXu6qPc3eYB
         q2YzlPP1T9UKpe7Q9mIxJyaqy7VAevWqDKMxzI67gzvuTeXm6Gi5RuEXLk0oWoqb8Jgb
         xFyz1MZZHNMjSKyI8/wvQg0UpIlg3FyDIIeqrUIgxEBBfYwTKV7MWzF57hNpKj8yrMZ9
         PYJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=IAhmxgyUn+3puZP47lqpZkdMTNzFXF7nVwm1DCYVbek=;
        fh=AhhlmGcLVuaISs2tKJw0jGxWjELXPQ3d7F4gLh24Y6A=;
        b=V0ZkyyWRjldsQISYuVB/PHMahzusKN7z5jjTAF0RI1qFtm1H2Y2m+UjWwaoKMwrSfE
         cQ7LoK9Jv9DxDWaQG7PLBQMiBQaZBdmXvwVqDBQfUpKgNbtsyTAC/pphigBSkhk1geY/
         zpEwtAVhEReJCkUEQ4TwRczBBIP/QuUv955JGSwLtg/h0gjcwrVu/0lAgpppo1ZLW0bK
         YWg7+VgCnyygYGb3dbD13gmuBRHPpOR/UU4tVzYkunIPrzYXI/Bvz/E45/3B5Di1lXBa
         iUboAj2EsZHvzWVQfskAP7ZmfAUOAi70TucVCpPeC/3PiYWieDawoAWWSdEdXZdGeIW9
         ooRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T0T91BQZ;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293886; x=1758898686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IAhmxgyUn+3puZP47lqpZkdMTNzFXF7nVwm1DCYVbek=;
        b=KrAjnxzyKfXYJ4zfUYKL9/P+ukGS9ULl234lwTrNgMBpx9Jd2QBR2p2z8XFVt3oIxa
         +zOKtdHVpNE4wEr3bzeNQ2T4i7S1LQZqXL2zPSazMINGScd4rcB8BvDiGUU94txGOkk6
         t60Ig8jOJedGvNEI7THtI/r9fGXVrXGpiAx2Tpj1h5T4+HuPHLcIpgFp1qzneCFaAFCr
         UOegCIhiz2QXHfFRVJJbVM8IByN5RgK6K4TOVZP7id3e97h5dy+BIHtDTjN3ojOuYWC+
         gDN1AUXNBxhriG9yj/2UitPHjGNK48WE/7fsfT1ViFOOEq4QcUFQ9mmTaTkiCEmvrpfg
         KVWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293886; x=1758898686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=IAhmxgyUn+3puZP47lqpZkdMTNzFXF7nVwm1DCYVbek=;
        b=gwKCXtXPa9dsifU6HhpRN88KGFlB8M7EbFRus4PKbTofEyHz86GOw6Gik+RxhucMtK
         SoTq0z8aLsDfHtHjoBKVzeoyBNk62ueHkpaPsubEc62RVDhLLuogBCA+tR9LsiExqCjm
         vQH3JjiNBspiXM0IQSwXuqUMQArMI4GVENjQCgtn9quWO7u/JybBWhgqZ6UovHEeY/Ns
         xfTMOzBRyOPMZP1Bc8hj5/3idriM2dt6/JyzsE6Gt8QJrthGeTW/wrV9xkIb+HbGiHiS
         yy2Z9q9Kpaa8J41F1Fry/okPD9x1y2EqssvPTihNfmdcDV23x0bk/mzUd5RqJQ70Hr9+
         /Pkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293886; x=1758898686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IAhmxgyUn+3puZP47lqpZkdMTNzFXF7nVwm1DCYVbek=;
        b=pku2LcgyH4IsA9JkquuhIxGXoE3weymCAt2KtqZOJj2vNfNQxEHGu29tMee1WM0MoL
         GBaA9d5bLTtPGFRRshMRQ9plpzayOq7TQ2uXluamgUIza1x+EmAdX+MFi7fXlT+YIlH8
         OcAHQltLYOv1xvzRH19B20k8KNhRSa7ar0cZ8avx/YgSZuS2VRhOR5Tuk1qPIAptqw2E
         LxcpfojKTJU8KLT5iamCZqkFwtOKLusv2J8idp7AnSEdxUQaxykx259wOJO9Jl1K0duv
         dSma9UnwSucL/qHKdruwOGtYplHKri+Z6+7lKv2ztpxDrdNZIfR3GBR9UnhlN5ePZ2DW
         gO4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXakCuTZtkTwQxUqdghqQ649b0hw8cA3rG3xkPc+ogHpY4c6ktAP2nTW4RyrTErp+bB8CGKw==@lfdr.de
X-Gm-Message-State: AOJu0YzyCUqngRr/PvAnUUuEqFT7cNFuZdk3aaFBOGDxvW3LTE+macDv
	VRT3JMEBBKnBGcvTORnthgPYbmbaH0ZruzYIFuoPlXQf2vY+ZaH1UE91
X-Google-Smtp-Source: AGHT+IHz4Tss6x3fIG+XdigduEb+TMdZtuY2cEXJUfsjLX+d9I+tx8zHuDWaRbobS0VJV1zSPiSZmw==
X-Received: by 2002:a05:6000:603:b0:3da:d015:bf84 with SMTP id ffacd0b85a97d-3ee7db4c66amr2997234f8f.25.1758293885590;
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4G76qeaLQMLkuJXBe1ULj3Kfw/CLfz/WKI28ebUoPtpw==
Received: by 2002:a05:600d:f:b0:468:2a1f:69bf with SMTP id 5b1f17b1804b1-4682a1f6bbals4633275e9.1.-pod-prod-02-eu;
 Fri, 19 Sep 2025 07:58:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+kWCZsGN/N0be0iPvzDwVMRoP09F4uSOBjLoZXtthGAL4hjKCpTsXytyhD+yCSFzyJuq+1JG+EvM=@googlegroups.com
X-Received: by 2002:a05:600c:17d1:b0:45c:b5f7:c6e7 with SMTP id 5b1f17b1804b1-4682c93f406mr21025485e9.0.1758293882479;
        Fri, 19 Sep 2025 07:58:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293882; cv=none;
        d=google.com; s=arc-20240605;
        b=TccRyihN9/y5IcVbSwLDm6eI5cdpGHf1OXmY7WS18s8o9mARECzC9ebHPBq4K7X2jY
         bBhfVuM/vaZ7XoONx0R7aq2NwAqo82M4V4TmSpvu1Ybp4uaO7xfcNBqtxG1CDrts0Nmn
         HvpJucrVGjAtYlAp0/IulTv073Z+KIQ48wyQYqi96saT+b7d4xWsD/IeisWAtIrTV+6U
         xk2eDMSKyaD7+ikln82mZheBTAw1V1cjnPh+mmWo0YzMhiKz4kzYp8SGoXheLWV91+nl
         XQZVGJB5GwR5XhSxMD8ozjc3QaAR69mW2lN+p7e98j6tmwmEOIv1Rv299yK/Q754pwt0
         DTDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sfh1bNw7MLcAN8E4ek/ZR2D+Z9BQxSpA6YNYJoSqpiw=;
        fh=j0zL2wFw5vEKKcOI6Fvr4C8QqhhuPmhjfagicJAyO4g=;
        b=blUUx/wgbHyRbNRKQA3q6Bkk8TJjzLrZo+5af8tbwKLFuY/co1eOFopDayU78r/n8O
         34ZBRrbg56u0HmxOHdbswn4ggeFw7AhLehi0Y3ar+a2/6i7dMoFdGN3i+Y4ND3OP9964
         o0gF1SbyO1nhEQGlnZkE8GZ0jLvfs8BbphbX4mUJSBFWTiEkaGStjkUQhqZa0TW9wquM
         TSmbRnsxPtppyAhngAFdZE6gmXXVjYvpno8Zlf2K5WBoe8JIH6HGGrMpndzwt3aGO0XN
         sWEuOtSxuCsGhctIm3eOzJ0uhcQIUXwe2vnqSYzc8s192K51aWYMM3k09Vxzw9CsWNZr
         e2SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T0T91BQZ;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f3251efaasi611375e9.1.2025.09.19.07.58.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3ed20bdfdffso2277309f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV6iJ726EIjlSoCNcBJwwoJ6l6yPqVUC4nVZ5zHYdzLfbeZMic8U9iMoMT19mpBzNfr+uaKeamC+Mc=@googlegroups.com
X-Gm-Gg: ASbGncuO2RSBp4Q3gH0bhJGqVP1xGXCB3+wG9PrTwYXmWU0ee8KcAnJehd/eOGJZDNT
	l413ZgvTNIRUgamxP395BH9hY9K5SmwVHNEXQzNzl0q2Szw5T+2nW5pEAKtKtj8FIu2bfnNSp26
	1hajePxYq2OHceFrfQOSEl6J6f+cPnbBIGOT0V1C/ppAny9sj2fPDoXtVYQwDs7Zw1FdPGOfwan
	+9xqAXhuPBYvZND8Hid/Py6sXTbSqAj4Yd5ebzQ1pA8VBHEykkwCe8Xl8Cm/K+uJXUDnDbZCGwX
	yH5QRLgLIrSMfZPP3+osfUXTr6JZrTw+pY9G5R9djsj//WXqyLaUSRr2wBsNv/Om7oqrbs9H7bw
	iUZCl72Zmb3saDboXHOpqUWv90UtrKlCjvuOUl3EUabEiL7Uihqj8+HTsKqSbhmC/5DQRuANX78
	mOtM0GE/WuJAtCSNU=
X-Received: by 2002:a05:6000:24c9:b0:3ec:ce37:3a6d with SMTP id ffacd0b85a97d-3ee857699acmr2826209f8f.47.1758293881422;
        Fri, 19 Sep 2025 07:58:01 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.58.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:58:00 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
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
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v2 03/10] kfuzztest: implement core module and input processing
Date: Fri, 19 Sep 2025 14:57:43 +0000
Message-ID: <20250919145750.3448393-4-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=T0T91BQZ;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

From: Ethan Graham <ethangraham@google.com>

Add the core runtime implementation for KFuzzTest. This includes the
module initialization, and the logic for receiving and processing
user-provided inputs through debugfs.

On module load, the framework discovers all test targets by iterating
over the .kfuzztest_target section, creating a corresponding debugfs
directory with a write-only 'input' file for each of them.

Writing to an 'input' file triggers the main fuzzing sequence:
1. The serialized input is copied from userspace into a kernel buffer.
2. The buffer is parsed to validate the region array and relocation
   table.
3. Pointers are patched based on the relocation entries, and in KASAN
   builds the inter-region padding is poisoned.
4. The resulting struct is passed to the user-defined test logic.

Signed-off-by: Ethan Graham <ethangraham@google.com>

---
PR v2:
- Fix build issues identified by the kernel test robot <lkp@intel.com>.
- Address some nits pointed out by Alexander Potapenko.
PR v1:
- Update kfuzztest/parse.c interfaces to take `unsigned char *` instead
  of `void *`, reducing the number of pointer casts.
- Expose minimum region alignment via a new debugfs file.
- Expose number of successful invocations via a new debugfs file.
- Refactor module init function, add _config directory with entries
  containing KFuzzTest state information.
- Account for kasan_poison_range() return value in input parsing logic.
- Validate alignment of payload end.
- Move static sizeof assertions into /lib/kfuzztest/main.c.
- Remove the taint in kfuzztest/main.c. We instead taint the kernel as
  soon as a fuzz test is invoked for the first time, which is done in
  the primary FUZZ_TEST macro.
RFC v2:
- The module's init function now taints the kernel with TAINT_TEST.
---
---
 include/linux/kfuzztest.h |   4 +
 lib/Makefile              |   2 +
 lib/kfuzztest/Makefile    |   4 +
 lib/kfuzztest/main.c      | 242 ++++++++++++++++++++++++++++++++++++++
 lib/kfuzztest/parse.c     | 204 ++++++++++++++++++++++++++++++++
 5 files changed, 456 insertions(+)
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c

diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
index 38970dea8fa5..2620e48bb620 100644
--- a/include/linux/kfuzztest.h
+++ b/include/linux/kfuzztest.h
@@ -150,6 +150,9 @@ struct kfuzztest_target {
 
 #define KFUZZTEST_MAX_INPUT_SIZE (PAGE_SIZE * 16)
 
+/* Increments a global counter after a successful invocation. */
+void record_invocation(void);
+
 /**
  * FUZZ_TEST - defines a KFuzzTest target
  *
@@ -243,6 +246,7 @@ struct kfuzztest_target {
 		if (ret < 0)											\
 			goto out;										\
 		kfuzztest_logic_##test_name(arg);								\
+		record_invocation();										\
 		ret = len;											\
 out:														\
 		kfree(buffer);											\
diff --git a/lib/Makefile b/lib/Makefile
index 392ff808c9b9..02789bf88499 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -325,6 +325,8 @@ obj-$(CONFIG_GENERIC_LIB_CMPDI2) += cmpdi2.o
 obj-$(CONFIG_GENERIC_LIB_UCMPDI2) += ucmpdi2.o
 obj-$(CONFIG_OBJAGG) += objagg.o
 
+obj-$(CONFIG_KFUZZTEST) += kfuzztest/
+
 # pldmfw library
 obj-$(CONFIG_PLDMFW) += pldmfw/
 
diff --git a/lib/kfuzztest/Makefile b/lib/kfuzztest/Makefile
new file mode 100644
index 000000000000..142d16007eea
--- /dev/null
+++ b/lib/kfuzztest/Makefile
@@ -0,0 +1,4 @@
+# SPDX-License-Identifier: GPL-2.0
+
+obj-$(CONFIG_KFUZZTEST) += kfuzztest.o
+kfuzztest-objs := main.o parse.o
diff --git a/lib/kfuzztest/main.c b/lib/kfuzztest/main.c
new file mode 100644
index 000000000000..c36a7a0b7602
--- /dev/null
+++ b/lib/kfuzztest/main.c
@@ -0,0 +1,242 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KFuzzTest core module initialization and debugfs interface.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/atomic.h>
+#include <linux/debugfs.h>
+#include <linux/fs.h>
+#include <linux/kfuzztest.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+#include <linux/kasan.h>
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
+MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");
+
+/*
+ * Enforce a fixed struct size to ensure a consistent stride when iterating over
+ * the array of these structs in the dedicated ELF section.
+ */
+static_assert(sizeof(struct kfuzztest_target) == 32, "struct kfuzztest_target should have size 32");
+static_assert(sizeof(struct kfuzztest_constraint) == 64, "struct kfuzztest_constraint should have size 64");
+static_assert(sizeof(struct kfuzztest_annotation) == 32, "struct kfuzztest_annotation should have size 32");
+
+extern const struct kfuzztest_target __kfuzztest_targets_start[];
+extern const struct kfuzztest_target __kfuzztest_targets_end[];
+
+/**
+ * struct kfuzztest_state - global state for the KFuzzTest module
+ *
+ * @kfuzztest_dir: The root debugfs directory, /sys/kernel/debug/kfuzztest/.
+ * @num_invocations: total number of target invocations.
+ * @num_targets: number of registered targets.
+ * @target_fops: array of file operations for each registered target.
+ * @minalign_fops: file operations for the /_config/minalign file.
+ * @num_invocations_fops: file operations for the /_config/num_invocations file.
+ */
+struct kfuzztest_state {
+	struct dentry *kfuzztest_dir;
+	atomic_t num_invocations;
+	size_t num_targets;
+
+	struct file_operations *target_fops;
+	struct file_operations minalign_fops;
+	struct file_operations num_invocations_fops;
+};
+
+static struct kfuzztest_state state;
+
+void record_invocation(void)
+{
+	atomic_inc(&state.num_invocations);
+}
+
+static void cleanup_kfuzztest_state(struct kfuzztest_state *st)
+{
+	debugfs_remove_recursive(st->kfuzztest_dir);
+	st->num_targets = 0;
+	st->num_invocations = (atomic_t)ATOMIC_INIT(0);
+	kfree(st->target_fops);
+	st->target_fops = NULL;
+}
+
+static const umode_t KFUZZTEST_INPUT_PERMS = 0222;
+static const umode_t KFUZZTEST_MINALIGN_PERMS = 0444;
+
+static ssize_t read_cb_integer(struct file *filp, char __user *buf, size_t count, loff_t *f_pos, size_t value)
+{
+	char buffer[64];
+	int len;
+
+	len = scnprintf(buffer, sizeof(buffer), "%zu\n", value);
+	return simple_read_from_buffer(buf, count, f_pos, buffer, len);
+}
+
+/*
+ * Callback for /sys/kernel/debug/kfuzztest/_config/minalign. Minalign
+ * corresponds to the minimum alignment that regions in a KFuzzTest input must
+ * satisfy. This callback returns that value in string format.
+ */
+static ssize_t minalign_read_cb(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
+{
+	int minalign = MAX(KFUZZTEST_POISON_SIZE, ARCH_KMALLOC_MINALIGN);
+	return read_cb_integer(filp, buf, count, f_pos, minalign);
+}
+
+/*
+ * Callback for /sys/kernel/debug/kfuzztest/_config/num_invocations, which
+ * returns the value in string format.
+ */
+static ssize_t num_invocations_read_cb(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
+{
+	return read_cb_integer(filp, buf, count, f_pos, atomic_read(&state.num_invocations));
+}
+
+static int create_read_only_file(struct dentry *parent, const char *name, struct file_operations *fops)
+{
+	struct dentry *file;
+	int err = 0;
+
+	file = debugfs_create_file(name, KFUZZTEST_MINALIGN_PERMS, parent, NULL, fops);
+	if (!file)
+		err = -ENOMEM;
+	else if (IS_ERR(file))
+		err = PTR_ERR(file);
+	return err;
+}
+
+static int initialize_config_dir(struct kfuzztest_state *st)
+{
+	struct dentry *dir;
+	int err = 0;
+
+	dir = debugfs_create_dir("_config", st->kfuzztest_dir);
+	if (!dir)
+		err = -ENOMEM;
+	else if (IS_ERR(dir))
+		err = PTR_ERR(dir);
+	if (err) {
+		pr_info("kfuzztest: failed to create /_config dir");
+		goto out;
+	}
+
+	st->minalign_fops = (struct file_operations){
+		.owner = THIS_MODULE,
+		.read = minalign_read_cb,
+	};
+	err = create_read_only_file(dir, "minalign", &st->minalign_fops);
+	if (err) {
+		pr_info("kfuzztest: failed to create /_config/minalign");
+		goto out;
+	}
+
+	st->num_invocations_fops = (struct file_operations){
+		.owner = THIS_MODULE,
+		.read = num_invocations_read_cb,
+	};
+	err = create_read_only_file(dir, "num_invocations", &st->num_invocations_fops);
+	if (err)
+		pr_info("kfuzztest: failed to create /_config/num_invocations");
+out:
+	return err;
+}
+
+static int initialize_target_dir(struct kfuzztest_state *st, const struct kfuzztest_target *targ,
+				 struct file_operations *fops)
+{
+	struct dentry *dir, *input;
+	int err = 0;
+
+	dir = debugfs_create_dir(targ->name, st->kfuzztest_dir);
+	if (!dir)
+		err = -ENOMEM;
+	else if (IS_ERR(dir))
+		err = PTR_ERR(dir);
+	if (err) {
+		pr_info("kfuzztest: failed to create /kfuzztest/%s dir", targ->name);
+		goto out;
+	}
+
+	input = debugfs_create_file("input", KFUZZTEST_INPUT_PERMS, dir, NULL, fops);
+	if (!input)
+		err = -ENOMEM;
+	else if (IS_ERR(input))
+		err = PTR_ERR(input);
+	if (err)
+		pr_info("kfuzztest: failed to create /kfuzztest/%s/input", targ->name);
+out:
+	return err;
+}
+
+/**
+ * kfuzztest_init - initializes the debug filesystem for KFuzzTest
+ *
+ * Each registered target in the ".kfuzztest_targets" section gets its own
+ * subdirectory under "/sys/kernel/debug/kfuzztest/<test-name>" containing one
+ * write-only "input" file used for receiving inputs from userspace.
+ * Furthermore, a directory "/sys/kernel/debug/kfuzztest/_config" is created,
+ * containing two read-only files "minalign" and "num_invocations", that return
+ * the minimum required region alignment and number of target invocations
+ * respectively.
+ *
+ * @return 0 on success or an error
+ */
+static int __init kfuzztest_init(void)
+{
+	const struct kfuzztest_target *targ;
+	int err = 0;
+	int i = 0;
+
+	state.num_targets = __kfuzztest_targets_end - __kfuzztest_targets_start;
+	state.target_fops = kzalloc(sizeof(struct file_operations) * state.num_targets, GFP_KERNEL);
+	if (!state.target_fops)
+		return -ENOMEM;
+
+	/* Create the main "kfuzztest" directory in /sys/kernel/debug. */
+	state.kfuzztest_dir = debugfs_create_dir("kfuzztest", NULL);
+	if (!state.kfuzztest_dir) {
+		pr_warn("kfuzztest: could not create 'kfuzztest' debugfs directory");
+		return -ENOMEM;
+	}
+	if (IS_ERR(state.kfuzztest_dir)) {
+		pr_warn("kfuzztest: could not create 'kfuzztest' debugfs directory");
+		err = PTR_ERR(state.kfuzztest_dir);
+		state.kfuzztest_dir = NULL;
+		return err;
+	}
+
+	err = initialize_config_dir(&state);
+	if (err)
+		goto cleanup_failure;
+
+	for (targ = __kfuzztest_targets_start; targ < __kfuzztest_targets_end; targ++, i++) {
+		state.target_fops[i] = (struct file_operations){
+			.owner = THIS_MODULE,
+			.write = targ->write_input_cb,
+		};
+		err = initialize_target_dir(&state, targ, &state.target_fops[i]);
+		/* Bail out if a single target fails to initialize. This avoids
+		 * partial setup, and a failure here likely indicates an issue
+		 * with debugfs. */
+		if (err)
+			goto cleanup_failure;
+		pr_info("kfuzztest: registered target %s", targ->name);
+	}
+	return 0;
+
+cleanup_failure:
+	cleanup_kfuzztest_state(&state);
+	return err;
+}
+
+static void __exit kfuzztest_exit(void)
+{
+	pr_info("kfuzztest: exiting");
+	cleanup_kfuzztest_state(&state);
+}
+
+module_init(kfuzztest_init);
+module_exit(kfuzztest_exit);
diff --git a/lib/kfuzztest/parse.c b/lib/kfuzztest/parse.c
new file mode 100644
index 000000000000..5aaeca6a7fde
--- /dev/null
+++ b/lib/kfuzztest/parse.c
@@ -0,0 +1,204 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KFuzzTest input parsing and validation.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+#include <linux/kasan.h>
+
+static int kfuzztest_relocate_v0(struct reloc_region_array *regions, struct reloc_table *rt,
+				 unsigned char *payload_start, unsigned char *payload_end)
+{
+	unsigned char *poison_start, *poison_end;
+	struct reloc_region reg, src, dst;
+	uintptr_t *ptr_location;
+	struct reloc_entry re;
+	size_t i;
+	int ret;
+
+	/* Patch pointers. */
+	for (i = 0; i < rt->num_entries; i++) {
+		re = rt->entries[i];
+		src = regions->regions[re.region_id];
+		ptr_location = (uintptr_t *)(payload_start + src.offset + re.region_offset);
+		if (re.value == KFUZZTEST_REGIONID_NULL)
+			*ptr_location = (uintptr_t)NULL;
+		else if (re.value < regions->num_regions) {
+			dst = regions->regions[re.value];
+			*ptr_location = (uintptr_t)(payload_start + dst.offset);
+		} else {
+			return -EINVAL;
+		}
+	}
+
+	/* Poison the padding between regions. */
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+
+		/* Points to the beginning of the inter-region padding */
+		poison_start = payload_start + reg.offset + reg.size;
+		if (i < regions->num_regions - 1)
+			poison_end = payload_start + regions->regions[i + 1].offset;
+		else
+			poison_end = payload_end;
+
+		if (poison_end > payload_end)
+			return -EINVAL;
+
+		ret = kasan_poison_range(poison_start, poison_end - poison_start);
+		if (ret)
+			return ret;
+	}
+
+	/* Poison the padded area preceding the payload. */
+	return kasan_poison_range(payload_start - rt->padding_size, rt->padding_size);
+}
+
+static bool kfuzztest_input_is_valid(struct reloc_region_array *regions, struct reloc_table *rt,
+				     unsigned char *payload_start, unsigned char *payload_end)
+{
+	size_t payload_size = payload_end - payload_start;
+	struct reloc_region reg, next_reg;
+	size_t usable_payload_size;
+	uint32_t region_end_offset;
+	struct reloc_entry reloc;
+	uint32_t i;
+
+	if (payload_start > payload_end)
+		return false;
+	if (payload_size < KFUZZTEST_POISON_SIZE)
+		return false;
+	if ((uintptr_t)payload_end % KFUZZTEST_POISON_SIZE)
+		return false;
+	usable_payload_size = payload_size - KFUZZTEST_POISON_SIZE;
+
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+		if (check_add_overflow(reg.offset, reg.size, &region_end_offset))
+			return false;
+		if ((size_t)region_end_offset > usable_payload_size)
+			return false;
+
+		if (i < regions->num_regions - 1) {
+			next_reg = regions->regions[i + 1];
+			if (reg.offset > next_reg.offset)
+				return false;
+			/* Enforce the minimum poisonable gap between
+			 * consecutive regions. */
+			if (reg.offset + reg.size + KFUZZTEST_POISON_SIZE > next_reg.offset)
+				return false;
+		}
+	}
+
+	if (rt->padding_size < KFUZZTEST_POISON_SIZE) {
+		pr_info("validation failed because rt->padding_size = %u", rt->padding_size);
+		return false;
+	}
+
+	for (i = 0; i < rt->num_entries; i++) {
+		reloc = rt->entries[i];
+		if (reloc.region_id >= regions->num_regions)
+			return false;
+		if (reloc.value != KFUZZTEST_REGIONID_NULL && reloc.value >= regions->num_regions)
+			return false;
+
+		reg = regions->regions[reloc.region_id];
+		if (reloc.region_offset % (sizeof(uintptr_t)) || reloc.region_offset + sizeof(uintptr_t) > reg.size)
+			return false;
+	}
+
+	return true;
+}
+
+static int kfuzztest_parse_input_v0(unsigned char *input, size_t input_size, struct reloc_region_array **ret_regions,
+				    struct reloc_table **ret_reloc_table, unsigned char **ret_payload_start,
+				    unsigned char **ret_payload_end)
+{
+	size_t reloc_entries_size, reloc_regions_size;
+	unsigned char *payload_end, *payload_start;
+	size_t reloc_table_size, regions_size;
+	struct reloc_region_array *regions;
+	struct reloc_table *rt;
+	size_t curr_offset = 0;
+
+	if (input_size < sizeof(struct reloc_region_array) + sizeof(struct reloc_table))
+		return -EINVAL;
+
+	regions = (struct reloc_region_array *)input;
+	if (check_mul_overflow(regions->num_regions, sizeof(struct reloc_region), &reloc_regions_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*regions), reloc_regions_size, &regions_size))
+		return -EINVAL;
+
+	curr_offset = regions_size;
+	if (curr_offset > input_size)
+		return -EINVAL;
+	if (input_size - curr_offset < sizeof(struct reloc_table))
+		return -EINVAL;
+
+	rt = (struct reloc_table *)(input + curr_offset);
+
+	if (check_mul_overflow((size_t)rt->num_entries, sizeof(struct reloc_entry), &reloc_entries_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*rt), reloc_entries_size, &reloc_table_size))
+		return -EINVAL;
+	if (check_add_overflow(reloc_table_size, rt->padding_size, &reloc_table_size))
+		return -EINVAL;
+
+	if (check_add_overflow(curr_offset, reloc_table_size, &curr_offset))
+		return -EINVAL;
+	if (curr_offset > input_size)
+		return -EINVAL;
+
+	payload_start = input + curr_offset;
+	payload_end = input + input_size;
+
+	if (!kfuzztest_input_is_valid(regions, rt, payload_start, payload_end))
+		return -EINVAL;
+
+	*ret_regions = regions;
+	*ret_reloc_table = rt;
+	*ret_payload_start = payload_start;
+	*ret_payload_end = payload_end;
+	return 0;
+}
+
+static int kfuzztest_parse_and_relocate_v0(unsigned char *input, size_t input_size, void **arg_ret)
+{
+	unsigned char *payload_start, *payload_end;
+	struct reloc_region_array *regions;
+	struct reloc_table *reloc_table;
+	int ret;
+
+	ret = kfuzztest_parse_input_v0(input, input_size, &regions, &reloc_table, &payload_start, &payload_end);
+	if (ret < 0)
+		return ret;
+
+	ret = kfuzztest_relocate_v0(regions, reloc_table, payload_start, payload_end);
+	if (ret < 0)
+		return ret;
+	*arg_ret = (void *)payload_start;
+	return 0;
+}
+
+int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret)
+{
+	size_t header_size = 2 * sizeof(u32);
+	u32 version, magic;
+
+	if (input_size < sizeof(u32) + sizeof(u32))
+		return -EINVAL;
+
+	magic = *(u32 *)input;
+	if (magic != KFUZZTEST_HEADER_MAGIC)
+		return -EINVAL;
+
+	version = *(u32 *)(input + sizeof(u32));
+	switch (version) {
+	case KFUZZTEST_V0:
+		return kfuzztest_parse_and_relocate_v0(input + header_size, input_size - header_size, arg_ret);
+	}
+
+	return -EINVAL;
+}
-- 
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-4-ethan.w.s.graham%40gmail.com.
