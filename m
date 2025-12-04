Return-Path: <kasan-dev+bncBDP53XW3ZQCBB5NNY3EQMGQEOFEIMMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 22FB5CA3F4B
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:11 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-42e1e1ca008sf1186571f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857590; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q2aBkeaZ4qJa92GFXtHZQSMdOOgYV4ptQEucrqSf91SpLumKyaYBNnQLsCejZbYGVW
         h5rDMtuqleUotfIpS9Ll8UupboZmxGnpOBk080KjZ3/llfsmLvKeTmLdmnS5kEzk+0mX
         uUSoLGyGR8AaLX6MWKlxFGUkrS1bMC791YH8duMmPrLJSa7f3neeGsAjC0/SKUktAxcD
         rgY4C+8rN8rouhJlBEhG7y/1HK2b4FXo0mKPSt2VKhTwN2Arm6Q4sUyrHfT/HmxL4D9m
         KfXivN2pAE2VQOXAlcz04OQL1K6Y+kAvG6H8SgWOxESpmvu11KBOmWNXT2tBDN6e+3cx
         ndKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=za+3YrVMJTDL836ejSOuUTPHCMecWEK7zPlcwmwrYxs=;
        fh=ESlo1NjRGEjubPalHmbNKbERfW9luBpEH+tDXj+krjo=;
        b=M9QKqRnnlQ8Q6lgMDeAziK5GH1XNge6mt67AO5Txb/n5MTYZOn+/kVfyoU1I59RUu0
         H2LDaKOTwthv8VQEO8iVUNStjx5lsDU8+6etMzGLdWOrscLpbglOuNQjbTGCNlvAEigp
         d+PpG1hhEr/5K2JIfbt3xiN29McYwy1+aaLf/sVsMv2TcMrXvjrGl3JER2WH1dzSNSWg
         CgiF/LSECQp6Wk23cBd24c2vhbr4ggOAcJ7OgFYJLvA37gMBXbvgCgq1lBGpBCxrHtuS
         RDliYo4IbmtH4Av9jPi8zj8NvMXotSact5UilZ0vrF+JOpaUM1zy4CRSN+CuHIQAWd3D
         /kDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LlQflSBn;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857590; x=1765462390; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=za+3YrVMJTDL836ejSOuUTPHCMecWEK7zPlcwmwrYxs=;
        b=jNvTJfU3lk48oxl+okcFu6HOuo4uBNMpx+kCbxaVgL7ol/Tf1f+GjG7C5qQO9pF7Go
         XpmtlEBEcIsMkTU6l7hA1Bj5eZw87lVdXfTFcsf3bqnQSi6AZCpSYTTFjwpxtYY0tHIB
         7tn6Tsfc6wBmWaNHd+trUDDhkODXcaYbNkU4fz9K/Lw9FCby9J7+k+YcRvGmMGkUC5yz
         tPC+sBPtyDfRN6jo14Y6r59SlM3HTgQInDcE7nuCsDGbmvqUWjapc5jUehdLp3odS7i2
         HhpgflISGYwfHqBUGeT9KgHf0P7jJtUPLsl1vMGEdNP9gs7FArcW91pUfOuIkIys0XuP
         QEnw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857590; x=1765462390; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=za+3YrVMJTDL836ejSOuUTPHCMecWEK7zPlcwmwrYxs=;
        b=aqKx7jN5zLMATIs23ezjj/K4+QTxahOEMmj6jdJfeSgOsEFUVRlEvZC3cMsoBh2gAz
         ymT2ubN1g6S1yeB7rtQymYMtkBu4EGSGGhIGIcbrqqkszQcLe16i35E5dFsWpUepT3JK
         K8cGENjBAkx19JgDwdLEdm5bl+rQ9HVbM09F/jvdEg5mRpeVr2fKayaWXU3yw5oKR5l7
         cJydiMM4yRK92cEhIin9FB4hI2j3lLm6dHBxfgyxeHLeJm0DQoKXBiojS33y0+D43cjF
         xuAWMZ7z+7f/ZXLt+3BQaGdU/8Jizco9qx3Ssd+c4PDNWJm+j5tCJepfDa0xIT54VdKN
         w2AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857590; x=1765462390;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=za+3YrVMJTDL836ejSOuUTPHCMecWEK7zPlcwmwrYxs=;
        b=e7g47+Et8+oarLRA0Xbe1KvW7YUHupWOoGmx+gLGz/30gju5HvAUzx7IUVMS1E4bdn
         88buNU7WTT9Ted+KXPi31fZBOMB9veWVC7t07P7JQT8qEl1yy1d2zvjCgbjed17NA4Rs
         2aGLmo0WBl5lc7V5ix0iiHIpZJhV1URWy95oToYpRpUKJONTSMDPNsYcCDW6AhqnORks
         u6+gZF388MJGkWz1dnK+EYt8z3xWBOoKbdEQQjmdtwez81Mjyxabdgh50X2TyUr7jEIp
         43vK8A7DMEEUDElwijgUAMJdnaPiapYyuZ+aAOfUao9U3N5gpAzohyO6jH+LjyIZdcn+
         GVWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX1ViElOjijqNxVztXN071+Kcnl0Xw0h0gQEs6gO5mTAe6LkW1BDNP9A6amNjJ7EDVfdaKZLg==@lfdr.de
X-Gm-Message-State: AOJu0YwZ9q8Le2vX793WtXjPtHpz5GNWpzvue9PyePlaJF4gQ6x/1bD3
	3rM7TcpGcJwM7Joc9ebFTzM2MQWGIU8n0qd25trO1CJfrdRowWHJTqn2
X-Google-Smtp-Source: AGHT+IG/t7xcRauzzYTDBIcsDhHu7eBQVYpPwc8/MbbMe87+ex7BlqLU25enGAnyniR/a73zQVh+QQ==
X-Received: by 2002:a5d:4ac6:0:b0:42b:5448:7b34 with SMTP id ffacd0b85a97d-42f7876a185mr3203989f8f.7.1764857590121;
        Thu, 04 Dec 2025 06:13:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a25Rss4SITVSg+CIrH/fSf8EAfKCdbdUVT/v8/iOWZMw=="
Received: by 2002:adf:a29e:0:b0:42b:2dd2:76b8 with SMTP id ffacd0b85a97d-42f72018c75ls274621f8f.2.-pod-prod-00-eu-canary;
 Thu, 04 Dec 2025 06:13:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWA6/3iUiiDfvlzztY4C57NIQ0KGfKMfRWGEkA2NUWVGeOyTlstS+ib3YNEoMoanXGmTSvZX91cdqA=@googlegroups.com
X-Received: by 2002:a05:6000:d88:b0:429:eb05:1c69 with SMTP id ffacd0b85a97d-42f7874fa0bmr3236367f8f.2.1764857587164;
        Thu, 04 Dec 2025 06:13:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857587; cv=none;
        d=google.com; s=arc-20240605;
        b=gFvWNUXeb7yZcsLsg6qbCSZhnboiibT/O9S5T1iH2HLgqFZn7NtLW5FuBiWpC6Z4kl
         aOeOInbl8lRvJc3JYTBAYWhzZGe7QXG2Fxd798wp5Loj8gyWng93ZO1BjK0a7TLjEFfc
         /cMXHGXft96oK74aotiK+nQr6Dd59VsO1K5Z46nkFhURVRGm/iYE1usUkQXNiPaMtWQE
         OtTDAROC9VsqWLlapwKXLHVVprTp9eot3Isy/qzh+KPeCov9qeJHx5WVOjysiIKCmPq8
         rjokRxttn3oHhKLNODqHRs4q5IrMV77lzV08ZWrsNdTPaD1xT43hNyKQOiHa4mEbNDL6
         8TlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=isyNyNcz2cmNMZXUIhi196/Z7TRsBZBkmSpv3VPEYmw=;
        fh=a+XN0sMx78vRkyXxMqoO76mlTf25OWWhweeT9WkDrGQ=;
        b=d3ebrBtlXygZK0LJsmSu5c9zx5QBh++pWbBsQPVY9C+o2Ug9l+z7DJ88npeA722r3C
         OTgfSyJfByewHSO1COy4jV5FJ63d+AKy4LDez7cUJYP74PEPSTAYSRezqPDMv6Tmge9i
         8OFgbll9dyBbs5KjHlrRduCisFg1yXp1Ff26UwDYke2neiU0ur3TmPOOmTax+aeh8L+G
         dD+6k0MgI/l15E75ZTXkpI1DFWVML1X8vspvr4/gG9VxopLDSpIFDs91pCf3ZiwX+8w8
         KaKBsPQCgOzC9ASWMfdLB9fCnhWNh6zEulEDtPsKYa6+Nlxd60N6xQl8uCWlcI3eQIYF
         RDnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LlQflSBn;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d325b82si22434f8f.11.2025.12.04.06.13.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:07 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-42b32ff5d10so1398671f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVFaEd77RYsamWJGQp0t+n1chtozuOcTYLgy/5WbrP0OsLQ8N5azqFcvJeAyjx/QqMDZUENLizv2WE=@googlegroups.com
X-Gm-Gg: ASbGncvHkoZeNU6iDQbuzZqDbQ+5SO/bFW8wch5/FxGNo+aQojSUampRxn2jElR3ssy
	T1BACXv+TJCpSd5TQJgSfM2pIyAekqOZvhuhIEPDQjxP1SEmqfzDe6xCzBrpOlxWLGQ3vfeysI+
	WSjvR8aVlMMLtsav5qwVmiJ5jxB7xvTQxOVItPdV/ydD8KCLVqpsMmzfB0G/NjvRYiqZcs/1GUF
	MlGOVkaqwrYEUgg6iERCpnJVp2EvHRW+fNyjuUqPLy84jm7/gxiPYSfzC6spO0xxyXkLwszVxPN
	NPy7Ul2nB8QsMzX8uUHb/kJsZKU8ZwaNHU5VU2tHxA2/jsg3Ioaj6LY+TeHddujFe9UnPIfqaAl
	XA/L0+S467yAHZ0eHlQAsotqdsyiSwA8W41eZV/sL97pO58IIWjLRIns5T+uW4TwBZbvKoX+Myq
	LKEZ+Pwjgev26uA6YpUZpgsRArfRSA1hsyWAvSmcAhWVerXwecfuTc8nhPBCV4bTRD0w==
X-Received: by 2002:a05:6000:290c:b0:42b:3661:304e with SMTP id ffacd0b85a97d-42f78874e61mr3830533f8f.16.1764857586521;
        Thu, 04 Dec 2025 06:13:06 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:06 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
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
Subject: [PATCH 03/10] kfuzztest: introduce the FUZZ_TEST_SIMPLE macro
Date: Thu,  4 Dec 2025 15:12:42 +0100
Message-ID: <20251204141250.21114-4-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LlQflSBn;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

The serialization format required by a KFuzzTest target defined with the
FUZZ_TEST macro is overkill for simpler cases, in particular the very
common pattern of kernel interfaces taking a (data, datalen) pair.

Introduce the FUZZ_TEST_SIMPLE for defining simple targets that accept
a simpler binary interface without any required serialization. The aim
is to make simple targets compatible with a wide variety of userspace
fuzzing engines out of the box.

A FUZZ_TEST_SIMPLE target also defines an equivalent FUZZ_TEST macro in
its expansion maintaining compatibility with the default KFuzzTest
interface, using a shared `struct kfuzztest_simple_arg` as input type.
In essence, the following equivalence holds:

FUZZ_TEST_SIMPLE(test) === FUZZ_TEST(test, struct kfuzztest_simple_arg)

Constraints and annotation metadata for `struct kfuzztest_simple_arg` is
defined statically in the header file to avoid duplicate definitions in
the compiled vmlinux image.

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
---
 include/asm-generic/vmlinux.lds.h |  4 ++
 include/linux/kfuzztest.h         | 87 +++++++++++++++++++++++++++++++
 2 files changed, 91 insertions(+)

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 9afe569d013b..2736dd41fba0 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -974,6 +974,10 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 	KEEP(*(.kfuzztest_target));					\
 	__kfuzztest_targets_end = .;					\
 	. = ALIGN(PAGE_SIZE);						\
+	__kfuzztest_simple_targets_start = .;				\
+	KEEP(*(.kfuzztest_simple_target));				\
+	__kfuzztest_simple_targets_end = .;				\
+	. = ALIGN(PAGE_SIZE);						\
 	__kfuzztest_constraints_start = .;				\
 	KEEP(*(.kfuzztest_constraint));					\
 	__kfuzztest_constraints_end = .;				\
diff --git a/include/linux/kfuzztest.h b/include/linux/kfuzztest.h
index 1839fcfeabf5..284142fa4300 100644
--- a/include/linux/kfuzztest.h
+++ b/include/linux/kfuzztest.h
@@ -483,4 +483,91 @@ fail_early:													\
 	}													\
 	static void kfuzztest_logic_##test_name(test_arg_type *arg)
 
+struct kfuzztest_simple_target {
+	const char *name;
+	ssize_t (*write_input_cb)(struct file *filp, const char __user *buf, size_t len, loff_t *off);
+} __aligned(32);
+
+struct kfuzztest_simple_arg {
+	char *data;
+	size_t datalen;
+};
+
+/* Define constraint and annotation metadata for reused kfuzztest_simple_arg. */
+__KFUZZTEST_CONSTRAINT(kfuzztest_simple_arg, data, NULL, 0x0, EXPECT_NE);
+__KFUZZTEST_ANNOTATE(kfuzztest_simple_arg, data, NULL, ATTRIBUTE_ARRAY);
+__KFUZZTEST_ANNOTATE(kfuzztest_simple_arg, datalen, data, ATTRIBUTE_LEN);
+
+/**
+ * FUZZ_TEST_SIMPLE - defines a simple KFuzzTest target
+ *
+ * @test_name: the unique identifier for the fuzz test, which is used to name
+ *	the debugfs entry.
+ *
+ * This macro function nearly identically to the standard FUZZ_TEST target, the
+ * key difference being that a simple fuzz target is constrained to inputs of
+ * the form `(char *data, size_t datalen)` - a common pattern in kernel APIs.
+ *
+ * The FUZZ_TEST_SIMPLE macro expands to define an equivalent FUZZ_TEST,
+ * effectively creating two debugfs input files for the fuzz target. In essence,
+ * on top of creating an input file under kfuzztest/@test_name/input, a new
+ * simple input file is created under kfuzztest/@test_name/input_simple. This
+ * debugfs file takes raw byte buffers as input and doesn't require any special
+ * serialization.
+ *
+ * User-provided Logic:
+ * The developer must provide the body of the fuzz test logic within the curly
+ * braces following the macro invocation. Within this scope, the framework
+ * provides the `data` and `datalen` variables, where `datalen == len(data)`.
+ *
+ * Example Usage:
+ *
+ * // 1. The kernel function that we wnat to fuzz.
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
+	static void kfuzztest_simple_logic_##test_name(char *data, size_t datalen);					\
+	static const struct kfuzztest_simple_target __fuzz_test_simple__##test_name __section(				\
+		".kfuzztest_simple_target") __used = {									\
+		.name = #test_name,											\
+		.write_input_cb = kfuzztest_simple_write_cb_##test_name,						\
+	};														\
+	FUZZ_TEST(test_name, struct kfuzztest_simple_arg)								\
+	{														\
+		/* We don't use the KFUZZTEST_EXPECT macro to define the
+		 * non-null constraint on `arg->data` as we only want metadata
+		 * to be emitted once, so we enforce it here manually. */						\
+		if (arg->data == NULL)											\
+			return;												\
+		kfuzztest_simple_logic_##test_name(arg->data, arg->datalen);						\
+	}														\
+	static ssize_t kfuzztest_simple_write_cb_##test_name(struct file *filp, const char __user *buf, size_t len,	\
+							     loff_t *off)						\
+	{														\
+		void *buffer;												\
+		int ret;												\
+															\
+		ret = kfuzztest_write_cb_common(filp, buf, len, off, &buffer);						\
+		if (ret < 0)												\
+			goto out;											\
+		kfuzztest_simple_logic_##test_name(buffer, len);							\
+		record_invocation();											\
+		ret = len;												\
+		kfree(buffer);												\
+out:															\
+		return ret;												\
+	}														\
+	static void kfuzztest_simple_logic_##test_name(char *data, size_t datalen)
+
 #endif /* KFUZZTEST_H */
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-4-ethan.w.s.graham%40gmail.com.
