Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4PA7W7QMGQETI2KGWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 27FFBA8B476
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:15 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-39ee57e254asf231676f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793714; cv=pass;
        d=google.com; s=arc-20240605;
        b=FwAHI3BbIeRqgoHUCyRXM/YHloYiGyecdjlm0jceaRbdZSx/OAyeODlbBCX3yxUwvH
         5WI3WH7wQ+67u7kVA0+Msuw4nASVS5v8EBqErkjOiv6Pn/5rA7yc2VYTvqjCo5QPljdV
         YrArrhjjY/OjxGj2QtwpfFQI1LlrZtkoooyg3Hv+eDIU8qDdVOP8kZk8NIyuzYBpWOsR
         nZFF44n0+UyPPEVlxzjPZYvheNMrayLQehFwXdD/b94XVJqNNdgPHHl0EQZwgttm4LX7
         Ty76KEDUx/3xA7mKBMkc4aEwqW2xE47qiuHY7Vt6BoewcvAbWcMRdYGlfsMcMFRBvezZ
         BhyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/3dEPIFdUJbkev0lEjJyQGU9kXHNvTE0/5v/nTbNYII=;
        fh=qcSTorWs4lIdqHjrSizUfJHpKPN/plSA8epwAPZoJ5s=;
        b=GSqdWy67DAsCV+ihibLBjqu3ZT2JRzK7xe0BJebUS2kc2CNdB1nouY8W3jOCXgeiJS
         xlvVg4yRDQ5fGF6BqJcyfxUXrce2jp3cGllA6BttGPQNlK4gdCsfdXG5V8vQ/TNIwxXk
         6riE3c35JvFWTWYHsyF+b1wV68oXXYwwNg4fRvewAViypQWyrdrkTJRpTAeokZrQnlfD
         33PUduLoPpqUGIEtLW2bot1gSYLnRA1+Dm4IwQOe9UQTAQ9MVPtyXtP2dDPX2XXgWY0P
         DYCiKpv6nN6gXuh0ob1puaAsGJB35Iz9DNSifipW0HiZDOag5MMhUf8TN8yPD04BYIu7
         YKog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2saisvcI;
       spf=pass (google.com: domain of 3bnd_zwykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3bnD_ZwYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793714; x=1745398514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/3dEPIFdUJbkev0lEjJyQGU9kXHNvTE0/5v/nTbNYII=;
        b=PGsx1rxM75zQHMkfvEcKh9kt4anv8Grsf7bPz/852kI39vrsUYZcZn6i1hqCSSj7C7
         sPHSBsYGASPTvdsUuyBMBxsc58xB8Q2TBIQ6vPHGdzSvvkfZGrrsWI8xSD4k0sX43vz+
         j2f9X3VdMH1tqXaMOiIviiemGZ+vPwWxSaAwNLkoofL3VK2GPRYIxRdzFN5OiqtNmScu
         +Db8sS3VWSqz4Otzkfh4sC4EsSOrvnOaNzjZfKH91MYtzDn15SMX4cqX6qaMGZ6w+MjF
         ih68PjlRedZZzWNkBmhdC9I270J6pO152hREYkejIJnejBpV5PYzjAipY1EXHQ0zQdTe
         1PVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793714; x=1745398514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/3dEPIFdUJbkev0lEjJyQGU9kXHNvTE0/5v/nTbNYII=;
        b=SIj+hkOqgyZFfJdPLrVJodxOFDNL7tukw/pCjw3sFUJ4G2jVbDqo26R1Y8Yyk2eVbw
         tm1Hx0U8iLmpZ6+ieV5Fg1Wrar/dclseYFB7Q4PmR3mcya4SgfxoQklG8SpV17ekHrFe
         d1W3FOHTlCX6+ApMFhDTRTOnJxbwP9ZH2+39uyl+8jeUFQJSwaGxIlS7U2Uo5e6scHVL
         erm8WtAzQLAmYOmouIAH4s/yZmbhcoJUo6iJYNuIPmQMm831tEjUOmLbMuq0dWRif9WL
         G+GgCiazlhZLOqHpbmXDIjdVisaEgmBwWYWgW2O4SlcHGP4WVDCtG87g2kyGDPix2sc6
         2cGA==
X-Forwarded-Encrypted: i=2; AJvYcCVrx/d4u1SeYh3CCVcLzLzcaDFRYF4+38+ysd1pPdgkBJO3hRysu4oBs+qIwscps+w+/6HS4w==@lfdr.de
X-Gm-Message-State: AOJu0YxeYQTXXCo0DzidDEM/oTeQD8vadpS9xlpKUnMJquPBK0SCE1CR
	ro079ojNa7MWbpyaG4t8fXukiRjFZYfU2HC498zFJk6WqL+7lBpS
X-Google-Smtp-Source: AGHT+IEeTzgNqVMkaupGu6qA9ErpIzF3wLg6L0Ic0MFznGqoyHXpyiKkAReeXqphP50gyKjcrlqObA==
X-Received: by 2002:a05:6000:420b:b0:391:39bd:a381 with SMTP id ffacd0b85a97d-39ee5b1bdf1mr859314f8f.30.1744793713845;
        Wed, 16 Apr 2025 01:55:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALJgq64mA6RJli0hnDUQjtXzSxQXevboPPetbJs1EcTsQ==
Received: by 2002:a5d:64eb:0:b0:39a:c467:8d12 with SMTP id ffacd0b85a97d-39d8df8f4f5ls120893f8f.1.-pod-prod-02-eu;
 Wed, 16 Apr 2025 01:55:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtLiGzK4mBiflcZDeZsOCWunXjxQqC5vFkmw3tm58OMglQKit6p9f+QH+uuuqRiwbd6ydn0YQTtHo=@googlegroups.com
X-Received: by 2002:a5d:6d8b:0:b0:38d:d0ca:fbad with SMTP id ffacd0b85a97d-39ee5b15bbcmr934748f8f.14.1744793710955;
        Wed, 16 Apr 2025 01:55:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793710; cv=none;
        d=google.com; s=arc-20240605;
        b=gl+rTpSWNuXQZKbvTKgh+Ha75hBOXRgAm0OE2wb6Wmsj7Oxx54UWJsRDrEnwGDM5Da
         ZLeJ/YsyclVGkY2vFTIJLIdPhVfsSDxbeJxFUbP4AacOVYodcdTYy24DM5f47zLNogCt
         RUPpob96yKtHC5s6oXtLCC1E1BRBpq2OmKLiK6Uav/lN8sM4/A4ofxUHjyeFvjxXH2Px
         jtB+sjrtrmE5AxWNvWR0WxcVfYES2wboB4SgHxzFVaV0u/ifPl6QIG+MfLnPHXANfDfb
         hQKMjvM9J2clM3Jf3fVWCFSGyrs/kwneFFh8D+UtAINA0ITIiAEpVXKld65ah6xYJCWg
         H+ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZC4wZ/r+6T3+g58Jq4R0q5y2fMNgcKM6hKjFFkcrcac=;
        fh=MHpPLoZtvoW6uKqqyWrPJ7qKwigGIXSdDTGtY9UsCjc=;
        b=IRj1iI7VqLjO9KEgz++Qk9xGY4QK7TJoNt5CYrY1Cuk1IwF20H8iO5pl85DEo3spH6
         J0EPaPNqYqzbCqyowbF5hpOm38S026ry7mlpQwl6REfsafxPjB/Xpr7TAqjiA//UWh4S
         5Uy2OqeLmbWiq3jjD7o+cmLlGEZm/ftnEfN/PT7c3xzwZ71IkBxVg7+YV7o2qYljFhSy
         e3Y2p1RBtnnUNqxg83q0nUroxabSioZ/GCSsNAwN3MUB3QTk9xGY4DmMnfjWcwsLfJM9
         BbsV5y2aV2vgCsx8oQkNEQ0d9Q0H2GW5vw8U79jmstQV4f8cZ6irlM2iC0eLrB91fDev
         Tz2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2saisvcI;
       spf=pass (google.com: domain of 3bnd_zwykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3bnD_ZwYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4405b33f28asi266095e9.0.2025.04.16.01.55.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:55:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bnd_zwykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ac3df3f1193so494303966b.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:55:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUm76CzJ3kgkI0gE31bby93FTk/ey2rFf6/GP1ppKKYnuladG59r0fhM5/Qg8heAlDi73ZBDRTLi2M=@googlegroups.com
X-Received: from ejzs20.prod.google.com ([2002:a17:906:c314:b0:ac6:b746:be0b])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:f594:b0:abf:4708:8644
 with SMTP id a640c23a62f3a-acb42add337mr75919066b.43.1744793710441; Wed, 16
 Apr 2025 01:55:10 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:43 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-6-glider@google.com>
Subject: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2saisvcI;       spf=pass
 (google.com: domain of 3bnd_zwykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3bnD_ZwYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
in the presence of CONFIG_KCOV_ENABLE_GUARDS.

The buffer shared with the userspace is divided in two parts, one holding
a bitmap, and the other one being the trace. The single parameter of
ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
bitmap.

Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
pointer to a unique guard variable. Upon the first call of each hook,
the guard variable is initialized with a unique integer, which is used to
map those hooks to bits in the bitmap. In the new coverage collection mode,
the kernel first checks whether the bit corresponding to a particular hook
is set, and then, if it is not, the PC is written into the trace buffer,
and the bit is set.

Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENABLE)
returns -ENOTSUPP, which is consistent with the existing kcov code.

Also update the documentation.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 Documentation/dev-tools/kcov.rst |  43 +++++++++++
 include/linux/kcov-state.h       |   8 ++
 include/linux/kcov.h             |   2 +
 include/uapi/linux/kcov.h        |   1 +
 kernel/kcov.c                    | 129 +++++++++++++++++++++++++++----
 5 files changed, 170 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd24..271260642d1a6 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -137,6 +137,49 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
 processes only need to enable coverage (it gets disabled automatically when
 a thread exits).
 
+Unique coverage collection
+---------------------------
+
+Instead of collecting raw PCs, KCOV can deduplicate them on the fly.
+This mode is enabled by the ``KCOV_UNIQUE_ENABLE`` ioctl (only available if
+``CONFIG_KCOV_ENABLE_GUARDS`` is on).
+
+.. code-block:: c
+
+	/* Same includes and defines as above. */
+	#define KCOV_UNIQUE_ENABLE		_IOW('c', 103, unsigned long)
+	#define BITMAP_SIZE			(4<<10)
+
+	/* Instead of KCOV_ENABLE, enable unique coverage collection. */
+	if (ioctl(fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE))
+		perror("ioctl"), exit(1);
+	/* Reset the coverage from the tail of the ioctl() call. */
+	__atomic_store_n(&cover[BITMAP_SIZE], 0, __ATOMIC_RELAXED);
+	memset(cover, 0, BITMAP_SIZE * sizeof(unsigned long));
+
+	/* Call the target syscall call. */
+	/* ... */
+
+	/* Read the number of collected PCs. */
+	n = __atomic_load_n(&cover[BITMAP_SIZE], __ATOMIC_RELAXED);
+	/* Disable the coverage collection. */
+	if (ioctl(fd, KCOV_DISABLE, 0))
+		perror("ioctl"), exit(1);
+
+Calling ``ioctl(fd, KCOV_UNIQUE_ENABLE, bitmap_size)`` carves out ``bitmap_size``
+words from those allocated by ``KCOV_INIT_TRACE`` to keep an opaque bitmap that
+prevents the kernel from storing the same PC twice. The remaining part of the
+trace is used to collect PCs, like in other modes (this part must contain at
+least two words, like when collecting non-unique PCs).
+
+The mapping between a PC and its position in the bitmap is persistent during the
+kernel lifetime, so it is possible for the callers to directly use the bitmap
+contents as a coverage signal (like when fuzzing userspace with AFL).
+
+In order to reset the coverage between the runs, the user needs to rewind the
+trace (by writing 0 into the first word past ``bitmap_size``) and wipe the whole
+bitmap.
+
 Comparison operands collection
 ------------------------------
 
diff --git a/include/linux/kcov-state.h b/include/linux/kcov-state.h
index 6e576173fd442..26e275fe90684 100644
--- a/include/linux/kcov-state.h
+++ b/include/linux/kcov-state.h
@@ -26,6 +26,14 @@ struct kcov_state {
 		/* Buffer for coverage collection, shared with the userspace. */
 		unsigned long *trace;
 
+		/* Size of the bitmap (in bits). */
+		unsigned int bitmap_size;
+		/*
+		 * Bitmap for coverage deduplication, shared with the
+		 * userspace.
+		 */
+		unsigned long *bitmap;
+
 		/*
 		 * KCOV sequence number: incremented each time kcov is
 		 * reenabled, used by kcov_remote_stop(), see the comment there.
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 7ec2669362fd1..41eebcd3ab335 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -10,6 +10,7 @@ struct task_struct;
 #ifdef CONFIG_KCOV
 
 enum kcov_mode {
+	KCOV_MODE_INVALID = -1,
 	/* Coverage collection is not enabled yet. */
 	KCOV_MODE_DISABLED = 0,
 	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
@@ -23,6 +24,7 @@ enum kcov_mode {
 	KCOV_MODE_TRACE_CMP = 3,
 	/* The process owns a KCOV remote reference. */
 	KCOV_MODE_REMOTE = 4,
+	KCOV_MODE_TRACE_UNIQUE_PC = 5,
 };
 
 #define KCOV_IN_CTXSW (1 << 30)
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index ed95dba9fa37e..fe1695ddf8a06 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -22,6 +22,7 @@ struct kcov_remote_arg {
 #define KCOV_ENABLE			_IO('c', 100)
 #define KCOV_DISABLE			_IO('c', 101)
 #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
+#define KCOV_UNIQUE_ENABLE		_IOR('c', 103, unsigned long)
 
 enum {
 	/*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 7b726fd761c1b..dea25c8a53b52 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -29,6 +29,10 @@
 
 #include <asm/setup.h>
 
+#ifdef CONFIG_KCOV_ENABLE_GUARDS
+atomic_t kcov_guard_max_index = ATOMIC_INIT(1);
+#endif
+
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
 /* Number of 64-bit words written per one comparison: */
@@ -161,8 +165,7 @@ static __always_inline bool in_softirq_really(void)
 	return in_serving_softirq() && !in_hardirq() && !in_nmi();
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
-				    struct task_struct *t)
+static notrace enum kcov_mode get_kcov_mode(struct task_struct *t)
 {
 	unsigned int mode;
 
@@ -172,7 +175,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
 	 * coverage collection section in a softirq.
 	 */
 	if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
-		return false;
+		return KCOV_MODE_INVALID;
 	mode = READ_ONCE(t->kcov_state.mode);
 	/*
 	 * There is some code that runs in interrupts but for which
@@ -182,7 +185,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
 	 * kcov_start().
 	 */
 	barrier();
-	return mode == needed_mode;
+	return mode;
 }
 
 static notrace unsigned long canonicalize_ip(unsigned long ip)
@@ -201,7 +204,7 @@ static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
 
 	if (likely(pos < size)) {
 		/*
-		 * Some early interrupt code could bypass check_kcov_mode() check
+		 * Some early interrupt code could bypass get_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
 		 * raised between writing pc and updating pos, the pc could be
 		 * overitten by the recursive __sanitizer_cov_trace_pc().
@@ -220,7 +223,7 @@ static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
 #ifndef CONFIG_KCOV_ENABLE_GUARDS
 void notrace __sanitizer_cov_trace_pc(void)
 {
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+	if (get_kcov_mode(current) != KCOV_MODE_TRACE_PC)
 		return;
 
 	sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
@@ -229,14 +232,73 @@ void notrace __sanitizer_cov_trace_pc(void)
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
 #else
+
+DEFINE_PER_CPU(u32, saved_index);
+/*
+ * Assign an index to a guard variable that does not have one yet.
+ * For an unlikely case of a race with another task executing the same basic
+ * block, we store the unused index in a per-cpu variable.
+ * In an even less likely case the current task may lose a race and get
+ * rescheduled onto a CPU that already has a saved index, discarding that index.
+ * This will result in an unused hole in the bitmap, but such events should have
+ * minor impact on the overall memory consumption.
+ */
+static __always_inline u32 init_pc_guard(u32 *guard)
+{
+	/* If the current CPU has a saved free index, use it. */
+	u32 index = this_cpu_xchg(saved_index, 0);
+	u32 old_guard;
+
+	if (likely(!index))
+		/*
+		 * Allocate a new index. No overflow is possible, because 2**32
+		 * unique basic blocks will take more space than the max size
+		 * of the kernel text segment.
+		 */
+		index = atomic_inc_return(&kcov_guard_max_index) - 1;
+
+	/*
+	 * Make sure another task is not initializing the same guard
+	 * concurrently.
+	 */
+	old_guard = cmpxchg(guard, 0, index);
+	if (unlikely(old_guard)) {
+		/* We lost the race, save the index for future use. */
+		this_cpu_write(saved_index, index);
+		return old_guard;
+	}
+	return index;
+}
+
 void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
 {
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
-		return;
+	u32 pc_index;
+	enum kcov_mode mode = get_kcov_mode(current);
 
-	sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
-				       current->kcov_state.s.trace_size,
-				       canonicalize_ip(_RET_IP_));
+	switch (mode) {
+	case KCOV_MODE_TRACE_UNIQUE_PC:
+		pc_index = READ_ONCE(*guard);
+		if (unlikely(!pc_index))
+			pc_index = init_pc_guard(guard);
+
+		/*
+		 * Use the bitmap for coverage deduplication. We assume both
+		 * s.bitmap and s.trace are non-NULL.
+		 */
+		if (likely(pc_index < current->kcov_state.s.bitmap_size))
+			if (test_and_set_bit(pc_index,
+					     current->kcov_state.s.bitmap))
+				return;
+		/* If the PC is new, write it to the trace. */
+		fallthrough;
+	case KCOV_MODE_TRACE_PC:
+		sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
+					       current->kcov_state.s.trace_size,
+					       canonicalize_ip(_RET_IP_));
+		break;
+	default:
+		return;
+	}
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
 
@@ -255,7 +317,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	u64 *trace;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
+	if (get_kcov_mode(t) != KCOV_MODE_TRACE_CMP)
 		return;
 
 	ip = canonicalize_ip(ip);
@@ -374,7 +436,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 	/* Cache in task struct for performance. */
 	t->kcov_state.s = state->s;
 	barrier();
-	/* See comment in check_kcov_mode(). */
+	/* See comment in get_kcov_mode(). */
 	WRITE_ONCE(t->kcov_state.mode, state->mode);
 }
 
@@ -408,6 +470,10 @@ static void kcov_reset(struct kcov *kcov)
 	kcov->state.mode = KCOV_MODE_INIT;
 	kcov->remote = false;
 	kcov->remote_size = 0;
+	kcov->state.s.trace = kcov->state.s.area;
+	kcov->state.s.trace_size = kcov->state.s.size;
+	kcov->state.s.bitmap = NULL;
+	kcov->state.s.bitmap_size = 0;
 	kcov->state.s.sequence++;
 }
 
@@ -594,6 +660,41 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
 	return false;
 }
 
+static long kcov_handle_unique_enable(struct kcov *kcov,
+				      unsigned long bitmap_words)
+{
+	struct task_struct *t = current;
+
+	if (!IS_ENABLED(CONFIG_KCOV_ENABLE_GUARDS))
+		return -ENOTSUPP;
+	if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
+		return -EINVAL;
+	if (kcov->t != NULL || t->kcov != NULL)
+		return -EBUSY;
+
+	/*
+	 * Cannot use zero-sized bitmap, also the bitmap must leave at least two
+	 * words for the trace.
+	 */
+	if ((!bitmap_words) || (bitmap_words >= (kcov->state.s.size - 1)))
+		return -EINVAL;
+
+	kcov->state.s.bitmap_size = bitmap_words * sizeof(unsigned long) * 8;
+	kcov->state.s.bitmap = kcov->state.s.area;
+	kcov->state.s.trace_size = kcov->state.s.size - bitmap_words;
+	kcov->state.s.trace =
+		((unsigned long *)kcov->state.s.area + bitmap_words);
+
+	kcov_fault_in_area(kcov);
+	kcov->state.mode = KCOV_MODE_TRACE_UNIQUE_PC;
+	kcov_start(t, kcov, &kcov->state);
+	kcov->t = t;
+	/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
+	kcov_get(kcov);
+
+	return 0;
+}
+
 static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
 {
@@ -627,6 +728,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
 		return 0;
+	case KCOV_UNIQUE_ENABLE:
+		return kcov_handle_unique_enable(kcov, arg);
 	case KCOV_DISABLE:
 		/* Disable coverage for the current task. */
 		unused = arg;
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-6-glider%40google.com.
