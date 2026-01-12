Return-Path: <kasan-dev+bncBDP53XW3ZQCBB3UWSXFQMGQEEISHWXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D5EED1500C
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:47 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-64b735f514dsf8393771a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246126; cv=pass;
        d=google.com; s=arc-20240605;
        b=Etq0uIiQew3dt6HXvQoAchKD3JDxwHIOhWIZ4GXwCoGSe0uWbU4Nclqcs6OQ8EheJ1
         qjjZzDIxKfxrbIyVBP/uhvf8Qlr/kWEOqDmaewEATjh1p9mTgaHMrYWYZ0XGWHwQkuTy
         WoB6QxPT2vqgkVbn2M8Pdwys1GmwMsVQP6+N2+CdwvE/MLQ2KmPmmGsOPGPbLcgfnFNr
         Rw0Jd2gDj77AHB9Ytb8jsS76Ed+hVJBmH5VoKstTQArR4gtSRog5ATyhgwMtiejEq2HQ
         ZWqkz3VHyXAtt5neJubup7NyZJd3WqaqG+imbVBE8Ym82hVVUKNSeI8kiYhMX5FsZBYf
         tbPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=sYcoja4ihzemO4YWfuEaBQfRwfy+K2uRU4FdSafxA/s=;
        fh=7nIn2JedPiDmgnTR91DofhV0a+aorxcEZY1+oSMFsVY=;
        b=VXWSKrq0WIq6r3UW4GAGp9tMB0JC0DRVU9lmwJsIw7LBLfN/qTQRRqHs6XjLU6aV23
         qOacPmybk5mVHPX5+CKKS/UvYJKA0ohRDMDVOq5lbh7zQKzpekaIR+I5uN2c6d5Zg9kN
         WI65siH5e7JS/pl4OHSDsffbYmExguD6T9eGVaKVNNqhd/EIw6jReTJb+naaQHpG8Uf0
         C5+YQGOx8fOmXuMF8F7QST/6Dpe1crS7GXu+OkuL69o/qINoLKp97yi86dsESVC2bBT9
         1n+i1JJ80LPsBHO6JG5awlIrEcRsXRLAlcIxQ/nAc2CQFtt2LqDTJDmE9dzU2W7vTBZ/
         jiCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=atZq1Kno;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246126; x=1768850926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sYcoja4ihzemO4YWfuEaBQfRwfy+K2uRU4FdSafxA/s=;
        b=EbOSAIAlMRQmIZ8N9dCnFsDlFb8b+akMIb6hhQKVmaSk0DFN0lfFFHH82e9p6jzlnI
         UVZwNDlZnMDjQTK2ZN1L0puxWHJIuGoGDrAs+ZNbOHtMd/xD/fg1fT3q4PMwr6KKFWry
         Ao2ELLXEbHg+Ln5QlKxE74rMF9Dbd/uo7nWqIk21V3xNXc7BTVi5bF/XtaUSHLE51Kwl
         eOVsCPA4jPiB19NZSz1ZuXCgXhyWPBDdC6KASfhwYeMVK07qdjjQEmjbC0psgBGN20lh
         KdC2VNqUJKkzOCpxVOmryXsoEJLcdT1YX+QlxJxM0Wh2m3rgcYeG1WTtgAhXzELDqDLp
         EXbg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246126; x=1768850926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=sYcoja4ihzemO4YWfuEaBQfRwfy+K2uRU4FdSafxA/s=;
        b=Af4NmfUGXd5dBkuppiAFeVdkAA1mnLdPnC5daJqGfW+35Q7NrLvmGxDQ6RLPBGE14d
         XKGYgsPdRDg2kKBH0t9+C7WDruxDWNjEHeAqNfry7J8CURvmWiO7c97h6ZWN1JeVqzUF
         9ZQMRV2m4ZjzNMSBnanOdeyonD56A8V3nBNFAaNF41v/8fIo0tVlYHTtWFONEKaMR8ov
         zzve/+QP6u0Ih2Hc1x2gQZdDC5kEgF3tiz4Rvpy0qB6o276X8bNOVREXAZU+R4N6GFdA
         Wdx29PeFpauXH/E1rDlHQvfaV7ZbL0zoUtFvcNuj6Z+EBhJTVGAhzTPGeLHQSDNgKhPc
         r+hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246126; x=1768850926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sYcoja4ihzemO4YWfuEaBQfRwfy+K2uRU4FdSafxA/s=;
        b=FZgAqV3B/obMAg+EP6FEhEQP/zphtcpYLgHcM0ZvnS0UZRDvVvmWxqJB8vRt0IaKuW
         gIc1oCRMiJyfocbhvmtuYyEPzBnWlu5QTQaGDbkAsuZzPi95dMqnbtLRPpy631h7t3t9
         hB76FILWOcJYMg56QgAVGUQhDeHHuKaRmgaoBk4WB7XuPFf065ukt2brRufOW0WsumZe
         muLaciOowL+LiSgqEUF18EDDBc7RO/fg72o9wGP8jBT0Rs1v7EmDxwLaJoRuLxhUKwpi
         AeJjtjwx4TV+E8K54ahiFy1vB+xo/kgPggu5zL2Azp08sYNyR3LZP00jliafR3Twq3ry
         /sYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6HCCFjbFHWjCzvYde+FwukQp4tv7u9+YKr2wBg9ZhVyqwjzVk72+p5eykLQAJ1Kdp5uQbxw==@lfdr.de
X-Gm-Message-State: AOJu0YxEugjvS6h72kSs0VAutXvhCQcfCoI4IH1z39P0B9QCsJ6t9aqW
	cztppFvmNHnoETiDU2Y9/41g6tRn4DGU3dCTqKLF6KxHCziilCI5epV9
X-Google-Smtp-Source: AGHT+IHOXA3b/e0c31QHw4cN+lZCBQ31uYygA6BBf2cyg8OCq4JhlVVskxksy7oT6BSvUC8i6R6Qeg==
X-Received: by 2002:a05:6402:3487:b0:637:dfb1:33a8 with SMTP id 4fb4d7f45d1cf-65097dcc598mr17981580a12.3.1768246126487;
        Mon, 12 Jan 2026 11:28:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FIwhAf8H6Z3mKOD1xFmOc28dQ25PujsUdaa1X0JezerA=="
Received: by 2002:a50:fc13:0:b0:64b:643e:9559 with SMTP id 4fb4d7f45d1cf-650748c9c1els2058566a12.1.-pod-prod-07-eu;
 Mon, 12 Jan 2026 11:28:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3yjnH1ksumXDNBKdCu9j1CCFPwOR5z1hMAii5hEX7XeZTLj3Co0EQdU7es3OSzmMXoSYa4qZpJa8=@googlegroups.com
X-Received: by 2002:a17:907:9614:b0:b7d:1d1b:217a with SMTP id a640c23a62f3a-b84453a11d9mr1812334466b.34.1768246123765;
        Mon, 12 Jan 2026 11:28:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246123; cv=none;
        d=google.com; s=arc-20240605;
        b=XqrXxyqXtzJ3c3cmLySRaxIEOeayxDyYkbc5sehDUKt1e8o6xwTmMuApOlVdVybx9C
         udyn0AHF0EQZn8MxbRdkiAUvpzVQfKoHFKYbInQNvMhOxLi0TjvBpkoDYsY8BA7gOhgG
         npefL4UlhzdWvpAX4tVXoNocC0uACIcpCXtQ6QpfBrOolYLVlFjzr6A+Wm4sVnAc+sqX
         xZBxAcu0GFXNEy0HqA95st385NeyQTZ09oQCh5qLGn++/3jo4uINjy0Eza8pZzC+5Ibk
         O34LASTcv4XWnQ4cBIVBPmkmQg1W7DIcwSLuDhX4oM6TacW0MeiK83skRVeNb8E4K/yZ
         muhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Hw+SyBhpJj8Dk0rbLbmvCfZKQJWCvJPz8EnXuKWjIzw=;
        fh=weINUX+67yAULNNYY1dEEPcotIv8cDk02bi5kpeFA8Q=;
        b=CPVI9Gk4hbwVYsy6a09K8tVGbpSTndFsifJHYZ3t8c2FdpbiCtdXcS0xXudukrHBwv
         mvn7wZnIEF5zAkcmCB9zXf04BXGIvWDpHlUY7BSd7FtchA5No2MVxXSLjTQ0EkPCzN7u
         Scm+2l3xrbWky0YovIRsmop7qK1BLgtQbNgoS4w3iWFYT4Rv1WFjxoG+JgzR8Z7qQFUN
         4TvCE12NWLwFlV+m7TNDgde5NkuIP+1qHucdQ0UQ0WkJT0sNmN634CaDavsdPp6ut0G3
         byBu+KTKbnH8P7lkeqBnoKTVqWgMp7fHh7NKBybEK+HeyBLgvb8XKwHgrdmeeORGPjuI
         L+WA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=atZq1Kno;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870d104efdsi9453366b.4.2026.01.12.11.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:43 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-65063a95558so10156268a12.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZBI/hDZ6J3GVVVySW8lsx5ccfw2I7T1Cu48IjAoh1L/Vch0Rp829JRFwIb88lwAf5nc808rvqqVw=@googlegroups.com
X-Gm-Gg: AY/fxX56UxgIEWKUsIvC6bv3y1VaI7oLdmGojnAvdLZfJ0n6dHdFRiTE3Nvi7dRdB6Y
	AX5sOXcs2mjahWFVN3C/oYQtG9RthjgjUl7mysd+7xBV71Avw5szZ8PnuFiPgldJCRq6thz9vsA
	sVBbFa+3BaQlQJ9Be/Hm3d1ZCRKvm2ZJRev2fUNA3aTbex1gU3hMMX5urKhaBtEdeI6/ZhX/TZW
	7tw5uT5WM50Qo60hrEbCq2X1DsDbgmwIoZm0UOQpG/AabjfkrbhSGjhYbcRw1GN9bxpdZWMo8Uc
	0zB07f2ToM9Tl9lR5etzv7jvclTlAICo5Nqsylt+4yY+EcPx3Z6LxHC9VIxcbQz0jqxuVu7ghAU
	+8fbs+7JiyMOejxuxi5vj+s4pJjiIYwYVpPc8iDxpdzv8ueXUC1PyAzwrp3bEG7CqTBOR9SfuI1
	SpEDqh7zmhm7fEtf3o8zy4WsOg524ZH3OEEyNr6oFxkoF7qY/frw==
X-Received: by 2002:a05:6402:1e8c:b0:64b:6007:d8dc with SMTP id 4fb4d7f45d1cf-65097dcd890mr17558013a12.7.1768246122989;
        Mon, 12 Jan 2026 11:28:42 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:42 -0800 (PST)
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
Subject: [PATCH v4 2/6] kfuzztest: implement core module and input processing
Date: Mon, 12 Jan 2026 20:28:23 +0100
Message-ID: <20260112192827.25989-3-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=atZq1Kno;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add the core runtime implementation for KFuzzTest. This includes the
module initialization, and the logic for receiving and processing
user-provided inputs through debugfs.

On module load, the framework discovers all of the simple test targets
(FUZZ_TEST_SIMPLE) by iterating over the .kfuzztest_simple_target
section, creating a corresponding debugfs directory with a write-only
'input_simple' file for each of them.

Writing to an 'input_simple' file triggers the following fuzzing
sequence:
1. The binary input is allocated and copied from userspace into a
   kernel buffer.
2. The buffer and its length are passed immediately to the user-defined
   test logic.
3. The kernel is tainted with TAINT_TEST to indicate that untrusted input
   has been fed directly to the internal kernel functions.

This lightweight implementation relies on the caller (e.g., a fuzzer or
script) to provide raw binary data that the target function can process.

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>

---
PR v4:
- Remove parsing, relocation, and KASAN poisoning logic to support the
  move to a simple-only design.
- Remove the '_config' debugfs directory and associated state tracking
  (minimum alignment, invocation counts) to reduce complexity.
- Enforce zero offset in `kfuzztest_write_cb_common` to ensure inputs
  are passed down as single, contiguous blocks.
PR v3:
- Handle FUZZ_TEST_SIMPLE targets by creating a write-only
  'input_simple' under the fuzz target's directory.
- Add implementation for `kfuzztest_write_input_cb`.
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
 lib/Makefile           |   2 +
 lib/kfuzztest/Makefile |   4 ++
 lib/kfuzztest/input.c  |  47 ++++++++++++++
 lib/kfuzztest/main.c   | 142 +++++++++++++++++++++++++++++++++++++++++
 4 files changed, 195 insertions(+)
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/input.c
 create mode 100644 lib/kfuzztest/main.c

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
index 000000000000..3cf5da5597a4
--- /dev/null
+++ b/lib/kfuzztest/Makefile
@@ -0,0 +1,4 @@
+# SPDX-License-Identifier: GPL-2.0
+
+obj-$(CONFIG_KFUZZTEST) += kfuzztest.o
+kfuzztest-objs := main.o input.o
diff --git a/lib/kfuzztest/input.c b/lib/kfuzztest/input.c
new file mode 100644
index 000000000000..aae966ea76b3
--- /dev/null
+++ b/lib/kfuzztest/input.c
@@ -0,0 +1,47 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KFuzzTest input handling.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+
+int kfuzztest_write_cb_common(struct file *filp, const char __user *buf, size_t len, loff_t *off, void **test_buffer)
+{
+	void *buffer;
+	ssize_t ret;
+
+	/*
+	 * Enforce a zero-offset to ensure that all data is passed down in a
+	 * single contiguous blob and not fragmented across multiple write
+	 * system calls.
+	 */
+	if (*off)
+		return -EINVAL;
+
+	/*
+	 * Taint the kernel on the first fuzzing invocation. The debugfs
+	 * interface provides a high-risk entry point for userspace to
+	 * call kernel functions with untrusted input.
+	 */
+	if (!test_taint(TAINT_TEST))
+		add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
+
+	if (len > KFUZZTEST_MAX_INPUT_SIZE) {
+		pr_warn("kfuzztest: user input of size %zu is too large", len);
+		return -EINVAL;
+	}
+
+	buffer = kzalloc(len, GFP_KERNEL);
+	if (!buffer)
+		return -ENOMEM;
+
+	ret = simple_write_to_buffer(buffer, len, off, buf, len);
+	if (ret != len) {
+		kfree(buffer);
+		return -EFAULT;
+	}
+
+	*test_buffer = buffer;
+	return 0;
+}
diff --git a/lib/kfuzztest/main.c b/lib/kfuzztest/main.c
new file mode 100644
index 000000000000..40a9e56c81ad
--- /dev/null
+++ b/lib/kfuzztest/main.c
@@ -0,0 +1,142 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KFuzzTest core module initialization and debugfs interface.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/atomic.h>
+#include <linux/debugfs.h>
+#include <linux/err.h>
+#include <linux/fs.h>
+#include <linux/kasan.h>
+#include <linux/kfuzztest.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Ethan Graham <ethan.w.s.graham@gmail.com>");
+MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");
+
+extern const struct kfuzztest_simple_target __kfuzztest_simple_targets_start[];
+extern const struct kfuzztest_simple_target __kfuzztest_simple_targets_end[];
+
+struct target_fops {
+	struct file_operations target_simple;
+};
+
+/**
+ * struct kfuzztest_state - global state for the KFuzzTest module
+ *
+ * @kfuzztest_dir: The root debugfs directory, /sys/kernel/debug/kfuzztest/.
+ * @num_targets: number of registered targets.
+ * @target_fops: array of file operations for each registered target.
+ */
+struct kfuzztest_state {
+	struct dentry *kfuzztest_dir;
+	struct target_fops *target_fops;
+	size_t num_targets;
+};
+
+static struct kfuzztest_state state;
+
+static void cleanup_kfuzztest_state(struct kfuzztest_state *st)
+{
+	debugfs_remove_recursive(st->kfuzztest_dir);
+	st->num_targets = 0;
+	kfree(st->target_fops);
+	st->target_fops = NULL;
+}
+
+static const umode_t KFUZZTEST_INPUT_PERMS = 0222;
+
+static int initialize_target_dir(struct kfuzztest_state *st, const struct kfuzztest_simple_target *targ,
+				 struct target_fops *fops)
+{
+	struct dentry *dir, *input_simple;
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
+	input_simple = debugfs_create_file("input_simple", KFUZZTEST_INPUT_PERMS, dir, NULL, &fops->target_simple);
+	if (!input_simple)
+		err = -ENOMEM;
+	else if (IS_ERR(input_simple))
+		err = PTR_ERR(input_simple);
+	if (err)
+		pr_info("kfuzztest: failed to create /kfuzztest/%s/input_simple", targ->name);
+out:
+	return err;
+}
+
+/**
+ * kfuzztest_init - initializes the debug filesystem for KFuzzTest
+ *
+ * Each registered target in the ".kfuzztest_simple_target" section gets its own
+ * subdirectory under "/sys/kernel/debug/kfuzztest/<test-name>" containing one
+ * write-only "input_simple" file used for receiving binary inputs from
+ * userspace.
+ *
+ * @return 0 on success or an error
+ */
+static int __init kfuzztest_init(void)
+{
+	const struct kfuzztest_simple_target *targ;
+	int err = 0;
+	int i = 0;
+
+	state.num_targets = __kfuzztest_simple_targets_end - __kfuzztest_simple_targets_start;
+	state.target_fops = kzalloc(sizeof(struct target_fops) * state.num_targets, GFP_KERNEL);
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
+	for (targ = __kfuzztest_simple_targets_start; targ < __kfuzztest_simple_targets_end; targ++, i++) {
+		state.target_fops[i].target_simple = (struct file_operations){
+			.owner = THIS_MODULE,
+			.write = targ->write_input_cb,
+		};
+		err = initialize_target_dir(&state, targ, &state.target_fops[i]);
+		/*
+		 * Bail out if a single target fails to initialize. This avoids
+		 * partial setup, and a failure here likely indicates an issue
+		 * with debugfs.
+		 */
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
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-3-ethan.w.s.graham%40gmail.com.
