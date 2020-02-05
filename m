Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI6S5TYQKGQEOVEFEPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 8781C1539B2
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 21:44:19 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id s13sf2066815wrb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 12:44:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580935459; cv=pass;
        d=google.com; s=arc-20160816;
        b=X0kS8Rs3MfNug/aINEWBjyXt9p4z8GO6kB0LLl5M4LAOlRNaZv7/36HvWDd5RCAI10
         iertKVPO3JuoVxR6WThlaEt9a3+BpyNo5rGK+gZMBA66t9kBwVIN/A7mi84/hOancW8B
         CJUol0vXnfqxwG0y+qFYF/RFtR6c9nTj/u5eXQjfkC5zCuOCux67yxqRUdEzU0ezRFbV
         91vv5KZK8yomi9H5z0etXJpxOcrWGPUglR+uVCxIx+bEhXZyLySLyggSUqgqJ6u5BqlV
         1nEqvBcn2+IENQM/mNh4dmWS1+Rd1VFAomA/L4YqHqq6fG10Ws7QjCq/iEQDTdGJvgW3
         /MEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+6sh6SKZgSUREUKXVFeikKb0716/m1ArfxMY79p4T6c=;
        b=gyUfoELhtly424wa1fYSOCDp32JjcLqIk2b92D6EGVchtBHMwvF0QgLlSNVHV2lppx
         Tffy7F9+m03I+rdwPuZs14djk7Cw2DOv8P+cOl8qtWut8rrsjWEHuyWYXDN7dMsRsANT
         6562Y2fnZheH1FbkYs+yyaWkks9uC1l2ctmKbztAd+k1xeVEWWXkw0ff9694SRaGHxuZ
         2GxVdiOgYzqGOFwCl4keerbxxTk0avnZ257IAHGWT/xxzyaXQ2zkEiA2VO3DqGtuNlXx
         3l5G7gBtGurS7ppek6BBi9inAP+lbSEgHPMNybq1X+E6Oy7Xp4eIx5tB5zTqA8xlrM29
         ukVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IqOTXcZR;
       spf=pass (google.com: domain of 3iik7xgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Iik7XgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6sh6SKZgSUREUKXVFeikKb0716/m1ArfxMY79p4T6c=;
        b=qG6LPy/7x/q3N31FOpYLevEh4UwWGYeEfMxHhP/W5U2PZGm5lA93s9itYQ2Y7iRDOy
         YBViq5GeedfoGIuOWrouT6pB83yAoyT1THY7CK99ts2QA1iLXgqK269OGEz0PeSPfeGM
         BYrOzlGnuQxoL9smFekrIs5qRKoEX2Rdrv8A5aIyvFIwjf2X075IlWm8ZfsJ7+M8NGLG
         M3gDvhXJJLTSZ4nWmjv/IeW6IegiNiDN8iqmWhk10CyK8z2E+MTkjYorLneGpEhuiXa9
         hkERV0LlErCFCT2MhyPnN0qD3PhPtjRhdZ1tqY2lVsRSWpjgJ3abfXM0iE6dL9vKRAWi
         ZxFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6sh6SKZgSUREUKXVFeikKb0716/m1ArfxMY79p4T6c=;
        b=kmu7axfddlMrt9Y7W2hr7AK2FK2VVimK3jnmgYTDLbo0hMXqWqyIiGO5qf732qjgKU
         jVVbAWF+EJU4dnL7rd06xCB9g++Kr99KQ3BYJQmCWP0ygXWHMVLAEOfQ5vlumlrfx2Qa
         AK2UvsKY7zgx0ZijBlWC3m5Yz7skx0CiMaiqcZTcP05Fjou1KJAIn0QeXnJoRxPCjhTG
         kmaREEsbzDuRIj2IZUP4fScl9DalNdl0BhJsDDG2TaxCS/xmB4hzQfRXLsGxH5M5JgQk
         WG6Ao4GVvAeCuybrw087IoS6+d34iily0/AGTB3lW0K6AD8eVXXV+UqmXLedRtSeqmgV
         VD1g==
X-Gm-Message-State: APjAAAWz5WhK5zfDsBPqP7llu5NYnVrQdx6z8zg/HkHzqcqVZC7xWf19
	WjJbOvKOCBbzlESB7ekxl2Y=
X-Google-Smtp-Source: APXvYqwAyAxRoWz8xteQwsj+oOvNzJa764Cqr81jCsxl1NYJ0QKE9In6NwUPcCzq9yiv8e3k7yP/Rw==
X-Received: by 2002:adf:9427:: with SMTP id 36mr419374wrq.166.1580935459292;
        Wed, 05 Feb 2020 12:44:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:65d0:: with SMTP id e16ls2070201wrw.1.gmail; Wed, 05 Feb
 2020 12:44:18 -0800 (PST)
X-Received: by 2002:adf:dd8a:: with SMTP id x10mr381002wrl.117.1580935458642;
        Wed, 05 Feb 2020 12:44:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580935458; cv=none;
        d=google.com; s=arc-20160816;
        b=r/4kdFhpwAQTzvPdyRj/W+yaHDC0ftVljTfbYfMSPhMd+Ga7jR7dYaMAWXAanHd9AA
         sX+8k7o5Nlro8mBgjcHMbadZ0eFnyNCiBU5oDSEtWq1xCUe/ZRpTgvjygK+g2gR203Rv
         Wh0u3GVcDt4QArXzNUDb2U7fYna8QuzTLjl5cuIIr521iJlVtYfO2lxG8xYLPyFtmbYg
         7ahqaLz3hwUJQitxsDu6FEwqKid9TCGZDWbhcYBeObwoA2Vj21X248kqTKBUiZ7mKBZf
         +MwPFi8UdilcYH2ETx3fZ8yt8ehRC0ssa5E198X+XEzstuwYQkoQR9bG83lnonvCC4Hz
         AcMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sqwbag/mHy/vE3+gzAzb/2Oiv0jGf8Mn6Bv8Q3gyQkw=;
        b=pTVJVK4d4QqwS/Zrj6dwv+uVRbBFrFDYNv26HoW62gW+AgP/rp0fIofEylK7xCs82/
         Z1lyOReYrGd/Tp/zABof2M6kEzYuqqNJT9uSSLetNZZxdR9XymOAe0gQIth3Rm/8sR7e
         Cl4G6HrcUThZcRDr4x2ha8j8SJw4AfZXGQyrKHJBg+MHL/wIu6eY0SJFDjor99Y7gIFF
         RWamWpDyk6yZo7MMRCt7gjkdJEKoaKB2UKfLyz58kTdTmr0MZW3QpUpGdL0WJx2dAN3V
         yN7uCNRhAENZhHOOoY1G5sIv1h2cDtmVEbEl3dmSryGc2xo/ufheDZHSYhipjE9zt2su
         7GOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IqOTXcZR;
       spf=pass (google.com: domain of 3iik7xgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Iik7XgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id t131si37432wmb.1.2020.02.05.12.44.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2020 12:44:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3iik7xgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m4so1552633wmi.5
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2020 12:44:18 -0800 (PST)
X-Received: by 2002:a5d:6646:: with SMTP id f6mr418289wrw.276.1580935458188;
 Wed, 05 Feb 2020 12:44:18 -0800 (PST)
Date: Wed,  5 Feb 2020 21:43:32 +0100
In-Reply-To: <20200205204333.30953-1-elver@google.com>
Message-Id: <20200205204333.30953-2-elver@google.com>
Mime-Version: 1.0
References: <20200205204333.30953-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 2/3] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IqOTXcZR;       spf=pass
 (google.com: domain of 3iik7xgukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3Iik7XgUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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

Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
may be used to assert properties of synchronization logic, where
violation cannot be detected as a normal data race.

Examples of the reports that may be generated:

    ==================================================================
    BUG: KCSAN: data-race in test_thread / test_thread

    write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
     test_thread+0x8d/0x111
     debugfs_write.cold+0x32/0x44
     ...

    assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
     test_thread+0xa3/0x111
     debugfs_write.cold+0x32/0x44
     ...
    ==================================================================

    ==================================================================
    BUG: KCSAN: data-race in test_thread / test_thread

    assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
     test_thread+0xb9/0x111
     debugfs_write.cold+0x32/0x44
     ...

    read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
     test_thread+0x77/0x111
     debugfs_write.cold+0x32/0x44
     ...
    ==================================================================

Signed-off-by: Marco Elver <elver@google.com>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
---

Please let me know if the names make sense, given they do not include a
KCSAN_ prefix.

The names are unique across the kernel. I wouldn't expect another macro
with the same name but different semantics to pop up any time soon. If
there is a dual use to these macros (e.g. another tool that could hook
into it), we could also move it elsewhere (include/linux/compiler.h?).

We can also revisit the original suggestion of WRITE_ONCE_EXCLUSIVE(),
if it is something that'd be used very widely. It'd be straightforward
to add with the help of these macros, but would need to be added to
include/linux/compiler.h.
---
 include/linux/kcsan-checks.h | 34 ++++++++++++++++++++++++++++++++++
 1 file changed, 34 insertions(+)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 21b1d1f214ad5..1a7b51e516335 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -96,4 +96,38 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
 #endif
 
+/**
+ * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
+ *
+ * Assert that there are no other threads writing @var; other readers are
+ * allowed. This assertion can be used to specify properties of synchronization
+ * logic, where violation cannot be detected as a normal data race.
+ *
+ * For example, if a per-CPU variable is only meant to be written by a single
+ * CPU, but may be read from other CPUs; in this case, reads and writes must be
+ * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
+ * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
+ * race condition. Using this macro allows specifying this property in the code
+ * and catch such bugs.
+ *
+ * @var variable to assert on
+ */
+#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
+	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
+
+/**
+ * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
+ *
+ * Assert that no other thread is accessing @var (no readers nor writers). This
+ * assertion can be used to specify properties of synchronization logic, where
+ * violation cannot be detected as a normal data race.
+ *
+ * For example, if a variable is not read nor written by the current thread, nor
+ * should it be touched by any other threads during the current execution phase.
+ *
+ * @var variable to assert on
+ */
+#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
+	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
+
 #endif /* _LINUX_KCSAN_CHECKS_H */
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205204333.30953-2-elver%40google.com.
