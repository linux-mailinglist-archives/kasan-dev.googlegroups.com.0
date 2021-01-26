Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPNZYCAAMGQEPBHVAZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 47DF9303F15
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:44:30 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id u8sf11472629qvm.5
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:44:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668669; cv=pass;
        d=google.com; s=arc-20160816;
        b=LaSVZkcLIgVP7+2+UgVq0yxRWxwnJglIxZCOGkQTL51JCoUEq6r9jhBhjcxrQtqLKY
         lulWKvhWAL/ytt9XJjio1ipM/gAHrJLUwexUWnEUVeT4FImS+Q4kwktlJMNzBvHhfljZ
         Ysm4b0nOIPXnlT5dRHEc7sk2AiP1DWUYza62KoeHNwMUgTle5e7W+ZYVnU6mA8Ppmexv
         +4v8fKc8TelQ5hMDRCmdxNlI5WRn0l/x5VgcBu/LJuYyhFuv4eM4UF62juJWTT1HAWHj
         ZlW2fz5mErEhpOFWqm0Mh1pptaP53WXt+m264g0to6A90AEAxUkWPXsUX3xidwl4C2bR
         3fNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j7dODL4jsNzKq0EPPnWD/mb70ZBiGRZPFvnZ6p2kwl8=;
        b=i711MgeoxoJ6XA4BjIeOwWKDzaVL73ThUaGiv8dB3kSO//WuDAMW8dIiQ/hsjqoy8d
         sULoHkSVbRiObjeYfT4HycXbmfwCsEmKFvLe4R9fwpQ9hM6wdyhYwNwSelYMaseaNdlN
         mcaDJGeExRV2B/DRdKwjzTpuvl9iN6RyJrLXkwrjuP8Non3AZ1WIDNl5hwNdbnU4mmth
         JUp8chB4Ea3pt4ebOZqSS5ZKc1RiKXqIrDw9YKI8cNuTrZKrRu0kYz6Y5njTdn8RCU2R
         3NW2lTLT68nJkMwBxRt00gvVDZs0Aeg+MR0gZ6433/+/txdeZW//FanoAnDy/9efpxhS
         j9MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j7dODL4jsNzKq0EPPnWD/mb70ZBiGRZPFvnZ6p2kwl8=;
        b=KjHCWy/o+vJDDTzVIiwEfnVT8H2Qv2IKj3pODlxF7sUXdRdg4RG2JGqJHTHSh1B9KJ
         ggoHpQ7gxwLaMKXDvn1yNQBsw9unuEo71IrkSBoheHUQuoSGXKCMhaSOWPCsUDiOgsD2
         YzLhFVXZt/89I+4G0Er1n9KTEHtWgXj1Pko9Ds1bgJtjgk2UcSLNk3OZNMVm2JttUjdr
         J8s6GI5ckf9EA/gd2B8DbQGtW00nfrxcSjIs8bFX/Z8VthjNrgicTCN2acNPXxW0u8gr
         GWERRLlAqaTewo2yarfR9ZBqsu3okmDhP2pF9WkMJN0gktAAROTsL+kh9N7QcsiWFsOH
         uDfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j7dODL4jsNzKq0EPPnWD/mb70ZBiGRZPFvnZ6p2kwl8=;
        b=cLs1bgW6owvgF9BLILbeCnqw82YE8JLiRi0Pj3YY/DRKLATVUILSN3U/vt26AnDo8W
         F0GXampz0S12LhBJHcI0ArKKcGCnAEA9fVbfsG7GjS7RQryEMbkoCTjVTysuezn8tPPQ
         oNONzOtgM6IccsCi2AemLMbCeHjllwYEUcztmbt7MJXAkCEUnxgkr/YvhSUbEYzHmlJS
         twEyQB09Y9zHaoLTXTAErU5rJw+mcABRhQrA9t4Zsbug62EquSuuTcK0PpFlkk+v4JBB
         D/OqqDNyFRFol3Tcw3YFVPleyEm0MZu56mn19yZ7nqXwnP0OOz+WHx2PewCJDxfl5DLZ
         lexg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cmd1NB/gHQvqBpO/pIxal/4nmcUHDBsooej1sN/G/8QVMmw6S
	T9fYG3RLgRY3NRHy9Dmg214=
X-Google-Smtp-Source: ABdhPJx0D0KvxERjl5BzYsNPyI5JHARkQA2j4gOU4myhXYyo9ex7Vt5Aw63kB/e96lnoE5wP3+PJoA==
X-Received: by 2002:a37:a08c:: with SMTP id j134mr5526028qke.92.1611668669276;
        Tue, 26 Jan 2021 05:44:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4644:: with SMTP id t65ls8525895qka.5.gmail; Tue, 26 Jan
 2021 05:44:28 -0800 (PST)
X-Received: by 2002:a37:2784:: with SMTP id n126mr5715822qkn.328.1611668668553;
        Tue, 26 Jan 2021 05:44:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668668; cv=none;
        d=google.com; s=arc-20160816;
        b=Nx3YbA1ZGP5Z435SSCT02RiAOBcT2DOf8MgMpAnuyYQ6t/S9B2f7Luy2eYGUCuO/E5
         pXknPdmU2oOOLpyS9npH/wLZq/pi0yMDkvhlE6Kam5ojzE/5Z7qCijS3SjnJK3niuGdj
         GZfMyEaE+7cOByEqBF6rmcITjmaqIbMjtm9gFZCTVnqXqUQFOleJb81O6MCondDYHU1W
         3yTekKCzJBhiuht6Qc7u9VUp5JK10kkSqdgNm95nzMMnwbwCvaEdi1ybIdCrw2qAXF5H
         5l+Epv1HYtKf41V2qSNbiRPwXWhC+4k7gtQmCO7sdBd4daxS7TMd1AsIxL2cN/L6+hru
         einw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WRgb/0XUFzrxy0cLsXJGYUgjnXLxUxBvCvb2JFCh9XQ=;
        b=F9JZz355YqoICKrFJ7q0P26MmgMhawTmslEXMGx9Q4jChlUeAhZNoyiDf/xWLPvoJJ
         bA8wfPzn/USQ695ArGDlXOBF4d4YyBn0QP7DXisC0SkeeswZ1zajL24/CRwJsfUo2V4F
         A734T6g3KxyNO0yu408JGF6WYOVWFZFOk2Y/vLIiHfdj+YjRqaJImfOndKhTYB+dccrs
         EDpmpAaVaqFjbFBKShy5d2pbVgIfbd9UHeMzNhAf4KbqjnGnZLGzCMwDvMUk1Yg9eHEQ
         fcQG7HnP/a8HBoI51Ah1IKBprSn5mgnQ8PkPFfzohT93l64tk05P/GUdAV+Gx3akMnAH
         A2uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n6si350470qkg.7.2021.01.26.05.44.28
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:44:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CC54F106F;
	Tue, 26 Jan 2021 05:44:22 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E7EE03F68F;
	Tue, 26 Jan 2021 05:44:20 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v5 1/2] kasan: Add explicit preconditions to kasan_report()
Date: Tue, 26 Jan 2021 13:44:08 +0000
Message-Id: <20210126134409.47894-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210126134409.47894-1-vincenzo.frascino@arm.com>
References: <20210126134409.47894-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() accesses the
metadata only when addr_has_metadata() succeeds.

Add a comment to make sure that the preconditions to the function are
explicitly clarified.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index fe1ae73ff8b5..0aea9e2a2a01 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -333,6 +333,13 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)arch_kasan_reset_tag(addr);
 }
 
+/**
+ * kasan_report - print a report about a bad memory access detected by KASAN
+ * @addr: address of the bad access
+ * @size: size of the bad access
+ * @is_write: whether the bad access is a write or a read
+ * @ip: instruction pointer for the accessibility check or the bad access itself
+ */
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134409.47894-2-vincenzo.frascino%40arm.com.
