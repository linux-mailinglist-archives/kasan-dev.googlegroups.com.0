Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB25UVOAAMGQEMI5HNTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E83B3004AE
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:00:13 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id y34sf3474572pgk.21
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:00:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324012; cv=pass;
        d=google.com; s=arc-20160816;
        b=KxyjF7dSeLgH1DBgbLek+kjcNHx/Oz01pldGo0uHcT3UaKKDVGybozdL2gAr+K/K5a
         X5MP81PVhnSkpdyTANFOEdotAvelIYEVepKPSiQ7mHV8lLWTyPdXEQrU7uZkU4EwUo0E
         pi5EdIOwL49kqObh7kws0NZJk4yrZgxZJwNzVHSxJJIakNkN4V0muj632pR2IRIiZNgY
         m8nQZKVaj9360PvzvSAzq2o6f8+Bwhr8O4GIKE2/Hf/lNEX92zda3PxQAZW6tSgRMV5U
         J3T+xU4yAxSJTeqXubEqrB41Bo0nLIFXv7QHDU+jLXB7a33Hwdtp3LpNOVCSJyEntYq1
         Te2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sThyli1fcdDd1E4wtgqBxmg1mhuxQpAv7Mip9iUFNkA=;
        b=CnTgxu7SUG5skdb653u60FEjCgPb5ZiMh9yxs3j/+cUn9itLDvszN5cGFfwQsBFdoY
         kpT5+4+6GZ1a5UnoZ6w8d8GqLY7inLCYhW7kpwTYUc9yWX2rwy5CtsHAsVtxRzEeCC6D
         YlWqlkOIXpN/rr+gami+UbyGMm+xlUhqBS5igYmM9K7a8of1wGhCPsDYObAz91dPdsUY
         FUjY+jE1tf7V4NS7QXwpjc3Jp0za6NCzo8DmLoklNGjcDTK/Yb7PkZk2cjAALgLGIrC4
         TjBhBvK33WjDD1JafLvr26xIlFy8BZmS0hWH4NAKQUvXpBSzcdFnCyZgzcABEd3enhiy
         giKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sThyli1fcdDd1E4wtgqBxmg1mhuxQpAv7Mip9iUFNkA=;
        b=DK2cyZ3olltX0GgdN2+SJcCuj0T3JrCTkG7QH/gVDMBAvATl4Q6Uv99oYzL9Y5Gbte
         3JBt7tTWvklTrovyDr8KUfHeBk3T9BtzEhS2QLA4GOiAVy4DrRJNkRCYIDZGfG+1v78Q
         /yy0bVWa2G+HKzKqDcnspKTVGccIE2BFs6UWCA8ZO1mFaQNAgR5JmS4EI8D+hZZaZ17R
         gbxdFhZnFWjBVBqb/iedSpK+He3iVaYLsa8tIQMRoGqqEWXthLZUC1Dgw8xrNKC6m6v6
         cYLluyiXDgfF6XxK2x8WSmEzEZ8FHEZeuUUoUQV3wtmm/KuAsQQ5ZprFY9zmF5jCEnPC
         iI2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sThyli1fcdDd1E4wtgqBxmg1mhuxQpAv7Mip9iUFNkA=;
        b=DWPmfCI9qEqhmI3q6DbkjYhGnjE+Qff0tH8nygrMotgF775qat/FThwG+Rva64p8va
         O6JkqTQYE7zk/1UU3YhNiRqZzv185bR+3pCtto3xBMSLwzwzXHCJ/Q2OSjRPhqcLRMm5
         xAebpEToNvlHQmH4LJHoKGU1zC5zOtCJd9bT+mG+ApIFXzA2CiRXKJ3uj7jd58q/y71f
         LjTaGzVf0mE4aEGHXACpoYN6CXMG3Kv2pWN7iZO3zTF/wdoZ/2wn3OuZrk0i+TVIZxQO
         NfBqwZtVVywDUM7u90CKi6xFiXeToQWOErUDNnjlfb07Z7vwREETehvdKzV/SJVYKl/p
         4fTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GZ1LuTUpl7b7oNefOhtLubX3/pRr0l9PHhpafaS8QRydtdD3p
	9GhtAsKHxXXkM9PU3d91HzI=
X-Google-Smtp-Source: ABdhPJxBizILjbal/kNX8S0zjcSThOh1BoxLb0jbDW9Ts9NCv5Tk8DUNdXAUUnERckMpousgqeNyug==
X-Received: by 2002:a17:90b:d8d:: with SMTP id bg13mr5695174pjb.189.1611324012079;
        Fri, 22 Jan 2021 06:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8bca:: with SMTP id s10ls1560768pfd.10.gmail; Fri, 22
 Jan 2021 06:00:11 -0800 (PST)
X-Received: by 2002:a63:3246:: with SMTP id y67mr4693293pgy.438.1611324011272;
        Fri, 22 Jan 2021 06:00:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324011; cv=none;
        d=google.com; s=arc-20160816;
        b=EPHp9tDF8KJvWogeJsHIBxj5KrKHQrYknT/S9L3UpYmqk9eqEmrEGdTfoC6XQixwkN
         bk6ZxgJxCBpcxLVSDXywn6FhAMPRl8SgfHA/ic2MLZgXKvRntdqQbKKjNa7e4lO95sBT
         1Z59tBdoKiEwnvzDa+j92bvoBnYiZ1uUEPh0tuNwN+9abLFKX2+A0DlXNKCmmwtNVG+F
         llQlTLuQ1LLCLy/ZY18ZNWUwvDj+Se4gk+bKK8Ta9BEz/Eo/tKyKivUvm+i3ZuHvOykG
         qTPtFZbPgeq7fNc9waOJgGZM6/bWaLxCkEySQP5NpVcnQK+EKC9Gl6v0MKtEEgbXiCnv
         g6Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=W8hrTJyuzY83Wbon47iRI40fyexQg4UBVm6M6c6SipI=;
        b=0z4iVodyiw6lbIdFdTKdO1NUJFqZ1dqmXMBc1ZDzqNYOBu816Yzti4D7AtHd3E0TvT
         bhD7YgmPa5PqOmFzBdVvNILjRsyMVuEO8W0jd5rLny4XJ8/Gj/V9moJlIU4HX2Ty1KvV
         t6Aeh9sQA16w1bRYWyqSmWLm0+sG8aQFv+i+eglO1u4FGFFNRFuHvymK6rTqReu24dBd
         7fVg2BziDADJZZ75behb8nRK6nMDRifqUSymPhgX4+FUvqCsiVS5gsCdyeOVOiyTCC3K
         i4NbgM6iIF4pA2rHj3Di2qGpvZSoCDxh3qXWEkgayM+3f5Bc136CQuWWhEkdbhcjAzg7
         H3Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id mm22si266400pjb.3.2021.01.22.06.00.11
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:00:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5DD671595;
	Fri, 22 Jan 2021 06:00:10 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B132B3F66E;
	Fri, 22 Jan 2021 06:00:08 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 3/4] kasan: Add report for async mode
Date: Fri, 22 Jan 2021 13:59:54 +0000
Message-Id: <20210122135955.30237-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122135955.30237-1-vincenzo.frascino@arm.com>
References: <20210122135955.30237-1-vincenzo.frascino@arm.com>
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  2 ++
 mm/kasan/report.c     | 11 +++++++++++
 2 files changed, 13 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb862d1f0e15..b0a1d9dfa85c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
+void kasan_report_async(void);
+
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 234f35a84f19..2fd6845a95e9 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -358,6 +358,17 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags);
 }
 
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous mode enabled: no access details available\n");
+	dump_stack();
+	end_report(&flags);
+}
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122135955.30237-4-vincenzo.frascino%40arm.com.
