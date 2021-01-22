Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBTXLVOAAMGQE6F5LWQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 75CF63007EF
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:57:03 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id u9sf2694288oon.23
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:57:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611331022; cv=pass;
        d=google.com; s=arc-20160816;
        b=AvFgq/O+aTVB/2g19DpvieqDgnSnvtrfPUX/KRprk7gRlgSyRh8EUpnub2eYLOUy83
         zK2W6PofK25bvKhygDNJuGSomMtHrZVPwDN+eRFxJo17CW8lHjCA5741POSQeMr+YK9/
         G2Qw/bjmczJ7+TIkGkCRQNdcaODvGcHZc6Sw06N5AzWGN98Z7oyecIzBNCPy92BdQ+tf
         JQnRRQJSoNW7zEw+uGm5qnJHQZ7aAgWjQXAcKihpfiKC7IC9I9S6nhIZgtcecKUN0xPs
         IPqyXvjYEgCloHU8/5EZ0NELIoxeCG5v8J3y4V/0B1/rIOxk/y7m3XihvaMPH2G0gaCs
         H+rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=V65Ig5GnE+nAyeQy8FPdc/Ob07fVXmHqttGLTpteQg4=;
        b=LkZWnsNyPvSh0MFo4wpywXQUFeE1eNfO1NUxUhcaWAQpQEU3ezZaIUhVfRiYs/GxOF
         UdDLWIYluMT4EERl8Yr2zZJrOJInSva1llUaLhseo4e2XB31ObIvD4unQ2c5UpsagFGS
         zkCCkHc6ytXKF4btf/mQdKDUWy+PylcoW71G+NL6oN1+W4l5UZnABTIBMBIIkzfjB1HZ
         SVEPWAwcrzlJVw9JQpxULKUKKeLK8bQ7yYpaOBn/sz5lSJo2Uv9U4BBaAO2NHL/5X8aL
         3O51RdBJn7PSGKmhzSEX/QPL/hrL9MOlt2G+GMpM8j3qzT5AmqtTougeHdR9Gu/lO+nn
         dRlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V65Ig5GnE+nAyeQy8FPdc/Ob07fVXmHqttGLTpteQg4=;
        b=aByp7N5zWdCJGvOX7v574ri+mDk1LHNxSbfFipDDsFZrsnroW8Q31HdrgCunDctebS
         i9qEVpGhMVinsVsBGzo3BirGucl0XB0OLZNrqCo7u9iIYfzi8lyVw8BlRqYLvLWG3iyJ
         yiDMupVsYKxg8bcrn3xtZmOTG0skL8iVT0zR+zsCUFp0HG4+UKZ5+XJ7YC1icYjK1yX+
         3cfGQx1wTwi9WTRS33mSzqaSgsg0lfTgy8xeJ8F2FR1gQiiZkKlVK7ksCrO2mt3Sxd+a
         fxkmiOAifiNoXj7Ernxz+wTRzffhhAmD+zqG+CFVAlGJGBT1agE0mIToibstvyv7Zv1S
         k/2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V65Ig5GnE+nAyeQy8FPdc/Ob07fVXmHqttGLTpteQg4=;
        b=jtHQaN9wweLQPqZE2lzMG0FUXYbkBjUJd28YybbHWMybnlv46DW4lsIfLBtAn4BS0Q
         hZjhksadSHfl9J+zc+ZiEI4+mTmXVfZ8xPLzzaFl7g2pCuS3JLw14bjK/LKhQ3tAS6sm
         J4CbSHA8lsTAw+4ptqQfdM6rAajGxeJNOt1DdZB0xYdXIN2FGic5p1GLZHLywKbaYF20
         L2HLA87k0E4MDAqdt8AGnLt+T2Z8nsl4bH3cGJxQ5EDvGXpbkYKDN9g9FZQcGWGOCRYf
         5M1SQrZy8HnN3U8fzp/an5N2op4z1ayi3jHPeLEVj4SEwa7HsEc/wv6Jf3U99BEmF7zW
         4xIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hB+PVidIY1UyxtCSOZ7ie15Gymjb7speisp8O0dDHLmuwNFZL
	7SzAAKS2hxvPCernDHeR74c=
X-Google-Smtp-Source: ABdhPJworyPfhiJbyJPtLcOHeDtgvx12+KW98k87Qb9Owlg7joHBnmxdKqw1Mp26zaiicx0NBOkfyw==
X-Received: by 2002:a05:6808:24a:: with SMTP id m10mr1251395oie.95.1611331022532;
        Fri, 22 Jan 2021 07:57:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d755:: with SMTP id o82ls1373543oig.2.gmail; Fri, 22 Jan
 2021 07:57:02 -0800 (PST)
X-Received: by 2002:aca:d644:: with SMTP id n65mr3590559oig.111.1611331022206;
        Fri, 22 Jan 2021 07:57:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611331022; cv=none;
        d=google.com; s=arc-20160816;
        b=Ze2QyCX8shGpQ8DeLxgZkfCdN9dJlFrsUz9Q+9SvPsK4hPOf2lGSqPx6tB9bHcV7nU
         trI4pODr8Io0sRNTZAVUuXyMIhVyyOyH/zac78SjJn0S16LPnOHO/9c8jKtL+P5AlLDS
         Z1XIQIOCcK/CrU5qYUlFPjJA/BuYtsvXiIsPmvz5P/DaSaBcH4rhPzfTr9pMTMcq7imx
         EP5HOvku8qftDtt7i5SFD99kiTXt4a+SooxEOP4mXt7MxclLXBFzvPvw4l02hgVGBo/J
         KLcBnurSrFDteiKOLubuHm9z/l+CTC7RZcnREAemcpqxq+V8wK77iMY+Z/YXeEMBz/Sz
         4IhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WXbqdBna7iODZSaixZkTe06xbUD/80Lb3HWe+rZkpdQ=;
        b=IUv0F/2VIkb4FfRMDBcDCeUQ8kICWk873tCyZD9UeFWK/Ft17d84gLqR7jialvmnf+
         f4LsZuXyTZVUhtPnkZkLGLCi6f8bW27a/8aDSkaSBp5RLBNE1ktBTFuNaMGShsJjdt0Z
         4Om/HXyI1YVP7AiTLO+kLkLQZCHj+HpIAP/nuTH3o4+XHGG4tO1dbgdDNozMFbABcyq1
         OTr4Dp+PuvVTYuBAOx6umNVQA+yU9P/57uddX5JQ85w/BXsQlUBuooPiBa6DSEpocD3e
         5RLJWs8DfCo2kE7wdpj4Q45+QJ4E69No4i85njmW1MWDQ3CBUuVygffAz+m9GMIcsLeb
         SrYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e6si349165oie.2.2021.01.22.07.57.02
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:57:02 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 091181570;
	Fri, 22 Jan 2021 07:57:02 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3F0783F719;
	Fri, 22 Jan 2021 07:57:00 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
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
Subject: [PATCH v4 3/3] kasan: Make addr_has_metadata() return true for valid addresses
Date: Fri, 22 Jan 2021 15:56:42 +0000
Message-Id: <20210122155642.23187-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122155642.23187-1-vincenzo.frascino@arm.com>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
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

Currently, addr_has_metadata() returns true for every address.
An invalid address (e.g. NULL) passed to the function when,
KASAN_HW_TAGS is enabled, leads to a kernel panic.

Make addr_has_metadata() return true for valid addresses only.

Note: KASAN_HW_TAGS support for vmalloc will be added with a future
patch.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/kasan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..8c706e7652f2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 
 static inline bool addr_has_metadata(const void *addr)
 {
-	return true;
+	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122155642.23187-4-vincenzo.frascino%40arm.com.
