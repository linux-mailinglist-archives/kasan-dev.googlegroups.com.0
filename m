Return-Path: <kasan-dev+bncBCCJX7VWUANBBAMN437QKGQE4L7JZBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id F2BA52EFEF6
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 11:33:38 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id y2sf8264369pfr.12
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 02:33:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610188417; cv=pass;
        d=google.com; s=arc-20160816;
        b=ilub0AFIVlW3bWgxTQKcsPvN3eBegpdP3+MFbZvc5vFJP53++yBj9seEnMymYvBmIz
         CGutTeGz/wVAiBfXdCwTDnv5nCByH9YwyZTcPQ+udKzMwePTZTbgy3N6oRfR/+cTZqki
         BvpvpKizMb5CjbpfT89RBNLzZq3gO6k3Vlsom0kxXO4VA51vmYawQex0wx5eNTICPlXt
         NBt4VNLqmP3hpn1OegPCiLJODGjR1TCtWBmKxGY2rzY+/9FV9924MHJwjZwVr6Bf+KWE
         X0wy3odoZLX8HS50O07GyTK2oniD+uPuWBXZBOW63ITIH5fiXWvPssC1SGM/41I+AV2Q
         rUHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Pzfz6V5L2y5CFGbJBrIqTSOXVjgBUDCxRMkrDfHlmKc=;
        b=xdyaMEErx8XgMsA2Mz8NTu+YJ100yeKyBBye3ASIjU7PxFeSZDN5x5oVR/t72O7dv3
         evvMbt6rkWkvWcpu0c7F4xVs3F2NXHkDKSbNNpatWRUiEycwBlE3Rz3k734LLGS6Wi9s
         NO73ug5naiTuIh46ew6bxKbox4f2QzjJ0MSu1t1bgYchm3hIKdEz4RADpwG66X35Tqh+
         zo1LonuDhlrnaH+mLXrmGdzSUbrNbOH3FV9dy3qN+BGwj8CD8sU5j2GPIUlcRSdNEfjz
         bKhuiqbTehj96REiJI0s2k08DkCd/t5+brKlFYGFd//e6PuVq1In/8ncTGQWqMATZyVf
         QNbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="AG/rOYoY";
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pzfz6V5L2y5CFGbJBrIqTSOXVjgBUDCxRMkrDfHlmKc=;
        b=c6veocbR8MtI+g0JHUUnFmYJcB8OSrPtNbcJWULKAwmW1k8APQG1D1An3DCiTacJAL
         bphBeCLXIw39qv1ewHpsr+my2gLYdvWhLR9k3UbNr/P4A2pGohK4HgezyQiGkwGR5mlI
         91wvvi6Z7Nd0JJVymdi0xGQ6zP83FXI9ihXyR5gsD78bjIs7HHTcqplZsunm0wmXweUw
         ajhgG4FObx/QjFjhqr6Ma85WlCVNvno5bX6keftvOTHNw4v3mhtdoZUbsog7pcYd+C17
         wzi/oe/FF7LaazNhL0WlrnbuvyQVmIWxPnXEePQOyJgQDVj4ehc4kGV/Ptrl8Sq3+5jL
         ExTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pzfz6V5L2y5CFGbJBrIqTSOXVjgBUDCxRMkrDfHlmKc=;
        b=bNVNF4DEQYpI94gwGak/+yV7h7ezshq9UIb/ykLRxIwWE78O1o/6M0UmoJbHOnLX6Y
         zb50hWOjerhSVPOfbm7Fd+Gt78gyV96+3R/4kvKE3KhCJjs/Wb0S6iog5CzVgHNLsCMk
         sow8LbqqLpWYwa00wpLccViCxLRJFczPqgZ7qGyJALj3weiQcurjAfZVTnZWJUAcaqxr
         QLTZQMVZZdWSDdCDWUH/j7jM6A6+YZkfEXO4p98JCyTGVC088CpQZaGKtESNgPv6fiwj
         JjKwSIQ5SsianZSa1EFCU1Ej7OC2kwgMcV1d7DX8e4xOEyFppf7AAqSe566GuUXHVaWC
         6T3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pzfz6V5L2y5CFGbJBrIqTSOXVjgBUDCxRMkrDfHlmKc=;
        b=ENRS3KDhKnKD3exdHQfAJCritCBPDlnhak40sSh56VPXIbBAOtWD3qcmgBClWDG08b
         nH2hxpn1UCuxkD5UFRRrLqSvk37S0lsZNcHGVXLFPHdgM+QGn8BNgG6prSDaVEcVyUDO
         LTtoNinQVME2CrRK0bcFp/xLL/fK8pii9gGsaPLnY7Tvmtz4h8y+WsCS5tDwaWIjoqwl
         GGNop+THdTvERz/+RuOnraTAyrI8Pt+OfIABChf7VoCRw0X+wCz+N0IH6JyfJd5fiuZC
         m2m6541YI/+ad+dkF3R3/MX6VHOsBILTN47CYdwi+O/XZSQsVY8jy4xf5n6T4nYNnonm
         29GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533b03EWin73w1ma7bMXKAigqFtattSl/a2RWzxPGwIwHnTsA45s
	jhGzcAvcExrh1aH9UzXxm9Y=
X-Google-Smtp-Source: ABdhPJx/zNAlAbWLDNT3wlmKCTz1djK1IkZbQp2OXUdqTFQObIWLkrGJcopHaLQdDTxRQ6YKifEf7A==
X-Received: by 2002:a63:130b:: with SMTP id i11mr10978503pgl.300.1610188417766;
        Sat, 09 Jan 2021 02:33:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:548:: with SMTP id 66ls5992521plf.6.gmail; Sat, 09
 Jan 2021 02:33:37 -0800 (PST)
X-Received: by 2002:a17:90a:d70e:: with SMTP id y14mr8122254pju.9.1610188417238;
        Sat, 09 Jan 2021 02:33:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610188417; cv=none;
        d=google.com; s=arc-20160816;
        b=ow3tp53uBM2BjYVt9yrU/IW5tbgCuoQduBknf+fnntOrz6hDhQUXStm30s+V7Ag1OL
         iDiJDYeINDnYvE5dFdiSI/6LAZ3fPb//xgv6VUMgewTTqidfY6M9A5Ulaj+0D0XNlSO/
         QPv8EWeUSZkK31phA1gu4mx0u8Qhe62yEp6alNjffYKvNunU2X9BnYjMcu7xuggH//kR
         9AGCvWqZaDewvLhV3UV6Nma5AxvOBpZj59AHt0kjSdUrg60Tp9wn7h1aSCkjdapgM0Nx
         kD2ruKzwcM9EB8mt2mS+SxSBwSLjXnWgkKcZAtyyWDZ/ejhtYAdNno+mb2GtnaZv8evf
         HYAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oLn/SnoBrp3vqZ9sozuXKpJ43I84HTjowTO19xhLeG0=;
        b=izpwwYsyr8izD52fIWdRnopC7cIYtmjoTPN4kUgyYIh9WFh/RWAOZAz1dAs4JIXMe2
         oN7/OlxNpo3R1N9eounZbqA+NqhJqKq2xMohr/uXH0V9EdCrZRULVC+Ovq142TNY8jm9
         On9XYOv0BtIerG/V/4Z250Umu4Q/Rk8c1CsNXZ9V1uQZHr3eAf8uSGeZKVySYAchcUR4
         DORSH0l0dwumlgxl0tWFuSmr3Rn60rH0wGnmMaKoq8lYEDmxHdcD5Mu2ZYjMknFdQb5i
         QHb4l0zsiX4i34FZxiXppGc3U3SC0p/DnHrWAgaAcOohOI+yuxQcjqGXCGJjoQPIe2z0
         OPAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="AG/rOYoY";
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id m63si482093pfb.3.2021.01.09.02.33.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Jan 2021 02:33:37 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id w1so6600522pjc.0
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 02:33:37 -0800 (PST)
X-Received: by 2002:a17:902:bb95:b029:dc:e7b:fd6e with SMTP id m21-20020a170902bb95b02900dc0e7bfd6emr11108147pls.12.1610188416663;
        Sat, 09 Jan 2021 02:33:36 -0800 (PST)
Received: from localhost.localdomain (61-230-13-78.dynamic-ip.hinet.net. [61.230.13.78])
        by smtp.gmail.com with ESMTPSA id w200sm11691572pfc.14.2021.01.09.02.33.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Jan 2021 02:33:36 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	ardb@kernel.org,
	andreyknvl@google.com,
	broonie@kernel.org,
	linux@roeck-us.net,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	robin.murphy@arm.com,
	vincenzo.frascino@arm.com,
	gustavoars@kernel.org,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v2 3/4] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
Date: Sat,  9 Jan 2021 18:32:51 +0800
Message-Id: <20210109103252.812517-4-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
References: <20210109103252.812517-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="AG/rOYoY";       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

now we can backed shadow memory in vmalloc area,
thus support KASAN_VMALLOC in KASAN_GENERIC mode.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 05e17351e4f3..ba03820402ee 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -136,6 +136,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109103252.812517-4-lecopzer%40gmail.com.
