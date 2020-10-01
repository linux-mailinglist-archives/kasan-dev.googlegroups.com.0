Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPOE3H5QKGQEZ4I42VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D23A280B18
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:57 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id x6sf29952wmi.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593917; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pa5XWGvnM+4oipHnCSArPchujV1jXTWr16KP1O79+YdndlRFQw6YsZ6Ua8BNX5GhjJ
         BjMmRGdphJkQBoXf+wCUhJwoQaC7i8OWT/ZIY2MZXUc6QrGITL0ashfZyR+Qm0di9915
         ugkSeVilQ7g1Y2uDstS7+iMI3NByHytgwvXJ3YJJ825iFCCBIFNU154PANqyJjTAR/K/
         Ck4T9QqNQqgb0mxw6tJMGZ6rGw0eFQhX4X3N3FebMpaq+7tBE3jrCbeSHn2RaNg74DYG
         aPycc8zP9A221++5CrxyCbodoijxJqAGYQR3twXJTBt9WS/+cQuAgUqhJ98jVO4F2grz
         hunA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UIrfcDZ0f3auTSHNb//QZHPdnqS4dsqiV6epmXJwYGw=;
        b=h7FD/0/9S6GFA7vEqRBQ9eayMZ1TuIvpo84ksxwzs/s6VtUMRmnmgurh2MNF7MxGO6
         ovevKPTqMHnUpVB1IjSLv4qD+lWYhbKRzNVNWYxZB9bcJBc1AKmHjevBXzPKN00UEGAL
         UjEE8w7/3hFrFw6dsMElkLwSg4vvg9/Qd388eyL1Ag44Skixq4224AsTJDM1u+rMFhMY
         DcvuDPRRFctP42BVynKQwWCCC6CuOO5y6cvQ++YXm1g/25z3CKGywxEIRGdT7yLxMg2O
         dc7VNXnesM/D4ijMhpRZ68PCyAgE2ZrDQj01KGu/wai3F/1mREH8zMe/yXjTAFz6frXE
         8h7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pAocIZmC;
       spf=pass (google.com: domain of 3pgj2xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PGJ2XwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UIrfcDZ0f3auTSHNb//QZHPdnqS4dsqiV6epmXJwYGw=;
        b=lrYJdF5ETLANlCnM9UTNuu+jp7J94e/76boozK6BJkzKa7i91JEnXzWAv9+IdIImoW
         ggWodi6C7FjGzzsPYJGMvywVPEghsoTWiplV96BuQFl+GGvSIMSfUYqGTNUgIYSYGYnv
         9cX2ff5JZ+NOagiEfPaZ0q2pnYpaFWft3whgxYEd6UprtzZdx6eko+E6LOTosol4b4r0
         Yjb0TFExpgOy7yD4R1DsySpJGM2thj51hzKLZstR2KNR9pO7jJEufKWziBzLfQT6Fen/
         0jY5+/vT3CRESPOvszpqdd/R3vfsf4WVetEYzsNwrPnRlmVAqxObfVgRVFHtbdLYZiLS
         zBLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UIrfcDZ0f3auTSHNb//QZHPdnqS4dsqiV6epmXJwYGw=;
        b=LJ1cN3/tr1+yBSV9zNaR3HvAr6b0DmtX7xOlXe+uHmyKwzQp/kF7rFS73F2fZt9GxW
         /aQdpZvDbJks1J+c7PLNJObqKxpRo1Vl2Xpu1zjYLT0U+2X2cGeh1gF8H2BZQRM+0c7g
         sFW4KVoyTeByFT4WgGQRpWfAwFuZh932GAc9JESBkfaTpz/DmpYjAURU0r+6/Ui2ItDo
         LOAL5lcnaJMuvWOM4xyahXxwosVAMCOkEE5PLl7ezPSFwWIUjFJ3zm83Mg2YpWwQ9Go6
         WEmwRHDhaLlg3bAGxo+ommfQxuS3ryl05eOG1oyUAhmVitcB2PazMg8N+lIATLRt/QkC
         /ezg==
X-Gm-Message-State: AOAM532+FQkge/JU8Q4osg8zJNs+YzkkMMEpwUKoY/BqonMBIFsrFC2w
	2gtYdQ4E6+Z4fXMw0SPYQkw=
X-Google-Smtp-Source: ABdhPJyve+z8/bocya68J3WT8Y0VJn4tFuMH1zshYhSm02Re8FAHHBkaGITsCMktPeuq/HWUNxdFuA==
X-Received: by 2002:a7b:c182:: with SMTP id y2mr2398853wmi.21.1601593917415;
        Thu, 01 Oct 2020 16:11:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd0a:: with SMTP id a10ls6608458wrm.2.gmail; Thu, 01 Oct
 2020 16:11:56 -0700 (PDT)
X-Received: by 2002:a5d:4448:: with SMTP id x8mr12107581wrr.207.1601593916742;
        Thu, 01 Oct 2020 16:11:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593916; cv=none;
        d=google.com; s=arc-20160816;
        b=FkLfrS7n7tumjQA3mNf7IgPWr0p0voFwl0f8vi8bfVj+qLCXzOvZRFnK8a1Mb94l0H
         jCDjN6X38vpjDurQUKfUSN8MhdOJKhNgkmbKqmF1eqrU1VjR5dYGlxiTH+/xGb5ClQ4p
         BLRqpOoCRTcicfk15oRvBVFpaqrL/AOnnhE+LnUXR9Rn0mgNmPbUTgueOOOPMyHZhiV3
         TKzADEG3FXdNHwxIVHOTICO7barZyOG3kYgxiwuQKb9W8h2w8AExfL6NHVQx/+ji19Cj
         TeGJvvjYcUVSRngQI4qdJmQ8+Lr6/CmMfZBiHCJCQAkn2dY4kw6TXnvG/Vnaok1eJVMh
         1eVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1KLKr1XfEclxqghDKYb7g6gC3yvYfdSQNk9s8vHxzWM=;
        b=MH6ZiFMMhedBLV0p7YrpbeO1sagnP63UFDJz8ja5hXExxWO2WT2MZOw9YsCSgzxeVV
         46qEwjmPbedCCpR05vYV5hyefYg9bufwtnw61Q808aMvrdt+nHObW4Lql0osktKSzRct
         0p3XkymbLDvsr+sqIKYeFQ/mnyvaSEnh2q23q8y5Qb+0MW7Yt2SihvbjH/BBan9ObqGw
         zck53e8wS8ptchkLIlFfUqVorx5IRwXdQnoQ67rxWTbn9oZFLViyUxOrg3o+lY1l9CwV
         6yj/AehE/sj5okf4ihOiUtlQSbQkfZ6TUO+rjJ8uE0BtCDUBDPqy7DVwmDiQ9B5u6+Ea
         UtEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pAocIZmC;
       spf=pass (google.com: domain of 3pgj2xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PGJ2XwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f3si131193wme.3.2020.10.01.16.11.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pgj2xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b2so126434wrs.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:56 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:56cd:: with SMTP id
 m13mr11181249wrw.261.1601593916429; Thu, 01 Oct 2020 16:11:56 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:31 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <bcd566b9e00a28698d12a403f02dc89fcfd03558.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 30/39] arm64: kasan: Enable TBI EL1
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pAocIZmC;       spf=pass
 (google.com: domain of 3pgj2xwokcds7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PGJ2XwoKCds7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) that is
built on top of the Top Byte Ignore (TBI) feature.

Enable in-kernel TBI when CONFIG_KASAN_HW_TAGS is turned on by enabling
the TCR_TBI1 bit in proc.S.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I91944903bc9c9c9044f0d50e74bcd6b9971d21ff
---
 arch/arm64/mm/proc.S | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 6c1a6621d769..7c3304fb15d9 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -46,7 +46,7 @@
 #endif
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1
+#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1 | TCR_TBI1
 #else
 #define TCR_KASAN_HW_FLAGS 0
 #endif
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bcd566b9e00a28698d12a403f02dc89fcfd03558.1601593784.git.andreyknvl%40google.com.
