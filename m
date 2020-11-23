Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSVQ6D6QKGQEOMCVBNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E96102C156E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:07 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id 185sf8021764pfw.18
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162506; cv=pass;
        d=google.com; s=arc-20160816;
        b=RO0YhrjzSudbcozPcXgwIqs6PKVICHbaoyc+150x7KJwVZNnyxsDojl7o/ubejdYEO
         A2oPjeWp3/OMb2XSAkVtK1S5HqwxaigornfsYG8o/dR8ILVPs0Te40GqxkagzDAp2Kdl
         wnX9zi98uDH3eSp+vFX3Rwdxbl2TZMqWuGckxPK7gmwu6RDfrjVhQTBUiULRDDtQZgQW
         E37YMpvTHfq9fIasUxOtMj941ZiwpY5JLZ7PHhX30Heu8C2sRIjD/GCbC4eo5O5ridmi
         HMxTJBnifZXbcwYYQoZL1W53W+w+eozm7FUgBUQTuiTnT7WgZ0uWT8X8kzK5KvQFyx4z
         sBpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qqerlZbvkhLoxzuChdSxQIYhuQJm/wfAfrfAmeTXyWo=;
        b=LiyNinrNNIc+KddWBU+u/bwWW9FYhobOfqXFlalsKEQfgFUyABXPO+xu5raloApHwO
         j0GDIEgYJEhqTIc3lL3iW/lkucuay618N4oX8KQe1v+qaQg4WKrbvwancPf6KUtOvkJW
         cBkK4btdrWU34Pde0e+7sLS2kvzfvkaVL+lWP6vRTcDKv4fetX5ZVeQoygBzpIDGHM+0
         Cy4iQnHKnHrkFUjGhpDvfmdwuudyLyCj5f51j/mCl8xv7WJiuWJCby9wJd1uvIS//u8y
         P7544Nwux53B6J+JF/aLv6NQyCdz7ms7omg2O5fr2GdeMzeA0vyuAQ0VCSpoXkzda9le
         +Zsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ftOluYgs;
       spf=pass (google.com: domain of 3sri8xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3SRi8XwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qqerlZbvkhLoxzuChdSxQIYhuQJm/wfAfrfAmeTXyWo=;
        b=Aw8rZIrtBKAGwSNGVNCb4jHougMJ5iCnUDBLhQtmmfi0/AXbqDbsjvaitle5+2rxfI
         BH+imv6TQVSja7Wy6/an5h0X0S+kszjA00oxPM+QBm2RJPuTWR+K07csgAESMg0rgvDo
         wZ5TQObzbCEdyHhrkiGDLkXnU4qPFLerluds1Crt9vYGYMPmwVTScQYyH1kt3lC0/VEk
         CEVcV7zpmxDnQWaMi+ozwoGOgpOo1UgXclYZpkdzQPCrkIoCuX2rWL/Mfs15ohTLfn/z
         yZGXM3bkquGr91ImGcuyltbKpEpzmvM/bblf6uZCDhK/vcQE+YaU8qrrNC1QgkWU/WCo
         TMQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qqerlZbvkhLoxzuChdSxQIYhuQJm/wfAfrfAmeTXyWo=;
        b=WZZCjbUg9ILa2i6oiSU4f6QVRMS2v7aJVmAqEWX23KVpIctlUPjB+edQo5dnmI8yqW
         Y8c6rPbu5xyo5mw0CrK6giMDKLCfVzSSS6qSnSiRHqf/gEgAAVkzQk4ZCoEBDJrri0yL
         /Ca39lscYP20o2w8OsE9c4iV8EAvoAc3JbCrwItAjcxwxUrPZGD0l8xuBtCwybv5RpnV
         17WlQam1hSCwO/gnPDwuk1kJWnfRKAI8uD+bC8xmB4MV8wHmcHhXLpwKvRMZ2TBloFTE
         fhUVNiDOR7bRaJQt5wl+qS48TMDDRuO7x6uoYyp4P88irAIAQcXeRHFlbYQGIlvngqak
         QxYA==
X-Gm-Message-State: AOAM53103wkYo9gb3wgsTizei59bXfh2G5FBV3ZxViP6v4BqCnK1+vn7
	w+fMXviHnz31zKUkoLNKe3g=
X-Google-Smtp-Source: ABdhPJxq80m33mXqU+bSiRj7oS1jfXCxBf7QJvtRmJs6PNAhQbvI9a8Wrjtc+tpj/U0O1iEBVDQisA==
X-Received: by 2002:a65:6a13:: with SMTP id m19mr1001619pgu.260.1606162506575;
        Mon, 23 Nov 2020 12:15:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:881:: with SMTP id q1ls5446189pfj.4.gmail; Mon, 23
 Nov 2020 12:15:06 -0800 (PST)
X-Received: by 2002:a63:658:: with SMTP id 85mr963031pgg.315.1606162506053;
        Mon, 23 Nov 2020 12:15:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162506; cv=none;
        d=google.com; s=arc-20160816;
        b=dsv4kMGJkES1C1qrNRki/Je4d12U3LKpt6B5F+bifpCkSCzbuUEv8o7dMQQayFNlq2
         NsnUOh3D3cP5deD3lwWBAHFmdKYyc/ma9tVY30FemtGL6QXkuJK5VxEkadNT3pP6mF15
         pjz0trigwNm6N3TotwwKP3saI6b+juGoMdHl385zwpWUQMgkuDCT55Wod8LE10B6BZN5
         T1JXepKtmW1e4WIE5EZYstbwxik0jmkvLKm7iTT3sd65vdTnTWdLoJGjVbkt7vA1L2ZZ
         03d51gnEVIMeQUFKmJfUWKlEE1SOYDYg99rjM5wINGkV/2fm5ZNoh7wrF4pGYIB+pOC7
         zZMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=01BW1GkidBPog12oysmILVzISd/+h9nT3tAZwCe3eCQ=;
        b=JBkSTAjxvaDtcsHkplcuBwYiPaE9fyV/plznNh1PV97PhrR/Z4+1yZd9j+V5BKl6bR
         uygCTDqLcVv3ZRdGJ8VtpPQMpxObhPZqBTHhcqOJY3uFO8cUY6RYYc99KZomGrQ2Mhmu
         gYXZnNvUG9d+cJo4eyK4+ipT0fCcfoiO3UteyI/YsPCGP/50jH09fwR9kzh3k7CtT3C5
         9HPbpn5usqR04fubY/FaF1ayM4fNzmOu/WZEKkVbpVUwVdGkkPG6tMfTNITPm14ebiZ4
         uDq14pJzMDz/ii5Dc8RRHwc/8sYTeFC1/T0vl0HlLpP5cO/AV8zwCuOzit3FEC9y/Zfm
         3TWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ftOluYgs;
       spf=pass (google.com: domain of 3sri8xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3SRi8XwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id i22si87340pjx.1.2020.11.23.12.15.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sri8xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id x85so15559774qka.14
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:06 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:804a:: with SMTP id
 68mr1169751qva.1.1606162505149; Mon, 23 Nov 2020 12:15:05 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:35 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <ecdb2a1658ebd88eb276dee2493518ac0e82de41.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 05/19] kasan: allow VMAP_STACK for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ftOluYgs;       spf=pass
 (google.com: domain of 3sri8xwokcw4mzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3SRi8XwoKCW4MZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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

Even though hardware tag-based mode currently doesn't support checking
vmalloc allocations, it doesn't use shadow memory and works with
VMAP_STACK as is. Change VMAP_STACK definition accordingly.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
---
 arch/Kconfig | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 762096e4ec16..6092102b29e9 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -955,16 +955,16 @@ config VMAP_STACK
 	default y
 	bool "Use a virtually-mapped stack"
 	depends on HAVE_ARCH_VMAP_STACK
-	depends on !KASAN || KASAN_VMALLOC
+	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
 	help
 	  Enable this if you want the use virtually-mapped kernel stacks
 	  with guard pages.  This causes kernel stack overflows to be
 	  caught immediately rather than causing difficult-to-diagnose
 	  corruption.
 
-	  To use this with KASAN, the architecture must support backing
-	  virtual mappings with real shadow memory, and KASAN_VMALLOC must
-	  be enabled.
+	  To use this with software KASAN modes, the architecture must support
+	  backing virtual mappings with real shadow memory, and KASAN_VMALLOC
+	  must be enabled.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ecdb2a1658ebd88eb276dee2493518ac0e82de41.1606162397.git.andreyknvl%40google.com.
