Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCFU4GAAMGQEQRFBO4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D52C30B0A5
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:44:10 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id f5sf11406970qtf.15
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:44:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208648; cv=pass;
        d=google.com; s=arc-20160816;
        b=cO46soUuFUs7wYdIJqkXV/R56hFSRMsSkSpXeS655UsndqQh8rIMQwi+dhnw9muMc0
         Mq2Yd64Ij8R62By0q6l2ASI4ASMklGbP7mZMMbXu+aGo4UcAIXSMafixYENNYpUORFJL
         3KDCuhP4grBrNlGVoi1g8+2eSGcVPRGIrbvCQ3/aCDjMmDadkvSSmKHoMXl5f2BjlA5K
         jL0MiiiI7kKPtcKCwD3m7hc8RObal/jj/BzFVEoHx8qbEaxOz2cwz/7J7mmcN9i6kkqz
         /PWoqmyy/FlTx508J5F54hZCcB20BwxkSpKgnfU/9H15HVD620wgG4rQDHypDsKotow8
         L5dQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Q0mlt3wJKF9n8TmX7gUyiM3hL+eLjOJR+23Sg+GI88Q=;
        b=BT2YND0WcYH/63O2oatEGfHMF3sdkDYMaWHyVj6wrvvBtAqBy4pjPL7Nt19UAJg1R9
         Adocwu3NfcOB4/NO3zIgzbRv3FcAfTh154sJqzPNfdkYZZYHnzkbZXFmR0X0XCp+uP6f
         qXc9ZkpGtW16+gp0kQtrKx2X4TZ0JGSAOTZvItCOWXjMNQJ6xb8b4B//DAXbOmCRnMZV
         0EFqfwNi7d7dzlTJKmNn67ODUO6Bt5XtCn4c6hCn5jE8THdrK44bz18YxWm9GuVDMW51
         NHXVcWYNGEml6P7C0hpceWD68TER8aEYI5HPmuwOKbAE+VijO2beC0oLq+YN7OsZf9YA
         gMlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=scCt97wj;
       spf=pass (google.com: domain of 3cfoyyaokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3CFoYYAoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q0mlt3wJKF9n8TmX7gUyiM3hL+eLjOJR+23Sg+GI88Q=;
        b=c+pbEh9NQIm8DyJuMaEQgY5wsa/eI1wJlMA0GB2DO86zua7YgdcAoMedbU4/i7Jl/9
         zV2r0KJ0PJ3yo3mZ49OOAcJWSVd2wl2QAkUucaYQ2bMWCz4/HaJulhVXiYI8to1LkG5B
         H+8/Rip90E06ac45ZA6vg2OIlHgOdMZcz1YNx/RuDEPZvWuLwhiYsrRvwZLn4z095yVx
         4wOiJQuA8o59nW3nOZqH2N/kp885HVD1SMfAg6K7ab+CFRywXcYoXg5vnRMJR9OI+SiW
         O446FuCcIdC4JEg1Qu4wXnbjcljdvP5Mlduu5AwAMgUvd6PHq2nPt8SY661OrexlbKQI
         pvPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q0mlt3wJKF9n8TmX7gUyiM3hL+eLjOJR+23Sg+GI88Q=;
        b=VHaYlHUJzYs6RTWM/LsI4lGQBVMoYIw5qPPjOhRLE3QqcNm0bBfMQStiyQqypdG/99
         S4sMqpECzXY7dVvRCH2SEXu8dGnXW5VrXC5u7JTdS1E3sJOd0aYGfF6yd9PqGV/HQ0ZU
         VefdfoWFolZUnfI4kq6euj8YAQK5LC9mxhg8dF5Az/nbrKkWzVzm8fqVZddms5XbB6rc
         bmVTLZPSkHBmvyEItbgBZJjo++P04W1H4lkxIQa+3OIpsX6V9eOE9q/OpB1TQVX9QKP2
         jWTu2zniwdQY63twoK3+JTh40Wx0Z/TYIfi0liEEIjZ54wIQ6bIIWjrrGuXCzJwpYFkT
         IjMA==
X-Gm-Message-State: AOAM532JHHDahsM11lNh9WO644exJ5ZBwQPm0SBzXll3Y9lRCEfItRdS
	gJCIihnfx4JLGDnSkoAYbsE=
X-Google-Smtp-Source: ABdhPJxFG+ij37nYJkigh2QYX6+uB4q61C3sC5mwfbNFIavCh5y03CLkn9rmWWW6307cUOpokH9O4g==
X-Received: by 2002:a37:cd5:: with SMTP id 204mr17222830qkm.410.1612208648713;
        Mon, 01 Feb 2021 11:44:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a404:: with SMTP id n4ls3730683qke.7.gmail; Mon, 01 Feb
 2021 11:44:08 -0800 (PST)
X-Received: by 2002:ae9:dc87:: with SMTP id q129mr18128752qkf.297.1612208648387;
        Mon, 01 Feb 2021 11:44:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208648; cv=none;
        d=google.com; s=arc-20160816;
        b=N1aLB6DESonPgryOXbdDaPiiJodiIYrnvLdDc274x/HNAgWa7rHZBjUEjiRadhNbY+
         ohfyKp6d1gUJswndEGDxwVPjHkyvjizK325ZzuT1cD34LBwFRPU7ezo+0GfB7TF0otpy
         cNge1dQjFuUFwB4o7mAXii7GmmkAp5NrCgSeG2h1NJUG6UmI1xtRcZEeYOFRaSay9L7X
         /fcMMqttaz+0cPbNE2k78obqK9s2v7x7JADsSROlAi1CxScHTJlVkCYZRs7BWZH3Ablu
         VN7vhq0pMV5qy3jjqp89eIYQ3VKR5qjT+MzcLcZo1TmJZy2r2uIIL3B3KCDgdjX46mGw
         KCBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=9ElhXeWA9hrtQUSa92BHDv89rLolOBWVaEOaHObQHiY=;
        b=jHHpZI2OOmIB2FuXFUjwLIEovqxRL1xmoY9y/xAtwGTO2g9+Gt04KpxKQEUo/izzDd
         CLe/QoCeqv8I0ZQvFxN5z/VGkuOKTy8/adj/jcazcHbPijZS+F/dmo42NIz6o/tG2LV3
         xvFKaKml4+8dAHqn4e1j1aUFf3QiMSd+0kZVyJHZUTnUGp/gmf1W4dZFopzP+F4TwEyY
         mNh6e/Qp5aI0D/KetlmQipDyfF0J9K1FUGislgQ/r4AdHwm4VQ9dsQC/OmfjxlvZqF1x
         IsA/Hrpcf3OCiLGioGxJWtv1oynrQtEETIDAx8uolISHdl5DWdi3hG03QybXXmo664ju
         1aJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=scCt97wj;
       spf=pass (google.com: domain of 3cfoyyaokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3CFoYYAoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id z14si1468125qtv.0.2021.02.01.11.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:44:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cfoyyaokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id b1so12017058qvk.17
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:44:08 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:11ab:: with SMTP id
 u11mr16841497qvv.17.1612208648056; Mon, 01 Feb 2021 11:44:08 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:36 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 12/12] arm64: kasan: export MTE symbols for KASAN tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=scCt97wj;       spf=pass
 (google.com: domain of 3cfoyyaokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3CFoYYAoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

Export mte_enable_kernel() and mte_set_report_once() to fix:

ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/mte.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 8b27b70e1aac..2c91bd288ea4 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -120,6 +120,7 @@ void mte_enable_kernel_sync(void)
 {
 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
 }
+EXPORT_SYMBOL(mte_enable_kernel_sync);
 
 void mte_enable_kernel_async(void)
 {
@@ -130,6 +131,7 @@ void mte_set_report_once(bool state)
 {
 	WRITE_ONCE(report_fault_once, state);
 }
+EXPORT_SYMBOL(mte_set_report_once);
 
 bool mte_report_once(void)
 {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d128216d3b0aea0b4178e11978f5dd3e8dbeb590.1612208222.git.andreyknvl%40google.com.
