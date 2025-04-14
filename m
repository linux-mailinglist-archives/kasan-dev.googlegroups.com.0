Return-Path: <kasan-dev+bncBD4NDKWHQYDRBLML627QMGQEG6DFJKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id A6D55A88EBF
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 00:01:30 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-22650077995sf67541305ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 15:01:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744668089; cv=pass;
        d=google.com; s=arc-20240605;
        b=J6kz2zTxBIXyi9wClWivdOub/NGPasd5tlXrqoH/UzQ61cx3bcyio7BIzW/23tCsv3
         to1TYtkHy3S6f+jDBG4Lq06E2MBR60kP49fV2JQh1G5N0X+kbHhuZrXkpzqbjQMYiOgH
         q6bW4m2hzWhC2q0G4La9VMZP4dZVVUyPShIrmDVskOcHYocwIkJijPpo8iOKoSBeUvl0
         QAm1cNQEG1ATYjEB4SZAl5PhFVhFXvr1/2KdKvoqfLOU+xWXDYwTF0KxQo6MXY7vdTCD
         PburTrz83vyn951C4F10VMVhLqvzBFhhTg8N4JSgPXcaMcS9fO8WyZBRZk4a9/UxuHL5
         C8uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=YZ+2h3KKcEA+1gXomTpTg4piHde6pZq2XpzFWqCltmY=;
        fh=im7gk7X/SjTViFh7f1ZWSgjONkpUSfjODvYmOgzTXhk=;
        b=VoAtQQ+RRL5PI/3voaGUD6y8N9Ci17HLy9gALIBl1/Ebxa3kzImVXYOCRnGG9G1lGe
         dqNqPIMVxP6UOqsfyXDWMWWVCoXYvqLuoEdAFfquq5iHC8rwC6bxJMuOm+FUq9KENmKo
         7/sFIHAmOl/Y3vujIwuNzvbILS02f4roo7/DNOZUAYOFbPo04i1ML41cHJWdQ0nsju65
         LYcRjiiFALMhUk+oOap4ghAOO8q8ACSci5gCEFL77ZbmFddiyzirOLewtXvHzDHs+G/d
         ix9o50D85yWR+lhVGayNHdcygs8pfvjdw85hDbVN4Zm66K/HYZMlkIAglPjtrAi1ihjf
         zasA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="avycfQ4/";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744668089; x=1745272889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YZ+2h3KKcEA+1gXomTpTg4piHde6pZq2XpzFWqCltmY=;
        b=pA4Z0mC0308QghLFGdRn4H292Sr0pv19idq7D2er9oQRyA8nJZ3rXD9fOgAKQQPH7i
         jN5FLj8w9AqzkN9bHoawrSHy3awzkB+OTAusPIEchBgNGAXrjDwO559Qe7pj99LA81s8
         qYNeowdU4exER0GPgkQZP+11FGdz8T59csTAb9/sluGOJeu9+D5hCR79DxFk3krJrAPe
         tFsgVUSRDnD6X5NddpT/usz1JMeV0pRIUaoU/oCkbLDDbqsuc7ow+21ugHKYl1G7ffhg
         gFQzbYDwmdkY6mxd5fZM00i1v+g2khKSSl08P3RBruHKNlK5n5t/NGY8zCMKV+HHVPlP
         pAcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744668089; x=1745272889;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YZ+2h3KKcEA+1gXomTpTg4piHde6pZq2XpzFWqCltmY=;
        b=Um1CF3Xgp83xqW8rogsC03QTM8cSKFxD9yh664evMaE0kKwqTY2z/qRRqGFYO93TK7
         rhWYbNAa0mdMnYZmY8iV9A3MrGbHdq+4QwWp/Jnuo+S8pEfMVUavOBLshAUIfCdD+vcz
         fkHEQqco6DiGlv3pcedvsNU1xLpeUG54HjDaBzwq/B5bSNyxChbzIUqJhYuyQd1iOxHZ
         2zj+wBwEK8uo/Bdpe4Vi+FkF6QCTrzZDWiIQ3CEg7QnfszklwnXgt9G64L1GrqzYoI6C
         N904JoSgD6SfbObJYJs/62K2s/vlssmxKe/o1rdHYStHFgMBNr2iZmocHyZ4hR0Iwctj
         o2fw==
X-Forwarded-Encrypted: i=2; AJvYcCUWFIL9cCI3fyaRo1Dv47WubqaCnA1WKvzK04qsQjskqVod/vUJI4lerxmRSXqYzqKCozEW9w==@lfdr.de
X-Gm-Message-State: AOJu0YzR3N8VUQ7B3WI+iFdNd0hcxewX073CA5WSTxhI7DBbtRbF5EK0
	i2TYjfgaFFnSmvm/o8Yj6HVB9BjWu41vOKgX8s5G3d4XwC1evhRe
X-Google-Smtp-Source: AGHT+IE0ZZVj8Eefz6LiFm5rktzJc8uR45uGFc0zPSxi0Ep+W0ZGwF828/lMMdArcxPWBKZoSO5xwQ==
X-Received: by 2002:a05:6102:5f05:b0:4c5:505a:c1f5 with SMTP id ada2fe7eead31-4c9e505d56emr9692962137.24.1744668077858;
        Mon, 14 Apr 2025 15:01:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIPW+YMATJmM6m/on0cr40ut9XPSX6mSI6VLOEpgBwduQ==
Received: by 2002:a05:6214:2e43:b0:6e8:f69b:bae9 with SMTP id
 6a1803df08f44-6f0e493e935ls12837036d6.0.-pod-prod-03-us; Mon, 14 Apr 2025
 15:01:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDF8h8HdHKRH23DrgHOB9p0rX9Q0IEDbwYore/SY9zaTPV5JLaGGrYfealcIEebF3c6wddHalLEbc=@googlegroups.com
X-Received: by 2002:a05:6214:40d:b0:6ea:d033:284c with SMTP id 6a1803df08f44-6f223221e56mr207771186d6.0.1744668076885;
        Mon, 14 Apr 2025 15:01:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744668076; cv=none;
        d=google.com; s=arc-20240605;
        b=iPLFOiwKRbrgL3TsNvBrUhgGe8Yy5BfOOP5iOgLYvYo6nvZm3mVq7wjgC1zaNYYDI6
         8O0UxU/7p/oV+k/CioMNRIC/qqgQIndyBR0aFsXl/UmM4TnySiyo8AVx6Nc8W6TivBvQ
         B+v9yNMwkh5jc2HXvGfOMjUbw//vImOZQtKB4pmNUqyLz/VKHinr4+3gbgit8AXeVQhM
         EPNg7Rs5iqPqA7THqdg1U7mOiVmKJuSMswouEanjcPsIRZYhirppejBwapixWxIiSKAp
         Vx4rh/alDAr7ExLtv+LhylDgOHk1lbJXtjkzxQO0LnXRGHF91s17KfHu0X6IaW274+cZ
         nuFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=K0rUgNTAWtT24QTgGiWkQRLfY/ETfO5NZ7RWuVTGXh4=;
        fh=saV9n7AK1OhldAK5b4fN6LI7xi5CG5Qg7+tHoANiiXk=;
        b=MWX116b8/wmRnsZR78hbGRF7L4xAYU1k0E56TjPMZWol3JypWt3jsbTAVWTzk+PNuG
         kIkLE159dpz3OhXi4bl5Rq2PgGg7GAAnrF9CkKaSbyh9y0hPA0NdNI6HTC0JcMvmcYEb
         eOD6e9VYVJoxx32pe/AYgKMdbPtv0bxaeeviR9qKfoQNh/rMUIztUWFK9iCWnXtUx6yD
         CQanXtDcmkKsox6n4xY1XDDmdrcbp6vDtaz5WPpllWpjRi4UspMnGjC6uxgsOO8QUDY8
         LOGv/xGus1W+CWpaUMwbrchbkq21NH3v89mvwFurr+pvM+TmsiUkINixp5qQdQfSbO7V
         J0+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="avycfQ4/";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f0de9cc5f1si4392726d6.3.2025.04.14.15.01.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Apr 2025 15:01:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 27DC0A412D4;
	Mon, 14 Apr 2025 21:55:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5EA36C4CEE5;
	Mon, 14 Apr 2025 22:01:14 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Apr 2025 15:00:59 -0700
Subject: [PATCH] lib/Kconfig.ubsan: Remove 'default UBSAN' from
 UBSAN_INTEGER_WRAP
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250414-drop-default-ubsan-integer-wrap-v1-1-392522551d6b@kernel.org>
X-B4-Tracking: v=1; b=H4sIAJqF/WcC/x3NQQrCMBBG4auUWTuQhiroVcRFpvlTByQNk7YKp
 XdvcPlt3tupwhSVHt1Ohk2rzrmhv3Q0vkOewBqbyTt/dUM/cLS5cEQK62fhVWrIrHnBBOOvhcK
 SHOSGJP4u1CrFkPT3Pzxfx3ECt51ZE3EAAAA=
X-Change-ID: 20250414-drop-default-ubsan-integer-wrap-bf0eb6efb29b
To: Kees Cook <kees@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
 stable@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=1816; i=nathan@kernel.org;
 h=from:subject:message-id; bh=1l08P30O+lKCvZ5y1d3ISGQUNkb1SwA1W+kwuLxu/6E=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDOl/W1eWOfmu1DwxweuGvH3/Sf4k3X33El1u672ftf+R6
 henoktLO0pZGMS4GGTFFFmqH6seNzScc5bxxqlJMHNYmUCGMHBxCsBElJgYGeYJHfpSVKezRjLY
 5psHd3usUePBLd6OTZ3hbaoW72cmWDIy7Hz4Penn6vQbBxLDUk+xfPrTVGl7w5jjnt4j/YUhAeq
 tXAA=
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="avycfQ4/";       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

CONFIG_UBSAN_INTEGER_WRAP is 'default UBSAN', which is problematic for a
couple of reasons.

The first is that this sanitizer is under active development on the
compiler side to come up with a solution that is maintainable on the
compiler side and usable on the kernel side. As a result of this, there
are many warnings when the sanitizer is enabled that have no clear path
to resolution yet but users may see them and report them in the meantime.

The second is that this option was renamed from
CONFIG_UBSAN_SIGNED_WRAP, meaning that if a configuration has
CONFIG_UBSAN=y but CONFIG_UBSAN_SIGNED_WRAP=n and it is upgraded via
olddefconfig (common in non-interactive scenarios such as CI),
CONFIG_UBSAN_INTEGER_WRAP will be silently enabled again.

Remove 'default UBSAN' from CONFIG_UBSAN_INTEGER_WRAP until it is ready
for regular usage and testing from a broader community than the folks
actively working on the feature.

Cc: stable@vger.kernel.org
Fixes: 557f8c582a9b ("ubsan: Reintroduce signed overflow sanitizer")
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
 lib/Kconfig.ubsan | 1 -
 1 file changed, 1 deletion(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 4216b3a4ff21..f6ea0c5b5da3 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -118,7 +118,6 @@ config UBSAN_UNREACHABLE
 
 config UBSAN_INTEGER_WRAP
 	bool "Perform checking for integer arithmetic wrap-around"
-	default UBSAN
 	depends on !COMPILE_TEST
 	depends on $(cc-option,-fsanitize-undefined-ignore-overflow-pattern=all)
 	depends on $(cc-option,-fsanitize=signed-integer-overflow)

---
base-commit: 26fe62cc5e8420d5c650d6b86fee061952d348cd
change-id: 20250414-drop-default-ubsan-integer-wrap-bf0eb6efb29b

Best regards,
-- 
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250414-drop-default-ubsan-integer-wrap-v1-1-392522551d6b%40kernel.org.
