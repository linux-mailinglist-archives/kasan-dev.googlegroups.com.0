Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDMC6OWQMGQERHEC76Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 24618846D90
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:47 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dc6dbdcfd39sf3046158276.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869006; cv=pass;
        d=google.com; s=arc-20160816;
        b=Imp4sL+JSTmt2muloGeD2f3K2JzJwzj8HXBMhkO4UdwwD/Sf0KrDpmPgRL/cD9kAxJ
         K+xplBbAc7eEB/F+iSvvV4DXtFAM8XrN2enfIvXG08Juyhs/yqftipVg+0BpV6k7as3j
         xAvc1oI8plNRTmxjSBV35g8VzdA7acd/F+7uDq3+A8R8qN1ItL680jZH9lyrhs8dQPw1
         Qisu15Y1LHhLGdrjCFpBe0682x8V8jyLq+N3x7X+vpI0CIRK+vYC3OLH6dkh1vO7YiLK
         Vjvm9n3FihqylPQYFwln1lEOUYEMfI+RByVLHk09OrxTN/HpTe6iA/lQsQNe6VQgsA77
         t9YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=P2P+aLVoxNrNxkuP7JgqquHqISmA+1v+m/QEIna0pYo=;
        fh=q3Ga648FGXIHtEFq63lTSCLO5p+NzStVMsxM2bN6dPY=;
        b=Okeo6hABeDzkSq7eRzXk/RJGF6JRvMX81ZGlyVaYP5nHaP0k9Y9V2VhFsEfJEfQHB8
         ugEI0ttRbbTme9ZSERLe0xzUCBxv1cbvXqFY9akXNTnt3OYfBXQsq4u9PGEvquEi6Kpl
         KbbGLehJXup+Yx7mBL2nUz08RDpy7pJzra7qwkGN/5RPo+slOp15gO4Xvop2cfCZt6+B
         /Ihb0yOmOye12K9TZq8kAb8PMRNur3FcNiI8U+oqo2UaYOL7J/nWQj9BFAs1+6vhHTFa
         kPkeKHY3yLKrJDGgRTc9VI6eEOoiQQWrWt1ckIJKQpNigoVXbZOuS0khNyOU6TzLTQr1
         r+Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iOK+Cg12;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869006; x=1707473806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P2P+aLVoxNrNxkuP7JgqquHqISmA+1v+m/QEIna0pYo=;
        b=AH5OBsQQmO9kR4agI6bs9p33sImGmIhnG2L4a/7i7J7nYlvbuXMb1CMjw/ebjswVox
         lvZIX8acmxHOB7bzq3Ce8XyDXoFbKBA6MO5CE5FzVH70+fiHg04d9KMM8wi7t97eKJYQ
         UtJhKChbI6A8ScpftcN5LezVU3YcVR/ikxU371fEJ7nm3VZkREhEQXFd9iyQ/cysBEds
         qSxKAvaaC4wYHk+jqIUOW/nTqcbIqpDP7HYMnVatqay+scUOKk0yM61KWCQ2Cp855Zcn
         1/hnFrZjlq2JgRBUkcVYfIsVFf2g0P/XBWsVc8dvREGPQgxICslRyMUucGmIQrii44sR
         0rSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869006; x=1707473806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P2P+aLVoxNrNxkuP7JgqquHqISmA+1v+m/QEIna0pYo=;
        b=nz+z1LK22wUmkFm4fUoV+KqZa+V3NVbSNBawmYfoyyVyQ0hntTjQwgo+cILQr17i5Y
         d+XGqYQK2BlSe3OjYHZwhbSpyvcAJeuSuvQ9bKRvZP5HLGaRT/odNEkrMj1LWpBuf2xy
         eM7Tlkz0LGo7a5ZvZSEljOFq6v3jT/LzHHSRUSAUYsr7nYkXPiJmpd7pzCPVSSMEigb4
         y64UtbO29aELRut6YI7rYD/K0oWhKchJN8+LePlqmKZvnobynyrJv+OL+x0fVmxwMBqL
         Ui/35c8IWQPZAHtTlw9AqwhSSl1NcluNhk2B2PhMMxiZ6/eUHX8SmotcO13K4DL31NWG
         zPGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy8Vjpwc/rc9pHY7Dmq+zjE/4Lq3Eu7g7bXrZdVtsLTajXwCnT+
	PSdiHzgdYQcUsro63xvcvCjeDxoKVKZnpS+xyWI1CP/J8CWBkPhM
X-Google-Smtp-Source: AGHT+IGNynCNz5iMDzlvnuAKTPZoXLQ2U4cpLNtf6c790Sq3kklmlmdUsVcdMZc1pzVByArP5OGewg==
X-Received: by 2002:a25:ac5e:0:b0:dc6:4b37:e95 with SMTP id r30-20020a25ac5e000000b00dc64b370e95mr1709094ybd.26.1706869006011;
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d0d8:0:b0:dc2:65e1:72bf with SMTP id h207-20020a25d0d8000000b00dc265e172bfls88329ybg.1.-pod-prod-05-us;
 Fri, 02 Feb 2024 02:16:45 -0800 (PST)
X-Received: by 2002:a25:8481:0:b0:dc6:bcb3:5d8e with SMTP id v1-20020a258481000000b00dc6bcb35d8emr1619193ybk.20.1706869005271;
        Fri, 02 Feb 2024 02:16:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869005; cv=none;
        d=google.com; s=arc-20160816;
        b=SSFpnL+xUwxRArYhxYj33MNYErDyfRGylbYMV5X8wKU2Os/8MVb5B0IyslkAJTHaOg
         fcmKfP7viyuovS3X1ezCrO+BiqSwlWKcvOsBv9mAIscunNgzb8i8pzBoRpQVn1noP9Hc
         Gx2GEvm1OLNVfWFovaR+JRaWu09ShJNT6q3fXJjzLhCOYUR9gptwt8P5gWsErbMth2hx
         Ya0A+u4iCLqSyzHbVY4+XXtFtpznxW22GP5wQfpcqButYPEl+R9rYgrzrrtI2Wl7OfaC
         uD8SApFVtUl3qpLtz6RB7vjpX3dU4Q93rtg3/DVJMGoRQlyCQ3ljrMcTCaCx3F4+WZgU
         CwEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=huDkFM2jKbuwvr+cQsGrJ0cboThbc1r4eSZ54RE7EeI=;
        fh=q3Ga648FGXIHtEFq63lTSCLO5p+NzStVMsxM2bN6dPY=;
        b=hH1OSL9TNCaz+iGFzgO49EaZ+DxoaX4K+fdQCtSM04wDTwbNAm2oiGwunJrBw498Wz
         2yrwyrONSj7FawH7SsBwvNtvd46yidlXb32s0Sbp5o1yGr2rmCAvCTtZT+hMcoE6aiFV
         kBfN/BrEuPS4RMSPO6ZODW3uzFfi0U+Me5ZjEdyHmhWNMAJ6HeTrU0KdQhadKqWr3g4K
         dTWRNvrArEfuBHNEStjvCqXUe+qcVNIFv2Tz3RlWpHPr0UOxq93nAIKZni9jcuDbmkPO
         dvvsc1f6ctim/y5Q9hwiYOpTkDILNg8eCZIWE1N7ODRiJQoy8pM/3kF4nxTPMk5XPLvm
         eLgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iOK+Cg12;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCU6uwlnwJjxKKS46iKWByS1f5D39g0p4Km3LmmG5pzCjBGdlyLWtpeTuHJeTsD3WKKdLwe6eRlLevKqx3cHTCwnJcA/ide/pyX0AQ==
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id d10-20020a25360a000000b00dc657e7de95si161023yba.0.2024.02.02.02.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:45 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1d95d67ff45so9813155ad.2
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:45 -0800 (PST)
X-Received: by 2002:a17:903:94d:b0:1d8:b6c8:d9e0 with SMTP id ma13-20020a170903094d00b001d8b6c8d9e0mr1942830plb.68.1706869004906;
        Fri, 02 Feb 2024 02:16:44 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCXm2ltGXSQ3/dMDFTJd44WjKZdXshEPXPWN2y6WE7E3b+jubgNaOYkuw5VnqA4S9HtLo7qrYKsGKPoYxH5O74AVwvWb9iE10rFYm3n026lPQhoITT6P5EG3S6E0ARfoiPiilFHc1P170f3L7IIRjKqdWIGevmKqtcYBEq7HSe5RdITj0U96a6pTvHsJ0MsK89PKSs0ECjcxeR0yzhKvgzBGQqSm8nHFrtSeBcJzXXMaebLLOFOmheGxxf2ic7AR58qnNPxprUyVeY6wzFzi0cNWRnRpzjgIFyrNRmmyNKPD3NRk/rVYnE+xKRRmrDd7B9gCDwG/+ve4xCBvu8plPkZxiwuj9XZhaBIbvySbpOS8aXTc+kkoQ0Qr2U1llnNgaFQ1nY7H3f/ojjTTW/r7ggMMWTwS5GebQqKR5ZQk4UXJjEiv18IkKd03pIO+QQHhwRvi75ST2re8QSg/NZZvCu22i34f/ZfVkuhFBAKeP0EdJTIi3pDLw2DCTd0qk2OzZQ3esIyeHUi4SbRQEhDRzSl/EdxhSOD37RLyKKeZsvcQw/KOdAqAawSDSPy0Zwzh0G32VHyd7skIHFuGmVRga32CpsILSaLLA4ITFo88rafydugjzXu00x+4wzcP6wX8+lbazQTj
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id jv5-20020a170903058500b001d8fb2591a6sm1262459plb.171.2024.02.02.02.16.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:16:42 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Fangrui Song <maskray@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org,
	linux-doc@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 1/6] ubsan: Use Clang's -fsanitize-trap=undefined option
Date: Fri,  2 Feb 2024 02:16:34 -0800
Message-Id: <20240202101642.156588-1-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240202101311.it.893-kees@kernel.org>
References: <20240202101311.it.893-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1455; i=keescook@chromium.org;
 h=from:subject; bh=ZxwmE0nZsP1Nk3oxW4DdUpU7gFnVfTpHfJ1XVp+L1j0=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEHvUSDUiKlA+mbRPre0Ef3vI3/FZn+MH1H0
 nTpBmdXXdWJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBwAKCRCJcvTf3G3A
 JpS9D/0Q6QBoQC8jBK/SWwnCyPlA7roqa2Ww1Yr5HWnO8NGYyqLoAR/MLiePscunq9kQo7XF14S
 P8vBlWa3w59PmmPOE6/K+Yo4XhNmZJHNn57MFcpldH9PXBny2KEOQhIlpz0+Qq7zhOLddFXdahg
 miGo2qdGlfIpjGAwlRLZVr4XDKEdKus3gLReWRkeV1eaUGK+SU4BE0S9e5Ucv2MjqDKeYkX5U8P
 qcJlKCdupyTdD22vLQjZ4hg0UIOxJJ0JvKAgP5koezT5XzlYxQPfD+lFdixQeprPlZX44YEoD1u
 2gFGFM/Q8utBzYdgJDHKWh8ZFe9OdEKUCuYvCh/uj3WvrNcdeiAwxXTFx+YFw7lp/nUQ9zNbifH
 i0lKwy9Brl+6w2SYcs69qdsxG5hhti2yLUQW5qr1cxQetC9HV+eqLTMxbCd+Gm8bec7x5A7gPkl
 z9qKNMgq9aRbauhd0kdkjl+d6TuQcysN/udCqYNxsTkdS7yBgm/IdQ7OZjnlsgDA30jgME0SH/I
 ACfSg1lLhSUiA5YoWC7kX0F96o0tirE4vqzxv/Puh7Cw53eqsLhs+IiSDSXdodWu7vsBW7YDlsh
 iWO7s+1g4L7hMvsHJrbpcnHePzJ54JOQLt5okcZPy+IE+zSi6oA38qRXNbFz3mjkKY40YEX37q4 8g1LnhWR9uKDhnA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=iOK+Cg12;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Clang changed the way it enables UBSan trapping mode. Update the Makefile
logic to discover it.

Suggested-by: Fangrui Song <maskray@google.com>
Link: https://lore.kernel.org/lkml/CAFP8O3JivZh+AAV7N90Nk7U2BHRNST6MRP0zHtfQ-Vj0m4+pDA@mail.gmail.com/
Reviewed-by: Fangrui Song <maskray@google.com>
Reviewed-by: Justin Stitt <justinstitt@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Bill Wendling <morbo@google.com>
Cc: linux-kbuild@vger.kernel.org
Cc: llvm@lists.linux.dev
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 scripts/Makefile.ubsan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 4749865c1b2c..7cf42231042b 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -10,6 +10,6 @@ ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
 ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
 ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
 ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
-ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= -fsanitize-undefined-trap-on-error
+ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
 
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101642.156588-1-keescook%40chromium.org.
