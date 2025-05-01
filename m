Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD5AZ7AAMGQEDRTF2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0306AAA643C
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 21:48:33 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-603fd09171csf992257eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 12:48:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746128911; cv=pass;
        d=google.com; s=arc-20240605;
        b=iY8VgZNZLFA1mADfgsLgDXRMZ13sTOwkIj6C3cDAd2OmKXRR2FWA4jkxaJ8h0mD068
         u7pA6RuVBMt6cvCPM99h81KlTqtcoOlM2v1rinAjGtNlwXXbye4/giQI/jvZ/YSrSuWv
         l3fL4FlooELj71aQJYkL5hD1n6h6dEP6Nlok2rGC0nxS00k8g+TvJh2viQF/+QSbHIq5
         T45yFzvXPUlls62kCp82Zy1THxXEo11G433ErHiRm37FwoUszAkkx8Nfn1qtrtBlp65B
         hyZp1Q4lDrRSmLaexOO+ElVMp7HQd6IkTtIP0Wpp/XG78bGM64ikYpbKcBK1GUIL50tW
         qryg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1Wtqe5ZQL8lyheAntcCjQvrHJqtjJIwMN7ndALIgDYE=;
        fh=HyHVDGx9rt2Yz4mPk5HDiC20WfnB5RTXBF1ySp5q/Ow=;
        b=Ddkjj59v3bjgHer/suwA4RVceUTvLINYTc+YOtNlfxVOqSdnKsTpylIMT0zBr+JHwZ
         TdmMB/E2Ff3bVKw+QIyR8QRst7FBPJLa/rMksfTc0FvkTn3gYt+XIrjMnIxFTC5O2Xnl
         30OVNZ/4UKvx3DGB6ctEu0fK6SSVhYNJRdRRCI/RZPf5FTsYm9nPaTAiFHI1YRx0HbA3
         hI0FXrGE5ApvodURqgcbbCNvNgx2wE5bDr/Oj3E+a0/jSm7EEeqHGPRfVXqjI4sv31Jr
         0UnyuvSeLzYD2x8dqYdXHUEcQbQ3RsKBxMBzg7qMeKVq1S8a0wK/X4LiuOpMuAAimVUX
         aDCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iEZ0cBDP;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746128911; x=1746733711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1Wtqe5ZQL8lyheAntcCjQvrHJqtjJIwMN7ndALIgDYE=;
        b=o2+Ei5HO+yWrtej90ZPoGeyxzAIUewRRCbz7GMHNJ900AwAXrVpvetrfNdi6dNW7Ym
         ykJSykJBCX9K0ir455JvUTO4IXltZ/FAEghbZ2uPTzonZLo2XFtq6SJoMsFM3yIl6rJr
         B5bWtl/sgBLlmPXnj1ji33yYFUDafijSDFndTFWfrQuriotG6g1ZD/Ix3KewBk5ckDhQ
         GaSkDOicN3/JSdPkazcGoljac2Wlm9nUHEUcSvc8YlbexM3KBCLLthVJoorJROWyUonB
         ki92FbAzi3iinY9YIDIrrtB1JjWDzwOAzo/Dp2S/LOQFmkNOz8HkYh5b7FYDW5jsH6Nq
         5LDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746128911; x=1746733711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Wtqe5ZQL8lyheAntcCjQvrHJqtjJIwMN7ndALIgDYE=;
        b=EJNFjGQ5T4DFVyjSdx7oTnh19KvrtuE2cPStpkQu3q1tY8znmsvgiS3OHlrdezHq8X
         ucEq0PsRYIYfm9tZKYCIccCbF4eBFy5n3HkMqKjIR2eWch7XlxJ/jEwMI+gKBqPiuMfI
         1tBGUjVwThUL3GrT3x2Lw/Hf5ukSFWzdzq5bbhb9SUBIxzYcvM/JYp7xVz1SLN+dY4Hp
         Q1b2oBvhRth7nIe/k4AqzN8JPnc4w8m9S+g6ZdsLh9pRNJGBZ2AkirEvWuyk1KTAvuPj
         uuNWc1iHXR1Ep2oGvH4Z0QvMZGLUdDj4ITkBo+FwovB0ct6TV06tfLRckKr5W+j9q1D5
         fofw==
X-Forwarded-Encrypted: i=2; AJvYcCUJSHb3M3QptqrsD04tbmutx1M7Z57q6sSjXcAGsZmVVIuDx8sjljVz0yZoYNQk6gqAkJZY1Q==@lfdr.de
X-Gm-Message-State: AOJu0YzT0YhljIbmKS6gfkGCzx26D3aZrC20rL02UiiAIAAxXsPAWaKV
	yycbLzCN7zAMrhXf4hquunBliuN060cePfG/1Hw/mKsfGWrN68wi
X-Google-Smtp-Source: AGHT+IGTAWPG37TJEqDDzHyVyazqjY9gc6M/p6oiA29oWcHSN2Tjbd2+fIONg6ml8t1lrBufHE2C1Q==
X-Received: by 2002:a05:6820:8118:b0:604:229:7c08 with SMTP id 006d021491bc7-607ee6c332cmr124045eaf.2.1746128911352;
        Thu, 01 May 2025 12:48:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG8jfpcej27IJbo+fTQaCCNrfbPmiiKsB6m6xvADCM7IQ==
Received: by 2002:a4a:df04:0:b0:602:2643:a008 with SMTP id 006d021491bc7-607def4a44cls317485eaf.2.-pod-prod-05-us;
 Thu, 01 May 2025 12:48:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwpQGRlUrOzkFHHVy6/q31oUKPQMHwaNih5HXPXaSUs+h3NsiYpG7pymI+jpbgiekHplLCJopHwic=@googlegroups.com
X-Received: by 2002:a05:6830:6083:b0:72b:9f17:1da0 with SMTP id 46e09a7af769-731da136d70mr119279a34.7.1746128910398;
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746128910; cv=none;
        d=google.com; s=arc-20240605;
        b=UmOrmQTMk7b9yc1xu0MkLgwtGUke95f3BgBvgv10X6fZEhrNec7ITVPnTK9WfWFMNu
         oBHn6FNhKn1yBIG/NCGCJ22pVsY8xVN0/Q/QaHpxUZmnn2WUv3j25n1SgFRxHZQZLbE6
         C38r8DmcgxNUCzICPsCSvY01Hi+5z7rmGNFgmtekTsz4NNYeKghrtD/tVEVqmsd5spgb
         xBKX5QHVOQiQW8NGlC16W69O8HrJ4PXpZby2YUbbhvK0KHOlVQl4U1R9fo1zCDYKEgfQ
         kvvbQOzyucaKHdwxO5k+EE8q02UpxVKWVuSIP/RZB8HF9IdbNTYknIwLDWqe/v+Vy+N3
         GIcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U/dim4ff2u2L8dSspWgwtyF0xVuI5I8RkgaOtD5Fj08=;
        fh=CQj82khfeVF/yH5cZ8tVNPv919jLwhP8g7+yWpmZZCg=;
        b=bOTNbbK5YqG6sX6CEUjAPLSHRz0hSagYW4GtJYZmogJnedhFbnzlYxtYLQ7FCIpz8j
         YjAUXsiwa9ui0gu2XMY+MmHN8/fwdu9H2rXs797NUkZ6zeP2OOn3DaEgn7BuZOjLFvL1
         sJ1JaTcEEhSH+kjSCDP21h0zQlZl1k68HT+oWOd+3sSbpKWPP6OWEfz+6gAA1BDy21Od
         eaBXBLU0YGKpWGJNjDumI/AQGujUMFwqFiYgrMhIb9AlzZm8waP/SKNbBEVJDar5zteT
         EAIlYo5R1tZKcQg4zUjDL6h5y1qgw8i2fFsPdyW1HUll96EEYDmdfk1VQBVyrpOHpo+O
         1M9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iEZ0cBDP;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-731d31ce9a8si72214a34.2.2025.05.01.12.48.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 21D9549D52;
	Thu,  1 May 2025 19:48:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1D297C4AF0C;
	Thu,  1 May 2025 19:48:29 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kernel@vger.kernel.org
Subject: [PATCH 3/3] integer-wrap: Force full rebuild when .scl file changes
Date: Thu,  1 May 2025 12:48:18 -0700
Message-Id: <20250501194826.2947101-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250501193839.work.525-kees@kernel.org>
References: <20250501193839.work.525-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2139; i=kees@kernel.org; h=from:subject; bh=EquXf22t1MG3qlvTmHUyGycZGdk2twt1J14XgIQ4XgY=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnCFxhVw5LkMtT9F1052nPHuakx/wafkvXdLeWmT+V0x I5O0EvtKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmEiHOcP/+vxpzp/EF33dfr7I rHzutYapwnX5fJ9t70n23E33Oau8npHh19meOVfrLig1qc56t0x7ZcinFGPV3KJ/4i/eZy9VbJL hBgA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iEZ0cBDP;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

Since the integer wrapping sanitizer's behavior depends on its
associated .scl file, we must force a full rebuild if the file changes.
Universally include a synthetic header file that is rebuilt when the
.scl file changes.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Justin Stitt <justinstitt@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-hardening@vger.kernel.org>
---
 scripts/Makefile.ubsan | 1 +
 scripts/basic/Makefile | 9 +++++++++
 2 files changed, 10 insertions(+)

diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 9e35198edbf0..254d5a7ec994 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
 ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
+	-include $(objtree)/scripts/basic/integer-wrap.h	\
 	-fsanitize-undefined-ignore-overflow-pattern=all	\
 	-fsanitize=signed-integer-overflow			\
 	-fsanitize=unsigned-integer-overflow			\
diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
index 31637ce4dc5c..04f5620a3f8b 100644
--- a/scripts/basic/Makefile
+++ b/scripts/basic/Makefile
@@ -15,3 +15,12 @@ $(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
 	$(call if_changed,create_randstruct_seed)
 
 always-$(CONFIG_RANDSTRUCT) += randstruct.seed randstruct_hash.h
+
+# integer-wrap: if the .scl file changes, we need to do a full rebuild.
+quiet_cmd_integer_wrap_updated = UPDATE  $@
+      cmd_integer_wrap_updated = echo '/* $^ */' > $(obj)/integer-wrap.h
+
+$(obj)/integer-wrap.h: $(srctree)/scripts/integer-wrap-ignore.scl FORCE
+	$(call if_changed,integer_wrap_updated)
+
+always-$(CONFIG_UBSAN_INTEGER_WRAP) += integer-wrap.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501194826.2947101-3-kees%40kernel.org.
