Return-Path: <kasan-dev+bncBDCPL7WX3MKBBSHHVG7AMGQEUUNBI3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 34232A55F4D
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 05:19:22 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5feaeffd84csf459416eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 20:19:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741321160; cv=pass;
        d=google.com; s=arc-20240605;
        b=BpAHHyTlSifolXCyPeS/zVOIVzfE2i9+EBlED+aZjIm6AJ3SI6obsFK8eFsv7djX4/
         S+MA9D/H3J26gipzY/Uz9bN1XGXdI3TpVfY0hnSYiALTHxJWUULgWA8uAg5ISe92s1+e
         4w2Du5Jq12/toLKFouxw6Y3npNtzx6jbISuiIbTyRP5yJngvuigt5vD/T1VfLNiVoDMW
         nbdb7pEKvBt7Zfxy2jSX5Hm6DwliozjeL/qGvjcuV9l34mbrkwLBc0fLd64chm9Oh2oo
         5bSecQ6pha+U3hEUNGSPSy15bsDSgaypRF3sCnaMaoNGHpAE4TlMthC7HqsXeiAkvVF5
         rqSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ra0Zz0+NYRcLmfb2GBhNkHrA5FOdfNupVvPIOTQYaWE=;
        fh=LEYrlIVipHamuU9LzO4k6rnu/g9y/NqHP18cy+kvCkQ=;
        b=k3vEbJ1dnoOCCMXCHPgpWAjTsgWyH+20g7gsl9G0620qa40KroRuCcmRltalSEOYAO
         ATs0oWiOSYoU1ELyI3ePcgCuL1ZKxPEF/N7iN94/Th21Swc5Ld/IFkpbinud7j2z0v+9
         NDYeRlzLwqf5mw5pv1YSsBx93boktJj3gYK2B0zkt6PZ8PS4+TmUZ2T7nfevyFy628zp
         y2UlbSt1/oQb74hMBEBXoA2U9YEvO7rjmFtsv61CFlUBp8Q1P2mm/dVm6QKzwuoiNRjk
         XFYvVqMUQVMqzkUoyBDJ7Fkz7yRDrLHxgWr8eh3Uo5jpxbCbdSVcYCcLt97uJv3vLBrr
         r35Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Buin79jU;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741321160; x=1741925960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ra0Zz0+NYRcLmfb2GBhNkHrA5FOdfNupVvPIOTQYaWE=;
        b=bkUEuhiTaSb1S0AuLqSVm05HreKj9lT4qt9w6plbeUdcKzk1ScKlJAPePnAIdZQWZR
         044zFxvQdLdHt6/xPP0+0D2nfYe1iVsCMXrDkeNBA00gGiiJWYbgd2cAYi8bLIFlmEj5
         xQjwupb48JwspSxOHNLMwM0s/lZkG3DuSOJtiRFiW6dgybsyCQTCNnxHOahW231crR8G
         EiAQHe4BBytjzNe026v+zwfwOp4bMeTEbtO+qRlvERhXS4BU6pTvN+jeH8x0dcE0Q/0q
         EbqysuwEWDV5xqTfN1MIxA7WxceDUdDV1Bs3z28wepBhevIJtjuCaHXC8ik+TVHtDCWv
         cjng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741321160; x=1741925960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ra0Zz0+NYRcLmfb2GBhNkHrA5FOdfNupVvPIOTQYaWE=;
        b=V7mEsb97imMNdAgCRQRQ5bcZQxf/zHn/EAWlLAHw2nFn0qgxUZkCKot4mZLZ+lE9Iu
         VtbmKvF058pah8hWO8O6iBIQMjnIqdw2pju8RmCAPlnknb5UefujKtqupmRYjt1Z9Tck
         r9/nm+VJ1DzRJiJQvvVvf0FaD3rDv8D2tKP6ofvn54gHVldc5tR4uwnrfr951+Kxgm//
         Ke6VO66bulCKkGu5EnPzgJtDJKge7AnAYI1yjuaVKsyKuuBnjS1qrh9iqPFVgxmPuGZ7
         cLrNYwZbHVJqlXTNCOL7bkyjcCJ9PA4mRJzkFNck0ccsbkxVv8Jw1zBZyd10SaSVTOmd
         e8FQ==
X-Forwarded-Encrypted: i=2; AJvYcCUs/H8gqvvdsKJ0tCx3kX0OvuEmpFVRrisNmI8dVwdjYW6o5BqTBZErUZjfIT8pn4QK70/0Mw==@lfdr.de
X-Gm-Message-State: AOJu0Yx+fyVVNT6v1NwoCxV9VIN7Ml94yOt5VJFhGjblXK5yL+s2VcFL
	wNlaCN+/qe3XxUd7gZEjDYbsEQVCqnV6dQFUTURXsZl9eYmMQPGb
X-Google-Smtp-Source: AGHT+IFTOQHxpWN/16R5+qQQG8E9VAMJ1GdfiKJJnctT25KuIHOULEOfpEpIo3QJXnLBgUjZQZAzoQ==
X-Received: by 2002:a4a:ee17:0:b0:5fd:d5b:f46c with SMTP id 006d021491bc7-6004a55504fmr1043183eaf.0.1741321160298;
        Thu, 06 Mar 2025 20:19:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEow6EAtPzidAivysEB2FmqVtQjfjLzNHlMREPRw32VuA==
Received: by 2002:a05:6820:547:b0:600:2484:a57f with SMTP id
 006d021491bc7-6003e9bc3ecls570071eaf.1.-pod-prod-02-us; Thu, 06 Mar 2025
 20:19:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW+/D7mNdlk4etkn6RjDmBd8w6BZWq2P/SExhVByjMnPtMUTpFJLVupPTByFHZfjaEYbmL8EC5LHME=@googlegroups.com
X-Received: by 2002:a05:6808:4491:b0:3f6:7cbe:32a0 with SMTP id 5614622812f47-3f697b188c8mr1180914b6e.4.1741321159529;
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741321159; cv=none;
        d=google.com; s=arc-20240605;
        b=Qz0eRJc+RkBtCczmzeLu55RXvspJrySsMlnUbeaYZIxuyinsk4DSzzVh0dRHlcjBa/
         R/ZXyvsf52LuvSHQTq+u5ejZEJyHCgAZRL7ijD4T/aJaXDD9OZG7oHUD+5bm6REh30tc
         aXrM5+BFvqPiNPjT7NxFeqoqVIqmKJ4bgzizU4sSmgJm6XKuX5BHKZd0e7ltfEY4TAJv
         9z982XRwHd8jLeCAuuBiqq4TZM6HMYQJCWDlttZK9uxz3Ci+ciqUmmEC7Ra4/wkeodxM
         3hdIyN4eTwE0ng+5tsJ0oEwXBMD0LxLpeDZuixn2QqBhqkMN+G+Ls0+LIbgX4MPc733L
         KAqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rSVRMaf1ccxeIs9yGefLqyfIIBQNw9cMA6cD02mzDPQ=;
        fh=WmcTCN75u22BydJkotoS3NBme+IxbkylNkQxY0jZPho=;
        b=OhTeof7rL7STa0OoKq0UbiA8bwvkEc2MeNfWLU1i2R2sPTxqDTXzcNgNNqXCct86OE
         K9g8fHuwTbp61avpOTWIP8srpE67PZXExQfrgUb7cxT9ieaw+StbfRK5iCkssVoMu5m3
         tETNhG4UHXuX/9FfwGHigqH6UjKltYJ6YaYdEG+TY3Ivi4/oQebzAPmD4KbPiieuGVnh
         5/WcdHol1RqmXFTjOIW9aSpp+j8WA6FYiI5uLXDbMU+URMvfU10bb922vW0FzGKSTqa5
         2dKFIFel5zxmRRDtgyR9JHkpLRtc6fm4/OITMaz3mMFBxEFfxt8jtur7BtqLJod5MBzy
         nl7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Buin79jU;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3f68f036e18si110028b6e.4.2025.03.06.20.19.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 34102A4544D;
	Fri,  7 Mar 2025 04:13:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DF828C4AF09;
	Fri,  7 Mar 2025 04:19:17 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Justin Stitt <justinstitt@google.com>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	Miguel Ojeda <ojeda@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Hao Luo <haoluo@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	Bill Wendling <morbo@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Tony Ambardar <tony.ambardar@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Jan Hendrik Farr <kernel@jfarr.cc>,
	Alexander Lobakin <aleksander.lobakin@intel.com>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 3/3] ubsan/overflow: Enable ignorelist parsing and add type filter
Date: Thu,  6 Mar 2025 20:19:11 -0800
Message-Id: <20250307041914.937329-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250307040948.work.791-kees@kernel.org>
References: <20250307040948.work.791-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2672; i=kees@kernel.org; h=from:subject; bh=uNpuQxTpZBJvM7GGSJmEy7lrrBKKHc7fIlKudivWp4k=; b=owGbwMvMwCVmps19z/KJym7G02pJDOmnive33Kyu+u8yKfiLVCOnWmx084Lfr96smbtIRLf/Y /i1tR++dpSyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAEzk6FNGhjMLtQ0mlb6V+2tR 4rv444FVF+UfOWn5vX6TuOWrR3HWmjiGf2rWE+S+bv728PWUGc1T79xsMF5YJ606fauk2+YfCQ4 mlQwA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Buin79jU;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Limit integer wrap-around mitigation to only the "size_t" type (for
now). Notably this covers all special functions/builtins that return
"size_t", like sizeof(). This remains an experimental feature and is
likely to be replaced with type annotations.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Justin Stitt <justinstitt@google.com>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
Cc: linux-kbuild@vger.kernel.org
---
 lib/Kconfig.ubsan               | 1 +
 scripts/Makefile.ubsan          | 3 ++-
 scripts/integer-wrap-ignore.scl | 3 +++
 3 files changed, 6 insertions(+), 1 deletion(-)
 create mode 100644 scripts/integer-wrap-ignore.scl

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 888c2e72c586..4216b3a4ff21 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -125,6 +125,7 @@ config UBSAN_INTEGER_WRAP
 	depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
 	depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
 	depends on $(cc-option,-fsanitize=implicit-unsigned-integer-truncation)
+	depends on $(cc-option,-fsanitize-ignorelist=/dev/null)
 	help
 	  This option enables all of the sanitizers involved in integer overflow
 	  (wrap-around) mitigation: signed-integer-overflow, unsigned-integer-overflow,
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 233379c193a7..9e35198edbf0 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -19,5 +19,6 @@ ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
 	-fsanitize=signed-integer-overflow			\
 	-fsanitize=unsigned-integer-overflow			\
 	-fsanitize=implicit-signed-integer-truncation		\
-	-fsanitize=implicit-unsigned-integer-truncation
+	-fsanitize=implicit-unsigned-integer-truncation		\
+	-fsanitize-ignorelist=$(srctree)/scripts/integer-wrap-ignore.scl
 export CFLAGS_UBSAN_INTEGER_WRAP := $(ubsan-integer-wrap-cflags-y)
diff --git a/scripts/integer-wrap-ignore.scl b/scripts/integer-wrap-ignore.scl
new file mode 100644
index 000000000000..431c3053a4a2
--- /dev/null
+++ b/scripts/integer-wrap-ignore.scl
@@ -0,0 +1,3 @@
+[{unsigned-integer-overflow,signed-integer-overflow,implicit-signed-integer-truncation,implicit-unsigned-integer-truncation}]
+type:*
+type:size_t=sanitize
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250307041914.937329-3-kees%40kernel.org.
