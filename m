Return-Path: <kasan-dev+bncBDCPL7WX3MKBBSHHVG7AMGQEUUNBI3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F17AA55F4E
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 05:19:22 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ff7aecba07sf1065154a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 20:19:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741321161; cv=pass;
        d=google.com; s=arc-20240605;
        b=SfJY5adD9Zyy8TXF6FFBoq8VY2+A/TtM/0g7msFYVxHMFHoa2yFwNuXR4HI6qJYzx9
         CYbnOioCCN8jJJv/77ZYkIRbZOP1vPRzxe9KeVRK2n6LyNzjlIBgWkiXxNgwZeopKYIG
         EJMQyi9dgQuuWfeQnwWMK89hMj+nDTpfgwLUKIS1HLfd2Q/Q6GsOPzibs4QVyLFbTyGb
         pJOdwmRSDGg1Vtz/CUgXftGF59H8lvAXz/4r24gy8MMGR3df5b4fMMKKbqPGcx3Q3CZY
         hx6wihWysuqXxcbIR3s6rl/4GicHWYSzbU+alEM9MNHx8dRHoyVzpxWI6rZsDhpqRBNp
         /UfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=rU0x3yVI2+lMGuOR3xkoESo9UO8Likq/kcfOOe413mE=;
        fh=XSaMD442x+9SS0L1pssy96XJ6iu1+W8jM+cJfbfvngI=;
        b=U/LLmtpaGec5Q/XkwJ2YgAvAw0LFf6cpeRKNHu/KK/RokrNcE09DbxLylcxFR+KKqz
         S3bCH4W7HQF1bT29o01jO5pqxgptzpaSyZuY7eui9K17C2rFsMdeup4T79KrflPIv3NT
         l2+QZJ3zewRjkQyOS7O41+1dkF2TX/egbx2EQ8taQo30soxGljKZ5Z2yjkocnViyRv0f
         zoxo6d4O63/GrOa0475/GN9DdlJH+UCQwhS2ssKVeu1BZ3+f8Jcw3pAAYThzk/GSn3et
         KszLVhLFtMMrMjx5zUMg6jWwDRgKlnsPT8BNLkEpIaKyBcPJkEYbXkJ8o2E0dYdxpd48
         6t6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rpGqn/ZZ";
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741321161; x=1741925961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rU0x3yVI2+lMGuOR3xkoESo9UO8Likq/kcfOOe413mE=;
        b=SF31uwjEOau69GCv1and0g/roqfqYvyciNvvuEnWwd62Mr7WBmh1osWEmltZ3Z04yX
         LLu+Lxgzs3pfoNpLyWYJq5CX+Po0PHFPkkRruIY2rQDHrbqgw1kABGzFLLQ8SLc/bXRp
         bJ4ShQk2V0Fgg7CbYKb6zugeCvA8bDb8FVxjcaSU2AthuXLiWhf9IshQXK2d9+Zwk5Ml
         klP1m0rVfgQkEa0NWED99fDn956QMGSuBhBnnMCEI+l82wPRKVbzudiFqaufquBBdj5+
         w/SWny+jvhQ3/rjDiQp/Kk8C7Yhlj5dCN8D9wOS5gaWrBu6J5745q+WwwzgTuCQFHVM4
         gh5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741321161; x=1741925961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rU0x3yVI2+lMGuOR3xkoESo9UO8Likq/kcfOOe413mE=;
        b=eGFHJbls7vJxp4r3D+7a51yD7c4cS51r2vOWoe1H2YbEru0guZKUDoORz784OVYlC3
         Y8u7S++j4KtMMtSBKP45abYbYdsp9qSGjJz7OqA2Ix7UcqLsoDZtPgqsYwDzT7R8Se/Q
         vQCJbpF/C6/OrJ/m0vsjpBfsD+SjMflHZQCaL9FKjoz+/vt8VdY21U8cRhBWlNXidaeY
         dLMxl6KrRh7CcHsRXft0Snh7jm3Dc+qiJwe4OYmJqKgK7lm1IL0GwMlcEmlrN+nG7Kzx
         H4chuL8vX1FSuYXKJk/ar521Ni121RuzjhI4y5vJiGY07fs4s68MMG8m4T8QJN8f2r1h
         RnAw==
X-Forwarded-Encrypted: i=2; AJvYcCWQsRnPNScHf0HWoJUUrG4ifWy0zdvy0TiyrBzoGzOhnyKAjFdGQibk1HYKQxjPcvWYqZwI9g==@lfdr.de
X-Gm-Message-State: AOJu0YzVMxIOBgtXTtVLnRxAHkduAw6EvubFom5eHrxPpCK0/0t5JWFV
	ohUeJeycSKwyzSZE43gRNGhJxiieKOk4kiR/K2iJqQ1FI98eDUz5
X-Google-Smtp-Source: AGHT+IEnBkwl5uJ5dv0ryFmfcxIHtID3vjzvQxxzMRToYljQ0HeTS2b8qn2cppVMTmnOF3U+G0Hx2g==
X-Received: by 2002:a17:90b:4a0a:b0:2ff:62b7:dcc0 with SMTP id 98e67ed59e1d1-2ff7ce931a9mr2976819a91.15.1741321160635;
        Thu, 06 Mar 2025 20:19:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFfskUD1fe/UJCYX5st8w2CFZBh4J9zZhrzg6GLSfdSGg==
Received: by 2002:a17:90a:f00a:b0:2f8:3555:13c3 with SMTP id
 98e67ed59e1d1-2ff6289d673ls1548697a91.2.-pod-prod-09-us; Thu, 06 Mar 2025
 20:19:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUkO0KxINkFELPUUZc4/FxEBLW9TXrEUhqwwwpbK3clyOaeyGFW+w3I0zNTCQaDmNKcE80d6UX5Mdc=@googlegroups.com
X-Received: by 2002:a17:90b:1f88:b0:2ff:5a9d:9390 with SMTP id 98e67ed59e1d1-2ff7ce76d0emr3077825a91.8.1741321159431;
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741321159; cv=none;
        d=google.com; s=arc-20240605;
        b=e4fT6hGEUIiS3Q108MLJO0KNOrWsFLhvl4QzYWy7V+XJhmdBbpKAWD2s6Hm6jVk5WQ
         cW7oGPprBvCnLrP8jFk7/7O6UqvNwr3FUQml4g0yTR9JnoTUUf+nQ7rBKCDNeIOGNxbK
         IdfsoqA6uSpY12mt7RfK6ksLrffJBL39JPKaGnQkjkKZJual0rLcAds8MONOmFhbYBdi
         fF17XpqPmbI1i5Kl7B7NimHxTicuONnvFjCMC8jA8jeMYFA+hSxXywe1l0WqwplrWpfQ
         GLfxgc79o0BFPBLTJe8Z9rvk/dBgDTI8h+pLLkC6GZ7ZUTR4BXfA++7BXAcw4LT1hx42
         hq8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OPTclFJWOxgc5/PKVg4yBeONooJjghXw7V83peNDyz4=;
        fh=Ss416SUgoCDHv4IZdMUBFPyvlEGEJNcrdQ4+z430jNw=;
        b=DV1neDPd68V45npMhazITHo32I/Cai+SF68itCOtxHIxPj10GesPIXPGMkdlhRVam2
         f0xJKlyIrV6XikblO3SZn+mj37KyoMwt4OqwI3TW2DokbSznmUbdseVHAxqS1izjVVrD
         2XhBvkPXfAzAuChR5s+XPtKWUL/l23MmtxDcfGIcjsS21YnIsmHBxb+75QZVB19bFfh2
         CDaCZy8Ul6ZPtctYJFz3UXAaXOEWz4NKAYkVXURiEad2uwfow2wpZF153vPwJxsUjxRg
         9Lk8hXiVnWmQ0uP2mLi+9B9sEworgLCcZtRECK63M/cMSubh2J99okn7orrOqoq84q9q
         ExEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="rpGqn/ZZ";
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ff5c605e62si313357a91.1.2025.03.06.20.19.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Mar 2025 20:19:19 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id ABAD7A45443;
	Fri,  7 Mar 2025 04:13:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DA624C4CEE2;
	Fri,  7 Mar 2025 04:19:17 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Justin Stitt <justinstitt@google.com>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
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
	linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 0/3] ubsan/overflow: Enable pattern exclusions
Date: Thu,  6 Mar 2025 20:19:08 -0800
Message-Id: <20250307040948.work.791-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1304; i=kees@kernel.org; h=from:subject:message-id; bh=HdpOnS7Eic+UbYPCcALNkxTU2FKSqjORHtZap9XlbFA=; b=owGbwMvMwCVmps19z/KJym7G02pJDOmnivc9WDdJnPdalex1RaudYX/mSYtfr5ZaxpWtqjyt9 5P6wfmiHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABNRTWJk2Ls3+nLnp+qNm3pd i7/l+q32Xp9lKsT2w+HqrwYGvp+pKxkZznY7Kx+w8zbRv2vpHFciXPDncomFpWdCpd20INdqyTU cAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="rpGqn/ZZ";       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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

Hi,

This brings Linux's integer overflow mitigation integration up to the
current set of features available in Clang for handling things sanely
(i.e. pattern exclusions). While this isn't over yet, it puts all the
infrastructure in place to continue keeping up to date with current
Clang development. The next step is to add support for the coming
canonical wrapping and non-wrapping types[1].

-Kees

[1] https://discourse.llvm.org/t/rfc-clang-canonical-wrapping-and-non-wrapping-types/84356

Kees Cook (3):
  ubsan/overflow: Rework integer overflow sanitizer option to turn on
    everything
  ubsan/overflow: Enable pattern exclusions
  ubsan/overflow: Enable ignorelist parsing and add type filter

 include/linux/compiler_types.h  |  2 +-
 kernel/configs/hardening.config |  2 +-
 lib/Kconfig.ubsan               | 25 +++++++++++++------------
 lib/test_ubsan.c                | 18 ++++++++++++++----
 lib/ubsan.c                     | 28 ++++++++++++++++++++++++++--
 lib/ubsan.h                     |  8 ++++++++
 scripts/Makefile.lib            |  4 ++--
 scripts/Makefile.ubsan          | 10 ++++++++--
 scripts/integer-wrap-ignore.scl |  3 +++
 9 files changed, 76 insertions(+), 24 deletions(-)
 create mode 100644 scripts/integer-wrap-ignore.scl

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250307040948.work.791-kees%40kernel.org.
