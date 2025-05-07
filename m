Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5WG53AAMGQEAKNG6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id DDB9BAAE88F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:23 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-708aead74d2sf2323947b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641782; cv=pass;
        d=google.com; s=arc-20240605;
        b=KwsKFlkkyILHeyIziI1g+EyK0tgraDpKdVd3ef8RyhIQpNLw99NMlgjwhNUjBXP2R2
         b/y+UVGZihpr4d+chA9wJTAo15C3JCTPl2powGrSILeeIZqsefq0HDOH4N7x+dCoRHWi
         Ig3DpVmpt47dDr9DymAe6jgIckn8OxboGvkSvacvYju/1Le/7N+B1h7WqgRDeGrDE3UR
         blGL//4MFo/tBw8zAtxuJOLOeXz2iTRcne8tNVoeQ0pPnRwaXG8ex2m02hiJBLIx30v4
         0ld46Bpws6vZv6U2DvYAek7LFg5qfiVU7wrPUeKra6e0M/sNbThcYBRSHTMgvpoUtBMI
         a6qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=EI76UgF968McNQaanR65OVJ/QyL2J/q1bC56dwAGBrk=;
        fh=tBAqqcI/jY4IEbCzSgr4n52I+xha2efpTbmch8PnjzU=;
        b=JRBo6DKwpdABr/Q88WoLSkgrU1wzEytOtxnKvRaDWnpGB/pJ+Es0KorEhemIxbLi4K
         vR+hX4edeoU1vNkPfo3/fDpTgkl1K45ETmS91YFvB5ciXYfw7CurNwVwPI7B3hI1Z5RO
         KFmZsUPKUC129133HShNiQxvMJr5R1wGaCZZtfBmtG16JNSBybqNVuebdIbBH5Eytax4
         09yKc5HuuAEQrwxebZFwNE2+953R77fIc3faU2X3VLZuiIf5RVsjmG5vOwULVJqyvc5Y
         LPBdql59p7e5aS1SIYjzMC3itslC5Lp4maTzg9bmK/KytC0nu8hgnBtjmN9/5JhKmn0Y
         i9xQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F7UcDZXd;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641782; x=1747246582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EI76UgF968McNQaanR65OVJ/QyL2J/q1bC56dwAGBrk=;
        b=rkwA3rtwxiG2VG+kvHErBYTg2qxyxGKf9eTfUbTm8QOaGEQikaGrqqqQoRP5Alk6fY
         a9tovujTMqWJWV/ECrG7cmz+znDX+AKM/iSim7UiZjfGxJBo8Zp77nf3i3wBqkdgrC2V
         u7tLucXOKvRHkKwbTFX1WpctVAngnqx1WKcc0mOCSeprTtcAP4eM5KeLGjh/LLJ6ALbn
         aoLTfhLpjEod5y2MhDqTRT2W9Wf3DONFNAIY3LJgVedvZOPav0YayU3ckZwRNGiIstr2
         TGRnCW519Z2LkUrb28WKFyj4OsHteSxJ9eFKWmoxxKw7N6sSYU6fp5X/sR1PGh+nyBUD
         /asQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641782; x=1747246582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EI76UgF968McNQaanR65OVJ/QyL2J/q1bC56dwAGBrk=;
        b=Ra9xsYQSTqXZ+oKy1dqye7HSbz1Gn53GlB5ogKIIH8B4zVLpo+qYbFBmsGatqHPAv+
         OwgfmDg1Shy4rY2nrmJNDde1TyitdhT9C4y0/Kiau4HfNdm7PAyyYn6Oivwu2Wec6bBm
         QCMLVzB6pvnhJLsbwJFDZaOk40gijqpvDFyEkEAEyJvHTZZG5uXUoT8ZZrOwjAAciBU2
         ibIHvTuLA3zObsi5Q0Y1nRD9udmRt0GWXdsdNWdMDdgzXh9mlJP9Gkf+iqN2oTccFpg+
         A7dsTvCLc2X8b795I5f4rkZ8s8Z6OdB91QkCBjRStwF9PSPGoMyjDNh3dzOinep/AB55
         j6wA==
X-Forwarded-Encrypted: i=2; AJvYcCVMVkuLV3ypKymJWMpiWleV2vhpZRul/eUlre40rBVjTcWWsLCK3qCKGK87oinTtpYgw+p9kQ==@lfdr.de
X-Gm-Message-State: AOJu0YylazdAxw2kXVd+jyboWsdPaEelfmXZvjVUJf74zpifMNaoGdJV
	UjLWtyVUVtLXB4q6G1bh735OxC5QEIp1nFevqUvLxGJmF+b+sjLY
X-Google-Smtp-Source: AGHT+IEZ9KZ/XML3L23joAczDs486ktuSkdGGXsPhwNrQ0xcTDa4FVoXcmVBdLaqUFJqD+fH1BfVuw==
X-Received: by 2002:a05:6902:2589:b0:e72:d88e:80d4 with SMTP id 3f1490d57ef6-e78822f3249mr4587430276.42.1746641782595;
        Wed, 07 May 2025 11:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEFkV3H7mOOOZXzK3TAb2TEasSNP+uwZtVLBr74SRWmWw==
Received: by 2002:a25:e0d3:0:b0:e74:6e83:3091 with SMTP id 3f1490d57ef6-e78edfc1cdals167808276.1.-pod-prod-01-us;
 Wed, 07 May 2025 11:16:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/OaXouyJYnaTojmOrz4cHJpyUR4whXhhCZ4tzOx2plOJokdP3xnep2a0mOwqAlikaPiTjSBD2e5I=@googlegroups.com
X-Received: by 2002:a05:6902:2012:b0:e73:29db:6c5d with SMTP id 3f1490d57ef6-e7880e7fbc7mr5849151276.3.1746641781848;
        Wed, 07 May 2025 11:16:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641781; cv=none;
        d=google.com; s=arc-20240605;
        b=GkahtZRl31r+kQ0PR4c/vmTiU/z5OJdWsbGt26IePcGhTDW+DORbm2MZM/OMNrFkyx
         cFtXIJFtw703z90jC5n/24H0LRayDi8GC7Qrr1+IYtUM9b9eKOo3xAOUH6r18t/WV431
         re5YAWONKo2Y/CpVGiZhW28D4ZU0uSQ4tMnhBbz28gOk65sxQOWA+LGFv+fsoaZm9i70
         2WI4K7OVIZsu+M3aGzThQqecyHrfdAX68qYGG+H5wGcnH39ZJ8KI75Z1u/3CP9ge4m77
         xIS+OkUbDkS+EqkoRfNJWY1UUKbV3g1ULiCmaVJrgS801Y485RPy9G32pQRmVfU3JFNz
         esbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U5nQ6TR6aiKBeffDEy4PqW+LaWc3J9ohAONyKi28DJc=;
        fh=E0y4v5tyVvTKcj6/CrXHB5Z6/5j5ivJUS9F4aWSLazw=;
        b=NrFNS92mxomnqVt0dJhDCbxjAvWnmbhRVEbBqmViTWT4ia+lNc/WbfiF87n1JERXQD
         pMkXR277gF20VTE35iS/hUZro0yIrFxya9T1Gzo7e4EuXD423449MQTzlPu5QnLPDyBo
         YKBwSihKhg6Ej8wU5CkXgNUonhxMlnHesCMNzvlB+7+7SbHDN3BgERl7zOcA3IWxhdcL
         OGnUvjKlIG9/R8vjXqYmZV+kd/f34BUaXZFGq7nxr2p2S4sh3aNEm9AxzqzU975LWtud
         A8yNyLbG3KhhyXZgIpepqGWa+L3LC0muQTJzjrS6S6wNet7BU2cMMwLzenFXhfZp7KSz
         +04A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F7UcDZXd;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e75fa106fdfsi170992276.0.2025.05.07.11.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 359C15C5F3F;
	Wed,  7 May 2025 18:14:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EB66C4CEE2;
	Wed,  7 May 2025 18:16:21 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-hardening@vger.kernel.org,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 8/8] configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON
Date: Wed,  7 May 2025 11:16:14 -0700
Message-Id: <20250507181615.1947159-8-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=961; i=kees@kernel.org; h=from:subject; bh=JBC57/AJ4s9wnqVrwmV7BOpA+2zHUnfcHWTkMgWl8NU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi3OdD7t0n7oULsejGJ/+9MQm/geGMg9cz00Vqajg/ sTnY3e9o5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCJToxkZNsxfvyhx39Nzpiyy k1d9mfdaZ2I4d4Fed23ppfk+FmvT+Bn+V65ZP6cwRVHDaFl+g9uJIPvmT50TbXLDqlrmpn0pTfX nBAA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=F7UcDZXd;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
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

To reduce stale data lifetimes, enable CONFIG_INIT_ON_FREE_DEFAULT_ON as
well. This matches the addition of CONFIG_STACKLEAK=y, which is doing
similar for stack memory.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 kernel/configs/hardening.config | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index 3da00926b4eb..7d92a740e490 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -60,6 +60,9 @@ CONFIG_LIST_HARDENED=y
 # Initialize all heap variables to zero on allocation.
 CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
 
+# Initialize all heap variables to zero on free to reduce stale data lifetime.
+CONFIG_INIT_ON_FREE_DEFAULT_ON=y
+
 # Initialize all stack variables to zero on function entry.
 CONFIG_INIT_STACK_ALL_ZERO=y
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-8-kees%40kernel.org.
