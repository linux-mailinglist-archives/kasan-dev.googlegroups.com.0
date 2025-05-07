Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5WG53AAMGQEAKNG6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 25F57AAE891
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:24 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d922570570sf918465ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641783; cv=pass;
        d=google.com; s=arc-20240605;
        b=iPoIDL6dDyoXoETF6ltaE52sfGdi3b4B/+rIo4EcFC1ycih7k6ZngoTEEGJaAKUm72
         1wdxYvIUK5FKXlbxEzECO32OBZ2ubNrkDnqrUjaRHEt5scF6CV3uwPrfhgwg9EP10+7/
         UtUzmCL/Fer9iLIAIqF3CliVTs+7AHTqKYfcD/ggMKlqeAWMnWb2+wfjv+YNnrhE/1g8
         sznfhZ15QtA/DsrWRXM9MVRIEfNUkAvfhgliAeZkEoW1T3kEbLrTsFBkbs1h5pNgrUE1
         h7d7ecOCHqWzINaTmbP+u/ZlChjKq7ng629qVsNLy7oO43dQXTjM3NbMyUe4DW/i68Ah
         QoxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z7Ys/wqazHi/MELMy0qXjLX2/Je4XvwxgYWJt5K36GY=;
        fh=2FTTmlZqn/GQZI68hBr9FyQPO8nY37957p+WVaz3ZGc=;
        b=kEVc6IbZMp07OPALI2XiQc33KHLT0SLGT/rw7oj48fPpE18QFesuFmqoOcP0ciUXyK
         5xveD2OtMsTbm4zy7+CEJbiM65ADNKQ45M63a51nGHGpCs+NQhhfuTisQ/nstEJlRbWx
         HvqM0UvHqIY8PXnLtpK+m4WIPVi0EfsZUrVMQxHQ7BzwOpW3Jo8WMXkmOoEfsiYFpXRH
         1rn142Lfsz0UOoSlKBgOQdTse0SqQt9FH0QES8K+vfJiGCfYPVGRUZtulRbmImjIvpfb
         JSeuA4NY2KIQHl3SgUb4bIAOandQAHGvQ+8Yc8cQf62ilsjAujtxsZChYbFDfhWGzf/u
         IbEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Galm7MFz;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641783; x=1747246583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Z7Ys/wqazHi/MELMy0qXjLX2/Je4XvwxgYWJt5K36GY=;
        b=nqGdVdFHyOC33XPaC+k+3WsnCs21FUQzwyVc7EsghlCBUQafNujXd8ckPXmbJrim8z
         w0SF7FmQFFvKuJoT1adxkn/gYnwHneoRwVRGM3zFhqMnAjC9AHDH3vGjzpKpCZbg8xiL
         Eo6p8sevRrwXAC/rrJcfSRikIO7qOUBjGEUccc0A+Je+8SCYFN8j02fXP+NWTXic6ef4
         Q43V/UfL8NdMxtVPPnoCwsFh+fSMN8CCpS15CSv5qVG+JgaY9zBa+YBo0ALtIx2Fbo57
         5M/7cuG5MB3SV5i8+5gtwe97wvrbEN7wnhSbnbqDOAak2jSqBo4EmzCUNZG5Nc2ZQm6Z
         BTGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641783; x=1747246583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z7Ys/wqazHi/MELMy0qXjLX2/Je4XvwxgYWJt5K36GY=;
        b=Xrf0zSmWBcx7WJx+OQO+w0C+wrTpnXJ4BwpYXHYNXXC4MOixbJqFAVgUJLNRS6ToS/
         gKAc5UmuJNpFAneBxan4a2NMQ+QQEuaQ4LqiqJ0iDymdbGqCiqWeHI0MZz0eyRJVwtY9
         ++jsVBbSCBFtPsJxBduTaR12b9Tz010XY9KWBFTQnTsRCJQ5PnUiPnD04dsjIN4PYYw1
         bIabmU1SmZh2/OkmbmG3g5GcTiyFfvc5spR0wYRh+pWIZ5qGGSYQdTBR11jxxTTJPLAN
         6cfnxp5Wnsx9kxV+BIklXfZJBfTqrTSnfp9azioeWHAy1wy1/vgOtndNQLzrCSfE/Qia
         qChQ==
X-Forwarded-Encrypted: i=2; AJvYcCU19E66OFNBaKRpTR2rxHRkAPdqdvCH4e1hboDIOKcU1W82QjkVO7B90Bm61yLWlxhzIEbc8w==@lfdr.de
X-Gm-Message-State: AOJu0YyFs3Cpp1pZWFpgYIFLelzNDGxfhz3J11qT+qkj3J1ZXv4Q7Wuu
	uhj2oi7tU6EqvFKHTw5NLTeeXhjA/ofCBguuetjSTS2AOReqrVDc
X-Google-Smtp-Source: AGHT+IH6d4gk6ZjKV03Acw7hvv/ll/SMD7dQ85BqaNJtDXGuERkdc3tcCp3B5cPYo6iSnoSJX7oV0A==
X-Received: by 2002:a05:6e02:1529:b0:3d2:b0f1:f5bd with SMTP id e9e14a558f8ab-3da738ed7b0mr49519455ab.3.1746641782749;
        Wed, 07 May 2025 11:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFw+VzgvOnJVDmzCa3r03Ri0pWpO1E0yfjPkAiBqBGMKA==
Received: by 2002:a92:90e:0:b0:3da:7571:e095 with SMTP id e9e14a558f8ab-3da784b7ca5ls1168615ab.0.-pod-prod-04-us;
 Wed, 07 May 2025 11:16:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFZZcAPTQv9akpXsxYz+y1KnRt8ikdyKWwP1RcOo9otHeyOJGWszbfmhcwXVKoM7s47c9E/9YLeu4=@googlegroups.com
X-Received: by 2002:a05:6602:6d0a:b0:85b:b82f:965b with SMTP id ca18e2360f4ac-8674794b831mr583379739f.12.1746641781857;
        Wed, 07 May 2025 11:16:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641781; cv=none;
        d=google.com; s=arc-20240605;
        b=lgLPqfmCfF+maVt84qOu8D0YEk61zQU9JIL/pBybUztZNR25G+LZWlUHk3L/DPkMsE
         3evliGdMigUa39lx8P5jlQRZwC6XJgwtu9oHhmItk80ptYkoSELh5arZCYzm9j/SuZ0m
         VrotDPow0Q0hOHOhUYj4iqPZ1ltWsbOq8ufu20+nQopNP4o5Zr0WHSUJVmYxA/YajBcm
         jS7DlRfUrYrBnL6SM8degQDLLH6zvcR/ipzIpD/M0lP2C7IXK62VpZ2cwVQLIp9/UFqs
         8K4+ML9yxJY2lDAmcoL7eb4CNjJm4Yt/t+ER8v2uEG40vAF7L7PkHo3gxD0EXFteV9Eo
         SjXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BspcMuvBrNbRChwbfJfiH+xXBVeCAdFjM5ETHUBIXVs=;
        fh=E0y4v5tyVvTKcj6/CrXHB5Z6/5j5ivJUS9F4aWSLazw=;
        b=aEOP7fpH5CAF2yHq10/PsZK2fKFG5nkJmbEnod1nYgeR9PUb719okqMxUV4YUsD2mn
         KzsQiql6Hp0gGNJkYKd7h5YdVvAufeOgu+bagvyftPcrqyD3aZBjL2XyqI8nS7I90zZD
         BUhIqh2Fj5SunVGyjb76waamMKye14edKOy2F5K8Yv19GEMPfkq6yHWDEUyLN5+npKOr
         1Z+ntLo/AZBnBEw4Pop2uVyXPQZuPDuzhyNCRG2ufxFaWNzqX/xOAli3KzlXdLTb558l
         4RgA04BaUbQAbT9WE4iAbmETnimxacQSIrWRKK2kn57qk+EOZOKcUEwE3m/iNmsCQ+uU
         b2pQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Galm7MFz;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-864aa135ce4si61625239f.0.2025.05.07.11.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3C18D5C5F57;
	Wed,  7 May 2025 18:14:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40B73C4AF09;
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
Subject: [PATCH 7/8] configs/hardening: Enable CONFIG_STACKLEAK
Date: Wed,  7 May 2025 11:16:13 -0700
Message-Id: <20250507181615.1947159-7-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1035; i=kees@kernel.org; h=from:subject; bh=voDf6H+5x8ZJ+QNvLaKxp1ngBKm9HW1NaIJiF5gitL0=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi3NndCfFZfNKLYsNrJ26vcOTL89ba72XzNPJVjs9u S6YOVh0lLIwiHExyIopsgTZuce5eLxtD3efqwgzh5UJZAgDF6cATKTsBiNDx94c+e3PfryMY4kJ m5dxOLHrbdTcm/xLJ6UelLZ+09L/heG/q46Tus+VBTWHLX+eee7NGPv0yjELoStvXEK7Fl3oXvG DBQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Galm7MFz;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
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

Since we can wipe the stack with both Clang and GCC plugins, enable this
for the "hardening.config" for wider testing.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-hardening@vger.kernel.org>
---
 kernel/configs/hardening.config | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index dd7c32fb5ac1..3da00926b4eb 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -63,6 +63,9 @@ CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
 # Initialize all stack variables to zero on function entry.
 CONFIG_INIT_STACK_ALL_ZERO=y
 
+# Wipe kernel stack after syscall completion to reduce stale data lifetime.
+CONFIG_STACKLEAK=y
+
 # Wipe RAM at reboot via EFI. For more details, see:
 # https://trustedcomputinggroup.org/resource/pc-client-work-group-platform-reset-attack-mitigation-specification/
 # https://bugzilla.redhat.com/show_bug.cgi?id=1532058
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-7-kees%40kernel.org.
