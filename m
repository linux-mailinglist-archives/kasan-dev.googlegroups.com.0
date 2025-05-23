Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDXYX7AQMGQE6XJHJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 35404AC1B05
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:44 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e7d6927009asf2157592276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975183; cv=pass;
        d=google.com; s=arc-20240605;
        b=VJzZg7GN7O5fehmWaGJsx6lNkBTEckXOv6uW/dibKOJ3WeJo63lb3cpq8OglXVcEnY
         GsBiOX+r6eLLWFPzaUW0Ndw1RORL68TjtbYYHlhUTESCaCe9ev9QrDaG29a31k6/bZhI
         kDopzoWxJBbfXDAwWkP/JyjjcGI5vz7KLX3Gk3QlhNJYVrb/uZw1kKpUHm3OYomVWFKu
         wfv3hoEN0w5VaB2i28kZ9H7s5hvzkNzm1M3SFvhhwaY5gFTi7A6nUp6oRIGjHyUqT0O2
         7g2K7VOHrLWku7DPNJoL9Hcu8/ooG9quHX9AEyYygx3wlkwGjLrulYBvwI4XxSKCnqf4
         g82w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7k/t5kU5yiQ73km8Fv39Or8U82tPmkc9SLM0IcYoGSU=;
        fh=yZoTb+DUqV7xGU1G9330sLibhvbO9+5FRwkX+qnyGU4=;
        b=b/s6Ys/jRwSh8ri1hVG+M6utu2OtCNPvbPaoUcpZahQR6fsyX1QWWn8ACBjDQq5qgj
         SVUwG4nd3cUMYm3Rz78y7xlZLqVmfVMWgYSWZwcG7hreGtMlpe99wmZsgfM6vEqgAaqY
         DcjFyVGSQy8JJflsUijia+QsbP8X6dyriTfMQN+fbQWtasNqP7iBCXKPmzNuKc3LAp3x
         TvyWA+0XKilKXuVezUUQnZu2onK/DurVAoBoU58YMdoSKhOoGawZAMs5QN4Sbx6Tb73M
         7b4xD7N1F2KEVDoEbwSbQhd6U4FYQeju9iSh3aasvJGVF47LGZH6JU1ULMKTuCjm0Zmq
         5VSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mlt9V43N;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975183; x=1748579983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7k/t5kU5yiQ73km8Fv39Or8U82tPmkc9SLM0IcYoGSU=;
        b=Ti+TRmHaW991K8OAGUB47YEYcl2Cirk9+X1ISukLhR/SuSHUbU7u7ljke9IZGVPkHK
         xu7EKvXVN3LWGM62mjfK2plRA0uqkFrYYdfqC4tbCsgiyUOI32Os/irz9k4pS9QbULX4
         Yc/vENbk83WwO3up2PYlFlrqvkiDnjz8Hshn0H6U0x6SQFw+bMlxIbkRyUTthIWZF0AG
         YS7GAgz4AwoOVJTLbErvZiqi31Wt5RXShUACSCRJLxvq0aoPK8fhKXbV5I9Qn6NhQih1
         YVvudlJn0ohuRbGRq3db++QGWZmjlBxB6JpcdkEhvljMJRdDRmkVKnRsXFaPJ5oYBEzz
         Hqtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975183; x=1748579983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7k/t5kU5yiQ73km8Fv39Or8U82tPmkc9SLM0IcYoGSU=;
        b=Cf1PUU4LTsBVczphKboQZWdh3MGlpKxOLhp4nCj3jPm3c0EeRBXI0sTpsZzBJlt/oC
         tSUo3CkPhvOiAaarB6pxLHwdE6AO8hER50fb7jiPRMYyuKgLrIGAyZoX/cCCc1w3aVkd
         7VUCmKu2Q1lxrZF2/7fnTRBly6aPyLb5kAYgt8IbszS9NjNid8ALkHx9j1PmzH8LzKos
         A3ZomaXhUXn4KWgP0LdAKJW/iKwgwfu2y34FEdu30mEu06ZXWFHejfpnttlQtxtOcekJ
         DwA+d2XTei7jq02zxVIW52wa17o0SbcisgitHkG0RTfbHbpwMMLiZZxUKPK9aYN/VTi/
         c0Ug==
X-Forwarded-Encrypted: i=2; AJvYcCUphaPY2r6S3R9Bbj7xaIx3RwVwk2zrbcOGUIPohdH+1XfCSdPNb8cbna3Bi24gHgZjlmeAJA==@lfdr.de
X-Gm-Message-State: AOJu0Yzopns45d/IS8gFPFH5oAlekkk/ovxHZG6tQyT9uJT/Ksc6vh9m
	M5XWikfJxOZdGUtjjm4rwr+l9SrlVm2f+H8gJLd5nWNxYfjXzBf+91dh
X-Google-Smtp-Source: AGHT+IFE3jCAMnZbQurcQmL2LFfiNAi2rCHgX3uTPG31PopzRkSYQIGnBxVZw0DQDVIDk27eSlmvTg==
X-Received: by 2002:a05:6902:18c1:b0:e7b:9684:8b71 with SMTP id 3f1490d57ef6-e7b96849201mr26149352276.30.1747975182967;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHfQDfsH+TqyNRg/Y3sQjGHQGrTHbCEHRyKT2Q/B+MQXg==
Received: by 2002:a05:6902:2806:b0:e7d:801a:4dd6 with SMTP id
 3f1490d57ef6-e7d801a4ed1ls282844276.0.-pod-prod-05-us; Thu, 22 May 2025
 21:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3cuKvk9GToAJ5HR0KmE6WAO4bPNwFPgZtQ804ZCmLpFz/QmxhuFq6ZvPD7ydzW3mXJ1VcMYkx7C4=@googlegroups.com
X-Received: by 2002:a05:6902:1102:b0:e7d:6dd9:61b1 with SMTP id 3f1490d57ef6-e7d6dd96370mr6046278276.45.1747975182225;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975182; cv=none;
        d=google.com; s=arc-20240605;
        b=L7B2jPFCA1qdq9iAmCs6tHNMTGptfjpH21bfJ0UQE2cBLa3B/INls+w6NDumiertss
         R9STxxpAndfvlZbQRK8XQ+9V3PA91ggyNU6KiRvb3PFOIOV7BHpr1PQ+kLaVwha7k+mH
         PzKvMUsS+MYvcqfaa86ukkTwOfQCROfOOnG2TkOR2CQ3uW0rojyI6LaL3OOR166SI1Xq
         P0mW6326pIK87Ynfdub3kja5uz/zkWvm4qbSe1c0lbC4poBAeEnAIJYffQ+u+mAqMrDv
         lG2JhU+82kJg0of/Jo/azsxgI6poSOHDjkSK/LKKlA9nt4fcVCw+cmm2hnZapD26af5U
         8ffg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1XSpvLlvtj4VtScpjrFy6wBiDmzEp6kgT61xywF6hNg=;
        fh=E0y4v5tyVvTKcj6/CrXHB5Z6/5j5ivJUS9F4aWSLazw=;
        b=KtnXmWbVBGmDYHyyU4MYTEcnlf319LxCVcLtUYzBxWBDXnuUgxMb/lkjYHzc49tYt0
         3mvwgZsfSlX/BXztsieGQfNsg9/X29WPu3gJKOeNsKi+TbsTmMWuK3zeSA6gXMC5eMWe
         ZdTogBx/ofGfvK54Zh3bhS+pKiVbNF3LFfyR6WvYkB7TGHBNi7Vpsg7FMwMCapp7J/Sd
         6RScuC7K1/AFATwDJLjzg5IITJxWn2AnuBIEJZgvey3mGOWhsd0r7+ZUoD5TrDLB5y+5
         SjlVQyGb18Z90sHzoQa93qJw3Vbv53La8COhIRlMncpXj7QX0HIi0ENIVHec9SnpkZv9
         ctYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mlt9V43N;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e7d81ebf1e7si23596276.3.2025.05.22.21.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 73D2E62A6C;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 375BCC4CEF0;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
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
Subject: [PATCH v2 13/14] configs/hardening: Enable CONFIG_KSTACK_ERASE
Date: Thu, 22 May 2025 21:39:23 -0700
Message-Id: <20250523043935.2009972-13-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1038; i=kees@kernel.org; h=from:subject; bh=hftQ+JwDBzI0zRNacsurrBG64kHnxlfHAL+GJc3UtlU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v38HyWWXKGX9Fha1ip2xar75gzP/j6q95Jmz43H6d fc3TrsmdZSyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAEyE/SHDX6HNeeWcaw/7rJ2y 6+fW8y+a07ddtX01ccPv5zYrb7rddeNj+MNv+XBylp3fp4kvJqYU+moZvBBbtaU3/mb8VCcD2V+ hfJwA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Mlt9V43N;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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
index dd7c32fb5ac1..d24c2772d04d 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -63,6 +63,9 @@ CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
 # Initialize all stack variables to zero on function entry.
 CONFIG_INIT_STACK_ALL_ZERO=y
 
+# Wipe kernel stack after syscall completion to reduce stale data lifetime.
+CONFIG_KSTACK_ERASE=y
+
 # Wipe RAM at reboot via EFI. For more details, see:
 # https://trustedcomputinggroup.org/resource/pc-client-work-group-platform-reset-attack-mitigation-specification/
 # https://bugzilla.redhat.com/show_bug.cgi?id=1532058
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-13-kees%40kernel.org.
