Return-Path: <kasan-dev+bncBD4NDKWHQYDRBY76SGEAMGQERIQXVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E9483DC12D
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 00:38:29 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id m123-20020a1fd5810000b029025c99c6b992sf1091932vkg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 15:38:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627684708; cv=pass;
        d=google.com; s=arc-20160816;
        b=otEHmmdJuperfn71pxFNsw5imJbN+UO73+2tH8r4qdoU3lAIMZAM97RM3g9jvW1Mrt
         dZ3FQ0IDQ6oTRBVHpq+aguAt9S0N6c3b5Tjf4pgymgdD99eq58kdsHSFhaWApYX7SfBM
         SFq90hbWMnHDBzUUxadeAZDO0bnc91wl0cLDqdBzgQ9e3RV/kaXV0W9VduStr3ipp73g
         1qzg1tvvSrZEoQbxjX9PzGYGUPyRAhqcr1m+Wzt6GdvWdRLpNhYLpO1q5m2dJuG20z3b
         TN5c4FrDsOdpESm+4eBYehaYY7Hw8XURDHwf4XuhiEqzSwkuFlPUhXG47ybTtXWw0db4
         qqgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1cPYKcULJ+9Su+dEG7FDeUsZhpCCWMVoPYdMNRKqTZU=;
        b=ivJi6hIYLeoY/knak572rqH/kEKarqyFy8k65nkOQYbv8WL8ztQObNpYOlhlXnk8ye
         zoCv/9bl8Me89j0h9pDdtu1vxX849tKk4+8c3/H9O6yvuXJGICZ2jfHisiPxRoincqAb
         CnKbPZ5M7kR7TqRKU5DXfLBBN55n/CB3EEUXOgXV6YABWMZDOrHPMLy1l7LfoNwxK9Gr
         h/xHiVo1+RXf5MFBTMnBZxVCWsBG5NVvp4GLpQzlSbNuEbI0S9VqBVXTiwgLVnAejrF+
         jE4L6ekHcOSF70oLaFaPesvBwXpAH0uUdVbpL8ZDwgiMHc+JOHXfnKzZppTVYqKK6i3O
         RNAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CBLwAqSq;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1cPYKcULJ+9Su+dEG7FDeUsZhpCCWMVoPYdMNRKqTZU=;
        b=if8pR3HUkM4p2vlQZY+SDbc8oK4zqWM7WkddiyxASPaTj4Ldu24KxWNZfDkb9GD1R1
         /ARfTu5eA61ewJ5HqObihZ6mNm8+K/PnP5N+hPeBgMQ6TJ8+1QfuQsre8nyFkjD7k1dm
         yK5zBMm95umbzfQZY9Gk/epXOGzTCtNdy1QHZs121TyfRMgAS6wl3jwTA9nsNiISEKrm
         Fq318lKppX6q5QCdTAn0TrSot7O+e8+87SWlTVDujtr7L6+AfyTClKQB0vhIkYZwARAE
         fxf0bzC+Jd/I7iFNZvyboGAHXPArY4XT62L5E5aCfI6a1NC4FZiK2UQ56XCL0CiZyqJv
         DPIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1cPYKcULJ+9Su+dEG7FDeUsZhpCCWMVoPYdMNRKqTZU=;
        b=hhWcwEN5WAbd+rA+/SYcQbtQkaS+sIqWrXXGG5fZhNjmuT8SacDmPrfqlZNodjZD2E
         IvVMThwlwDyWPgGIQTHrKLoslPmXEg/CzEiFd/yUuikIf0vAUHCfn41HZN8SS4oCL6tq
         eNXLdyxy51NTuBjK4T2xf9vwkUqwucB0G7qm5eBX1pIzP8JgpFbSEvh63W5RmPz6n1wf
         eVooDBO+T0zaeAUluqXt7FvbTGV1d7C4ndwvSktw2HP7XijejAq45ywcMfse/PB3Twcw
         XFaiR4juXtQe+dU1iHXxju9GhU1MCbRVpOPcAX0P8kSGm9t/DaL5Vt2Q9nM1xjiGfxkw
         NClA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ThWrN/Y3lTV95VJOOm3YBA03NaUFflDjes9RxV+VCos5Vua2j
	uXN3rIaoMP6yixWcyIhijDw=
X-Google-Smtp-Source: ABdhPJzaoyFimZOgVV0LNxJ+iBdyXh8FDwDB3KLtURH4pBA5Z9xzKFW4MjcUhpoQSZwviSNnUbxvaw==
X-Received: by 2002:ab0:5a0e:: with SMTP id l14mr4849403uad.88.1627684708063;
        Fri, 30 Jul 2021 15:38:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1527:: with SMTP id o36ls433647uae.3.gmail; Fri, 30 Jul
 2021 15:38:27 -0700 (PDT)
X-Received: by 2002:ab0:7455:: with SMTP id p21mr4860879uaq.73.1627684707577;
        Fri, 30 Jul 2021 15:38:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627684707; cv=none;
        d=google.com; s=arc-20160816;
        b=mn2A9I7TjvRhNsZ6w+0OsZAlrSHdC+inWpyEQjrbZuPZtjcK2OKBdprrSY5ftXh/pP
         3GuVF0O0l3H/XKgR5jlAqYmiVh1rdt1HSP5zISY294x/bXc/lnq62tTZrfDOFsw6NA8A
         Bg61436kdypIjlVIBUMHIiaVBnSsW3l9pRpzV3wPsoGFvUecsR/a4w0egvzRjxNwqN8G
         8l2lM0jcWnCfmvaHi1g8u8mVQKX44FDAmjVzIPJlYT2YZDCbmleiZMNb96+9ozppKl0Z
         Qm4/qgVhZ+6SgURMNdZpuA3E5XleQzBCi0pCSleI9aOuDGsPZsr7YQTUeO2tV7ozdUak
         G88g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=fR3YoTsGn10UoLhjKnWcrXTpAUviMKq9lqUMnVNwz2Y=;
        b=g3LVbX3bOd3wfAe3Zi8xjiIMyjEHNlIBYXF4aCj6DQu+JH7WHzaQhyu6XA1qY0THSB
         nShZ0jfcx3jzBnro6RNR2aI6SnnwOgLAFOGByahN33RUOv1Fq3B+hXnrGSjj4tE5UmX/
         KQrpNK+XJdpbp7yC7luTFRKWv8ZFYqMUviJklzYxdx9E3q5p6g6BtPhPKeSp/W3HY//j
         CA6CmLwaMQAfRcX5Mdiz6dnKHIbGqbtxGHerNg5l9+FCrY3nc/kvK0T8wyToZI/+wPx3
         BAfQPGUxpWc7R3wv6U1Pxu6ISETtV/Hc6KU9sTq+1B0ZMHYH07NbTA+/r3Ve6BYmPXwL
         gEDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CBLwAqSq;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f11si203265vkp.2.2021.07.30.15.38.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Jul 2021 15:38:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8B00660F42;
	Fri, 30 Jul 2021 22:38:24 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
To: Kees Cook <keescook@chromium.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Nick Desaulniers <ndesaulniers@google.com>
Cc: Fangrui Song <maskray@google.com>,
	Marco Elver <elver@google.com>,
	linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	clang-built-linux@googlegroups.com,
	Nathan Chancellor <nathan@kernel.org>,
	stable@vger.kernel.org
Subject: [PATCH] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
Date: Fri, 30 Jul 2021 15:38:15 -0700
Message-Id: <20210730223815.1382706-1-nathan@kernel.org>
X-Mailer: git-send-email 2.32.0.264.g75ae10bc75
MIME-Version: 1.0
X-Patchwork-Bot: notify
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CBLwAqSq;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

A recent change in LLVM causes module_{c,d}tor sections to appear when
CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
because these are not handled anywhere:

ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being placed in '.text.asan.module_ctor'
ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being placed in '.text.asan.module_dtor'
ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being placed in '.text.tsan.module_ctor'

Place them in the TEXT_TEXT section so that these technologies continue
to work with the newer compiler versions. All of the KASAN and KCSAN
KUnit tests continue to pass after this change.

Cc: stable@vger.kernel.org
Link: https://github.com/ClangBuiltLinux/linux/issues/1432
Link: https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3fc08a59a01865
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
 include/asm-generic/vmlinux.lds.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 17325416e2de..3b79b1e76556 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -586,6 +586,7 @@
 		NOINSTR_TEXT						\
 		*(.text..refcount)					\
 		*(.ref.text)						\
+		*(.text.asan .text.asan.*)				\
 		TEXT_CFI_JT						\
 	MEM_KEEP(init.text*)						\
 	MEM_KEEP(exit.text*)						\

base-commit: 4669e13cd67f8532be12815ed3d37e775a9bdc16
-- 
2.32.0.264.g75ae10bc75

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210730223815.1382706-1-nathan%40kernel.org.
