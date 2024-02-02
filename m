Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDEC6OWQMGQEWV36UTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4528B846D8E
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:46 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-36381f0e0a6sf13420885ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869005; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yjjej090mlftRwuoS82QYFNMtJaYyyHs65a0bwJlPE/InxkALsD/Ybh16Yp/bk0WoF
         dSBmQa9IGKophAdRSbSWeKzVqu2DwmUUs1xkI9INArUmwQ1wExkPaEjp1JKH6CnMuBtX
         3j1bWX2ixmKz5/0FDwTBsFcfwKTiGSyfGbS7j/jwbPW2CqPRoE3tg8Qfghptd0hiSztA
         feDHKrpvza2HDR1cNaZM9JKP5ABBxQsBvnzo489gIXt5/8t8mYP1yYCRKYqa9yXMqiy4
         MM8KsIZh3MA/MJADvBxiC4ZRlzBctTvVl6h3bpCoVtAq9rzHdNH5t5sE4gu+e+JbEfk5
         e4og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=idpua571Z/RyxJdhpG0d945dyewzE+8q1du1iUvKj0o=;
        fh=LzZXYqhaV6PNk38EayPCv88tiFSPjMIVqsdLpNeAzNc=;
        b=Oxtyt5MzpTXbAUXJr01NUmC2pMibGPbWhh0L8fB5fepHEfbOy/DYh+gLxibEi5Wmht
         CyYopBTBzlHaLAGPUwwKcMlwTyYt7dO9LEw+/SNvSWIZGljxozqi5uC6FyNgM+qKR14W
         4Tmcy3H7lsH94qUAflOBT0+74yop3OrBg/VKfS2wIGZ8XqVV+D6+X+cYmLKefx1zsSos
         rLhCpuitcEZfPtxSPaB44bMXYFeKaIdPiIqfMhevfavwTX1b2O3WrXw3lI6UjIRaDaZK
         OpwmG9F9se3CgDor2nNmPO9Z/CwwgFwAe4mIo98LfEUQmAoRWGfO65NnxWNIDowgnLYB
         /WQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iFqTA+7q;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869005; x=1707473805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=idpua571Z/RyxJdhpG0d945dyewzE+8q1du1iUvKj0o=;
        b=ucHuLP2UguPWe7Fjp9S5W7Ckv62tg07MUVdcvRJNKhk7nrwFn7N3BmwVeb/iukshdX
         HhpKRJMV3KJ5nrpHpnj90cwORANh2O86F+Ize7IH6nRrGWaoMMHJ4LVnovJvvSe9/w+w
         vPbshPwkFxUhLZzpQkqTykDZDxzppkR28HWZq/+xvBzKsGOgf4JcnbKXg9hcZYqPE6I5
         KJEb51PcrEtqjpprjLAk85FO76z6FyFBsnlg1QNCHG3W4Fr0pevL2I7gyydiBN6Cm2MD
         QBS68k1W8a3d2kQMg10JOBygsFGkLCFl0l1UzsLciXWC7fcYdEWBsEByuhYBx/ecZEkY
         CdQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869005; x=1707473805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=idpua571Z/RyxJdhpG0d945dyewzE+8q1du1iUvKj0o=;
        b=tqA7qfgOIdC3tLd/2M8DbYiv2EDdd3MEd9bjY8veAM6uTaTQ8RTar0+s2b9VFJO6Lv
         8qC3OAjbRlavt8oa8BjuPlGlxJ9kqlnRWghYPAQU1R8p5qn+526yFdAPPlMIGKmHCiWE
         6Q/IA04oBT45OypQKWpC8bS+pWqhtiERXQ/TFdmjUzvphuEtKBldsx7xJUm95wgAr7uW
         4BfRkTXO3WrvQnWmKFDzUgkFv21SjuppOtaBnMmb3SFRdfGnzUg9e+T2V1Ml09SyM71W
         SN+lKqJEB4GT89fhMHWYXScMCZu9FD3RF8jiemaZhXElwP0mzqQXuH7zr4zmomRobn+2
         oNHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwshNyqHFBWOcXEnO19vunz3VKwu5tH38OTw4qEUHZeW4NZ9RuO
	Vb23UeMc4otWahAgfcCxOof6HDpwlEp6FPvnSbIo8GLr9D4VsJFa
X-Google-Smtp-Source: AGHT+IHVVs2E64tRbId0Adly8/fFtlqgpAIAH4mbjeoE+iPnOPrYbKT7+80KbpGNPsSQhCEJNQeFIA==
X-Received: by 2002:a92:6811:0:b0:363:812d:d6a6 with SMTP id d17-20020a926811000000b00363812dd6a6mr8208929ilc.3.1706869005006;
        Fri, 02 Feb 2024 02:16:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3006:b0:363:7733:5749 with SMTP id
 bd6-20020a056e02300600b0036377335749ls324160ilb.1.-pod-prod-07-us; Fri, 02
 Feb 2024 02:16:44 -0800 (PST)
X-Received: by 2002:a05:6602:2bc1:b0:7c0:106c:67af with SMTP id s1-20020a0566022bc100b007c0106c67afmr7831759iov.14.1706869004225;
        Fri, 02 Feb 2024 02:16:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869004; cv=none;
        d=google.com; s=arc-20160816;
        b=spFNRqLRhas39nrRT5TCFQj4SOFdjsgQqW7fAhGfA4WfByV3Y8xlX8stlf7pWPC4ZO
         hLwSvGuFwxLmfFkiqxaUQ+tJHjBx59l/zgIo7E589HaGY682GWf/RVgocSx8xZTQ3/ig
         ojg9RxTesfaFkiObslNhXuJ1ShbECD/vh39Gi8Yr1mfa1G0C8+uOMwo3HZ3nvQcCI4r9
         8td898DgrQschp/kDmWho+vQZL7C1FIW0HU+pPnoStfoR2y2E5seFOJb8M5KRq0SDkWT
         DlzaOVEbQmGaz/sTQbDWKUvQg4O42kUfEBw91BrCybnptKRbUY7R8LapEc5x23wqBu7i
         GQ5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=6EHXdAThkGXTR3eJPl49+AVsRbrPUkQd45PvGXZEUlI=;
        fh=LzZXYqhaV6PNk38EayPCv88tiFSPjMIVqsdLpNeAzNc=;
        b=EVgdxRSs2sMckJ9/xpHg5YjE5zD370sDZ1urDme3CLEOe+FrLxz0qONxc0qp1KtNCi
         KkvYLVYfV0Su0N/gd36PpVF8rXkb2yiLahr61LZkNRcNZQhK+F9iCnDcPYCpHyRfuuIp
         bfy72swE456uGNgm9W60kwroaMkhPIMVmre3TC4CMJM8QdMxg8UAZK9eCRPvwfVGv5b/
         v9jW73H075PR0OpqmwvT07/v8V1XCjWaJEowgYbvl3eejIQrBdlLIDORY3FlpR0fXSc6
         IDQ3g/9xx1KetWlvHm85OYMhhX7cNCaNByqLkFIanIGwy4xO3e8x8nfLasblo37l/lW5
         K3Hg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iFqTA+7q;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCWqHdcx0EgNZD7Oo/BUKFuQC5gXUKGejBeIZnEp+pEXInlYiI4EZP+9+xJGwhhtEVpRZlIbUcq50+rfTjXFsulreaSlLHrQf5oYpg==
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id q11-20020a056638238b00b0046e5105dd3esi153296jat.7.2024.02.02.02.16.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:44 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-5dbd519bde6so1625077a12.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:44 -0800 (PST)
X-Received: by 2002:a05:6a20:94cd:b0:199:c9a2:fb0 with SMTP id ht13-20020a056a2094cd00b00199c9a20fb0mr8667691pzb.16.1706869003557;
        Fri, 02 Feb 2024 02:16:43 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCWM0evwmk61ML9mKlP7sQqZt4NIu2CDf4tNN7ZfZBwVop6WGktFTrN8OQ6otbkJV/lVl6pxcL/V59G96BahEDFx4D7uY4o04C+92sAr/f+65Vbvjtnyg2OPcPHZOyvi6dhxH+kafSvPLJ0gPpvBuxExxguupg7UHSjrbBnSuY7diqz3XRNyLJLE+k3NrKhDBQVfDkjSCPv5+IPi2tsC4kTfC8bHtbQ9Ds1QNM+OfHrrAG95YPgJkHok9YDBlFI2yp2omYAuCblWCU4E8xsjCg4uDuDPIrLsHiSO/YSQ877+xeTLG4We7BgzltdppTfhDtq5LoXEOHmAuGsaNV44gP/1OkY/j2EKxPna1dwhxyWss5i11x9OKRpqTatFqLO9bRvuZjNP5JYKnM70Ypx/DONZf56mG3Z/X3xbiG9mWGOrrlhF8VkWCvK/2DlLipi7xDyBvtYleNfk9SMbxw2SILv94Pjffr/mFJybLlIBEQVzRFgY1Lzh5lWQA7tomI9J5O+hbVp6srbBPr/obebIVCKkQqaan6RFPi81BbO8TUbrbFI8LUK+uytdppF3tBQ/UWgWGYhbMHdL3uarjfDfTC+h/5sXe7a55tsWq4g=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u26-20020aa7839a000000b006dde0724247sm1273062pfm.149.2024.02.02.02.16.42
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
	Bill Wendling <morbo@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 0/6] ubsan: Introduce wrap-around sanitizers
Date: Fri,  2 Feb 2024 02:16:33 -0800
Message-Id: <20240202101311.it.893-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2894; i=keescook@chromium.org;
 h=from:subject:message-id; bh=2l9nEKso4+AOWcpX8WNY7A6dHeDCfYN/6uhOB8hks2s=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEGR2w/jDkKre5GPT1/M/XftJt/c1PyB4wL/
 haxlFPUi1KJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBgAKCRCJcvTf3G3A
 JtsCD/9zn8FXQvcFAIIQgYZmbnBXO2DwIbRtXhGNbq2Nup24+qU2V23CPL1rxaHKDC/EiJJEnKb
 e5BpVrssi1sNVM0eT1gSuZh3+Fe9MuSkT1qu5cuE+fhykPOt7JYBmAot97DhLNGpbC4Wh6wS2Gm
 zt9zRh7VdGjswl0SiQQT3Ko7H0hMo+8Du/2ufEy3yiken9zj1VMMJ1KoVnxpVhaMUra5smuX5fZ
 xfIadzk4bYAjWidY713+WT72pgRr7qsh7cHstL2GUq2+nI0GL0j6nmtuhPKMexyPaOp6rTzXwvb
 Z7GBANHBt9W7RFT2e5jxCw2iSyb/9aZQDjTzC7dGQNytXEvHnP+Phzhj7xCmXOuITiwx70ObSXS
 ME7gGoLJ13vK/Z1MOOR4KUNhbNwuaGi5yPooFb0xcsg4KnCSY2MOorFK9WWpu/OjmWo+DxUMEvR
 1J/KCnkcS1uyoVLsNj2Sh3VJJfz2UhtJtuwtqbFW43Uy4aaj00q7AmQ+NDje2eWQ70R0R+2XSMI
 ndQHgrn7bxz13hk+ym9Je7oT6lJtEH74ncnlLRyN2B+2wk61/16LUCxqpP2Qjq0ZUSeYdi1IICL
 eEpdx3A5WLH/w5PScFuSOwRUsIvtR3tCIgLvj1N4YRLGfj9EYX2DFA1VIUBOXReGwVa9kHKDz29
 jIcc1AN WIb7pOrg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=iFqTA+7q;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52a
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

Hi,

v2:
 - improve CC list
 - add reviewed-by tags
 - reword some commit logs
v1: https://lore.kernel.org/all/20240129175033.work.813-kees@kernel.org/

Lay the ground work for gaining instrumentation for signed[1],
unsigned[2], and pointer[3] wrap-around by making all 3 sanitizers
available for testing. Additionally gets x86_64 bootable under the
unsigned sanitizer for the first time.

The compilers will need work before this can be generally useful, as the
signed and pointer sanitizers are effectively a no-op with the kernel's
required use of -fno-strict-overflow. The unsigned sanitizer will also
need adjustment to deal with the many common code patterns that exist
for unsigned wrap-around (e.g. "while (var--)", "-1UL", etc).

-Kees

Link: https://github.com/KSPP/linux/issues/26 [1]
Link: https://github.com/KSPP/linux/issues/27 [2]
Link: https://github.com/KSPP/linux/issues/344 [3]

Kees Cook (6):
  ubsan: Use Clang's -fsanitize-trap=undefined option
  ubsan: Reintroduce signed and unsigned overflow sanitizers
  ubsan: Introduce CONFIG_UBSAN_POINTER_WRAP
  ubsan: Remove CONFIG_UBSAN_SANITIZE_ALL
  ubsan: Split wrapping sanitizer Makefile rules
  ubsan: Get x86_64 booting with unsigned wrap-around sanitizer

 Documentation/dev-tools/ubsan.rst | 28 +++-------
 arch/arm/Kconfig                  |  2 +-
 arch/arm64/Kconfig                |  2 +-
 arch/mips/Kconfig                 |  2 +-
 arch/parisc/Kconfig               |  2 +-
 arch/powerpc/Kconfig              |  2 +-
 arch/riscv/Kconfig                |  2 +-
 arch/s390/Kconfig                 |  2 +-
 arch/x86/Kconfig                  |  2 +-
 arch/x86/kernel/Makefile          |  1 +
 arch/x86/kernel/apic/Makefile     |  1 +
 arch/x86/mm/Makefile              |  1 +
 arch/x86/mm/pat/Makefile          |  1 +
 crypto/Makefile                   |  1 +
 drivers/acpi/Makefile             |  1 +
 include/linux/compiler_types.h    | 19 ++++++-
 kernel/Makefile                   |  1 +
 kernel/locking/Makefile           |  1 +
 kernel/rcu/Makefile               |  1 +
 kernel/sched/Makefile             |  1 +
 lib/Kconfig.ubsan                 | 41 +++++++++-----
 lib/Makefile                      |  1 +
 lib/crypto/Makefile               |  1 +
 lib/crypto/mpi/Makefile           |  1 +
 lib/test_ubsan.c                  | 82 ++++++++++++++++++++++++++++
 lib/ubsan.c                       | 89 +++++++++++++++++++++++++++++++
 lib/ubsan.h                       |  5 ++
 lib/zlib_deflate/Makefile         |  1 +
 lib/zstd/Makefile                 |  2 +
 mm/Makefile                       |  1 +
 net/core/Makefile                 |  1 +
 net/ipv4/Makefile                 |  1 +
 scripts/Makefile.lib              | 11 +++-
 scripts/Makefile.ubsan            | 11 +++-
 34 files changed, 278 insertions(+), 43 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101311.it.893-kees%40kernel.org.
