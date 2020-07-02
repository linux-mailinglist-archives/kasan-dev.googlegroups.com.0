Return-Path: <kasan-dev+bncBDQ27FVWWUFRB5MY6X3QKGQEYMEZXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 813F9211A52
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 04:54:46 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id u13sf2270303uap.7
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jul 2020 19:54:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593658485; cv=pass;
        d=google.com; s=arc-20160816;
        b=PWVoQjhuPttHRU9B/abeyz+MPZKgxC63yeklE9r1X2AjHnGdX/1gUp5cm7KmTSYz0U
         7lnUPQLd18xWpSq/Qhumq5coZveh8ht7ltOwSuWMLYeWioGxt363nkNM0gNLjHxxkXx5
         rFBkrxlBuhvU9e/2iu6L0DOwOjf8aYHkadSnLdqdSx3vF9HNNS4TQWD9MviwUTUql5ab
         iDYxL8jWk5pUAPPppsyFy658nRGz0JQhdswiTmOIiDNm10fBqALuQFRSYEhRFMJhFS1k
         JsusXOz8SXHW8aCvCwooNznLoc1bnzmTeV0wLMkB2TgCAH2jITZSWDrOkt2oFd50ILwy
         t3HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cbggMaMaRDkoBX8O6IOmG+UW1hRcRvMwXWnsRHYc3uE=;
        b=O2TWTwE7ctzr4P04GN17zJbNGmBbeS2bOvP2IJkSXXRZ+EV07DyiNGsF+J1R2OwzxS
         uavGKkO8PNO/ukrKTK9Uvk9HHDkchcezHWJnFUdD2jQCGBvvW9nZTyLm8ndkEIBnE8TC
         fwP3eugV59yn/XRGbN4IPzmrLLoXoW6Fq2SCDWEnD7WmrB78srLyQiW4atjQayr/8KCp
         AWvjR4Z5ysqadLhTswyuQXP1Iw6vXFvyDAX+me5/s1q5LCM7yd8bhEnGVDlj7cE+j5gq
         U6qkqBYL4MMzqAKT2Pp4BgSU3+ScNjqUcDYYXBymxiuEm0P36+dVI6i1kRlCwo1hoFNM
         jmbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZP48jJgv;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cbggMaMaRDkoBX8O6IOmG+UW1hRcRvMwXWnsRHYc3uE=;
        b=FPrioXzke0+mOqvmgX6jlwfzNBGRfL9qc6oX6FDW0iQOnKfZHdvak92ZGTtTIdO+Gp
         RC48qqEPlUbglsHJGHOCr4PrTilTlW0y+y2fjUiT/1k0dMAKoHifdiKLP60rxBQKcZ5j
         L/4HtY3cD6w0uJFRflsYVKjsFWYVWe+shRVcQWM0FEtB0/RLhOGq/hlTKSBHnxhBCYL/
         +kszyPoVFx2d2O4GF69EtIUzn1OMnC9hjYiObR6haiaTu0wpz7R1K4AsiDG5exdsGAQZ
         Rybs5rNZ/6L7O3/qUBHhuwPEYnesQkuoyx2s26zwXtU4DuN52JLTn2Y1muNFvEnsyLZ+
         kh3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cbggMaMaRDkoBX8O6IOmG+UW1hRcRvMwXWnsRHYc3uE=;
        b=HFIKXqkthM3Z+S1uF4iWK6y7S4jM0xNJJUJEyFEoUzTJUcouaUxfvkAS3uGYuCKIhl
         S2hPymphLs63F9IhoZsuaiZknFLZeEn1CWLQNuhu5jsWmxuSZZHn8dYKP5snVUDzDnkY
         4kZpAlkEM92oKkeKxZUW7I3tAh7LLI2heQGTygeL3wfUL5znou2qLxVAQMtTfKn527nY
         0bVB4UKYM0TmJouKu3gaHeOgcqh3tsFm4b5EafopHsRD8iJK7u9/aP7i9aW0KCMD7J4Y
         XE6zHmde4JMU0kcBmebB0H5qI0IQdLU8zYk+kEer3agV89muON96b6sWMa+SUbZieF7R
         XlVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ChYSymqazqfv+xQFLknfJI0sOYZ1B0Bf0JA3StClyQ89qB/Fx
	LqypTNtBwLvfP4XsT3DZ++c=
X-Google-Smtp-Source: ABdhPJw6gU1QkMWK9u3zopaz+F5GLeMW5KjMybDcJNOyq17Rl8yNV/NtQjk6dvY3dU5S3w6LhrDyew==
X-Received: by 2002:a1f:9e8a:: with SMTP id h132mr21170078vke.14.1593658485397;
        Wed, 01 Jul 2020 19:54:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c58c:: with SMTP id h12ls538832vsk.8.gmail; Wed, 01 Jul
 2020 19:54:45 -0700 (PDT)
X-Received: by 2002:a67:ce08:: with SMTP id s8mr10619053vsl.103.1593658485023;
        Wed, 01 Jul 2020 19:54:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593658485; cv=none;
        d=google.com; s=arc-20160816;
        b=YF3K+gK4hXOKcq630IOJMjGCoyPRn5IjsDYnsXAivzyLNEZDqATeVowuOtWXbWtkkM
         J9/6ljX6eL1CLJeKwt0WntDc6oArTlGI1ZYIrS3ER+WPF8c5iWnWM2gBYGC8E3ufoSao
         /mUuL32TsR8skAz7UBfvIns+ea/eTiqN0QR1P4sn5YuqzmPkWO/LGjLBPP1Z0V9DbdyH
         JJ54lNpPawVyntYTnykGr+sa+F9zuheE/nG27kCzZMTlUr5uVV9lhl/qZojK0jS4LvUP
         +daOQz+oY59A2GHgEnFJb7cFkQKNVT7JhqjsbyBy3jTkTur4QdYHfYNEvRN9pfYwZYAz
         8jpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D4Q7wlnC9uinQAfoiYOmKAt3GyYnF0nwS1m28sSQDUo=;
        b=b8zn8nVAElJEaFwzlkxtdew1cUZOToXWUjNtIJZfbB5cnWzi7E48YhkoGjbYZaTCCS
         JVC93KVz/ozXwmbsuom6hYDikMopE2DH/Vp6zaFIPwwzHI3a/sGSpAj7iREYcujnrl7G
         owqeRp3TJfXY7XyXeGiDonKOD3vrBuccYRLq8PX3PX7yHq7rsIBY4Wdnguux3Cd2ojZ3
         duFRY02KIYwkPjJJLA7nWVYwbGK0gq34NGoUhzUXG3J7dX21mtxkXIMCi3SwhvgJfD75
         RQ6qwr5tlxx5xNPyVUKo08ZLpCOnd+LVWyf0jL4mXkGydxGIXWZ++f0drhPCrXxk+zGu
         3Mcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZP48jJgv;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id a68si474358vke.1.2020.07.01.19.54.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jul 2020 19:54:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id j12so11858325pfn.10
        for <kasan-dev@googlegroups.com>; Wed, 01 Jul 2020 19:54:44 -0700 (PDT)
X-Received: by 2002:a63:20d:: with SMTP id 13mr22820110pgc.166.1593658484159;
        Wed, 01 Jul 2020 19:54:44 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-3c80-6152-10ca-83bc.static.ipv6.internode.on.net. [2001:44b8:1113:6700:3c80:6152:10ca:83bc])
        by smtp.gmail.com with ESMTPSA id h6sm7031275pfo.123.2020.07.01.19.54.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jul 2020 19:54:43 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 2/4] kasan: Document support on 32-bit powerpc
Date: Thu,  2 Jul 2020 12:54:30 +1000
Message-Id: <20200702025432.16912-3-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200702025432.16912-1-dja@axtens.net>
References: <20200702025432.16912-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ZP48jJgv;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

KASAN is supported on 32-bit powerpc and the docs should reflect this.

Document s390 support while we're at it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 17 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..554cbee1d240 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures. It is also supported on 32-bit powerpc kernels. Tag-based
+KASAN is supported only on arm64.
 
 Usage
 -----
@@ -255,7 +256,9 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently this supported on x86, s390
+and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
+with module support, where it is required.
 
 This works by hooking into vmalloc and vmap, and dynamically
 allocating real shadow memory to back the mappings.
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..26bb0e8bb18c
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,12 @@
+KASAN is supported on powerpc on 32-bit only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is optional, unless built with modules,
+in which case it is required.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200702025432.16912-3-dja%40axtens.net.
