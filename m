Return-Path: <kasan-dev+bncBAABBBXV4CDQMGQEYAG4XIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A0253D121F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 17:17:27 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id j195-20020a1f23cc0000b02902575e138255sf506660vkj.4
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 08:17:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626880646; cv=pass;
        d=google.com; s=arc-20160816;
        b=cRtFYnIafDnft4yo5SzRaTO2ikbBkD3lJwfMg6t/n87I1OyqNOlnH63P7m7p1nZl7l
         IW148KW3JNqRpoNgRNZdU75HWgks6+pbFLIP2ZBk+LcIGmVWxXhJ1A1XKWhOeJWTM7fW
         qhgmoFAmjikQobJRhO+zerE4GcEXQhBC4ktiSoPIuJujFtwyoGOLqQmqWSSK7OK0PzX+
         YGjb1V+Yqy+FnbvoYV5mK1/SWfwk4qKByyjx4289CpZetiMbwtnoxNIpJfAKIinjVw/C
         zNg/+KyvXhjogxOC8UFZ7cMOcCW2vxVveH9650gBXDe027GLbfMJ7nRYkZnp6JhNUKTn
         ebDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=re9YbOyCOfDxM5+XnYldf8X+RWblysNI5pntQ72DNKo=;
        b=glPGzKLtbzgHOQa6HPeL8wcynEAG3d6lXyEFTdKg797mz0sFxsMPTFTTzjMM6YkYPN
         tNpAUCqxxgn0Cv6K219iGk+wpWyHiUCJQ73jH+5rJuSpnRz86n28MRuDUznpG0Ixp+JU
         vECGXjQztJ5V+hDLnSWylt/mW+VafjBEjoOLVlfb54bxL/hYpKzBfcZRYrtrp7R7hGi5
         UsJy+V5X9ipPNk27TxUZoGI79IJiKqXLZluOgDcZiyQrh8aO4hc+qHV0N4VbHsTJZ2oZ
         88SJ7h9QkRinmm3YAGWTV1gXxJYixQjneSTs8jL1nIHw/Tlr0r3hi4Vzpmkbdz0kYxML
         2mxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Nkd0f/Md";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=re9YbOyCOfDxM5+XnYldf8X+RWblysNI5pntQ72DNKo=;
        b=qc02Y1WWuBppC6bnfo1rkYegEuzaPuWRfMEScBHKTPyjM4KEAt229KLhwu+1eiYv5S
         ZTvyjk0JAeqzkguI+Oxs9YPTIFTwb2+wVR03UhPRCZkIH08C0reUgtAxlwOFQXQfi9pQ
         omNxOFXvqPVWQ4mgaHn28nIHVaNkDiTxIuWttBwrCSx1ho90hvFpWiYUikZUwTE6K/RL
         tC7CYzCRAcj0tlRuRMZNTTI9iiWjbzmSNw82tFLiwUPAn2hmidVTtYAvbwou3hy6zODT
         sxkoMPWYF4AjBb5L2SJUj4btkVNujL7Hv6Lkdh8A633td62+XJTFnMt+rIFhT5N4WS3B
         8XWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=re9YbOyCOfDxM5+XnYldf8X+RWblysNI5pntQ72DNKo=;
        b=Ktgfz89aGRk9zpfAqOF0mm0raFhn2Yuv003r6KsV5MsZbm12ReP1N0sBroEZ0l+HFq
         Sn0xlsW4JRYJHjkhc47AMyxD92YPRG6v3FWsaJpkoT7TUeyegZWcEnWnNGx7CS0+5PHi
         u6qtbvCAcQ0za27B2N/ywmFt04mC6tHWHPAonHOFzIuX1Tj8mz3eyQWESsSH6jjll611
         gwaEb2VrAVivEDBKkrnNKJfzkKZLGZfcjIhhmsAQeXMwGjKet0e2TKIXKe4qdhqIhC3J
         nBVqnf8gn4RiLbbVpHHP4PpXcQTt6hWVeModEGVOttUbgeDbUADYt9SAsf9q0n/UzLN2
         dheg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532tVkEQfIR5KqpKI8lwyF/7D/qmN5BzxTzfp/dgYC0cN+KJSa0u
	y2V1rfzdQI3RqtPDdSK5MkM=
X-Google-Smtp-Source: ABdhPJxAfJUBOXTcBXhS7Ld6MkxlPlsBnbK8KCPxGY1Eo9eFz+b1fl/lOXkR/KihIpPzRQ8F+7bJ1Q==
X-Received: by 2002:ab0:24d3:: with SMTP id k19mr37781928uan.140.1626880646195;
        Wed, 21 Jul 2021 08:17:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:a81:: with SMTP id n1ls661518vsg.8.gmail; Wed, 21
 Jul 2021 08:17:25 -0700 (PDT)
X-Received: by 2002:a05:6102:10dd:: with SMTP id t29mr34567036vsr.24.1626880645724;
        Wed, 21 Jul 2021 08:17:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626880645; cv=none;
        d=google.com; s=arc-20160816;
        b=L7AxZj+OVmz41z5o3iueyp5XXuQBbf8BFUc5zBl6UsCsvWMjXVywg6zOqs6uKSr9OS
         OVwbwGtknF5CoUNKaP88Id4XFrlO+VldOi0Ygwgn2RgaHosJ1Tfb/a563nf/67X7z3fD
         usTWUBCi8W4qOf4qe69scgzZiIefvjUBsBt/Tlo7fnJCtSiLz0oCokZRa3OL+1oaBWxS
         pFmyLyHTQvkZiTYn1l+0cWI46MO5liE1kIis19Ci0o6UJ0maU7YXNzk/+b7+dTIkICIW
         ESVj6RX83BkQ19MT79hea1GBgd3yRWwjbOW46ZWJhNZv5sNj/CDo69CAGDGf1mu8gWAM
         QReQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=x+CjU2X7HWl2mpQjZOW1ScZ9DGFHlS6dtukA3cc8NIo=;
        b=Pg4d3SlTEac0AodBFMIvEWovhLtnBjK6ZZpBW0F/xgaETYdTyM08FmvTDAAL+JxxwU
         WdJflOxqrLcgViC1Oyn5SrApECIXrKYw3cImuRG4GDJr2AbzrPwqkxf26fchUFgDzjhr
         ERZUKUr4BQE6gB17NatDm9T5udSm6cqM0aAClj2F/sm34gNDS4yCc5KysvnBA1S31JeQ
         ILAlm3I4Erc2J/dohfHq5RxnC6AD6U+u7oMvhsYXmuWtHbqN/efobwL7I1nilh+VKKr8
         CkjQaOL/YmtCBUcwpnBBYr2PFa4hJOLO5RiZDURKUctcH3dZqrXY1V70UbibrDUUgBkY
         hxIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Nkd0f/Md";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a1si1693808uaq.0.2021.07.21.08.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 08:17:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 245B061246;
	Wed, 21 Jul 2021 15:17:21 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Mike Rapoport <rppt@kernel.org>,
	Abbott Liu <liuwenliang@huawei.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] ARM: kasan: work around LPAE build warning
Date: Wed, 21 Jul 2021 17:16:59 +0200
Message-Id: <20210721151706.2439073-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Nkd0f/Md";       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

pgd_page_vaddr() returns an 'unsigned long' address, causing a warning
with the memcpy() call in kasan_init():

arch/arm/mm/kasan_init.c: In function 'kasan_init':
include/asm-generic/pgtable-nop4d.h:44:50: error: passing argument 2 of '__memcpy' makes pointer from integer without a cast [-Werror=int-conversion]
   44 | #define pgd_page_vaddr(pgd)                     ((unsigned long)(p4d_pgtable((p4d_t){ pgd })))
      |                                                 ~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      |                                                  |
      |                                                  long unsigned int
arch/arm/include/asm/string.h:58:45: note: in definition of macro 'memcpy'
   58 | #define memcpy(dst, src, len) __memcpy(dst, src, len)
      |                                             ^~~
arch/arm/mm/kasan_init.c:229:16: note: in expansion of macro 'pgd_page_vaddr'
  229 |                pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
      |                ^~~~~~~~~~~~~~
arch/arm/include/asm/string.h:21:47: note: expected 'const void *' but argument is of type 'long unsigned int'
   21 | extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
      |                                   ~~~~~~~~~~~~^~~

Avoid this by adding an explicit typecast.

Fixes: 5615f69bc209 ("ARM: 9016/2: Initialize the mapping of KASan shadow memory")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 arch/arm/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 9c348042a724..4b1619584b23 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -226,7 +226,7 @@ void __init kasan_init(void)
 	BUILD_BUG_ON(pgd_index(KASAN_SHADOW_START) !=
 		     pgd_index(KASAN_SHADOW_END));
 	memcpy(tmp_pmd_table,
-	       pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
+	       (void*)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_START)),
 	       sizeof(tmp_pmd_table));
 	set_pgd(&tmp_pgd_table[pgd_index(KASAN_SHADOW_START)],
 		__pgd(__pa(tmp_pmd_table) | PMD_TYPE_TABLE | L_PGD_SWAPPER));
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721151706.2439073-1-arnd%40kernel.org.
