Return-Path: <kasan-dev+bncBAABBFEI4X7QKGQEUHE6D3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AC4FD2EFE18
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 06:50:13 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id x25sf7308334otq.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 21:50:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610171412; cv=pass;
        d=google.com; s=arc-20160816;
        b=JKj3+N8pwisLapKu3u0X/K7+N8kv0KsSqXPe29mp0DmR54RjNotCIyoyN2TgFxVMbV
         jj5MO/wb4a74nhZu+kLzWjd2jisj4QoCSKQ1AZ2tRZjTJKRlUIyPrGrmML16mAYVXIOX
         LMPTsaZrDqON6ajowIgEfb69WpprNxrbcprqnZNF+KKa9nGgepXbsiti7s0hduYz3nUR
         7965RbO0SM5TraNMwrouOp6XVGWYXOyWPoKtdJOtk1pTqhgkZ+9cAc+DBzr7LChuIWZl
         +nH2DlX7OslWcps7yok4i1W+Osh8/GwV33Gvn7Q2UnkImLj+t2VAp57K/1XYRApfCCGV
         PPaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=j1WsMVY87tJ+8NAqKBsYIHsQlx1jGrAMFyDnWPifuDY=;
        b=knuHvk32TDNFnPUojOZCv9vDE4GZhLLDakThX4QC4Qb0wShhzV+Gv33cvhXjy67j4O
         kXR7+BODxzwrb22KuE+SJ/KmMC4NjQerDkCFeiDy5KmSRDvY+fBi0M6hC3yUEOK5p18U
         WdlBdWdFbAOoGmuGwXYrON9KWbR2DbLVu+fxL54H5JocNw/HoyUXcGd3Ju5r4iztrInE
         rUKX1CtUumpY4HNSmUMwoNp6bimQjAiVL8mSvyC20h3pEDr8XHemyVT4VtTA2sWbXMgp
         +VzmTYYGL/3DcrqHlhaOHkGLemyVM0aQ1pXZENwrEN96gI6VJTHUkpOJI3z1+YF9jKna
         CVDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@yeah.net header.s=s110527 header.b=JViLdV3k;
       spf=pass (google.com: domain of hailongliiu@yeah.net designates 123.58.177.131 as permitted sender) smtp.mailfrom=hailongliiu@yeah.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=yeah.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j1WsMVY87tJ+8NAqKBsYIHsQlx1jGrAMFyDnWPifuDY=;
        b=XJdwUMyuj2VN5D83yo4WT+ndio50Q70hotRfuNGPw8S4Prh4izRCwPcMietDdmPvZ8
         LaYvkmrHFGXWx06QJmaK9eaV1Xqlj6glLQqKM4xVZKsYs7/jLjRnxzHR1+32x45/tHCx
         bP7eymOjOSaMF0ocZ2QTXiYZKFP18uGctF9xt/tTt5rvigiMdBsLVY/9L5j/8KSsQhQG
         jXuIh9hDBPv95ZTfertHhiyoCalEIUCYEoYJ3CgSbgSmyWLN6xZflVbBixLQ12EvLNO8
         AXBGXnTkxQtXHhELIrbntJDqtaVUJi0jNCEh5mqpnM4wobTJVZUQf9kWyXNv096Kq8Nb
         V/hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j1WsMVY87tJ+8NAqKBsYIHsQlx1jGrAMFyDnWPifuDY=;
        b=BcQhoCGsNbKLaRt2XlOvvgoRruaxNxAW0eDziXMiEkvWNye4Dh0q6cuJ/Bac6vlxiT
         jnrzWqQzKC8AsLGGiQv4cadrnFTZuL7i6apGTrPx/wxhTgvG6A3ENwg1nOQa3g4SSH8M
         DiwZzbqvWxS7Pi9yXG0QYsJ7P5UCH9cTwL9NH5HNW+Z/RLKb+aXYsd6z+igMykVuBLQj
         7Hh+tyF96BcrMo/TiF4ApmsWWa3Sd04PeZzNoKtNgbcjulenBe2VVmgG24gd5ICCSxQc
         JJJtphmdIMzH3J54XABWoVkE0U/WkeBVQH4H6Qd4xoAkJqLjOlQsOrugzRLkdCjax1J8
         Ee5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OGIzP2FJTes9KTLu6yOoXgOXkn0+icGF57Ec7IxnDjf2SOYiq
	n8KOItYX9JrAce6uPB6qYKI=
X-Google-Smtp-Source: ABdhPJxd+AQ8vGuEkyMXGQkG5MbRoJNxYpdebk/KF9VpbL8zz1rDT1V6srw4oRl/CI5lR4FX6oU2Dg==
X-Received: by 2002:a9d:4d05:: with SMTP id n5mr4947393otf.99.1610171412714;
        Fri, 08 Jan 2021 21:50:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:758a:: with SMTP id q132ls3454372oic.4.gmail; Fri, 08
 Jan 2021 21:50:12 -0800 (PST)
X-Received: by 2002:aca:3bd6:: with SMTP id i205mr4407147oia.156.1610171412441;
        Fri, 08 Jan 2021 21:50:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610171412; cv=none;
        d=google.com; s=arc-20160816;
        b=h2dTmb3wjDrBMn1d1bngR/C6cTLF1sR0MTJfhe36FChcveWbzwnzIBpaN9CPETqHvk
         gCVRdttqeWsavdNjtlB73SInQIQISLiKLmQntk2JBn2auApkdZT4U49Y3IGBoE9hUQDS
         9vfjHPeC2ahAjH2GR9jiuShNurbQEeOT585hp98HyUv+5orYvuXtb6WTVvDlQm05qlPY
         zrcQg/auE7iodbJHYsFR5Eo5Vub0mvhxCAWfHY7L3LrGxzA9HJJuTFKqun3ibg86P4Z5
         mscYkEHtpWKagQPmMcYt7YBbKsL263GbJ4pwwJtV52M+1dRnq/k2PtRmFobEZ+ce0cF8
         dAuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=zDK7a7BMsR406vQhn8yt5kdzH5+TBL67jk5gCyRgOb8=;
        b=Ua/tS59BsVZ57VoSETKGGBIClgi+sEAa1MJsp0EQVPwMYgLYfmkk8z4kuoyDfFNPzK
         22hEW/zaefwEKTOT+2ulYzh+VejQwmkn4w7y9GqMKWesLcC+G2Bm0LTuMOLtvfu1yfl+
         G5YZg/W1PlaxDmzpdMap5TTaS1PJKjJkteaGim7TtbkyATKX8rgNJuNBvr0ubIZQUL/r
         eEXbSs+0MGPUZhxHE17GYpjimm4LrxKhDyhetO5LTKGUOveWP6Mgs/hBFpXlRavfsrAd
         t5sa7K/zjS06Sl+hVh2hvXXUP4HbIWA2mae5RAT9ceAizIsvoV2upXzJIQYUv4H3d+AB
         RF0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@yeah.net header.s=s110527 header.b=JViLdV3k;
       spf=pass (google.com: domain of hailongliiu@yeah.net designates 123.58.177.131 as permitted sender) smtp.mailfrom=hailongliiu@yeah.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=yeah.net
Received: from mail-177131.yeah.net (mail-177131.yeah.net. [123.58.177.131])
        by gmr-mx.google.com with ESMTPS id s126si911575ooa.0.2021.01.08.21.50.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Jan 2021 21:50:12 -0800 (PST)
Received-SPF: pass (google.com: domain of hailongliiu@yeah.net designates 123.58.177.131 as permitted sender) client-ip=123.58.177.131;
Received: from localhost.localdomain (unknown [117.139.248.191])
	by smtp1 (Coremail) with SMTP id ClUQrAA3PHhEQ_lfmujYLQ--.64199S2;
	Sat, 09 Jan 2021 13:46:46 +0800 (CST)
From: Hailong liu <hailongliiu@yeah.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Russell King <linux@armlinux.org.uk>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Hailong liu <liu.hailong6@zte.com.cn>
Subject: [PATCH] arm/kasan: remove the unused code for kasan_pgd_populate
Date: Sat,  9 Jan 2021 13:46:32 +0800
Message-Id: <20210109054632.9399-1-hailongliiu@yeah.net>
X-Mailer: git-send-email 2.17.1
X-CM-TRANSID: ClUQrAA3PHhEQ_lfmujYLQ--.64199S2
X-Coremail-Antispam: 1Uf129KBjvJXoW7ArWfuF1UXw13KF4UCrWUCFg_yoW8JFWfpr
	ZxZas7Jr4DC3Zaga9rJw17ur1UA3Z3Ka45tw1qqa1Fyry7WryUKryUG34fu3y8GFWxZF4F
	v3yFqr98Ga1DJaDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDUYxBIdaVFxhVjvjDU0xZFpf9x07brYL9UUUUU=
X-Originating-IP: [117.139.248.191]
X-CM-SenderInfo: xkdlz05qjoxx3x61vtnkoqv3/1tbiGAYV6F6NjfRM7QAAso
X-Original-Sender: hailongliiu@yeah.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@yeah.net header.s=s110527 header.b=JViLdV3k;       spf=pass
 (google.com: domain of hailongliiu@yeah.net designates 123.58.177.131 as
 permitted sender) smtp.mailfrom=hailongliiu@yeah.net;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=yeah.net
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

From: Hailong liu <liu.hailong6@zte.com.cn>

First, for arm architecture the pgdp is always the same as pmdp. So if we
alloc a table and fill in the entry then it will be overlay later by the
kasan_pmd_populate(), then there will be a leak for the table alloced
kasan_pgd_populate().

On the other hand, pgd_none() always return 0 for arm and therefore this
branch will never be walked.

Signed-off-by: Hailong liu <liu.hailong6@zte.com.cn>
---
 arch/arm/mm/kasan_init.c | 15 ---------------
 1 file changed, 15 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 9c348042a724..f0e591f7e430 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -126,21 +126,6 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
 	pgdp = pgd_offset_k(addr);
 
 	do {
-		/*
-		 * Allocate and populate the shadow block of p4d folded into
-		 * pud folded into pmd if it doesn't already exist
-		 */
-		if (!early && pgd_none(*pgdp)) {
-			void *p = kasan_alloc_block(PAGE_SIZE);
-
-			if (!p) {
-				panic("%s failed to allocate shadow block for address 0x%lx\n",
-				      __func__, addr);
-				return;
-			}
-			pgd_populate(&init_mm, pgdp, p);
-		}
-
 		next = pgd_addr_end(addr, end);
 		/*
 		 * We just immediately jump over the p4d and pud page
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109054632.9399-1-hailongliiu%40yeah.net.
