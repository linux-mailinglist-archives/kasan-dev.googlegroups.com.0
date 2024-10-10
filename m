Return-Path: <kasan-dev+bncBAABBIE6TW4AMGQEHPXDY4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB9E9997B7B
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 05:50:57 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2878304b155sf1209371fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 20:50:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728532256; cv=pass;
        d=google.com; s=arc-20240605;
        b=eq8vGJ5gEiA+w1kbosW6islnx+0Y1rO+gCtxXKraEIKQVFs7vJxqRh093isShK0Qbi
         LOT474yQLx3U3vCxRnuI6TtW/ghyOQtVkUyvLG5Of9gOMfV/0S2DmYKhk8MEyqEjLzyq
         6DLbUEYVdmknIyWhMkTAWbBc3OHatBEsK3SBcvXblV5G7BagUi7rEvb1+Fi0Iu4mVbsI
         QTAw5pGuPXmk4xwfoPdUOwNLGZvP9V4mlcJ1rQ+UL3fDBcdzRdmMSm0n0sLYZiKuh4Nu
         8sKuaHtL1JV0b5hhLER+hQvjUnegD1gsPaEkTxpZZ2ZISax4OKq1i9j47MDs9E+96lCz
         1liA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oqA8gVobDUkBil0H7aQECGIkvpcO0lDoCnL3QOvCpwI=;
        fh=ql9K20nac2SI7JqykKqJLFIo631FzQRnfQCipln1pLA=;
        b=ZmxAcetKB504xkuKoGlK/cgtR+3E9cFeviqn0lXzPOZxqLgdsOfjHPpgVfMLO6h8JV
         1jc1rVrPz2ROYf0krsKrV0baxWpDfigQjBF22snfajGzpj2zL1IMwwP+/LkT6E/jCWzn
         /Bl3O9JeGFinXvtOB5YPhygybnxybiZsUS0voUEbLOt4jXtAESkrdUlaDWc+Qqy9hg3f
         YgTzZogtrXnw1NPcEeeIUh8goh7RFiH6X68qOkjIkgFHQOk0rZT5TeClItl8l/PNDt97
         xX5MsXkY0ZqQXMCNrl2GF2SKI8ya1G5Qd1N8VqGvyDJHgX3LdgRURCECzWScQ+O41Np8
         79hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728532256; x=1729137056; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oqA8gVobDUkBil0H7aQECGIkvpcO0lDoCnL3QOvCpwI=;
        b=iKCvs//GHSb9MZd1wdHaMEphJmvmign4QJCzx+54ov1lA5fxWYQRthtgEIv/dE3UpF
         USsAIekpbUUprZjloS6usInGOj1Q3LR0DzPw3r1okgNImEOSUkmgpbYya7PHh4yE1lt/
         KCLEOlP7mfqW7VBoagm+FNRSdTevFR5CEGpBV0J0exD5isEoo0OwcjBsejgFMt8jVWXH
         sDjsv9ni8gT2o3zz1spBsLdDpTjZ602nemnnvxYY+sgvP7vZYUU2KnvTPh4Hcf2Dm9Do
         Ypwkoik2ecLTk9RPepBepiimW1tvMl3IgzHB5ajA1VdvNM/cZ4se8e6ti2PfXEpdEMCS
         1e0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728532256; x=1729137056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oqA8gVobDUkBil0H7aQECGIkvpcO0lDoCnL3QOvCpwI=;
        b=Wd9KpAjVfzz3JEbVO76eoLu1NeH22IZQ2HMW4BnsgL/uHppNCVaAEEAuM9N696vl4f
         FTpBG3B652gtJYVh6U8/XIsoervPH/rVejX6EMPLpJmR9HRS0NsvxPkqCu54lTDyKQgQ
         6gAnYU3KIpp41ohtWHkmQHNerKkyjkf9hLXk6oIM3kKydLJmF+WXkPHiNXkksE+c9lc7
         7/MkIUFMspibcsXRYl6iAtDyCKZwcARGBCRG1ocHT/Vt9m+z0r3vaMjS/rCuaur1gHoq
         voHGlZm1k0GNZJgZbo3rK9bfmlbqxNbw/dFaFVRZPJD1gqqJpUEkd2n/H9dGMyhkMzwD
         bggA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOqnaF/aS+cEUxnoFkX0is+jKd+ERV8guQhC4bqcL8AudCUZ/pb3oYDiigOF0N+1LsYLIvDw==@lfdr.de
X-Gm-Message-State: AOJu0YzVLvEh6ASUqsCLdspxkbzNsU/b0+kn9+8YtaF4veiQSBlZU/Ir
	gAAvxsg3dAo5czyXTJIyBhoKNcxz/0tiHqawBtLjoPv1XADGlOr8
X-Google-Smtp-Source: AGHT+IEK/hxlB/mtkxSODJ/wgBv8f3SfAVHCmPoj3r0cxtvQHPnIvWfbfMShF7vCMMFCcDErg75mZw==
X-Received: by 2002:a05:6870:c093:b0:254:b337:eeb5 with SMTP id 586e51a60fabf-2884d4e0830mr1334196fac.18.1728532256184;
        Wed, 09 Oct 2024 20:50:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:728b:b0:25c:ac6e:8806 with SMTP id
 586e51a60fabf-2884dac6ccbls199326fac.1.-pod-prod-00-us; Wed, 09 Oct 2024
 20:50:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVO5wAmzhIvgdMDBodh4kdGdncRweIxRzvUBiwfWfd+JykUMCJp9V1A9rOKEknDkaJe4BXfdNbBceQ=@googlegroups.com
X-Received: by 2002:a05:6871:4314:b0:288:4a73:1fe6 with SMTP id 586e51a60fabf-2884d531baemr1462405fac.21.1728532255062;
        Wed, 09 Oct 2024 20:50:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728532255; cv=none;
        d=google.com; s=arc-20240605;
        b=UTdXQ18Gww9Gl96x9r8TgkeUZdlZxZrRcEYBaInsP7fUb4l7ykbv/aYcGSf6RbixMs
         2eJkCdZUYI3MxvhWJgsxjZ8T8es07OwIzspPsR8We4OI4n+OL5aeR0cpsBW32RbfVN1e
         tDpwJFTIuiPb1pJvwjxviaxLKIspSl7p7ECR/fdzj8TW+tjpnW0HpBt9OaEB2ysMjoV3
         qYQ7eID9zuozikoyJZVvfvINCWkEU65gyqHqE1+vpRwgTVhThOQtuh08lYcjGGbHmIQc
         qb/Y+3HGp7kyixLXCzeduDMOhI+wGC0MGV8kOgJhApLOVptPFkMh2rXBtG+qCyIRGW6S
         5DBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ojkToVyZt+6AV6/9LXFFZWf07ErRU8/WaYD6ufYZxvY=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=bJ2ISZtT6fNke7wnqqCrq/CBvvSkc6rLc2mqqxOYeitiCQ06ujwRcFYyJFnXOIoJik
         wSaE88h1TbHTgciHYDmA0ngTF1meWP8p7sn0lRLya72t1EVMCnMi0RJ7AbpkjR3KJoeG
         S5H1IFYiLM7PdIDwey8uPCiPEmPGMjGvYSCPJIXFka+SnQk5RfmXTjGDOFEbBKPUdYpn
         lbW175ofv3ZQq0a21cADuih4eEu6yuqveiEWF1gmBg+JpzaSXMDQ8Ot+uEQJwjKjfKhP
         PPevPxX1TVUMj6QyJMbMdjyVrWTJF1ETczHgookRmjHBac/Gun48XUY+vT8zuoIC7yFI
         FK1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-2885829bc8dsi16939fac.1.2024.10.09.20.50.53
        for <kasan-dev@googlegroups.com>;
        Wed, 09 Oct 2024 20:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8AxCGoaTwdnybsRAA--.25766S3;
	Thu, 10 Oct 2024 11:50:50 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMDx7tUZTwdnFP8hAA--.52915S4;
	Thu, 10 Oct 2024 11:50:50 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 2/4] mm/sparse-vmemmap: set pte_init when vmemmap is created
Date: Thu, 10 Oct 2024 11:50:46 +0800
Message-Id: <20241010035048.3422527-3-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241010035048.3422527-1-maobibo@loongson.cn>
References: <20241010035048.3422527-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMDx7tUZTwdnFP8hAA--.52915S4
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

Like pmd_init(), a weak function kernel_pte_init() is added and it
is only effective on LoongArch system. When pte table is created for
vmemmap kernel space, function kernel_pte_init() is called here.

It has no any effective on other architectures.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 mm/sparse-vmemmap.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index edcc7a6b0f6f..c0388b2e959d 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(unsigned long size, int node)
 	return p;
 }
 
+void __weak __meminit kernel_pte_init(void *addr)
+{
+}
+
 pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 {
 	pmd_t *pmd = pmd_offset(pud, addr);
@@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
+		kernel_pte_init(p);
 		pmd_populate_kernel(&init_mm, pmd, p);
 	}
 	return pmd;
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241010035048.3422527-3-maobibo%40loongson.cn.
