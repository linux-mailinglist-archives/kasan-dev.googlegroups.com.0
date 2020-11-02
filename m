Return-Path: <kasan-dev+bncBDX4HWEMTEBRBE64QD6QKGQEIQJDS5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 115392A2EF3
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:36 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id r15sf5970793ljn.16
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333075; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9GgYsANAwjejTJo7lcL7o+Mh5SsP2zfLl1/yIFI3EEUrNl6R7mkfY4nWMX/XoTajy
         tyq/1QWkvjMo4JUm3FIQpH7a1LzX2fHtBtQXt0Is0n9diHxLhNqjmcf1cik8G14eId4O
         J04ixuJJR0YDstyVfYx2zw/vPHs9lLajotGCCIaEzwUvIjFhfVj4pupX3+O10+dDeiwY
         DqpNHG1QBBlnqtoSmFuphL5hCwt2vpdONhdgRmwoKeuLI+RWPjb1EBQORxUuzEBg1aFe
         6Um5cNnmr1vbxq0pL+11VILlpuEcop2IWPil2oQ+t2WWL6GPnhrmP14cF/RiuDp83D8J
         4E0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FlnHvAnXf1uRl3njAuXdKmigeqPyVv48JFKfckd2LKM=;
        b=yR73eDtbkaWyQNK26DwsXLUcGo5i7bY7NpIc7BqCVWN0JolZJ7KuMJpiHLV+1JprQH
         3VYrJD4/ScTeq6zLzfkfT1dS1MCgJbnJz0a2c6CByZTlXrrEj86MXsvLLRU3ZGje0l1P
         EbMH6Lsl5w4rWIMANp+7djtA56+gXh3t1SIBBX7RFsn49CHFlLgrnSs/WFL28r6YP1Ke
         HM82FqGT7sxyKrvYoGo0faSs+kHz+CYh7b8iDxGi+CLcw1gZ/ugicwanmpZqatHHcjr2
         rEHsjwiajC/DM5BvpzydKSAygo4Mj0MTUnq3YF+3yUPn9XaSfV5Ec6Pb/qE/abGWtO0B
         zsRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bIDVeRsj;
       spf=pass (google.com: domain of 3ei6gxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ei6gXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FlnHvAnXf1uRl3njAuXdKmigeqPyVv48JFKfckd2LKM=;
        b=i7wZTxt4Lc2F4x0kIG3Sq520IUZ1OYa3wWVDFC/aERkIWkiELJ+2f8fwDmRgG0j3LM
         6mXIiy36LQ+sk4S6FuApImA5J4QLRR/xM9wYuUoY2H6xib3BMf0EfxD5hWjtofQ0xeY+
         RZRhFFeDDzt3enw7cJd9iiqQZyS7M2ZlvHiIfcv5+ORnwIzZ+lpRUyciJE3CN20wgo0n
         vhHAThdIs2MeMQeVYwNIKPeYKmkiaSeuplc84NOXAva322YtPpM1fCGhR+VJ7rEE+i+i
         R44u+iSBoj4MY8MWdRDqFJ+UlFzzhjedG61f9gKDz0KA/h6UxGj71Zo+Vj3Ly11n1SSy
         x36Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FlnHvAnXf1uRl3njAuXdKmigeqPyVv48JFKfckd2LKM=;
        b=EyqIZC7o6E3P+zVqm1sTtGryrZ5S5Wcvi1plZu9T1mC2geNaL689bwAkuSQBKVEPh1
         8tirw8rXZs1xuRYT+rLUTXMYgCeeugAh+435tAE/TBZG44ZGj8HcPCw5+MRnyqwsa64R
         vu/qWgSRnd2om5w+th0EbOsAFMacxLr6j5qzjOntWZgOBZJkMojGi5L9/BN1htGTOS0b
         WroTCd4ZITeeyB4xivAcHy1X6r45X1mUXAMfFgWBBpS77LGsLYQgcxXuB/m0EK3fQvej
         YQr+OZ73JYvIwvj2V1J1Oddsr0eoHnz2Wp+9QC6WCDi6pI3jP5q7Y8so0DAL3uMijzxw
         wyTg==
X-Gm-Message-State: AOAM530uikiAuf7dsAZFMEidJFDMSPPfYLxOCgJeJJaaemLbDfuPFVAT
	Uq90yFcU1F4r0WHdUH8N55Y=
X-Google-Smtp-Source: ABdhPJzXsn66B2cYuAWGGdJqG5AykWJ4tyAQh+DbHj349627maZi2t3H5E3cq3pCTMknXd0+5xVoqA==
X-Received: by 2002:a05:651c:1343:: with SMTP id j3mr6603561ljb.336.1604333075626;
        Mon, 02 Nov 2020 08:04:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:888a:: with SMTP id k10ls2470153lji.10.gmail; Mon, 02
 Nov 2020 08:04:34 -0800 (PST)
X-Received: by 2002:a2e:3e17:: with SMTP id l23mr6859919lja.425.1604333074611;
        Mon, 02 Nov 2020 08:04:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333074; cv=none;
        d=google.com; s=arc-20160816;
        b=vPVqbCJ8dXtjz7YrdE09t3/HdLYqvhHTWohD3uuq/JqJswl485KEnexrJXOGeT1rAg
         vpSGuvURHOw8G5lq5PkJV5veujkfxLLpTvalC1ZP3p2D6x7Plt3uMxDGTFqu1r9TrwBB
         7DkSnlT/76Yd3kO2rofOZVrfPWgcOq8cS4WRdFyv11tkCuevVC8pEY9rBuAHbzg6+pgG
         spSjMsae4fNAqtrdMxYVO3n9e4W8X0bieHRKlh+H86/GhxEVBdACB6s8eQzdol66Wg5N
         k9cSMZC1pir9IVcZdJXxRBKVHAKYEiGAlfTMPbY7mdEWca4jD4PZhINPSzOipFASf2VR
         aKAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=k0rwmvWkh3wc2lbCLJgzaa11WuGN21taMrm4zUJORUQ=;
        b=yoYrw8HWfVxXqIrwhcEVIfLoMXsMwwp28yApz9bSfaYYI9eOlVPXz8AEcHJIuxcJjV
         NUBox1e8JzpMrT55DXn9rGAlnsft2ixTWftbofmGkfLetZJw3wPR3mYvT71pW54FiFI9
         zpTAbtvmY/giwxElmzJEXoe33Ha/xA24ZLmk9uvvjr1jeQPbc1WHr86fvFWU3+mDHO3s
         S13fMLcHjtM8RGfc1m9JmUv1+AD5A9iAMZJ/0X9JerlD8xhpLGUPtqpgS9qDiuSwinpb
         FYKo2Faft7mwauI8oRatuBZhJwDw1Vn5Sk6hlMdNzC4HimeyLKwMMyuKbSKtCH3fVoGj
         k9lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bIDVeRsj;
       spf=pass (google.com: domain of 3ei6gxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ei6gXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y11si266030lfg.7.2020.11.02.08.04.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ei6gxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t14so6652764wrs.2
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:414b:: with SMTP id
 h11mr17902427wmm.157.1604333074095; Mon, 02 Nov 2020 08:04:34 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:43 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <88290ed7a2bafc5e1eb4872ec0eebac5060d0b64.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 03/41] arm64: mte: Reset the page tag in page->flags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bIDVeRsj;       spf=pass
 (google.com: domain of 3ei6gxwokcfetgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ei6gXwoKCfETgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

The hardware tag-based KASAN for compatibility with the other modes
stores the tag associated to a page in page->flags.
Due to this the kernel faults on access when it allocates a page with an
initial tag and the user changes the tags.

Reset the tag associated by the kernel to a page in all the meaningful
places to prevent kernel faults on access.

Note: An alternative to this approach could be to modify page_to_virt().
This though could end up being racy, in fact if a CPU checks the
PG_mte_tagged bit and decides that the page is not tagged but another
CPU maps the same with PROT_MTE and becomes tagged the subsequent kernel
access would fail.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I8451d438bb63364de2a3e68041e3a27866921d4e
---
 arch/arm64/kernel/mte.c  | 1 +
 arch/arm64/mm/copypage.c | 1 +
 arch/arm64/mm/mteswap.c  | 1 +
 3 files changed, 3 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 8f99c65837fd..06ba6c923ab7 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -34,6 +34,7 @@ static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 			return;
 	}
 
+	page_kasan_tag_reset(page);
 	mte_clear_page_tags(page_address(page));
 }
 
diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 70a71f38b6a9..348f4627da08 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -22,6 +22,7 @@ void copy_highpage(struct page *to, struct page *from)
 	copy_page(kto, kfrom);
 
 	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
+		page_kasan_tag_reset(to);
 		set_bit(PG_mte_tagged, &to->flags);
 		mte_copy_page_tags(kto, kfrom);
 	}
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index c52c1847079c..0e7eccbe598a 100644
--- a/arch/arm64/mm/mteswap.c
+++ b/arch/arm64/mm/mteswap.c
@@ -53,6 +53,7 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
 	if (!tags)
 		return false;
 
+	page_kasan_tag_reset(page);
 	mte_restore_page_tags(page_address(page), tags);
 
 	return true;
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88290ed7a2bafc5e1eb4872ec0eebac5060d0b64.1604333009.git.andreyknvl%40google.com.
