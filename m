Return-Path: <kasan-dev+bncBD52JJ7JXILRBFGA62PQMGQE42ZIKQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C65F6A530A
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 07:32:54 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id i6-20020a170902c94600b0019d16e4ac0bsf2544754pla.5
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 22:32:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677565972; cv=pass;
        d=google.com; s=arc-20160816;
        b=fNBdv8TiyTsQpWAwfhTod+pmyca9fqM59+NSYXixRnlYUVqayVTsiRS/NuXw6ducx3
         9XypVATZzrkVAvr0uGT2CzIvBYaxQuiPd0Qp1PSMdzhKaGkZzLzrWRNyI1CnO/injxDx
         PaRgjPaAPFOCYjyuf8ED7amHzlg/ZHJsy86eh41wO27JMA4EZ5NW8cMUyq8KedbV4DuC
         4YZBw43S0pBExN4cmzGEFiuTZzZMnxlkZH2ZiVXTY+hjuzWK5Zzawg7B32iXSBKzChDw
         1fBqaH/2M/9fzZ4Zt8zEfwM5k6IkYMOsUj9bGTt80vzSjlqxYbm0vsly+yMklHOEfcIn
         RK2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=t+qzmPaOplmwozdVS9yZQvTNqCmEgzsS5+bJhDWgntg=;
        b=ohxe9YIxTaKkw1eRfFJzRl6aMHJJCCwJWvEWJ1DuQGaAE140sILEBq9d689dR+NyCD
         vf14mYUNVxs/Ms5D0ehFz2rW7r9gAj87ZeWlXNTjln1VPkPufsXVkTKRmoIA7sTCN7xD
         AqpVHLoBNFpC6ZmKjXnC236YIufyAGPWdEjfoGkNgzg5SjGKPhiRSIS8HulU+o8wcMw9
         bUni39zWCKxv/6ul5IJFTXeBE+Xt0cHTTCVrj6GuCHy8+yRW3dMgEtjVVWPBD/Pxn6ur
         qLw+2AX8W6qIKu8WNZw45bJgiB2KybfeySWXQYhPKvBAxIO3jrVlQbe7h7hXN1AeAeR3
         vqog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=exeEIY5f;
       spf=pass (google.com: domain of 3eqd9ywmkcw8cpptbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3EqD9YwMKCW8cPPTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=t+qzmPaOplmwozdVS9yZQvTNqCmEgzsS5+bJhDWgntg=;
        b=m3blaYjom+EBNIPcwuER+5ZWitw/vlEpAIXVxOXgWnrmTCJy2KmNDMJCcPLTdS8+QQ
         ttyf5QsqIc5ZHj/kNVfmxQoGMEl8mA0ZugF+Kxzo8toFPzRr5nCF7LKC1z8EgZmFHLuw
         GquyIj3RQIXK3C7oXdXvrGRds9LaJHTn2LRJoUsOX/ah8jAIscY6rvb7DGFrcn+OyEqa
         uTFWoi4F1Wy364mqfzFsqUUYEeBVJQrYQEQTPmDx16LykynKbZ3zoxcg7YwlRu4IG7cN
         qqCanH4nx5UkaNYT972LEUT577GhV9kka55W04wkjfGKe5yrh+eF+6/flbAu6malZhho
         Zl1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=t+qzmPaOplmwozdVS9yZQvTNqCmEgzsS5+bJhDWgntg=;
        b=FmiKTI3KCMBBzLGKrukzi6Yoy6kGKYCVeXcE5v/uAtw6UYbLYgEHfginvNHZlg3rGl
         juXoYNA6Ai/9EcyrVCTbT5gdLyF0goTLK0HDAia8xUsVG8nAIud+ljM4VJzEWp4rXVHX
         FVV4UyYXaj/3kxeJj8ck6CQDxZK5mbubjjDNTrH97vZj+Ft3TsnWNrBfrFJATYrnsTk6
         01C1KYgm9wteEUsqMxhMBfqGJjamFpqB+d+2tIfLZrWVrPT8ge5xzR0AOIErvejvuQsW
         Pczmj5Nfr/UyVFJkCM6bRe/b1+Wx0mzfod8nwE7K9K+uRmWAkB+jPiZ6pn3e7VwjJi0U
         AYYg==
X-Gm-Message-State: AO0yUKUdhPZanxHzparDh2QMz071lOX3jc0HQHBDss/+mdW+WQXytpZV
	4T8l31LQMUIPWNlQ5QJmX60=
X-Google-Smtp-Source: AK7set/kOdsAbvzy+6kAJ/qsVRsOVGg4wab2pIk//8Lc25QHHpvANg/WTV3MXR5gw8fD51lW36q02Q==
X-Received: by 2002:a17:90a:b81:b0:237:5ddf:25d8 with SMTP id 1-20020a17090a0b8100b002375ddf25d8mr694856pjr.4.1677565972713;
        Mon, 27 Feb 2023 22:32:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4ca:b0:196:751e:4f6e with SMTP id
 o10-20020a170902d4ca00b00196751e4f6els13240164plg.10.-pod-prod-gmail; Mon, 27
 Feb 2023 22:32:51 -0800 (PST)
X-Received: by 2002:a17:90b:4d12:b0:237:50b6:9843 with SMTP id mw18-20020a17090b4d1200b0023750b69843mr2268734pjb.0.1677565971686;
        Mon, 27 Feb 2023 22:32:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677565971; cv=none;
        d=google.com; s=arc-20160816;
        b=U9ABSEmyKgwY+47ZZ+Sc+BDuzDIqMm9hlAYtU9cXV+CPDe5p/EgO7yLbW9r07+61aj
         X0l6gvFSqomErArIc982atNy+JLg6drzoI3gFbd2JUaLhysgWbccACoadTg7sk8RXdrX
         WMSzaczS7TB8DePJysmoWNBMa6BxXnetRxemgcmkwyt6H6WeF3PKBBYX37PV1CWNF5yd
         lj3FcrC563fnZDAj7eW+2ZDx1NKiXkuDA7onRSvbALFp3i19QOiR1ZYjsW0gtQ91p6T/
         +YeTZ6IzuX3ftvLQ3cl4zm6Lpq8zyXUiIUwIFtvv52i2J9qUwPjjxCq/Pq9M0G4awjkw
         uvbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=eey2bWIXShb0HJ2rZd6676jnb6hRL1sBGHfdZHZ/mnM=;
        b=IprksYlDSseNzaJEaq3TmSUC49efui5RSPflmD+3p0N6UqSCGFu9lTPSvhHFwtpDkN
         SU8D6mktez/eXzIXLoiljCYMSUJkTbWOaAhV4ibFgHCAp5mTyfE3f/PyaBdN8Pl+ooxY
         T0dBtW0copGl3IMiDl9H/ODYJZykTx0l3yZxqqrj+GBO93k56qSbeP/ikbyWEz0K+uOe
         EPLJ9x69CBSAiq0JBXF113m58m/iG1Bq0uT12lhi6qnkdMT2U1WLQCvOW7nq47817Rcd
         taqB11qzTcjLqH2XmcXch0VRmAlXpN3v8r1wxEpATPdMdGO6Veoge+Gew7ypQ4BagBB9
         jrdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=exeEIY5f;
       spf=pass (google.com: domain of 3eqd9ywmkcw8cpptbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3EqD9YwMKCW8cPPTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id pv5-20020a17090b3c8500b00237782d64basi731427pjb.1.2023.02.27.22.32.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Feb 2023 22:32:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3eqd9ywmkcw8cpptbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-536d63d17dbso192406317b3.22
        for <kasan-dev@googlegroups.com>; Mon, 27 Feb 2023 22:32:51 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:cb8e:e6d0:b612:8d4c])
 (user=pcc job=sendgmr) by 2002:a05:6902:1388:b0:855:fdcb:4467 with SMTP id
 x8-20020a056902138800b00855fdcb4467mr1957716ybu.0.1677565970984; Mon, 27 Feb
 2023 22:32:50 -0800 (PST)
Date: Mon, 27 Feb 2023 22:32:39 -0800
In-Reply-To: <20230228063240.3613139-1-pcc@google.com>
Message-Id: <20230228063240.3613139-2-pcc@google.com>
Mime-Version: 1.0
References: <20230228063240.3613139-1-pcc@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Subject: [PATCH v2 1/2] Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=exeEIY5f;       spf=pass
 (google.com: domain of 3eqd9ywmkcw8cpptbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3EqD9YwMKCW8cPPTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

This reverts commit 487a32ec24be819e747af8c2ab0d5c515508086a.

The should_skip_kasan_poison() function reads the PG_skip_kasan_poison
flag from page->flags. However, this line of code in free_pages_prepare():

page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;

clears most of page->flags, including PG_skip_kasan_poison, before calling
should_skip_kasan_poison(), which meant that it would never return true
as a result of the page flag being set. Therefore, fix the code to call
should_skip_kasan_poison() before clearing the flags, as we were doing
before the reverted patch.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Fixes: 487a32ec24be ("kasan: drop skip_kasan_poison variable in free_pages_prepare")
Cc: <stable@vger.kernel.org> # 6.1
Link: https://linux-review.googlesource.com/id/Ic4f13affeebd20548758438bb9ed9ca40e312b79
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/page_alloc.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index ac1fc986af44..7136c36c5d01 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1398,6 +1398,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
+	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1470,7 +1471,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!should_skip_kasan_poison(page, fpi_flags)) {
+	if (!skip_kasan_poison) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230228063240.3613139-2-pcc%40google.com.
