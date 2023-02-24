Return-Path: <kasan-dev+bncBD52JJ7JXILRBIFM4GPQMGQEW2PVU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B7496A1689
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 07:16:02 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id v2-20020a67c002000000b0041f41eaafefsf2560773vsi.11
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 22:16:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677219361; cv=pass;
        d=google.com; s=arc-20160816;
        b=JFIBRS9dVlavgRXNP0AY4R212gW+19Ho+1KdTG48wPuDEHV02RjzN2WHqF7cJwSfwu
         HjH87O8MmMphzK1X227usCdagz+RD6DO1KJ+9WyiVsN1KZcMBYb5hWph7MY20/lMpDAZ
         On3n411AtOFeE/Eq6KvqWj/GWuNX6fFoSgXBBx5gdPD8c+hCquGJcGkv3KZuZ8Qgs/Km
         61e0leAs2Gv0MPcRaNdNiYH9tDaMoI02KDfzhpO6wFi6pYk5NRFYX7fyLgcXdS/ayOZ9
         kRi+McBZgLFqVIG4E2BqK5g3oa1RjBRkluHuoAGT8kjGIwGPY3Tblc3yORXYIESYbwWF
         3ygg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=wPUxT8/LAGoZoRSjXvplP+6Flc47u1WwpJSESUD26XA=;
        b=rWUnaOkPH02xmFc1dxe0QuOC6va6z8BP5rrr9ADQ4C2B6Jt4mNvA9uRDbj1RcDroRk
         1j5d+IcwVOjamEHqBQhQXHpX+EnBfAP5F9+mx5rtweuSpsZhAZmbgxgnsnolKkWYdSwY
         HWr7CcK2RRskrH2ag8K6F3N2K4w7w7uQMFceS9Lh+BTU11KIIOvxdkFP6O5QuylWzV5K
         LSYibOaa5U+8N0ZNhfEI6KeZdElFDS/3jV+lPhcXRRkUnkYpKTRI4kQm0+20xKXYUPbn
         z/RHMY9n2qHuJ815jRxLtvBlr98s2KoeKD+D8OM04D1vLdrTYeCQSaO1GS9gQXxm/u38
         cKdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="JlyeV/p0";
       spf=pass (google.com: domain of 3h1b4ywmkcdid004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3H1b4YwMKCdID004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wPUxT8/LAGoZoRSjXvplP+6Flc47u1WwpJSESUD26XA=;
        b=PN4drtPaZ3EHqY3KcQQJK6NOuBg9X9C5LDsPt1d/QZA4rros5/mM5E0EgGIPJ5pJ5F
         AbVB3wcnwT4fGbqmo8IQRU/A3VO5INNRQlY9JTcNzSoFQsf3nI/wMUzneEq9fR3sDmJC
         z1Fz1pcuT+alqBvl4DZt+9Jr5dt+11+df6wvRNfodspsScmSD3yhIIT3fyjjEXo1Rmxa
         TLjraMBsi0ARSLKdMjxig1f2KckPdC5Xyz35VycHVIK8IYDlSQlmUAUuYjShHJfi0ObG
         SkE/ShT8tPcssOa7Zs4jwxfvUDu8dWqBmyku+8of+zPPsW/FsJ7a87Zmy3RX33mtekoh
         3W0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wPUxT8/LAGoZoRSjXvplP+6Flc47u1WwpJSESUD26XA=;
        b=BYf9zpGIfB0eTNmjz4Av+GgM6yYKuJ7kPQCFtzxJSl+fLCqRqBjeo0T4sxNVRKVmvN
         kLtiNUGrV2gxQN52sFMx8eNw7/ILJP7gE5Ej2SzbHYEK36WHt/4w8cWbAjqTgx9t9ivv
         unPVx+3z+6mF97R9GFEKoxXSc11knJF3r0HaJv5iwEi/kQ2GyFJARaZ2LEvIaNxazBeW
         L3UAJ0fYC9877h5xZJ7ZDbVZ3JQR7cF++NFhoNtXVC25unINlnSMFIdDU0oYDXRI7g/H
         EVLJ2jpPEcwshEnvPAzHc6s0QMkSLGUoiEslq57tMj/GTHFaisMXklNuCoBnm9rxsSBq
         PRQg==
X-Gm-Message-State: AO0yUKWS+yz38PD+lhwOI1bqhkzxzsWEko/Bz+QAgxGLm+Oe2v/sHtYp
	ZO03dbvJ467SkKa8v6YDIkM=
X-Google-Smtp-Source: AK7set9qQbJLuTYoZ5Gs97QvaHPDLJszblKc8t7kaTMk1dX3IBsYi07sGlB8ZBYA0jDYTml8OlyBKQ==
X-Received: by 2002:a1f:bdcd:0:b0:40f:2033:6994 with SMTP id n196-20020a1fbdcd000000b0040f20336994mr1935069vkf.2.1677219360770;
        Thu, 23 Feb 2023 22:16:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e889:0:b0:412:21e8:b26d with SMTP id x9-20020a67e889000000b0041221e8b26dls693486vsn.2.-pod-prod-gmail;
 Thu, 23 Feb 2023 22:16:00 -0800 (PST)
X-Received: by 2002:a67:fc8b:0:b0:41f:3c1a:576e with SMTP id x11-20020a67fc8b000000b0041f3c1a576emr2824698vsp.20.1677219360154;
        Thu, 23 Feb 2023 22:16:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677219360; cv=none;
        d=google.com; s=arc-20160816;
        b=xZ+zBfFdiCP5WifGP8Ygyh5MsAfSrAb9c4B14bj514FnasE/2Vhs4yZoNQrg1h7Mhy
         VaH5FoGBr/97yekW3NiuUUIM+NRGiKDvbdp61dZgwIF+M62znYS2Y6aH1QHepZfgulr9
         qf9Asp6BsIzYcdMmuW0nZFM0t/kxPT5GAeBenunKX43+CH1atuZyH3m1Sfuf+CGo+hki
         8vcTbhPb3qpjpBl0sWTmwwB+XAQwK4b8UBOc94oM+ixGe3VwnDwVj2loVHcbHlHJ7CGi
         DT58xjcPjhixlm/1FUVzIaYsigeIID83M8AFetLxq+kkHEem+HeLsBGrm5C7jtk+Q9fe
         8hmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DwUBlkJdKPYrehLUGi744iL0IslrZEMB0ydUaeQ3WSw=;
        b=ftgn8DIISPmxDM0Ps9JHtsFqJQxybPzCPTMPn6GwUS3Vps45NR2zYprSxHddG0p54O
         GUG4/1cUfI1Np0Go3/Y3vy3w65BtQBI/rI+VjWZ2F27Hj/gRJLvnq/XMytQgdzP2P/zc
         bERo627zT6B9yuRSLm/JAkbeH/ZYwSRg6Q7ZsyW08uldnQCIAZ5wJyuc4/zOcSWOKRG6
         VE0CKi0pb36TXNmf4tCc++nYEw4DVYIRx9Js56tmxSIJu6O/kQi+cPo92hgwm7AwSbmx
         Av75ywP64pN+aGQ2OwnhdGEhCrgBljO8wMiX4OODrXXpfd5j6XzEO0GxaspEp3qAn39s
         vo4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="JlyeV/p0";
       spf=pass (google.com: domain of 3h1b4ywmkcdid004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3H1b4YwMKCdID004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id m18-20020ab05a52000000b00690829432ebsi117460uad.2.2023.02.23.22.16.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 22:16:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3h1b4ywmkcdid004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-536e8d6d9ceso140216817b3.12
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 22:16:00 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:d302:b63f:24c7:8a65])
 (user=pcc job=sendgmr) by 2002:a05:6902:154b:b0:9f5:af6b:6f69 with SMTP id
 r11-20020a056902154b00b009f5af6b6f69mr4862249ybu.5.1677219359839; Thu, 23 Feb
 2023 22:15:59 -0800 (PST)
Date: Thu, 23 Feb 2023 22:15:50 -0800
Message-Id: <20230224061550.177541-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Subject: [PATCH] Revert "kasan: drop skip_kasan_poison variable in free_pages_prepare"
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="JlyeV/p0";       spf=pass
 (google.com: domain of 3h1b4ywmkcdid004cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3H1b4YwMKCdID004CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--pcc.bounces.google.com;
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
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230224061550.177541-1-pcc%40google.com.
