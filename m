Return-Path: <kasan-dev+bncBAABBHMB36GQMGQEFGPXYAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CBE7E4736C9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:29 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf8013159lfh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432349; cv=pass;
        d=google.com; s=arc-20160816;
        b=H1W3H8eODuy9t7F2ksk7iZKhbGReduXN1vPyWkNkPPIn8XQ1KifIYt7IUW1t1BPlcF
         ijmPdRsyffB6a2iZekHJcv2DaNJY8b24JEoIT1p+HnLBWG01xUTeuGup8edYqng0MIfz
         mDfYCmgOnCnxeH7cqg76iseGc/Fcxv2Rvmz1elYTHjNc7PmSmtnkn3/VyghjWvH2L5Cn
         1ehHcNepCXzn8S+I1ayC/jSBsaTxe4BQMusvsNC5HRecYOoEal2JK4re/l7XMQE/Vic0
         maS5qGVJ6FDDsnhhHzvxf8MCvC+y8Z140lFr9LmM6CCcplRmOWE/BpAkp/cEZyMMUvR+
         cl6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+ddW8TfkqrnmcxdUM0O04Pz37LDyvWKvlIB5tUyiGN8=;
        b=Pzgqq1iyBPSdLLNVS27EEFQ5NIYCNT0pj3EZSFI4QUs4GhKP33R+OfLmEer9xcBbg8
         JMWvj/jACIC1p6eRf0pJayNZdLhS3tK0zBt1B5Ae7/Xp+W5uFIk6I8pUgNftDHocMnlT
         NpucIf283CctNcCifZtnHSff4rPgw6EqvBXfX6vfPTxqbhcb8mkCo70zWloF1sW/XEVc
         AQWrjDjNWrPve8tXO6a3jrLyg2f9yFEWH5XKo7cX8tGa8A9GBMkf5HkD2U7Raj9XZD8G
         XFIChlLRXIQeTFXKTDdtt/XuCdo7UvNwpuQz5Uexm6JVsDH4UT9Qv+6av6/LH7kPJm3y
         vvhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QGQsUAkR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ddW8TfkqrnmcxdUM0O04Pz37LDyvWKvlIB5tUyiGN8=;
        b=DE7K30gJkGEoSzO/d5x8Hji00iuQJP6pAKrtR3iK9ZdQ743BcrKnumFQWBhRaykqiM
         8OBGHhZ2VijM8MVu93WOB5H3WUX9EUs48ZZO/IqW6YM2iLrZdshVtZNg64FGdIASTqO8
         WVdf/lDFDQx++gh7WuohPun5MdpWBpzW1EXWs9Fj4iEe26j3896bokLHP9BJrThfeTk/
         rXWVECYAwL7pu3OrWizo30QgKOxXQ8rMeRkJufi+NXJAp6T/Tq5IG+HLxaRAYbnbENnF
         akoFiTi40om208Szj0qHJLwrlW5bbsyC8WggBsj/FK+lW2/XWkHMrHaTp9gIglXD1+hi
         LGXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ddW8TfkqrnmcxdUM0O04Pz37LDyvWKvlIB5tUyiGN8=;
        b=IDqyJmuks1p+q+AdHbPV0/y/YHPQkfueuTorO1PfLeci/3WDMdMwRHY7nI19I/ctVF
         H+Xr4AAtHWAJEi01oGtshX9r29AoHXBf8q+xuuKNWbitVc+FXsNYzEHzuW+a5pfM8ffA
         ieU5In4d1tYu80fHwr9VvZze7h3RiWJ17PaLGL+uC4GkWtAKCGUVW8Cut5Tud4mAJOea
         /C3JHs6uHBbGBt4akcWW1YA3Kd6adInyIZOvfXVp7cBZqjYciby2KqURVrG+E+C9VUMu
         iRpfiza1f7dmv4ZQlfGnMPCYxfOvOT1j7/fMeViNs4Z6h76Tdqxat+UhnCjGdWqMs1OS
         5T/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SYwTB6+2mqswVfLVlVhO0zdiJODcrZ9hnt+RKpqyh7SexQRf8
	n+KNrGZNVv1P5KkokabcA5Y=
X-Google-Smtp-Source: ABdhPJxYdVcXv29zz5N4dr0FZWOYQtBAWpRJ7aSlLMo1qX4Mse4L+jGkX1eANYnAhlAuhtVSLoTH7Q==
X-Received: by 2002:a05:6512:3f27:: with SMTP id y39mr904123lfa.675.1639432349421;
        Mon, 13 Dec 2021 13:52:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1550185lfu.0.gmail; Mon,
 13 Dec 2021 13:52:28 -0800 (PST)
X-Received: by 2002:ac2:5d46:: with SMTP id w6mr878542lfd.15.1639432348549;
        Mon, 13 Dec 2021 13:52:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432348; cv=none;
        d=google.com; s=arc-20160816;
        b=zxL7E25GIj/ngKUCSdfPoXRAie1ClLIId2UNx1ydh3gfkrKC+aZXGTOBlXvc4kjYx6
         +YW2k5cnnt+ETCOCtHhlDdaeeL0ayKEXV/VXKexEtvFoBLGqySQL9b2BFOJFEUXHtOgR
         TU+ohbaavPKSuyFChugZijRbLf1C7iBw2piQPjT62SiUs6nun+aw+bq+8eBbO80mmxYo
         wE2L2Cw//A3VOYzPihytTcROdTJ/loI47OxgrmCtfsmZrYP+7tSDW6RK1qGGwsSscMc4
         +b7HZpTHwDmTYjTh61p8eZBfj4jy1SZrb0kR5o4xKPCjkN4gC3vmQCHhZnAJ2csKXkhj
         OICg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lLRehdStIsdn/AnAQZ01/ErmphlQVweFQPGIsWoJgns=;
        b=fpZB5M2fFAyH64WLLcv406e8kL39ZLh9mrfmvN3OoS6JkXFxgr2mPrkltZrAkMFoD7
         SWSHtiTK8SZXUMv6mRk5Ni8DGwj64o/3cNik74xcSSOrTr6yngPaKdgufueF77HToC1V
         XuDJzHnt5+LwiQ/4QxyArsoLZTd9MmwFxSImocR98fXZf7pj6Xd2FXobVkG5ZO8Mtkfl
         oep3FH+nQYh+PwROWzcZPSC6aI8YYbooiT/6+xH6mIle9iZGnhEcwpeWeWsJGmf7oF+k
         jK6pH7POac0PNNC3veF9uqAKnJRHA+YP+r0OAmKaminPcEx5N3dsUAXTayMN2N50GqUc
         DbOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QGQsUAkR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id b29si778774ljf.6.2021.12.13.13.52.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 06/38] kasan: drop skip_kasan_poison variable in free_pages_prepare
Date: Mon, 13 Dec 2021 22:51:25 +0100
Message-Id: <a6739f787ac816cdbb191aea4f3bb4427bd3f0c9.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=QGQsUAkR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

skip_kasan_poison is only used in a single place.
Call should_skip_kasan_poison() directly for simplicity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/page_alloc.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 114d6b010331..73280222e0e8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1300,7 +1300,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
-	bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
 	bool init = want_init_on_free();
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
@@ -1374,7 +1373,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	if (!skip_kasan_poison) {
+	if (!should_skip_kasan_poison(page, fpi_flags)) {
 		kasan_poison_pages(page, order, init);
 
 		/* Memory is already initialized if KASAN did it internally. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6739f787ac816cdbb191aea4f3bb4427bd3f0c9.1639432170.git.andreyknvl%40google.com.
