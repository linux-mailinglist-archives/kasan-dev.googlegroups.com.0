Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBNO6D6QKGQE4SYMVKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D602D2C1559
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:42 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id a27sf13348732pga.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162181; cv=pass;
        d=google.com; s=arc-20160816;
        b=FYNKqwxwQdmZGEzALIUib77JnCTv1vSuvo0Rp1nG2uTNfUQyHoAeON5rQdIt67r/sc
         o/enZJpozbvky3XV8VtpvoOY/VRRvbJy4OpEBhmQnzELE0WSUrwrGWXC6FTeaCm5osH2
         apCaGnEC2eYCzuT8jp/ZOGI4fH2nHfODkmZehl/rHZPKDLfEM+1oejpQZ1Rb5yg2Esx3
         kR+XYQZXW5VN9L1CpVmOEtTyyaDYy0DQS9UscxQ53vDQIX6qrxXE28GlyJPrxGupTlrx
         k5jK1k13QFwDpAd/tVok/n46z0fNwVUTBAkZp0kPhVnDmjiXPjiPIEP5FGexAIgwcVgw
         D/lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5RSD8it4TNJHo6vX8TGyVMyA6jtPnWyjO1LLtj/34AE=;
        b=S5Pcq++ehsvNauGi88KX0x0QzCBPmdk9QtZQglg3l2SDHnHMvFky+32Gr0gmobLzGT
         BSTHwx5Xz0dz8LviZ6iBUuBpLmTZ46QFn+KSS+Bcz0pJAuAiafhAdaVdy2i8MEhNHHTF
         UAWh5rpUXKpbXZMJylUN+R9hX4Uc2DvjVbttlt4p0dTmbvV12enwcY44LFzeEqt8aGSM
         xHJ5ETog0VwX0dPwxT7rHYuuZ7r/iruimTy6tCf7iuRguwA4zVeuQnhgCRDy/RKKK7B0
         OBeb8oecnHqqvBV6buazMi3H0MBI5/lA83OjShKHfOdEZPET/LuIgvC9TYy3gFl3Ivhp
         MNlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vkxW6RZN;
       spf=pass (google.com: domain of 3bbe8xwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3BBe8XwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5RSD8it4TNJHo6vX8TGyVMyA6jtPnWyjO1LLtj/34AE=;
        b=kEXHFapZDlJELsqn853LKQ8VAr+fM7qP3otIMXBOd+5PvVYwwOlX+zsHRO1QAbf2ue
         7OL3MVEVKQUho8O7Ew3clWIBeMpI9ofoPR9THGNH3CRi63OfHpcpV516qD8Bmpv84lP+
         DbgXYZnr06P+Nc3HNQ4eo6DfEw3r5psYCBYB5PgVBRL2RQ/9IH9lZZzBtJ2pf3JIQYXd
         l5y46cdOmbgEQE8Q7+wn8JzCtxOjbMK5Alaq1cTnxMZB0RLhHjVi3ZsN2ozXvMN/MODp
         sVUKATDpXhDLrqpHjywNf+W9Nv6tiSC/toZdB2BPPW+c3KQeXX4Z/TuAeiKZByA+OF11
         ekQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5RSD8it4TNJHo6vX8TGyVMyA6jtPnWyjO1LLtj/34AE=;
        b=AtIKxbbark50gc5dfpS+Ql4msePOkDkyIqPUoa6+VF0AS/8QtkqJJGdVqtHH2xiEp7
         BKILXyyvsS6GrsjxspyFEZEnh/dEVYCi+geX43mBlECwUSV5Rm0zf3MwFjgMQQ95WZp2
         nP19tSg4WzjZe1fVFD2kGRwuoAQrDoDw3mTFvYiD4NmfMydHublMX6qMDb56bVhUjsHT
         YPeD4/5HA78nmWJleayeNJespJXwqfETIAdl3yPQBzSytlSbvVG8M1XWc5IEv3CnLRKj
         jIsxEtFqxgrGV3Lbvbq485zhpkHGvL9fcJtlSfLwhCyPsJztmGJ+LN6xSB7/eFVmxpAS
         ZRAw==
X-Gm-Message-State: AOAM532Cn3YAmdsRY99X1/0ncilG6CwOlVomjoJWdTFzj5rR/OzsxttD
	qw32UdVnfq9uBoJMh0D7ja4=
X-Google-Smtp-Source: ABdhPJzh98EUvVhA2w00x9GU0X3vc63rkQPzvNC99DJL7eDB6g6F6jlMdRApePczLvQw2E0idajoug==
X-Received: by 2002:a17:902:b410:b029:d6:b42c:7af9 with SMTP id x16-20020a170902b410b02900d6b42c7af9mr922227plr.21.1606162181626;
        Mon, 23 Nov 2020 12:09:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls6650184pld.8.gmail; Mon, 23
 Nov 2020 12:09:41 -0800 (PST)
X-Received: by 2002:a17:90a:f815:: with SMTP id ij21mr681335pjb.210.1606162181059;
        Mon, 23 Nov 2020 12:09:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162181; cv=none;
        d=google.com; s=arc-20160816;
        b=STzR8lzexV6lqq6w0LeZvsJBjzU71DlD9SdggQLlDbLMbv6X5+yKNyY21safiotoiL
         9DyHMxmdvBXz8kTBoaTz6PbhoRJG6qJnneuBBA2JELWXGaKINiBsUrTAOD1Glcz8IpuS
         EhO5qHuwBwgaSHyZu8HGVF+3ZNIVkD3gcM89BZ/OrQbB3B0yWiiT/v4Tni1sQ1E8oNQJ
         vyQuGyxpeu9J4awS3p4AHGokGJE6AH5niX6valhW6zgEjeyYb8CU/o0lERuOsuaz3O7r
         Je4ExHgBmV6J8HXxkmnDOP4ukT4a0NMx9NDVWIjAMJLeKlwXw5soGlp/+KrNMYk7vqhT
         DmzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JqOdOudIAs6fCsGoOMJBOXRAJ4nBM51Q9IuLvpe9X7o=;
        b=ZkI0V0IDxEbmoLCTHDNMxuE7DulTWv5sVe72kO7N/Eb4aLJdv+lWhtsTeQsK7LEwEo
         JXy3in3qDkNs/jn1nlrONsaeAjegubPCqxveHAyzMTXk4/art4ersegzKA6FjIFJMOPa
         RpNCA0Nh6fybIgOf02VRY1lNVeFVZWvej1w13K7UFeC6055TQgS/aCt/rL2oPGVL+1aC
         9nMVkJZyFlNnr+wZzIRgXTNSA7SDqV7Bb2lLKj8b5QvtFTO1pZOetuIWxUnmwsY76sU+
         +zAFzEiz4DSBg2MHqO2nFhYUCf5lHAqybL+wp9jchqsEMWw299EEMSwwo0TyuP2xY1Vd
         FiDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vkxW6RZN;
       spf=pass (google.com: domain of 3bbe8xwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3BBe8XwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id u133si907314pfc.0.2020.11.23.12.09.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bbe8xwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id s128so15571998qke.0
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:41 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:a8f:: with SMTP id
 ev15mr1201051qvb.20.1606162180614; Mon, 23 Nov 2020 12:09:40 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:55 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <ebef6425f4468d063e2f09c1b62ccbb2236b71d3.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 31/42] kasan, mm: untag page address in free_reserved_area
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vkxW6RZN;       spf=pass
 (google.com: domain of 3bbe8xwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3BBe8XwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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

free_reserved_area() memsets the pages belonging to a given memory area.
As that memory hasn't been allocated via page_alloc, the KASAN tags that
those pages have are 0x00. As the result the memset might result in a tag
mismatch.

Untag the address to avoid spurious faults.

Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: If12b4944383575b8bbd7d971decbd7f04be6748b
---
 mm/page_alloc.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 42c32e8a9c5d..236aa4b6b2cc 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -7659,6 +7659,11 @@ unsigned long free_reserved_area(void *start, void *end, int poison, const char
 		 * alias for the memset().
 		 */
 		direct_map_addr = page_address(page);
+		/*
+		 * Perform a kasan-unchecked memset() since this memory
+		 * has not been initialized.
+		 */
+		direct_map_addr = kasan_reset_tag(direct_map_addr);
 		if ((unsigned int)poison <= 0xFF)
 			memset(direct_map_addr, poison, PAGE_SIZE);
 
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ebef6425f4468d063e2f09c1b62ccbb2236b71d3.1606161801.git.andreyknvl%40google.com.
