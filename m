Return-Path: <kasan-dev+bncBD52JJ7JXILRBIEWXKPQMGQEPOR7FZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2055A699D44
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 20:59:30 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id kw4-20020a17090b220400b00233d236c7b4sf1386510pjb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 11:59:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676577568; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q5ZV9kHwrAdB3I2VHC1j1B3L/7ZDqFZGPcNOZyAZ9aE+PWPYXmKBOLYKROJrmuBu/7
         ZdPq9C2r/2H/lqMUTmYAhzFRwS39hh1jj1t4HqekDj34CPbHuOP8b0rcVn3TKakWgUH0
         IKb3Z11hje9KJl+O/9TEzw+QuSMsqP622D4v36rfMij2RUIGAe/1m+iUfJyBIbhd8FGb
         3g8RMvH9ALU7TgSlwbvIFPSi1yk8zOIMSPmOowzBQsDWSCcYOpEegb1lbR7veSIaw98F
         NY40JJgz7lNQJAGHWLzuhlZdDNFOyJruIJbi8Aght2LSJL7cFQWadGsEAhQuLzj6/Y0H
         trpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=0jKbGII4DT1WzSgBmODqa6ZTmuRziJGruRjrcSF99xM=;
        b=ZiVOQjti3nHC/n1Zn0nu3tdLfgsS6b8AV4OmK2mvZW83ul8LAADnUSKRiiDI47EPW+
         vW7tXXOV2m79UY5fJOH8Hh2XhZUNC8UappuLollBOFnQRS5qVqedMEnlBClLPoWmni4U
         DfMPy8YehB2QebXONyFRupAXWu3EecpdlnpPce2y72+3TTdoNj+YJB4XK12nHQ2ZGxDc
         cJNgEU3YnXfZfDfbXqvfFzfi2aAvwnFjSnVc14e1tR71u8RzYcJ5LsV4VCtMZoRgSjWA
         zOSaA2IFhgZGxapcbi1iaZeaVs0HKCn/KafnmkInqQ5j3bu+qnBRYMIDKgBLhpiOHtjh
         4+5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MfYxEJgQ;
       spf=pass (google.com: domain of 3hovuywmkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HovuYwMKCRUAxx19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676577568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0jKbGII4DT1WzSgBmODqa6ZTmuRziJGruRjrcSF99xM=;
        b=FMmLp29L6snO5mQPlhaQwJy261XPNsIotvVpTy2coeOH8ranQrqJOzZx2xv/wPtyhc
         /Bg9VpzLQeOjOH02FcHrU+Xc4lOhjUfUrnmXmyfIuSws5ZEwGyOSNH07Qt2lM0hG35GO
         sCaSPo5Qox93CCTN471VplGiQM7sIgOYVRe47hP5OXbSLNGrulda32ps/BE8AdZuSok6
         0XPfUsSdalMezw1ttNPLQEBUYl1q60Pg36OluxU9sAn9ivL+++/0J2VUsEqgd2FkqnDC
         KTmHhjsEGXtwHukcuJ9E+ezyrA+bTEveJS9OTelArB7RunypaqZWzgoLuGjxWQLNCGwc
         T0kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676577568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0jKbGII4DT1WzSgBmODqa6ZTmuRziJGruRjrcSF99xM=;
        b=F3sgbeU+GI/3NlsyQwse2IDXjlz5ZNCZrsC/Hr2OSXoerZTh6dRYWQzyiWfn19jpdy
         hqZhY17YzYk7qk5d8vRnfzzQWOAOvAJ4T8G2ESmRRo11WiJ9QSHFW+nq7FQUVYGmqVMG
         hEc6321KjnK9cj/lVTB35WWt6KxGQUHKGNbpexwrVYDmV+NLDL2XbqtY5OORstEb9oA4
         m9TzBDhOelIQ+J6Y0KBiymngJBmtLDV9gcQGz/nEh/mS/ljGwmNAMcGwWjlrK1s4TlCY
         zMORPrc8RpWM/KN0iMd8Be9kgczVsRKOFi6obFxnhp16z/fuABYzXGQP0ctHhChwHs/z
         shzw==
X-Gm-Message-State: AO0yUKVTtqiGIRs5xfVihUCztNA/r/ez2hoIP41qX5AnVuwcCnvzEITO
	vcnjYTlX/JsUYMlw57UN5dQ=
X-Google-Smtp-Source: AK7set9gdUQtm42LW3VU+1vH3MNZcKGtCCtS60egCVMkD3cq1RadhB8aqpL031nIWXwZ8SmH8OEDcw==
X-Received: by 2002:a17:903:41d0:b0:19a:b302:5172 with SMTP id u16-20020a17090341d000b0019ab3025172mr1517951ple.3.1676577568338;
        Thu, 16 Feb 2023 11:59:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b709:b0:194:d87a:ffa6 with SMTP id
 d9-20020a170902b70900b00194d87affa6ls3159446pls.1.-pod-prod-gmail; Thu, 16
 Feb 2023 11:59:27 -0800 (PST)
X-Received: by 2002:a17:902:7c11:b0:19a:968d:26f9 with SMTP id x17-20020a1709027c1100b0019a968d26f9mr5281094pll.54.1676577567585;
        Thu, 16 Feb 2023 11:59:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676577567; cv=none;
        d=google.com; s=arc-20160816;
        b=C8XKwVFkbe5ZqRPYOgHZWTcbH/GpekexB/RUMmKKRUhwqNBFu44mKwdtbwk1Zy+JMY
         RDGK2UYuyu9VuUiPSDlC11xMes0x/FL0g42UboOL8X29+GM6v5NlCjrvrnVdCg9l0Obf
         0wHB2J/A+3mqkPaToQQ6HHFtQnYU4Y6zr+oJ8P4iLFLuP8WpnF6t/ezFPeYr9lK/MwHN
         Ferxk1uAJ4U2/JfYG+RwLIM86bqbNqHBnZxa5MhU9mijPnl5aIOFv6Nw0GIzpbg5WJp8
         lJAkAYH2UWOYymWMqBGwzlwSYHmYRp+OUI5EhEGaGvbTuJEF2b4xCmI197OYwUsu/Wba
         WNog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=3QfkogShxWtsNsvou0R7Oeyf0p1vHT8U6yd4wg7Fm6c=;
        b=OLiJg+2BtdD9uNJuEevv2/oBARF2ajNS05KFbwI3cp/mpQuTVX6L/XYucNjTpBXd7k
         DKoD7zA8XOTHFP5qb7yUHKdIM5Zd+fQloXJe3CJX/jNGG8KoWtY5obCP4XubXbwyAQtH
         k9g2duBld4coaIiHPiTAbZF001y1rm5yZSrT+TyD/3GmLOFfrvuqwh2RDwa1iEugXDMA
         mjoGKegH4DxypC3VhZQMMCkGXFAxQAdJKRmrpvHbse9PCYuSZvUFK1j6dJY6Jq64EyLc
         PFAfZyuBYdu/3e64Ov71zPPoKAF3k0BtrxLKgEp5xkrEheq/RCu3fINa4/jwl7irFhil
         gtcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MfYxEJgQ;
       spf=pass (google.com: domain of 3hovuywmkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HovuYwMKCRUAxx19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id l8-20020a170902f68800b0019a849a40b8si43763plg.6.2023.02.16.11.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 11:59:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hovuywmkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-533a4855c86so10526017b3.19
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 11:59:27 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:9dcb:3224:f941:1aad])
 (user=pcc job=sendgmr) by 2002:a81:9e03:0:b0:52e:e396:3ad with SMTP id
 m3-20020a819e03000000b0052ee39603admr1016051ywj.171.1676577566917; Thu, 16
 Feb 2023 11:59:26 -0800 (PST)
Date: Thu, 16 Feb 2023 11:59:24 -0800
Message-Id: <20230216195924.3287772-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Subject: [PATCH v2] kasan: call clear_page with a match-all tag instead of
 changing page tag
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MfYxEJgQ;       spf=pass
 (google.com: domain of 3hovuywmkcruaxx19916z.x975vdv8-yzg19916z1c9fad.x97@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3HovuYwMKCRUAxx19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--pcc.bounces.google.com;
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

Instead of changing the page's tag solely in order to obtain a pointer
with a match-all tag and then changing it back again, just convert the
pointer that we get from kmap_atomic() into one with a match-all tag
before passing it to clear_page().

On a certain microarchitecture, this has been observed to cause a
measurable improvement in microbenchmark performance, presumably as a
result of being able to avoid the atomic operations on the page tag.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I0249822cc29097ca7a04ad48e8eb14871f80e711
---
v2:
- switched to kmap_local_page()

 include/linux/highmem.h | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 44242268f53b..212fd081b227 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -245,12 +245,10 @@ static inline void clear_highpage(struct page *page)
 
 static inline void clear_highpage_kasan_tagged(struct page *page)
 {
-	u8 tag;
+	void *kaddr = kmap_local_page(page);
 
-	tag = page_kasan_tag(page);
-	page_kasan_tag_reset(page);
-	clear_highpage(page);
-	page_kasan_tag_set(page, tag);
+	clear_page(kasan_reset_tag(kaddr));
+	kunmap_local(kaddr);
 }
 
 #ifndef __HAVE_ARCH_TAG_CLEAR_HIGHPAGE
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230216195924.3287772-1-pcc%40google.com.
