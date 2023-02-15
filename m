Return-Path: <kasan-dev+bncBD52JJ7JXILRB76RWGPQMGQEFIZNOBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id AB1DD6975B1
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 06:09:21 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-16e0874cbafsf3854183fac.8
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 21:09:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676437759; cv=pass;
        d=google.com; s=arc-20160816;
        b=t4T3M3TriNL7oSvON0FGsbn1MqdoI9S+9V63UdlwR+l2q9ZpF4TF+Wp6xVBNeY4Jsp
         COTgXwSx31mlppvY54im3YU+4+F/ClMs0+cWIaTKCFYrG9am/uqwN1Y5NwBPItjdxJAK
         qWHYE0CIbRuDVfqNNk3vEW702g7sIUlePQySB4N08PxDKm5dikzVbGkphTVIPTVC+xlz
         eIYqrVoBTvk4m1p3URKNRHk8KgfuDGvZvR/G7c5OOaLq4RLr1uvJuaRHAsOuGnpnKYXG
         3pel4E641m267OCdfoGuhKj87t6JFr1Jwmqiku5pQhjpiUyW5jwOMoOU+4Ot3gUV0irN
         42Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=VzNlEBjkJts08HHNknIT+EoEgtOnucJRSkALoR+LhJg=;
        b=ey6P+1rr3EqRvqPLbRCCQ/Xnmuw8k1F9f6m3QAtbKqmRZ4KUUgMapFCYcWflH1xa5M
         bbvhn+l6Mo/jRAjYtecOQYrsbbY+2Tz8BSxvg7EzaWdKdD3inZJQBHSQU0zig3iP9KXE
         i/1icC/sJ6rrafimo2IuYVkH0w5V8r4TlZ+1/tshstNBx7UpDGnPeQL6KV5ViAe8160B
         l1hDNz1cDFJSVwwGn8JgEMtDq8A4R3HwfzKLYQYRjgNwNVPzh9vQ0ucpuUdI2NqN4zIE
         6Hocoz49bnnHcePv3ZSbJ6BH+mILXqlQ/e5jGvOZZshPxMp8BHT2DxOoS6pAI45HWFev
         yT2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PAVs9wTH;
       spf=pass (google.com: domain of 3_mjsywmkcacwjjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3_mjsYwMKCacWJJNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VzNlEBjkJts08HHNknIT+EoEgtOnucJRSkALoR+LhJg=;
        b=nsWB02+2IySL+jiUWUDclSvxa39Wgz/B20DbBGsyBpIx9bEZcWCvSQwD/rhPbA8Y7y
         fX4VSBR6oDeHZT6ZWO+FuFsTJYlXG46yCVHHcVFe4Gt1MUg9nkYRFnjxims9VOFWQwaF
         3Q+MKZ9Gpjiqo9mtS6qNM2fb4H63jn8b4ZH/LxWO2asWebk4IwemD1TfkTKGfxpH+MCo
         6yJtCjpI4A2PylGQ+giOlzRgwE0jW9EQ1YLyJzZ8ZmThSHSGbUzu9zBbWwZhQUT2ubi+
         DIygD1fGD33INe6WEzYqJ7JCZw4UeQaDH5ASIpWq9pt/PHXdThKTvq1IdbcaX0YMNUPl
         +BnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VzNlEBjkJts08HHNknIT+EoEgtOnucJRSkALoR+LhJg=;
        b=q9UDSTClpMmVWImWCcdGmd5IinCgI6Ub1VdU7q6bF6t7qBLv8l1YM/ukDU4YF0kLGu
         EJtgJdSY3Em7JEbKR1aeTi7tg644RCYb87z/2KOJZx0Nx4+55k8m1QMdmZ729I2JY3xB
         PpIfeXvytxYU8DoeqyDevhPqw1S/MpZCmzAr3ykX+/ehnovfgszGmPMEIowJjXLLpFQr
         AexdZ+WDLOuGYIkl3nPkZ30L6Ztr0a7LdeyjGfshZT84dgS0R5Q+6bqSDxX/MI6D6Gix
         L+kTQh12mQGmeRjPq1RDcfDjuoHQ0Y+n+figcTNBa+H/736ljwhSaK+ztdU5gf1rZjBv
         3eLQ==
X-Gm-Message-State: AO0yUKWTT/ft4ViXydjcem6vMnUslU/aC1qDMtAOgnKK4v5r+Cy35ayj
	MHdC6RhRYgH5S8ttAdQ5cYk=
X-Google-Smtp-Source: AK7set/wMT2CoWYtZNkB6Ygctlo0by3iKCEo3objr7w2x9DMAx/J2euMDpblhhISwOyqWBN9S5xbWA==
X-Received: by 2002:a05:6870:a551:b0:16e:ddd:ce26 with SMTP id p17-20020a056870a55100b0016e0dddce26mr135111oal.45.1676437759675;
        Tue, 14 Feb 2023 21:09:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:efc3:0:b0:374:cdbf:d1f8 with SMTP id n186-20020acaefc3000000b00374cdbfd1f8ls5535824oih.2.-pod-prod-gmail;
 Tue, 14 Feb 2023 21:09:18 -0800 (PST)
X-Received: by 2002:a05:6808:3a97:b0:378:67d5:3d0e with SMTP id fb23-20020a0568083a9700b0037867d53d0emr275950oib.33.1676437758769;
        Tue, 14 Feb 2023 21:09:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676437758; cv=none;
        d=google.com; s=arc-20160816;
        b=dPXev7m04K4b+H+yJCsadsEPbU3idsf6Na19kmXXghnJkP1iOlNqWWGbFcYrA+4JTc
         HERfZnEFVUooS4F6zkicP/07+JToLtJJexhbsFlnrI1JYbpYBs98mZfsmXHfNmCXB4jo
         rIKX0Lq9Sq4u3wEvSqFyg4RU0Pf/uBK32MqT879FvSwh6jqGxyY0LWyydD4MT1IYrS1/
         vEVrqP2QLxYU87aLaTfXQ4kWrdE+yfqcuHsU7qaZIaZlT4d/QCHy4dYTz7Xi09fIi6dB
         SsgMp5ZggW5xz+9xLPYoOLeup4j4m4MRbOfScKNwNQu25SLVp/R07wmobi4i5HpFzjGb
         pVhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:dkim-signature;
        bh=oz1c94+PpSpdOwRxmJhtyfwix/rF7URLVnLJpJ4OuRQ=;
        b=m9zsWz3e1vpEPH2oxRYJq0iQRAB/NIp+u7wFuNrZl5zMhwcqvG/k9rW3X3NXeetwqq
         XwKfGUziVHzViHp9TbseajGaMApH40KtZBo4uvfP2nCMSSgk3h0mGMMv3XhRjpFJL+D9
         6D6iPEAmEAdAWf9DHPRe8qaTCQ/t6BMrqx7wepGvYpT50l5W0vndRU6x2+uZVilzvH4n
         6DmHhQQHe4oG3wqr54Fx/+OD/oufB1JAVKuwncnWTr+qI+sEND+IEGTi9hPo7+j1i8Tk
         iyFEDgUDtnZoZ9H2ytiuKZHHeP5cMPufOiH6q3+wLesDsZhgmPOS9TuSCkXaqGaIx3NY
         FKew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PAVs9wTH;
       spf=pass (google.com: domain of 3_mjsywmkcacwjjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3_mjsYwMKCacWJJNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id y126-20020aca3284000000b0037f7b2015d2si3797oiy.2.2023.02.14.21.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Feb 2023 21:09:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_mjsywmkcacwjjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-4fa63c84621so192625067b3.20
        for <kasan-dev@googlegroups.com>; Tue, 14 Feb 2023 21:09:18 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:d5d8:eed0:c0c1:29d7])
 (user=pcc job=sendgmr) by 2002:a05:6902:341:b0:8bb:3a1:e811 with SMTP id
 e1-20020a056902034100b008bb03a1e811mr129660ybs.348.1676437758447; Tue, 14 Feb
 2023 21:09:18 -0800 (PST)
Date: Tue, 14 Feb 2023 21:09:11 -0800
Message-Id: <20230215050911.1433132-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.581.gbfd45094c4-goog
Subject: [PATCH v2] arm64: Reset KASAN tag in copy_highpage with HW tags only
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, 
	"=?UTF-8?q?Guangye=20Yang=20=28=E6=9D=A8=E5=85=89=E4=B8=9A=29?=" <guangye.yang@mediatek.com>, linux-mm@kvack.org, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PAVs9wTH;       spf=pass
 (google.com: domain of 3_mjsywmkcacwjjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3_mjsYwMKCacWJJNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--pcc.bounces.google.com;
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

During page migration, the copy_highpage function is used to copy the
page data to the target page. If the source page is a userspace page
with MTE tags, the KASAN tag of the target page must have the match-all
tag in order to avoid tag check faults during subsequent accesses to the
page by the kernel. However, the target page may have been allocated in
a number of ways, some of which will use the KASAN allocator and will
therefore end up setting the KASAN tag to a non-match-all tag. Therefore,
update the target page's KASAN tag to match the source page.

We ended up unintentionally fixing this issue as a result of a bad
merge conflict resolution between commit e059853d14ca ("arm64: mte:
Fix/clarify the PG_mte_tagged semantics") and commit 20794545c146 ("arm64:
kasan: Revert "arm64: mte: reset the page tag in page->flags""), which
preserved a tag reset for PG_mte_tagged pages which was considered to be
unnecessary at the time. Because SW tags KASAN uses separate tag storage,
update the code to only reset the tags when HW tags KASAN is enabled.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/If303d8a709438d3ff5af5fd8570=
6505830f52e0c
Reported-by: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.Lee@m=
ediatek.com>
Cc: <stable@vger.kernel.org> # 6.1
Fixes: 20794545c146 ("arm64: kasan: Revert "arm64: mte: reset the page tag =
in page->flags"")
---
v2:
- added Fixes tag

For the stable branch, e059853d14ca needs to be cherry-picked and the follo=
wing
merge conflict resolution is needed:

-               page_kasan_tag_reset(to);
+               if (kasan_hw_tags_enabled())
+                       page_kasan_tag_reset(to);
 -              /* It's a new page, shouldn't have been tagged yet */
 -              WARN_ON_ONCE(!try_page_mte_tagging(to));

 arch/arm64/mm/copypage.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 8dd5a8fe64b4..4aadcfb01754 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -22,7 +22,8 @@ void copy_highpage(struct page *to, struct page *from)
 	copy_page(kto, kfrom);
=20
 	if (system_supports_mte() && page_mte_tagged(from)) {
-		page_kasan_tag_reset(to);
+		if (kasan_hw_tags_enabled())
+			page_kasan_tag_reset(to);
 		/* It's a new page, shouldn't have been tagged yet */
 		WARN_ON_ONCE(!try_page_mte_tagging(to));
 		mte_copy_page_tags(kto, kfrom);
--=20
2.39.1.581.gbfd45094c4-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230215050911.1433132-1-pcc%40google.com.
