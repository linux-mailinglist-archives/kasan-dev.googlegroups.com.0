Return-Path: <kasan-dev+bncBD52JJ7JXILRBXWSVOPQMGQET3VOYCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2855E695628
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 02:52:33 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id mi18-20020a17090b4b5200b00230e56d5a44sf5354197pjb.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 17:52:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676339551; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTV8wk1/5wXF/aep9qeIgMrcuLR673XJBTn5a0uGEL7r7uEbGlj9rHZUHG6ldtxjn8
         PXxuSxw4dIvgwXuNBs0YYLeeXQaSkTRCWTmDkznyLddTKlR9b+LrW0Nz+2kxLe7/Cb+o
         L9oLN616VJEDBbosMhLlngHsImHIxKMhE1pmnneyacSNwps47rsHMrTwfhhANWkfnyGB
         AhghFBOvVJR+P/6wkKOyQXbTfRQKyJX2mbVw1gzwkCkT7nNEZhTDHZtD/gZTHKE5RU47
         EVggRxP8ThZ9psAaJwpTHnXjpuIa7S9KEcdiBaqrEkaHmIJAMk+DxpcjfhQdmRAWOWbW
         Tl1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=JZDSkjHtpDwEBsEMErHcvxqPadKF9TeYUkx3JOGYOng=;
        b=tmzJdjs0NTAjb8n2iY9r4GyjffaSWt4IuZ4drNT2/G9I//i4y6RQKWVRvSyu54AtM5
         XE4f/9a4VwlCImi3iJSN7hbIMY/9C0PbkES6VJcFGD/w1dmqLCPI8KhWdyUTKtruOFko
         qbsrpEtZSu0SHDoC+5WLpa3BvOa1rhQ1GqPBFu7B7HlLZTeWOLXkTecBYQC3GjnAtqkR
         L5IGISDBkKpOZEpA8wBKPqmogH8FPPGTkioAhFq1mITV/uGcQUoCILf+QSjMgujpmZ8j
         nYOhs3jrXxaP/eZ8T4KW4kPNmAs8iwOyVZRgFFD/yJHprfI8u5aJ7WEHUY5zZk8z6vte
         OFbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cF3vp2hn;
       spf=pass (google.com: domain of 3xenqywmkcqireeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XenqYwMKCQIreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:from:to:cc:subject:date:message-id:reply-to;
        bh=JZDSkjHtpDwEBsEMErHcvxqPadKF9TeYUkx3JOGYOng=;
        b=BoyCEX902sBRAtkescUKDLKXHvgviobZLil7XD38LQ8Zfc0ABarsUpEymrRbcWCcVU
         6ZMb4SXQui+tqP84/zi4ukJweeYP9k37LMXUvaY1JXpDfr4WyJI0TFZzPyrpqBp2jbpW
         IR3uatKX5zP1tAgNVetr9ALwed7aLyiJGYs4gux2OyIdStYn1RJ+/kWQpI28lf+5LSyP
         VCEDbwJdhZeLheLmkpjM2rdVyJDXS/C4QCxaAod/qOEkUnW/ds52Z7cStA/Vmig0ul88
         +ozBJo080vqsF59lqBgWM1eR6AyScvHxm6nHwwZC4PwyYruloEF03/FMz376Fj8p+y5V
         XJ/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JZDSkjHtpDwEBsEMErHcvxqPadKF9TeYUkx3JOGYOng=;
        b=OnE1iNiWdCaBD3FdnGkqUxUeVqUFz1fcClycFs7+Z114IxmKT4USSlt0lTmW4NyddW
         KvOTLlzJiAl658K3T9zRDk1SXTBKvn58lNELT5qrt0hQFr0e4Ibomw+6oDXhtEmLydFh
         xJALJQlN9BE5xJbpl7fR2eOycb03OduU8uHHng8xaKo9H7RvkK5ReSqMfDUrdCVMtX6w
         lnrIX8KcEVrSV1Pg8TJ0HONoMx5iakAB5GUodehukm5Yp+6kQFeOOePEQa2lDVr41JOt
         t83jvExr3tOzHFk4uNoWDXYmBiN1fdWb3qVxTIOl2cAw4fRzxY+sC6fMyD4StGrkNoIk
         62sw==
X-Gm-Message-State: AO0yUKVZSsY++LF4LCt7O2R1kRU4N5l1VVOm6KEJ76V71DxWmJfQTOvw
	0Ry+ROu/yaWfS1iiMtLJU94=
X-Google-Smtp-Source: AK7set+Rtoti6oLuOBK8kJLtEnYFJ4CrmIwKcC0OxSuyg4yllJoPTF9mPVEQ8cfqa0Yp/saEkbfCEQ==
X-Received: by 2002:a62:7b83:0:b0:5a8:ad86:81a3 with SMTP id w125-20020a627b83000000b005a8ad8681a3mr119128pfc.25.1676339551123;
        Mon, 13 Feb 2023 17:52:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f293:b0:199:50f5:6729 with SMTP id
 k19-20020a170902f29300b0019950f56729ls5132511plc.11.-pod-prod-gmail; Mon, 13
 Feb 2023 17:52:30 -0800 (PST)
X-Received: by 2002:a17:90b:4a02:b0:234:5eb:2177 with SMTP id kk2-20020a17090b4a0200b0023405eb2177mr716112pjb.9.1676339550368;
        Mon, 13 Feb 2023 17:52:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676339550; cv=none;
        d=google.com; s=arc-20160816;
        b=nxImbs6DZqME355et538kkPIj4yNdDYZXErN7kL48E5UWycPJ6ReEeoLPTBIY07j0h
         +Qkhvk7SK3uuJ8nUamHd3KLEn87jIqatVxgiXJSaqS2SJdWAH9AmOdnm0rdi0rhpUNM+
         hcTx/iT9bnOwNN2dGwx2ev2nU2DTuS3dzHQem37xXEF1DAKqe647jy2T7uLZ+Em8uvQB
         NHoyQdsLP5/qOovx6bqD0oxxpFXvr0iGSj00yO24Zk2NLHjcNoQyvL2ha874ykpYaDKF
         eV/JZCvZHBHWtvvGVgOg6FB6ZxREGyxfu7m5GfdHFmPX1v3+vQNxFBojHyFRq+LM0C1R
         XcJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:mime-version
         :message-id:date:dkim-signature;
        bh=2J+3GOG2P0hnwklMWKGq0tLBKfNtpEESwIEDcAq6rlI=;
        b=r6m5proF0bCRk5qSgnBlRDPCE5Ae/8RwJCz5DuRl72ZKXtfzTQ1EQ9VHfbNWA1K7Tr
         J0ycaegtOsQA21lVzE4f/sQj24BUD30pLFa/IZOklhj7VVzJ6nnsZUlJaADL/J00ktqL
         E68RbQYh1iHInguVHXjJNs1DqP5Sxb9t/l9kAr7q5JZV/lPchRRvhIMg9s7AYuF+9Jb7
         o4nI2lHSb1mGpOoB9edazeGlwO3/vvar6YlYHBLzi6rPQikyct4Ig4xTS1GLIb10bgxW
         pZCdFUux8UFlcBRQMy1GuxiExWiXzd9hY0xhJDQgobqmFF8SRl47Vl/AA3NmUBklDsaK
         AXaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cF3vp2hn;
       spf=pass (google.com: domain of 3xenqywmkcqireeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XenqYwMKCQIreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id w2-20020a17090aad4200b0022c4c6f4b8dsi499649pjv.0.2023.02.13.17.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 17:52:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xenqywmkcqireeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id y125-20020a25c883000000b0086349255277so14239740ybf.8
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 17:52:30 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:6153:a2b0:1bfd:87af])
 (user=pcc job=sendgmr) by 2002:a05:6902:1147:b0:8df:1fcb:f1c8 with SMTP id
 p7-20020a056902114700b008df1fcbf1c8mr9ybu.2.1676339549200; Mon, 13 Feb 2023
 17:52:29 -0800 (PST)
Date: Mon, 13 Feb 2023 17:52:14 -0800
Message-Id: <20230214015214.747873-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.581.gbfd45094c4-goog
Subject: [PATCH] arm64: Reset KASAN tag in copy_highpage with HW tags only
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
 header.i=@google.com header.s=20210112 header.b=cF3vp2hn;       spf=pass
 (google.com: domain of 3xenqywmkcqireeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XenqYwMKCQIreeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--pcc.bounces.google.com;
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
---
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
kasan-dev/20230214015214.747873-1-pcc%40google.com.
