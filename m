Return-Path: <kasan-dev+bncBD52JJ7JXILRB26XRORQMGQEW7BUVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FA66704371
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 04:35:25 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6ab02d76ff0sf7016233a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 19:35:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684204524; cv=pass;
        d=google.com; s=arc-20160816;
        b=ITf9X8vJDqMZ0vsmDl4OY72Bo9s6qjyo2jsA02gMHHQfaSUKj/hnNGX7L9+h6bzd3L
         fwKdW4QQarm7LycI5bqbTcySplBu3/d9KDBS77IMwlnvlxCzyE0BvvtDBozN6dBggR1q
         CVD0GVUgOsPCQk7Oy5hDjx0swdfJIVbIyMoRxo1lBax8rwAxGUJExC85xfoUJD2zvuvQ
         9sDlWcT8oBwpSGBOSTOT/BYXc9k5m5Yr7XrWZi96UgSkr/A/fQVDgSxeHWR/bBqz/637
         xpZRwVOsPkRQsnVRFDtvcK/GboLP8uhYvRYXGbsisDU0Lm7e/lKr+PY6FaVlGltucHNO
         61ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dmPzToyZtWTR0enZC8ZCOtoscCJs5Ad4xeRMw2r+SAM=;
        b=1H4NKQ7XoFwhTg2A1NDYKet3zxLd1/Ap8/4B4JSaevbauXyDqu4WBtgEzuPtLVl+W+
         2Nj+ZxVxD0R0d5RXThocYOtmrLxW2C8I35N71TviATeuO20p7DrLQtmagL03ji9NXJw3
         VPRGirMio99WhFnmeA2Y9/chbYPakXtsTtJ0wXk/FNWnRvrMv0h0IXFZE0Fdaun+LgOq
         9dUN60AwAj8gitb1/hQImxUUsurxZ5cwK9hs+G6SnP0h2j9Q2LiM4mxQRen2WYrV7Lyg
         0mHUnMUCSq9tEijhfw5Pf6N0fdQo/XFNssG1GM4/Yjzd1FPDUXzAP88yuD59J53RGZlT
         +lAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5CElQQQJ;
       spf=pass (google.com: domain of 36utizamkcxckxxbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36utiZAMKCXckXXbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684204524; x=1686796524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dmPzToyZtWTR0enZC8ZCOtoscCJs5Ad4xeRMw2r+SAM=;
        b=dCdCtz3TaFWHT0m/xUnfigAx9Hc3HNy7xzoQ00i6GX1hSUp4MF711tVR+lj1MYGVsS
         BTfpQGgxQcoQJK6NAu/PCR66w+UaEUrz0EjQUQFmsfTSmp1MDgX1DHv/jd4gInn8+rUo
         13hiMPyaeBrdsibhrhTFu1HZe6FUG8K4jTc40cGzj9htx7GpmOciLdPKbNceEeDN8549
         9lDh+5cYrD09RMjGEb65J9nZv5ThvHZYhRtNSGJATCoBitC7r40ExrMWUmMq42Nse7GT
         RTbxvC8De4NdRK7zfGJbMviO7b/AbcNh070GMljzUtR+4XJwMyZogZWLZ09nPkU7pDT6
         fWeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684204524; x=1686796524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dmPzToyZtWTR0enZC8ZCOtoscCJs5Ad4xeRMw2r+SAM=;
        b=Mnz9B6Eamfe5047X88u0+QwMS/ov3RMcP5X3ndedDpGXGqee+k2Gfb9a/wD5ibVd2n
         8l9X5iQcJQMjcnv9xr/CdwEDZ5qKTd+poHV0VKsQVTaSy4ferRD6TKLKnGF2CbUVwrXC
         Jd/o4MJgXSOifxOYgYEaqLp+XNmbnPbTxFqpN91qKlFhCKIOdzZGzbACQRuzhv3vZhJV
         UluGraPVbgeU5ovCKC/7qZ7f5wGms2rS7aROm4KLXuApWK5lE49l/lKX0csfAfNpkhbH
         QrYCDsP78t0M5NfHHd8LIIdLZQcYjohbn1i+CPgNiPaCheCfzSIT0BoCQZsrUlonHj6O
         xlVQ==
X-Gm-Message-State: AC+VfDzs3UnJwBFmdbDSqfmCHh7+G/0QAlvrZGZxUXmjowfM0UvYUF9k
	SFKL1vyioVN6Y6Y8XD/wkIk=
X-Google-Smtp-Source: ACHHUZ5iC+wulx9dlH1Jo2/ADJc0x2FvmqD+vIJnjemPPr6AMzXfKxRb+B8dtJHN1dGvmE7CDu+XAA==
X-Received: by 2002:a05:6830:1086:b0:6a5:d944:f1d6 with SMTP id y6-20020a056830108600b006a5d944f1d6mr5690877oto.3.1684204523861;
        Mon, 15 May 2023 19:35:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:bb96:0:b0:547:e5e:2ff2 with SMTP id h22-20020a4abb96000000b005470e5e2ff2ls1950400oop.0.-pod-prod-04-us;
 Mon, 15 May 2023 19:35:23 -0700 (PDT)
X-Received: by 2002:a4a:a5ce:0:b0:552:3abe:f179 with SMTP id k14-20020a4aa5ce000000b005523abef179mr6355504oom.6.1684204523410;
        Mon, 15 May 2023 19:35:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684204523; cv=none;
        d=google.com; s=arc-20160816;
        b=VfmIl4qkTCvPsx29btbnNyQlsc51Suyorc0nKbFKue3cCGwPPlGFHuK3nnUFg1f3n9
         P0dVeHcGw9KCxUn3J0ox+KETPSQdF8wkDvZ/FpUHECJ81kdQAgTixSv1JCdbrHrJ2jRq
         HZPDv70HZJnhurrdt+8lmy3KW2hLViYiTjNuIU7s8Frrau6Elllh24LiCbcukf5FkAmR
         Gb76zLsIYsxL43fSByx7hufTBPKPUIMvlFOINfbZJBNuNr3kv9aGH3cQ++9HfWv1ujD+
         WXeuiKKuMsWpRDOKqYVvthFZGRGq03XVK1izO5GvIvKmXv5iGviQiPioD9L/mpRoejEL
         cb1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=BNa4l1F+5QMrqUAe4k1x2vD+9zG0bZzdq9LlZrfkoEE=;
        b=T1NiC/Zau0rwZkR7PcKPe8EMWwStDWS/DqfXsUyJrA3WVaLc7+0JP1FrtC3PDs4i+W
         0ZLcWo3JyzngP6SOQb8M9HVmGBUyCXDoKBHy8AdjPeUQ/IabehQXCV2fi+t8xuwESos3
         I8Qd9CvR5N3mL2YoVSfz9y0GWuzSeMfRwbbpW//cGqfB9MlWKhaUZWkcCiBhXu10xcHV
         wNGY4T8vCBeLQO0f+XIXiElw1K4YfoRkhqLnvc57DeM80b0miwDxsPeMGyyYlXXZ/ZHp
         qfCCzT8m0O4cfOEt90G/ZuCctm4BvmL7kn8rCtYTbORV35HVow3ULlO8ZyNZYAXLM/VF
         xbXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5CElQQQJ;
       spf=pass (google.com: domain of 36utizamkcxckxxbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36utiZAMKCXckXXbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id bp15-20020a056820198f00b005526738f83esi747309oob.1.2023.05.15.19.35.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 May 2023 19:35:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36utizamkcxckxxbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a7e3fc659so30154503276.1
        for <kasan-dev@googlegroups.com>; Mon, 15 May 2023 19:35:23 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:c825:9c0b:b4be:8ee4])
 (user=pcc job=sendgmr) by 2002:a25:d8cd:0:b0:b9a:703d:e650 with SMTP id
 p196-20020a25d8cd000000b00b9a703de650mr15802130ybg.7.1684204522988; Mon, 15
 May 2023 19:35:22 -0700 (PDT)
Date: Mon, 15 May 2023 19:35:12 -0700
In-Reply-To: <20230516023514.2643054-1-pcc@google.com>
Message-Id: <20230516023514.2643054-2-pcc@google.com>
Mime-Version: 1.0
References: <20230516023514.2643054-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v2 1/2] mm: Call arch_swap_restore() from do_swap_page()
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=5CElQQQJ;       spf=pass
 (google.com: domain of 36utizamkcxckxxbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36utiZAMKCXckXXbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--pcc.bounces.google.com;
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

Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
the call to swap_free() before the call to set_pte_at(), which meant that
the MTE tags could end up being freed before set_pte_at() had a chance
to restore them. Fix it by adding a call to the arch_swap_restore() hook
before the call to swap_free().

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61=
020c510678965
Cc: <stable@vger.kernel.org> # 6.1
Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@mediate=
k.com>
Link: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.=
camel@mediatek.com/
---
v2:
- Call arch_swap_restore() directly instead of via arch_do_swap_page()

 mm/memory.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/mm/memory.c b/mm/memory.c
index 01a23ad48a04..a2d9e6952d31 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -3914,6 +3914,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
 		}
 	}
=20
+	/*
+	 * Some architectures may have to restore extra metadata to the page
+	 * when reading from swap. This metadata may be indexed by swap entry
+	 * so this must be called before swap_free().
+	 */
+	arch_swap_restore(entry, folio);
+
 	/*
 	 * Remove the swap entry and conditionally try to free up the swapcache.
 	 * We're already holding a reference on the page but haven't mapped it
--=20
2.40.1.606.ga4b1b128d6-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230516023514.2643054-2-pcc%40google.com.
