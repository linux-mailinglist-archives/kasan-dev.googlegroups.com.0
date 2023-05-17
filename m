Return-Path: <kasan-dev+bncBD52JJ7JXILRBJXUSCRQMGQEQ6JTQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id D8C49705D0C
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 04:21:27 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7578369dff3sf623516585a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 19:21:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684290086; cv=pass;
        d=google.com; s=arc-20160816;
        b=UdBVoQcBxcynGL32KQLbiNFilo4k6rr6Tq8UqdWKqyykBt+K5+JhMJh2mVJWCl/23F
         pDgq014G3FW1VELKzc9uyTAktVD8vAkQm5JEXvYyHY1EIJyMwx6c9wyNxkmwt+BPTMU5
         W5CM6Uotge/eCouYn3taCoLXyx2SjgG1C72B1ReD1u4Moc0YRIrrXVGYC4r/koeWNCmm
         Fs0xBdnBqrJgb0fj8J0W5WJQlyzBNz+9jgjNunQQ0v7z10JB5qrUPrKClN4LopZriBrN
         gAXK+vrvug9fg7xNyNgJuWm8n0gqiV7tq3rXEYvPrzdmA1C9qyFWzBdHb7rYXIddIesH
         fgfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nfJN2RvChZR20GO/29snSpwK7ssQK3L3JyGApZ/ov7s=;
        b=qWYRSwIT+dlhpg88DkbGkQTEOnui9b7+ox6PnHpQ4XvZuAOacHARrbFQa7OZsEiXqM
         YzABRirczqu2iyu0ShAZscJq8iLuiqR97wMj1Qh2z22cgjtAr5NE5J/x+bAZGmiw+DIR
         FFqQ1X/D4V7gs8nkqbnmXkIv2wux/dg5aztEPMKIYaw2olFQuLZcK4kCrpIA/suHZksk
         ItYcOIGrb/zrGcAYNWXXVZk6cZKVvVWdl8/e9SNlnU6hyXNGJlSRu0PQmVKN1puCii6O
         cKG9FlXwpR7mLnJohryIQMImQcprPjk1ETA0LNPJDgN5LKgdELbNhGEBUi/lc+Rx/jZn
         o3SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="kU3u/jVP";
       spf=pass (google.com: domain of 3jtpkzamkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JTpkZAMKCVQByy2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684290086; x=1686882086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nfJN2RvChZR20GO/29snSpwK7ssQK3L3JyGApZ/ov7s=;
        b=NpF9gy7+HC+ywZkFw+Eeo0v04dTwcNwXoBhXnBeW1Wyi95wYjQ3Ry4++jDq5VM32R3
         fCwEG6eWluQ0xorDlUi75f+IR8ADk9CFXcnShpOfYzpkc3CAeoVKwQkOxP8waeYC7p8w
         h9cGTgf88Uu64ju0chCe0pDL8tC7OCI7Fk9qQaEI3Z1CLlkWY82/5PLiBlJOce2+N/y2
         8r/HWg9LFB4fbgwqeBeuh+uCfK7gW60nlnoDwQE85yIn49GfN+CZfAMMzQsuf0u/5kbF
         90p2OrzLLj3/kbk338VeiqSqj3PQ/U2aTrGWJyBDx1Y/kMKdmVatVPaSIyKdHYaNSA9J
         ZmGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684290086; x=1686882086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nfJN2RvChZR20GO/29snSpwK7ssQK3L3JyGApZ/ov7s=;
        b=RYPVuzD+WU0up5jQ1rgID/P3BvzkOxykQL2JUCF2YY95Mi71rwfFSVqoYGEsfTzuJw
         Q2A2Zdni0BQNswxiDgcyIwB4yQD9bmIwH882WZX2TfcfnQ4gxeDdIOzJIgImXgdY6FBk
         jyTYL1R0/GZzGOSRwsuL5RJLGg4OABG+eQSJIlSvRmeNeFzyp46uEBbOJDV3CWxhBw7p
         Jiwyn7FhsNA7I3OEUzoC3zkAfow/V/CaaoPrEZevoCvHzbqFbG15dzAScGmPArU3Nca/
         HwXndPlyDOTntIGXGb61rpzTiprbWrc9h9nbvwmcfRflqKDOR+UodCzKP7A/a2PkRvnh
         5giA==
X-Gm-Message-State: AC+VfDzmlVPg/MYd5KOHy6lbBYbfym+pJJwm+Wt6tojXgBAMq8OOMUgY
	p4dX3vlYRKGk310iFqPsOss=
X-Google-Smtp-Source: ACHHUZ4WYPJa20E9Uf2PC9vu3U1FP68zjxQfOGpVheiRuVRAvyG/YQh1qcARmQDW7mtB671lLAQ9YQ==
X-Received: by 2002:a05:620a:199e:b0:74d:f736:a060 with SMTP id bm30-20020a05620a199e00b0074df736a060mr612169qkb.6.1684290086594;
        Tue, 16 May 2023 19:21:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:428a:b0:61a:86aa:41cb with SMTP id
 og10-20020a056214428a00b0061a86aa41cbls4073376qvb.9.-pod-prod-gmail; Tue, 16
 May 2023 19:21:25 -0700 (PDT)
X-Received: by 2002:a05:6214:76a:b0:621:fde:7239 with SMTP id f10-20020a056214076a00b006210fde7239mr52157728qvz.42.1684290085744;
        Tue, 16 May 2023 19:21:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684290085; cv=none;
        d=google.com; s=arc-20160816;
        b=W3SH9RENt1XdBlYAKS3/wwIsR76GxZTHdGz4UgtJejccK+IsdK0yrsn3xkdcHlV6oA
         VpzalXdS78dJqFUBww+2HEY2geXdRyLqmzOclky/exR79mrw+F7s/h1n6ngRqw1+lImk
         A8Epbr07fYRv0IQ5k3HWpe2HOAdsgolPCVcBhAej82XORC11Ct8i8bRVu4vRwuwxwjqE
         +B9r3EfOtsmA6vdrk49HeXYm+YoU3a14MM0AniaVfSN6u1wWeW/ndEBk+bmjjboePZjE
         4cvFus0bg8QTjJlZZJHtIHJlgzM/IHv5FK2GXxdFD6nGsWop3gDFZvRGLO2iEseber3w
         HYwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=icy+EhZ3UBgzX+LkBKZmwy9I7D5yLVOL3MyBuUnW0II=;
        b=hpPtJ8wUzG+1NS/c5kmEv0Y2Dx+7Iel5PAMLnZKr37hwlokJXv5LbrKJSwDvWOwedu
         EqjP3b09zxoZ6JDRc/6ztNq8p/JqZujQKhWGM0tztt5EZ6g7LeKf4K+3Fpxr7EUqdOWZ
         PJ0L1gKaoVjUoQakbIGyno3f30uJXWB5M6pMEWz0GFXFO8jbQX86aD+LXLryvki9SNfc
         K8it4iTb16FG+64Qt3PB6lwSrDk3udenRVGG7L7gzGSK/GLIxxOtOxQI5gj2n+yN6AqI
         NU9XlDyKwdJZmE21kqTCi9FsEG+QtL2dxogn6KpitwnwpwYye2faojCj294afpYYhFd5
         J07g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="kU3u/jVP";
       spf=pass (google.com: domain of 3jtpkzamkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JTpkZAMKCVQByy2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id rr12-20020a05620a678c00b007591830af64si75987qkn.7.2023.05.16.19.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 19:21:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jtpkzamkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-ba81b37d9d2so220671276.3
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 19:21:25 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:b3a7:7c59:b96b:adaa])
 (user=pcc job=sendgmr) by 2002:a5b:309:0:b0:ba6:a54d:1cae with SMTP id
 j9-20020a5b0309000000b00ba6a54d1caemr8869621ybp.0.1684290085477; Tue, 16 May
 2023 19:21:25 -0700 (PDT)
Date: Tue, 16 May 2023 19:21:11 -0700
In-Reply-To: <20230517022115.3033604-1-pcc@google.com>
Message-Id: <20230517022115.3033604-2-pcc@google.com>
Mime-Version: 1.0
References: <20230517022115.3033604-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v3 1/3] mm: Call arch_swap_restore() from do_swap_page()
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
 header.i=@google.com header.s=20221208 header.b="kU3u/jVP";       spf=pass
 (google.com: domain of 3jtpkzamkcvqbyy2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JTpkZAMKCVQByy2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--pcc.bounces.google.com;
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
Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d43=
4.camel@mediatek.com/
---
v2:
- Call arch_swap_restore() directly instead of via arch_do_swap_page()

 mm/memory.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/mm/memory.c b/mm/memory.c
index f69fbc251198..fc25764016b3 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -3932,6 +3932,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
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
kasan-dev/20230517022115.3033604-2-pcc%40google.com.
