Return-Path: <kasan-dev+bncBCF5XGNWYQBRBGP4YWOAMGQEQ43SAVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 680706468D3
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Dec 2022 07:03:07 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id e37-20020a635025000000b00476bfca5d31sf391034pgb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Dec 2022 22:03:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670479386; cv=pass;
        d=google.com; s=arc-20160816;
        b=GE6628tmcAGMkroLy4+wR5RvN0VBMgSS38Qlkfg1iKo+D5YCgvGA5O2G4sBdC0CTGw
         1+4qzNDzM5Ka/Sz0hPXWdnnm6hr08yR2sJ9+nIul18h6LEeoe9e/Ie/aov6sOrDtqmmw
         IcoFTJaKoaSnFKz6uwkC2QZblflUOMORejvQWHYaDxe3GJSMhVnWQT68NBwyPR3MT0w1
         9NRDh5AYMnOKSCJSPllUVdmaGH9iJ/21xDAUMXRGHORWdNx7uAbLU9IWddKIVc0wG9JS
         MAGHK3xcCIFW3KZDrd5/aJ7RArpafoxRtBRhnxtva66lis53S/bNmbmRPSv9UR5czAL1
         SYng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dyZpy34bbMZ2H4t9BbEuKSLbZEJRZgWqFGBU7lB3NoM=;
        b=M06s1Qj2DFkx/d57M6Xd6Lpp1X4q7XZOFSpVRFB5czXakODJrVXhiVSFiw5qUdxfNH
         S/IsxWT17hTJtvE3AlBCFiYcw16dOhndm0IY3uucBExYc9PWseH5tuBhbCpv9YzV00s2
         f9rNDpmQPspRG7PeC6TCqwGabuP1m4NnCJNeQ4Inpb4Nqaz+r6ggKQ2tNjtNdcVp5Hzf
         K5nqGIDCVIUqg7i1hbwlzcG7Lq3rly+YnzAqRkr3LtUXeIYebVU35F5qY4fkfqUeKAO1
         S/EycxOmiLUmncCkl6a/ttUeBpo59rSXNUzorCJEhNV6WVic2YVHR8u9BtcVXvt1NUDk
         gUAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QD4UFIWq;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dyZpy34bbMZ2H4t9BbEuKSLbZEJRZgWqFGBU7lB3NoM=;
        b=jrz71MMKPThZuYLZt3x24BIev70FETZC+ga7IHkCujgKN6F/DJ9m0CnA35dHLG+FLd
         AULIz9PxnQ2nea7YDp3uq5upFfiIguE9g2xIa9vkMenG0RhUgl7X1NnXapNrKgrCsqb/
         m2Re4X3tbpqBElJZdNqyyzoTuSc/VvUf3vtzcwDdb55F8YiMLvPOm0vPKexVGJTLa7KN
         547SiLJld5QsW4EsyTDzs+tnNnFMCn7DfcygKlFL3n7MSOl3AUt36NXAB1HaoVrcL4j1
         hQtnc3ymivUK3W4amL4fkmXBswSdFbQFA/iPiB+zR/n/L3Omr7+1loUoJEdXc881qlHP
         oKUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=dyZpy34bbMZ2H4t9BbEuKSLbZEJRZgWqFGBU7lB3NoM=;
        b=pOoyD1sWEaTCnijZlTS7gHbvnRWgJUphYxTgEBWMgZdbbucEY9sEGLocm8XlWAfB6K
         rHPQL+QC4crkFNXj0eS2jVysnFyobSnqPaZY8K47PJJejM6igciptcS3AGYAd+qnvm7C
         Qcw1dkapwza1ZR9Rj76pBt2ZCRzAZGmWfWQO27nW4BjqOgb1rOJWmnG+hYt2qq7v2uVF
         DT1Ur2d8AjKEGTFMOraQMX4fNipE+YGIWy0/TtmqSJQ44XVaezNaZS8yziEthbg+FKAa
         M618HJ4pS0JPG1SAg7sDtetB6WmIgvNxVnA3tKX9degx8OgKi9ihEJafzBxNxJ6sL9+x
         D2Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkRGVJGaO7cpYHgdedgodZ+P4eYadu3q6K8q9mASnApPTyIWgn2
	qleb70hrK/SCDksCD50/Cmo=
X-Google-Smtp-Source: AA0mqf6IklmcyHJKk8qzhqbn8sC5Q3FD6B7hWABP4sDb4Yh44RmPUmt9cQ+fN2tdCivStfCGdLJ2OA==
X-Received: by 2002:a17:903:2686:b0:189:8f60:54a9 with SMTP id jf6-20020a170903268600b001898f6054a9mr48920992plb.65.1670479385760;
        Wed, 07 Dec 2022 22:03:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:62cc:b0:219:4318:f24e with SMTP id
 k12-20020a17090a62cc00b002194318f24els4617419pjs.0.-pod-control-gmail; Wed,
 07 Dec 2022 22:03:04 -0800 (PST)
X-Received: by 2002:a17:902:e883:b0:188:f4ca:97b1 with SMTP id w3-20020a170902e88300b00188f4ca97b1mr77118100plg.139.1670479384723;
        Wed, 07 Dec 2022 22:03:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670479384; cv=none;
        d=google.com; s=arc-20160816;
        b=YWlEFNJ1b5RGwA4xS1UCUus/PXcGMS28BYxt84L/jO3B291GCTu4GJyNcXyqyz2mNp
         NXacJaCW7H54Z61odAm+NsY3KtKvDfwMO2R4Q72I/Qhyz5RL3DAFcuTqJvcy19up7N7w
         QS7o+jUvhP75hy9AqoI68yixUbOF0iAhxrW9U1tKUWT4Idn47lAIQhIag/ouNxj/zl3x
         6tHrHt9GWnPLw+BOqGRWA4ygsIOgMzrXizkBg4GBy+OxGU0VCOLx4FUkrHBJfrADe0GR
         Mz4GqvGEZBZr4yOLkQ1zYPm5TgUJ8YifmqxaWymx/qKy7Je/91fy8rVm8kfhmsyvREtV
         t3hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EPhmNwWi4z0Ewzi20WGpci8FcsM0lxXDqeltE0OefvQ=;
        b=APYOu6wkZ+EQFMdhpDPHW/M8yrrqEbrJY1/n3kZD5154YF4htF7HAUOz472MroVd2w
         rBZKnF39IZqUAwAp/BU8UdkzCVuRHxza9jAbn+8w3sIBv7CC2XyxoFHsX43R7WR69L5I
         NsJ4S7LVPDzEfBtJ94J/Wb3nr1YyQxEaq8txkzPCnQJmhkXzcl5zmQCWN8pe37jJsUqP
         VkrxOIY8u0SFfgdBZ16MkuE/QzZvD73ksbLa96S0dAKgeI3L3/Tn0J7th9nG35YMug4o
         y0gOs6r5kcr3uKjm/Cya7/eCFnNq33f3cloToysA8MIE0LsGGhQHd4VMYX65GEM3Sv1t
         6h0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QD4UFIWq;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id u16-20020a170903125000b0018712ccd6e0si1513890plh.2.2022.12.07.22.03.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Dec 2022 22:03:04 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 62so381825pgb.13
        for <kasan-dev@googlegroups.com>; Wed, 07 Dec 2022 22:03:04 -0800 (PST)
X-Received: by 2002:a05:6a00:1a4c:b0:574:97d4:c10f with SMTP id h12-20020a056a001a4c00b0057497d4c10fmr65265284pfv.81.1670479384355;
        Wed, 07 Dec 2022 22:03:04 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id j4-20020a17090a840400b00219cf5c3829sm2070908pjn.57.2022.12.07.22.03.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Dec 2022 22:03:03 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jakub Kicinski <kuba@kernel.org>
Cc: Kees Cook <keescook@chromium.org>,
	syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
	Eric Dumazet <edumazet@google.com>,
	"David S. Miller" <davem@davemloft.net>,
	Paolo Abeni <pabeni@redhat.com>,
	Pavel Begunkov <asml.silence@gmail.com>,
	pepsipu <soopthegoop@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	ast@kernel.org,
	bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Hao Luo <haoluo@google.com>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	jolsa@kernel.org,
	KP Singh <kpsingh@kernel.org>,
	martin.lau@linux.dev,
	Stanislav Fomichev <sdf@google.com>,
	song@kernel.org,
	Yonghong Song <yhs@fb.com>,
	netdev@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	Rasesh Mody <rmody@marvell.com>,
	Ariel Elior <aelior@marvell.com>,
	Manish Chopra <manishc@marvell.com>,
	Menglong Dong <imagedong@tencent.com>,
	David Ahern <dsahern@kernel.org>,
	Richard Gobert <richardbgobert@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	David Rientjes <rientjes@google.com>,
	GR-Linux-NIC-Dev@marvell.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH net-next v3] skbuff: Introduce slab_build_skb()
Date: Wed,  7 Dec 2022 22:02:59 -0800
Message-Id: <20221208060256.give.994-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=7775; h=from:subject:message-id; bh=0NU8DDppqfAVLsDlfD+CO5h/nC1dPBT2P22dmT0qs/s=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjkX4T8itmDqz4eyTltyQjXCELJvJjKlc3Cc8Uy4Uo wA3kFEKJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY5F+EwAKCRCJcvTf3G3AJtpJEA CSFMdkjZnrrqIciMt7F/Iys/d0n+Bm7l+cY6KzpPc866MFxjbtFv1bpZY58WcNggumlz0EVVSvLxgQ 3i5EUOP4LV75465l5Y4K8EBgUquHqYUQw6ejtHDoHEDSza1r8Q6YLTBVU3Q2AE1SYRsUTBZpLAxRGS A706N11gpuBeLptE0B3VKTQT3NYBvqLSZ5aWG6B4cjFlSxVb42do2Ip4aQasccTdU1FPD9ceTlCsNg GPkXxwOo6M4+Phr1QgE6OzGNqfHKEMjOTQcrwG3tPaIj8zu3Skzu+wmg38K8eHIdBurcf1NL8Jau96 8i3Am2Akw/4uQ+uBpTVt4M6zBLig6gDB6NmGmGupXSBe3/ChpBIB9WtsTmMlJGW4uwK6eXEUMkcfwe OxLuVS1w75c/yNv+d3mbIfMGtzb/bqv0GhmruHcqKHw1zjN6Ngdipo4H0kqKGhwuU6CtWz73ojFNRb kNA2gW0VkJZQHtwyZQnXPlVEAh7IZNhl6TXV46hBvUSDP2MUU5QonqQs/qULRaw6P4KH5d+yiswesS ucokQWTA1IvyZX1dm3+QK0Ti+Z9TnQen9CIgsPCAdD9BqOapmZArDrEbq33+Ml6bOq9+u5HnNl78uU A5sKU5bKYk3fWyKSURPECICkTXIebhoGmGWHqG4Rf9DwgP/3dot7jelU+Org==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QD4UFIWq;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::529
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

syzkaller reported:

  BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
  Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295

For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
build_skb().

When build_skb() is passed a frag_size of 0, it means the buffer came
from kmalloc. In these cases, ksize() is used to find its actual size,
but since the allocation may not have been made to that size, actually
perform the krealloc() call so that all the associated buffer size
checking will be correctly notified (and use the "new" pointer so that
compiler hinting works correctly). Split this logic out into a new
interface, slab_build_skb(), but leave the original 0 checking for now
to catch any stragglers.

Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Eric Dumazet <edumazet@google.com>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Pavel Begunkov <asml.silence@gmail.com>
Cc: pepsipu <soopthegoop@gmail.com>
Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrii Nakryiko <andrii@kernel.org>
Cc: ast@kernel.org
Cc: bpf <bpf@vger.kernel.org>
Cc: Daniel Borkmann <daniel@iogearbox.net>
Cc: Hao Luo <haoluo@google.com>
Cc: Jesper Dangaard Brouer <hawk@kernel.org>
Cc: John Fastabend <john.fastabend@gmail.com>
Cc: jolsa@kernel.org
Cc: KP Singh <kpsingh@kernel.org>
Cc: martin.lau@linux.dev
Cc: Stanislav Fomichev <sdf@google.com>
Cc: song@kernel.org
Cc: Yonghong Song <yhs@fb.com>
Cc: netdev@vger.kernel.org
Cc: LKML <linux-kernel@vger.kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
v3:
- make sure "resized" is passed back so compiler hints survive
- update kerndoc (kuba)
v2: https://lore.kernel.org/lkml/20221208000209.gonna.368-kees@kernel.org
v1: https://lore.kernel.org/netdev/20221206231659.never.929-kees@kernel.org/
---
 drivers/net/ethernet/broadcom/bnx2.c      |  2 +-
 drivers/net/ethernet/qlogic/qed/qed_ll2.c |  2 +-
 include/linux/skbuff.h                    |  1 +
 net/bpf/test_run.c                        |  2 +-
 net/core/skbuff.c                         | 70 ++++++++++++++++++++---
 5 files changed, 66 insertions(+), 11 deletions(-)

diff --git a/drivers/net/ethernet/broadcom/bnx2.c b/drivers/net/ethernet/broadcom/bnx2.c
index fec57f1982c8..b2230a4a2086 100644
--- a/drivers/net/ethernet/broadcom/bnx2.c
+++ b/drivers/net/ethernet/broadcom/bnx2.c
@@ -3045,7 +3045,7 @@ bnx2_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u8 *data,
 
 	dma_unmap_single(&bp->pdev->dev, dma_addr, bp->rx_buf_use_size,
 			 DMA_FROM_DEVICE);
-	skb = build_skb(data, 0);
+	skb = slab_build_skb(data);
 	if (!skb) {
 		kfree(data);
 		goto error;
diff --git a/drivers/net/ethernet/qlogic/qed/qed_ll2.c b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
index ed274f033626..e5116a86cfbc 100644
--- a/drivers/net/ethernet/qlogic/qed/qed_ll2.c
+++ b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
@@ -200,7 +200,7 @@ static void qed_ll2b_complete_rx_packet(void *cxt,
 	dma_unmap_single(&cdev->pdev->dev, buffer->phys_addr,
 			 cdev->ll2->rx_size, DMA_FROM_DEVICE);
 
-	skb = build_skb(buffer->data, 0);
+	skb = slab_build_skb(buffer->data);
 	if (!skb) {
 		DP_INFO(cdev, "Failed to build SKB\n");
 		kfree(buffer->data);
diff --git a/include/linux/skbuff.h b/include/linux/skbuff.h
index 7be5bb4c94b6..0b391b635430 100644
--- a/include/linux/skbuff.h
+++ b/include/linux/skbuff.h
@@ -1253,6 +1253,7 @@ struct sk_buff *build_skb_around(struct sk_buff *skb,
 void skb_attempt_defer_free(struct sk_buff *skb);
 
 struct sk_buff *napi_build_skb(void *data, unsigned int frag_size);
+struct sk_buff *slab_build_skb(void *data);
 
 /**
  * alloc_skb - allocate a network buffer
diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
index 13d578ce2a09..611b1f4082cf 100644
--- a/net/bpf/test_run.c
+++ b/net/bpf/test_run.c
@@ -1130,7 +1130,7 @@ int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
 	}
 	sock_init_data(NULL, sk);
 
-	skb = build_skb(data, 0);
+	skb = slab_build_skb(data);
 	if (!skb) {
 		kfree(data);
 		kfree(ctx);
diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 1d9719e72f9d..ae5a6f7db37b 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -269,12 +269,10 @@ static struct sk_buff *napi_skb_cache_get(void)
 	return skb;
 }
 
-/* Caller must provide SKB that is memset cleared */
-static void __build_skb_around(struct sk_buff *skb, void *data,
-			       unsigned int frag_size)
+static inline void __finalize_skb_around(struct sk_buff *skb, void *data,
+					 unsigned int size)
 {
 	struct skb_shared_info *shinfo;
-	unsigned int size = frag_size ? : ksize(data);
 
 	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
 
@@ -296,15 +294,71 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
 	skb_set_kcov_handle(skb, kcov_common_handle());
 }
 
+static inline void *__slab_build_skb(struct sk_buff *skb, void *data,
+				     unsigned int *size)
+{
+	void *resized;
+
+	/* Must find the allocation size (and grow it to match). */
+	*size = ksize(data);
+	/* krealloc() will immediately return "data" when
+	 * "ksize(data)" is requested: it is the existing upper
+	 * bounds. As a result, GFP_ATOMIC will be ignored. Note
+	 * that this "new" pointer needs to be passed back to the
+	 * caller for use so the __alloc_size hinting will be
+	 * tracked correctly.
+	 */
+	resized = krealloc(data, *size, GFP_ATOMIC);
+	WARN_ON_ONCE(resized != data);
+	return resized;
+}
+
+/* build_skb() variant which can operate on slab buffers.
+ * Note that this should be used sparingly as slab buffers
+ * cannot be combined efficiently by GRO!
+ */
+struct sk_buff *slab_build_skb(void *data)
+{
+	struct sk_buff *skb;
+	unsigned int size;
+
+	skb = kmem_cache_alloc(skbuff_head_cache, GFP_ATOMIC);
+	if (unlikely(!skb))
+		return NULL;
+
+	memset(skb, 0, offsetof(struct sk_buff, tail));
+	data = __slab_build_skb(skb, data, &size);
+	__finalize_skb_around(skb, data, size);
+
+	return skb;
+}
+EXPORT_SYMBOL(slab_build_skb);
+
+/* Caller must provide SKB that is memset cleared */
+static void __build_skb_around(struct sk_buff *skb, void *data,
+			       unsigned int frag_size)
+{
+	unsigned int size = frag_size;
+
+	/* frag_size == 0 is considered deprecated now. Callers
+	 * using slab buffer should use slab_build_skb() instead.
+	 */
+	if (WARN_ONCE(size == 0, "Use slab_build_skb() instead"))
+		data = __slab_build_skb(skb, data, &size);
+
+	__finalize_skb_around(skb, data, size);
+}
+
 /**
  * __build_skb - build a network buffer
  * @data: data buffer provided by caller
- * @frag_size: size of data, or 0 if head was kmalloced
+ * @frag_size: size of data (must not be 0)
  *
  * Allocate a new &sk_buff. Caller provides space holding head and
- * skb_shared_info. @data must have been allocated by kmalloc() only if
- * @frag_size is 0, otherwise data should come from the page allocator
- *  or vmalloc()
+ * skb_shared_info. @data must have been allocated from the page
+ * allocator or vmalloc(). (A @frag_size of 0 to indicate a kmalloc()
+ * allocation is deprecated, and callers should use slab_build_skb()
+ * instead.)
  * The return is the new skb buffer.
  * On a failure the return is %NULL, and @data is not freed.
  * Notes :
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221208060256.give.994-kees%40kernel.org.
