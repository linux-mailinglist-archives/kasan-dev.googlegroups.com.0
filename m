Return-Path: <kasan-dev+bncBAABBDW7Q3YQKGQEBPUHKJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C0AA140A52
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:58:55 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id z14sf10598919wrs.4
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 04:58:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579265935; cv=pass;
        d=google.com; s=arc-20160816;
        b=L18m9cGfWer3E3gZqfr9qIpOMDa5OsvTLxXZ2qCgwTof7DXSVbUZ8BnTsTWWDLtZYc
         U/qkf0DxS5eBwCe+XFuTWkbxWzY91uObMqUJv1+EhILbLMzPeOQwcMejvOrHoDMOosC2
         cvRThfRbC+R8sc6uphmwzU3j4BndC3K/PXLfszWKxwBtlMfEHUKXZK3yncEuIRiNRzA9
         48ph0TAVwqF7AjuhBdWwJiU+eocOg3ow4s5oes0/EnTc0CBh+efeyDAMkRya/sef/LYL
         9Eg4NtXOXAFXFRh2nPAMdK5hWOwVYplqEZupMvcJY73WdnIENQwZ+YkQpLOTyQ1OjKjC
         FfKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=NfK3PuBZXRJlnSylBJbZmAQdgOKImzR2lvmzCm/+gyE=;
        b=Yff1HL1bt9XcgM/wSVDgPXa4A1CY8/wJHfyE+2YLsR9iHwM2VBkQ+EQjMiF9r7YYqa
         1huf9Zpho5jpC1iPvdhtENe80suHnPsMh0bt5gK5niNo5av699xDlWwEoPLJtStmc7Uw
         tocaKdaARhAQPhPYwxN+080nlJskjZd99uGhVwNloLJa7GUZeu42337caTLjgOMbctlG
         h+XEYAvjW2mdjVDtNYDc4/4khWVnP5SPUAqqVurBuXDkLNrLbW7Wpcfg9r1cs4Nw1oI2
         YyC7nQqyT4nIfMYmSa+l63oXktsc0r1dLfzWf0RXoFsa8AziFO6viW5P/YDgWQ9yGvAT
         +INw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=ZVGaqM0Q;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NfK3PuBZXRJlnSylBJbZmAQdgOKImzR2lvmzCm/+gyE=;
        b=Rmjung8vOdSJ87at67+qvYvLfNJXnhY4RXSeOLQbSzJqVX8Ew8frb+3qcFoMJUqvj9
         smQ5+M9oVA8hZq185Tj59k+EnQ9JuwK/1AKfVBqNcLpZr8/3wr3MomKOmCjkJAlxHHeS
         CZfGcy5o+jffyDo2LpOeMu+jnLEPCBpnPVO02TKrO7fgQ/k/QGVJ7OF36gx4QKqQwV7r
         9KV7rcipJrPnYPdXaZw7jh9cZsYseEZryz81c3w+8JNMFQACF6cJ8EbaoHOHiaTgoVul
         BVNpAjbAiSgFgmZoWNxLnIWXknW6satQo+Yr9+L49aed8SIf8dwuBlnbLVqBORKEPmVO
         a7Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NfK3PuBZXRJlnSylBJbZmAQdgOKImzR2lvmzCm/+gyE=;
        b=r6sGaB/qBJHIiqBI3YEv00j/QIFGfcc7d9WVdZFyaWdjVG2bz48qAMxOX3ouNoxJDD
         bSTpmp+Y83uFrwRArcAOE3cYuCYNpuN+CTf8NfPc5io/1OO0Xiuu/4jaXJTHgonq36WJ
         Y0lmmrd97J1Uj0kY2E/TKqmOlarSsjwNUyQzdEeWqjPpihgOKL2yKNnyPzscR3pYZQa3
         3xWSXh62HgzIHNMJxR/G5+NR5PqOiktTbymM8Q/O5J6X7X4HxnXbukVjC+CGFkfiJwDw
         wskafiYO21aAAjPfRdr7smORJ7Osixf4XEID6xMuoftDzzDNa81MHTheNPqaOyN4hR8o
         W9RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUmGuARn8ZJWxRs4vWoPFyWzTG2AcOdil+jjYb+0qnN+cgXBoa2
	ukJQw8BOJZ78w+TjiFmSvl4=
X-Google-Smtp-Source: APXvYqzTMZEkQzktz/5U3Wveyq5bnCJvarmoKAe8AhxbrwaGesQ/eT6D6RcBxJ+ha8Z+nTYKrMSPLA==
X-Received: by 2002:a5d:4b88:: with SMTP id b8mr2920680wrt.343.1579265934988;
        Fri, 17 Jan 2020 04:58:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb4c:: with SMTP id u12ls8901450wrn.6.gmail; Fri, 17 Jan
 2020 04:58:54 -0800 (PST)
X-Received: by 2002:adf:de86:: with SMTP id w6mr3013281wrl.115.1579265934578;
        Fri, 17 Jan 2020 04:58:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579265934; cv=none;
        d=google.com; s=arc-20160816;
        b=RCVg4ra+6FKsIGMSH0vNk6J0yo9WC4Nw2ov0bIXS8sbQxTuIjVHBn9yAorNLYeRTj5
         PIqpdUutHA+ZSusRYie1pq6l0GuHDou6aLmXXcpGx+169fylcSYkOdjpKLPY1HSjMRdE
         LEkwv+uGMS3KlTmmWo9SOhTEE5+OJ0PjEqOSkWLdEfIv0/Uu6pIE+sxyYbr0M6aitYp1
         ot5acTBYx8wSDiOMEZOSsXPWVvKU/PAV+y/I7H3qkmjlY0PR/p9Uk4b1M1jnj8qtn674
         n9x8D6+4dBc2nCXqlPpuqBvS9pYDsAb/IFQV+Zf+ANVdlSzMP9pVJyp1zgqAJ70OAUxz
         BoJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=sSeG/8S7uZ8CHXZ5AXhNnUqtp2MAORYb3iKHPG9qIqw=;
        b=oDQRmvkw4y3/csrAwnDMOPiqcegKm6RAyTcni7dcAay1J9ZiKUve8Uey0mU1hmE2nK
         FUXTyX2+upFfoXPYHFpfmcDYanw6EBADmVQKRzknnd0OfHnxJ3IurwssCFnLqUiNn3aI
         6TcMYka8I3aPJ21W0ZiOXRJW/asDafbyFn7DV6wVmhNiPR3zxSKAP6HKuSSXbeLWBZ49
         ScE++vrY2/BQ/dr0IVFlSOow1M3Ej5ck2XKdLLDNCKdeY9GXFSrPAvHy3Bibvr2n2SMj
         Jyyyx/LMBVDE62lEa8upNgl1HWQIl8o/YKrI+1ebmeXnYtuVQ8uiIZo0MTLytRoj/rYx
         /AQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=ZVGaqM0Q;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa6.hc3370-68.iphmx.com (esa6.hc3370-68.iphmx.com. [216.71.155.175])
        by gmr-mx.google.com with ESMTPS id x5si585778wmk.1.2020.01.17.04.58.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 04:58:54 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) client-ip=216.71.155.175;
Received-SPF: None (esa6.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa6.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa6.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: 9Pu+Dt4AmrdPopz9X+nqR/BgvGLwCGMi4qVLlyuEh3k94OexmfeofNXTntlanbYRuLsYxfZlBT
 Lrz3S4mzj+puxMJ8Jo8y0SfffVP7bc/scRO23dHBd+HX4rVw+kT+b7tFlF8c35lmDBLBJ1mctn
 9EZXkeeJCjvAkP89TdmjIz9xq7qCRFedYIaST8GIAjgqtr6KH2oRrTOJGpO4JtV9OtGaVMwiCK
 IH/1chH8J4VSQ7BL2hBX6eO3omZmcU4WoyMDnXGfzaGCdmOjnujJAIYi5Amz6ZEpyDylGUShII
 GIE=
X-SBRS: 2.7
X-MesageID: 11502060
X-Ironport-Server: esa6.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,330,1574139600"; 
   d="scan'208";a="11502060"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Sergey Dyasli
	<sergey.dyasli@citrix.com>, Wei Liu <wei.liu@kernel.org>, Paul Durrant
	<paul@xen.org>
Subject: [PATCH v2 4/4] xen/netback: fix grant copy across page boundary
Date: Fri, 17 Jan 2020 12:58:34 +0000
Message-ID: <20200117125834.14552-5-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117125834.14552-1-sergey.dyasli@citrix.com>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=ZVGaqM0Q;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

From: Ross Lagerwall <ross.lagerwall@citrix.com>

When KASAN (or SLUB_DEBUG) is turned on, there is a higher chance that
non-power-of-two allocations are not aligned to the next power of 2 of
the size. Therefore, handle grant copies that cross page boundaries.

Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
v1 --> v2:
- Use sizeof_field(struct sk_buff, cb)) instead of magic number 48
- Slightly update commit message

RFC --> v1:
- Added BUILD_BUG_ON to the netback patch
- xenvif_idx_release() now located outside the loop

CC: Wei Liu <wei.liu@kernel.org>
CC: Paul Durrant <paul@xen.org>
---
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 60 +++++++++++++++++++++++++------
 2 files changed, 50 insertions(+), 12 deletions(-)

diff --git a/drivers/net/xen-netback/common.h b/drivers/net/xen-netback/common.h
index 05847eb91a1b..e57684415edd 100644
--- a/drivers/net/xen-netback/common.h
+++ b/drivers/net/xen-netback/common.h
@@ -155,7 +155,7 @@ struct xenvif_queue { /* Per-queue data for xenvif */
 	struct pending_tx_info pending_tx_info[MAX_PENDING_REQS];
 	grant_handle_t grant_tx_handle[MAX_PENDING_REQS];
 
-	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS];
+	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS * 2];
 	struct gnttab_map_grant_ref tx_map_ops[MAX_PENDING_REQS];
 	struct gnttab_unmap_grant_ref tx_unmap_ops[MAX_PENDING_REQS];
 	/* passed to gnttab_[un]map_refs with pages under (un)mapping */
diff --git a/drivers/net/xen-netback/netback.c b/drivers/net/xen-netback/netback.c
index 0020b2e8c279..f8774ede9f0e 100644
--- a/drivers/net/xen-netback/netback.c
+++ b/drivers/net/xen-netback/netback.c
@@ -320,6 +320,7 @@ static int xenvif_count_requests(struct xenvif_queue *queue,
 
 struct xenvif_tx_cb {
 	u16 pending_idx;
+	u8 copies;
 };
 
 #define XENVIF_TX_CB(skb) ((struct xenvif_tx_cb *)(skb)->cb)
@@ -439,6 +440,7 @@ static int xenvif_tx_check_gop(struct xenvif_queue *queue,
 {
 	struct gnttab_map_grant_ref *gop_map = *gopp_map;
 	u16 pending_idx = XENVIF_TX_CB(skb)->pending_idx;
+	u8 copies = XENVIF_TX_CB(skb)->copies;
 	/* This always points to the shinfo of the skb being checked, which
 	 * could be either the first or the one on the frag_list
 	 */
@@ -450,23 +452,26 @@ static int xenvif_tx_check_gop(struct xenvif_queue *queue,
 	int nr_frags = shinfo->nr_frags;
 	const bool sharedslot = nr_frags &&
 				frag_get_pending_idx(&shinfo->frags[0]) == pending_idx;
-	int i, err;
+	int i, err = 0;
 
-	/* Check status of header. */
-	err = (*gopp_copy)->status;
-	if (unlikely(err)) {
-		if (net_ratelimit())
-			netdev_dbg(queue->vif->dev,
+	while (copies) {
+		/* Check status of header. */
+		int newerr = (*gopp_copy)->status;
+		if (unlikely(newerr)) {
+			if (net_ratelimit())
+				netdev_dbg(queue->vif->dev,
 				   "Grant copy of header failed! status: %d pending_idx: %u ref: %u\n",
 				   (*gopp_copy)->status,
 				   pending_idx,
 				   (*gopp_copy)->source.u.ref);
-		/* The first frag might still have this slot mapped */
-		if (!sharedslot)
-			xenvif_idx_release(queue, pending_idx,
-					   XEN_NETIF_RSP_ERROR);
+			err = newerr;
+		}
+		(*gopp_copy)++;
+		copies--;
 	}
-	(*gopp_copy)++;
+	/* The first frag might still have this slot mapped */
+	if (unlikely(err) && !sharedslot)
+		xenvif_idx_release(queue, pending_idx, XEN_NETIF_RSP_ERROR);
 
 check_frags:
 	for (i = 0; i < nr_frags; i++, gop_map++) {
@@ -910,6 +915,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
 			xenvif_tx_err(queue, &txreq, extra_count, idx);
 			break;
 		}
+		XENVIF_TX_CB(skb)->copies = 0;
 
 		skb_shinfo(skb)->nr_frags = ret;
 		if (data_len < txreq.size)
@@ -933,6 +939,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
 						   "Can't allocate the frag_list skb.\n");
 				break;
 			}
+			XENVIF_TX_CB(nskb)->copies = 0;
 		}
 
 		if (extras[XEN_NETIF_EXTRA_TYPE_GSO - 1].type) {
@@ -990,6 +997,31 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
 
 		queue->tx_copy_ops[*copy_ops].len = data_len;
 		queue->tx_copy_ops[*copy_ops].flags = GNTCOPY_source_gref;
+		XENVIF_TX_CB(skb)->copies++;
+
+		if (offset_in_page(skb->data) + data_len > XEN_PAGE_SIZE) {
+			unsigned int extra_len = offset_in_page(skb->data) +
+					     data_len - XEN_PAGE_SIZE;
+
+			queue->tx_copy_ops[*copy_ops].len -= extra_len;
+			(*copy_ops)++;
+
+			queue->tx_copy_ops[*copy_ops].source.u.ref = txreq.gref;
+			queue->tx_copy_ops[*copy_ops].source.domid =
+				queue->vif->domid;
+			queue->tx_copy_ops[*copy_ops].source.offset =
+				txreq.offset + data_len - extra_len;
+
+			queue->tx_copy_ops[*copy_ops].dest.u.gmfn =
+				virt_to_gfn(skb->data + data_len - extra_len);
+			queue->tx_copy_ops[*copy_ops].dest.domid = DOMID_SELF;
+			queue->tx_copy_ops[*copy_ops].dest.offset = 0;
+
+			queue->tx_copy_ops[*copy_ops].len = extra_len;
+			queue->tx_copy_ops[*copy_ops].flags = GNTCOPY_source_gref;
+
+			XENVIF_TX_CB(skb)->copies++;
+		}
 
 		(*copy_ops)++;
 
@@ -1674,5 +1706,11 @@ static void __exit netback_fini(void)
 }
 module_exit(netback_fini);
 
+static void __init __maybe_unused build_assertions(void)
+{
+	BUILD_BUG_ON(sizeof(struct xenvif_tx_cb) >
+		     sizeof_field(struct sk_buff, cb));
+}
+
 MODULE_LICENSE("Dual BSD/GPL");
 MODULE_ALIAS("xen-backend:vif");
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117125834.14552-5-sergey.dyasli%40citrix.com.
