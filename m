Return-Path: <kasan-dev+bncBAABBNPH6XYQKGQEYLAN6NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA54E15594B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 15:27:01 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id g11sf1975361edu.10
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 06:27:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581085621; cv=pass;
        d=google.com; s=arc-20160816;
        b=G8lkb8pRaea4e9SEQH5e69Xz/ov5Hyn4gPB/vyAIsZQcv8hSVLdglAx2eaZnJi6vtz
         Br9BMW4H2qLCJtLifhE0ivfT79LUyXv+XdFWeNIdRe0OoI2bU+EGb7LiWzTnT/GRsnra
         sW7NGu/Czn570ylkZZY8l4O6UUSnz7RZPhEidAhxDx3lU25WXenxjTu4IbboZke4J+Ov
         94qt3H+VifBuN72cpesmZPYt3ESxSanK8DWjvHgUdKThLHuOzTBYSBTw30q3M4AQN5Ky
         TuNkpP/R6NukUyQ5drQ33BHNCOmfyopDtmfamnEUzQ7cwIrBNxFksTa0oYmVNi0foQLd
         ejSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=aHoV/uVYlb6f/d0PHPmJUvbxYEWPMRcdQFaYh0K5zNU=;
        b=y6AsIOtbycvjNEpJjj9G2XOJw2suvVGwnuY2HejYQ97bAxehQfCIXwnFK/fljP4IXj
         MB0ZI24WKnhmDdYTDIkdwaOQ/uPaSSCd930KTgSuAIo4UMtGL82bPozXVaTpaWfIPoBh
         8A7ctejZvevD68RJgUfZDwpq8OqwfwYqQB3dVcfwEiz0Y9hrwgMHaR8vl75SVSAA6NDR
         fnaOrE0KBS4mJodGnJZbaaA4lXREQ1u1H/pMamXzK8G9HQYpAIz35iHCHO2viE+nt26f
         cB/O9Aomg4iBV5Qaw612EAk8IUYTvBkivkmq+E2DOHyILdm9XJ/voFHIQbSxIEeICFfp
         3Nnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=eQEjheAg;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aHoV/uVYlb6f/d0PHPmJUvbxYEWPMRcdQFaYh0K5zNU=;
        b=YtWJbuXT+pm1uNarAwD9AY0kf+RUaU560nJVtaBHjyCNj6mdWQLOXlfAuCVAUK0Cqg
         Qau8Pg5dGYkfbo6MC/iAIg8fXV5H/95mS0nXC1tk/CeyLD0oBvV8F2wGTBgZolhtNM+Z
         9Nk5z1/rqlrIgTa2CnR5btV6j7Pc60qtFm1k8P2UZrlAgDU+neIWpSfqn2fy78yi6Mue
         nIw1vEAX2iqOSFHfvVYF77+gpimWBVyUei3jBLknzC3UsU43GqeCk7NBQdE4M0ZW551V
         O9E4KMxgczup9ZoyX6NqMLc+Wqbmn6ujfEp7flXAUd+Toki0zPea0W13pqf+pnmoEfa9
         Rz+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aHoV/uVYlb6f/d0PHPmJUvbxYEWPMRcdQFaYh0K5zNU=;
        b=bF/oY1Gqp5yWlO4KG6nSoN6wexxZLs4aM3D8nHKg9cMqtotjQzBZmeiih8X7TtOFto
         v44ez6dX40g3av7PJftGmBssjDNR5wEkTjgSW9GAenDELnd06294uZvOyHYMpOxQsP/c
         Ujwm1WLa1bPVRXVa8dZk0UK4PbIXwif/MO6Yq/DMdxQnMNkYJXCmzGPznAbYP1kufpz7
         UEJjf+8tFzahdbMKL6Mdr1rURy9Oj5obbLN1hvTMA5vv2e+t2wCiKKO2AJxduJJL4KG6
         rzBsg7meB4QuCQqwFWayE4VKN7YZANF+ILvXANJfqElf4NbICRHCkfZlEVhANPK+/45v
         wBfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVHI0sCHHxbIDLjmphTFPYGzWYv4qyc1Cv7AYIF8+MLoGUNHTQD
	v4Fp3i+ivIS7JihHgz5828Q=
X-Google-Smtp-Source: APXvYqwneZZRNkSJMpBkC22jZxWZpWFm8+w5AmQqw1TEGAwKxlojC+RwJ+Lc/3Viu2HlM34L3RL3Cw==
X-Received: by 2002:a17:906:f245:: with SMTP id gy5mr8413721ejb.225.1581085621552;
        Fri, 07 Feb 2020 06:27:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:e20e:: with SMTP id gf14ls60263ejb.10.gmail; Fri, 07
 Feb 2020 06:27:01 -0800 (PST)
X-Received: by 2002:adf:cd04:: with SMTP id w4mr5257898wrm.219.1581085621153;
        Fri, 07 Feb 2020 06:27:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581085621; cv=none;
        d=google.com; s=arc-20160816;
        b=B0vK2XZ4QVO4NxqakCLlVhfcB51t4CSThOXGG63SmhbjIx43gpRcXDaddmccPrNcl+
         Q0NwN0kGK22RoJ+sD0oRKGfoqxSvQnf1QLF3pL87bAlBRKIgSebS6U1nhth4vhwf3lqw
         YXqHuqHohtgW923wzlX90E+PtNsDA25QyNxr26CmzQTENJ0HZqvg+31HJdprwNLxsCXW
         cgxbb7J/sOKL/KF9nG2Us3cBPPJHPrqTA8UQDzt6YGxzy9ZKdFsHXQq4Ono7mPKWa/kd
         t5oo+Xg4Fi/FLZiviOnWe+dkq6dUxXbTOntV4uAIpCaoi3ITo8IddYSEHMRUVjpm+P9E
         Ezhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=bpl9CbjPCGJCfDoXSYcJuP7uAkPIMcA6dbtqHCt746E=;
        b=mo3ywUdsaoPlzYlsdD73znLV3nswpqn3921fQcJYh80VW16OANQqq9Nax3YukpFujc
         ddfDAq5fSOFHN5P8uG9LdkWE14Y4Kk0QOPsVgS0uzTxJf3JaMnjI3W14MWgHIExtq+11
         Q4Vyw4ikn5cWR0VD333JrVRZlBWmjUOaRvyIVWPtf0gFg8qDgynqj3EQaelOHN0oxSeh
         H28CigWue9wgHJa56M/y/8eZ4Ta6VOEq0tmZytvC2k2jRCwnnVaYwl0l7Nws/06gdSZk
         mCC6d7/2ymhH1PyoffwgJzv3+jOfHGsCSI5Li04muib2NFbRw5mzr84MgZelLXc5ceVi
         00Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=eQEjheAg;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id 202si286519wme.0.2020.02.07.06.27.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 06:27:01 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: 0LSwV5f+ce7LmCuyeNmBPXSPCt25wkJPqq44O0V1EgoVlnukj5AqmkkFejo0CY5l5ERMbV+FBD
 B9HTCM3bMTG8GxBCwMm19Kw9z4XyUkLs7ZW7Kfol7V6XvpuBIrm0bWGE/NcA5xrwYsAUNlnZJK
 h6OwQYuh0W6BirgUV/IwqdC4udufQdUKpYVFFhPfiL65EbUtbtW3JqkDnms3Dj4sQxM8Ang2vW
 6XTrHCYqY/Hpz6cTLB+pzDrK2qVjF3srYEHaUV3qYfkqBx0oqOswZiQYm718ghYtnIAW8MQ7ym
 W+w=
X-SBRS: 2.7
X-MesageID: 12479586
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,413,1574139600"; 
   d="scan'208";a="12479586"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Sergey Dyasli
	<sergey.dyasli@citrix.com>, "David S. Miller" <davem@davemloft.net>,
	<netdev@vger.kernel.org>, Wei Liu <wei.liu@kernel.org>, Paul Durrant
	<paul@xen.org>
Subject: [PATCH v3 4/4] xen/netback: fix grant copy across page boundary
Date: Fri, 7 Feb 2020 14:26:52 +0000
Message-ID: <20200207142652.670-5-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200207142652.670-1-sergey.dyasli@citrix.com>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=eQEjheAg;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
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
Acked-by: Paul Durrant <paul@xen.org>
---
v2 --> v3:
- Added Acked-by: Paul Durrant <paul@xen.org>
CC: "David S. Miller" <davem@davemloft.net>
CC: netdev@vger.kernel.org

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
index 315dfc6ea297..41054de38a62 100644
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
 
@@ -1688,5 +1720,11 @@ static void __exit netback_fini(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207142652.670-5-sergey.dyasli%40citrix.com.
