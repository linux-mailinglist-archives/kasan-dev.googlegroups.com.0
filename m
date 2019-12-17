Return-Path: <kasan-dev+bncBAABBYOC4PXQKGQELNT3XZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42CEA122E13
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 15:08:34 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id m12sf6064089oic.10
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 06:08:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576591713; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfQTlovI7+6JvljnFZRoSBAe+zoJBZnFXPJDAi6XPl6Y+SOAirUg7UW6X4RlX/n/TP
         //hqC9qGZt/aR/HKfhlTaoDY1oYE5txPMscfIhUuc5Px3FG0Lu3uHykqWhO/w5Q1qH1W
         eu+Y1151Ljvyg1oVF5MSuwG+hdBINP33OfV4U0pPQWCVmwXxJLhVI9tGTpwO/ll/jWnB
         QhmzQ/gXYHq+o3YhfIgJIJu1ybLdIeu9lcoips8G3TqAeysnZ+d/v5VjDJVs355QDraF
         hPSTwPoSACFOL4MYJKkz7GGOc2bApCMHb2ozl/gcSJnHj4av3ppS4mw0eRFCufgRd6zk
         hJpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=HGHnxOQ7DN7kQeslgAW6nAEG8OPV4NJaQ3MT0F5ntDs=;
        b=kUg2YixKQyz2zsM9gcf97IOZLAGyJpcBHTZoOtdjxwUcJKbhKppCpxX40/sOQW3Ifg
         cWRv3OvNiABEZ9ibGE15sKfPtQ2Dg+t8CZib1XvBcCopRA9GWZc88eG7jsV860lnO+rX
         IZqbGabqFJljTqc6wczqmE4jjuM7jQdLoK6p79YiNVgTStFmMNGTgJ9d+TGkYEvhuU0C
         oMlpiEaUykUHfbX4991hqb/lEhMQIef/Miuy8CdLoNV7m0ncKM3Nu/s4JC0wzPCQxTed
         guQhNH9+kaNguRjqSfmNIFky8Dwz251MApRYEiokKGoc+4R9bKznbWfRrmjRmMIdHl9+
         HLVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=EHH06fs7;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HGHnxOQ7DN7kQeslgAW6nAEG8OPV4NJaQ3MT0F5ntDs=;
        b=KrFdt+/CGn4v4XsG9pY9ACe2Iu48aa4SOdRwW2zB52DAtnBt1eDvaK9ZxQpDT+d+Lu
         JsJhDFyiWKcH3W5fYAtZmlwWVTdHri/b5uMpquy6wklEEFl4G8vbA5H7d2k18IMBtCKb
         Qatm/PaqCwz3QfQpQ5szFBdqHACWn80ZxKh/8IrOsXPAcYptchXEAdFHffsIuhfvTncP
         c6u70OPwaFF1XLa98Ac1gWnvDZiEBa4Hav+sDQ3kZiYr+nGgKVGzAmWe+xcqmN1HWLTM
         HkXeOyDbAJfnHQMSwC3NhhFOHoq8JyIi3bfZksUD5m6M37OwIKiEX34cyn3RZtG63RT2
         JJiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGHnxOQ7DN7kQeslgAW6nAEG8OPV4NJaQ3MT0F5ntDs=;
        b=fDhw9MBd7jriA1lzg+uIpZ0z63LVfAq8OmR6T3/ywYkjpzvBLdpzXGf/8+HHQ29nd2
         Jb9r0q6XOIoc1vcHtJ27jLJP4tUmGYyhduXVUKE7qZGQ3I/YgyJbTQ7WfXw0WIxl8pj2
         vcKctN5Uqbw8txJ1PR+h+/qyeVK+Lz1TYzGsaXIq5JV1Tp3q7aTsah4B3bVWPhtXBjFJ
         iVXg3NyopBsffguchF/SyfRCoYFr1hoWutBZuQQIDUK7fRyLdauSRjADwS1CsboO0keD
         weGEFOXku2p+3lYX8BDF2IfuxzMrADlXPmptKvD9pHiFtcpaexZqzX9+SSMWK0YD1S4R
         3MAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVyi+DPQcO7AKOfmv0se2kV3usBMrQByIk/B5wczF4+5ZGo80dr
	TCfLiF+o4ALWtFmEsfGzmdE=
X-Google-Smtp-Source: APXvYqxb7en+iOS5tkJOhpmX1HJHVzUTCXLDYX821AcL7Zvd1feKAN2MwlQQC17ioNzQq9POGEGcHw==
X-Received: by 2002:aca:2118:: with SMTP id 24mr1583520oiz.28.1576591713087;
        Tue, 17 Dec 2019 06:08:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7dd6:: with SMTP id k22ls5682702otn.5.gmail; Tue, 17 Dec
 2019 06:08:32 -0800 (PST)
X-Received: by 2002:a05:6830:1d59:: with SMTP id p25mr39332692oth.308.1576591712829;
        Tue, 17 Dec 2019 06:08:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576591712; cv=none;
        d=google.com; s=arc-20160816;
        b=PQn3kQcorTxbj9f3vvpwTKJYHDIq9oAGpBHrkp/+J0Iq8AoZwQE82ajLUpPzYbrOBJ
         hcYWLt2i4VZtqHedBz9OSVGo99+x6asvvAxrUImjqewsSvFJuq9pxcw2Km6kiOvS9+Y0
         jrFfuTMDzEOi+rBqG/t4tHaUeNZ0af31qmn7KedGwRw+VKv+5kjkFKCcpnXcpwErzKbL
         liTyjsUPOitCVnKmHZ8CWK5QwkLUI5o4W5qoHQ+WvHI4u5SV4V+6eakeRhNdpTc5NjFP
         /GsoJp7BSQ+OGaOQ5/aokDpEb37BF6sgiZWlAYC+1xy+SUSCuo5fgkqIN2gjhdM/H0xP
         FfeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=75LwR+oKNoXWQlFU3giayzpTgte9bxyZuW+mdIAvvRM=;
        b=yyzqvThhWtnM3hhkGOJ1SOGSVp4EdH5zoS03Q8oQL/hMklVB2Kjh1nm2Bo6quxSNLW
         EaW6XRiSTimu4RILohdAHw0Sx0ZpNJ4EBaopfW6izEU+rlsji95N3f1LVkkyAgDhPPL9
         Rzshan9OB1wRe2JZtp3d02MEbuVjDLE9wU4K2I+vxNiomQn4tOBVw3zNJeTA1Vjn1x+p
         ux8rGCjtC2miQSKdF2X0WSO1xSFG1lI8v49bxGyAOp4n09xuiKfBDfLBPo/lk2YonCDq
         GBJDROk/vgJgT0BpKDSEIXHZ49GvXeZxXR2pPG4pLK6wMQW47uuP+e9CXb+rOax+WXHD
         hDoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=EHH06fs7;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id w63si1023058oif.2.2019.12.17.06.08.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Dec 2019 06:08:32 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) client-ip=216.71.145.153;
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa2.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: c65bE5BcO9T8b9RJhnirPK271/3uK8BZrOgCVjCsLdfABV/XxAMsPzl2UkjdtDcZ/Gg6QeSIkH
 ySnzwPhtaZYva01O+x4zrVmCY/qs5XpOLaQ78Qlg4y8rtiDpHMriZIBFBQ0SfRntFUUpCvvUD0
 PduTQgXJZNLk6WxApDPLJKDEkWdHqvvxvSL6XEbKovKaE2nYXDZSxAAk5IjBb3IXGRGzbz46wJ
 VzBt50j8MfHcrTQk63No93tIdkXQY2ji13iPuOtnB4uH+NeAoDHKk/kb0/AgSZAMGf2+8cDon4
 VS4=
X-SBRS: 2.7
X-MesageID: 9817028
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,325,1571716800"; 
   d="scan'208";a="9817028"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Sergey Dyasli <sergey.dyasli@citrix.com>
Subject: [RFC PATCH 3/3] xen/netback: Fix grant copy across page boundary with KASAN
Date: Tue, 17 Dec 2019 14:08:04 +0000
Message-ID: <20191217140804.27364-4-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191217140804.27364-1-sergey.dyasli@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=EHH06fs7;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as
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

When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
allocations are aligned to the next power of 2 of the size does not
hold. Therefore, handle grant copies that cross page boundaries.

Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 55 ++++++++++++++++++++++++-------
 2 files changed, 45 insertions(+), 12 deletions(-)

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
index 0020b2e8c279..1541b6e0cc62 100644
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
@@ -450,23 +452,27 @@ static int xenvif_tx_check_gop(struct xenvif_queue *queue,
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
+			/* The first frag might still have this slot mapped */
+			if (!sharedslot && !err)
+				xenvif_idx_release(queue, pending_idx,
+						   XEN_NETIF_RSP_ERROR);
+			err = newerr;
+		}
+		(*gopp_copy)++;
+		copies--;
 	}
-	(*gopp_copy)++;
 
 check_frags:
 	for (i = 0; i < nr_frags; i++, gop_map++) {
@@ -910,6 +916,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
 			xenvif_tx_err(queue, &txreq, extra_count, idx);
 			break;
 		}
+		XENVIF_TX_CB(skb)->copies = 0;
 
 		skb_shinfo(skb)->nr_frags = ret;
 		if (data_len < txreq.size)
@@ -933,6 +940,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
 						   "Can't allocate the frag_list skb.\n");
 				break;
 			}
+			XENVIF_TX_CB(nskb)->copies = 0;
 		}
 
 		if (extras[XEN_NETIF_EXTRA_TYPE_GSO - 1].type) {
@@ -990,6 +998,31 @@ static void xenvif_tx_build_gops(struct xenvif_queue *queue,
 
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
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191217140804.27364-4-sergey.dyasli%40citrix.com.
