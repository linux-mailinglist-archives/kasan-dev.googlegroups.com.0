Return-Path: <kasan-dev+bncBAABB37G27YAKGQE2R6REZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 859F9134603
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 16:21:19 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id y21sf941505lfl.11
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 07:21:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578496879; cv=pass;
        d=google.com; s=arc-20160816;
        b=GnwRhxVZA8D9RNOu8VeBy21JF335Rm2ZOxc3wVo+aGikvCg6JNiz+93FC3I085HHjP
         /dLnQANgvUu35gIC0KhBVJmUsHVsaFFVdzD82PgRgGMzBUyLvZKKGtoZSEMZUe7Wk5kJ
         4pPlvQsKarbSmIbiPr76wymdB6imhTQRu3JVnxfmf5kTDqGeG8TsLWGch21sYrqB9+WZ
         oHFr5mp3bMF5lp7iSbPLoC4tSBSokiIOY/wGanxptO6GKXBpzJrfYfzknkAq34rC3gLZ
         6EbuexPvPSOf7wVsFIdO38sKWz0y4XD9tmbqYBnsYMYJkCgFB7iMgZlUUxu30mQFKaR7
         iGPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=d3nYhbPjOWVQCDOdqkxHd0nPR7M1IWNXlLqsF4ur4e4=;
        b=snZXs6CdNHxgVdWE46FMnZAWUgJtt4Rlqy/RoHMMAkP8kljFaxijWW7vt+rXFAl4lW
         CQ+4Sc+EyvEnYQoqafmtjLtVAop5T+iwsUEdRzd5AKMR3wBwMpMugOVKmNPa+aSAqCK9
         pfpFxUUBM1Ea//3h0pNimiXz1FC3WV1BABUAf/RO3sf425vBcWjdIXsCOqbnqbleA8Zn
         EDmpG8raLGYmDbxNrZGrmtNHuh5OTuvk9alPcTK2SJarElDeaWQSDC6BeMe6F1siS5z7
         nZKRLYYkOrkyNcExqa8eUQUNQggDCpBTRr8qwGfR1ia/y51SZTEUmH1bFn5HyVxmHYrc
         SGBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Kkq7BvLV;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d3nYhbPjOWVQCDOdqkxHd0nPR7M1IWNXlLqsF4ur4e4=;
        b=aGySbj8V1BI6JdPlPlEy+/o4V9rbCYXYBQO77Mp+QM0wC9ObctU+X69JClY+G4C+FW
         1M+p253jZIv61Jd2DSamwG6G1rYoQPljelscx/kVQZ08QSnDisFGNQuP749qs/KXW789
         UoUcLTXoQRjSUYglGT5oI2ucl14d964Vk9LgjHv9MsnYxluzeTRY7ow3IverSgx7fD96
         ISeZawoeUwyaC5UlZDS9TqFTZmNDAgZTbiMUiYDcJLsqzOW9uV0wDsYNX0aDJpBu3dtL
         XSJKukIcmNdbi/YQ5ZALNXUTYFgp9geyKfv4qSBLg3GzfSGRfGB8xxlsIkJWdBU+VrTP
         3t0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d3nYhbPjOWVQCDOdqkxHd0nPR7M1IWNXlLqsF4ur4e4=;
        b=bs7YL9Uwpv1cymbw6nBLun0+RbFuEN83syiZSw4phTFy8RSz80M69tmVjrJtJTSO3S
         XceyF/vrv391XINttYqdf1+er9fQR0INe8ddddzlK+RTnBQFfX8UEvShMruBFjOvzmKg
         yZWJyuWv0oP3eBtd9E1wd6NG51F/KYhLdaPwikUnp+HVMZ/C/qbkjCqLRxkFDDP5YUHX
         +l6z5cnhw4E+dyM1m3YGUUF7FGCeX7jDtVTKPVjed6Yc6yBfcs58ULgbGriw2uHpvIiT
         EACaQf7mIQwFHBlHxeo8lSZYwV6cM0qzu0d+e/lv39/XkxEYXlMhjVAZchd9vsofNNOi
         4esg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX0Xzk8pXnGApR11vumYuheYxBgPfZuP8m/5vRtsqu2R2e5boL9
	fH7qdVfyCogPQwyW1noQajw=
X-Google-Smtp-Source: APXvYqwYjPBvUIsO45lqUjck5vfK84NDZMP3Qc1RiEvBU87x9TWZNbKLDq/Ui6Xia7T+67Sx4QH20A==
X-Received: by 2002:a19:40d3:: with SMTP id n202mr3237625lfa.108.1578496879075;
        Wed, 08 Jan 2020 07:21:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:915d:: with SMTP id y29ls296645lfj.7.gmail; Wed, 08 Jan
 2020 07:21:18 -0800 (PST)
X-Received: by 2002:ac2:47ec:: with SMTP id b12mr3038574lfp.162.1578496878693;
        Wed, 08 Jan 2020 07:21:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578496878; cv=none;
        d=google.com; s=arc-20160816;
        b=b+ebAU53zzhedGtnkSFX/vhLg6CvfPNSXO6/KYrusgF+FXVQSTlll0Twrfxidw50kB
         CFNri9S8ClRpRO/hLLVqmcXs867yP6DbvkBvaycmX6zMuoa28HbO7RqsjJdcGVJMVFx/
         pubrCo7gUn0dqyW2urGB+VrON9HAwbIZlH2ly+FtVPgaGjemFUnNTjAyZRYs82ydZqlB
         sbOgeF9DjWitHotVwUZfeXarBl8+kwferBEod2vhjRqUuflBQRij18va04a3cTVXQDbh
         zjUjtOc9JmOiDL5CBXmlA9QNYYmyDTGeBm/U8VZ7tCN9mRsSM3pM8ZU6wewSIWDf7rgh
         zVBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=NWCg9bQc0zrAeQwS7MlzOnEKTVtDLEnV+SehGUh4Y3U=;
        b=qSJMbhuPAgE3usW1LbfDMMlCV/63n+46ZjMtpNh3IVxYsconwSq971K09E48ueTBz7
         EMS+Vie+sg6P6LxLM5fhvzYV8l+kAh/IEXF+dA7b94BEM3T3ecaYg1CHhfBpQc/w9Mto
         VDC357vNql6xqJiYd1oPtTophTwfuueiHcRK2/m396iD9yRirvpLEjuNnUIpdS9r+VZY
         YJRMBopUm/Vmc16oZfTJVHWtKIDeLkVQSgWwge5OK+xIW9cNFDg18j5IWI9VRQSmDnB5
         C0iSLiYtTr0fuK5vfE/Jmk91TSMTSXswm5bzKwWEaJLmW5S2vH12obT/p74hAV4KoLIR
         Eu+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Kkq7BvLV;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa6.hc3370-68.iphmx.com (esa6.hc3370-68.iphmx.com. [216.71.155.175])
        by gmr-mx.google.com with ESMTPS id v16si156858lfd.2.2020.01.08.07.21.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 07:21:18 -0800 (PST)
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
IronPort-SDR: oiTgJTAJYiU8q6hVq1bN4YDuqH1mfR29MxyRm3RWttoThy1554uFarHZBrmWCz0Qji3LgPyiYl
 wVYgmEW3+apuNXVHZzQ2evsQ/icA7m0e5gzf3KjRtDbA8Kb81q1Zi+YTZQJT1VeEzKDY9vrqGd
 mphdiYyxzhMu6ziAdm5TqRpEyDEIa3kEtPXoYBa95UXoue/cu0RlvAuQv+7ixycHCaFCz83l7J
 1fF5yzFP14m9eiE+RKg38qcdy3uaCDjVN2GZu5kmbiO046EFaW/01HjVei+dA+4ZV77rJtKOZb
 ibA=
X-SBRS: 2.7
X-MesageID: 11061017
X-Ironport-Server: esa6.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,410,1571716800"; 
   d="scan'208";a="11061017"
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
Subject: [PATCH v1 4/4] xen/netback: Fix grant copy across page boundary with KASAN
Date: Wed, 8 Jan 2020 15:21:00 +0000
Message-ID: <20200108152100.7630-5-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200108152100.7630-1-sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=Kkq7BvLV;       spf=pass
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

When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
allocations are aligned to the next power of 2 of the size does not
hold. Therefore, handle grant copies that cross page boundaries.

Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
RFC --> v1:
- Added BUILD_BUG_ON to the netback patch
- xenvif_idx_release() now located outside the loop

CC: Wei Liu <wei.liu@kernel.org>
CC: Paul Durrant <paul@xen.org>
---
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 59 +++++++++++++++++++++++++------
 2 files changed, 49 insertions(+), 12 deletions(-)

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
index 0020b2e8c279..33b8f8d043e6 100644
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
 
@@ -1674,5 +1706,10 @@ static void __exit netback_fini(void)
 }
 module_exit(netback_fini);
 
+static void __init __maybe_unused build_assertions(void)
+{
+	BUILD_BUG_ON(sizeof(struct xenvif_tx_cb) > 48);
+}
+
 MODULE_LICENSE("Dual BSD/GPL");
 MODULE_ALIAS("xen-backend:vif");
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200108152100.7630-5-sergey.dyasli%40citrix.com.
