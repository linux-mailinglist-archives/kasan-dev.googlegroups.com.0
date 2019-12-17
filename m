Return-Path: <kasan-dev+bncBAABBTXB4PXQKGQEJ264Z2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0F1F122FDC
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 16:14:23 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id x11sf4374717otk.6
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 07:14:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576595662; cv=pass;
        d=google.com; s=arc-20160816;
        b=kKjjCKWEzXZhwOV0MaWmCACj88SgBLOcMbjMZCy9YBtRvjmvLdwI0WdfC1oRk4dqEJ
         xpRZAFMIZRuFFOw2pxFRQITDHAOrc6Naj+JHZeRbFnF9NS4P0kbQHBZUw0prKdXvJSdj
         swwaaESw1NdkAKaiIIQZ1UIPVDFfq8XFAwiXY1ISQaVh1SSz+hGSVnkaEI1DbpmO3meW
         gKRFSWy8ZOvCPdd+jS+FtaqA/3JkODmEpxlY6syfH4Xx3qoXZyJQydAfjpKHD3s/FX9f
         uCCjS0LhBT6UvhVq5Lu7jIHAX9Szax23cfrOKUlt4YD4EKTFMawTj3Szw8lr7jni8PbQ
         AYMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:reply-to:precedence:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:ironport-sdr
         :dkim-signature;
        bh=mUlHi85lKdEqgATshbsCcgaNYwjyjV3eBd5OHbnlGxQ=;
        b=CdRwcInKol1XjAGXpBNwWfWavP9WFRi+Lq/IXe3WWxTwzZPIVy1X9jODUw1XDHQgOz
         wPfOEPY7IXO7avI0DkMcYLMXXGEqyEoa+wLoDAZSWUIjSmMImbdHkVFuo7kideH+A7zF
         BZcKlRy9ev9aeIaiH7JyWSAWVwkjyizaEYqdAi2QG6gJHR+w5NtWBQURz9nJHIyJduBi
         7RExq3AH+NAz15yXDToIuI2ywjC8Ki9gDwePIMDqklDapbZaJ3+laYDv9x8k72/ptNis
         j/k0OTCqXSn4Tw3VUzcXLWpeyeGsOMAgzTBqnhMoodgwBt+MyaDwIwvFs/ySWj8riekQ
         2IlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b="pO/cbvyK";
       spf=pass (google.com: domain of prvs=247c3a56a=pdurrant@amazon.com designates 207.171.190.10 as permitted sender) smtp.mailfrom="prvs=247c3a56a=pdurrant@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=ironport-sdr:from:to:cc:subject:thread-topic:thread-index:date
         :message-id:references:in-reply-to:accept-language:content-language
         :mime-version:precedence:x-original-sender
         :x-original-authentication-results:reply-to:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mUlHi85lKdEqgATshbsCcgaNYwjyjV3eBd5OHbnlGxQ=;
        b=ThJvlqNVxfzEwqaWTLJEkDy1/3WqxGi1dYA86sRDvFt51gGa0QCuqOFc+4zhI4fEtj
         IRKGz/C4mSlzFc521/JyR28cdLr7SQP6UUbp2sAjpKEmaDHbJONky1unVctgNJ2LK7p0
         6Wfh1wJ3lXip8MYzcFkeNai4GhvljrZSp023chjkFtxEOqE/77z78W8wmbFCWcEPk7nu
         iYf0MDK7rhqIyILmx5lAeisnOhZx/uxJj7kHLU+XCb8Q4nl5VD96/vtac9e3eYtSCcDS
         /DmWg7DhO0p0sY8Wlmit0tSAMN7Zb8OReaL1dC27Is3sDVoioj5JfSfAIcNfgK3TMNKK
         MDFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:ironport-sdr:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:precedence:x-original-sender
         :x-original-authentication-results:reply-to:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mUlHi85lKdEqgATshbsCcgaNYwjyjV3eBd5OHbnlGxQ=;
        b=A7PJUIM3eTRCvInkcnbBR0rz6Z/cPw/0bUqm8C8LkoDca1uODNgyCCJYLocUTszZgn
         3/B+UjBL2M9duL7F63hlI7zmDq/81+KnZP8wIu75GE6K02E6y6uBCKSPa6U7exxsv8zq
         YaBK/nDpDOD/t4Ukqw3FJHLZxM9zqYuJ2lMcFVlg2r5P7OYJ1cyXrNjWAG6+EuVwCkM8
         zWL99C0vXZvCvJR6LQAESPPbVPf4Y2035se/J6JZDFHnFZg0twKdOc+yvC2OScxJL0Td
         BuIQOZzXCjoA8QxbObVrxFSr0ltOoyz1GW9E7mX5XpXo1JqbfOLg75J1GbAUHFZi/s+T
         57bA==
X-Gm-Message-State: APjAAAVf/l7xMl5GhfeWaQdfFjpj8zWy75q6Kyi/aoIejv0LfhxXk1wC
	KMukqK5SZ1IpPePRrEkpXRw=
X-Google-Smtp-Source: APXvYqzOcOdo4Wu56BZTkP6t4m3UJqLoW9bmR42wz3URUmiD816DuL1o8wbCsKUTRlERkQww3iwaNw==
X-Received: by 2002:aca:d507:: with SMTP id m7mr1693253oig.48.1576595662215;
        Tue, 17 Dec 2019 07:14:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf95:: with SMTP id f143ls1572974oig.7.gmail; Tue, 17
 Dec 2019 07:14:21 -0800 (PST)
X-Received: by 2002:aca:fdc2:: with SMTP id b185mr1848639oii.74.1576595661831;
        Tue, 17 Dec 2019 07:14:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576595661; cv=none;
        d=google.com; s=arc-20160816;
        b=mBRxlZGcxUTZE8IfF8APXnuIcicmYOpFjeyyUanvubhwEfNIFImI58SDnLWMPSMdg/
         U/rkDPiTvPVf3XrX1hjCYeBTUBr266b64rkCzcDh4B7GRiWBYXc3OvFfyYxhpKgPBsAw
         PywKZOfkkGTdvvKIGf+sWaUu9FKlUaoR/aFT/wogrhVzk9yVfchbqZqxgK3mX2RMgz1a
         SfWvW70uJ7T78P+w/IY6xkOu5NliQVB5KXcIjK3o6xIneVGnLkPQVG6JWzGCGyCf3dhn
         TzjTSj1ZThHtnuCosb4om3BzxIkQkYVhn/wrNYgNekXivQAs8XpYf+cAsyokUcw63Xj/
         srbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=precedence:mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:ironport-sdr:dkim-signature;
        bh=nvnhKOPGUnKBSzlXHGO7yql/nTH132NVVImvXDaLlyE=;
        b=TeqBLph9Nua94YxTDOMEE39DGSPU7KKXaCw2RjDfkC4NTfxvl83OZiXdKMgjgsp4Ku
         QTH4a1h9EhrMA8tRBaFJdvNTEYCxAQ89ha1BcN388yz8XbX/9pBG03YVgly78qOWOaba
         rwbxjFcYSaZEscAIwlnWc2kF4RG81fkIDe7JyPDdTjHWHkK93M5rh6eIVyXsf6Dz7zTO
         xk0X1eYCpAaCv8IT0cNAGhZgIS/tVs4CORFp2Br4YTqelUMoOwxJFNV6QlC7Mz1a/BEb
         C1kWWcjuGOf4FsPTfYbxQ1/fF/8GArvaYkOcI8BF7aNRsj/AQ7uZ7sIim2VByT2LteKJ
         9G7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazon201209 header.b="pO/cbvyK";
       spf=pass (google.com: domain of prvs=247c3a56a=pdurrant@amazon.com designates 207.171.190.10 as permitted sender) smtp.mailfrom="prvs=247c3a56a=pdurrant@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
Received: from smtp-fw-33001.amazon.com (smtp-fw-33001.amazon.com. [207.171.190.10])
        by gmr-mx.google.com with ESMTPS id z2si945621oti.5.2019.12.17.07.14.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Dec 2019 07:14:21 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=247c3a56a=pdurrant@amazon.com designates 207.171.190.10 as permitted sender) client-ip=207.171.190.10;
IronPort-SDR: WiqUlRzcYaihh5s2TAgZrBB/GiTaQvKw2TzPl9PRlhywhqtxuORZ9jO7XWS91yYjzzNiQvojLo
 1HS9Pj4QC6Hg==
X-IronPort-AV: E=Sophos;i="5.69,325,1571702400"; 
   d="scan'208";a="15412641"
Received: from sea32-co-svc-lb4-vlan3.sea.corp.amazon.com (HELO email-inbound-relay-2c-87a10be6.us-west-2.amazon.com) ([10.47.23.38])
  by smtp-border-fw-out-33001.sea14.amazon.com with ESMTP; 17 Dec 2019 15:14:07 +0000
Received: from EX13MTAUEA001.ant.amazon.com (pdx4-ws-svc-p6-lb7-vlan2.pdx.amazon.com [10.170.41.162])
	by email-inbound-relay-2c-87a10be6.us-west-2.amazon.com (Postfix) with ESMTPS id 26C83A1C29;
	Tue, 17 Dec 2019 15:14:06 +0000 (UTC)
Received: from EX13D32EUC003.ant.amazon.com (10.43.164.24) by
 EX13MTAUEA001.ant.amazon.com (10.43.61.82) with Microsoft SMTP Server (TLS)
 id 15.0.1367.3; Tue, 17 Dec 2019 15:14:05 +0000
Received: from EX13D32EUC003.ant.amazon.com (10.43.164.24) by
 EX13D32EUC003.ant.amazon.com (10.43.164.24) with Microsoft SMTP Server (TLS)
 id 15.0.1367.3; Tue, 17 Dec 2019 15:14:04 +0000
Received: from EX13D32EUC003.ant.amazon.com ([10.43.164.24]) by
 EX13D32EUC003.ant.amazon.com ([10.43.164.24]) with mapi id 15.00.1367.000;
 Tue, 17 Dec 2019 15:14:04 +0000
From: "'Durrant, Paul' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sergey Dyasli <sergey.dyasli@citrix.com>, "xen-devel@lists.xen.org"
	<xen-devel@lists.xen.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
CC: Juergen Gross <jgross@suse.com>, Stefano Stabellini
	<sstabellini@kernel.org>, George Dunlap <george.dunlap@citrix.com>, "Ross
 Lagerwall" <ross.lagerwall@citrix.com>, Alexander Potapenko
	<glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, "Boris
 Ostrovsky" <boris.ostrovsky@oracle.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: RE: [Xen-devel] [RFC PATCH 3/3] xen/netback: Fix grant copy across
 page boundary with KASAN
Thread-Topic: [Xen-devel] [RFC PATCH 3/3] xen/netback: Fix grant copy across
 page boundary with KASAN
Thread-Index: AQHVtOOxycSsl6gyPk+5/XL6YmuKRKe+Zpag
Date: Tue, 17 Dec 2019 15:14:04 +0000
Message-ID: <8e2d5fca57a74d31be8d5daf399454c0@EX13D32EUC003.ant.amazon.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
 <20191217140804.27364-4-sergey.dyasli@citrix.com>
In-Reply-To: <20191217140804.27364-4-sergey.dyasli@citrix.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.43.166.146]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Precedence: list
X-Original-Sender: pdurrant@amazon.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amazon.com header.s=amazon201209 header.b="pO/cbvyK";
       spf=pass (google.com: domain of prvs=247c3a56a=pdurrant@amazon.com
 designates 207.171.190.10 as permitted sender) smtp.mailfrom="prvs=247c3a56a=pdurrant@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
X-Original-From: "Durrant, Paul" <pdurrant@amazon.com>
Reply-To: "Durrant, Paul" <pdurrant@amazon.com>
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

> -----Original Message-----
> From: Xen-devel <xen-devel-bounces@lists.xenproject.org> On Behalf Of
> Sergey Dyasli
> Sent: 17 December 2019 14:08
> To: xen-devel@lists.xen.org; kasan-dev@googlegroups.com; linux-
> kernel@vger.kernel.org
> Cc: Juergen Gross <jgross@suse.com>; Sergey Dyasli
> <sergey.dyasli@citrix.com>; Stefano Stabellini <sstabellini@kernel.org>;
> George Dunlap <george.dunlap@citrix.com>; Ross Lagerwall
> <ross.lagerwall@citrix.com>; Alexander Potapenko <glider@google.com>;
> Andrey Ryabinin <aryabinin@virtuozzo.com>; Boris Ostrovsky
> <boris.ostrovsky@oracle.com>; Dmitry Vyukov <dvyukov@google.com>
> Subject: [Xen-devel] [RFC PATCH 3/3] xen/netback: Fix grant copy across
> page boundary with KASAN
> 
> From: Ross Lagerwall <ross.lagerwall@citrix.com>
> 
> When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
> allocations are aligned to the next power of 2 of the size does not
> hold. Therefore, handle grant copies that cross page boundaries.
> 
> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>

Would have been nice to cc netback maintainers...

> ---
>  drivers/net/xen-netback/common.h  |  2 +-
>  drivers/net/xen-netback/netback.c | 55 ++++++++++++++++++++++++-------
>  2 files changed, 45 insertions(+), 12 deletions(-)
> 
> diff --git a/drivers/net/xen-netback/common.h b/drivers/net/xen-
> netback/common.h
> index 05847eb91a1b..e57684415edd 100644
> --- a/drivers/net/xen-netback/common.h
> +++ b/drivers/net/xen-netback/common.h
> @@ -155,7 +155,7 @@ struct xenvif_queue { /* Per-queue data for xenvif */
>  	struct pending_tx_info pending_tx_info[MAX_PENDING_REQS];
>  	grant_handle_t grant_tx_handle[MAX_PENDING_REQS];
> 
> -	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS];
> +	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS * 2];
>  	struct gnttab_map_grant_ref tx_map_ops[MAX_PENDING_REQS];
>  	struct gnttab_unmap_grant_ref tx_unmap_ops[MAX_PENDING_REQS];
>  	/* passed to gnttab_[un]map_refs with pages under (un)mapping */
> diff --git a/drivers/net/xen-netback/netback.c b/drivers/net/xen-
> netback/netback.c
> index 0020b2e8c279..1541b6e0cc62 100644
> --- a/drivers/net/xen-netback/netback.c
> +++ b/drivers/net/xen-netback/netback.c
> @@ -320,6 +320,7 @@ static int xenvif_count_requests(struct xenvif_queue
> *queue,
> 
>  struct xenvif_tx_cb {
>  	u16 pending_idx;
> +	u8 copies;
>  };

I know we're a way off the limit (48 bytes) but I wonder if we ought to have a compile time check here that we're not overflowing skb->cb.

> 
>  #define XENVIF_TX_CB(skb) ((struct xenvif_tx_cb *)(skb)->cb)
> @@ -439,6 +440,7 @@ static int xenvif_tx_check_gop(struct xenvif_queue
> *queue,
>  {
>  	struct gnttab_map_grant_ref *gop_map = *gopp_map;
>  	u16 pending_idx = XENVIF_TX_CB(skb)->pending_idx;
> +	u8 copies = XENVIF_TX_CB(skb)->copies;
>  	/* This always points to the shinfo of the skb being checked, which
>  	 * could be either the first or the one on the frag_list
>  	 */
> @@ -450,23 +452,27 @@ static int xenvif_tx_check_gop(struct xenvif_queue
> *queue,
>  	int nr_frags = shinfo->nr_frags;
>  	const bool sharedslot = nr_frags &&
>  				frag_get_pending_idx(&shinfo->frags[0]) ==
> pending_idx;
> -	int i, err;
> +	int i, err = 0;
> 
> -	/* Check status of header. */
> -	err = (*gopp_copy)->status;
> -	if (unlikely(err)) {
> -		if (net_ratelimit())
> -			netdev_dbg(queue->vif->dev,
> +	while (copies) {
> +		/* Check status of header. */
> +		int newerr = (*gopp_copy)->status;
> +		if (unlikely(newerr)) {
> +			if (net_ratelimit())
> +				netdev_dbg(queue->vif->dev,
>  				   "Grant copy of header failed! status: %d
> pending_idx: %u ref: %u\n",
>  				   (*gopp_copy)->status,
>  				   pending_idx,
>  				   (*gopp_copy)->source.u.ref);
> -		/* The first frag might still have this slot mapped */
> -		if (!sharedslot)
> -			xenvif_idx_release(queue, pending_idx,
> -					   XEN_NETIF_RSP_ERROR);
> +			/* The first frag might still have this slot mapped */
> +			if (!sharedslot && !err)
> +				xenvif_idx_release(queue, pending_idx,
> +						   XEN_NETIF_RSP_ERROR);

Can't this be done after the loop, if there is an accumulated err? I think it would make the code slightly neater.

> +			err = newerr;
> +		}
> +		(*gopp_copy)++;
> +		copies--;
>  	}
> -	(*gopp_copy)++;
> 
>  check_frags:
>  	for (i = 0; i < nr_frags; i++, gop_map++) {
> @@ -910,6 +916,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue
> *queue,
>  			xenvif_tx_err(queue, &txreq, extra_count, idx);
>  			break;
>  		}
> +		XENVIF_TX_CB(skb)->copies = 0;
> 
>  		skb_shinfo(skb)->nr_frags = ret;
>  		if (data_len < txreq.size)
> @@ -933,6 +940,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue
> *queue,
>  						   "Can't allocate the frag_list
> skb.\n");
>  				break;
>  			}
> +			XENVIF_TX_CB(nskb)->copies = 0;
>  		}
> 
>  		if (extras[XEN_NETIF_EXTRA_TYPE_GSO - 1].type) {
> @@ -990,6 +998,31 @@ static void xenvif_tx_build_gops(struct xenvif_queue
> *queue,
> 
>  		queue->tx_copy_ops[*copy_ops].len = data_len;

If offset_in_page(skb->data)+ data_len can exceed XEN_PAGE_SIZE, does this not need to be truncated?

  Paul

>  		queue->tx_copy_ops[*copy_ops].flags = GNTCOPY_source_gref;
> +		XENVIF_TX_CB(skb)->copies++;
> +
> +		if (offset_in_page(skb->data) + data_len > XEN_PAGE_SIZE) {
> +			unsigned int extra_len = offset_in_page(skb->data) +
> +					     data_len - XEN_PAGE_SIZE;
> +
> +			queue->tx_copy_ops[*copy_ops].len -= extra_len;
> +			(*copy_ops)++;
> +
> +			queue->tx_copy_ops[*copy_ops].source.u.ref = txreq.gref;
> +			queue->tx_copy_ops[*copy_ops].source.domid =
> +				queue->vif->domid;
> +			queue->tx_copy_ops[*copy_ops].source.offset =
> +				txreq.offset + data_len - extra_len;
> +
> +			queue->tx_copy_ops[*copy_ops].dest.u.gmfn =
> +				virt_to_gfn(skb->data + data_len - extra_len);
> +			queue->tx_copy_ops[*copy_ops].dest.domid = DOMID_SELF;
> +			queue->tx_copy_ops[*copy_ops].dest.offset = 0;
> +
> +			queue->tx_copy_ops[*copy_ops].len = extra_len;
> +			queue->tx_copy_ops[*copy_ops].flags =
> GNTCOPY_source_gref;
> +
> +			XENVIF_TX_CB(skb)->copies++;
> +		}
> 
>  		(*copy_ops)++;
> 
> --
> 2.17.1
> 
> 
> _______________________________________________
> Xen-devel mailing list
> Xen-devel@lists.xenproject.org
> https://lists.xenproject.org/mailman/listinfo/xen-devel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8e2d5fca57a74d31be8d5daf399454c0%40EX13D32EUC003.ant.amazon.com.
