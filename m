Return-Path: <kasan-dev+bncBAABBGF52HYAKGQEGEF3JGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id DE2DB1323AC
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2020 11:34:01 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id m13sf19443089qka.9
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2020 02:34:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578393240; cv=pass;
        d=google.com; s=arc-20160816;
        b=l7er0HiazHlEkz/xqipIVdKDC6r7/PnH82ruWg41xbTZHeTbCXxji5Ved+EKYtZpKy
         XWNYBkyYz0se7gMCkr5etrpxVncGFr4njWrlFYoAjkAXppMimapeuXUhOBM3UyM1q/L/
         rG8956/0dLLsyMjBLFoybO8nJRukoqeG1aNfntJu6+vY2WodcUM68X6Q6SVBlAvbfVQe
         G+JUDMqlgUVnXN7/q2/GDuDo28wB6wD1nvViPpFeftMYRI9MMD9uSvUbXEuDegzGp8VH
         FrDs/nTX3IovXzHQIu7Ous7oWJQRh0uzEUkFZGdrup75EF/oZrzn666x9zednFJBQAbd
         xQPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=adHJ0ZsKLijukA3Md/SVXtY2QNzRxjwFpHjBegaTKLM=;
        b=fMw/YRX1j6la5c8sqgw1V2+D7wfe+OxEzLU8DytusotZcIT5K/NaWO6Qwnn8HYEMEo
         rLW60l84sFx9B/4qH2UFukpNMj9JPhM2eMRM2KeU3+S0t8Z/Rt1FtKKXp0l+TTkXZ7G1
         LIhN/SIMZwtTsS8Izf2GCmg00uWKpGDAX0bzrCgdKujntMizpssrHD6u2phJhqjSICyA
         p6qzR+Og2o3db47XKc6b6liV4G0vT2epWGk2mon+iTPv0GGP9/NQ7MrhNHHWCFCRBn+P
         c3V84qw4y4g1uZb+GrdYdBq5A7HU/yqLVTfyBhMVI7GC61rKFHwZSNgBhwr3LinyEZwz
         4Jng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=DqlDD0SI;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=adHJ0ZsKLijukA3Md/SVXtY2QNzRxjwFpHjBegaTKLM=;
        b=k1UXjYDO26yLQ8UAG7bKuuNYPmKsnE8tq+SwUs9vG7o3bIeKsQPRycuOxJEyi3oQe8
         weS8oQz9sz2Bvaykh5DCvT4gpys7AA1wRNOyHuk4GVXqaWaV6gBlCwEB39V26pGzDVsU
         3+O0WKRFntbwQ3PLwY9gmuRzewd/I9ltXSODas/o6occRLb6HlFjAUawiD+s+VJl9Kdn
         qvOANHfvw8l6t9X0jBMPdXOz1sxopNoKvA1ZiJtH+CPPkoJaODIgeo+BfYNLNGJgI0Pw
         I5hFenBnYDcgtV83C2qN4ZzTP8kCmrEL0XO4g9dAhMTFgBTy+JT066a2K0JN0S93NsR8
         2cvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adHJ0ZsKLijukA3Md/SVXtY2QNzRxjwFpHjBegaTKLM=;
        b=EtuUHKPyhOfniTx8mchqxbwReFBGdrEH5jj6bBixakP0hygQwL7voiK2gxMhiAIX6V
         vsC/rpM1HjWymvDmg80HgJ8D/n1cy6W3NVzgOL5lAM3YPXLQtv3mI3GBQ77io5tJpEuM
         I74k27RQ8sCeqUkN0ua0qLVEQfmveo1/K03x73rKu52Zp9BV3JYokb2NjU/8f/L2qiQ1
         X2VU7/ACSVAy9mDziiYK90mfR6V5M/heywsSg1zI8nFv5mSAIsJlgZZ4bJMyB6lKrWvF
         pZioA+LHwadBFx1tqCSV/VYUjARuMmbvnrBZ1WdFewfI9im1xVAq077uIV38NeUL1N0m
         AS/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWQzX/Q/WJzDT1mDR3zjnZ2e5SGw5cl0s10mLc7F6DqTifwhv+e
	48SO+vmuTCodyI0WlphTBZ0=
X-Google-Smtp-Source: APXvYqxYGwfTY21in2O5aR+sPRiVWWosclQvgHaQnkxIRuhECTi+xLhxEIHKMvsy7cOkMX96J+zkNg==
X-Received: by 2002:ad4:4d50:: with SMTP id m16mr82464274qvm.186.1578393240654;
        Tue, 07 Jan 2020 02:34:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2712:: with SMTP id g18ls7281384qtg.3.gmail; Tue, 07 Jan
 2020 02:34:00 -0800 (PST)
X-Received: by 2002:aed:2a12:: with SMTP id c18mr77905354qtd.200.1578393240241;
        Tue, 07 Jan 2020 02:34:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578393240; cv=none;
        d=google.com; s=arc-20160816;
        b=FCJQc0/IIyepAkk2MNp0Y962iMHEFz/EQRHwQin3u/DwB9X+ajRkIYfoXE/tdlWZtR
         yeGiW/uEz9FhFtW0Z9GzPH1rO9Ysj0RArG6Pi7csIakCfmihHh+G91do1TOSnCsO7Flj
         xAcQ8wdvov0WJjMXNepMGBWywy+cXXAf5v+iJw/ngjFggiv5uUTAReJ0xd/+lsgsent0
         9ObfZvKZpLnmqMNkGgF8W4dmx6+MtdzVf+mZAcMJUmpIutAN+cgP+auVk9JL/P36jsOW
         yEuKPQ0rLYjYLbyCkFsW7S8EjTrfYRXe35chNwVHWqWxMKPheREBKSlVDJEUGpsp+1cw
         aqtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=bjXuuBFMTZhwh1IPvCr7FmXQ6n56RkDh4XNcV9Au/54=;
        b=n3z+9PjHPx6JQ1wRkIVR2KlTEoKODFmVw4oIZoLgeHZ3o8rsTNOK524vpISbShMHzI
         t85Htbj8gk7cRrU2kFIVMVkTQF0yTxl9EmkcaWZ57SLumfbprhA/As5FvCt7MjP+PdOi
         a/Su56po3RK6dF9t6CrwbCw+U/JDkGHzJcvV+BvZIdM8J2dgKOpXVkyi4ETr8Adb8T30
         jhgK440Pa35/Hay0UnV1BSLwuxMPkwp3fkPwVJ00QUoqZkymJPt7LMYak9ApXxOwUBHZ
         ApDjV/6cjWVfx8+PcaD+EM08rkZHX6BGQD6bFz5Nsk8O7LSI4hfMlufClfVhWGatChsz
         KffA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=DqlDD0SI;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id d135si2241787qke.7.2020.01.07.02.33.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 Jan 2020 02:34:00 -0800 (PST)
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
IronPort-SDR: iyYQjhefkR0muYjKwTb36+XIOUJ+gc2PhRc9NrwemCf1i3BaA6RVntv+r1OugCWlK/hHj6yLuV
 CrU/7HZxnvEA1YcHBcEVjGfU4/F4fqnpfsSfPdOja8du+46VPz75T7BP1Dfl5T/YruKMhjhDEt
 F9JUnNW+WNKl3fWs9j3JP1vW/VcPbjdISoUEiINvCEQp/ZTmr7VXejs4Q+dKu2yZljChXrvbZb
 mzoWIgppp57ADJAebm9DAx+vtNNecL3jVskp22W6WSUEwxd86iyY3A+c2jRgu3Ex8S98+2pKqQ
 Gmc=
X-SBRS: 2.7
X-MesageID: 10556611
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,405,1571716800"; 
   d="scan'208";a="10556611"
Subject: Re: [Xen-devel] [RFC PATCH 3/3] xen/netback: Fix grant copy across
 page boundary with KASAN
To: "Durrant, Paul" <pdurrant@amazon.com>, "xen-devel@lists.xen.org"
	<xen-devel@lists.xen.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
CC: Juergen Gross <jgross@suse.com>, Stefano Stabellini
	<sstabellini@kernel.org>, George Dunlap <george.dunlap@citrix.com>, "Ross
 Lagerwall" <ross.lagerwall@citrix.com>, Alexander Potapenko
	<glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, "Boris
 Ostrovsky" <boris.ostrovsky@oracle.com>, Dmitry Vyukov <dvyukov@google.com>,
	"sergey.dyasli@citrix.com >> Sergey Dyasli" <sergey.dyasli@citrix.com>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
 <20191217140804.27364-4-sergey.dyasli@citrix.com>
 <8e2d5fca57a74d31be8d5daf399454c0@EX13D32EUC003.ant.amazon.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <1e9c5008-d263-5a90-b1ba-c304861f7ad2@citrix.com>
Date: Tue, 7 Jan 2020 10:33:55 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <8e2d5fca57a74d31be8d5daf399454c0@EX13D32EUC003.ant.amazon.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=DqlDD0SI;       spf=pass
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

On 17/12/2019 15:14, Durrant, Paul wrote:
>> -----Original Message-----
>> From: Xen-devel <xen-devel-bounces@lists.xenproject.org> On Behalf Of
>> Sergey Dyasli
>> Sent: 17 December 2019 14:08
>> To: xen-devel@lists.xen.org; kasan-dev@googlegroups.com; linux-
>> kernel@vger.kernel.org
>> Cc: Juergen Gross <jgross@suse.com>; Sergey Dyasli
>> <sergey.dyasli@citrix.com>; Stefano Stabellini <sstabellini@kernel.org>;
>> George Dunlap <george.dunlap@citrix.com>; Ross Lagerwall
>> <ross.lagerwall@citrix.com>; Alexander Potapenko <glider@google.com>;
>> Andrey Ryabinin <aryabinin@virtuozzo.com>; Boris Ostrovsky
>> <boris.ostrovsky@oracle.com>; Dmitry Vyukov <dvyukov@google.com>
>> Subject: [Xen-devel] [RFC PATCH 3/3] xen/netback: Fix grant copy across
>> page boundary with KASAN
>>
>> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>>
>> When KASAN (or SLUB_DEBUG) is turned on, the normal expectation that
>> allocations are aligned to the next power of 2 of the size does not
>> hold. Therefore, handle grant copies that cross page boundaries.
>>
>> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>
> Would have been nice to cc netback maintainers...

Sorry, I'll try to be more careful next time.

>
>> ---
>>  drivers/net/xen-netback/common.h  |  2 +-
>>  drivers/net/xen-netback/netback.c | 55 ++++++++++++++++++++++++-------
>>  2 files changed, 45 insertions(+), 12 deletions(-)
>>
>> diff --git a/drivers/net/xen-netback/common.h b/drivers/net/xen-
>> netback/common.h
>> index 05847eb91a1b..e57684415edd 100644
>> --- a/drivers/net/xen-netback/common.h
>> +++ b/drivers/net/xen-netback/common.h
>> @@ -155,7 +155,7 @@ struct xenvif_queue { /* Per-queue data for xenvif */
>>  	struct pending_tx_info pending_tx_info[MAX_PENDING_REQS];
>>  	grant_handle_t grant_tx_handle[MAX_PENDING_REQS];
>>
>> -	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS];
>> +	struct gnttab_copy tx_copy_ops[MAX_PENDING_REQS * 2];
>>  	struct gnttab_map_grant_ref tx_map_ops[MAX_PENDING_REQS];
>>  	struct gnttab_unmap_grant_ref tx_unmap_ops[MAX_PENDING_REQS];
>>  	/* passed to gnttab_[un]map_refs with pages under (un)mapping */
>> diff --git a/drivers/net/xen-netback/netback.c b/drivers/net/xen-
>> netback/netback.c
>> index 0020b2e8c279..1541b6e0cc62 100644
>> --- a/drivers/net/xen-netback/netback.c
>> +++ b/drivers/net/xen-netback/netback.c
>> @@ -320,6 +320,7 @@ static int xenvif_count_requests(struct xenvif_queue
>> *queue,
>>
>>  struct xenvif_tx_cb {
>>  	u16 pending_idx;
>> +	u8 copies;
>>  };
>
> I know we're a way off the limit (48 bytes) but I wonder if we ought to have a compile time check here that we're not overflowing skb->cb.

I will add a BUILD_BUG_ON()

>
>>
>>  #define XENVIF_TX_CB(skb) ((struct xenvif_tx_cb *)(skb)->cb)
>> @@ -439,6 +440,7 @@ static int xenvif_tx_check_gop(struct xenvif_queue
>> *queue,
>>  {
>>  	struct gnttab_map_grant_ref *gop_map = *gopp_map;
>>  	u16 pending_idx = XENVIF_TX_CB(skb)->pending_idx;
>> +	u8 copies = XENVIF_TX_CB(skb)->copies;
>>  	/* This always points to the shinfo of the skb being checked, which
>>  	 * could be either the first or the one on the frag_list
>>  	 */
>> @@ -450,23 +452,27 @@ static int xenvif_tx_check_gop(struct xenvif_queue
>> *queue,
>>  	int nr_frags = shinfo->nr_frags;
>>  	const bool sharedslot = nr_frags &&
>>  				frag_get_pending_idx(&shinfo->frags[0]) ==
>> pending_idx;
>> -	int i, err;
>> +	int i, err = 0;
>>
>> -	/* Check status of header. */
>> -	err = (*gopp_copy)->status;
>> -	if (unlikely(err)) {
>> -		if (net_ratelimit())
>> -			netdev_dbg(queue->vif->dev,
>> +	while (copies) {
>> +		/* Check status of header. */
>> +		int newerr = (*gopp_copy)->status;
>> +		if (unlikely(newerr)) {
>> +			if (net_ratelimit())
>> +				netdev_dbg(queue->vif->dev,
>>  				   "Grant copy of header failed! status: %d
>> pending_idx: %u ref: %u\n",
>>  				   (*gopp_copy)->status,
>>  				   pending_idx,
>>  				   (*gopp_copy)->source.u.ref);
>> -		/* The first frag might still have this slot mapped */
>> -		if (!sharedslot)
>> -			xenvif_idx_release(queue, pending_idx,
>> -					   XEN_NETIF_RSP_ERROR);
>> +			/* The first frag might still have this slot mapped */
>> +			if (!sharedslot && !err)
>> +				xenvif_idx_release(queue, pending_idx,
>> +						   XEN_NETIF_RSP_ERROR);
>
> Can't this be done after the loop, if there is an accumulated err? I think it would make the code slightly neater.

Looks like xenvif_idx_release() indeed wants to be just after the loop.

>
>> +			err = newerr;
>> +		}
>> +		(*gopp_copy)++;
>> +		copies--;
>>  	}
>> -	(*gopp_copy)++;
>>
>>  check_frags:
>>  	for (i = 0; i < nr_frags; i++, gop_map++) {
>> @@ -910,6 +916,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue
>> *queue,
>>  			xenvif_tx_err(queue, &txreq, extra_count, idx);
>>  			break;
>>  		}
>> +		XENVIF_TX_CB(skb)->copies = 0;
>>
>>  		skb_shinfo(skb)->nr_frags = ret;
>>  		if (data_len < txreq.size)
>> @@ -933,6 +940,7 @@ static void xenvif_tx_build_gops(struct xenvif_queue
>> *queue,
>>  						   "Can't allocate the frag_list
>> skb.\n");
>>  				break;
>>  			}
>> +			XENVIF_TX_CB(nskb)->copies = 0;
>>  		}
>>
>>  		if (extras[XEN_NETIF_EXTRA_TYPE_GSO - 1].type) {
>> @@ -990,6 +998,31 @@ static void xenvif_tx_build_gops(struct xenvif_queue
>> *queue,
>>
>>  		queue->tx_copy_ops[*copy_ops].len = data_len;
>
> If offset_in_page(skb->data)+ data_len can exceed XEN_PAGE_SIZE, does this not need to be truncated?

It is performed as the first thing inside the if condition below.

>>  		queue->tx_copy_ops[*copy_ops].flags = GNTCOPY_source_gref;
>> +		XENVIF_TX_CB(skb)->copies++;
>> +
>> +		if (offset_in_page(skb->data) + data_len > XEN_PAGE_SIZE) {
>> +			unsigned int extra_len = offset_in_page(skb->data) +
>> +					     data_len - XEN_PAGE_SIZE;
>> +
>> +			queue->tx_copy_ops[*copy_ops].len -= extra_len;
>> +			(*copy_ops)++;
>> +
>> +			queue->tx_copy_ops[*copy_ops].source.u.ref = txreq.gref;
>> +			queue->tx_copy_ops[*copy_ops].source.domid =
>> +				queue->vif->domid;
>> +			queue->tx_copy_ops[*copy_ops].source.offset =
>> +				txreq.offset + data_len - extra_len;
>> +
>> +			queue->tx_copy_ops[*copy_ops].dest.u.gmfn =
>> +				virt_to_gfn(skb->data + data_len - extra_len);
>> +			queue->tx_copy_ops[*copy_ops].dest.domid = DOMID_SELF;
>> +			queue->tx_copy_ops[*copy_ops].dest.offset = 0;
>> +
>> +			queue->tx_copy_ops[*copy_ops].len = extra_len;
>> +			queue->tx_copy_ops[*copy_ops].flags =
>> GNTCOPY_source_gref;
>> +
>> +			XENVIF_TX_CB(skb)->copies++;
>> +		}
>>
>>  		(*copy_ops)++;
>>
>> --
>> 2.17.1
>>
>>
>> _______________________________________________
>> Xen-devel mailing list
>> Xen-devel@lists.xenproject.org
>> https://lists.xenproject.org/mailman/listinfo/xen-devel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1e9c5008-d263-5a90-b1ba-c304861f7ad2%40citrix.com.
