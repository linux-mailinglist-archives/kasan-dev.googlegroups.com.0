Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOELY6OAMGQEWCI7JFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id CC817646E0E
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Dec 2022 12:08:41 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id h9-20020a05640250c900b00461d8ee12e2sf809371edb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Dec 2022 03:08:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670497721; cv=pass;
        d=google.com; s=arc-20160816;
        b=B1cZy2+Mvcdlb/MZxeUg8qhuinWqBiPEM/Bl3ZFzAyVhks0KNe8JQnrRqyXwuNAdlR
         mJDwd6AJlCt5CDuXstKzGPpDk3o9Cpn+b3THQvDiD1CuIZCUrVLJ0L7gInnOoTo0arzd
         O81MT585iNrkWTTWinMg16X8mbrXZRlBRr3g3D1fL2JTSCBogFhr7hzhRyw66N+V85S0
         wJ2y6I1DcU6CjOqAlqi5+60i2dES9ekvRcI+ZQQU12m50z4RcWdRqwVWpgrKvAkNmrzZ
         4PhW10MBmiatH9Yov2zsSTDgvg+x9CZmrdIX1mOQat5Lb2+h7FwZp5Qke94ol+k76MOt
         lQpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=uvluoUIX5KnIryTXnUKFAK76Q26XTzm1q6mAtHQMjeg=;
        b=uAGXt2iHRFQJVhqVIqXwQ6onhxc7zIubyF4MeH2VONAhxHAKMtBi7dyoyoP5ERpaGG
         I0n/Wgjt/EEeCGMkpW1UTAsOvshft1bt9jIsMUF7kJfBidDwaIectPkgkKEriIMA/X3q
         7Vh9zZJwNMHtgK6l/mbWTxEFiIu2uUWeza1zRmozvcrkSAoFH06fUiEMrlVVYu3v5ofG
         +/g1d4Dwy4c94dwLVs+Hf3d9abZ03YEs1n1nlNJXhyp/nG3NL5VZFkhcYRZ/a0C1x/Qq
         /PgIBW/cRdj+dxcRCw/vbykAvCjZJvzP2eJkxhY7YM2e0W+v+gl9wg/gi9cqi6hiVJQX
         UVSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0aZG2rmP;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uvluoUIX5KnIryTXnUKFAK76Q26XTzm1q6mAtHQMjeg=;
        b=qv/Jo+VzmsE2G0fYmbmovh+3eGsS0aKZtyGogxcPGau8BlR4aN0OYQfdfHDjyyRm2+
         gje4958CQBb76syDcf46EbzsRP3Vn7C+H60YOtI2ocowjH+jDR3Vl3f4OUU8wboapRWl
         VvFul3D9UTlrqTKUxM5GmcY1ssaLIwvbG8g+aeFmh1sWhEJOeJMqsw0nojPtOkB+Owno
         oWecyZqkSVPugylR2sGhKUkefWeXZWZ0e63btzYi5nge+9Fpze8tmfPKLUdez3qG3ruo
         l5f8EfuovrXDGFeoFou8UCQulWgyTdlQiS6R44Qf21GWSID+hLZxjplnFQMOPOC5lel7
         GenQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uvluoUIX5KnIryTXnUKFAK76Q26XTzm1q6mAtHQMjeg=;
        b=7EFZepi0nUUuAkL64wyK1lbRdghtxiPgIdWDmO4Cn+wZwZTCRpVSyaGGE+mK2cEoEn
         Q5h3Fs+cghulKh21cJg7+vLPVOtDm7vy6kH1LR+Jbtl2J4pRplS2xtwftip6okge/n+Y
         sQjtbDZhQLH7DSDVtNpvyrYc4OdOQ5ApEJS8uD3aXO0xw5SXG321RMv/8Chfyz7gn+2R
         XF6hEyUvnT/52YKKNnk0VRnFhlEj8gskPSyNFAL5eS5EtCnFjLVQ8kIf8tvO9zbXYDHJ
         4D1dlOj9LCvr7d1ZNeLVU3jBRBxnuVoQQedNA6YGChE0bwXi+wnDy9hiagJANkUHPQVA
         cRRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plTPn/rhcOz6+vD9PlajKel+3SWNYrE3Wofi6r+IAQ8F9iAjQue
	JWpy9oPhWNRazxaHi7A1Aew=
X-Google-Smtp-Source: AA0mqf7hzA7TmjvqzF6wlKHg7+QShKTNBnVXnJGV4DE9XCoRdtQfx+FHp7bWCVF08deJXS3uUHfj2A==
X-Received: by 2002:a17:907:1dee:b0:7c0:dfb7:6574 with SMTP id og46-20020a1709071dee00b007c0dfb76574mr16724099ejc.38.1670497721116;
        Thu, 08 Dec 2022 03:08:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:190a:b0:45c:bfd9:fb45 with SMTP id
 e10-20020a056402190a00b0045cbfd9fb45ls716187edz.3.-pod-prod-gmail; Thu, 08
 Dec 2022 03:08:39 -0800 (PST)
X-Received: by 2002:aa7:cc8a:0:b0:464:1296:d5d4 with SMTP id p10-20020aa7cc8a000000b004641296d5d4mr81170763edt.83.1670497719726;
        Thu, 08 Dec 2022 03:08:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670497719; cv=none;
        d=google.com; s=arc-20160816;
        b=M7OU2MHQtfZmc67mOgm5NN7jtnl1WZWBLrooF9OaDYkNHuyRqsPI+H37fzb8oJC2Og
         US2pWcMbpFgSIn2QSW12rEwOOM+xUoRViGbc753RQk2BxpHxoD2LWbHI93uS89d8HNnz
         44bZKzTHpYpx+gDdf9gkM5wyNw6Myi+Ze5cbJQWT1hnyoIsx5g/KSm2Q5krLuE6HZMcI
         Ihsuq3yH40NZ7aQ+EDQVEg21TOXMH+IPHGf+jknttcfZBjwYMaDPrJv9nzfe3knRAySa
         Rmsz8hfaeiwakDLo4tO1cRvZQW2ZAFZWNi+i2GA2rM1sttUh9CC4SQYOYdTgWZzT4nsr
         4lng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=qYJKBANfv55V7w+9coBcBtTUfxC6BQ0fclSJzAtAWiI=;
        b=0YInq1TpNMrLVkRTl90jqmrV29V5SBHc6lx4H7xhjK36K4sBNP6iYoLW7fwqg+NSGu
         3NZBadeWSqboj5QyQd2DLFcQDDesQKiWfLjT7nLzSYJRYMhKjjCGPBkXWZR2SKibmGqY
         nYUNRIx0KoGMHfUFhKSr5Rh13UyGGuKTC7bftOVQ+yt9IpxXPoGyiklmrhhe+hClT480
         uZ31H9AuoEVSYSaQiA8fQvcBFJ2qo6DHIEkTTJ25nG4DqNBAfWDHt6rMD4Ty0ibN1jIp
         9IQrZNKcgLDGQEX+hrI6yWg1nsfWwzrT91IEny94B7C8sTlsrtXNqiuxSx58/YEvUKdB
         RobQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0aZG2rmP;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id jy7-20020a170907762700b007b27af75123si998934ejc.1.2022.12.08.03.08.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Dec 2022 03:08:39 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4F1E6337A9;
	Thu,  8 Dec 2022 11:08:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BA511138E0;
	Thu,  8 Dec 2022 11:08:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id DWbCLLbFkWPXHgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 08 Dec 2022 11:08:38 +0000
Message-ID: <332c3841-54c2-4777-be90-32d7cef90668@suse.cz>
Date: Thu, 8 Dec 2022 12:08:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH net-next v3] skbuff: Introduce slab_build_skb()
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>
Cc: Kees Cook <keescook@chromium.org>, Jakub Kicinski <kuba@kernel.org>,
 syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
 Eric Dumazet <edumazet@google.com>, "David S. Miller" <davem@davemloft.net>,
 Paolo Abeni <pabeni@redhat.com>, Pavel Begunkov <asml.silence@gmail.com>,
 pepsipu <soopthegoop@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrii Nakryiko <andrii@kernel.org>, ast@kernel.org,
 bpf <bpf@vger.kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
 Hao Luo <haoluo@google.com>, Jesper Dangaard Brouer <hawk@kernel.org>,
 John Fastabend <john.fastabend@gmail.com>, jolsa@kernel.org,
 KP Singh <kpsingh@kernel.org>, martin.lau@linux.dev,
 Stanislav Fomichev <sdf@google.com>, song@kernel.org,
 Yonghong Song <yhs@fb.com>, netdev@vger.kernel.org,
 LKML <linux-kernel@vger.kernel.org>, Rasesh Mody <rmody@marvell.com>,
 Ariel Elior <aelior@marvell.com>, Manish Chopra <manishc@marvell.com>,
 Menglong Dong <imagedong@tencent.com>, David Ahern <dsahern@kernel.org>,
 Richard Gobert <richardbgobert@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, David Rientjes
 <rientjes@google.com>, GR-Linux-NIC-Dev@marvell.com,
 linux-hardening@vger.kernel.org
References: <20221208060256.give.994-kees@kernel.org>
 <6923d6a9-7728-fc71-f963-3617e5361732@suse.cz> <Y5G6RnoyZC78UO4q@feng-clx>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y5G6RnoyZC78UO4q@feng-clx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0aZG2rmP;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/8/22 11:19, Feng Tang wrote:
> On Thu, Dec 08, 2022 at 09:13:41AM +0100, Vlastimil Babka wrote:
>> On 12/8/22 07:02, Kees Cook wrote:
>> > syzkaller reported:
>> > 
>> >   BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
>> >   Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295
>> > 
>> > For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
>> > build_skb().
>> > 
>> > When build_skb() is passed a frag_size of 0, it means the buffer came
>> > from kmalloc. In these cases, ksize() is used to find its actual size,
>> > but since the allocation may not have been made to that size, actually
>> > perform the krealloc() call so that all the associated buffer size
>> > checking will be correctly notified (and use the "new" pointer so that
>> > compiler hinting works correctly). Split this logic out into a new
>> > interface, slab_build_skb(), but leave the original 0 checking for now
>> > to catch any stragglers.
>> > 
>> > Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
>> > Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
>> > Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
>> > Cc: Jakub Kicinski <kuba@kernel.org>
>> > Cc: Eric Dumazet <edumazet@google.com>
>> > Cc: "David S. Miller" <davem@davemloft.net>
>> > Cc: Paolo Abeni <pabeni@redhat.com>
>> > Cc: Pavel Begunkov <asml.silence@gmail.com>
>> > Cc: pepsipu <soopthegoop@gmail.com>
>> > Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
>> > Cc: Vlastimil Babka <vbabka@suse.cz>
>> > Cc: kasan-dev <kasan-dev@googlegroups.com>
>> > Cc: Andrii Nakryiko <andrii@kernel.org>
>> > Cc: ast@kernel.org
>> > Cc: bpf <bpf@vger.kernel.org>
>> > Cc: Daniel Borkmann <daniel@iogearbox.net>
>> > Cc: Hao Luo <haoluo@google.com>
>> > Cc: Jesper Dangaard Brouer <hawk@kernel.org>
>> > Cc: John Fastabend <john.fastabend@gmail.com>
>> > Cc: jolsa@kernel.org
>> > Cc: KP Singh <kpsingh@kernel.org>
>> > Cc: martin.lau@linux.dev
>> > Cc: Stanislav Fomichev <sdf@google.com>
>> > Cc: song@kernel.org
>> > Cc: Yonghong Song <yhs@fb.com>
>> > Cc: netdev@vger.kernel.org
>> > Cc: LKML <linux-kernel@vger.kernel.org>
>> > Signed-off-by: Kees Cook <keescook@chromium.org>
>> > ---
>> > v3:
>> > - make sure "resized" is passed back so compiler hints survive
>> > - update kerndoc (kuba)
>> > v2: https://lore.kernel.org/lkml/20221208000209.gonna.368-kees@kernel.org
>> > v1: https://lore.kernel.org/netdev/20221206231659.never.929-kees@kernel.org/
>> > ---
>> >  drivers/net/ethernet/broadcom/bnx2.c      |  2 +-
>> >  drivers/net/ethernet/qlogic/qed/qed_ll2.c |  2 +-
>> >  include/linux/skbuff.h                    |  1 +
>> >  net/bpf/test_run.c                        |  2 +-
>> >  net/core/skbuff.c                         | 70 ++++++++++++++++++++---
>> >  5 files changed, 66 insertions(+), 11 deletions(-)
>> > 
>> > diff --git a/drivers/net/ethernet/broadcom/bnx2.c b/drivers/net/ethernet/broadcom/bnx2.c
>> > index fec57f1982c8..b2230a4a2086 100644
>> > --- a/drivers/net/ethernet/broadcom/bnx2.c
>> > +++ b/drivers/net/ethernet/broadcom/bnx2.c
>> > @@ -3045,7 +3045,7 @@ bnx2_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u8 *data,
>> >  
>> >  	dma_unmap_single(&bp->pdev->dev, dma_addr, bp->rx_buf_use_size,
>> >  			 DMA_FROM_DEVICE);
>> > -	skb = build_skb(data, 0);
>> > +	skb = slab_build_skb(data);
>> >  	if (!skb) {
>> >  		kfree(data);
>> >  		goto error;
>> > diff --git a/drivers/net/ethernet/qlogic/qed/qed_ll2.c b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
>> > index ed274f033626..e5116a86cfbc 100644
>> > --- a/drivers/net/ethernet/qlogic/qed/qed_ll2.c
>> > +++ b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
>> > @@ -200,7 +200,7 @@ static void qed_ll2b_complete_rx_packet(void *cxt,
>> >  	dma_unmap_single(&cdev->pdev->dev, buffer->phys_addr,
>> >  			 cdev->ll2->rx_size, DMA_FROM_DEVICE);
>> >  
>> > -	skb = build_skb(buffer->data, 0);
>> > +	skb = slab_build_skb(buffer->data);
>> >  	if (!skb) {
>> >  		DP_INFO(cdev, "Failed to build SKB\n");
>> >  		kfree(buffer->data);
>> > diff --git a/include/linux/skbuff.h b/include/linux/skbuff.h
>> > index 7be5bb4c94b6..0b391b635430 100644
>> > --- a/include/linux/skbuff.h
>> > +++ b/include/linux/skbuff.h
>> > @@ -1253,6 +1253,7 @@ struct sk_buff *build_skb_around(struct sk_buff *skb,
>> >  void skb_attempt_defer_free(struct sk_buff *skb);
>> >  
>> >  struct sk_buff *napi_build_skb(void *data, unsigned int frag_size);
>> > +struct sk_buff *slab_build_skb(void *data);
>> >  
>> >  /**
>> >   * alloc_skb - allocate a network buffer
>> > diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
>> > index 13d578ce2a09..611b1f4082cf 100644
>> > --- a/net/bpf/test_run.c
>> > +++ b/net/bpf/test_run.c
>> > @@ -1130,7 +1130,7 @@ int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
>> >  	}
>> >  	sock_init_data(NULL, sk);
>> >  
>> > -	skb = build_skb(data, 0);
>> > +	skb = slab_build_skb(data);
>> >  	if (!skb) {
>> >  		kfree(data);
>> >  		kfree(ctx);
>> > diff --git a/net/core/skbuff.c b/net/core/skbuff.c
>> > index 1d9719e72f9d..ae5a6f7db37b 100644
>> > --- a/net/core/skbuff.c
>> > +++ b/net/core/skbuff.c
>> > @@ -269,12 +269,10 @@ static struct sk_buff *napi_skb_cache_get(void)
>> >  	return skb;
>> >  }
>> >  
>> > -/* Caller must provide SKB that is memset cleared */
>> > -static void __build_skb_around(struct sk_buff *skb, void *data,
>> > -			       unsigned int frag_size)
>> > +static inline void __finalize_skb_around(struct sk_buff *skb, void *data,
>> > +					 unsigned int size)
>> >  {
>> >  	struct skb_shared_info *shinfo;
>> > -	unsigned int size = frag_size ? : ksize(data);
>> >  
>> >  	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
>> >  
>> > @@ -296,15 +294,71 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
>> >  	skb_set_kcov_handle(skb, kcov_common_handle());
>> >  }
>> >  
>> > +static inline void *__slab_build_skb(struct sk_buff *skb, void *data,
>> > +				     unsigned int *size)
>> > +{
>> > +	void *resized;
>> > +
>> > +	/* Must find the allocation size (and grow it to match). */
>> > +	*size = ksize(data);
>> > +	/* krealloc() will immediately return "data" when
>> > +	 * "ksize(data)" is requested: it is the existing upper
>> > +	 * bounds. As a result, GFP_ATOMIC will be ignored. Note
>> > +	 * that this "new" pointer needs to be passed back to the
>> > +	 * caller for use so the __alloc_size hinting will be
>> > +	 * tracked correctly.
>> > +	 */
>> > +	resized = krealloc(data, *size, GFP_ATOMIC);
>> 
>> Hmm, I just realized, this trick will probably break the new kmalloc size
>> tracking from Feng Tang (CC'd)? We need to make krealloc() update the stored
>> size, right? And even worse if slab_debug redzoning is enabled and after
>> commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
>> kmalloc space than requested") where the lack of update will result in
>> redzone check failures.
> 
> I think it's still safe, as currently we skip the kmalloc redzone check
> by calling skip_orig_size_check() inside __ksize(). But as we have plan

Ah, right, I forgot. So that's good.

> to remove this skip_orig_size_check() after all ksize() usage has been
> sanitized, we need to cover this krealloc() case.

Yeah, can be done as part of the removal then, thanks.

> Thanks,
> Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/332c3841-54c2-4777-be90-32d7cef90668%40suse.cz.
