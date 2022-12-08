Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBN5ZY2OAMGQECS6ORLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id D15CC646A32
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Dec 2022 09:13:44 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id j11-20020aa7c40b000000b0046b45e2ff83sf559059edq.12
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Dec 2022 00:13:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670487224; cv=pass;
        d=google.com; s=arc-20160816;
        b=N6QanQ29X7Ey0wyXd6gMgaIshhMvZpg8sHgr0VKHYTnF/BnPx5SQIO4sBxtJCtkAGY
         9MfS6IMA6hAPoOQpQ9CMzrwc0ublb+ohmFD/V5LgQXrh6nggmxj4Qc0NjMtWQaWjek17
         pWzevVx2amMECkD3rDwv6MIWXOcMgK4C6hbawJSrHUVZ3usqNebhIMtSCIqJew3W7yBO
         BxNHmZ87emJ0p6O1kvlJnZlfayvgLtHWLNvaOEofi4gxqtn0q46iGPf1Zvq9sxyW53Mi
         Rozpooo10RiTDXpkjLlxxO62/Q8RfSzTRhvYCL5X+3dUPZLMBmCkw9Gx6gYCyEuV6DcP
         N/UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6QoJ3XGBcndhiFMMRlTwtIqwnitgx/fk7yzncW2ZMKw=;
        b=qbFDyUf3LLMUOlksFCfShhABcwbd7orfclDLCTRVdM/yYL75ahqQmvgnx4tntXIFrO
         O+a8sAZ844Ft3HNyr1guXmlAqpW7C3mXot3SEz/MYt3BXG66f9IrR+hLkANIopEZAin7
         NYZhB5cyE5E7e/37l19TDqpCJTF43LSJMq7z1LkRzMfqcvOzZQ/TTkJznLy9gZPJwoAC
         +MvLacSziDY5govS8N+6+5s8uGnTHwzzRVb0C8gxBQ4bkCRF1IJICuH5zein7O6ZT8eg
         yHqWEYPHrYx5kVThItvjZ9JC5q2ZmoBWhNYjMhMIHRuth9op8lp1ePac4a3sB4OUnYkZ
         SmRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bUmI0w3L;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6QoJ3XGBcndhiFMMRlTwtIqwnitgx/fk7yzncW2ZMKw=;
        b=Mi1oJsHXbnqWTPduAgxsMCavY7XV8eNgFBMT1cHBqbJy9KKFN3eycptp2PzVtuCZUU
         h1dyeOs0U76T1h2QkXqBcu7TAsTlihzdLWVReM+L7eaHjzH+rCyoZRUTRnWPs+blWmhP
         aaDf02hocBjLCSeRI1tpKuluGuRK0WiwAxAta2TubmVZlBpAqAU+jnhYng1+M26eiRUb
         Y2ILYjmDY4V1aN26f0JPEciHM7+FBCyM5vxPBtkz2W96Dfe2l1eON8fWQSlpI8I7J0cb
         MwdGVW0CMeG2ywIjs9hUEzmc4p5Q6lscyG2oxYaBseUAsvGvMzOHdEyE5i3e1f+wY9PZ
         TnWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6QoJ3XGBcndhiFMMRlTwtIqwnitgx/fk7yzncW2ZMKw=;
        b=HJHbf00M2lHkYqz6sbxpiE84fUc2dPCijOPdm1axhctnN8hekb4kxN/uwC9iQ9pHXZ
         Cl3+p0x5/doNIYRwwSKuxStE//H7CpulPE6fMis9LGy/SI9ktOJQmz30YX8vQF3vi9ZX
         /mkj5RmTwfOj12LvNxbKHEg8jYV3/A7Dmer4G5QSpTRhiog62CeDLwBAJUbNwpXhsdlj
         2TLw2ek1ZTZiuzbYbzlCneieOmnXKhDt2wI4vK2HspK13iyiRf44KaPlzNt06LtEpSq8
         mgEmFY5A3TKlzTJiAn3hXEIHxM3XuREOuGrRPTg7S87T8VHbc4QKVo3IeRjIrlPZsO4t
         X8iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plTjxoE48Nl+zYRrOTIIFH5TS/5FZ8zZmJoaPID60OjE7p/koXs
	iV2BhlxZeEO1Ef8OaRgFpW8=
X-Google-Smtp-Source: AA0mqf7oVdC1/R6cQTPGJeLFUPnwUl+akHzJA3jXzNq+vEcvlYpbuC3UgLDwt58VhhIoVHGnac4iDg==
X-Received: by 2002:a17:907:8dcc:b0:7b2:b5aa:f1e0 with SMTP id tg12-20020a1709078dcc00b007b2b5aaf1e0mr17396549ejc.54.1670487224213;
        Thu, 08 Dec 2022 00:13:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5215:b0:43d:b3c4:cd21 with SMTP id
 s21-20020a056402521500b0043db3c4cd21ls330429edd.2.-pod-prod-gmail; Thu, 08
 Dec 2022 00:13:42 -0800 (PST)
X-Received: by 2002:a05:6402:d74:b0:46d:1a33:2197 with SMTP id ec52-20020a0564020d7400b0046d1a332197mr7988415edb.282.1670487222794;
        Thu, 08 Dec 2022 00:13:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670487222; cv=none;
        d=google.com; s=arc-20160816;
        b=md8brFrWQSDmIYC941GbOUwyLtiYVtFGKo58XPII4LrdKjhbbsuJHi7rpiKMIWEbJu
         a1Yzk8onBVA8qmiS+/7jR67I21/8gxoM6lcJvAf/5lBthDLGtDGda/+KFHleamoLe60E
         k1LaaG8dOQWOa1Lo4UaULx6kFFg99rl2TYG4emFrkSG4V7IvN8QVKE0EsUcxkBJv7tcW
         o6nlYzNxyGaDsrr8ahfp9fEg1c2SlvgYHaZYNegC1+cTZDmoJVn9Pj+03SitSKwzEg/4
         WUDJUdZ9v4xlv+SjCv7fcTp3osJXYZnfHq2yGZb7wS9OGeM6A6FU5h1Kx7SaJ4zZqyYa
         Z74g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=jL4y5FJYbDHm9XGKTrDmZ6J5zAhRaZRJLpsFAXD4/0o=;
        b=StzPYPzVPw8KKLVhGNswC4/RS5Z2JxccRBXKb0Y5xz3yMBVrhS7YdGz4azBDfWecJS
         bwCRmHDnuhtL7d6NdODgbKRCqnfF8oBgZZcTWzyKhGjkvhSGGkZEm2eYLN1c7zJ+3RZa
         2gdUF/WZvfA1QnXfUcDDiv+FIKPxTcLWXy2n86OmaEEqnAdP267owyvm/IvBPyv0cljK
         f2RkUPBAamkdUhcnX4DFoQOR17FB74OMOHEW0wfRKo9mKu0WxaBhk8Vj2X4noU4Oti6M
         qzNNT2HdZsVyN2lSqKdGBYaskVHxRAKw15WMDAHaOITVz3m8T8oH2ITVQCLG6nLJQ51r
         0EYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bUmI0w3L;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id s15-20020a056402014f00b0046920d68fe2si366124edu.4.2022.12.08.00.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Dec 2022 00:13:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 5971A33697;
	Thu,  8 Dec 2022 08:13:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D55BD138E0;
	Thu,  8 Dec 2022 08:13:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id NGJkM7WckWPMHQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 08 Dec 2022 08:13:41 +0000
Message-ID: <6923d6a9-7728-fc71-f963-3617e5361732@suse.cz>
Date: Thu, 8 Dec 2022 09:13:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH net-next v3] skbuff: Introduce slab_build_skb()
To: Kees Cook <keescook@chromium.org>, Jakub Kicinski <kuba@kernel.org>
Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
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
 linux-hardening@vger.kernel.org, Feng Tang <feng.tang@intel.com>
References: <20221208060256.give.994-kees@kernel.org>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221208060256.give.994-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=bUmI0w3L;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/8/22 07:02, Kees Cook wrote:
> syzkaller reported:
> 
>   BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
>   Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295
> 
> For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
> build_skb().
> 
> When build_skb() is passed a frag_size of 0, it means the buffer came
> from kmalloc. In these cases, ksize() is used to find its actual size,
> but since the allocation may not have been made to that size, actually
> perform the krealloc() call so that all the associated buffer size
> checking will be correctly notified (and use the "new" pointer so that
> compiler hinting works correctly). Split this logic out into a new
> interface, slab_build_skb(), but leave the original 0 checking for now
> to catch any stragglers.
> 
> Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
> Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
> Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
> Cc: Jakub Kicinski <kuba@kernel.org>
> Cc: Eric Dumazet <edumazet@google.com>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Paolo Abeni <pabeni@redhat.com>
> Cc: Pavel Begunkov <asml.silence@gmail.com>
> Cc: pepsipu <soopthegoop@gmail.com>
> Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
> Cc: Vlastimil Babka <vbabka@suse.cz>
> Cc: kasan-dev <kasan-dev@googlegroups.com>
> Cc: Andrii Nakryiko <andrii@kernel.org>
> Cc: ast@kernel.org
> Cc: bpf <bpf@vger.kernel.org>
> Cc: Daniel Borkmann <daniel@iogearbox.net>
> Cc: Hao Luo <haoluo@google.com>
> Cc: Jesper Dangaard Brouer <hawk@kernel.org>
> Cc: John Fastabend <john.fastabend@gmail.com>
> Cc: jolsa@kernel.org
> Cc: KP Singh <kpsingh@kernel.org>
> Cc: martin.lau@linux.dev
> Cc: Stanislav Fomichev <sdf@google.com>
> Cc: song@kernel.org
> Cc: Yonghong Song <yhs@fb.com>
> Cc: netdev@vger.kernel.org
> Cc: LKML <linux-kernel@vger.kernel.org>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
> v3:
> - make sure "resized" is passed back so compiler hints survive
> - update kerndoc (kuba)
> v2: https://lore.kernel.org/lkml/20221208000209.gonna.368-kees@kernel.org
> v1: https://lore.kernel.org/netdev/20221206231659.never.929-kees@kernel.org/
> ---
>  drivers/net/ethernet/broadcom/bnx2.c      |  2 +-
>  drivers/net/ethernet/qlogic/qed/qed_ll2.c |  2 +-
>  include/linux/skbuff.h                    |  1 +
>  net/bpf/test_run.c                        |  2 +-
>  net/core/skbuff.c                         | 70 ++++++++++++++++++++---
>  5 files changed, 66 insertions(+), 11 deletions(-)
> 
> diff --git a/drivers/net/ethernet/broadcom/bnx2.c b/drivers/net/ethernet/broadcom/bnx2.c
> index fec57f1982c8..b2230a4a2086 100644
> --- a/drivers/net/ethernet/broadcom/bnx2.c
> +++ b/drivers/net/ethernet/broadcom/bnx2.c
> @@ -3045,7 +3045,7 @@ bnx2_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u8 *data,
>  
>  	dma_unmap_single(&bp->pdev->dev, dma_addr, bp->rx_buf_use_size,
>  			 DMA_FROM_DEVICE);
> -	skb = build_skb(data, 0);
> +	skb = slab_build_skb(data);
>  	if (!skb) {
>  		kfree(data);
>  		goto error;
> diff --git a/drivers/net/ethernet/qlogic/qed/qed_ll2.c b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
> index ed274f033626..e5116a86cfbc 100644
> --- a/drivers/net/ethernet/qlogic/qed/qed_ll2.c
> +++ b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
> @@ -200,7 +200,7 @@ static void qed_ll2b_complete_rx_packet(void *cxt,
>  	dma_unmap_single(&cdev->pdev->dev, buffer->phys_addr,
>  			 cdev->ll2->rx_size, DMA_FROM_DEVICE);
>  
> -	skb = build_skb(buffer->data, 0);
> +	skb = slab_build_skb(buffer->data);
>  	if (!skb) {
>  		DP_INFO(cdev, "Failed to build SKB\n");
>  		kfree(buffer->data);
> diff --git a/include/linux/skbuff.h b/include/linux/skbuff.h
> index 7be5bb4c94b6..0b391b635430 100644
> --- a/include/linux/skbuff.h
> +++ b/include/linux/skbuff.h
> @@ -1253,6 +1253,7 @@ struct sk_buff *build_skb_around(struct sk_buff *skb,
>  void skb_attempt_defer_free(struct sk_buff *skb);
>  
>  struct sk_buff *napi_build_skb(void *data, unsigned int frag_size);
> +struct sk_buff *slab_build_skb(void *data);
>  
>  /**
>   * alloc_skb - allocate a network buffer
> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
> index 13d578ce2a09..611b1f4082cf 100644
> --- a/net/bpf/test_run.c
> +++ b/net/bpf/test_run.c
> @@ -1130,7 +1130,7 @@ int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
>  	}
>  	sock_init_data(NULL, sk);
>  
> -	skb = build_skb(data, 0);
> +	skb = slab_build_skb(data);
>  	if (!skb) {
>  		kfree(data);
>  		kfree(ctx);
> diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> index 1d9719e72f9d..ae5a6f7db37b 100644
> --- a/net/core/skbuff.c
> +++ b/net/core/skbuff.c
> @@ -269,12 +269,10 @@ static struct sk_buff *napi_skb_cache_get(void)
>  	return skb;
>  }
>  
> -/* Caller must provide SKB that is memset cleared */
> -static void __build_skb_around(struct sk_buff *skb, void *data,
> -			       unsigned int frag_size)
> +static inline void __finalize_skb_around(struct sk_buff *skb, void *data,
> +					 unsigned int size)
>  {
>  	struct skb_shared_info *shinfo;
> -	unsigned int size = frag_size ? : ksize(data);
>  
>  	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
>  
> @@ -296,15 +294,71 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
>  	skb_set_kcov_handle(skb, kcov_common_handle());
>  }
>  
> +static inline void *__slab_build_skb(struct sk_buff *skb, void *data,
> +				     unsigned int *size)
> +{
> +	void *resized;
> +
> +	/* Must find the allocation size (and grow it to match). */
> +	*size = ksize(data);
> +	/* krealloc() will immediately return "data" when
> +	 * "ksize(data)" is requested: it is the existing upper
> +	 * bounds. As a result, GFP_ATOMIC will be ignored. Note
> +	 * that this "new" pointer needs to be passed back to the
> +	 * caller for use so the __alloc_size hinting will be
> +	 * tracked correctly.
> +	 */
> +	resized = krealloc(data, *size, GFP_ATOMIC);

Hmm, I just realized, this trick will probably break the new kmalloc size
tracking from Feng Tang (CC'd)? We need to make krealloc() update the stored
size, right? And even worse if slab_debug redzoning is enabled and after
commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
kmalloc space than requested") where the lack of update will result in
redzone check failures.

> +	WARN_ON_ONCE(resized != data);
> +	return resized;
> +}
> +
> +/* build_skb() variant which can operate on slab buffers.
> + * Note that this should be used sparingly as slab buffers
> + * cannot be combined efficiently by GRO!
> + */
> +struct sk_buff *slab_build_skb(void *data)
> +{
> +	struct sk_buff *skb;
> +	unsigned int size;
> +
> +	skb = kmem_cache_alloc(skbuff_head_cache, GFP_ATOMIC);
> +	if (unlikely(!skb))
> +		return NULL;
> +
> +	memset(skb, 0, offsetof(struct sk_buff, tail));
> +	data = __slab_build_skb(skb, data, &size);
> +	__finalize_skb_around(skb, data, size);
> +
> +	return skb;
> +}
> +EXPORT_SYMBOL(slab_build_skb);
> +
> +/* Caller must provide SKB that is memset cleared */
> +static void __build_skb_around(struct sk_buff *skb, void *data,
> +			       unsigned int frag_size)
> +{
> +	unsigned int size = frag_size;
> +
> +	/* frag_size == 0 is considered deprecated now. Callers
> +	 * using slab buffer should use slab_build_skb() instead.
> +	 */
> +	if (WARN_ONCE(size == 0, "Use slab_build_skb() instead"))
> +		data = __slab_build_skb(skb, data, &size);
> +	__finalize_skb_around(skb, data, size);
> +}
> +
>  /**
>   * __build_skb - build a network buffer
>   * @data: data buffer provided by caller
> - * @frag_size: size of data, or 0 if head was kmalloced
> + * @frag_size: size of data (must not be 0)
>   *
>   * Allocate a new &sk_buff. Caller provides space holding head and
> - * skb_shared_info. @data must have been allocated by kmalloc() only if
> - * @frag_size is 0, otherwise data should come from the page allocator
> - *  or vmalloc()
> + * skb_shared_info. @data must have been allocated from the page
> + * allocator or vmalloc(). (A @frag_size of 0 to indicate a kmalloc()
> + * allocation is deprecated, and callers should use slab_build_skb()
> + * instead.)
>   * The return is the new skb buffer.
>   * On a failure the return is %NULL, and @data is not freed.
>   * Notes :

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6923d6a9-7728-fc71-f963-3617e5361732%40suse.cz.
