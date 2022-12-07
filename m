Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBCVVYGOAMGQE52N62RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A266645652
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Dec 2022 10:19:07 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id v14-20020adf8b4e000000b0024174021277sf4022273wra.13
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Dec 2022 01:19:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670404746; cv=pass;
        d=google.com; s=arc-20160816;
        b=kqPGzw7to0EGdD9yVmx6mmYxd9pS4io5FCjBI75EB/PVZc9GxBz22bSLHXmMV3VIsK
         d14Qnps6WVucXFpePanps/Gdatp0j+mlJoDz0nla+81J+QDHNkeyyDGRn7tgS5Bz2B8I
         8ykOT7d68Xv3xNavBHkncAIAdfA6zU/fIXJcxlAcjiCF/fo/HVA3tIgVQpc1GQWNsL+N
         527vxQLtjUQNg5pia2BfgcJ+QEnwQe1VDN7CPsVeph6xEalW2hkGyFSiDAAPashG2U23
         HHz+AnihkrJTWEvPG/NApPhi4E0yq4jX6RKPGFSdF6/4oOPK4Hm73BUiXjW/CvAeAj2d
         Vs7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=vlj6m6MjjeKn/O1Go+ghIeCXO9z++sSFM6eBUpP6gU4=;
        b=0T1AGSwpmASEtPwEeH7UPnyX5Jah3UtJ+/jFDT8M4c4vABtLJlkHHFcKu0bsvTeaN5
         zH9IIaikPQdez3AVcnnRTOjov+U0vjDLcAYuFG9yj3Orc5k6jk3F4O2gT2sDy0J9Tu0Y
         kmXY4QeL/2VLRgRnWdHncDHRgHabRXFhVMoDrI6zjpRiFQMV5DGx8mxXoG8dlZFbPxBD
         JbVpwp88Om3YQod7OtDirpUwr6MXZfx4iOXf0lkdqrW0dNZmbQEw0GzOnXuUnoqI61q/
         1b18pBnYmk65jfliz2Y/0cpwFMxX/xlm9z/KqxFcpoTeJR187i9K+3RK9zcQ7h2nc0SN
         D2IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0aPcXOex;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wXLCuKSs;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vlj6m6MjjeKn/O1Go+ghIeCXO9z++sSFM6eBUpP6gU4=;
        b=IcVR+lphGaJjVV2jimZeEo+W08LKJhEDJS1GLtK+jx8GjmTVF92PL/rGP9hJKqC53k
         NouLVLx+Fw2HPd22qv1i8Us3BdnIfAH4ioRmHparL7hZSWj5Z6L78wQnW/fQJAd8ADs+
         mym/OrLkvG5owatE0mm5l73uIwrdOZFgg170Y05w9Hn3cai23LHcHvTAdNaLCT10NciJ
         /PcMaB2W6mBlkXmUSNb5K7RA7hCmg2S/wW8qGNV7tZ0kmdkOXs5HprSDuZ1YUkIbv9ub
         zUy+kzculLtJHBOxABlkVQCNX4poIJHtsHCeG09EtLckpy6gZYtFobiqeZlEM4oP5VTo
         WYTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vlj6m6MjjeKn/O1Go+ghIeCXO9z++sSFM6eBUpP6gU4=;
        b=Dwh21+Gm7FufwsIcbzBOkq919B0wpfroWl6nUq+Xi/2KX3rJqmxGd1ccnh9YX4gl6s
         8u1VpAdEwqlVsIu8Drq7KlB/2qoi6HD1WcZ1pgv4N/0IwP3Dd4/KJtYgq6VV3RG7z+DU
         GMKiFO2l1VeEqhNY3XI0fK3CXNDVJdD8VY/u01+r7MIDnKj4bsFq/LO10Os3PbY2ZIks
         I/jypAO4sELZuejQRXfEY3rSDZl9BKtjQIQBdMObLFV+PUcF2DucRnNElqly7nM5dVLY
         iiNmFOwCjwPLEpGqYcc+KAp/rA6F+mtN5MMSllTyptskK+Ob8Gtx3RHnczB+RHAYmX6m
         YmWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plLUrVKZdRtC3ye+ohIEwh60g16kdm8ydVUTcaOl/Rj4u/oSc/s
	gm/AxYhg9pfyXzGjXqr+6yg=
X-Google-Smtp-Source: AA0mqf56AXVDLQ5OOO3yDf42euls3gi/Ng4f/+WATxrS3F/VYrBjImdOZSK3OWKAtsbxVzvc/l+Bwg==
X-Received: by 2002:a1c:6a04:0:b0:3cf:77cc:5f65 with SMTP id f4-20020a1c6a04000000b003cf77cc5f65mr59661978wmc.25.1670404746585;
        Wed, 07 Dec 2022 01:19:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3d1:be63:3b63 with SMTP id
 m23-20020a05600c3b1700b003d1be633b63ls2319002wms.1.-pod-canary-gmail; Wed, 07
 Dec 2022 01:19:05 -0800 (PST)
X-Received: by 2002:a05:600c:c3:b0:3c6:c0e7:88b9 with SMTP id u3-20020a05600c00c300b003c6c0e788b9mr64745083wmm.47.1670404745266;
        Wed, 07 Dec 2022 01:19:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670404745; cv=none;
        d=google.com; s=arc-20160816;
        b=baok9lA99Fd9R+pNHydCodiQmgy42BVHu+BUSXG5JRyu3ah/aAxVE6oHDCoN5AFS/X
         2VW10bS/xjGB8LzSPaW01Bw0TBUWQb6Gj2piRhXID1hqEIgfbFhqMzZw9O/h+YpG15we
         VsrZDQWfGAFSBPt51V/qtpihtTjp+lGoL7HvzSyi+2Kq6QPBYgUGJuO88CF03VDT0YV3
         t9GuqFqLGySxHf8R1hu8KigdtuouwoB3kzVQc8qGNmddntp2paf64BhnaA8X0l4AF7Qn
         JTkAjbNEmzKeQvV2gsaTWwSwHLVD7FarCmh3L4OGfG1um+JWJk8qOfxi3T3ine476p7g
         LKXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=ijRcVYqPEjBAfgioAlVUgPdPwzo/HNYZ8f5vv1ik9Sk=;
        b=fqj9/JBYLbLH/RHaRPJltxptkSYvhCEa53DvYmbfF6ianZ33yJQXMQA2fTXgoWezLT
         r4AT/VUM0iUZr56NTJrofNZJa/Hd8E/DP5my1P0ATHFk5EZUoVzOro9QDf+cUBkOKPPc
         52G54nZZevOpUbS3lXHfD8JjkoxCxjlNLlyJghD6gr9vJy/Ak0OkmDBzbui4rZyUzpzf
         FPxaHeuCH6Mqf/7jaFciXDhxsDmMY7Idp05l+u5diavlnyNAiCVra6CpskUb7bwErjFb
         teiWrYCppkmqCh3ozpCEaymzwUcgbzUzLydKBoZUckC6pLn2WqAJg59o1UjG07WSW3RP
         fWKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0aPcXOex;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wXLCuKSs;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id o16-20020a5d4090000000b00239778ccf84si847585wrp.2.2022.12.07.01.19.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Dec 2022 01:19:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap1.suse-dmz.suse.de (imap1.suse-dmz.suse.de [192.168.254.73])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D08EF1FDBC;
	Wed,  7 Dec 2022 09:19:04 +0000 (UTC)
Received: from imap1.suse-dmz.suse.de (imap1.suse-dmz.suse.de [192.168.254.73])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap1.suse-dmz.suse.de (Postfix) with ESMTPS id 63842136B4;
	Wed,  7 Dec 2022 09:19:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap1.suse-dmz.suse.de with ESMTPSA
	id EnylF4hakGOjZgAAGKfGzw
	(envelope-from <vbabka@suse.cz>); Wed, 07 Dec 2022 09:19:04 +0000
Message-ID: <ef7c0afb-cc93-e171-d439-bf2a7b960db4@suse.cz>
Date: Wed, 7 Dec 2022 10:19:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH] skbuff: Reallocate to ksize() in __build_skb_around()
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>, "David S. Miller" <davem@davemloft.net>
Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
 Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>,
 Paolo Abeni <pabeni@redhat.com>, Pavel Begunkov <asml.silence@gmail.com>,
 pepsipu <soopthegoop@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrii Nakryiko <andrii@kernel.org>, ast@kernel.org,
 bpf <bpf@vger.kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
 Hao Luo <haoluo@google.com>, Jesper Dangaard Brouer <hawk@kernel.org>,
 John Fastabend <john.fastabend@gmail.com>, jolsa@kernel.org,
 KP Singh <kpsingh@kernel.org>, martin.lau@linux.dev,
 Stanislav Fomichev <sdf@google.com>, song@kernel.org,
 Yonghong Song <yhs@fb.com>, netdev@vger.kernel.org,
 LKML <linux-kernel@vger.kernel.org>, Menglong Dong <imagedong@tencent.com>,
 David Ahern <dsahern@kernel.org>, Martin KaFai Lau <kafai@fb.com>,
 Luiz Augusto von Dentz <luiz.von.dentz@intel.com>,
 Richard Gobert <richardbgobert@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, David Rientjes
 <rientjes@google.com>, linux-hardening@vger.kernel.org
References: <20221206231659.never.929-kees@kernel.org>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221206231659.never.929-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0aPcXOex;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=wXLCuKSs;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/7/22 00:17, Kees Cook wrote:
> When build_skb() is passed a frag_size of 0, it means the buffer came
> from kmalloc. In these cases, ksize() is used to find its actual size,
> but since the allocation may not have been made to that size, actually
> perform the krealloc() call so that all the associated buffer size
> checking will be correctly notified. For example, syzkaller reported:
> 
>   BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
>   Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295
> 
> For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
> build_skb().

Weren't all such kmalloc() users converted to kmalloc_size_roundup() to
prevent this?

> Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
> Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
> Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Eric Dumazet <edumazet@google.com>
> Cc: Jakub Kicinski <kuba@kernel.org>
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
>  net/core/skbuff.c | 18 +++++++++++++++++-
>  1 file changed, 17 insertions(+), 1 deletion(-)
> 
> diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> index 1d9719e72f9d..b55d061ed8b4 100644
> --- a/net/core/skbuff.c
> +++ b/net/core/skbuff.c
> @@ -274,7 +274,23 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
>  			       unsigned int frag_size)
>  {
>  	struct skb_shared_info *shinfo;
> -	unsigned int size = frag_size ? : ksize(data);
> +	unsigned int size = frag_size;
> +
> +	/* When frag_size == 0, the buffer came from kmalloc, so we
> +	 * must find its true allocation size (and grow it to match).
> +	 */
> +	if (unlikely(size == 0)) {
> +		void *resized;
> +
> +		size = ksize(data);
> +		/* krealloc() will immediate return "data" when
> +		 * "ksize(data)" is requested: it is the existing upper
> +		 * bounds. As a result, GFP_ATOMIC will be ignored.
> +		 */
> +		resized = krealloc(data, size, GFP_ATOMIC);
> +		if (WARN_ON(resized != data))

WARN_ON_ONCE() could be sufficient as either this is impossible to hit by
definition, or something went very wrong (a patch screwed ksize/krealloc?)
and it can be hit many times?

> +			data = resized;

In that "impossible" case, this could also end up as NULL due to GFP_ATOMIC
allocation failure, but maybe it's really impractical to do anything about it...

> +	}
>  
>  	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ef7c0afb-cc93-e171-d439-bf2a7b960db4%40suse.cz.
