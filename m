Return-Path: <kasan-dev+bncBAABBREZYCOAMGQEZ4W5IFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 19AA86452A3
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Dec 2022 04:47:18 +0100 (CET)
Received: by mail-ua1-x93c.google.com with SMTP id h41-20020ab0136c000000b00419beaab4a3sf3370078uae.5
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Dec 2022 19:47:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670384836; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZoEHLDZUoCzH0Hvgf+bDN73T4TRvWasTT1Z//QcBbsXQj3PhyBYvpXYE5QT8KV4oJA
         IJ8aJfErARIDUVabuaskqB9ypCrrImM3MJ9PpFB43HC5DRwaiGPxhgcXQ6tGUQi2O4/C
         FWbl2Ie0yUBb5xmPy4rTnTGMhl/sv3uhTnZkPEwTNrAGfxIx/aih+Qgz5fNvyAuSNR8c
         v+FVDcT718PngzuE+9USHAIzzCJlhH9kBKvoUT7SeS1y9Z/+ky1tQHXS2DJquhhsdvVZ
         206kZI4lwmBj4+DzqsSdyJJAep0htqa4O638RnmuXfwGLDQICyJtNtJUXtJuQ00/JqLp
         Lr5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:references:in-reply-to:user-agent:subject
         :cc:to:from:date:sender:dkim-signature;
        bh=eEJ8h+B4SnK0gGVi9FNWA6q9XN7Ub9A7eHkeIcsPgkI=;
        b=nkV5SCvPsIUv5HxRsWZKPu/NkbdyFajNMU7idzLL5NuEL90PQ0r2MqBTTi0uW4kgOw
         zmcFI09EUAZ3X3h0+qZbSRKcgxKZeUUu4Lc5vDu7LxHWnINX8mmelLAg/zgHoQl9FEOQ
         MgbIz5yecpEMwtFpenlaLco4vs1bJQwasDLJNuEdb0HZQwG8bzp1D1ktUP0ITUD3pZz9
         RiMlqTJln4M1hk/V9yGYdmfKcTyjJ0qAyzT9c/kx1zynvjYj+GBe/FdIHOO6zU14+nSq
         ug9L0Tp0AYxmA1jkxR9KkU5Z5i6IpM92EI2UVeQEBlKF169oCYhes72cZQSiDaX82J5f
         HIGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q0fQujpV;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :references:in-reply-to:user-agent:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eEJ8h+B4SnK0gGVi9FNWA6q9XN7Ub9A7eHkeIcsPgkI=;
        b=Suqsy9P3Txv0TPyVo82DYVojdHE9AylvbqycTo12fLAvRhGFPJb75wZ/iKuPtB/pA1
         8NgwUbgBrUh+Qm3Qo5nWWKvUHrXkUFmA7VUoliO7gGnzfokVJ5y4xlURYyd31Na4bzTs
         64e95evZyAWSkuh9/to1Nt8ER1hPjI2qB/pxbtQ4dpEJf/idGvH5VrB4iyeDbbCBRvzI
         a317U9ykwwh0t2QXT5SRVosokHivz1tyr7ttx31lcyygpjBREdEujkMKuSiF3OwLOl2W
         /2FhgwLlneTWu4J0B/5RE40+BFhERjZX7RhC4e4afhWWcBozbvlz+n6CocQ4g6s5057E
         HISQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eEJ8h+B4SnK0gGVi9FNWA6q9XN7Ub9A7eHkeIcsPgkI=;
        b=ToKCp8uzXi4bck0sCDHqW7hItM9YrynFWQ+6lt2i+SJv4xOjcCP1No0d3QKGGZX3Tn
         27yNMS7/oLY5lVT+e4AH1B0Vk5MtsoAW8oHTGyJ1id2RpY43N/9EoKe3vwqoF5HqKc4U
         VByvff9olVKQDJds1LsX82tXxYX7YrAz40K4eKBZ7DHHwtQuwYLoGZzM6SxhljehLuLu
         YuqAonCDUqkiIVlLH1gzVdfEcvjapgsL8gvDl3jAPVtMFvSYgfUilU/qovJtxyooo20n
         zfkJyPG/5u/S4QvLMGPTxgpbnLu6IMhbWrQv+Y/YMdP8xrVGXROZ7oVx3zXdbU8ryvox
         BOFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmKHd6yzdNVPfOK8aBA1pQL3XVyE9duZmopVKmm1RdpLdb2yeUg
	UoF9/Ii0ab7eOfXwXSWxvnU=
X-Google-Smtp-Source: AA0mqf65/SjCAmkVkOhVUTLPVmPaxc45EhPPAb04e7V3wvPP0miMhbMw/rvMwOLBI2AnK1YYBsEQXQ==
X-Received: by 2002:a1f:e281:0:b0:3b8:26be:f5c0 with SMTP id z123-20020a1fe281000000b003b826bef5c0mr45868365vkg.17.1670384836622;
        Tue, 06 Dec 2022 19:47:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:24d2:0:b0:418:b95b:4c4d with SMTP id k18-20020ab024d2000000b00418b95b4c4dls67171uan.2.-pod-prod-gmail;
 Tue, 06 Dec 2022 19:47:15 -0800 (PST)
X-Received: by 2002:ab0:6512:0:b0:419:2056:34b8 with SMTP id w18-20020ab06512000000b00419205634b8mr26285249uam.85.1670384835831;
        Tue, 06 Dec 2022 19:47:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670384835; cv=none;
        d=google.com; s=arc-20160816;
        b=o7QCQGbt1XiFFJ82H842br0x4lgfzPZu/aa39TyKulr8j4OJqJeQtgpwTP9/Qx0YJc
         dZhq1ZHLBOFFgmQNny2uKTNJ0+tXM3xSPfw2FCsEogtfiTebu/byRQparYyjATE2SuFF
         isV1teUvs2FJ1lkFw66aVIZZwFHlUFxwZrqmdujJScLrkLW4Fw3squtMIdjfw9bUvjj9
         d0JYG1nM77QpHgxLWJqNVagrYC8/l90DvjY/XMD6hzjuUnNiNuspN2xYi+iisXQywKQX
         eVX+D7gUmfhzcI7r0tnWtHyeLJOdDb/6zLhLXPERLWK6hwVUhpQN2JOmDbJHM4bqnrWM
         mMrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=+Zg6g9s55PSkO/tLBQ1l15QHQg37doptvKA+8DzNXV8=;
        b=WT8a7YwczfBd1ag6DJ7Cwn46dhlQ0w3S4LeXl+m4lovOifHPeViJlbEfH42XTpF0ad
         T7KmwTooQycj/iId7o3osnpGvhiHmQUnXHtuuEGGtTl79mjnNeRwdfCwrH3GedgfJNWU
         yZkA6YJTWL+td0fHGJR6pdTwju0BxZ8rb5krDfaTB8tjAMo8vtFDWta5Uezi9EdAEVNl
         Vh8+6GF+LHxSYdr4vMIDtoC0BL30nnRtMj6rZSD7WwcJYzkIYcRFrccPcjJbMRqsZ9Cj
         aLgTJGMIyfTXc7gXPXXbiHajFEox0S+CdFU9cQvdH/WN1an14aXWVVpyU8xZTQtjnOEG
         CPjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q0fQujpV;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u7-20020ab03c47000000b004192f334e13si2256564uaw.2.2022.12.06.19.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Dec 2022 19:47:15 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6B19C619DD;
	Wed,  7 Dec 2022 03:47:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A349AC433C1;
	Wed,  7 Dec 2022 03:47:14 +0000 (UTC)
Date: Tue, 06 Dec 2022 19:47:13 -0800
From: Kees Cook <kees@kernel.org>
To: Jakub Kicinski <kuba@kernel.org>, Kees Cook <keescook@chromium.org>
CC: "David S. Miller" <davem@davemloft.net>,
 syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
 Eric Dumazet <edumazet@google.com>, Paolo Abeni <pabeni@redhat.com>,
 Pavel Begunkov <asml.silence@gmail.com>, pepsipu <soopthegoop@gmail.com>,
 Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>,
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
 Andrey Konovalov <andreyknvl@gmail.com>,
 David Rientjes <rientjes@google.com>, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] skbuff: Reallocate to ksize() in __build_skb_around()
User-Agent: K-9 Mail for Android
In-Reply-To: <20221206175557.1cbd3baa@kernel.org>
References: <20221206231659.never.929-kees@kernel.org> <20221206175557.1cbd3baa@kernel.org>
Message-ID: <67D5F9F1-3416-4E08-9D5A-369ED5B4EA95@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Q0fQujpV;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On December 6, 2022 5:55:57 PM PST, Jakub Kicinski <kuba@kernel.org> wrote:
>On Tue,  6 Dec 2022 15:17:14 -0800 Kees Cook wrote:
>> -	unsigned int size =3D frag_size ? : ksize(data);
>> +	unsigned int size =3D frag_size;
>> +
>> +	/* When frag_size =3D=3D 0, the buffer came from kmalloc, so we
>> +	 * must find its true allocation size (and grow it to match).
>> +	 */
>> +	if (unlikely(size =3D=3D 0)) {
>> +		void *resized;
>> +
>> +		size =3D ksize(data);
>> +		/* krealloc() will immediate return "data" when
>> +		 * "ksize(data)" is requested: it is the existing upper
>> +		 * bounds. As a result, GFP_ATOMIC will be ignored.
>> +		 */
>> +		resized =3D krealloc(data, size, GFP_ATOMIC);
>> +		if (WARN_ON(resized !=3D data))
>> +			data =3D resized;
>> +	}
>> =20
>
>Aammgh. build_skb(0) is plain silly, AFAIK. The performance hit of
>using kmalloc()'ed heads is large because GRO can't free the metadata.
>So we end up carrying per-MTU skbs across to the application and then
>freeing them one by one. With pages we just aggregate up to 64k of data
>in a single skb.

This isn't changed by this patch, though? The users of kmalloc+build_skb ar=
e pre-existing.

>I can only grep out 3 cases of build_skb(.. 0), could we instead
>convert them into a new build_skb_slab(), and handle all the silliness
>in such a new helper? That'd be a win both for the memory safety and one
>fewer branch for the fast path.

When I went through callers, it was many more than 3. Regardless, I don't s=
ee the point: my patch has no more branches than the original code (in fact=
, it may actually be faster because I made the initial assignment unconditi=
onal, and zero-test-after-assign is almost free, where as before it tested =
before the assign. And now it's marked as unlikely to keep it out-of-line.

>I think it's worth doing, so LMK if you're okay to do this extra work,
>otherwise I can help (unless e.g. Eric tells me I'm wrong..).

I had been changing callers to round up (e.g. bnx2), but it seemed like cen=
tralizing this makes more sense. I don't think a different helper will clea=
n this up.

-Kees


--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/67D5F9F1-3416-4E08-9D5A-369ED5B4EA95%40kernel.org.
