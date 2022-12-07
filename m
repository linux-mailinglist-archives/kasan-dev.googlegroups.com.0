Return-Path: <kasan-dev+bncBDBZNDGJ54FBBMPFX6OAMGQEMDL37AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 93B01645198
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Dec 2022 02:56:03 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id z1-20020a17090a66c100b002196a0895a6sf100469pjl.5
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Dec 2022 17:56:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670378162; cv=pass;
        d=google.com; s=arc-20160816;
        b=MmTeXlpYyeC4zpRnvPOJ7MB8yc/wpL2ED7+xWvpzKIyxD+SKQbnh0nGRm+VEr/8Faf
         PIwnxE4LGXdMtkCDlDym/NdVr+vzlaK7M8X/tOPcRUl95SLgNZGPFTr70UM768tmgGV0
         sb4igT83x1+u7Ngb4vmJaVd+DbjtXATRosN/eIQpIaiXlKpt/6omI//fyviREsXDC8RX
         dGmAN9XwQFQTnyVota38Zbl0IHG4hf18FEG0mrZwpKcbWvE0NWyi/ZGD7tsjFPQUtQpw
         MV5cOLJvwcPrXSB14A688aYXCUxNIxpLxD8J3dHAsG20IjrkMxidQRqQD69eMaNBzRrv
         zjQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BsAZqsRpp6AvILnwthptKH0/zYpczQINVEuSKnoWiLA=;
        b=nhct7wqiUj8p5tmggCRPWCf1x1iKeXDHjePSuaXEg/zWRl+0m3hf2guoR7MnQHUUC7
         mIJ4txXAIWEHamahg5LHIWdws2BQ+ACwWI+bfFSg5brbu88treEzkdp1Ehsjt5le9egR
         4XwaajXDa5SBIdlRqikUNyoGai6/R2gBVIWpTCKwZOmo/c68maWJd4X3OoVicWT/w3Gi
         fxJHJfddNYj+Ft2yYz8Iq2DAm6garHmCmowO0lWk6J7HxrrIvQD+az7L1+hE1n/dDFCj
         Nfbtsa2QhSCQAR5S8imjmYSiZqo5PYjFL1t3SG+4bWjbxJtHkXIbt92Ct6wbVG99QqKl
         OM9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=skStzngA;
       spf=pass (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BsAZqsRpp6AvILnwthptKH0/zYpczQINVEuSKnoWiLA=;
        b=r2HYJEPtUpIDtti2yIHBjkdjMe9rMuVa87CkWA17meohp+fNCCifSrbvdpBWj/xHgk
         lmD/KxHlo+huIF57+0usR5XCrAqYmAOH4LeK7c00IWTdUgqmIhzV3tIGCgLlnrO3dz80
         bzqlU5A+I03Vuq9MEjvBWqI+mgeOU4kDtCatqF/HAADYBkhMfWn6K0JwgLTmjeg5lS71
         qBoRLSJpxQw3+T3tqNF7O3IVwxuLCRzFTZ7TVh7FVqfwq4UObwkdpJurX9LtQujIT8P8
         M6TaUk1+nd3v6lwMAmsmTN0OLH2hhSV0nfEiMwNe6v4JJ+JGmkNcdTuaOTZLk/EhLU1J
         oXFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BsAZqsRpp6AvILnwthptKH0/zYpczQINVEuSKnoWiLA=;
        b=rmzNK9NCB09Yg4WFHX0MmEwhAp+fq+OkqyQn5FP6x5iK/YTn6urrPDwPk00ppo0acW
         07oGKNv+40OJRFiA+GvI8SzQ1kHnIk3vyTvy7OGg9jnm7SmABg72idNiIXXLrYlE4Uz/
         78Vhdh0XfKuxLWkD9EQb7LHkmjl1apeYMkFZxiEfJng1E8jk/FaNPmLyaG0t/KfvBlKA
         DtqoBH52ReNgrHGFzeZAPNiH16VY+pUla2InxepHWGLo9KEAW42GPSEsxgyHClNyPvW8
         gBVAVZlTfvcMCqQ6xSZfppu+Z0GgyA2N+a8RykSsXOP/rdgaxQLBwcU+ead32dLIdsdq
         Ab5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pl/ZCAoXnbfXfo3rnNBvUmL2wFjekbAKVePo5TGmXOLhWxJoTfX
	CGMemr/IGiFRdPZj3v6zPvk=
X-Google-Smtp-Source: AA0mqf6PbP8qlGfpV3ZX6UaJ3wm5QKY1d+p+9YkKTyAdvbdsVSQHcKvSIhnEm7qBIlO5Pg1ajI9LhA==
X-Received: by 2002:a17:90a:a903:b0:219:4976:4a18 with SMTP id i3-20020a17090aa90300b0021949764a18mr43370380pjq.151.1670378161908;
        Tue, 06 Dec 2022 17:56:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8808:0:b0:56b:ff73:9863 with SMTP id c8-20020aa78808000000b0056bff739863ls530575pfo.5.-pod-prod-gmail;
 Tue, 06 Dec 2022 17:56:00 -0800 (PST)
X-Received: by 2002:a62:65c3:0:b0:562:ce80:1417 with SMTP id z186-20020a6265c3000000b00562ce801417mr71752829pfb.19.1670378160552;
        Tue, 06 Dec 2022 17:56:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670378160; cv=none;
        d=google.com; s=arc-20160816;
        b=bTIZZ5dG6cQi970keVnU3t0sBlmC3zcjtJ2IntCBdPQ45N/A7o1QodcZTjUknjSu5S
         nRK4R4MYR3aWhbIwKDPVbLuPUDSf2+AnQ7bTdIVrrhXCgthWUj6Mx3zjd2X6PrTmPHvI
         0nKNtN/hiqe13Gnkeud9ApYDQmms6Kv/CLQwE7xKtx2row53S7VJeg9AjdBpc77TgQp5
         XT2R+lZgunvlNOuLhcd/FeeIHm2yVek5orYGyE0h9iPjHy8JGlhcV472+Vx+mubHgE+h
         mW+dc3vlTbxRQgnXDahq6L0o7NRB2I6n9K4W+fXYqCVQd166lJga6fi1RtmJ5dQVA148
         IF3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6ss3NotY+O/dAGanZHAjy148q9mDzs0P4RzMe/ro2ho=;
        b=MyRXQPTOgtYVtfJZLBblfdTDckDdVk/vyEw1ZT6b66iMCKjRqHrPKepWxKf4RRtW3S
         hg4XJtUCt8log/UiEbsdU5zjrgTcsVJGZIocn5BAw33zmAaPjdmQ49pmdB90VAoswgEO
         h1Gahijt3JR+hb8Q2BXVQNLkG4LFkQ/ur0OJqJvewICnaSL4F9+agUCWNKBHsh+Ln/DQ
         AmaIGVCM24tloYTvVRRpkfZPnXGposDR+wnz/1Mhuxxw83tkEl3LCKAzVK/3TRvffev3
         PqFdZAFgJuxFwmxVnxTZSw/lKgc77WZabDW6pSszCAPOnzwurvEoxj8jLrQ6Mpo/y7mW
         kP/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=skStzngA;
       spf=pass (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c5-20020a170902d48500b00186b3b9870fsi1277996plg.11.2022.12.06.17.56.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Dec 2022 17:56:00 -0800 (PST)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EA83C61158;
	Wed,  7 Dec 2022 01:55:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 57939C433D6;
	Wed,  7 Dec 2022 01:55:58 +0000 (UTC)
Date: Tue, 6 Dec 2022 17:55:57 -0800
From: Jakub Kicinski <kuba@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com, Eric Dumazet
 <edumazet@google.com>, Paolo Abeni <pabeni@redhat.com>, Pavel Begunkov
 <asml.silence@gmail.com>, pepsipu <soopthegoop@gmail.com>, Vlastimil Babka
 <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, Andrii Nakryiko
 <andrii@kernel.org>, ast@kernel.org, bpf <bpf@vger.kernel.org>, Daniel
 Borkmann <daniel@iogearbox.net>, Hao Luo <haoluo@google.com>, Jesper
 Dangaard Brouer <hawk@kernel.org>, John Fastabend
 <john.fastabend@gmail.com>, jolsa@kernel.org, KP Singh
 <kpsingh@kernel.org>, martin.lau@linux.dev, Stanislav Fomichev
 <sdf@google.com>, song@kernel.org, Yonghong Song <yhs@fb.com>,
 netdev@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>, Menglong Dong
 <imagedong@tencent.com>, David Ahern <dsahern@kernel.org>, Martin KaFai Lau
 <kafai@fb.com>, Luiz Augusto von Dentz <luiz.von.dentz@intel.com>, Richard
 Gobert <richardbgobert@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 David Rientjes <rientjes@google.com>, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] skbuff: Reallocate to ksize() in __build_skb_around()
Message-ID: <20221206175557.1cbd3baa@kernel.org>
In-Reply-To: <20221206231659.never.929-kees@kernel.org>
References: <20221206231659.never.929-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=skStzngA;       spf=pass
 (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Tue,  6 Dec 2022 15:17:14 -0800 Kees Cook wrote:
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
> +			data = resized;
> +	}
>  

Aammgh. build_skb(0) is plain silly, AFAIK. The performance hit of
using kmalloc()'ed heads is large because GRO can't free the metadata.
So we end up carrying per-MTU skbs across to the application and then
freeing them one by one. With pages we just aggregate up to 64k of data
in a single skb.

I can only grep out 3 cases of build_skb(.. 0), could we instead
convert them into a new build_skb_slab(), and handle all the silliness
in such a new helper? That'd be a win both for the memory safety and one
fewer branch for the fast path.

I think it's worth doing, so LMK if you're okay to do this extra work,
otherwise I can help (unless e.g. Eric tells me I'm wrong..).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221206175557.1cbd3baa%40kernel.org.
