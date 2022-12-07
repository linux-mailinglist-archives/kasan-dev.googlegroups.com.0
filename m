Return-Path: <kasan-dev+bncBDBZNDGJ54FBBQ5BYCOAMGQEEAKJCNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 302506452D4
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Dec 2022 05:04:20 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id v125-20020a1cac83000000b003cfa148576dsf9391455wme.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Dec 2022 20:04:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670385859; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2Co2OsifSSbtyN9ApHLskkpqLUpPq0ViWlpZTUH3aonEe+49gXzOo0UkI/2j3KH2J
         uRs91kY8DUB5s6bx8d43i/8FSHQWp5OBqzXRznuc9ezmIRg3JwRueth2X8w28HTr6CMA
         lA5JLuDKRa+MRnw1WVA/xvXFVmCwZW8naWzU+Yh3OKeRB3OPpsab05qkkG5iCOWaXi7K
         7fVCyvEtCobq91StCICSm2ruTEYsm290h2SQnQ8hi8GdKkWXGZcStaKyaGmN6N/HHGjc
         zsrhCclZGNShOImGrtgv1R5S44fGzs3r2V0LrKgv/VrXsRNz5wq68x6nlQ4W8BYwmnlG
         Kniw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qWfKfcDYIuAo5dOKPZESrhM57FS8hmfBMSWR3++/5Qk=;
        b=Gq7iLaDh7CQtywrtcCS71E5aPrW1Imp46OXLvSE+koLTxg+HVob26z69YjBWc3280K
         87mFayUC1uUBLIL9pOw2jwRniHxVak0LW0ymI7yq74rr/IZHYdLvdtHJ28tS950Ddtkn
         IUueo4UExddHRynrsN8/45CPPZ86sMEB/Dc25sN8F15ooP0WVEsdbslGWYJaW3SdP6+6
         vS7Xh/wMkAHWLE586x5MhSm1V0JvREzi/Amn99HjdvLanEGZGa3DnLJq0uBjsd4Z6Edx
         qxCGod5RGcFaqzzJXxw4EEacjIX2gj1XIqXHJCrTpnkcm86jskT0yPEXajBdlPUNTNYA
         ZFvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tGd2X79t;
       spf=pass (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qWfKfcDYIuAo5dOKPZESrhM57FS8hmfBMSWR3++/5Qk=;
        b=TJMjgAmfOnh/JjCDLj5Ltih2Uwdp6iemd9SbPfbspbQFGIk7EOp408+9IFhsnRxOSz
         Fob7I6TIHR5HlYzg78SisH2QsMSRLDsdk2zw0hgmw1ribOfg0Ty5XQuw0gfaJnWDCgQX
         EjMzjfNRAVTU+RmG+i2cIYd5D3r6vFKhNKmlEwykh74VzxSfjznge3e8GHyrk6zYfJZ+
         37g3hipDdtpaNCkP+lceHXU3fDEK7ekcKF9S+iMzslUL/aLrA+YiXp2oczYmi01BS3hb
         t6nXZilSiSi0kwz9bduRjnQ+azpjPJ/I/fSEuKtmg/288H581TdffUIYAf3QUViVBRvU
         ysjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qWfKfcDYIuAo5dOKPZESrhM57FS8hmfBMSWR3++/5Qk=;
        b=0P1xwaevY4lhODQgzfNLmy0uLHbZ+qBusDEFb8H8P/VyG3GiqesFNYMOJAG+My17UJ
         tCjEfyfzgu9B3Euo8g/UDFzr35uK4EQOC3WbEgUO4qOEekVLrVP8atyJ560MjDMaOu+h
         KpvCcsMXz9EEnOe+RKoGfVVfMqvbIUEFAp2+YcR5Gzwtlxc66RvoalPUwC0enTmzt4Vf
         uaP/EMT9inyOJtGxc9BXnPLacBkdvrMkR6Ql/AEdcPPWqP5ynOgWDyIiafG9LAzNRlj2
         xp2lXXLXxYmyuu/1tEtyJJc+Cd6QvEb7WBdtz1dvPhSRKwbq0tIRI42lv4IJt1+OePk7
         UDNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmxDxjPcWDLO8UBzT7HF0Z+iiKL5I49GIleLYxlmFMR2qMWSC4X
	iDqJl7oIJq1ic8ideNXtqqg=
X-Google-Smtp-Source: AA0mqf6DKpNzOdwhLCrkf86lg98pwa3WMiFoolBZ79AWYjCZwZOwBF2/uIPOrZVow9Qjai6H+fC8Mg==
X-Received: by 2002:a1c:a381:0:b0:3cf:4d14:5705 with SMTP id m123-20020a1ca381000000b003cf4d145705mr53328836wme.35.1670385859572;
        Tue, 06 Dec 2022 20:04:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:218b:b0:3cf:afd2:ab84 with SMTP id
 e11-20020a05600c218b00b003cfafd2ab84ls664212wme.2.-pod-control-gmail; Tue, 06
 Dec 2022 20:04:18 -0800 (PST)
X-Received: by 2002:a1c:4b05:0:b0:3d0:8819:a815 with SMTP id y5-20020a1c4b05000000b003d08819a815mr14301256wma.90.1670385858270;
        Tue, 06 Dec 2022 20:04:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670385858; cv=none;
        d=google.com; s=arc-20160816;
        b=vmnKG1AMnDA0gSdxw4fPENBlPIQu4M4vHfkQ7k4ORzhMAgy21uRUXeVPR4LgnhRJb0
         dLFlJKvdyLjqU9itpd3nsgnhukjGMldtAFTskW/lW3jp1W4NWq8l9RVyTf5De1ic/87F
         muvI78WOWZG2MohY82MheHPXPrnn+jIZhShdcwWynezaMXXZ7N3D05moWvMYfO8cT1dx
         MgSRCd8LnvoWlDo1g2uXTKayXO3WGYMwLhNO/L4PYlge8nJRBVINaOQrdnF+O01EVeOS
         cDlPLebAZG3miAm3iqG8KAgd4XSGim8Ngo4x9NKXY7R7GdnsOzU4hXkbyXWW//9nsYaB
         41kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZbnPAfkHUkw83rIV2VpmVUObG5YQxq1j1iqXoF1Seew=;
        b=eYIK1v0EFp3eJN7UxebanO02Q0eIsFu/IOGZa9FnMFrNCEny2EC7vjmof79vXRFcNa
         8/5NLu8WzVyMn6I2dJ8wd2APfjcz0su2aMaR1NfFW4ey1OANSEYnhRqE7+DuH+FWIkqM
         RAtd30hW93i+7o8bCa9OZw0vpD+FLxpkW9ij08yoXeophvXYvQvosavlHy0iXB0CE2Rw
         zjzuEYg/J0MuUSYtG/Iz4LMfXT2IVOkm9+jQd+Ct9Upkw++rkVNFvz3qf+IcAHZJsTRS
         E5XqJsC0SJ45L/XRjrNzvXI3H31Mf54pfhjgzwUkKOoq++ar8CgGQBUOStw3ZM8+YllR
         I3pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tGd2X79t;
       spf=pass (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id c4-20020a7bc004000000b003cf1536d24dsi19234wmb.0.2022.12.06.20.04.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Dec 2022 20:04:18 -0800 (PST)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E93F7B81CC0;
	Wed,  7 Dec 2022 04:04:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A2BDCC433C1;
	Wed,  7 Dec 2022 04:04:15 +0000 (UTC)
Date: Tue, 6 Dec 2022 20:04:14 -0800
From: Jakub Kicinski <kuba@kernel.org>
To: Kees Cook <kees@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, "David S. Miller"
 <davem@davemloft.net>,
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
Message-ID: <20221206200414.5cd915d8@kernel.org>
In-Reply-To: <67D5F9F1-3416-4E08-9D5A-369ED5B4EA95@kernel.org>
References: <20221206231659.never.929-kees@kernel.org>
	<20221206175557.1cbd3baa@kernel.org>
	<67D5F9F1-3416-4E08-9D5A-369ED5B4EA95@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tGd2X79t;       spf=pass
 (google.com: domain of kuba@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, 06 Dec 2022 19:47:13 -0800 Kees Cook wrote:
> >Aammgh. build_skb(0) is plain silly, AFAIK. The performance hit of
> >using kmalloc()'ed heads is large because GRO can't free the metadata.
> >So we end up carrying per-MTU skbs across to the application and then
> >freeing them one by one. With pages we just aggregate up to 64k of data
> >in a single skb.  
> 
> This isn't changed by this patch, though? The users of
> kmalloc+build_skb are pre-existing.

Yes.

> >I can only grep out 3 cases of build_skb(.. 0), could we instead
> >convert them into a new build_skb_slab(), and handle all the silliness
> >in such a new helper? That'd be a win both for the memory safety and one
> >fewer branch for the fast path.  
> 
> When I went through callers, it was many more than 3. Regardless, I
> don't see the point: my patch has no more branches than the original
> code (in fact, it may actually be faster because I made the initial
> assignment unconditional, and zero-test-after-assign is almost free,
> where as before it tested before the assign. And now it's marked as
> unlikely to keep it out-of-line.

Maybe.

> >I think it's worth doing, so LMK if you're okay to do this extra
> >work, otherwise I can help (unless e.g. Eric tells me I'm wrong..).  
> 
> I had been changing callers to round up (e.g. bnx2), but it seemed
> like centralizing this makes more sense. I don't think a different
> helper will clean this up.

It's a combination of the fact that I think "0 is magic" falls in 
the "garbage" category of APIs, and the fact that driver developers
have many things to worry about, so they often don't know that using
slab is a bad idea. So I want a helper out of the normal path, where 
I can put a kdoc warning that says "if you're doing this - GRO will
suck, use page frags".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221206200414.5cd915d8%40kernel.org.
