Return-Path: <kasan-dev+bncBDY2PHGY7ULBBJ6XSXYQKGQE3JGZIBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A67614264A
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 09:58:16 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id o82sf549894ybc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 00:58:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579510695; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ix4icI9DV3vSx/oz/gcpelnxHICFTw5q6Cs5/E609gqbYBMgmU9jdHkyCr3JfZTSl9
         duDKa2ZoChDnAYeNS2c9UY8jbQZ8GQy85qMks4aex3p3ABRpP23iw1WfLO/WsoKDh1Ny
         UM6c/RbTncDuhCBnJw2Wi+C87wD3hH1u333hy5bR9qpCNq8T6gAYFcb6v26dsRITghvm
         /GvqbbrJCZJWGdG50ZKzbFg42Lf4m4bO6QCuZ4XMVB8gr9Aurvxs6g+N+nxRlQqWnQrI
         ZYieWUeBLKGiqbrcilwBNNHBjYQhe8MobFXPaVA90pqbjCeAK0Iojhgz+D/sop9YgtKI
         E5Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=dB5B0AeAapuipGJkSHPx9+LIommN1BabjjyP7gprWeA=;
        b=k9sHl3rLdaDbRJpI4l6ZmIjr0eLyIcrlGKLq7Vee5/+Zo+Zg1yEe7vvdA4PXhq6UU+
         9ZCRXANnKeenJrzGiDA+LzOdAUXOX4wTkQGSwhaL3563qfn116oGh850ujdEoVXi158R
         9XmtGlVOAvoJosCw4Go18MI+Jzh6vVASiHIdgyNdJPdVIvOh7BmYF9n52TMcLCY4L90D
         YNvFXq1NRGYKHBBn2A0sMrXSBZoV2nMzXconw5oBmoSplG45ql5BHgok+wURkJ8WaVbY
         IuqYTLG7EDmK5DNrA6sgDRheGR15o2Gc554Sa6+YdFk23B95Wvc1twfjikrp+hgq7rX9
         UN4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WdDp0lZv;
       spf=pass (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=pdurrant@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dB5B0AeAapuipGJkSHPx9+LIommN1BabjjyP7gprWeA=;
        b=qbE3yhtSwNaTBsNuXMnoxMlpUrb+DKQjwrMyiMvpYLvKmYYN4PeMGVbUhgbP8iyPPa
         wROYA9aVh0o1v2ClMNk5SD99XQxbYB2JaBKUpd9UL7vbw0FMlYHOFTvUeHOV6170fgb4
         qi3lx9ZHkP91y5pbQjujIkKrmpg1PqOU0KhFIJ2KkSFSNzrpD2AD09jsasFfnEJc6Co+
         B0184mW6nv5G6ToOGPS0tVJQX8SnJjC8WiIqu2vk5q3BWccMinMLmoSAiFeGVHPVUJQ9
         M8OUlVjS4sCxHnlDe2Yfb+SEmvS/FIwU7/6espIc92bD/9L/muUcW7gFRk3Yq4xKDeIa
         jGaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dB5B0AeAapuipGJkSHPx9+LIommN1BabjjyP7gprWeA=;
        b=QL4RVxv9owJ87B2nW5TovF8kLnp7pA35Yn4xcjs+Fpba42nUyh7xj4Iqidkjr94Mxq
         rm4NsPNr4NHGt9rdWdReoXkKN27pKKMoLqRv8J5MDVBoiBoJcqfMXrQ0dGxprjOw0LGL
         T2FM/nmOPLG9f5Upxtha/LTqt0rqbH3BFmVbSpv8BsUeb3x2z6ciBbrCtf9r46ivifZF
         NDHm5MLWOaA3lVCY8tBcTCTakUQ6rNJvLRtWS4xU+JWtRq9joct291Qg/0ZT1qqhXx0y
         ucDj85g6ldijmRaWNpacBY0qjErgyn2sNNeAUXKHO+b+50SK7J52JaXktGdU5u5YoDbk
         l9MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dB5B0AeAapuipGJkSHPx9+LIommN1BabjjyP7gprWeA=;
        b=K3qJPtydtlxqojjqUxfmVUB1jElZoYE7YGC7sPeCH2cTMl9g0Bt0uJLKdAReTYs30G
         lM+jZlU2aFQ1URVchJ6oKSNZ3jY68NRAonIf29FLFY037tfur0rJKwA8dtuU976ahQ4q
         TVfnXSPyKgXl3iWJsQzZUSudRp5ZEYA0+zFZhXLpbFqO+VbbWy71Z37A01m6dh9S7crI
         +GlfMiMCShGmW0Oq+QD9p86AEYR+s470ZzQkCquVeVuISIcleneN4rJXVEDYB/g3d9wb
         x7T6ktVXBtJIWlpE2KIS/EzyywxXT275y+30SsWIVE7jh0MJEMrfwR1Jyv9/+2rPdQ4X
         7dcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXcz1xkHb/C0jBm31OIMdnPrTMS+0/r7a/RH/JGMFIHBfyTsnBv
	whoc9J91nloqEjmv36rm1ts=
X-Google-Smtp-Source: APXvYqz+kpbL3d7DAIHCgr+cijxYByjtl/DFD6elTpDEWr4Z0+VOFHZlzfuq00YlDbVNMcnoch97WQ==
X-Received: by 2002:a81:a189:: with SMTP id y131mr41659492ywg.329.1579510695169;
        Mon, 20 Jan 2020 00:58:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:cc05:: with SMTP id o5ls5242054ywd.1.gmail; Mon, 20 Jan
 2020 00:58:14 -0800 (PST)
X-Received: by 2002:a81:6f85:: with SMTP id k127mr42116526ywc.507.1579510694829;
        Mon, 20 Jan 2020 00:58:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579510694; cv=none;
        d=google.com; s=arc-20160816;
        b=RGpJ+bQ1eQC8sHT8COd+4b6mDLU9Qs8sPYXat3B28JxQncMihtGrVlb+wbEWWXierO
         udlhXb5fDzpfTVx38qu+HUp6/uK48QQ5ejBGEkBtQtWfB5tLKP9KPmbnXr1fmrS2Op+u
         QegJ5R1PpIusry5ya8gFkFFrezWdDWPULiysC4rp4hL3o+sWZ41rEJvLi4U8+jZRk/sQ
         yS//z8IfUjMVYd2WWZtklBpq7xjPgant4ZGM56fEC6+e6kKaQM+KL6BuNoOwMUlldx21
         RAiMGALrNOX9KMVsL5ec/mOyAb5jAnk3KI3FRyz/8VygrhyTnnbiHYUmXXp9AbFEqmLk
         MQZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OtvuAZ/43/mZHHfizo8i6GGUaKzklYrgQcNWjIYaCCE=;
        b=nP+iMgm4EsZf41+nDxTv4y85Ro4vqXaJ2gC1SPjAulIO+Q1E8WFqnIzqLmK1/EltYN
         E1DdNpf5D1nDJkhPSmEIFZFvq0MHG5xXYYYLNMqHMOuLApR5ApMP9cdaf/1Or1SyPqHu
         tUaaO505hNysGVfpAfAn9TSbyx9+ueSaWn5IQISa2Sqn4LxA26Tz468vkgRV+83oc4js
         JlScs8U1MMdfF7VjbagiG7JD/mNNdeIlda5IlF/1AZrxdu0ya661PMPugxoIJxtjB2ex
         1zsv2g//q2Phx1hO3wUW8o3kVjXhoBwPQsy66/ihWm+N1eGcw29XhSOYTFuXt+FGJZOm
         y48g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WdDp0lZv;
       spf=pass (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=pdurrant@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id s131si1020357ybc.0.2020.01.20.00.58.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 00:58:14 -0800 (PST)
Received-SPF: pass (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id k3so15224922pgc.3
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 00:58:14 -0800 (PST)
X-Received: by 2002:a63:220b:: with SMTP id i11mr58192051pgi.50.1579510693988;
 Mon, 20 Jan 2020 00:58:13 -0800 (PST)
MIME-Version: 1.0
References: <20200117125834.14552-1-sergey.dyasli@citrix.com> <20200117125834.14552-5-sergey.dyasli@citrix.com>
In-Reply-To: <20200117125834.14552-5-sergey.dyasli@citrix.com>
From: Paul Durrant <pdurrant@gmail.com>
Date: Mon, 20 Jan 2020 08:58:02 +0000
Message-ID: <CACCGGhApXXnQwfBN_LioAh+8bk-cAAQ2ciua-MnnQoMBUfap6g@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] xen/netback: fix grant copy across page boundary
To: Sergey Dyasli <sergey.dyasli@citrix.com>
Cc: xen-devel@lists.xen.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Boris Ostrovsky <boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, 
	Stefano Stabellini <sstabellini@kernel.org>, George Dunlap <george.dunlap@citrix.com>, 
	Ross Lagerwall <ross.lagerwall@citrix.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Wei Liu <wei.liu@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pdurrant@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=WdDp0lZv;       spf=pass
 (google.com: domain of pdurrant@gmail.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=pdurrant@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, 17 Jan 2020 at 12:59, Sergey Dyasli <sergey.dyasli@citrix.com> wrote:
>
> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>
> When KASAN (or SLUB_DEBUG) is turned on, there is a higher chance that
> non-power-of-two allocations are not aligned to the next power of 2 of
> the size. Therefore, handle grant copies that cross page boundaries.
>
> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> ---
> v1 --> v2:
> - Use sizeof_field(struct sk_buff, cb)) instead of magic number 48
> - Slightly update commit message
>
> RFC --> v1:
> - Added BUILD_BUG_ON to the netback patch
> - xenvif_idx_release() now located outside the loop
>
> CC: Wei Liu <wei.liu@kernel.org>
> CC: Paul Durrant <paul@xen.org>

Acked-by: Paul Durrant <paul@xen.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACCGGhApXXnQwfBN_LioAh%2B8bk-cAAQ2ciua-MnnQoMBUfap6g%40mail.gmail.com.
