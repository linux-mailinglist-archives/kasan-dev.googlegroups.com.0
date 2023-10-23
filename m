Return-Path: <kasan-dev+bncBDW2JDUY5AORBRVY3KUQMGQE3Y25N3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E5EA7D3BFD
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:16:08 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-581d755f1afsf5641025eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077766; cv=pass;
        d=google.com; s=arc-20160816;
        b=EfstkEQTgoE5MkEBnuLGL7LnvTNBy/+CV4oTHzfgNBfymuEEdXll0MOfO/VfsA7hOt
         wVK6r3dZVWjUDy96Tb9y1QAExELrynkHbkAa4XNtFQ6RMWmT2Zv827qcxcHSQFuIo03y
         YQ8IPbecFIOIkWXpbzuDuxdvF/RF5moUYgiuF5BA7SHf6HcQTp5rGib10pB+rKfgBoCK
         v48Nl0BhQ6tzSGV/TA83G9U+wRphK+yCVSUd6bm932xm3Slo1h3JhyY4CvOtGmwSuXIv
         ralc3qhBX1icZExyGLtnC3hn20cRRnf7HKyPauaGepSZG4QxsNo9SI0ExChxGJpHT5DY
         ebVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=fk5vhqjo6JoZucEBfNMn9kEsP44TFXLw/J7GFCbTFlo=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=siiuymZSP7mjEW8kDZhwFi721Gj6bIjO8IpSMOMw1DI9JWSLsRuqzaqNNLUTrnCmcN
         lIsjwXAVklKyVc+CCaj9Ojk7v9os0CRGnjYwqXIAulbsoOEPJl+OGw2o7978EDkOc1dX
         E+q9Z5TmgBDBAIVaCoN5OEMOdgVI0+DeEoTpya31TiuQ5fBH266kjAKurJGR6XxFwHBa
         QxSxXzhyJUoaZfqKfo+d4hM4sKCl4qpq7LKgQkW8SEv2Q8ByGbBiYNsaLZW7CW+LEjU3
         JTH+qpLHBZtRJ6A21vMZ2MEQIFTiFi3wA7ZGW/bqfhnI2s5uTMaiCDuEniJz5rA5yAMR
         pHkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VKEMB3Im;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077766; x=1698682566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fk5vhqjo6JoZucEBfNMn9kEsP44TFXLw/J7GFCbTFlo=;
        b=Jf4LJ95GCJsxFI/yaP+uqo20vvxzBRuHpXpxq2qLqZrSfR3F5MbQcPzyQENZOJ4H20
         7yISyQCQOGPWAg7pkqAMoFW8BtZ9oljfigai6uKxsxH9YALUexCf9NCaCxdEPalZ9/Vm
         AnSl6m/Z7NNPkJnLZVfNFtiyyS8nmBCK4MUdF2DXdG3x9Byee8UNh4NO/3tNnKTirVmx
         QZGVvsNOEMwcvCxcDQGzD8nElO2XKpf6zCTlFyiwHsezJAg69isyi5FR2Z+QvbtKy9zh
         8577D9prV1vELq05Nyw4pBtKSByQ0Fu1gbP9rRHGRzLU6jx05/4MQmlQ52gnU/KQUXBS
         Vndg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077766; x=1698682566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fk5vhqjo6JoZucEBfNMn9kEsP44TFXLw/J7GFCbTFlo=;
        b=JSoGlcL39GW1LphDq/zxeivGdbEgrC4/T9W6bgy28zgSGiHJ2IHc8K65Lky2HGxK5C
         sXFXPyiPP4ZoW7nm3lYRkRN+xCFLqTXBhvmJ3FZvVPLs5NF/rtlC9BP3hT4uQBk3xQRq
         55mcHRwa6vuOLfZ2oupCRDhYaAAMQXstlkTtSuVx9rYQTHO8x5avVCMqRS4+Mf6ieuqT
         TnjSV6HhUP0pFqeRlBzP9p+ngg9mCeYJpA1h400mEjg4TlHWu2C/vUh3At+iWrUaWxK8
         2PqFHw5iOVYJzyHDMDS6urqQLtmK4F+FA/ZELO+rWNv6GSfiDGH6NjuCNKfCd7yDwLH0
         YpWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077766; x=1698682566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fk5vhqjo6JoZucEBfNMn9kEsP44TFXLw/J7GFCbTFlo=;
        b=O0HN+jLgZAl3gwrjyCNwBhQhSMWDOXPV1b7x9UfVax4ncit3f1Noxl64jFlpyzRQNV
         fYMTy9SFEt32B+o7sb2L0MPYpga5p6SO+mHNCf74CX/xy8t4M1PBnVDBat0T7PX9d6FJ
         8flUXPyGeCxFerFwWM4GH5Cm3hKsmT0HuJM+n+VRhtPNDYKacC33kXmX6eLtKsqx55wn
         aEXwo8D29J+iQpSRxXA7B6ktbLqg6Vf5AY2+YVIKfhT7BVEzG7/LZfgxd9MAWixqEM3Z
         J7E9obKt5KtlHchZ4I64KuLue4+qlSarY3xJmssaNB5JIOyKjomdG1nEWcOBuCyBbHr7
         h7BA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyCDqERI2I/V2k8tUw+ZRSwD6YZ5evM5LGyWeLUT54ZwJY9aTuz
	XemWtShr5RKp4PpxZsk9T9Q=
X-Google-Smtp-Source: AGHT+IGrV3z5g0DnXG34zxlkSVzokvegrC6N7WGGAjOpIllTiCQ9CnbMyYodtYNuq2GoLuD4EsWwDQ==
X-Received: by 2002:a05:6871:528d:b0:1eb:1fa3:7b05 with SMTP id hu13-20020a056871528d00b001eb1fa37b05mr9326275oac.27.1698077766366;
        Mon, 23 Oct 2023 09:16:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ed96:b0:1ba:cb89:5d4f with SMTP id
 fz22-20020a056870ed9600b001bacb895d4fls1140573oab.1.-pod-prod-09-us; Mon, 23
 Oct 2023 09:16:06 -0700 (PDT)
X-Received: by 2002:a05:6870:82a7:b0:1e9:924a:7382 with SMTP id q39-20020a05687082a700b001e9924a7382mr11225321oae.3.1698077765823;
        Mon, 23 Oct 2023 09:16:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077765; cv=none;
        d=google.com; s=arc-20160816;
        b=MnZTgirUrQxYRE3iMqaebdMPZij8namQPewkT76qENeNJgSpiiqpg+9QCrO5uTCED4
         HsLj3vJ/cssD8VD/IyXL0n3pWaDhRN3C3Nl8+Y11R2fhEtH+rUDX8/WqS7qLtmOhhMHl
         JiCKsFQe6p4ULH5yWzvMcuVBMPFLpMXfpBM2rJ0D6tsbJauoeS7VsOyaTbfJJYRBU4Au
         DKE8ZCx/UnOiRF/CZ5ix2em9EDqHFuKNvpVw0cZ1AJ/XKmFkEHtI98JZ6EVw4t+jURhs
         xcrnuDSgDiu/p4bRdpQpxCqJfg6LGFiWnG6LTaWQBEmnCKJ6CobZQCx9a5SU0oC1RzL7
         L32g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I7P8oczVJ6z+n4v15CASAjFJRtKrm1cxI4uPJHeGdVo=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=wKhku2ay06Kpz1gEEjyZ3KvekHgbc3lMUmCZ0Hc5ZffY1nEk8yBXkSQw7GDDDm/kcJ
         yetZ4cf1wRfc6L+N5wu4fSdiwlbkiYoQpbsjBtQQIDXFkbPshWjk+cXDPPg8/DSsaenC
         lzqDBbwBSOzjh2/ial5XOgDvptfGOY8rd8qW9Q8IPX9qI4CMEhWmDghTPWmPQswRJppC
         oAtrJNFoEX+Lr+y4ZuGFhaoD7o6sHROeHriL4ETu7e4DOtp88pyZ3UlVc4GWbDaDKGZl
         /sYXchEANL+wyXWJYwb7ZVsxzgRngP6GKipXr6BxxN6qvndaq3htAjf4vQZJMJEqsrv3
         NjOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VKEMB3Im;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id w32-20020a056870232000b001e9dab71a2dsi1050376oao.4.2023.10.23.09.16.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:16:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-27e1eea2f0dso1704634a91.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:16:05 -0700 (PDT)
X-Received: by 2002:a17:90a:8a12:b0:27d:1af5:3b17 with SMTP id
 w18-20020a17090a8a1200b0027d1af53b17mr6747462pjn.26.1698077765375; Mon, 23
 Oct 2023 09:16:05 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <e78360a883edac7bc3c6a351c99a6019beacf264.1694625260.git.andreyknvl@google.com>
 <CAG_fn=UAF2aYD1mFbakNhcYk5yZR6tFeP8R-Yyq0p_7hy9owXA@mail.gmail.com> <CAG_fn=XyqgfZO=bduYPTGpM9NovQPZOzZf8cidt7=m6H092sSg@mail.gmail.com>
In-Reply-To: <CAG_fn=XyqgfZO=bduYPTGpM9NovQPZOzZf8cidt7=m6H092sSg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:15:54 +0200
Message-ID: <CA+fCnZcWki62K40j56rKopo5JcjBbm5yGwjo8nHstssP5A1asw@mail.gmail.com>
Subject: Re: [PATCH v2 06/19] lib/stackdepot: fix and clean-up atomic annotations
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VKEMB3Im;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Oct 6, 2023 at 7:22=E2=80=AFPM Alexander Potapenko <glider@google.c=
om> wrote:
>
> On Fri, Oct 6, 2023 at 6:14=E2=80=AFPM Alexander Potapenko <glider@google=
.com> wrote:
> >
> > On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wr=
ote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Simplify comments accompanying the use of atomic accesses in the
> > > stack depot code.
> > >
> > > Also drop smp_load_acquire from next_pool_required in depot_init_pool=
,
> > > as both depot_init_pool and the all smp_store_release's to this varia=
ble
> > > are executed under the stack depot lock.
>
> Maybe add this to the comment before "if (!next_pool_required)" ?

Will do in v3.

Re removed parentheses: will restore them in v3.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcWki62K40j56rKopo5JcjBbm5yGwjo8nHstssP5A1asw%40mail.gmai=
l.com.
