Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUGM3OVQMGQEO3PA34A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C037680C6C7
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:37:05 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-1fafe28b183sf906976fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702291024; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQIkvJPvGryEGWeFBqmj1nnPL4lupgwGFxgk7hnd/WtR0Kankda7vkNDNJEi6yRGPG
         aHuIxsMJ0u2h+1KmYGrhxN/BN6wz8fcRMW31ia18GxigxBxBbP7UrSWqjOFpes0RTj9X
         3sxtPEQ3OkJU+ueAJUFuQGenWIVF6oiW3ekd9VNPelokjT9Em+qQyhCuiZ1n/ut1HOfO
         COwKY8g/4O52jdmpxRyGaz/oVUIYf/k+z51wlR4uv5sLrZkfvnxCd2T66toOUGFWUiIa
         dpnlCJNrOsakT7iTJU3x5ijtikJurhAyj5Tr08NKDzGJrrU70Kxleqh6H/hdO6e/TKvY
         ywgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a+F49+MaL2iyLKrD9NSeMad92Q1rVMg28s4jWvoaDGE=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=N/6+SC+Dm+wT+xEVeNDBHd7wtCbID9CSo3lnczoyJAT1VUM5yf4iTHD6pB9r6qIvL4
         8/kf4y+B/rkyNwX9VqMFDcsAY6JTT7j0+0EKKM4J8bw4YRovu9auY5KHGGxdTXR2Yuou
         sMlWLFm4bcSdgaF0Dbd7N4dyHkBuo8fKSsjKDek/o4Ogojsrdf2VYNGq5rRdq0wcW2NX
         npc0yRN8UIR6M1mOoCiNZ3oSsFdFc7RfpLM49DFoRnqn14Iv1rAqKEtUma0lcYKuXBKb
         x0CaygCeAZhWTwg/Bqnh0zXw1dDsRlzBt4LUj4K634OKGH4v+y32rkgicxpyariL7V1K
         l5CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GzEjHFvI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702291024; x=1702895824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a+F49+MaL2iyLKrD9NSeMad92Q1rVMg28s4jWvoaDGE=;
        b=nPv1Y46vts+ULYGAJQ7QY84yp3u2RLLQhtOpk8NvN+huNuCMoU1UUMcEfBp36HTDnu
         GVfpdPK9P2EIEfqo4LAxNd2R7Pg+l4Nq4KIZPXvpzXHnPfya+Hs+PdC/lXVtEd8DIJL4
         OhpOt4ramfx6ylQXGIMMye1JKbCP3vTeDHc8rRTLvnaKTLeDZQksQNJ9rBFXQBeE3UkJ
         eDnM9FdNhymLT2hHCohNFTp5bcogtktWpvxRwMCejOnI6rXA0XRtVYt3N2tIITVgUYAl
         Upuf8/9sNPn2BmvnEnBviI2crNaD5y4F/+Qpo/r6rec8EcqQ4x7E2zcoiW3sbE3lAwC8
         7sYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702291024; x=1702895824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=a+F49+MaL2iyLKrD9NSeMad92Q1rVMg28s4jWvoaDGE=;
        b=oTdtgWPtQVCJG7R6TdL/hsnCi+UDyWGI5EtEA2frTnWkUk1MmR68x3ut+UeBRr3k1v
         E1lLLcM8CCaqxhVH0UHL/OWtctf3VOnDdRWPXOT1O8cBbdVQBBFk2/8sTDL0bKL5JsW9
         Tspqf9L7PnEVfHHG8dqu7XIetePUCm04e1iaBDOTFZfJsLlkaF7hb7ozis4KEilK3R+D
         wy0jvyvtT0aWprLmenNBNI/QNKIFxNXaKaELpBJ1HY5TlVJ46ecc1hRtHzTwuKMikT3j
         wq7sxmoljLmT4dlaabrn8Sx9eKPB1LEktv7tBTPAFDSuMfmaUrsVSaVOHhk+3qaZukuS
         gvgQ==
X-Gm-Message-State: AOJu0YzzmfQOrxL9MUrCB1crJ8lJnFpUTt9EKJjJ9/oXhq8IQxXZMZqx
	lm1G3Q0j9F8ghtbh3zqBOWg=
X-Google-Smtp-Source: AGHT+IGRc2sFDMYsJvBwBPznTTNdifka7dIC9vFzrmSd5P/oySYo4TLxCEsqbyUlG37swlOy3dtjuQ==
X-Received: by 2002:a05:6870:970b:b0:1fb:5e42:5096 with SMTP id n11-20020a056870970b00b001fb5e425096mr8361840oaq.5.1702291024596;
        Mon, 11 Dec 2023 02:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ab18:b0:1fb:3407:6091 with SMTP id
 gu24-20020a056870ab1800b001fb34076091ls5097106oab.2.-pod-prod-06-us; Mon, 11
 Dec 2023 02:37:04 -0800 (PST)
X-Received: by 2002:a05:6871:5a95:b0:1fb:75b:2b8d with SMTP id oo21-20020a0568715a9500b001fb075b2b8dmr2101705oac.73.1702291024049;
        Mon, 11 Dec 2023 02:37:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702291024; cv=none;
        d=google.com; s=arc-20160816;
        b=tgmooY+jDP3jurjk3/iFQDjtwBkF30agB2GJTOa3Z5M+HEYnFsipAhxjQf5jMX0LDO
         UL1ZWGJ7QVMOymB+p66xNj+aYvZwUXYIE1LS76zyhSwvX+yU0fo6z5tvmI1MVTS1yOVy
         oElGv7TYHiAaBVIYshxojBuolDvbuspBoNKBK6f7BFSiThKczq0kdWDPkWLAqIJOKpwV
         xZxJ3nB9fsJc6ALjNjLHcJUbZyJbMExWpZBAlVBfPYvdlpx8HdjDpQ9Jj4Pcl5m5koX5
         Z7gkRvpJIli3H212iv56zggDtRI/tkAIEDwhV3W2d6XGKUX2ee2rbZ+UFpyI1iU3rFSx
         kHIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9xZZSpag6K2BrrxUB+HXexjy0tvgok7Hn3gQdazxamw=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=yQ8YNqgEAdsUIvf8O5tFRdScZV3WH366wPerYtnC6CA8ltkJz+w16igaL5IYlTL+ee
         iNeN+KuKtWTowuyD6sL2jDvHOl6hqYLhJwsRvfsW1CIP8UAd6W5kOlYG7I8OGsUmIvmd
         gaL+TvYDfQWh/HcwPcgALAcoXzt7x2R4G4JmyqcZtOMWrM2Z2eJJYhPw0TQVnlZM9sBC
         Kgd1HW7d7PdUlqMLFTDYP6o1SVowEoRJ9CJPI1Xh2HVUlu7Fghkj3HgZnGJ+Yv27smBd
         G02nLvalpqyN04I2Klti05w02iCDEBcMRBfvC/fBl2gjiylz9k7FGGZctdeIbjkUpR+G
         0JOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GzEjHFvI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id lw12-20020a0568708e0c00b001fab154c144si771024oab.1.2023.12.11.02.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:37:04 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-67ab19339b4so29808146d6.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:37:04 -0800 (PST)
X-Received: by 2002:a05:6214:5cc:b0:67a:97a4:1f73 with SMTP id
 t12-20020a05621405cc00b0067a97a41f73mr5565614qvz.40.1702291023543; Mon, 11
 Dec 2023 02:37:03 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-26-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-26-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:36:27 +0100
Message-ID: <CAG_fn=W7EQph__sbiBvNdaaSFG3-vweA396Oa81QoXAE8+b9yA@mail.gmail.com>
Subject: Re: [PATCH v2 25/33] s390/cpacf: Unpoison the results of cpacf_trng()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GzEjHFvI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Prevent KMSAN from complaining about buffers filled by cpacf_trng()
> being uninitialized.
>
> Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW7EQph__sbiBvNdaaSFG3-vweA396Oa81QoXAE8%2Bb9yA%40mail.gm=
ail.com.
