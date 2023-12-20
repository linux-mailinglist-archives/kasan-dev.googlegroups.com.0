Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY47ROWAMGQE5ZU3PXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id C3C96819E01
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 12:28:36 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4260c84c473sf291731cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 03:28:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703071715; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3L4ESi4TX6GoYe/foOOu01Llw6xj3Smsjo1rgqK5ip8PNPQVVuok+wWQqRq2NWFNJ
         Hc8gnIuo2ZlkWpGw8fw5Dh7QDpoZ5oq20YT5/EVzHzlXo2x8/+UupBbJRSLvnXqoiaHL
         vjdbfuV6bGiTyNMZEJm8gxg2ZIakSwk/3L27waHoFDTg7tVJ6mofGHkxt+z8rbJ9kWnT
         brXCRLNyZiz6+sP7+fdE9/gBGJszkzPZc/vUJa4L4Uk0FXt8AVTJR//3bkp6btE6x9p/
         g3JpmJADgKNu/as0OPohDPV59vrxrk/Y4N6bH10xS7KvEMqil7dGY25bS+M8ptcUCCdh
         R9kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fuAx86oDDfpLm0VHrF0awbTnRscKML7Hct32Lr1oq3g=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=J6QyhpUI+ySDslG7moLbVA5Mg35Uw3XXvt9Xmt3Rzj0/rTe0Y4QcezButc/n2FABwF
         l72tPXmZdsK/j17A7sVDGre+Aj+sNhBRxrS9wUtjIiSBXRIcgxmNnBdEA5+9IauHJEnH
         BCKqRU7kO8MN5DjD9qVWWhoejlMlThZviT1fMPGbqiO3I9PRS219rCh2M1rm3o5xZCmu
         2CPw8IFM3KjE0LpQsiQf7h+g1Mnrc9Bd8c6PJIqsS8VgGcj21zZ0CNbyAYgIQPpQn3ve
         Dt6CFyj4NHsU4qO0uzm+TsSF42+VQRXGSQmAg5FMDd+BB7FFAQkHp2GIr0GnDTrvSJ7a
         EnkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="SbDz/fJk";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703071715; x=1703676515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fuAx86oDDfpLm0VHrF0awbTnRscKML7Hct32Lr1oq3g=;
        b=nw+MjJPaEUl3hgM4H8kKjLnO5BmqhI0OVxywydPLXGPgnr1orlKBSq/7YaXRnUyshm
         ITLFztBtR7mVLx/ZJYPRuzA5QA2VdyVNsrzQXtE8kVEpz+ATexSIUf7Am6EHhk8uz0jT
         hE1JaD6MU8Ey/xrTDj4Ore8xM3mIqgkdQ3nNQ4wrVRFYoDHk8JVwq4rKIfwvsmkZojPO
         ie5cqC7RTbsij5I3mEN38h3aPr3iqAsq+TmpeuZm56exH9OaLjv2VGpiJzqiBuyxeVt5
         bKNRSC9GVDAZ3cyCmlxVaADkLEspp9kKVvaGtLQDXs+V1kui/xGiST69ECQND5UTzjoe
         q+iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703071715; x=1703676515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fuAx86oDDfpLm0VHrF0awbTnRscKML7Hct32Lr1oq3g=;
        b=wYHS6QsDxTivHSrmI1BjsknSPIG/08Mc7R1oJeJ+Hgf7FhWzghxqmikj/b2UyJF1Os
         GiltnfVs5x4K7EblARtQPGk/k4Q2GWIu2flmePDG7dG/5V7NYv2sUOCVo7SEr6aKXuyb
         xI07/QaH2Jpn+E2wwkm/TaCtKmGTgpm4WhbTrCHqY3+cjlsanuX5Z9H7rWWcjuRveKQi
         Tta9GrG8N7EEqBBuNZ0cOzhSq/pkatlzK7VOK0Z486kAlmkGoJJbZ4yss637inYXdTEj
         OVXXAufqaQALi3CKOSE27mx+7LAYnCLPK/oGd/vy4+a+JdsxDUqBrZWZ4jSySxUXazjb
         4slA==
X-Gm-Message-State: AOJu0Yw2d9DAApQPVT+jqaFYS+NSz3QepXDoolBfEnKivg6RumIezDfU
	+P9QjiT4rKUspJPY+4LEfao=
X-Google-Smtp-Source: AGHT+IFce2zXNyS3jLfU2TvexkQMOWY+tE+mHqgNXPeop8ZGh65lgmM1ByPeXF51OeqSgHwr4QZjSQ==
X-Received: by 2002:a05:622a:1307:b0:425:75cf:90e9 with SMTP id v7-20020a05622a130700b0042575cf90e9mr259129qtk.22.1703071715608;
        Wed, 20 Dec 2023 03:28:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3019:b0:67a:1a58:78fc with SMTP id
 ke25-20020a056214301900b0067a1a5878fcls261815qvb.1.-pod-prod-07-us; Wed, 20
 Dec 2023 03:28:35 -0800 (PST)
X-Received: by 2002:a1f:7dcb:0:b0:4b6:af71:1af3 with SMTP id y194-20020a1f7dcb000000b004b6af711af3mr3949527vkc.11.1703071714887;
        Wed, 20 Dec 2023 03:28:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703071714; cv=none;
        d=google.com; s=arc-20160816;
        b=HlmOfMFYJJNASfdBEInpGjlHGKdjhY5NO88SjIz/BFsey/8T9C0wEro+HyhpjB0CAi
         uoi+SaZeAhTeaCnXfXnPH3y+TgSszbKCAvNd5oftULnBwGtTNiLi7zgvYksOGrDQgdEt
         +3gC1GxjfxWhrxep0w7YSvJI4IlEpXCv/9OEu1+Q627wLRZecFOGNH/7RI0o9lBSd8tI
         XPCsvrN9Ni3uaTkaBbktkZ3Aqp/QvER2jKF1HI8YuSM02i1VxeWLwVojAagfO8JuJ62C
         nzXbIIiNqNIQQxoSIyYt1a7ZgSmPX0yhJWvLIIFQwSsnD2dZPqNfbAr/sDYH1/8k593y
         F7Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hcGG20SZ9UCuGoY4ieTF40E4xDyL6a01++66TUtS6is=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=rhNYkXZEFKyLXGVN3MbNfsswYjpjAk/ubS4fsC2i4HExHwNck+yG+YUF4vqrRT5M/F
         gO/XTIuMBGGnAa/mtJVZyFiVMzNITSS2ZlUo+AI+7Z80xttkTs+Ak1Vjb9QjApzL0YNS
         /m+fNEdGY2qFumeqPZzrPyzq9+9hWx3pyKlh2LspISvDNGJV2XbLhw6u0PFSkboBNuQr
         yOUEKg4kgvNmda2NctbDmgsj1Idia/dJx8Wm8yS5tGAhazHhvfT/HlRYlTWoPLbh2n6R
         S+diFy4Oww5A6g7H4OrmBvklKE1N8JNdn9TEKGXxwgNTgEyPgWaomSM1l0UqBgPgFc7D
         YDiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="SbDz/fJk";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id bq25-20020ab03e19000000b007cc016eff1dsi369155uab.1.2023.12.20.03.28.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Dec 2023 03:28:34 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-67ef18444ecso40125166d6.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Dec 2023 03:28:34 -0800 (PST)
X-Received: by 2002:a05:6214:d47:b0:67f:3d14:4b6e with SMTP id
 7-20020a0562140d4700b0067f3d144b6emr7374255qvr.130.1703071714268; Wed, 20 Dec
 2023 03:28:34 -0800 (PST)
MIME-Version: 1.0
References: <20231213233605.661251-1-iii@linux.ibm.com> <20231213233605.661251-34-iii@linux.ibm.com>
In-Reply-To: <20231213233605.661251-34-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Dec 2023 12:27:53 +0100
Message-ID: <CAG_fn=WP2ZPdptOoEnCen3BuYs3EgB1nNfmoxDnC9LZK9r4CrQ@mail.gmail.com>
Subject: Re: [PATCH v3 33/34] s390: Implement the architecture-specific kmsan functions
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
 header.i=@google.com header.s=20230601 header.b="SbDz/fJk";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as
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

On Thu, Dec 14, 2023 at 12:37=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
> prefix and calling kmsan_get_metadata() again.
>
> kmsan_virt_addr_valid() delegates to virt_addr_valid().
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWP2ZPdptOoEnCen3BuYs3EgB1nNfmoxDnC9LZK9r4CrQ%40mail.gmai=
l.com.
