Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJ6B26VAMGQETRBG3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id B1BD17EDD8F
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:28:08 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-41cd5077ffesf228661cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:28:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700126887; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mom17qajczHlCk6ZDnHVNTpGK5sOKfSJ2pJAorCkb235aF6HAYRc/EAtn3uwLv7pNa
         8k3Y6PvPDBYu4D4NEC+zjNh1fn9gm4icfMuBSsFJVAv20ZvShDJolcIni1GjemKMiZCw
         dyU00StlzehbxRsLwyJLsjU8iLXYYPZh+cpPDLpbVfKqTvT2J3SOX0CaOXMZ8kmtGjBF
         ewe0M0B4SswR+ARSlglnZndDfTzIxrtMmxZwQOdTx6ZFqjAchg6cHvzGLGbLzsIalH5l
         shR0DZr9/XiQblYYuNjkqoxYef0Y0u9WuxgL+Zc9XfLmrFy6cBm6pbfHz6ODXLvtpzAi
         2MNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xuhRr+a9U3WcL+KRZd7ggxfwPaCZ6fyKAcsAz/2OOkg=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=cYNAl9AvBBWle107AQKfrovss5Fyz2MQMWnx0GF+oa0nB+JN+a7gU8X81015+I77yl
         bAiOx42XgS/rN8P6Y/zwksIGG97l7KYPFRGv0+hiqFULjWKkMCrMXXdfMcY8AFhuzmKr
         fej8m1a1V8INuu5tO4bX6EZNhTY+bq+6hKLYK3uYu5R8bbv5YfIcXSboh2yiSlh3nq4l
         sei/kQLz/BoeKTZh5Xi4vIRSsAbaxXs/qHFrxb2jPeWyCOPgWEmIACCxaQMoUpZmd7Uu
         6VGq7frB89ob7M9l/aCsNBrnT+jEmX6ab89jIO8uDmTPkQQo1Or3sct6qxnm7ZTEvbL1
         lz3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2ov1B61W;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700126887; x=1700731687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xuhRr+a9U3WcL+KRZd7ggxfwPaCZ6fyKAcsAz/2OOkg=;
        b=LELPWdR7dW5amO70+132V0OgQBmewpfJIEtzDgL7liPS1arVWgREtg/8jixugxzuqn
         Cf5wcU2Xivm0RmGVtj7OHSxyoPaAhhUX0iNRtSWJaWLJ9hLYmNa9h03dqpDfBOVPi7dC
         fggXg6UrbWBJfoBRgodh2i8H3Sh8ylCpH6czpf4exseo+YuWd0TJZr61VsnauMN93Hfz
         Uo2UGyhNeIor/MP8JcLe0A7cDYL2rMle98Q53J/uq98CqoG3Zy9ycZeBYHhc8fCHQxjl
         SsGpeYRTcGOBoFMDnYGsqF9M9RULbhwXojJ/bIgN0RJ7P+l/pNAYDAMwC144SVB9Inqi
         WsQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700126887; x=1700731687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xuhRr+a9U3WcL+KRZd7ggxfwPaCZ6fyKAcsAz/2OOkg=;
        b=sAUltMI3QkyFHViMU/6AYMFfoPeL/8utCNXTMMestUJ59Uu6ZNlVqA0+OXfdyqoVNY
         rsiJTV8pMmhyHfGp3QdVfbUR8NvDBsMd2GcXEVtsnZK6gh0Qt7Zn/ZoHanygzO62bNOD
         6X6aigp9biOXWs9qzfEbJ2niav+nRrTuAXoK0El4lTItmM9p0o0YlMiC3NCAz9sRuxd0
         K6lPsda7cfArE74kw49Yv4272alWd1RXb6BkLjIbdVPkWATf3YuEKHyng3c4OkayzJ+W
         aJ1agNKQwuBf+b/warJyKETkdh2CVNeixi+4KswhOcUsQUyOhgLpzc+m1Mv4HU/SgMaG
         LH8g==
X-Gm-Message-State: AOJu0Yw8LbMRTigt3Qqe4kpr+eGKo9zqSJtv2GHvA3ZZnlYZCKd8LHOF
	lLz7MoTiB+jbvTArpucBMDI=
X-Google-Smtp-Source: AGHT+IEWGtEVmQZ7o2cNQrcK/ezVADk1069C+o+/BuIHNZ1xSPLo4Hd/6p+83oEZdB9wV0dDuNOTow==
X-Received: by 2002:a05:622a:5c6:b0:403:ac9c:ac2f with SMTP id d6-20020a05622a05c600b00403ac9cac2fmr160157qtb.17.1700126887650;
        Thu, 16 Nov 2023 01:28:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ed33:0:b0:63d:1f5c:79f5 with SMTP id u19-20020a0ced33000000b0063d1f5c79f5ls645599qvq.2.-pod-prod-03-us;
 Thu, 16 Nov 2023 01:28:07 -0800 (PST)
X-Received: by 2002:a05:6214:268f:b0:66d:fa0:ab2f with SMTP id gm15-20020a056214268f00b0066d0fa0ab2fmr10211112qvb.18.1700126886822;
        Thu, 16 Nov 2023 01:28:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700126886; cv=none;
        d=google.com; s=arc-20160816;
        b=Bpgj1T8THw43DjsfNU7ZHy5LH6OJFACZCwHaMWQZR5Wn+YlY31vxh7WPsCUVptbwRQ
         Deyo4AuwTx9g0jNzXRvrOuewyjobNHkAiqFK9R7NBH0K//ydkm+53VWlIIrQBHs/yxHp
         /nM9cCfC5G+J0a3S6JPQ+xKIRsyg5e+XdpOpGnJu5QSWS+QVcnCQWW8Cpgm0fR9Ou7eJ
         b8hzeM/aOfT8VUq/5rG4F0/KWThtiFDtYs1IbWJApLzDPkyxYm56f71Hf2T4+n5Eadmd
         tbzeT+aO5fa2NKIIhwHsdfuD8fU69ysxFwA5aUNiYz8BoDQR/WlvIojhaUTECxtR74zt
         WiTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KHxIHoAh95uWA47oz0tiRhia9t+geZSbB1hJPltpI8c=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=oZmCArWqkXkJt3ThBuproy0gvBC6sRpkGAZ4Lcus1+yLm4tekAg8ILX0KKnnwRK63o
         S5D6qlxQnDL3+4FbYHJJCy8ruY3TMX+tyebcHKTxdmO8GRxJFFTzw5Eh99qAjU5z28ot
         3100aleR0EtFjlHc8/uaw9K558QrjtwX/Vk+vKwO+N1K2d/ffsRod4kmOye/tzLmCFHO
         thXqti8yoFhkG17dHniR4fhxXGGbPMPjxjjgsadPPIF+auLVqpG8j5ugJiLOm6u2JhWz
         U6nDLsyKTaYcijU9sKDlALvS7G/vyf+SnzibrM8UJBk19BeN23hUfrjE1DiBCGXHVVrE
         bPow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2ov1B61W;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id a11-20020a0cc58b000000b0065d001394bfsi809977qvj.7.2023.11.16.01.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:28:06 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-5be6d6c04bfso5943387b3.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:28:06 -0800 (PST)
X-Received: by 2002:a25:2487:0:b0:d9c:cc27:cc4a with SMTP id
 k129-20020a252487000000b00d9ccc27cc4amr11964662ybk.32.1700126886326; Thu, 16
 Nov 2023 01:28:06 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-3-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-3-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:27:26 +0100
Message-ID: <CAG_fn=WYywAHC_KfZjk2Wqv6RmZQe1wiAAryN4BC6QZBA3FJDw@mail.gmail.com>
Subject: Re: [PATCH 02/32] kmsan: Make the tests compatible with kmsan.panic=1
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2ov1B61W;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> It's useful to have both tests and kmsan.panic=3D1 during development,
> but right now the warnings, that the tests cause, lead to kernel
> panics.
>
> Temporarily set kmsan.panic=3D0 for the duration of the KMSAN testing.

Nice!

> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWYywAHC_KfZjk2Wqv6RmZQe1wiAAryN4BC6QZBA3FJDw%40mail.gmai=
l.com.
