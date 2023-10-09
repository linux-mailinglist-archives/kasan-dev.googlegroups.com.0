Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZWNR6UQMGQEUOP7RFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F2CB7BDA2E
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 13:41:27 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-668f04867desf55254796d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 04:41:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696851686; cv=pass;
        d=google.com; s=arc-20160816;
        b=EM3WneZXv4KgtoZZYpG4BEoAP1U/yBYn4cr3/pYiCECtvZyECG6BR6uIaGv1TzwQO+
         JWzmM8iU4WOfpubH4bTeQWQHaFpnnl1vpuywzBy5EGdcs2JQRBmIQ5hMou54rPXXYZNQ
         kj2D1GVwjGB5ZM5VHykJesT5mQkjorVmG8LX2iyKroUFhZZgwZCR5bCxjHmREtwVC8Mq
         PY/e/cE+SmI2kAQIiDs+WykMtJrBqdU86f69hQ+DMU61qtZbLZbr8a8SE3MSn83tx7N9
         pRzdu7hH+l/AON1QLl0yvOzL/hwXBe/DqugYB3XEoX6xQAf9okGz0E7WMYHvr6NFkpu9
         YtiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pUztScuEG8HaB1rLYXE7BHoYFgaS9xDbyhWZ9ik0qIA=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=Fkkry9jR69Zb0u+lrZZzQ4yp1CJMdZDl9NTWUk1EHK/xrDengoP73AlO2ne2KdnpLq
         1ISs0jHGgsrdJwYxLzBvOD5Q3HPF8fy3ZBcmMhFWeXnCoqs56GY/IUD71nYy9gMr2kFc
         IsYYo6pL9awQLTty9AfHjs7Rei8B4rZ0vH50LPbU1oM1S5I3DSdWAY+vAlUGM9iCx+D6
         TKHQOj0OcfVjrrKGWkrniyqSpgi+3jCqvef2zCj41NC4MjQHPQuyrz1EYhaSYftGptiy
         nWfARiEurPtw8voi4pXFNsNSrt8an55LC+BE3Y9w95fRFOj2LHSoD2DndozzxkslJCEc
         K7Gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=F8IYoIFY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696851686; x=1697456486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pUztScuEG8HaB1rLYXE7BHoYFgaS9xDbyhWZ9ik0qIA=;
        b=X1CYS/DsLndFwA+rSKsCArir3YS1THqdWq8RVa0Oiml+qNCsI7pxp5QSBb9ckUPOB6
         qxHTXmqNUNpSGX5SorhHTDCOzGQAjdoayzrkz5Hm4X3xReAE+rbeyK3UeddctmLE7wLe
         rCwbZ/uqrwDVwK3gLHCXtdjhV6/4faDm1wlDPfTaaKY9h0da4p53nkjN6MUoV5/WPfwo
         N/VlIsdYs3N6mhHLJ2PJTYcYNiS1oAPJhXw082zx9IiCUkGUkrHOjM6GXvQRA3csvqze
         Vjli2E3eSuY6sxzPZyG/7sTRL28INSUnRHe0u8oAWA0fppFN95HvDCXmuVcs1hVRUYed
         ZAdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696851686; x=1697456486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pUztScuEG8HaB1rLYXE7BHoYFgaS9xDbyhWZ9ik0qIA=;
        b=nnSB6pp9SqzqDdqNGs5DP0+vVxg18fqbouJ3IRNoAqAM4dlASKWlsRcqWARifk60ab
         31+IHP7mjY2vZ+/JWVhZXpahuMWYoxPB07GcQeYbvkejBThgEtGReCAfnbbdu/TK+MuF
         aV9l2pQ5AosQ+MSh7laqLww9yN2tynQRlvhHnCQ6GyVicoivlT2FuUxbpF1dvod20EQO
         MjCek7IZ8UZvfCVSpaJaRelloUlKvcrBsZhTHrLDiY6jnzebIBL6bjdqufs33pGaarW5
         xiX9lxKgx9M1usU7Tyb3PzlOL1yCfpiuM5g6XlRdWQ76OPeExJYqO/Wh+aAArAufFweX
         dXBQ==
X-Gm-Message-State: AOJu0Yz9QzsltRd5D8OONrzMcz88jUCKH0FXwa2Firy7eOMqf1tQlVmO
	WKauAzihr7/5cDd/BYh/B80=
X-Google-Smtp-Source: AGHT+IHfAXfm071XkHQnKX3k17iMudMR4KqUBhEvvHzCl2rOY2F2PY/h3Sf36FBBSW3Fvz0tzXHMwA==
X-Received: by 2002:a05:6214:2dc4:b0:65b:821:58c1 with SMTP id nc4-20020a0562142dc400b0065b082158c1mr15117306qvb.57.1696851686268;
        Mon, 09 Oct 2023 04:41:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aa06:0:b0:65a:f497:7ead with SMTP id d6-20020a0caa06000000b0065af4977eadls4167799qvb.0.-pod-prod-02-us;
 Mon, 09 Oct 2023 04:41:25 -0700 (PDT)
X-Received: by 2002:a05:6102:2757:b0:44e:9614:39bf with SMTP id p23-20020a056102275700b0044e961439bfmr10990441vsu.6.1696851685538;
        Mon, 09 Oct 2023 04:41:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696851685; cv=none;
        d=google.com; s=arc-20160816;
        b=bePi5Re15rU5K3JD/VMJxiHfa7RUvUEAsaS5W0YWMXMUv0PogCpnuL8E8xw2F4FJJP
         LdM2mv11Dj+Te/MF92jf8/sh17tw9ClL9+Ch8mTmqMQ8cm3qX0lxc5ASqGqGaWKye0yF
         DxANCowFJD71vHQq/MwW1vq2r1Ug3VCQ/l/o2wj4Ok03dndF5vEB/WFBA+eBMUSbwtiI
         ao5Faozg3JwDJbTdzhjVWiM1eExZGSqFfei7Fm/sXO3HOXAeB6WX0gzSD8Xu0D+YGaBC
         hrenLrzVljWK/x/Vebyo7apea4sSXcyxOMbk8/QUZp853bxn0Zi74RqUc3Ts5RIWjIFe
         tLMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I8Ea6TW7T9MLSMJpTNywUDmHSrDqthlTo8veDLZhSMo=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=qgNwFpczCdsf+tgPiveZAtXTFraeFHCBLdWC8q06KXZyfR0LGYNEd0OBIfIdI8/PEE
         m6h6RyWAoAZPB8+Cdxa3RfyCgiUtnaSLYWcGuOc2WcWevFboAnklYk0OgjuRJ42ItPum
         23JAZ6mZlVnKFFOKPEyLLHaTT4SYdPYVyte6aHxjKs8o2V/CqtrWHfFX87jm6D7qjYci
         hiZ9JBrk5VZcAjykcttAgQFjhJ9iGio/HF8tTCX6ACJCaw1RJyEKq2ZJZc2RxoGbw/we
         23fNEjB3Wu1u+X58TSsQqNBUEOtOsFLbOfA4FvNNJNsRFVE0jmXZTmFmBgut+YPJWX6K
         Ljdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=F8IYoIFY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id m6-20020a05620a214600b0076709fdb678si603027qkm.4.2023.10.09.04.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 04:41:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-65b051a28b3so27884036d6.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 04:41:25 -0700 (PDT)
X-Received: by 2002:ad4:4d92:0:b0:668:da55:6c17 with SMTP id
 cv18-20020ad44d92000000b00668da556c17mr14592159qvb.49.1696851685150; Mon, 09
 Oct 2023 04:41:25 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <c15b94412d146957c8be423c8dc1d3b66f659709.1694625260.git.andreyknvl@google.com>
In-Reply-To: <c15b94412d146957c8be423c8dc1d3b66f659709.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 13:40:45 +0200
Message-ID: <CAG_fn=WLgOq_dAK7pHro0DkyaLY7juCyHhLgKwxbbwUp=qgOKw@mail.gmail.com>
Subject: Re: [PATCH v2 15/19] lib/stackdepot: add refcount for records
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=F8IYoIFY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
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

On Wed, Sep 13, 2023 at 7:17=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add a reference counter for how many times a stack records has been added
> to stack depot.
>
> Add a new STACK_DEPOT_FLAG_GET flag to stack_depot_save_flags that
> instructs the stack depot to increment the refcount.
>
> Do not yet decrement the refcount; this is implemented in one of the
> following patches.
>
> Do not yet enable any users to use the flag to avoid overflowing the
> refcount.
>
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWLgOq_dAK7pHro0DkyaLY7juCyHhLgKwxbbwUp%3DqgOKw%40mail.gm=
ail.com.
