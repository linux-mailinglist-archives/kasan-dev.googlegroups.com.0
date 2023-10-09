Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJOZR6UQMGQEA7ESRWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id DBB687BDAAA
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 14:05:58 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-418134c43d7sf74211661cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 05:05:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696853157; cv=pass;
        d=google.com; s=arc-20160816;
        b=jeiK1SB+aE3C4wSSKxZnU0LSm2qJOQde3j1Oi9lWQaMRJkROCGzDn0ImoBjQ1fDb5W
         SiWMnjcONubq8P4GxW+2tRRAqdd7S4bKasCybh6AG7yMkrh6Sy6zNjiaxYMDs/Z0Zky5
         THQZhu68VAhMZGUg1hMcWrIgkShEajVqYtD7QBtbtwymerYHuWNBP52iqSWL2s+WyoTj
         zjZFAca1RD09eEEmLMK/WJTnUi8wCNjufjm7ooxmzeg2DdWRpEkeNbXUWekbCo6Ac6HQ
         8DQbRR4vz3U0IXMQtDHg0GIagRysEn5LES4hajhAMIp7osGKMXesC7E8C/rRnCCUDTqn
         iayw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wBQpCm6FC748mYixG0fkX4EX8PQDsCM48012ZfKN7IU=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=ytav33qYJ5BYZ81CeVedcFxsp7SyJcL7FAfZLKyTRyAuWTv5CBbw/DXRYiRHzAA4Ax
         hM4yqFomNpR0iMdIp/MDgjLU+sNtRzsEo54UxXLxj4YwTCw6v2aGIQ/pxsuhPxqbfP2K
         Y8s7ZrRgBZ2lFAYXwHNDnphsSikB6Xw8BqXhJfTFCCwonVbfiwYgN492g/XsZxYZvFc/
         whl2M7Wh/MIxqI8qD1/QS4/OOq6oSyaTc5hsLhcF7lD2jPN1Jk2f1nn2p6/NsMDVALP1
         1KfwWgyjJWK4mzLlMrGqSFQNC91+PbPL0jRO/ykNYVYZB5L5d/EJsifqWOflnV84jLUq
         Y8oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gDkTHgJF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696853157; x=1697457957; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wBQpCm6FC748mYixG0fkX4EX8PQDsCM48012ZfKN7IU=;
        b=Vg/PRaHFojfcbNtG8yz3t2/1+J5B7wXb/HYs8cwDrk/7jCTr0A53/bH804v8zbLV//
         vXl3ifyNXRMa0RGvEeB0P4qS/IQDaZ1drRODoOLOa4/Fu6eJukG22yGMf/QLgYQA4HTH
         6FfHHBjTNO1OS3TuyAuru2tVVP8n7VWj6UkYYo6WyPaGdSB6HHumiJxOrIWMzJVF/4iF
         Ef3T2OpWDVF/dvVczwyvzt2Ty8agByKrGoy23d2pnc/TveLwoJgrPVMobjbrDSFZw6YW
         hjCucT9G2TrzqyUsV4NZDM10CQRxYwK5Foc+mK8hzLN0M+tZ3dGSBUWKfU8VckXNNedO
         443g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696853157; x=1697457957;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wBQpCm6FC748mYixG0fkX4EX8PQDsCM48012ZfKN7IU=;
        b=izwfjytp2RVS2B0WOr/eMF3KTMyUsmeMWC/EJyhA5CekFDS71h+leoZnnkOnmficmh
         M81b5kk+daINEfN/8HycQ68Zqh8n0OcSqfwgw7/7mgxVesnzcpBjUMqc7SCQQH4o+FUo
         dKPJdvGzfrYDKxVepULpMsAG5x9ijmgGZlV9+WJg/KFa5rtaGnGd0C8rEUKwl9jj4uDt
         16a194SwjcF2MRm/xZ236NbeD+c/1kcpCEW3xeZM9H2dagZUPZS9Lm/YDMSvOtmglG6U
         vUj7PPmk8TULARijIrrkx0I+mL37PHB3lLFIXoDJKZDNbJ32xnEzTXhFfQwemJF6qdmk
         Je4g==
X-Gm-Message-State: AOJu0YyZ5i3xjrTkHxMh1y1Xdk9+kS/faOoZ3XKeL+rcuSv1L1V5YH4A
	Sg6o1ui1W+RbaY9eDYhbrFfe7g==
X-Google-Smtp-Source: AGHT+IFjA6Ido9XDKiBulq3IonXDzy0iqvjlveT72C3nl4Mr9JAEqQmy5eFYDGBAgFenOlAcgLcMwQ==
X-Received: by 2002:ac8:58d5:0:b0:412:2d6f:6149 with SMTP id u21-20020ac858d5000000b004122d6f6149mr17319822qta.34.1696853157409;
        Mon, 09 Oct 2023 05:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:a93:b0:419:abab:603c with SMTP id
 ku19-20020a05622a0a9300b00419abab603cls81475qtb.1.-pod-prod-00-us; Mon, 09
 Oct 2023 05:05:56 -0700 (PDT)
X-Received: by 2002:a05:620a:c45:b0:775:cda7:88c with SMTP id u5-20020a05620a0c4500b00775cda7088cmr14146037qki.38.1696853156724;
        Mon, 09 Oct 2023 05:05:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696853156; cv=none;
        d=google.com; s=arc-20160816;
        b=lsq95RuSKdzgxIuhgE8YBjBiI/Iu29wTmtOti8fDf8rQ1sb+p74QgEFKxP8gNYqmrd
         o5J4gBzAmoL2V15jMw/v78tnp4RfCc3+LutKAMExsFUSC/t0efJZkOMkHgVsC99/G67Z
         nfoi3HYMpg62IcOKcUyLP2ek3lzpCwVoLPWOqNEOX7H9CvkyYFMgl+rZZI2B+yFiNDK+
         TfX9d+7Whg4I6hYpwLbzv/nM2mZLsZxMt1XxRwrI8n3gsYbOaicC5uK3vnwmOQIy4z6L
         z6VUzBGlmYa9Vy8Lft2cwR5dDm5QeI784bUaZWMxrqA2SJ1Grr3HkUCBGERkcot2fBwn
         /YmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2VY/6yygJv/miZhZ8h6odHp72SB3kIR4yZRTmobOqWU=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=ZwaLHjk/AsiSYFzXDUD3QGZ7yDhcRl0dbRZy+VcXy3PTWZVKMWT07LOmmRRCLsY+v4
         Xr3AR4lNskR2xVTDjoTNbdHE0pB7inIdZmV8XmaSmBZ2UqmT/0XHVntcu+TIsR6GccBj
         FcvfzPKgVh/6kD7SbUqf/Slh9vrE+yQJu9oYZXqN6T0OXmrWVxQUYRPIAOa6YtfFfNrM
         jHkW3BW8yKKOSK8GicMgcH99tuuN42yfmuIzChRSUYV6nj1p8QtevRWHBMsoP358OnHK
         fOuAVenX0Yjm6C6UL0ZP58AYocfj4/+MLq9TA0TLwVnPIZoRF1ozi6MwWkuOxSTKSMkX
         nvtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gDkTHgJF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05620a178e00b0077419b27788si543745qkb.0.2023.10.09.05.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 05:05:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-41517088479so45032961cf.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 05:05:56 -0700 (PDT)
X-Received: by 2002:a05:6214:762:b0:65b:72a:78df with SMTP id
 f2-20020a056214076200b0065b072a78dfmr16256736qvz.10.1696853156331; Mon, 09
 Oct 2023 05:05:56 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <556085476eb7d2e3703d62dc2fa920931aadf459.1694625260.git.andreyknvl@google.com>
In-Reply-To: <556085476eb7d2e3703d62dc2fa920931aadf459.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 14:05:16 +0200
Message-ID: <CAG_fn=VJtzkvrMu84BuNtbjkmRuQx7aLLSsew-Hns5bAdSnm2Q@mail.gmail.com>
Subject: Re: [PATCH v2 17/19] kasan: remove atomic accesses to stack ring entries
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
 header.i=@google.com header.s=20230601 header.b=gDkTHgJF;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
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
> Remove the atomic accesses to entry fields in save_stack_info and
> kasan_complete_mode_report_info for tag-based KASAN modes.
>
> These atomics are not required, as the read/write lock prevents the
> entries from being read (in kasan_complete_mode_report_info) while being
> written (in save_stack_info) and the try_cmpxchg prevents the same entry
> from being rewritten (in save_stack_info) in the unlikely case of wrappin=
g
> during writing.

Given that you removed all atomic accesses, it should be fine to
remove the inclusion of atomic.h as well.

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVJtzkvrMu84BuNtbjkmRuQx7aLLSsew-Hns5bAdSnm2Q%40mail.gmai=
l.com.
