Return-Path: <kasan-dev+bncBDW2JDUY5AORBWVFSO3AMGQEGA3ZHWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id EA28A958D72
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 19:31:07 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4280291f739sf49267105e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 10:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724175067; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPjXh5OnaCO2TQVnh+lJ4+6Sv5RP4NIW9XEzEyyUGpyLFptlQwY+MiSS6Z+AGbvaSD
         x3TJbZDhkJ4wszCHXf4VQk8RQ4cjykZcPsP5q9qFujFZm6gDdCmHyX+Rqj7bdo2YFsso
         67wOJLbd4jAPbNAgsoaPztP4aiOEDyjfhFrI8TKyExt+WeSvVKn46/32D7xdVa2pC4Ee
         td+aW3OPULyGdvNT7w1Ppq/aGhieinL7M1I5Eu+AjC9m73KYC292qN9TI3qlOfqnAqJ/
         sRmbIJ80qBfQvDLJBxlXuM/tuN4wDpQTu8TTYc+srDG87/lNbMaVN/Cn9pbY+mWoqnkU
         0NOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=XhrEbKeT9tJhgytJ3MXoHTua/JQBHib3KyyWJeK3f8k=;
        fh=7nEHrnZD6GwsZi1PLHvyV3rkuIw7DloMLqBhoC2U4/A=;
        b=O2Atvbd3qnsSDG64UoQ7FrXC186DUMmyODJMkSZW6gdqTcfQmXEwOUe7ity8+CKPNq
         +fGdmDSkfbIrwzEd/7hurJc7UOrIBlXmQJ7BjPL+4jpa13nCnlJNEMZWQC1VgRyv4MRk
         Czsoj5FjbFz/vaCLOH9kkhlQf8l6FqUW1MT7ryWkWBLNrWc7gs2cwNfhUr8ChPh167KR
         WPl+LD3UrV+jCcNwSm9PM8dIKjv/YBbxHRfDXUnDsFfQcINKV6+zy6g/QANSZd3mxcVE
         jbT97Nwu0Sg7joxzF2AK1C7491qZdS1zVLtCX0yZ1dj9Tc2hxZUtXaX7KPNvtR6j1Ix3
         iQoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QEjQZaXY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724175067; x=1724779867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XhrEbKeT9tJhgytJ3MXoHTua/JQBHib3KyyWJeK3f8k=;
        b=MqUGra3PHjKxxDzkq/lumf4fCxoN5cA4+ydEOVnyJ6U6RevYS/3moXNPEZrWWxaYON
         TUYvsrNAvBhz1PiWY4li3MPUrqBcBqnILG4Qh4b0Btb9U+C1llNdQx/oGUHPqSyfMl7m
         EZxXywFwmiTdCr+QKBJIoW/2164SEFlwE7A9+azK0+8lGTJUVtoP+o9HmrrMiMiaQFvV
         DXWU40/6nbYCQP+DtaVNS9+koITq99LLk0i+jTYNfxFsmtvuLngIV6a5rt3/14aEeOKS
         ZsodA1MeIgmuCf5tsM0VcMe9TQiywqeokzLKfI/QSNuE8+3Mky+UrLU83+3AmUXxH48x
         /mIQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724175067; x=1724779867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XhrEbKeT9tJhgytJ3MXoHTua/JQBHib3KyyWJeK3f8k=;
        b=I3hV909zGAI1k0lAIYZDJv6du61Q8UHvzyFpDcl79ZWcs9fJT33Jc1UrwE00ge7PkZ
         IJ4Wqd9VYSYANNpGfKsD1G98crzjBxbcIwPmCPwVv8G7v6tJG0CkLRKUti3u4c8wzlxM
         gdlFPuzKHD3mbnuKhm5DMtbkvE/NPr6/JJNg00OgcDVUcRwSdvHfd0Z3pCiL9xSFN2LB
         UNHT+SZpB61vUci/Q2H3hgBJpAga2+8b6xtt5Vg4ARmYBty21hM7fQRKHnq18Jm/OQ+y
         DMztljxaCt1r3zOE/GrxGnp/635XBLIERSnGCflpcjUlT0IYpCIkg5jcPDWRgmTVper7
         U6mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724175067; x=1724779867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XhrEbKeT9tJhgytJ3MXoHTua/JQBHib3KyyWJeK3f8k=;
        b=Kt5O/tT00g8PPFQ2rmn9vcD+mpgy/mA8NmTo/NRt08pbbSM3mbEDoDkATasRRHm/oT
         LUqMAxmSJY+JVFhJto2mDc9rDgrcEMp2E3Zy1khIVW6HyEAEDG7VSHV4HUbz8hb6lxDv
         sCL7QUpe/aaezAZScf1KMeJgsNTfWss/bfszlRDktxEe+GFavoRkpHJ1RQiS6nCvOg9v
         6eYlvJJp2n4371kNROHfMLHchrL66CtP7m7uA2hwUEyQHwVaL/ApgB0unUgtmLxXG6F6
         HiZoD+F2Y0SRlYae8Op+ocL2be8XiVwcb8I4sBMGHSfvZXfH6QBCZtnhwpVAVkN53gaH
         /NDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1YgGVOtmiAtbhvpeCkzY3rmbyiwj6oFetQn3LvMW+tUnVVKDYnwgHm60k1QeLp0ooVRTqRGevaTVJSQrVndp+kUp0NO+4tg==
X-Gm-Message-State: AOJu0YzSqpNhce2y70dZG1baICYUekZ1BnxGqTr7t8Ugc8BVoetBYcfH
	B4XD3V5y58kvxT9upOeO9b+Fi25qtIZQfW/C1zFb7tX2qWNLAx5B
X-Google-Smtp-Source: AGHT+IF1T5KOgZwtfLXZSeGcCcKSqGNKvwsIngPu3EmU5C8KTuGlKlz6oHbmrQlxuUmzZMT/Yb/vbg==
X-Received: by 2002:a05:600c:45d0:b0:426:6edb:7e14 with SMTP id 5b1f17b1804b1-42abd2571aemr488235e9.35.1724175067135;
        Tue, 20 Aug 2024 10:31:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3587:b0:426:68ce:c99e with SMTP id
 5b1f17b1804b1-42ab0964730ls8658645e9.1.-pod-prod-03-eu; Tue, 20 Aug 2024
 10:31:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaFlo4WHUl11R7HEHUKDSVJ7F1NArXFq65S5gCri2GDXwzLLfHofq1uY8CXdKeprin7uunn+b0NZnmzco3ITTOM+PwQXOB2CB9yQ==
X-Received: by 2002:a05:600c:458c:b0:426:602d:a243 with SMTP id 5b1f17b1804b1-42abd217603mr650735e9.16.1724175065178;
        Tue, 20 Aug 2024 10:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724175065; cv=none;
        d=google.com; s=arc-20240605;
        b=Vj8JfMCFFkYENC8BFMfPt1mg740uFncXXGfxTrtYCHa3yVnyMe3FtHUgDtkOnqHUI6
         dm7cMgZaxySdn4gK5iEC5IUruRgQmRo3mUhtT/khblYQWPMm2+ThpsD0Hg6pPNJ3t+bl
         Q8FC3PrUeRojGdKdyt7BY8Yf+hhYvws6CeF+2bCgAJuEVxnxweYb8ld52FjzWG5i9Sy5
         KHN5v8iJtgbrC8tUkX8UgQkSGRzZ7dpo2CDEO5RKyEqMKQ0X2Mukf+Xo+xOD6EZoslym
         6swahh2pz7lYTkkqzrZ4d4vBmTloezryU4CX4uwEm5cxyZVv/nL/HtNou48wJTz7uSOy
         mDqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=I+lMfrKucvnoaMISj0r1o4QzhUsUMyiYhDB1sLk5438=;
        fh=JteQkyR5ATkQeAx4rJckjCI6XW8KIfMYDXue5t9eOu4=;
        b=fK8CZufynIyC119FF3NxSO3TqpOci16VaeqBcry6OvgH04hqrDuiCRrNSBlgv3f+Gj
         9mqS/I2ldbyObA3hYETdnzODD99MPzC8bLfbWMckNJIM1H4Cx6ahe1dwy/kX5a2r1mDo
         A36lbxU885JYogF8UeC71Wc/foW/F1dnzVJQdamN8gkcnRt6B1YBGrdXRjPmiBux0mL1
         sftoz97qjEH7sskBkbVetAW9kFJB6CQ2LsAmwWqvrzgLEbfqH7pL+RIZhg8Mq3nvGZN/
         nxj/5tD5GAhTjEK7RVDtoQm76VklnML00I791vVBbAbuFsfsrWTbujzLHvQPfh0Qolhd
         Oa2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QEjQZaXY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42ab87f26aasi1388855e9.1.2024.08.20.10.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2024 10:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-429ec9f2155so40795405e9.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 10:31:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVY4x0Q0gWpbH9udgEN8rrlS6iWcQL5IaJ8gYAnDAOTq+G4hBoMw89ReSLGwb6S93P92G1mrmuhbWAfTLRndTLYBCnnSHymiEbCVg==
X-Received: by 2002:a05:600c:45d0:b0:426:6edb:7e14 with SMTP id
 5b1f17b1804b1-42abd2571aemr487465e9.35.1724175064325; Tue, 20 Aug 2024
 10:31:04 -0700 (PDT)
MIME-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com> <20240819213534.4080408-4-mmaurer@google.com>
In-Reply-To: <20240819213534.4080408-4-mmaurer@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Aug 2024 19:30:53 +0200
Message-ID: <CA+fCnZcN9BSvhj3iQNVAiudkMFg3kCPBgDJQoJshx3BJx3N2qQ@mail.gmail.com>
Subject: Re: [PATCH v3 3/4] rust: kasan: Rust does not support KHWASAN
To: Matthew Maurer <mmaurer@google.com>
Cc: dvyukov@google.com, ojeda@kernel.org, Alex Gaynor <alex.gaynor@gmail.com>, 
	Wedson Almeida Filho <wedsonaf@gmail.com>, Petr Mladek <pmladek@suse.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Yoann Congal <yoann.congal@smile.fr>, Kees Cook <keescook@chromium.org>, 
	Randy Dunlap <rdunlap@infradead.org>, Alice Ryhl <aliceryhl@google.com>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Vincent Guittot <vincent.guittot@linaro.org>, 
	samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QEjQZaXY;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 19, 2024 at 11:35=E2=80=AFPM Matthew Maurer <mmaurer@google.com=
> wrote:
>
> Rust does not yet have support for software tags. Prevent RUST from
> being selected if KASAN_SW_TAGS is enabled.
>
> Signed-off-by: Matthew Maurer <mmaurer@google.com>
> ---
>  init/Kconfig | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/init/Kconfig b/init/Kconfig
> index 72404c1f2157..a8c3a289895e 100644
> --- a/init/Kconfig
> +++ b/init/Kconfig
> @@ -1907,6 +1907,7 @@ config RUST
>         depends on !GCC_PLUGINS
>         depends on !RANDSTRUCT
>         depends on !DEBUG_INFO_BTF || PAHOLE_HAS_LANG_EXCLUDE
> +       depends on !KASAN_SW_TAGS
>         help
>           Enables Rust support in the kernel.
>
> --
> 2.46.0.184.g6999bdac58-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcN9BSvhj3iQNVAiudkMFg3kCPBgDJQoJshx3BJx3N2qQ%40mail.gmai=
l.com.
