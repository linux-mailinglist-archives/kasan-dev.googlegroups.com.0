Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6NRVCPQMGQEQ5IOI6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B1E106943BE
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:03:22 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id j60-20020a9d17c2000000b0068bd57aa53asf6281366otj.17
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 03:03:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676286201; cv=pass;
        d=google.com; s=arc-20160816;
        b=KGsFSB/JAl1gu2DRbW4pcRNKZGqcG+mjyrnG8DLMSIADXrdZCA3Isc6rmUFs3P9kOW
         6N/WomGxLc3iaRSzOQHtJH2dwySl43hXe3WgIQXg59rd5LmAsGt8/H8PzNDu4VEslPXa
         0kT28iJFVjOFHsH5pb2C9/C5go/Z/l4Sqpnd9yizW5HPXjtGNOUtW/j5TFq3y1IZF023
         ZRXkp/RPaMz0cuvlU1GGKdw6xGjPdQO60XBMgNTmEm2Lao6TfzAtYOiIMz7Ao6CGu4e7
         ZiGwoqFcdUmXKBDAA57eBmrLlF+rz4GHzf+vyzDy5qjRdairInL6KrddflSh4GU5OALw
         5/4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rbuv8BqVcEKmILThmanZpd1tMcPY5R3CeNrscyo1Jj8=;
        b=CeyZwkyrSpwzuBaD69sRYOYRwXEkpx0vw67hBqJ2JacXMuzfaJnZ4wmeTxXIHJkvup
         O0h6NpMvyQOa/WPOt/fdtpY3EdmwghodG47MYTVx54nvwjp6+Z0B6RjY2X7k014optRJ
         OZk19OHMD2MhrwOySpt0UaAbFbEwqhgv99quOiTir2RC+IiHaeRji2ooFn/u4mh5k4lo
         95H94xOTWJpZHbRFTJNgFVPyiKbDag2+6n15RHpmMyxS5O4OyoZuvryMYCdkvylB0lW6
         UxeZK9ub2HChWBtVIVQL29Lw/Vb90DtGKZfNESWGWFL8CQ1IUCNfHFUpU3GUGDEEvwHk
         GcRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="btEreWe/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rbuv8BqVcEKmILThmanZpd1tMcPY5R3CeNrscyo1Jj8=;
        b=qbzPufy8nkcvTDru9E7ZG2BvY0T6BoYRqwP2jVhQ42I2sTdS+dcaOCWDsZkLIqXW0h
         V5hE0LF1JOJgqemwncbdZooIF2HMkND6volpa2ptbM3vnuLhdrvZ74euvNOXD7AVEr8N
         pBWCUGKOkVlzvvpm53Qn4jv/pUwenBSRrfK0TI5jnJpP0SjxWF3GwpmHf43UbhCYxvYm
         cctd4PMFmgYaDwl2s2+rFRGh+330wGNGy9kZ6b7UWoNJTXagjy0rYAUmXhktDBaR84Tb
         s96AjAknUQcM2BqDrI6MzDBobb07l+7eTOrfhxW7A2y9e/zmVrHCk4/eHQLYX6b0CRk6
         Sxpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rbuv8BqVcEKmILThmanZpd1tMcPY5R3CeNrscyo1Jj8=;
        b=eYgLHY0ub2v0EaVWVbp7iuaIuMd8O2NWhRP0RfZfayWzQ1BMzVMvzlPJecZX3GfjPd
         WtV1NXYUjhCN2yIzcOZxiGSr3DDXIBRMAh8ihor+PWBLQRGVbzSjB6D6EjKTd0Y+UKO3
         oj1xvN3TG57k93psy4je4DJ0MuIqlS/YXk2Qmql6zPFXLC8SCANYila7ZDFovNz3ZKHj
         ilqEc9As2KwtRb5bPi4tUpksziSO04D7I2Qi518TxsKmk8uH8B3TmVTOPdc40uDHkdX3
         8tNrv4mxyPoa+Lly+0LXc4nTMEIE9pKy3zwCbse41AVHm3naiuOrS4Y2l3Ty7Guw2QCS
         ZNjg==
X-Gm-Message-State: AO0yUKV8ZJQ+xYcaX+pyhsjcQuXaMefVp8EyTaH68p27y7HGmmRXmsyJ
	oRZJxXNhFzj5290jzBa4QAg=
X-Google-Smtp-Source: AK7set+NXQXFGjYpbakAEuKdT14m4tXxX/e1WBbZa3EFnaplOL+kV55bQ6R79XTo7qPepigKs1fuFg==
X-Received: by 2002:a05:6808:23cb:b0:378:43ef:467b with SMTP id bq11-20020a05680823cb00b0037843ef467bmr2280084oib.200.1676286201548;
        Mon, 13 Feb 2023 03:03:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:218e:b0:35a:f69:4b04 with SMTP id
 be14-20020a056808218e00b0035a0f694b04ls3716583oib.6.-pod-prod-gmail; Mon, 13
 Feb 2023 03:03:21 -0800 (PST)
X-Received: by 2002:aca:2408:0:b0:378:8a65:332e with SMTP id n8-20020aca2408000000b003788a65332emr12739894oic.28.1676286201139;
        Mon, 13 Feb 2023 03:03:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676286201; cv=none;
        d=google.com; s=arc-20160816;
        b=rwUmnegOx647iv8BY9xZ1Bhyc/lrjUl5ROb2Chh8KI10yHjL647UDKcXOXzn8bjkGd
         pAjivaVoPO05kMFTKATNvUW9jJbLfy5tzEVrmNSCeZ+fFihUFZll4gl8MTqlmQyVvmvz
         YVOwhPBohZNqFBb39mAYEqpOCOGYFtCdeXwZvYV7OgzxMoenQYCpIx2TMJZKQ/YbykpQ
         /0/7bHaoko5mE2UK6io9eBv+jw+eeEZk8QEKAdAAsx1shKX+ELQgfi6wA7gquSADDiVs
         7z77NdigxcR+q86wduuAyFU+g2Y3ALEuNlhm3kbCjPyvprHkdOessH0oOzToEQ8WK0/Y
         nnHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I9smNmbml/2Z1XuxlO46/mzGZGe1qNudBrmiurlMq0I=;
        b=wlo2/6MJn5R9s+5DkdMaPpbK11rqF+U+rlDE1PKR55aIeQeUh1b0oBTV2xR/1+DUYd
         IPApz/fVVlK/sVIodITnZ3QhR2nlDN1ReA7EKryl6y0io+9FaAXgEX9yQcdmVe6bg3/z
         pOxin2F9tsdz5NcFzY8y+ZWbBLIUZzVqg9VPIDhNFd/ISjawAVEEavyWoWYsmHrSoPf/
         t1lPRNo9/BFud7CgkXQyNmBMkL892NxaY4vKoIgr2rnGUEHSrxbiRzNmRV3KqLspNMiy
         mYGpfNs0muUP+IA5/6pvPFG4JszdLgUlpNmsDPfSW3vzGZqIok4Grrsel7ere63J23Il
         Ng5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="btEreWe/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id bf41-20020a056808192900b003783a8a36f0si929905oib.1.2023.02.13.03.03.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 03:03:21 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id h29so3187145ila.8
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 03:03:21 -0800 (PST)
X-Received: by 2002:a92:3f0c:0:b0:313:f6fa:bc50 with SMTP id
 m12-20020a923f0c000000b00313f6fabc50mr2367655ila.5.1676286200296; Mon, 13 Feb
 2023 03:03:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <ce149f9bdcbc80a92549b54da67eafb27f846b7b.1676063693.git.andreyknvl@google.com>
In-Reply-To: <ce149f9bdcbc80a92549b54da67eafb27f846b7b.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 12:02:39 +0100
Message-ID: <CAG_fn=WJC8wj64NTGMuHzsiTs1hfXxFT_Z1zC6+Fh5cOEKLYNA@mail.gmail.com>
Subject: Re: [PATCH v2 12/18] lib/stacktrace: drop impossible WARN_ON for depot_init_pool
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="btEreWe/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as
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

On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> depot_init_pool has two call sites:
>
> 1. In depot_alloc_stack with a potentially NULL prealloc.
> 2. In __stack_depot_save with a non-NULL prealloc.
>
> At the same time depot_init_pool can only return false when prealloc is
> NULL.
>
> As the second call site makes sure that prealloc is not NULL, the WARN_ON
> there can never trigger. Thus, drop the WARN_ON and also move the prealloc
> check from depot_init_pool to its first call site.
>
> Also change the return type of depot_init_pool to void as it now always
> returns true.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWJC8wj64NTGMuHzsiTs1hfXxFT_Z1zC6%2BFh5cOEKLYNA%40mail.gmail.com.
