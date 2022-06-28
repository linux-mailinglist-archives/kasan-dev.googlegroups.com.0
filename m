Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7445OKQMGQED5BZ2PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id F21A355BFE7
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:48:48 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id i16-20020a170902cf1000b001540b6a09e3sf6776789plg.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:48:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656409727; cv=pass;
        d=google.com; s=arc-20160816;
        b=tlb96goGbegtpOdSdj8+jmXMMItii5ajp8yL0+NRslypDevTklLfnOHIiwm0G9KZ0K
         LBf5zRZRSz7FDYA4W1lBib7YboUcbS0/yStiSj/HChyHgKIyg72/9VwIjomEmMjpHBNY
         5tX01zQO09Qo4u+3MMgTnp2/GrOmMmNMjDJOs+WEQt/izXTsdATbG1nJCWgj8kWL+ZaQ
         QRArwZSTAnbg6k0tp9m+In87Wssn2awz/67l89kx5bYv1rR9y1l+CUXg9O+mKrSvb4n8
         +l8HeFahX5zZaSp7qLdn4DlwtEudiPXVDMSOhJ1/6fLu6xqrlxzeoFxPoUfRJvhVA2Qn
         nk4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rcji2j4/UDZ0EKkl8I+3MxTWouCG3eO0kJG6YLfn6JY=;
        b=hYqL1WpuirRsG57tbzHnsHvzm9M+THJTj2vAO8U9Vb6M33gNhT+HGrdOsi05zyU0A1
         DTxJ2mg4IcI7bmMhpmzRS5W7b/0X2vYEGJ1Ej6AoAmt+aC6jFfSHo5AtyAM8h8Hn8OJU
         eL7m3sBYs3fATCoBWvfkyj0q/xBbvP9vwUbfqB6XEtb0QxqT7o5Vy5oHKMgyl4QWPgkm
         3J3q1emuAIRpSYyxu5KxHDtql1Sd5X60+onr/YTBEwL7/3A6fOcY/iQ//pyaTGfZppkD
         sLiiXeJn2eAA+p2PhS6sH+tbXG7c4yaKEQsNhSLu/Yd9TchIdTTy3Uy6AiI3wbY4wF4D
         TJNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=I7H7zqGd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rcji2j4/UDZ0EKkl8I+3MxTWouCG3eO0kJG6YLfn6JY=;
        b=RSl1J65IgG3njx2a9PGVyxB8mRy5OhpZsLj5h7QWwjjZeCzZj8NBnuRGS2BzTd9nvK
         OARO6rIEK0rIaQ39wcNVSmkCWJwYPxIOxbtyz3QhQ7WwxijcazrY1i4KAhbNWe/Fq6WF
         wf/+4NHFOKuBWl1m6rGjjTzfhZ+m3924Gh6Aoyo+s+CevfO/plrN+lEN+nstQJGD3BWx
         iAmARb2hyu/FDeHNjIPiczs67oVcJNyaxETprw5Z36xe9P3kzk20azFfjsLgsUkv33lR
         qqrgWCOjSMijDZS+uVU4hDc+mekuOC/7/ACYPoJ7sq6Ocy5QrYJL6t2oetkP305MCIq3
         xvyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rcji2j4/UDZ0EKkl8I+3MxTWouCG3eO0kJG6YLfn6JY=;
        b=Gtl3/3iJaX436QcMnEQufFtLqbRHRykeC7vsB2FFg/2m6Jg0u+RHUQqw1YCx74jWIs
         NkWBUSq7TWmJ/xjijjPAUsOT0iR+eANro5Sy8T3JVLSQwe4msISmhKWwEDL3in5uoHEE
         JVrQPEFCMP2HKKNgkTFt7oGERiuXvVWTpLwkIeesJqvjWtbZCk2MSzNixJEYoUg4zwWR
         rq3nGWeW4xk0oIPO6IaiRcdPZGEZDbQzSeFb9SWh9BVk3l05nwkWIBRfrV5MKask/EUg
         5k9J/ea/qDNkio+tEGYfrk+tHSpU8JwaT6+ljk50AxN0kE6TW/85KFnfQO3S1+LiBiju
         J0pQ==
X-Gm-Message-State: AJIora+LlqHyo+3BKN0mrjsxOrT/omSiwbROxWCFKxKXmALXq8mzFqsj
	LYLa1UU7kJgYuZ0oM+qA5mo=
X-Google-Smtp-Source: AGRyM1vLwJXZA9buxUqan5bTFJfXGNqlEylklmfiMki8OKfwMCE13TaJT2icZEQD4vd5VPetqgplwA==
X-Received: by 2002:a17:902:be12:b0:167:6cbd:f113 with SMTP id r18-20020a170902be1200b001676cbdf113mr2831609pls.69.1656409727707;
        Tue, 28 Jun 2022 02:48:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a884:b0:1ed:4fc3:d84d with SMTP id
 h4-20020a17090aa88400b001ed4fc3d84dls117550pjq.3.-pod-prod-gmail; Tue, 28 Jun
 2022 02:48:47 -0700 (PDT)
X-Received: by 2002:a17:903:32ce:b0:16a:607b:31df with SMTP id i14-20020a17090332ce00b0016a607b31dfmr4251539plr.117.1656409727033;
        Tue, 28 Jun 2022 02:48:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656409727; cv=none;
        d=google.com; s=arc-20160816;
        b=HSItXzQjGET6CQhNkxwR9HZjs9e5AUp4zATTs0dyt9ruBF7MVdP7blELi3HQ0AFbJj
         i4Q1LhnzDSaKIOHYFHho2frubdPllByBmoB389W80lKPskF2urTNsNWQtiA5nVMQuVVT
         g3/GFdO1jCyOq2I8IsflMocMaPVOJ4XMUlm+JqidZcjP1M6ybYATkl6qYz3hpee0Zllv
         I4EHsKoM+E2zDOlpSxIv6kdrN1776PGT3d2eL048806HNkm9hs0CxxfNvqvCLkzfBzbN
         IMwZyFzt3FsRHFnKKriY4754F+z27URClovm88B6557sG2yGOYFpUVpCs/mMFsICD0fK
         261w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nnzSecJwwLdHdpah55TWOev8stQAWT9vGpRIkDipvhw=;
        b=mbR73+7fXC5Tnq1zPOUzOCiXSqZFRp4VOAjBALg86uxle8GwkXEK/QFKaFSgGHrxEm
         T9K39RatUZJBnv3BQKYbOg6n9Dc1bwdRskMRDEKz6j0tR0KhvE5yapHwq8UHReikk4q1
         zaykKVEc2yBbQTCESiEVj/tG2KAth5nQ89o4ZPgvqWy8gd/WJclX7/+x1FJMGxhjCDHu
         F3JBsgIv7QvBjCs/0CZhvG8LH1GLQSlWsujSVhyBYIGQzuP1CWm+yxv46XXuGTRF3j88
         JYOdaNvHeRXOWh26FWJ0HYRjoGl7mmFy9Q8j+ZVXQLZD2WBDJybv0aqgrNMkDKG3jmrI
         b24A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=I7H7zqGd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id nu12-20020a17090b1b0c00b001ed12b499c8si517632pjb.0.2022.06.28.02.48.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:48:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id g4so9734035ybg.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:48:46 -0700 (PDT)
X-Received: by 2002:a05:6902:152:b0:66c:e116:6a7 with SMTP id
 p18-20020a056902015200b0066ce11606a7mr8598779ybh.533.1656409726603; Tue, 28
 Jun 2022 02:48:46 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1656409369.git.mchehab@kernel.org> <687a2e724020d135bc7dfef0ec9010a00ecc0a3a.1656409369.git.mchehab@kernel.org>
In-Reply-To: <687a2e724020d135bc7dfef0ec9010a00ecc0a3a.1656409369.git.mchehab@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 11:48:10 +0200
Message-ID: <CANpmjNPbHYKJqFB-qNjPWsLQyk3fWrqfU3qob_E-8KMLrzpCQQ@mail.gmail.com>
Subject: Re: [PATCH 14/22] kfence: fix a kernel-doc parameter
To: Mauro Carvalho Chehab <mchehab@kernel.org>
Cc: Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	Jonathan Corbet <corbet@lwn.net>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Sumit Semwal <sumit.semwal@linaro.org>, dri-devel@lists.freedesktop.org, 
	kasan-dev@googlegroups.com, linaro-mm-sig@lists.linaro.org, 
	linux-kernel@vger.kernel.org, linux-media@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=I7H7zqGd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 28 Jun 2022 at 11:46, Mauro Carvalho Chehab <mchehab@kernel.org> wrote:
>
> The kernel-doc markup is missing the slab pointer description:
>
>         include/linux/kfence.h:221: warning: Function parameter or member 'slab' not described in '__kfence_obj_info'
>
> Document it.
>
> Signed-off-by: Mauro Carvalho Chehab <mchehab@kernel.org>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

> ---
>
> To avoid mailbombing on a large number of people, only mailing lists were C/C on the cover.
> See [PATCH 00/22] at: https://lore.kernel.org/all/cover.1656409369.git.mchehab@kernel.org/
>
>  include/linux/kfence.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a4b680..9c242f4e9fab 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -210,6 +210,7 @@ struct kmem_obj_info;
>   * __kfence_obj_info() - fill kmem_obj_info struct
>   * @kpp: kmem_obj_info to be filled
>   * @object: the object
> + * @slab: pointer to slab
>   *
>   * Return:
>   * * false - not a KFENCE object
> --
> 2.36.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPbHYKJqFB-qNjPWsLQyk3fWrqfU3qob_E-8KMLrzpCQQ%40mail.gmail.com.
