Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3NVSKWAMGQE7KQ4JSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0959681BF67
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:07:11 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-203437c6092sf1407052fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:07:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189229; cv=pass;
        d=google.com; s=arc-20160816;
        b=V801HL1F8a7LZVmdwsTa8sFZTBUK3Z6m62xAbrkyBjEV7DHzqImuDoseVGCRXk/h0m
         IWquP0y25gri+Co+50Hzl88VOQGEkB1n/7mIR25e/+Igyg5sDKe0hiIpaWAn2TMYLVZG
         gowLtoAqN8gS/CWJSYxMQZKKAs9Ydzxv9QZckS7HDUZVyYrweNM7b8kcS2wJoWhUYejB
         1XfJk0gn6q4aZIis6AcWx1xxYrnUkPovg6Mb3v1yrjr4OLjjk+My11mrzmn+e8Xoe7Ck
         /X8yQ8e+9oEstuma1ObqzqrOjYjcyxWJmAEKd5Dgg77BQbvndB2vCuAAFLgh+zhAqSGk
         ua1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LXaEVJxK3lhY9FOSs/z6s5qarmu3oOVO/5zSCR/aRVE=;
        fh=7a8Mpr0ki9GLJ4yTkY3PJCJzY6hhsHVyNI1Z1U4x8q8=;
        b=CL1yqdK4zw0GP5ZzjUqGXFSsIr/qlC9W2TJULkH/GXdMU1hpG1LZzVsZNhDp8ZZunL
         T0lYy4m2fW/OmdjVIAbbGMnh51fBIpiEhditQD96PQv5/zHMEQlixkGz5L1hfmHfAisY
         tJQA5RTWfO2EAtJ5NbvzvjI/rMD004V8zoEyEwpFa/ySm1NfVmqfvuSwq9vTotF3sLiO
         mHOoMr/x8mxRX0smaLnxoTo3GqcOcvSwLRR7pNKxI6Q9JIOzlG+cqy60kDMijVlHxfTe
         1DGrIKfT6HfxaoelR9wxrvBncBe8E9GHU7bpSlCiMbfjJTl8UywkiAMJ8eJiKUd1MCEn
         Cdtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=etUf6HnG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189229; x=1703794029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LXaEVJxK3lhY9FOSs/z6s5qarmu3oOVO/5zSCR/aRVE=;
        b=f/iN3/CdkdZq32sLYZ+E0wGx6ky5F5TNCp/RMzJTr22QYGylh7hL5K5rB6hsuSUgTi
         jwFofCnN9NuFOuLph3zfX/njWhWOs4II6OX1LSbmcWqyMnAAOHBul0NtFafE4o8i8qIU
         uk9pOIwpiEzcnEtxXKLmlZyPbHCnvlzKT0W++muyzDWPKihfWaZ/Qv2v0QL2Y0h79qqL
         +CxjIe8wiVIE0MWcb/RVqteJrnI68u1Lr6Flq+eIWXu0DnQELd8+461zS7gEcgriMZHP
         xU4ZtxFmbYgBu+vL3qpVOwIonPIt/ecKhLdEj+LzlbTqgHsL5U14+njzMZMht6MgSiCL
         nsmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189229; x=1703794029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LXaEVJxK3lhY9FOSs/z6s5qarmu3oOVO/5zSCR/aRVE=;
        b=CBoMRC/9U07WjoYnmHDUFnj8fIiOBZAOEnnWrSy5t9xtVHbo1M6zehVd0fl3ccUlhv
         jdD/T77oAZ6XCoREdrwQqe/G9ev+p51YtiW46uCcwAoeCKFtsZJADG3kwtzhLkqB/f7l
         5Ck3emy7TXo0Ciu32eZmDTMiQePsmvxIx0XCt0/IboISoYM7qGVYQliWgBby4w/tRO2K
         ErHgWn1/BGBFXg2nSH3hr8p/mwoDI6cjPkHN/1OgiIvxar9PBxgWjC9RK8jMKVug1jah
         tXvKrgmpQRFDpfZJsQpF9jXfsxl8XMrVy/fJTwnD0an6oJb0SpmhRKWmJE0n/jNmuqF4
         UkuA==
X-Gm-Message-State: AOJu0YzW4RK5WwrgvgBWtrlpkZpjpnEt2eQ+3R7xUW6fKvUwbLtzRQoX
	QUdToyyqfLzu3+h9y6jRhYw=
X-Google-Smtp-Source: AGHT+IGR3QnZeL84hlZ6hGq9D6rtuvDhzbbKXDKz4xVuC2aoRkW496sRKOW7qnBE0QRNJemL9KrFRg==
X-Received: by 2002:a05:6870:a711:b0:203:ef0f:7042 with SMTP id g17-20020a056870a71100b00203ef0f7042mr427272oam.21.1703189229515;
        Thu, 21 Dec 2023 12:07:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d894:b0:203:871f:79bc with SMTP id
 oe20-20020a056870d89400b00203871f79bcls1667761oac.1.-pod-prod-09-us; Thu, 21
 Dec 2023 12:07:08 -0800 (PST)
X-Received: by 2002:a05:6871:7515:b0:204:1b34:2139 with SMTP id ny21-20020a056871751500b002041b342139mr410162oac.110.1703189228566;
        Thu, 21 Dec 2023 12:07:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189228; cv=none;
        d=google.com; s=arc-20160816;
        b=tzmNY81nPizKwyko/mA/MUzmB1MmACuJH/M2zDXRk9DQH/Ft42YkdKzmQhmnJhZ9hV
         G+97JC1dohoHtnUuPAC3kUw0+VSIqlLYoLxqgLRA/ofrE1BLDRERcOchSpjNmwJMfX3E
         2t+rot0pbwQr6qf61eBuEfbYzh8Q1qDDPuaIjG3dDm66FeluVuKh086snjD9oIUFvzkz
         IHo5Lk9P2Kg0PH/7Bpj1G5k9z8YRw3A5etmBhWazkAaAix8yexkaMt3tJ605GcJVpOAq
         uDXx4YG8p9Cb1mokF57Kl2H5x0YGMiJlbZZDJ2XRKqzjNlZmpWtkxTvKuUQgF06E9VHZ
         uioQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=46inm7EUcbpVm7rpSw28k0//HHFlqfxCAk6ESa9fcvo=;
        fh=7a8Mpr0ki9GLJ4yTkY3PJCJzY6hhsHVyNI1Z1U4x8q8=;
        b=CTE/zNd9yFFk/a2fLUD+BoII2mdILFVK9jXM9Ou63Xk/33CQak2HwIN2LwlYBYop+2
         zvrok/Te8klqw69pQS81R08nBE0XPWQPPKJ+EUoMpMa0PIrOOkoc7wMdjWW70oYgCTTs
         KjYSWVrocx9CcpNMinyNsAG2ojQjDu6zjDN2MuWj0MCi2bG7A7ZqRLVEkkxE7AWKWPoH
         TM6UIkalCEzycrcuFMalpQdYdhE2UpKpOQA/tveEmHZ4hY4neU3vZMAvhaaFfsMx7nJC
         otBcLMYiuwlfT9zJ9Ao5Ux4P9HgJqebiP0IPYP61CwhJefVus5B4lsO0W4g8udtYc/hM
         SGIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=etUf6HnG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id ci16-20020a056122321000b004b2e6e4330asi579158vkb.1.2023.12.21.12.07.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:07:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id ada2fe7eead31-4665fb8a7e9so287342137.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:07:08 -0800 (PST)
X-Received: by 2002:a05:6122:2b9:b0:4b2:f6a2:7736 with SMTP id
 25-20020a05612202b900b004b2f6a27736mr177040vkq.28.1703189228145; Thu, 21 Dec
 2023 12:07:08 -0800 (PST)
MIME-Version: 1.0
References: <20231221180637.105098-1-andrey.konovalov@linux.dev>
In-Reply-To: <20231221180637.105098-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Dec 2023 21:06:29 +0100
Message-ID: <CANpmjNNY81MMtRVgux5725viFoq2i7PzjVvrnbJmT8ArmTMBUA@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: fix for "kasan: rename and document kasan_(un)poison_object_data"
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=etUf6HnG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as
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

On Thu, 21 Dec 2023 at 19:06, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Update references to renamed functions in comments.
>
> Fixes: ac6b240e1ede ("kasan: rename and document kasan_(un)poison_object_data")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/shadow.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d687f09a7ae3..0154d200be40 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -130,7 +130,7 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>
>         /*
>          * Perform shadow offset calculation based on untagged address, as
> -        * some of the callers (e.g. kasan_poison_object_data) pass tagged
> +        * some of the callers (e.g. kasan_poison_new_object) pass tagged
>          * addresses to this function.
>          */
>         addr = kasan_reset_tag(addr);
> @@ -170,7 +170,7 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         /*
>          * Perform shadow offset calculation based on untagged address, as
> -        * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
> +        * some of the callers (e.g. kasan_unpoison_new_object) pass tagged
>          * addresses to this function.
>          */
>         addr = kasan_reset_tag(addr);
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNY81MMtRVgux5725viFoq2i7PzjVvrnbJmT8ArmTMBUA%40mail.gmail.com.
