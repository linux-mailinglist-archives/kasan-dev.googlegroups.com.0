Return-Path: <kasan-dev+bncBDYYJOE2SAIRBZ6GUCMQMGQEILZTKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id EB0A65BC400
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 10:08:08 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id v6-20020ab05b46000000b003beeaa937cesf3818723uae.9
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 01:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663574887; cv=pass;
        d=google.com; s=arc-20160816;
        b=vbu7GMqrgloIFgQ/Qdqepn2b1mqfxg7Ofe9maykfesWB0IurhxKV/MsXXdR/NBn4Mz
         ZIFwp5xYGtIRpr/Esx04IPCx/oLNO3oVmyOW8eclwXxcNo6l+WxzhBGOxn8P4Mez6aPc
         KT9sxiiJ6YISwyywyiD+tGiHr34ZwXdJCQKfBiPapcoNxkABY2BYF48IKoi0NDREuQCn
         P56g3iAhSYbSsgoq9jD2HfgtKUk9YFoM1WNLMOvoRV+YZO5rPNKG9NfXK8B/zu4f+yJi
         d/S+ZGhHRr0GqJDrIBcIe65z2+PVSY8/4ZAawfAoGHgVoXr3k7n8i53SI5nHOqkkVOLU
         StMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dejaAOTChWK6F+pjhiR2HhwsZe0UeJfNzdFruQqwApo=;
        b=aizIHh7IGGHAxcQaYgxTgPACcBrdcQ5zdmvBqjSHyTaKdBG2bVwo2h9NS6dsjOEunQ
         CVb5IY24rTZ3VEyztIaixmY+JOXETktomrWyx/85Dj0LYr4qrf5MuxgfAg8YBmFbAPkc
         I9M3C7NH4HwPvd4NPXjudrKodixL32tmQJglf57uPoZK6yjacNqZLWEIsNeeg1jCiVv+
         oQ3jzs1yQg/D5iQfyvAs0j/j0gIHZ/8WRK4vTCc3PHBUUhd3I7sCCcJmlEVWq1v1wXEU
         htcUc/znZoLLdrBC0sXcnrBt2/3s3ixSemle9bJ5yF03RDB/Ht3rqECVxAvsIGXAsLhl
         +V1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nHCnfixG;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=dejaAOTChWK6F+pjhiR2HhwsZe0UeJfNzdFruQqwApo=;
        b=VTmOqnSQgQwbvT4gjzvTQgBQK4qFQ9XYB6LniO8FkGmcGP89SlktF/KqHvNWBekjal
         4zWSMVCLa0c72sUzD0KtXmcB5ovYeX76q0tz0nJKD3LIIJhbzq9gLc7YhoVCPK+5sDFx
         ScNlX3eF0UGxlk6GoFUGwkX7GPAGJTZUU7mfCK90qAROhGHAX0mmKbzRavhBN1APr7qF
         wXkKx6GKozVhM0aavAguGI5TA0UeVsefb/fElBXStUaUYKxCjCtY2qi00XzoutqIeQPU
         X7u32Wcx27Qu0/cAjPedi1847jCjvb2jxDcXxKbt/UpNuvi+dcPcumzVFv/acVEbCL77
         4nPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=dejaAOTChWK6F+pjhiR2HhwsZe0UeJfNzdFruQqwApo=;
        b=0Le4n2WE4sgWHfM47+LtAFLjUUMgma45XudPeIi1WFH+tXzhkQyGGbw0qCdYm0fW7y
         CQ7jqioGHOCKDzOK9LPYZHV8LrDe6Npk6lHNFEEX4sd85imSkyfs0GtqVmIB4MhJwwn1
         pUDy3M5WkOwp4UT6OnWUmt7T99r9o60CXh0FH+vIVgzUUWYn6x/VIgYyZrtzkbL9TNvH
         zIy7ulea4sa8DHNeX/9vIaeINSo/2S0yF3RCdocrofftpzboVVc7qCKLF/MsNx0GbF4N
         W/2gfaXzLSkv0tJJo/FN4XAEi6cMpt6gas6GXmM5xKp+eL7Qdwxv1cKDdkC6Ta3DhTlY
         qh7Q==
X-Gm-Message-State: ACrzQf0aKfFHDmXlvhGAMJK12e05tvZKsCmbYbjZy61pjPXg4kbcFpgA
	TYES5NpHCthgNJo5SfzDCpI=
X-Google-Smtp-Source: AMsMyM6l+BNpDs7Ein5ssHvBZBf8GjEmdWX+E5MahOscVvRy8SakcZWag2EEvINcgLwgTGASxXso2Q==
X-Received: by 2002:a1f:20d0:0:b0:39e:befa:fb4b with SMTP id g199-20020a1f20d0000000b0039ebefafb4bmr5415668vkg.7.1663574887322;
        Mon, 19 Sep 2022 01:08:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e01a:0:b0:397:63a3:3998 with SMTP id c26-20020a67e01a000000b0039763a33998ls737828vsl.7.-pod-prod-gmail;
 Mon, 19 Sep 2022 01:08:06 -0700 (PDT)
X-Received: by 2002:a67:d984:0:b0:398:4f25:38b with SMTP id u4-20020a67d984000000b003984f25038bmr5758704vsj.20.1663574886730;
        Mon, 19 Sep 2022 01:08:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663574886; cv=none;
        d=google.com; s=arc-20160816;
        b=UiB6BSyNmVTLsaEeC34uON+r69SZgXnxCvW06QnNfE0cGujk+oi7tW+EL3cj7+HObM
         ygy0ZoBkwTp9UMartJNYQ1cJwfXH1pvz1qlmjJqKPT3yBZv8wnBP5qF0HhGuVsl82Er3
         MzwgWhJlLagJ315X92JMwAObAmBDhdkF+u870ReE9i02iK//Os2GlRENeNIx7F2riPMk
         F2Y3aNFOdmD2OeXihX8AbAEnYU5JpNc3X2ns5+ARv+qG3NQt9I3aKdNRsbU1pWn1B1Zm
         x1cChhs3rMAy2P3+22iyda0RfeEAodI0BOFrUKYCCwxNv823SIgwH+k5FMecta+qKeJY
         IDag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2SOaDgh3Xbp2cThKaHYYChzQVSEAWBeCFOscJLAXKq8=;
        b=ZI1vHElGhNtzcDxwnPK0MhqXFIG92dpJslrlZsegm/n1EvdrBHLg8QVDCKobIVyAa1
         LggqijEcFSzIwb06RsEljnnfOv/EU0vdgyyUC3Weqd2e1uNHdLEIoLN51UBfo3UjfkFp
         /cdd7bNuMunY6FG5R8CxTZYBpMOQPdoawsZSdD3uO03VVcsSSchrDTFllL5R0pErKoBe
         +5nFVADQfatfC7dALG5Qs+GPR0JT+ObKKDeR3iLjBMdqjkoJxTma5I8VpbAGp7lI3IaF
         umFvzOgbs+uag5WIfTzT2nvqKw/cj4f8auIZ0iKcrNq4mGE4zhtiMw+VpRTwbzNg8/zt
         JGeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nHCnfixG;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id u7-20020ab03c47000000b0039f9087ee0fsi1127926uaw.0.2022.09.19.01.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Sep 2022 01:08:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id h5so13678061vkc.5
        for <kasan-dev@googlegroups.com>; Mon, 19 Sep 2022 01:08:06 -0700 (PDT)
X-Received: by 2002:a05:6122:10e4:b0:3a3:e3:d448 with SMTP id
 m4-20020a05612210e400b003a300e3d448mr5281172vko.29.1663574886403; Mon, 19 Sep
 2022 01:08:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1662411799.git.andreyknvl@google.com> <CA+fCnZdok0KzOfYmXHQMNFmiuU1H26y8=PaRZ+F0YqTbgxH1Ww@mail.gmail.com>
 <CANpmjNM3RqQpvxvZ4+J9DYvMjcZwWjwEGakQb8U4DL+Eu=6K5A@mail.gmail.com> <20220912130643.b7ababbaa341bf07a0a43089@linux-foundation.org>
In-Reply-To: <20220912130643.b7ababbaa341bf07a0a43089@linux-foundation.org>
From: "'Yu Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Sep 2022 02:07:30 -0600
Message-ID: <CAOUHufZg_FfKvNAsTmJvWA5MoMWQAjSpOHvWi=BAmsUPd3CZmg@mail.gmail.com>
Subject: Re: [PATCH mm v3 00/34] kasan: switch tag-based modes to stack ring
 from per-object metadata
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yuzhao@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nHCnfixG;       spf=pass
 (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::a32 as
 permitted sender) smtp.mailfrom=yuzhao@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yu Zhao <yuzhao@google.com>
Reply-To: Yu Zhao <yuzhao@google.com>
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

On Mon, Sep 12, 2022 at 2:06 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Mon, 12 Sep 2022 11:39:07 +0200 Marco Elver <elver@google.com> wrote:
>
> >
> > ...
> >
> > > Hi Andrew,
> > >
> > > Could you consider picking up this series into mm?
> > >
> > > Most of the patches have a Reviewed-by tag from Marco, and I've
> > > addressed the last few comments he had in v3.
> > >
> > > Thanks!
> >
> > I see them in -next, so they've been picked up?
>
> yup.
>
> > FWIW, my concerns have been addressed, so for patches that don't yet
> > have my Reviewed:
> >
> >
> > Acked-by: Marco Elver <elver@google.com>
>
> Updated, thanks.

Hit the following with the latest mm-unstable. Please take a look. Thanks.

BUG: rwlock bad magic on CPU#0, swapper/0, ffffffdc589d8218
CPU: 0 PID: 0 Comm: swapper Not tainted 6.0.0-rc3-lockdep+ #36
Call trace:
 dump_backtrace+0xfc/0x14c
 show_stack+0x24/0x58
 dump_stack_lvl+0x7c/0xa0
 dump_stack+0x18/0x44
 rwlock_bug+0x88/0x8c
 do_raw_read_unlock+0x7c/0x90
 _raw_read_unlock_irqrestore+0x54/0xa0
 save_stack_info+0x100/0x118
 kasan_save_alloc_info+0x20/0x2c
 __kasan_slab_alloc+0x90/0x94
 early_kmem_cache_node_alloc+0x8c/0x1a8
 __kmem_cache_create+0x1ac/0x338
 create_boot_cache+0xac/0xec
 kmem_cache_init+0x8c/0x174
 mm_init+0x3c/0x78
 start_kernel+0x188/0x49c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOUHufZg_FfKvNAsTmJvWA5MoMWQAjSpOHvWi%3DBAmsUPd3CZmg%40mail.gmail.com.
