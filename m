Return-Path: <kasan-dev+bncBDW2JDUY5AORBX555KJQMGQEDUYR2TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 28E7A52223F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 19:20:33 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id x21-20020a4ac595000000b0035e6f78ae62sf8867848oop.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 10:20:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652203232; cv=pass;
        d=google.com; s=arc-20160816;
        b=dpRBxehKtaZAp9mkOvYb+sVtDbvyj8wkZlZoV5no9qmAHy3RN6MzQZIsO87DvOu8p9
         vCEr2/tKphwD3A7LMZ1wmfGyUNUUabRgj7604A0MVnBSN2Cj/Khg5JzubYRv+ISCZtzq
         aqFx9Pm2N0YxKSbeSbrUb8O6Th87s2SPdzRLJ1snetHTBw7eOLtqy7psZ1/MtB7WpWzc
         GcU95FJKSsmKmcBcE9OncZhIFd2UpBBAUzRxlPwHys5z5xNkToD0xw4K+tG2VDXZBP7O
         Nf2EgJS/oF80GSDILBog9kM35qkHPBCXiz/q0RtMjNsv+2GSHldrJxF7teSC5LAtAldW
         4Evg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4Wx30usIz01HOs35T55D1lEnPqyGIA7i23YAP3P/ZFc=;
        b=sabpLlt4GQCDPv2eU5GetBhHcvvQbZHO3w2IMmUvkyWJaRQx9wgBAt3p/mfY1tibyQ
         V4BWNC+YVprc/EnFQKAKtgdX6ya3B8tkhGLFLCJcpdd2XysIkwi/lMbLP+lV9YEyH0Z7
         CqZri4rLJ39gXNdBZK155giiZxnZET9kOjmYKdzPZV3/nCndWbcvp65FkZpzbbVExnXG
         v72bV452nrjgnADy5ip6yJ0QYA0KNKm28c36Q3/Wa+39SXZ3jcKuGOhjOJmj0wEyc7y8
         rjg+yBsqZqki5fNCi+3u0s/ZJ/Z2qj5X5VQu15bQwQvpNsuUO4rIBce9XNFt+HniF/xC
         vnIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Lt7mUYnn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Wx30usIz01HOs35T55D1lEnPqyGIA7i23YAP3P/ZFc=;
        b=XGgvK2j/zB+jf9bpkoRi5X3of86Kq0zl3TbQiUtXsbLUsPYGKTEQ7vbeXD8v843WPi
         VOY7em2PPWNwcQad9Y1YDRjyCpUOKQtdjlwyvfomYYxifKc8AkMHuxRxOe6hNgdeiLWw
         i7mBFXkueSOMO30LrinwOjkqtZKNwRNSMChCQXffNDwSSMuKAsuyvjqt7ucv6/aOFw73
         a5QqRJjqd+7gFcnjAjFJ0G/zjoyQuThkkviLgypcW0NjOaWRAvE84DEBIxI3miyasuJc
         43MC7hXXHiQ4cJfUMf5dyuabgCK63SYP3A6JVU+nrc5v92K5UnWtYONdXAJ7TvsFCgXT
         PReA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Wx30usIz01HOs35T55D1lEnPqyGIA7i23YAP3P/ZFc=;
        b=WzTEE5RTOCJAhPvDUu3C5X80ALC1JO4erA7KGRzRPor3K61j4+IdS5MXg1Z/62YcH6
         UONM5/+UOUJdOL3YRCHcu8ipfPtXNCnp5v3csWcrnfKJ4wAJjX6ryeq7HuxNm8KX6mD3
         +TYh+f2hMl8K44hBOkA1tL9B6jnSJrlFc87jHlxrtBxteF1/R1sOai5IBK+IhZqQVIeX
         CCUq/3qazIA74Th42j57JH4uQWB3+gbI4amKLU1RIiL3qWap0Kf9E3YggUAI2IpEaRP6
         rVH4omoL+J3+Ti5sQn73nKAfo0FgJE62D5H2n7BTXUUsY9HE8G4qDcq7aIrou5GM9Cmx
         8BYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Wx30usIz01HOs35T55D1lEnPqyGIA7i23YAP3P/ZFc=;
        b=V+C7DuWCkgIOwjOeXzHlqBJT0fvRbjOLMX8KERhIeD1/B+IokjA6Kzqd4metf1lg7i
         ejZnhBE4EIh2OjnBG6NUO4CUkhQTg9aX7OmFOQpUF66rhvxlO0jjD9hUk6DpzhpN6uqq
         NXxx1Wr2mlw0Uvt6I+qZOcHAIuODwkcxMfib8lEQLp1wgUZeh3lYR8FotW2Oail5gtlH
         PkyXImV23s+4Z4Xe3x0J53jVxAphTVyzYoC+uxNM72JXbxxDte0JzbzSGlvPbd2QqSg+
         8b0ZqanqmPZqVgV/+/9kJs123BR0SrnDrcTqmOqfF3v6vVwqLVNc0ycnpHjuJJXlpgAJ
         aVWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530kNmCfs3IJLeNuTLLS4rGhZzupTa4csEgy6Kv+KCO7IoSMKP4E
	FtfCoeu4dooraGveYsW/WSo=
X-Google-Smtp-Source: ABdhPJzAHexUGpIh0oQQL++1IijxStxQSQafBGrrYzOu1+3jGApJUq+DxD564JTfa29Kcf6e1LdEPQ==
X-Received: by 2002:a05:6870:3c8e:b0:ee:561b:2458 with SMTP id gl14-20020a0568703c8e00b000ee561b2458mr661864oab.206.1652203231925;
        Tue, 10 May 2022 10:20:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f693:b0:e2:1a68:2965 with SMTP id
 el19-20020a056870f69300b000e21a682965ls7243033oab.2.gmail; Tue, 10 May 2022
 10:20:31 -0700 (PDT)
X-Received: by 2002:a05:6870:b4a0:b0:ed:a0a2:4ec7 with SMTP id y32-20020a056870b4a000b000eda0a24ec7mr690776oap.120.1652203231685;
        Tue, 10 May 2022 10:20:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652203231; cv=none;
        d=google.com; s=arc-20160816;
        b=x5U4mwMP04UL71D57Et3od25RmG52CXMcH/z90/dW+kCmb2PLrjVooLHtg523BVT23
         uEyMnKeSM9WysEYMgM8vgi4jqAvmuXFM2WI2xtk84TuCX6P5wKhQP7M/UvY56U2EdCuw
         G2rSQ4tRLVNv7Ln+0k2w6+wWrYVuZA3flfd9ZG/N2e+xiM+6wIril/bsy9b6yBDhTey6
         +0Gx7khYlcTMlDqh6JV+AMX6rSGg0yKHKAaRWTWf9i/P3snS4EylBFs8pddSIzc6Q5t8
         Jp6dB1KUUTLAxua6PrKtq7PkUIK8e7D5q21zmafM7g5somw9NrxtMszcKBlzv0O+VCLA
         GsGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qBpP6H1QXIcItowN4taveL7xKKbFDSnKJ/RJbBSFPLc=;
        b=uUHgcpFZzQMPFIf/2yekWxPZuOuEDuBzoDNU3Uqb6jCYLKMjJGUO+L/J1nAJ2GEkc1
         BBWE8mzbglG1MgqB4HiKT5O+JTrhNGk98QmVeMzSSkkTNKDL9MoZhgoEhcszY8bfVY9F
         vJMQEmtdJTZF2PvVne7Fh0liPXMzpaLhi/HjpZ8btumIKxQybI8r9kwK2Y84MF/Ec/aO
         kM2jCLyduwOsEqvK5hGB9iKQtNya6zfJY+GNfYxFspAzUv6NAac2d04UpRjGG2HF4ipn
         PodwV7x9kYj23aRIVJ+OrxCe3R74qilxdnYu7502xXdy23OkZ8A2X6gvisvt53mjKNLE
         Gkpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Lt7mUYnn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id l13-20020a056830268d00b00605f6345a99si937756otu.3.2022.05.10.10.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 May 2022 10:20:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id r17so11780080iln.9
        for <kasan-dev@googlegroups.com>; Tue, 10 May 2022 10:20:31 -0700 (PDT)
X-Received: by 2002:a92:3609:0:b0:2c6:3595:2a25 with SMTP id
 d9-20020a923609000000b002c635952a25mr9876403ila.233.1652203231521; Tue, 10
 May 2022 10:20:31 -0700 (PDT)
MIME-Version: 1.0
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
 <47afaecec29221347bee49f58c258ac1ced3b429.1652123204.git.andreyknvl@google.com>
 <YnpTJR177vJ5G+HW@elver.google.com>
In-Reply-To: <YnpTJR177vJ5G+HW@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 10 May 2022 19:20:20 +0200
Message-ID: <CA+fCnZcCOFR-E_HFjgpz1GqPbtnothC1+cTK6Nu2fOua_1-iuQ@mail.gmail.com>
Subject: Re: [PATCH 3/3] kasan: clean-up kconfig options descriptions
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Lt7mUYnn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 10, 2022 at 1:57 PM Marco Elver <elver@google.com> wrote:
>
> > -       Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> > -       (the resulting kernel does not boot).
> > +       (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
>
> Why aren't they made mutually exclusive via Kconfig constraints? Does it
> work these days?
>
> Either KASAN_GENERIC and KASAN_SW_TAGS do "depends on !DEBUG_SLAB ||
> COMPILE_TEST", or DEBUG_SLAB does "depends on !(KASAN_GENERIC || KASAN_SW_TAGS) || COMPILE_TEST".
>
> I feel DEBUG_SLAB might not be used very much these days, so perhaps
> DEBUG_SLAB should add the constraint, also given KASAN is the better
> debugging aid.

They are made exclusive: it's the KASAN option that depends on
!DEBUG_SLAB. And KASAN_HW_TAGS doesn't have this note, as it doesn't
work with SLAB at all at the moment. Moving the constraint to
DEBUG_SLAB might make sense, but let's keep this patchset as a
non-functional change. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcCOFR-E_HFjgpz1GqPbtnothC1%2BcTK6Nu2fOua_1-iuQ%40mail.gmail.com.
