Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGFFVCPQMGQE3ZBIDWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id A2D6A6942FF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 11:36:09 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id i17-20020a25bc11000000b007b59a5b74aasf11959344ybh.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 02:36:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676284568; cv=pass;
        d=google.com; s=arc-20160816;
        b=NV+PKkW2eU3A20Cx0a3tg20oNoxGHp/N4uN6pRrV0Rgxbx9WhG2nw0N9ppgrXXn5Og
         tXgzuSLfBvXBxMJ4Y4v1jjX1n2/52uGUp0L386Wi4oCJJbk+9noi8P4vtSGDhXWIWBeL
         gbrYUiZwmnVU9o4L0z6W/ZwhOsL1/RvAiSlH1eZTYFO9nrt+JNdC/MeUuM9elToslCb3
         GIZ4joT09FeSWupbFdD1c0tKUtOBYr6Tl/InG39WUik/IURQsReumR7ePxXljQvd1FJz
         Vkwc0Jvt/j40kIUcjOh3d7D/DtCERPOI1RyZ9Av34orhRBm78RO+UVcuW4XLfQGr9s75
         T0Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gnWbhLY3VgoYP/id5uu9F5UO6AFbL9csQQdHZLbBTHk=;
        b=mayOTVNVvjFpRwBOLlV2GQDzmeuy6I5KMZ0LCGZCKvDJ1CjIfGpxGaz1W21Eefu/jA
         eam/1AbxlYdNRZTM9bzV9OEr+PfOsedgbM6UwiHUvaWgzXNDqJBePhlzWN6y+nZ2tyZ6
         JWs4JtQTeRUk4LFVbIbA0HK+01/5y1jPYQGRRWQZiGpk+F4oe7Luytow5t/TWOgYUqWC
         r3xvezjMPzGXaFC9+/KQ2UpqOq6vevESp1UxKWkox2BwWq83sdYlTD/SM4gqhusmv4Wl
         V8MIB+sKe476xaMtynjmqgo62fPtb8VE6GEIaK5QWIfn73XD/E5HkAzjqa5qF8FWIuPb
         rNVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IG2Iretl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gnWbhLY3VgoYP/id5uu9F5UO6AFbL9csQQdHZLbBTHk=;
        b=POm+bvyS/i5GwZkVF8TqgEmzPgarfiXV/0jeqQA074Ux96t/6dGhzbEpq4VWU9unSg
         CLZDzOCwjFfyiYoqKaHJzQDF8ZNAhv7kU4VEKjDNuWZD+XpX93xGQCY2oSnWVOo477sL
         P7/Q1GAAdlW1PLGqJZYwoj7SsKxDx5UMdfsdKLBnErCbSM2RGGgcNi1Sa00RM69TXnpY
         fvFXs5elWoChzrOsa/+8i+jdwanqrzfTDXaMyGInm001zlZBvbCT/z/f/svroLL12Qkq
         ZiV+Zs7tt7rnu5pevh68BdHMzJJ6FD/LRZOZuGBJMae1v840MxKXhLSErIwKva3FDkj1
         LkuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=gnWbhLY3VgoYP/id5uu9F5UO6AFbL9csQQdHZLbBTHk=;
        b=VJPD8GJjjnjYwxPnzXk/znJ6yBUMrze06rdIoYC2nVfA1ySluIaNbejzC+HH9jTWwn
         Vu/JjSHdUgLZmU0KX03KzG6mUPPeB6LquWz7qKL67qVcRKSTjn7zU+gVRmmo42yrNtd/
         XIYyzeppBcwwkHsl030fSsk5uWbKxPYfHgUFHIBRrO8qCeM0j0WAUa6VnHROfuVJswUg
         MfCxXXqXrJgGCYqStE38rvPiSVbh5WUkC4EBqbxYlmIOpI49QX7OC7MH7DgEa1MGe7Wo
         9pKNrq1xIeDrGuE0flWBG3XDZp8PmobHj/uZS9wwqO3eYOPdOy8Tqs8saRQcIZ4Xqbpn
         jjbA==
X-Gm-Message-State: AO0yUKVllJ2+SS8VvX10xUeCbHi4xQ4GMMHrB944HtLhjoZ9MX0vSAVi
	/Gi9vr/DD2Kh1lmrRSKbmFM=
X-Google-Smtp-Source: AK7set8s7Vyr2LgTCMHbYzkAbr/TUvdmqpY8IkeEphnoCc632dZcoLiOrj6M9hYdE5yXRKVGthDyBA==
X-Received: by 2002:a81:49d7:0:b0:52f:65c:9334 with SMTP id w206-20020a8149d7000000b0052f065c9334mr672408ywa.165.1676284568422;
        Mon, 13 Feb 2023 02:36:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:29c:b0:52f:3dfb:b256 with SMTP id
 bf28-20020a05690c029c00b0052f3dfbb256ls211846ywb.1.-pod-prod-gmail; Mon, 13
 Feb 2023 02:36:07 -0800 (PST)
X-Received: by 2002:a81:e40d:0:b0:509:a17a:7374 with SMTP id r13-20020a81e40d000000b00509a17a7374mr16006835ywl.3.1676284567853;
        Mon, 13 Feb 2023 02:36:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676284567; cv=none;
        d=google.com; s=arc-20160816;
        b=MmM9bAOanWEsSzkNbJrEO6TNh+UX7xaQ074GE+zd5MeIDTI3EmUk15kpP4jf99xVhZ
         LgvYJYdoiV3RWWOl6dI5hbKHce3qCZvjAqPpGexsBqZbYSetw8WGd6qq6dI+vdN1CE2i
         BPaxXJIVpke/EIKG0aaubXhf8C7ZsyrzExseoI3uGDlD2m3Aoa4ctLqCE44CjtyuWxfD
         +Wa7bhLcrHjJkOTN4J97rAXT09ZTcFBrbC81jfDY1xKfRNtNt++CQr2RQjzwofgrgkNO
         oFc2JQUU57oDEa5HlAd7YGslcK4AEthIQ/XEv5UZQRj1CLh4nmVawmOQIeLjGntHlyYS
         V0Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MB6QgxzH0xV/jeUMQj67Vw4mnLp5zoDu0fxoHPLQUaA=;
        b=OHDOh8EsbbUaeMHPo0+R23fhrzxwFc2trNJYgvljCv5Ru/mb6GGkdG3MGAdnCO5THx
         t9VAL66hMnq1RlY0Rzjtu1AYIQOSdyCFbHVaKudlHFlUuwxRsUTj8B6JdXsXZiVQ6yxN
         3KncOOZwf43ICtX5FPrQHAe5HzA6fYzZxuukXj2FGqxipADkGv04z/xhOKG2WubIJwW1
         52sKRx2SnVdNaTkfBSTNjGM7aBqTX/2nJuFf8jFd1bu3eb8Utgwcn1FOaNVjquHC6Hxk
         jBYGiIGo2PVgg4WNbZ0B91wWlXYtibvLm7+h2DK1SPuxGZtV2Ho7CwhZ15SxszkLLeu3
         lyyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IG2Iretl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id s142-20020a257794000000b0090621221d35si786494ybc.2.2023.02.13.02.36.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 02:36:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id y2so4314204iot.4
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 02:36:07 -0800 (PST)
X-Received: by 2002:a02:a794:0:b0:3ad:3cae:6378 with SMTP id
 e20-20020a02a794000000b003ad3cae6378mr12237646jaj.16.1676284567286; Mon, 13
 Feb 2023 02:36:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <923c507edb350c3b6ef85860f36be489dfc0ad21.1676063693.git.andreyknvl@google.com>
 <2085e953-ff9d-4d2e-cb35-24383592f2c4@suse.cz>
In-Reply-To: <2085e953-ff9d-4d2e-cb35-24383592f2c4@suse.cz>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 11:35:28 +0100
Message-ID: <CAG_fn=VHAJ4tyVeEv4ZUcP9eAt7+Teatgfu6APdEDM6J1jqGhQ@mail.gmail.com>
Subject: Re: [PATCH v2 09/18] lib/stackdepot: rename slab to pool
To: Vlastimil Babka <vbabka@suse.cz>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IG2Iretl;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as
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

On Mon, Feb 13, 2023 at 11:20 AM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 2/10/23 22:15, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Use "pool" instead of "slab" for naming memory regions stack depot
> > uses to store stack traces. Using "slab" is confusing, as stack depot
> > pools have nothing to do with the slab allocator.
> >
> > Also give better names to pool-related global variables: change
> > "depot_" prefix to "pool_" to point out that these variables are
> > related to stack depot pools.
> >
> > Also rename the slabindex (poolindex) field in handle_parts to pool_index
> > to align its name with the pool_index global variable.
> >
> > No functional changes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVHAJ4tyVeEv4ZUcP9eAt7%2BTeatgfu6APdEDM6J1jqGhQ%40mail.gmail.com.
