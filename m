Return-Path: <kasan-dev+bncBDW2JDUY5AORBXEAXSPAMGQE6NC6UWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id F01B06789DE
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 22:47:09 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id p25-20020ab05859000000b006001ac8d2efsf3695695uac.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 13:47:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674510428; cv=pass;
        d=google.com; s=arc-20160816;
        b=aEWOfPKLfqzRVG0IB7T77sSPEQDmhisHOHbYMGwQWgwmHGRC6hHbbd/LDOYMCtiA1X
         CNrgJLNqhQzJl717aGrFODQnDcy5beHECKBKS72dEda5l/2vmda3UcGih8nldLVSUCAy
         y6X7brXThf5hUXq9I1ztuouWz41MWCfd/pCrCn4mmNIXd+ELPeOmYuYLSZIlWknc4Lz5
         3ImRtHDJnRXK2Y+JvW4gSHLjcaLsJzWnk2iQAXOexr9XeKAV0qWFSoHJa6jmdlcP72Pl
         H+M52VU09VJiRYaYYj70JhKQq/aSfQzkSsWOF+RCZbkmlV9RFLW6DosnVMbKlpgGyCrp
         D9pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0CaFbmHKPgyJ/AB2dIAqFSXaM6cGEvseNr2eotLkdqY=;
        b=hYctdytzV4uvYA1dYFBzbSWOl+NXB3hPpj7vuzgM6vULfVLFF/N717lxAv4WHC0jCv
         cHMrX8owwkiePYegZqObGMHRpaeeekAEZy5GSGFoPOeP3jk8/Wx2u5asvu0Sf/rEW652
         ZqT71fc8UbwdxzSn8jpaHyE7iSjSkgRVAtjHnLLKSUCAn/gKdsljIpicmNwDHB9yU0DM
         rO0kh3FxoJJuZZK2u20WGTvj/x9kkNLLkIx8M+Ocx4IQu/VLkzdq/mNUieTrNRPYuP9S
         emURI80dk9t9kaROSVN09AbUGz6HfYG4aFR1Pp5F1L39yNJwgYUQ38b1uIxsgtMrVMHz
         6/Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I7B2lxMU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0CaFbmHKPgyJ/AB2dIAqFSXaM6cGEvseNr2eotLkdqY=;
        b=VjMorD/twVU5kTtw473i4vR8PKYtrhIABSLIqON6rVGCbd5/jusnGdQPjRzSWVfnpQ
         +4gBsB9PoSYEiyqQuaTNqIf6lnpJJ2Dl0ezkQSqbELQJCKIvVHwXiAatV1v1q1SkQcT3
         7tSotcudGD261pRtaW8GbdfQJPiZJFWISnXbkQMpMpwuZ/5/MsWeF30ni35lyGxA0gHx
         rhvcT8A9x7eWhTkPezea5PqDZTbEfAmBUlvxnXm7H3wZZyS3dHiO8u5r9VpXgOCIfJE8
         hZ7CEl97Ch30GzGOHynkZDTUXuDHV2AylNFcmb3dTkt3sbb1TWLdDAVOCZoWhPNr4Htb
         1r9w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=0CaFbmHKPgyJ/AB2dIAqFSXaM6cGEvseNr2eotLkdqY=;
        b=BWNggJAVYG1PxxGQHSJQ0TnagVdBKS06pNvyQVgElaOJZ+WBB0yixd777r1uNvv71h
         0DED4Bp0tv8ErgwfZfDKmPmKyhortI7CoTiIOPSOcUw5f2sNjpny7do2YrCUpv8eODiD
         c4YT/aL07vYJKki1wGWTmnzX8kjgiFXUthKCtXWmvHxOwOXsO8rIU9OB5M/aQal7jHkp
         5L7HJesO1j7qw9idhmETGRu8c3DHN2OTNpyj4RAVXYMSLkpMOh2eTaA6ClS7hj1hYmkn
         BW1FIkT9CjGugGit+cNptNCjf918o709fcEl6TddIvd4BdIGpubkUQkXDNNdOR13+qGZ
         REgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0CaFbmHKPgyJ/AB2dIAqFSXaM6cGEvseNr2eotLkdqY=;
        b=Say+lwqLtIDLJ8VrszniXBrgbaujKbDSTx9fGYrx8YLDDgQx/9dLiBz6bRbYMKrPbg
         MeanRFZxTKxgx87DUvw1dt9Dm3MQjRqzQtOkYd6EuDXx7H5XG4u1DRImjmW1rzeWvZyi
         A3yNuAV4Rf9SOECiDChnecEasColopmV6XT4Wa7ZwZapb65pFZAotpQz8r7uWh6rGmxZ
         s4IfSJGP0OllbG00XKwti3jUtPCUhITWz7gYsZP5yickN0+iDdaSisps9UJ3pjTOXOhH
         3ojVVja3IGx35oAU4et6P1Z6U/3EZKzIxZn6WE4qDUMW6hu8mJkGBfwJUibwfi49sJnZ
         3KZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koCI+XSvqvLRFQqqEOG0iXL3J5CzOKXlaa2/I4tIjXxySViWDqk
	+72lW6Q/g8rHVxAzHlnOkKs=
X-Google-Smtp-Source: AMrXdXvhoxDcfJAxkFRYdgG+cqUHDTv5U4JNhMEjJzyCYOKpyCy9UWS/wKO5vUaijQ7hfiqMlEYhSg==
X-Received: by 2002:a67:fe4f:0:b0:3c6:c5a3:9ad7 with SMTP id m15-20020a67fe4f000000b003c6c5a39ad7mr3449677vsr.46.1674510428740;
        Mon, 23 Jan 2023 13:47:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:20ca:0:b0:3b5:df37:23a6 with SMTP id g193-20020a1f20ca000000b003b5df3723a6ls2354127vkg.7.-pod-prod-gmail;
 Mon, 23 Jan 2023 13:47:08 -0800 (PST)
X-Received: by 2002:a1f:3f15:0:b0:3e1:6dca:748d with SMTP id m21-20020a1f3f15000000b003e16dca748dmr14242053vka.13.1674510428125;
        Mon, 23 Jan 2023 13:47:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674510428; cv=none;
        d=google.com; s=arc-20160816;
        b=fenL1M06+FdZcaqP6mbbuPLyLx993xiLjl1YwI7WS7/QmCSlvhn0bdg1lC8rdq4bnD
         026MezU9lnxAoyxOYPGtrfYyg3Pkdbvgwq6u6NGw9j+mxtgYZhgW4/2v7sr2A8RYEiOO
         r57tDq5dPx6zwsuR2ysa1XIOsHg4DAKI5fdxr7fBb+GWud17UgWhNhr/FpWH3Jl/t9gl
         4Uk9qhT8e0W8xlIwOwkfXdU5I6VV5VQU2EB7F1idxmPhZo70oq7ETnfdnJS2a6fIcuhW
         FrgMWy2Q60wDTz5aG0LaN2HlMNbGoyWYuNPzWoH4gfRAAwbOC8I1zapfhC6v34xZ4GAn
         Pi5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bNWIhXG5Qs/cS/Kge9YI8j6hmkwjT8WYdLmFW/zVK4w=;
        b=wqfH4EKWsyUQG2lEV7BB7UKDC0yDhPz0KdojRMs9KByXVW6pHyjrKTaID+aeTj7arh
         rdXLln0GiqDJ0sHE7YANfEdBuB67a5YRK9p+Z2QpGXJJlrIiIUKOZxwG+IuZS5e4xxD1
         PnbGouzdGpH6eX80o0R6ZcZB4daraKmAHzL+UM6jul0RDTVV4w2KMQ/TRAamekOHkUOV
         cZ7BxMardfgEanWZiDAqHNRNNeavUu1uEvniaQXVYhQvfakvzY4hgtTLBLTJ6QXocjiq
         WZRoIdDseyQlzRyKK+JTg83SjUFSEdCkVOwNSG3j3n2UHrrfs53E5Pqge9dYFClOlGrd
         BsBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I7B2lxMU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id d28-20020ac5c55c000000b003d53e3ed270si18310vkl.0.2023.01.23.13.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 13:47:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id s67so10057796pgs.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 13:47:08 -0800 (PST)
X-Received: by 2002:a05:6a00:3496:b0:576:f9e2:a968 with SMTP id
 cp22-20020a056a00349600b00576f9e2a968mr3320171pfb.84.1674510427720; Mon, 23
 Jan 2023 13:47:07 -0800 (PST)
MIME-Version: 1.0
References: <20230118093832.1945-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20230118093832.1945-1-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Jan 2023 22:46:56 +0100
Message-ID: <CA+fCnZcS-p5nCALg4-96cp+sXNZSvN_u=L+=xK+zaH2rigJMKw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: infer the requested size by scanning shadow memory
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, qun-wei.lin@mediatek.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=I7B2lxMU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a
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

On Wed, Jan 18, 2023 at 10:39 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> We scan the shadow memory to infer the requested size instead of
> printing cache->object_size directly.
>
> This patch will fix the confusing kasan slab-out-of-bounds
> report like below. [1]
> Report shows "cache kmalloc-192 of size 192", but user
> actually kmalloc(184).
>
> ==================================================================
> BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160 lib/find_bit.c:109
> Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> ...
> The buggy address belongs to the object at ffff888017576600
>  which belongs to the cache kmalloc-192 of size 192
> The buggy address is located 184 bytes inside of
>  192-byte region [ffff888017576600, ffff8880175766c0)
> ...
> Memory state around the buggy address:
>  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
>  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
>                                         ^
>  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> ==================================================================
>
> After this patch, slab-out-of-bounds report will show as below.
> ==================================================================
> ...
> The buggy address belongs to the object at ffff888017576600
>  which belongs to the cache kmalloc-192 of size 192
> The buggy address is located 0 bytes right of
>  allocated 184-byte region [ffff888017576600, ffff8880175766b8)
> ...
> ==================================================================
>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=216457 [1]
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> ---
> V1 -> V2:
>  - Implement getting allocated size of object for tag-based kasan.
>  - Refine the kasan report.
>  - Check if it is slab-out-of-bounds report type.
>  - Thanks for Andrey and Dmitry suggestion.

Hi Kuan-Ying,

I came up with a few more things to fix while testing your patch and
decided to address them myself. Please check the v3 here:

https://github.com/xairy/linux/commit/012a584a9f11ba08a6051b075f7fd0a0eb54c719

The significant changes are to print "freed" for a slab-use-after-free
and only print the region state for the Generic mode (printing it for
Tag-Based modes doesn't work properly atm, see the comment in the
code). The rest is clean-ups and a few added comments. See the full
list of changes in the commit message.

Please check whether this v3 looks good to you, and then feel free to submit it.

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcS-p5nCALg4-96cp%2BsXNZSvN_u%3DL%2B%3DxK%2BzaH2rigJMKw%40mail.gmail.com.
