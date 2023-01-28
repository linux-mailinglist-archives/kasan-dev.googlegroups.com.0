Return-Path: <kasan-dev+bncBDW2JDUY5AORBO6H22PAMGQETG44KMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DBBE67FB61
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 23:37:49 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id c2-20020a25a2c2000000b008016611ca77sf9084102ybn.9
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 14:37:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674945468; cv=pass;
        d=google.com; s=arc-20160816;
        b=GrSgWKeVQ1ZFZ48G99R0XR5VwzHxCipT607mZw1Kj/QCSlwTL+6NhOtucO9n5N30we
         /fqQ+uv7Rk/Y3BUzcJcZaOYv5pJgi1aUCBV2H8xHc2RzDux7AstKtnQcIiaYELP6tNIp
         HO7HfgEaU2/a+4pLkrK3cvgKKCiG9r2nQdtr1wZFga5KZDU0BxHwIFDgkvK02jOEVgIP
         L7oOTdIWQoKT/KQmCqHJ/BuVkerTc39PeOSbglBAySUslxkJ+StJSP4wF1WckJtqfwVR
         K7k1198ir5EhWHYJAs7fQMLjIDZ2eLvpznygq+Qe/AGEuCWBO+d2vDfD0pJ0NTPY1d/o
         8tqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=HUxvYcKhiKB2Y1T1fGI71Gw42x+BQchTBBiHua4uPjM=;
        b=BK+CAumCjlPZ2nHSFfKLc3ZdpW+Dl+wR02rj8cmWV5qI7SIkyvai+7QwQwNSF8SxHV
         qRdD3rMJk176khwSBUtbCfK/9H3h1X4r0y9UupJweLP0PK/elbTbLlD6hyQnH3Y56UBt
         INBFyQ0ThcHh+mPVUvHUtgfSXnDvKDlFNWKiBoeyeyObDgdU7gxAoLXk4kURUjg9mBcV
         3OFCClT2gJEhzyHcfkarFFFI+DWD04RuGVtP8duwVBYDDxjU6sEzGBoMaycVtATyeZbY
         NGv6aoWHbNWnLXbFSMUckStPY+5jA1wYMB8y3vXplZzviijJZhxCqOD833UP/hnb1Vl6
         GxSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gDrOrkXX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HUxvYcKhiKB2Y1T1fGI71Gw42x+BQchTBBiHua4uPjM=;
        b=P6ZVuAtEAYWxmeuOyDSONZWmzOPj5RzMhFIQTDukLy+v9CxBBYixTw5clJjWyXfcwE
         xPrlEnthbMUQmzJKq/3Og4Q8K5Cpk/p2QprI84kOhZoVlR3oJQA+vWumk/jJ2RmZ+P1m
         oVaY1q+tnTOvWlWS0Qm2x21FsfdVAOdznBsABOk3R06A8IFJGq8eOLBgMcfeYpvhUZAM
         7oCqdCUyGWCew0YfmiAKBTQpXxDzNknl8kw21y3sGQ34I/gjcLKf00OfclAJKhOTiaQ4
         yNQWiQ3+anRJhS+FdlAyfp0UKUQATET2Pe4jvPWliJ1jP4k8WJywnhxiShiTNsKfTRrt
         IP8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=HUxvYcKhiKB2Y1T1fGI71Gw42x+BQchTBBiHua4uPjM=;
        b=OYeR1bZ+KlaN5YdRWufWVPz88Znp3d3euJrCeBgq0WHjdfO3wLOccy50ZYiPyFYoAk
         Y8jngZzKDpjvhFRoAN8e+lmMg6CkU29IIohPttXwQXIY7oKYULewASHIZhQaReuUpXd6
         dgQ+rBXcBO1xAjTrXisfiVx7zNWPoKn/tVYljOPUFiBnnjc73rKRZmu4CX7ZcCpEXHOX
         rXl152mWOJQLe0ZJSkNpw+QGvcqZokf2MS8BVdMsyqzPuNgK2Lawmf3GI3fa3ElOOHFc
         ZJRHDbhdDGQsNj2S+nq5TQApuRYclMuNO+rIZO/IyGbg9LOZsjIrEXAZPOAbzrERxECA
         yPoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HUxvYcKhiKB2Y1T1fGI71Gw42x+BQchTBBiHua4uPjM=;
        b=0EB9OJS7RTqC0KohKqh4fXrT/d0O7gYwSCtRLSSg/J4NBopW+lN2TVjBHgDfrM9xNO
         KbcgHfW3nXaLeBqNkY5Dq6BWYiyzdSK+rzwFTWIY3f9L06PSahemGuN3iKMBDRBKi8X5
         HVH58dMxUmW5fE8EdTQPn63pasxS4Hr1eslvjgL6xHEjGOg8Rf4J9yvcOvFe/xEbY9oK
         GoP/BHt0pNtozjjPxZIOhsWmZJKHD9cgzdempVv44paU1m4MV1s0+d57a0WSZUuPjUtF
         AMF6mVp5pMKGHU/7GInK3/uKbjWYZvkZRdYpYHZv31jirjBIG6U6xEjQmckwZrtZLCOH
         /KjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kphG8KsibHm90qrIaos8qWX157Zy0hP+V5XSL62V6dL1Ojl+Ioa
	ul15/TLSYHWFNFSRuYsAubQ=
X-Google-Smtp-Source: AMrXdXugRtd5bmLYY0dHljfcSU+sUIOkm6Z5KAVVxDM3ARS8yYrEuJGUb1L0t2WhN0qhu4oIHhPT7w==
X-Received: by 2002:a81:160a:0:b0:4e3:f87:8c24 with SMTP id 10-20020a81160a000000b004e30f878c24mr5933264yww.248.1674945467800;
        Sat, 28 Jan 2023 14:37:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:f541:0:b0:3fe:c52c:dd9a with SMTP id e62-20020a0df541000000b003fec52cdd9als5620031ywf.4.-pod-prod-gmail;
 Sat, 28 Jan 2023 14:37:47 -0800 (PST)
X-Received: by 2002:a81:a105:0:b0:506:46a6:ea8a with SMTP id y5-20020a81a105000000b0050646a6ea8amr2580564ywg.28.1674945467193;
        Sat, 28 Jan 2023 14:37:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674945467; cv=none;
        d=google.com; s=arc-20160816;
        b=D7FiefPTT5SemZ0WVAfFoJe0hcPxqAmOROlKQtSmuS/BIEql4YsyhQuX8cjbuA3yuB
         Ubas33c9RoMCj/djrn54cbRYLF2F6XHVCKuAVZr7qt1HNMdP4zfC1KlNxBVA/eP0uvTY
         7ZsL5F/4gzemVc3eR9e/+kEDRioD79zDpdY7QQPzx3zgQm6ED+hcO284Q4n4IpcVhYeh
         K2y45jNV7bAaHUC7tGBVeuBYySKLhWRGHCKHGzvUlpE4rnf3w0ciFqtKVVmWZvP0fvGA
         slSO3me2EVo7O/VW3N3K+Pn3Ewp728iVvDbjFqsWf6yNvDq0w0YnSVCn/j/vNdk54fND
         Xm/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g2fjqw/303bMNNUpoe3r4ayfN5p/kfqZGtLtAxKocJg=;
        b=PkGCUcEJ2JK73FrR0Y3BYFo05tAXxNCg1aUlZPsH16HoF5RmVXxe2fJ10WjqcPoz3J
         604q25PkeoXkZk+0/QgakceNlzejX1IS/XcRBZKUBegJMk4UQAS9/R7N+qRFkfKHuadb
         6xZ7kl26YIJ51JPIkQlLEQIRLiBJqncTvaTcXufPTOAE7w8fZWPuduCJHOc3cGRDjBBQ
         oFC8/+ZSiTRjIjqKokYA1ua6LLenslGQkeKFXO+s3k9n+duEqkUiKurwao8RQNJPPH+o
         yyIAKYTDtz92SqicZza+nkxlQucO3tvpGZWdxFe+spPn4QIv4+kYW4GTv6mpd8nlFZes
         3tcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gDrOrkXX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id h184-20020a0df7c1000000b004ebb8d55a14si1227614ywf.1.2023.01.28.14.37.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 28 Jan 2023 14:37:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id 5so8260091plo.3
        for <kasan-dev@googlegroups.com>; Sat, 28 Jan 2023 14:37:47 -0800 (PST)
X-Received: by 2002:a17:902:aa4b:b0:194:b3c6:18ee with SMTP id
 c11-20020a170902aa4b00b00194b3c618eemr4707438plr.29.1674945466747; Sat, 28
 Jan 2023 14:37:46 -0800 (PST)
MIME-Version: 1.0
References: <20230128150025.14491-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20230128150025.14491-1-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 28 Jan 2023 23:37:35 +0100
Message-ID: <CA+fCnZdSvTR=Ug3P9ZVxq9AG9Dh+TqLxDMRVOhvE8Sr1a2Oq4w@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: infer allocation size by scanning metadata
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, qun-wei.lin@mediatek.com, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=gDrOrkXX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::631
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

/On Sat, Jan 28, 2023 at 4:00 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>

Ah, I think you need to reset the commit author before sending, so
that the patch gets recorded as authored by you.

> Make KASAN scan metadata to infer the requested allocation size instead of
> printing cache->object_size.
>
> This patch fixes confusing slab-out-of-bounds reports as reported in:
>
> https://bugzilla.kernel.org/show_bug.cgi?id=216457
>
> As an example of the confusing behavior, the report below hints that the
> allocation size was 192, while the kernel actually called kmalloc(184):
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
> With this patch, the report shows:
>
> ==================================================================
> ...
> The buggy address belongs to the object at ffff888017576600
>  which belongs to the cache kmalloc-192 of size 192
> The buggy address is located 0 bytes to the right of
>  allocated 184-byte region [ffff888017576600, ffff8880175766b8)
> ...
> ==================================================================
>
> Also report slab use-after-free bugs as "slab-use-after-free" and print
> "freed" instead of "allocated" in the report when describing the accessed
> memory region.
>
> Also improve the metadata-related comment in kasan_find_first_bad_addr
> and use addr_has_metadata across KASAN code instead of open-coding
> KASAN_SHADOW_START checks.
>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=216457
> Co-developed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>

Or change the Co-developed-by/Signed-off-by tags.

I don't mind either approach.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdSvTR%3DUg3P9ZVxq9AG9Dh%2BTqLxDMRVOhvE8Sr1a2Oq4w%40mail.gmail.com.
