Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAX37OTQMGQE5QOCS7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 619C379A7A9
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 13:44:08 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-401be705672sf33473095e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 04:44:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694432643; cv=pass;
        d=google.com; s=arc-20160816;
        b=g2NRUDee6zCO5ubvLpHzJ/sc1hy33l1rvMmfFv8ySdyqx15Z0Z2cLh5L0sMMhG08tQ
         222nC5EELVafSYTRo60Jv5Vhrdz1cn17FegcJ7W8fb7Bbn7wISimVocZXq8GBZ9a8azS
         W20uFHfGu0HYRqbRCvB7yPG3oadkRC67fQVNQdGxJjlkOJGKYcYfBTMSf/pSFBK78SHg
         GE/s7Vsibb2jh71kAia5HDCYGr1fa0I8qZ9peqizF7bEJfDqChrNGC6G+IYRArHhcI22
         tUlekVpFDEnQ1CRyq6dDd4ryXkxo0LIJofpfq+GyVrbXp+v1Nt4hpQ9Wf/XEnZfdsYo0
         tBJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AFwTtRdRtzwf+g4v26WjrIcA5OI/ivQSOEONUnJDod8=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=LQzfb9kFH99P48WpcmUkA4MGbCTsPxLAdUlKzjvwxQu0NIP4XiP6LjKVdb5Xl01Vl8
         nuB8aYcTrpSQ8z+IpNJOZfk34dlLIggQ1ZwhBlOE8hHEtrtTf0ZmXUQQtuamzLPTg6uf
         2SBnWjYir1nwwFJNHip29Iu6478mehjcAYEMomp5LITkTl+3gSvW0ySTKthb5EiDIChy
         KGHNinQLMN9LYRJkoQGJmPsRMOd4iBHujDRNsT6RQrMWSVc9oGx1uMfk1kRBDSeNrHyN
         qUhgxx/vzz4r3gFxuudb9MmTEO0NsAbsMe9RoYAHJq61r1Na7uknb2C1AhAxvJxHmepQ
         1eiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=fNT596GT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694432643; x=1695037443; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AFwTtRdRtzwf+g4v26WjrIcA5OI/ivQSOEONUnJDod8=;
        b=OryaO5U2ZFco1SrfnmLMeq3CVKDiNKTfZ21eJMb5J88JbHOvzw/0dGjeKxsF2zSvqU
         7uoZrw4dSb5EI5KcYyvJCUfoRCCi4zjwXXu+/3BL2MH8pYJPXYi1seVLxNRe4H/XYUiu
         ZocqfdqfFscGKkGICLN5+VdoAQGtvlwebjwj5TdVdzPEVCYrIeby1+3fXHIElqTMHnH3
         nsPm8hN/UnwNo/WZm0D3gbaFVv2InK9mUaH3JL9ko7b5E1yTDPM61KjrEWFeoYOQhjJ6
         /5vYEfbKa1c/ppEen5293r+KJbM+nNK2iHlYIuqGwRr+zS3z4BbwXzvJ6bXZsMgUnJ4L
         XRBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694432643; x=1695037443;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AFwTtRdRtzwf+g4v26WjrIcA5OI/ivQSOEONUnJDod8=;
        b=oGZlxpLzYt5jbMvViGSY82ghIS5EMAM1g8x8f9d25DHdv2LkT5MGosLZBMNems8Kzz
         A2vClVJ17ncF9b5n2hblVcNF1tR5iXiS/vz98n4nqZpzji5zDuPlLkm+8BtkiPhxIY6L
         IuIMiVDKuNlAWuFTSEwooBcc9+VWhOfTlNMYgXqaiDvyDS1U0PIgnTvXmw2MLNKttzUe
         pldZgPgPbkbgp5+RHwVw5XN/8Q8n4tnT6r2dfGGYY5crBwHw2z9IWfaahweqj/LZm6Ql
         AelGxF4U3/i2NrbBuPJ+4bN3tUPUfM4BYaak1ua9wxeeMNCW4wCRenp5UPRzX1WZGmTs
         EuRA==
X-Gm-Message-State: AOJu0YxPJlmNYOCP5syiu02j/QRdWBwWwwdcKz9tD4rogMLtnEHL8ECg
	XNJvjRwWS0YgCcQSFMTYQZY=
X-Google-Smtp-Source: AGHT+IE+0V0hjwyYS9vSYJ+QUVkT8aRET0uEylsuIb996qw6zD3fxxKy8DLL70h2o6u9yg5ik22t/Q==
X-Received: by 2002:a7b:c846:0:b0:401:b53e:6c39 with SMTP id c6-20020a7bc846000000b00401b53e6c39mr8467823wml.6.1694432642408;
        Mon, 11 Sep 2023 04:44:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f12:b0:3fe:e8fc:697a with SMTP id
 l18-20020a05600c4f1200b003fee8fc697als1883493wmq.1.-pod-prod-01-eu; Mon, 11
 Sep 2023 04:44:00 -0700 (PDT)
X-Received: by 2002:a5d:444f:0:b0:317:6314:96e2 with SMTP id x15-20020a5d444f000000b00317631496e2mr9035619wrr.14.1694432640649;
        Mon, 11 Sep 2023 04:44:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694432640; cv=none;
        d=google.com; s=arc-20160816;
        b=G26PE9IsmVjXkPopV+tmf4ZOEix3UjM9ovr1u48LlbyJ1a65RR4R24FxO3gUScibMU
         hlL/faiV2YKZuP4qdKJiVOCRP2GX9dZQ2DdAdt4fFZY+PTC4AqzL9KhweecoVucd25gX
         drHSr4468jWjGcSpre3mhdMcZBR1PNui78nZA1l6WP9JLWDWzq0DHBRN5SBa1slCsFOs
         i1q6sG14zNNhgakjilssbT9AWwMNfg8GaTAawTCf8812T95n/G5st9eCx7D3vdXS2UJh
         IXPLHbEReYTbTUbJnaXMwD7KOn/6IjBdUmcWJt9l57MKHeGMuA7rdU6MlnZvbLs1Ia8/
         uh3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FdxNots/ZdhIISnEaFRRuK2rgiRRh92V2Io2TUdmEu4=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=IeAcJtZSHicD3grlSjKG1HIiFFZ2G/+ipG7wSw8E3yh9esmJWKv0NYIGpFyD76BvTR
         67kDs12lW66hDWanSUOz+waNyC4N/U/gCxintpHxJHqcgcZXJAdZ/WfZN7JXxWmR22X3
         74thvBRqKKIwXpVWa/PYoUZNavRCTbD8Qyax9PwxpaCXZVgfdkOIvhoVyLkkOpKi1enl
         3cSIL6PJB3zfu1cbNw/gi/GVnEUemJiXiCifG0qLoTXoiq68cC1ryNsf16NCAyaQyEX8
         esxG1GZPl7h+3Emu8am9rIeq3x6TN3EklWOQ18aa5ZUjj8ULtAMYMZxVApYOc2NA+/kx
         KHtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=fNT596GT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b00403018fc1e6si393542wmb.1.2023.09.11.04.44.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 04:44:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-40061928e5aso49334105e9.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 04:44:00 -0700 (PDT)
X-Received: by 2002:a7b:c389:0:b0:401:d947:c8a9 with SMTP id
 s9-20020a7bc389000000b00401d947c8a9mr7855842wmj.19.1694432640069; Mon, 11 Sep
 2023 04:44:00 -0700 (PDT)
MIME-Version: 1.0
References: <20230907130642.245222-1-glider@google.com>
In-Reply-To: <20230907130642.245222-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Sep 2023 13:43:23 +0200
Message-ID: <CANpmjNOO+LUgCWHPg4OXLzm9c7N3SNfLm1MsgME_ms07Ad5L=A@mail.gmail.com>
Subject: Re: [PATCH 1/2] kmsan: simplify kmsan_internal_memmove_metadata()
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=fNT596GT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Thu, 7 Sept 2023 at 15:06, Alexander Potapenko <glider@google.com> wrote:
>
> kmsan_internal_memmove_metadata() is the function that implements
> copying metadata every time memcpy()/memmove() is called.
> Because shadow memory stores 1 byte per each byte of kernel memory,
> copying the shadow is trivial and can be done by a single memmove()
> call.
> Origins, on the other hand, are stored as 4-byte values corresponding
> to every aligned 4 bytes of kernel memory. Therefore, if either the
> source or the destination of kmsan_internal_memmove_metadata() is
> unaligned, the number of origin slots corresponding to the source or
> destination may differ:
>
>   1) memcpy(0xffff888080a00000, 0xffff888080900000, 4)
>      copies 1 origin slot into 1 origin slot:
>
>      src (0xffff888080900000): xxxx
>      src origins:              o111
>      dst (0xffff888080a00000): xxxx
>      dst origins:              o111
>
>   2) memcpy(0xffff888080a00001, 0xffff888080900000, 4)
>      copies 1 origin slot into 2 origin slots:
>
>      src (0xffff888080900000): xxxx
>      src origins:              o111
>      dst (0xffff888080a00000): .xxx x...
>      dst origins:              o111 o111
>
>   3) memcpy(0xffff888080a00000, 0xffff888080900001, 4)
>      copies 2 origin slots into 1 origin slot:
>
>      src (0xffff888080900000): .xxx x...
>      src origins:              o111 o222
>      dst (0xffff888080a00000): xxxx
>      dst origins:              o111
>                            (or o222)
>
> Previously, kmsan_internal_memmove_metadata() tried to solve this
> problem by copying min(src_slots, dst_slots) as is and cloning the
> missing slot on one of the ends, if needed.
> This was error-prone even in the simple cases where 4 bytes were copied,
> and did not account for situations where the total number of nonzero
> origin slots could have increased by more than one after copying:
>
>   memcpy(0xffff888080a00000, 0xffff888080900002, 8)
>
>   src (0xffff888080900002): ..xx .... xx..
>   src origins:              o111 0000 o222
>   dst (0xffff888080a00000): xx.. ..xx
>                             o111 0000
>                         (or 0000 o222)
>
> The new implementation simply copies the shadow byte by byte, and
> updates the corresponding origin slot, if the shadow byte is nonzero.
> This approach can handle complex cases with mixed initialized and
> uninitialized bytes. Similarly to KMSAN inline instrumentation, latter
> writes to bytes sharing the same origin slots take precedence.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

I think this needs a Fixes tag.
Also, is this corner case exercised by one of the KMSAN KUnit test cases?

Otherwise,

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/core.c | 127 ++++++++++++------------------------------------
>  1 file changed, 31 insertions(+), 96 deletions(-)
>
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index 3adb4c1d3b193..c19f47af04241 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -83,131 +83,66 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
>  /* Copy the metadata following the memmove() behavior. */
>  void kmsan_internal_memmove_metadata(void *dst, void *src, size_t n)
>  {
> +       depot_stack_handle_t prev_old_origin = 0, prev_new_origin = 0;
> +       int i, iter, step, src_off, dst_off, oiter_src, oiter_dst;
>         depot_stack_handle_t old_origin = 0, new_origin = 0;
> -       int src_slots, dst_slots, i, iter, step, skip_bits;
>         depot_stack_handle_t *origin_src, *origin_dst;
> -       void *shadow_src, *shadow_dst;
> -       u32 *align_shadow_src, shadow;
> +       u8 *shadow_src, *shadow_dst;
> +       u32 *align_shadow_dst;
>         bool backwards;
>
>         shadow_dst = kmsan_get_metadata(dst, KMSAN_META_SHADOW);
>         if (!shadow_dst)
>                 return;
>         KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(dst, n));
> +       align_shadow_dst =
> +               (u32 *)ALIGN_DOWN((u64)shadow_dst, KMSAN_ORIGIN_SIZE);
>
>         shadow_src = kmsan_get_metadata(src, KMSAN_META_SHADOW);
>         if (!shadow_src) {
> -               /*
> -                * @src is untracked: zero out destination shadow, ignore the
> -                * origins, we're done.
> -                */
> -               __memset(shadow_dst, 0, n);
> +               /* @src is untracked: mark @dst as initialized. */
> +               kmsan_internal_unpoison_memory(dst, n, /*checked*/ false);
>                 return;
>         }
>         KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(src, n));
>
> -       __memmove(shadow_dst, shadow_src, n);
> -
>         origin_dst = kmsan_get_metadata(dst, KMSAN_META_ORIGIN);
>         origin_src = kmsan_get_metadata(src, KMSAN_META_ORIGIN);
>         KMSAN_WARN_ON(!origin_dst || !origin_src);
> -       src_slots = (ALIGN((u64)src + n, KMSAN_ORIGIN_SIZE) -
> -                    ALIGN_DOWN((u64)src, KMSAN_ORIGIN_SIZE)) /
> -                   KMSAN_ORIGIN_SIZE;
> -       dst_slots = (ALIGN((u64)dst + n, KMSAN_ORIGIN_SIZE) -
> -                    ALIGN_DOWN((u64)dst, KMSAN_ORIGIN_SIZE)) /
> -                   KMSAN_ORIGIN_SIZE;
> -       KMSAN_WARN_ON((src_slots < 1) || (dst_slots < 1));
> -       KMSAN_WARN_ON((src_slots - dst_slots > 1) ||
> -                     (dst_slots - src_slots < -1));
>
>         backwards = dst > src;
> -       i = backwards ? min(src_slots, dst_slots) - 1 : 0;
> -       iter = backwards ? -1 : 1;
> -
> -       align_shadow_src =
> -               (u32 *)ALIGN_DOWN((u64)shadow_src, KMSAN_ORIGIN_SIZE);
> -       for (step = 0; step < min(src_slots, dst_slots); step++, i += iter) {
> -               KMSAN_WARN_ON(i < 0);
> -               shadow = align_shadow_src[i];
> -               if (i == 0) {
> -                       /*
> -                        * If @src isn't aligned on KMSAN_ORIGIN_SIZE, don't
> -                        * look at the first @src % KMSAN_ORIGIN_SIZE bytes
> -                        * of the first shadow slot.
> -                        */
> -                       skip_bits = ((u64)src % KMSAN_ORIGIN_SIZE) * 8;
> -                       shadow = (shadow >> skip_bits) << skip_bits;
> +       step = backwards ? -1 : 1;
> +       iter = backwards ? n - 1 : 0;
> +       src_off = (u64)src % KMSAN_ORIGIN_SIZE;
> +       dst_off = (u64)dst % KMSAN_ORIGIN_SIZE;
> +
> +       /* Copy shadow bytes one by one, updating the origins if necessary. */
> +       for (i = 0; i < n; i++, iter += step) {
> +               oiter_src = (iter + src_off) / KMSAN_ORIGIN_SIZE;
> +               oiter_dst = (iter + dst_off) / KMSAN_ORIGIN_SIZE;
> +               if (!shadow_src[iter]) {
> +                       shadow_dst[iter] = 0;
> +                       if (!align_shadow_dst[oiter_dst])
> +                               origin_dst[oiter_dst] = 0;
> +                       continue;
>                 }
> -               if (i == src_slots - 1) {
> -                       /*
> -                        * If @src + n isn't aligned on
> -                        * KMSAN_ORIGIN_SIZE, don't look at the last
> -                        * (@src + n) % KMSAN_ORIGIN_SIZE bytes of the
> -                        * last shadow slot.
> -                        */
> -                       skip_bits = (((u64)src + n) % KMSAN_ORIGIN_SIZE) * 8;
> -                       shadow = (shadow << skip_bits) >> skip_bits;
> -               }
> -               /*
> -                * Overwrite the origin only if the corresponding
> -                * shadow is nonempty.
> -                */
> -               if (origin_src[i] && (origin_src[i] != old_origin) && shadow) {
> -                       old_origin = origin_src[i];
> -                       new_origin = kmsan_internal_chain_origin(old_origin);
> +               shadow_dst[iter] = shadow_src[iter];
> +               old_origin = origin_src[oiter_src];
> +               if (old_origin == prev_old_origin)
> +                       new_origin = prev_new_origin;
> +               else {
>                         /*
>                          * kmsan_internal_chain_origin() may return
>                          * NULL, but we don't want to lose the previous
>                          * origin value.
>                          */
> +                       new_origin = kmsan_internal_chain_origin(old_origin);
>                         if (!new_origin)
>                                 new_origin = old_origin;
>                 }
> -               if (shadow)
> -                       origin_dst[i] = new_origin;
> -               else
> -                       origin_dst[i] = 0;
> -       }
> -       /*
> -        * If dst_slots is greater than src_slots (i.e.
> -        * dst_slots == src_slots + 1), there is an extra origin slot at the
> -        * beginning or end of the destination buffer, for which we take the
> -        * origin from the previous slot.
> -        * This is only done if the part of the source shadow corresponding to
> -        * slot is non-zero.
> -        *
> -        * E.g. if we copy 8 aligned bytes that are marked as uninitialized
> -        * and have origins o111 and o222, to an unaligned buffer with offset 1,
> -        * these two origins are copied to three origin slots, so one of then
> -        * needs to be duplicated, depending on the copy direction (@backwards)
> -        *
> -        *   src shadow: |uuuu|uuuu|....|
> -        *   src origin: |o111|o222|....|
> -        *
> -        * backwards = 0:
> -        *   dst shadow: |.uuu|uuuu|u...|
> -        *   dst origin: |....|o111|o222| - fill the empty slot with o111
> -        * backwards = 1:
> -        *   dst shadow: |.uuu|uuuu|u...|
> -        *   dst origin: |o111|o222|....| - fill the empty slot with o222
> -        */
> -       if (src_slots < dst_slots) {
> -               if (backwards) {
> -                       shadow = align_shadow_src[src_slots - 1];
> -                       skip_bits = (((u64)dst + n) % KMSAN_ORIGIN_SIZE) * 8;
> -                       shadow = (shadow << skip_bits) >> skip_bits;
> -                       if (shadow)
> -                               /* src_slots > 0, therefore dst_slots is at least 2 */
> -                               origin_dst[dst_slots - 1] =
> -                                       origin_dst[dst_slots - 2];
> -               } else {
> -                       shadow = align_shadow_src[0];
> -                       skip_bits = ((u64)dst % KMSAN_ORIGIN_SIZE) * 8;
> -                       shadow = (shadow >> skip_bits) << skip_bits;
> -                       if (shadow)
> -                               origin_dst[0] = origin_dst[1];
> -               }
> +               origin_dst[oiter_dst] = new_origin;
> +               prev_new_origin = new_origin;
> +               prev_old_origin = old_origin;
>         }
>  }
>
> --
> 2.42.0.283.g2d96d420d3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOO%2BLUgCWHPg4OXLzm9c7N3SNfLm1MsgME_ms07Ad5L%3DA%40mail.gmail.com.
