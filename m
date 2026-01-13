Return-Path: <kasan-dev+bncBDW2JDUY5AORBGF4S3FQMGQEOY5AMZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EFF9D16247
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:21:30 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-64ba13b492asf8628953a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:21:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768267289; cv=pass;
        d=google.com; s=arc-20240605;
        b=L5VY13lWSOijhqtVT2qysgWxwrYqTOBX4Sz8Pyp4bnzTcgxXiR7dbf3MJNX5OgWYJF
         NQcsUHqelRIz9W2ExqYKSEkx8j+Y3nhA7Dll3emu5lk0levHzTvNVcwPbJfMB1nXa3yd
         N4smxV73OpgisPRw43aIgRps6egBL6NvKskEvNO7MCpwaUZbcz8c8p+btdlvOpLUX8e/
         Jggra+WWtrmNVJCD2UvGaYz8s+di1DANyFaxlAtchwN2Km7Lh7S6kAf2317RONl+4SjT
         8bGMVDa3U0m8A3e2oHymNqDXjf+p6Z6VZ+CW9pnhrzRJ6TKHyQeGPGAwx7dRNa1KWfEC
         +fVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ZtLbl0UriHsm0FwnJlyZF7n+w7FrkxveGU3iSr9krS8=;
        fh=k0wZfi36GNPIZ0oNwr+g7VF0Q8UuvhqMNVl5uhvoMQk=;
        b=NCknnVeXpP4lUoJy21c00gCdFkI+LmIUFv93+T5qSRlMN/gHuDUeh9+zeacsJN7x+g
         O3RzOOBTJSNaNwQZ+lyTrsKSZEewOamVVPtOiaQ3PxoeFZzvL2szZMAWHAF/AbTM1kg/
         DmI9Kb8I9/8MPd+bqVwFPWevSr7AiI2CUqeOVMV38HQxRMsQusJT8Luv4ZFgFcc/xnHa
         RwjI4H4sdsah3u8hYZ2yBi+4hEkZymJQxrJ42ATCJ3XPz7LopJJyFUNb/GVI9asYI8j1
         eQZAYkU53GhfQe76p+EX6egLMllJd10956oiRT7BVWUhu0FIpKAW6GYit87obIlqe4ak
         YnRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cpB2/QmG";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768267289; x=1768872089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZtLbl0UriHsm0FwnJlyZF7n+w7FrkxveGU3iSr9krS8=;
        b=p1Ctsp4GdDNIAtM8CQvYKXrbEFvHRxvXI9hnyjfHUk+d9poUvNYDR5ESP5eewtI65x
         S28zwai/4zzS84mgHZgG7eklTZUei9lwUggrnNDaZ8IWehDAau97uq47atccm/1XOLz9
         VKfPV82Err7fOdzJXX0pWgVnFZRPaBJGfsrnLjKuBVscbdHR6s89wp6h9JSfZExHwKu/
         nlpHwYfb3rvdkDbc0zsISm+QnsGo1EZJQ/EQcX6WrfcqMIgzGeq3H+8C2119Q0zS2H/q
         P78CFXjTcHGNFyTBJBPWjeJzNJbqa6wnAosTElOPFnKNybmNanI0j5amOX/euZpJ6QWS
         Nk5w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768267289; x=1768872089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZtLbl0UriHsm0FwnJlyZF7n+w7FrkxveGU3iSr9krS8=;
        b=BoEHc6+PryVEpLeJVsuYyInzTLySeeDGX3utuaXGhshh/MzxlAaDvGEbBccFaHG95g
         B/iWiBKaPAEFdYQ5K1jTh6QHPq9lGJwiy32rcuRGaEpk9drcQjRXmqMCeXxxZC7qs2Yj
         IvLv1sxGiX+9GRl119e5LNOZrpc4oj3LRE9H0AIkEkS6CIADZZJYWEFp0D+RONCNgb4u
         nclbRfn4rHlLO7cLNzV9vFBlQfBgESVZ2TydwBQnjO0UGhMnQ2y8i/hlCE9afPknfPo3
         PH6PB/hVumXItoplK1TDGYhwP7VhLnZbuuav29+r233kFz6yC554ghVydqQmM5SzIjFk
         Hrfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768267289; x=1768872089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZtLbl0UriHsm0FwnJlyZF7n+w7FrkxveGU3iSr9krS8=;
        b=VlXS3ZZ8mdPgzlD7zAoXoKzG0Fa2Zv+sTxWoOJKTnw/TBZWmyRyzHbpNH6vUw7RGs5
         dMy1qTW9mLoWIRqTmmI/kX99GK2y8aqAmFFxWX9H4Lu92Fv2KlT9PTJucdnIhjeFkFqH
         jZmyBgjMoVmPKnRjBr47gE2AdCI9rlE3hH6t7UZyMvi8P5rD5CB5CqCxrfrM77mbj5bx
         250YUQw1NzqLCQsSVYq/LCX1jjdrwSTxozSB2bzt89ce+Q4eXaFzLvlYdqpxQEhAhadJ
         kuDUwvexjPY3mXg2t85KTiNlAX4EqhGBXXQVOxhHLMjWcIalRAf42n1h4Sn/DIf+aHsB
         TncA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2FAdRJ0pCBoJLO4mjQf9hyWwSnB3zAETZ5EEPuR4Pd3t8A2FhhuFTAn2R7kz6YNIsN/pEhA==@lfdr.de
X-Gm-Message-State: AOJu0YxT4JcC2Wp8hcfilVvzQOyC5jRwkCPH+sIz/izvQEpkQ2eCmIuk
	Ru4h2xypulgCjbMPZzg6vvRqxT3KlC+BSMma63qLtt5s7Ucw6N8ke5Pi
X-Google-Smtp-Source: AGHT+IE0I/QnDzdYX07OE0Io/VsH8HzEzs8eEuNLGFbuSZJlH7+L/xHAWsV43BoeMGkEuOnGWGG7ew==
X-Received: by 2002:aa7:cd8e:0:b0:64d:4f75:aa28 with SMTP id 4fb4d7f45d1cf-65097e49e0amr13946940a12.18.1768267289331;
        Mon, 12 Jan 2026 17:21:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ESRhPbwBrr3+OYY9t/NxgoqL7rd0sDYsBuIhao5HgsdQ=="
Received: by 2002:a05:6402:3043:20b0:64b:9695:8dac with SMTP id
 4fb4d7f45d1cf-65074a03e55ls5279338a12.2.-pod-prod-05-eu; Mon, 12 Jan 2026
 17:21:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWn25LTYaQzu3UVSJlQbVIvebrluIXxqwwqiRHyKVkRQ52iJMlQhp2fgtrEyJm+AbOL/pFfSuXGw90=@googlegroups.com
X-Received: by 2002:a17:906:9f87:b0:b73:2b08:ac70 with SMTP id a640c23a62f3a-b844539fc4fmr2006301766b.49.1768267287152;
        Mon, 12 Jan 2026 17:21:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768267287; cv=none;
        d=google.com; s=arc-20240605;
        b=TrJXAcea+7X2zs5YEBMKllC3BUcD5RQTnnSVCZtvBoQmRDb16X4kb+DSs82FvzzfpU
         VgmxzXPrPgrHjgspL1nbEo37en44mzoS2JTH7+lbp+6pk0msN+ruYboWdGSHsjb5eauD
         8K4dPq5lXAtXkV6wIKOWfEaqD547Lm5Va7zyckq0HEoC6sbw767BiPz/GOdq3oZ9jEu0
         wHJk0tr3/vsHNow8mzLyqNaATQd3JPEYDd78BK/qhY3PnXa/TsZ5CnqwvpNMAgRD40Ah
         HTDzOSUD6WnzboxY2/sVGJxi90NbWKpNa8XLQQB+qkdjz3ykJOZ7XbgM+ZPBS2Myr8SC
         iM2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B49RRc+uw/7CnjkDBtwFzIn6uJK+tMPJfHRkdXOkfA0=;
        fh=++hq3y7EvGxzq6mD9TdjRlwdBVIKW1Y/FQ97cBU25a0=;
        b=YoJYg66I4QwSQSh6ZLQvEsZZw2PMvkiy+hmizujn4IUnZrZUAgIrqUMKZhj0++Hdr4
         KlISaB5qoGRIqaU8w2Q9l0u+5i6iB2rk/UPxA30s9T5YTj/9tABIWJ8NUtTdiGyFycRL
         6bJqSv2qyWkeExXp3jIZlWOI24UBnI5nVUyCHrDeXh7xLS0oLScvjZDiXL/PpFVvjYAy
         eGG7gZlTp5jN0xC1nsRPafFTkIotprtis11F5R956t/Bcaezvz0W/UrHpSbBdCetm113
         apAb6hZmDGR1NI0eACmi7MyVMgiINmZ54bhD32J2MEdakG04d1u8n+STgcG1UGNZ7/Lr
         DjqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cpB2/QmG";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870d104efdsi11022166b.4.2026.01.12.17.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 17:21:27 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-42fb0fc5aa4so5213367f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 17:21:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXKJwjzrIqOqvtTtWZ6RcpwAiAvWff4EiaFpIR0jrDpyhWrtzM9kqMayCCejhEH8B3ypPBhJNh7wFI=@googlegroups.com
X-Gm-Gg: AY/fxX69UjYRnZZLqzPXGmWispgAcESBzHDhZvYcJzY8E38lOe/xmwV56wManickXwV
	Cbr33d0JUx9ZUCXOYPZD6uH+nf9LVAFMA3nuu38lKw7dh1M7QN511E2RIGj+QaPPQinWxHESM69
	Ua5mCQZlHtFZEFoZFrV5ud/VYPhFm3xIHWWfzIyrILyvGpAvYrSiluPMDsnSZtLgPF16jx4+0pu
	Wi9tFDUuDgiuuQCYZ3HfLrGXzJW443YSvHRdHUbBbEtlUCvVuAuQj0kd1JkPdhb0Q4/1wCWwO0Y
	6liY59BrYpKiKVJizfW2w5jMpCRi5Q==
X-Received: by 2002:a05:6000:2882:b0:431:907:f308 with SMTP id
 ffacd0b85a97d-432c37a375cmr23160903f8f.61.1768267286471; Mon, 12 Jan 2026
 17:21:26 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jan 2026 02:21:15 +0100
X-Gm-Features: AZwV_QgNCKYV65kMyu0l_dWwfZe-OUyCZiqTrFscvNfb1KMt_cAloyWYmxxC2zI
Message-ID: <CA+fCnZdTDzruwLA2MdE=+5KQC5VKMEjm49Z5ez-dDO27y4GORw@mail.gmail.com>
Subject: Re: [PATCH v8 04/14] x86/kasan: Add arch specific kasan functions
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>, 
	Wei Xu <weixugc@google.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="cpB2/QmG";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
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

On Mon, Jan 12, 2026 at 6:27=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> KASAN's software tag-based mode needs multiple macros/functions to
> handle tag and pointer interactions - to set, retrieve and reset tags
> from the top bits of a pointer.
>
> Mimic functions currently used by arm64 but change the tag's position to
> bits [60:57] in the pointer.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v7:
> - Add KASAN_TAG_BYTE_MASK to avoid circular includes and avoid removing
>   KASAN_TAG_MASK from mmzone.h.
> - Remove Andrey's Acked-by tag.
>
> Changelog v6:
> - Remove empty line after ifdef CONFIG_KASAN_SW_TAGS
> - Add ifdef 64 bit to avoid problems in vdso32.
> - Add Andrey's Acked-by tag.
>
> Changelog v4:
> - Rewrite __tag_set() without pointless casts and make it more readable.
>
> Changelog v3:
> - Reorder functions so that __tag_*() etc are above the
>   arch_kasan_*() ones.
> - Remove CONFIG_KASAN condition from __tag_set()
>
>  arch/x86/include/asm/kasan.h | 42 ++++++++++++++++++++++++++++++++++--
>  include/linux/kasan-tags.h   |  2 ++
>  include/linux/mmzone.h       |  2 +-
>  3 files changed, 43 insertions(+), 3 deletions(-)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index d7e33c7f096b..eab12527ed7f 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -3,6 +3,8 @@
>  #define _ASM_X86_KASAN_H
>
>  #include <linux/const.h>
> +#include <linux/kasan-tags.h>
> +#include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  #define KASAN_SHADOW_SCALE_SHIFT 3
>
> @@ -24,8 +26,43 @@
>                                                   KASAN_SHADOW_SCALE_SHIF=
T)))
>
>  #ifndef __ASSEMBLER__
> +#include <linux/bitops.h>
> +#include <linux/bitfield.h>
> +#include <linux/bits.h>
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), t=
ag)
> +#define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
> +#define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_UL=
L(60, 57), (u64)addr))
> +#else
> +#define __tag_shifted(tag)             0UL
> +#define __tag_reset(addr)              (addr)
> +#define __tag_get(addr)                        0
> +#endif /* CONFIG_KASAN_SW_TAGS */
> +
> +#ifdef CONFIG_64BIT
> +static inline void *__tag_set(const void *__addr, u8 tag)
> +{
> +       u64 addr =3D (u64)__addr;
> +
> +       addr &=3D ~__tag_shifted(KASAN_TAG_BYTE_MASK);
> +       addr |=3D __tag_shifted(tag & KASAN_TAG_BYTE_MASK);
> +
> +       return (void *)addr;
> +}
> +#else
> +static inline void *__tag_set(void *__addr, u8 tag)
> +{
> +       return __addr;
> +}
> +#endif
> +
> +#define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
> +#define arch_kasan_reset_tag(addr)     __tag_reset(addr)
> +#define arch_kasan_get_tag(addr)       __tag_get(addr)
>
>  #ifdef CONFIG_KASAN
> +
>  void __init kasan_early_init(void);
>  void __init kasan_init(void);
>  void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int n=
id);
> @@ -34,8 +71,9 @@ static inline void kasan_early_init(void) { }
>  static inline void kasan_init(void) { }
>  static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size=
,
>                                                    int nid) { }
> -#endif
>
> -#endif
> +#endif /* CONFIG_KASAN */
> +
> +#endif /* __ASSEMBLER__ */
>
>  #endif
> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
> index ad5c11950233..e4f26bec3673 100644
> --- a/include/linux/kasan-tags.h
> +++ b/include/linux/kasan-tags.h
> @@ -10,6 +10,8 @@
>  #define KASAN_TAG_WIDTH                0
>  #endif
>
> +#define KASAN_TAG_BYTE_MASK    ((1UL << KASAN_TAG_WIDTH) - 1)

How about KASAN_TAG_BITS_MASK?

When KASAN_TAG_WIDTH =3D=3D 4, the mask does not cover a whole byte.


> +
>  #ifndef KASAN_TAG_KERNEL
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
>  #endif
> diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
> index 75ef7c9f9307..3839052121d4 100644
> --- a/include/linux/mmzone.h
> +++ b/include/linux/mmzone.h
> @@ -1177,7 +1177,7 @@ static inline bool zone_is_empty(const struct zone =
*zone)
>  #define NODES_MASK             ((1UL << NODES_WIDTH) - 1)
>  #define SECTIONS_MASK          ((1UL << SECTIONS_WIDTH) - 1)
>  #define LAST_CPUPID_MASK       ((1UL << LAST_CPUPID_SHIFT) - 1)
> -#define KASAN_TAG_MASK         ((1UL << KASAN_TAG_WIDTH) - 1)
> +#define KASAN_TAG_MASK         KASAN_TAG_BYTE_MASK
>  #define ZONEID_MASK            ((1UL << ZONEID_SHIFT) - 1)
>
>  static inline enum zone_type memdesc_zonenum(memdesc_flags_t flags)
> --
> 2.52.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdTDzruwLA2MdE%3D%2B5KQC5VKMEjm49Z5ez-dDO27y4GORw%40mail.gmail.com.
