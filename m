Return-Path: <kasan-dev+bncBAABB35XU64AMGQEYHQAFEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CD7C99B007
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:16:17 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-45f2775733bsf60532911cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:16:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728699376; cv=pass;
        d=google.com; s=arc-20240605;
        b=U/GSHCE/Fj6quU9/htIw9geUxP/JgP20m+wUwSDbARKKpB9QcVMMfIgm0P+mErnBc0
         Pa3uIuBLq7ivs9lih0jA8eRZMm0sfCAZZTYe2+erhT+PZL1FhWWNLPwNuXbBsPDaRkHj
         4CfE2/44X3G+t7o17SJdjXy/HTDsj8O9ePKtc8H+i2lhAXfsu8EV/QAe5cWw+FiD6Hsb
         vLVljMW/lSAwD5BV3JfXilAjKROjsMx3V4b+sYafdE77ysmUax13V1yXC/FA+V11jLmn
         jcoKHIzj8ntcFgixFF0Ley0lqFvbdi7wJRl5Uu5zYY1krM+Ib6mGucZ/jd/crCDcFQzs
         eJMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LIbPKNbalAYvVXNYszYA90FcLPpEkvs8o4ITxwTVRm0=;
        fh=JtioxvNFEDi3wj/7DPLakVecZaoDhJiyi1NVZYPibV4=;
        b=bG+7IaDSV17/Q4D5783eR6rc+4xDnMYDy22eEAwGezfosv7sNpvqeLrYI5Dq1SJdbQ
         F6qCD6zfaeB0KBTE0QcFSEOP7gd/eYRCL9n6XBwnBu6FFeajSuf9hvh/hXf/wwi6TrhR
         zn1LaZPpPCOhdWogjJxiKkA+jTSZtX7sb/IrgZv8vfenS1PpTufU2+W4UgtQwa5Hukql
         EMGlpBrtG+5D+nKAGPr2EXyMmDAe2SwX87yWKB7mPKoslxiNWKuomlm4M1gfC576cWnn
         WYPjs63T7AXwSCR4arG8IPBmmRbGMR1nKxFLKOL3+YDzGUoEPLczXSNPlQAl/fclgC8B
         dNhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p4N5svc+;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728699376; x=1729304176; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LIbPKNbalAYvVXNYszYA90FcLPpEkvs8o4ITxwTVRm0=;
        b=ZWt4caKtJ51ZASg5lL+9SfTYqTFV8mFjsB2qY8iJgjmeV3y2AoHuupyy5fVl3s7ks8
         ytCmjly0ire4WWIZ2eh47LSoYTBa+VntUJ3wWbRJG7dzeau4V4BMzLLEroK/kro8Kuzz
         A6SYOkrgvP1y01be223XV3hYiuzc8AOZ4QUJewWMC30vihX1w4rEed4zxcW//ijbpon0
         ratxNtlx69x12TqxILFaqUPCI/utqHFsJjhfM3YkERB0929/ql1XYpo4LONp5ETIk759
         VS7Ly5L/x5zYWG8sM0ZsPD1dWIfTP6X3/R48bLccPgSZ2Y2rbJXLkP+mt29gbgWc1mON
         2kDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728699376; x=1729304176;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LIbPKNbalAYvVXNYszYA90FcLPpEkvs8o4ITxwTVRm0=;
        b=ScHVhtcDm1Nt2vxdOChn5x8s1r8JCdB4Uu3yNX1VyxeT/XgGXnL6v56aVkT55L1Jo7
         gpBhpYXuJGDSX5QlHFLu3BLpY35h9+S9CXfIF8szUl2n7mFuYqTpG7bRRLgi+BgNXPdx
         hu60RYfKNpNdD0HaSKIEUmHegLJqOcVUYjlHDSF9gwyhB3r6QyA7olKwpmszexmAiFc/
         dgsyuiXP7WmvtbS8zGkkgNKTiU6UC9s+Em4N3THDfY4zkbAGQewQPW8ZDwzcjcxLALeI
         SURIHeD1eb0sFAQGkAIfeXqZ/6eb0wC8Fq/T7fO6k9qHHH8cTHljV1w3Gz/wyUtbSqDp
         MhbQ==
X-Forwarded-Encrypted: i=2; AJvYcCVxlecNfTI+I8hYx1whX4jfYdYvlcqhp1BTWlxuPLokXCDCBuMSXFVZdoJGbzZlWig4VXfgQQ==@lfdr.de
X-Gm-Message-State: AOJu0YyV9Crt2abVUzyQ3HuNuiRdRpiKk9LSPWhZ22hBviO0emmEM8BR
	EjUxr+vbRV0LvluThmZiWwGqQ1NbdO7/OJw6CWfAOwR5hqBk3GGy
X-Google-Smtp-Source: AGHT+IGJAZQ4iQ42ubB2vgyoEhb1p9ouUZLgTSfyS5XoXENQKtxacCj911wcSG5qdCgKXG4V+YmW3A==
X-Received: by 2002:ac8:5786:0:b0:45d:8684:4324 with SMTP id d75a77b69052e-4604bc49d71mr64518961cf.58.1728699375824;
        Fri, 11 Oct 2024 19:16:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7e92:0:b0:458:4c68:593b with SMTP id d75a77b69052e-4603fd41cf2ls45652051cf.1.-pod-prod-07-us;
 Fri, 11 Oct 2024 19:16:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjM8esOGWvUv47rRkwRe6AqKFtuogWtV7G7GtdzKW6HY9KSjBJui0lDtueyaq98OGBUCUgqthzyhc=@googlegroups.com
X-Received: by 2002:ac8:7d05:0:b0:458:3eb3:7485 with SMTP id d75a77b69052e-4604bc2e052mr87988301cf.45.1728699375346;
        Fri, 11 Oct 2024 19:16:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728699375; cv=none;
        d=google.com; s=arc-20240605;
        b=FGwTKF2UgqwYn+Qalvgj2ybHgywQltUMHNhx/do5XBTFXJ5QtReWUDz0V73snZaMJa
         +uAJ0GM6LMoNqTzbHR6R3BkgXoMG1hRvaNfgdG++AVqLZYpHnfNGE2ZqgdyKEBcnEOhF
         zrjsE6aErZf727QDSkffTq8kmkADrvW0Ipev5yFcUk0iQcT16osbawiG07SfkwHXNBKo
         a5NNkMxdn9Fq/NlhIKZsx1Tj/YRpvjy9pXcyNJpeSakolzC9lnFEmZloMS6i7Z79GG+n
         FnMstaNxgN1FGVzgcd5T3IG+YHxDu8XXeRJNYIWbblq5ZIERFQgeZdC3xwvdCnaMmwTM
         hxxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hBbRyvijNRbZM+G0HaA6T8rmiyA27hByTcUbYTf8TTE=;
        fh=nEzdCh8rAPc59k5reRyTeNwrikMX8LCXSaJv969v7kw=;
        b=MBQhfUA0HKQbBEcO7e+5ilOxfFjWDHRC/4ktGnNlCXHCysKBUXYVd1rcREste/5+Nr
         Wa2ERggrKiZRlgwbYAz2VQeSBTEeVienYpFrZJyTGElDPDdhGgcgNMOzeF7r5Sfr7MwE
         3aexgGZb9HjXzv34y9OnZGjocD5glIloIY1Q74wdMn5zcxx9BjPu/mSBnnL8t3lL9zTP
         o3/K1PhXFhRoQ2Te8WgDEz43Y1lR62lOusGRU2w37bhka7/2b5uclnWgnjQ66w/4gZr+
         gFxxXgsWTUChFlT53GFjFiiKpMSfMz2l6ylL3ea/34RUuwy5b6eIG5hREuegAxzxxJ+v
         q/gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p4N5svc+;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4604289f980si2523801cf.4.2024.10.11.19.16.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 19:16:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 86CFB5C54E4
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:16:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8F36AC4AF0B
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:16:14 +0000 (UTC)
Received: by mail-wm1-f46.google.com with SMTP id 5b1f17b1804b1-431286f50e1so722585e9.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 19:16:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWTwqjDd3qU6AoyIqyKMdy2emT62dpUeiNC5NUILxVUM6iKlC0R5Pf2WsORe7/BL3o8FzF7LX9K6jI=@googlegroups.com
X-Received: by 2002:adf:9bd2:0:b0:37d:51b7:5e08 with SMTP id
 ffacd0b85a97d-37d5ff5a4cemr1208845f8f.18.1728699373163; Fri, 11 Oct 2024
 19:16:13 -0700 (PDT)
MIME-Version: 1.0
References: <20241010035048.3422527-1-maobibo@loongson.cn> <20241010035048.3422527-4-maobibo@loongson.cn>
In-Reply-To: <20241010035048.3422527-4-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 12 Oct 2024 10:16:01 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6OR_HYSF451vSk_qSt1a6froSPZKY-=YSRBQgww5a+0A@mail.gmail.com>
Message-ID: <CAAhV-H6OR_HYSF451vSk_qSt1a6froSPZKY-=YSRBQgww5a+0A@mail.gmail.com>
Subject: Re: [PATCH 3/4] LoongArch: Add barrier between set_pte and memory access
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=p4N5svc+;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Bibo,

On Thu, Oct 10, 2024 at 11:50=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> It is possible to return a spurious fault if memory is accessed
> right after the pte is set. For user address space, pte is set
> in kernel space and memory is accessed in user space, there is
> long time for synchronization, no barrier needed. However for
> kernel address space, it is possible that memory is accessed
> right after the pte is set.
>
> Here flush_cache_vmap/flush_cache_vmap_early is used for
> synchronization.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
>  1 file changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarch/inc=
lude/asm/cacheflush.h
> index f8754d08a31a..53be231319ef 100644
> --- a/arch/loongarch/include/asm/cacheflush.h
> +++ b/arch/loongarch/include/asm/cacheflush.h
> @@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long start, un=
signed long end);
>  #define flush_cache_dup_mm(mm)                         do { } while (0)
>  #define flush_cache_range(vma, start, end)             do { } while (0)
>  #define flush_cache_page(vma, vmaddr, pfn)             do { } while (0)
> -#define flush_cache_vmap(start, end)                   do { } while (0)
>  #define flush_cache_vunmap(start, end)                 do { } while (0)
>  #define flush_icache_user_page(vma, page, addr, len)   do { } while (0)
>  #define flush_dcache_mmap_lock(mapping)                        do { } wh=
ile (0)
>  #define flush_dcache_mmap_unlock(mapping)              do { } while (0)
>
> +/*
> + * It is possible for a kernel virtual mapping access to return a spurio=
us
> + * fault if it's accessed right after the pte is set. The page fault han=
dler
> + * does not expect this type of fault. flush_cache_vmap is not exactly t=
he
> + * right place to put this, but it seems to work well enough.
> + */
> +static inline void flush_cache_vmap(unsigned long start, unsigned long e=
nd)
> +{
> +       smp_mb();
> +}
I don't know whether this is the best API to do this, and I think
flush_cache_vunmap() also should be a smp_mb().


Huacai

> +#define flush_cache_vmap flush_cache_vmap
> +#define flush_cache_vmap_early flush_cache_vmap
> +
>  #define cache_op(op, addr)                                             \
>         __asm__ __volatile__(                                           \
>         "       cacop   %0, %1                                  \n"     \
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6OR_HYSF451vSk_qSt1a6froSPZKY-%3DYSRBQgww5a%2B0A%40mail.gm=
ail.com.
