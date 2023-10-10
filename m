Return-Path: <kasan-dev+bncBDW2JDUY5AORBYODS2UQMGQEXHGTGVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE0127C0427
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 21:11:30 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-58109e43fa5sf3455330eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 12:11:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696965089; cv=pass;
        d=google.com; s=arc-20160816;
        b=xxPmvAi44EfpGMuTiseDKKDCkkufEVUedUI46uGBD0PVe4H4KfBln7H8lx8sIqnbTW
         XQDML800HbH7MB0lpafL49hPjrSN2risJj4nl5ETqEgj2ihp0EOduyjjdq4Xl5VWmn7L
         hhA6l4KdLxkJXQS+tzl0hNiwz96WqH49TD8fpG/UtTXfceZTFMyhZYBnEL+pfGOsA2Bu
         1aqKveCe+6mOxMXxARwBRzZr1ZljcMkU8i6WxXOI9J9yD3RzeWHERQMjUu4zYJx4cT6K
         ebAb0QRuSKQYjMOOTcqvnMZjsTljK4mKg5acEGRQKs9pwPuwO8QsNthw/J0cgIh+3PB6
         BOcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gkGpn7r5DRCfEwhmSAG2lcL6vObva6q4ozRAZe1M+V0=;
        fh=rVI26fjIEVEwBRLs/MAJ7KCT6UJyMVZPMdcTEyNhzSU=;
        b=tFEoHfyDT3lu7alESmy7L4MVvzJMeeJDYaTcPqOWfIMc9n8p31mdGG9ShXGGkbXc4K
         7rAtHNQ+lJwcY/EvxaoazaSp9y7P+dt0CwGB/Y7wCDd4xmjcE1coGkLVntWN7za7yyuE
         m14fhhIaYNCNNokBA6E2ipIkjLPqGz41zzdTmDoc+fLm4iewVEE2V/xUFymg34kAsU91
         CcLTheATrlL3mbA6KshvBK5f6v7Ozt5SQRbuGROSXToAT2Mv8MRmPocVXJ7uXleWXIuH
         34fYqipUidpp6azBqR3IBcP/lHfy6bp4fKzf3P8KVpcu22WPnGQpxx73lc9oW5+KVFSR
         OI6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wbc2ZGs6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696965089; x=1697569889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gkGpn7r5DRCfEwhmSAG2lcL6vObva6q4ozRAZe1M+V0=;
        b=q0P4d83XR0eton+ZzQlmlTrd92kaQu3FBd1dfEeT1bu7eeX3hqoAJW2Xk3czvAmtdV
         wD/7xPUD0Vi6LMUQJX+BVHHDiwzN2O+sFpo69aBLoYRfoqYxXer8gfJHRcdd7K6Uhrgd
         j6F0CQAG+7BW1KXRyXnB4NggzXN0rKmi5lyCYq3TtqNdf/5k9q5tN2aapEhiuQ7HX4bZ
         GHMpP362O19Lcz4rPHR6yPu0As1G7KLkyEQBnRkzesP44uQOX2AUB7bMvjx+Bm1EYXvj
         LF587kigpUERDeeLDNKPJl9ltyKtzymLhXl6gIDMft1Q4OapZqlAGOfoKfLrpbFryLOY
         O89w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696965089; x=1697569889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gkGpn7r5DRCfEwhmSAG2lcL6vObva6q4ozRAZe1M+V0=;
        b=HC7hses5rt8JumgrEP4dSXITR0f3v92vhXwIKhp8iOU7H8HyzrcAaHOqFD6qG9NFr7
         hDGr+zEfgoolSfDTVFdmWz3Mg6oXVAA6prBCGXYTPP36C7Gi8eqG5W5B39nDJx6eRi4t
         RyKy6dfXu5rLxZAP7GGphnIGu/jDhCfQYdty4WU+36yuclvoUB5il2YixpvLx+j4jWS7
         jnmGsdTI+xU1t5ku1IUBWapA6nWLv+Y3LCeMChDwGDRP7djxlQsfwIgRUWFYNCFkID0E
         MPBrQx881/hIZaFQDnwoG67Eqo0FslYWbtPJh23wCjM8jtlkoyu4KEq0TwW3JehmKwUJ
         ZQSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696965089; x=1697569889;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gkGpn7r5DRCfEwhmSAG2lcL6vObva6q4ozRAZe1M+V0=;
        b=tL2P4zjXuppGeLiCeS3kdvQqjbyena7T4dE71hVpsPQFVK/7kvSS0bpvSK8YuxzrW2
         3aWtfwKBTQ3M4dfuxXpApir4PN9HHyZpUjHK3VDOxCSGW8wkddaHjWeT7aFqEjtqBFlY
         McpZdrjks9hWGYYpzAhOc8QZe0zl9R6RZfwrmEehXUJfQrTYq7Pv6pwzX4eODbTkkdP8
         RRogKeVutmwNiMQJ+oxlk0wTXK/nl+Hm5HyQvFyOcxOYA8qn0QdG50LxXrJs23tr2V79
         l/kFyAYYSSr8EknFYxRnrS5QRLThkniC6Cz2Q8+QSNuvGRoSFii3X/LQfX2A4iR6Ua4V
         sDyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxjNTee/SlfVpfMF4eA1v25cfuKHXcR6HHfw1GgheXry2AcdQnX
	FD1JOTi1xp+dsN/TqkINg20=
X-Google-Smtp-Source: AGHT+IEwLrtBhqJYw40VLWIL+KZSf7ImasrWJpdjLGBnXeoUgJA1D9F0rlQVMhOntxlnm1TRmqudwQ==
X-Received: by 2002:a05:6870:829e:b0:1d6:6430:f743 with SMTP id q30-20020a056870829e00b001d66430f743mr19281146oae.19.1696965089420;
        Tue, 10 Oct 2023 12:11:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e3ce:0:b0:656:3716:f1e6 with SMTP id e14-20020a0ce3ce000000b006563716f1e6ls5871922qvl.0.-pod-prod-06-us;
 Tue, 10 Oct 2023 12:11:28 -0700 (PDT)
X-Received: by 2002:a0c:de0f:0:b0:66c:f87c:af78 with SMTP id t15-20020a0cde0f000000b0066cf87caf78mr2058135qvk.54.1696965088413;
        Tue, 10 Oct 2023 12:11:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696965088; cv=none;
        d=google.com; s=arc-20160816;
        b=eBC7igGh4k4agpvvDNTVEN2ymeUC8YOf88ofVIeg78PNv5kLgsNWn1rbd7SsLwQQtZ
         0uFBh+IEy+xKYlIYqsGnMoO1LT7m1s2mIZojFmmRoUlLC9HtLushwUos7khYwWPQhD0a
         EuWhPN0en1JY3PBMJ0PYni7fKZ6aIAcTkXe2Z+uTBeOIrAYMtmczg26QgIX5rN6w7dQO
         t4Gi4ZIK85RTRWu6FJ9FN5B9omx0hgL7cPKFcci8BX3vdG7CVr9pioniusWTbk7U7NZN
         yIPHwG8oF8WC5bXQ09XHIrot4u/UBIXNcaZvj5yd+quMCk62q0ArFppo8iBs1xdQLNP7
         oMVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=r9C33FK/mhypuEKRvbN96wMq7Q2blPztB7nZo12h8b8=;
        fh=rVI26fjIEVEwBRLs/MAJ7KCT6UJyMVZPMdcTEyNhzSU=;
        b=dp/tKTa5MJ5m5PKqHHnmlMf6YKo+DWgLFYR0zcILaqUqgNYnn2MrKUSCra4zTzTwjE
         cXmnoF9g9ynUlwB4K/pon/SB2SA7ghwnYQ9Dfk2GwzJzld8zKiF4++pnqvjE7rLfLF87
         f3YAv1NTBeRQ9FwQv4uW+W1Nr/2wPNeppO+YwGVYvtvB3Wed3vwMXl3csKGZFkUXpj3p
         ylqdQM7KQUvN4x1cq2GxfhLJNhEM1droT6JQfZ2Xmay1EpVCvq2ohi3MP77icuDvrK1J
         KuC6d+0v/Dd44Me5NfJtfteEAtKM+rqvV6ddRrw4O55DXxsOPfgUY026s9TBt7FXn44v
         4EQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wbc2ZGs6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc2a.google.com (mail-oo1-xc2a.google.com. [2607:f8b0:4864:20::c2a])
        by gmr-mx.google.com with ESMTPS id h13-20020a05620a21cd00b0076eebae2e3esi676999qka.6.2023.10.10.12.11.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Oct 2023 12:11:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a as permitted sender) client-ip=2607:f8b0:4864:20::c2a;
Received: by mail-oo1-xc2a.google.com with SMTP id 006d021491bc7-57b635e3fd9so2966404eaf.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Oct 2023 12:11:28 -0700 (PDT)
X-Received: by 2002:a05:6358:7246:b0:14f:9904:a17f with SMTP id
 i6-20020a056358724600b0014f9904a17fmr12015198rwa.15.1696965087737; Tue, 10
 Oct 2023 12:11:27 -0700 (PDT)
MIME-Version: 1.0
References: <20231009073748.159228-1-haibo.li@mediatek.com>
In-Reply-To: <20231009073748.159228-1-haibo.li@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 10 Oct 2023 21:11:15 +0200
Message-ID: <CA+fCnZev8zdLV2Q4P5gyGEvLZpmpd5Afi8j3KAyHTFGKt5oTOg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan:print the original fault addr when access
 invalid shadow
To: Haibo Li <haibo.li@mediatek.com>
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, xiaoming.yu@mediatek.com, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Wbc2ZGs6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a
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

On Mon, Oct 9, 2023 at 9:37=E2=80=AFAM Haibo Li <haibo.li@mediatek.com> wro=
te:
>
> when the checked address is illegal,the corresponding shadow address
> from kasan_mem_to_shadow may have no mapping in mmu table.
> Access such shadow address causes kernel oops.
> Here is a sample about oops on arm64(VA 39bit)
> with KASAN_SW_TAGS and KASAN_OUTLINE on:
>
> [ffffffb80aaaaaaa] pgd=3D000000005d3ce003, p4d=3D000000005d3ce003,
>     pud=3D000000005d3ce003, pmd=3D0000000000000000
> Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43
> Hardware name: linux,dummy-virt (DT)
> pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=3D--)
> pc : __hwasan_load8_noabort+0x5c/0x90
> lr : do_ib_ob+0xf4/0x110
> ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.
> The problem is reading invalid shadow in kasan_check_range.
>
> The generic kasan also has similar oops.
>
> It only reports the shadow address which causes oops but not
> the original address.
>
> Commit 2f004eea0fc8("x86/kasan: Print original address on #GP")
> introduce to kasan_non_canonical_hook but limit it to KASAN_INLINE.
>
> This patch extends it to KASAN_OUTLINE mode.
>
> Signed-off-by: Haibo Li <haibo.li@mediatek.com>
> ---
> v2:
> - In view of the possible perf impact by checking shadow address,change
>    to use kasan_non_canonical_hook as it works after oops.
> ---
>  include/linux/kasan.h | 6 +++---
>  mm/kasan/report.c     | 4 +---
>  2 files changed, 4 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 3df5499f7936..a707ee8b19ce 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -466,10 +466,10 @@ static inline void kasan_free_module_shadow(const s=
truct vm_struct *vm) {}
>
>  #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASA=
N_VMALLOC */
>
> -#ifdef CONFIG_KASAN_INLINE
> +#ifdef CONFIG_KASAN
>  void kasan_non_canonical_hook(unsigned long addr);
> -#else /* CONFIG_KASAN_INLINE */
> +#else /* CONFIG_KASAN */
>  static inline void kasan_non_canonical_hook(unsigned long addr) { }
> -#endif /* CONFIG_KASAN_INLINE */
> +#endif /* CONFIG_KASAN */
>
>  #endif /* LINUX_KASAN_H */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index ca4b6ff080a6..3974e4549c3e 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -621,9 +621,8 @@ void kasan_report_async(void)
>  }
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
> -#ifdef CONFIG_KASAN_INLINE
>  /*
> - * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the hig=
h
> + * With CONFIG_KASAN, accesses to bogus pointers (outside the high
>   * canonical half of the address space) cause out-of-bounds shadow memor=
y reads
>   * before the actual access. For addresses in the low canonical half of =
the
>   * address space, as well as most non-canonical addresses, that out-of-b=
ounds
> @@ -659,4 +658,3 @@ void kasan_non_canonical_hook(unsigned long addr)
>         pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
>                  orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
>  }
> -#endif
> --
> 2.18.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

On a related note, I have debugged the reason why
kasan_non_canonical_hook sometimes doesn't get engaged properly for
the SW_TAGS mode. I'll post a fix next week.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZev8zdLV2Q4P5gyGEvLZpmpd5Afi8j3KAyHTFGKt5oTOg%40mail.gmai=
l.com.
