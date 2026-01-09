Return-Path: <kasan-dev+bncBAABBNMJQTFQMGQE2SICJPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 07636D0A72C
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 14:37:59 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-47d28e7960fsf46302015e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 05:37:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767965878; cv=pass;
        d=google.com; s=arc-20240605;
        b=JR/NV8HKB/8er4NSudASHUrEi+FI/T6qNExO69FqYT9TzMggPnENg4mUct8IliOCL8
         vDH4YvfN47h6NtV/CYZ7nMtB8zrYl3w8VloGgY8T6oPKHclfEEDwlc9LG2qZ/cihmMR9
         Toflx+3xIrohuMG31bmm2B1QC+hRI2kfQZvAk6RXlaZyN6mSOkjkkeHHbTl4psMuFsEL
         KJY2MP2BReSTi1OicjDC+HbpGyWjW8KyTIBVhpKRHTtS0znQ+Q+/tTXm+VTwFazA7JxJ
         eP2sWe0jrhZ0ZQ9DeOLAGXklBQgpeb7tSebKgLAcI/Q4lPrhyCXYNqsU3BLeNf3ERo1V
         1O3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=ftYrnpdV0PLqHL1Ks7fXWJchQ+9ZMeW+AIEv1TqiYrs=;
        fh=KeeJwLiwRALb/51f3gttQf8lgOajz9eypVqWbxYB/0U=;
        b=UJiiTkN4mUm3ay0/EtTiARWEiNIQlUe6+FWfTBHaIcYCyPiTYBIjn7Nk0zHjI2Y/FV
         rZ+1ej4YkjDrw5jAL+UMf1YopfT6AuaqE+Ka4dF4zv07OoFwmKkBa81f/V3owjI290iJ
         GG7651aHrjsLrQ+3WAEQ2D+WytSwH4yVWfLaBaVua/BwJCmfeJBmOucWVua9nn7hrMCo
         jM0n2l28OHyXW47Fh2LIdTiQTlSjjFC/xBNC7IRQxL9nbFVoFt7SPCe1VfolSSae3qTM
         SkxVCZMOvLgwkWB8krasDcy3UBi/2SxjgGfPlRua6FErJM5k0pR4hCrwHN8TChog9FT8
         efHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=FJlY+lwD;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767965878; x=1768570678; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ftYrnpdV0PLqHL1Ks7fXWJchQ+9ZMeW+AIEv1TqiYrs=;
        b=xm+uGDeKi6YXKMSlJotz1xtAEyUWdT1EgKLPtvv7r3MepQ9zROklwfuxSVlNoSiEdy
         wpfbIrYug9KU6Oj9THZUeNQ3NhA6LE8L2Oko21Vc3qrh4cvwTU2Az/jwsvlX0ncyy7Jg
         KmxoNPP7dk+gPsa2KO0hGpI0nPw79FMHb0qdUVJeKhLgPnbjoZDBc651YqeaAcgv704F
         K8lIGHHQE7jmXB2IDggGi6UyIBdwmfMCvneBHdsoSgV+P5JHtcT2b5W55ksB/XbRDH6h
         TNl25LXXyDTd6pNnqvzgln1iGXTdSJrhImr54Wt69Crl9KlrHlW3ND1mNJNnauNTlC8F
         11gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767965878; x=1768570678;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ftYrnpdV0PLqHL1Ks7fXWJchQ+9ZMeW+AIEv1TqiYrs=;
        b=dIaUBfjqKohRTm3kk/zzN9UE17/59BQDmNItbhjJenbXmeRcKm19/HxfmuoZD49H+S
         zSSF8HxH1AV0Jx8GuRag9RVZ3aXY687KUPrQKwcqwvMWcFRph9H/PgX9vczUSsdYTy3h
         r9AbcYypXg+elqmggTVKJxeX0hL4TqmAwlZ9IhTzwYfZ0+4/BBsu/W/EW++T5VjoNW4N
         gFWUh+2QZfpasDUvwI/PICvknFn/IvWzyGqA2U804WTuaMBPoNQvtBVW+a8PK+LDvrSt
         PHuymYA6VXjWYjdUCGkJ9e0Qymiq1NMHzqnxnBbGvJ5scL+pi6e4uak+E/BiP09DmkiA
         FJ6Q==
X-Forwarded-Encrypted: i=2; AJvYcCVM0m7/1e3//0yzQqPwevNvxM5o/2NfMucl42PgdPvMgCwTHasyD0iQ0mL54512YYEIVxat0A==@lfdr.de
X-Gm-Message-State: AOJu0YwzVTfkGiWijJD6yCsicCjQPcb6KhKdcivwxZk0MR+5JV3P5tFB
	SV7NViFUeunmcP9lBULdYHOFaS9kEDzGA/KSqLNY94b8AdPfDqWzM7MI
X-Google-Smtp-Source: AGHT+IGomc3Fn292Px6okdgHZUsEFpaYiM+Y+lrWBiRbkAXxQBt3ifT1f1XP4eiscK9acllZnjdfOw==
X-Received: by 2002:a05:600c:470c:b0:46e:53cb:9e7f with SMTP id 5b1f17b1804b1-47d84b3b4ccmr102273275e9.18.1767965878130;
        Fri, 09 Jan 2026 05:37:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa0s8ZHrHK+M7E5WcbJD0ZQQrNbOjX4Xbhy9lCL7GqY5Q=="
Received: by 2002:a05:600c:4443:b0:477:a036:8e82 with SMTP id
 5b1f17b1804b1-47d7eaa4893ls25319745e9.0.-pod-prod-08-eu; Fri, 09 Jan 2026
 05:37:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXm8xFknBKOWElerZdhVgG0rH/ynFQEv8kHmtDiByJoM2ZuZaPxymHmoNnsJ3LcHA265bEj2RY7Z7g=@googlegroups.com
X-Received: by 2002:a05:600c:1991:b0:477:b48d:ba7a with SMTP id 5b1f17b1804b1-47d84b4119amr106731435e9.32.1767965876343;
        Fri, 09 Jan 2026 05:37:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767965876; cv=none;
        d=google.com; s=arc-20240605;
        b=Kx8DXYxhCLNkb6Wv6tRA6HAHOjpfr1RvGGlMfhE8kJtl9dBnPzePT1++eZWrn5OqQ5
         4LoVizlmQzJQIo92GI+QX2c7jLw/aQV3qpkZB11XdC0nHcnvU1wfyZxZc3C52lm6t6lI
         gkbSRaBJtKnoJRqEx1+/5foUJOjXPnyJwf1QdcN/s4UoZllwbkuxUp5Tu+GdgN47JHw8
         dbDfbhtogMiAyM0+hP6qypXo94LmvtE40VspaUardWqopDoEDNyex/eymL+kYsnQ+yzq
         jRSROGH1Gsj/Foa39oISpCN5dnEe7OGAcPE19+80eoRNsfiQDUgLgMFtXWdXY2dQW0SS
         ZbHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=j3NjXkb3MtCkcFp1gZdZbK2WKHYzWPAkjB9Zixe5dUM=;
        fh=PoxFXLwFYhvRGFpd2HMlRbNC7nvNlYHEaucKbeYLoQY=;
        b=PKlzCSmWbmfhmgV3dmHXHFF9ErI8qHIUBHcloMotqV1D6vXtnxB+xiycdsR0JpP4JZ
         Rx5Rhgt7nZ1F17HajYMZmtJoAl9IVtooMKBDBQrLDCNEs7ceav+FQvSaQFAa+Raky7YK
         QGOfBLErNB/8XunYVwoadPkEtzUkFDOaGI4rio+rqflanaBeepZ/D4m+Bfda5kiKSRIH
         NHTQqfEnFNKzllxAyDBqlAKZacPs1GQXZ4b3je2ADnDR16owHws5dzWw8MDx+TbQPSv6
         eEzPQuPqaKBjWUKQLjjtptdCW+NiNua5uPpLblIcQ6so0vnQ0nSvBdgt1Kyjz7GKTTqv
         6ptg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=FJlY+lwD;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47d8701b262si659995e9.1.2026.01.09.05.37.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 05:37:56 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Fri, 09 Jan 2026 13:37:49 +0000
To: Will Deacon <will@kernel.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v7 02/15] kasan: arm64: x86: Make special tags arch specific
Message-ID: <aWEDDjQms8zbMgsB@wieczorr-mobl1.localdomain>
In-Reply-To: <aV_v18YWCHXMETVK@willie-the-truck>
References: <cover.1765386422.git.m.wieczorretman@pm.me> <0db7ec3b1a813b4d9e3aa8648b3c212166a248b7.1765386422.git.m.wieczorretman@pm.me> <aV_v18YWCHXMETVK@willie-the-truck>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 0570fdf76a1b4710800e4cf7ba907d1afc4ce5d7
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=FJlY+lwD;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Hi, and thanks for looking at the patches!

On 2026-01-08 at 17:56:39 +0000, Will Deacon wrote:
>On Wed, Dec 10, 2025 at 05:28:43PM +0000, Maciej Wieczor-Retman wrote:
>> From: Samuel Holland <samuel.holland@sifive.com>
...
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
>> +#define KASAN_TAG_WIDTH		4
>> +#else
>> +#define KASAN_TAG_WIDTH		8
>> +#endif
>
>Shouldn't this be 0 when KASAN is not in use at all?
>
>Will

This file (as well as the x86 version) gets included in
include/linux/kasan-tags.h:

	#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
	#include <asm/kasan-tags.h>
	#endif

	#ifndef KASAN_TAG_WIDTH
	#define KASAN_TAG_WIDTH		0
	#endif

So the 8 or 4 value is only assigned if SW_TAGS or HW_TAGS are enabled.
Otherwise it's set to zero.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WEDDjQms8zbMgsB%40wieczorr-mobl1.localdomain.
