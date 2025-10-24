Return-Path: <kasan-dev+bncBDW2JDUY5AORBXFZ5PDQMGQEO4P7KPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 19FD1C040F8
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 03:56:47 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-290b13e3ac0sf12947485ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 18:56:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761271005; cv=pass;
        d=google.com; s=arc-20240605;
        b=gb+HgRwAk3STOL33AgwLXFRqRqKzt/WHXfoHNNmQLjj6h5ds86b8+y6k1UnWy7W7DU
         ioA/3/0zeKOidjU0Bq1BDHyPpH7cKRcwBsmt++B9nq+4i3SkD5ML53hxFXH7IaNBTGUs
         SLvmO4JK8Di0RDCVn4JGYBXtmvts1MM92FfS9DGlpRUrzM9/J5mt6AHowRoptJTEfR/u
         nQj4cT5YStmxaDD7LyAuuVT/RtNt64hJiGCbBnmFbdd9e8wUyMGU9YKkvJ7UiaMaREoD
         DR7sRkKZH4JtgjfOXTbeaJSiNt4YFPgIjCb2Uev/1m64KT2jrGpcAW2iAYzK6pbzqNra
         IRNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=yyB2kBgyKo+ISSeJwhcEJCNo0uxpScptB8WHlTkxJxg=;
        fh=9woeEaeTOEMbSSXXPECEZVphWw7OVqP+5XE8YDuwAGY=;
        b=dbWTRH4ACoU0HVWAZfT6UXVO87VejZtzYHlO2nSD/xWvwMvXdFF94aoyMmSajeEKbe
         r84x0i9xLosho4egjbmHLu0UMb8qVTkRivMyIQpSztYVaTMpAwzPifdVDMLt7zJuQ2/G
         lvfr8VP6XrTScigO2CItLwblKBbF0D9FPlX3SAnvQCNAeZONnZNOTCgrzMR7glWuAYK4
         SI04Nr5uLEalo+NeLera9aT98HqKV/Bx+suA3k2efhPnVgZMfPS2Cdkw0WY7FVQcOjXz
         acqXwO4Z9DXlgHot05HiZT1XkDrjCw1EunXu1rci9N91V/EnDNqL1xw/98HldPNc9Vxx
         qnNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JL4m8RYf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761271005; x=1761875805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yyB2kBgyKo+ISSeJwhcEJCNo0uxpScptB8WHlTkxJxg=;
        b=AnsOGouk2zqt63JlpCSMYsdmfbsAIh5SRiOy1bL4mRdkfYAaycSTcjFgph/ZQp7fB2
         W/S6J6mgXL7zv/D2JjvUkxfF9pOIIMEb2mAYMxYDb7i0WUCx7orcmtnZ8k7PFym7D/lo
         mOXQAzmCzBsLDH4qHHfpxd4ImU1NZl0uvD4Um9iqwQVmqALiLyr6cdKZSTxWloaucK3r
         IFbP/Ia5Cfp6+M5Pb4VoVnfx9KnhdYaIzORia1/sxLUh+zWMC6NQjLb9QqBdj9X1RhtU
         M9sajSAL04DzNe4bG5Zco5a5nDhzqHwnKiLJlWA5OEEjtZKgzKFugu7jjY+lmHZ2VRtw
         aP4g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761271005; x=1761875805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yyB2kBgyKo+ISSeJwhcEJCNo0uxpScptB8WHlTkxJxg=;
        b=NVZlGi66c3VoTmGZzaQPvnHUTTvHCNfBN64p49ocENSa1TWyyhkOJB8AbE7S/3jHJ+
         Qpm3xv0Wvn1xYphA8kQjk7G3Ru0jpNzbg5QS1kgjwWnC0WANifLRi2pWc6jIa4R1PcLb
         ApfHK6IIHquZy51liYHwauC7cotWPa8fdt5ybHCB01miYzDXwU/iHvCX52sNiKxC7bSf
         v1YmTfS8uyZYEliv08md98GkEl+HFBEOwG7RNaBY1+2rACkf3lJR4XoHC/Mo1o+vq21n
         jL5IAcb4n8rAL5sHXa8YyNHO5utKjTcdHq9APobRNcPveQVjud48WOPvnkB77ygEHgU1
         CXGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761271005; x=1761875805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yyB2kBgyKo+ISSeJwhcEJCNo0uxpScptB8WHlTkxJxg=;
        b=RkBICb/0HTQi6cG/wgenmmJiFlzCfku6fKN4x/LvaanUJacGGscyn4m032XUG+71e8
         rGcaRSl2zDTasRJMMmfg3qeOOKpBxYaQYctVdVvvkfQ0RivcDpfOj6ObGq0tS2Y+5Ju4
         VuFQRibme72PTGgjhooG4dOiSyROivjw7QHVSDjNn/CPizRrD4VbQtaKEQ4xwYadJZUq
         0FdsmkprgI+sgXssdY6bBpqYOTmz13osXuNG2Hj9D+VBWTTZucSyZDgDtrK22Adudjpo
         NqCLQh6wu+dLGtk4RZSnetDeby9+c2KgQW6nz8f/BtF1DUQNL9UgnCE9b0e24njwn0sk
         IA0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgJokRRiHlYhHoeoOek0EThyhhcaI8jEe1+uxgVvjnGgBaIKTPtimDoaZSjT07jT6Z6ZVmkg==@lfdr.de
X-Gm-Message-State: AOJu0YwhzQFZ5YjW1wUW3cqxxJgWzcuvX29sgN+WfAWxxsCvQxAWbCM4
	NTW3/mZJ6DE/u5fY67Z0mHHBo0kM44uHxbEzCQ8dhYkr60DxiVHMvByG
X-Google-Smtp-Source: AGHT+IHTLjvkiP1y6m+wLp+BKclplTMmpMvvsyYO0IsOPqvZ5E1i9s8rRAhYdwXDRXiiDk4Hj3rxHA==
X-Received: by 2002:a17:902:e891:b0:26e:62c9:1cc4 with SMTP id d9443c01a7336-2948b95762emr4943575ad.4.1761271004588;
        Thu, 23 Oct 2025 18:56:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+blU7ItOSi97Op4LrLw/74amZ2AgqmaHr0hLtcp6omkWg=="
Received: by 2002:a17:903:290e:b0:293:57b:aae9 with SMTP id
 d9443c01a7336-2946cfcd36els9992585ad.1.-pod-prod-02-us; Thu, 23 Oct 2025
 18:56:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBFxa4zV0CHxBY4BzHJatyP2ZiYRMrb1tXobr59lN4Nw2vxNFNw+Tt/AzCgCFFOATim8yILm3u+CQ=@googlegroups.com
X-Received: by 2002:a17:902:c411:b0:276:305b:14a7 with SMTP id d9443c01a7336-2948ba0d467mr6404585ad.33.1761271003075;
        Thu, 23 Oct 2025 18:56:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761271003; cv=none;
        d=google.com; s=arc-20240605;
        b=SmvYyF6HrXSNLFLP5a4smxaADwEcT4EEUVipVmEA/YNfQqthjtOjnuQInjNzat8Gmo
         Xg/YgexO3IkcRLkx3nLDOo2dFamWU0jKcHK/BrDG8CBpebfsJvJ5nEcmKs52j4cHC2MA
         DUkm9+Hk5ZdMg93hpeNGlXTm9zkxPlJRo8WBUcffqrymryr+3a0+EjyJJ7bliOW8Pl9k
         ySp0e/fhvR47U9r7RkyBPBk8bXamzPJDFkOKK7r7l1jI7tVOkMj7XYXNPS+VBtDDa7d/
         ZM4qVZekwGdLhS43yrnfQ/Cw0yH53I3IJU53S+lbZ/Vu/SldvNywBBJZzLDG7V2S9kTt
         UJCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=h3wXd6gCAHDSdcT184SwaO/DYF8T98vh52YBZMXknyg=;
        fh=1IfrLbSiNU8Kos4lNh7ySqidAY+7cxBdlCBjBumRRD0=;
        b=IYCVwXC9uZQI7NiW4kUcvn/AOw0+tP9ezi/7TRjucpRcuhTHWT6/fU1Nr9k2QqYpPO
         Yag20KTqMtVBFhsM+T2F7+SEGE8XuH5LUz7S4VUEKU+d1bpS/ZpvDbHvAPo/yJ6boe76
         i2LVn0sTGlU0l+JcPCZ96FEAp8EclU+QrRzuNdWQcG4UKClBmseWDNEps5tRWvYi9m5H
         rshk32jkh8tzxc8HZd7yqZvVY4bgKAijLnvb9IG416msmOS9CRu/F0BNDd6J/K9ToLxk
         rOjl28FnlKWBKyOJiThuZMFC0GQ3PUKMv+fS9UhyfJGxEtLbZNel6d+XfJHdmBe+luT8
         6lfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JL4m8RYf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe36.google.com (mail-vs1-xe36.google.com. [2607:f8b0:4864:20::e36])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2946c8b29a8si2164865ad.0.2025.10.23.18.56.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Oct 2025 18:56:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::e36 as permitted sender) client-ip=2607:f8b0:4864:20::e36;
Received: by mail-vs1-xe36.google.com with SMTP id ada2fe7eead31-5aa6b7c085aso1887653137.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Oct 2025 18:56:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXuXvQuAgvel11mukKhaODt47egk0iO503SFC7yCjC6OVK+ril/E+3XskXtjhUtQ1mfejhA64DhKfs=@googlegroups.com
X-Gm-Gg: ASbGncuiOL8Ttv4zLQfK01/8s/A9BH0B2L5c+58ciUnDL6TjyoczWjZT8+zMm1Avwdu
	ReuiAXudWmiS2VzZxcfxXvpkFAyDFzvq31tbI1Iub660D1BEcU94zlna/LBenhAi45bq4sjOLEo
	fAP7rprdydmWwfXTzATpD/xI0Oh0X5XQtxB7Wic8tmNQWEZZEl7Vly2Q1JwAuUspCWaUZNpIbba
	BBhIQUrQIJIxprjOB03ilvo5EX2dQiN6owJwasN3Wp7VP7pHn7vIcjMZmc7twKmsdJo6Iyxr2DI
	O0iB4kHzoP69GKn1ailrtCqUsRU+hA==
X-Received: by 2002:a05:6102:508f:b0:5d6:12fc:76e1 with SMTP id
 ada2fe7eead31-5db3f8c5d89mr162595137.17.1761271001978; Thu, 23 Oct 2025
 18:56:41 -0700 (PDT)
MIME-Version: 1.0
References: <20251023131600.1103431-1-harry.yoo@oracle.com>
 <aPrLF0OUK651M4dk@hyeyoo> <CA+fCnZezoWn40BaS3cgmCeLwjT+5AndzcQLc=wH3BjMCu6_YCw@mail.gmail.com>
In-Reply-To: <CA+fCnZezoWn40BaS3cgmCeLwjT+5AndzcQLc=wH3BjMCu6_YCw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 24 Oct 2025 03:56:29 +0200
X-Gm-Features: AWmQ_bnZfgWxvUlSV_cSyZkt3ycyNMFflOIinUoHSDKlFI4Ch_9TGgYATVsEHdg
Message-ID: <CA+fCnZdkWnRpp_eXUaRG_HM7HSDm4fLATpsqJhaxT_WGjhOHLg@mail.gmail.com>
Subject: Re: [PATCH] mm/slab: ensure all metadata in slab object are word-aligned
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>, 
	Alexander Potapenko <glider@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Feng Tang <feng.79.tang@gmail.com>, 
	Christoph Lameter <cl@gentwo.org>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JL4m8RYf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::e36
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

On Fri, Oct 24, 2025 at 3:19=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Fri, Oct 24, 2025 at 2:41=E2=80=AFAM Harry Yoo <harry.yoo@oracle.com> =
wrote:
> >
> > Adding more details on how I discovered this and why I care:
> >
> > I was developing a feature that uses unused bytes in s->size as the
> > slabobj_ext metadata. Unlike other metadata where slab disables KASAN
> > when accessing it, this should be unpoisoned to avoid adding complexity
> > and overhead when accessing it.
>
> Generally, unpoisoining parts of slabs that should not be accessed by
> non-slab code is undesirable - this would prevent KASAN from detecting
> OOB accesses into that memory.
>
> An alternative to unpoisoning or disabling KASAN could be to add
> helper functions annotated with __no_sanitize_address that do the
> required accesses. And make them inlined when KASAN is disabled to
> avoid the performance hit.
>
> On a side note, you might also need to check whether SW_TAGS KASAN and
> KMSAN would be unhappy with your changes:
>
> - When we do kasan_disable_current() or metadata_access_enable(), we
> also do kasan_reset_tag();
> - In metadata_access_enable(), we disable KMSAN as well.
>
> > This warning is from kasan_unpoison():
> >         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> >                 return;
> >
> > on x86_64, the address passed to kasan_{poison,unpoison}() should be at
> > least aligned with 8 bytes.
> >
> > After manual investigation it turns out when the SLAB_STORE_USER flag i=
s
> > specified, any metadata after the original kmalloc request size is
> > misaligned.
> >
> > Questions:
> > - Could it cause any issues other than the one described above?
> > - Does KASAN even support architectures that have issues with unaligned
> >   accesses?
>
> Unaligned accesses are handled just fine. It's just that the start of
> any unpoisoned/accessible memory region must be aligned to 8 (or 16
> for SW_TAGS) bytes due to how KASAN encodes shadow memory values.

Misread your question: my response was about whether unaligned
accesses are instrumented/checked correctly on architectures that do
support them.

For architectures that do not: there might indeed be an issue. Though
there's KASAN support for xtensa and I suppose it works (does xtensa
support unaligned accesses?).

>
> > - How come we haven't seen any issues regarding this so far? :/
>
> As you pointed out, we don't unpoison the memory that stores KASAN
> metadata and instead just disable KASAN error reporting. This is done
> deliberately to allow KASAN catching accesses into that memory that
> happen outside of the slab/KASAN code.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdkWnRpp_eXUaRG_HM7HSDm4fLATpsqJhaxT_WGjhOHLg%40mail.gmail.com.
