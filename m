Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXW7Z6ZQMGQELA25SRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BD5C90FFC7
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 11:01:20 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5bfb2547babsf706769eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:01:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718874078; cv=pass;
        d=google.com; s=arc-20160816;
        b=no3FSV8N8H5MsG4vWUFiQSLu/dZ40mp3K2+nRvYRPzU/zFvpeUUlcsFuXjSyZxROVS
         3mXFhZ2pBJhM2p7q19TkpIV2fIKqmbJZFirFavjLHxlXOJwMO6UVLkKSHn5uI5atc/v7
         J4py/9LZjiyG7MQqxV2zw/BjaNdvVPhAjf2TXnSurdp/0y1nSgisa6Gx81QJIaBfmNcO
         L6ZRAQEb9UOw27dDvyK1AezrdR/Y/Zw+5WrMjz2FIRak9V6ItWTcfR6f6R7qBf5Jj0k+
         r5gx31+x1RIUU4qFD971NGMKBQJY6iErr3dA0gTZKkhpBitimI1x600lR5m87gxCSQa9
         YKkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0nzoNMJ4VORcv+VtWELXYoLC17KhXyFy7kgEj+LTeYE=;
        fh=UcB1xITk/E3dbjALnPFPdNjXG/yBi0oo1Xs5TL/5dRE=;
        b=H0wGidpdoSj20VfngW5sq43vEBokkZ+IgxWmWt8OA0k/559lPF7MQQGk9HtUEgiF9o
         aIEU9PT0KYAOFVlg0D0lYM/FE8f50GpaD+0g9h/278yaIBgdOTZBr40QjWY9/0d/bJ8L
         S87u4+1P6pAUDveLGPAuoh7pmPdOsslPTktFc8a0F2eq8usRhMmbsQhBHRxL9nZm/VoO
         p1CJzQqFHtl+m8kQUCSofK2SO1mlEaBlpGKC960AJ6kZhDy2y4TpBGXnmljux1mOhOCl
         gQSyNC8KNf5UrabaYWAvBbsIvRwtt1ROCeJpuwdEvIZ2AE3mNUCCWEncW8GJqzuEBQiP
         KRyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="VK8XoPI/";
       spf=pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718874078; x=1719478878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0nzoNMJ4VORcv+VtWELXYoLC17KhXyFy7kgEj+LTeYE=;
        b=JEk2SeNNOU8dV/F5VNEkW/GXJd8wR/m1z22e3wQJAiUlUVtAxIjVnf80d3HI1rFF2f
         0RzX6q1bTUpEAmi7a9cDA6FO0gIRM2+NGsvrI227v8wQ28Ut4MEA/FOm9mS5iYKlCpOZ
         JD2bFuW+GVcEiVkZVjpVENtVhHfc1UEVfSaJi8o8ua5EQoPO9mRdr1iKDxNpJTTQYEQ1
         h/QeluCD5xajnZ1/EPmbUFQ/13kqHYPCdLYWv5MnyiFy2qxttlUgaP68IVqdLssnTEqv
         0xxwmyE/lY30V8L2ZaG/8mZjgOF5L4qhxCfboRxUjoQ7QKm2DaLvlQRpDd5RgZt5oltv
         9iPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718874078; x=1719478878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0nzoNMJ4VORcv+VtWELXYoLC17KhXyFy7kgEj+LTeYE=;
        b=TwqpfK9228PTxKV6TAb2O9UsrULBvGy3AJ1KGf2aU34eFrKCjfFwyJajowrruMH2oS
         siqoc8QHpc9EZEpbDK69pzNV7tsOlnljRptJ+w9vNFOCJ+7Mj6DXheSYsbbDxyKUaR6F
         LGsn3NXSln86GtIdK90shJzFWmMkGiFCXDjkRAz0RBx07ObRxkzM8sfWkH52V9k9a7gX
         e2Zkw8X0NKk8gkwpAChsyAxqjUkTvETL+j8zE+JnCSq4r5kjdZTkxtun4KC4ZLjV7WBP
         ZdiYrbM7gl6pATKBRQcATkr55MclLIHwwWrK4WnmAzb0KtvDzrrhzYsbK9JthxyL32Eh
         AcPQ==
X-Forwarded-Encrypted: i=2; AJvYcCWb5G5t3eFbe3e+DYAUJ8h83Q8zVEYgAStrV7uIcw49PG9SoUzFBCMK482h9Um3FqWvsxD5IUpFpsAhEw60qXHUcAKGxbVwHA==
X-Gm-Message-State: AOJu0YxSzykcwDhOaYMQJgWnWY3ELtNQ4jvoNLGQhsQjKppnijaFhhA7
	EH1IeIpUfRbDPAA6ov5SnSQr9RfaITQU7KfR7hCOi00h4etv6Wcf
X-Google-Smtp-Source: AGHT+IFYyuuDsDB8jbApyIboVfONEsaKXytac25vXMM+i3xK+/tE/ZaFqxTS+KWGURBNbbpE57IyQA==
X-Received: by 2002:a4a:874a:0:b0:5ba:f20c:361b with SMTP id 006d021491bc7-5c1adbfa2d0mr5501148eaf.8.1718874078560;
        Thu, 20 Jun 2024 02:01:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3242:0:b0:5ba:a73a:6de7 with SMTP id 006d021491bc7-5c1bff43a6als472198eaf.1.-pod-prod-08-us;
 Thu, 20 Jun 2024 02:01:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaa7Eu5TLY72nVKMS2uVgoqS70fqa4hYhzqljGyY4jfrwRP9tcCi/nZeoE43jx9vzCUOdIh0naNXbwn0YZbEAPwJIHdRoWtGIQCg==
X-Received: by 2002:a05:6808:2120:b0:3d2:2b5c:5181 with SMTP id 5614622812f47-3d51bafced1mr4968186b6e.52.1718874076576;
        Thu, 20 Jun 2024 02:01:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718874076; cv=none;
        d=google.com; s=arc-20160816;
        b=JPWH3amnpeE056Ki7jWpqOw/s4lzQBTUdktprbHOOfTjensbRCZRlTBgL1iQWitIov
         yi1zMocOY4wKDa5lfO+SZc6/8ypJ8+5Yq0pl2LqapOY9k/QXtu8CU+yAhweHWecdM/Wk
         xqNBatM1fKs6holOMi4Gg2gnLkx31zdn/QHS3Or7zoeoV6qQ2PnX0NMX4uHC/pmcHLmy
         R0KMwTn3Z6RGlOesG1kuK6LERh724HWa4sLFr7RjDoB5jZgHF7qQ6S0wk350Bs8ehmDT
         oQ6K390D+CshV8ovGnFLUvxB4gx8IaxrWVn0CruqdAh7BKtaa6WvNHhnxs7Ohb0B6yeO
         +CoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wvjuFU7W414jubVBbYupAK//Gvt1g9N5iqVrvVU/lM8=;
        fh=RsVtFEH19fg3OmONkSrQdxsCP6133ngYiV4QQ3V14F4=;
        b=0NJq0RA8Qx02XF0sMi5JkTa0omAxiqLHfiI8GAObMOqY2dyMtTOo4khal555i5Dz/Q
         BbKWr+C5TJz0/HohZbTztyYea/tdrf2TICfIbDmoKFP95UNc3WTFtJrIGmDos+BRfJon
         3BZ6TGHOGJLALPRLrBsZA66p1TEIf6QTpcf7IhuodKXUHJ6fhPcmkRpnLXuOADpIJTXo
         BAXJB35YSevNb8OTbDGNQVxBLXcsymnzcbqRQjV8+w8fO+e5s7E9Ploh5JpUX5gxHPm4
         x1FIH28fttOWuopldLqyeclJe2PMKAcDTyI+6cZP8G1osQ8Tt/+TTW/4bN7ULGWEXGJU
         gStg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="VK8XoPI/";
       spf=pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x31.google.com (mail-oa1-x31.google.com. [2001:4860:4864:20::31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d247740eb2si642930b6e.3.2024.06.20.02.01.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 02:01:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2001:4860:4864:20::31 as permitted sender) client-ip=2001:4860:4864:20::31;
Received: by mail-oa1-x31.google.com with SMTP id 586e51a60fabf-24c9f892aeaso344411fac.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 02:01:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVEzHH5NwZz7fjYK060DnwGyglRkfgNDE1q0Gb0PiiVGLs6V62Woq0ahIIAoqMCGCTbe4RM3vbjgCuiKB9AffgCcu17YiaIUtAWPg==
X-Received: by 2002:a05:6870:3a0f:b0:259:f03c:4e91 with SMTP id
 586e51a60fabf-25c949cd968mr4093311fac.8.1718874075898; Thu, 20 Jun 2024
 02:01:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-18-iii@linux.ibm.com>
In-Reply-To: <20240619154530.163232-18-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 11:00:39 +0200
Message-ID: <CAG_fn=VbO5m18MU6v4-YCbC03dBuBGBRTzi7sEvZCL6vSDG=9w@mail.gmail.com>
Subject: Re: [PATCH v5 17/37] mm: slub: Disable KMSAN when checking the
 padding bytes
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="VK8XoPI/";       spf=pass
 (google.com: domain of glider@google.com designates 2001:4860:4864:20::31 as
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

On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Even though the KMSAN warnings generated by memchr_inv() are suppressed
> by metadata_access_enable(), its return value may still be poisoned.
>
> The reason is that the last iteration of memchr_inv() returns
> `*start !=3D value ? start : NULL`, where *start is poisoned. Because of
> this, somewhat counterintuitively, the shadow value computed by
> visitSelectInst() is equal to `(uintptr_t)start`.
>
> One possibility to fix this, since the intention behind guarding
> memchr_inv() behind metadata_access_enable() is to touch poisoned
> metadata without triggering KMSAN, is to unpoison its return value.
> However, this approach is too fragile. So simply disable the KMSAN
> checks in the respective functions.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVbO5m18MU6v4-YCbC03dBuBGBRTzi7sEvZCL6vSDG%3D9w%40mail.gm=
ail.com.
