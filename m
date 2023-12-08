Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTETZWVQMGQEFHKEE6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5038A80A9CE
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 17:52:30 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6d87bcf8a15sf3212245a34.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 08:52:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702054348; cv=pass;
        d=google.com; s=arc-20160816;
        b=J0QBYXb6p3ZGBnLzObwZmX+owMlX9Ekd/mDf9EfrtaewZG8thABnOcD53GCxiu54dp
         c1r8Lr7i5AIFQ8tgaNKUiqJ2IM329i7YRmG1jLTWhJPEP6T1/l9AATB4V2Dc08QPMCfT
         VCa2OZV4r38075f8PpiELjHjbM/4KVJW3VXVF8uwVXs8m4y7k3XQ9ooxuDUWH/GdTqi8
         BH4ro9bR82hG7zKcDmObW7kHfPdrRfl5U1faM0aweFHAWueDWNEJFyKb9UTtIvK9QjGa
         tfAr+xify+LGK9P2aCIw2NFnO95PmSMEF4oY098b7+IBYHqpkw+ZnWvgVspHfewchMiE
         Lntw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SNH/3f45nDSjUxygKR7+df3C9sABCTk7tFuOjka6cdg=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=J8W+5Wnc/009KRdGFODCfXJAZkP5onbHK6bdkQK8Db7BbYwQlJL31HeAH9gfoZP1u1
         LwIAdsOE9hZpsz/n4VuQZiH0PdZRYHoZSr7hjIbrqmqPv+BYQcnsKG2cyW71MDbgZV/I
         QwhtHm+54EP0egSJwdmeCJ+j3B0O3uKhL96ZhXU1P44sUTks/RjWuYn/HgAHPH1tUqP9
         WPkzwBJTWHEhKjd17L5WU2KrFnGgKV+BP19MMbAC+FDPsZnvn8cNvKEpAjcyzmtKiPYo
         Bdkismm8KW6PNHVbrnfPYbsS+/FbOVcdI4MmyK7/OmGWjPO10movl34kgkPzc1I2W4/C
         1Uyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B3pkHgkF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702054348; x=1702659148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SNH/3f45nDSjUxygKR7+df3C9sABCTk7tFuOjka6cdg=;
        b=GESorA4jIZRE5gNoLaPpoOygJo5inGtPLoSK7p36UqwhXTwQwZpfZrntqj+qXdYrxH
         IYbopfbUDMr/6ZpZGuVngLwF8ctzzL7VYSbWyGQMAQvGL6rYHqwMkeLBwQji9z7uvG0c
         aXwQq5j/TCOIIuMRzybsBwzEzJdhEgv2l1z4Jqp/HZxWJRcDUvHGTPfqqPTpslwd7Tf4
         15i45AHqXGF4WB/GEoNBt93Qb3q+HY1Z6IOglisPmsZvpcBdhlYM26B6GbpttsR7AN8B
         zB/YziISqHDECdi+Ec+trTkxl3kmDr2Libr07lP9UMco3W3/ZQ1q3/AHiDyeRwp/+WvG
         UPmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702054348; x=1702659148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SNH/3f45nDSjUxygKR7+df3C9sABCTk7tFuOjka6cdg=;
        b=BPvChq2OJ92XOxspcyvRgQzWWwi/4sTYxlyH7z+/gboKkoKOf/G9hNsRAu0RI3p1My
         XYFgFs8yBrFlJqmfMfiks5T/b3pMaWHwzRSMGIwjOfr2CPIbUffI3FzUB0UPD/r/cUkU
         LQSm5N5ebeJ1bHSKLM4MtpP7bb0UWJDu3RgAyJDtua4MouF8mxbY2qOJWuOrxTt6Am9f
         ldzJyiBWVGsxvHQ9unFNAyQ10fxQA9wKyK7luHQmhVyEXVicHXYzTs40j5r1nqRA56yt
         19gqI3Z7IKPTDgxV+JJB4y6dCE3+j4qKUCPOIBatue9EopoaKgLHoKvU6amMY/f17xYP
         kFKQ==
X-Gm-Message-State: AOJu0YwgpjnSl+g7jznpPkRtTxwRoOd8AsgCJlF0m2wE2/XOIHMy19a7
	KI1INcjjpF5dmo1+JZTWJdQ=
X-Google-Smtp-Source: AGHT+IF+V0/aPzrQejSC3axUmp6WgbfrGQW4fUb1wunoERaL7ZpckHsyrndmT/lB0WuNgilh3TLXlQ==
X-Received: by 2002:a9d:7519:0:b0:6d8:4bfb:eb4c with SMTP id r25-20020a9d7519000000b006d84bfbeb4cmr341409otk.9.1702054348736;
        Fri, 08 Dec 2023 08:52:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a20:b0:423:731a:7859 with SMTP id
 f32-20020a05622a1a2000b00423731a7859ls1479851qtb.0.-pod-prod-09-us; Fri, 08
 Dec 2023 08:52:28 -0800 (PST)
X-Received: by 2002:a05:620a:55b3:b0:77f:4e6e:f533 with SMTP id vr19-20020a05620a55b300b0077f4e6ef533mr387947qkn.27.1702054347815;
        Fri, 08 Dec 2023 08:52:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702054347; cv=none;
        d=google.com; s=arc-20160816;
        b=eL90dGhW95c42VmytPPeZ5vdauhqxL6ePTl4MXSS9E3C2Ae67V8xMTbE23lggJgzdL
         vTON9ia7M7Bo19t8Za739QDnJCUVGivDdUsN+ibgKHmiT/kW1KIW8csJX6UeZr10FLED
         hJxttF+drrflfhP/1ZVYv/hvHcNwcP5+wXl14CFlGYK6ynayCZpNwhu78hPY29E5abow
         xXYXjyh9BLDEk4t7SW6rDFyYceGDyp4Dser7IAZhOTQ/V8JbZjNYreY7FFpx6zXnlxfH
         VxPA7pbKeDwAVeIbfFuxzlgvIttvHFGL9xfFnGJvqylnUjhQqCEz4n6sva/uxpi048jE
         RREA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TCwpDcUhOmDqjvrlR1SNfeF5wJTZtg8zSBwCC0FJlGs=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=UMOu3UZcngU79gPYJ0AaCaoVuLUP5v2UjlefvV0dVkPpqaGfTIgFRjFCSoM3dZqnlr
         5y4RUUjeRPpd7nh862PEVf8H0mq6I0rtX4Iv1/IrZ51vdChJxgJPz8dvvFDVneQ7Xvb9
         IKaXAlbXX/JO5xXIWxNoaO2gUtQShrzTK+8qxLxNlH3e6BVWjrvWlvYG0mOLKMSuaRTF
         ZqU9wgGOvT6BvbZgsr5JpWb9oyU/gvNDchCEHgitPrchEsQt0fiwCEvwu+r8Nvjr9ETW
         b6CyQqT7aF68pBS/VhF4LxQWLBiT0mGzdd5IYah7Fm9LtL91OpedSiPHNdCKqDqjKRu2
         zGDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B3pkHgkF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id ot5-20020a05620a818500b0076989bfc79fsi200846qkn.1.2023.12.08.08.52.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 08:52:27 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-67a9cba087aso12974986d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 08:52:27 -0800 (PST)
X-Received: by 2002:a05:6214:4013:b0:67a:ccb7:4fe0 with SMTP id
 kd19-20020a056214401300b0067accb74fe0mr319829qvb.82.1702054347432; Fri, 08
 Dec 2023 08:52:27 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-10-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-10-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 17:51:51 +0100
Message-ID: <CAG_fn=X-jgQo9p205h+G=omdN-u3n5bUAGZ6u3W7=8bo966gfg@mail.gmail.com>
Subject: Re: [PATCH v2 09/33] kmsan: Introduce kmsan_memmove_metadata()
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
 header.i=@google.com header.s=20230601 header.b=B3pkHgkF;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
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

On Tue, Nov 21, 2023 at 11:07=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> It is useful to manually copy metadata in order to describe the effects
> of memmove()-like logic in uninstrumented code or inline asm. Introduce
> kmsan_memmove_metadata() for this purpose.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  include/linux/kmsan-checks.h | 14 ++++++++++++++
>  mm/kmsan/hooks.c             | 11 +++++++++++
>  2 files changed, 25 insertions(+)
>
> diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
> index c4cae333deec..5218973f0ad0 100644
> --- a/include/linux/kmsan-checks.h
> +++ b/include/linux/kmsan-checks.h
> @@ -61,6 +61,17 @@ void kmsan_check_memory(const void *address, size_t si=
ze);
>  void kmsan_copy_to_user(void __user *to, const void *from, size_t to_cop=
y,
>                         size_t left);
>
> +/**
> + * kmsan_memmove_metadata() - Copy kernel memory range metadata.
> + * @dst: start of the destination kernel memory range.
> + * @src: start of the source kernel memory range.
> + * @n:   size of the memory ranges.
> + *
> + * KMSAN will treat the destination range as if its contents were memmov=
e()d
> + * from the source range.
> + */
> +void kmsan_memmove_metadata(void *dst, const void *src, size_t n);

As noted in patch 18/33, I am pretty sure we shouldn't need this function.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX-jgQo9p205h%2BG%3DomdN-u3n5bUAGZ6u3W7%3D8bo966gfg%40mai=
l.gmail.com.
