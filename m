Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAETZWVQMGQEWKCIAOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E2A180A9CB
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 17:51:14 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-35d66f169bfsf21443825ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 08:51:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702054273; cv=pass;
        d=google.com; s=arc-20160816;
        b=X/yc04EO/skuraopQvl6QDSkfN8GkLnyjeLVYiAknFvkp+Bv27/0VdPDOI/HOnoGcJ
         9PZcnu4/aJk3ZuY6kmt0tFg4cobNxenqq4sWqsVKSwA6e9izSfU1tduFpQFHdHoUvSyZ
         nVUN7pc22/CcwrR7cd6QvixcfD2MMdbR9hP8RgsLhVV1arpPc0iF91jBQAZW9DspOYdf
         KYbbJB7McikTpPwLQtVJMtXGb0TL7fogvlyVp+zZcWCbaOfg7tajee/t1btHJXLs5HBF
         Lq3kRkPgBaLfGnGNhcFX+fmMtmXm5c0bDFFI5naP9Rc9Vnrta4G7QGKgoSXKI86DCaHr
         72Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2q6PAKUk2QcRzFjchyfxXxMFxs74HT+N3I7xYMLNw/8=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=tSO0pHYnQ4tBvaiI3W4QepIXpc2JjsZOUTm29GnwutDonM3ldjPMB31JwceLRIQg+6
         UP2AXSxHKrlT+pS1q1+A8zq57v4xdUCwKbertsRS1LSclq2eryp112pg9uKFmCH0yJZR
         juTV/dAlZBCn1nXFFbaBB51EOsmV7DVt52s32VKJdcbeliKPcdV57i2L7nQtmS9PDYuw
         izZbcxXyufs4kiFlhzFvjJZZ07IbEahtveWpV53srmJuKRFWacWsTr1xc6Zqu6bGpmG9
         ZkCeHjuaHLPRlj9H1rrX7botv+f9B/ZcmTdc3nAG1Vvq1qjYX7MpXRxLkLQkRTqpTVJm
         9M3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="2GC7Vy/O";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702054273; x=1702659073; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2q6PAKUk2QcRzFjchyfxXxMFxs74HT+N3I7xYMLNw/8=;
        b=hUtEZzrAgmsDFX7tX8co4OrlZDWU4UHW/mjr1fBr+oVB84tqddWQ5EVt9vu7F4MVR8
         yF7xeP9Ibmhkvcqe0C/JLM2UQ+5uQUQUF0L/LjggzSxfdk8dTh0Eab1qbCPUwSHFDDU3
         guz6lkl8+MTq9RNw9VGugN4QCHbaglazZEzkk7WRnb4T5c9uiU0MohJjrhppWJ5tx9av
         KJZmlVvlUOKt4SoCDTDQAHmr+brYRfqQSCPqhOaEdiKdJh0ORBufmuuU7LRcOc17krOE
         Hz7hh8ysNgPteB2xjN7dYE7MsNrY73n0p/WhAF/DS1Mx9qvnvMJFdyfmffFhYns7/jMI
         wBrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702054273; x=1702659073;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2q6PAKUk2QcRzFjchyfxXxMFxs74HT+N3I7xYMLNw/8=;
        b=FM8F5bNPOVvZCuanjhPgpgCInP+zv0GCBwTUpErXGPPvNREKWa6dOCkJF5rjPC4PVH
         DUZuXs5YCkA2voHnJjm6lxx0gEoeYtgCSHxnjW9BjCLljRdDdVTw9cEY1fFcufWA8yyx
         afciXt0vgqgMRMWGTFnC3aaNKppPikHsqWcLHcKm+VG8HA85QN7d3NGRlzBDMQ7PGGza
         5Jj1aC1MmKClElMGyJBP2zfhA4UE688m4CouNql9bodI6lZTGZNKC9KfjtXvvrOeB9us
         f5ki2g67BTUNGAUyWI5t1LuoZRQcT2ix+JlsLbcIBO8wl4121r3U9BrWB5Y2WAinswze
         Crww==
X-Gm-Message-State: AOJu0YwqIHVGnlsg+9T98OODIrlDmujJ3UDDQKHoHiOpUfhMpkMUcgHa
	97SBI5Hgb5e5gzVvAlZBkSk4pg==
X-Google-Smtp-Source: AGHT+IF4MJNQHdetskiVXCMAuJZ/BB6tq+K72jcwyjos0UcWl0ECRR3YxlhZSK2O7d9W79E1V4mbKg==
X-Received: by 2002:a05:6e02:12e8:b0:35d:4ecb:1752 with SMTP id l8-20020a056e0212e800b0035d4ecb1752mr528314iln.2.1702054272408;
        Fri, 08 Dec 2023 08:51:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c6d0:0:b0:35a:a617:5f3f with SMTP id v16-20020a92c6d0000000b0035aa6175f3fls69252ilm.0.-pod-prod-09-us;
 Fri, 08 Dec 2023 08:51:11 -0800 (PST)
X-Received: by 2002:a6b:6517:0:b0:7b3:92f4:f3e9 with SMTP id z23-20020a6b6517000000b007b392f4f3e9mr447411iob.21.1702054271224;
        Fri, 08 Dec 2023 08:51:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702054271; cv=none;
        d=google.com; s=arc-20160816;
        b=GkJ1d/CPDWuqU66XAK1xfXpwZAM/usaLGlMrJcQ3HmK4RuWi2ccITjrbUa8lXWTfdl
         TJFvfz5XedzH1iTnecL9rhQ75oW7ply4/g8arh/wc6om4QZzjMRUN7V0MTkynvEdtrHc
         SpHxR3cFCJf5Te9DCqCKer7NP+g9NzjmCePBbgB5aEMFvoDI8Uc944ZG0ETbKlB1+2LK
         m75M55hwR+Je1hqhF5XJx9gc7bX2GjE3dLEWlu6y9uBbaWmUvTdkbTzvb48G2S+8rcie
         Iim3dGXe4MOgR0N3eUTernKMOTIybHViJ3kwlaruQM9oKqm22J0BauQljjSQuBEAVJ4j
         p/uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eIcp9jypYULc/a0PN4uogFYiIDljiHAuDtNHVxk71mg=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=q6QVwXg/HcGubjZ2IWT2MwJtfrCQNImobXpscgKPBaoNBrY3PdLE6/Rqp10kCng+za
         j3tljMujcyAq6wDT57AXxjiZfvHZ9C4u/ZWyS1weDvjlKpt650itIck/4EJo6Q7EZJGv
         JN+kOI0GHDRkurmYUPDM6oh8C5SRANLSjmVhGgjGs9J0ydVKVFHfjiFCdsdc2oE2H+Lu
         2k3mt+jgAp9OCaNoP9qVB59ia/HpbuP4MueW6vqKALLEvx1g/2FJadSzpy7aqIZgcYVo
         suGLAoxCms0iyN+Eo1Pde9CTXry+YZ8NRJc45euIhXG9c7go+4ieXYNv2C5TdiY9BNHe
         FJiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="2GC7Vy/O";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id dm8-20020a0566023b8800b007b6ea185e56si221506iob.2.2023.12.08.08.51.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 08:51:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id 6a1803df08f44-67a9febb2bfso13033726d6.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 08:51:11 -0800 (PST)
X-Received: by 2002:a0c:ea88:0:b0:67a:9a7d:ee10 with SMTP id
 d8-20020a0cea88000000b0067a9a7dee10mr256389qvp.0.1702054270555; Fri, 08 Dec
 2023 08:51:10 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-19-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-19-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 17:50:30 +0100
Message-ID: <CAG_fn=XQkhecLYFmJugOG+GawvDQ5Xsj5fTRbOAhU8Z5CfsjPA@mail.gmail.com>
Subject: Re: [PATCH v2 18/33] lib/string: Add KMSAN support to strlcpy() and strlcat()
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
 header.i=@google.com header.s=20230601 header.b="2GC7Vy/O";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Currently KMSAN does not fully propagate metadata in strlcpy() and
> strlcat(), because they are built with -ffreestanding and call
> memcpy(). In this combination memcpy() calls are not instrumented.

Is this something specific to s390?

> Fix by copying the metadata manually. Add the __STDC_HOSTED__ #ifdef in
> case the code is compiled with different flags in the future.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  lib/string.c | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/lib/string.c b/lib/string.c
> index be26623953d2..e83c6dd77ec6 100644
> --- a/lib/string.c
> +++ b/lib/string.c
> @@ -111,6 +111,9 @@ size_t strlcpy(char *dest, const char *src, size_t si=
ze)
>         if (size) {
>                 size_t len =3D (ret >=3D size) ? size - 1 : ret;
>                 __builtin_memcpy(dest, src, len);

On x86, I clearly see this __builtin_memcpy() being replaced with
__msan_memcpy().

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXQkhecLYFmJugOG%2BGawvDQ5Xsj5fTRbOAhU8Z5CfsjPA%40mail.gm=
ail.com.
