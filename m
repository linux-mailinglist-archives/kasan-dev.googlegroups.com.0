Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3GB3OVQMGQELF3RD4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BF7280C62A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:14:06 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-28863e42bc5sf2525734a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:14:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702289645; cv=pass;
        d=google.com; s=arc-20160816;
        b=czzc4NxuTNk2Qk4iB6QseU9aqMAUY/hhC8/JV4PEJah1dE1ES5RWesm5TCuxcyUNIt
         e6fxAcf2K482AP9dVFw5EoO+K4peR9hF5JEnYbPCFEAz2tEhuZ7WaJcpLtt+vGL6ELbY
         FIa/Cx9vhldcqGccXG+5+zMGV4NA7eD4QD/tQgySn4pg2kpoqTHFREz19TYPn2GxtYIb
         H4vighXq2oFDoJPxNn/1gAPiE2VvBZsAIzCdbBPuiy+5AJ8NPlyZO9FIS1OiBDhZXjzB
         /1LilBnqRjZJHBA8c17ovzNTzj867xHjLilqtXBwzWGElR6hlPMP7qNDa7GqXHrffV8d
         wWqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SyPOEoVrnWaqE+L+If83xWI8iELDX/aInj6ZSGburg0=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=j7+uwOpMeWeN3rxN9btKmTzXmuhVJR2EMUaHHNplHGGQOh4QOLCXN9EoMcHNMrKexn
         AAcvMLlDRKV7QslRVLVM4UGb/x1zPhGwo0wjISNJ3XhcT5S+mjAJhU5I9HELscX7O2HL
         kVem1SLGOUlGPfSbBqwETYhg8qKbGtHm2Hwi4zpdOPF4wUfguprBxW35MfsZ8pPm1zTp
         59IePMD6TZoPmrWaWluxh+Zk3sG/tC/cVjzWgVdklgIEXOCx17sXJL9ur3cw0mLqbTQU
         +c+KbYPAVL3Hcn+6yODXbtOKWZ6hvxC6AFLEXzR0CvzVOjDo9/HjKrMwxr6kQEz73YU/
         EmTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UxdF0HkH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702289645; x=1702894445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SyPOEoVrnWaqE+L+If83xWI8iELDX/aInj6ZSGburg0=;
        b=pnCmrPWq0AzjxIMUoe4thi1DEZH2tUh49DSE5//bhs7F4Mplul9RF2ygO0HsouSelF
         LEoYImWx2CEeGbhQFGk/wDVKTrPXMkNbdZACs36e7zbnRHwb1oBNHaEmqJf22N2c1R1a
         a8IXh/ti9cgVxhyjoqjBZIjhuFBhauexlTt1B0YqFLB8ZCSWndTXT/E1S+dd0lJtGmeW
         H0pBIKGcLWAYIGaPlscsN+oScEnN4oaEXGm4gAouQwpODFd/biDIArMHjFxy1iZVbH0d
         3FZ60MnW/GVQb4A/QiRNLWYqBgGnQhsDxtO7BAU/a5Mcgdll5KDRwuPj5vV/Ya2+odKV
         gXPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702289645; x=1702894445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SyPOEoVrnWaqE+L+If83xWI8iELDX/aInj6ZSGburg0=;
        b=ny0uJvzil753O5OY/lJyryGozdFjDJST6fWoKghUhdDydx0nCJhtysUNdLbmVpend8
         TmFZ1oOTFqjbr9Y961rIDKbJ1s7TDYeWHOEi7jPv3Ph5n2VSviw2+kVc70vyQMjYxM7B
         A36Ib9VH5Mo4W4xFpGxsm0adKAIR6UOk8QTOczQ3oZ4ZSQg55ef5sIHiI2vnC+P8W1Ht
         muCjOt3eTpR2R3YfNxbfQWpofZRfA9hmzHTy0Gf7XsqXXvqPSvNFov7ulRQnMb/BkUEp
         TbB3RYJryOVGuUEUtzq2f6EuS2ooczdRkcsVgNGVluSlRQrGKH/C/ot4dPyy06dgSogK
         b6pA==
X-Gm-Message-State: AOJu0Yxl4APd96KAFtD9rIE38Uk6W+LYWgHycqxYqbysIKUtCQNVlvZA
	f4R/fwvFL/fn1V53UK0C31c=
X-Google-Smtp-Source: AGHT+IGPcb7uL5qrvEHF93r1VnsA0bhXwDi3gpvh2IRP5oYD2WUf/KoRZr/icE4pPCIGl4zCaL9FuQ==
X-Received: by 2002:a17:90a:fb48:b0:286:8672:5199 with SMTP id iq8-20020a17090afb4800b0028686725199mr1344792pjb.35.1702289644766;
        Mon, 11 Dec 2023 02:14:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1f46:b0:280:878:8539 with SMTP id
 y6-20020a17090a1f4600b0028008788539ls955914pjy.2.-pod-prod-07-us; Mon, 11 Dec
 2023 02:14:03 -0800 (PST)
X-Received: by 2002:a17:90a:d306:b0:286:f3ec:289 with SMTP id p6-20020a17090ad30600b00286f3ec0289mr1540051pju.45.1702289643612;
        Mon, 11 Dec 2023 02:14:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702289643; cv=none;
        d=google.com; s=arc-20160816;
        b=vejLkEyD2twwpEX++ziBFT/mPZ5H8N5+MIaeoouWa/c17uL6ig/9VaG32SoR4L+h0+
         aBDTKPX7Lo0HFBPNI84LN+v846k13a8Zfr40m0HSUvhMSO1AhJ8MQfnGkxjZWem8GwNZ
         w5009fUtWINl77EuDGzux+h2cUfApZJ+DdM6ZtrJkm6otD8Gc2yenaPSGvNjmYNxahgt
         iUSiF6x+kQoFkFaVr1htJf4E2uo1zcViICuCQ1JtgkuOfR8yFsjTg0fJETvZmkSJrG/H
         9GwFGvQC83+h3wrnyN0RWHebijnX0e6B/r4M0qOcD8AHWHt8Hxn29uO/2T/zjb5JdyhC
         M1HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5Z6zY4c0Tb5+ieU4d3Nz6Jn4MLK8nHKOQpLlbBpEjKg=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=YqquR8+n0VLcPbX5rxx9KQjzU5i/H6B02HDJ01ZM6aAA7aaY81YSTxyK64Js5QS/j8
         pS1wu8bmWnTRl9AGTv4IINOoY091APpnLmXvfsrUamBAiM9Kg9Hg75gil2lstq4H2ehe
         RTGy9Qv8XvjjTGSHEszdBeJwWVitfe0nWw5NS9wFd88p9qWl8N+mWKaEDcQYwx6msgK7
         SPOyT7NHT0puYoWX00eVNGRn+Pwt9c52cJn32fOhMFRaVKoUEZxSCDPzvK3JWQYj9NYq
         mWulNIqQlx7Qzlz+T9ykrYVC3GZk8UVQFc4jA4PnfwpJsV+Qg4jJfADdjfqZUepdnHQF
         x6FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UxdF0HkH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id si5-20020a17090b528500b00285318fade4si665974pjb.3.2023.12.11.02.14.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:14:03 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-5d8a772157fso35301717b3.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:14:03 -0800 (PST)
X-Received: by 2002:a05:690c:3249:b0:5df:4992:9f90 with SMTP id
 fg9-20020a05690c324900b005df49929f90mr2222920ywb.34.1702289642775; Mon, 11
 Dec 2023 02:14:02 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-28-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-28-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:13:26 +0100
Message-ID: <CAG_fn=VE7M590AqPceT1qjtf7qS1QGBfvnprz9s=0U2WgRmK6w@mail.gmail.com>
Subject: Re: [PATCH v2 27/33] s390/mm: Define KMSAN metadata for vmalloc and modules
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
 header.i=@google.com header.s=20230601 header.b=UxdF0HkH;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112f
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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
> The pages for the KMSAN metadata associated with most kernel mappings
> are taken from memblock by the common code. However, vmalloc and module
> metadata needs to be defined by the architectures.
>
> Be a little bit more careful than x86: allocate exactly MODULES_LEN
> for the module shadow and origins, and then take 2/3 of vmalloc for
> the vmalloc shadow and origins. This ensures that users passing small
> vmalloc=3D values on the command line do not cause module metadata
> collisions.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

(hope some s390 maintainer acks this as well)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVE7M590AqPceT1qjtf7qS1QGBfvnprz9s%3D0U2WgRmK6w%40mail.gm=
ail.com.
