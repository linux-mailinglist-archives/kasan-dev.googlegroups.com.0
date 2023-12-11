Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU6S3OVQMGQERABKEDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0190E80C72E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:49:57 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dbc5f7781fasf1673549276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:49:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702291795; cv=pass;
        d=google.com; s=arc-20160816;
        b=EnTmx0Hg7IQTU1pf2dowHD9dN9SuemHG1mI9nZbzfw8VUweCptg/6kLvIpMzYvvEWM
         GnbNDiex/ZSARjUQdpkgLxW5LXA8RLsWBsqL9DxiiGxUZEGMLbOvy6bWEt+1JeECilI3
         RWHjbIehzF/tCQoNE/xcFhXNlNe4BtdLP8lrKhHuoKlCbQOAgLMJDOftxDJmPXdQNHuH
         dukGKLiZusrv4G2CeDXD3341cmMOnx9VT+2dFuVbeJTJ3J49uFaTZEAKH8YyXxdzZJP8
         c9ZQ7BWWRNuCqapyzY8x8iUbSec8hwB+p3rP1rHkJNi6juyVq4go8aApBJeyCVxdsXKp
         Q6uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DYL+n0xvfUc37T1V6LVLnmCKOTfQzCoPuWmB10iVdR0=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=yNnYQxZe5ZYHcpdk79VMIeAjklCo0R/SoOtsZFxAG+hyBVco9qyi8P+rF4wodCUhBF
         HZRR7IGbNYm+XNip178+Qxl8jV2YYHDIsUkMdbwCWrFTlmrlquyVAlTNQ/ULOmsBr+gB
         bgDhCH0QV4is9av/rYlNtBMmJfGGOJvFWVsUSLtaFW/mZcIROl8ttufrbcXKvRtebZyu
         qfMAoXFJBc0cfUN7V+WUMVpTmOevqEIT7GFo/zWw+yKNlSY6nPvNcZkDjb+BibTGztxp
         /ivQEUcxqci9sSLuw6Wo+5FbsyC0xt3L2YZBBWT5N4sb8MJ+W0QyGB8M+hWL/fG17Zym
         RH7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3eQxZMJX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702291795; x=1702896595; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DYL+n0xvfUc37T1V6LVLnmCKOTfQzCoPuWmB10iVdR0=;
        b=xeuQxGmMg+YuL9oU5Ai0dQ0T0UrR+j/a2e3SRV9ECJFqQeW7uLey8DUq3Lb5IZt/aR
         Qby3KgooZfZc2EiAo227s9NdjmKMg/0USAFgmiWOiZbISgSYwjc1V0B/yyOGMSFJYFKh
         DWSjcYHYecoDn+Yl+3c+WP/chznbjqg6FWJiIbRJL+ATrRwP+j7L9u1RYFoiKo0nuis/
         ApZ2tV9jT+4XKri9pqb7egXYyttjk316rtJvwsso99QQGw4H2V/zZ7lJdOFOa9XPIh4F
         qp8PkF+94YrgDC3+X0uPEF79DuXkXRy2rA7s7IKCJdPa9Bu6feZ+SqkkXlgnJ+GBp3aE
         eSmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702291795; x=1702896595;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DYL+n0xvfUc37T1V6LVLnmCKOTfQzCoPuWmB10iVdR0=;
        b=BKHt2jtkpa8dCgPYgUwLT9v75PCO9nZxkNKCMOrbTxvP+EhqDs1c5MisNXMc7WKfam
         RiaZhIokYu/PdDR+GXvLuLHJsxmKFly+mbwer4/ocdoTjtLtDNoE0iNUgBK90MH4OuaV
         G+zbq6dx6gzqdbKsWOl03YI7S8l8ah2vm/Oy82QquEDSAF283QQyZkoTpO8A+mfXNeSF
         AhsWwu7q5rPzlcRpG5h2nbwb+s1s7coTpT4n/3+YyQENyvbq0/+7537QE92fv2ZGkB+5
         HNkdFU5Nb8rRlboA5Cl2UGOSCRKXR7DF7M9sfbSgXePTEcyRn3OIGGsTm2/Zgi2TR0zj
         qFlA==
X-Gm-Message-State: AOJu0YxV9SKXX6pSGH+NsFZYpkAXTO/mz1lrdpPAR0KxLYEmLQctlvUn
	5kSjVGliMBTaWrIfOJ88LTo=
X-Google-Smtp-Source: AGHT+IHtn1lLxszgoDZ8TWUXKtyjsqzPZNWp/0bc8YucwYfbjYJmpdze+QfCyPOEBnsimAXVavqvEQ==
X-Received: by 2002:a25:76cb:0:b0:db7:dad0:76ca with SMTP id r194-20020a2576cb000000b00db7dad076camr2361786ybc.102.1702291795592;
        Mon, 11 Dec 2023 02:49:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4b88:b0:679:fa52:346a with SMTP id
 qf8-20020a0562144b8800b00679fa52346als54612qvb.0.-pod-prod-09-us; Mon, 11 Dec
 2023 02:49:55 -0800 (PST)
X-Received: by 2002:a05:6102:511f:b0:464:9a2c:e357 with SMTP id bm31-20020a056102511f00b004649a2ce357mr3003498vsb.3.1702291794871;
        Mon, 11 Dec 2023 02:49:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702291794; cv=none;
        d=google.com; s=arc-20160816;
        b=HyBGPo8Nx6/QWOSLIAlfpVFyADx3ss9X3b7Zm7KFrXdfKuVQdJ3ka3ahwoYSFjjAti
         Pgft0mpab0pYWrGimRQ4zHVWHIpf1EhXSgfF55zWk/isbY7IIJr+gKEBcxCzR1SeRdsH
         efQ4pJ5RmnpRjWQOt8GNRKlfVadfn1zxytY/r6sYyzDIW1rJLqZlaWB8ZOXZk2/gzQcc
         WTOLLAMTW4EuyzKuKpmTd0gMzn1QT+1YuCg/7B/lNFi9oIeF7gQjgE5TQdCAKHqxDNl2
         r+8WezAEVZrunbF2AM3p6dvqVBEoZfQH3o8i+PBQBntpHdO0uxhaFXarFWMOasCOCC5Z
         Ig+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tcKQpflfU4B5TCVP/h08UJJZWjI+RvIJpIXiYwS5E2M=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=iD2WLOVdWTXy5oghguZ8E0Pxtj2HayIcw/RPyB/nuEzKDIZ54gzgv1/GheZhcsTk88
         efJ96aKBsDOHZIOKaDuyLoBaDOsX6Jyxxg1gb0fSWlv6E3i5O6kBJ8EO084E6jcM3gfO
         /4wuQxdV3yaD8g49EcTArEbEqb7M2fJVuoflYPeRHWP2omSdgH/QtW6iiWVi7NbLE/J/
         DfhQYiqju4CY/xPj5YU2J6BQ0ErSQEr05alp/n0WRVUlshYDzGnuqTLHZjum5725QgKU
         hApzUHnmLvqKOTonq0v0bBiFUKbQ2i3auy4LcOQFlidvfZD2Qq7qlbGoNTztRE3xVW9s
         Jx0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3eQxZMJX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id h37-20020a0561023da500b004649987350fsi1974612vsv.0.2023.12.11.02.49.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:49:54 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-da077db5145so3345289276.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:49:54 -0800 (PST)
X-Received: by 2002:a05:6902:1aca:b0:dbc:5dfc:9d6 with SMTP id
 db10-20020a0569021aca00b00dbc5dfc09d6mr2177747ybb.35.1702291794335; Mon, 11
 Dec 2023 02:49:54 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-29-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-29-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:49:18 +0100
Message-ID: <CAG_fn=WjEV4CP2RTX1xeuG=kd9Lj5X1Tf4QCRuNW-vzDUpzBGw@mail.gmail.com>
Subject: Re: [PATCH v2 28/33] s390/string: Add KMSAN support
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
 header.i=@google.com header.s=20230601 header.b=3eQxZMJX;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as
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

On Tue, Nov 21, 2023 at 11:03=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Add KMSAN support for the s390 implementations of the string functions.
> Do this similar to how it's already done for KASAN, except that the
> optimized memset{16,32,64}() functions need to be disabled: it's
> important for KMSAN to know that they initialized something.
>
> The way boot code is built with regard to string functions is
> problematic, since most files think it's configured with sanitizers,
> but boot/string.c doesn't. This creates various problems with the
> memset64() definitions, depending on whether the code is built with
> sanitizers or fortify. This should probably be streamlined, but in the
> meantime resolve the issues by introducing the IN_BOOT_STRING_C macro,
> similar to the existing IN_ARCH_STRING_C macro.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWjEV4CP2RTX1xeuG%3Dkd9Lj5X1Tf4QCRuNW-vzDUpzBGw%40mail.gm=
ail.com.
