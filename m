Return-Path: <kasan-dev+bncBCCMH5WKTMGRBANZZSVQMGQEGDF6VCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B2CE80A487
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 14:39:15 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1fb3db72d92sf3588414fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 05:39:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702042754; cv=pass;
        d=google.com; s=arc-20160816;
        b=i2eMJDZUsZYziTkWWZvWXdqrqFBwe1YXZZfePOhIbmOyefmBqmp3AW/wDJeKRG2tXP
         UadPT7V4PjEXCtfqnWWBFelLSYnD6VjFO/GUduhRpuKSjcgYuzZ0zJiAscjyc2wXOmYn
         8lqyQ0QoK3FElhWKDpi7f+v7MxDO5Vr3xSV9u8bT5Ay/prcJG4wCVrRb+wz7Ov7D2F2Q
         AjJ5SB6dGSl9HvXgddRJ/h862Ew+Yg1CkmM69CIxDhH+liPkIrJtNaDI6dy8P63kKBSF
         mTxC6WWSGd9NEtWPh58dTWRLXaaBqdoVucsrxsYzrIfkIFOaysi7vdKWQMe4H4GBJPaL
         VJGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uBFUBrU9b5uK1ROohSVwifv2X72NXogpNEskEDPXyWg=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=GQD3KSdqLXMXbA4YcY3FXxexFaSi+sXV0PvdyVEABYTexu1yTcRzruICWSjt0va6Jv
         8p7QXKuLnic8k3tfFkupROEwPPLyia06ds0UI1xT4Wnx9GrpJ+/l6XMu1YIsG0o6pNEl
         wI6Sk5dXFK0RWojNnTYSjP2UBeVE74WQf8mye6av6uStBXpwigHl08x2PyhIcav1p6lE
         laO7NyWtv40NB/OMdR7xSHAOaajSqDjlgHFJtlFM+5+f4/o1Boi8k+rMFtUOD7VKOanS
         obIfoqLSiR3rpYDkuEJBWmNBiSR/A+i8hClBI4Ylna7wC1YAA7fvKfGBhpm9y1jj1xB4
         Xcyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HTvH7TCS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702042754; x=1702647554; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uBFUBrU9b5uK1ROohSVwifv2X72NXogpNEskEDPXyWg=;
        b=xIqJobcWD6DdBx1ONwVEZqd07uQUpaTqv2NxAZzo8Xc96drpvcQDkmAXrnYWMHD7L3
         VjzGR//7V+30EPIXm7mp7psFKVqayMZm7cH+TvbaAoHJ19rQEyrXNoMDGG3IQAdX6RZ7
         mUHufpIvAsXva1MRvWO2Rx5GKaugZAWYUNYndj5+AgOZCkh/6jfvTTqPEmQ+Km5buE8L
         AgfcGdLdQPOwPK6NDJViTN0nUTo6VyEwBlDzQF6RpVJ/Zk0tF087K6IM2mQJnZsNVL2r
         p7gIx5reoOQOGrzofOq0PQDoVk3KEG4L1w2LLBL72hJOWxEIOxunHjCoGXleUAV6EvgY
         k89A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702042754; x=1702647554;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uBFUBrU9b5uK1ROohSVwifv2X72NXogpNEskEDPXyWg=;
        b=jyjMPeTmL+CVbmiC8l6JUysMlnrxy64ZzF4BLp1OlRZyVUkG9DfBNcqpaxgO/06mX0
         TNojxWRslEgM91rhm6TysRQYtonMB5xI5wHvQtHVfVWO/nMFvItKY96urRavZF/aS22F
         6JTPCI13GeWHxvylQFQApxHyiaEr/zp65ssLvxiqs6h7fFlHVEbxQnqTta/IyUD8pzHa
         auO6+/xZLtExIX5QiFbNd8195ueJ3k8O0ZHjQe+maY1KxZrk6WQOzZMT4P/Y/IybIyyK
         C+hB+MWSy9VWLhp4evgt5765ZlxYGgFYeyBm+Y7yjH9Wne9WgMf4bPukebCDEuFzjHes
         3xmg==
X-Gm-Message-State: AOJu0YyxjIDQv/6Hhf5J37nZ7/uM8EuBiYtzHcFpzModrzHxihuR1Dbf
	Iiy4pWhagNYsGfmOZYlcP98=
X-Google-Smtp-Source: AGHT+IEqYSZcHvtdNC2TJFRCtK5eYqQb4Cgm/FBoH+1xtaVA9XIGSGQ1Px17VWrpRe75VKZlDWBKfg==
X-Received: by 2002:a05:6870:961d:b0:1fb:d30:c160 with SMTP id d29-20020a056870961d00b001fb0d30c160mr105803oaq.3.1702042753909;
        Fri, 08 Dec 2023 05:39:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c45:b0:1fb:3148:c486 with SMTP id
 lf5-20020a0568700c4500b001fb3148c486ls2667894oab.2.-pod-prod-04-us; Fri, 08
 Dec 2023 05:39:13 -0800 (PST)
X-Received: by 2002:a05:6358:1206:b0:16e:29eb:98c8 with SMTP id h6-20020a056358120600b0016e29eb98c8mr5303405rwi.30.1702042753226;
        Fri, 08 Dec 2023 05:39:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702042753; cv=none;
        d=google.com; s=arc-20160816;
        b=RFCxEZBXzYKyg6ul8OjwLLDxaoe0xKBCtZ38XEWmH2OjDkve/k/ZBqw42oIj43y8jZ
         PdxrXwMRsFZC+S7oxjHrLDTfUOUDDW+tKGnKlQqm3i201aan5i2Z52oh8pIIE2p0dIGg
         QdTCt93n7zU+yfvx4zieswITMzCdQzqvQzXwhcdbJho0aR5i2ygfd00t+yuBh6zYXk/D
         YI2x1F2ooIpLqV8LKGdmX+ebhP9L2Q5HiE1WmR/jwq289JiDlzLqZQO/qdMm3Zx9QBtu
         /7lUh6sQORoMlzU4QclQRU3wRhmYLb9x87Szbom5SFpNQImWLZhR8IdUdPjZcx219arR
         P+Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rN8Rat4FZlrJAhphwUeTKAqkkJCDvqW2t49f375msAs=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=HKXPODkiNtHjukxUT5fSV882MowSmc5a9GhrO0fMBKejxMRLqTyxAvIpO9exk2Nnnx
         1z8wGdPu0gQdRGdGWsurxtUJvEPAD0PtIvAY4w9fQVn4aUpHgGW2Px8sEFZFUYO/nSh8
         Mbz41FUp/iYE8hBzuB783txfEOCXvPAMpnDDduspRmY+HP5iAEJHmHK1UHD3x6lGSOGy
         z/tppOKeUQwb0xtycNaB+GrYGLO3c+Xh2erajGOfs+slO/LnPDX2QqE+IiuQyDQAvGE6
         tAv/XrG9nVi9gSRaM81Roa84Y1IXL6Ink/zgL40zA63D0yww0ONET/7qArllj4tkucCo
         06Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HTvH7TCS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id z8-20020aa78888000000b006ce99cc58afsi123066pfe.3.2023.12.08.05.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 05:39:13 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id 46e09a7af769-6d9dadc3dc0so1186774a34.1
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 05:39:13 -0800 (PST)
X-Received: by 2002:a05:6830:1a:b0:6d7:f363:eb0 with SMTP id
 c26-20020a056830001a00b006d7f3630eb0mr39559otp.35.1702042752413; Fri, 08 Dec
 2023 05:39:12 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-25-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-25-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 14:38:36 +0100
Message-ID: <CAG_fn=U8kGUCHQb7580bfVgh9=E1zjch3vB0tV5ooFxWsGNQkg@mail.gmail.com>
Subject: Re: [PATCH v2 24/33] s390/checksum: Add a KMSAN check
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
 header.i=@google.com header.s=20230601 header.b=HTvH7TCS;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32b as
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
> Add a KMSAN check to the CKSM inline assembly, similar to how it was
> done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
> instruction").
>
> Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU8kGUCHQb7580bfVgh9%3DE1zjch3vB0tV5ooFxWsGNQkg%40mail.gm=
ail.com.
