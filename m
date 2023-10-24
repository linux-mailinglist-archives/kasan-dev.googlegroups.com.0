Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOGK36UQMGQEMDLBE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6221B7D56B2
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 17:39:38 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-27d1aee59fesf3427196a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 08:39:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698161977; cv=pass;
        d=google.com; s=arc-20160816;
        b=I0PLScS9XYXsA6M524NHXj99QNdqm+mhpoDtFNdTfzJVoX00PL/nMsYb04MjmAAoB9
         5X2b0dN4b57Fk4m/+K0q5kEkIFRs93KoDfW1HvbxYZJvYoMlBdtaraImgjds7W6XPvPZ
         sD+j+6L4yudscj38U7LivOmOHxbWOaYDHSOh0kG1Uir9S8vwypAYG+1arTRUmfhiTEm9
         NKuX09o4pwtUp059zJbn/8M5l7aV1wUHYDc0ETnKLc86abfNZYhYLQTP30F2B6XgI4rT
         tbc0RQNunrr2x4RtIOy9FZlWHJ1FduoDK96zp0wP690KfnTUIMKdCjMOWUlAzErMlWQA
         FgsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CGItBVlN82j0Otzq4rn/F2fe/J+TYdt30Z3v/x14EDY=;
        fh=7a8Mpr0ki9GLJ4yTkY3PJCJzY6hhsHVyNI1Z1U4x8q8=;
        b=m48b24iNeOW3S+fVprp2dflYbBWeJtGlOmzFDLXHWfgVQmspn76KAsL6/5dHtUpK/g
         PeOkE1qkTeMMc+0ZR1xk7rm0Ms1SklMSEghmilMCpDzThM/gJfNZ1oVsCQBBJ95HtwII
         qvreTnDlZUGkPK/jSQ+HCqsogmTXMiWD3/ZdNpZ/6KVEmrIQIvn5pQkJGuaxbJJlIv8q
         phYUrseaTfaSYmnEzYOcyolf6McFcw/G2oTRanv0BF+QvwTSPghL22eD7OlJbvN/U4Xd
         9kqIsyPLnpK7HKSLxR50830jwKs10PgQKfmuEJmEn8hwm4kniwDq4WKQDYFmNt73LjUp
         6rpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w08kP7lv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698161977; x=1698766777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CGItBVlN82j0Otzq4rn/F2fe/J+TYdt30Z3v/x14EDY=;
        b=WD3aR97ZPyEXuM/lm4//Yt62nwZbc61eIl/VIk0HwAEfFMFz7P5QjV6LnySUWVleaH
         ohGkWmUUZMv964Ox8CMgiupjpI0TLibozn4HGb8e71q4zoJpuFS3+69flzhfWtTA2nkJ
         iDUjDlYhqBT1qsMLwasIIJJdzdrkwQ5y0e+lGn3jwIc4KPKh4M7c7iWVW6PckLrtEpuX
         uYFTwYfDFI4mN+5d3LPjE9WhKW97hMRfrwlQGdPbkzgSe93XjCAbEvD+SSAwieG0JUdW
         n/8lf6My5NMOz/S/Mh2Y0jqzoprPkIxQF6RZE+jC+mqgKbR/lxkcv3lwRqtIbIFaisMI
         xvvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698161977; x=1698766777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CGItBVlN82j0Otzq4rn/F2fe/J+TYdt30Z3v/x14EDY=;
        b=bHRGM10eVCjRgMqIjDltbKDJXMrbCD7O+Qk3O7ceXTztqsioP8wlnvEkhvrN1j+Fk+
         tKqjWVI5saCX5FMoIK5/q0iORG2ngSbOXZw+xXtTQk55LcSzTpEsK5K7LEqcOstc52wl
         ZiFp8J9YKfN5GI5lu8BkWc9S/FSAYsn6xCze8JM+Ah2sI+3XGvTbXNr1FmEtGYBGTh7s
         BbRQRILhuAEkatKzYQBYlBx1vKdyC7rR+cYvxD66JtO+F6wDltG2Q5hciukSCD3KGZA7
         w9ywHR+FHjIughrXOsW0sYLfbR9s4eOW328gH97cC9xpOl4GgubMX3+xsLWP1Aj/x+b9
         9/pQ==
X-Gm-Message-State: AOJu0Yw/taAhgX9v/E0Fyrh/gTvzZ0H4PVQCAnQ1FV5ZKhWpx/RRfqwO
	dvig8sLOdLkeSzwozmUekOU=
X-Google-Smtp-Source: AGHT+IGt1o6X1T6NjAAHouEREogjczTjSxVKzngEPvwlm3kMYxS21sJvUf1blxvP1s3tRCn4VaFUsA==
X-Received: by 2002:a17:90a:d44e:b0:27d:9b5:f28d with SMTP id cz14-20020a17090ad44e00b0027d09b5f28dmr9661179pjb.8.1698161976662;
        Tue, 24 Oct 2023 08:39:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a89:b0:279:3b6:830b with SMTP id
 lp9-20020a17090b4a8900b0027903b6830bls1346234pjb.0.-pod-prod-05-us; Tue, 24
 Oct 2023 08:39:35 -0700 (PDT)
X-Received: by 2002:a17:90b:3509:b0:27d:775:56d9 with SMTP id ls9-20020a17090b350900b0027d077556d9mr10427091pjb.15.1698161975607;
        Tue, 24 Oct 2023 08:39:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698161975; cv=none;
        d=google.com; s=arc-20160816;
        b=h9jSwG8oY+GJPZT7fOvXa0Z4vW8R0JZym8MmVfKMTJfN3KKrBoOAZg5n6ds9UEWUY7
         gL1lVaOEWnYPCLcR9DHB+e5zq8DdrXOS3zFyraGgFEOTzE4AVVUx1ySt7WkIJP1r07Ux
         8K4rzIroWZqbGIuHKHxU77agwI44pEkSbqviemNU8Bb07Qn7eO1i5hzzNWZQznifr9Y9
         mLVaSp8ELZaF+aAJDsQwFEAUv17jqtiIy57KmnoxBSCXfzss+w3yMojzbtnnLQWjVMbW
         d8MMUQCSyNUE4ysN23Z3/jkAHT1mV55i/neuLGv2oS9ftH7AR5Qi9E8hHD+QogeYTHxt
         WmmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ey4VomTRBY3avfKTyvFYcfzW8AVbvE2wkpROIGAd9Vc=;
        fh=7a8Mpr0ki9GLJ4yTkY3PJCJzY6hhsHVyNI1Z1U4x8q8=;
        b=LNyBh57t4aHIoQztvqbkAKZD0Z2qxuShwYU1bNy78fTVJtQxgI6pe5EmmZod2ZVJwZ
         kBfwC2KwZBBadPtqg2/zldHP/2Lhtyn+lpUAE9RcnXQ8VrRCJJKszc/E1mt3aX+TS+B9
         JKq/wMM9E/9E0xa+0tkXaj02jTcjmOPoby5iMnDGEXm11/2Sb1GObAqkIhgxms9R0fOm
         zofHMIHSQMrYqMI72ghLdFo4rQGVjYlEFKSPxf98PCUP5Z5p0kCQ7fNs2CymwR82gCsu
         cFHzqsaIyvqE1HyauRWQ+8hGufou+s+HoPsyvbgDWI1XsU/X6JjgcjsG5siNyvHm1EB3
         0/xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w08kP7lv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id sm9-20020a17090b2e4900b00271abb7337csi870843pjb.1.2023.10.24.08.39.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 08:39:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id ada2fe7eead31-457cdfc293bso1823592137.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 08:39:35 -0700 (PDT)
X-Received: by 2002:a67:e019:0:b0:457:d3fd:caaa with SMTP id
 c25-20020a67e019000000b00457d3fdcaaamr9623309vsl.8.1698161974486; Tue, 24 Oct
 2023 08:39:34 -0700 (PDT)
MIME-Version: 1.0
References: <5fb11a4743eea9d9232a5284dea0716589088fec.1698161845.git.andreyknvl@google.com>
In-Reply-To: <5fb11a4743eea9d9232a5284dea0716589088fec.1698161845.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Oct 2023 17:38:56 +0200
Message-ID: <CANpmjNOJm=PUE0N856owRnxrZx7d5cW0MqCp9Me6GrSit=NcUg@mail.gmail.com>
Subject: Re: [PATCH 1/1] Documentation: ubsan: drop "the" from article title
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=w08kP7lv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 24 Oct 2023 at 17:37, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Drop "the" from the title of the documentation article for UBSAN,
> as it is redundant.
>
> Also add SPDX-License-Identifier for ubsan.rst.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/ubsan.rst | 6 ++++--
>  1 file changed, 4 insertions(+), 2 deletions(-)
>
> diff --git a/Documentation/dev-tools/ubsan.rst b/Documentation/dev-tools/ubsan.rst
> index 1be6618e232d..2de7c63415da 100644
> --- a/Documentation/dev-tools/ubsan.rst
> +++ b/Documentation/dev-tools/ubsan.rst
> @@ -1,5 +1,7 @@
> -The Undefined Behavior Sanitizer - UBSAN
> -========================================
> +.. SPDX-License-Identifier: GPL-2.0
> +
> +Undefined Behavior Sanitizer - UBSAN
> +====================================
>
>  UBSAN is a runtime undefined behaviour checker.
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOJm%3DPUE0N856owRnxrZx7d5cW0MqCp9Me6GrSit%3DNcUg%40mail.gmail.com.
