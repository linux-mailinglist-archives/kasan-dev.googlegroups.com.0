Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFFM26VAMGQETQZ7JIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FDE27EDD05
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 09:43:02 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1cc42b91848sf1320585ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 00:43:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700124181; cv=pass;
        d=google.com; s=arc-20160816;
        b=jrhe/RTUZSY0uLgzv7FSIMoMKU2fxW6DKSa9M67K/iN/cZ6yP0OANPVZ29kQiJLqUt
         kWKWxtkkpXZIrmyhRBdOP8uXwtiBsxW9Q7nRbXy8iIpO2EErzwkiWQAYF1GPQ5Ga0uWJ
         rAQMFVrTaq7XGbNQx/fsw7oaVK8MjwQLipqbbpQZyZbVoPNllLJFUW6+iN7isCNHmX6w
         CKcuFyPvadmU1Bzh3IfuXI99fFTKIs20xXk+x0M46Rw5000S8dAxl8D7wDhrsSZb8Og2
         LBQtgzo2yMqpAdMv8zDk6YhEvolbvecoswdh6ZybCoA8qSZVLctcXVpu/qqyxMKFLbor
         /rKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WFKXlVggudJTnlQODBMp2spiugiP44FuEa2vc1xAHoY=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=YggoSOvGZ70ABBNw0oKuvV1RiLe0EeSOFjWlInB4oxUYBaVauLx2RGHVu3LDvq1gAJ
         c2c8Y0kXEspunMlrvyfY7yDSjXjpYLi4McjrUXda3IIZ3cV6Eru3vcB5Iw/DKIQwClas
         orW40OZQMqbcSTd41FDyVjSNAnZtKbYZROHLBhmgwAHN7bWR3LvQB+t7MazipR5TfXQR
         Rki6GgU6W0GF7Ct/U3i+8YdbNHRHebFASdPgRlE8Za4YSwKp2n2uJMVS9HDufBATu2no
         mcmN+OfgXd+lU8hqXHb1txRlV0HPtETD0wlog9G+jahidVtAuJQ/l9TQ0H4q2oG3/sFL
         +QKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YjcmwubC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700124181; x=1700728981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WFKXlVggudJTnlQODBMp2spiugiP44FuEa2vc1xAHoY=;
        b=u0KcpuDbPxncHHhSujqf2YEm8e7DA5bZyE7feWi4Rlstz9STUTUxAo/komTKgmGFl+
         Soziwhr15IY8JthfxmjElKGuMpClxBivbapwehBQZpwonTDig/qzktsCcrkJys9oAjLO
         ym3roXGApeHX4rvRHjAZ7NhzIWL3KTOllfCVm1+8+srKpdPXmNmfAYFvGgF3gKueugip
         hwlKOVHsd4lpeVgKKTG5Imo36wgFTPRrr9c3ZuUCoeKXfunvKVFY0fLrdOjAscx4ox/q
         vY6dGc13c438z0m9eVdZ/LCLP+s5jw8cEO2mt2RSXlXmWN92frG2XPsIMglgn1x/1iET
         jjYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700124181; x=1700728981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WFKXlVggudJTnlQODBMp2spiugiP44FuEa2vc1xAHoY=;
        b=mrC5DQEJbhC44ZoQ5kpCpKPzMFPSHO2LJkeC1pgMr9OpRC+AixVUg3ziP1MpSxxStO
         XfG3WNDPaWQzgxbIute4HuhpR0fju2NRZCiZp2IPf+KFWUrl+vYEwvy8qEhUoNmEuhxQ
         RJyC9yIIzsnMa1c0C109R7CJrTKUAZqhSKOpnVouqINxvGCArysDHitey2fEtTl8lvO1
         gzSqrGDoeLx+uwvPdv9XJ+9fjuX9086GOwVB5B0NqLM4wWqLOm9VHPG4wd4C7LrlG2CU
         HwUndikmEuGYwYcjGnJhFtMpRBfaxgIfGs19/QBDZZGG8lCBUxdXas+AKf9IROcTxG+a
         6lpA==
X-Gm-Message-State: AOJu0YyBbiFAvTOVKrjgfW7/Dqn+C+ZNW49+qq50bMk8d3zmijTLAEsc
	aaFPWSZ+TqsXiG71oQoQhkw=
X-Google-Smtp-Source: AGHT+IGYH6QHlk85brOeRvOxXMIcfFUURy9nc92veRCBfsFjc5TKG37NlbKrOP4xNCNGKsPOC4fdeQ==
X-Received: by 2002:a17:902:f681:b0:1c4:4470:bfa7 with SMTP id l1-20020a170902f68100b001c44470bfa7mr191928plg.29.1700124180900;
        Thu, 16 Nov 2023 00:43:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:cc4:b0:6c4:dc47:794e with SMTP id
 b4-20020a056a000cc400b006c4dc47794els553665pfv.0.-pod-prod-02-us; Thu, 16 Nov
 2023 00:43:00 -0800 (PST)
X-Received: by 2002:a05:6a21:718b:b0:187:bc51:de6e with SMTP id wq11-20020a056a21718b00b00187bc51de6emr1254894pzb.26.1700124179711;
        Thu, 16 Nov 2023 00:42:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700124179; cv=none;
        d=google.com; s=arc-20160816;
        b=s6mxm36/P7CI4DnqhmTV9qOF1/9pcoss2F5aFtfSoZu7QzZms/kiwxsiDufYmEr7uq
         HoyC7d1bIoQOiHbhI6xhWLwZpk3/UnCFy/F3SNDWPGka1lUcGMTc1/S8vlRiJXkfJr3y
         3dFlrSX89DeFSr3OvjxjEIj5bHWn7ezhu4ZhfCtcjIWBmBG8FX02LkYCvRpOP/+9fDxQ
         KBN66SnAiM8hbXtC8INBaurlxRgnby/MXpZK5kGyP20CK/v4Bq2ylhOS4ohoGJYNmMDx
         xayydn7Sl8FhDo8UJLEUbB/fmYIlxiXQJooct56kyRT/G4rzol7+z8eQlH23i1Mm288G
         /LQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rm7nK+NtRd4bAMB5kW+BiMwXh44U1dcDR7sRoBwvzjA=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=R9ALMt25bLbr2EAZ/sE+HK6gY1DvUtS2WKUjWGQ8IjT7Ws6pXAO0+0mr0cBfFKe+oD
         n+qFozZzG/Ii3KqE06Nm7Tc3AdkjoTEWHJuKIYX+vUmD5T07v+HKwrByDQZ60nAEaO1+
         afJEh9zGfjj/tboeNFB1SXEkOTKbWpFaRNoVgcFRLzeLpAUPDgYaJn115NZbedtPboae
         4e/402h1EPxHd3lvjk60rZjWobm4nCNM5hn6OixIm6j9ykbK3N5mONpV4AU095dPyQgW
         Vn8+yiFGQj/q7FkMLAhr9CL7BxUXztXDj7im3WJyE6cVSGRLj5JXmCM5vhmAKwXvflnX
         HR3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YjcmwubC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id e20-20020a170902f11400b001cc5b5f692csi641780plb.0.2023.11.16.00.42.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 00:42:59 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-672096e0e89so2850626d6.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 00:42:59 -0800 (PST)
X-Received: by 2002:a0c:fbc2:0:b0:670:6340:2b03 with SMTP id
 n2-20020a0cfbc2000000b0067063402b03mr7946532qvp.21.1700124178734; Thu, 16 Nov
 2023 00:42:58 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 09:42:18 +0100
Message-ID: <CAG_fn=U+X=EE9SSb61E=QDReBXn6PGiX4gJnMfNKsTwQ6saKcA@mail.gmail.com>
Subject: Re: [PATCH 00/32] kmsan: Enable on s390
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YjcmwubC;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Hi,
>
> This series provides the minimal support for Kernel Memory Sanitizer on
> s390. Kernel Memory Sanitizer is clang-only instrumentation for finding
> accesses to uninitialized memory. The clang support for s390 has already
> been merged [1].
>
> With this series, I can successfully boot s390 defconfig and
> debug_defconfig with kmsan.panic=3D1. The tool found one real
> s390-specific bug (fixed in master).
>
> Best regards,
> Ilya

Hi Ilya,

This is really impressive!
Can you please share some instructions on how to run KMSAN in QEMU?
I've never touched s390, but I'm assuming it should be possible?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU%2BX%3DEE9SSb61E%3DQDReBXn6PGiX4gJnMfNKsTwQ6saKcA%40mai=
l.gmail.com.
