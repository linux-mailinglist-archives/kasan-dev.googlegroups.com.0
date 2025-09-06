Return-Path: <kasan-dev+bncBDW2JDUY5AORBSPM6DCQMGQEPUTUOUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A255FB46E09
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 15:25:31 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-55f5f436648sf1816880e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 06:25:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757165131; cv=pass;
        d=google.com; s=arc-20240605;
        b=ClvUKJFfAyhJotW51Rq/EabJ4rFWDbvzKQm3irJFUr5a0meGqodQ5IMtgOWFJWXcsM
         m9wP1XCkaPKtAY/Q/JITU/ysGaNIlA7wBMg1MqGwSM+RI9zTi0VvnXzGM8UfzE71gZd5
         KR/dRR6LG1VcAZwP6u9kdyGUhIwyDBk6UGRgOWZ2onqjKGle4BAPRIfERttbXY9MF/6Y
         QEGVmC9hBhZwzLmqsTf0QiikU8UJqEnlZJETuZ9nEh2j/+a1nTpc9HpGOomABD1UNdW7
         QBnYvN5rFik+9c85yYtQ+yK9s0RmdmnAri5fB4aavQa1IkEMaZyAVhvx5zAa/Fe794JV
         J1jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=cN6dRDMgPgOT/T7KzsVxKDDG+WanA9u7uWV7x2Pl3EQ=;
        fh=RHGcXzbMgnCPPrnYzsCQ5VxpdwSJlPdreu2lEf8HJr0=;
        b=DPzCwnLPSPPmBbMi0+xT8t5/URRG/Klrs7igj7JqUq5mtc/z5KoWMDfWvNq6o61ZIE
         7Lgw/AA94NXOZfTRUSVd654cgtcjE+3guEaS5h9sRyDsoU8hW+9Pmko6I8e7uDyU5GA+
         twZ3eqqA4fdhVHR0iT8F28+A5/RyjTer9LaVbszlXwF/lyE8r8u132slHOm9KxaPFxZU
         aPSTTR9SUBzvxLjiPpXHANBtusEVEpOXusVDe7eAvaTpzYO24Z4aSOzogtm+eRO25q5N
         h9KGR0Xii2hZ4jZCmU0yabmLC88bDOznl6k5JLqK7opZwveMIorilx5NKwgPopQI/uE0
         GKlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nIz16Z3p;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757165131; x=1757769931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cN6dRDMgPgOT/T7KzsVxKDDG+WanA9u7uWV7x2Pl3EQ=;
        b=JC0GX6s9T9pDfafcPV53F7xwv/3Ct9LHZAr46EvkLUbm+vAD9dYUKNkj2ipwomPEU/
         fWkwQyhXm/zjXW2cTZdVZ/B6O3FsQ9SFOFOBW1hjUhV9wtcZTiLsR646jXhR2rLqjc7f
         P0ksQv+afz4Lb0mpXIq/Sk5t0EdQ7MsI+zQx/biq0+XS/FK3aBtcJwJKKjzQsER68WgW
         NJtWo8NGFyVCn4kz8gfwNCJXJ754g6YLX12vh/i+E5T2ob5lTrCzGU5RW8qg18/e8NHF
         mwAKfsaFddatdrMot1kmrFrWf/z9F28P1Y6MwaDxRJRN5Smo05dte7eue+QqZv46Q7bd
         1O4w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757165131; x=1757769931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cN6dRDMgPgOT/T7KzsVxKDDG+WanA9u7uWV7x2Pl3EQ=;
        b=PN79Uqns8zWs0t8WteqrQhb6LTHo3QUG7RZms7t/Umsc13vs4kPToLBWbuDFBR9n6M
         UOUSSc7qnJoz8MV30YqbzwiNY9zK1MCbxO9ZiRiT3vIX+DoanAAqbFTzEHZmLJiDzoP2
         Ll2QEE1aWV02NFGzHTnl8rbkDesNfNLSxFh31w9rZZOp9pSH/p5p9mHz3xHtAwGbz9Fb
         FB97Tnex9pIAn3uRjwys4WGQFp3u27lnaERUyWF5WM8ui9O1HfYo9tN5fUg9FNBdVAdH
         uUrVGiRMl2B/kMEHDS/BmtGhHlavpdKdfDmbjYSTGXFqX6Xd182ZY7YCLC7rGMaAqThN
         0Z0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757165131; x=1757769931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cN6dRDMgPgOT/T7KzsVxKDDG+WanA9u7uWV7x2Pl3EQ=;
        b=uei6qPQ2IFRcDcostwhD17/Ku75osmjUqdXgmIpLVfKTmkPGq0+vEZVkjn8dg5wlTk
         9o/vzadsmlerw2Y+NIu1AVXNm34pO6UYlYFooxdmgn48/VcEA87Is0pgP7kQ55RXAXVr
         iV2oZYBE8arWsso/fXxxignK/6ripS1o+NEp15U1/K2a8yn2JeyFS+z917rtsPqkvBkk
         fU0RpmPNiMh/1voNKDrc6biy7D4P7jjYZNioKdY6Q34nSg257ESfuVaKmvgfzb2UdH5K
         4i3+eXxXNQ4/t2NbCSig1PDDXId8IWhMyI0JN3KWeDOdsbSAk93hktfr+4TJ2ZZqxpOr
         LKgw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZPpaHEynuoY0Pm36nX9JXIrVuPi14qpX9YVKzdlZG0gQxpfaOYr8PHEJTA/uD5NRlYQZQPw==@lfdr.de
X-Gm-Message-State: AOJu0YxPKvupR6r+gI8quuRuWrb4FHAWEwfwczxvE69cXGNlnVux2l5M
	LjjQhd3fGMLqzsod0ZeCg+MpRLEIyHsdz4oByOT4B/xbFJO0zGTGzlZF
X-Google-Smtp-Source: AGHT+IGTINFTlf2YRPdEpoeO+GG7F5qiJ7tpe6X29kIGWQFwqgrd7JkDbgf0tXB/5ENB7IRv22Kq6A==
X-Received: by 2002:a05:6512:2248:b0:55f:5195:9251 with SMTP id 2adb3069b0e04-5626275da0emr556341e87.28.1757165130393;
        Sat, 06 Sep 2025 06:25:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZehcKl53oAx6QVao5OUdsdsgR998c+BfFNIxizXlkkAvQ==
Received: by 2002:a05:6512:6409:b0:55f:48d5:149e with SMTP id
 2adb3069b0e04-5615bad373bls489449e87.2.-pod-prod-04-eu; Sat, 06 Sep 2025
 06:25:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTaXhm23TzLI4v6lXyb4g61bMbhpWRVkKBozTlw5N4srVHTHNh7BU/VcUZvxAUWyxaY8G4ONhoTWA=@googlegroups.com
X-Received: by 2002:a05:6512:31d5:b0:55f:54a8:9ec with SMTP id 2adb3069b0e04-562639b639amr594396e87.52.1757165127499;
        Sat, 06 Sep 2025 06:25:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757165127; cv=none;
        d=google.com; s=arc-20240605;
        b=klxNTakXtcpTSK+DW+eAa4t918z5KNLLIXBzEw7vBbv3MG1WezKkK5nP6pEMM2h+Mg
         +/BBCmizqbVY7rM/VTR64iwHEa10zNt7z6NydO98TYnjqUcSY+Qzoxp2mc8urucJXW2S
         pAMqTNINeKSVQQIIs/pHqPTT4lHPt76d8lUser3xTDCnmcshj9+6IBBLP317ZirHKsA6
         ILYIGzTqq8jF65hEu7L8GrproFjJMBOETaDEvI1V/DM2N//LkhbymC3xIjzmPZ/NJoxt
         1o42oN/PwHthOSkR9cNyU86EtaHW+Vt5bCYBzxaZYEbPwOAI1oty6m87E+QH3wSUPw5E
         QWpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VE+Mx/TU7aQIVb363hbvW+WQvMnqT6BMcQeprM6OFYE=;
        fh=Bqx4GQV/z4BaGEKc9SBB9KdMqO0FBI/btyWKgLrlAek=;
        b=iT2mkeDNzNr6R5jiQz1ZzFZcGObC2dp2XOercL4f0CPKU816ypH2qwN/cpZPUo0ZWy
         Kg9qv9h0GUA3anuuiCEUwCQdA46mlEgwJl2UUVTha8NbA90glAPJuIxu89gBYkxNB3q+
         3gpg2SQsVhRqYFpDZOESYQaKa0/exWoa37x8ifKmoX3vq/Y63GDZSLWAdcYj7uxmyFAE
         nUuHnvNUmJ+A4n3lKWEHXz4sdMnmyEEQuh9QInc/v2ydmnTGmLAei95a5H+U9ZOiqjJ3
         xBFtLPdRt4xIa5fk8rqSnsMMrBb1jBeh10HprIqwQb/6BiBfLZS//f3UxfUruZYaRTmK
         dHpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nIz16Z3p;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608ac674c0si173718e87.3.2025.09.06.06.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 06:25:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3e2055ce973so1534981f8f.0
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 06:25:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSmxXN1Pt+RWDIEGeTi8uzBQlHTcbMRQU4uus6gwLQKTFp2KfPgcaRjVd6Ctl9D1kztRMRUgVstP4=@googlegroups.com
X-Gm-Gg: ASbGncuGvyYaHWs+bFlv0/E8Z6mw8N6JZGZ6g7VbQvakShIGGQQKZtWqi2KEbdIfUxy
	LRW6TmnTBkRnw/LlOx+b9gx6LSAN/wayJO156RhIQmg2k1NL7zucQiuKL19CgEJac887bJCxhCJ
	SbUNJghKdFkoJ2y6Y6GSnOmfw8WIS06EuB4y5O4QJmXtpArJeyolTWkOqIR6cqNYVZ8RnZ1E3dk
	owXc7TB
X-Received: by 2002:a5d:5887:0:b0:3d1:6d7a:ab24 with SMTP id
 ffacd0b85a97d-3e641a6095cmr1198571f8f.17.1757165126529; Sat, 06 Sep 2025
 06:25:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com> <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
In-Reply-To: <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 15:25:15 +0200
X-Gm-Features: AS18NWDtWolEoXZVKCJMBulXUlUwGez_rwjXq9tKdDHHBjrrgE8FIXbdfmCaUgk
Message-ID: <CA+fCnZf0z526E31AN_NUM-ioaGm+YF2kn02NwGU6-fmki-tkCg@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: glider@google.com, dvyukov@google.com, elver@google.com, 
	linux-mm@kvack.org, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	christophe.leroy@csgroup.eu, Andrey Ryabinin <ryabinin.a.a@gmail.com>, snovitoll@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nIz16Z3p;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Fri, Sep 5, 2025 at 10:34=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> Baoquan, I'd be in favor of implementing kasan.vmalloc=3Doff instead of
> kasan=3Doff. This seems to both (almost) solve the RAM overhead problem
> you're having (AFAIU) and also seems like a useful feature on its own
> (similar to CONFIG_KASAN_VMALLOC=3Dn but via command-line). The patches
> to support kasan.vmalloc=3Doff should also be orthogonal to the
> Sabyrzhan's series.
>
> If you feel strongly that the ~1/8th RAM overhead (coming from the
> physmap shadow and the slab redzones) is still unacceptable for your
> use case (noting that the performance overhead (and the constant
> silent detection of false-positive bugs) would still be there), I
> think you can proceed with your series (unless someone else is
> against).

Hm, just realized that kasan.vmalloc=3Doff would probably break if
CONFIG_VMAP_STACK is enabled: read-only shadow for vmalloc =3D>
read-only shadow for stacks =3D> stack instrumentation will try writing
into read-only shadow and crash.

So I wonder if there's a way to avoid the lazy vmap freeing to deal
with the RAM overhead.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf0z526E31AN_NUM-ioaGm%2BYF2kn02NwGU6-fmki-tkCg%40mail.gmail.com.
