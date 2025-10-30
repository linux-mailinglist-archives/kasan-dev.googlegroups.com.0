Return-Path: <kasan-dev+bncBCUY5FXDWACRBNXBRLEAMGQEJTKYGIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B7C41C1DE77
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 01:26:31 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-428566218c6sf177359f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 17:26:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761783991; cv=pass;
        d=google.com; s=arc-20240605;
        b=CSSCnyi7V1x0Pqa2VY8roWSqOyGhIu/KnR26WS5FCx7WfVXzzF1+lAcrgus0EOf501
         KI72GN/6xMQP4iNiHGgvHk2DaXJenHC9siO3WSIwQDc7tnDuE+YYlOCd/qE/iPK0cJI3
         B9OoESAXl+ZZtA10rfuknl6o19fOEsV4cm0+vpJ0ND9raltRCoatEWYWWr5B2/AlVL50
         f74phCtlMpBSO7+grpkDQa2Nxd+R6HmP60WEioakQULwtSZJEHp2jnkFfMAu84kg2gYs
         lM25YUpq8HfIcqeOvVnX+8Ge/u+hH7hboCd96lHTEbeOrPPbxaKEXF4w9vKedW7pnsO1
         D07w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HZleJp04rM0U7ovSINPlbFfm5iy9a9UNbnFqZ/1/6xg=;
        fh=FR1ZDB9Mz8EVyNaqLjrvEF87d6OZ8YzTul3ezS0G1Hk=;
        b=PYrES4HQ1CZk/7hWZrxT0c0RUQ5auT6aQO97O3Ls8bsk6dSqt0nCN06fR+ukaIfvZq
         +MhhG/l5kA4XELUneXkAiUPlyw4X5FSOcQIzSiqqN/T3lo1mjD5PkwVWEbrkPr1nhaIF
         sfWMTpC/qo8RQsP0/iUURLLzlxbOETkXRQUXtHzeq5mcFXxF6e3BHW1I8cbZe/6U7ru5
         iKEZrzULVGWSBhQ3bG5Tuhia+vdyV4gwdJgEfbkWIZwpYVL3igSU6XNZV6FbrDcP0V//
         jrLXff25HObW53JWQpCRDjSJHh7Te3wk/TsyhH7MS4pWWY1taNom8lL/6KHdwBAJwRlz
         Fcbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OtCmXaoJ;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761783991; x=1762388791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HZleJp04rM0U7ovSINPlbFfm5iy9a9UNbnFqZ/1/6xg=;
        b=pVzk2bqfLj2u1ZYL0ZXnX1Haxxmkz2dLyvExPTrRDREdN5Xc36PLYolc25F2aTlCjn
         gHvS5mU+jUDO+rc/Xo2oeZpvhmzFJ8bNqDeC3tpabPHoxdLAg5epQaHI8IjDlL1Zwirj
         40mnItDMHY5WiQ14vv5zUGaLMBXLs8hWdVCwo9kYqq6Ke567xCD6YCeWPyNH6PrDasMg
         qYaVqyIjBWzNnYXlNMCRjvIx/DPoHUckvpgDJg5F7YPc1KGpwvEyAvamuX8bqUW4fSOr
         AGVF2FHWv6NmzpCfULq4uph3UNon8WGCC7/CiYWUXA3jeojyeM4S+IvVSL4HbgX8k/OA
         kstw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761783991; x=1762388791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HZleJp04rM0U7ovSINPlbFfm5iy9a9UNbnFqZ/1/6xg=;
        b=PRMKNrDoK1l7j3zRznYarm8IlONEDnJ2mNjJx8mCQl6ynpZW23x1060yGhah0ErMAs
         kFX9TZ82QTTvAFk084hm/ZTKurQSbg2Zhk+iJX66KhrRQ9RJ10ZWdySrOcoEphicaFnw
         oTpaG6XO6q9H8duXyOTQZqxhowg17YTlKTdzUBsen/yr54/lz5dkWH/98Zump5eh/pU4
         g3um6YQy4FBmEmSa51PD6XH1tlOEtwXr/lzx5qD3tsCY/p0cdF5C56xwMOWYZwlbzrlI
         io4/sE7V2t1uJPSJ76d+bGtskUiIdYk8sR1G2vFrOjXydzOfVqntID0EwCHaep1pLzu6
         MSTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761783991; x=1762388791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HZleJp04rM0U7ovSINPlbFfm5iy9a9UNbnFqZ/1/6xg=;
        b=P/dC9nFiBTf/YHfdrEl3Xnx03in8CXjz8lJsPvJucEcl/eNdJO4T/hvFxYnXsVKPQb
         l98KIYjxkfHECEwLiQiXbn8QaG1Lz8NOZgoySYFn+TJr3OjUhOLEGDJsO+fBheQQlxk7
         iWSILWjQbpHFm38yCDkBcW9U9BBknvw/a5REfrQfPvBplk2yZg49nmiou8GkN8n5X1Ev
         inBv/EWATrtq3xzm3aOb5nN20LreVAE8SRZXx5xqltgl+5zMna/QzuaDRhOlqJqo1IGi
         vS89IZiKIggi21DHPKAQd+pJqaTwq/5Sm+gLN5FAn36GqUsNdq2Ta3y2s3dzXf89CzXe
         waKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5bq61yEbUhNKTpM+IszkZtf0k++7607FxyOW+QiYeUwTH+kzU9OQHnye8oNi7jr2IP0a15g==@lfdr.de
X-Gm-Message-State: AOJu0YyyG3oEeHxd5T5VgG/27BPG4KkGN36O17BygS/lWiWJ7xTwCOQu
	gDmLsZcRltEkz3jXJkjN3+rUSa+3UM1fBMuqz+uYiqRW7A7rFbzLx4o/
X-Google-Smtp-Source: AGHT+IGZlsX0Bo1T2V6aDjGvHMjkKZ+NHFID68H17QHRsnyJm10Z6F/hjDdPj03Zw6QGvJaJNIjfiw==
X-Received: by 2002:a05:600c:3f0a:b0:46f:b43a:aee1 with SMTP id 5b1f17b1804b1-4771e1f3e5dmr38668065e9.38.1761783991086;
        Wed, 29 Oct 2025 17:26:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YML1wBsfom38t1ndV8h/GUEzW9DejTVvbF4xbULlTvIw=="
Received: by 2002:a05:600c:4643:b0:477:bee:1e82 with SMTP id
 5b1f17b1804b1-477276e5d8els1006825e9.0.-pod-prod-01-eu; Wed, 29 Oct 2025
 17:26:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqgNUfoo1MX+Cg9GRTm8qbLlr+sFrG4WbBSKavLsryySztgPVt2fxW8wji8VDFYHDwMN4ludTzDmc=@googlegroups.com
X-Received: by 2002:a05:600c:c48e:b0:477:942:7515 with SMTP id 5b1f17b1804b1-4771e17e177mr38888965e9.11.1761783987409;
        Wed, 29 Oct 2025 17:26:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761783987; cv=none;
        d=google.com; s=arc-20240605;
        b=c51mdTkdnR4CB6TPIuMAc7wp5wmR0DkPna+Mq9M8gK9sbsOFsVs42KVQH7QsN8ujaw
         nQYChbJR7rhH7fD6wpYvCM1kgMFf8TzEwyFNCWZQCSyuIBct1W7aOLzkBYWkU6YJlcJH
         TLcieP4p25PkubmUG16TTijjdjcigL3uQsXmiz4/WM/7TVEFYXFJsGqzPZtl6fj/JQlN
         sJ3z5X59h8lhw2daIRZtYI5bodrH05SxKGIf1yyf4X0RCXOaXOxTpw+iE7RgL07EMvuu
         34ld5wBhmdbl5SorWxEifFJn/Ka7bgrbaTwqPNvMMzLmeqibwgoIePBDYEJ5czQ1TUDD
         llEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zPUsAbPnavZ4td1AfI8HdK6vuKE/XGdHzWIQ9Lztg84=;
        fh=rT8YZZpqaJBP1M7f6o0Dzg5nfs5huzMMLJnOmaNomto=;
        b=UOvc8JT5TNdI/xOBcgB6sl7kV3Hs0el36ZGqgKEQ1Wj93gmSPo3oo63cKlYoedgmds
         aj+IZ8V1CbWgfNtEZSMPrtYKxQHoSnjVu/jdL1pgYNw1uty7UCLh/Snopq8GdniDzF+m
         wlmB2Jzyicu7ao0AlZ0oDtPK4GeJa5D2VssW7EgkQNEeEw8Sndvl3CTXH903OQL1gA1O
         tQdsNdCzuiTLcODz1qEuszYLc+V9qJqA7e3zzgSBBKRat2zYHcImz6WqLLINN3M0jNd3
         RMoZZGoT0U3h7KoOQQyr1666Sa+fYScU91D7AAEmrFKTzzNlyyVnG0z7twtWd5HEoZk/
         ERQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OtCmXaoJ;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995f8f612si292413f8f.2.2025.10.29.17.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Oct 2025 17:26:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-3ece1102998so315643f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Oct 2025 17:26:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdM2VhGY+XLZe+J4+7H8grOWov622BDkXp9Lb5tpg6NRYck3dfF9WhjBE0k6GQ2Y0IHDPQmNnJP64=@googlegroups.com
X-Gm-Gg: ASbGnctwYHherOlkcJoc+8K2IBkovW+D1mKuXH0qqmwtXdYHi00UCOZonnbmbx1AhBE
	5GITGUjdOBiIz9rV8DDYSropAmu0f3N5gMOY8v2SxQoHm5U/i2SXNu6Fw78sLEirkRAnF6LpEjj
	PheBHog1+HVw2mym2Z/MYSDb06tNam1Ky9QluhyDk+EkB5yV0KN3IQzQV3yU20qRCYivIs7MmzD
	8QxFMQLogX86LG7FG5QD8kINgSXcdoo/oA2n6IWq058fEiLfR6JF3iCKk1B5THTqb8zn/HckAwb
	9ZfG6Tw/FX8eC9VFVx5RRqBojwMA0O3vqC73qhw=
X-Received: by 2002:a5d:5f90:0:b0:3e8:f67:894a with SMTP id
 ffacd0b85a97d-429aef715f6mr5362079f8f.5.1761783986804; Wed, 29 Oct 2025
 17:26:26 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-11-6ffa2c9941c0@suse.cz> <CAADnVQKBPF8g3JgbCrcGFx35Bujmta2vnJGM9pgpcLq1-wqLHg@mail.gmail.com>
 <df8b155e-388d-4c62-8643-289052f2fc5e@suse.cz>
In-Reply-To: <df8b155e-388d-4c62-8643-289052f2fc5e@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Wed, 29 Oct 2025 17:26:15 -0700
X-Gm-Features: AWmQ_blIRE7qylf1r00bSF1LUzzYB2Ikdwsc9BuLrth2mRvMZNLO8ddWxSZ_asA
Message-ID: <CAADnVQ+TQZXhOhfG27kKdX8QUmua6AAqX81CnkS2W=4TANPUiA@mail.gmail.com>
Subject: Re: [PATCH RFC 11/19] slab: remove SLUB_CPU_PARTIAL
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OtCmXaoJ;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 29, 2025 at 3:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> > but... since AI didn't find any bugs here, I must be wrong :)
> It's tricky. I think we could add a "bool was_partial =3D=3D (prior !=3D =
NULL)" or
> something to make it more obvious, that one is rather cryptic.

That would help. prior and !prior are hard to think about.
Your explanation makes sense. Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQ%2BTQZXhOhfG27kKdX8QUmua6AAqX81CnkS2W%3D4TANPUiA%40mail.gmail.com.
