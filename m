Return-Path: <kasan-dev+bncBDW2JDUY5AORBDPTY3EQMGQE5MFI36I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B926CA48F1
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:40:46 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-477c49f273fsf11365845e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 08:40:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764866446; cv=pass;
        d=google.com; s=arc-20240605;
        b=I2KXNPg7e8R5EbcZiFQ2tiMT0hXPFOfYdIRIiGAxiO9Goc2xMAx0pX5uLus9mJF81R
         kIPybzi1qCYqkSELu0SaSdfFz5uCpobNj20R8w7VcIb1cKnWIPsJnl7YAiUN2bgjPa3Z
         4AvGo1NtF0k457U/914CKnvMjPAdHKUZdsgVZ47CNSxq3jMuoGOrgEpPn9L4h1OBSR1a
         slMdPqud2a6lKrkI4fNxzZ4rn9KoXly4hN9WlGJHKKtujivovjtDYHKqGTxM9XTyQv/y
         1vpDK4zpRpsD5WY9W6lzcWPYA4XP7hYG0YE3fOGYJmXtkSpHDFsvuwL++OlSgd4eYWZE
         FhAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KaJO95Mguon1QXeQ5tN1SscZHM7j+s0U/coGyAH360Q=;
        fh=Cqk+OIaao0rsADikmLPRiDiv06nYpaV7UXvbQEqtBfA=;
        b=AIevcQMlP3pxbjh7raB0Lsm6yxUzinFod/eRcalqsOO+0/3aMCGOmPISf/0lHcJ9lo
         BwMRxOboJMKmAegxF08Q76W3msG2Eohn24fKVVgfAtHKi1+BnbMav4IDJR11eRYqQp0b
         h6GNl2ezKPPCRdwX3lYA0i25MTLeO3WEHVReB2liIsdyT4nA9RiaecpPoJdaMjCO9UFK
         /DbriHooUcKmNVwULSHQa4s8VmPk8ERT2R3dQw/uswuoqzc+tyNWHR8+AJ9besXA/gKH
         4tYO502LgRS21VzVBCxVmepc9tX32ioXTCPiAgZEzJJsWTzjo/3sLU/n9qyYt0heIZ5t
         WHYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q1NfjZMa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764866446; x=1765471246; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KaJO95Mguon1QXeQ5tN1SscZHM7j+s0U/coGyAH360Q=;
        b=aWk0Jwb6l8mghnrbAKPQyB3Els2lcICCnT6aziE+WCbgBPkRGN1f8WlxyaGgPvO6Py
         yvh/tmL8LK0l5LB6qcfK4cqfyMbI+bnKnKZ3FN8XZQ76cVbZK/2QW/yndJ7AX5F+e+AW
         b/gu2RdgcTK6+Bq2J8yuHCZzcwRmNRBm60KwS09TYb3lcbjVwk9tD+gQDA4ULksQwMKN
         sepzDKw8DRLmvy2zMraHQ7Hmf6LYbJ6idR+aScrSkQLY3NHd06DLFVDCrF4XCH3Tjvzh
         ZNZF8cTLOcJ8DYh4lU8KtaHfAwawgOc7Ds/V4vaGmI1o5Lu0+hrgz//eNaCMZNrBxFPi
         qFTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764866446; x=1765471246; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KaJO95Mguon1QXeQ5tN1SscZHM7j+s0U/coGyAH360Q=;
        b=MPed5lV5tPTvz246deV5jnXvHo9GJClE9oTqdTFNcfUbKvvdB5W821rLWHZzS0p0is
         RK/mirgLmu3xkXgqrQp7i2/xwjCEYenrWmWtTDnef+LNmgKUn9Xd9GBnPCC3K41QuWh5
         Yd3Be7ZxD6Leh5tzN0l7NWnu3Ih5rFSee3o1BaUT0GikRjYE8jC47Koddmx0ZAHL7z1o
         DTLAEd3e77oDFlb5nTyNxesNt+eh8zpb4dyN8CzbL1vqQdoMHsB0Z3wWzBZyR0P3eXSa
         sk8yGlAgl8dyOTizC3iS+gby9Vl+8j4Lmi0gHOLNAerWDWB22R0a/KLZlVtepeHNdp1L
         eXqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764866446; x=1765471246;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KaJO95Mguon1QXeQ5tN1SscZHM7j+s0U/coGyAH360Q=;
        b=EOMGgOdRL0LpBpza3SAKcbBLi0VPqrs+LCsFP3kqOyiAVr7toSam9wJBjS9gw0o3Vz
         Zuv4hnPQPS9SMDTj/GAYpsnz1GHgKpgrsPsyVVBYgI1qnlbpVSqdeggvfLxOAVDCOies
         ezNhWdeVEYR93lCG4p4IplT/vHsHw37I7Eio81ZBjIEinsu740sZqCSD1SKGaOrklOIU
         Wqk9TmpFwoW/4gJm+tQUAPQXsuhfV4nQ8MiOCGpYsC7Q+xmu5tbo+FK41/niJ3nkQs3I
         SFoC1CLRUoX4P6agLiaHX1tp7nxf4Dpf8VuAvapJeSm9mc7n/i0Q0gg7gf1jkOiTDYQx
         igZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbZvvBkRt2ITMKFm/cUUAcFyy9Fw/5tHCjKGYtX+DdGhGIvYpkkCk/ItD38Mrfx7VVXHidxA==@lfdr.de
X-Gm-Message-State: AOJu0Yx4BuBTtsTX5wVIPJedHnceuiWgnpAn6actE6wROedbfnmZDCEB
	Jilf3gUcw8AMg/TkZOaLZe2ehi0ljCyYmv6/vg+smGU6B5i5zt2y24ek
X-Google-Smtp-Source: AGHT+IGkrrM5OZwiOKDMgS9Pp7ZPu48TMNKyY6gjfj8GElnbt0eUC1EHXiBYubTAjREXiM2HaAjrlw==
X-Received: by 2002:a05:600c:a0b:b0:471:13fa:1b84 with SMTP id 5b1f17b1804b1-4792aeeb501mr81673095e9.12.1764866445928;
        Thu, 04 Dec 2025 08:40:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+as3jt7dIzF4en0MvvFHo6vmwuOD5nzQmGpzoXjq+nC4w=="
Received: by 2002:a05:600c:198e:b0:477:a036:8e60 with SMTP id
 5b1f17b1804b1-4792fb778d3ls5804575e9.0.-pod-prod-02-eu; Thu, 04 Dec 2025
 08:40:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWv4lqYtG+RV0vQgp2qExHsK5gxUFRL+GbKoiNKXSQIz3hL8uXokJysKbjMxvs5/QOSNXzJzMkN/Ig=@googlegroups.com
X-Received: by 2002:a05:600c:3b26:b0:477:9ce2:a0d8 with SMTP id 5b1f17b1804b1-4792ae60275mr83654165e9.0.1764866443302;
        Thu, 04 Dec 2025 08:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764866443; cv=none;
        d=google.com; s=arc-20240605;
        b=RFzwxAqncXaL26HFlsKyLHUED6RhSvox9P7l2P2x6FGp15wN4zpWj3wJkyrgDbkdkd
         Z4SmpbgIEjt6vXrfHyz2WVDg8C5VqMODyPqQFbi2xWrrOR9Lyptb+hBMRQ7z1T/bZrJR
         VPLOuHC3gxIaaj641JYALv10/wO7kGteLgibC8+JXr3vNItaAHpvp5FL5ih1lvR0Xogz
         kCAXhdXAS0YWQi24WdmmVDDJ/YoimSzls0IzIGS5D/TVARlfeE5U86LhYPnorLfxiTT1
         906tMyjppx0K+Sn7bcos05m2HdSf215QgspxomPfe4h9+1LSGVWCilx5fo8aMEjM0rju
         GEZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wb9ZdPQgurLaP8ZtzTPbdlyBs0CGGHqRQ+aYAuE+t9k=;
        fh=rsSXyRah40v9ShBVl+MDQ4gxRi3VFsWUuMbhnOSND9E=;
        b=Lczg79oDNCWNmYkreN5kdcgCuLMIchRr8Vmrl473iVIm071lF4SXbpk/P2+Uc5kzrY
         PqqUw0m590wr6U8bCS6Xg5EwjwZ1VphB8Q33UwKTOAWB5F7aZT/xAHAsyYD0Wku8C6q2
         zW6B6Fov0n4JuZwpxxwyOpuhzTSlB3gluyl9rdLlnfPenaAvJgeurzGRWCOyWMVseNz5
         EIIq6UOn5COqz1qKtwJ5KpXNueQfXKprOODn40w4SOTEGzu+vCUgWrIhmb9SydVjQcxP
         4eshm+Ye2Ff2paqomB5zpjQCzpAkM2dTAVxspv/CLu0mtg976K1JVw5nCioyXMjEA2IJ
         Gyjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q1NfjZMa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792afab915si821375e9.0.2025.12.04.08.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 08:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-4779d47be12so10919585e9.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 08:40:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVHRxHskOgjUUjNscEyKIUdXfnf7dA2Ng68OMOFQItY1elqd5ZZxqqDin/0OFWNXlkXiN14MjlryGo=@googlegroups.com
X-Gm-Gg: ASbGnctwCAqHWUvX3DDoNmILPtlSbAAzHuChcHt8tsDXIGKL1HOephA/Bf/0SH0WE1T
	gnfTlYPFwVl1nb20WBHYJJ6KN/9yCaCTeE1UrtfG4ryKG+BT6GWwwKhNQM7Ne4C4TbibDjum02i
	K8u/U0Px1VUz2ncOUo8+BJVqRsOE8dcB42pVS+6ICqy+RYxtrxrtXIXA+3U7znxF+L7PLgp5KDQ
	UaAEfL6j2rn2QVWhFotYI6M5Vev1BUHQqHI+iCJK+0E6e/wB43casSkEWewNTHPiwhYzEp2eDlx
	YIDv+DU/hdmigj9vh1fOFw/nhyc0
X-Received: by 2002:a05:6000:1a87:b0:42b:483f:da8b with SMTP id
 ffacd0b85a97d-42f73187378mr7778677f8f.25.1764866442731; Thu, 04 Dec 2025
 08:40:42 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <20251128033320.1349620-4-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-4-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 17:40:29 +0100
X-Gm-Features: AWmQ_bnAHBHdMEtZR2H-axXWT-9zuGdxSA8XYx7l16HmfMLSXrkVqTo9q2sNGCg
Message-ID: <CA+fCnZfVPGYkFrEaU0-AzxUDLQcwoT08XuTrXf9oifHWEbhA=g@mail.gmail.com>
Subject: Re: [PATCH v4 03/12] mm/kasan/sw_tags: don't initialize kasan if it's disabled
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q1NfjZMa;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Fri, Nov 28, 2025 at 4:34=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>

This commit message is too empty :)

> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  mm/kasan/sw_tags.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 6c1caec4261a..58edb68efc09 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -40,6 +40,9 @@ void __init kasan_init_sw_tags(void)
>  {
>         int cpu;
>

Here and in other places where you check this flag, add a comment: "If
KASAN is disabled via command line, don't initialize it.".



> +       if (kasan_arg_disabled)
> +               return;
> +
>         for_each_possible_cpu(cpu)
>                 per_cpu(prng_state, cpu) =3D (u32)get_cycles();
>
> --
> 2.41.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfVPGYkFrEaU0-AzxUDLQcwoT08XuTrXf9oifHWEbhA%3Dg%40mail.gmail.com.
