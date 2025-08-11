Return-Path: <kasan-dev+bncBDW2JDUY5AORBZXE47CAMGQEGKWGWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5844AB20A7B
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:38:48 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-458b9ded499sf28826325e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 06:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754919528; cv=pass;
        d=google.com; s=arc-20240605;
        b=H+nV5RDcOumZgsxp4gux8fs9vND4Kh4ZHmIdE5KAcROg+ymVeG4N+nNf49kfzx87Oc
         yhHcRDnAx5y0VAQTZoJn9xvsTDd00hl1UDt25pil4JuvSk3D7C3el2y2GWdum89vIDCO
         mgogsyQoDo4ifC8pquDGDtjh3d1T88YN9WaQcP2OhUsuafrKnfUt/RMtwmAKskA3xxH2
         +lOHacOpMFyZVGIF4QHDNzv0SNpfMZ3BQybXUa5ty5dBLNgtg+AYFjyYqfM6uYAYr0XR
         Grp1AIWRQa2zKA0NI9w9qfSKgj4KUHN97eWlJyZbNr9yqRwVqqB+DoJL9C1MIG28El7x
         39ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=cXZ3f08d9UbWVfl/xt9VTkDJDnOTWV/bYGhZ8ukQf48=;
        fh=ibuTFj02bzQWrPYt62JSmc7nime3QO9u/kw+GakXxGU=;
        b=KZidYHTcZaZhxj+JnuPQoqHd+n9YSXje2WXeTadKWJSiczR3JL4Dy2dpXdB+neo9tY
         kZbZMVII3Zzr+qWvVkP0wjf6/jbnVlC+F3YykYHrtboDwoHpeXmXmkxIK5zF/91Ey+ay
         7cCHks3+CqLy3AO1vz+V3MJhLf0jKkSzGh238snDIoCJbLZN/hg4LzNixevWKBVpSxC0
         pGfQtzFErkRKMtfiN64JsSWSCwW3I7tumSYqSY92FTgEvV4iQV8Z0b38ovHL+Sblmok3
         C0IU+oCQDgc8FZ+fsy3EckuT0uhl45E/dfrn+vujg5Ou5Q4gYCn30z+qdYo+pvn9+ufi
         oPQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XjriO9Fx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754919528; x=1755524328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cXZ3f08d9UbWVfl/xt9VTkDJDnOTWV/bYGhZ8ukQf48=;
        b=k+gfI2TXllJIjUb4UJ7UUaY6ZgQTaquDGwgS/rMvrGz8O2TbVmP61ZA4esjeJR5fwc
         GtWKuMcyOZ0lZSPfGNpHxKqh+OzFQNT3atiB5YL8FWMqczApe2H7DPll1Et5edNzk0dA
         v3CX8ptjcY1PzWy75EhNWVSlgshBeTsuFUjVebtzSBNdOv10cv+hLAoaE9CAjOfdxs0w
         zlvNmJZoLD8BwijX4cwZvyQce8BJopcZ6zP9mbeXT7gxbTyEYzH9x3BaMG0OqL0EtDxe
         7LXwnxNHI3OdezYjvA3CmGNBdOre0rvWR0AZyCcurxtwwqlCD5KuLBrzafSYIwayeGU8
         2iiw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754919528; x=1755524328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cXZ3f08d9UbWVfl/xt9VTkDJDnOTWV/bYGhZ8ukQf48=;
        b=YSmyLRW18rAneUPQDTac+3GMRklDq0t5Dmm8TFEcfSMk/xQ+AzwKeJJWQgd0rJB+ND
         QkUEZlxf1P+SPjc/mNSosOkmre8Vxp654HgfvD+wHKw7rpJWTiwpisB+SURQClMzlK35
         LfaT/GQeHjO4ZtwbHQkHC/wRJ7zDlggrCh7gYdlljBSYRmXHXM/LXj0kDFESa9Q+n3U+
         ECWBGdYCEwLw+GpvqpssgHePqXStz8zUie1Fkt9hFAftYpkCnS1v4n25CfBEj8RD3PXm
         RK0o4uz2J6CWQ2Q9cqqZF3tLsgD+eWI8ebTnL1PiUgfQi+9uAjfJnD1Gz2yZjJcPBJSI
         9lhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754919528; x=1755524328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cXZ3f08d9UbWVfl/xt9VTkDJDnOTWV/bYGhZ8ukQf48=;
        b=P4ab5zHfB9Bd9OGMeaBeRknl3Yhg3JV8X0ZBiE/+nQ1x0P2ceFVVtfpTwCCnv9v9F2
         QK/BAjl7clBFYZXlbUjzcbjBdqyy1Sa23siWwjQey+s9VxDJZeCE4bfm3mav8ueeRYdC
         QbIIhOqMg6JTVeewVENewHUxoXOIXAIt1NmJKMv5PQ254+owDnw13QzUZtR1CZ7T7uRf
         aDj1knbHE60REzFayzNSBLVsftmkFYgW3lhGwtQd7e6JKkMW7oBBt3TlI6jWq+4AuTy+
         aYJowQ2DZXtEXCYCUBR4vvf01W5yXiULq6hQKsJUVKR2pCwvnA2hfsa3E5oUyFC9Brq+
         f3VA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9qndLITD+J9kF49P4ULbNNdLONe1qyoTQKKTTP53WaBzXm1uQ8U2L+Nc/EFHumJDUfZjoAg==@lfdr.de
X-Gm-Message-State: AOJu0YyHo0sa3jRHe5RjuGVxWH9JX1jHGpxifS/kqPPkXTEOS+HV5NBD
	5heXZ4QgHsxgAHFq3jZzCMOUNGKwvhAPdKuInSY8BxAl3F+ORwEyftjR
X-Google-Smtp-Source: AGHT+IGxKJRcA+Wda9/uTCwpy+4PYcuKW8DFVR6tWmxtzWa1Bs7RO8Dhhyi0rvwdAlRe1hkwb8HcZw==
X-Received: by 2002:a05:600c:468b:b0:455:f59e:fdaa with SMTP id 5b1f17b1804b1-459f4f9b7e5mr83904315e9.21.1754919527344;
        Mon, 11 Aug 2025 06:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfqizvBK7Dn3rIrRdFecSXympecOa0KSyfj6shs36W+uA==
Received: by 2002:a05:600c:5309:b0:455:1744:2c98 with SMTP id
 5b1f17b1804b1-459f03e7a93ls24674535e9.1.-pod-prod-02-eu; Mon, 11 Aug 2025
 06:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfMxC8lUYgNtt/W+VC5JrowHjZoJYGJ1k3KqWdTG6ALCOy73Nn5hpMEeg6t/401ouRDxl1pTtLXeg=@googlegroups.com
X-Received: by 2002:a05:600c:1caa:b0:458:b01c:8f with SMTP id 5b1f17b1804b1-459f4f5109dmr113078375e9.8.1754919524674;
        Mon, 11 Aug 2025 06:38:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754919524; cv=none;
        d=google.com; s=arc-20240605;
        b=WJpqwnfdUE9lNfYVc7JhBROaTj9nfpX7mtQiVzLITWVfrMxYVY6VrfMEYVpRKVkOJR
         vrEkCvF+ZqdbgXhBi1Nyqd0Yjnz8Z8/6b0rw7Af8dnP5hOH2tG8QqXbf4nBCYJu3805R
         D5t5qYuWBh0QACtbprQ39kVoV6MNioj3GS7z9r/7zS/RO5hPwujh4K94e/rmeqskZAkf
         Nmrp6B3NPXZbvUfalXwXfb+QAMvNlsbjzXP95mRyC3xejzkMPbEWfZduy//M/mssC1wG
         UEzauJfRjtRrVVxE8gXS2niEnDHyTeVYyM+VH3VW6kAA8Q36Q6jGwF4YO3YfKmJ9to65
         UvEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TBCgH1jXbD8cQk7vL0lpvlc3a5C92LMaThlyJ1yPJn8=;
        fh=mfKwS8Xe6MbWQcmOnlnMXAkQoYQaXMWQFg1g3sRUYd4=;
        b=kSe3M5iWcuWAThcSppbbA++pKjsbpCDEaqEOiXbkLZEuVkP1+behYwWKR8WC595xqn
         jq2Iq0QpVq8Kn7y4IMjGz8hOfAB2xlNuiMDUw+NXdutM7sFCnN+ZQ0nzBNI67wrlLLv9
         rubHV4QHlYZjLIoo0sxwwolFcQ3qlDoFyB22gUcpjKXcK//y5BN91E7rxwmYiBq5FL5e
         IfSrlPkF217n2YMKf4dsaEzIBxeRQldspjQ+N73NQi5BLF+cF5cl5yX3P1ZKNce79xxi
         0rpPBpyfYITLdrADpJ2iwLvyF2g9GegdgrKEAHJc2gOCYbHG+0r7ajNzajfC1Yqry9bA
         VaUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XjriO9Fx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-459ea059f9fsi2369865e9.1.2025.08.11.06.38.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 06:38:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-3b7920354f9so3611931f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 06:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCzLKE1g4GpoRo89r6Pg0SibZLGP5N/BHBgFGH1jZ4+7iG+bg8XZ2vRTUqbRixTLaz2xBbwB6ccG0=@googlegroups.com
X-Gm-Gg: ASbGncu6ltAq/fbsRiyfAi6ZTkn/5NgFqELSn0/rBJsMqmQiOFFGqBr16pOMeKu0tn8
	cTr9KsGaIQ746Vfd6vUmO6iWLEnzZoXy5YLDb8d/YyAF+6z1K+wQi0PVydfWOYEKq771j4gCzwk
	j75VZFFSxF+4RJB0NIDEgSTkeniyb7ekRrCSaTePaOWKT55b4TzUREtYyKpUqLDXpnHXD6FZ2yf
	M02jsnAsZ5Cdeit
X-Received: by 2002:a5d:5889:0:b0:3b7:90f3:cd8a with SMTP id
 ffacd0b85a97d-3b900b83c9bmr10624691f8f.49.1754919523921; Mon, 11 Aug 2025
 06:38:43 -0700 (PDT)
MIME-Version: 1.0
References: <20250811034257.154862-1-zhao.xichao@vivo.com>
In-Reply-To: <20250811034257.154862-1-zhao.xichao@vivo.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 11 Aug 2025 15:38:30 +0200
X-Gm-Features: Ac12FXx7kQl8MpZMBlEL69UNklwxkty7tb561BkfRgxFfLERdIDidFrWBBBiqgk
Message-ID: <CA+fCnZf8XVydjMNRfR3JDeE=3i_0p+w0gTP8ep43LVU8k2Tsxw@mail.gmail.com>
Subject: Re: [PATCH] mm: remove unnecessary pointer variables
To: Xichao Zhao <zhao.xichao@vivo.com>
Cc: ryabinin.a.a@gmail.com, akpm@linux-foundation.org, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XjriO9Fx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Mon, Aug 11, 2025 at 5:43=E2=80=AFAM Xichao Zhao <zhao.xichao@vivo.com> =
wrote:
>
> Simplify the code to enhance readability and maintain a consistent
> coding style.
>
> Signed-off-by: Xichao Zhao <zhao.xichao@vivo.com>
> ---
>  mm/kasan/init.c | 4 +---
>  1 file changed, 1 insertion(+), 3 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ced6b29fcf76..e5810134813c 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -266,11 +266,9 @@ int __ref kasan_populate_early_shadow(const void *sh=
adow_start,
>                 }
>
>                 if (pgd_none(*pgd)) {
> -                       p4d_t *p;
>
>                         if (slab_is_available()) {
> -                               p =3D p4d_alloc(&init_mm, pgd, addr);
> -                               if (!p)
> +                               if (!p4d_alloc(&init_mm, pgd, addr))
>                                         return -ENOMEM;
>                         } else {
>                                 pgd_populate(&init_mm, pgd,
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf8XVydjMNRfR3JDeE%3D3i_0p%2Bw0gTP8ep43LVU8k2Tsxw%40mail.gmail.com.
