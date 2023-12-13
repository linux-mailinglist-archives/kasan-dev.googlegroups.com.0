Return-Path: <kasan-dev+bncBCKMP2VK2UCRBDO24WVQMGQELJD4J3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 23004810C82
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 09:36:31 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1fb1f23d1bcsf11664908fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 00:36:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702456589; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vlh2Hp6HhEUbyzkPuFfRMJkjRChTmIpXpLQu9M/1SUAvICWn+dONWWyuAoTPAqYzwX
         3FoMz2ngUnivGZWbNoU26JGOFic7Zu+dZ/bQX4iJKhUY905qwo7KtC3D+TKXg4Qgz0Eu
         3soJax0ARkSYosA3kPZDFjTQWCddDuz6t4TQwnAbw0DDuftUquAfe+BDwwoTblN+zf7v
         IEXFYX5gILj2e7qpC4Sf/kzgg+84+mUVLgjVeUF4frrE+hUjrn0B1D6bTqp+NSS6HUoK
         rETFNJEdUV/myMF+gnmmdJUrO91ZRFplzajPShC6L7x6n8lRcM1+Tnt49uWkRrrdL6tf
         Io+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=/xpPU0ufg2eCy4M/h6emctH4n1hIHb0qVK/h+zLQs6I=;
        fh=AOnSgS9LVXiRdAR+aLT/1Y9cXsv2OczNkK4k6g7et0U=;
        b=rJWCh1m0zh5suphTY2lOcDFQp+xP2dltBqLqKodcmQyaZ9+IwaYVrjIDHVAHB3GctX
         l9NsNNJT1ocv5ouMPPkmQY71zCSRMEiD71Ibu1GZlDbsvCOxkOmHvP/llu7nbR8Yaqod
         eLh6Q1n1bghQvt4RzyOYKKvF07FIy5wlKmzxpy7RlkOBjcbNKHVCKLtEoiW+aKpcro2y
         U6noTU9OC2koAMT8yLb32c3pzUaVeIXbPJ3W8YAkbqSupHAMk9YLrav9esv2ItLBqYX5
         h84SIdDDaefHQgzhq79q3qF+jHg+zVdifINHoa84iwtEtC2VFy99zC/Afm99kQ+nVt3k
         pI0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.161.47 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702456589; x=1703061389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/xpPU0ufg2eCy4M/h6emctH4n1hIHb0qVK/h+zLQs6I=;
        b=jNremCIlUX+76nfaS5Xq0FUsYfVgCQP6kEzDtjM9RIcIPrez0GYYlIQnKhw18XdLJ3
         GMA+c1V4WBTpPyj8b2kf46OGRkgs966QK2OIEjsegCXvdIpKC7NQmjre0ptjLvStJ1a3
         vhF0r9q/bV1uNv7aDdsDFzvDuu+qGDjC40vdM1HsJU7AKPtFruxjOwyk8RfRj1haPlsA
         ijS308SEiHCjZW0EoCjL+Tg/rsFeQZ1T8i3B4NezlbNivhXPX9D5epeIKOc0Qr6QJDOP
         8RYQi/GFyZaPRVvrr67g7N6BOeHoVJTjlzoqPo8leqBtNEpfL4JG25XfmxEJIiXCltVA
         byUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702456589; x=1703061389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/xpPU0ufg2eCy4M/h6emctH4n1hIHb0qVK/h+zLQs6I=;
        b=NUDps9a9g4Iiif3GUq1A04LQm2Q+Da2/gVjRC/khZBbLqRbQGSPpkf9dZObVrHJ0kj
         c68PsfZmfwb5sbkXDR1rS//QywcZgomy6hdwQFL+O31c6ODoH0SLHn9NYDoDXvnEbAz0
         zPnM0JsTqo2c45F6MtZg6mcbj/7u4cFscb3KeVGMZSfGE5O6L6R6rWQt79qiF03O7ZVL
         4BoCRcNPHIxxuIx6b2VSubvh6hDuSFpO7ruiyN/SbFmul2SIQgDdTGnvxpAbh8wNZfrb
         ppBqdeG8bpj2nORxNaK7U3xu1qKDSWPZxot8016hUWjjZB8Hi55l0reWjXH/YMPl+BQD
         m0wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxX1vDI6HeYWS83p2/s1z9bCSXvVHbue9RSLHVFD42YTErFqkqM
	h9zAW+VNPCLyqb7nIGbhxCM=
X-Google-Smtp-Source: AGHT+IEWtQ9rlcVpUTVGqCvGeWvbhHaKTJEAxPxHdS04Z9o4xCFXoGHyhIHM+cg+zjfhH62Ac55Ibg==
X-Received: by 2002:a05:6871:e80a:b0:1fb:75a:c413 with SMTP id qd10-20020a056871e80a00b001fb075ac413mr8104819oac.60.1702456589322;
        Wed, 13 Dec 2023 00:36:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:499a:b0:1fa:21a5:2e09 with SMTP id
 ho26-20020a056870499a00b001fa21a52e09ls2778297oab.1.-pod-prod-03-us; Wed, 13
 Dec 2023 00:36:28 -0800 (PST)
X-Received: by 2002:a05:6870:790c:b0:1fb:75a:c41e with SMTP id hg12-20020a056870790c00b001fb075ac41emr7881769oab.71.1702456588392;
        Wed, 13 Dec 2023 00:36:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702456588; cv=none;
        d=google.com; s=arc-20160816;
        b=HFMyzhpwDKndBNdku65aSDWlVS7di2HIJfhoWVYIsDsBiN0Q7yre4ygYYtbbdqPXqY
         4kzG5GFZWXVvlBcQ2FYgqpgiaijWMe78lHYw8aR3z6n6W+r+iFjr7NIPdJreOPldUUY/
         oZMghg05ixW97fZx0+RGVHkcbhcvMwitinxvYBxjNcZg0M8BobeqJCUq1Uwu+gL//HJj
         pyuErSJKisupgNiT1o6A0Z5NiD3NjJ4jx9nBAxqymMU7aNo8qgz6JEgyFJoq85pODt8L
         3ilNhlt2yTidxd/Z+ojLzDdyHnA11aeqMgTHOs0mTw5VU2jT+3VffPYFTt7ARRRO5TA+
         YYFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=6anvPPkB7zC5RyRZfp8ATi41Ad4dEiA0WoUIsmcFlew=;
        fh=AOnSgS9LVXiRdAR+aLT/1Y9cXsv2OczNkK4k6g7et0U=;
        b=jiAS7eLuixjY8GBF6EwzXvqQGbBfWLps5ZaDwpVY8VHGfFecQ51J/cEf0cnZQcxUbJ
         6k22WmyzVT8l+kjkNiy2h/mqd6TPYQeoPQ3SIjrJYFpcD+AvA00HnvKEgXpg252AiJ6H
         klkR/usDQn4QDUk6gGWlMZ+n625cd7zzGNLT1174cgekbqpVp0Odu7oUfNjEly/xXB0b
         Z1w/tOmVy2mEk2YLZ9qizqhGmoWwoVGgkT4La+c7gv4lkk5xmAouaHHBwW2h+CFEIwen
         4P+pKVsHLM/Fjn3k6EXYkxgpb3f/A/yJgYdRNbV2W87HKLEv0p/iIXP7GDFAskgd5ilI
         ws0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.161.47 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-oo1-f47.google.com (mail-oo1-f47.google.com. [209.85.161.47])
        by gmr-mx.google.com with ESMTPS id bq20-20020ab03e14000000b007cb4cbaf243si65338uab.0.2023.12.13.00.36.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 00:36:28 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.161.47 as permitted sender) client-ip=209.85.161.47;
Received: by mail-oo1-f47.google.com with SMTP id 006d021491bc7-58d1b767b2bso4220630eaf.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 00:36:28 -0800 (PST)
X-Received: by 2002:a05:6808:1511:b0:3b9:e20f:96e7 with SMTP id u17-20020a056808151100b003b9e20f96e7mr7853110oiw.28.1702456587532;
        Wed, 13 Dec 2023 00:36:27 -0800 (PST)
Received: from mail-yw1-f172.google.com (mail-yw1-f172.google.com. [209.85.128.172])
        by smtp.gmail.com with ESMTPSA id t3-20020a255f03000000b00d9cceda7947sm3776234ybb.3.2023.12.13.00.36.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 00:36:27 -0800 (PST)
Received: by mail-yw1-f172.google.com with SMTP id 00721157ae682-5d8d2b5d1b5so46464427b3.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 00:36:27 -0800 (PST)
X-Received: by 2002:a81:a1ce:0:b0:5e2:2917:273d with SMTP id
 y197-20020a81a1ce000000b005e22917273dmr1045743ywg.43.1702456586772; Wed, 13
 Dec 2023 00:36:26 -0800 (PST)
MIME-Version: 1.0
References: <20231212213457.132605-1-alexghiti@rivosinc.com> <20231212213457.132605-2-alexghiti@rivosinc.com>
In-Reply-To: <20231212213457.132605-2-alexghiti@rivosinc.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Wed, 13 Dec 2023 09:36:15 +0100
X-Gmail-Original-Message-ID: <CAMuHMdWMuSBKHaPGKTf2pGdgsD5dMaxcrZw3Ox3G=ShjnOAKnQ@mail.gmail.com>
Message-ID: <CAMuHMdWMuSBKHaPGKTf2pGdgsD5dMaxcrZw3Ox3G=ShjnOAKnQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] mm: Introduce flush_cache_vmap_early()
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Arnd Bergmann <arnd@arndb.de>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Christoph Lameter <cl@linux.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.161.47
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

On Tue, Dec 12, 2023 at 10:36=E2=80=AFPM Alexandre Ghiti <alexghiti@rivosin=
c.com> wrote:
> The pcpu setup when using the page allocator sets up a new vmalloc
> mapping very early in the boot process, so early that it cannot use the
> flush_cache_vmap() function which may depend on structures not yet
> initialized (for example in riscv, we currently send an IPI to flush
> other cpus TLB).
>
> But on some architectures, we must call flush_cache_vmap(): for example,
> in riscv, some uarchs can cache invalid TLB entries so we need to flush
> the new established mapping to avoid taking an exception.
>
> So fix this by introducing a new function flush_cache_vmap_early() which
> is called right after setting the new page table entry and before
> accessing this new mapping. This new function implements a local flush
> tlb on riscv and is no-op for other architectures (same as today).
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

>  arch/m68k/include/asm/cacheflush_mm.h  | 1 +

Acked-by: Geert Uytterhoeven <geert@linux-m68k.org>

Gr{oetje,eeting}s,

                        Geert

--=20
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMuHMdWMuSBKHaPGKTf2pGdgsD5dMaxcrZw3Ox3G%3DShjnOAKnQ%40mail.gmai=
l.com.
