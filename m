Return-Path: <kasan-dev+bncBDRZHGH43YJRBBNTUG3QMGQE62NCFEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B39D97A5C9
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 18:15:04 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6c36e60b5f9sf92212926d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 09:15:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726503302; cv=pass;
        d=google.com; s=arc-20240605;
        b=MMF+qnlj0aQpP+l6j8V54n1tuXuI9eyLn/QFnZhomcOvbju1UXecLDvxaV9NR6m2nT
         rGChTNGmG1oJyEL5446UH5M1nQubTkypuwJpPUVLDqtr8QC47yAG4GKUYoIWPDjEFnDH
         KW/6+pQ5z0zsKiX7NjWVPm7laAYSSiI21/MDtbYQ0YIu7d3L7Ru7wA5pL7t+0UAg1eUa
         T9tDGsvhnvRbMH9xPRQt8lCtbbMhpYLKygf/aNmT+CRWhY1ZWKQeczU28yMZZd5sZ4wu
         yCmIJt4OJJuXq3+Pgc1fkBwkG4ui+2RSCSJAbSk483+bwblQc1bQUCAsifGg0nq/OERv
         2ZuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zV7MMrG5vIhm5PM/ep1IvEwSFjE3RrJWuHCGEn3xQwQ=;
        fh=G1BNAm8cujAwbD5Zjefc/kcFoF/xS8nvQYmzsMuZz8w=;
        b=JUbs8oeG7IOVgRy0tL89yt02H1F8GdBlTDB84IfQKVZjT8paCkGpulyDOC5sUImMHL
         egzLPxOE+9N4b8X1ae7r/KrtTGm55lGB+aeZRFKTR/sc4DNmA7611YcY/ErBfungeF+P
         PRSp0W12UwuSOB2gHz1qdPyTfa0s9KesmH/eseW+T2zAWGh1GwAGf7OjUaMif131d8Uq
         PuEU5sqyTx8sD579KGlLZJ9gy+DDjPosIRqSYuGXnhe5mugOMS5B5aS/hdracPZMosYz
         abpLvorm2Ii4GTpMsYw0F/nnj8u7/cj/3PRIMFaZ2IMRPVELjdaOs42xU3jTzCD3JRBL
         4+rA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hIDOw2EG;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726503302; x=1727108102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zV7MMrG5vIhm5PM/ep1IvEwSFjE3RrJWuHCGEn3xQwQ=;
        b=BCO57BBYKpkEO+PhbqrjKvu/VgQ7NlSxNU6zGahbePAtS/QJ0OzegYVgGmDb/9hh49
         Zajd3Kk1IdVKjvwTGYJv8GyMs0Wa/N6SypRjJalt8Bt/K11H+cAAizZFsMztcRoG5lWa
         s4hQdXTX2guaDv2lsJ5qj/JhDvnLv1PD2egJXwz68/JNMuXhhyQrllwY97Xd1LKoBHZ/
         6YR+zMTv2DolaJMggKNXQaSXKenLdDNOJTgc4kLZJ88PBBDsAwQFGUYYyLTOsmGKbhpL
         qv5VYz/+iKOblfcmCxKxqneB/tWZXpyvLfwxdg7/Mmn4VBW28GpQqbqa0y2Ef5e4YrHC
         3jYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726503302; x=1727108102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zV7MMrG5vIhm5PM/ep1IvEwSFjE3RrJWuHCGEn3xQwQ=;
        b=WlkWzhtiVenQz5ZEYkAn2dYGzSq/j0fhS8cUDOvAvw7ZFD/IZQ3CoCRbo2sm52hWY+
         M6FM1yaXo2sni4goJnkCCo1FdFuC9uAtqUKMKfedB1CftULDpKBF0YSGTsnZgfTMVqj1
         qDNYyDvBeOI9L8lxZ7Vr1bvG7xOHJ0xaslw7F26Hn8ZgPX5qeNrHpG8lE5qrNQIbHafT
         yOjuP18sWDYSfL3hlQMHTOgaVVhkhxr+iSFS99+oDepSWCxgCPolbuj00uKd4bLLtXIr
         Rq7r7F/te+jSzk5eBebgHrw43H8J7tNmrhRT1ify45sL/2ZqMdC7BTXS/dsKKgtpperO
         vlzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726503302; x=1727108102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zV7MMrG5vIhm5PM/ep1IvEwSFjE3RrJWuHCGEn3xQwQ=;
        b=IZsmfW0+o1r8yn2MLqE2f4XJdIWpQisc8SgiTONLHb0kx+Hx/LFC7np96zv5ugE3xg
         UsMjs/as0CAvzB1MP7+eYOhedma6Nr3AsvngUpYS1s5+T9qH+rpuxSHUatS5yhiSJcD6
         9wl+i0tx0v5vx2yk/6fyiTnpXre8ogBdGgm5hwJLegsmA+exQpnbOCprlG3+a5tEmOB8
         gIVGztMx+Bg+cF0Ns909s534/LU5WcRZLzEwoVYiojQrHxd3IKslMcku9R17Yd1KMWqN
         W9s8wYLmg7FrXTWNRPWNbX/naTr3Cd6egx5h9PMkW9PP5fq42GHetyeYqz5XimMZWxM/
         LgvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0FNFcGLMvABfg7h9CmhyF+JaIiyV19UydnfJo6pkfgAftsuCRhYbYOBm8BRFjHnhP5vF47g==@lfdr.de
X-Gm-Message-State: AOJu0Yym8Oea65J4p9UCYTclpJTPbv0jFtH9AjPXQqC8y7xtcGPyW9zd
	cui7iX7Pr3R82QhLbBNRdSsAFbN5oIPDPkwxxZmRp1xYYT8yOc5o
X-Google-Smtp-Source: AGHT+IEtEmX58yypol4+xLhFRa4IjO0I8uiyEF3vkE8LTBADRwf4m2aWUwuXZEsIjbHlBYff6qKA3A==
X-Received: by 2002:a05:6214:5546:b0:6c5:6876:44d1 with SMTP id 6a1803df08f44-6c57dfa2d75mr185909996d6.12.1726503302070;
        Mon, 16 Sep 2024 09:15:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1c0e:b0:6bd:735f:a70e with SMTP id
 6a1803df08f44-6c5733293b4ls98204966d6.0.-pod-prod-06-us; Mon, 16 Sep 2024
 09:15:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmgI50I/hawkfvZ0igyqQAZXOuoZx46bSgpM3yLmuIjR4DgJnDlyTSKTCErzd83Rd7YaNNrKNHcec=@googlegroups.com
X-Received: by 2002:a05:6214:2f0f:b0:6c5:55bc:2705 with SMTP id 6a1803df08f44-6c57df773a1mr193133756d6.6.1726503301289;
        Mon, 16 Sep 2024 09:15:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726503301; cv=none;
        d=google.com; s=arc-20240605;
        b=C3g5MSjZc40CfEiUqhPl45mnyxJvIXd2uChtD895TgsfiwYB8oIrAD6FL7P1yl4MmV
         BUPbgA6sI7jq642WwNCivYyJSZNw5i72FE5oJcxE2F0EVZcTmIpvP3kQpKt0/Tw1IySx
         +wDMMDPjTmOh1lk+z+IAdNmM7JJwY0bLz0tkOg2VgZnCAXb+NZH78o2Z6Wq+fZs1PBrV
         JtzRkl5mA9xr3kZ6gQt06GCj5F+UEGDDnYmmOH9LQyt7seHiIkmU6w/uNzh9CqpSPshC
         t8E1fgsewzXRpdFy3ChOmM7AMs7knPB8JWYt+0kFrgCtvcmBbMVDufHJrYvxthRTKZG5
         BvuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wiS1s9vOxm6L7SGZsOGa9cdvA3FRdBWjMI6jegocdTc=;
        fh=zh7njPJ53Kx/P2FJFbFqyPIRy8E7BpLozBkRaO+nMME=;
        b=RicBKUDsjpcHZJ2E6dBIzrG/oodFpFkI6Msh6kMAWDfE4vtT5vszXbPLIfSeNQ6BPc
         Tk+KT8MaDU5Tn2CeAPjjLtJt3nMujFZgatsQnN29mqSoSoOljTnFkfbZrlX7eL6E2N3D
         SlEqYVip+QxvwbG1gAYUIqR3TCfG6PTuRQB6jw4UMOcJ1nkOAjTHlEPVGz2j4uWfNl+D
         lnhzHzCbreJKvENhbVXrn+tO1/sDEit6wesTzuArP1b3z+IdYf/dkjsWQmAeG6MoJMB1
         sfvNi8hqFCJJGPEISxeJIsjrLvu/vFe4jLkfNuxGc1FZdW7r6I7ToL3fMk4ZTaPDeG90
         aSOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hIDOw2EG;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6c58c692c17si1977906d6.5.2024.09.16.09.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Sep 2024 09:15:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-2d883286bd2so372458a91.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Sep 2024 09:15:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSwM71ug/M9k+J+jMXv7NpLicUYsVdQ63ibstrd4aMpUc3HCiH2qL2sb8p6qGUb2IVblXnAQHsZCY=@googlegroups.com
X-Received: by 2002:a17:90a:5e05:b0:2d8:cc31:6c5b with SMTP id
 98e67ed59e1d1-2dba001867dmr7480536a91.4.1726503300191; Mon, 16 Sep 2024
 09:15:00 -0700 (PDT)
MIME-Version: 1.0
References: <20240814161052.10374-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240814161052.10374-1-andrey.konovalov@linux.dev>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 16 Sep 2024 18:14:47 +0200
Message-ID: <CANiq72=EoDbhyUXaLqdgkDEQNJoXQHWNdBnAmC5uzHCxBrJ+Tw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: simplify and clarify Makefile
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Matthew Maurer <mmaurer@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hIDOw2EG;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Wed, Aug 14, 2024 at 6:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> When KASAN support was being added to the Linux kernel, GCC did not yet
> support all of the KASAN-related compiler options. Thus, the KASAN
> Makefile had to probe the compiler for supported options.
>
> Nowadays, the Linux kernel GCC version requirement is 5.1+, and thus we
> don't need the probing of the -fasan-shadow-offset parameter: it exists i=
n
> all 5.1+ GCCs.
>
> Simplify the KASAN Makefile to drop CFLAGS_KASAN_MINIMAL.
>
> Also add a few more comments and unify the indentation.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Applied to `rust-next` for the Rust KASAN patch series. Thanks everyone!

(Andrew is also carrying it, but we agreed to do that).

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72%3DEoDbhyUXaLqdgkDEQNJoXQHWNdBnAmC5uzHCxBrJ%2BTw%40mail.gm=
ail.com.
