Return-Path: <kasan-dev+bncBCUY5FXDWACRBI7D3LDAMGQEDBAXVZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 231C2BA4699
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 17:30:45 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-46e39567579sf7482245e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 08:30:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758900644; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kf4r/1QZv9cmYID1QLnZiCfRNdI5x1CbiVZEpkFxuCSG/HNAAPLYmIE0dPzEAJKKNm
         6IDWPDEayjYKrGykEMsRUbZkcelEUDCyCddtUxXltI2hikxuBAaxkTJctUomhZ9SGHnw
         z62kxLynN1iDPbLrsnia5AbDFFiKiyfXyaSJUfRQBi14dXnqPrAm4uAotETGmzvGoUt2
         Su9ccmoxaPl3nFu1j9hSGTlUQ2khJdHk1fsUUXTs52VsWer79IaL6+dSzKcBtu3aPyOX
         DbyGtk0rM1dCZVmccTX2Bl+VR+iqN6BjgINwjBCzs5I4TuO+41kB8ejbiNs/Oyxd/zqs
         sHhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=lH1bVg6dWycb2nYRRWJvjCbHIeQ7pE7vDOVgHWRSySk=;
        fh=gCLoJVAMvXSfiEIcUpQgpueAz3kdfFd8rFEkcxuWU24=;
        b=DNfzYWeVvVPTg59uKLUTDaT+TXBPsHSqykvVPjTCXjbXlhdq7ydQ42gD+EsJaEjqGV
         0+NcxutjaDhsWRJCZRv3PiKVPlOa8KUoLcIbgdfLSj4CaO5R5ERw0zH7rU9W/4wcjSIc
         /oZB55ZAkQ7YHC8OqoKLB2Iv1VXJs6ikse5h6SxUX4scWOPhYy9N4eTJvoVVE/452vGl
         nbgfyOkN6yeRvh/3g7PNCs237DS/665oqqYa+di4cWg/wbJXLjaVWUC+A+t0TxmBgLIg
         E5Td97lzNPqpZ5mDtGPDJ2F/KuQCFLv0i2uS0CLVQz1d+E+rVHzSLxcE+6z9vo0DwMeT
         5w9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BTMlz3XZ;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758900644; x=1759505444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lH1bVg6dWycb2nYRRWJvjCbHIeQ7pE7vDOVgHWRSySk=;
        b=Zxj1sKWL/eyUjQGg3KenRQoF5xRhaDy0CoAN6cD4vSC9FXoJV77gM8ldCccQg+IQJJ
         tNuhKxL3/qRdMsWfHfM4gwKXkyPn1PKmlHBtMaB8arDKdJGuwRF83YZjHSjpZjZThPia
         7YeVsiocdLHY+NjKwUEmLpYYykaiZFG2fZIjifUJThs87+2qLb7BmmWHprpWFGsVjMgY
         o8sgFdEwvF8Dj+WIaMNkByMDhHNwSxOYBTBsbOIJe8uaBA6/uUAVEGreruYfXxounbSX
         k9V+sAQDeTdIxCKJMp9LLFIl7isWmHRKFxOhjbkg5NbQy3USA05LbaaqvJv3ky+mvwod
         Ti+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758900644; x=1759505444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lH1bVg6dWycb2nYRRWJvjCbHIeQ7pE7vDOVgHWRSySk=;
        b=bx5zsNgE50X7VMlofsnU0apF/hbHEEkRfgKHvUyo5UMcg6fB+Zt+vp33uyxZPokw2b
         8ERwo9XVUP79fl6J5Mpj1X4AGi2g+Fmdyb204paA+maNwrA6R2rRHnHEFZC72FZHMsp1
         VihWwV1gHecg9ddEQmW/j+U7A6VdJVp6KRdH//GJRT2uSWrEdFYlgaQUQM7ct1FRJeGm
         8N/Xpl6iGF9/MmBqT174bM+wfIYV/rHoFzD/y2mYhLU0jvVJ4WacInX708a/sNaRd6I1
         2OPz+fqu5kcxRtvjBFYc8lkPWCeLErSID7LY4NXsXaIYZK6AP7JPtIXWPn0XFt54IugR
         Yj0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758900644; x=1759505444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lH1bVg6dWycb2nYRRWJvjCbHIeQ7pE7vDOVgHWRSySk=;
        b=Ol2uUOe6yJEhXs5xWjU1QL9R74rsjhb3rqY19YirPY9GDhEw3kU7S3EeuDMGhalM63
         PwfbN3GKtEiC6S5z2VjNIEHVUo5pikNnEXSAoJj6ZoDPFd0AE7waIeCqEKJgR808+MNk
         xKS9XHdrDXnhGltTJJe/twYXUrT0OhnYvBmFd8WRn6TEgW9srB+YAFsEkYGjGHAmwSwN
         lgags/stv0iWRV7ELHQZ/w5Q0KsKMgq84HOQnbSwbD9HMALwVaFkGHvy6IOJ5Vw/6doy
         D1fkY8YIb5zaEt+68HwHIBUhSzYEaNfHSuoLwRU2OKL4Zein/T+E2wzXmSky/9OkxRGg
         SREw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrv5v/fBeIZwSD2y+TecsGhaMUk+1a+XN1nrcKI32OSU9e0mC7Md+f0dc1Vg1jEHqk+tUHQQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYdlMlyypK96rbaz70DwohMuqcqzXtARcLKXmOlzI/dzSi71qq
	cp/XJjYX9LyUSkjDdGH2GhkSH1wR5PW87QM5rTp2Aaen2Un+kWiGurcC
X-Google-Smtp-Source: AGHT+IEZxt08U/lz6FaAB541Iki8mSWKtg5+Pwrv5bLnGBpeW6u0etNIvrCWynSkUmFk6HV0F4yhwA==
X-Received: by 2002:a05:600c:1553:b0:46e:39e4:1721 with SMTP id 5b1f17b1804b1-46e39e41ae1mr38375255e9.12.1758900644202;
        Fri, 26 Sep 2025 08:30:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7M8kZKy50fRAVZ2kL4gQfg7jUQ0Gd+Xe2hKW+KWDnIdA=="
Received: by 2002:a05:600c:154c:b0:45b:6a62:c847 with SMTP id
 5b1f17b1804b1-46e32dcfd37ls14185885e9.0.-pod-prod-08-eu; Fri, 26 Sep 2025
 08:30:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUA2Zmk6Bu5qkbmYOHb0IG/mqPiDz728uY5kmCOA2ILY1ZsSIbJvTStgcmHjQV0Gm7VHV59yxBRMjA=@googlegroups.com
X-Received: by 2002:a05:600c:1547:b0:46e:37a4:d003 with SMTP id 5b1f17b1804b1-46e37a4d2cdmr75496945e9.8.1758900640808;
        Fri, 26 Sep 2025 08:30:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758900640; cv=none;
        d=google.com; s=arc-20240605;
        b=LoWk+EOhxtSVYRnbpH0Tay0QxmnR8MpBHAaw/swYjFqcc4Bim3cddsGeSEiTVclJbl
         19D3SzKQMpGBhdRytMZF66BrqWE/NyGMBaKp/Un83lKT44iI37cRckKMR9lCO8bdBPOY
         3pQDhd8JP6MVKjQnA/YXRdzA9ZlI/cAZKzUMB7x104OIdedPy/MO0+dMOTawpshJ/xZu
         NOozZZ39IQOFtXQR0qOmTW+Tup/CW/Dn6zpsWXwgPJq8FYmnmUvh3iWj2Y/x7D7U1yYn
         43Vr7PypMPXMn9RjomnfGEVXpocmliZHDPv9jjr/DqaJYquh4XjrM586X5mlAfpS1seD
         eMPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Hw0PkEDAgZJmZX4JQxCB6B2llrhkqMZatxLmc7xYfO8=;
        fh=2Tcac5KHmnYhhdKm/AJoIMkhA+g5IK2vjSCbvP72Zc0=;
        b=LLa35v72INXdBuwv6WLa53n1CNPVjenigL9DJoA2+cXHSOI4qG/kjuYSx2v6zCn4bt
         qjzMP8IkguxEhccQn9A/QH9wi016frIxXFFySzHYJ+Hm0oO8VcE22SzUBFja7kZzMkZk
         H+KLusLc7c1YUS1BdDtGav1JyUnmaCHK2S5QOq72PUYb/QqBFjrpRGbmXNKWQNFoG5uJ
         3ss4FJk3UlG49hexV5B3xKpntg48bNuvASlF/3A4tHBSkAF1YlFxRhDpKWHxFcQr1J6v
         4Dow2R+yNWuHonyWHXyBShjHAHFAw82LuIDvbPUzxJ4UnNCkDEZgWK8WfuKU/s5RBEYQ
         juBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BTMlz3XZ;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e32b4f4dbsi1155405e9.0.2025.09.26.08.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Sep 2025 08:30:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-45dd513f4ecso14522715e9.3
        for <kasan-dev@googlegroups.com>; Fri, 26 Sep 2025 08:30:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLiOwVfjsDNxSoyO0EGn/M3kFClzqhYvO79+aWBbaxEgqq5BhCzQcLZVdan/PhwaeHjUFB6lOqmBY=@googlegroups.com
X-Gm-Gg: ASbGncsL4cBjsoFCWRVl5vfdObD/kAJj/2dEhbzdoNQQ4mT8c1wgOCRT9dbnjs6dx8a
	JZSpfRQcr7hL3sYOvMokeaRL+OD3sOaufYsBaKAgua8Z+DabwqSXX7DGiD/JVY8KOBfwRH1OLhp
	9isMoCrjFuScgydBSZ463gQOVUKCiP3gFDPN+rV5XB04yGh3HE71Jh8OQPPIiWcvW3+E5xUMO88
	dO2unr8k1Ot95KVyME7
X-Received: by 2002:a05:600c:1553:b0:46e:39e4:1721 with SMTP id
 5b1f17b1804b1-46e39e41ae1mr38372785e9.12.1758900639846; Fri, 26 Sep 2025
 08:30:39 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz> <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz> <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
 <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com>
 <CAJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF=ZzNOfQ@mail.gmail.com>
 <CAADnVQKt5YVKiVHmoB7fZsuMuD=1+bMYvCNcO0+P3+5rq9JXVw@mail.gmail.com> <7a3406c6-93da-42ee-a215-96ac0213fd4a@suse.cz>
In-Reply-To: <7a3406c6-93da-42ee-a215-96ac0213fd4a@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 26 Sep 2025 16:30:28 +0100
X-Gm-Features: AS18NWDPulJjeGNZJBavOvdAFs79dpLiwntGES88AId5C9cShcZs5_ox3eb1K2Y
Message-ID: <CAADnVQKrLbOxav0+H5LsESa_d_c8yBGfPdRDJzkz6yjeQf9WdA@mail.gmail.com>
Subject: Re: [linux-next:master] [slab] db93cdd664: BUG:kernel_NULL_pointer_dereference,address
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, kernel test robot <oliver.sang@intel.com>, 
	Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BTMlz3XZ;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Fri, Sep 26, 2025 at 1:25=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 9/19/25 20:31, Alexei Starovoitov wrote:
> > On Fri, Sep 19, 2025 at 8:01=E2=80=AFAM Suren Baghdasaryan <surenb@goog=
le.com> wrote:
> >>
> >> >
> >> > I would not. I think adding 'boot or not' logic to these two
> >> > will muddy the waters and will make the whole slab/page_alloc/memcg
> >> > logic and dependencies between them much harder to follow.
> >> > I'd either add a comment to alloc_slab_obj_exts() explaining
> >> > what may happen or add 'boot or not' check only there.
> >> > imo this is a niche, rare and special.
> >>
> >> Ok, comment it is then.
> >> Will you be sending a new version or Vlastimil will be including that
> >> in his fixup?
> >
> > Whichever way. I can, but so far Vlastimil phrasing of comments
> > were much better than mine :) So I think he can fold what he prefers.
>
> I'm adding this. Hopefully we'll be able to make sheaves the only percpu
> caching layer in SLUB in the (near) future, and then requirement for
> cmpxchg16b for allocations will be gone.
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 9f1054f0b9ca..f9f7f3942074 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2089,6 +2089,13 @@ int alloc_slab_obj_exts(struct slab *slab, struct =
kmem_cache *s,
>         gfp &=3D ~OBJCGS_CLEAR_MASK;
>         /* Prevent recursive extension vector allocation */
>         gfp |=3D __GFP_NO_OBJ_EXT;
> +
> +       /*
> +        * Note that allow_spin may be false during early boot and its
> +        * restricted GFP_BOOT_MASK. Due to kmalloc_nolock() only support=
ing
> +        * architectures with cmpxchg16b, early obj_exts will be missing =
for
> +        * very early allocations on those.
> +        */

lgtm. Maybe add a sentence about future sheaves plan, so it's clear
that there is a path forward and above won't stay forever.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKrLbOxav0%2BH5LsESa_d_c8yBGfPdRDJzkz6yjeQf9WdA%40mail.gmail.com.
