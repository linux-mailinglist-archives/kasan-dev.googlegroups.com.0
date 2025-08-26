Return-Path: <kasan-dev+bncBDRLRRU6WEBBBN5WW3CQMGQE6X2SZGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A1704B35C29
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 13:32:09 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e95388e15e3sf3594666276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 04:32:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756207928; cv=pass;
        d=google.com; s=arc-20240605;
        b=dqILf9Olpdu56zofccDrcIiPdkMuDo5NRMNkz/4vz/WjKt4nr970uv4BXaawgARnYH
         wYuuzZjGSCaoVzHmCVR7khKtHxwrVx1xub2SKme4/pmd3l9ap7QYyMZc5aMBRR2b9toL
         gqeXUwgvCHT2ytK8vCJxQIhCV+Nbu12x8CvQ3s8GUzOHXmUzZxLbwP0oH/bPH2E6PpRU
         /YnYj8nUO9/BHHbYHEJevJjgBSuMi42mRz4L/KczeVi4KxDT7xaMHz6J1PGZHvjksS/C
         GhmC2VafDlSvagR9AJBsn0NFjifUox9mfxn07ghjIH63uQrhl3b4ijJXwy8CX0/RXGC/
         4CPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ytpHi57qfGWEOG5ayrjuOWg6HBJTOugDhMH50mD9JM4=;
        fh=RMVm8Nti4+xx16Dz1l+W4S0hj+mbOPVPODxLoavffYU=;
        b=Mm6OI80dg5lmJS8saJnfRtYy6XTeZWEvVSvqB0Il+Omacgi/eyOisd0yTTjmqf5Wx+
         SS8v8xzIuzZDt7KZCo4PivPg6PV0EFdcsEpir202wDvV6hI5JZeIW/hA7Ici6F/pM3bU
         +FcU5u0YVzGfFA7mDlQ300thyTOA+jyoYlUb4ylfnLzM2sMJ3WgU7e2hNR3u+xTPU2aS
         cuJsl3WVbEYNJ0Fz62ODC+REf5P9kp/snPSJvXfvVVninp2lhZ4Ge+SlCBaUG3io8dSF
         3m5YKvuokQklleZE/0fhGgKljqrrbxXbqWi9hQceTngiXPyvlQJ0KoiqyjQhq4gk62fJ
         ZAbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Cp/nrf2y";
       spf=pass (google.com: domain of revest@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=revest@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756207928; x=1756812728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ytpHi57qfGWEOG5ayrjuOWg6HBJTOugDhMH50mD9JM4=;
        b=ZOnIlpEYi2rZKV4XXyAsF9PcAUkdoeAuyOL+ZwU4J3clAiVQFpppht12zMfEiWiZfd
         VHQNMmVHLPZGgsrQ29uUNOawrJeUcnOpTWa/fOdTj0h5XV7xRK29VzrFHD+2Es3dZkvR
         a5v/L1Uj2CoXfECPAkWITaXfQHhRVZFmG6HC040nLBx/STvZyMIA0lp93dcugtPIdPQK
         bTzjy9J8ZBMgsvK+3S6Wo3rRWr7jVwZq0NG3IDUQ7Gln0n/FCqnadoDsqKVQqp6s+Dzw
         ekjlQxlXln8xnNLrOYNTWqrJSBSNR4h3wT/XcghijW9Jekz2W+t0Oo6XtcSuTtwLcaIF
         AqRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756207928; x=1756812728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ytpHi57qfGWEOG5ayrjuOWg6HBJTOugDhMH50mD9JM4=;
        b=DEYlw4UO7kbeSHTXv/rnw1FnLTKnxQW93F1Ow3Lu2hmHn2SyyW9eBqzuqWux5uiMwF
         RXQ9Xg53bkSOzj9k0NhWGN3DGJls0YbQsICmIoRCXYVcjleIVVW52WOBaYfUHPmHzIcP
         kmVlJ45pL117MN7/egdyow4VQ1llTNYsGz7hPcoz8Hl6No0rK2rtveQ5owq1h3oqghot
         83oO8tZvpjy/1P167SFsA6nkgrKwwzEqXibh6Wy0MiCctnDuwbu4MoWWlTT3eX344OSH
         BTGrorX9MQUqMFZ3UoSyb0Sm+750hY5HPHd4ZYBflBZ5nY+ICrWQVtV3qxZYnVOa6UeN
         z2mg==
X-Forwarded-Encrypted: i=2; AJvYcCWW0STeTaSz+WulHuP9lLfyhkzjmTwAucPnTwd6nDLuIlzFwX7I2jHUoRK9kWIY4Zg3qoDiEw==@lfdr.de
X-Gm-Message-State: AOJu0YzLLHUWCJMSvlIZ56G39L/o8y4V/ahU4J5qVtZ+vVtQ+GBhAk1L
	40XjXPHIA7qQsxXFw/ci2j4E2ks3AX0J6Cl0mnFwzl/6dgygTDnfRkdh
X-Google-Smtp-Source: AGHT+IFD/EBwsyVZV3dOR03ysa1GYypzxM7Yk1dG44vvnxbiYrNXPztwRSLClM2W5Des1gT+sl0pTA==
X-Received: by 2002:a05:6902:3103:b0:e85:e81d:9e20 with SMTP id 3f1490d57ef6-e951c2c8547mr13846482276.8.1756207927959;
        Tue, 26 Aug 2025 04:32:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfc9NsJ2BRY+MC/1y2IXrArTM6wn/HrU8XLWpdwekKpaw==
Received: by 2002:a25:1f46:0:b0:e93:349e:511f with SMTP id 3f1490d57ef6-e96d52de903ls1310705276.1.-pod-prod-05-us;
 Tue, 26 Aug 2025 04:32:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAfsIgykk5Zv9p2DNp2fAY4jkm/2O3oUgmzCcDf0NeRnWgYOv8BC1XF5XQqj/A07IihXsBI55uoac=@googlegroups.com
X-Received: by 2002:a05:690c:3345:b0:71f:b944:104f with SMTP id 00721157ae682-71fdc568115mr173417897b3.50.1756207926911;
        Tue, 26 Aug 2025 04:32:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756207926; cv=none;
        d=google.com; s=arc-20240605;
        b=NrRSli8cBGUELMksAwIv5UwruOX6B8RhNoUuzTqQ4ALrzpygEYuqFv+AHq82QOxlhE
         aLt7+URErmZxL/PGjYZDeJ55x+3/88ZPT7gLuirVZvNiHF1dnLntsXb2aQRc+gKJ6GS8
         gIuofRJ/JefFdfFZ6ORt4pJLyJ8zO3td5+Jq+e9hWP6/slmz4zaJcBst5aqitgFZJ1T6
         7aQeZQrHbCR6dpBcWsOj9lLinS8opf9mV2u5O1H7xkMCVSgcapoIS/xfbHKeGxwMpa7V
         nF4446vtLZdXnoJU4T5X1zsSmKSY6tw0FruY0rwI8BZzyhXndmGceBYAASpJMAQnPLn6
         /pZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bgjl982rkJtQB6+NNyAU1pdVTWqd4G+6D2+THSotuPo=;
        fh=gw2ErfdPvitI2WIwxRz5zAVSXl3XSV7c1lxL50dYbnY=;
        b=HTB+z7m1OngnXatr4/Z0QWXWOsO9Ypf3lE7zyTQVvPnqh9qUpss8aCW8QXjGYmbd0g
         3zqbP6tWqwTy5yiEAnYixaK2ddOHuVWlY04y5WuIICtlnvdNNltNnnHS0BYulCiEWItz
         Tfo7qKmMPOEaxBIbm5VK6RmLqYGSh5i6Fx92lurLgbWG+B3amaFG8hJwPq0+7nq3VD3r
         0PraCTIEepZxdAPQqR2GL1pHnt8hvqeQyD8mbw3MNrLdUtkLSDWbO4DNm7pYR+JvTltD
         weRlBpsMBCNM6mIjSuz2qTwo/xOkJ8ytXNj9cnWzDGdbom3sOyQ/8rt3Yg8ZweRS5HXe
         pvsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Cp/nrf2y";
       spf=pass (google.com: domain of revest@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=revest@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7212cb27f01si655947b3.4.2025.08.26.04.32.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 04:32:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of revest@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-4b12b123e48so286581cf.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 04:32:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW3ptqASkLM8u7cR0I5bf76R0Xr8mWy1xZH0du65h8UAN5n9/I/qAMk3Bpc7At/dqFljZ2rzs+mIJk=@googlegroups.com
X-Gm-Gg: ASbGncuvhvcP3MGryE1W3ujmnaUwIGQhrmFM031J+MMrMp7Z7ZAjpF8u3NMwRPqGzOv
	RJTa0uNgwWDj6QE4KT6fsEBHqPDBskB8NaUkjUbeyiG1u1mTQ3+S5o6ESmOiyjy0Us3GJU3Ae1W
	bikRFDFPm8P+mG/2etLeWXdIdR3PToosX3XvrfyB0dgKrQppuDRJ+WRRHmQPIIramlW27CGDObY
	314fM+QQ61fCr3pzeQCoY9tclSsnUK7VWzihvDSnmpjq+V21Uf4
X-Received: by 2002:a05:622a:148b:b0:4a9:a4ef:35d3 with SMTP id
 d75a77b69052e-4b2e2c1e0cdmr4401241cf.7.1756207925975; Tue, 26 Aug 2025
 04:32:05 -0700 (PDT)
MIME-Version: 1.0
References: <20250825154505.1558444-1-elver@google.com> <97dca868-dc8a-422a-aa47-ce2bb739e640@huawei.com>
 <CANpmjNMkU1gaKEa_QAb0Zc+h3P=Yviwr7j0vSuZgv8NHfDbw_A@mail.gmail.com>
In-Reply-To: <CANpmjNMkU1gaKEa_QAb0Zc+h3P=Yviwr7j0vSuZgv8NHfDbw_A@mail.gmail.com>
From: "'Florent Revest' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Aug 2025 13:31:54 +0200
X-Gm-Features: Ac12FXzALeR2tDEEna1F4OrekZEDGHVi9TgPcdxl6W-rTLz9deGbqXZWqVvOe9c
Message-ID: <CALGbS4U6fox7SwmdHfDuawmOWfQeQsxtA1X_VqRxTHpSs-sBYw@mail.gmail.com>
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: Marco Elver <elver@google.com>
Cc: GONG Ruiqi <gongruiqi1@huawei.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	David Hildenbrand <david@redhat.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Harry Yoo <harry.yoo@oracle.com>, Jann Horn <jannh@google.com>, 
	Kees Cook <kees@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Matteo Rizzo <matteorizzo@google.com>, Michal Hocko <mhocko@suse.com>, 
	Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: revest@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Cp/nrf2y";       spf=pass
 (google.com: domain of revest@google.com designates 2607:f8b0:4864:20::82d as
 permitted sender) smtp.mailfrom=revest@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Florent Revest <revest@google.com>
Reply-To: Florent Revest <revest@google.com>
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

On Tue, Aug 26, 2025 at 1:01=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Tue, 26 Aug 2025 at 06:59, GONG Ruiqi <gongruiqi1@huawei.com> wrote:
> > On 8/25/2025 11:44 PM, Marco Elver wrote:
> > > ...
> > >
> > > Introduce a new mode, TYPED_KMALLOC_CACHES, which leverages Clang's
> > > "allocation tokens" via __builtin_alloc_token_infer [1].
> > >
> > > This mechanism allows the compiler to pass a token ID derived from th=
e
> > > allocation's type to the allocator. The compiler performs best-effort
> > > type inference, and recognizes idioms such as kmalloc(sizeof(T), ...)=
.
> > > Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a s=
lab
> > > cache to an allocation of type T, regardless of allocation site.
> > >
> > > Clang's default token ID calculation is described as [1]:
> > >
> > >    TypeHashPointerSplit: This mode assigns a token ID based on the ha=
sh
> > >    of the allocated type's name, where the top half ID-space is reser=
ved
> > >    for types that contain pointers and the bottom half for types that=
 do
> > >    not contain pointers.
> >
> > Is a type's token id always the same across different builds? Or someho=
w
> > predictable? If so, the attacker could probably find out all types that
> > end up with the same id, and use some of them to exploit the buggy one.
>
> Yes, it's meant to be deterministic and predictable. I guess this is
> the same question regarding randomness, for which it's unclear if it
> strengthens or weakens the mitigation. As I wrote elsewhere:
>
> > Irrespective of the top/bottom split, one of the key properties to
> > retain is that allocations of type T are predictably assigned a slab
> > cache. This means that even if a pointer-containing object of type T
> > is vulnerable, yet the pointer within T is useless for exploitation,
> > the difficulty of getting to a sensitive object S is still increased
> > by the fact that S is unlikely to be co-located. If we were to
> > introduce more randomness, we increase the probability that S will be
> > co-located with T, which is counter-intuitive to me.
>
> I think we can reason either way, and I grant you this is rather ambiguou=
s.
>
> But the definitive point that was made to me from various security
> researchers that inspired this technique is that the most useful thing
> we can do is separate pointer-containing objects from
> non-pointer-containing objects (in absence of slab per type, which is
> likely too costly in the common case).

One more perspective on this: in a data center environment, attackers
typically get a first foothold by compromising a userspace network
service. If they can do that once, they can do that a bunch of times,
and gain code execution on different machines every time.

Before trying to exploit a kernel memory corruption to elevate
privileges on a machine, they can test the SLAB properties of the
running kernel to make sure it's as they wish (eg: with timing side
channels like in the SLUBStick paper). So with RANDOM_KMALLOC_CACHES,
attackers can just keep retrying their attacks until they land on a
machine where the types T and S are collocated and only then proceed
with their exploit.

With TYPED_KMALLOC_CACHES (and with SLAB_VIRTUAL hopefully someday),
they are simply never able to cross the "objects without pointers" to
"objects with pointers" boundary which really gets in the way of many
exploitation techniques and feels at least to me like a much stronger
security boundary.

This limit of RANDOM_KMALLOC_CACHES may not be as relevant in other
deployments (eg: on a smartphone) but it makes me strongly prefer
TYPED_KMALLOC_CACHES for server use cases at least.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALGbS4U6fox7SwmdHfDuawmOWfQeQsxtA1X_VqRxTHpSs-sBYw%40mail.gmail.com.
