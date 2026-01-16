Return-Path: <kasan-dev+bncBC7OD3FKWUERBX4JU3FQMGQECL23BVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id CCBD0D29668
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 01:22:57 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2a09845b7fasf10211275ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 16:22:57 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768522976; cv=pass;
        d=google.com; s=arc-20240605;
        b=f0HSD+d+KyqIkzk+m8jf6Ws9hXcXE/ObD/1Pq0AeLqll4ZAidvjtuCtK37wdGqkO2/
         OJ3OElw1r2bzNk8LfyWLklG7087gfSWuU6nqpsEQB59gqu6UWMDdtuVqF0WsCIYERzwh
         nCQcfYplSLna3+F2PT4cYWuH7caymJiNMREsBt07+hTS++sk1a61tr2Hx49ITGZX53pq
         NfHLkjdtbhL+I4sypM/US7x4z7/dEO3hfN0tOyRdY+xuh4RJMzmcMwRd88Xr4CHxASQL
         Y+2cgF8zAlsukbxNsSLwvBiLdtcwKLlvuMHoaZJOp0+nhqtarfI7f9J5wKc6IONBvxbe
         aVvg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y+m7Vco3UZsBI480hubiasfIJi7Nf2AHSyDymHxCq3M=;
        fh=LdeXizgIquxeRH1e9gYgpetTWL74HwGye/+LhOOncLA=;
        b=QCn26K3xDYt5GkV9+AStrWznOMn8VNaHbD2RBCNzfULJo8MEtenlJKQgt2NCJmDtGA
         I7iC4DgWxOXTwG4x57WHNUDHerfrGrhp2atKxV56i9gd17SqjVcEtybFmzJtOqTCVvIV
         D52YquIiktn4D95A8CSBwRebYr/BnkQlNnzX+HcnJSIkEUMqWR7+u/SlXJFO2PS5WV5d
         2m4pn+esn285tgibbAepVSz8IeGM831SdmI2Djgs+wL9ivsVrKMPKOQo8J6AH3250bHJ
         akmW5glLlAVctQ2y7nYIJpwTK0CoCkaWbsEkW5iAWGF2J3XiErU30w7stJY4z6uJe7uL
         yNcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="gw4Gs/R9";
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768522976; x=1769127776; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y+m7Vco3UZsBI480hubiasfIJi7Nf2AHSyDymHxCq3M=;
        b=Lfngf3tEu9sjWtgpZM997Sit/3vvuRe1fedCPAoXY1OLelQ6kpRBbLgmI+4+StEGLj
         QDaq4HiYHemSWTyHrS4MDC/wd9utv9YB/ZICVMzbqPyvHGDV1ptsfjzJs8qD9acAHS4H
         eyG3vWJPNyNx4mcaBv9+QKPzfR2i7iAumZW+7HBkZ/gkiKtip5Txkmu9pHAAqZ9xp0ur
         7kAxmpbQcEXHHBpvMDYDlllr/m0vyERBoP0tHt+p3JYEv84BgNgSkQsXWp/3fGYLhSxf
         1wxXF6LEaqInwmL00E4fKuTwenAHXEYbfN+bwOwT1+LKzNmIWfA2/KE1QfEB9s2r7SeJ
         L9Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768522976; x=1769127776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=y+m7Vco3UZsBI480hubiasfIJi7Nf2AHSyDymHxCq3M=;
        b=Be76L4savhc7ez0/bUMMZpfASPfYvLalHH9L3SptuH3ZqUlWMMa/Vg/D3HZBgTp0Vf
         YiFKBuz+GdgxmDL1Et94EtoLTI61gDpPPe6ow35/Cfwy7ib07AOzqqwM3VzhjPZBeI++
         o6s7c61jZHWhdEh3Pe8OeBM5rNXFza+qSyU8f0ytyyIyOCCfzX49eJSaXN/JeT7ZHszs
         ODZNqmc/lHGAZnM+L6qrdKeoE9TbJ4k3EJwiVmfTw9ZL7yO2OClTDTeT5hqXG05CtiAC
         1TQYAsh4DmETTD571tldzTUCAp1IoUjijv2ho7QuW9m8KkMMG3/TM2v6nPtj6Y4daNpL
         wZew==
X-Forwarded-Encrypted: i=3; AJvYcCVzyyID6WCx7BKmuU0CCJtrtw0MqE/jbJmbS6Lppp21PYV7He9CYlfiO7vaKamujdednPI8ew==@lfdr.de
X-Gm-Message-State: AOJu0YxfoLEkAmPDLxjgkZLjWLpX9DUktwd7VX8CsH7+oVSu3mRTzuXJ
	jVczkyHgWJV2i1Iqq/JRL/txBiAcSmLa7Mgdv65rAIJmFn4KGpDD1vqB
X-Received: by 2002:a17:903:1967:b0:2a0:ccdb:218d with SMTP id d9443c01a7336-2a7188a976bmr10600845ad.17.1768522975653;
        Thu, 15 Jan 2026 16:22:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EdyWzDX0im3AIopUs9Ka0EXqAPeAAB9cYmi/ARZjWHOA=="
Received: by 2002:a17:902:bc45:b0:295:586a:9d87 with SMTP id
 d9443c01a7336-2a703336e25ls9940975ad.1.-pod-prod-05-us; Thu, 15 Jan 2026
 16:22:54 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVbz6cDY+b7TBBZ3GjRxH1Gfu0dcpngKtKVppz0K9NkYFRUY6l2H/x2XObXcMqAB++Tev5Yz/D7QjM=@googlegroups.com
X-Received: by 2002:a17:903:1a2e:b0:2a1:1f28:d7ee with SMTP id d9443c01a7336-2a7189737e7mr7863235ad.57.1768522974233;
        Thu, 15 Jan 2026 16:22:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768522974; cv=pass;
        d=google.com; s=arc-20240605;
        b=kdckkL5dZwBRucNTZDZqrvHIeq+2lEEpgJnAkrTSJ4aU4smwP40HAQMo8cMje7pip2
         Ey0Lfqq47wnEtU6DSeJwm6TcF5psBKNYfFKMyah0VV4XKTogezd/7EqEhq99/TYxngw9
         nrzhZRJWJt1RD4Zx0ABRkz26E4Gja1zsI5czdQaheSP8SU4Xf6q1V6dNbpu/Hx2YyV7x
         UGmHhDDXIn+i1prCdsmuUB5xbJMV+NEr+h54cd0hpH/ojq4MANiViOxrkDnemLO/GjB9
         bdEjavQU3mOXo+/WOhEp27AEnKnwaQu9re84KrDbzj+HK1zEckwj/vF9hRGtNtsKDB0C
         Dmiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DW/ITMg56jRAZJtQnAt5F58BDqK/01GQKI49GCbQ0F8=;
        fh=9wcs31wRJam36rwv/Ww3ltn685IxYg+QStwBqYAZxLE=;
        b=VWFc5BQeasIKV0dFLvkuRmauA5IgexYqnaqU257hhLG6OlZfSKZYThvvXQJRQFDlBJ
         0Ydwx8E1wmxcakUO904Pmpt08H7ClKT1jez/WDwrNwKAJYp27g+/48O1o0j7JicV+nVe
         ixEeAhAGhEMHDpOcB29kjhKYfDIsZ2sR5kG4KuQ87Ie/R7Oige9MGHKjKzjE3Qq78wlz
         kGVHYWw+o5agr5x6Zam9jAYKZBMeC0TKsbZxZPwJntcTFpsYwz1kjtPgkp5ymyx6E0Gf
         sdIwGgHMEs20Z850OnYh6mpVMMAC/DvI4+6nX3pk3XYtWxNplkuVF/4J48W4AJHEaKf5
         ub1g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="gw4Gs/R9";
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a718f8abcesi321435ad.0.2026.01.15.16.22.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jan 2026 16:22:54 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id d75a77b69052e-50299648ae9so103611cf.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Jan 2026 16:22:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768522973; cv=none;
        d=google.com; s=arc-20240605;
        b=P5iz5imH+HKS/5064+XDej78Q9TBimTRgXQhBRIbmrVROLIeHTtAG44IoPN/krM4rY
         Wn9SZIGCACO/9icbOF6sAOe94/0m7iSBRdXpmbEiokEtAgTgjsOo1zMM/vLAp0K9zWX9
         WBJHiVpoLDm1zIFDtmIVIOOnUO/phv6Lf71oxhMSZzxAgZ80xAoyGa75niOVrOKhdajY
         YsU48BEP/q4iKWDuk9qcfN/xqJJxilnH7LtRFkt82OzegyN/Ju34bX+3IKAXKs1ypI4d
         SZg0I0XggapkbOcxKx5nKaxXoFTdPjUDM8gQSKDWvjkEpXTRwFSuVeX0J750IJKClp/2
         gGMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DW/ITMg56jRAZJtQnAt5F58BDqK/01GQKI49GCbQ0F8=;
        fh=9wcs31wRJam36rwv/Ww3ltn685IxYg+QStwBqYAZxLE=;
        b=QawYRrACHsWX5focMPY35P96oK23zP2ySLBeKkJA6nUMFSn36Wv+/CSKKOjWd1dbgF
         hm+nuXNFPD27k9ii3abMXeS6dD/XMqs7LOqyH2OK0laCkQu/wOVb9zffi/AJz6XXx3Cv
         Fo6mJeCX7jYTQDsfhgoB6SvRZauNEyE7LTUsZ7DIixSe+1BFMmrjp3yJT+e87N/QT8F5
         OMqaHrP3/3xC78Ii185BtMHzSoTyjQbIPs5bxhJdQP8rdDMUH7kEKUhuPXV3hTlu/8HP
         HsFkLotNGoW+7RSFKyS3IvWT/6qbyQhFUXXKAUljvcAtDF1plQyO/fatENP5/Ws4/Y+i
         DI8g==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWzjawQDPMONOLxEgWP0RRlVoDFlUtY8d2hCnWNzT5oygEHf5ZYPj5pXbqyAL/FEEf6JnuSVEJ2qOI=@googlegroups.com
X-Gm-Gg: AY/fxX6+L1zywqGU1p7ZCLIMhmpF6yDdjNXVn6NymrGAy5uUvj7wzjkDrI5/z2rdYdV
	S1P80yzS4K6kznxg982w1Ccw4CKQzSZJmjcqLMmC/ZDRdKZd9Pxs+txhROeGcSZq40HJwyGwnok
	k08KW/1pMqVGq8xhli3+h3mSGDUq3SGv1Hrq063mBQO6Y5FNBxJqjWJq7EBdskKVQxo8SCQCCEF
	vd6Xo1VauUgU0l7vORxTTPCJyC1UHD+wWP9gjGJfBmdFUNTthVKns6pj+uvuwfZO5FGTojvuSON
	XXRuEoZZfk76sMAYdjGf3fk=
X-Received: by 2002:ac8:7d0b:0:b0:4f3:54eb:f26e with SMTP id
 d75a77b69052e-502a367742fmr2431351cf.1.1768522972940; Thu, 15 Jan 2026
 16:22:52 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz> <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jan 2026 00:22:42 +0000
X-Gm-Features: AZwV_Qi0xiGM2d4FuoLFqXrZf077B4nd0NZeqj4924Qs7epHRHPkVirBgIQQHEM
Message-ID: <CAJuCfpHowLbqn7ex1COBTZBchhWFy=C3sgD0Uo=J-nKX+NYBvA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 03/20] mm/slab: make caches with sheaves mergeable
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="gw4Gs/R9";       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Before enabling sheaves for all caches (with automatically determined
> capacity), their enablement should no longer prevent merging of caches.
> Limit this merge prevention only to caches that were created with a
> specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab_common.c | 13 +++++++------
>  1 file changed, 7 insertions(+), 6 deletions(-)
>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 52591d9c04f3..54c17dc6d5ec 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -163,9 +163,6 @@ int slab_unmergeable(struct kmem_cache *s)
>                 return 1;
>  #endif
>
> -       if (s->cpu_sheaves)
> -               return 1;
> -
>         /*
>          * We may have set a slab to be unmergeable during bootstrap.
>          */
> @@ -190,9 +187,6 @@ static struct kmem_cache *find_mergeable(unsigned int=
 size, slab_flags_t flags,
>         if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
>                 return NULL;
>
> -       if (args->sheaf_capacity)
> -               return NULL;
> -
>         flags =3D kmem_cache_flags(flags, name);
>
>         if (flags & SLAB_NEVER_MERGE)
> @@ -337,6 +331,13 @@ struct kmem_cache *__kmem_cache_create_args(const ch=
ar *name,
>         flags &=3D ~SLAB_DEBUG_FLAGS;
>  #endif
>
> +       /*
> +        * Caches with specific capacity are special enough. It's simpler=
 to
> +        * make them unmergeable.
> +        */
> +       if (args->sheaf_capacity)
> +               flags |=3D SLAB_NO_MERGE;

So, this is very subtle and maybe not that important but the comment
for kmem_cache_args.sheaf_capacity claims "When slub_debug is enabled
for the cache, the sheaf_capacity argument is ignored.". With this
change this argument is not completely ignored anymore... It sets
SLAB_NO_MERGE even if slub_debug is enabled, doesn't it?

> +
>         mutex_lock(&slab_mutex);
>
>         err =3D kmem_cache_sanity_check(name, object_size);
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpHowLbqn7ex1COBTZBchhWFy%3DC3sgD0Uo%3DJ-nKX%2BNYBvA%40mail.gmail.com.
