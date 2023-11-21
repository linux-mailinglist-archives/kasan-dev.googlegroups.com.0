Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBAOS6GVAMGQEXEQSVNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 194017F2761
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 09:23:31 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-5cb92becbf6sf6252457b3.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 00:23:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700555010; cv=pass;
        d=google.com; s=arc-20160816;
        b=0/lX4KoEqt93MjqpZixIqzcHYpRw4/BAeeko3HX3i0uGfpzADSxivDLqx2PbqnRxkF
         FnxlrADctzBKYZWIeqcoed4iYA6nXI3wiTDHvU36YXs7HbMmIFOPBnQ5tVKyV1WGxWGj
         WTUyKanegN/2SDnC/oiiqqbyfE/njXVNdyyhuN6m2O+cPOJothIaZGkry30WRkOiZmmc
         j10wHN7x3JuV4qo9oE2RFDJjUgHjvc6RDLF2G2Hb6Tko6fnm3GYA2m4Bf7xuJHo2VQ2G
         CNm6Yl30iMKiCIBqLg7XkYHN7ch+4F2ta8d6CII6StydX8BdbIsnYsntGoovTZ6RMJpB
         Sc8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=S9JF9cRz8EZBE57yjmgn3c1t5SiTQtasvZ7EHWPF9KM=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=sj2Y4fRFlPnXBRcAGv0RcnnA/+HehsvOH/SL6dzd3zhq3OQ8QJYDVAwaLB+kIDbzEC
         CB3CIjNjcH91v4/Pu9cwsfIekVmn4A0io99b4fzAkR1xMhAn/NkBqL8PU17wK04o8CdF
         EYEKGcDypYvByajLocXK5PJhuHm2XltDUapRKkANk/nyL/ZpT5KzH4YsoGQZ5hDRXegT
         sV4LvIiDu4WpHoQHiZh+mVfdKhlqoSx4bwbjxo09AFDJ6SPqTO+Y+Y7H0I0Zg+hli8mD
         f303/viWPoQhFlvpCl22UM5MIsIEd5AE6UWGJAmXd5vKYY0AvaX8LSi/fzzncth9LGmq
         y+Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MTiuO0pf;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700555010; x=1701159810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S9JF9cRz8EZBE57yjmgn3c1t5SiTQtasvZ7EHWPF9KM=;
        b=AJbZjHgcLBZt3bes424BDt4YbLm5pHXHggEjXsr6h+Or/eECRzV/Jdt4csrlPQWIZ4
         ek9RKZ7QwBrCJKOxSyBmJmKXL2MmU/cy5d7lNezmYa2qmG2hUOGjXclQWLzkRhrpsgne
         SOYxJfIdccbZQV4GpmFJZXgMR5N4jHbqybY2hxFwoLCIgpvGAYiFMT8M5/crqVIYb6qr
         ENfoujRv0ib+I3KCsbUXR7l6L5D/R5XnWdEdOg18GEi3r8O01C6Y5zf2gUSx8VYj5dxU
         3ivchN5E/KhTLYVaPUKbRSOEnQ3Ojh5yCwqasPxwna0pjQqQdB2CCUpIdWipa4Alp/1w
         ABpg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700555010; x=1701159810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S9JF9cRz8EZBE57yjmgn3c1t5SiTQtasvZ7EHWPF9KM=;
        b=KQ4By9GkTlqy5znMKYpBq09wXYH+2u+4Iwgnae7MgnX/al68n9FUWqTfQRGnItffMx
         rNyWB1RXaLsFU57o4i2Z2BaVk4xmGC4u7I2o0uIMKd0pySlaIlnQfR8J4DadXHiIfUOY
         8S2cYCCDGgikuqwPFoef+BHonxSz9T65KGfTSieUox8RFU3el0t+dD4XPfKYuLT7QFfv
         MikBWQCB9q65XuAqe44K0IEBnzL0CgSzCGAxAUMJm16EwBoEhwY3/wCje21BzLWNqlR7
         Jm1gp2C23EpeXiRqs0MHI6CR0+6iqgluybdcBCbpQU1i6BMmgJtr4vqhbe3ncfkRFti1
         kOwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700555010; x=1701159810;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S9JF9cRz8EZBE57yjmgn3c1t5SiTQtasvZ7EHWPF9KM=;
        b=GSJz+QuAVZ1DvWm655VMyl7K5mOFMwUi4yZgVjb+6vVMrQDQJyVeRuDkKe7T906MJ9
         F4s29h95AqwMeMYZWtqh7oO3XyVNRfAvRwOJEYww1np6zpBswHb2+p7umV/g9A/ypBvz
         7/mpaCP6LkC8Fqcu6STzfUu/d+ftFsBnQdarq5ykO4PQU9ouJqkc8ZRJiL96J+rocONi
         KHwpFY+GUfekvnI96VxT5Uo4lFMFTyN0vIg6z0vjv1nHVawoGJ8T34dNxnPkozK9siPs
         Cu/4ZyBuR6cM5ChVw0LSWsc5MS48751t2dTG4DrQSfNhr7+r6f0DLChdgtA4TH6H5N13
         mvKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyuf3GDPztY+vuPE5gMZaLs7Qy8xFvUnhMxF1NwOn+1Z25AfZTo
	/DZgEIA/2poQWRC4RkOGvCA=
X-Google-Smtp-Source: AGHT+IFeRxhj3uJHm3wFeVxZ9dHn7JJANg7nrBbsJvsAmfj4PaeXouHIG8iOe1dD6Zp1iMwOxSXCtg==
X-Received: by 2002:a25:e693:0:b0:db3:c340:11e2 with SMTP id d141-20020a25e693000000b00db3c34011e2mr3382975ybh.57.1700555009749;
        Tue, 21 Nov 2023 00:23:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7758:0:b0:d86:8d6e:b575 with SMTP id s85-20020a257758000000b00d868d6eb575ls746203ybc.1.-pod-prod-06-us;
 Tue, 21 Nov 2023 00:23:29 -0800 (PST)
X-Received: by 2002:a05:690c:2e84:b0:5ca:ddd2:b03 with SMTP id eu4-20020a05690c2e8400b005caddd20b03mr3232256ywb.5.1700555008752;
        Tue, 21 Nov 2023 00:23:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700555008; cv=none;
        d=google.com; s=arc-20160816;
        b=s87spYaNqdxOZeuLbd3AppuJieI1dUina4XytpeTHilA6ZP9+rE72hBskbudh3h704
         VhtYJYBj+Sf9nadD490Aiwsd2lfsNlxu7CHVpaPa9PVCw+X7qTVW13JOpwgpQEExoj9w
         1MgCa092uiuQZRABr0SRn4Gfh7mlhUZ/MmjDdqIMY77BeaxnYYC18NfXeKrq+l5Peq84
         ZWL3W36avs1gsCjckQcJ6MO79pGSWAt2xkSFj83IZPMYXSz2EnbiGUiWeERKUhXMFRw7
         6arw+kzTwREQFOPNTaflaCDAHArS35ht61VoLRNmojcrFmCQwSv5ie3+nusCos6X6OFT
         /TGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VTTlQmptyhl28YwEosbclj7OWg+yV7E5QNOLel4gX6s=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=VN3xvOiStbj5xpdai4HJACEuWrCNZUOsqqez1IgevJnUtUJfnVx9HSFrMHy92maOUg
         q0hHN8J2YIC9WRE0rmbxNJgVRrmCO3AI2h2h1K8DIqv9WOHGdydpdESi+izv5CZUDVMc
         825RHlKToViTIEoIvoutwvYCwo0219uCKVwXEvpRpvDMyp3W8aafZ4ksLaHMsRt3gKQ6
         TaEPA2DhhYL5wNKL/9TpOjJEiRN9AjlUFgNW2GvXZdRmZ+ngKBHydx1nNdz3+tNl56ou
         Apd3WocjWySyR3rO/o30X5FtazHIsmMU1JsVMKFnJZ4D7dIsMS9IgpOzR/LZ/1GIg4w3
         sBWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MTiuO0pf;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe29.google.com (mail-vs1-xe29.google.com. [2607:f8b0:4864:20::e29])
        by gmr-mx.google.com with ESMTPS id dk3-20020a056214092300b00679e06a26casi242464qvb.1.2023.11.21.00.23.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Nov 2023 00:23:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e29 as permitted sender) client-ip=2607:f8b0:4864:20::e29;
Received: by mail-vs1-xe29.google.com with SMTP id ada2fe7eead31-4629f1d872dso594825137.3
        for <kasan-dev@googlegroups.com>; Tue, 21 Nov 2023 00:23:28 -0800 (PST)
X-Received: by 2002:a67:fbcc:0:b0:45d:a89f:e1f4 with SMTP id
 o12-20020a67fbcc000000b0045da89fe1f4mr4547806vsr.9.1700555008189; Tue, 21 Nov
 2023 00:23:28 -0800 (PST)
MIME-Version: 1.0
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz> <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Tue, 21 Nov 2023 17:23:17 +0900
Message-ID: <CAB=+i9R+307rFa8d6evMFMZwPrrCXmafGrZavMhupBYph6tSAg@mail.gmail.com>
Subject: Re: [PATCH v2 03/21] KASAN: remove code paths guarded by CONFIG_SLAB
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <muchun.song@linux.dev>, 
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MTiuO0pf;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::e29
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Nov 21, 2023 at 3:34=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> With SLAB removed and SLUB the only remaining allocator, we can clean up
> some code that was depending on the choice.
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

[...]

> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index ca4529156735..138c57b836f2 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -144,10 +144,6 @@ static void qlink_free(struct qlist_node *qlink, str=
uct kmem_cache *cache)
>  {
>         void *object =3D qlink_to_object(qlink, cache);
>         struct kasan_free_meta *meta =3D kasan_get_free_meta(cache, objec=
t);
> -       unsigned long flags;
> -
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_save(flags);
>
>         /*
>          * If init_on_free is enabled and KASAN's free metadata is stored=
 in
> @@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, stru=
ct kmem_cache *cache)
>         *(u8 *)kasan_mem_to_shadow(object) =3D KASAN_SLAB_FREE;
>
>         ___cache_free(cache, object, _THIS_IP_);
> -
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_restore(flags);
>  }

FYI there's a slight conflict (easy to resolve, though) when I tried
to merge this on top of linux-next,
due to a recent change in KASAN:

https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/=
?id=3D0e8b630f3053f0ff84b7c3ab8ff98a7393863824

Thanks,
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9R%2B307rFa8d6evMFMZwPrrCXmafGrZavMhupBYph6tSAg%40mail.=
gmail.com.
