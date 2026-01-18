Return-Path: <kasan-dev+bncBC7OD3FKWUERBB4NWXFQMGQEI5CTC5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C5CD1D399CF
	for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 21:46:00 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-6505cbe401asf3474659a12.0
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 12:46:00 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768769160; cv=pass;
        d=google.com; s=arc-20240605;
        b=jdT8sEuNSibpb49EWLam7menXFpFQ4MJn/pxA2CDC9uXaqOks3KuzWueSOGT0g8uAZ
         gC2PAR0IPGW/IVm8W9hjaT6UtYuEVzRet9Bi2I+kEMURfgeh4VVVA+VOCxse8SZvn+Nd
         KDiDTJiaf2c8gMPOt3ABvgTgWjJ+XrJlPBNiNxzo+6Y532MLOVtQ3s01cbiDBAdv3eVN
         KBoGZM1TF3lkOXpe7tR5hy0QSLSBzRWY5lmq7dxBwMAxbp2/wpDIygPp3g8AuGuXXf+H
         DKGrf64vUKpX3FI9SoIj1fQlnQtQfOUkocIW/Do75hJ2waW6jwbXMDytWLaKSETaGI21
         WuZA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8afEdDdBYL2CuYEnO/5OrXpesEAqAHKmWOKa//raGIQ=;
        fh=p4IcHhgv3v3PJ+4bFhJVGfDA4OJ/uKyhWtyp4h3k63g=;
        b=bMGk5Xr0GBPwd81a1uRpu1WzgSMXQ2J3UvsjxaN7L0TJB78qNMnE1bdwzNz5qz9Q0K
         dgpRYbaUNqOws/BFuNl2ix6NO6BOr9j8C+wibZM6fpQ6KTkSlZKsKLqGXUkr+RiOpf2f
         YV1rsptty8VJHW7y7sQHQVOxMYzIyLs5gMwjQG95zXKmvQ4HKzUg77yh1elsmCF1ykD/
         1KJuil2QB/xKMXWemn3y/67ve9mDLtxhJtA8JhSSKqhuFYDPV/uz3QX4FZlkQNVyLRw/
         S7wGpKwFFMG7Sgq5N4cK86tI7UbhtfH8sheNZNxtc2Z708zfvjphrpixTsbZfBjEMZtx
         irgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EibxbMVq;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768769160; x=1769373960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8afEdDdBYL2CuYEnO/5OrXpesEAqAHKmWOKa//raGIQ=;
        b=Uz2A8BkE8txrFLEh/rd3PjVmniTh3UnGkqh0v86h+iAYuvKktG4ESfIepcYRslkDTC
         Lbd4rQVlEGwnm3yxIqSHrAj91C0kJFFLPvz58+7xrAkEQXmXfMiE3ZxbHXHvb099FwBF
         xmddKfrOqmhMgvJUsjpiQk/7OJOQOOrVsO3/Mj0rpZkjB05Ukp9mvtGY106mNKtI25n1
         +Ov8Q/1B8y7gxuxVCG+pYrEGsp6oPDjJJpBoqQchXLKbeGZbJlW9995N44NqvWKEnmNk
         M3KiKBn0kzFFR0N/RTRn/5MHnu/BlEncvKjIZ5J9drkKFkm12hlv+gvx/UWyCH2+DHtU
         z8qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768769160; x=1769373960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=8afEdDdBYL2CuYEnO/5OrXpesEAqAHKmWOKa//raGIQ=;
        b=bTsqGMyGMacOYDo/jRQd8m9AKANO/DTvxlzjuhmeMNgON5RrWT0uWAuk+nZQ1R9JYe
         6SVnxtW0Ofa3BXH5GmOrMWe0SEp4WadyNmLPo4+49ahrn9UzdtSFmbwYWQdvakF5/TgQ
         8+FQIuANIyw/ZjoHdebXzA/Ur/3yreGC1qFaxyrlgzvEJR4JbUfgjbLxj4WgdfK3toxD
         nSl2IzItJwVwFz/yvqtKc+YLLRg/r6E1GOP/19IHtIylaqyZDjz0pYEqLLAEKjc2sxga
         zKS8u4U0xY0+PFZg2szTTJQCeOxn2X+DnidCxIVbRYhr117Zr2E6lfdjewUSZHpfL1AX
         GL9w==
X-Forwarded-Encrypted: i=3; AJvYcCVwT6Rk8n72Kogv4gVYlYZIQ/g+PKugSSLWkSUgfulZikM1trms+aTjW9TuPR/aseu7nkz+sw==@lfdr.de
X-Gm-Message-State: AOJu0YxQDyGWiqNvgB62jdayuPCqSnUV05UGCksdAtBs3D0SUFBc8vf/
	jhb+Pbd1kxPySgetFZnZsFoUJw+gYLlHw58oeUt8ouizFg537Yi4PJWM
X-Received: by 2002:a05:6402:27cd:b0:64c:fc09:c972 with SMTP id 4fb4d7f45d1cf-65452aca675mr7298474a12.17.1768769159828;
        Sun, 18 Jan 2026 12:45:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HM4egOgAy0x0TDRR6Og3PQYiJEXw9Am/Um4q4ruHwnKw=="
Received: by 2002:a05:6402:5350:10b0:64c:7925:f275 with SMTP id
 4fb4d7f45d1cf-6541c5e017als2617090a12.1.-pod-prod-09-eu; Sun, 18 Jan 2026
 12:45:57 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVrF8x4KWOp6AdYG1EjapGvXcbIdosALeXp0faPD117pqxInwM1y1OzyNv3NKeSjXo0lEhzYZCeTQI=@googlegroups.com
X-Received: by 2002:a05:6402:3206:b0:656:a153:f0f8 with SMTP id 4fb4d7f45d1cf-656a153f2ecmr1362279a12.29.1768769157602;
        Sun, 18 Jan 2026 12:45:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768769157; cv=pass;
        d=google.com; s=arc-20240605;
        b=C0OgM2eprPGWh5G//lDNbUPeM12n3JmlybQiRPRXjuUTgD6atHAB1tltUpddZogMxf
         9C8csyVzgzwEkCZLZssPj9b9SyVWmTEzUA2kmTr351pGza56VV6CcGTxX68DYMzeoz4o
         F2Wo8LA+RBozaRkptvZT1620URTA0FT7QXiDKkPyV86f3ieFslLRrgjlwdVEmz5+RPk0
         GBMMiW0tTfAbvdkJF4Bk6YvwyyjigMWSXLEUMVB5fGNNUrNxeoT0HNelIX5okfeoC256
         6Gypg6p6TyaDhxf9LRocCZuQszjw3+1Gkurb4M7bOls9KDES5/J9xIYQ5EQxo7I9j59x
         5k+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IJvJDVCfQGiQhTyEeyupPbB3kxPlJFu+RnX8pclHBaI=;
        fh=ZOoqdsD/M12jR7SYhpLkx+5/cYxIS+6W6b4XOL5JsAo=;
        b=COfeknr1Ik4ChKVeyBSGQoNjTpUryx1tR3+p/QG8FtAJd+Kb15KqR1WN0eKtjoarJ9
         36e8TKgMYI3jQ7G3vX7nyzZ3wwvgElK/+3Lbpq45e4+4Z6R9D03LunWzgZMq24bP4ZCG
         ODRlYXlDXpYfjbwPnw92xEpKx50yEWzCMWTMRZADSPIEDBo+ns5UXB1EEjRnCzYVILt7
         UE8UnA1bb6pECFVGTL3NVQJARIwQKp8Ew2xF6aX2Q0vJG1uZlN81/MMNn+1F8x7wM6xU
         k6I+xIAqnFmn4CU/p/2MTjlFSkV6JgMQRwFG4xtj98H3LjO4Tb5yoFpB+vPLDHw4mKl7
         kS0g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EibxbMVq;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654530dca1fsi111248a12.4.2026.01.18.12.45.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Jan 2026 12:45:57 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-652fe3bf65aso4485a12.1
        for <kasan-dev@googlegroups.com>; Sun, 18 Jan 2026 12:45:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768769157; cv=none;
        d=google.com; s=arc-20240605;
        b=Q8reskN2zG5L6Bzn+dr4MIVfrqGFTj45XjGXmhkFpcRwOfaN+zFLssWQv98oqGQO86
         SjeEIabx9teosf+Pgvbq79tiuT50NNLFcksqhA6cAm8oTVBcm0HI2sGErqv2olgkdDt5
         3PeuVYtFKRzcU/Kdi+6VSD0ekhRJhOCkmdO/LDDWyU3IM3YFH2RqDr2RLxlsYJLs6Gcc
         u+S2me1XlwEvg8OO3n02kpB6P/pw+gMHcCHUc/J/8JvvmhqP38C4XhU28rNVTAoYGs+0
         lYw/py2cn7CN9QNT31f709I+6YDFh1folg/ETRpdu21mJS22oUXtNmCEURx4QF6xnIHy
         /yRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IJvJDVCfQGiQhTyEeyupPbB3kxPlJFu+RnX8pclHBaI=;
        fh=ZOoqdsD/M12jR7SYhpLkx+5/cYxIS+6W6b4XOL5JsAo=;
        b=cUeByfGJQaEV6oOiPKDVuCT+SJ/Oa1cDM6tqO84aw/zIAmDdXje0nPhKlO4DO/Gqpn
         3hc76ovWJdk0kTwx8bj2JKE5065oa845wHqURf6wh/fRc1e4031Vh1L+GZBVPZAh+2YD
         N1QEaVJuTOLTgs9VTSWjm514SAH3RXz0aTX5nYLOoOoNCOfftlD5/TC9/qGqEs92Ot/J
         XiXxOe306259SqBDFsysJ6XKyDhoq4TXL+EPLGWmncBB/5R/prcCshn8imfl1JFkm7YZ
         tvNts/8NOD9LatD03/SGINSSbNzZj8IejQAx9fhJBZy03ga/FqHGi96Vq7Iro1AevDQZ
         qQpg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXoCx9yC5HByF1mK9JG5IDHg7gMp+jds8r4RmJP3on+GiCBQOKU7mBZxXsd76jkHCNnW0GSwK9I15Y=@googlegroups.com
X-Gm-Gg: AY/fxX47Ri+CcgG3TDRP8nfuLuepFPwRxydy+6dj8H2vcVehD5AUsQmzCssIMJ0OW1U
	jpBoJlIM1j9yqq38bW2iAfS5m1plUlw8C++jcG9F3el5svNJH1kK7wHv+m3+VV70fQpx6NRPeeH
	nA7Mf9+DyXcOaWF66NpRrFF6BLZh3mKA05SMchqaRhdYiMfzB/oMrfgtdvrXnXnu4IHSYVCVje7
	GQvI3KbPbMWQJWTyjeaCrw+gs6L+jskswSeNkn7FnvtoK5q1Te+9ytaGH++yT5UJVCqOuWSDjJZ
	AzbelSxznVm2/uPg3CiqTW8=
X-Received: by 2002:a05:6402:b79:b0:650:5d5c:711c with SMTP id
 4fb4d7f45d1cf-6561ee75634mr22230a12.17.1768769156751; Sun, 18 Jan 2026
 12:45:56 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 18 Jan 2026 20:45:43 +0000
X-Gm-Features: AZwV_QiwVzd1b1HBHsztjRZ_PLBdReYsBX8Ibd28htOveyCZqKIEsBm2-CrYcsc
Message-ID: <CAJuCfpELoHBKSq=DyLPPtQwqL=nPaQ1cBD-sthJd64MbW40Bxw@mail.gmail.com>
Subject: Re: [PATCH v3 07/21] slab: make percpu sheaves compatible with kmalloc_nolock()/kfree_nolock()
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
 header.i=@google.com header.s=20230601 header.b=EibxbMVq;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=surenb@google.com;
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

On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> kmalloc_nolock() and kfree_nolock() will continue working properly and
> not spin when not allowed to.
>
> Percpu sheaves themselves use local_trylock() so they are already
> compatible. We just need to be careful with the barn->lock spin_lock.
> Pass a new allow_spin parameter where necessary to use
> spin_trylock_irqsave().
>
> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> for now it will always fail until we enable sheaves for kmalloc caches
> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slub.c | 79 ++++++++++++++++++++++++++++++++++++++++++++-------------=
------
>  1 file changed, 56 insertions(+), 23 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 706cb6398f05..b385247c219f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2893,7 +2893,8 @@ static void pcs_destroy(struct kmem_cache *s)
>         s->cpu_sheaves =3D NULL;
>  }
>
> -static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
> +static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
> +                                              bool allow_spin)
>  {
>         struct slab_sheaf *empty =3D NULL;
>         unsigned long flags;
> @@ -2901,7 +2902,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(str=
uct node_barn *barn)
>         if (!data_race(barn->nr_empty))
>                 return NULL;
>
> -       spin_lock_irqsave(&barn->lock, flags);
> +       if (likely(allow_spin))
> +               spin_lock_irqsave(&barn->lock, flags);
> +       else if (!spin_trylock_irqsave(&barn->lock, flags))
> +               return NULL;
>
>         if (likely(barn->nr_empty)) {
>                 empty =3D list_first_entry(&barn->sheaves_empty,
> @@ -2978,7 +2982,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sh=
eaf(struct node_barn *barn)
>   * change.
>   */
>  static struct slab_sheaf *
> -barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empt=
y)
> +barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empt=
y,
> +                        bool allow_spin)
>  {
>         struct slab_sheaf *full =3D NULL;
>         unsigned long flags;
> @@ -2986,7 +2991,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, s=
truct slab_sheaf *empty)
>         if (!data_race(barn->nr_full))
>                 return NULL;
>
> -       spin_lock_irqsave(&barn->lock, flags);
> +       if (likely(allow_spin))
> +               spin_lock_irqsave(&barn->lock, flags);
> +       else if (!spin_trylock_irqsave(&barn->lock, flags))
> +               return NULL;
>
>         if (likely(barn->nr_full)) {
>                 full =3D list_first_entry(&barn->sheaves_full, struct sla=
b_sheaf,
> @@ -3007,7 +3015,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, st=
ruct slab_sheaf *empty)
>   * barn. But if there are too many full sheaves, reject this with -E2BIG=
.
>   */
>  static struct slab_sheaf *
> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
> +                       bool allow_spin)
>  {
>         struct slab_sheaf *empty;
>         unsigned long flags;
> @@ -3018,7 +3027,10 @@ barn_replace_full_sheaf(struct node_barn *barn, st=
ruct slab_sheaf *full)
>         if (!data_race(barn->nr_empty))
>                 return ERR_PTR(-ENOMEM);
>
> -       spin_lock_irqsave(&barn->lock, flags);
> +       if (likely(allow_spin))
> +               spin_lock_irqsave(&barn->lock, flags);
> +       else if (!spin_trylock_irqsave(&barn->lock, flags))
> +               return ERR_PTR(-EBUSY);
>
>         if (likely(barn->nr_empty)) {
>                 empty =3D list_first_entry(&barn->sheaves_empty, struct s=
lab_sheaf,
> @@ -5012,7 +5024,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs,
>                 return NULL;
>         }
>
> -       full =3D barn_replace_empty_sheaf(barn, pcs->main);
> +       full =3D barn_replace_empty_sheaf(barn, pcs->main,
> +                                       gfpflags_allow_spinning(gfp));
>
>         if (full) {
>                 stat(s, BARN_GET);
> @@ -5029,7 +5042,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs,
>                         empty =3D pcs->spare;
>                         pcs->spare =3D NULL;
>                 } else {
> -                       empty =3D barn_get_empty_sheaf(barn);
> +                       empty =3D barn_get_empty_sheaf(barn, true);
>                 }
>         }
>
> @@ -5169,7 +5182,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gf=
p, int node)
>  }
>
>  static __fastpath_inline
> -unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void=
 **p)
> +unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t=
 size,
> +                                void **p)
>  {
>         struct slub_percpu_sheaves *pcs;
>         struct slab_sheaf *main;
> @@ -5203,7 +5217,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache =
*s, size_t size, void **p)
>                         return allocated;
>                 }
>
> -               full =3D barn_replace_empty_sheaf(barn, pcs->main);
> +               full =3D barn_replace_empty_sheaf(barn, pcs->main,
> +                                               gfpflags_allow_spinning(g=
fp));
>
>                 if (full) {
>                         stat(s, BARN_GET);
> @@ -5701,7 +5716,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_=
flags, int node)
>         gfp_t alloc_gfp =3D __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
>         struct kmem_cache *s;
>         bool can_retry =3D true;
> -       void *ret =3D ERR_PTR(-EBUSY);
> +       void *ret;
>
>         VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
>                                       __GFP_NO_OBJ_EXT));
> @@ -5732,6 +5747,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp=
_flags, int node)
>                  */
>                 return NULL;
>
> +       ret =3D alloc_from_pcs(s, alloc_gfp, node);
> +       if (ret)
> +               goto success;
> +
> +       ret =3D ERR_PTR(-EBUSY);
> +
>         /*
>          * Do not call slab_alloc_node(), since trylock mode isn't
>          * compatible with slab_pre_alloc_hook/should_failslab and
> @@ -5768,6 +5789,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_=
flags, int node)
>                 ret =3D NULL;
>         }
>
> +success:
>         maybe_wipe_obj_freeptr(s, ret);
>         slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
>                              slab_want_init_on_alloc(alloc_gfp, s), size)=
;
> @@ -6088,7 +6110,8 @@ static void __pcs_install_empty_sheaf(struct kmem_c=
ache *s,
>   * unlocked.
>   */
>  static struct slub_percpu_sheaves *
> -__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves=
 *pcs)
> +__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves=
 *pcs,
> +                       bool allow_spin)
>  {
>         struct slab_sheaf *empty;
>         struct node_barn *barn;
> @@ -6112,7 +6135,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>         put_fail =3D false;
>
>         if (!pcs->spare) {
> -               empty =3D barn_get_empty_sheaf(barn);
> +               empty =3D barn_get_empty_sheaf(barn, allow_spin);
>                 if (empty) {
>                         pcs->spare =3D pcs->main;
>                         pcs->main =3D empty;
> @@ -6126,7 +6149,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>                 return pcs;
>         }
>
> -       empty =3D barn_replace_full_sheaf(barn, pcs->main);
> +       empty =3D barn_replace_full_sheaf(barn, pcs->main, allow_spin);
>
>         if (!IS_ERR(empty)) {
>                 stat(s, BARN_PUT);
> @@ -6134,7 +6157,8 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>                 return pcs;
>         }
>
> -       if (PTR_ERR(empty) =3D=3D -E2BIG) {
> +       /* sheaf_flush_unused() doesn't support !allow_spin */
> +       if (PTR_ERR(empty) =3D=3D -E2BIG && allow_spin) {
>                 /* Since we got here, spare exists and is full */
>                 struct slab_sheaf *to_flush =3D pcs->spare;
>
> @@ -6159,6 +6183,14 @@ __pcs_replace_full_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs)
>  alloc_empty:
>         local_unlock(&s->cpu_sheaves->lock);
>
> +       /*
> +        * alloc_empty_sheaf() doesn't support !allow_spin and it's
> +        * easier to fall back to freeing directly without sheaves
> +        * than add the support (and to sheaf_flush_unused() above)
> +        */
> +       if (!allow_spin)
> +               return NULL;
> +
>         empty =3D alloc_empty_sheaf(s, GFP_NOWAIT);
>         if (empty)
>                 goto got_empty;
> @@ -6201,7 +6233,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struc=
t slub_percpu_sheaves *pcs)
>   * The object is expected to have passed slab_free_hook() already.
>   */
>  static __fastpath_inline
> -bool free_to_pcs(struct kmem_cache *s, void *object)
> +bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>  {
>         struct slub_percpu_sheaves *pcs;
>
> @@ -6212,7 +6244,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object=
)
>
>         if (unlikely(pcs->main->size =3D=3D s->sheaf_capacity)) {
>
> -               pcs =3D __pcs_replace_full_main(s, pcs);
> +               pcs =3D __pcs_replace_full_main(s, pcs, allow_spin);
>                 if (unlikely(!pcs))
>                         return false;
>         }
> @@ -6319,7 +6351,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *=
obj)
>                         goto fail;
>                 }
>
> -               empty =3D barn_get_empty_sheaf(barn);
> +               empty =3D barn_get_empty_sheaf(barn, true);
>
>                 if (empty) {
>                         pcs->rcu_free =3D empty;
> @@ -6437,7 +6469,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, =
size_t size, void **p)
>                 goto no_empty;
>
>         if (!pcs->spare) {
> -               empty =3D barn_get_empty_sheaf(barn);
> +               empty =3D barn_get_empty_sheaf(barn, true);
>                 if (!empty)
>                         goto no_empty;
>
> @@ -6451,7 +6483,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, =
size_t size, void **p)
>                 goto do_free;
>         }
>
> -       empty =3D barn_replace_full_sheaf(barn, pcs->main);
> +       empty =3D barn_replace_full_sheaf(barn, pcs->main, true);
>         if (IS_ERR(empty)) {
>                 stat(s, BARN_PUT_FAIL);
>                 goto no_empty;
> @@ -6703,7 +6735,7 @@ void slab_free(struct kmem_cache *s, struct slab *s=
lab, void *object,
>
>         if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) =3D=3D numa=
_mem_id())
>             && likely(!slab_test_pfmemalloc(slab))) {
> -               if (likely(free_to_pcs(s, object)))
> +               if (likely(free_to_pcs(s, object, true)))
>                         return;
>         }
>
> @@ -6964,7 +6996,8 @@ void kfree_nolock(const void *object)
>          * since kasan quarantine takes locks and not supported from NMI.
>          */
>         kasan_slab_free(s, x, false, false, /* skip quarantine */true);
> -       do_slab_free(s, slab, x, x, 0, _RET_IP_);
> +       if (!free_to_pcs(s, x, false))
> +               do_slab_free(s, slab, x, x, 0, _RET_IP_);
>  }
>  EXPORT_SYMBOL_GPL(kfree_nolock);
>
> @@ -7516,7 +7549,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache =
*s, gfp_t flags, size_t size,
>                 size--;
>         }
>
> -       i =3D alloc_from_pcs_bulk(s, size, p);
> +       i =3D alloc_from_pcs_bulk(s, flags, size, p);
>
>         if (i < size) {
>                 /*
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
AJuCfpELoHBKSq%3DDyLPPtQwqL%3DnPaQ1cBD-sthJd64MbW40Bxw%40mail.gmail.com.
