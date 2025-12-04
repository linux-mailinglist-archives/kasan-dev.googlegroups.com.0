Return-Path: <kasan-dev+bncBDW2JDUY5AORBDWIY3EQMGQE5Y5QR4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E247ECA4292
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:09:03 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-64165abd7ffsf1356689a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:09:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764860943; cv=pass;
        d=google.com; s=arc-20240605;
        b=XwJOGQSTXCAEXY24uTFSRRtInC+Pu5QmtmaoU39NFUb3e191VqYgan2lSw7ejMbbRi
         7UbusD+pW7XoZxQZizLoM9JHrIlc1JS9OlAlynrtocdQBhQ29GXd8WqlvM/5MRcy9ZIr
         kiKbpU6afBvr/X3HsTnYhSXam09M9UWM8bL6JKK+8PyAMlBM38VH54hpxNxcvHjPwllL
         1DgC3KZgdi+6xZjvMGQqap2JPm7kAemieVY+L+KFZYe7CihIke+7IuLOQ1Gp2T1cajk3
         wk/tiiaTSvDyVhjwJ4gdgLJU4069gi7N/PgqVAyLLq7n7KeL2hVtxScePC+RR8RgTwbD
         bpog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qEQgiT/40R4bbElcVSZFp/iU7ysQ/YTUhubuEyAJVPo=;
        fh=fNfuMK9wQfCI+jdT5x+nBrhyDtmZNXW1Y2hu726f/XU=;
        b=hmtgFkPmuEEqwmEkH/C9Cjvq9wfs7lcwd3Jgi0+FVqqIJpDaBI8hYdOiDkv3sZFB69
         EATODGCnyr/ePw5zzAVkKih8ZQeuhptWCadtGzfqJGARi6zbzplGqvhjXZGmzw5Sh6Ca
         5NGEsVNBaHAi2FA50sv+mEwikSyooM6HOqF2jqrI0iGH/HZBtGdJuLcrFyG8JUu4ws7p
         t9zBGwyTni11MrzpY9zpEh56P4HqicL+Db75Mw1QyOrkuuU7Se7PD5+1r2hicSsD6H6X
         IDV8X2Sqt+92cP+407xuwj7mkc6WuehB9v5ZVRDUSACLqvYoUZU1l18Tx9UcFpMraKcW
         FmtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SfEZt6Yc;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764860943; x=1765465743; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qEQgiT/40R4bbElcVSZFp/iU7ysQ/YTUhubuEyAJVPo=;
        b=mPwcjSFDVaS3iYxfOgHCp5J2YKF1in4OO9Fx21rZOLatBhd1k7njANsBbda7V63dLS
         G+rJ7BjrnBjWBmVYGbksaLUC3I3038Z2fB56+hm9qK2YkCC8NJuJbh8N+imtqgQtqFBB
         r5pzpNF4rz0GhN4aVBDvDrX5/xrLmTneQz1RkVUNN+KImr3IK1NjvMZbOoWy3DjxTRX9
         iXFlj+RlFpBQzEcpcAJ2EbhgPgfM/bvf0hUCPTFAW1flMg81PNhSFmbpDDVSlEtMXK8L
         9Lj93o/vfqOqoZwuhX7XOJHMW5uctPHDLKO3hgkQabVEasvZXxYllk7EVQbZvhMmkuCH
         Mqdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764860943; x=1765465743; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qEQgiT/40R4bbElcVSZFp/iU7ysQ/YTUhubuEyAJVPo=;
        b=KZkUxsafBfjrBM6g14/pGWCoUqOGzVoVxgCu6mli0Taye/deZRR1c1uq/+eFDFyoB6
         Iuc3nxK3wEX4qqPlCDXCh+KXcKO+hapSthluthh1O4RpxIE/SNlPDO42K1lLEiO/MdXk
         y9Ld8zW9ugc7dx5BvAUhdFcapNvq5Gmu6JtKxPm6MAIDszQMdnovCKpMgIBZ1Ew57YAG
         NUlPzx9ZliIrOgeLq7u9orGfMj5tW+jrNXMSZNazjmGYCMMdqfTxYU/uGc+JwXvYSdjM
         EwwGz69Y9i4G+lqlOoeBVgyBtxzTPFZhfFgsmvPmw3Znrz3Kihf5jCtvh/oZiSEw4prp
         DOPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764860943; x=1765465743;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qEQgiT/40R4bbElcVSZFp/iU7ysQ/YTUhubuEyAJVPo=;
        b=oEnXD8klYeOLSYo9Fy61GJswGX678ik7+CyBrMkKWiQ92wZ43+e+4keRg0RYhLaSLo
         NaAuUT0ZnsXVQTO7h5gCGfdjE07VrEQabDX41aZCaPp42Tn5peAXCu1ufiXqEMJMkakD
         yXzgoPxMQsgQdFXrpRZEhOJz6SeaVIuVYUSkG7MUlVT9IIWRxZqW8k99Qiw8bUbi5YSQ
         KLBcbUUZSXVdwa5Qgw0gnxw5oTO0XK4xNGomwIiJG6Ewbf+odlro2RNwA3mTQ0ffNUK2
         EYs2G8DP+SmZiZjqTh937ba9Q1z5x90+NbKby+M+DTg8EGZH51v/+gtR28tkIYPbDkcH
         z89g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAlN/EjwiYIlQj5idO9DU2f+sfUgGlJ71ac6VfijbftYOI1WBFCkxjR39Y2lTAQIoS0tuAqA==@lfdr.de
X-Gm-Message-State: AOJu0Yw39YDvznB+BuAyBmWJGKVlZGQLJZ4irB6fLCi8cNASMpWTMntq
	DWn+eS2k64lfkajKSPw4OnI26q97nwQkSE+7W+8XJPDrNELM3tPRUlO9
X-Google-Smtp-Source: AGHT+IH7R68jamrXhOsq/VnQXf1e14QjForOg6cAODLyFQvv3PQ+pqqBQQXlkRwdCaM738+OdC+P+Q==
X-Received: by 2002:a05:6402:518a:b0:647:56e6:5a3e with SMTP id 4fb4d7f45d1cf-6479c4adbb1mr6533864a12.30.1764860943034;
        Thu, 04 Dec 2025 07:09:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZRT7v/wpVvJqyscfvSBzRY6zmbwqbcrb80+nsZfRfKXA=="
Received: by 2002:a05:6402:1ec7:b0:647:9380:1e4c with SMTP id
 4fb4d7f45d1cf-647ad2ee0b2ls1213658a12.0.-pod-prod-01-eu; Thu, 04 Dec 2025
 07:09:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVgDmdZPAmFTt1qGBaHbc8Q38gmWyHFHazo4IS6s9x3tgOhiLQbE2//sNq4XBIjV3O9lgd6l3KiXzo=@googlegroups.com
X-Received: by 2002:a05:6402:4314:b0:640:976f:13b0 with SMTP id 4fb4d7f45d1cf-6479c3f6eb5mr5999254a12.12.1764860940251;
        Thu, 04 Dec 2025 07:09:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764860940; cv=none;
        d=google.com; s=arc-20240605;
        b=IexrIVKIXXE9gtZ1XMO5gqrh3Hjderhh+fZXxG8OG7VNjouQYP8FRa5N1bhEpKNfKY
         hLK14pR+3PGAeivaR6kQo3k9MgWXEme1YmI7SFx9lC1bZ/InUZ/muLgNnlv0runXuCHr
         dgx0AxetcSoyEaehkx0GmkBQtfYkfvIzEIAVy0IBEMV3zhfco8sJOTGLB+JTzuhLVt/p
         5BFxG7g/pBhZ9VLy/RFWLj7KqObMWvE3wrThgVq9pYHbrswGkFGLXgYXFy8dFhHTzgOB
         lF1u095jAYkR72nUFv6vMun+Q0z0Eube3Dvwn1TPkk4c1Jm3Z/zBZ8+OQI3EKi4oGU2+
         1RUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SuUcWJogoj5Zy6UaFHm38nZ24EUypEOSoXHBrVrDbNA=;
        fh=iaWxQhURIv4pazLYHlLyAXBYfsfMTgGOLPtgYiOBqDk=;
        b=csJW6rMeIvY6KB1Oh7eTyfJwmxtD1Yuoy61B3yNmcV7qmJ1OOGX1Z/FWtkIMKZetm4
         StdaErv7SN1UCvpJDoU2OAhvvtXpbb/rM+DWBdSoKbJBwbjIebArO3PMdJCPC//q4aOw
         mkxLmvGz/oUVG5an7d0mhbolOCFH0uDgH/uyTKnChzx5PXzRVEzTUvzUsUB46KpJxawu
         aUdJ4XJ4RvoY9dYRfg0ux7/mjukkz+H5ZQBAcQhvUUUSftt+SW1b3QU0GrQ0JN/yXBa6
         UCumuYlRzTb+rGnSf0ukKxkt21vpkWQ9egntCvfuAh9YRj0J8fkhntxdx4BDffqAdcvo
         WNjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SfEZt6Yc;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b33844d4si27278a12.8.2025.12.04.07.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:09:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-47795f6f5c0so7391595e9.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:09:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUGViFq3johWPvScIKaz+UvM2t1GQd5lLqjJedSQxNoNcrFAbo1WNuEFCHDqmt9XaMkFk6Y2Xvknws=@googlegroups.com
X-Gm-Gg: ASbGncsZe4l7bo/jNPHah5ufOQd8qxuWGSbIlsKDO92iRPcLTIB49hsen8Om2mHeZq+
	/yuyVhLxeMAUkJQuIoyJeEMMqf0eq0BVHfbzJUvs6Ow50MVIy5DyqBcSgITYelmx7DjWzzdCgtD
	z/4CQPsj7vei+C3xdOOEJMnKRmPPt0gJ4I2KzWycGjcEuAb0LYhDA81tRy8vJ9nAxx0VBNq2yB8
	2HPJthO2wiGuGCn517WNKMAT3/4k4+yQai+haNOdUBi9cS0rjJ9ospSHcj9aFQYixztzIiEUb7I
	Ckf/yIjqkEKnpZFNb5P+GEK7G/wr
X-Received: by 2002:a05:600c:4443:b0:477:7f4a:44ba with SMTP id
 5b1f17b1804b1-4792aee3a05mr61970655e9.4.1764860939413; Thu, 04 Dec 2025
 07:08:59 -0800 (PST)
MIME-Version: 1.0
References: <20251128185523.B995CC4CEFB@smtp.kernel.org> <CA+fCnZeKm4uZuv2hhnSE0RrBvjw26eZFNXC6S+SPDMD0O1vvvA@mail.gmail.com>
 <2f817f0ba6bc68d5e70309858d946597d64bac8b@linux.dev>
In-Reply-To: <2f817f0ba6bc68d5e70309858d946597d64bac8b@linux.dev>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 16:08:48 +0100
X-Gm-Features: AWmQ_bmRB-ksejN_0Sq4l24XGjc90aU-UQEIYgag1iEv7qWtJahCQTEp5QO-pZ4
Message-ID: <CA+fCnZeizRWUFs2k_7wbhJ5v+LdD8H77C0vrP6jp52qp0G_6zw@mail.gmail.com>
Subject: Re: + mm-kasan-fix-incorrect-unpoisoning-in-vrealloc-for-kasan.patch
 added to mm-hotfixes-unstable branch
To: Jiayuan Chen <jiayuan.chen@linux.dev>
Cc: Kees Cook <kees@kernel.org>, mm-commits@vger.kernel.org, vincenzo.frascino@arm.com, 
	urezki@gmail.com, stable@vger.kernel.org, ryabinin.a.a@gmail.com, 
	glider@google.com, dvyukov@google.com, dakr@kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SfEZt6Yc;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a
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

On Thu, Dec 4, 2025 at 2:00=E2=80=AFPM Jiayuan Chen <jiayuan.chen@linux.dev=
> wrote:
>
> December 3, 2025 at 23:18, "Andrey Konovalov" <andreyknvl@gmail.com mailt=
o:andreyknvl@gmail.com?to=3D%22Andrey%20Konovalov%22%20%3Candreyknvl%40gmai=
l.com%3E > wrote:
>
>
> >
>
> > >  ------------------------------------------------------
> > >  From: Jiayuan Chen <jiayuan.chen@linux.dev>
> > >  Subject: mm/kasan: fix incorrect unpoisoning in vrealloc for KASAN
> > >  Date: Fri, 28 Nov 2025 19:15:14 +0800
> > >
> > Hi Jiayuan,
> >
> > Please CC kasan-dev@googlegroups.com when sending KASAN patches.
> >
>
> Sorry about that. I missed it.
>
> > >
> > > Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes t=
wo
> > >  issues:
> > >
> > >  1. In vrealloc, we were missing the KASAN_VMALLOC_VM_ALLOC flag when
> > >  unpoisoning the extended region. This flag is required to correctly
> > >  associate the allocation with KASAN's vmalloc tracking.
> > >
> > >  Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explici=
tly
> > >  sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with =
it.
> > >  vrealloc must behave consistently =E2=80=94 especially when reusing =
existing
> > >  vmalloc regions =E2=80=94 to ensure KASAN can track allocations corr=
ectly.
> > >
> > >  2. When vrealloc reuses an existing vmalloc region (without allocati=
ng new
> > >  pages), KASAN previously generated a new tag, which broke tag-based
> > >  memory access tracking. We now add a 'reuse_tag' parameter to
> > >  __kasan_unpoison_vmalloc() to preserve the original tag in such case=
s.
> > >
> > I think we actually could assign a new tag to detect accesses through
> > the old pointer. Just gotta retag the whole region with this tag. But
> > this is a separate thing; filed
> > https://bugzilla.kernel.org/show_bug.cgi?id=3D220829 for this.
> >
>
> Thank you for your advice. I tested the following modification, and it wo=
rks.
>
>         if (size <=3D alloced_size) {
> -               kasan_unpoison_vmalloc(p + old_size, size - old_size,
> -                                      KASAN_VMALLOC_PROT_NORMAL);
> +               p =3D kasan_unpoison_vmalloc(p, size,
> +                                          KASAN_VMALLOC_PROT_NORMAL | KA=
SAN_VMALLOC_VM_ALLOC);
>                 /*
>                  * No need to zero memory here, as unused memory will hav=
e
>                  * already been zeroed at initial allocation time or duri=
ng
>                  * realloc shrink time.
>                  */
>                 vm->requested_size =3D size;
>                 return (void *)p;
>         }
>
>
> > >
> [...]
> > Would be good to have tests for vrealloc too. Filed
> > https://bugzilla.kernel.org/show_bug.cgi?id=3D220830 for this.
> >
>
> Thanks, I will add test for vrealloc in kasan_test_c.c.

Awesome!

But as mentioned in the other thread, let's first implement a
standalone fix for the original issue (that can be backported) and all
these extra additions can come as separate patches on top.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeizRWUFs2k_7wbhJ5v%2BLdD8H77C0vrP6jp52qp0G_6zw%40mail.gmail.com.
