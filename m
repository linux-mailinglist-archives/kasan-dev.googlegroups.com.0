Return-Path: <kasan-dev+bncBC7OD3FKWUERBLG4VHFQMGQEUNOU5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 03933D339A8
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 17:58:22 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-88a43d4cd2bsf28962816d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 08:58:21 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768582701; cv=pass;
        d=google.com; s=arc-20240605;
        b=RbUziMtkYUarz5TS7Qh+5Bw3nMRYlNMksJvDiwonR/G6WIzuz0pk+VDKEagwpQtfmX
         qnqg+n4pYMSXwyXiEtWCZnzwJBQp6R7kvQ0JCTgXaKfJvOHWy2jEWLYSlKmrDQu6EHsp
         cJnA18n9kxM4w5dZMxtBQvLjGf43o1+t3jKNHCezeo+5Gc8MAE1Pqn7lOSpuNI6rIy/Q
         SBxxHOZRYGYr49T8cZ3ou2Q0ykHGJsTjzW+nMZBLkBiVH92jffEnbu7J66VzZ1Kx8fNM
         k0hMeEPTzk1695maRlmpLVLZbA9lkYWb1q77LCUIglsFEA0azEBB44q8gIe0LT4SagN7
         UV2Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uDSDYS/XbMes99VRBUbsHLUre0glI/2qGbtWPAoJ7yk=;
        fh=e7kZENlCdndkUOc4UUhdOf2THG67lwIOBvvwK5xwvaY=;
        b=TVUtHFo4q9VIL4pqdKzR8E9eNJYg53UCqePmW+SGZwobH39e2l2pXNAzfajf6/Je5g
         xWhGvf58wV9nMpc9M8dZgWTg+M+tQY5eBv32k+G4PYM5Y3ExS2y0Ip0wZ6x+9n4ZcFoL
         zDdGWLoDUBTUb0mYFYGyUc98eud9XMuvenqwuM/LVWMR7tDcvYZ/iZlFLyWlfa/3fDqH
         9NFduCg6XmQEJP6KMZTslWjZuiWdP5ffbwGiO+3xkqDuylWbq8dX9w4n8E/XgDf2mAcT
         nrRJ8wfBAUU3WTAL49AirqHs55bnJBt+IMDJ61Th035OxlF+eBblD/llMtEfJ3aPzeKF
         9d6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0jnCPqtJ;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768582701; x=1769187501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uDSDYS/XbMes99VRBUbsHLUre0glI/2qGbtWPAoJ7yk=;
        b=NwWbprjp0sfKjRZ+A2vX1tQxGRZtJ4qXYQgPJCOGolh9rq4r+z4GQ00UYLf3e71Eu8
         TzReiu8wyO/PL4BuKjq7sKwCxrFTaNQe2uPIHJVHKb2WHC3Amf5OyLRZQZG0YZIvg35A
         u/ltrBz921OCAr7i6fHkr2d2jyBESqlLZlzGxm+dKxBVOFrxZoUk/bqux7Fwv6t+pl/3
         L4//PeAIWAFAC1qepB4fUIibccc8XEChf6FYu+JCKYtzQ1UA/KX+wLwXdoCOvKYjvMbs
         vOuCB7mAQyM9w/f8DqEDQMvmOGyXw77X7jz4MEANYe7F/xOF/nPSHy9Q5t3HHlMg7QKy
         rYpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768582701; x=1769187501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uDSDYS/XbMes99VRBUbsHLUre0glI/2qGbtWPAoJ7yk=;
        b=apdi8N/F1sitrH5SpCzbl9KBcIZQzsVE6pmHn0F+eYxvFoEmNh/NERRbMkTOKi24N9
         58HJ+ln0LD8jiU3UcDkthc89/b0uK3+HjcKBE/cXTQJUPRQPXEeQfpVcKS84Jiz8xsVb
         Ff5ODhsYnKl+JjeeeDwoyDiWp98h0x18XNEHivIXxf4XRlVuJLhEvNBQp/rrZ56ep8tB
         mxl/c84VEMaNMd0Cjc3bLtonLMAh2m6jG6cNRRjjLa2tMLqWQecvGwgzH5zxQRqw+zA9
         slxOIW15hQTV2/aKp+aaSkonEKNZi/pprQoQjFLJFI7bvqqgNsKPSah31BeA5J+KJ2OO
         ZAPg==
X-Forwarded-Encrypted: i=3; AJvYcCUyJMOLpNFuDE0p5RZBLon0z1p+ZZ6mRdsH1+v6FYm1ioV7Pl0RkGlAPo+h1J+nMORpdwX45g==@lfdr.de
X-Gm-Message-State: AOJu0YwXUc+NtfXOkc1ql4k43p5c/COZjRoSd5tLTtqf9O7XJP29Wder
	bZ+pETB8hO9dI4Qc+qFhR586Hyc7Qhkyz2PHJ3Ay5DVhlIxIUn/7nzGx
X-Received: by 2002:a05:622a:1902:b0:501:51fb:622c with SMTP id d75a77b69052e-502a16d2f7amr48703001cf.37.1768582700628;
        Fri, 16 Jan 2026 08:58:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EvsoXsZBNBFkgfSkalAsxPx6m7niVpHesgjnwdHRnNfw=="
Received: by 2002:a05:6214:1947:b0:888:3ab3:a46f with SMTP id
 6a1803df08f44-894221e2904ls31797016d6.0.-pod-prod-08-us; Fri, 16 Jan 2026
 08:58:19 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW2vIPA3ZJB+aFuBeJ1SulrfznEkKlBExpPXcdwW7NfQl2dnEJ5gDTTrBdLKawdkqMQSSx4uwm4Qkw=@googlegroups.com
X-Received: by 2002:a05:6102:a52:b0:5ef:aeff:82f9 with SMTP id ada2fe7eead31-5f1a55c0311mr1174574137.35.1768582699715;
        Fri, 16 Jan 2026 08:58:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768582699; cv=pass;
        d=google.com; s=arc-20240605;
        b=G4pvbxHlThPdNLKlqI7fSEMIZh2NgfHfHFXsGEdKHyozE8BN5rbNqFUJfpvZqz20Z4
         13iBLYXDQm++R6Ve3daca8K9YTLuR99UEz5DzJxjlAlG5+qGGJhxm9o4eMon5aUQZaKv
         0h8TrJ7+dnctbaFszDvKN7hQRhRye3BLtrjOqeApfsfIKLkepi1i7UUJTbOaM5XD51kZ
         QxZGveetYTnjmVx5TUVvvtFrjJIBpF4mEk/gBD+fm4ateu6sUg2J7b2VZpy/ldT/9jmc
         vMfZXdlqHRrZLrRsdbtVpAOCOButkYsGvZe5QdcFqOe5vIZ/pcRl2+ciRlIc6EsPsJwP
         WILg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UaTAsxPYTCPWjwQ4mQCkSgV5i6jSjH4fHwMIaU55o8I=;
        fh=H630gUxdfYP7zI3HkqIH+9XB9sjncIGjWGvJP0DZlJY=;
        b=MSEuUukclE8WE6G+zTfr531XYHLAftfyN7Ba510EvhruhbAFZZa/Q0xFypJJ09P4+A
         5oHW/q/ekzjQQAIlFNtJZGAozDYAwR7o0NeRJ9tiYDGspwxHmcXbSUrtHMv7NiOsXAxY
         VJM965kyFMDUfEwq4Xe+WFhWU0/SXoSA/JQTXilY6tlI2OcvU7b8BRKPPIKAlR8Xdvv8
         l9GUfb8Fpg9tk53LH8iRL2wwDVesMH8rk3bNuFHfw8y6SST187XDrTt3avEQTZThb89K
         NuKDz1zxfJXa3G7wqqIGz0L3G5NZMNzNlTK6dgVDx+oBLnOCfgt7yhltPzLJyYaz3s0R
         dFgg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0jnCPqtJ;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5f1a6f4c6c3si93760137.3.2026.01.16.08.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 08:58:19 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-5014acad6f2so537221cf.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 08:58:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768582699; cv=none;
        d=google.com; s=arc-20240605;
        b=WHyCaHuc6sm+kCMcLmlFFlYBXa9N0J9nzyMv0LVYXsP7FS5ky8AKNMM4j+Ygu7dJnP
         s3XhNy7+A1+U1r7Hbu6K+BRDGj/x7eu6GktkLKFRDx/B+/Kd7bDzqh1Z0ML0i7hvLwp4
         dLCt+m6aOUGXvrZd93fBnleCJQ7Pgefj9TiBA1ZfvImL7P07Yp/32DovgESxnJsTU/7O
         dkn7JYSmyynfRdgmiDRqKQ/fhdDm8+2S2bmuZqZC8/cturjuWim49Gq91+cLp1wFxWzp
         dd1fA5ZsjmbvC7cu7z2FFD4vqruEkfFKf5rJeaCOt3eUT+n8N9FXl+wDISj/hWVfnWpV
         536g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UaTAsxPYTCPWjwQ4mQCkSgV5i6jSjH4fHwMIaU55o8I=;
        fh=H630gUxdfYP7zI3HkqIH+9XB9sjncIGjWGvJP0DZlJY=;
        b=ejTA3eE8XAYil8zeg+yCCvd/fjmMxMfyLmYK/dqyuDzJQCv9FdOdLmLvsGSXTYN9W+
         UtF6xqdFEQ5oXnsbvdTtQpksu2H5bVPGkbLlsXx5HCMjvdDtto3jAoFdUNyRv/Jf9zKa
         3hWg+YNFdw5ivRpA37OapFX0o2lA4hGGxhqaxGyyhBC0f5M5nC1mieDtWOIEUHT6iKEs
         /uTr5B4AfW58x9ndbHqh10XWsfVCgvd2DdnbHyx8a1C61jKY56dyQemXC7sFfbXFPcsB
         i3Cxiwe/4+qge6joEuzNny4uPQTHFY+Ehb2snYM9B+9iSYe4Lxq7j6Lw0Tv53u2u3P4M
         xwaw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCV+6E11nUncnC9/vufm6GbTDLcvjp7ppKUoud+CjYwY83UgrevjuHKorKBiMgixi6CYKu1lA7vqs4o=@googlegroups.com
X-Gm-Gg: AY/fxX52/RQkCOQqkoopbuq/RvG3od/+1v/cXN/gitX4sL4EtTe0d7CpCnm4rGOe2Cd
	YBhZvjnG+HsvkLSuOR9M+efrX/Yp6HeWlCfjkWmffiiqfWppSoGj3x+VY4DaTuOMHgNpwJQ4MU0
	6ygNtedbAcQilvJaFlirI8xoI86GDTEL2jagg5whRbZjLOesZdHfdcF28T+uoYoCRRFZ5J4RR7G
	Nja/WXas67tbi0X/RNfiYn719gTztYfVtE+29irUjPNwpihwEJaq2E6wUKRYrSczsBVTw==
X-Received: by 2002:a05:622a:4c6:b0:4f1:9c3f:2845 with SMTP id
 d75a77b69052e-502a36feeefmr9677951cf.9.1768582698713; Fri, 16 Jan 2026
 08:58:18 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-3-98225cfb50cf@suse.cz> <CAJuCfpHowLbqn7ex1COBTZBchhWFy=C3sgD0Uo=J-nKX+NYBvA@mail.gmail.com>
 <4e73da60-b58d-40bd-86ed-a0243967017b@suse.cz>
In-Reply-To: <4e73da60-b58d-40bd-86ed-a0243967017b@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jan 2026 08:58:07 -0800
X-Gm-Features: AZwV_QiGfwWS_a1m6Zzi_yFSpjGioLT9sSjsdK1eWkPIvYtSYBlLySU-l0-N1MQ
Message-ID: <CAJuCfpGikJpueGo1hW8ONimHOALnpftT22F7xYuL5CpnphJu+A@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=0jnCPqtJ;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=surenb@google.com;
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

On Thu, Jan 15, 2026 at 11:24=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 1/16/26 01:22, Suren Baghdasaryan wrote:
> > On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> Before enabling sheaves for all caches (with automatically determined
> >> capacity), their enablement should no longer prevent merging of caches=
.
> >> Limit this merge prevention only to caches that were created with a
> >> specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.
> >>
> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> ---
> >>  mm/slab_common.c | 13 +++++++------
> >>  1 file changed, 7 insertions(+), 6 deletions(-)
> >>
> >> diff --git a/mm/slab_common.c b/mm/slab_common.c
> >> index 52591d9c04f3..54c17dc6d5ec 100644
> >> --- a/mm/slab_common.c
> >> +++ b/mm/slab_common.c
> >> @@ -163,9 +163,6 @@ int slab_unmergeable(struct kmem_cache *s)
> >>                 return 1;
> >>  #endif
> >>
> >> -       if (s->cpu_sheaves)
> >> -               return 1;
> >> -
> >>         /*
> >>          * We may have set a slab to be unmergeable during bootstrap.
> >>          */
> >> @@ -190,9 +187,6 @@ static struct kmem_cache *find_mergeable(unsigned =
int size, slab_flags_t flags,
> >>         if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
> >>                 return NULL;
> >>
> >> -       if (args->sheaf_capacity)
> >> -               return NULL;
> >> -
> >>         flags =3D kmem_cache_flags(flags, name);
> >>
> >>         if (flags & SLAB_NEVER_MERGE)
> >> @@ -337,6 +331,13 @@ struct kmem_cache *__kmem_cache_create_args(const=
 char *name,
> >>         flags &=3D ~SLAB_DEBUG_FLAGS;
> >>  #endif
> >>
> >> +       /*
> >> +        * Caches with specific capacity are special enough. It's simp=
ler to
> >> +        * make them unmergeable.
> >> +        */
> >> +       if (args->sheaf_capacity)
> >> +               flags |=3D SLAB_NO_MERGE;
> >
> > So, this is very subtle and maybe not that important but the comment
> > for kmem_cache_args.sheaf_capacity claims "When slub_debug is enabled
> > for the cache, the sheaf_capacity argument is ignored.". With this
> > change this argument is not completely ignored anymore... It sets
> > SLAB_NO_MERGE even if slub_debug is enabled, doesn't it?
>
> True, but the various debug flags set by slub_debug also prevent merging =
so
> it doesn't change the outcome.

Yeah, I thought that would not matter much but wanted to make sure.

After finishing the review I'll have to remember to verify if that
comment on slub_debug/sheaf interplay stays true even after
args->sheaf_capacity becomes the min sheaf capacity.

>
> >> +
> >>         mutex_lock(&slab_mutex);
> >>
> >>         err =3D kmem_cache_sanity_check(name, object_size);
> >>
> >> --
> >> 2.52.0
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpGikJpueGo1hW8ONimHOALnpftT22F7xYuL5CpnphJu%2BA%40mail.gmail.com.
