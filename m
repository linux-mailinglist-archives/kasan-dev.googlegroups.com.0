Return-Path: <kasan-dev+bncBDW2JDUY5AORBM72SGWAMGQEZZ57SKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 606DE81BDBB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 19:00:21 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-42792c54367sf17897161cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 10:00:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703181620; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZbdKDWj+YdklbIrx2oEMa4DUrdMB2eMgZVEJqhX9f442psFDgzVw1iHTvk025i/9L/
         UmwaOypw+1Xnu6chHu8qUAoYb6aB/MnWeMyX/HK0gweesJLHVC034xID+whgUKMrLd2E
         7N26S5CAFNfCqUHZNT0XFMkEOq6lGqGhnDt8fJPMFLHRX2qfrOs7jyoi1MK3wUJ2ac+t
         0FEwkkkIMDgLD3KlVDgk/5NkxqG5v6Vm2VNuf979MM4y1fiPsFk3nCGFBjJaUSE1Mj5q
         9M6nuAOJfm3VfRQkvYfEpL1tfodWfrzK7bPTQDbq67PxoO0IoZ8IwbZ4+dUedGqKMPN4
         m0tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=tw0QxI8AsBVBaAE/etnjUMYP9aj48S/ex0WqhHCQnSY=;
        fh=CB4ptyjYu7VnqzlBYLJm816Cx+cYjKJLqHHW+myXDTg=;
        b=ieEkA1AyU3QIKhT6HN8CLp/idvjsgXPnDr+fMRax1TVUPVIMINVgjqfBX+NqFxHCg0
         5tl7459FqumYW20jMBFLeNyW5FJK1chHF6ZmVMHthmkVGmTNhsZulcSEBzjw/F/bPPaA
         p/7wDxZk6mZ1k/8ViCD2/G5fPpqMgFetETTBAK0j4TUPg9pXEZh/UgVFL3Sae9I0wkag
         NZzwTfRbyP/FkpK9OGo5jMXFeKfXHcsqBAk/GHryGp6eIU+6TGb38zkNyBPa6WQ649zP
         55N9D4dIW+u2VDT5x81j9fhkfWUEdAcuuIXZd4CIOsLBShtwDIPr2LNOYAw3EE6XVlVa
         HtOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RtYdimWF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703181620; x=1703786420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tw0QxI8AsBVBaAE/etnjUMYP9aj48S/ex0WqhHCQnSY=;
        b=pdpUUZvYZY/sqle/UC3l2KojdgFHpPP1DoedlHbkbJKAeUvmztmFggOyCps/O7JlKR
         sGF+/5Kb3rDjP50xBWpsbAStsTf2frkohOsgOML8s8yOOuOJuBQciXcFG/lvpUcEmCDz
         v2lX1U+BWbSuxikZlJYDt3gCIQpUogDd61IVfYZFSVdu2TdQpgRGYVG05zeIuUokpRwx
         AeljmyaPWzZS29lPXUptdoCTpRC50QW6xWZH3F6Ro5pd9XNswIT6mENchZmmsKVWlgKg
         O1AGwxJj01zpogSKLVMOOfPWnp/B3XktgdIbPzpHEvhuz/IcVa2mBg7JFLlQ+HK1AYmh
         mu1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703181620; x=1703786420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tw0QxI8AsBVBaAE/etnjUMYP9aj48S/ex0WqhHCQnSY=;
        b=BwYGnxjueAUWEGNS87JIroiRAGGgMESP0JhsA8U8Cg3s0bV7NSIhb3IPkr9m/vQiTK
         /hsctJtLUPRezs3Hn5CpWrDnsI48klpPa8lLXBaopI2yCnKHWEmUR1Yc//NSVQ5Cra8r
         4FMXrPR7SHOYdLHeO/CzpbDM2WvJh+CQiQpZ4xbBeA4k4s66ug+hpkoJThb4Q4kSfPp5
         hDHF1WbbGLxw3NnQFzXC5ycZ+aWLZP3+4WdnjJTM8XARIS7nD1ok3ypoC2+5pCRpyGxI
         lVBA7ZBv1OvoXacWBwIi+5LCo1XnjV1536U7QxxxCAktuU73qcVsXqiXVQ8thoEA5tn5
         twgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703181620; x=1703786420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tw0QxI8AsBVBaAE/etnjUMYP9aj48S/ex0WqhHCQnSY=;
        b=JgvoV1yTuvd1AQDJNMswHzpgjNsG07i6i7OrbYRC3hOwGdzN0zzaIn3xQ3ePL7XvFm
         TMdvhH1Xstpijd4uplw12FHz1OBQD3PynEEnW5GsiXa2BR23uN+usPZmzRXdJEhMhrLH
         otr2Mq5vVfG2a9tsMt/xlQNWZhsFml3HtMtZuxosyr+46dEnVtuit+sUhlVZa9pE9f9T
         AU9+oN9eb5/Ovl8+YVSQDDK2Eap7XJKpm8efzYTlpwEpwbP1Oyrd/is6QFEUHmI5Y3Sa
         Oc3ZWF+QAY3BSvtxeDV92TvbSN4rWVsxbjonfCW9br17BDPAcTknKpsh+lwEAgt6qBEz
         y+GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YywqB18DXGL851Bs9LUZNnqvc0PajYOhffm77kzHivdbsU4tcZn
	nNrsoF3NiFilJp1a25uXzho=
X-Google-Smtp-Source: AGHT+IE2PubAFMjUgGvBKdjfg7Hc8Y2fw68FZ2elPmiee+clb6/KP2Ri1pAgJNIhXUzUpNZSTnNhIw==
X-Received: by 2002:a05:622a:5c90:b0:423:78de:56ba with SMTP id ge16-20020a05622a5c9000b0042378de56bamr188021qtb.5.1703181620007;
        Thu, 21 Dec 2023 10:00:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d10:0:b0:423:707e:9eb with SMTP id f16-20020ac85d10000000b00423707e09ebls663992qtx.0.-pod-prod-00-us;
 Thu, 21 Dec 2023 10:00:19 -0800 (PST)
X-Received: by 2002:a05:620a:2091:b0:77f:c0eb:9ff9 with SMTP id e17-20020a05620a209100b0077fc0eb9ff9mr102237qka.70.1703181619167;
        Thu, 21 Dec 2023 10:00:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703181619; cv=none;
        d=google.com; s=arc-20160816;
        b=M4neIJW3kcL3EZmUyO2cGwTZDU19A8esY5QeusSXcCLlHkjrqkub3BZJGPdBSAVSNC
         vcpvxxPxMFfsWOoobguqHyO/y9X9oCc9Y5xD/Yz+nzSYI74V3azVFePTtI6O3io88Gjp
         2PnoigdGtQEtbKNwDtcv2On0wscBPgsnU//fMJeGu51chBFLdIQjEtOdt3nKqGsLFt2e
         HNnyKR8u231NIkeiLbnlkYs2bPC7kpjFNwWgrr8X+LXCuApVasKsGYT8XDQFc3wkjFp3
         2BaZ2qN/RwFuaMW/Mu271pSQyDWL/iH/uAOh3udmai13Qn1s8rp6FPlfS9KV121I4PB6
         DPuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VDdp8WfkBByjzDwq6Ok/AjXzstviyjPC8n93eKiHrkU=;
        fh=CB4ptyjYu7VnqzlBYLJm816Cx+cYjKJLqHHW+myXDTg=;
        b=LUf7mKnG7lteCijP2yaFF7qh/aALWjKGTQwAMHFHmbV81b4JmtEtJYdN7RUnouNyGj
         pdWawljSkDiWkflrrdN4X+c/JfQWQITKSmM3xkhJAeDeupk8ykQRSmMwEFfA0XFq9B3z
         s87MT9DH3WwEPq7Grmfuf0uQ+TTEs+/vu+URybGMj4h/ogcmBvOWaGL1gt1AIXWSwBwE
         RTSodCQhNK+AD83wzUA3XKwdEzcUDsJbfjBJVXwW6TyW/BuJrHJqUII6ElNg20Zs3dXO
         y58vEZnGdi6ldalxR2mHqLj52faYjwmWjAPEfUWVrJCR9n9CzbzdQ0hpF5RN5KUmYtHA
         iMbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RtYdimWF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id v6-20020ae9e306000000b007811b471a29si166094qkf.4.2023.12.21.10.00.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 10:00:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-5cd84c5442cso1606874a12.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 10:00:19 -0800 (PST)
X-Received: by 2002:a05:6a20:394b:b0:194:3af:19ca with SMTP id
 r11-20020a056a20394b00b0019403af19camr61272pzg.47.1703181617939; Thu, 21 Dec
 2023 10:00:17 -0800 (PST)
MIME-Version: 1.0
References: <20231221-mark-unpoison_slab_object-as-static-v1-1-bf24f0982edc@kernel.org>
 <CA+fCnZfO6JyNvf7Wt7sOBoPKTX_UGexuWpyvgXYq9XSJEp-dLg@mail.gmail.com>
In-Reply-To: <CA+fCnZfO6JyNvf7Wt7sOBoPKTX_UGexuWpyvgXYq9XSJEp-dLg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Dec 2023 19:00:07 +0100
Message-ID: <CA+fCnZcPmxCOpAucAJd=WoNHUeA5TpmLeRs+zei8E63Se-xP4Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: Mark unpoison_slab_object() as static
To: Nathan Chancellor <nathan@kernel.org>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, patches@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RtYdimWF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Dec 21, 2023 at 6:33=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Thu, Dec 21, 2023 at 6:27=E2=80=AFPM Nathan Chancellor <nathan@kernel.=
org> wrote:
> >
> > With -Wmissing-prototypes enabled, there is a warning that
> > unpoison_slab_object() has no prototype, breaking the build with
> > CONFIG_WERROR=3Dy:
> >
> >   mm/kasan/common.c:271:6: error: no previous prototype for 'unpoison_s=
lab_object' [-Werror=3Dmissing-prototypes]
> >     271 | void unpoison_slab_object(struct kmem_cache *cache, void *obj=
ect, gfp_t flags,
> >         |      ^~~~~~~~~~~~~~~~~~~~
> >   cc1: all warnings being treated as errors
> >
> > Mark the function as static, as it is not used outside of this
> > translation unit, clearing up the warning.
> >
> > Fixes: 3f38c3c5bc40 ("kasan: save alloc stack traces for mempool")
> > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> > ---
> >  mm/kasan/common.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index ebb1b23d6480..563cda95240b 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -277,8 +277,8 @@ void __kasan_kfree_large(void *ptr, unsigned long i=
p)
> >         /* The object will be poisoned by kasan_poison_pages(). */
> >  }
> >
> > -void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_=
t flags,
> > -                         bool init)
> > +static void unpoison_slab_object(struct kmem_cache *cache, void *objec=
t,
> > +                                gfp_t flags, bool init)
> >  {
> >         /*
> >          * Unpoison the whole object. For kmalloc() allocations,
> >
> > ---
> > base-commit: eacce8189e28717da6f44ee492b7404c636ae0de
> > change-id: 20231221-mark-unpoison_slab_object-as-static-3bf224e1527f
> >
> > Best regards,
> > --
> > Nathan Chancellor <nathan@kernel.org>
> >
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> I'll fold this fix into v2 if I end up resending the series.
>
> Thank you, Nathan!

Let's actually mark it as "static inline", I'll send a v2.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcPmxCOpAucAJd%3DWoNHUeA5TpmLeRs%2Bzei8E63Se-xP4Q%40mail.=
gmail.com.
