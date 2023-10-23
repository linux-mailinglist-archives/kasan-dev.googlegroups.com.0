Return-Path: <kasan-dev+bncBDW2JDUY5AORBFNZ3KUQMGQEVEYLFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 303297D3C14
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:17:27 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3b2e7a8fbbdsf4999842b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:17:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077846; cv=pass;
        d=google.com; s=arc-20160816;
        b=mqH0sjcnG/8N2H/Tza9MiZW+sySZiHrTb5ZmlnVInp8u5quVvdhvyBpKKkMBrDKq8C
         4ju1bpjcdvhUZdGJHYIwcDqjjazF4iS21j1Yk9h7nKTmGbZoqwZJtq7jHJnB/s+3vPhR
         f8V7TnluOri6zKR9gedNKFsGKwB0E7dyUTRFEm4ww/m381pAyZ6tN1/IoiibND2DkeoD
         trJq45gcAkx4vRd8Q2bYD85jHq0dCuOGOYwqRuSmpGZkU5WUMolReOW7qry48oWTxi49
         k5Yn9H5bBetRAK67FJsq46EwLgYPBmdN8jpLCp0qRTVz4I8uWumpruDGxHg2UjVWlI1P
         tRQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xphE2fA5vxR7UbCfaSyVBi7J4P9oJKfNIPfIRp7hVfs=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=JgNMznaP9Uuhg879whJpg3sQLbx9xMl6gAHa+7/zrk8MTjCVphpjeYKLfcKs1Rn7Em
         DtoX652nKxAO3uxttzBpC5AynIkhyA8L/FBNcCqT6PqKo4FoTGIU3NGugKJsRdc2+LkS
         7bWyiu/MvFSzcVLc3UmIkscT3NhIDRI4KqXSU2L9BZBD8+oF89kMwXtmPFmsvB84ahfk
         uPidtNbXvE0xs8Bd+LtBw6TmCLtoqDq42OYTuVrLzNkLS9fcN1ghRH3QZmyScbUHfANF
         +GbnaaDYrjouuN4GL+pijfdRmlf6RIA/3Z6WstLsDRmFoasnmG3pnPew2gy+m9Sx8QG6
         HZHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MDXehsEV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077846; x=1698682646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xphE2fA5vxR7UbCfaSyVBi7J4P9oJKfNIPfIRp7hVfs=;
        b=sqvm3HblMmdqoGfKSmr1wXUANEELP6wckJ1PgQ2QnfYSANyxui3T3IO/c7eKy/n22E
         o6aKNadMz7+cKsHO3z573BT3CpQv9YZirKgu2fwtV6wkI9KM61zU6zXQAuuBGTjx+E1r
         Csw3vG7HoLrAq35WolWliqoju8DFcDwJOZmhdgVEtiNHcZKe8x31Ai438bvqMQVsD6uH
         tlnikv3kwyguCBPjB8yyiTeEfwrghGBSsqC77YdKFE7H6ILQ8gwTPoCONM2AneMLDT7n
         TbAMFAwv2N4/swVm17yuYVAU21A4LAa/xd7JV3v8MhwW/iX8VBdi3rRCcsrzTgU+WPSl
         +BhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077846; x=1698682646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xphE2fA5vxR7UbCfaSyVBi7J4P9oJKfNIPfIRp7hVfs=;
        b=XNnYQbCyGmejS7/TOAfIk3bkWkOTBxL9gkdgfllgvh5GNXfUjFdgT8Xbqf79hkVodN
         Xb0Mc16FnOkeKRwjrhO2c6EuAb3Nxc3aG+wrh7KMXiufq3/a/V7BsQHHvTBaSvOpJoZH
         VXmTmTjAcdWi/BdigV5r+I3TeI6sKvMO3tG38ksIhWxikuAGYbedx+uwqEcKczgkSaGl
         e1aM6z8lfTip1QENusOtUbkBzeYWxqsIO/1ivcBUQgNyz/y2U8gaLNiodeLSeLd2X/f+
         09/yKXww5vJE5bomlKGKxDegAKUnQYw3ZvtiugRVe8ndCqLSbRTMQONBymTqWtW6A+MX
         JZ6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077846; x=1698682646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xphE2fA5vxR7UbCfaSyVBi7J4P9oJKfNIPfIRp7hVfs=;
        b=DuC0gCoKKQQHbMUetVJ6Q8Bvh36jb8Bs3MWt1dlaP0aEMEWUCrYPUgs94c3Atlj/fJ
         lW9iG8rTyzPcUHAccghtiVMUiwRIEOfASOLW35ONUV13UsEvTmCMuj4fy1LkffiXda2N
         xfrFzfg/dbHG7qm/OUJYwXnA74K0fm00bPtaW2A8d1wahhIYx26fDWSTo4oKTVTY6kkp
         Vs09JyWFz7QOPd8M8d+//LUz+km5q4MaGHC88KYGdUv7AJfdt3rMqFb7OHRnmweS95iY
         Ve2PVEn9ACGrABqwWGrwl1Uac4JkGKgAz7P35/DT9VqRcbZJinFI3VX354vnaL3LGiQ+
         kH+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz93AYKOOSa+c4Hd89MAdOnZC90LXjunxBzZEpTMUHkFN83qmdd
	CuQHDKeOJZtO7wVICw4F5H8=
X-Google-Smtp-Source: AGHT+IF8pmadtOfyBPE1/HX3csDM0HmKA5g1mPl5AjAjxbgGMgD8DLgFmKjsvHtiok7w9TSRRUQJBQ==
X-Received: by 2002:a05:6808:311:b0:3af:b6ea:2e2 with SMTP id i17-20020a056808031100b003afb6ea02e2mr6906759oie.59.1698077845780;
        Mon, 23 Oct 2023 09:17:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4388:b0:656:3716:f1e6 with SMTP id
 oh8-20020a056214438800b006563716f1e6ls3041415qvb.0.-pod-prod-06-us; Mon, 23
 Oct 2023 09:17:25 -0700 (PDT)
X-Received: by 2002:a67:e002:0:b0:457:cd98:490b with SMTP id c2-20020a67e002000000b00457cd98490bmr7287498vsl.0.1698077844860;
        Mon, 23 Oct 2023 09:17:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077844; cv=none;
        d=google.com; s=arc-20160816;
        b=IyMsMUFsM+GmXVG7uIstw+svEJ48EltMNdQtN0r8EXp1KCQpQz9T0uRPj3GicyhPkk
         2+kN+ABnrClP/mGh9Gfh+sLljY1nUv3KbeFQvUHb/LAWbVEajONUTxDYKQks2M/RCN1J
         J1i0zAplq46W4buytEOojjbmde1N2vl/7CjJ0uJGLqXodBYI5XqyRleOQ4kkIS8RThq3
         fHgmmNMnQNiZFyuAFVKO7P6CgwQpaAg15kMDKFCrIb171+QdEfXY4qIh4X53rxC3+QkI
         KB9yN5gmQstfzl9Zj50Z5ARU+3g13TUNjAH316y+VZMnp3r/C+SLCpI+a+1fY9/ImZCh
         9PVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=C2cbWsLkEimzOV8VOGRLrBW3hA2WqDn8Mgiw4dAIqPI=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=YDcz/lKqAPlGnlbW5KMGquzgdews2bryjAGleRmb46tDWzeN5BC9Dkz9fAYIAGKC6C
         H11aLYL0dEArDPEddZw29ZqROGoWEg997k3xYCuZbSIZrcVYfOZcZ8C9fukWmp9FrUiy
         BBGsSysgMJhhYKhUrpIGreCQlRL9K+mO1eMUcfDS6leMy9CRTAZ4XlNhBSDyP2fKcjsU
         lXpzTEwQ0E75R3X4EPnVHtxtwsdNrqq/uMHBkpVq2G6eMZIi6PuSeWghtyELqWFk2KaT
         20wirDxe9JRuuGhxgiAHvnOhupkRwKwFLxh08xJzSqQ9aV01oi8xw/skyy7BzSOH71ji
         fLOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MDXehsEV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id h3-20020a0561023d8300b004508d6fcf6csi775608vsv.1.2023.10.23.09.17.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:17:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-5ac88d2cfaaso2713451a12.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:17:24 -0700 (PDT)
X-Received: by 2002:a17:90b:1098:b0:27d:54b9:c3d4 with SMTP id
 gj24-20020a17090b109800b0027d54b9c3d4mr9572424pjb.1.1698077843855; Mon, 23
 Oct 2023 09:17:23 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
 <CAG_fn=XnH_z70wPtX=jRtKsb+Kxu5hosnZbnNC=mw6juSm7idA@mail.gmail.com>
In-Reply-To: <CAG_fn=XnH_z70wPtX=jRtKsb+Kxu5hosnZbnNC=mw6juSm7idA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:17:12 +0200
Message-ID: <CA+fCnZdzpHEPnFa1A5TtFu_si3RbQrBEFXHhALEtnVR4nhfzEw@mail.gmail.com>
Subject: Re: [PATCH v2 14/19] lib/stackdepot, kasan: add flags to
 __stack_depot_save and rename
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MDXehsEV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::529
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

On Mon, Oct 9, 2023 at 12:10=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Wed, Sep 13, 2023 at 7:17=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Change the bool can_alloc argument of __stack_depot_save to a
> > u32 argument that accepts a set of flags.
> >
> > The following patch will add another flag to stack_depot_save_flags
> > besides the existing STACK_DEPOT_FLAG_CAN_ALLOC.
> >
> > Also rename the function to stack_depot_save_flags, as __stack_depot_sa=
ve
> > is a cryptic name,
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> (assuming you'll address Marco's comment)
>
> ...
>
> >  void kasan_record_aux_stack_noalloc(void *addr)
> >  {
> > -       return __kasan_record_aux_stack(addr, false);
> > +       return __kasan_record_aux_stack(addr, 0);
>
> Maybe make the intent to not allocate more explicit by declaring some
> STACK_DEPOT_FLAG_CAN_NOT_ALLOC =3D 0?
> (Leaving this up to you)

The next patch adds another flag, so STACK_DEPOT_FLAG_CAN_NOT_ALLOC is
probably not the best name. I could add something like
STACK_DEPOT_FLAG_NONE, but I think this might create an impression
that there's some kind of NONE flag that affects the behavior of
stack_depot_save_flags in a special way.

I think we can just keep the value as 0, as it seems what the kernel
does in similar cases. E.g. for slab_flags_t, the kernel passes 0 to
kmem_cache_create when there are no special flags required.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdzpHEPnFa1A5TtFu_si3RbQrBEFXHhALEtnVR4nhfzEw%40mail.gmai=
l.com.
